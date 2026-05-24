//! AI runtime + agent-task pipeline glue.
//!
//! The module wires together:
//!
//! 1. [`BudgetStoreTracker`]: adapts `nyctos-core`'s SQLite
//!    `BudgetStore` to the `nyctos-ai::BudgetTracker` host port the
//!    adapters call on every successful round trip. The trait surface
//!    lives in `nyctos-ai`; the SQLite backend lives in
//!    `nyctos-core`; this binary owns the wiring.
//! 2. [`run_payload_synthesis_pass`]: scans a finished
//!    `RunBundle<Diag>` for diags carrying
//!    `Unsupported(NoPayloadsForCap)` and fans out one PayloadSynthesis
//!    task per finding. Concurrency is capped by
//!    `[ai] max_concurrent_one_shot`; spend is recorded against the
//!    run's `budgets` row.
//! 3. [`run_spec_derivation_pass`]: same shape as the payload pass
//!    but firing on `Inconclusive(SpecDerivationFailed)` diags.
//!    Successful outcomes land in the `harness_specs` table and the
//!    parent finding's `spec_id` back-link is stamped.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use nyctos_ai::{
    read_spec_excerpt, run_chain_reasoning, run_exploration, run_live_evidence_review,
    run_novel_findings, run_payload_synthesis, run_spec_derivation, AiRuntime, AnthropicSdkAdapter,
    BudgetTracker, ChainReasoningOutcome, ClaudeCodeAdapter, CodexCliAdapter, EscapeSuiteGate,
    EscapeSuiteVerdict, ExplorationAuditEntry, ExplorationEndpoint, ExplorationFinding,
    ExplorationHaltReason, ExplorationKnownLead, ExplorationOutcome, ExplorationScope,
    LiveEvidenceReviewInput, LiveEvidenceReviewOutput, NovelFindingDiscoveryOutcome,
    PayloadSynthesisOutcome, Pricing, SharedBudgetTracker, SpecDerivationOutcome,
    DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS, DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
};
use nyctos_core::store::{
    AgentTraceRecord, CandidateFindingRecord, CandidateStatus, ChainRecord, FindingOrigin,
    FindingRecord, HarnessSpecRecord, PayloadRecord, PentestCandidateRecord, Store, TaskKind,
};
use nyctos_core::{
    ids::short_token, now_epoch_ms, AiConfig, AiRuntime as ConfigAiRuntime, RepoOutcome, RunBundle,
    RunConfig, SandboxBackend, SandboxConfig, SecretStore, WorkspaceHandle,
};
use nyctos_nyx::Diag;
use nyctos_sandbox::payload_runner::{HarnessSource, HarnessSpecInput, PayloadRun, PayloadRunner};
use nyctos_sandbox::BackendKind;
use nyctos_types::agent::{AgentTraceMetrics, AiError, Budget, BudgetKind, Prompt};
use nyctos_types::chain::{
    ChainReasoningEdge, ChainReasoningInput, ChainReasoningNode, CHAIN_REASONING_DEFAULT_MAX,
    CHAIN_REASONING_PROMPT_VERSION, NODE_KIND_ENTRY, NODE_KIND_FRAMEWORK, NODE_KIND_SINK,
};
use nyctos_types::event::{AgentEvent, EventSink, SandboxEvent};
use nyctos_types::novel::{
    FileForReview, NovelFindingDiscoveryInput, PriorFinding, DEFAULT_FILES_PER_BATCH,
    DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS, NOVEL_FINDING_DISCOVERY_PROMPT_VERSION,
};
use nyctos_types::payload::{
    AttackProvenance, PayloadSynthesisInput, PAYLOAD_SYNTHESIS_PROMPT_VERSION,
};
use nyctos_types::product::RouteModel;
use nyctos_types::project::ProjectAuthProfile;
use nyctos_types::spec::{SpecDerivationInput, SPEC_DERIVATION_PROMPT_VERSION};
use nyctos_types::verify::{Oracle, VerifyResult, VerifyVerdict};
use tokio::sync::Semaphore;

use crate::{live_planning, pentest_tools, route_model};

// Per-call PayloadSynthesis / SpecDerivation caps now live on
// `AiConfig` as
// `[ai] payload_synthesis_per_call_cap_usd_micros` /
// `[ai] spec_derivation_per_call_cap_usd_micros`. The tracker-side
// cap (resolved per-run from `[ai] default_run_budget_usd_micros`,
// falling back to `AiConfig::DEFAULT_RUN_BUDGET_USD_MICROS`) is the
// authoritative bucket the adapter checks against; the per-call
// value is informational on the wire and bounds a single call below
// the run cap when the operator wants tighter clamps.

/// Radius (in lines) of each excerpt the SpecDerivation prompt
/// receives. The vendored `HarnessSpec` only needs a few lines around
/// the call site, sink, and framework binding; a wide window would
/// blow the prompt budget without adding useful signal.
const SPEC_DERIVATION_EXCERPT_RADIUS: u32 = 4;

/// Maximum upstream files the SpecDerivation pre-fetch attaches to a
/// prompt. Capped at three relevant files (call site, sink, framework
/// binding) so the prompt envelope stays bounded.
const SPEC_DERIVATION_MAX_EXCERPTS: usize = 3;

const LIVE_TEST_PLAN_PROMPT_VERSION: &str = "phase24.live_test_plan.v1";
const LIVE_TEST_PLAN_EXCERPT_RADIUS: u32 = 18;
const EXPLORATION_KNOWN_LEADS_MAX: usize = 24;

/// `BudgetTracker` impl backed by the SQLite `budgets` table.
///
/// `(run_id, kind)` rows are inserted lazily on first observation so
/// callers do not have to pre-seed them. The lazy init goes through
/// `BudgetStore::ensure_default` (`INSERT OR IGNORE`), which is a
/// single SQL statement so concurrent fan-out tasks cannot clobber a
/// peer's `spent_usd_micros`. Subsequent `add_spend` calls take the
/// `UPDATE ... RETURNING` fast path inside `BudgetStore::add_spend`.
pub struct BudgetStoreTracker {
    store: Store,
    default_cap_usd_micros: i64,
}

impl BudgetStoreTracker {
    pub fn new(store: Store, default_cap_usd_micros: i64) -> Self {
        Self { store, default_cap_usd_micros }
    }

    fn kind_str(kind: BudgetKind) -> &'static str {
        match kind {
            BudgetKind::OneShot => "OneShot",
            BudgetKind::AgentLoop => "AgentLoop",
            BudgetKind::Total => "Total",
        }
    }

    async fn ensure_row(&self, run_id: &str, kind: BudgetKind) -> Result<(), AiError> {
        self.store
            .budgets()
            .ensure_default(run_id, Self::kind_str(kind), self.default_cap_usd_micros)
            .await
            .map_err(store_err)
    }
}

fn store_err(e: nyctos_core::StoreError) -> AiError {
    AiError::BudgetTracker(format!("{e}"))
}

fn ai_error_should_halt_pass(err: &AiError) -> bool {
    matches!(
        err,
        AiError::BudgetExceeded { .. }
            | AiError::UpstreamRefused(_)
            | AiError::Transport(_)
            | AiError::AdapterUnavailable(_)
    )
}

/// Convert `[ai.pricing.<model>]` overrides from `AiConfig` into the
/// `HashMap<String, Pricing>` shape the Anthropic adapter consumes.
/// Operator-friendly per-million-token USD rates collapse to
/// micros-per-token via [`Pricing::from_per_mtok_usd`]. Returns an
/// empty map when the operator has not declared any overrides; the
/// adapter then falls back to its built-in pricing table.
fn pricing_overrides_from_config(config: &AiConfig) -> HashMap<String, Pricing> {
    config
        .pricing
        .iter()
        .map(|(model, override_)| {
            (
                model.clone(),
                Pricing::from_per_mtok_usd(
                    override_.input_per_mtok_usd,
                    override_.output_per_mtok_usd,
                    override_.cache_write_per_mtok_usd,
                    override_.cache_read_per_mtok_usd,
                ),
            )
        })
        .collect()
}

async fn selected_one_shot_runtime(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    default_cap_usd_micros: i64,
    pass_name: &str,
) -> anyhow::Result<Option<Arc<dyn AiRuntime>>> {
    let tracker: SharedBudgetTracker =
        Arc::new(BudgetStoreTracker::new(store.clone(), default_cap_usd_micros));
    match config.runtime {
        ConfigAiRuntime::None => Ok(None),
        ConfigAiRuntime::LocalLlm => {
            tracing::info!(
                pass = pass_name,
                "selected local-llm runtime does not support one-shot tasks yet; skipping"
            );
            Ok(None)
        }
        ConfigAiRuntime::Anthropic => {
            let api_key = match secrets.get(nyctos_core::secrets::ACCOUNT_AI_ANTHROPIC) {
                Ok(Some(k)) => k,
                Ok(None) => {
                    tracing::info!(
                        pass = pass_name,
                        "selected Anthropic runtime has no API key configured; skipping"
                    );
                    return Ok(None);
                }
                Err(e) => return Err(anyhow::anyhow!("secret store error: {e}")),
            };
            let mut adapter = AnthropicSdkAdapter::new(api_key, tracker)
                .with_pricing_overrides(pricing_overrides_from_config(config));
            if let Some(model) = &config.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Ok(Some(Arc::new(adapter)))
        }
        ConfigAiRuntime::ClaudeCode => {
            let mut adapter = match ClaudeCodeAdapter::discover(tracker).await {
                Ok(a) => a,
                Err(err) => {
                    tracing::info!(
                        pass = pass_name,
                        "selected Claude Code runtime unavailable ({err}); skipping"
                    );
                    return Ok(None);
                }
            };
            if let Some(model) = &config.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Ok(Some(Arc::new(adapter)))
        }
        ConfigAiRuntime::Codex => {
            let mut adapter = match CodexCliAdapter::discover(tracker).await {
                Ok(a) => a,
                Err(err) => {
                    tracing::info!(
                        pass = pass_name,
                        "selected Codex runtime unavailable ({err}); skipping"
                    );
                    return Ok(None);
                }
            };
            if let Some(model) = &config.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Ok(Some(Arc::new(adapter)))
        }
    }
}

async fn selected_agent_loop_runtime(
    config: &AiConfig,
    store: &Store,
    run_cap_usd_micros: i64,
) -> Option<Arc<dyn AiRuntime>> {
    let tracker: SharedBudgetTracker =
        Arc::new(BudgetStoreTracker::new(store.clone(), run_cap_usd_micros));
    match config.runtime {
        ConfigAiRuntime::ClaudeCode => {
            let mut adapter = match ClaudeCodeAdapter::discover(tracker).await {
                Ok(a) => a,
                Err(err) => {
                    tracing::info!(
                        "ai exploration: selected Claude Code runtime unavailable ({err}); skipping pass"
                    );
                    return None;
                }
            };
            if let Some(model) = &config.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Some(Arc::new(adapter))
        }
        ConfigAiRuntime::Codex => {
            let mut adapter = match CodexCliAdapter::discover(tracker).await {
                Ok(a) => a,
                Err(err) => {
                    tracing::info!(
                        "ai exploration: selected Codex runtime unavailable ({err}); skipping pass"
                    );
                    return None;
                }
            };
            if let Some(model) = &config.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Some(Arc::new(adapter))
        }
        ConfigAiRuntime::Anthropic => {
            tracing::info!(
                "ai exploration: selected Anthropic API runtime does not support agent exploration; skipping pass"
            );
            None
        }
        ConfigAiRuntime::None | ConfigAiRuntime::LocalLlm => None,
    }
}

#[async_trait]
impl BudgetTracker for BudgetStoreTracker {
    async fn cap(&self, run_id: &str, kind: BudgetKind) -> Result<Option<i64>, AiError> {
        self.ensure_row(run_id, kind).await?;
        let row =
            self.store.budgets().get(run_id, Self::kind_str(kind)).await.map_err(store_err)?;
        Ok(row.map(|r| r.cap_usd_micros))
    }

    async fn current_spend(&self, run_id: &str, kind: BudgetKind) -> Result<i64, AiError> {
        self.ensure_row(run_id, kind).await?;
        let row =
            self.store.budgets().get(run_id, Self::kind_str(kind)).await.map_err(store_err)?;
        Ok(row.map(|r| r.spent_usd_micros).unwrap_or(0))
    }

    async fn add_spend(&self, run_id: &str, kind: BudgetKind, micros: i64) -> Result<i64, AiError> {
        self.ensure_row(run_id, kind).await?;
        self.store
            .budgets()
            .add_spend(run_id, Self::kind_str(kind), micros)
            .await
            .map_err(store_err)
    }
}

/// Counts surfaced by [`run_payload_synthesis_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PayloadSynthesisPassReport {
    pub synthesised: u32,
    pub quarantined: u32,
    pub failed: u32,
    pub total_attempts: u64,
    pub spend_usd_micros: i64,
}

/// Fan-out PayloadSynthesis across every `Unsupported(NoPayloadsForCap)`
/// finding in `bundle`. No-op (returns a default report) when the
/// selected runtime does not support one-shot tasks or is unavailable.
pub async fn run_payload_synthesis_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<PayloadSynthesisPassReport> {
    let inputs = build_inputs(bundle, workspaces);
    if inputs.is_empty() {
        return Ok(PayloadSynthesisPassReport::default());
    }
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "payload synthesis",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(PayloadSynthesisPassReport::default()),
    };
    tracing::info!(count = inputs.len(), "payload synthesis: fanning out");

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_one_shot_resolved()));
    let per_call_cap = config.payload_synthesis_per_call_cap_usd_micros_resolved();
    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();
    let mut handles = Vec::with_capacity(inputs.len());
    for input in inputs {
        let rt = Arc::clone(&adapter);
        let sem = Arc::clone(&semaphore);
        let sink = events.clone();
        handles.push(tokio::spawn(async move {
            let permit = sem.acquire_owned().await.expect("semaphore closed");
            let started_at = now_epoch_ms();
            let outcome = run_payload_synthesis(rt.as_ref(), &input, sink, per_call_cap).await;
            drop(permit);
            outcome.map(|o| (started_at, o))
        }));
    }

    let mut report = PayloadSynthesisPassReport::default();
    for handle in handles {
        match handle.await {
            Ok(Ok((started_at, outcome))) => {
                apply_outcome(store, outcome, &mut report, runtime_name, &runtime_model, started_at)
                    .await?
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "payload synthesis call failed");
                report.failed += 1;
            }
            Err(join) => {
                tracing::warn!(error = %join, "payload synthesis task join error");
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

/// Walk `bundle` + `workspaces` and turn each `Unsupported(NoPayloadsForCap)`
/// diag into a `PayloadSynthesisInput`. Public to keep the inner
/// filter unit-testable without spinning up an adapter.
pub fn build_inputs(
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> Vec<PayloadSynthesisInput> {
    let mut out = Vec::new();
    for repo_bundle in &bundle.per_repo {
        let RepoOutcome::Success(diags) = &repo_bundle.outcome else {
            continue;
        };
        let Some(workspace) = workspaces.get(&repo_bundle.repo) else {
            continue;
        };
        for diag in diags {
            if !diag.is_unsupported_no_payloads() {
                continue;
            }
            let line = i64::from(diag.line);
            let finding_id = nyctos_core::store::finding_id_hash(
                &repo_bundle.repo,
                &diag.path,
                Some(line),
                &diag.cap,
                &diag.rule,
            );
            let lang = infer_lang_for_file(workspace.workspace(), &diag.path);
            let sink_ctx = diag.sink_ctx(workspace.workspace());
            out.push(PayloadSynthesisInput {
                finding_id,
                run_id: bundle.run_id.clone(),
                cap: diag.cap.clone(),
                lang,
                sink_ctx,
            });
        }
    }
    out
}

async fn apply_outcome(
    store: &Store,
    outcome: PayloadSynthesisOutcome,
    report: &mut PayloadSynthesisPassReport,
    runtime_name: &str,
    runtime_model: &str,
    started_at_ms: i64,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    match outcome {
        PayloadSynthesisOutcome::Synthesised {
            finding_id,
            cap,
            lang,
            output,
            prompt_version,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            let provenance = AttackProvenance::LlmSynthesised.as_str().to_string();
            let rec = PayloadRecord {
                id: format!("payload-{finding_id}-{finished_at:x}-{}", short_token()),
                finding_id: finding_id.clone(),
                cap,
                lang,
                vuln_bytes: output.vuln_payload.into_bytes(),
                benign_bytes: Some(output.benign_payload.into_bytes()),
                oracle_blob: Some(output.vuln_oracle),
                attack_provenance: Some(provenance.clone()),
                prompt_version: Some(prompt_version.clone()),
                created_at: finished_at,
            };
            // Atomic dual-write so a partial failure of the finding
            // stamp does not leave an orphaned payload row behind.
            store
                .payloads()
                .insert_with_finding_provenance(&rec, &finding_id, &provenance, &prompt_version)
                .await?;
            let trace = build_trace_row(
                TaskKind::PayloadSynthesis,
                Some(finding_id),
                runtime_name,
                runtime_model,
                &prompt_version,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.synthesised += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
        PayloadSynthesisOutcome::Quarantined {
            finding_id,
            reason,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            let blob = serde_json::json!({
                "kind": "PayloadSynthesisQuarantined",
                "task": "PayloadSynthesis",
                "reason": reason,
            })
            .to_string();
            store.findings().quarantine(&finding_id, &blob).await?;
            let trace = build_trace_row(
                TaskKind::PayloadSynthesis,
                Some(finding_id),
                runtime_name,
                runtime_model,
                PAYLOAD_SYNTHESIS_PROMPT_VERSION,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.quarantined += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
    }
    Ok(())
}

/// Map a source path to a language tag the prompt can quote. Keeps the
/// table small (PayloadSynthesis only ships for the languages nyx
/// already supports); unknown extensions land as `unknown`.
pub fn infer_lang(path: &str) -> String {
    let lower = path.to_lowercase();
    let basename = lower.rsplit_once('/').map(|(_, b)| b).unwrap_or(&lower);
    let ext = basename.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    let lang = match ext {
        "py" => "python",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "go" => "go",
        "rs" => "rust",
        "java" => "java",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" => "cpp",
        _ => "unknown",
    };
    lang.to_string()
}

/// Per-file language inference that prefers the extension table but falls
/// back to a shebang lookup when the file has no recognised extension.
/// Handles the bin/foo + `#!/usr/bin/env python3` case the bare
/// [`infer_lang`] cannot reach. Reads at most the first 256 bytes from
/// disk; unreadable / non-existent files degrade to the extension result.
pub fn infer_lang_for_file(workspace_root: &std::path::Path, rel_path: &str) -> String {
    let from_ext = infer_lang(rel_path);
    if from_ext != "unknown" {
        return from_ext;
    }
    let basename = rel_path.rsplit_once('/').map(|(_, b)| b).unwrap_or(rel_path);
    if basename.contains('.') {
        return from_ext;
    }
    let mut buf = [0_u8; 256];
    let abs = workspace_root.join(rel_path);
    let Ok(mut file) = std::fs::File::open(&abs) else {
        return from_ext;
    };
    use std::io::Read;
    let Ok(read) = file.read(&mut buf) else {
        return from_ext;
    };
    if read < 2 || &buf[..2] != b"#!" {
        return from_ext;
    }
    let line_end = buf[..read].iter().position(|&b| b == b'\n').unwrap_or(read);
    let line = String::from_utf8_lossy(&buf[..line_end]);
    lang_from_shebang(&line).unwrap_or(from_ext)
}

/// Parse a shebang line (without the trailing newline) into one of the
/// language tokens [`infer_lang`] can also return. Returns `None` when
/// the interpreter name is unrecognised. Handles three common shapes:
///   * `#!/usr/bin/python3 ...`         → basename of the first token
///   * `#!/usr/bin/env python3 ...`     → first non-flag token after `env`
///   * `#!/usr/bin/perl -w`             → ignore trailing flags
fn lang_from_shebang(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let trimmed = lower.trim_start_matches("#!").trim_start();
    let mut tokens = trimmed.split_whitespace();
    let first = tokens.next()?;
    let first_leaf = first.rsplit('/').next().unwrap_or(first);
    let leaf = if first_leaf == "env" {
        tokens.find(|tok| !tok.starts_with('-')).map(|tok| tok.rsplit('/').next().unwrap_or(tok))?
    } else {
        first_leaf
    };
    let lang = if leaf.starts_with("python") {
        "python"
    } else if leaf == "node" || leaf == "nodejs" {
        "javascript"
    } else if leaf == "deno" {
        "typescript"
    } else if leaf == "ruby" {
        "ruby"
    } else if leaf == "php" {
        "php"
    } else if leaf == "perl" {
        "perl"
    } else {
        return None;
    };
    Some(lang.to_string())
}

/// Process-local sequence number so two trace rows minted in the same
/// millisecond produce distinct ids. Reset per process; the resulting
/// id is `trace-<task_kind>-<finished_ms hex>-<seq hex>`.
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a fresh `AgentTraceRecord` describing one AI task call.
///
/// `metrics` carries the per-call `TokenUsage` + `CacheStats` + model
/// each task's `*Outcome` envelope lifted out of the underlying
/// `Response` / `AgentResult`. Pass `None` for deterministic callers
/// (e.g. the payload verifier) that have no AI metrics to record.
#[allow(clippy::too_many_arguments)]
fn build_trace_row(
    task_kind: TaskKind,
    finding_id: Option<String>,
    runtime_name: &str,
    model: &str,
    prompt_version: &str,
    spent_usd_micros: i64,
    started_at_ms: i64,
    finished_at_ms: i64,
    metrics: Option<&AgentTraceMetrics>,
) -> AgentTraceRecord {
    let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    let id = format!("trace-{}-{:x}-{:08x}", task_kind.as_str(), finished_at_ms, seq);
    let duration = (finished_at_ms - started_at_ms).max(0);
    let (tokens_in, tokens_out, cache_hits, cache_misses, resolved_model) = match metrics {
        Some(m) => {
            let cache = m.cache.unwrap_or_default();
            let model_str = m.model.clone().unwrap_or_else(|| model.to_string());
            (
                i64::from(m.usage.input_tokens),
                i64::from(m.usage.output_tokens),
                i64::from(cache.cache_read_tokens),
                i64::from(cache.cache_creation_tokens),
                model_str,
            )
        }
        None => (0, 0, 0, 0, model.to_string()),
    };
    AgentTraceRecord {
        id,
        finding_id,
        task_kind: task_kind.as_str().to_string(),
        runtime_name: runtime_name.to_string(),
        model: resolved_model,
        prompt_version: Some(prompt_version.to_string()),
        conversation_jsonl_path: None,
        tokens_in,
        tokens_out,
        cost_usd_micros: spent_usd_micros,
        cache_hits,
        cache_misses,
        duration_ms: Some(duration),
        started_at: started_at_ms,
        finished_at: Some(finished_at_ms),
        verifier_blob: None,
    }
}

async fn persist_trace_row(store: &Store, row: AgentTraceRecord) {
    let task_kind = row.task_kind.clone();
    let finding_id = row.finding_id.clone();
    if let Err(err) = store.agent_traces().insert(&row).await {
        tracing::warn!(
            error = %err,
            task_kind = %task_kind,
            finding_id = ?finding_id,
            "failed to persist agent trace row"
        );
    }
}

/// Counts surfaced by [`run_live_test_plan_synthesis_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LiveTestPlanSynthesisPassReport {
    pub candidates_seen: u32,
    pub planned: u32,
    pub no_plan: u32,
    pub failed: u32,
    pub attempts: u32,
    pub spend_usd_micros: i64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttackPlanningPassReport {
    pub candidates_seen: u32,
    pub candidates_planned: u32,
    pub skipped: u32,
    pub failed: u32,
    pub attempts: u32,
    pub spend_usd_micros: i64,
    pub plan_context: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_attack_planning_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    route_model: &RouteModel,
    auth_profiles: &[ProjectAuthProfile],
    target_urls: &[String],
    events: EventSink,
) -> anyhow::Result<AttackPlanningPassReport> {
    let candidates = store.pentest_candidates().list_by_run(&bundle.run_id).await?;
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|c| matches!(c.status.as_str(), "Proposed" | "NeedsLiveTest"))
        .collect();
    let mut report = AttackPlanningPassReport {
        candidates_seen: candidates.len() as u32,
        ..AttackPlanningPassReport::default()
    };
    if candidates.is_empty() {
        return Ok(report);
    }
    if target_urls.is_empty() {
        report.skipped = candidates.len() as u32;
        report.plan_context = Some("attack planning skipped: no live target URL".to_string());
        return Ok(report);
    }
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "attack planning",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => {
            report.skipped = candidates.len() as u32;
            report.plan_context =
                Some("attack planning skipped: no configured one-shot AI runtime".to_string());
            return Ok(report);
        }
    };

    let started_at = now_epoch_ms();
    let prompt = build_attack_planning_prompt(
        &candidates,
        workspaces,
        route_model,
        auth_profiles,
        target_urls,
    );
    let budget = Budget {
        run_id: bundle.run_id.clone(),
        kind: BudgetKind::OneShot,
        cap_usd_micros: config.default_run_budget_usd_micros_resolved(),
    };
    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();
    let resp = match adapter.one_shot(prompt, budget, events).await {
        Ok(resp) => resp,
        Err(err) => {
            report.failed = candidates.len() as u32;
            if matches!(err, AiError::BudgetExceeded { .. }) {
                report.plan_context =
                    Some("attack planning halted: AI budget exhausted".to_string());
                return Ok(report);
            }
            return Err(anyhow::anyhow!(err.to_string()));
        }
    };
    let finished_at = now_epoch_ms();
    report.attempts = 1;
    report.spend_usd_micros = resp.cost_usd_micros;
    report.candidates_planned = candidates.len() as u32;
    report.plan_context = Some(compact_attack_plan_context(&resp.content));

    let metrics = AgentTraceMetrics::from_response(&resp);
    let mut trace = build_trace_row(
        TaskKind::AttackPlanning,
        None,
        runtime_name,
        &runtime_model,
        &resp.prompt_version,
        resp.cost_usd_micros,
        started_at,
        finished_at,
        Some(&metrics),
    );
    trace.verifier_blob = Some(
        serde_json::json!({
            "kind": "attack_plan",
            "run_id": &bundle.run_id,
            "project_id": &bundle.project_id,
            "content": resp.content,
        })
        .to_string(),
    );
    persist_trace_row(store, trace).await;
    Ok(report)
}

fn build_attack_planning_prompt(
    candidates: &[PentestCandidateRecord],
    workspaces: &HashMap<String, WorkspaceHandle>,
    route_model: &RouteModel,
    auth_profiles: &[ProjectAuthProfile],
    target_urls: &[String],
) -> Prompt {
    let targets = target_urls.iter().map(|u| format!("- {u}")).collect::<Vec<_>>().join("\n");
    let routes = route_model::compact_route_model_for_prompt(route_model, 80);
    let auth = pentest_tools::auth_profiles_summary(auth_profiles);
    let candidates_json = serde_json::to_string_pretty(
        &candidates
            .iter()
            .take(30)
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "source": c.source,
                    "source_ids": c.source_ids,
                    "title": c.title,
                    "class": c.vuln_class,
                    "severity": c.severity_guess,
                    "status": c.status,
                    "confidence": c.confidence,
                    "hypothesis": c.hypothesis,
                    "affected_components": c.affected_components,
                    "source_excerpt": candidate_source_excerpt(c, workspaces).map(|ex| serde_json::json!({
                        "path": ex.path,
                        "line": ex.line,
                        "kind": ex.kind,
                        "body": ex.body,
                    })),
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string());
    let system = r#"You are Nyctos's senior pentest planner. Produce a ranked, safe attack plan for authorized testing of the operator's local application.

Return exactly one JSON object and no Markdown. Do not claim a vulnerability is verified. For each hypothesis, specify the deterministic evidence the verifier must collect and the rejecting evidence that would disprove it. Prefer harmless probes. Mark destructive or aggressive probes clearly so Nyctos can block them unless explicitly enabled."#
        .to_string();
    let user = format!(
        "TARGET BASE URLS\n{targets}\n\nAUTH PROFILES\n{auth}\n\nROUTE MODEL\n{routes}\n\nCANDIDATES\n{candidates_json}\n\nRequired JSON shape:\n{{\"threat_model_summary\":\"...\",\"top_hypotheses\":[{{\"candidate_id\":\"...\",\"rank\":1,\"mapped_routes\":[\"GET /api/...\"],\"needed_auth_roles\":[\"anonymous\"],\"safest_probe\":\"...\",\"fallback_probe\":\"...\",\"destructiveness\":\"safe|state-changing|aggressive\",\"expected_confirming_evidence\":\"...\",\"expected_rejecting_evidence\":\"...\"}}]}}\n"
    );
    Prompt {
        prompt_version: "phase-live.attack-planning.v1".to_string(),
        task_id: format!("attack-plan-{}", short_candidate_id(&candidates[0].run_id)),
        model: None,
        system,
        user,
        max_output_tokens: 3000,
        temperature: 0.0,
        seed: None,
    }
}

fn compact_attack_plan_context(raw: &str) -> String {
    let compact =
        raw.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
    compact.chars().take(4_000).collect()
}

/// Convert static `PentestCandidate` rows into executable HTTP plans
/// before the live verifier runs. This is the missing bridge between
/// Nyx's source signal and the local dev site: the verifier deliberately
/// refuses to guess at routes unless an AI pass has turned source context
/// into method/url/body/oracle JSON.
pub async fn run_live_test_plan_synthesis_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    target_urls: &[String],
    route_model: Option<&RouteModel>,
    auth_profiles: &[ProjectAuthProfile],
    browser_checks_enabled: bool,
    allow_state_changing: bool,
    attack_plan_context: Option<&str>,
    events: EventSink,
) -> anyhow::Result<LiveTestPlanSynthesisPassReport> {
    let mut report = LiveTestPlanSynthesisPassReport::default();
    if target_urls.is_empty() {
        return Ok(report);
    }

    let candidates = store.pentest_candidates().list_by_run(&bundle.run_id).await?;
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|c| matches!(c.status.as_str(), "Proposed" | "NeedsLiveTest"))
        .filter(|c| !candidate_has_executable_live_plan(c, target_urls, browser_checks_enabled))
        .collect();
    if candidates.is_empty() {
        return Ok(report);
    }
    report.candidates_seen = candidates.len() as u32;

    let synthesizer =
        live_planning::LiveTestPlanSynthesizer::new(live_planning::LiveTestPlanSynthesisContext {
            route_model,
            target_urls,
            auth_profiles,
            browser_checks_enabled,
            allow_state_changing,
        });
    let mut ai_candidates = Vec::new();
    for candidate in candidates {
        let plan = synthesizer.synthesize(&candidate);
        let finished_at = now_epoch_ms();
        match plan {
            nyctos_types::live_plan::LiveTestPlan::NoPlan(no_plan) => {
                let reason = no_plan.no_plan_reason.message.clone();
                let plan_blob =
                    serde_json::to_string(&nyctos_types::live_plan::LiveTestPlan::NoPlan(no_plan))?;
                store
                    .pentest_candidates()
                    .set_test_plan(&candidate.id, &plan_blob, "NeedsReview", None, finished_at)
                    .await?;
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "NeedsReview", Some(&reason), finished_at)
                    .await?;
                report.no_plan += 1;
            }
            executable => {
                let plan_blob = serde_json::to_string(&executable)?;
                match normalise_live_test_plan(&plan_blob, target_urls) {
                    Ok(Some(_)) => {
                        store
                            .pentest_candidates()
                            .set_test_plan(&candidate.id, &plan_blob, "Proposed", None, finished_at)
                            .await?;
                        report.planned += 1;
                    }
                    Ok(None) => {
                        ai_candidates.push(candidate);
                    }
                    Err(err) => {
                        tracing::warn!(
                            candidate_id = %candidate.id,
                            error = %err,
                            "deterministic live test plan synthesis produced unusable plan"
                        );
                        ai_candidates.push(candidate);
                    }
                }
            }
        }
    }
    let candidates = ai_candidates;
    if candidates.is_empty() {
        return Ok(report);
    }

    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "live test plan synthesis",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(report),
    };

    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();
    for candidate in candidates {
        let started_at = now_epoch_ms();
        let prompt = build_live_test_plan_prompt(
            &candidate,
            workspaces,
            target_urls,
            route_model,
            auth_profiles,
            browser_checks_enabled,
            allow_state_changing,
            attack_plan_context,
        );
        let budget = Budget {
            run_id: bundle.run_id.clone(),
            kind: BudgetKind::OneShot,
            cap_usd_micros: config.default_run_budget_usd_micros_resolved(),
        };
        let resp = match adapter.one_shot(prompt, budget, events.clone()).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(
                    candidate_id = %candidate.id,
                    error = %err,
                    "live test plan synthesis call failed"
                );
                report.failed += 1;
                if ai_error_should_halt_pass(&err) {
                    break;
                }
                continue;
            }
        };
        let finished_at = now_epoch_ms();
        report.attempts += 1;
        report.spend_usd_micros += resp.cost_usd_micros;
        let metrics = AgentTraceMetrics::from_response(&resp);
        let trace = build_trace_row(
            TaskKind::LiveTestPlan,
            None,
            runtime_name,
            &runtime_model,
            &resp.prompt_version,
            resp.cost_usd_micros,
            started_at,
            finished_at,
            Some(&metrics),
        );
        let trace_id = trace.id.clone();
        persist_trace_row(store, trace).await;

        match normalise_live_test_plan(&resp.content, target_urls) {
            Ok(Some(plan)) => {
                let plan_blob = serde_json::to_string(&plan)?;
                store
                    .pentest_candidates()
                    .set_test_plan(
                        &candidate.id,
                        &plan_blob,
                        "Proposed",
                        Some(&trace_id),
                        finished_at,
                    )
                    .await?;
                report.planned += 1;
            }
            Ok(None) => {
                report.no_plan += 1;
            }
            Err(err) => {
                tracing::warn!(
                    candidate_id = %candidate.id,
                    error = %err,
                    response = %resp.content,
                    "live test plan synthesis returned an unusable plan"
                );
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

fn build_live_test_plan_prompt(
    candidate: &PentestCandidateRecord,
    workspaces: &HashMap<String, WorkspaceHandle>,
    target_urls: &[String],
    route_model: Option<&RouteModel>,
    auth_profiles: &[ProjectAuthProfile],
    browser_checks_enabled: bool,
    allow_state_changing: bool,
    attack_plan_context: Option<&str>,
) -> Prompt {
    let excerpt = candidate_source_excerpt(candidate, workspaces)
        .map(|ex| {
            format!(
                "path: {path}\nline: {line}\nkind: {kind}\n```\n{body}```",
                path = ex.path,
                line = ex.line.map(|l| l.to_string()).unwrap_or_else(|| "unknown".to_string()),
                kind = ex.kind,
                body = ex.body,
            )
        })
        .unwrap_or_else(|| {
            "source excerpt unavailable; infer only from candidate metadata".to_string()
        });
    let components = serde_json::to_string_pretty(&candidate.affected_components)
        .unwrap_or_else(|_| "[]".to_string());
    let source_ids = serde_json::to_string_pretty(&candidate.source_ids).unwrap_or_default();
    let targets = target_urls.iter().map(|u| format!("- {u}")).collect::<Vec<_>>().join("\n");
    let routes = route_model
        .map(|m| route_model::compact_route_model_for_prompt(m, 40))
        .unwrap_or_else(|| "route model unavailable".to_string());
    let auth = pentest_tools::auth_profiles_summary(auth_profiles);
    let browser = if browser_checks_enabled {
        "enabled"
    } else {
        "disabled; return no_plan_reason for browser-only/client-side-only candidates"
    };
    let state_changing = if allow_state_changing {
        "state-changing probes are explicitly allowed by run policy"
    } else {
        "state-changing probes are not allowed; return no_plan_reason for mutation-only verification"
    };
    let attack_plan =
        attack_plan_context.unwrap_or("no prior attack-planning trace available for this run");
    let system = r#"You are Nyctos's live-test-plan synthesizer. Work like a senior application security tester converting a static signal into one safe, executable HTTP verification plan for a local development app.

Return exactly one JSON object and no Markdown. Prefer harmless probes that demonstrate reachability, authorization bypass, reflection, unsafe redirect, exposed data, or other vulnerability-specific evidence without destroying data. Use only the supplied target base URLs.

Nyctos can execute these deterministic tools in the verifier: http.request and auth.login_as(role) through configured header/cookie/token injection. Browser plans are allowed only when the operator enables browser verification and Playwright is installed, so prefer HTTP unless the source is clearly client-side.

The oracle you return must be a confirming oracle: if all predicates pass, the candidate should be vulnerable. Do not encode rejecting/safety evidence as success. A 401/403/404 response, escaped output, no reflection, or absence of sensitive data is rejecting evidence; return {"no_plan_reason":"..."} when that is the only safe probe.

Do not fetch static source assets such as .js/.css/.map files to prove a sink string exists. A served bundle or source snippet is not live exploit evidence. For client-side-only DOM issues, return a browser plan only when a real browser workflow can exercise attacker-controlled input; otherwise return {"no_plan_reason":"..."}.

If you cannot derive a meaningful exploit-confirming live test from the source context, return {"no_plan_reason":"..."}.

Executable plan schema:
{
  "kind": "http",
  "method": "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS",
  "url": "absolute URL under one supplied target base URL",
  "path": "optional path, useful for audit only",
  "headers": {"Header": "value"},
  "body": "optional raw request body",
  "json": {"optional": "JSON request body"},
  "expect_status": 200,
  "status_range": "2xx|3xx|4xx|5xx",
  "body_contains": "positive exploit marker or sensitive marker that must appear",
  "body_not_contains": "optional guard string or array; never the primary confirming evidence",
  "header_contains": {"Header": "substring"},
  "rationale": "brief reason this would confirm the candidate"
}

For authorization boundaries, prefer first-class authz plans when matching auth roles exist. Use role comparison for vertical checks (for example user vs admin on the same action):
{
  "kind": "authz_role_comparison",
  "hypothesis": "...",
  "allowed_role": "admin",
  "challenged_role": "user",
  "request": {"method": "GET", "path": "/api/admin/report"},
  "oracle": {
    "type": "role_comparison_break",
    "forbidden_status": [401,403,404],
    "positive_markers": ["admin report", "accountId"]
  }
}

Use object ownership for horizontal checks (for example user_b reading user_a's seeded object). Include a configured object id or seed and capture one before comparing owner vs accessor:
{
  "kind": "authz_object_ownership",
  "hypothesis": "...",
  "object": {"name": "project", "owner_role": "user_a", "id": "123", "positive_markers": ["nyctos-owned-project"]},
  "accessor_role": "user_b",
  "owner_request": {"method": "GET", "path": "/api/projects/123"},
  "accessor_request": {"method": "GET", "path": "/api/projects/123"},
  "oracle": {
    "type": "object_ownership_break",
    "forbidden_status": [401,403,404],
    "positive_markers": ["nyctos-owned-project", "123"]
  }
}

For client-side authorization checks where the role boundary only appears in the rendered app, compare the same browser workflow under two roles:
{
  "kind": "authz_browser_role_comparison",
  "hypothesis": "...",
  "allowed_role": "admin",
  "challenged_role": "user",
  "workflow": {
    "url": "/app/admin",
    "steps": [{"action": "wait_for_selector", "selector": "main"}],
    "oracle": {"text_contains": "Admin Console"}
  }
}

If you cannot provide positive role/object markers, use a legacy differential plan only for non-authz comparisons and expect it to be rejected as weak without sensitive_body_markers:
{
  "kind": "differential_http",
  "hypothesis": "...",
  "steps": [
    {"as": "user_a", "method": "GET", "path": "/api/accounts/123"},
    {"as": "user_b", "method": "GET", "path": "/api/accounts/123"}
  ],
  "oracle": {
    "type": "forbidden_equivalence_break",
    "expected_allowed_step": 0,
    "expected_forbidden_step": 1,
    "forbidden_status": [401,403,404],
    "sensitive_body_markers": ["email", "accountId"]
  }
}

For multi-step stateful bugs, use an HTTP workflow. Captures can extract response values and later steps can reference them as {{name}}:
{
  "kind": "http_workflow",
  "steps": [
    {"as": "user_a", "method": "POST", "path": "/api/projects", "json": {"name": "nyctos-probe"}, "captures": {"project_id": {"from": "json", "path": "id"}}},
    {"as": "user_b", "method": "GET", "path": "/api/projects/{{project_id}}"}
  ],
  "oracle": {"step": 1, "status_range": "2xx", "body_contains": "nyctos-probe"}
}

For client-side-only bugs, use a browser plan only when browser verification is enabled:
{
  "kind": "browser",
  "url": "/app/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
  "steps": [{"action": "wait_for_selector", "selector": "body"}],
  "oracle": {"alert_contains": "nyctos-probe"}
}

At least one positive live evidence oracle is required: body_contains/header_contains for HTTP, positive_markers for authz role/object probes, or text_contains/html_contains/selector_exists/selector_text_contains/url_contains/title_contains/console_contains/alert_contains for browser and authz browser probes. expect_status/status_range/body_not_contains may be included only as guards around that positive evidence. Do not return generic homepage checks, blocked-request checks, no-reflection checks, or static bundle/source checks."#
        .to_string();
    let user = format!(
        "TARGET BASE URLS\n{targets}\n\nAUTH PROFILES\n{auth}\n\nBROWSER VERIFICATION\n{browser}\n\nSTATE-CHANGING POLICY\n{state_changing}\n\nROUTE MODEL\n{routes}\n\nSENIOR ATTACK PLAN CONTEXT\n{attack_plan}\n\nCANDIDATE\nid: {id}\ntitle: {title}\nclass: {vuln_class}\nseverity: {severity}\nstatus: {status}\nhypothesis: {hypothesis}\nsource_ids: {source_ids}\naffected_components:\n{components}\n\nSOURCE EXCERPT\n{excerpt}\n",
        id = candidate.id,
        title = candidate.title,
        vuln_class = candidate.vuln_class,
        severity = candidate.severity_guess,
        status = candidate.status,
        hypothesis = candidate.hypothesis,
    );
    Prompt {
        prompt_version: LIVE_TEST_PLAN_PROMPT_VERSION.to_string(),
        task_id: format!("live-plan-{}", short_candidate_id(&candidate.id)),
        model: None,
        system,
        user,
        max_output_tokens: 1600,
        temperature: 0.0,
        seed: None,
    }
}

fn candidate_source_excerpt(
    candidate: &PentestCandidateRecord,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> Option<nyctos_types::spec::FileExcerpt> {
    for component in &candidate.affected_components {
        let Some(obj) = component.as_object() else {
            continue;
        };
        let Some(path) = obj.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let repo = obj.get("repo").and_then(|v| v.as_str());
        let Some(workspace) = repo.and_then(|r| workspaces.get(r)).or_else(|| {
            if workspaces.len() == 1 {
                workspaces.values().next()
            } else {
                None
            }
        }) else {
            continue;
        };
        let line = obj.get("line").and_then(|v| v.as_i64()).and_then(|v| {
            if v > 0 {
                Some(v as u32)
            } else {
                None
            }
        });
        if let Some(excerpt) = read_spec_excerpt(
            workspace.workspace(),
            path,
            line,
            "candidate",
            LIVE_TEST_PLAN_EXCERPT_RADIUS,
        ) {
            return Some(excerpt);
        }
    }
    None
}

fn candidate_has_executable_live_plan(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
    browser_checks_enabled: bool,
) -> bool {
    let Some(plan) = normalise_live_test_plan(&candidate.test_plan, target_urls).ok().flatten()
    else {
        return false;
    };
    let kind = plan.get("kind").and_then(|v| v.as_str()).unwrap_or("http");
    browser_checks_enabled || !matches!(kind, "browser" | "browser_workflow")
}

fn normalise_live_test_plan(
    raw: &str,
    target_urls: &[String],
) -> Result<Option<serde_json::Value>, String> {
    pentest_tools::normalise_live_test_plan(raw, target_urls)
}

fn short_candidate_id(id: &str) -> String {
    id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(48).collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn run_live_evidence_review_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    run_id: &str,
    candidate: &PentestCandidateRecord,
    proposed_plan: serde_json::Value,
    live_evidence: serde_json::Value,
    oracle_result: serde_json::Value,
    deterministic_review: LiveEvidenceReviewOutput,
    events: EventSink,
) -> anyhow::Result<Option<LiveEvidenceReviewOutput>> {
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "live evidence review",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(None),
    };
    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();
    let started_at = now_epoch_ms();
    let input = LiveEvidenceReviewInput {
        run_id: run_id.to_string(),
        candidate: candidate.clone(),
        proposed_plan,
        live_evidence,
        oracle_result,
        deterministic_review,
    };
    let outcome = run_live_evidence_review(
        adapter.as_ref(),
        &input,
        events,
        config.default_run_budget_usd_micros_resolved(),
    )
    .await?;
    let finished_at = now_epoch_ms();
    let review = outcome.output.clone();
    let mut trace = build_trace_row(
        TaskKind::LiveEvidenceReview,
        None,
        runtime_name,
        &runtime_model,
        &outcome.prompt_version,
        outcome.spent_usd_micros,
        started_at,
        finished_at,
        Some(&outcome.metrics),
    );
    trace.verifier_blob = Some(
        serde_json::json!({
            "kind": "LiveEvidenceReview",
            "run_id": run_id,
            "candidate_id": &candidate.id,
            "decision": review.decision.as_str(),
            "review": &review,
        })
        .to_string(),
    );
    persist_trace_row(store, trace).await;
    Ok(Some(review))
}

/// Counts surfaced by [`run_spec_derivation_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpecDerivationPassReport {
    pub synthesised: u32,
    pub quarantined: u32,
    pub failed: u32,
    pub total_attempts: u64,
    pub spend_usd_micros: i64,
}

/// Fan-out SpecDerivation across every `Inconclusive(SpecDerivationFailed)`
/// finding in `bundle`. No-op (returns a default report) when the
/// selected runtime does not support one-shot tasks or is unavailable.
pub async fn run_spec_derivation_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<SpecDerivationPassReport> {
    let inputs = build_spec_inputs(bundle, workspaces);
    if inputs.is_empty() {
        return Ok(SpecDerivationPassReport::default());
    }
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "spec derivation",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(SpecDerivationPassReport::default()),
    };
    tracing::info!(count = inputs.len(), "spec derivation: fanning out");

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_one_shot_resolved()));
    let per_call_cap = config.spec_derivation_per_call_cap_usd_micros_resolved();
    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();
    let mut handles = Vec::with_capacity(inputs.len());
    for input in inputs {
        let rt = Arc::clone(&adapter);
        let sem = Arc::clone(&semaphore);
        let sink = events.clone();
        handles.push(tokio::spawn(async move {
            let permit = sem.acquire_owned().await.expect("semaphore closed");
            let started_at = now_epoch_ms();
            let outcome = run_spec_derivation(rt.as_ref(), &input, sink, per_call_cap).await;
            drop(permit);
            outcome.map(|o| (started_at, o))
        }));
    }

    let mut report = SpecDerivationPassReport::default();
    for handle in handles {
        match handle.await {
            Ok(Ok((started_at, outcome))) => {
                apply_spec_outcome(
                    store,
                    outcome,
                    &mut report,
                    runtime_name,
                    &runtime_model,
                    started_at,
                )
                .await?
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "spec derivation call failed");
                report.failed += 1;
            }
            Err(join) => {
                tracing::warn!(error = %join, "spec derivation task join error");
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

/// Walk `bundle` + `workspaces` and turn each `Inconclusive(SpecDerivationFailed)`
/// diag into a `SpecDerivationInput` pre-populated with up to three
/// file excerpts (sink, call-site, framework). Public so the inner
/// filter + pre-fetch can be unit-tested without spinning up an
/// adapter.
pub fn build_spec_inputs(
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> Vec<SpecDerivationInput> {
    let mut out = Vec::new();
    for repo_bundle in &bundle.per_repo {
        let RepoOutcome::Success(diags) = &repo_bundle.outcome else {
            continue;
        };
        let Some(workspace) = workspaces.get(&repo_bundle.repo) else {
            continue;
        };
        for diag in diags {
            if !diag.is_spec_derivation_failed() {
                continue;
            }
            let line = i64::from(diag.line);
            let finding_id = nyctos_core::store::finding_id_hash(
                &repo_bundle.repo,
                &diag.path,
                Some(line),
                &diag.cap,
                &diag.rule,
            );
            let lang = infer_lang_for_file(workspace.workspace(), &diag.path);
            let sink_ctx = diag.sink_ctx(workspace.workspace());
            let excerpts = collect_spec_excerpts(workspace, diag, SPEC_DERIVATION_MAX_EXCERPTS);
            out.push(SpecDerivationInput {
                finding_id,
                run_id: bundle.run_id.clone(),
                cap: diag.cap.clone(),
                lang,
                callee: sink_ctx.callee,
                excerpts,
            });
        }
    }
    out
}

/// Pre-fetch up to `max` excerpts for SpecDerivation: the sink line
/// first, then each distinct flow-step file (labelled `call_site` for
/// the first hop and `framework` for subsequent ones). Excerpts that
/// cannot be read are silently skipped; the agent tolerates an empty
/// list and produces a `Quarantined` outcome if it cannot infer the
/// harness shape.
fn collect_spec_excerpts(
    workspace: &WorkspaceHandle,
    diag: &Diag,
    max: usize,
) -> Vec<nyctos_types::spec::FileExcerpt> {
    let mut out = Vec::new();
    if let Some(ex) = read_spec_excerpt(
        workspace.workspace(),
        &diag.path,
        Some(diag.line),
        "sink",
        SPEC_DERIVATION_EXCERPT_RADIUS,
    ) {
        out.push(ex);
    }
    let mut first_upstream = true;
    for path in diag.flow_step_files_ranked() {
        if out.len() >= max {
            break;
        }
        let kind = if first_upstream {
            first_upstream = false;
            "call_site"
        } else {
            "framework"
        };
        if let Some(ex) = read_spec_excerpt(
            workspace.workspace(),
            path,
            None,
            kind,
            SPEC_DERIVATION_EXCERPT_RADIUS,
        ) {
            out.push(ex);
        }
    }
    out
}

async fn apply_spec_outcome(
    store: &Store,
    outcome: SpecDerivationOutcome,
    report: &mut SpecDerivationPassReport,
    runtime_name: &str,
    runtime_model: &str,
    started_at_ms: i64,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    match outcome {
        SpecDerivationOutcome::Synthesised {
            finding_id,
            cap,
            lang,
            spec: _,
            spec_blob,
            prompt_version,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            let provenance = AttackProvenance::LlmSynthesised.as_str().to_string();
            let rec = HarnessSpecRecord {
                id: format!("spec-{finding_id}-{finished_at:x}-{}", short_token()),
                cap,
                lang,
                spec_blob,
                attack_provenance: Some(provenance.clone()),
                prompt_version: Some(prompt_version.clone()),
                created_at: finished_at,
            };
            // Atomic dual-write so a partial failure of the finding
            // back-link does not orphan the harness_specs row.
            store
                .harness_specs()
                .insert_with_finding_spec_link(&rec, &finding_id, &provenance, &prompt_version)
                .await?;
            let trace = build_trace_row(
                TaskKind::SpecDerivation,
                Some(finding_id),
                runtime_name,
                runtime_model,
                &prompt_version,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.synthesised += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
        SpecDerivationOutcome::Quarantined {
            finding_id,
            reason,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            let blob = serde_json::json!({
                "kind": "SpecDerivationQuarantined",
                "task": "SpecDerivation",
                "reason": reason,
            })
            .to_string();
            store.findings().quarantine(&finding_id, &blob).await?;
            let trace = build_trace_row(
                TaskKind::SpecDerivation,
                Some(finding_id),
                runtime_name,
                runtime_model,
                SPEC_DERIVATION_PROMPT_VERSION,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.quarantined += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
    }
    Ok(())
}

// Per-call ChainReasoning cap now lives on `AiConfig` as
// `[ai] chain_reasoning_per_call_cap_usd_micros`. Same shape as the
// PayloadSynthesis / SpecDerivation knobs.

/// Heuristic path fragments that mark a file as a vendored framework
/// binding. The ChainReasoning prompt tags nodes whose source path
/// matches any of these as `framework` so the model can recognise
/// glue code that is not under the operator's control.
const FRAMEWORK_PATH_FRAGMENTS: &[&str] = &[
    "site-packages/",
    "node_modules/",
    "vendor/",
    "/lib/",
    "/framework/",
    "/frameworks/",
    ".cargo/registry/",
    "_vendor/",
];

/// Counts surfaced by [`run_chain_reasoning_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChainReasoningPassReport {
    pub chains_persisted: u32,
    pub cross_repo_chains: u32,
    pub members_stamped: u32,
    pub spend_usd_micros: i64,
    pub attempts: u64,
    pub failed: u32,
}

/// Fan-out (single-call) ChainReasoning over the run's finding graph.
/// No-op (returns a default report) when the selected runtime does not
/// support one-shot tasks, is unavailable, or the bundle has fewer than
/// two findings.
pub async fn run_chain_reasoning_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<ChainReasoningPassReport> {
    let _ = workspaces; // workspaces unused: the graph is built from bundle metadata only.
    let input = match build_chain_input(bundle) {
        Some(i) => i,
        None => return Ok(ChainReasoningPassReport::default()),
    };
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        config.default_run_budget_usd_micros_resolved(),
        "chain reasoning",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(ChainReasoningPassReport::default()),
    };
    tracing::info!(
        nodes = input.nodes.len(),
        edges = input.edges.len(),
        repos = input.repos.len(),
        "chain reasoning: dispatching"
    );

    let runtime_name = adapter.name();
    let runtime_model = adapter.default_model().to_string();

    let started_at = now_epoch_ms();
    let outcome = match run_chain_reasoning(
        adapter.as_ref(),
        &input,
        events,
        config.chain_reasoning_per_call_cap_usd_micros_resolved(),
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            tracing::warn!(error = %err, "chain reasoning call failed");
            return Ok(ChainReasoningPassReport { failed: 1, ..Default::default() });
        }
    };

    let mut report = ChainReasoningPassReport::default();
    apply_chain_outcome(
        store,
        &input,
        outcome,
        &mut report,
        runtime_name,
        &runtime_model,
        started_at,
    )
    .await?;
    Ok(report)
}

/// Walk `bundle` and turn each diag into a `ChainReasoningNode`. Edges
/// are derived from `Diag::flow_steps`: each step inside a diag that
/// resolves to *another* diag's `(path, line)` produces a directed
/// `Reaches` edge, with `cross_repo = true` when the two diags live in
/// different repos. Public so the inner graph builder is unit-testable
/// without spinning up an adapter.
pub fn build_chain_input(bundle: &RunBundle<Diag>) -> Option<ChainReasoningInput> {
    // Collect every node + an index keyed by (repo, path, line) so flow
    // steps can resolve to a finding id without a quadratic scan.
    let mut nodes: Vec<ChainReasoningNode> = Vec::new();
    let mut by_location: HashMap<(String, String, u32), String> = HashMap::new();
    let mut repos: Vec<String> = Vec::new();
    for repo_bundle in &bundle.per_repo {
        if !repos.contains(&repo_bundle.repo) {
            repos.push(repo_bundle.repo.clone());
        }
        let RepoOutcome::Success(diags) = &repo_bundle.outcome else {
            continue;
        };
        for diag in diags {
            let id = nyctos_core::store::finding_id_hash(
                &repo_bundle.repo,
                &diag.path,
                Some(i64::from(diag.line)),
                &diag.cap,
                &diag.rule,
            );
            let kind = classify_node_kind(diag);
            by_location
                .insert((repo_bundle.repo.clone(), diag.path.clone(), diag.line), id.clone());
            nodes.push(ChainReasoningNode {
                id,
                repo: repo_bundle.repo.clone(),
                path: diag.path.clone(),
                line: Some(diag.line),
                cap: diag.cap.clone(),
                rule: diag.rule.clone(),
                severity: diag.severity.clone(),
                kind: kind.to_string(),
            });
        }
    }
    if nodes.len() < 2 {
        return None;
    }

    // Edges: per diag, walk its flow_steps; whenever a step lands on a
    // location that resolves to another known diag, link that diag to
    // the current diag. The edge direction goes "from upstream step ->
    // sink diag" so the model sees an entry-to-sink traversal.
    let mut edges: Vec<ChainReasoningEdge> = Vec::new();
    let mut edge_keys: HashSet<(String, String)> = HashSet::new();
    for repo_bundle in &bundle.per_repo {
        let RepoOutcome::Success(diags) = &repo_bundle.outcome else {
            continue;
        };
        for diag in diags {
            let sink_id =
                match by_location.get(&(repo_bundle.repo.clone(), diag.path.clone(), diag.line)) {
                    Some(id) => id.clone(),
                    None => continue,
                };
            // Walk every step; match by (repo, path, line) first, then
            // by (any repo, path, line) so a cross-repo step finds the
            // diag whose path matches even when the step itself does
            // not name a repo.
            for step in &diag.flow_steps {
                let same_repo_key = (repo_bundle.repo.clone(), step.path.clone(), step.line);
                if let Some(from_id) = by_location.get(&same_repo_key) {
                    push_edge(&mut edges, &mut edge_keys, from_id, &sink_id, false);
                    continue;
                }
                // Cross-repo: scan for any other repo whose diag
                // matches (path, line).
                for (other_repo, _, _) in by_location
                    .keys()
                    .filter(|(r, p, l)| {
                        r != &repo_bundle.repo && p == &step.path && *l == step.line
                    })
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    let key = (other_repo, step.path.clone(), step.line);
                    if let Some(from_id) = by_location.get(&key) {
                        push_edge(&mut edges, &mut edge_keys, from_id, &sink_id, true);
                    }
                }
            }
        }
    }

    Some(ChainReasoningInput {
        run_id: bundle.run_id.clone(),
        repos,
        nodes,
        edges,
        max_chains: CHAIN_REASONING_DEFAULT_MAX,
    })
}

fn push_edge(
    edges: &mut Vec<ChainReasoningEdge>,
    keys: &mut HashSet<(String, String)>,
    from: &str,
    to: &str,
    cross_repo: bool,
) {
    if from == to {
        return;
    }
    let key = (from.to_string(), to.to_string());
    if keys.insert(key) {
        edges.push(ChainReasoningEdge {
            from: from.to_string(),
            to: to.to_string(),
            label: "Reaches".to_string(),
            cross_repo,
        });
    }
}

/// Coarse role tag for a node. The static pass's flow_steps drive the
/// `entry` decision; framework detection is a path-fragment heuristic;
/// every remaining diag is a `sink`. The classification is advisory
/// for the prompt; the model is free to override.
fn classify_node_kind(diag: &Diag) -> &'static str {
    let lower = diag.path.to_lowercase();
    if FRAMEWORK_PATH_FRAGMENTS.iter().any(|frag| lower.contains(frag)) {
        return NODE_KIND_FRAMEWORK;
    }
    if diag.flow_steps.iter().any(|s| s.kind.as_deref() == Some("source")) {
        return NODE_KIND_ENTRY;
    }
    if diag.flow_steps.iter().any(|s| s.kind.as_deref() == Some("sink")) {
        return NODE_KIND_SINK;
    }
    // Default: diags surface where the static pass landed, so bare
    // diags without an explicit `source` step lean toward `sink`. The
    // `other` bucket exported by `nyctos-types::chain` is reserved
    // for clearly non-source / non-sink nodes a later phase may add.
    NODE_KIND_SINK
}

/// Persist a `ChainReasoningOutcome` against the store. Writes a
/// `chains` row (carrying the chain-level `attack_provenance` /
/// `prompt_version` on the chain itself) and stamps `findings.chain_id`
/// on every member via `set_chain`.
///
/// Provenance ladder: ChainReasoning is the lowest-priority writer for
/// `findings.attack_provenance` / `findings.prompt_version` (below
/// PayloadSynthesis and SpecDerivation) and intentionally does not
/// touch those columns on member findings. ChainReasoning is a graph-
/// level synthesis pass — it does not produce the payload the verifier
/// executes, nor the harness spec the verifier wraps the payload in,
/// so the chain's prompt version is not the canonical attribution for
/// any individual member finding. Per-chain provenance is recorded on
/// `chains.attack_provenance` / `chains.prompt_version` instead, where
/// the UI can render it without colliding with the per-finding writers.
async fn apply_chain_outcome(
    store: &Store,
    input: &ChainReasoningInput,
    outcome: ChainReasoningOutcome,
    report: &mut ChainReasoningPassReport,
    runtime_name: &str,
    runtime_model: &str,
    started_at_ms: i64,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    match outcome {
        ChainReasoningOutcome::Ranked {
            run_id,
            output,
            prompt_version,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            report.spend_usd_micros += spent_usd_micros;
            report.attempts += u64::from(attempts);
            let provenance = AttackProvenance::LlmSynthesised.as_str().to_string();
            let repo_by_id: HashMap<String, String> =
                input.nodes.iter().map(|n| (n.id.clone(), n.repo.clone())).collect();
            let created_at = finished_at;
            let trace = build_trace_row(
                TaskKind::ChainReasoning,
                None,
                runtime_name,
                runtime_model,
                &prompt_version,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            for (rank, chain) in output.chains.iter().enumerate() {
                let cross_repo = chain
                    .member_ids
                    .iter()
                    .filter_map(|m| repo_by_id.get(m))
                    .collect::<HashSet<_>>()
                    .len()
                    > 1;
                let member_ids_blob = match serde_json::to_string(&chain.member_ids) {
                    Ok(b) => b,
                    Err(err) => {
                        tracing::warn!(error = %err, "chain reasoning: dropping chain with unserialisable member_ids");
                        continue;
                    }
                };
                let rationale_blob = serde_json::json!({
                    "rationale": chain.rationale,
                })
                .to_string();
                let chain_id = format!("chain-{run_id}-{rank:02}-{created_at:x}-{}", short_token());
                let rec = ChainRecord {
                    id: chain_id.clone(),
                    run_id: run_id.clone(),
                    cross_repo,
                    member_ids: member_ids_blob,
                    rationale_blob: Some(rationale_blob),
                    attack_provenance: Some(provenance.clone()),
                    prompt_version: Some(prompt_version.clone()),
                    status: "Proposed".to_string(),
                    verification_attempt_id: None,
                    evidence_blob: None,
                    severity: None,
                };
                store.chains().insert(&rec).await?;
                report.chains_persisted += 1;
                if cross_repo {
                    report.cross_repo_chains += 1;
                }
                for member_id in &chain.member_ids {
                    match store.findings().set_chain(member_id, &chain_id).await {
                        Ok(()) => report.members_stamped += 1,
                        Err(err) => tracing::warn!(
                            error = %err,
                            chain = %chain_id,
                            finding = %member_id,
                            "chain reasoning: failed to stamp finding back-link"
                        ),
                    }
                }
            }
        }
        ChainReasoningOutcome::NoChains {
            run_id: _,
            reason,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            tracing::info!(reason = %reason, "chain reasoning: no chains produced");
            let trace = build_trace_row(
                TaskKind::ChainReasoning,
                None,
                runtime_name,
                runtime_model,
                CHAIN_REASONING_PROMPT_VERSION,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.spend_usd_micros += spent_usd_micros;
            report.attempts += u64::from(attempts);
        }
    }
    Ok(())
}

// ----- NovelFindingDiscovery ----------------------------------------------

// Per-call NovelFindingDiscovery cap now lives on `AiConfig` as
// `[ai] novel_discovery_per_call_cap_usd_micros`. The pass halts
// further batches once the cumulative `(run_id, OneShot)` spend
// crosses the run cap; the per-call value bounds a single batch
// below the run cap when the operator wants tighter clamps.

/// Maximum bytes of source per file forwarded into the batch prompt.
/// Files above this are truncated and the `truncated` flag is set so
/// the model knows not to invent line numbers past the visible region.
const NOVEL_DISCOVERY_FILE_TRUNCATE_BYTES: usize = 8 * 1024;

/// Hard ceiling on the raw on-disk size of a candidate file before the
/// walker skips it outright. Above this size the file is almost always
/// generated, vendored, or otherwise low-signal; truncating an enormous
/// file would waste the upstream tokens.
const NOVEL_DISCOVERY_MAX_RAW_BYTES: u64 = 256 * 1024;

/// Directories the file walker refuses to descend into. Vendored or
/// generated trees would dominate the priority list and burn budget
/// on code outside the operator's control.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "_vendor",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    ".next",
    ".nuxt",
    "site-packages",
    "third_party",
];

/// Path-keyword score table the priority heuristic uses. Routes,
/// controllers, models and DB layer files float to the top of the
/// batch queue. The table is intentionally short and language-neutral.
const PRIORITY_KEYWORDS: &[(&str, i64)] = &[
    ("route", 6),
    ("controller", 6),
    ("handler", 5),
    ("view", 4),
    ("api", 4),
    ("model", 4),
    ("auth", 4),
    ("login", 4),
    ("query", 3),
    ("sql", 3),
    ("db", 2),
    ("exec", 3),
];

/// Maximum boost applied to [`priority_for`] when a path's historical
/// AI-promotion rate is at the ceiling (rate = 1.0). At rate = 0.0 the
/// boost is zero; the boost scales linearly in between. Sized so the
/// strongest converters can outrank a plain `route`-keyword hit (which
/// scores +6 today) without drowning out the keyword signal entirely.
const PROMOTION_RATE_WEIGHT: f64 = 10.0;

/// Counts surfaced by [`run_novel_finding_discovery_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NovelFindingDiscoveryPassReport {
    pub batches_dispatched: u32,
    pub batches_halted: u32,
    pub candidates_persisted: u32,
    pub failed: u32,
    pub spend_usd_micros: i64,
    pub attempts: u64,
}

/// Fan-out NovelFindingDiscovery across every successfully-ingested
/// repo in `bundle`. No-op (returns a default report) when the
/// selected runtime does not support one-shot tasks or is unavailable.
///
/// This is the most expensive AI pass; a per-run cap (default $5
/// model spend, sourced from
/// [`DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS`]) halts further
/// batches once the cumulative `(run_id, OneShot)` spend crosses it.
/// All output starts in Quarantine (`candidate_findings.status =
/// 'Pending'`); promotion to a real finding lands with the payload
/// verifier.
pub async fn run_novel_finding_discovery_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<NovelFindingDiscoveryPassReport> {
    let tracker: SharedBudgetTracker = Arc::new(BudgetStoreTracker::new(
        store.clone(),
        DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS,
    ));
    let adapter = match selected_one_shot_runtime(
        config,
        store,
        secrets,
        DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS,
        "novel finding discovery",
    )
    .await?
    {
        Some(adapter) => adapter,
        None => return Ok(NovelFindingDiscoveryPassReport::default()),
    };

    drive_novel_finding_pass(
        adapter.as_ref(),
        tracker.as_ref(),
        store,
        bundle,
        workspaces,
        events,
        DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS,
        config.novel_discovery_per_call_cap_usd_micros_resolved(),
        DEFAULT_FILES_PER_BATCH,
    )
    .await
}

/// Inner driver, generic over `AiRuntime` + `BudgetTracker` so tests
/// can wire a scripted runtime + in-memory tracker without going
/// through the production Anthropic adapter. The pass runs each repo's
/// batches sequentially (against one shared `(run_id, OneShot)` budget
/// bucket) so the cap check has a deterministic ordering.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_novel_finding_pass<R: AiRuntime + ?Sized>(
    runtime: &R,
    tracker: &dyn BudgetTracker,
    store: &Store,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
    run_cap_usd_micros: i64,
    per_call_cap_usd_micros: i64,
    files_per_batch: usize,
) -> anyhow::Result<NovelFindingDiscoveryPassReport> {
    let mut report = NovelFindingDiscoveryPassReport::default();
    let mut halted = false;
    for repo_bundle in &bundle.per_repo {
        let RepoOutcome::Success(diags) = &repo_bundle.outcome else {
            continue;
        };
        let Some(workspace) = workspaces.get(&repo_bundle.repo) else {
            continue;
        };
        // Historical AI-promotion rate per source path in this repo,
        // used to bias the priority heuristic toward files the verifier
        // has previously confirmed. A store error degrades to "no
        // boost" rather than failing the pass — the keyword + size
        // heuristic still produces a usable ordering on its own.
        let promotion_rates =
            match store.findings().per_path_promotion_rate(&repo_bundle.repo).await {
                Ok(map) => Some(map),
                Err(err) => {
                    tracing::warn!(
                        repo = %repo_bundle.repo,
                        error = %err,
                        "novel finding discovery: per-path promotion rate lookup failed; \
                         falling back to keyword + size heuristic only"
                    );
                    None
                }
            };
        let inputs = build_novel_inputs_for_repo(
            &bundle.run_id,
            &repo_bundle.repo,
            workspace.workspace(),
            diags,
            files_per_batch,
            promotion_rates.as_ref(),
        );
        if inputs.is_empty() {
            continue;
        }
        tracing::info!(
            repo = %repo_bundle.repo,
            batches = inputs.len(),
            "novel finding discovery: dispatching repo batches"
        );
        let runtime_name = runtime.name();
        let runtime_model = runtime.default_model().to_string();
        for input in inputs {
            let spent_before = tracker
                .current_spend(&bundle.run_id, BudgetKind::OneShot)
                .await
                .map_err(|e| anyhow::anyhow!("budget tracker error: {e}"))?;
            if spent_before >= run_cap_usd_micros {
                halted = true;
                report.batches_halted += 1;
                tracing::info!(
                    spent_usd_micros = spent_before,
                    cap_usd_micros = run_cap_usd_micros,
                    "novel finding discovery: budget cap reached; halting further batches"
                );
                continue;
            }
            report.batches_dispatched += 1;
            let started_at = now_epoch_ms();
            let outcome =
                match run_novel_findings(runtime, &input, events.clone(), per_call_cap_usd_micros)
                    .await
                {
                    Ok(o) => o,
                    Err(err) => {
                        tracing::warn!(error = %err, "novel finding discovery call failed");
                        report.failed += 1;
                        if ai_error_should_halt_pass(&err) {
                            halted = true;
                            break;
                        }
                        continue;
                    }
                };
            apply_novel_outcome(
                store,
                outcome,
                &mut report,
                runtime_name,
                &runtime_model,
                started_at,
            )
            .await?;
        }
        if halted {
            // Once the run-wide cap has tripped no further repo's
            // batches should fire either, but record their count so
            // operators see the full halted surface.
            break;
        }
    }
    Ok(report)
}

/// Pure data path: walk the repo workspace, prioritise files by the
/// route/controller/model/db keyword heuristic, partition into batches
/// of `files_per_batch`, and attach the matching nyx priors per batch.
/// `promotion_rates`, when set, maps repo-relative paths to their
/// historical AI-promotion rate (see
/// `FindingStore::per_path_promotion_rate`); a non-empty entry boosts
/// the file's priority. Public so the prioritisation + batching can be
/// unit-tested without spinning up an adapter.
pub fn build_novel_inputs_for_repo(
    run_id: &str,
    repo: &str,
    workspace: &std::path::Path,
    diags: &[Diag],
    files_per_batch: usize,
    promotion_rates: Option<&HashMap<String, f64>>,
) -> Vec<NovelFindingDiscoveryInput> {
    let files = walk_source_files(workspace);
    if files.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(i64, std::path::PathBuf, u64)> = files
        .into_iter()
        .map(|p| {
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let rate = promotion_rates.and_then(|map| {
                p.strip_prefix(workspace)
                    .ok()
                    .and_then(|rel| rel.to_str())
                    .and_then(|rel| map.get(rel))
                    .copied()
            });
            let score = priority_for(&p, size, rate);
            (score, p, size)
        })
        .collect();
    scored.sort_by(|a, b| {
        // Higher score first; tie-break on path to keep ordering
        // deterministic across runs.
        b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1))
    });

    // Group priors by file path so each batch only sees the priors for
    // files it actually contains.
    let mut priors_by_path: HashMap<String, Vec<PriorFinding>> = HashMap::new();
    for diag in diags {
        priors_by_path.entry(diag.path.clone()).or_default().push(PriorFinding {
            path: diag.path.clone(),
            line: diag.line,
            cap: diag.cap.clone(),
            rule: diag.rule.clone(),
        });
    }

    let mut out = Vec::new();
    let batch_size = files_per_batch.max(1);
    for (batch_idx, chunk) in scored.chunks(batch_size).enumerate() {
        let mut files = Vec::with_capacity(chunk.len());
        let mut priors = Vec::new();
        for (_, abs_path, _size) in chunk {
            let rel = match abs_path.strip_prefix(workspace) {
                Ok(r) => r.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            let Some((content, truncated)) = read_truncated(abs_path) else {
                continue;
            };
            if let Some(p) = priors_by_path.get(&rel) {
                priors.extend(p.iter().cloned());
            }
            files.push(FileForReview { path: rel, content, truncated });
        }
        if files.is_empty() {
            continue;
        }
        out.push(NovelFindingDiscoveryInput {
            run_id: run_id.to_string(),
            repo: repo.to_string(),
            batch_id: format!("{repo}:{batch_idx}"),
            files,
            priors,
        });
    }
    out
}

fn walk_source_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    // `ignore::WalkBuilder` honours .gitignore / .ignore / global excludes
    // and skips hidden entries by default. SKIP_DIRS layers in the
    // hardcoded skips that often are absent from a repo's gitignore
    // (target, vendor, __pycache__, site-packages, etc.).
    let walker = ignore::WalkBuilder::new(root)
        .standard_filters(true)
        .hidden(true)
        .parents(false)
        .require_git(false)
        .filter_entry(|entry| {
            entry.file_name().to_str().is_some_and(|name| !SKIP_DIRS.contains(&name))
        })
        .build();
    let mut out = Vec::new();
    for result in walker {
        let Ok(entry) = result else { continue };
        let Some(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let path = entry.into_path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !accepts_source_file(name) {
            continue;
        }
        let raw_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if raw_size > NOVEL_DISCOVERY_MAX_RAW_BYTES {
            continue;
        }
        out.push(path);
    }
    out
}

fn accepts_source_file(name: &str) -> bool {
    infer_lang(name) != "unknown"
}

fn priority_for(path: &std::path::Path, size: u64, promotion_rate: Option<f64>) -> i64 {
    let lower = path.to_string_lossy().to_lowercase();
    let mut score = 0_i64;
    for (kw, w) in PRIORITY_KEYWORDS {
        if lower.contains(kw) {
            score += *w;
        }
    }
    let s = size as i64;
    if s < 256 {
        score -= 5;
    } else if s < 2_048 {
        score += 1;
    } else if s < 50_000 {
        score += 3;
    } else if s > 200_000 {
        score -= 5;
    }
    if let Some(rate) = promotion_rate {
        let clamped = rate.clamp(0.0, 1.0);
        score += (clamped * PROMOTION_RATE_WEIGHT).round() as i64;
    }
    score
}

fn read_truncated(path: &std::path::Path) -> Option<(String, bool)> {
    let raw = std::fs::read(path).ok()?;
    let utf8 = match std::str::from_utf8(&raw) {
        Ok(s) => s.to_string(),
        Err(_) => return None,
    };
    if utf8.len() <= NOVEL_DISCOVERY_FILE_TRUNCATE_BYTES {
        Some((utf8, false))
    } else {
        // Truncate on a char boundary so we never split a UTF-8 sequence.
        let mut cut = NOVEL_DISCOVERY_FILE_TRUNCATE_BYTES;
        while cut > 0 && !utf8.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut head = utf8[..cut].to_string();
        if !head.ends_with('\n') {
            head.push('\n');
        }
        head.push_str("... <file truncated>\n");
        Some((head, true))
    }
}

async fn apply_novel_outcome(
    store: &Store,
    outcome: NovelFindingDiscoveryOutcome,
    report: &mut NovelFindingDiscoveryPassReport,
    runtime_name: &str,
    runtime_model: &str,
    started_at_ms: i64,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    match outcome {
        NovelFindingDiscoveryOutcome::Discovered {
            run_id,
            repo,
            batch_id: _,
            output,
            prompt_version,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            report.spend_usd_micros += spent_usd_micros;
            report.attempts += u64::from(attempts);
            let trace = build_trace_row(
                TaskKind::NovelFindings,
                None,
                runtime_name,
                runtime_model,
                &prompt_version,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            let trace_id = trace.id.clone();
            persist_trace_row(store, trace).await;
            let created_at = finished_at;
            for (idx, c) in output.candidates.iter().enumerate() {
                let id = candidate_id(&run_id, &repo, c, created_at, idx);
                let rec = CandidateFindingRecord {
                    id,
                    run_id: run_id.clone(),
                    repo: repo.clone(),
                    path: c.path.clone(),
                    line: Some(i64::from(c.line)),
                    cap: c.cap.clone(),
                    rule_hint: c.rule_hint.clone(),
                    rationale: Some(c.rationale.clone()),
                    suggested_payload_hint: c.suggested_payload_hint.clone(),
                    // Pending = quarantined for AI proposals; promotion
                    // to a real finding requires the payload verifier
                    // to confirm via PayloadSynthesis + dynamic verify.
                    status: nyctos_core::store::CandidateStatus::Pending.as_str().to_string(),
                    prompt_version: Some(prompt_version.clone()),
                    trace_id: Some(trace_id.clone()),
                };
                match store.candidate_findings().insert(&rec).await {
                    Ok(()) => report.candidates_persisted += 1,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "novel finding discovery: failed to persist candidate"
                        );
                    }
                }
            }
        }
        NovelFindingDiscoveryOutcome::NoCandidates {
            run_id: _,
            repo: _,
            batch_id,
            reason,
            spent_usd_micros,
            attempts,
            metrics,
        } => {
            tracing::info!(
                batch = %batch_id,
                reason = %reason,
                "novel finding discovery: no candidates produced"
            );
            let trace = build_trace_row(
                TaskKind::NovelFindings,
                None,
                runtime_name,
                runtime_model,
                NOVEL_FINDING_DISCOVERY_PROMPT_VERSION,
                spent_usd_micros,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            persist_trace_row(store, trace).await;
            report.spend_usd_micros += spent_usd_micros;
            report.attempts += u64::from(attempts);
        }
    }
    Ok(())
}

fn candidate_id(
    run_id: &str,
    repo: &str,
    c: &nyctos_types::novel::CandidateFinding,
    created_at_ms: i64,
    rank: usize,
) -> String {
    // The stable half reuses `finding_id_hash`'s 8-byte BLAKE3 truncation
    // so the candidate id mirrors the eventual `findings.id` shape if
    // the payload verifier promotes it. `run_id` + `rationale` are
    // folded into the `rule` slot so two candidates that differ only
    // in rationale do not collide.
    let folded_rule = format!(
        "{run_id}\0{rule_hint}\0{rationale}",
        rule_hint = c.rule_hint.as_deref().unwrap_or(""),
        rationale = c.rationale,
    );
    let stable = nyctos_core::store::finding_id_hash(
        repo,
        &c.path,
        Some(i64::from(c.line)),
        &c.cap,
        &folded_rule,
    );
    // Append created-at-ms + rank + a random 8-hex suffix so a
    // deterministic-replay path (same prompt response twice in the
    // same ms with identical rank ordering) still produces a unique
    // row.
    format!("cand-{stable}-{created_at_ms:x}-{rank:02}-{}", short_token())
}

// ----- Payload verification ----------------------------------------------

/// Counts surfaced by [`run_payload_verification_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PayloadVerificationPassReport {
    /// Findings that produced a [`VerifyVerdict::Confirmed`] verdict.
    pub confirmed: u32,
    /// Findings that produced a [`VerifyVerdict::NotConfirmed`] verdict.
    pub not_confirmed: u32,
    /// Findings whose verify run surfaced an `Errored` verdict.
    pub errored: u32,
    /// Pending candidate_findings flipped to Promoted after a
    /// Confirmed verdict.
    pub candidates_promoted: u32,
    /// Verifier invocations that bubbled an unrecoverable error
    /// (workspace setup failed, sandbox spawn refused, etc.).
    pub failed: u32,
    /// Findings (including candidates) that were considered but had no
    /// payload+spec pair to verify against. Surfaces "wired up but not
    /// yet exercised" so operators can spot a missing synthesis hand-off.
    pub skipped_no_payload: u32,
}

/// Per-run timeout for each sandbox run inside the verifier. Vuln +
/// benign each get this budget; a replay-stable check doubles it.
/// Tuned for the canned shell harness fixture; production tuning lives
/// with the operator-facing knob that arrives in a later phase.
const VERIFIER_PER_RUN_TIMEOUT_SECS: u64 = 10;

/// Marker prefix in [`nyctos_nyx::HarnessSpec::oracle`] that selects
/// [`Oracle::SinkProbe`] over the default [`Oracle::OutputContains`].
/// Format: `sink-probe:<sentinel-path>[#<expect-contains>]`.
const SINK_PROBE_ORACLE_PREFIX: &str = "sink-probe:";

/// Drive the deterministic payload runner across every finding (and
/// AI-discovered candidate) for this run that has both a `payloads`
/// row and a `harness_specs` row available. Verdicts land back on the
/// `findings` table: `Verified` for [`VerifyVerdict::Confirmed`],
/// `Closed` for [`VerifyVerdict::NotConfirmed`]. Errored verdicts leave
/// status untouched but stamp `verdict_blob` so the UI can render the
/// failure mode. Promoted candidates land a new `findings` row with
/// `finding_origin = AiExploration`.
pub async fn run_payload_verification_pass(
    run_config: &RunConfig,
    sandbox_config: &SandboxConfig,
    store: &Store,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<PayloadVerificationPassReport> {
    let runner = PayloadRunner {
        backend: pick_verifier_backend(sandbox_config),
        per_run_timeout: std::time::Duration::from_secs(VERIFIER_PER_RUN_TIMEOUT_SECS),
        replay_stable_check: run_config.replay_stable_check,
        shim_path: None,
    };
    let mut report = PayloadVerificationPassReport::default();

    // 1. Static + LLM-synthesised findings persisted under this run.
    let findings = store.findings().list_by_run(&bundle.run_id).await?;
    for finding in findings {
        let Some(workspace) = workspaces.get(&finding.repo) else {
            continue;
        };
        match drive_verify_for_finding(&runner, store, &finding, workspace, &events, &bundle.run_id)
            .await
        {
            Ok(VerifyOutcome::Skipped) => report.skipped_no_payload += 1,
            Ok(VerifyOutcome::Verdict(verdict)) => bump_verdict(&mut report, verdict),
            Err(err) => {
                tracing::warn!(error = %err, finding = %finding.id, "verifier failed");
                report.failed += 1;
            }
        }
    }

    // 2. AI-discovered candidates that have a payload+spec pre-staged
    //    against their candidate id. The synthesis hand-off that
    //    creates those rows is deferred; this pass picks them up the
    //    moment a future phase lands the synthesis side.
    let pending = store.candidate_findings().list_pending().await?;
    let now_ms = now_epoch_ms();
    for cand in pending {
        if cand.run_id != bundle.run_id {
            continue;
        }
        let Some(workspace) = workspaces.get(&cand.repo) else {
            continue;
        };
        match drive_verify_for_candidate(
            &runner,
            store,
            &cand,
            workspace,
            now_ms,
            &events,
            &bundle.run_id,
        )
        .await
        {
            Ok(VerifyOutcome::Skipped) => report.skipped_no_payload += 1,
            Ok(VerifyOutcome::Verdict(verdict)) => {
                bump_verdict(&mut report, verdict);
                if matches!(verdict, VerifyVerdict::Confirmed) {
                    report.candidates_promoted += 1;
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, candidate = %cand.id, "verifier failed");
                report.failed += 1;
            }
        }
    }

    Ok(report)
}

/// Best-effort fan-out of a `SandboxEvent` over the run-wide bus. The
/// underlying `broadcast::Sender::send` returns `Err` only when no
/// receiver is alive, which is not actionable for the verifier pass —
/// log nothing and drop the error so the pass continues.
fn emit_sandbox(events: &EventSink, event: SandboxEvent) {
    let _ = events.send(AgentEvent::Sandbox { data: event });
}

fn pick_verifier_backend(sandbox_config: &SandboxConfig) -> BackendKind {
    match sandbox_config.backend {
        SandboxBackend::Birdcage => BackendKind::Birdcage,
        // Process is the unhardened fallback; every other backend
        // lands in a later phase that grows the sandbox crate's
        // launchers, so route them through Process today.
        _ => BackendKind::Process,
    }
}

fn bump_verdict(report: &mut PayloadVerificationPassReport, verdict: VerifyVerdict) {
    match verdict {
        VerifyVerdict::Confirmed => report.confirmed += 1,
        VerifyVerdict::NotConfirmed => report.not_confirmed += 1,
        VerifyVerdict::Errored => report.errored += 1,
    }
}

enum VerifyOutcome {
    Skipped,
    Verdict(VerifyVerdict),
}

async fn drive_verify_for_finding(
    runner: &PayloadRunner,
    store: &Store,
    finding: &FindingRecord,
    workspace: &WorkspaceHandle,
    events: &EventSink,
    run_id: &str,
) -> anyhow::Result<VerifyOutcome> {
    let Some((payload, spec)) = load_payload_and_spec(store, &finding.id).await? else {
        return Ok(VerifyOutcome::Skipped);
    };
    let prompt_version = payload.prompt_version.clone();
    let spec_id = spec.id.clone();
    let started_at = now_epoch_ms();
    emit_sandbox(
        events,
        SandboxEvent::VerifierStarted {
            run_id: run_id.to_string(),
            finding_id: finding.id.clone(),
            repo: finding.repo.clone(),
            started_at_ms: started_at,
        },
    );
    let result = run_one_verify(runner, &finding.id, payload, spec, workspace).await?;
    let finished_at = now_epoch_ms();
    emit_sandbox(
        events,
        SandboxEvent::VerifierFinished {
            run_id: run_id.to_string(),
            finding_id: finding.id.clone(),
            repo: finding.repo.clone(),
            verdict: result.verdict.as_str().to_string(),
            replay_stable: result.replay_stable,
            elapsed_ms: finished_at - started_at,
        },
    );
    persist_finding_verdict(store, finding, &result).await?;
    persist_verifier_trace(
        store,
        Some(finding.id.clone()),
        runner.backend.as_str(),
        prompt_version.as_deref().unwrap_or(&spec_id),
        started_at,
        finished_at,
        Some(&spec_id),
        Some(&result),
    )
    .await;
    Ok(VerifyOutcome::Verdict(result.verdict))
}

#[allow(clippy::too_many_arguments)]
async fn persist_verifier_trace(
    store: &Store,
    finding_id: Option<String>,
    backend: &str,
    prompt_version: &str,
    started_at: i64,
    finished_at: i64,
    spec_id: Option<&str>,
    result: Option<&VerifyResult>,
) {
    let mut row = build_trace_row(
        TaskKind::Verifier,
        finding_id,
        backend,
        backend,
        prompt_version,
        0,
        started_at,
        finished_at,
        None,
    );
    row.verifier_blob = build_verifier_blob(spec_id, result);
    persist_trace_row(store, row).await;
}

/// Render the `agent_traces.verifier_blob` JSON for a Verifier row.
///
/// Returns `None` when no inputs are available (i.e. the runner failed
/// before producing a `VerifyResult` AND no spec id was known). The
/// shape matches the `agent_traces.verifier_blob` contract: every field
/// is independently optional so callers stamp whatever they have.
fn build_verifier_blob(spec_id: Option<&str>, result: Option<&VerifyResult>) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut obj = serde_json::Map::new();
    if let Some(id) = spec_id {
        obj.insert("spec_id".into(), serde_json::Value::String(id.to_string()));
    }
    if let Some(r) = result {
        let vuln_hash = hex::encode(Sha256::digest(&r.vuln_run.payload));
        let benign_hash = hex::encode(Sha256::digest(&r.benign_run.payload));
        obj.insert("vuln_payload_sha256".into(), serde_json::Value::String(vuln_hash));
        obj.insert("vuln_exit_code".into(), serde_json::Value::from(r.vuln_run.exit_code));
        obj.insert("benign_payload_sha256".into(), serde_json::Value::String(benign_hash));
        obj.insert("benign_exit_code".into(), serde_json::Value::from(r.benign_run.exit_code));
    }
    if obj.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(obj).to_string())
    }
}

async fn drive_verify_for_candidate(
    runner: &PayloadRunner,
    store: &Store,
    candidate: &CandidateFindingRecord,
    workspace: &WorkspaceHandle,
    now_ms: i64,
    events: &EventSink,
    run_id: &str,
) -> anyhow::Result<VerifyOutcome> {
    // Candidates do not yet flow through PayloadSynthesis +
    // SpecDerivation (that hand-off is the deferred
    // candidate-confirmation pipeline). The verifier picks up the
    // promotion side using a built-in per-cap harness template
    // seeded by `suggested_payload_hint` plus a constant benign
    // control. When the synthesis hand-off lands, this path swaps
    // over to the stored `payloads` / `harness_specs` rows the same
    // way [`drive_verify_for_finding`] already does.
    let Some(hint) = candidate.suggested_payload_hint.as_deref() else {
        return Ok(VerifyOutcome::Skipped);
    };
    let Some(spec_input) = builtin_harness_for_cap(&candidate.cap) else {
        return Ok(VerifyOutcome::Skipped);
    };
    let oracle = builtin_oracle_for_cap(&candidate.cap);
    let benign = builtin_benign_for_cap(&candidate.cap);
    let run = PayloadRun {
        finding_id: candidate.id.clone(),
        spec: spec_input,
        harness_source: HarnessSource::Synthesised,
        vuln_payload: hint.as_bytes().to_vec(),
        benign_payload: benign.as_bytes().to_vec(),
        oracle,
        attack_provenance: AttackProvenance::LlmSynthesised,
        workspace: workspace.workspace().to_path_buf(),
    };
    let prompt_version = candidate
        .prompt_version
        .clone()
        .unwrap_or_else(|| format!("builtin-cap:{}", candidate.cap));
    let started_at = now_epoch_ms();
    emit_sandbox(
        events,
        SandboxEvent::VerifierStarted {
            run_id: run_id.to_string(),
            finding_id: candidate.id.clone(),
            repo: candidate.repo.clone(),
            started_at_ms: started_at,
        },
    );
    let result = match runner.verify(run).await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, candidate = %candidate.id, "verifier errored on candidate");
            let finished_at = now_epoch_ms();
            emit_sandbox(
                events,
                SandboxEvent::VerifierFinished {
                    run_id: run_id.to_string(),
                    finding_id: candidate.id.clone(),
                    repo: candidate.repo.clone(),
                    verdict: VerifyVerdict::Errored.as_str().to_string(),
                    replay_stable: None,
                    elapsed_ms: finished_at - started_at,
                },
            );
            persist_verifier_trace(
                store,
                None,
                runner.backend.as_str(),
                &prompt_version,
                started_at,
                finished_at,
                None,
                None,
            )
            .await;
            return Ok(VerifyOutcome::Verdict(VerifyVerdict::Errored));
        }
    };
    let finished_at = now_epoch_ms();
    emit_sandbox(
        events,
        SandboxEvent::VerifierFinished {
            run_id: run_id.to_string(),
            finding_id: candidate.id.clone(),
            repo: candidate.repo.clone(),
            verdict: result.verdict.as_str().to_string(),
            replay_stable: result.replay_stable,
            elapsed_ms: finished_at - started_at,
        },
    );
    if matches!(result.verdict, VerifyVerdict::Confirmed) {
        promote_candidate(store, candidate, &result, now_ms).await?;
    } else {
        tracing::info!(
            candidate = %candidate.id,
            verdict = %result.verdict.as_str(),
            "verifier ran on candidate but did not promote"
        );
    }
    // Candidate trace row carries `finding_id = None` until the
    // data-model convergence stitches candidate ids into trace rows
    // (deferred). When promoted, the same call's verdict is also
    // attributed via the freshly minted `findings` row's
    // `verdict_blob`, so operators still have a path back to this
    // call.
    persist_verifier_trace(
        store,
        None,
        runner.backend.as_str(),
        &prompt_version,
        started_at,
        finished_at,
        None,
        Some(&result),
    )
    .await;
    Ok(VerifyOutcome::Verdict(result.verdict))
}

/// Built-in per-cap shell/python harness templates the candidate
/// verifier uses until the candidate-confirmation pipeline starts
/// driving real spec-derivation on candidates. Returning `None` makes
/// the verifier skip the candidate (it cannot construct a deterministic
/// harness for a cap it does not recognise). Caps that need a richer
/// runtime than a single `sh -c` invocation (XSS / SSRF / XXE / ...)
/// stay `None` until the candidate-confirmation pipeline lands real
/// per-candidate spec derivation.
fn builtin_harness_for_cap(cap: &str) -> Option<HarnessSpecInput> {
    match cap {
        "SQL_QUERY" | "SQLi" => Some(HarnessSpecInput {
            cap: cap.to_string(),
            lang: "shell".to_string(),
            setup: vec!["STORED='alice:pw1\\nbob:pw2\\nadmin:TOP_SECRET'".to_string()],
            invoke: "printf '%b\\n' \"$STORED\" | grep -E @PAYLOAD || true".to_string(),
            teardown: vec![],
        }),
        "OS_COMMAND" | "CMDi" => Some(HarnessSpecInput {
            cap: cap.to_string(),
            lang: "shell".to_string(),
            setup: vec![],
            // Evaluate the payload as a shell command. The sentinel-file
            // oracle (`OSCMD_SENTINEL`) fires when the payload performs
            // an injection side effect (touches the flag file); the
            // benign control is a shell no-op that leaves the workspace
            // untouched.
            invoke: "sh -c @PAYLOAD".to_string(),
            teardown: vec![],
        }),
        "PATH_TRAVERSAL" => Some(HarnessSpecInput {
            cap: cap.to_string(),
            lang: "shell".to_string(),
            // Stand up a `safe_dir/` the application "intends" to keep
            // payload-supplied filenames inside, and stage an out-of-band
            // secret (`oracle_secret.txt`) in the workspace root.
            // `oracle_secret.txt` is reachable only by traversing out of
            // `safe_dir/` (`safe_dir/../oracle_secret.txt`), so an
            // AI-suggested payload that escapes the intended container
            // leaks `TOP_SECRET_TRAV` to stdout and trips the oracle.
            setup: vec![
                "mkdir -p safe_dir".to_string(),
                "printf 'workspace\\n' > safe_dir/innocent.txt".to_string(),
                "printf 'TOP_SECRET_TRAV\\n' > oracle_secret.txt".to_string(),
            ],
            invoke: "cat -- safe_dir/@PAYLOAD 2>/dev/null || true".to_string(),
            teardown: vec![],
        }),
        "XXE" => Some(HarnessSpecInput {
            cap: cap.to_string(),
            lang: "python".to_string(),
            // Drive expat directly so the harness exercises the
            // DOCTYPE + ENTITY parse path that defines the XXE class.
            // CharacterDataHandler captures element text so an
            // entity-expanded marker reaches stdout; a malformed or
            // entity-free payload simply prints nothing.
            setup: vec![
                "import xml.parsers.expat".to_string(),
                "parser = xml.parsers.expat.ParserCreate()".to_string(),
                "out = []".to_string(),
                "parser.CharacterDataHandler = lambda d: out.append(d)".to_string(),
            ],
            invoke: "try:\n    parser.Parse(@PAYLOAD, True)\n    print(''.join(out))\nexcept Exception as e:\n    print('parse-error:', e)".to_string(),
            teardown: vec![],
        }),
        "DESERIALISATION" => Some(HarnessSpecInput {
            cap: cap.to_string(),
            lang: "python".to_string(),
            // Feed the payload bytes verbatim into `pickle.loads`. A
            // protocol-0 pickle that REDUCEs `builtins.print` with the
            // `TOP_SECRET_PICKLE` marker writes the marker to stdout
            // during unpickling; a benign pickle (`b"N."` = NONE+STOP)
            // returns `None` with no side effect.
            setup: vec!["import pickle".to_string()],
            invoke: "try:\n    pickle.loads(@PAYLOAD)\nexcept Exception as e:\n    print('deserialise-error:', e)".to_string(),
            teardown: vec![],
        }),
        _ => None,
    }
}

/// Sentinel filename the `OS_COMMAND` / `CMDi` builtin harness probes
/// to confirm an injection. Kept in sync with the `SinkProbe` oracle
/// returned by [`builtin_oracle_for_cap`].
const OSCMD_SENTINEL: &str = "nyx_oscmd.flag";

fn builtin_oracle_for_cap(cap: &str) -> Oracle {
    match cap {
        "SQL_QUERY" | "SQLi" => Oracle::OutputContains { marker: "TOP_SECRET".to_string() },
        "OS_COMMAND" | "CMDi" => {
            Oracle::SinkProbe { sentinel_path: OSCMD_SENTINEL.to_string(), expect_contains: None }
        }
        "PATH_TRAVERSAL" => Oracle::OutputContains { marker: "TOP_SECRET_TRAV".to_string() },
        "XXE" => Oracle::OutputContains { marker: "TOP_SECRET_XXE".to_string() },
        "DESERIALISATION" => Oracle::OutputContains { marker: "TOP_SECRET_PICKLE".to_string() },
        _ => Oracle::OutputContains { marker: "ORACLE_FIRED".to_string() },
    }
}

fn builtin_benign_for_cap(cap: &str) -> &'static str {
    match cap {
        "SQL_QUERY" | "SQLi" => "^alice$",
        // POSIX shell no-op: parses, executes, no filesystem effect.
        "OS_COMMAND" | "CMDi" => ":",
        // Workspace-local file the harness's `safe_dir/` actually
        // contains; resolves to `safe_dir/innocent.txt` and leaks no
        // secret marker.
        "PATH_TRAVERSAL" => "innocent.txt",
        // Well-formed XML with no DOCTYPE / entities: expat parses it
        // and CharacterDataHandler captures "workspace", which is
        // distinct from the `TOP_SECRET_XXE` marker the oracle expects.
        "XXE" => "<r>workspace</r>",
        // Protocol-0 pickle of `None` (NONE + STOP): unpickles cleanly
        // with no `__reduce__` side effect, so stdout stays empty.
        "DESERIALISATION" => "N.",
        _ => "__nyx_benign_control__",
    }
}

async fn load_payload_and_spec(
    store: &Store,
    finding_id: &str,
) -> anyhow::Result<Option<(PayloadRecord, HarnessSpecRecord)>> {
    let payloads = store.payloads().list_for_finding(finding_id).await?;
    let Some(payload) = payloads.into_iter().next() else {
        return Ok(None);
    };
    // The spec back-link lives on `findings.spec_id`, but candidates do
    // not yet have a back-link column (deferred). Fall back to picking
    // the most-recent spec for the payload's cap; in production each
    // finding has exactly one spec for the cap so this is unambiguous
    // until cross-cap variants land.
    let specs = store.harness_specs().list_by_cap(&payload.cap).await?;
    let Some(spec) = specs.into_iter().last() else {
        return Ok(None);
    };
    Ok(Some((payload, spec)))
}

async fn run_one_verify(
    runner: &PayloadRunner,
    finding_id: &str,
    payload: PayloadRecord,
    spec: HarnessSpecRecord,
    workspace: &WorkspaceHandle,
) -> anyhow::Result<VerifyResult> {
    let parsed = match nyctos_nyx::HarnessSpec::from_json(&spec.spec_blob) {
        Ok((p, _)) => p,
        Err(err) => {
            return Ok(VerifyResult::errored(
                finding_id.to_string(),
                derive_oracle("output-contains-error"),
                empty_verify_run(&payload.vuln_bytes),
                empty_verify_run(payload.benign_bytes.as_deref().unwrap_or_default()),
                attack_provenance_from(payload.attack_provenance.as_deref()),
                format!("harness spec parse failed: {err}"),
            ));
        }
    };
    let spec_input = HarnessSpecInput {
        cap: parsed.cap.clone(),
        lang: parsed.lang.clone(),
        setup: parsed.setup.clone(),
        invoke: parsed.invoke.clone(),
        teardown: parsed.teardown.clone(),
    };
    let oracle = derive_oracle(&parsed.oracle);
    let attack_provenance = attack_provenance_from(payload.attack_provenance.as_deref());
    if let Some(reason) = degenerate_oracle_reason(&oracle) {
        return Ok(VerifyResult::errored(
            finding_id.to_string(),
            oracle,
            empty_verify_run(&payload.vuln_bytes),
            empty_verify_run(payload.benign_bytes.as_deref().unwrap_or_default()),
            attack_provenance,
            format!("oracle degenerate: {reason}"),
        ));
    }
    let benign_bytes = payload.benign_bytes.clone().unwrap_or_default();
    let run = PayloadRun {
        finding_id: finding_id.to_string(),
        spec: spec_input,
        harness_source: HarnessSource::Synthesised,
        vuln_payload: payload.vuln_bytes.clone(),
        benign_payload: benign_bytes,
        oracle,
        attack_provenance,
        workspace: workspace.workspace().to_path_buf(),
    };
    match runner.verify(run).await {
        Ok(r) => Ok(r),
        Err(err) => Ok(VerifyResult::errored(
            finding_id.to_string(),
            derive_oracle(&parsed.oracle),
            empty_verify_run(&payload.vuln_bytes),
            empty_verify_run(payload.benign_bytes.as_deref().unwrap_or_default()),
            attack_provenance,
            format!("payload runner: {err}"),
        )),
    }
}

fn attack_provenance_from(label: Option<&str>) -> AttackProvenance {
    match label {
        Some("LlmSynthesised") => AttackProvenance::LlmSynthesised,
        _ => AttackProvenance::Curated,
    }
}

fn empty_verify_run(payload: &[u8]) -> nyctos_types::verify::VerifyRun {
    nyctos_types::verify::VerifyRun {
        payload: payload.to_vec(),
        oracle_fired: false,
        exit_code: -1,
        timed_out: false,
        stdout: Vec::new(),
        stderr: Vec::new(),
        duration_ms: 0,
    }
}

/// Convert the harness spec's free-form `oracle` string into a typed
/// [`Oracle`] predicate. The default is `Oracle::OutputContains` with
/// the entire string as the marker; an oracle prefixed by
/// `sink-probe:<sentinel-path>[#<expect-contains>]` selects
/// [`Oracle::SinkProbe`].
fn derive_oracle(raw: &str) -> Oracle {
    if let Some(rest) = raw.strip_prefix(SINK_PROBE_ORACLE_PREFIX) {
        let (path, expect) = match rest.split_once('#') {
            Some((p, e)) => (p.to_string(), Some(e.to_string())),
            None => (rest.to_string(), None),
        };
        Oracle::SinkProbe { sentinel_path: path, expect_contains: expect }
    } else {
        Oracle::OutputContains { marker: raw.to_string() }
    }
}

/// Detect oracle shapes that would silently coerce every verify to
/// `NotConfirmed` because their predicate can never fire: an empty
/// `OutputContains` marker, or a `SinkProbe` with no sentinel path.
/// Returns a short diagnostic when degenerate so the caller can stamp
/// `VerifyVerdict::Errored` instead of running the sandbox.
fn degenerate_oracle_reason(oracle: &Oracle) -> Option<&'static str> {
    match oracle {
        Oracle::OutputContains { marker } if marker.trim().is_empty() => {
            Some("OutputContains marker is empty")
        }
        Oracle::SinkProbe { sentinel_path, .. } if sentinel_path.trim().is_empty() => {
            Some("SinkProbe sentinel_path is empty")
        }
        _ => None,
    }
}

/// Serialise a `VerifyResult` and stamp `kind = "VerifyResult"` at the
/// top level so the UI can distinguish verifier output from the
/// legacy free-form `{"message": ...}` verdict blob without sniffing
/// field names. The original `VerifyResult` fields remain at the top
/// level so direct `serde_json::from_str::<VerifyResult>` consumers
/// keep working.
fn stamp_verdict_kind(result: &VerifyResult) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(result)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("kind".to_string(), serde_json::Value::String("VerifyResult".to_string()));
    }
    Ok(serde_json::to_string(&value)?)
}

async fn persist_finding_verdict(
    store: &Store,
    finding: &FindingRecord,
    result: &VerifyResult,
) -> anyhow::Result<()> {
    // Stamp the `VerifyResult` JSON with a typed `kind` discriminator so
    // the API and UI can distinguish verifier output from the legacy
    // free-form `{"message": ...}` verdict blob without sniffing
    // field names. The fields remain at the top level so direct
    // `serde_json::from_str::<VerifyResult>` consumers still parse.
    let verdict_blob = stamp_verdict_kind(result)?;
    let new_status = match result.verdict {
        // Verified = the verifier confirmed an actual exploit landed.
        VerifyVerdict::Confirmed => "Verified",
        // Closed = the verifier ran cleanly but the differential rule
        // rejected the finding. Operators can re-open by retriaging.
        VerifyVerdict::NotConfirmed => "Closed",
        // Errored leaves the row's status alone so a transient failure
        // does not bury an open finding; verdict_blob carries the
        // diagnostic for triage.
        VerifyVerdict::Errored => finding.status.as_str(),
    };
    let attack_provenance = result.attack_provenance.as_str();
    store
        .findings()
        .set_verify_result(&finding.id, new_status, &verdict_blob, attack_provenance)
        .await?;
    Ok(())
}

async fn promote_candidate(
    store: &Store,
    candidate: &CandidateFindingRecord,
    result: &VerifyResult,
    now_ms: i64,
) -> anyhow::Result<()> {
    let line = candidate.line.unwrap_or(-1);
    let rule =
        candidate.rule_hint.clone().unwrap_or_else(|| format!("ai-exploration:{}", candidate.cap));
    let id = nyctos_core::store::finding_id_hash(
        &candidate.repo,
        &candidate.path,
        Some(line),
        &candidate.cap,
        &rule,
    );
    let verdict_blob = stamp_verdict_kind(result)?;
    let rec = FindingRecord {
        id,
        run_id: candidate.run_id.clone(),
        repo: candidate.repo.clone(),
        path: candidate.path.clone(),
        line: candidate.line,
        cap: candidate.cap.clone(),
        rule,
        severity: "High".to_string(),
        status: "Verified".to_string(),
        finding_origin: FindingOrigin::AiExploration.as_str().to_string(),
        first_seen: now_ms,
        last_seen: now_ms,
        superseded_by: None,
        triage_state: "Open".to_string(),
        triage_assigned_to: None,
        verdict_blob: Some(verdict_blob),
        repro_path: None,
        attack_provenance: Some(result.attack_provenance.as_str().to_string()),
        prompt_version: candidate.prompt_version.clone(),
        chain_id: None,
        spec_id: None,
    };
    store.findings().upsert(&rec).await?;
    store
        .candidate_findings()
        .set_status(&candidate.id, CandidateStatus::Promoted.as_str())
        .await?;
    Ok(())
}

// ----- AI Exploration ----------------------------------------------------

/// Counts surfaced by [`run_ai_exploration_pass`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AiExplorationPassReport {
    /// Repos for which the exploration driver dispatched the agent
    /// loop (escape gate green, budget available).
    pub explorations_dispatched: u32,
    /// Repos that were skipped because the escape-suite gate returned
    /// red. The driver halted before the agent loop fired; operators
    /// see the failing fixture name in the structured log.
    pub halted_escape_suite_red: u32,
    /// Repos that were skipped because the per-run budget cap was
    /// already exhausted before the call.
    pub halted_budget_exhausted: u32,
    /// `findings` rows written with `finding_origin = AiExploration`
    /// and `status = Quarantine`. The payload verifier promotes them
    /// to `Verified` when a payload + spec pair confirms.
    pub findings_quarantined: u32,
    /// Exploration calls that bubbled an unrecoverable upstream error
    /// (transport, malformed response).
    pub failed: u32,
    /// Sum of `cost_usd_micros` reported by every dispatched call.
    pub spend_usd_micros: i64,
}

/// Static escape-suite gate. Pre-records a verdict the binary supplies
/// at startup so the AI driver can refer to a recent escape-suite
/// run's result without spinning up a fresh probe on every
/// exploration. Wiring this to a real periodic probe lives with the
/// release-pipeline phase that already needs to think about the
/// `nyx-sandbox-shim` install path; until then operators rely on CI's
/// own escape-suite run.
#[derive(Debug, Clone)]
pub struct StaticEscapeSuiteGate {
    verdict: EscapeSuiteVerdict,
}

impl StaticEscapeSuiteGate {
    pub fn green() -> Self {
        Self { verdict: EscapeSuiteVerdict::Green }
    }

    #[cfg(test)]
    pub fn red(fixture: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { verdict: EscapeSuiteVerdict::Red { fixture: fixture.into(), reason: reason.into() } }
    }
}

#[async_trait]
impl EscapeSuiteGate for StaticEscapeSuiteGate {
    async fn check(&self) -> Result<EscapeSuiteVerdict, AiError> {
        Ok(self.verdict.clone())
    }
}

/// Fan-out AI Exploration across every successfully-ingested repo in
/// `bundle`. No-op (returns a default report) when the selected runtime
/// does not support agent loops or its CLI binary is unavailable.
///
/// Each repo gets one exploration call routed through the Claude Code
/// agent loop. Findings the model records via the
/// `record_exploration_finding` tool land in the `findings` table with
/// `finding_origin = AiExploration` and `status = Quarantine`; the
/// payload verifier promotes them to `Verified` when a payload + spec
/// pair confirms (the same dynamic-confirm gate NovelFindingDiscovery
/// candidates flow through).
///
/// The escape suite is a precondition: a red fixture halts the driver
/// before any agent loop fires. A run-wide hard cap (default $10 in
/// USD micros, tuned for Claude Opus pricing) bounds spend; a per-task
/// soft cap emits a warning frame on the event bus without halting
/// the run.
pub async fn run_ai_exploration_pass(
    config: &AiConfig,
    store: &Store,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    target_urls: &[String],
    escape_gate: &dyn EscapeSuiteGate,
    events: EventSink,
    traces_dir: &std::path::Path,
) -> anyhow::Result<AiExplorationPassReport> {
    let run_cap_usd_micros =
        config.exploration_run_cap_usd_micros_resolved(DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS);
    let soft_cap_usd_micros =
        config.exploration_soft_cap_usd_micros_resolved(DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS);
    let adapter = match selected_agent_loop_runtime(config, store, run_cap_usd_micros).await {
        Some(adapter) => adapter,
        None => return Ok(AiExplorationPassReport::default()),
    };

    drive_ai_exploration_pass(
        adapter.as_ref(),
        store,
        bundle,
        workspaces,
        target_urls,
        escape_gate,
        events,
        traces_dir,
        soft_cap_usd_micros,
        run_cap_usd_micros,
    )
    .await
}

/// Inner driver, generic over `AiRuntime` so tests can supply a
/// scripted agent-loop runtime without going through the production
/// Claude Code adapter. Shape mirrors the `drive_novel_finding_pass`
/// inner driver.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_ai_exploration_pass<R: AiRuntime + ?Sized>(
    runtime: &R,
    store: &Store,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    target_urls: &[String],
    escape_gate: &dyn EscapeSuiteGate,
    events: EventSink,
    traces_dir: &std::path::Path,
    soft_cap_usd_micros: i64,
    run_cap_usd_micros: i64,
) -> anyhow::Result<AiExplorationPassReport> {
    let mut report = AiExplorationPassReport::default();
    let runtime_name = runtime.name();
    let runtime_model = runtime.default_model().to_string();
    let candidate_leads = match store.pentest_candidates().list_by_run(&bundle.run_id).await {
        Ok(candidates) => candidates,
        Err(err) => {
            tracing::warn!(
                run_id = %bundle.run_id,
                error = %err,
                "ai exploration: failed to load known scanner leads; continuing without them"
            );
            Vec::new()
        }
    };
    for repo_bundle in &bundle.per_repo {
        let RepoOutcome::Success(_) = &repo_bundle.outcome else {
            continue;
        };
        let Some(workspace) = workspaces.get(&repo_bundle.repo) else {
            continue;
        };
        let known_leads = exploration_known_leads_for_repo(
            &candidate_leads,
            &repo_bundle.repo,
            EXPLORATION_KNOWN_LEADS_MAX,
        );
        let scope = build_exploration_scope(
            &bundle.run_id,
            &repo_bundle.repo,
            workspace.workspace(),
            target_urls,
            known_leads,
            soft_cap_usd_micros,
            run_cap_usd_micros,
        );

        let started_at = now_epoch_ms();
        let outcome = match run_exploration(runtime, &scope, escape_gate, events.clone()).await {
            Ok(o) => o,
            Err(err) => {
                tracing::warn!(
                    repo = %repo_bundle.repo,
                    error = %err,
                    "ai exploration call failed"
                );
                report.failed += 1;
                if ai_error_should_halt_pass(&err) {
                    break;
                }
                continue;
            }
        };
        apply_exploration_outcome(
            store,
            &bundle.run_id,
            &repo_bundle.repo,
            &scope.task_id,
            outcome,
            &mut report,
            runtime_name,
            &runtime_model,
            started_at,
            traces_dir,
        )
        .await?;
    }
    Ok(report)
}

fn build_exploration_scope(
    run_id: &str,
    repo: &str,
    workspace_root: &std::path::Path,
    target_urls: &[String],
    known_leads: Vec<ExplorationKnownLead>,
    soft_cap_usd_micros: i64,
    run_cap_usd_micros: i64,
) -> ExplorationScope {
    let mut scope = ExplorationScope::new(run_id, format!("expl-{repo}"));
    scope.workspace_root = Some(workspace_root.to_string_lossy().to_string());
    scope.allowed_hosts = target_urls.iter().filter_map(|url| host_from_url(url)).collect();
    scope.target_endpoints = target_urls
        .iter()
        .map(|url| ExplorationEndpoint {
            method: "GET".to_string(),
            url: url.clone(),
            description: Some("launch profile target".to_string()),
        })
        .collect();
    scope.known_leads = known_leads;
    scope.soft_cap_usd_micros = soft_cap_usd_micros;
    scope.run_cap_usd_micros = run_cap_usd_micros;
    scope
}

fn exploration_known_leads_for_repo(
    candidates: &[PentestCandidateRecord],
    repo: &str,
    limit: usize,
) -> Vec<ExplorationKnownLead> {
    let mut candidates = candidates
        .iter()
        .filter(|c| matches!(c.status.as_str(), "Proposed" | "NeedsLiveTest" | "Observed"))
        .filter(|c| candidate_applies_to_repo(c, repo))
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        severity_rank(&b.severity_guess)
            .cmp(&severity_rank(&a.severity_guess))
            .then_with(|| {
                b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.into_iter().take(limit).map(candidate_to_exploration_known_lead).collect()
}

fn candidate_applies_to_repo(candidate: &PentestCandidateRecord, repo: &str) -> bool {
    let repos = candidate
        .affected_components
        .iter()
        .filter_map(|component| {
            component.as_object().and_then(|obj| obj.get("repo")).and_then(|value| value.as_str())
        })
        .collect::<Vec<_>>();
    repos.is_empty() || repos.iter().any(|r| *r == repo)
}

fn candidate_to_exploration_known_lead(candidate: &PentestCandidateRecord) -> ExplorationKnownLead {
    ExplorationKnownLead {
        id: candidate.id.clone(),
        source: candidate.source.clone(),
        title: candidate.title.clone(),
        vuln_class: candidate.vuln_class.clone(),
        severity: candidate.severity_guess.clone(),
        status: candidate.status.clone(),
        location: candidate_location(candidate),
        hypothesis: candidate.hypothesis.clone(),
    }
}

fn candidate_location(candidate: &PentestCandidateRecord) -> Option<String> {
    for component in &candidate.affected_components {
        let Some(obj) = component.as_object() else {
            continue;
        };
        if let Some(url) = obj
            .get("url")
            .or_else(|| obj.get("matched_at"))
            .or_else(|| obj.get("target"))
            .and_then(|value| value.as_str())
        {
            let method = obj.get("method").and_then(|value| value.as_str());
            return Some(match method {
                Some(method) => format!("{} {}", method.to_ascii_uppercase(), url),
                None => url.to_string(),
            });
        }
        if let Some(path) = obj.get("path").and_then(|value| value.as_str()) {
            let repo = obj.get("repo").and_then(|value| value.as_str());
            let line = obj.get("line").and_then(|value| value.as_i64());
            return Some(match (repo, line) {
                (Some(repo), Some(line)) => format!("{repo}:{path}:{line}"),
                (Some(repo), None) => format!("{repo}:{path}"),
                (None, Some(line)) => format!("{path}:{line}"),
                (None, None) => path.to_string(),
            });
        }
    }
    None
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    Some(host_port.to_string())
}

#[allow(clippy::too_many_arguments)]
async fn apply_exploration_outcome(
    store: &Store,
    run_id: &str,
    repo: &str,
    task_id: &str,
    outcome: ExplorationOutcome,
    report: &mut AiExplorationPassReport,
    runtime_name: &str,
    runtime_model: &str,
    started_at_ms: i64,
    traces_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    match outcome {
        ExplorationOutcome::Halted { reason } => match reason {
            ExplorationHaltReason::EscapeSuiteRed { fixture, reason } => {
                tracing::warn!(
                    repo = %repo,
                    fixture = %fixture,
                    reason = %reason,
                    "ai exploration: escape suite RED; halting driver"
                );
                report.halted_escape_suite_red += 1;
            }
            ExplorationHaltReason::BudgetCapAlreadyReached { cap_usd_micros, spent_usd_micros } => {
                tracing::info!(
                    repo = %repo,
                    cap_usd_micros,
                    spent_usd_micros,
                    "ai exploration: run-wide budget cap already reached; skipping repo"
                );
                report.halted_budget_exhausted += 1;
            }
        },
        ExplorationOutcome::Completed {
            findings,
            audit,
            final_message: _final_message,
            turns: _turns,
            spent_usd_micros,
            prompt_version,
            soft_cap_exceeded,
            metrics,
        } => {
            report.explorations_dispatched += 1;
            report.spend_usd_micros += spent_usd_micros;
            if soft_cap_exceeded {
                tracing::info!(
                    repo = %repo,
                    spent_usd_micros,
                    "ai exploration: soft cap exceeded; operator warned, run continues"
                );
            }
            let now_ms = finished_at;
            // Persist the proposed findings first, collecting the ids
            // that survived. The split-cost step below needs the actual
            // success count, not the proposal count.
            let mut successful: Vec<String> = Vec::with_capacity(findings.len());
            for finding in findings {
                match persist_exploration_finding(
                    store,
                    run_id,
                    repo,
                    &finding,
                    &prompt_version,
                    now_ms,
                )
                .await
                {
                    Ok(finding_id) => {
                        report.findings_quarantined += 1;
                        successful.push(finding_id);
                    }
                    Err(err) => {
                        tracing::warn!(
                            repo = %repo,
                            error = %err,
                            "ai exploration: failed to persist finding"
                        );
                    }
                }
            }
            // Split the call cost evenly across emitted findings so the
            // AiTraceViewer's per-finding "Total $..." sums to a real
            // share of the call cost instead of $0. When zero findings
            // survived, keep the cost on the parent row so the run-card
            // roll-up still observes the spend through its time-window
            // join. Token/cache metrics always live on the parent.
            let n_succ = successful.len() as i64;
            let (parent_cost, per_finding_costs): (i64, Vec<i64>) = if n_succ == 0 {
                (spent_usd_micros, Vec::new())
            } else {
                let base = spent_usd_micros / n_succ;
                let leftover = spent_usd_micros - base * n_succ;
                let costs: Vec<i64> =
                    (0..n_succ).map(|i| if i < leftover { base + 1 } else { base }).collect();
                (0, costs)
            };
            let audit_path = if audit.is_empty() {
                None
            } else {
                match write_exploration_audit_jsonl(traces_dir, run_id, task_id, &audit) {
                    Ok(path) => Some(path.to_string_lossy().to_string()),
                    Err(err) => {
                        tracing::warn!(
                            run_id = %run_id,
                            task_id = %task_id,
                            error = %err,
                            "ai exploration: failed to write audit jsonl"
                        );
                        None
                    }
                }
            };
            let mut parent_trace = build_trace_row(
                TaskKind::Exploration,
                None,
                runtime_name,
                runtime_model,
                &prompt_version,
                parent_cost,
                started_at_ms,
                finished_at,
                Some(&metrics),
            );
            parent_trace.conversation_jsonl_path = audit_path;
            persist_trace_row(store, parent_trace).await;
            for (finding_id, cost) in successful.into_iter().zip(per_finding_costs) {
                let per_trace = build_trace_row(
                    TaskKind::Exploration,
                    Some(finding_id),
                    runtime_name,
                    runtime_model,
                    &prompt_version,
                    cost,
                    started_at_ms,
                    finished_at,
                    None,
                );
                persist_trace_row(store, per_trace).await;
            }
        }
    }
    Ok(())
}

/// Persist the exploration audit log as JSONL under
/// `<traces_dir>/<run_id>/<task_id>.jsonl`. One JSON object per line
/// keyed on `action` / `summary`. Returns the absolute path that the
/// caller stamps on `agent_traces.conversation_jsonl_path`.
fn write_exploration_audit_jsonl(
    traces_dir: &std::path::Path,
    run_id: &str,
    task_id: &str,
    audit: &[ExplorationAuditEntry],
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;

    let run_dir = traces_dir.join(run_id);
    std::fs::create_dir_all(&run_dir)?;
    let path = run_dir.join(format!("{task_id}.jsonl"));
    let mut file =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&path)?;
    for entry in audit {
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(path)
}

async fn persist_exploration_finding(
    store: &Store,
    run_id: &str,
    repo: &str,
    finding: &ExplorationFinding,
    prompt_version: &str,
    now_ms: i64,
) -> anyhow::Result<String> {
    let line = finding.line.map(i64::from);
    let rule = format!("ai-exploration:{}", finding.cap);
    let id = nyctos_core::store::finding_id_hash(repo, &finding.path, line, &finding.cap, &rule);
    let verdict_blob = serde_json::to_string(&serde_json::json!({
        "kind": "AiExploration",
        "rationale": finding.rationale,
        "endpoint": finding.endpoint,
        "suggested_payload_hint": finding.suggested_payload_hint,
        "prompt_version": prompt_version,
    }))?;
    let rec = FindingRecord {
        id: id.clone(),
        run_id: run_id.to_string(),
        repo: repo.to_string(),
        path: finding.path.clone(),
        line,
        cap: finding.cap.clone(),
        rule,
        // Severity defaults to High pending verifier promotion; the
        // verifier can downgrade or close the row on `NotConfirmed`.
        severity: "High".to_string(),
        status: "Quarantine".to_string(),
        finding_origin: FindingOrigin::AiExploration.as_str().to_string(),
        first_seen: now_ms,
        last_seen: now_ms,
        superseded_by: None,
        triage_state: "Open".to_string(),
        triage_assigned_to: None,
        verdict_blob: Some(verdict_blob),
        repro_path: None,
        attack_provenance: Some(AttackProvenance::AiExploration.as_str().to_string()),
        prompt_version: Some(prompt_version.to_string()),
        chain_id: None,
        spec_id: None,
    };
    store.findings().upsert(&rec).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use nyctos_core::run::{CrossRepoCallgraphStub, RepoBundle};
    use nyctos_types::verify::{Oracle, VerifyRun, VerifyVerdict};

    use super::*;

    fn fake_verify_run(payload: &[u8], oracle_fired: bool, exit_code: i32) -> VerifyRun {
        VerifyRun {
            payload: payload.to_vec(),
            oracle_fired,
            exit_code,
            timed_out: false,
            stdout: vec![],
            stderr: vec![],
            duration_ms: 1,
        }
    }

    #[test]
    fn live_test_plan_normalises_relative_url_and_requires_oracle() {
        let targets = vec!["http://localhost:8787".to_string()];
        let raw = r#"{"method":"post","path":"/api/search","json":{"q":"nyctos-probe"},"status_range":"2xx","body_contains":"nyctos-probe"}"#;
        let plan = normalise_live_test_plan(raw, &targets).expect("valid").expect("plan");
        assert_eq!(plan["method"], "POST");
        assert_eq!(plan["url"], "http://localhost:8787/api/search");

        let raw_without_oracle = r#"{"method":"GET","path":"/"}"#;
        let err = normalise_live_test_plan(raw_without_oracle, &targets).expect_err("oracle");
        assert!(err.contains("no explicit oracle"));
    }

    #[test]
    fn live_test_plan_rejects_urls_outside_target_base() {
        let targets = vec!["http://localhost:8787".to_string()];
        let raw =
            r#"{"method":"GET","url":"http://localhost:8787.evil.test/","expect_status":200}"#;
        let err = normalise_live_test_plan(raw, &targets).expect_err("outside target");
        assert!(err.contains("outside supplied target"));
    }

    #[test]
    fn verifier_blob_carries_spec_id_and_payload_hashes() {
        let result = VerifyResult {
            finding_id: "f-1".to_string(),
            verdict: VerifyVerdict::Confirmed,
            oracle: Oracle::OutputContains { marker: "x".to_string() },
            vuln_run: fake_verify_run(b"VULN", true, 7),
            benign_run: fake_verify_run(b"BENIGN", false, 0),
            attack_provenance: AttackProvenance::Curated,
            replay_stable: None,
            error_message: None,
        };
        let blob = build_verifier_blob(Some("spec-abc"), Some(&result)).expect("populated");
        let v: serde_json::Value = serde_json::from_str(&blob).expect("json");
        assert_eq!(v["spec_id"], "spec-abc");
        assert_eq!(v["vuln_exit_code"], 7);
        assert_eq!(v["benign_exit_code"], 0);
        // sha256("VULN") = ad9a82ba23ddccd8...
        let vuln = v["vuln_payload_sha256"].as_str().expect("hex string");
        assert_eq!(vuln.len(), 64, "sha256 hex is 64 chars");
        let benign = v["benign_payload_sha256"].as_str().expect("hex string");
        assert_eq!(benign.len(), 64);
        assert_ne!(vuln, benign, "distinct payloads hash distinctly");
    }

    #[test]
    fn verifier_blob_is_none_when_no_inputs() {
        assert!(build_verifier_blob(None, None).is_none());
    }

    #[test]
    fn verifier_blob_with_only_spec_id() {
        let blob = build_verifier_blob(Some("spec-1"), None).expect("populated");
        let v: serde_json::Value = serde_json::from_str(&blob).expect("json");
        assert_eq!(v["spec_id"], "spec-1");
        assert!(v.get("vuln_payload_sha256").is_none());
    }

    fn diag_unsupported(path: &str, line: u32, cap: &str, rule: &str) -> Diag {
        serde_json::from_value(serde_json::json!({
            "path": path,
            "line": line,
            "severity": "High",
            "id": rule,
            "category": cap,
            "evidence": {
                "unsupported": "NoPayloadsForCap",
                "sink": {"callee": "cursor.execute", "args": ["q"]}
            }
        }))
        .unwrap()
    }

    fn diag_supported(path: &str, line: u32, cap: &str, rule: &str) -> Diag {
        serde_json::from_value(serde_json::json!({
            "path": path,
            "line": line,
            "severity": "Low",
            "id": rule,
            "category": cap,
        }))
        .unwrap()
    }

    fn make_bundle(run_id: &str, repo: &str, diags: Vec<Diag>) -> RunBundle<Diag> {
        RunBundle {
            run_id: run_id.to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: vec![RepoBundle {
                repo: repo.to_string(),
                outcome: RepoOutcome::Success(diags),
                started_at_ms: 0,
                finished_at_ms: 0,
                elapsed_ms: 0,
            }],
            callgraph: CrossRepoCallgraphStub::default(),
        }
    }

    fn handle(name: &str, path: &std::path::Path) -> WorkspaceHandle {
        WorkspaceHandle::for_local_path_test(name, path.to_path_buf())
    }

    #[test]
    fn infer_lang_handles_common_extensions() {
        assert_eq!(infer_lang("src/foo.py"), "python");
        assert_eq!(infer_lang("src/bar.ts"), "typescript");
        assert_eq!(infer_lang("Main.JAVA"), "java");
        assert_eq!(infer_lang("noext"), "unknown");
    }

    #[test]
    fn infer_lang_ignores_directory_dots_when_basename_has_no_extension() {
        assert_eq!(infer_lang("path.with.dots/bin/foo"), "unknown");
        assert_eq!(infer_lang("path.with.dots/bin/foo.py"), "python");
    }

    #[test]
    fn infer_lang_for_file_reads_shebang_when_extensionless() {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        std::fs::write(
            bin_dir.join("ingest"),
            "#!/usr/bin/env python3\nimport sys\nprint(sys.argv)\n",
        )
        .unwrap();

        assert_eq!(infer_lang_for_file(tmp.path(), "bin/ingest"), "python");
    }

    #[test]
    fn infer_lang_for_file_recognises_common_interpreters() {
        let tmp = tempfile::tempdir().unwrap();
        for (name, line, expected) in [
            ("py3", "#!/usr/bin/python3", "python"),
            ("node", "#!/usr/bin/env node", "javascript"),
            ("deno", "#!/usr/bin/env deno", "typescript"),
            ("rb", "#!/usr/bin/env ruby", "ruby"),
            ("php", "#!/usr/bin/env php", "php"),
            ("pl", "#!/usr/bin/perl -w", "perl"),
        ] {
            std::fs::write(tmp.path().join(name), format!("{line}\n# rest")).unwrap();
            assert_eq!(infer_lang_for_file(tmp.path(), name), expected, "shebang `{line}`");
        }
    }

    #[test]
    fn infer_lang_for_file_does_not_overwrite_a_recognised_extension() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.py"), "#!/usr/bin/env ruby\nputs 'x'\n").unwrap();
        // The .py extension wins; we do not re-read the file when the
        // extension table already produces a non-`unknown` answer.
        assert_eq!(infer_lang_for_file(tmp.path(), "foo.py"), "python");
    }

    #[test]
    fn infer_lang_for_file_returns_unknown_when_shebang_interp_is_unrecognised() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("oddball"), "#!/usr/bin/env mystery\n").unwrap();
        assert_eq!(infer_lang_for_file(tmp.path(), "oddball"), "unknown");
    }

    #[test]
    fn infer_lang_for_file_returns_unknown_when_file_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(infer_lang_for_file(tmp.path(), "ghost"), "unknown");
    }

    #[test]
    fn build_inputs_filters_to_unsupported_only() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.py"), "x = 1\ny = 2\nz = 3\n").unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-1".to_string(), handle("repo-1", tmp.path()));

        let bundle = make_bundle(
            "run-X",
            "repo-1",
            vec![
                diag_unsupported("a.py", 2, "SQL_QUERY", "rule-a"),
                diag_supported("a.py", 3, "SQL_QUERY", "rule-b"),
            ],
        );

        let inputs = build_inputs(&bundle, &workspaces);
        assert_eq!(inputs.len(), 1, "only the unsupported diag should fan out");
        assert_eq!(inputs[0].cap, "SQL_QUERY");
        assert_eq!(inputs[0].lang, "python");
        assert_eq!(inputs[0].run_id, "run-X");
        assert_eq!(inputs[0].sink_ctx.callee, "cursor.execute");
    }

    #[test]
    fn build_inputs_skips_failed_repos() {
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: vec![RepoBundle {
                repo: "broken".to_string(),
                outcome: RepoOutcome::Failed("scanner crashed".to_string()),
                started_at_ms: 0,
                finished_at_ms: 0,
                elapsed_ms: 0,
            }],
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let inputs = build_inputs(&bundle, &workspaces);
        assert!(inputs.is_empty());
    }

    #[tokio::test]
    async fn budget_store_tracker_creates_row_lazily_and_records_spend() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        // Seed a run row; budgets FK requires it.
        let run = nyctos_core::store::RunRecord {
            id: "run-bt".to_string(),
            project_id: None,
            kind: "Scan".to_string(),
            started_at: 0,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        };
        store.runs().insert(&run).await.unwrap();

        let tracker = BudgetStoreTracker::new(store.clone(), 1_000_000);
        let cap = tracker.cap("run-bt", BudgetKind::OneShot).await.unwrap();
        assert_eq!(cap, Some(1_000_000));

        let after_a = tracker.add_spend("run-bt", BudgetKind::OneShot, 2_500).await.unwrap();
        let after_b = tracker.add_spend("run-bt", BudgetKind::OneShot, 1_000).await.unwrap();
        assert_eq!(after_a, 2_500);
        assert_eq!(after_b, 3_500);

        // Row was persisted via the public store API.
        let row = store.budgets().get("run-bt", "OneShot").await.unwrap().expect("row");
        assert_eq!(row.cap_usd_micros, 1_000_000);
        assert_eq!(row.spent_usd_micros, 3_500);
    }

    #[tokio::test]
    async fn budget_tracker_concurrent_ensure_row_preserves_spend() {
        // Regression: concurrent ensure_row calls used to clobber
        // spent_usd_micros to 0 via upsert's DO UPDATE clause; the
        // INSERT OR IGNORE path keeps spend from prior add_spend calls
        // intact even when a peer task fans in just after.
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let run = nyctos_core::store::RunRecord {
            id: "run-cc".to_string(),
            project_id: None,
            kind: "Scan".to_string(),
            started_at: 0,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        };
        store.runs().insert(&run).await.unwrap();
        let tracker = Arc::new(BudgetStoreTracker::new(store.clone(), 1_000_000));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let t = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                let _ = t.cap("run-cc", BudgetKind::OneShot).await.unwrap();
                t.add_spend("run-cc", BudgetKind::OneShot, 1_000).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let row = store.budgets().get("run-cc", "OneShot").await.unwrap().expect("row");
        assert_eq!(row.spent_usd_micros, 8_000, "every concurrent add_spend must persist");
        assert_eq!(row.cap_usd_micros, 1_000_000);
    }

    #[tokio::test]
    async fn run_pass_is_noop_when_runtime_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig::default();
        assert!(matches!(cfg.runtime, ConfigAiRuntime::None));
        let report = run_payload_synthesis_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, PayloadSynthesisPassReport::default());
    }

    #[tokio::test]
    async fn run_pass_is_noop_when_anthropic_but_no_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig { runtime: ConfigAiRuntime::Anthropic, ..AiConfig::default() };
        let report = run_payload_synthesis_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, PayloadSynthesisPassReport::default());
    }

    #[tokio::test]
    async fn deterministic_live_plan_synthesis_plans_reclassified_nyx_candidate_without_ai() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.projects().create("project-live", "Live", None, None, None, 1).await.unwrap();
        store
            .runs()
            .insert(&nyctos_core::store::RunRecord {
                id: "run-live".to_string(),
                project_id: Some("project-live".to_string()),
                kind: "Scan".to_string(),
                started_at: 1,
                finished_at: None,
                status: "Running".to_string(),
                triggered_by: "Manual".to_string(),
                git_ref: None,
                parent_run_id: None,
                wall_clock_ms: None,
                total_ai_spend_usd_micros: 0,
            })
            .await
            .unwrap();
        store
            .pentest_candidates()
            .insert(&PentestCandidateRecord {
                id: "pc-nyx-open-redirect".to_string(),
                run_id: "run-live".to_string(),
                project_id: "project-live".to_string(),
                source: "NyxSignal".to_string(),
                source_ids: vec!["sig-nyx-open-redirect".to_string()],
                title: "Potential open redirect: /login/callback via `next`".to_string(),
                vuln_class: "OPEN_REDIRECT".to_string(),
                severity_guess: "Medium".to_string(),
                affected_components: vec![serde_json::json!({
                    "kind": "nyx_signal",
                    "path": "src/auth/callback.ts",
                    "route": "/login/callback",
                    "url_path": "/login/callback",
                    "method": "GET",
                    "param": "next",
                    "sink": "redirect",
                    "nyx_signal_id": "sig-nyx-open-redirect",
                    "cap": "Security",
                    "rule": "taint-unsanitised-flow",
                })],
                hypothesis: "Nyctos reclassified the generic Nyx signal as OPEN_REDIRECT."
                    .to_string(),
                test_plan:
                    "Derive a live HTTP/browser test from the affected route before confirmation."
                        .to_string(),
                status: "NeedsLiveTest".to_string(),
                rejection_reason: None,
                confidence: 0.7,
                trace_id: None,
                created_at: 2,
                updated_at: 2,
            })
            .await
            .unwrap();
        let bundle = RunBundle::<Diag> {
            run_id: "run-live".to_string(),
            project_id: "project-live".to_string(),
            started_at_ms: 1,
            finished_at_ms: 2,
            wall_clock_ms: 1,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let secrets = SecretStore::memory();
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let (tx, _rx) = tokio::sync::broadcast::channel(4);

        let report = run_live_test_plan_synthesis_pass(
            &AiConfig::default(),
            &store,
            &secrets,
            &bundle,
            &workspaces,
            &targets,
            None,
            &auth,
            false,
            false,
            None,
            tx,
        )
        .await
        .unwrap();

        assert_eq!(report.candidates_seen, 1);
        assert_eq!(report.planned, 1);
        assert_eq!(report.no_plan, 0);
        assert_eq!(report.attempts, 0, "deterministic plan should avoid AI");
        let updated = store.pentest_candidates().list_by_run("run-live").await.unwrap();
        assert_eq!(updated[0].status, "Proposed");
        let plan = normalise_live_test_plan(&updated[0].test_plan, &targets).unwrap().unwrap();
        assert_eq!(plan["kind"], "single_http");
        assert!(plan["url"].as_str().unwrap().contains("next="));
    }

    // -------- spec-derivation pass coverage --------

    fn diag_spec_failed(
        path: &str,
        line: u32,
        cap: &str,
        rule: &str,
        flow_files: &[(&str, u32)],
    ) -> Diag {
        let mut steps: Vec<serde_json::Value> = Vec::new();
        for (i, (f, l)) in flow_files.iter().enumerate() {
            steps.push(serde_json::json!({
                "step": i + 1,
                "kind": if i == 0 { "source" } else { "call" },
                "file": f,
                "line": l,
            }));
        }
        // Final sink step.
        steps.push(serde_json::json!({
            "step": flow_files.len() + 1,
            "kind": "sink",
            "file": path,
            "line": line,
        }));
        let mut diag: Diag = serde_json::from_value(serde_json::json!({
            "path": path,
            "line": line,
            "severity": "Medium",
            "id": rule,
            "category": cap,
            "evidence": {
                "inconclusive": "SpecDerivationFailed",
                "sink": {"callee": "cursor.execute", "args": ["q"]},
                "flow_steps": steps,
            }
        }))
        .unwrap();
        diag.lift_flow_steps();
        diag
    }

    #[test]
    fn build_spec_inputs_filters_and_attaches_excerpts() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("sink.py"),
            "1\n2\n3\n4\ncursor.execute('SELECT * FROM u WHERE n=' + q)\n6\n7\n",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("framework")).unwrap();
        std::fs::write(tmp.path().join("framework/orm.py"), "a\nb\nc\nd\n").unwrap();
        std::fs::write(tmp.path().join("router.py"), "r1\nr2\nr3\nr4\n").unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-1".to_string(), handle("repo-1", tmp.path()));

        let diag = diag_spec_failed(
            "sink.py",
            5,
            "SQL_QUERY",
            "rule-spec",
            &[("router.py", 2), ("framework/orm.py", 3)],
        );
        let skipped = diag_supported("sink.py", 6, "SQL_QUERY", "rule-ok");
        let bundle = make_bundle("run-S", "repo-1", vec![diag, skipped]);

        let inputs = build_spec_inputs(&bundle, &workspaces);
        assert_eq!(inputs.len(), 1, "only the SpecDerivationFailed diag fans out");
        let input = &inputs[0];
        assert_eq!(input.cap, "SQL_QUERY");
        assert_eq!(input.lang, "python");
        assert_eq!(input.callee, "cursor.execute");
        // sink first, then call_site (router.py), then framework (orm.py).
        let kinds: Vec<&str> = input.excerpts.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["sink", "call_site", "framework"]);
        assert_eq!(input.excerpts[0].path, "sink.py");
        assert!(input.excerpts[0].body.contains("cursor.execute"));
        assert_eq!(input.excerpts[1].path, "router.py");
        assert_eq!(input.excerpts[2].path, "framework/orm.py");
        assert!(input.excerpts.len() <= SPEC_DERIVATION_MAX_EXCERPTS);
    }

    #[test]
    fn build_spec_inputs_skips_failed_repos() {
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: vec![RepoBundle {
                repo: "broken".to_string(),
                outcome: RepoOutcome::Failed("scanner crashed".to_string()),
                started_at_ms: 0,
                finished_at_ms: 0,
                elapsed_ms: 0,
            }],
            callgraph: CrossRepoCallgraphStub::default(),
        };
        assert!(build_spec_inputs(&bundle, &workspaces).is_empty());
    }

    #[tokio::test]
    async fn spec_pass_is_noop_when_runtime_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig::default();
        let report = run_spec_derivation_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, SpecDerivationPassReport::default());
    }

    #[tokio::test]
    async fn spec_pass_is_noop_when_anthropic_but_no_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig { runtime: ConfigAiRuntime::Anthropic, ..AiConfig::default() };
        let report = run_spec_derivation_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, SpecDerivationPassReport::default());
    }

    fn seed_run(id: &str) -> nyctos_core::store::RunRecord {
        nyctos_core::store::RunRecord {
            id: id.to_string(),
            project_id: None,
            kind: "Scan".to_string(),
            started_at: 0,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        }
    }

    fn seed_repo(name: &str) -> nyctos_core::store::RepoRecord {
        nyctos_core::store::RepoRecord {
            id: format!("repo-default-{name}"),
            name: name.to_string(),
            project_id: nyctos_core::store::DEFAULT_PROJECT_ID.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: format!("/tmp/{name}"),
            branch: Some("main".to_string()),
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: 1_000,
            updated_at: 1_000,
        }
    }

    fn seed_finding(
        run_id: &str,
        repo: &str,
        path: &str,
        rule: &str,
    ) -> nyctos_core::store::FindingRecord {
        let id = nyctos_core::store::finding_id_hash(repo, path, Some(10), "SQL_QUERY", rule);
        nyctos_core::store::FindingRecord {
            id,
            run_id: run_id.to_string(),
            repo: repo.to_string(),
            path: path.to_string(),
            line: Some(10),
            cap: "SQL_QUERY".to_string(),
            rule: rule.to_string(),
            severity: "High".to_string(),
            status: "Open".to_string(),
            finding_origin: "Static".to_string(),
            first_seen: 3_000,
            last_seen: 3_000,
            superseded_by: None,
            triage_state: "Open".to_string(),
            triage_assigned_to: None,
            verdict_blob: None,
            repro_path: None,
            attack_provenance: None,
            prompt_version: None,
            chain_id: None,
            spec_id: None,
        }
    }

    #[tokio::test]
    async fn apply_spec_outcome_persists_record_and_stamps_finding() {
        // Acceptance: a finding whose strategies all failed in nyx now
        // produces a usable spec, which the store materialises so the
        // verifier can consume it.
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-S")).await.unwrap();
        store.runs().insert(&seed_run("run-S")).await.unwrap();
        let finding = seed_finding("run-S", "repo-S", "src/sink.py", "rule-spec");
        let fid = finding.id.clone();
        store.findings().upsert(&finding).await.unwrap();

        let body = serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "python",
            "entry": "app.handlers:run_query",
            "invoke": "db.execute('SELECT * FROM users WHERE n=' + @PAYLOAD)",
            "payload_arg": 0,
            "oracle": "row count > 0",
        })
        .to_string();
        let (spec, canonical) = nyctos_nyx::HarnessSpec::from_json(&body).unwrap();
        let outcome = SpecDerivationOutcome::Synthesised {
            finding_id: fid.clone(),
            cap: "SQL_QUERY".to_string(),
            lang: "python".to_string(),
            spec: Box::new(spec),
            spec_blob: canonical,
            prompt_version: nyctos_types::spec::SPEC_DERIVATION_PROMPT_VERSION.to_string(),
            spent_usd_micros: 3_500,
            attempts: 1,
            metrics: AgentTraceMetrics::default(),
        };
        let mut report = SpecDerivationPassReport::default();
        apply_spec_outcome(&store, outcome, &mut report, "test-runtime", "test-model", 0)
            .await
            .unwrap();
        assert_eq!(report.synthesised, 1);
        assert_eq!(report.spend_usd_micros, 3_500);

        let updated = store.findings().get(&fid).await.unwrap().expect("finding");
        assert_eq!(updated.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(updated.prompt_version.as_deref(), Some("phase15.spec_derivation.v1"));
        // Spec row exists and round-trips through the vendored schema.
        let specs = store.harness_specs().list_by_cap("SQL_QUERY").await.unwrap();
        assert_eq!(specs.len(), 1);
        let (parsed, _) = nyctos_nyx::HarnessSpec::from_json(&specs[0].spec_blob).unwrap();
        parsed.validate().expect("vendored schema accepts persisted blob");
        assert_eq!(specs[0].attack_provenance.as_deref(), Some("LlmSynthesised"));
    }

    #[tokio::test]
    async fn apply_spec_outcome_quarantines_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-Q")).await.unwrap();
        store.runs().insert(&seed_run("run-Q")).await.unwrap();
        let finding = seed_finding("run-Q", "repo-Q", "src/sink.py", "rule-bad");
        let fid = finding.id.clone();
        store.findings().upsert(&finding).await.unwrap();

        let outcome = SpecDerivationOutcome::Quarantined {
            finding_id: fid.clone(),
            reason: "spec derivation failed twice (attempt 1: ...; attempt 2: ...)".to_string(),
            spent_usd_micros: 1_200,
            attempts: 2,
            metrics: AgentTraceMetrics::default(),
        };
        let mut report = SpecDerivationPassReport::default();
        apply_spec_outcome(&store, outcome, &mut report, "test-runtime", "test-model", 0)
            .await
            .unwrap();
        assert_eq!(report.quarantined, 1);
        let row = store.findings().get(&fid).await.unwrap().expect("finding");
        assert_eq!(row.status, "Quarantine");
        let blob = row.verdict_blob.unwrap();
        assert!(blob.contains("SpecDerivation"), "blob: {blob}");
        assert!(blob.contains("failed twice"));
    }

    #[tokio::test]
    async fn spec_derivation_end_to_end_through_build_run_apply() {
        // Acceptance: a real Diag carrying Inconclusive(SpecDerivationFailed)
        // travels build_spec_inputs -> run_spec_derivation (scripted runtime)
        // -> apply_spec_outcome, lands a `harness_specs` row, and stamps
        // the parent `findings.spec_id` back-link. Pins the seam the per-half
        // unit tests already cover in isolation.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-E2E")).await.unwrap();
        store.runs().insert(&seed_run("run-E2E")).await.unwrap();
        let seed = seed_finding("run-E2E", "repo-E2E", "sink.py", "rule-e2e-spec");
        let fid = seed.id.clone();
        store.findings().upsert(&seed).await.unwrap();
        assert!(seed.spec_id.is_none(), "seed finding starts with no spec back-link");

        // Workspace lays out a sink whose `line: 10` matches seed_finding's
        // BLAKE3-keyed line, plus one flow-step file the excerpt collector
        // attaches as `call_site`.
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace.path().join("sink.py"),
            "import sqlite3\ndb = sqlite3.connect(':memory:')\n\
             # padding\n# padding\n# padding\n# padding\n# padding\n# padding\n# padding\n\
             cursor.execute('SELECT * FROM users WHERE n=' + q)\n",
        )
        .unwrap();
        std::fs::write(workspace.path().join("router.py"), "def route(q):\n    handler(q)\n")
            .unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-E2E".to_string(),
            WorkspaceHandle::for_local_path_test("repo-E2E", workspace.path().to_path_buf()),
        );

        let diag =
            diag_spec_failed("sink.py", 10, "SQL_QUERY", "rule-e2e-spec", &[("router.py", 2)]);
        let bundle = make_bundle("run-E2E", "repo-E2E", vec![diag]);

        let inputs = build_spec_inputs(&bundle, &workspaces);
        assert_eq!(inputs.len(), 1, "the SpecDerivationFailed diag must fan out");
        assert_eq!(inputs[0].finding_id, fid, "input finding_id must match seeded row");
        assert_eq!(inputs[0].cap, "SQL_QUERY");
        assert_eq!(inputs[0].lang, "python");

        let body = serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "python",
            "entry": "app.handlers:run_query",
            "setup": ["import sqlite3", "db = sqlite3.connect(':memory:')"],
            "invoke": "db.execute('SELECT * FROM users WHERE n=' + @PAYLOAD)",
            "payload_arg": 0,
            "oracle": "row count > 0",
            "teardown": ["db.close()"],
        })
        .to_string();
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-E2E", BudgetKind::OneShot, 5_000_000);
        let runtime = ScriptedNovelRuntime::new(vec![Ok(body)], 4_200, tracker.clone());

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let outcome = nyctos_ai::run_spec_derivation(&runtime, &inputs[0], tx, 5_000_000)
            .await
            .expect("scripted runtime produces a synthesised outcome");

        let mut report = SpecDerivationPassReport::default();
        apply_spec_outcome(&store, outcome, &mut report, "scripted-novel", "scripted-model", 0)
            .await
            .unwrap();
        assert_eq!(report.synthesised, 1);
        assert_eq!(report.quarantined, 0);
        assert_eq!(report.failed, 0);

        let specs = store.harness_specs().list_by_cap("SQL_QUERY").await.unwrap();
        assert_eq!(specs.len(), 1, "exactly one harness_specs row persisted");
        let spec_row = &specs[0];
        assert_eq!(spec_row.cap, "SQL_QUERY");
        assert_eq!(spec_row.lang, "python");
        assert_eq!(spec_row.attack_provenance.as_deref(), Some("LlmSynthesised"));
        let (parsed, _) = nyctos_nyx::HarnessSpec::from_json(&spec_row.spec_blob).unwrap();
        parsed.validate().expect("vendored schema accepts persisted blob");

        let updated = store.findings().get(&fid).await.unwrap().expect("finding");
        assert_eq!(
            updated.spec_id.as_deref(),
            Some(spec_row.id.as_str()),
            "findings.spec_id must back-link to the persisted harness_specs row"
        );
        assert_eq!(updated.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(updated.prompt_version.as_deref(), Some(SPEC_DERIVATION_PROMPT_VERSION));
    }

    #[tokio::test]
    async fn payload_synthesis_end_to_end_through_build_run_apply() {
        // Acceptance: a real Diag carrying Unsupported(NoPayloadsForCap)
        // travels build_inputs -> run_payload_synthesis (scripted runtime)
        // -> apply_outcome, lands a `payloads` row keyed to the seeded
        // finding with `attack_provenance = LlmSynthesised`, and stamps
        // the parent finding's provenance + prompt_version columns.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-P")).await.unwrap();
        store.runs().insert(&seed_run("run-P")).await.unwrap();
        let seed = seed_finding("run-P", "repo-P", "sink.py", "rule-e2e-payload");
        let fid = seed.id.clone();
        store.findings().upsert(&seed).await.unwrap();
        assert!(seed.attack_provenance.is_none(), "seed finding starts with no AI provenance");

        // Workspace with a python file at line 10 to match seed_finding's
        // BLAKE3-keyed line.
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace.path().join("sink.py"),
            "import sqlite3\n# pad\n# pad\n# pad\n# pad\n# pad\n# pad\n# pad\n# pad\n\
             cursor.execute('SELECT * FROM users WHERE n=' + q)\n",
        )
        .unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-P".to_string(),
            WorkspaceHandle::for_local_path_test("repo-P", workspace.path().to_path_buf()),
        );

        let diag = diag_unsupported("sink.py", 10, "SQL_QUERY", "rule-e2e-payload");
        let bundle = make_bundle("run-P", "repo-P", vec![diag]);

        let inputs = build_inputs(&bundle, &workspaces);
        assert_eq!(inputs.len(), 1, "the unsupported diag must fan out");
        assert_eq!(inputs[0].finding_id, fid, "input finding_id must match seeded row");
        assert_eq!(inputs[0].cap, "SQL_QUERY");
        assert_eq!(inputs[0].lang, "python");

        let body = serde_json::json!({
            "vuln_payload": "' OR 1=1 --",
            "vuln_oracle": "row count > 0 OR error contains 'SQL'",
            "benign_payload": "alice",
        })
        .to_string();
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-P", BudgetKind::OneShot, 5_000_000);
        let runtime = ScriptedNovelRuntime::new(vec![Ok(body)], 6_400, tracker.clone());

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let outcome = nyctos_ai::run_payload_synthesis(&runtime, &inputs[0], tx, 5_000_000)
            .await
            .expect("scripted runtime produces a synthesised payload");

        let mut report = PayloadSynthesisPassReport::default();
        apply_outcome(&store, outcome, &mut report, "scripted-novel", "scripted-model", 0)
            .await
            .unwrap();
        assert_eq!(report.synthesised, 1);
        assert_eq!(report.quarantined, 0);

        let payloads = store.payloads().list_for_finding(&fid).await.unwrap();
        assert_eq!(payloads.len(), 1, "exactly one payloads row persisted");
        let row = &payloads[0];
        assert_eq!(row.finding_id, fid);
        assert_eq!(row.cap, "SQL_QUERY");
        assert_eq!(row.lang, "python");
        assert_eq!(row.vuln_bytes, b"' OR 1=1 --");
        assert_eq!(row.benign_bytes.as_deref(), Some(b"alice".as_ref()));
        assert_eq!(row.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(
            row.prompt_version.as_deref(),
            Some(nyctos_types::payload::PAYLOAD_SYNTHESIS_PROMPT_VERSION)
        );

        let updated = store.findings().get(&fid).await.unwrap().expect("finding");
        assert_eq!(
            updated.attack_provenance.as_deref(),
            Some("LlmSynthesised"),
            "finding's provenance must be stamped by the dual-write"
        );
        assert_eq!(
            updated.prompt_version.as_deref(),
            Some(nyctos_types::payload::PAYLOAD_SYNTHESIS_PROMPT_VERSION)
        );
    }

    // -------- chain-reasoning pass coverage --------

    fn diag_with_flow_step(
        path: &str,
        line: u32,
        cap: &str,
        rule: &str,
        flow: &[(&str, u32, &str)],
    ) -> Diag {
        let mut steps: Vec<serde_json::Value> = Vec::new();
        for (i, (f, l, k)) in flow.iter().enumerate() {
            steps.push(serde_json::json!({
                "step": i + 1,
                "kind": k,
                "file": f,
                "line": l,
            }));
        }
        let mut diag: Diag = serde_json::from_value(serde_json::json!({
            "path": path,
            "line": line,
            "severity": "High",
            "id": rule,
            "category": cap,
            "evidence": {
                "flow_steps": steps,
            },
        }))
        .unwrap();
        diag.lift_flow_steps();
        diag
    }

    fn two_repo_bundle() -> RunBundle<Diag> {
        // repo-A controller (entry, has a `source` flow_step) reaches
        // repo-B sink. The sink's flow_step points at the controller's
        // (path, line) tuple in repo-A, so the graph builder produces a
        // cross-repo `Reaches` edge.
        let entry = diag_with_flow_step(
            "controller.py",
            5,
            "SQL_QUERY",
            "rule-entry",
            &[("controller.py", 5, "source")],
        );
        let sink = diag_with_flow_step(
            "db.py",
            42,
            "SQL_QUERY",
            "rule-sink",
            &[("controller.py", 5, "call"), ("db.py", 42, "sink")],
        );
        RunBundle {
            run_id: "run-X".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: vec![
                RepoBundle {
                    repo: "repo-A".to_string(),
                    outcome: RepoOutcome::Success(vec![entry]),
                    started_at_ms: 0,
                    finished_at_ms: 0,
                    elapsed_ms: 0,
                },
                RepoBundle {
                    repo: "repo-B".to_string(),
                    outcome: RepoOutcome::Success(vec![sink]),
                    started_at_ms: 0,
                    finished_at_ms: 0,
                    elapsed_ms: 0,
                },
            ],
            callgraph: CrossRepoCallgraphStub::default(),
        }
    }

    #[test]
    fn build_chain_input_emits_cross_repo_edge() {
        let bundle = two_repo_bundle();
        let input = build_chain_input(&bundle).expect("graph");
        assert_eq!(input.run_id, "run-X");
        assert_eq!(input.repos, vec!["repo-A".to_string(), "repo-B".to_string()]);
        assert_eq!(input.nodes.len(), 2);
        // Entry node classification picks up the `source` flow_step.
        let entry_node = input.nodes.iter().find(|n| n.repo == "repo-A").expect("entry");
        assert_eq!(entry_node.kind, NODE_KIND_ENTRY);
        let sink_node = input.nodes.iter().find(|n| n.repo == "repo-B").expect("sink");
        assert_eq!(sink_node.kind, NODE_KIND_SINK);
        // One cross-repo edge: entry -> sink.
        let cross: Vec<_> = input.edges.iter().filter(|e| e.cross_repo).collect();
        assert_eq!(cross.len(), 1, "edges: {:?}", input.edges);
        assert_eq!(cross[0].from, entry_node.id);
        assert_eq!(cross[0].to, sink_node.id);
        assert_eq!(cross[0].label, "Reaches");
    }

    #[test]
    fn build_chain_input_classifies_framework_path() {
        let mut bundle = two_repo_bundle();
        // Replace the entry diag with one whose path looks like a
        // vendored framework binding.
        let fw = diag_with_flow_step(
            "vendor/orm/query.py",
            10,
            "SQL_QUERY",
            "rule-fw",
            &[("vendor/orm/query.py", 10, "call")],
        );
        bundle.per_repo[0].outcome = RepoOutcome::Success(vec![fw]);
        let input = build_chain_input(&bundle).expect("graph");
        let node = input.nodes.iter().find(|n| n.repo == "repo-A").expect("fw");
        assert_eq!(node.kind, NODE_KIND_FRAMEWORK);
    }

    #[test]
    fn build_chain_input_returns_none_below_two_nodes() {
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: vec![RepoBundle {
                repo: "repo-A".to_string(),
                outcome: RepoOutcome::Success(vec![diag_with_flow_step(
                    "a.py",
                    1,
                    "SQL_QUERY",
                    "rule-1",
                    &[],
                )]),
                started_at_ms: 0,
                finished_at_ms: 0,
                elapsed_ms: 0,
            }],
            callgraph: CrossRepoCallgraphStub::default(),
        };
        assert!(build_chain_input(&bundle).is_none());
    }

    #[tokio::test]
    async fn apply_chain_outcome_persists_cross_repo_chain() {
        // Acceptance: a two-repo run with controller-in-repo-A
        // reaches-sink-in-repo-B fixture produces at least one cross-repo
        // chain row, with rationale stored and members back-linked.
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-A")).await.unwrap();
        store.repos().upsert(&seed_repo("repo-B")).await.unwrap();
        store.runs().insert(&seed_run("run-X")).await.unwrap();
        let bundle = two_repo_bundle();
        let input = build_chain_input(&bundle).expect("graph");

        // Seed the two finding rows the chain will link.
        let entry_node = input.nodes.iter().find(|n| n.repo == "repo-A").unwrap().clone();
        let sink_node = input.nodes.iter().find(|n| n.repo == "repo-B").unwrap().clone();
        for n in [&entry_node, &sink_node] {
            let f = nyctos_core::store::FindingRecord {
                id: n.id.clone(),
                run_id: "run-X".to_string(),
                repo: n.repo.clone(),
                path: n.path.clone(),
                line: n.line.map(i64::from),
                cap: n.cap.clone(),
                rule: n.rule.clone(),
                severity: n.severity.clone(),
                status: "Open".to_string(),
                finding_origin: "Static".to_string(),
                first_seen: 1_000,
                last_seen: 1_000,
                superseded_by: None,
                triage_state: "Open".to_string(),
                triage_assigned_to: None,
                verdict_blob: None,
                repro_path: None,
                attack_provenance: None,
                prompt_version: None,
                chain_id: None,
                spec_id: None,
            };
            store.findings().upsert(&f).await.unwrap();
        }

        let output = nyctos_types::chain::ChainReasoningOutput {
            chains: vec![nyctos_types::chain::ChainCandidate {
                member_ids: vec![entry_node.id.clone(), sink_node.id.clone()],
                rationale: "controller in repo-A reaches SQL sink in repo-B".to_string(),
            }],
        };
        let outcome = ChainReasoningOutcome::Ranked {
            run_id: "run-X".to_string(),
            output,
            prompt_version: nyctos_types::chain::CHAIN_REASONING_PROMPT_VERSION.to_string(),
            spent_usd_micros: 12_000,
            attempts: 1,
            metrics: AgentTraceMetrics::default(),
        };
        let mut report = ChainReasoningPassReport::default();
        apply_chain_outcome(&store, &input, outcome, &mut report, "test-runtime", "test-model", 0)
            .await
            .unwrap();
        assert_eq!(report.chains_persisted, 1);
        assert_eq!(report.cross_repo_chains, 1);
        assert_eq!(report.members_stamped, 2);
        assert_eq!(report.spend_usd_micros, 12_000);

        // Chain row landed with cross_repo + LlmSynthesised provenance.
        let chains = store.chains().list_by_run("run-X").await.unwrap();
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert!(c.cross_repo);
        assert_eq!(c.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(
            c.prompt_version.as_deref(),
            Some(nyctos_types::chain::CHAIN_REASONING_PROMPT_VERSION),
        );
        let rationale = c.rationale_blob.as_deref().unwrap();
        assert!(rationale.contains("controller in repo-A"), "rationale: {rationale}");
        let members: Vec<String> = serde_json::from_str(&c.member_ids).unwrap();
        assert_eq!(members, vec![entry_node.id.clone(), sink_node.id.clone()]);

        // Both findings have chain_id back-link stamped.
        let entry_row = store.findings().get(&entry_node.id).await.unwrap().unwrap();
        let sink_row = store.findings().get(&sink_node.id).await.unwrap().unwrap();
        assert_eq!(entry_row.chain_id.as_deref(), Some(c.id.as_str()));
        assert_eq!(sink_row.chain_id.as_deref(), Some(c.id.as_str()));
    }

    #[tokio::test]
    async fn apply_chain_outcome_handles_no_chains_without_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.runs().insert(&seed_run("run-X")).await.unwrap();
        let input = nyctos_types::chain::ChainReasoningInput {
            run_id: "run-X".to_string(),
            repos: vec!["repo-A".to_string()],
            nodes: vec![],
            edges: vec![],
            max_chains: 10,
        };
        let outcome = ChainReasoningOutcome::NoChains {
            run_id: "run-X".to_string(),
            reason: "chain reasoning failed twice (...; ...)".to_string(),
            spent_usd_micros: 1_000,
            attempts: 2,
            metrics: AgentTraceMetrics::default(),
        };
        let mut report = ChainReasoningPassReport::default();
        apply_chain_outcome(&store, &input, outcome, &mut report, "test-runtime", "test-model", 0)
            .await
            .unwrap();
        assert_eq!(report.chains_persisted, 0);
        assert_eq!(report.cross_repo_chains, 0);
        assert_eq!(report.members_stamped, 0);
        assert_eq!(report.attempts, 2);
        assert_eq!(report.spend_usd_micros, 1_000);
        assert!(store.chains().list_by_run("run-X").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn chain_pass_is_noop_when_runtime_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = two_repo_bundle();
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig::default();
        let report = run_chain_reasoning_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, ChainReasoningPassReport::default());
    }

    #[tokio::test]
    async fn chain_pass_is_noop_when_anthropic_but_no_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = two_repo_bundle();
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig { runtime: ConfigAiRuntime::Anthropic, ..AiConfig::default() };
        let report = run_chain_reasoning_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
            .await
            .unwrap();
        assert_eq!(report, ChainReasoningPassReport::default());
    }

    // -------- novel-finding-discovery pass coverage --------

    use nyctos_ai::{AiRuntime, InMemoryBudgetTracker};
    use nyctos_types::agent::{
        AgentResult, AgentTask, Budget, CacheStats, CostEstimate, Prompt, Response, TokenUsage,
    };
    use std::sync::Mutex as StdMutex;

    /// Scripted runtime mirroring the per-task fixtures. Each `one_shot`
    /// pops the next response from the back of the queue.
    struct ScriptedNovelRuntime {
        responses: StdMutex<Vec<Result<String, AiError>>>,
        cost_per_call: i64,
        tracker: Arc<dyn BudgetTracker>,
    }

    impl ScriptedNovelRuntime {
        fn new(
            responses: Vec<Result<String, AiError>>,
            cost_per_call: i64,
            tracker: Arc<dyn BudgetTracker>,
        ) -> Self {
            Self { responses: StdMutex::new(responses), cost_per_call, tracker }
        }
    }

    #[async_trait]
    impl AiRuntime for ScriptedNovelRuntime {
        fn name(&self) -> &'static str {
            "scripted-novel"
        }
        fn default_model(&self) -> &str {
            "scripted-model"
        }
        fn supports_agent_loop(&self) -> bool {
            false
        }
        fn supports_prompt_cache(&self) -> bool {
            false
        }
        fn supports_deterministic_sampling(&self) -> bool {
            true
        }

        async fn one_shot(
            &self,
            prompt: Prompt,
            budget: Budget,
            _sink: nyctos_types::event::EventSink,
        ) -> Result<Response, AiError> {
            let next = self
                .responses
                .lock()
                .unwrap()
                .pop()
                .expect("scripted novel runtime: no more responses");
            let content = next?;
            let cost = self.cost_per_call;
            self.tracker.add_spend(&budget.run_id, budget.kind, cost).await?;
            Ok(Response {
                prompt_version: prompt.prompt_version,
                task_id: prompt.task_id,
                model: "scripted-model".to_string(),
                content,
                usage: TokenUsage { input_tokens: 500, output_tokens: 200 },
                cache: Some(CacheStats::default()),
                cost_usd_micros: cost,
            })
        }

        async fn agent_loop(
            &self,
            _task: AgentTask,
            _budget: Budget,
            _sink: nyctos_types::event::EventSink,
        ) -> Result<AgentResult, AiError> {
            Err(AiError::UnsupportedMode("agent_loop"))
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            Some(CostEstimate { min_usd_micros: 0, max_usd_micros: self.cost_per_call })
        }
    }

    fn two_python_workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("app")).unwrap();
        std::fs::create_dir_all(tmp.path().join("models")).unwrap();
        // handlers.py: line 3 is the known SQL sink (the prior), line 6
        // is the intentionally similar second sink the agent should
        // flag.
        std::fs::write(
            tmp.path().join("app/handlers.py"),
            "def list_users(q):\n    sql = 'SELECT * FROM u WHERE n=' + q\n    cursor.execute(sql)\n\ndef list_admins(q):\n    sql2 = 'SELECT * FROM admin WHERE n=' + q\n    cursor.execute(sql2)\n",
        )
        .unwrap();
        // A lower-priority untouched model file so the walker has more
        // than one source file to choose from.
        std::fs::write(tmp.path().join("models/user.py"), "class User:\n    pass\n").unwrap();
        // A directory that must be skipped: ensure the walker doesn't
        // descend into node_modules.
        std::fs::create_dir_all(tmp.path().join("node_modules/junk")).unwrap();
        std::fs::write(tmp.path().join("node_modules/junk/index.js"), "module.exports = {}\n")
            .unwrap();
        tmp
    }

    #[test]
    fn priority_for_prefers_route_controller_handler() {
        let routes = priority_for(std::path::Path::new("app/routes/users.py"), 4_096, None);
        let plain = priority_for(std::path::Path::new("misc/notes.py"), 4_096, None);
        assert!(routes > plain, "routes={routes} plain={plain}");
    }

    #[test]
    fn priority_for_boosts_historical_promotion_rate() {
        // Two identically-keyworded paths: one with no rate, one with a
        // strong historical promotion rate. The boosted one must
        // outrank the unboosted one.
        let base = priority_for(std::path::Path::new("models/user.py"), 4_096, None);
        let zero = priority_for(std::path::Path::new("models/user.py"), 4_096, Some(0.0));
        let high = priority_for(std::path::Path::new("models/user.py"), 4_096, Some(0.9));
        assert_eq!(base, zero, "rate=0.0 must not change the score");
        assert!(high > base, "high={high} base={base}");
        // Cap saturation: rate above 1.0 collapses to the same boost
        // as rate = 1.0 (defence against a corrupt rate map).
        let saturated = priority_for(std::path::Path::new("models/user.py"), 4_096, Some(5.0));
        let ceiling = priority_for(std::path::Path::new("models/user.py"), 4_096, Some(1.0));
        assert_eq!(saturated, ceiling);
    }

    #[test]
    fn walk_source_files_skips_node_modules() {
        let tmp = two_python_workspace();
        let files = walk_source_files(tmp.path());
        let stems: Vec<String> = files.iter().map(|p| p.to_string_lossy().to_string()).collect();
        let any_nm = stems.iter().any(|s| s.contains("node_modules"));
        assert!(!any_nm, "node_modules must be skipped: {stems:?}");
    }

    #[test]
    fn walk_source_files_respects_repo_gitignore() {
        // A custom build dir that is NOT in SKIP_DIRS but IS in the
        // operator's .gitignore must be skipped. This is the close-out
        // case for the deferred "swap hardcoded SKIP_DIRS for the
        // `ignore` crate" item.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::create_dir_all(tmp.path().join("custom_artifacts")).unwrap();
        std::fs::write(tmp.path().join("src/main.py"), "x = 1\n").unwrap();
        std::fs::write(tmp.path().join("custom_artifacts/gen.py"), "x = 2\n").unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "custom_artifacts/\n").unwrap();

        let files = walk_source_files(tmp.path());
        let stems: Vec<String> = files.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert!(
            stems.iter().any(|s| s.ends_with("src/main.py")),
            "main.py must surface: {stems:?}",
        );
        assert!(
            !stems.iter().any(|s| s.contains("custom_artifacts")),
            "gitignored dir must be skipped: {stems:?}",
        );
    }

    #[test]
    fn build_novel_inputs_attaches_priors_per_file() {
        // One known SQL sink on handlers.py at line 3 -> the only prior;
        // the second sink at line 6 is intentionally NOT in priors so
        // the model has something to find.
        let tmp = two_python_workspace();
        let diag = diag_supported("app/handlers.py", 3, "SQL_QUERY", "py.sql.exec");
        let inputs = build_novel_inputs_for_repo(
            "run-N",
            "repo-1",
            tmp.path(),
            &[diag],
            DEFAULT_FILES_PER_BATCH,
            None,
        );
        assert!(!inputs.is_empty(), "walker must produce at least one batch");
        let first = &inputs[0];
        assert_eq!(first.run_id, "run-N");
        assert_eq!(first.repo, "repo-1");
        assert_eq!(first.batch_id, "repo-1:0");
        let paths: Vec<&str> = first.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.contains(&"app/handlers.py"),
            "handlers.py must surface in the batch: {paths:?}",
        );
        // The prior must be forwarded so the model knows to skip line 3.
        assert!(first
            .priors
            .iter()
            .any(|p| p.path == "app/handlers.py" && p.line == 3 && p.cap == "SQL_QUERY"));
    }

    #[test]
    fn build_novel_inputs_chunks_into_batches() {
        // Force a tiny batch size so the chunker fires even on a small
        // workspace.
        let tmp = two_python_workspace();
        let inputs = build_novel_inputs_for_repo("run-N", "repo-1", tmp.path(), &[], 1, None);
        assert!(inputs.len() >= 2, "got: {}", inputs.len());
        for (i, b) in inputs.iter().enumerate() {
            assert_eq!(b.batch_id, format!("repo-1:{i}"));
            assert_eq!(b.files.len(), 1);
        }
    }

    #[test]
    fn build_novel_inputs_promotion_rates_boost_path_to_top_batch() {
        // Two source files: a low-keyword path with a strong historical
        // promotion rate vs a high-keyword path with no history. The
        // boost (PROMOTION_RATE_WEIGHT = 10 at rate = 1.0) must outrank
        // the strongest keyword hit (+6 for "route"/"controller") so
        // the historically-converting file lands in the first batch.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("misc")).unwrap();
        std::fs::create_dir_all(tmp.path().join("app/routes")).unwrap();
        let body = "def x():\n    pass\n".repeat(40);
        std::fs::write(tmp.path().join("misc/notes.py"), &body).unwrap();
        std::fs::write(tmp.path().join("app/routes/users.py"), &body).unwrap();

        let mut rates = HashMap::new();
        // Boost the otherwise-low-priority misc/notes.py path to a
        // near-ceiling rate. "misc/notes.py" matches "exec" in the
        // keyword table (because the body contains "pass"? no — keyword
        // table operates on the lowercased path, which does contain "ex" but not
        // "exec"; the path "misc/notes.py" alone scores 0 for keywords).
        rates.insert("misc/notes.py".to_string(), 1.0);
        let inputs =
            build_novel_inputs_for_repo("run-N", "repo-1", tmp.path(), &[], 1, Some(&rates));
        assert!(inputs.len() >= 2, "expected at least 2 batches; got {}", inputs.len());
        assert_eq!(
            inputs[0].files[0].path, "misc/notes.py",
            "promotion-rate boost must lift misc/notes.py above route-keyword path",
        );
    }

    #[tokio::test]
    async fn drive_novel_finding_pass_persists_candidate_for_similar_second_sink() {
        // NovelFindingDiscovery acceptance: a repo with one nyx-finding
        // (line 3) and an intentionally-similar second vulnerability
        // (line 6) produces a CandidateFinding for the second one. The
        // candidate lands as `candidate_findings.Pending` so nothing
        // surfaces to the operator without the payload verifier
        // confirming it.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-1")).await.unwrap();
        store.runs().insert(&seed_run("run-N")).await.unwrap();

        let workspace = two_python_workspace();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-1".to_string(),
            WorkspaceHandle::for_local_path_test("repo-1", workspace.path().to_path_buf()),
        );

        let diag = diag_supported("app/handlers.py", 3, "SQL_QUERY", "py.sql.exec");
        let bundle = make_bundle("run-N", "repo-1", vec![diag]);

        let body = serde_json::json!({
            "candidates": [{
                "path": "app/handlers.py",
                "line": 6,
                "cap": "SQL_QUERY",
                "rule_hint": "py.sql.exec",
                "rationale": "list_admins reuses the same SQL-concat pattern as the prior at line 3",
                "suggested_payload_hint": "' OR 1=1 --"
            }]
        })
        .to_string();
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let runtime = ScriptedNovelRuntime::new(vec![Ok(body)], 7_500, tracker.clone());

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = drive_novel_finding_pass(
            &runtime,
            tracker.as_ref(),
            &store,
            &bundle,
            &workspaces,
            tx,
            5_000_000,
            5_000_000,
            DEFAULT_FILES_PER_BATCH,
        )
        .await
        .unwrap();

        assert_eq!(report.candidates_persisted, 1);
        assert!(report.batches_dispatched >= 1);
        assert_eq!(report.batches_halted, 0);
        assert_eq!(report.failed, 0);

        let pending = store.candidate_findings().list_pending().await.unwrap();
        assert_eq!(pending.len(), 1, "exactly one CandidateFinding must be quarantined");
        let row = &pending[0];
        assert_eq!(row.repo, "repo-1");
        assert_eq!(row.path, "app/handlers.py");
        assert_eq!(row.line, Some(6));
        assert_eq!(row.cap, "SQL_QUERY");
        assert_eq!(row.status, "Pending");
        assert_eq!(
            row.prompt_version.as_deref(),
            Some(nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION)
        );
        assert!(row.rationale.as_deref().unwrap_or("").contains("list_admins"));

        // The proposing AI call's trace row is back-linked on the
        // candidate via `candidate_findings.trace_id`. The quarantine UI's
        // trace viewer reads this back-link so the operator can see the
        // call that proposed a Pending candidate without joining on
        // task_kind = NovelFindings alone.
        let trace_id = row.trace_id.clone().expect("candidate must carry trace_id back-link");
        let traces = store.agent_traces().list_for_candidate(&row.id).await.unwrap();
        assert_eq!(traces.len(), 1, "back-linked trace must be reachable via list_for_candidate");
        assert_eq!(traces[0].id, trace_id);
        assert_eq!(traces[0].task_kind, TaskKind::NovelFindings.as_str());
    }

    #[tokio::test]
    async fn drive_novel_finding_pass_halts_on_budget_cap() {
        // Acceptance: the per-run cap halts further batches once spend
        // crosses the cap. With `files_per_batch = 1` and a two-file
        // workspace, the first call exhausts the cap, so the second
        // batch is marked halted instead of dispatched. The scripted
        // runtime is queued with exactly one response; if the halt
        // logic broke and a second one_shot fired, it would panic.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-B")).await.unwrap();
        store.runs().insert(&seed_run("run-Bg")).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("controller.py"), "def f():\n    pass\n").unwrap();
        std::fs::write(workspace.path().join("api.py"), "def g():\n    pass\n").unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-B".to_string(),
            WorkspaceHandle::for_local_path_test("repo-B", workspace.path().to_path_buf()),
        );

        // Use a small cap so a single call lands us at the ceiling.
        let cap = 1_000_i64;
        let body = serde_json::json!({ "candidates": [] }).to_string();
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-Bg", BudgetKind::OneShot, cap);
        // Only ONE scripted response, even though we expect TWO batches:
        // the second batch must short-circuit on the cap before issuing
        // a one_shot call, otherwise the runtime would panic on an
        // empty response queue.
        let runtime = ScriptedNovelRuntime::new(vec![Ok(body)], cap, tracker.clone());

        let bundle = make_bundle("run-Bg", "repo-B", Vec::new());
        let (tx, _rx) = tokio::sync::broadcast::channel(4);

        // Sanity: with files_per_batch=1 the walker must emit >=2
        // batches so the halt path is exercised.
        let inputs =
            build_novel_inputs_for_repo("run-Bg", "repo-B", workspace.path(), &[], 1, None);
        assert!(inputs.len() >= 2, "fixture must produce >=2 batches; got {}", inputs.len());

        let report = drive_novel_finding_pass(
            &runtime,
            tracker.as_ref(),
            &store,
            &bundle,
            &workspaces,
            tx,
            cap,
            cap,
            1,
        )
        .await
        .unwrap();

        // The first call exhausts the cap; every subsequent batch in
        // the same repo must be halted before issuing a one_shot.
        assert_eq!(
            report.batches_dispatched, 1,
            "exactly one batch should fire before the cap halts further dispatch"
        );
        assert!(
            report.batches_halted >= 1,
            "at least one batch must record a halt; got {}",
            report.batches_halted
        );
        assert_eq!(
            report.failed, 0,
            "no scripted errors expected; failure means runtime tried a second call"
        );
        let spent = tracker.spent("run-Bg", BudgetKind::OneShot);
        assert_eq!(spent, cap, "exactly one call's worth of spend should land in the bucket");
    }

    #[tokio::test]
    async fn novel_pass_is_noop_when_runtime_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig::default();
        let report =
            run_novel_finding_discovery_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
                .await
                .unwrap();
        assert_eq!(report, NovelFindingDiscoveryPassReport::default());
    }

    #[tokio::test]
    async fn novel_pass_is_noop_when_anthropic_but_no_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        let secrets = SecretStore::memory();
        let workspaces: HashMap<String, WorkspaceHandle> = HashMap::new();
        let bundle = RunBundle::<Diag> {
            run_id: "r".to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig { runtime: ConfigAiRuntime::Anthropic, ..AiConfig::default() };
        let report =
            run_novel_finding_discovery_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
                .await
                .unwrap();
        assert_eq!(report, NovelFindingDiscoveryPassReport::default());
    }

    // -------- payload verification pass coverage --------------------

    fn shell_spec_blob() -> String {
        // Canned SQLi-style shell harness. Same fixture as the
        // payload_runner unit tests, in JSON form for the
        // `harness_specs` table.
        serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "shell",
            "entry": "harness:run",
            "setup": ["STORED='alice:pw1\\nbob:pw2\\nadmin:TOP_SECRET'"],
            "invoke": "printf '%b\\n' \"$STORED\" | grep -E @PAYLOAD || true",
            "payload_arg": 0,
            "oracle": "TOP_SECRET",
            "teardown": [],
        })
        .to_string()
    }

    fn seed_payload(finding_id: &str, vuln: &[u8], benign: &[u8]) -> PayloadRecord {
        PayloadRecord {
            id: format!("payload-{finding_id}"),
            finding_id: finding_id.to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "shell".to_string(),
            vuln_bytes: vuln.to_vec(),
            benign_bytes: Some(benign.to_vec()),
            oracle_blob: Some("TOP_SECRET".to_string()),
            attack_provenance: Some("LlmSynthesised".to_string()),
            prompt_version: Some("phase14.payload_synthesis.v1".to_string()),
            created_at: 5_000,
        }
    }

    fn seed_spec(id: &str) -> HarnessSpecRecord {
        HarnessSpecRecord {
            id: id.to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "shell".to_string(),
            spec_blob: shell_spec_blob(),
            attack_provenance: Some("LlmSynthesised".to_string()),
            prompt_version: Some("phase15.spec_derivation.v1".to_string()),
            created_at: 6_000,
        }
    }

    async fn ws_handle_for(repo: &str) -> (tempfile::TempDir, WorkspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let handle = WorkspaceHandle::for_local_path_test(repo, dir.path().to_path_buf());
        (dir, handle)
    }

    fn empty_bundle(run_id: &str) -> RunBundle<Diag> {
        RunBundle {
            run_id: run_id.to_string(),
            project_id: "default-project".to_string(),
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        }
    }

    #[tokio::test]
    async fn verifier_confirms_finding_with_llm_payload() {
        // Verifier acceptance: an LLM-synthesised payload for a test
        // finding flows through the verifier and lands a verdict.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-V").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-V".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-V")).await.unwrap();
        store.runs().insert(&seed_run("run-V")).await.unwrap();
        let finding = seed_finding("run-V", "repo-V", "src/sink.sh", "rule-sqli");
        let fid = finding.id.clone();
        store.findings().upsert(&finding).await.unwrap();
        store.payloads().insert(&seed_payload(&fid, b".*", b"^alice$")).await.unwrap();
        store.harness_specs().insert(&seed_spec("spec-V")).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-V"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.confirmed, 1, "{report:?}");
        assert_eq!(report.not_confirmed, 0);
        assert_eq!(report.errored, 0);

        let row = store.findings().get(&fid).await.unwrap().expect("row");
        assert_eq!(row.status, "Verified");
        assert_eq!(row.attack_provenance.as_deref(), Some("LlmSynthesised"));
        let blob = row.verdict_blob.expect("blob");
        let result: VerifyResult = serde_json::from_str(&blob).unwrap();
        assert_eq!(result.verdict, VerifyVerdict::Confirmed);
        assert!(result.vuln_run.oracle_fired);
        assert!(!result.benign_run.oracle_fired);

        let traces = store.agent_traces().list_for_finding(&fid).await.unwrap();
        let verifier_rows: Vec<_> =
            traces.into_iter().filter(|t| t.task_kind == "Verifier").collect();
        assert_eq!(verifier_rows.len(), 1, "expected one Verifier trace row");
        let trace = &verifier_rows[0];
        assert_eq!(trace.runtime_name, "process");
        assert_eq!(trace.cost_usd_micros, 0);
        assert!(trace.duration_ms.is_some());
        assert!(trace.finished_at.is_some());
    }

    #[tokio::test]
    async fn verifier_closes_finding_when_payload_is_benign() {
        // Verifier acceptance: replacing the vuln payload with the
        // benign one yields NotConfirmed; the finding flips to Closed.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-B").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-B".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-B")).await.unwrap();
        store.runs().insert(&seed_run("run-B")).await.unwrap();
        let finding = seed_finding("run-B", "repo-B", "src/sink.sh", "rule-sqli");
        let fid = finding.id.clone();
        store.findings().upsert(&finding).await.unwrap();
        // Both payloads are the benign control; neither trips the oracle.
        store.payloads().insert(&seed_payload(&fid, b"^alice$", b"^alice$")).await.unwrap();
        store.harness_specs().insert(&seed_spec("spec-B")).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-B"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.confirmed, 0);
        assert_eq!(report.not_confirmed, 1, "{report:?}");
        let row = store.findings().get(&fid).await.unwrap().expect("row");
        assert_eq!(row.status, "Closed");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_on_confirmed() {
        // Verifier acceptance: an AI-discovered candidate gets
        // promoted from Quarantined to Confirmed when its verify
        // passes. The promoted row lands with `finding_origin =
        // AiExploration`.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-C").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-C".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-C")).await.unwrap();
        store.runs().insert(&seed_run("run-C")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-c1".to_string(),
            run_id: "run-C".to_string(),
            repo: "repo-C".to_string(),
            path: "app/handlers.sh".to_string(),
            line: Some(42),
            cap: "SQL_QUERY".to_string(),
            rule_hint: Some("sh.sql.exec".to_string()),
            rationale: Some("similar SQL-concat pattern".to_string()),
            suggested_payload_hint: Some(".*".to_string()),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();
        // Candidate promotion uses the built-in per-cap harness
        // template seeded by `suggested_payload_hint`; no
        // payload / spec rows are pre-staged. The candidate-confirmation
        // pipeline (deferred) swaps this to real per-candidate
        // synthesis output.

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-C"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        // The candidate flipped to Promoted.
        let promoted = store.candidate_findings().get(&cand.id).await.unwrap().expect("row");
        assert_eq!(promoted.status, "Promoted");

        // A new findings row appeared with finding_origin = AiExploration
        // and status = Verified.
        let findings = store.findings().list_by_run("run-C").await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_origin, "AiExploration");
        assert_eq!(f.status, "Verified");
        assert_eq!(f.repo, "repo-C");
        assert_eq!(f.path, "app/handlers.sh");
        assert_eq!(f.line, Some(42));
        assert_eq!(f.cap, "SQL_QUERY");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_for_os_command_cap() {
        // OS_COMMAND candidate promotion: the built-in shell harness
        // evaluates the `suggested_payload_hint` as a shell command via
        // `sh -c`. A vuln payload that creates the sentinel file trips
        // `Oracle::SinkProbe`; the constant benign control (`:`) is a
        // shell no-op that leaves the workspace untouched.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-D").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-D".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-D")).await.unwrap();
        store.runs().insert(&seed_run("run-D")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-d1".to_string(),
            run_id: "run-D".to_string(),
            repo: "repo-D".to_string(),
            path: "app/spawn.sh".to_string(),
            line: Some(17),
            cap: "OS_COMMAND".to_string(),
            rule_hint: Some("sh.subprocess.shell-true".to_string()),
            rationale: Some("user input flows into Popen(..., shell=True)".to_string()),
            suggested_payload_hint: Some(": > nyx_oscmd.flag".to_string()),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-D"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        let promoted = store.candidate_findings().get(&cand.id).await.unwrap().expect("row");
        assert_eq!(promoted.status, "Promoted");

        let findings = store.findings().list_by_run("run-D").await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_origin, "AiExploration");
        assert_eq!(f.status, "Verified");
        assert_eq!(f.cap, "OS_COMMAND");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_for_cmdi_cap() {
        // `CMDi` shares the OS_COMMAND template / sentinel oracle. This
        // test pins the alias so a future rename of the cap label does
        // not silently downgrade `CMDi` candidates back to "skipped".
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-E").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-E".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-E")).await.unwrap();
        store.runs().insert(&seed_run("run-E")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-e1".to_string(),
            run_id: "run-E".to_string(),
            repo: "repo-E".to_string(),
            path: "app/exec.js".to_string(),
            line: Some(8),
            cap: "CMDi".to_string(),
            rule_hint: Some("js.child_process.exec".to_string()),
            rationale: Some("user input concatenated into child_process.exec".to_string()),
            suggested_payload_hint: Some("touch nyx_oscmd.flag".to_string()),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-E"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        let findings = store.findings().list_by_run("run-E").await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cap, "CMDi");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_for_path_traversal_cap() {
        // PATH_TRAVERSAL candidate promotion: the built-in shell harness
        // stages a `safe_dir/innocent.txt` (the application's intended
        // container) plus an out-of-band `oracle_secret.txt` next to it.
        // The vuln payload `../oracle_secret.txt` escapes `safe_dir/`,
        // so the `cat -- safe_dir/<payload>` invocation leaks the
        // `TOP_SECRET_TRAV` marker to stdout and trips the
        // `OutputContains` oracle. The constant benign control
        // (`innocent.txt`) reads the in-`safe_dir` file and emits
        // "workspace", which the oracle does not match.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-PT").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-PT".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-PT")).await.unwrap();
        store.runs().insert(&seed_run("run-PT")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-pt1".to_string(),
            run_id: "run-PT".to_string(),
            repo: "repo-PT".to_string(),
            path: "app/serve_file.py".to_string(),
            line: Some(42),
            cap: "PATH_TRAVERSAL".to_string(),
            rule_hint: Some("py.flask.send_file-userinput".to_string()),
            rationale: Some(
                "request filename concatenated into send_file path without normalisation"
                    .to_string(),
            ),
            suggested_payload_hint: Some("../oracle_secret.txt".to_string()),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-PT"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        let promoted = store.candidate_findings().get(&cand.id).await.unwrap().expect("row");
        assert_eq!(promoted.status, "Promoted");

        let findings = store.findings().list_by_run("run-PT").await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_origin, "AiExploration");
        assert_eq!(f.status, "Verified");
        assert_eq!(f.cap, "PATH_TRAVERSAL");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_for_xxe_cap() {
        // XXE candidate promotion: the built-in python harness drives
        // expat directly. The vuln payload declares an internal general
        // entity `x` whose value is the `TOP_SECRET_XXE` marker and
        // expands it inside `<r>&x;</r>`; expat substitutes the entity
        // at parse time and the CharacterDataHandler captures the
        // marker text, which the `OutputContains` oracle matches. The
        // benign control `<r>workspace</r>` parses cleanly with no
        // entity declaration, so the captured text is "workspace" and
        // the oracle does not fire.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-XXE").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-XXE".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-XXE")).await.unwrap();
        store.runs().insert(&seed_run("run-XXE")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-xxe1".to_string(),
            run_id: "run-XXE".to_string(),
            repo: "repo-XXE".to_string(),
            path: "app/parse_doc.py".to_string(),
            line: Some(57),
            cap: "XXE".to_string(),
            rule_hint: Some("py.expat.parse-userinput".to_string()),
            rationale: Some(
                "request body parsed via expat without entity-resolution lockdown".to_string(),
            ),
            suggested_payload_hint: Some(
                "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x \"TOP_SECRET_XXE\">]><r>&x;</r>"
                    .to_string(),
            ),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-XXE"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        let promoted = store.candidate_findings().get(&cand.id).await.unwrap().expect("row");
        assert_eq!(promoted.status, "Promoted");

        let findings = store.findings().list_by_run("run-XXE").await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_origin, "AiExploration");
        assert_eq!(f.status, "Verified");
        assert_eq!(f.cap, "XXE");
    }

    #[tokio::test]
    async fn verifier_promotes_quarantined_candidate_for_deserialisation_cap() {
        // DESERIALISATION candidate promotion: the built-in python
        // harness feeds the payload bytes verbatim into `pickle.loads`.
        // The vuln payload is a protocol-0 pickle (`cbuiltins\nprint\n
        // (VTOP_SECRET_PICKLE\ntR.`) that REDUCEs `builtins.print` with
        // the `TOP_SECRET_PICKLE` marker; pickle.loads invokes the
        // REDUCE during unpickling, writing the marker to stdout and
        // tripping the oracle. The benign control `N.` (NONE + STOP)
        // returns `None` with no side effect, so stdout stays empty.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-PK").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-PK".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-PK")).await.unwrap();
        store.runs().insert(&seed_run("run-PK")).await.unwrap();

        let cand = CandidateFindingRecord {
            id: "cand-pk1".to_string(),
            run_id: "run-PK".to_string(),
            repo: "repo-PK".to_string(),
            path: "app/load_blob.py".to_string(),
            line: Some(91),
            cap: "DESERIALISATION".to_string(),
            rule_hint: Some("py.pickle.loads-userinput".to_string()),
            rationale: Some(
                "request body passed to pickle.loads without a safe-allowlist Unpickler"
                    .to_string(),
            ),
            suggested_payload_hint: Some("cbuiltins\nprint\n(VTOP_SECRET_PICKLE\ntR.".to_string()),
            status: "Pending".to_string(),
            prompt_version: Some(
                nyctos_types::novel::NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
            ),
            trace_id: None,
        };
        store.candidate_findings().insert(&cand).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-PK"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.candidates_promoted, 1, "{report:?}");
        assert_eq!(report.confirmed, 1);

        let promoted = store.candidate_findings().get(&cand.id).await.unwrap().expect("row");
        assert_eq!(promoted.status, "Promoted");

        let findings = store.findings().list_by_run("run-PK").await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.finding_origin, "AiExploration");
        assert_eq!(f.status, "Verified");
        assert_eq!(f.cap, "DESERIALISATION");
    }

    #[test]
    fn builtin_harness_table_covers_known_caps_and_skips_unknown() {
        // Sentinel test against silent drift in the per-cap table that
        // backs `drive_verify_for_candidate`. Every covered cap must
        // also return a non-`OutputContains{ORACLE_FIRED}` (i.e.
        // non-default) oracle and a benign control distinct from the
        // catch-all marker; every uncovered cap (XSS / SSRF — both
        // need infra we do not have: DOM runtime, loopback listener)
        // must return `None` so the verifier skips it instead of
        // confirming on a generic template that has no chance of
        // matching the real sink.
        for cap in
            ["SQL_QUERY", "SQLi", "OS_COMMAND", "CMDi", "PATH_TRAVERSAL", "XXE", "DESERIALISATION"]
        {
            let spec = builtin_harness_for_cap(cap).expect(cap);
            assert_eq!(spec.cap, cap);
            assert!(
                matches!(spec.lang.as_str(), "shell" | "python"),
                "cap {cap} lang {} unexpected",
                spec.lang
            );
            assert!(!matches!(
                builtin_oracle_for_cap(cap),
                Oracle::OutputContains { ref marker } if marker == "ORACLE_FIRED"
            ));
            assert_ne!(builtin_benign_for_cap(cap), "__nyx_benign_control__");
        }
        for cap in ["XSS", "SSRF"] {
            assert!(
                builtin_harness_for_cap(cap).is_none(),
                "cap {cap} should fall through to the candidate-confirmation pipeline"
            );
        }
    }

    #[tokio::test]
    async fn verifier_skips_findings_without_payload_or_spec() {
        // No payload/spec rows -> the finding is left alone and the
        // pass reports it as skipped-no-payload.
        let (_ws_tmp, ws_handle) = ws_handle_for("repo-S").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-S".to_string(), ws_handle);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-S")).await.unwrap();
        store.runs().insert(&seed_run("run-S")).await.unwrap();
        let finding = seed_finding("run-S", "repo-S", "src/sink.sh", "rule-orphan");
        let fid = finding.id.clone();
        store.findings().upsert(&finding).await.unwrap();

        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-S"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.skipped_no_payload, 1);
        let row = store.findings().get(&fid).await.unwrap().expect("row");
        assert_eq!(row.status, "Open", "status untouched without a payload");
    }

    #[tokio::test]
    async fn verifier_pass_emits_started_and_finished_sandbox_events() {
        // Subscribers on the run-wide bus see one VerifierStarted +
        // one VerifierFinished frame per finding the pass drives. Skipped
        // findings (no payload/spec) produce no event.
        let (_ws_tmp_a, ws_a) = ws_handle_for("repo-E").await;
        let (_ws_tmp_b, ws_b) = ws_handle_for("repo-F").await;
        let mut workspaces = HashMap::new();
        workspaces.insert("repo-E".to_string(), ws_a);
        workspaces.insert("repo-F".to_string(), ws_b);

        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-E")).await.unwrap();
        store.repos().upsert(&seed_repo("repo-F")).await.unwrap();
        store.runs().insert(&seed_run("run-E")).await.unwrap();

        // Driven finding: has payload + spec.
        let driven = seed_finding("run-E", "repo-E", "src/sink.sh", "rule-sqli");
        let driven_id = driven.id.clone();
        store.findings().upsert(&driven).await.unwrap();
        store.payloads().insert(&seed_payload(&driven_id, b".*", b"^alice$")).await.unwrap();
        store.harness_specs().insert(&seed_spec("spec-E")).await.unwrap();

        // Skipped finding: same run, no payload row.
        let skipped = seed_finding("run-E", "repo-F", "src/other.sh", "rule-orphan");
        store.findings().upsert(&skipped).await.unwrap();

        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let report = run_payload_verification_pass(
            &RunConfig::default(),
            &SandboxConfig::default(),
            &store,
            &empty_bundle("run-E"),
            &workspaces,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(report.confirmed, 1);
        assert_eq!(report.skipped_no_payload, 1);

        let mut started = Vec::new();
        let mut finished = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let AgentEvent::Sandbox { data } = ev {
                match data {
                    SandboxEvent::VerifierStarted { finding_id, repo, run_id, .. } => {
                        started.push((run_id, finding_id, repo));
                    }
                    SandboxEvent::VerifierFinished {
                        finding_id,
                        repo,
                        run_id,
                        verdict,
                        replay_stable,
                        elapsed_ms,
                    } => {
                        finished.push((
                            run_id,
                            finding_id,
                            repo,
                            verdict,
                            replay_stable,
                            elapsed_ms,
                        ));
                    }
                }
            }
        }
        assert_eq!(started.len(), 1, "skipped findings must not emit Started");
        assert_eq!(finished.len(), 1);
        assert_eq!(started[0], ("run-E".into(), driven_id.clone(), "repo-E".into()));
        let (run_id, fid, repo, verdict, replay_stable, elapsed_ms) = finished[0].clone();
        assert_eq!(run_id, "run-E");
        assert_eq!(fid, driven_id);
        assert_eq!(repo, "repo-E");
        assert_eq!(verdict, "Confirmed");
        assert!(replay_stable.is_none(), "replay_stable_check is off by default");
        assert!(elapsed_ms >= 0);
    }

    #[test]
    fn derive_oracle_picks_sink_probe_when_prefixed() {
        match derive_oracle("sink-probe:flags/seen.txt") {
            Oracle::SinkProbe { sentinel_path, expect_contains } => {
                assert_eq!(sentinel_path, "flags/seen.txt");
                assert!(expect_contains.is_none());
            }
            other => panic!("expected SinkProbe, got {other:?}"),
        }
        match derive_oracle("sink-probe:flags/seen.txt#leaked") {
            Oracle::SinkProbe { sentinel_path, expect_contains } => {
                assert_eq!(sentinel_path, "flags/seen.txt");
                assert_eq!(expect_contains.as_deref(), Some("leaked"));
            }
            other => panic!("expected SinkProbe, got {other:?}"),
        }
        match derive_oracle("TOP_SECRET") {
            Oracle::OutputContains { marker } => assert_eq!(marker, "TOP_SECRET"),
            other => panic!("expected OutputContains, got {other:?}"),
        }
    }

    #[test]
    fn degenerate_oracle_reason_flags_empty_marker_and_empty_sentinel() {
        assert_eq!(
            degenerate_oracle_reason(&Oracle::OutputContains { marker: String::new() }),
            Some("OutputContains marker is empty"),
        );
        assert_eq!(
            degenerate_oracle_reason(&Oracle::OutputContains { marker: "  ".into() }),
            Some("OutputContains marker is empty"),
        );
        assert_eq!(
            degenerate_oracle_reason(&Oracle::SinkProbe {
                sentinel_path: String::new(),
                expect_contains: None,
            }),
            Some("SinkProbe sentinel_path is empty"),
        );
        assert_eq!(
            degenerate_oracle_reason(&Oracle::SinkProbe {
                sentinel_path: "  ".into(),
                expect_contains: Some("leaked".into()),
            }),
            Some("SinkProbe sentinel_path is empty"),
        );
        assert_eq!(
            degenerate_oracle_reason(&Oracle::OutputContains { marker: "TOP_SECRET".into() }),
            None,
        );
        assert_eq!(
            degenerate_oracle_reason(&Oracle::SinkProbe {
                sentinel_path: "flags/seen.txt".into(),
                expect_contains: None,
            }),
            None,
        );
    }

    /// Scripted agent-loop runtime that mirrors the per-task
    /// fixture. Each `agent_loop` call pops the next outcome off the
    /// back of the queue; `one_shot` returns `UnsupportedMode` because
    /// the exploration pass only drives the agent-loop surface.
    struct ScriptedExplorationRuntime {
        outcomes: StdMutex<Vec<Result<AgentResult, AiError>>>,
        cost_per_call: i64,
        tracker: Arc<dyn BudgetTracker>,
        tasks_seen: StdMutex<Vec<AgentTask>>,
    }

    impl ScriptedExplorationRuntime {
        fn new(
            outcomes: Vec<Result<AgentResult, AiError>>,
            cost_per_call: i64,
            tracker: Arc<dyn BudgetTracker>,
        ) -> Self {
            Self {
                outcomes: StdMutex::new(outcomes),
                cost_per_call,
                tracker,
                tasks_seen: StdMutex::new(Vec::new()),
            }
        }

        fn tasks_seen(&self) -> Vec<AgentTask> {
            self.tasks_seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AiRuntime for ScriptedExplorationRuntime {
        fn name(&self) -> &'static str {
            "scripted-exploration"
        }
        fn default_model(&self) -> &str {
            "scripted-model"
        }
        fn supports_agent_loop(&self) -> bool {
            true
        }
        fn supports_prompt_cache(&self) -> bool {
            false
        }
        fn supports_deterministic_sampling(&self) -> bool {
            false
        }

        async fn one_shot(
            &self,
            _prompt: Prompt,
            _budget: Budget,
            _sink: nyctos_types::event::EventSink,
        ) -> Result<Response, AiError> {
            Err(AiError::UnsupportedMode("one_shot"))
        }

        async fn agent_loop(
            &self,
            task: AgentTask,
            budget: Budget,
            _sink: nyctos_types::event::EventSink,
        ) -> Result<AgentResult, AiError> {
            self.tasks_seen.lock().unwrap().push(task.clone());
            let mut next = self
                .outcomes
                .lock()
                .unwrap()
                .pop()
                .expect("scripted exploration runtime: no more outcomes");
            let cost = self.cost_per_call;
            self.tracker.add_spend(&budget.run_id, budget.kind, cost).await?;
            if let Ok(ref mut r) = next {
                r.task_id = task.task_id.clone();
                r.cost_usd_micros = cost;
            }
            next
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            Some(CostEstimate { min_usd_micros: 0, max_usd_micros: self.cost_per_call })
        }
    }

    fn empty_exploration_result() -> AgentResult {
        AgentResult {
            prompt_version: nyctos_ai::EXPLORATION_PROMPT_VERSION.to_string(),
            task_id: String::new(),
            model: "scripted-model".to_string(),
            final_message: "ok".to_string(),
            turns: 1,
            usage: TokenUsage { input_tokens: 100, output_tokens: 50 },
            cache: None,
            cost_usd_micros: 0,
            extracted: Vec::new(),
        }
    }

    fn pentest_candidate(
        id: &str,
        source: &str,
        severity: &str,
        status: &str,
        component: serde_json::Value,
    ) -> PentestCandidateRecord {
        PentestCandidateRecord {
            id: id.to_string(),
            run_id: "run-expl-leads".to_string(),
            project_id: "default-project".to_string(),
            source: source.to_string(),
            source_ids: vec![format!("{source}:{id}")],
            title: format!("{source} lead {id}"),
            vuln_class: "AUTH_BYPASS".to_string(),
            severity_guess: severity.to_string(),
            affected_components: vec![component],
            hypothesis: format!("{source} reported {id}; verify with live evidence."),
            test_plan: "Derive a safe live HTTP/browser confirmation.".to_string(),
            status: status.to_string(),
            rejection_reason: None,
            confidence: 0.75,
            trace_id: None,
            created_at: 1_000,
            updated_at: 1_000,
        }
    }

    #[test]
    fn exploration_known_leads_are_repo_scoped_and_prioritised() {
        let candidates = vec![
            pentest_candidate(
                "pc-zap",
                "ZAPBaseline",
                "Medium",
                "NeedsLiveTest",
                serde_json::json!({
                    "scanner": "zap-baseline",
                    "url": "http://localhost:3000/login",
                    "method": "GET"
                }),
            ),
            pentest_candidate(
                "pc-nyx-a",
                "NyxSignal",
                "High",
                "NeedsLiveTest",
                serde_json::json!({
                    "repo": "repo-a",
                    "path": "src/admin.ts",
                    "line": 42
                }),
            ),
            pentest_candidate(
                "pc-nyx-b",
                "NyxSignal",
                "Critical",
                "NeedsLiveTest",
                serde_json::json!({
                    "repo": "repo-b",
                    "path": "src/payments.ts",
                    "line": 7
                }),
            ),
            pentest_candidate(
                "pc-rejected",
                "Nuclei",
                "Critical",
                "Rejected",
                serde_json::json!({
                    "matched_at": "http://localhost:3000/admin"
                }),
            ),
            pentest_candidate(
                "pc-trivy",
                "Trivy",
                "High",
                "Observed",
                serde_json::json!({
                    "repo": "repo-a",
                    "path": "package-lock.json"
                }),
            ),
        ];

        let leads = exploration_known_leads_for_repo(&candidates, "repo-a", 8);
        assert_eq!(
            leads.len(),
            3,
            "repo-a should see its Nyx lead, Trivy context, plus global ZAP lead"
        );
        assert_eq!(leads[0].id, "pc-nyx-a", "higher severity repo lead should rank first");
        assert_eq!(leads[0].location.as_deref(), Some("repo-a:src/admin.ts:42"));
        assert_eq!(leads[1].source, "Trivy");
        assert_eq!(leads[1].status, "Observed");
        assert_eq!(leads[2].source, "ZAPBaseline");
        assert_eq!(leads[2].location.as_deref(), Some("GET http://localhost:3000/login"));
        assert!(leads.iter().all(|lead| lead.id != "pc-nyx-b"));
        assert!(leads.iter().all(|lead| lead.id != "pc-rejected"));
    }

    #[test]
    fn attack_planning_prompt_includes_candidate_source_attribution() {
        let candidate = PentestCandidateRecord {
            source: "RouteDiscovery+JavaScriptBundle".to_string(),
            source_ids: vec![
                "RouteDiscovery:api:GET:/api/admin/debug".to_string(),
                "JavaScriptBundle:web:GET:/api/admin/debug".to_string(),
            ],
            affected_components: vec![serde_json::json!({
                "kind": "route",
                "repo": "api",
                "method": "GET",
                "url_path": "/api/admin/debug"
            })],
            ..pentest_candidate(
                "pc-weak-admin",
                "RouteDiscovery",
                "Medium",
                "NeedsLiveTest",
                serde_json::json!({"repo":"api","path":"src/routes.rs","line":42}),
            )
        };
        let prompt = build_attack_planning_prompt(
            &[candidate],
            &HashMap::new(),
            &RouteModel::default(),
            &[],
            &["http://localhost:3000".to_string()],
        );

        assert!(prompt.user.contains("\"source\": \"RouteDiscovery+JavaScriptBundle\""));
        assert!(prompt.user.contains("JavaScriptBundle:web:GET:/api/admin/debug"));
        assert!(prompt.user.contains("\"confidence\""));
    }

    #[tokio::test]
    async fn drive_ai_exploration_persists_quarantined_finding() {
        // Exploration acceptance: an AI-discovered finding flows
        // into `findings` with `finding_origin = AiExploration` and
        // `status = Quarantine`.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-X")).await.unwrap();
        let mut run_row = seed_run("run-expl-1");
        run_row.id = "run-expl-1".into();
        store.runs().insert(&run_row).await.unwrap();
        let mut scanner_lead = pentest_candidate(
            "pc-zap-expl",
            "ZAPBaseline",
            "Medium",
            "NeedsLiveTest",
            serde_json::json!({
                "scanner": "zap-baseline",
                "url": "http://127.0.0.1:3000/login",
                "method": "GET"
            }),
        );
        scanner_lead.run_id = "run-expl-1".to_string();
        store.pentest_candidates().insert(&scanner_lead).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-X".to_string(),
            WorkspaceHandle::for_local_path_test("repo-X", workspace.path().to_path_buf()),
        );

        let mut result = empty_exploration_result();
        result.extracted.push(nyctos_types::agent::ExtractedAgentResult::ExplorationFinding {
            path: "<api:/api/admin/orders>".into(),
            line: None,
            cap: "AUTH_BYPASS".into(),
            rationale: "Admin endpoint accepts unauthenticated GET".into(),
            endpoint: Some("GET /api/admin/orders".into()),
            suggested_payload_hint: Some("curl -i http://127.0.0.1:3000/api/admin/orders".into()),
        });

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl-1", BudgetKind::AgentLoop, 10_000_000);
        let runtime = ScriptedExplorationRuntime::new(vec![Ok(result)], 250_000, tracker.clone());

        let bundle = make_bundle("run-expl-1", "repo-X", Vec::new());
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let gate = StaticEscapeSuiteGate::green();

        let traces_root = tempfile::tempdir().unwrap();
        let report = drive_ai_exploration_pass(
            &runtime,
            &store,
            &bundle,
            &workspaces,
            &[],
            &gate,
            tx,
            traces_root.path(),
            DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
            DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
        )
        .await
        .unwrap();

        assert_eq!(report.explorations_dispatched, 1);
        assert_eq!(report.findings_quarantined, 1);
        assert_eq!(report.halted_escape_suite_red, 0);
        assert_eq!(report.halted_budget_exhausted, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.spend_usd_micros, 250_000);
        let tasks_seen = runtime.tasks_seen();
        assert_eq!(tasks_seen.len(), 1);
        assert!(tasks_seen[0].objective.contains("KNOWN SCANNER LEADS"));
        assert!(tasks_seen[0].objective.contains("pc-zap-expl"));
        assert!(tasks_seen[0].objective.contains("ZAPBaseline"));
        assert!(tasks_seen[0].objective.contains("GET http://127.0.0.1:3000/login"));

        // The finding landed in the `findings` table with the right
        // origin + status. We do not call list_by_run because the
        // finding's run_id may differ from the bundle's (the persister
        // picks the repo's last_scan_run_id, which is None on a fresh
        // seed). Query by repo via the active-list helper with a
        // quarantine-inclusive filter.
        let filter = nyctos_core::store::FindingFilter {
            repo: Some("repo-X"),
            include_quarantine: true,
            ..nyctos_core::store::FindingFilter::default()
        };
        let rows = store.findings().list_filtered(&filter).await.unwrap();
        assert_eq!(rows.len(), 1, "expected one quarantined finding, got {}", rows.len());
        let row = &rows[0];
        assert_eq!(row.finding_origin, "AiExploration");
        assert_eq!(row.status, "Quarantine");
        assert_eq!(row.cap, "AUTH_BYPASS");
        assert_eq!(row.path, "<api:/api/admin/orders>");
        assert_eq!(row.attack_provenance.as_deref(), Some("AiExploration"));
        assert_eq!(row.prompt_version.as_deref(), Some(nyctos_ai::EXPLORATION_PROMPT_VERSION));
        let blob = row.verdict_blob.as_deref().expect("verdict blob");
        assert!(blob.contains("AiExploration"));
        assert!(blob.contains("unauthenticated"));
    }

    #[tokio::test]
    async fn drive_ai_exploration_red_gate_halts_with_banner() {
        // Exploration acceptance: a red escape-suite fixture halts
        // the AI driver. The agent loop must not fire (the scripted
        // runtime's
        // queue is empty, so a stray dispatch would panic), and the
        // report counts the halt.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-Y")).await.unwrap();
        store.runs().insert(&seed_run("run-expl-2")).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-Y".to_string(),
            WorkspaceHandle::for_local_path_test("repo-Y", workspace.path().to_path_buf()),
        );

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl-2", BudgetKind::AgentLoop, 10_000_000);
        // Empty outcomes queue: a dispatched agent_loop would panic.
        let runtime = ScriptedExplorationRuntime::new(Vec::new(), 0, tracker.clone());

        let bundle = make_bundle("run-expl-2", "repo-Y", Vec::new());
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let gate = StaticEscapeSuiteGate::red(
            "write_outside_workspace_is_contained",
            "wrote /tmp/escaped during regression suite",
        );

        let traces_root = tempfile::tempdir().unwrap();
        let report = drive_ai_exploration_pass(
            &runtime,
            &store,
            &bundle,
            &workspaces,
            &[],
            &gate,
            tx,
            traces_root.path(),
            DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
            DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
        )
        .await
        .unwrap();
        assert_eq!(report.halted_escape_suite_red, 1);
        assert_eq!(report.explorations_dispatched, 0);
        assert_eq!(report.findings_quarantined, 0);
        assert_eq!(report.spend_usd_micros, 0);

        // Banner frame on the event bus name-checks the failing fixture.
        let mut saw_banner = false;
        while let Ok(frame) = rx.try_recv() {
            if let nyctos_types::event::AgentEvent::Ai {
                data: nyctos_types::event::AiEvent::TokenReceived { token, .. },
            } = frame
            {
                if token.contains("escape-suite RED")
                    && token.contains("write_outside_workspace_is_contained")
                {
                    saw_banner = true;
                    break;
                }
            }
        }
        assert!(saw_banner, "expected escape-suite RED banner on the bus");
    }

    #[tokio::test]
    async fn drive_ai_exploration_splits_cost_across_emitted_findings() {
        // The Exploration call cost must be split across the
        // per-finding `agent_traces` rows so the AiTraceViewer's
        // per-finding "Total $..." sums to the proportional share of
        // the call. The parent row (finding_id = NULL) keeps the
        // token/cache metrics but carries cost = 0 to avoid double
        // counting in any join that touches both.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-split")).await.unwrap();
        let mut run_row = seed_run("run-split");
        run_row.id = "run-split".into();
        store.runs().insert(&run_row).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-split".to_string(),
            WorkspaceHandle::for_local_path_test("repo-split", workspace.path().to_path_buf()),
        );

        let mut result = empty_exploration_result();
        for i in 0..3 {
            result.extracted.push(nyctos_types::agent::ExtractedAgentResult::ExplorationFinding {
                path: format!("<api:/api/admin/endpoint-{i}>"),
                line: None,
                cap: "AUTH_BYPASS".into(),
                rationale: format!("Admin endpoint {i} accepts unauthenticated GET"),
                endpoint: Some(format!("GET /api/admin/endpoint-{i}")),
                suggested_payload_hint: None,
            });
        }

        // 1_000_001 / 3 = 333_333 with leftover 2 — first two rows get
        // 333_334, third gets 333_333. Total stays exact.
        let cost = 1_000_001_i64;
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-split", BudgetKind::AgentLoop, 10_000_000);
        let runtime = ScriptedExplorationRuntime::new(vec![Ok(result)], cost, tracker.clone());

        let bundle = make_bundle("run-split", "repo-split", Vec::new());
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let gate = StaticEscapeSuiteGate::green();

        let traces_root = tempfile::tempdir().unwrap();
        let report = drive_ai_exploration_pass(
            &runtime,
            &store,
            &bundle,
            &workspaces,
            &[],
            &gate,
            tx,
            traces_root.path(),
            DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
            DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
        )
        .await
        .unwrap();
        assert_eq!(report.findings_quarantined, 3);
        assert_eq!(report.spend_usd_micros, cost);

        let parent_rows: Vec<_> = store
            .agent_traces()
            .list_by_task_kind("Exploration")
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.finding_id.is_none())
            .collect();
        assert_eq!(parent_rows.len(), 1, "expected one parent Exploration trace");
        assert_eq!(
            parent_rows[0].cost_usd_micros, 0,
            "parent cost must be zero when findings split it"
        );
        assert_eq!(parent_rows[0].tokens_in, 100);
        assert_eq!(parent_rows[0].tokens_out, 50);

        let per_finding_rows: Vec<_> = store
            .agent_traces()
            .list_by_task_kind("Exploration")
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.finding_id.is_some())
            .collect();
        assert_eq!(per_finding_rows.len(), 3, "expected three per-finding rows");
        let total: i64 = per_finding_rows.iter().map(|t| t.cost_usd_micros).sum();
        assert_eq!(total, cost, "per-finding split must sum to the call cost");
        // Token metrics stay on the parent so totals views do not
        // double-count usage when joining both kinds of rows.
        for row in &per_finding_rows {
            assert_eq!(row.tokens_in, 0);
            assert_eq!(row.tokens_out, 0);
        }
    }

    #[tokio::test]
    async fn drive_ai_exploration_keeps_cost_on_parent_when_zero_findings_emitted() {
        // When the call surfaces zero findings, the cost must stay on
        // the parent row so the run-card spend roll-up still observes
        // the spend through its time-window join.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-empty")).await.unwrap();
        let mut run_row = seed_run("run-empty");
        run_row.id = "run-empty".into();
        store.runs().insert(&run_row).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-empty".to_string(),
            WorkspaceHandle::for_local_path_test("repo-empty", workspace.path().to_path_buf()),
        );

        let result = empty_exploration_result();
        let cost = 250_000_i64;
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-empty", BudgetKind::AgentLoop, 10_000_000);
        let runtime = ScriptedExplorationRuntime::new(vec![Ok(result)], cost, tracker.clone());

        let bundle = make_bundle("run-empty", "repo-empty", Vec::new());
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let gate = StaticEscapeSuiteGate::green();

        let traces_root = tempfile::tempdir().unwrap();
        let report = drive_ai_exploration_pass(
            &runtime,
            &store,
            &bundle,
            &workspaces,
            &[],
            &gate,
            tx,
            traces_root.path(),
            DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
            DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
        )
        .await
        .unwrap();
        assert_eq!(report.findings_quarantined, 0);

        let rows = store.agent_traces().list_by_task_kind("Exploration").await.unwrap();
        assert_eq!(rows.len(), 1, "expected a single parent row, no per-finding rows");
        assert!(rows[0].finding_id.is_none());
        assert_eq!(rows[0].cost_usd_micros, cost);
        // Audit was empty (no extracted items), so no JSONL gets stamped.
        assert!(rows[0].conversation_jsonl_path.is_none());
    }

    #[tokio::test]
    async fn drive_ai_exploration_writes_audit_jsonl_and_stamps_trace_path() {
        // Acceptance: when the agent reports tool invocations, the
        // exploration pass writes one JSONL entry per `AuditEntry` under
        // `<traces_dir>/<run_id>/<task_id>.jsonl` and stamps the path on
        // the parent `agent_traces.conversation_jsonl_path` column.
        let tmp_db = tempfile::tempdir().unwrap();
        let store = Store::open(tmp_db.path()).await.unwrap();
        store.repos().upsert(&seed_repo("repo-audit")).await.unwrap();
        let mut run_row = seed_run("run-audit");
        run_row.id = "run-audit".into();
        store.runs().insert(&run_row).await.unwrap();

        let workspace = tempfile::tempdir().unwrap();
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "repo-audit".to_string(),
            WorkspaceHandle::for_local_path_test("repo-audit", workspace.path().to_path_buf()),
        );

        let mut result = empty_exploration_result();
        // One ExplorationFinding (audit: "record_exploration_finding"),
        // one ExplorationEvent (audit: "<other>"). Two JSONL lines
        // expected.
        result.extracted.push(nyctos_types::agent::ExtractedAgentResult::ExplorationFinding {
            path: "<api:/api/users/me>".into(),
            line: None,
            cap: "AUTH_BYPASS".into(),
            rationale: "Endpoint accepts no token".into(),
            endpoint: Some("GET /api/users/me".into()),
            suggested_payload_hint: None,
        });
        result.extracted.push(nyctos_types::agent::ExtractedAgentResult::ExplorationEvent {
            message: "probed /api/health and saw 200".into(),
        });

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-audit", BudgetKind::AgentLoop, 10_000_000);
        let runtime = ScriptedExplorationRuntime::new(vec![Ok(result)], 100_000, tracker.clone());

        let bundle = make_bundle("run-audit", "repo-audit", Vec::new());
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let gate = StaticEscapeSuiteGate::green();

        let traces_root = tempfile::tempdir().unwrap();
        let report = drive_ai_exploration_pass(
            &runtime,
            &store,
            &bundle,
            &workspaces,
            &[],
            &gate,
            tx,
            traces_root.path(),
            DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
            DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
        )
        .await
        .unwrap();
        assert_eq!(report.findings_quarantined, 1);

        let expected_path = traces_root.path().join("run-audit").join("expl-repo-audit.jsonl");
        assert!(expected_path.exists(), "expected {} to exist", expected_path.display());

        let body = std::fs::read_to_string(&expected_path).expect("read jsonl");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected two JSONL audit lines, got {}", lines.len());
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 json");
        assert_eq!(first["action"], "record_exploration_finding");
        assert!(first["summary"].as_str().unwrap().contains("<api:/api/users/me>"));
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 json");
        assert_eq!(second["action"], "<other>");

        let parent_rows: Vec<_> = store
            .agent_traces()
            .list_by_task_kind("Exploration")
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.finding_id.is_none())
            .collect();
        assert_eq!(parent_rows.len(), 1, "expected one parent Exploration trace row");
        assert_eq!(
            parent_rows[0].conversation_jsonl_path.as_deref(),
            Some(expected_path.to_string_lossy().as_ref()),
            "parent trace must stamp the JSONL path"
        );

        // Per-finding child rows must NOT stamp the path; the audit log
        // is a per-call artefact, not per-finding.
        let per_finding_rows: Vec<_> = store
            .agent_traces()
            .list_by_task_kind("Exploration")
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.finding_id.is_some())
            .collect();
        assert_eq!(per_finding_rows.len(), 1);
        assert!(per_finding_rows[0].conversation_jsonl_path.is_none());
    }
}

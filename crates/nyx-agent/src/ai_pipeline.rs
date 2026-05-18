//! AI runtime + payload-synthesis pipeline glue.
//!
//! Phase 14 lands two things here:
//!
//! 1. A [`BudgetStoreTracker`] that adapts `nyx-agent-core`'s SQLite
//!    `BudgetStore` to the `nyx-agent-ai::BudgetTracker` host port the
//!    adapters call on every successful round trip. The trait surface
//!    lives in `nyx-agent-ai`; the SQLite backend lives in
//!    `nyx-agent-core`; this binary owns the wiring.
//! 2. [`run_payload_synthesis_pass`], which scans a finished
//!    `RunBundle<Diag>` for diags carrying
//!    `Unsupported(NoPayloadsForCap)` and fans out one PayloadSynthesis
//!    task per finding. Concurrency is capped by
//!    `[ai] max_concurrent_one_shot`; spend is recorded against the
//!    run's `budgets` row.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nyx_agent_ai::{
    run_payload_synthesis, AnthropicSdkAdapter, BudgetTracker, PayloadSynthesisOutcome,
    SharedBudgetTracker,
};
use nyx_agent_core::store::{PayloadRecord, Store};
use nyx_agent_core::{
    AiConfig, AiRuntime as ConfigAiRuntime, RepoOutcome, RunBundle, SecretStore, WorkspaceHandle,
};
use nyx_agent_nyx::Diag;
use nyx_agent_types::agent::{AiError, BudgetKind};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::payload::{AttackProvenance, PayloadSynthesisInput};
use tokio::sync::Semaphore;

/// Default per-run AI budget cap applied to brand-new `(run_id, kind)`
/// rows the tracker auto-creates. Until the settings page lands a
/// runtime knob, this constant is the runaway-limit fallback.
const DEFAULT_RUN_BUDGET_USD_MICROS: i64 = 5_000_000; // $5.00

/// Per-call cap forwarded into `Budget.cap_usd_micros` for every
/// PayloadSynthesis call. The tracker-side cap (above) is the
/// authoritative bucket the adapter checks against; this per-call
/// value is informational on the wire.
const PAYLOAD_SYNTHESIS_PER_CALL_CAP_USD_MICROS: i64 = DEFAULT_RUN_BUDGET_USD_MICROS;

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

fn store_err(e: nyx_agent_core::StoreError) -> AiError {
    AiError::BudgetTracker(format!("{e}"))
}

#[async_trait]
impl BudgetTracker for BudgetStoreTracker {
    async fn cap(&self, run_id: &str, kind: BudgetKind) -> Result<Option<i64>, AiError> {
        self.ensure_row(run_id, kind).await?;
        let row =
            self.store.budgets().get(run_id, Self::kind_str(kind)).await.map_err(store_err)?;
        Ok(row.map(|r| r.cap_usd_micros))
    }

    async fn add_spend(
        &self,
        run_id: &str,
        kind: BudgetKind,
        micros: i64,
    ) -> Result<i64, AiError> {
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
/// finding in `bundle`. No-op (returns a default report) when
/// `config.runtime != Anthropic` or no API key is configured.
pub async fn run_payload_synthesis_pass(
    config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    bundle: &RunBundle<Diag>,
    workspaces: &HashMap<String, WorkspaceHandle>,
    events: EventSink,
) -> anyhow::Result<PayloadSynthesisPassReport> {
    if !matches!(config.runtime, ConfigAiRuntime::Anthropic) {
        return Ok(PayloadSynthesisPassReport::default());
    }
    let api_key = match secrets.get(nyx_agent_core::secrets::ACCOUNT_AI_ANTHROPIC) {
        Ok(Some(k)) => k,
        Ok(None) => {
            tracing::info!(
                "payload synthesis: AI runtime is anthropic but no API key configured; skipping"
            );
            return Ok(PayloadSynthesisPassReport::default());
        }
        Err(e) => return Err(anyhow::anyhow!("secret store error: {e}")),
    };
    let tracker: SharedBudgetTracker =
        Arc::new(BudgetStoreTracker::new(store.clone(), DEFAULT_RUN_BUDGET_USD_MICROS));
    let adapter = Arc::new(AnthropicSdkAdapter::new(api_key, tracker.clone()));

    let inputs = build_inputs(bundle, workspaces);
    if inputs.is_empty() {
        return Ok(PayloadSynthesisPassReport::default());
    }
    tracing::info!(count = inputs.len(), "payload synthesis: fanning out");

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_one_shot_resolved()));
    let mut handles = Vec::with_capacity(inputs.len());
    for input in inputs {
        let rt = Arc::clone(&adapter);
        let sem = Arc::clone(&semaphore);
        let sink = events.clone();
        handles.push(tokio::spawn(async move {
            let permit = sem.acquire_owned().await.expect("semaphore closed");
            let outcome = run_payload_synthesis(
                rt.as_ref(),
                &input,
                sink,
                PAYLOAD_SYNTHESIS_PER_CALL_CAP_USD_MICROS,
            )
            .await;
            drop(permit);
            outcome
        }));
    }

    let mut report = PayloadSynthesisPassReport::default();
    for handle in handles {
        match handle.await {
            Ok(Ok(outcome)) => apply_outcome(store, outcome, &mut report).await?,
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
            let finding_id = nyx_agent_core::store::finding_id_hash(
                &repo_bundle.repo,
                &diag.path,
                Some(line),
                &diag.cap,
                &diag.rule,
            );
            let lang = infer_lang(&diag.path);
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
) -> anyhow::Result<()> {
    match outcome {
        PayloadSynthesisOutcome::Synthesised {
            finding_id,
            cap,
            lang,
            output,
            prompt_version,
            spent_usd_micros,
            attempts,
        } => {
            let created_at = now_epoch_ms();
            let rec = PayloadRecord {
                id: format!("payload-{finding_id}-{created_at:x}"),
                finding_id,
                cap,
                lang,
                vuln_bytes: output.vuln_payload.into_bytes(),
                benign_bytes: Some(output.benign_payload.into_bytes()),
                oracle_blob: Some(output.vuln_oracle),
                attack_provenance: Some(AttackProvenance::LlmSynthesised.as_str().to_string()),
                prompt_version: Some(prompt_version),
                created_at,
            };
            store.payloads().insert(&rec).await?;
            report.synthesised += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
        PayloadSynthesisOutcome::Quarantined {
            finding_id,
            reason,
            spent_usd_micros,
            attempts,
        } => {
            let blob = serde_json::json!({
                "task": "PayloadSynthesis",
                "reason": reason,
            })
            .to_string();
            store.findings().quarantine(&finding_id, &blob).await?;
            report.quarantined += 1;
            report.spend_usd_micros += spent_usd_micros;
            report.total_attempts += u64::from(attempts);
        }
    }
    Ok(())
}

/// Map a source path to a language tag the prompt can quote. Keeps the
/// table small (Phase 14 only ships PayloadSynthesis for the languages
/// nyx already supports); unknown extensions land as `unknown`.
pub fn infer_lang(path: &str) -> String {
    let lower = path.to_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
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

fn now_epoch_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use nyx_agent_core::run::{CrossRepoCallgraphStub, RepoBundle};

    use super::*;

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
        let run = nyx_agent_core::store::RunRecord {
            id: "run-bt".to_string(),
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
        let run = nyx_agent_core::store::RunRecord {
            id: "run-cc".to_string(),
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
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg = AiConfig::default();
        assert!(matches!(cfg.runtime, ConfigAiRuntime::None));
        let report =
            run_payload_synthesis_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
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
            started_at_ms: 0,
            finished_at_ms: 0,
            wall_clock_ms: 0,
            per_repo: Vec::new(),
            callgraph: CrossRepoCallgraphStub::default(),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let cfg =
            AiConfig { runtime: ConfigAiRuntime::Anthropic, ..AiConfig::default() };
        let report =
            run_payload_synthesis_pass(&cfg, &store, &secrets, &bundle, &workspaces, tx)
                .await
                .unwrap();
        assert_eq!(report, PayloadSynthesisPassReport::default());
    }
}

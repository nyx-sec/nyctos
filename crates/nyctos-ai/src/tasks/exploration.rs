//! AI Exploration agent task.
//!
//! Drives the Claude Code agent loop against a running chain-lane
//! sandbox so the model can probe a real deployment with HTTP, shell,
//! and bounded file-write tools. The goal is to surface vulnerabilities
//! the nyx static pass and the heuristic novel-finding pass miss:
//! shadow APIs, state-machine flaws, CORS misconfigurations, etc.
//!
//! Three guard-rails wrap every call:
//!
//! 1. **Escape suite gate.** An [`EscapeSuiteGate`] runs the
//!    escape-regression suite before the AI driver starts. A red
//!    fixture refuses dispatch with a banner that names the failing
//!    test; the [`ClaudeCodeAdapter::agent_loop`] is never invoked.
//! 2. **Per-run hard cap.** The adapter checks the same
//!    `(run_id, AgentLoop)` budget bucket every other task uses.
//!    Default cap is $10 in USD micros tuned for Claude Opus
//!    pricing; the agent task surfaces `BudgetExceeded` in the
//!    typed outcome.
//! 3. **Per-task soft cap.** A separate warning threshold emits
//!    `AiEvent::TokenReceived` with a `[soft-cap]` prefix when the
//!    agent crosses the limit mid-run; spend continues until the
//!    hard cap fires. Operators can pick up the warning in the trace
//!    viewer without halting an in-progress exploration.
//!
//! The crate stays vendor-neutral. It does not depend on
//! `nyctos-core::store` or `nyctos-sandbox`. The binary glue in
//! `crates/nyctos/src/ai_pipeline.rs` wires:
//!   * an escape-suite gate backed by the real probe binary,
//!   * persistence of each [`ExplorationFinding`] as a `findings` row
//!     with `finding_origin = AiExploration` and `status = Quarantine`
//!     (the same dynamic-confirm gate novel-finding candidates flow
//!     through; the verifier promotes them when a payload + spec pair
//!     confirms).

use std::time::Duration;

use nyctos_types::agent::{
    AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind, ExtractedAgentResult,
};
use nyctos_types::event::{AgentEvent, AiEvent, EventSink};
use serde::Serialize;

use crate::runtime::AiRuntime;

/// Stable identifier for the exploration prompt template. Persisted
/// on every audit log entry so trail-back is unambiguous. The
/// `phase23` substring is a historical version slug, not a roadmap
/// marker; rev it only when the prompt body changes in a way
/// downstream consumers must distinguish.
pub const EXPLORATION_PROMPT_VERSION: &str = "phase23.exploration.v2";

/// Research-mode exploration prompt revision. Research mode changes
/// objective construction and self-pacing, but the same escape-suite,
/// budget, host, and tool gates still wrap execution.
pub const EXPLORATION_RESEARCH_PROMPT_VERSION: &str = "phase23.exploration.v2.research";

/// Default per-run hard cap. $10 in USD micros, tuned for Claude Opus
/// pricing.
pub const DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS: i64 = 10_000_000;

/// Default per-task soft cap. Crossing this threshold emits a single
/// warning event but does not halt the run; the hard cap above is the
/// only ceiling that aborts an in-progress exploration.
pub const DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS: i64 = 5_000_000;

/// Default wall-clock ceiling on a single exploration. The adapter's
/// own `--max-turns` flag bounds turn count; this bound caps real time.
pub const DEFAULT_EXPLORATION_WALL_CLOCK: Duration = Duration::from_secs(15 * 60);

/// Default tool count exposed to the agent. Mirrors the four tool
/// names this task registers under the agent loop.
pub const DEFAULT_EXPLORATION_TOOL_NAMES: &[&str] =
    &["Bash", "Read", "Grep", "record_exploration_finding"];

/// Configuration for one exploration run.
#[derive(Debug, Clone)]
pub struct ExplorationScope {
    /// Run identifier; used as the budget-store key and the audit log
    /// stamp.
    pub run_id: String,
    /// Logical task identifier. Echoed back in every streamed event.
    pub task_id: String,
    /// Hosts the agent may probe over HTTP. The exploration prompt
    /// names every entry verbatim so the model knows the in-scope
    /// surface; tool-side enforcement lives in the binary's tool
    /// adapter.
    pub allowed_hosts: Vec<String>,
    /// Endpoints the env-builder surfaced for this run. Carries a
    /// free-form description per endpoint so the prompt can hand the
    /// agent a structured starting point.
    pub target_endpoints: Vec<ExplorationEndpoint>,
    /// Compact scanner/candidate leads already known for this run.
    /// These are breadcrumbs, not proof: the agent should use them to
    /// pivot, de-duplicate, and look for stronger evidence or related
    /// higher-impact flaws.
    pub known_leads: Vec<ExplorationKnownLead>,
    /// Enables deeper product-logic exploration instructions without
    /// changing the live execution gates enforced by the host.
    pub research_mode_enabled: bool,
    /// Product-invariant focus lines derived from ResearchMode
    /// candidates and prior exploration memory.
    pub research_focus: Vec<String>,
    /// Repository workspace root for CLI-native file/search/shell
    /// tools. The adapter also uses this as the subprocess cwd.
    pub workspace_root: Option<String>,
    /// Hard ceiling on tool invocations. The adapter's `max_turns`
    /// flag is the primary bound; this is the upper limit the
    /// exploration prompt advertises so the model self-paces.
    pub max_actions: u32,
    /// Wall-clock ceiling on the agent loop. Defaults to
    /// [`DEFAULT_EXPLORATION_WALL_CLOCK`]. Per-call adapter timeout is
    /// managed by the adapter itself; this is informational on the
    /// prompt envelope.
    pub max_wall_clock: Duration,
    /// Sentinel-write file path the `fs.write_sentinel` tool may
    /// target. Anchored relative to the chain-lane workspace so the
    /// sandbox kernel can enforce write containment.
    pub sentinel_path: String,
    /// Per-run hard budget cap in USD micros. Defaults to
    /// [`DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS`].
    pub run_cap_usd_micros: i64,
    /// Per-task soft cap in USD micros. Defaults to
    /// [`DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS`].
    pub soft_cap_usd_micros: i64,
}

impl ExplorationScope {
    /// Sensible defaults for the budget caps and wall clock; caller
    /// fills `run_id` / `task_id` / `allowed_hosts` / `target_endpoints`
    /// from the live run context.
    pub fn new(run_id: impl Into<String>, task_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            task_id: task_id.into(),
            allowed_hosts: Vec::new(),
            target_endpoints: Vec::new(),
            known_leads: Vec::new(),
            research_mode_enabled: false,
            research_focus: Vec::new(),
            workspace_root: None,
            max_actions: 24,
            max_wall_clock: DEFAULT_EXPLORATION_WALL_CLOCK,
            sentinel_path: "nyx_exploration.sentinel".to_string(),
            run_cap_usd_micros: DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
            soft_cap_usd_micros: DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
        }
    }
}

/// One normalized prior lead from Nyx, ZAP, Nuclei, or another
/// candidate-producing scanner. The binary constructs these from the
/// `pentest_candidates` table so raw scanner JSON never lands in the
/// agent prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationKnownLead {
    /// Stable candidate id the verifier/planner can use later.
    pub id: String,
    /// Source label such as `NyxSignal`, `ZAPBaseline`, or `Nuclei`.
    pub source: String,
    /// Scanner/plugin title or static diagnostic message.
    pub title: String,
    /// Capability/vulnerability class.
    pub vuln_class: String,
    /// Severity guess as stored on the candidate.
    pub severity: String,
    /// Candidate lifecycle status.
    pub status: String,
    /// Best compact location: URL, matched endpoint, or repo:path:line.
    pub location: Option<String>,
    /// Current hypothesis. The prompt renderer truncates this heavily.
    pub hypothesis: String,
}

/// One endpoint the env-builder surfaced. The prompt renders these as
/// a bulleted list under "Targets" so the agent knows where to start.
#[derive(Debug, Clone)]
pub struct ExplorationEndpoint {
    /// HTTP method (`GET`, `POST`, ...). The agent is free to switch
    /// methods; the value is descriptive, not authoritative.
    pub method: String,
    /// URL the agent may probe. Should resolve to one of the allowed
    /// hosts.
    pub url: String,
    /// Free-form description (e.g. "REST list endpoint",
    /// "websocket upgrade"). Optional.
    pub description: Option<String>,
}

/// Pre-flight verdict from the escape-suite gate. Green allows the
/// driver to start; Red refuses with the failing fixture name so the
/// operator can fix the regression before re-enabling exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeSuiteVerdict {
    /// Every escape-suite fixture stayed contained.
    Green,
    /// One or more fixtures escaped. `fixture` names the failing
    /// test; `reason` carries the short diagnostic for the banner.
    Red { fixture: String, reason: String },
}

/// Trait the binary implements to plug a real escape-suite runner
/// into the exploration task. Kept narrow on purpose: the task crate
/// does not need to know how the suite is implemented, only the
/// verdict it produces.
#[async_trait::async_trait]
pub trait EscapeSuiteGate: Send + Sync {
    /// Run the escape-regression suite (or a cached recent result)
    /// and surface the verdict. Returning `Err` is reserved for cases
    /// where the suite itself could not run; a normal red fixture
    /// returns `Ok(EscapeSuiteVerdict::Red { .. })`.
    async fn check(&self) -> Result<EscapeSuiteVerdict, AiError>;
}

/// Typed view of one tool invocation the agent took. Built directly
/// from the [`AgentResult::extracted`] list. Ships as the audit log
/// surface; the binary persists one row per entry as JSONL under
/// `<state>/traces/<run_id>/<task_id>.jsonl` and stamps the path on
/// the parent `agent_traces.conversation_jsonl_path` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// Recognised tool name (`http.probe`, `record_exploration_finding`,
    /// ...). Unknown tools fold to `"<other>"` with the raw input
    /// captured in `summary` so the trail still survives.
    pub action: String,
    /// Short human-readable description of what the agent did. Built
    /// off the extracted payload so it stays terse; the full input
    /// JSON lives in the upstream stream-json transcript.
    pub summary: String,
}

/// Typed exploration finding the agent flagged. The binary turns each
/// of these into a row in the `findings` table with
/// `finding_origin = AiExploration` and `status = Quarantine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationFinding {
    /// File path or pseudo-path (e.g. `"<api:/admin/users>"` for a
    /// shadow API). The validator accepts any non-empty string.
    pub path: String,
    /// Optional 1-based line number when the finding pins to source.
    pub line: Option<u32>,
    /// Capability tag; same taxonomy NovelFindingDiscovery uses.
    pub cap: String,
    /// Short explanation. Required and non-empty.
    pub rationale: String,
    /// Optional API endpoint description for shadow-API findings.
    pub endpoint: Option<String>,
    /// Optional payload sketch the verifier seeds PayloadSynthesis
    /// with when promoting this quarantined finding.
    pub suggested_payload_hint: Option<String>,
}

/// Why a halted exploration stopped before producing findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorationHaltReason {
    /// The escape suite returned a red fixture. The driver never
    /// invoked the agent loop.
    EscapeSuiteRed { fixture: String, reason: String },
    /// The per-run hard cap was already exhausted before the call.
    BudgetCapAlreadyReached { cap_usd_micros: i64, spent_usd_micros: i64 },
}

/// Outcome of one [`run`] invocation.
#[derive(Debug, Clone)]
pub enum ExplorationOutcome {
    /// The agent loop ran to completion (or hit the adapter's own
    /// timeout / max-turns). `findings` carries the typed
    /// [`ExplorationFinding`]s the agent recorded; `audit` lists every
    /// recognised tool call in order; `final_message` is the agent's
    /// closing summary.
    Completed {
        findings: Vec<ExplorationFinding>,
        audit: Vec<AuditEntry>,
        final_message: String,
        turns: u32,
        spent_usd_micros: i64,
        prompt_version: String,
        /// True iff cumulative spend crossed
        /// [`ExplorationScope::soft_cap_usd_micros`]. The driver emitted
        /// a `[soft-cap]` warning frame on the event bus when this
        /// flipped.
        soft_cap_exceeded: bool,
        /// Per-call observability lifted from the agent-loop result.
        metrics: AgentTraceMetrics,
    },
    /// The driver refused to dispatch. `reason` carries the gating
    /// condition (escape-suite red, budget already exhausted).
    Halted { reason: ExplorationHaltReason },
}

/// Drive one exploration call.
///
/// Sequence:
///   1. Run the escape-suite gate. Red halts immediately with a
///      banner event.
///   2. Construct the [`AgentTask`] envelope (system prompt + tool
///      list) and dispatch through `runtime.agent_loop`.
///   3. Lift `extracted` results into typed findings + an audit log.
///   4. Compare cumulative spend against the soft cap; emit a warning
///      frame if crossed.
pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &ExplorationScope,
    gate: &dyn EscapeSuiteGate,
    sink: EventSink,
) -> Result<ExplorationOutcome, AiError> {
    // 1. Escape-suite precondition.
    match gate.check().await? {
        EscapeSuiteVerdict::Green => {}
        EscapeSuiteVerdict::Red { fixture, reason } => {
            let banner = format!(
                "[escape-suite RED] {fixture}: {reason}; AI exploration driver refused to start"
            );
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TokenReceived { task_id: scope.task_id.clone(), token: banner },
            });
            return Ok(ExplorationOutcome::Halted {
                reason: ExplorationHaltReason::EscapeSuiteRed { fixture, reason },
            });
        }
    }

    // 2. Build the agent task envelope.
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.run_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };

    // 3. Dispatch. The adapter's own pre-call check refuses with
    //    `AiError::BudgetExceeded` when the run is already at cap; we
    //    translate that into a typed `Halted` outcome so callers can
    //    distinguish "never ran" from "ran and errored".
    let result = match runtime.agent_loop(task, budget, sink.clone()).await {
        Ok(r) => r,
        Err(AiError::BudgetExceeded { cap_usd_micros, spent_usd_micros }) => {
            return Ok(ExplorationOutcome::Halted {
                reason: ExplorationHaltReason::BudgetCapAlreadyReached {
                    cap_usd_micros,
                    spent_usd_micros,
                },
            });
        }
        Err(err) => return Err(err),
    };

    // 4. Lift findings + audit.
    let (findings, audit) = lift_extracted(&result);

    // 5. Soft cap check. Emits a warning frame the trace viewer can
    //    render; spend continues until the hard cap fires inside the
    //    adapter.
    let soft_cap_exceeded = result.cost_usd_micros >= scope.soft_cap_usd_micros;
    if soft_cap_exceeded {
        let warn = format!(
            "[soft-cap] exploration spent {spent} usd-micros, soft cap {cap}; hard cap is {hard}",
            spent = result.cost_usd_micros,
            cap = scope.soft_cap_usd_micros,
            hard = scope.run_cap_usd_micros,
        );
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::TokenReceived { task_id: scope.task_id.clone(), token: warn },
        });
    }

    let metrics = AgentTraceMetrics::from_agent_result(&result);
    Ok(ExplorationOutcome::Completed {
        findings,
        audit,
        final_message: result.final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        prompt_version: result.prompt_version,
        soft_cap_exceeded,
        metrics,
    })
}

fn build_agent_task(scope: &ExplorationScope) -> AgentTask {
    let allowed = if scope.allowed_hosts.is_empty() {
        "(none; refuse any HTTP probe)".to_string()
    } else {
        scope.allowed_hosts.iter().map(|h| format!("- {h}")).collect::<Vec<_>>().join("\n")
    };
    let targets = if scope.target_endpoints.is_empty() {
        "(none; survey the workspace before probing)".to_string()
    } else {
        scope
            .target_endpoints
            .iter()
            .map(|e| {
                let desc = e.description.as_deref().map(|d| format!(": {d}")).unwrap_or_default();
                format!("- `{m} {u}`{desc}", m = e.method, u = e.url)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let workspace_root =
        scope.workspace_root.as_deref().unwrap_or("(adapter cwd; no explicit workspace root)");
    let max_secs = scope.max_wall_clock.as_secs();
    let known_leads = render_known_leads(&scope.known_leads);

    // Prompt bodies live at
    // `crates/nyctos-ai/src/prompts/exploration.v2.{system,objective}.md`
    // so the trace viewer can resolve the literal template that drove a
    // given run.
    let (prompt_version, system, objective) = if scope.research_mode_enabled {
        let research_focus = render_research_focus(&scope.research_focus);
        (
            EXPLORATION_RESEARCH_PROMPT_VERSION.to_string(),
            format!(
                include_str!("../prompts/exploration.v2.research.system.md"),
                max_actions = scope.max_actions,
                max_secs = max_secs,
            ),
            format!(
                include_str!("../prompts/exploration.v2.research.objective.md"),
                allowed = allowed,
                targets = targets,
                known_leads = known_leads,
                research_focus = research_focus,
                workspace_root = workspace_root,
                max_actions = scope.max_actions,
                max_secs = max_secs,
                sentinel = scope.sentinel_path,
            ),
        )
    } else {
        (
            EXPLORATION_PROMPT_VERSION.to_string(),
            format!(
                include_str!("../prompts/exploration.v2.system.md"),
                max_actions = scope.max_actions,
                max_secs = max_secs,
            ),
            format!(
                include_str!("../prompts/exploration.v2.objective.md"),
                allowed = allowed,
                targets = targets,
                known_leads = known_leads,
                workspace_root = workspace_root,
                max_actions = scope.max_actions,
                max_secs = max_secs,
                sentinel = scope.sentinel_path,
            ),
        )
    };

    AgentTask {
        prompt_version,
        task_id: scope.task_id.clone(),
        system,
        objective,
        tools: DEFAULT_EXPLORATION_TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
        working_directory: scope.workspace_root.clone(),
        max_turns: scope.max_actions,
    }
}

fn render_research_focus(focus: &[String]) -> String {
    if focus.is_empty() {
        return "(none; infer product invariants from routes, auth profiles, and known leads)"
            .to_string();
    }
    focus
        .iter()
        .take(16)
        .map(|line| format!("- {}", compact_prompt_field(line, 220)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_known_leads(leads: &[ExplorationKnownLead]) -> String {
    if leads.is_empty() {
        return "(none; prioritize route/source survey and live behavior)".to_string();
    }
    leads
        .iter()
        .map(|lead| {
            let location = lead
                .location
                .as_deref()
                .map(|s| compact_prompt_field(s, 140))
                .unwrap_or_else(|| "unknown".to_string());
            let line = serde_json::json!({
                "id": compact_prompt_field(&lead.id, 80),
                "source": compact_prompt_field(&lead.source, 40),
                "severity": compact_prompt_field(&lead.severity, 24),
                "status": compact_prompt_field(&lead.status, 24),
                "class": compact_prompt_field(&lead.vuln_class, 48),
                "location": location,
                "title": compact_prompt_field(&lead.title, 140),
                "hypothesis": compact_prompt_field(&lead.hypothesis, 220),
            });
            format!("- {}", serde_json::to_string(&line).unwrap_or_else(|_| "{}".to_string()))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_prompt_field(raw: &str, max_chars: usize) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    for (idx, ch) in compact.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn lift_extracted(result: &AgentResult) -> (Vec<ExplorationFinding>, Vec<AuditEntry>) {
    let mut findings = Vec::new();
    let mut audit = Vec::with_capacity(result.extracted.len());
    for ex in &result.extracted {
        match ex {
            ExtractedAgentResult::ExplorationFinding {
                path,
                line,
                cap,
                rationale,
                endpoint,
                suggested_payload_hint,
            } => {
                findings.push(ExplorationFinding {
                    path: path.clone(),
                    line: *line,
                    cap: cap.clone(),
                    rationale: rationale.clone(),
                    endpoint: endpoint.clone(),
                    suggested_payload_hint: suggested_payload_hint.clone(),
                });
                audit.push(AuditEntry {
                    action: "record_exploration_finding".to_string(),
                    summary: format!("{path} cap={cap}"),
                });
            }
            ExtractedAgentResult::PayloadFound { rule_id, body } => {
                audit.push(AuditEntry {
                    action: "record_payload".to_string(),
                    summary: format!("rule={rule_id} bytes={}", body.len()),
                });
            }
            ExtractedAgentResult::SpecFound { capability, .. } => {
                audit.push(AuditEntry {
                    action: "record_spec".to_string(),
                    summary: format!("cap={capability}"),
                });
            }
            ExtractedAgentResult::ChainsRanked { chain_ids, .. } => {
                audit.push(AuditEntry {
                    action: "record_chains".to_string(),
                    summary: format!("ranked={}", chain_ids.len()),
                });
            }
            ExtractedAgentResult::ExplorationEvent { message } => {
                let summary = if message.len() > 120 {
                    let mut cut = 120;
                    while cut > 0 && !message.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    format!("{}…", &message[..cut])
                } else {
                    message.clone()
                };
                audit.push(AuditEntry { action: "<other>".to_string(), summary });
            }
            ExtractedAgentResult::AttackVulnerability { title, severity, .. } => {
                audit.push(AuditEntry {
                    action: "record_attack_vulnerability".to_string(),
                    summary: format!("{severity} {title}"),
                });
            }
            ExtractedAgentResult::AuthProfileDiscovered { profile, .. } => {
                audit.push(AuditEntry {
                    action: "record_auth_profile".to_string(),
                    summary: format!("role={}", profile.role),
                });
            }
            ExtractedAgentResult::AuthSetupVerification { status, checks, warnings } => {
                audit.push(AuditEntry {
                    action: "record_auth_verification".to_string(),
                    summary: format!(
                        "status={status} checks={} warnings={}",
                        checks.len(),
                        warnings.len()
                    ),
                });
            }
            ExtractedAgentResult::AuthSessionAcquired { summary, .. } => {
                audit.push(AuditEntry {
                    action: "record_auth_session".to_string(),
                    summary: summary.clone(),
                });
            }
        }
    }
    (findings, audit)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use nyctos_types::agent::{
        AgentResult, AgentTask, AiError, BudgetKind, CostEstimate, ExtractedAgentResult, Prompt,
        Response, TokenUsage,
    };
    use nyctos_types::event::AgentEvent;
    use tokio::sync::broadcast;

    use super::*;
    use crate::runtime::{AiRuntime, BudgetTracker, InMemoryBudgetTracker};

    /// Scripted agent-loop runtime. Each call pops the next outcome
    /// off the queue; `cost_per_call` is added to the shared
    /// `BudgetTracker` so cap checks behave like the production
    /// adapter.
    struct ScriptedAgentLoop {
        outcomes: Mutex<Vec<Result<AgentResult, AiError>>>,
        tracker: Arc<dyn BudgetTracker>,
        cost_per_call: i64,
    }

    impl ScriptedAgentLoop {
        fn new(
            outcomes: Vec<Result<AgentResult, AiError>>,
            tracker: Arc<dyn BudgetTracker>,
            cost_per_call: i64,
        ) -> Self {
            Self { outcomes: Mutex::new(outcomes), tracker, cost_per_call }
        }
    }

    #[async_trait]
    impl AiRuntime for ScriptedAgentLoop {
        fn name(&self) -> &'static str {
            "scripted-agent-loop"
        }
        fn default_model(&self) -> &str {
            "scripted-agent-model"
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
            _sink: EventSink,
        ) -> Result<Response, AiError> {
            Err(AiError::UnsupportedMode("one_shot"))
        }

        async fn agent_loop(
            &self,
            task: AgentTask,
            budget: Budget,
            _sink: EventSink,
        ) -> Result<AgentResult, AiError> {
            // Mirror the real adapter's pre-call cap check so a
            // pre-exhausted run halts at the BudgetExceeded boundary. Cap
            // is the spendable ceiling, so the boundary is `>` (matching
            // the post-call check directly below).
            let spent = self.tracker.add_spend(&budget.run_id, budget.kind, 0).await?;
            if spent > budget.cap_usd_micros {
                return Err(AiError::BudgetExceeded {
                    cap_usd_micros: budget.cap_usd_micros,
                    spent_usd_micros: spent,
                });
            }
            let mut next =
                self.outcomes.lock().unwrap().pop().expect("scripted agent loop: no more outcomes");
            let cost = self.cost_per_call;
            let after = self.tracker.add_spend(&budget.run_id, budget.kind, cost).await?;
            if after > budget.cap_usd_micros {
                return Err(AiError::BudgetExceeded {
                    cap_usd_micros: budget.cap_usd_micros,
                    spent_usd_micros: after,
                });
            }
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

    struct GreenGate;
    #[async_trait]
    impl EscapeSuiteGate for GreenGate {
        async fn check(&self) -> Result<EscapeSuiteVerdict, AiError> {
            Ok(EscapeSuiteVerdict::Green)
        }
    }

    struct RedGate {
        fixture: String,
        reason: String,
    }
    #[async_trait]
    impl EscapeSuiteGate for RedGate {
        async fn check(&self) -> Result<EscapeSuiteVerdict, AiError> {
            Ok(EscapeSuiteVerdict::Red {
                fixture: self.fixture.clone(),
                reason: self.reason.clone(),
            })
        }
    }

    fn sample_scope() -> ExplorationScope {
        let mut s = ExplorationScope::new("run-expl", "task-expl");
        s.allowed_hosts.push("http://127.0.0.1:3000".to_string());
        s.workspace_root = Some("/tmp/nyctos-target".to_string());
        s.target_endpoints.push(ExplorationEndpoint {
            method: "GET".into(),
            url: "http://127.0.0.1:3000/rest/products".into(),
            description: Some("juice-shop REST list".into()),
        });
        s.max_actions = 4;
        s.run_cap_usd_micros = 1_000_000;
        s.soft_cap_usd_micros = 500_000;
        s
    }

    fn fake_result(extracted: Vec<ExtractedAgentResult>) -> AgentResult {
        AgentResult {
            prompt_version: EXPLORATION_PROMPT_VERSION.to_string(),
            task_id: String::new(),
            model: "scripted-model".to_string(),
            final_message: "exploration complete".to_string(),
            turns: 3,
            usage: TokenUsage { input_tokens: 800, output_tokens: 400 },
            cache: None,
            cost_usd_micros: 0,
            extracted,
        }
    }

    #[test]
    fn research_scope_uses_research_prompt_template_and_focus() {
        let mut scope = sample_scope();
        scope.research_mode_enabled = true;
        scope.research_focus.push(
            "ResearchMode entitlement_mismatch on POST /api/billing/subscriptions/{id}/downgrade"
                .to_string(),
        );
        scope.max_actions = 40;

        let task = build_agent_task(&scope);
        assert_eq!(task.prompt_version, EXPLORATION_RESEARCH_PROMPT_VERSION);
        assert_eq!(task.max_turns, 40);
        assert!(task.system.contains("Vuln Research Mode"));
        assert!(task.objective.contains("RESEARCH FOCUS"));
        assert!(task.objective.contains("entitlement_mismatch"));
        assert!(task.objective.contains("RESEARCH CHECKLIST"));
    }

    #[tokio::test]
    async fn green_gate_lifts_finding_from_agent_loop() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl", BudgetKind::AgentLoop, 1_000_000);
        let extracted = vec![
            ExtractedAgentResult::ExplorationFinding {
                path: "<api:/api/admin/orders>".into(),
                line: None,
                cap: "AUTH_BYPASS".into(),
                rationale: "GET admin endpoint accepts unauthenticated requests".into(),
                endpoint: Some("GET /api/admin/orders".into()),
                suggested_payload_hint: Some(
                    "curl -i http://127.0.0.1:3000/api/admin/orders".into(),
                ),
            },
            ExtractedAgentResult::ExplorationEvent {
                message: "probed /rest/products for IDOR".into(),
            },
        ];
        let rt = ScriptedAgentLoop::new(vec![Ok(fake_result(extracted))], tracker.clone(), 250_000);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_scope(), &GreenGate, tx).await.expect("ok");
        match outcome {
            ExplorationOutcome::Completed {
                findings,
                audit,
                final_message,
                turns,
                spent_usd_micros,
                prompt_version,
                soft_cap_exceeded,
                metrics,
            } => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].cap, "AUTH_BYPASS");
                assert_eq!(audit.len(), 2);
                assert_eq!(audit[0].action, "record_exploration_finding");
                assert_eq!(audit[1].action, "<other>");
                assert_eq!(final_message, "exploration complete");
                assert_eq!(turns, 3);
                assert_eq!(spent_usd_micros, 250_000);
                assert_eq!(prompt_version, EXPLORATION_PROMPT_VERSION);
                assert!(!soft_cap_exceeded, "250_000 < soft cap of 500_000");
                assert_eq!(metrics.usage.input_tokens, 800);
                assert_eq!(metrics.usage.output_tokens, 400);
                assert_eq!(metrics.model.as_deref(), Some("scripted-model"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(tracker.spent("run-expl", BudgetKind::AgentLoop), 250_000);
    }

    #[tokio::test]
    async fn red_gate_halts_with_banner_and_does_not_dispatch() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl", BudgetKind::AgentLoop, 1_000_000);
        // Empty outcomes queue: if the driver tried to dispatch the
        // agent loop, ScriptedAgentLoop would panic on the `expect`.
        let rt = ScriptedAgentLoop::new(vec![], tracker.clone(), 100_000);
        let (tx, mut rx) = broadcast::channel::<AgentEvent>(16);
        let gate = RedGate {
            fixture: "write_outside_workspace_is_contained".into(),
            reason: "wrote to /tmp/escaped".into(),
        };
        let outcome = run(&rt, &sample_scope(), &gate, tx).await.expect("ok");
        match outcome {
            ExplorationOutcome::Halted {
                reason: ExplorationHaltReason::EscapeSuiteRed { fixture, reason },
            } => {
                assert_eq!(fixture, "write_outside_workspace_is_contained");
                assert!(reason.contains("escaped"));
            }
            other => panic!("expected Halted(EscapeSuiteRed), got {other:?}"),
        }
        // Banner event landed on the bus.
        let frame = rx.try_recv().expect("banner");
        match frame {
            AgentEvent::Ai { data: AiEvent::TokenReceived { token, .. } } => {
                assert!(token.contains("escape-suite RED"), "banner: {token}");
                assert!(token.contains("write_outside_workspace_is_contained"));
            }
            other => panic!("expected Ai::TokenReceived banner, got {other:?}"),
        }
        // No spend recorded: the agent loop never dispatched.
        assert_eq!(tracker.spent("run-expl", BudgetKind::AgentLoop), 0);
    }

    #[tokio::test]
    async fn soft_cap_exceeded_emits_warning_but_still_completes() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl", BudgetKind::AgentLoop, 1_000_000);
        let extracted = vec![ExtractedAgentResult::ExplorationFinding {
            path: "src/api/admin.ts".into(),
            line: Some(42),
            cap: "CORS_MISCONFIG".into(),
            rationale: "Access-Control-Allow-Origin: * with credentials".into(),
            endpoint: None,
            suggested_payload_hint: None,
        }];
        let rt = ScriptedAgentLoop::new(
            vec![Ok(fake_result(extracted))],
            tracker.clone(),
            // Above the 500_000 soft cap but below the 1_000_000 hard cap.
            750_000,
        );
        let (tx, mut rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_scope(), &GreenGate, tx).await.expect("ok");
        match outcome {
            ExplorationOutcome::Completed { soft_cap_exceeded, spent_usd_micros, .. } => {
                assert!(soft_cap_exceeded);
                assert_eq!(spent_usd_micros, 750_000);
            }
            other => panic!("expected Completed with soft_cap_exceeded=true, got {other:?}"),
        }
        // Warning frame landed on the bus.
        let mut saw_warning = false;
        while let Ok(frame) = rx.try_recv() {
            if let AgentEvent::Ai { data: AiEvent::TokenReceived { token, .. } } = frame {
                if token.contains("soft-cap") {
                    saw_warning = true;
                    break;
                }
            }
        }
        assert!(saw_warning, "soft-cap warning frame must land on the bus");
    }

    #[tokio::test]
    async fn pre_exhausted_budget_halts_without_dispatch() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl", BudgetKind::AgentLoop, 1_000_000);
        // Pre-seed spend above the cap so the adapter's pre-call check
        // fires before the queue is touched.
        tracker.add_spend("run-expl", BudgetKind::AgentLoop, 1_500_000).await.expect("seed");
        let rt = ScriptedAgentLoop::new(vec![], tracker.clone(), 100_000);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_scope(), &GreenGate, tx).await.expect("ok");
        match outcome {
            ExplorationOutcome::Halted {
                reason:
                    ExplorationHaltReason::BudgetCapAlreadyReached { cap_usd_micros, spent_usd_micros },
            } => {
                assert_eq!(cap_usd_micros, 1_000_000);
                assert_eq!(spent_usd_micros, 1_500_000);
            }
            other => panic!("expected Halted(BudgetCapAlreadyReached), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_error_surfaces_through_unchanged() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-expl", BudgetKind::AgentLoop, 1_000_000);
        let rt = ScriptedAgentLoop::new(
            vec![Err(AiError::UpstreamRefused("429 rate limit".into()))],
            tracker.clone(),
            10_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let err = run(&rt, &sample_scope(), &GreenGate, tx).await.expect_err("upstream");
        assert!(matches!(err, AiError::UpstreamRefused(_)));
    }

    #[tokio::test]
    async fn agent_task_envelope_carries_scope_in_objective() {
        let mut scope = sample_scope();
        scope.known_leads.push(ExplorationKnownLead {
            id: "pc-zap-10021".into(),
            source: "ZAPBaseline".into(),
            title: "X-Content-Type-Options Header Missing".into(),
            vuln_class: "X-Content-Type-Options Header Missing".into(),
            severity: "Medium".into(),
            status: "NeedsLiveTest".into(),
            location: Some("GET http://127.0.0.1:3000/login".into()),
            hypothesis: "ZAP baseline reported a header alert; seek stronger live evidence or a related issue.".into(),
        });
        let task = build_agent_task(&scope);
        assert_eq!(task.prompt_version, EXPLORATION_PROMPT_VERSION);
        assert!(task.system.contains("AI Exploration worker"));
        assert!(task.system.contains("record_exploration_finding"));
        assert!(task.system.contains("KNOWN SCANNER LEADS"));
        assert!(task.objective.contains("http://127.0.0.1:3000"));
        assert!(task.objective.contains("juice-shop REST list"));
        assert!(task.objective.contains("KNOWN SCANNER LEADS"));
        assert!(task.objective.contains("pc-zap-10021"));
        assert!(task.objective.contains("ZAPBaseline"));
        assert!(task.objective.contains("GET http://127.0.0.1:3000/login"));
        assert!(task.objective.contains("/tmp/nyctos-target"));
        assert!(task.objective.contains("max_actions:  4"));
        assert!(task.objective.contains("nyx_exploration.sentinel"));
        assert_eq!(task.working_directory.as_deref(), Some("/tmp/nyctos-target"));
        assert_eq!(task.tools.len(), DEFAULT_EXPLORATION_TOOL_NAMES.len());
        assert!(task.tools.iter().any(|t| t == "record_exploration_finding"));
        assert!(task.tools.iter().any(|t| t == "Bash"));
        assert!(task.tools.iter().any(|t| t == "Read"));
        assert!(task.tools.iter().any(|t| t == "Grep"));
    }
}

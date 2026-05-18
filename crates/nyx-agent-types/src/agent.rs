//! Shared types for the AI runtime layer.
//!
//! Every adapter (Anthropic SDK, Claude Code, OpenAI, ...) consumes the
//! same `Prompt` / `Response` envelope so the rest of the agent never
//! depends on a vendor SDK shape. The `prompt_version` field on `Prompt`
//! is persisted with every trace so a verdict can always be traced back
//! to the exact prompt that produced it.
//!
//! All types derive `ts_rs::TS` so the frontend consumes them directly
//! through the `build.rs`-generated bindings.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

/// Single-turn prompt envelope. The `prompt_version` field is the only
/// load-bearing constant - every adapter persists it alongside any
/// response so traces remain explainable across prompt edits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct Prompt {
    /// Stable identifier of the prompt template. Adapters and the trace
    /// store both persist this so a verdict can be tied back to the
    /// exact prompt revision that produced it.
    pub prompt_version: String,
    /// Logical task identifier used to namespace streaming events on
    /// the bus. The caller supplies it; adapters echo it back in every
    /// emitted `AiEvent`.
    pub task_id: String,
    /// Model override. When `None`, the adapter's `default_model()` is
    /// used.
    pub model: Option<String>,
    /// System prompt. Adapters that support prompt caching may attach a
    /// `cache_control` block to this slot.
    pub system: String,
    /// User message body.
    pub user: String,
    /// Hard ceiling on output tokens. Adapters clamp to vendor limits.
    pub max_output_tokens: u32,
    /// Sampling temperature. `0.0` for deterministic decoding.
    pub temperature: f32,
    /// Adapter-specific seed for deterministic sampling. Adapters that
    /// do not expose a seed ignore this.
    #[ts(type = "number | null")]
    pub seed: Option<u64>,
}

/// Adapter response envelope. Carries the model's final text plus the
/// accounting needed to persist a trace and reconcile budgets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct Response {
    /// Echoes the `prompt_version` from the request.
    pub prompt_version: String,
    /// Echoes the `task_id` from the request.
    pub task_id: String,
    /// Model name as reported by the vendor (which may differ from the
    /// requested alias).
    pub model: String,
    /// Final completion text.
    pub content: String,
    /// Token accounting.
    pub usage: TokenUsage,
    /// Prompt-cache statistics, if the adapter reports them. `None`
    /// when the runtime does not support caching.
    pub cache: Option<CacheStats>,
    /// Total cost charged for this call, in USD micros (1e-6 USD).
    #[ts(type = "number")]
    pub cost_usd_micros: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct CacheStats {
    pub cache_creation_tokens: u32,
    pub cache_read_tokens: u32,
}

/// Per-call budget contract. The adapter checks `cap_usd_micros` against
/// the per-run spend tracked by the host before and after every model
/// call; on cap-exceeded it emits `AiEvent::TaskHalted` and returns
/// `AiError::BudgetExceeded`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct Budget {
    /// Run identifier used as the budget-store key.
    pub run_id: String,
    /// Budget bucket. `OneShot` for `one_shot` calls; `AgentLoop` for
    /// multi-turn loops; `Total` is reserved for the per-run aggregate
    /// the host writes itself.
    pub kind: BudgetKind,
    /// Hard cap, in USD micros. Exceeding this cap halts the task.
    #[ts(type = "number")]
    pub cap_usd_micros: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum BudgetKind {
    OneShot,
    AgentLoop,
    Total,
}

impl BudgetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetKind::OneShot => "OneShot",
            BudgetKind::AgentLoop => "AgentLoop",
            BudgetKind::Total => "Total",
        }
    }
}

/// Pre-call cost prediction. Adapters that price deterministically
/// return this from `cost_estimate`; the host uses it for an early
/// halt check before the round-trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct CostEstimate {
    #[ts(type = "number")]
    pub min_usd_micros: i64,
    #[ts(type = "number")]
    pub max_usd_micros: i64,
}

/// Multi-turn agent task. The Anthropic adapter returns
/// `AiError::UnsupportedMode` from `agent_loop`; the Claude Code
/// adapter implements it. The type is defined here so both adapters
/// share one schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AgentTask {
    pub prompt_version: String,
    pub task_id: String,
    pub system: String,
    pub objective: String,
    pub tools: Vec<String>,
    pub max_turns: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AgentResult {
    pub prompt_version: String,
    pub task_id: String,
    pub final_message: String,
    pub turns: u32,
    pub usage: TokenUsage,
    #[ts(type = "number")]
    pub cost_usd_micros: i64,
    /// Structured artefacts the adapter lifted out of the agent loop's
    /// tool-use trace. The Claude Code adapter populates these from
    /// recognised function calls; PayloadSynthesis, SpecDerivation,
    /// ChainReasoning, and exploration consume them as the typed
    /// agent-loop output.
    #[serde(default)]
    pub extracted: Vec<ExtractedAgentResult>,
}

/// Typed view of the structured artefacts an agent loop produced.
///
/// The agent-loop trace is non-deterministic by nature; consumers do
/// not depend on event order, only on the set of `ExtractedAgentResult`
/// values the adapter recognised. Each variant carries the smallest
/// stable payload its consumer needs; richer per-variant schemas live
/// alongside the consuming task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind")]
pub enum ExtractedAgentResult {
    /// PayloadSynthesis output: exploit payload candidate (rule id +
    /// payload body).
    PayloadFound { rule_id: String, body: String },
    /// SpecDerivation output: capability spec inferred for a sink.
    SpecFound { capability: String, spec: String },
    /// ChainReasoning output: ranked chain ids with a short rationale.
    ChainsRanked { chain_ids: Vec<String>, rationale: String },
    /// Exploration output: AI-discovered candidate finding. Emitted by
    /// the Claude Code agent loop when it identifies a new
    /// vulnerability while exploring the workspace (shadow API, state
    /// machine flaw, CORS misconfiguration, ...).
    ExplorationFinding {
        path: String,
        line: Option<u32>,
        cap: String,
        rationale: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        suggested_payload_hint: Option<String>,
    },
    /// Free-form exploration trace event. Captures anything the agent
    /// surfaced that does not fit a more specific variant.
    ExplorationEvent { message: String },
}

/// Classify a tool-use block emitted by an agent-loop adapter into a
/// typed `ExtractedAgentResult`. Recognised names (`record_payload`,
/// `record_spec`, `record_chains`) lift their inputs into the typed
/// variant; any other tool name folds into `ExplorationEvent`. Adapters
/// that surface tool calls (Claude Code today, Anthropic agent-loop if
/// it ever ships) share this mapping so the trace store sees a single
/// stable shape.
pub fn classify_tool_use(name: &str, input: &serde_json::Value) -> Option<ExtractedAgentResult> {
    match name {
        "record_payload" => {
            let rule_id = input.get("rule_id")?.as_str()?.to_string();
            let body = input.get("body")?.as_str()?.to_string();
            Some(ExtractedAgentResult::PayloadFound { rule_id, body })
        }
        "record_spec" => {
            let capability = input.get("capability")?.as_str()?.to_string();
            let spec = match input.get("spec") {
                Some(v) => match v.as_str() {
                    Some(s) => s.to_string(),
                    None => v.to_string(),
                },
                None => return None,
            };
            Some(ExtractedAgentResult::SpecFound { capability, spec })
        }
        "record_chains" => {
            let chain_ids = input
                .get("chain_ids")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>();
            let rationale =
                input.get("rationale").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            Some(ExtractedAgentResult::ChainsRanked { chain_ids, rationale })
        }
        "record_exploration_finding" => {
            let path = input.get("path")?.as_str()?.to_string();
            let cap = input.get("cap")?.as_str()?.to_string();
            let rationale = input.get("rationale")?.as_str()?.to_string();
            if path.trim().is_empty() || cap.trim().is_empty() || rationale.trim().is_empty() {
                return None;
            }
            let line = input.get("line").and_then(|v| v.as_u64()).map(|n| n as u32);
            let endpoint = input.get("endpoint").and_then(|v| v.as_str()).map(|s| s.to_string());
            let suggested_payload_hint =
                input.get("suggested_payload_hint").and_then(|v| v.as_str()).map(|s| s.to_string());
            Some(ExtractedAgentResult::ExplorationFinding {
                path,
                line,
                cap,
                rationale,
                endpoint,
                suggested_payload_hint,
            })
        }
        _ => Some(ExtractedAgentResult::ExplorationEvent {
            message: format!("tool {name} input={input}"),
        }),
    }
}

/// Reason the adapter halted a task. Surfaced both on the event bus
/// (`AiEvent::TaskHalted`) and as part of the typed error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum HaltReason {
    BudgetCapReached,
    OperatorCancelled,
    UpstreamRefused,
}

#[derive(Debug, Error)]
pub enum AiError {
    #[error("budget cap of {cap_usd_micros} usd-micros reached (spent {spent_usd_micros})")]
    BudgetExceeded { cap_usd_micros: i64, spent_usd_micros: i64 },
    #[error("adapter does not support {0}")]
    UnsupportedMode(&'static str),
    #[error("upstream refused: {0}")]
    UpstreamRefused(String),
    #[error("upstream returned malformed response: {0}")]
    MalformedResponse(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("budget tracker error: {0}")]
    BudgetTracker(String),
    #[error("adapter unavailable: {0}")]
    AdapterUnavailable(String),
}

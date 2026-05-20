//! `AiRuntime` trait + concrete vendor adapters.
//!
//! Phase 12 ships the trait, the `BudgetTracker` host port, and the
//! direct-HTTP Anthropic Messages adapter. Subsequent phases add the
//! Claude Code CLI driver (Phase 13), OpenAI / Bedrock / Vertex
//! adapters, and a local-LLM driver. Adapters depend only on
//! `nyctos-types`; the agent binary wires the host-side budget
//! port to `nyctos-core`'s `BudgetStore` at startup.

pub mod adapter;
pub mod runtime;
pub mod tasks;

pub use adapter::anthropic::{
    AnthropicSdkAdapter, ANTHROPIC_VERSION, DEFAULT_BASE_URL, DEFAULT_RANKING_MODEL,
    DEFAULT_SYNTHESIS_MODEL,
};
pub use adapter::claude_code::{
    detect_claude_binary, parse_stream_json, ClaudeBinary, ClaudeCodeAdapter, DEFAULT_CLAUDE_BINARY,
};
pub use runtime::{
    deterministic_seed, AiRuntime, BudgetTracker, InMemoryBudgetTracker, SharedBudgetTracker,
};
pub use tasks::chain_reasoning::{run as run_chain_reasoning, ChainReasoningOutcome};
pub use tasks::exploration::{
    run as run_exploration, AuditEntry as ExplorationAuditEntry, EscapeSuiteGate,
    EscapeSuiteVerdict, ExplorationEndpoint, ExplorationFinding, ExplorationHaltReason,
    ExplorationOutcome, ExplorationScope, DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS,
    DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS, DEFAULT_EXPLORATION_WALL_CLOCK,
    EXPLORATION_PROMPT_VERSION,
};
pub use tasks::novel_findings::{run as run_novel_findings, NovelFindingDiscoveryOutcome};
pub use tasks::payload_synthesis::{run as run_payload_synthesis, PayloadSynthesisOutcome};
pub use tasks::spec_derivation::{
    read_excerpt as read_spec_excerpt, run as run_spec_derivation, SpecDerivationOutcome,
};

//! `AiRuntime` trait + concrete vendor adapters.
//!
//! Ships the trait, the `BudgetTracker` host port, the direct-HTTP
//! Anthropic Messages adapter, and the Claude Code / Codex CLI
//! all-in-one drivers. OpenAI API / Bedrock / Vertex and a local-LLM
//! driver remain on the roadmap. Adapters depend only on
//! `nyctos-types`; the agent binary wires the host-side budget port
//! to `nyctos-core`'s `BudgetStore` at startup.

pub mod adapter;
pub mod runtime;
pub mod tasks;

pub use adapter::anthropic::{
    AnthropicSdkAdapter, Pricing, ANTHROPIC_VERSION, DEFAULT_BASE_URL, DEFAULT_RANKING_MODEL,
    DEFAULT_SYNTHESIS_MODEL,
};
pub use adapter::claude_code::{
    detect_claude_binary, parse_stream_json, ClaudeBinary, ClaudeCodeAdapter,
    DEFAULT_CLAUDE_BINARY, MINIMUM_CLAUDE_VERSION,
};
pub use adapter::codex::{
    detect_codex_binary, parse_codex_jsonl, CodexBinary, CodexCliAdapter, DEFAULT_CODEX_BINARY,
    MINIMUM_CODEX_VERSION,
};
pub use runtime::{
    deterministic_seed, AiRuntime, BudgetTracker, InMemoryBudgetTracker, SharedBudgetTracker,
};
pub use tasks::attack_agent::{
    run as run_attack_agent, AttackAgentAuditEntry, AttackAgentKnownLead, AttackAgentOutcome,
    AttackAgentScope, AttackAgentVulnerability, AttackWorkspace, ExistingVulnerabilitySummary,
    ATTACK_AGENT_PROMPT_VERSION, DEFAULT_ATTACK_AGENT_MAX_TURNS,
};
pub use tasks::auth_setup::{
    run as run_auth_setup, AuthSetupOutcome, AuthSetupScope, AUTH_SETUP_PROMPT_VERSION,
    DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS,
};
pub use tasks::chain_reasoning::{run as run_chain_reasoning, ChainReasoningOutcome};
pub use tasks::exploration::{
    run as run_exploration, AuditEntry as ExplorationAuditEntry, EscapeSuiteGate,
    EscapeSuiteVerdict, ExplorationEndpoint, ExplorationFinding, ExplorationHaltReason,
    ExplorationKnownLead, ExplorationOutcome, ExplorationScope,
    DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS, DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
    DEFAULT_EXPLORATION_WALL_CLOCK, EXPLORATION_PROMPT_VERSION,
    EXPLORATION_RESEARCH_PROMPT_VERSION,
};
pub use tasks::live_evidence_review::{
    run as run_live_evidence_review, LiveEvidenceReviewDecision, LiveEvidenceReviewInput,
    LiveEvidenceReviewOutcome, LiveEvidenceReviewOutput, LIVE_EVIDENCE_REVIEW_PROMPT_VERSION,
};
pub use tasks::novel_findings::{run as run_novel_findings, NovelFindingDiscoveryOutcome};
pub use tasks::payload_synthesis::{run as run_payload_synthesis, PayloadSynthesisOutcome};
pub use tasks::spec_derivation::{
    read_excerpt as read_spec_excerpt, run as run_spec_derivation, SpecDerivationOutcome,
};

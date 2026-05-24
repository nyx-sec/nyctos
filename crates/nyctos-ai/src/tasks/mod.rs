//! Agent task implementations layered on top of `AiRuntime`.
//!
//! Each task is a small async fn that builds a typed `Prompt`, drives
//! the model through `runtime.one_shot` (or `agent_loop`), and lifts
//! the structured payload back into typed Rust. Persistence, retries
//! limited to validation failures, and budget caps all live here so the
//! adapter layer can stay vendor-neutral.

pub mod auth_setup;
pub mod chain_reasoning;
pub mod exploration;
pub mod live_evidence_review;
pub mod novel_findings;
pub mod payload_synthesis;
pub mod spec_derivation;

pub use auth_setup::{
    run as run_auth_setup, AuthSetupOutcome, AuthSetupScope, AUTH_SETUP_PROMPT_VERSION,
    DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS,
};
pub use chain_reasoning::{run as run_chain_reasoning, ChainReasoningOutcome};
pub use exploration::{
    run as run_exploration, AuditEntry as ExplorationAuditEntry, EscapeSuiteGate,
    EscapeSuiteVerdict, ExplorationEndpoint, ExplorationFinding, ExplorationHaltReason,
    ExplorationKnownLead, ExplorationOutcome, ExplorationScope,
    DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS, DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
    DEFAULT_EXPLORATION_WALL_CLOCK, EXPLORATION_PROMPT_VERSION,
    EXPLORATION_RESEARCH_PROMPT_VERSION,
};
pub use live_evidence_review::{
    run as run_live_evidence_review, LiveEvidenceReviewDecision, LiveEvidenceReviewInput,
    LiveEvidenceReviewOutcome, LiveEvidenceReviewOutput, LIVE_EVIDENCE_REVIEW_PROMPT_VERSION,
};
pub use novel_findings::{run as run_novel_findings, NovelFindingDiscoveryOutcome};
pub use payload_synthesis::{run as run_payload_synthesis, PayloadSynthesisOutcome};
pub use spec_derivation::{
    read_excerpt as read_spec_excerpt, run as run_spec_derivation, SpecDerivationOutcome,
};

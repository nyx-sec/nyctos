//! Agent task implementations layered on top of `AiRuntime`.
//!
//! Each task is a small async fn that builds a typed `Prompt`, drives
//! the model through `runtime.one_shot` (or `agent_loop`), and lifts
//! the structured payload back into typed Rust. Persistence, retries
//! limited to validation failures, and budget caps all live here so the
//! adapter layer can stay vendor-neutral.

pub mod chain_reasoning;
pub mod novel_findings;
pub mod payload_synthesis;
pub mod spec_derivation;

pub use chain_reasoning::{run as run_chain_reasoning, ChainReasoningOutcome};
pub use novel_findings::{run as run_novel_findings, NovelFindingDiscoveryOutcome};
pub use payload_synthesis::{run as run_payload_synthesis, PayloadSynthesisOutcome};
pub use spec_derivation::{
    read_excerpt as read_spec_excerpt, run as run_spec_derivation, SpecDerivationOutcome,
};

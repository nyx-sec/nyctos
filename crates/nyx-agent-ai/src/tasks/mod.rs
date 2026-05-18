//! Agent task implementations layered on top of `AiRuntime`.
//!
//! Each task is a small async fn that builds a typed `Prompt`, drives
//! the model through `runtime.one_shot` (or `agent_loop`), and lifts
//! the structured payload back into typed Rust. Persistence, retries
//! limited to validation failures, and budget caps all live here so the
//! adapter layer can stay vendor-neutral.

pub mod payload_synthesis;

pub use payload_synthesis::{run as run_payload_synthesis, PayloadSynthesisOutcome};

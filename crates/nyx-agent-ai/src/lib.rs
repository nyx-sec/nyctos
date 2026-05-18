//! `AiRuntime` trait + concrete vendor adapters.
//!
//! Phase 12 ships the trait, the `BudgetTracker` host port, and the
//! direct-HTTP Anthropic Messages adapter. Subsequent phases add the
//! Claude Code CLI driver (Phase 13), OpenAI / Bedrock / Vertex
//! adapters, and a local-LLM driver. Adapters depend only on
//! `nyx-agent-types`; the agent binary wires the host-side budget
//! port to `nyx-agent-core`'s `BudgetStore` at startup.

pub mod adapter;
pub mod runtime;

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

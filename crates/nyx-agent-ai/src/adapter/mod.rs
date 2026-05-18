//! Concrete `AiRuntime` adapters. Phase 12 ships `anthropic` (direct
//! HTTP against the Messages API); Phase 13 adds `claude_code` (CLI
//! subprocess for agent-loop work). Subsequent phases add OpenAI,
//! Bedrock, Vertex, and a local-LLM driver.

pub mod anthropic;
pub mod claude_code;

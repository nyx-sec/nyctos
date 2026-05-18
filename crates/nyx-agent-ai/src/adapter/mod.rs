//! Concrete `AiRuntime` adapters. Phase 12 ships `anthropic` (direct
//! HTTP against the Messages API); subsequent phases add Claude Code,
//! OpenAI, Bedrock, Vertex, and a local-LLM driver.

pub mod anthropic;

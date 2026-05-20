//! Concrete `AiRuntime` adapters. `anthropic` calls the Messages API
//! over direct HTTP for `one_shot` work; `claude_code` spawns the
//! `claude` CLI as a subprocess for `agent_loop` work. OpenAI,
//! Bedrock, Vertex, and a local-LLM driver remain on the roadmap.

pub mod anthropic;
pub mod claude_code;

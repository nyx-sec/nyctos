//! Concrete `AiRuntime` adapters. `anthropic` calls the Messages API
//! over direct HTTP for direct API work; `claude_code` and `codex`
//! spawn local all-in-one CLI backends. OpenAI API, Bedrock, Vertex,
//! and a local-LLM driver remain on the roadmap.

pub mod anthropic;
pub mod claude_code;
pub mod codex;

//! Concrete `AiRuntime` adapters. `anthropic` calls the Messages API
//! over direct HTTP for direct API work; `local_llm` calls an
//! OpenAI-compatible `/v1` endpoint; `claude_code` and `codex` spawn
//! local all-in-one CLI backends. OpenAI API, Bedrock, and Vertex
//! remain on the roadmap.

pub mod anthropic;
pub mod claude_code;
pub mod codex;
pub mod local_llm;

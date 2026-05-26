//! OpenAI-compatible local LLM adapter.
//!
//! This adapter targets local `/v1/chat/completions` servers such as
//! LM Studio, Ollama's OpenAI-compatible endpoint, and vLLM. It
//! implements one-shot tasks only; repository-aware agent loops remain
//! the responsibility of explicit CLI agent adapters.

use std::time::Duration;

use async_trait::async_trait;
use nyx_agent_types::agent::{
    AgentResult, AgentTask, AiError, Budget, CostEstimate, HaltReason, Prompt, Response, TokenUsage,
};
use nyx_agent_types::event::{AgentEvent, AiEvent, EventSink};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::runtime::{AiRuntime, SharedBudgetTracker};

pub const DEFAULT_LOCAL_LLM_MODEL: &str = "local-model";

#[derive(Clone)]
pub struct LocalLlmAdapter {
    api_base: String,
    bearer_token: Option<String>,
    http: Client,
    tracker: SharedBudgetTracker,
    default_model: String,
}

impl LocalLlmAdapter {
    pub fn new(
        api_base: impl Into<String>,
        bearer_token: Option<String>,
        tracker: SharedBudgetTracker,
    ) -> Self {
        Self {
            api_base: api_base.into(),
            bearer_token,
            http: Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
            tracker,
            default_model: DEFAULT_LOCAL_LLM_MODEL.to_string(),
        }
    }

    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = model.into();
        self
    }
}

#[async_trait]
impl AiRuntime for LocalLlmAdapter {
    fn name(&self) -> &'static str {
        "local-llm"
    }

    fn default_model(&self) -> &str {
        &self.default_model
    }

    fn supports_agent_loop(&self) -> bool {
        false
    }

    fn supports_prompt_cache(&self) -> bool {
        false
    }

    fn supports_deterministic_sampling(&self) -> bool {
        false
    }

    async fn one_shot(
        &self,
        prompt: Prompt,
        budget: Budget,
        sink: EventSink,
    ) -> Result<Response, AiError> {
        let model = prompt.model.clone().unwrap_or_else(|| self.default_model.clone());

        let spent_before = self.tracker.current_spend(&budget.run_id, budget.kind).await?;
        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
        if spent_before > cap {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TaskHalted {
                    task_id: prompt.task_id.clone(),
                    reason: HaltReason::BudgetCapReached,
                },
            });
            return Err(AiError::BudgetExceeded {
                cap_usd_micros: cap,
                spent_usd_micros: spent_before,
            });
        }

        let url = format!("{}/chat/completions", self.api_base.trim_end_matches('/'));
        let mut req = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .json(&build_request(&model, &prompt));
        if let Some(token) = self.bearer_token.as_deref().filter(|v| !v.trim().is_empty()) {
            req = req.bearer_auth(token.trim());
        }

        let res = req.send().await.map_err(|e| AiError::Transport(e.to_string()))?;
        let status = res.status();
        let bytes = res.bytes().await.map_err(|e| AiError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(AiError::UpstreamRefused(format!(
                "{} {}",
                status,
                String::from_utf8_lossy(&bytes)
            )));
        }

        let parsed: ChatCompletionResponse = serde_json::from_slice(&bytes)
            .map_err(|e| AiError::MalformedResponse(e.to_string()))?;
        let content = parsed
            .choices
            .iter()
            .filter_map(|choice| choice.message.content.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        if content.is_empty() {
            return Err(AiError::MalformedResponse(
                "OpenAI-compatible response had no message content".to_string(),
            ));
        }

        let usage = parsed.usage.unwrap_or_default();
        let token_usage = TokenUsage {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
        };
        let cost = 0;

        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::TokenReceived {
                task_id: prompt.task_id.clone(),
                token: content.clone(),
            },
        });

        let spent_after = self.tracker.add_spend(&budget.run_id, budget.kind, cost).await?;
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::BudgetTick {
                task_id: prompt.task_id.clone(),
                run_id: budget.run_id.clone(),
                spent_usd_micros: spent_after,
            },
        });

        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
        if spent_after > cap {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TaskHalted {
                    task_id: prompt.task_id.clone(),
                    reason: HaltReason::BudgetCapReached,
                },
            });
            return Err(AiError::BudgetExceeded {
                cap_usd_micros: cap,
                spent_usd_micros: spent_after,
            });
        }

        Ok(Response {
            prompt_version: prompt.prompt_version,
            task_id: prompt.task_id,
            model: parsed.model.unwrap_or(model),
            content,
            usage: token_usage,
            cache: None,
            cost_usd_micros: cost,
        })
    }

    async fn agent_loop(
        &self,
        _task: AgentTask,
        _budget: Budget,
        _sink: EventSink,
    ) -> Result<AgentResult, AiError> {
        Err(AiError::UnsupportedMode("agent_loop"))
    }

    fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
        Some(CostEstimate { min_usd_micros: 0, max_usd_micros: 0 })
    }
}

fn effective_cap(tracker_cap: Option<i64>, envelope_cap: i64) -> i64 {
    match tracker_cap {
        Some(t) => t.min(envelope_cap),
        None => envelope_cap,
    }
}

fn build_request(model: &str, prompt: &Prompt) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "max_tokens": prompt.max_output_tokens,
        "temperature": prompt.temperature,
        "stream": false,
        "messages": [
            { "role": "system", "content": prompt.system },
            { "role": "user", "content": prompt.user }
        ],
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatCompletionResponse {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<ApiUsage>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChoiceMessage {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ApiUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runtime::InMemoryBudgetTracker;
    use nyx_agent_types::agent::BudgetKind;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_prompt() -> Prompt {
        Prompt {
            prompt_version: "local.test.v1".to_string(),
            task_id: "task-local".to_string(),
            model: Some("llama-test".to_string()),
            system: "You are a triage assistant.".to_string(),
            user: "Return ok.".to_string(),
            max_output_tokens: 64,
            temperature: 0.0,
            seed: None,
        }
    }

    #[tokio::test]
    async fn one_shot_posts_openai_compatible_chat_completion() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer local-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-test",
                "model": "llama-test",
                "choices": [
                    { "message": { "role": "assistant", "content": "ok" } }
                ],
                "usage": { "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12 }
            })))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = LocalLlmAdapter::new(
            format!("{}/v1", server.uri()),
            Some("local-token".to_string()),
            tracker.clone(),
        );
        let (tx, rx) = tokio::sync::broadcast::channel(8);
        drop(rx);

        let response = adapter
            .one_shot(
                sample_prompt(),
                Budget {
                    run_id: "run-local".to_string(),
                    kind: BudgetKind::OneShot,
                    cap_usd_micros: i64::MAX,
                },
                tx,
            )
            .await
            .expect("response");

        assert_eq!(response.model, "llama-test");
        assert_eq!(response.content, "ok");
        assert_eq!(response.usage.input_tokens, 10);
        assert_eq!(response.usage.output_tokens, 2);
        assert_eq!(response.cost_usd_micros, 0);
        assert_eq!(tracker.spent("run-local", BudgetKind::OneShot), 0);
    }
}

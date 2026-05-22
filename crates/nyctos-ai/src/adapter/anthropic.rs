//! Anthropic Messages API adapter.
//!
//! Direct `reqwest` against `POST /v1/messages` to avoid pulling a
//! third-party SDK whose version drift would couple us to its release
//! cadence. The adapter implements `one_shot` only; `agent_loop`
//! returns `AiError::UnsupportedMode("agent_loop")`. Agent-loop work
//! lives in the Claude Code adapter sibling module.
//!
//! Wire format follows the public Messages API: a JSON body with
//! `model`, `system` (string or block array with `cache_control`),
//! `messages`, `max_tokens`, `temperature`. The response carries a
//! `content[]` array, a `model` echo, and a `usage` block with
//! `input_tokens` / `output_tokens` plus the optional
//! `cache_creation_input_tokens` / `cache_read_input_tokens` fields
//! the prompt-cache feature exposes.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use nyctos_types::agent::{
    AgentResult, AgentTask, AiError, Budget, CacheStats, CostEstimate, HaltReason, Prompt,
    Response, TokenUsage,
};
use nyctos_types::event::{AgentEvent, AiEvent, EventSink};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::runtime::{AiRuntime, SharedBudgetTracker};

/// Default Anthropic API endpoint. Tests override via [`AnthropicSdkAdapter::with_base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Pinned API version header expected by the Messages API.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default ranking model.
pub const DEFAULT_RANKING_MODEL: &str = "claude-haiku-4-5";

/// Default synthesis model (used as `default_model()` for general
/// one-shots; ranking-only callers pick the haiku model explicitly).
pub const DEFAULT_SYNTHESIS_MODEL: &str = "claude-opus-4-7";

/// Per-model pricing in USD micros per token.
///
/// Pricing sourced from public Anthropic pricing as of 2026-05-17.
/// Updating these constants requires no schema change; the adapter
/// already persists `cost_usd_micros` and `tokens_in/out` separately so
/// downstream consumers can reconcile if needed. Values use micros per
/// **token** (not per million tokens) so cost computations stay in
/// integer math.
const fn micros_per_token(per_mtok_dollars: i64) -> i64 {
    // 1 USD = 1_000_000 micros. per_mtok_dollars is USD per 1M tokens.
    // micros_per_token = per_mtok_dollars * 1_000_000 / 1_000_000 = per_mtok_dollars.
    per_mtok_dollars
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pricing {
    pub input_per_token_micros: i64,
    pub output_per_token_micros: i64,
    pub cache_write_per_token_micros: i64,
    pub cache_read_per_token_micros: i64,
}

impl Pricing {
    /// Build a `Pricing` from operator-friendly per-million-token USD
    /// rates. The micros math is identical to [`micros_per_token`];
    /// callers in `nyctos-core::config` use this to convert a parsed
    /// `[ai.pricing.<model>]` block into the adapter's internal shape.
    pub const fn from_per_mtok_usd(
        input_per_mtok_usd: i64,
        output_per_mtok_usd: i64,
        cache_write_per_mtok_usd: i64,
        cache_read_per_mtok_usd: i64,
    ) -> Self {
        Self {
            input_per_token_micros: micros_per_token(input_per_mtok_usd),
            output_per_token_micros: micros_per_token(output_per_mtok_usd),
            cache_write_per_token_micros: micros_per_token(cache_write_per_mtok_usd),
            cache_read_per_token_micros: micros_per_token(cache_read_per_mtok_usd),
        }
    }
}

fn builtin_pricing_for(model: &str) -> Pricing {
    // The match order matters: prefix matching catches versioned
    // suffixes like `claude-opus-4-7-20260101` returning the same
    // pricing as the alias.
    if model.starts_with("claude-haiku-4") {
        Pricing::from_per_mtok_usd(1, 5, 1, 0)
    } else if model.starts_with("claude-sonnet-4") {
        Pricing::from_per_mtok_usd(3, 15, 3, 0)
    } else {
        // Opus / unrecognised: default to opus pricing so unknown
        // models do not silently price as the cheapest tier.
        Pricing::from_per_mtok_usd(15, 75, 18, 1)
    }
}

#[derive(Clone)]
pub struct AnthropicSdkAdapter {
    api_key: String,
    base_url: String,
    http: Client,
    tracker: SharedBudgetTracker,
    default_model: String,
    /// Operator-supplied per-model price overrides. Keyed by exact
    /// model id (the same string the Messages API receives in
    /// `model:`). Lookup falls back to [`builtin_pricing_for`] when
    /// no override matches. Empty in tests and on installs that
    /// have not set `[ai.pricing.<model>]` in `nyctos.toml`.
    pricing_overrides: HashMap<String, Pricing>,
}

impl AnthropicSdkAdapter {
    /// Build a fresh adapter. `api_key` is the operator's Anthropic
    /// API key (the wizard pulls it from the OS keychain). `tracker`
    /// is the host-side budget port; tests pass `InMemoryBudgetTracker`.
    pub fn new(api_key: String, tracker: SharedBudgetTracker) -> Self {
        Self {
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            http: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            tracker,
            default_model: DEFAULT_SYNTHESIS_MODEL.to_string(),
            pricing_overrides: HashMap::new(),
        }
    }

    /// Override the base URL. Used by `wiremock` tests; production
    /// callers should leave the default.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Override the default model. Operators can pick the ranking
    /// model (`claude-haiku-4-5`) explicitly per-prompt; this knob is
    /// the fallback when `Prompt::model` is `None`.
    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = model.into();
        self
    }

    /// Replace the per-model pricing override table. Keys are exact
    /// model ids (no prefix matching); values are operator-supplied
    /// rates that win over [`builtin_pricing_for`] when they match.
    /// Pass `HashMap::new()` (the default) to fall back to the
    /// built-in table everywhere.
    pub fn with_pricing_overrides(mut self, overrides: HashMap<String, Pricing>) -> Self {
        self.pricing_overrides = overrides;
        self
    }

    /// Resolved pricing for `model`. Operator overrides win on exact
    /// match; otherwise [`builtin_pricing_for`] is consulted (which
    /// prefix-matches on the model family so versioned suffixes like
    /// `claude-opus-4-7-20260101` price identically to the alias).
    fn pricing_for(&self, model: &str) -> Pricing {
        if let Some(p) = self.pricing_overrides.get(model) {
            return *p;
        }
        builtin_pricing_for(model)
    }
}

#[async_trait]
impl AiRuntime for AnthropicSdkAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn default_model(&self) -> &str {
        &self.default_model
    }

    fn supports_agent_loop(&self) -> bool {
        false
    }

    fn supports_prompt_cache(&self) -> bool {
        true
    }

    fn supports_deterministic_sampling(&self) -> bool {
        // The Messages API does not currently expose a seed parameter.
        // `temperature: 0` is the only knob; flip this to `true` once
        // the upstream API gains a deterministic seed.
        false
    }

    async fn one_shot(
        &self,
        prompt: Prompt,
        budget: Budget,
        sink: EventSink,
    ) -> Result<Response, AiError> {
        let model = prompt.model.clone().unwrap_or_else(|| self.default_model.clone());
        let pricing = self.pricing_for(&model);

        // Pre-call budget check: refuse outright if we already past cap.
        // The effective cap is the tighter of (a) the run-wide cap held
        // by the shared tracker and (b) the per-call cap on the `Budget`
        // envelope, so a caller can tighten the per-call ceiling without
        // mutating shared run state. Boundary is `>` (cap is the
        // spendable ceiling); a call that lands exactly at cap proceeds,
        // the one after does not. The post-call check uses the same `>`
        // so both halves agree.
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

        let body = build_request(&model, &prompt, self.supports_prompt_cache());
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let res = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        let status = res.status();
        let bytes = res.bytes().await.map_err(|e| AiError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(AiError::UpstreamRefused(format!(
                "{} {}",
                status,
                String::from_utf8_lossy(&bytes)
            )));
        }

        let parsed: ApiResponse = serde_json::from_slice(&bytes)
            .map_err(|e| AiError::MalformedResponse(e.to_string()))?;

        let content = parsed
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => Some(text.as_str()),
                ContentBlock::Other => None,
            })
            .collect::<Vec<_>>()
            .join("");

        let usage = TokenUsage {
            input_tokens: parsed.usage.input_tokens,
            output_tokens: parsed.usage.output_tokens,
        };
        let cache = CacheStats {
            cache_creation_tokens: parsed.usage.cache_creation_input_tokens.unwrap_or(0),
            cache_read_tokens: parsed.usage.cache_read_input_tokens.unwrap_or(0),
        };

        let cost = i64::from(usage.input_tokens) * pricing.input_per_token_micros
            + i64::from(usage.output_tokens) * pricing.output_per_token_micros
            + i64::from(cache.cache_creation_tokens) * pricing.cache_write_per_token_micros
            + i64::from(cache.cache_read_tokens) * pricing.cache_read_per_token_micros;

        // Stream the materialised completion through the bus as a
        // single TokenReceived event. The Messages API supports SSE
        // streaming; this adapter ships the non-streaming path so the
        // request body stays deterministic and the wiremock tests can
        // assert against a fixed response. A future revision can
        // upgrade to `stream: true` and emit one event per delta.
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::TokenReceived {
                task_id: prompt.task_id.clone(),
                token: content.clone(),
            },
        });
        if cache.cache_creation_tokens > 0 {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::CacheMiss {
                    task_id: prompt.task_id.clone(),
                    tokens: cache.cache_creation_tokens,
                },
            });
        }
        if cache.cache_read_tokens > 0 {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::CacheHit {
                    task_id: prompt.task_id.clone(),
                    tokens: cache.cache_read_tokens,
                },
            });
        }

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
            model: parsed.model,
            content,
            usage,
            cache: Some(cache),
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

    fn cost_estimate(&self, prompt: &Prompt) -> Option<CostEstimate> {
        let model = prompt.model.clone().unwrap_or_else(|| self.default_model.clone());
        let p = self.pricing_for(&model);
        // Input-token count is unknown without a tokenizer; estimate
        // 1 token per 4 chars (the rough Anthropic guideline). Output
        // upper bound is the requested `max_output_tokens`.
        let approx_input_tokens = ((prompt.system.len() + prompt.user.len()) / 4).max(1) as i64;
        let min = approx_input_tokens * p.input_per_token_micros;
        let max = min + i64::from(prompt.max_output_tokens) * p.output_per_token_micros;
        Some(CostEstimate { min_usd_micros: min, max_usd_micros: max })
    }
}

/// Reconcile the two budget cap sources the adapter sees. The shared
/// `BudgetTracker` carries a run-wide cap configured at run start; the
/// per-call `Budget` envelope carries a `cap_usd_micros` the caller can
/// use to tighten an individual call. Min-wins so the envelope can
/// never raise the run cap, only lower it; a caller that wants the
/// tracker cap verbatim passes `i64::MAX`.
fn effective_cap(tracker_cap: Option<i64>, envelope_cap: i64) -> i64 {
    match tracker_cap {
        Some(t) => t.min(envelope_cap),
        None => envelope_cap,
    }
}

fn build_request(model: &str, prompt: &Prompt, prompt_cache: bool) -> serde_json::Value {
    let system = if prompt_cache {
        serde_json::json!([{
            "type": "text",
            "text": prompt.system,
            "cache_control": { "type": "ephemeral" },
        }])
    } else {
        serde_json::Value::String(prompt.system.clone())
    };
    serde_json::json!({
        "model": model,
        "max_tokens": prompt.max_output_tokens,
        "temperature": prompt.temperature,
        "system": system,
        "messages": [
            { "role": "user", "content": prompt.user }
        ],
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiResponse {
    model: String,
    #[serde(default)]
    content: Vec<ContentBlock>,
    usage: ApiUsage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiUsage {
    input_tokens: u32,
    output_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
}

#[cfg(test)]
mod test_support {
    /// Build a canned Anthropic-shaped JSON body for a single text
    /// response with the given usage.
    pub fn canned_response(
        model: &str,
        text: &str,
        input_tokens: u32,
        output_tokens: u32,
        cache_creation_input_tokens: Option<u32>,
        cache_read_input_tokens: Option<u32>,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{ "type": "text", "text": text }],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": cache_creation_input_tokens,
                "cache_read_input_tokens": cache_read_input_tokens,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runtime::{BudgetTracker, InMemoryBudgetTracker};
    use nyctos_types::agent::BudgetKind;
    use nyctos_types::event::{AgentEvent, AiEvent};
    use tokio::sync::broadcast;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_prompt() -> Prompt {
        Prompt {
            prompt_version: "phase12.test.v1".to_string(),
            task_id: "task-1".to_string(),
            model: Some("claude-haiku-4-5".to_string()),
            system: "you are a static analysis triage assistant".to_string(),
            user: "is this finding exploitable?".to_string(),
            max_output_tokens: 256,
            temperature: 0.0,
            seed: Some(42),
        }
    }

    fn budget(cap_usd_micros: i64) -> Budget {
        Budget { run_id: "run-1".to_string(), kind: BudgetKind::OneShot, cap_usd_micros }
    }

    async fn drain_ai_events(mut rx: broadcast::Receiver<AgentEvent>) -> Vec<AiEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let AgentEvent::Ai { data } = ev {
                out.push(data);
            }
        }
        out
    }

    #[tokio::test]
    async fn one_shot_returns_deterministic_response_through_mock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .and(header("x-api-key", "test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_support::canned_response(
                "claude-haiku-4-5",
                "yes, the eval sink is reachable",
                1_000,
                200,
                Some(500),
                Some(2_000),
            )))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let adapter = AnthropicSdkAdapter::new("test-key".to_string(), tracker.clone())
            .with_base_url(server.uri());

        let (tx, rx) = broadcast::channel::<AgentEvent>(32);
        let response =
            adapter.one_shot(sample_prompt(), budget(1_000_000), tx).await.expect("one_shot");

        assert_eq!(response.prompt_version, "phase12.test.v1");
        assert_eq!(response.task_id, "task-1");
        assert_eq!(response.model, "claude-haiku-4-5");
        assert_eq!(response.content, "yes, the eval sink is reachable");
        assert_eq!(response.usage.input_tokens, 1_000);
        assert_eq!(response.usage.output_tokens, 200);
        let cache = response.cache.expect("cache stats present");
        assert_eq!(cache.cache_creation_tokens, 500);
        assert_eq!(cache.cache_read_tokens, 2_000);

        // Pricing: haiku = 1 USD/MTok input, 5 USD/MTok output, write 1, read 0.
        // 1000 * 1 + 200 * 5 + 500 * 1 + 2000 * 0 = 1000 + 1000 + 500 = 2500
        // micros.
        assert_eq!(response.cost_usd_micros, 2_500);
        assert_eq!(tracker.spent("run-1", BudgetKind::OneShot), 2_500);

        let events = drain_ai_events(rx).await;
        assert!(events.iter().any(|e| matches!(e, AiEvent::TokenReceived { token, .. }
                if token == "yes, the eval sink is reachable")));
        assert!(events
            .iter()
            .any(|e| matches!(e, AiEvent::CacheMiss { tokens, .. } if *tokens == 500)));
        assert!(events
            .iter()
            .any(|e| matches!(e, AiEvent::CacheHit { tokens, .. } if *tokens == 2_000)));
        assert!(events.iter().any(|e| matches!(e, AiEvent::BudgetTick { spent_usd_micros, .. }
                if *spent_usd_micros == 2_500)));
        assert!(!events.iter().any(|e| matches!(e, AiEvent::TaskHalted { .. })));
    }

    #[tokio::test]
    async fn budget_cap_halts_after_overspend() {
        let server = MockServer::start().await;
        // Return a response whose cost computes to $0.02 (20_000 micros)
        // with a $0.01 cap. Haiku: 20_000 input * 1 + 0 output = 20_000.
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_support::canned_response(
                "claude-haiku-4-5",
                "ok",
                20_000,
                0,
                None,
                None,
            )))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 10_000);
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker.clone()).with_base_url(server.uri());

        let (tx, rx) = broadcast::channel::<AgentEvent>(32);
        let err = adapter
            .one_shot(sample_prompt(), budget(10_000), tx)
            .await
            .expect_err("budget cap should halt");
        match err {
            AiError::BudgetExceeded { cap_usd_micros, spent_usd_micros } => {
                assert_eq!(cap_usd_micros, 10_000);
                assert_eq!(spent_usd_micros, 20_000);
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }

        let events = drain_ai_events(rx).await;
        assert!(events.iter().any(|e| matches!(
            e,
            AiEvent::TaskHalted { reason: HaltReason::BudgetCapReached, .. }
        )));
    }

    #[tokio::test]
    async fn agent_loop_returns_unsupported_mode() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = AnthropicSdkAdapter::new("k".to_string(), tracker);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(4);
        let task = AgentTask {
            prompt_version: "v1".to_string(),
            task_id: "t".to_string(),
            system: "s".to_string(),
            objective: "o".to_string(),
            tools: vec!["fs.read".to_string()],
            working_directory: None,
            max_turns: 3,
        };
        let err = adapter
            .agent_loop(task, budget(0), tx)
            .await
            .expect_err("agent_loop should be unsupported");
        assert!(matches!(err, AiError::UnsupportedMode("agent_loop")));
    }

    #[tokio::test]
    async fn pre_call_cap_halt_when_already_over() {
        // No HTTP call is expected; the mock server's absence guarantees
        // a failure if the adapter still tries to dial out.
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 100);
        // Pre-load existing spend strictly above the cap. The boundary is
        // `>` on both pre- and post-call checks so landing exactly at the
        // cap is the spendable ceiling, not a refuse condition.
        tracker.add_spend("run-1", BudgetKind::OneShot, 101).await.unwrap();
        let adapter = AnthropicSdkAdapter::new("k".to_string(), tracker.clone())
            .with_base_url("http://127.0.0.1:1");

        let (tx, rx) = broadcast::channel::<AgentEvent>(32);
        let err = adapter
            .one_shot(sample_prompt(), budget(100), tx)
            .await
            .expect_err("should halt before HTTP");
        assert!(matches!(err, AiError::BudgetExceeded { .. }));

        let events = drain_ai_events(rx).await;
        assert!(events.iter().any(|e| matches!(
            e,
            AiEvent::TaskHalted { reason: HaltReason::BudgetCapReached, .. }
        )));
    }

    #[tokio::test]
    async fn envelope_cap_tightens_run_cap_min_wins() {
        // Tracker run-wide cap is generous ($1) but the per-call envelope
        // tightens to $0.01. The call cost lands at $0.02, so the
        // post-call check must halt against the envelope-tightened cap
        // and report 10_000 (envelope), not 1_000_000 (tracker).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_support::canned_response(
                "claude-haiku-4-5",
                "ok",
                20_000,
                0,
                None,
                None,
            )))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker.clone()).with_base_url(server.uri());

        let (tx, _rx) = broadcast::channel::<AgentEvent>(32);
        let err = adapter
            .one_shot(sample_prompt(), budget(10_000), tx)
            .await
            .expect_err("envelope cap should halt");
        match err {
            AiError::BudgetExceeded { cap_usd_micros, spent_usd_micros } => {
                assert_eq!(cap_usd_micros, 10_000, "envelope cap must win when tighter");
                assert_eq!(spent_usd_micros, 20_000);
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }

    #[test]
    fn effective_cap_takes_min_of_two_sources() {
        assert_eq!(effective_cap(Some(100), 50), 50);
        assert_eq!(effective_cap(Some(50), 100), 50);
        assert_eq!(effective_cap(None, 75), 75);
        assert_eq!(effective_cap(Some(100), i64::MAX), 100);
    }

    #[tokio::test]
    async fn upstream_error_surfaces_as_upstream_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker).with_base_url(server.uri());

        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let err = adapter
            .one_shot(sample_prompt(), budget(1_000_000), tx)
            .await
            .expect_err("upstream 429 should surface");
        assert!(matches!(err, AiError::UpstreamRefused(_)));
    }

    #[tokio::test]
    async fn request_body_includes_cache_control_on_system() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "system": [{
                    "type": "text",
                    "cache_control": { "type": "ephemeral" },
                }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_support::canned_response(
                "claude-haiku-4-5",
                "ok",
                1,
                1,
                None,
                None,
            )))
            .mount(&server)
            .await;

        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker).with_base_url(server.uri());

        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let _ = adapter.one_shot(sample_prompt(), budget(1_000_000), tx).await.expect("one_shot");
    }

    #[test]
    fn cost_estimate_is_bounded_by_max_output_tokens() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = AnthropicSdkAdapter::new("k".to_string(), tracker);
        let est = adapter.cost_estimate(&sample_prompt()).expect("estimate");
        assert!(est.min_usd_micros >= 1);
        assert!(est.max_usd_micros >= est.min_usd_micros);
    }

    #[test]
    fn capability_flags_match_phase12_contract() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = AnthropicSdkAdapter::new("k".to_string(), tracker);
        assert_eq!(adapter.name(), "anthropic");
        assert_eq!(adapter.default_model(), DEFAULT_SYNTHESIS_MODEL);
        assert!(!adapter.supports_agent_loop());
        assert!(adapter.supports_prompt_cache());
        assert!(!adapter.supports_deterministic_sampling());
    }

    #[test]
    fn pricing_override_wins_over_builtin_table() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let mut overrides = HashMap::new();
        overrides.insert("claude-opus-4-7".to_string(), Pricing::from_per_mtok_usd(12, 60, 15, 1));
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker).with_pricing_overrides(overrides);

        let resolved = adapter.pricing_for("claude-opus-4-7");
        assert_eq!(resolved.input_per_token_micros, 12);
        assert_eq!(resolved.output_per_token_micros, 60);
        assert_eq!(resolved.cache_write_per_token_micros, 15);
        assert_eq!(resolved.cache_read_per_token_micros, 1);
    }

    #[test]
    fn pricing_override_unmatched_model_falls_back_to_builtin() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let mut overrides = HashMap::new();
        overrides.insert(
            "claude-opus-4-7-20260101".to_string(),
            Pricing::from_per_mtok_usd(99, 99, 99, 99),
        );
        let adapter =
            AnthropicSdkAdapter::new("k".to_string(), tracker).with_pricing_overrides(overrides);

        // Override is keyed by exact id; `claude-haiku-4-5` does not
        // match, so the built-in haiku rate sheet wins.
        let resolved = adapter.pricing_for("claude-haiku-4-5");
        assert_eq!(resolved.input_per_token_micros, 1);
        assert_eq!(resolved.output_per_token_micros, 5);
        assert_eq!(resolved.cache_write_per_token_micros, 1);
        assert_eq!(resolved.cache_read_per_token_micros, 0);
    }

    #[test]
    fn empty_pricing_overrides_match_builtin_table_for_every_family() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = AnthropicSdkAdapter::new("k".to_string(), tracker);

        let haiku = adapter.pricing_for("claude-haiku-4-5");
        assert_eq!(haiku, Pricing::from_per_mtok_usd(1, 5, 1, 0));

        let sonnet = adapter.pricing_for("claude-sonnet-4-6");
        assert_eq!(sonnet, Pricing::from_per_mtok_usd(3, 15, 3, 0));

        let opus = adapter.pricing_for("claude-opus-4-7");
        assert_eq!(opus, Pricing::from_per_mtok_usd(15, 75, 18, 1));
    }
}

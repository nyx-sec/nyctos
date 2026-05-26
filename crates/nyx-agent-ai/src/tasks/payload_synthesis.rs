//! PayloadSynthesis agent task.
//!
//! Given a finding whose static-pass output asked for differential
//! payloads (`Unsupported(NoPayloadsForCap)` in the run-state vocabulary),
//! drive an `AiRuntime::one_shot` call against a strict JSON contract,
//! parse the response, and produce either a [`PayloadSynthesisOutcome::Synthesised`]
//! envelope for the binary to persist or [`PayloadSynthesisOutcome::Quarantined`]
//! after two consecutive validation failures.
//!
//! The task crate stays vendor-neutral. It does not depend on
//! `nyx-agent-core::store`; the binary turns a `Synthesised` outcome
//! into a `PayloadRecord` at write time.

use nyx_agent_types::agent::{AgentTraceMetrics, AiError, Budget, BudgetKind, Prompt, Response};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::payload::{
    PayloadSynthesisInput, PayloadSynthesisOutput, PAYLOAD_SYNTHESIS_PROMPT_VERSION,
};

use crate::runtime::AiRuntime;

/// First-attempt system prompt. Plain JSON contract; no prose, no code
/// fences, three string fields. Source lives at
/// `crates/nyx-agent-ai/src/prompts/payload_synthesis.v1.md` so the trace
/// viewer can resolve the literal body that drove a given run.
const SYSTEM_PROMPT_V1: &str = include_str!("../prompts/payload_synthesis.v1.md");

/// Retry system prompt. Identical contract but with the explicit "your
/// previous reply did not parse" framing the model can act on.
const SYSTEM_PROMPT_V1_STRICTER: &str = include_str!("../prompts/payload_synthesis.v1_stricter.md");

/// Outcome of one `run` invocation. Carries enough state for the
/// caller to either persist a payload row or quarantine the finding.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PayloadSynthesisOutcome {
    /// Both validation gates passed. The caller stores the
    /// `output.vuln_payload` / `output.benign_payload` / `output.vuln_oracle`
    /// triple under the finding with `attack_provenance = LlmSynthesised`.
    Synthesised {
        finding_id: String,
        cap: String,
        lang: String,
        output: PayloadSynthesisOutput,
        prompt_version: String,
        /// Sum of `cost_usd_micros` reported by every `one_shot` round
        /// trip this task drove (one on success, two on retry-then-success).
        spent_usd_micros: i64,
        /// Number of round trips that actually fired. `1` on first-pass
        /// success, `2` after a retry.
        attempts: u32,
        /// Accumulated per-call observability across every attempt.
        metrics: AgentTraceMetrics,
    },
    /// Both attempts failed validation. The caller flips the finding
    /// row to `status = Quarantine` and surfaces `reason` in the
    /// verdict blob so the operator sees why.
    Quarantined {
        finding_id: String,
        reason: String,
        spent_usd_micros: i64,
        attempts: u32,
        metrics: AgentTraceMetrics,
    },
}

/// Drive one PayloadSynthesis call for `input`.
///
/// `cap_usd_micros` is the per-call budget. Both attempts share this
/// cap because the runtime checks against the same `(run_id, kind)`
/// bucket via the `BudgetTracker` host port.
pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    input: &PayloadSynthesisInput,
    sink: EventSink,
    cap_usd_micros: i64,
) -> Result<PayloadSynthesisOutcome, AiError> {
    let task_id = format!("payload-{}", input.finding_id);
    let budget =
        || Budget { run_id: input.run_id.clone(), kind: BudgetKind::OneShot, cap_usd_micros };

    let prompt = build_prompt(SYSTEM_PROMPT_V1, &task_id, input);
    let resp1: Response = runtime.one_shot(prompt, budget(), sink.clone()).await?;
    let cost1 = resp1.cost_usd_micros;
    let metrics1 = AgentTraceMetrics::from_response(&resp1);
    let first_err = match parse_output(&resp1.content) {
        Ok(output) => {
            return Ok(PayloadSynthesisOutcome::Synthesised {
                finding_id: input.finding_id.clone(),
                cap: input.cap.clone(),
                lang: input.lang.clone(),
                output,
                prompt_version: resp1.prompt_version,
                spent_usd_micros: cost1,
                attempts: 1,
                metrics: metrics1,
            });
        }
        Err(msg) => msg,
    };

    let prompt2 = build_prompt(SYSTEM_PROMPT_V1_STRICTER, &task_id, input);
    let resp2: Response = runtime.one_shot(prompt2, budget(), sink).await?;
    let total_cost = cost1 + resp2.cost_usd_micros;
    let metrics_total = metrics1.merge(AgentTraceMetrics::from_response(&resp2));
    match parse_output(&resp2.content) {
        Ok(output) => Ok(PayloadSynthesisOutcome::Synthesised {
            finding_id: input.finding_id.clone(),
            cap: input.cap.clone(),
            lang: input.lang.clone(),
            output,
            prompt_version: resp2.prompt_version,
            spent_usd_micros: total_cost,
            attempts: 2,
            metrics: metrics_total,
        }),
        Err(second_err) => Ok(PayloadSynthesisOutcome::Quarantined {
            finding_id: input.finding_id.clone(),
            reason: format!(
                "payload synthesis failed twice (attempt 1: {first_err}; attempt 2: {second_err})"
            ),
            spent_usd_micros: total_cost,
            attempts: 2,
            metrics: metrics_total,
        }),
    }
}

fn build_prompt(system: &str, task_id: &str, input: &PayloadSynthesisInput) -> Prompt {
    let args_json =
        serde_json::to_string(&input.sink_ctx.args).unwrap_or_else(|_| "[]".to_string());
    let user = format!(
        "cap = {cap}\nlang = {lang}\ncallee = {callee}\nargs = {args}\n\nexcerpt:\n```{lang}\n{excerpt}\n```\n",
        cap = input.cap,
        lang = input.lang,
        callee = input.sink_ctx.callee,
        args = args_json,
        excerpt = input.sink_ctx.excerpt,
    );
    Prompt {
        prompt_version: PAYLOAD_SYNTHESIS_PROMPT_VERSION.to_string(),
        task_id: task_id.to_string(),
        model: None,
        system: system.to_string(),
        user,
        max_output_tokens: 768,
        temperature: 0.0,
        seed: None,
    }
}

fn parse_output(raw: &str) -> Result<PayloadSynthesisOutput, String> {
    let body = strip_code_fence(raw.trim());
    let out: PayloadSynthesisOutput =
        serde_json::from_str(body).map_err(|e| format!("malformed json: {e}"))?;
    if out.vuln_payload.trim().is_empty()
        || out.vuln_oracle.trim().is_empty()
        || out.benign_payload.trim().is_empty()
    {
        return Err("one or more required fields were empty".into());
    }
    Ok(out)
}

fn strip_code_fence(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("```json") {
        return rest.trim().trim_end_matches("```").trim();
    }
    if let Some(rest) = s.strip_prefix("```") {
        return rest.trim().trim_end_matches("```").trim();
    }
    s
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use nyx_agent_types::agent::{
        AgentResult, AgentTask, AiError, CacheStats, CostEstimate, TokenUsage,
    };
    use nyx_agent_types::event::AgentEvent;
    use nyx_agent_types::payload::SinkCtx;
    use tokio::sync::broadcast;

    use super::*;
    use crate::runtime::{AiRuntime, BudgetTracker, InMemoryBudgetTracker};
    use nyx_agent_types::agent::BudgetKind;

    /// Scripted runtime that replays a fixed sequence of `one_shot`
    /// responses. Each call pops the next entry; if the queue is empty
    /// it panics. Tracks the prompt sequence so assertions can verify
    /// retry-with-stricter-prompt happened.
    struct ScriptedRuntime {
        responses: Mutex<Vec<Result<String, AiError>>>,
        prompts_seen: Mutex<Vec<String>>,
        tracker: Arc<dyn BudgetTracker>,
        cost_per_call: i64,
    }

    impl ScriptedRuntime {
        fn new(
            responses: Vec<Result<String, AiError>>,
            tracker: Arc<dyn BudgetTracker>,
            cost_per_call: i64,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                prompts_seen: Mutex::new(Vec::new()),
                tracker,
                cost_per_call,
            }
        }

        fn prompts(&self) -> Vec<String> {
            self.prompts_seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AiRuntime for ScriptedRuntime {
        fn name(&self) -> &'static str {
            "scripted"
        }
        fn default_model(&self) -> &str {
            "scripted-model"
        }
        fn supports_agent_loop(&self) -> bool {
            false
        }
        fn supports_prompt_cache(&self) -> bool {
            false
        }
        fn supports_deterministic_sampling(&self) -> bool {
            true
        }

        async fn one_shot(
            &self,
            prompt: Prompt,
            budget: Budget,
            _sink: EventSink,
        ) -> Result<Response, AiError> {
            self.prompts_seen.lock().unwrap().push(prompt.system.clone());
            let next =
                self.responses.lock().unwrap().pop().expect("scripted runtime: no more responses");
            let content = next?;
            let cost = self.cost_per_call;
            self.tracker.add_spend(&budget.run_id, budget.kind, cost).await?;
            Ok(Response {
                prompt_version: prompt.prompt_version,
                task_id: prompt.task_id,
                model: "scripted-model".to_string(),
                content,
                usage: TokenUsage { input_tokens: 100, output_tokens: 50 },
                cache: Some(CacheStats::default()),
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
            Some(CostEstimate { min_usd_micros: 0, max_usd_micros: self.cost_per_call })
        }
    }

    fn sample_input(cap: &str) -> PayloadSynthesisInput {
        PayloadSynthesisInput {
            finding_id: "f-1".to_string(),
            run_id: "run-1".to_string(),
            cap: cap.to_string(),
            lang: "python".to_string(),
            sink_ctx: SinkCtx {
                callee: "cursor.execute".to_string(),
                args: vec!["query".to_string()],
                excerpt:
                    "def handler(query):\n    cursor.execute(\"SELECT * FROM users WHERE name='\" \
                     + query + \"'\")\n"
                        .to_string(),
            },
        }
    }

    fn ok_body(vuln: &str, oracle: &str, benign: &str) -> String {
        serde_json::json!({
            "vuln_payload": vuln,
            "vuln_oracle": oracle,
            "benign_payload": benign,
        })
        .to_string()
    }

    #[tokio::test]
    async fn sql_query_finding_produces_payload_pair() {
        // Scripted responses are popped from the back; queue with the
        // first-call answer last.
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let body = ok_body("' OR 1=1 --", "response leaks row data", "alice");
        let rt = ScriptedRuntime::new(vec![Ok(body.clone())], tracker.clone(), 2_500);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome =
            run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect("one_shot ok");

        match outcome {
            PayloadSynthesisOutcome::Synthesised {
                finding_id,
                cap,
                lang,
                output,
                prompt_version,
                spent_usd_micros,
                attempts,
                metrics,
            } => {
                assert_eq!(finding_id, "f-1");
                assert_eq!(cap, "SQL_QUERY");
                assert_eq!(lang, "python");
                assert_eq!(output.vuln_payload, "' OR 1=1 --");
                assert_eq!(output.benign_payload, "alice");
                assert_eq!(output.vuln_oracle, "response leaks row data");
                assert_eq!(prompt_version, PAYLOAD_SYNTHESIS_PROMPT_VERSION);
                assert_eq!(spent_usd_micros, 2_500);
                assert_eq!(attempts, 1);
                assert_eq!(metrics.usage.input_tokens, 100);
                assert_eq!(metrics.usage.output_tokens, 50);
                assert_eq!(metrics.model.as_deref(), Some("scripted-model"));
            }
            other => panic!("expected Synthesised, got {other:?}"),
        }
        // Acceptance: spend recorded against the run budget.
        assert_eq!(tracker.spent("run-1", BudgetKind::OneShot), 2_500);
    }

    #[tokio::test]
    async fn malformed_first_attempt_retries_with_stricter_prompt() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let good = ok_body("' OR 1=1 --", "leak", "alice");
        // Queue is popped from back: first call -> garbage, second -> good.
        let rt = ScriptedRuntime::new(
            vec![Ok(good), Ok("not json at all".to_string())],
            tracker.clone(),
            1_000,
        );

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect("ok");

        match outcome {
            PayloadSynthesisOutcome::Synthesised { attempts, spent_usd_micros, .. } => {
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 2_000);
            }
            other => panic!("expected Synthesised after retry, got {other:?}"),
        }
        // Two prompts seen: first the v1 system, then the stricter.
        let seen = rt.prompts();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("Reply with exactly one JSON object"));
        assert!(seen[1].contains("previous reply did not deserialise"));
        assert_eq!(tracker.spent("run-1", BudgetKind::OneShot), 2_000);
    }

    #[tokio::test]
    async fn two_malformed_attempts_quarantine() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let rt = ScriptedRuntime::new(
            vec![Ok("still not json".to_string()), Ok("not json at all".to_string())],
            tracker.clone(),
            1_000,
        );

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect("ok");

        match outcome {
            PayloadSynthesisOutcome::Quarantined {
                finding_id,
                reason,
                spent_usd_micros,
                attempts,
                metrics,
            } => {
                assert_eq!(finding_id, "f-1");
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 2_000);
                assert!(reason.contains("failed twice"), "reason: {reason}");
                assert_eq!(metrics.usage.input_tokens, 200);
                assert_eq!(metrics.usage.output_tokens, 100);
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
        // Spend still tracked even when quarantined - the model still
        // burned tokens.
        assert_eq!(tracker.spent("run-1", BudgetKind::OneShot), 2_000);
    }

    #[tokio::test]
    async fn missing_field_in_response_is_treated_as_malformed() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        // First a body missing `benign_payload`, then a correct body.
        let bad = serde_json::json!({
            "vuln_payload": "' OR 1=1 --",
            "vuln_oracle": "leak",
        })
        .to_string();
        let good = ok_body("' OR 1=1 --", "leak", "alice");
        let rt = ScriptedRuntime::new(vec![Ok(good), Ok(bad)], tracker.clone(), 1_000);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect("ok");
        assert!(matches!(outcome, PayloadSynthesisOutcome::Synthesised { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn empty_field_in_response_is_treated_as_malformed() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let blank = ok_body("' OR 1=1 --", "leak", "   ");
        let good = ok_body("' OR 1=1 --", "leak", "alice");
        let rt = ScriptedRuntime::new(vec![Ok(good), Ok(blank)], tracker.clone(), 1_000);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect("ok");
        assert!(matches!(outcome, PayloadSynthesisOutcome::Synthesised { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn code_fence_wrapper_is_tolerated() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let inner = ok_body("p", "o", "b");
        let wrapped = format!("```json\n{inner}\n```");
        let rt = ScriptedRuntime::new(vec![Ok(wrapped)], tracker.clone(), 500);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input("OS_COMMAND"), tx, 1_000_000).await.expect("ok");
        assert!(matches!(outcome, PayloadSynthesisOutcome::Synthesised { attempts: 1, .. }));
    }

    #[tokio::test]
    async fn upstream_error_surfaces_through() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let rt = ScriptedRuntime::new(
            vec![Err(AiError::UpstreamRefused("429 rate limit".to_string()))],
            tracker.clone(),
            1_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let err = run(&rt, &sample_input("SQL_QUERY"), tx, 1_000_000).await.expect_err("upstream");
        assert!(matches!(err, AiError::UpstreamRefused(_)));
    }
}

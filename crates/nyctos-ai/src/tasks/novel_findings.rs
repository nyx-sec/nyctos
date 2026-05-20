//! NovelFindingDiscovery agent task.
//!
//! Given a batch of source files plus the nyx static-pass findings that
//! already exist on those files, drive an `AiRuntime::one_shot` call
//! against a strict JSON contract, parse the response, validate each
//! candidate, and produce either a
//! [`NovelFindingDiscoveryOutcome::Discovered`] envelope (zero or more
//! candidates) or [`NovelFindingDiscoveryOutcome::NoCandidates`] when
//! two attempts both produce malformed output.
//!
//! The task crate stays vendor-neutral. It does not depend on
//! `nyctos-core::store`; the binary turns every candidate into a
//! `candidate_findings` row (quarantined awaiting Phase 19's verifier)
//! at persistence time.

use std::collections::HashSet;

use nyctos_types::agent::{AgentTraceMetrics, AiError, Budget, BudgetKind, Prompt, Response};
use nyctos_types::event::EventSink;
use nyctos_types::novel::{
    CandidateFinding, NovelFindingDiscoveryInput, NovelFindingDiscoveryOutput,
    NOVEL_FINDING_DISCOVERY_PROMPT_VERSION,
};

use crate::runtime::AiRuntime;

/// First-attempt system prompt. Plain JSON contract; describes the
/// sink taxonomy the structured output is keyed on plus the rules the
/// validator enforces. Source lives at
/// `crates/nyctos-ai/src/prompts/novel_findings.v1.md`.
const SYSTEM_PROMPT_V1: &str = include_str!("../prompts/novel_findings.v1.md");

/// Retry system prompt. Identical contract with the explicit "your
/// previous reply did not validate" framing.
const SYSTEM_PROMPT_V1_STRICTER: &str = include_str!("../prompts/novel_findings.v1_stricter.md");

/// Outcome of one `run` invocation. The binary turns every
/// [`Discovered::candidates`] entry into a `candidate_findings` row
/// (quarantined until the Phase 19 verifier promotes it). `NoCandidates`
/// is recorded only in the agent trace.
#[derive(Debug, Clone)]
pub enum NovelFindingDiscoveryOutcome {
    /// Both deserialise + validate gates passed. `output.candidates`
    /// may be empty (the model legitimately found nothing); the caller
    /// still records the spend / attempts and ticks the trace forward.
    Discovered {
        run_id: String,
        repo: String,
        batch_id: String,
        output: NovelFindingDiscoveryOutput,
        prompt_version: String,
        spent_usd_micros: i64,
        attempts: u32,
        metrics: AgentTraceMetrics,
    },
    /// Both attempts produced malformed output. The binary surfaces
    /// `reason` in the agent-trace store; nothing is persisted to the
    /// `candidate_findings` table for this batch.
    NoCandidates {
        run_id: String,
        repo: String,
        batch_id: String,
        reason: String,
        spent_usd_micros: i64,
        attempts: u32,
        metrics: AgentTraceMetrics,
    },
}

/// Drive one NovelFindingDiscovery call for `input`.
///
/// `cap_usd_micros` is the per-call budget. Both attempts share the
/// same `(run_id, kind)` budget bucket via the `BudgetTracker` host
/// port.
pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    input: &NovelFindingDiscoveryInput,
    sink: EventSink,
    cap_usd_micros: i64,
) -> Result<NovelFindingDiscoveryOutcome, AiError> {
    let task_id = format!("novel-{}", input.batch_id);
    let budget =
        || Budget { run_id: input.run_id.clone(), kind: BudgetKind::OneShot, cap_usd_micros };
    let known_paths: HashSet<&str> = input.files.iter().map(|f| f.path.as_str()).collect();

    let prompt = build_prompt(SYSTEM_PROMPT_V1, &task_id, input);
    let resp1: Response = runtime.one_shot(prompt, budget(), sink.clone()).await?;
    let cost1 = resp1.cost_usd_micros;
    let metrics1 = AgentTraceMetrics::from_response(&resp1);
    let first_err = match parse_and_validate(&resp1.content, &known_paths) {
        Ok(output) => {
            return Ok(NovelFindingDiscoveryOutcome::Discovered {
                run_id: input.run_id.clone(),
                repo: input.repo.clone(),
                batch_id: input.batch_id.clone(),
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
    match parse_and_validate(&resp2.content, &known_paths) {
        Ok(output) => Ok(NovelFindingDiscoveryOutcome::Discovered {
            run_id: input.run_id.clone(),
            repo: input.repo.clone(),
            batch_id: input.batch_id.clone(),
            output,
            prompt_version: resp2.prompt_version,
            spent_usd_micros: total_cost,
            attempts: 2,
            metrics: metrics_total,
        }),
        Err(second_err) => Ok(NovelFindingDiscoveryOutcome::NoCandidates {
            run_id: input.run_id.clone(),
            repo: input.repo.clone(),
            batch_id: input.batch_id.clone(),
            reason: format!(
                "novel finding discovery failed twice (attempt 1: {first_err}; attempt 2: {second_err})"
            ),
            spent_usd_micros: total_cost,
            attempts: 2,
            metrics: metrics_total,
        }),
    }
}

fn build_prompt(system: &str, task_id: &str, input: &NovelFindingDiscoveryInput) -> Prompt {
    let user = render_user_message(input);
    Prompt {
        prompt_version: NOVEL_FINDING_DISCOVERY_PROMPT_VERSION.to_string(),
        task_id: task_id.to_string(),
        model: None,
        system: system.to_string(),
        user,
        // The batch carries up to ~30 truncated files; the response is
        // small (a candidate is ~150 bytes serialised). 4096 leaves
        // plenty of headroom for a dozen candidates per batch.
        max_output_tokens: 4096,
        temperature: 0.0,
        seed: None,
    }
}

/// Compact, model-friendly serialisation of the input. `serde_json` is
/// avoided for the file bodies because fenced code blocks are far
/// easier for the model to read than escaped JSON strings.
fn render_user_message(input: &NovelFindingDiscoveryInput) -> String {
    let mut out = String::new();
    out.push_str(&format!("run_id  = {}\n", input.run_id));
    out.push_str(&format!("repo    = {}\n", input.repo));
    out.push_str(&format!("batch   = {}\n", input.batch_id));
    out.push('\n');

    out.push_str("priors (already flagged by the static pass; do NOT rediscover):\n");
    if input.priors.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for p in &input.priors {
            out.push_str(&format!("- {} L{} cap={} rule={}\n", p.path, p.line, p.cap, p.rule,));
        }
    }
    out.push('\n');

    out.push_str("files:\n");
    for f in &input.files {
        out.push_str(&format!("\n--- {} ---\n", f.path));
        out.push_str("```\n");
        out.push_str(&f.content);
        if !f.content.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n");
        if f.truncated {
            out.push_str(
                "(note: this file was truncated; do not invent lines past the visible region)\n",
            );
        }
    }
    out
}

fn parse_and_validate(
    raw: &str,
    known_paths: &HashSet<&str>,
) -> Result<NovelFindingDiscoveryOutput, String> {
    let body = strip_code_fence(raw.trim());
    let out: NovelFindingDiscoveryOutput =
        serde_json::from_str(body).map_err(|e| format!("malformed json: {e}"))?;
    validate_candidates(&out.candidates, known_paths)?;
    Ok(out)
}

fn validate_candidates(
    candidates: &[CandidateFinding],
    known_paths: &HashSet<&str>,
) -> Result<(), String> {
    for (i, c) in candidates.iter().enumerate() {
        if c.line == 0 {
            return Err(format!("candidate {i}: line must be >= 1"));
        }
        if c.cap.trim().is_empty() {
            return Err(format!("candidate {i}: cap was empty"));
        }
        if c.rationale.trim().is_empty() {
            return Err(format!("candidate {i}: rationale was empty"));
        }
        if !known_paths.contains(c.path.as_str()) {
            return Err(format!(
                "candidate {i}: path {:?} is not in the batch's file list",
                c.path
            ));
        }
    }
    Ok(())
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
    use nyctos_types::agent::{
        AgentResult, AgentTask, AiError, CacheStats, CostEstimate, TokenUsage,
    };
    use nyctos_types::event::AgentEvent;
    use nyctos_types::novel::{FileForReview, PriorFinding};
    use tokio::sync::broadcast;

    use super::*;
    use crate::runtime::{AiRuntime, BudgetTracker, InMemoryBudgetTracker};
    use nyctos_types::agent::BudgetKind;

    /// Scripted runtime that replays a fixed sequence of `one_shot`
    /// responses. Same shape as the payload / spec / chain test
    /// fixtures.
    struct ScriptedRuntime {
        responses: Mutex<Vec<Result<String, AiError>>>,
        prompts_seen: Mutex<Vec<String>>,
        user_messages_seen: Mutex<Vec<String>>,
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
                user_messages_seen: Mutex::new(Vec::new()),
                tracker,
                cost_per_call,
            }
        }

        fn prompts(&self) -> Vec<String> {
            self.prompts_seen.lock().unwrap().clone()
        }

        fn user_messages(&self) -> Vec<String> {
            self.user_messages_seen.lock().unwrap().clone()
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
            self.user_messages_seen.lock().unwrap().push(prompt.user.clone());
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
                usage: TokenUsage { input_tokens: 500, output_tokens: 200 },
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

    fn sample_input() -> NovelFindingDiscoveryInput {
        // One known SQL_QUERY sink at line 3 (the prior); a second
        // syntactically-similar sink at line 6 the model is expected
        // to flag.
        NovelFindingDiscoveryInput {
            run_id: "run-N".into(),
            repo: "repo-1".into(),
            batch_id: "repo-1:0".into(),
            files: vec![FileForReview {
                path: "app/handlers.py".into(),
                content: "def list_users(q):\n    sql = 'SELECT * FROM u WHERE n=' + q\n    cursor.execute(sql)\n\ndef list_admins(q):\n    sql2 = 'SELECT * FROM admin WHERE n=' + q\n    cursor.execute(sql2)\n".into(),
                truncated: false,
            }],
            priors: vec![PriorFinding {
                path: "app/handlers.py".into(),
                line: 3,
                cap: "SQL_QUERY".into(),
                rule: "py.sql.exec".into(),
            }],
        }
    }

    fn ok_body(candidates: serde_json::Value) -> String {
        serde_json::json!({ "candidates": candidates }).to_string()
    }

    #[tokio::test]
    async fn similar_second_sink_produces_a_candidate() {
        // Acceptance for the per-task layer: a file carrying one known
        // nyx sink + an intentionally similar second sink yields a
        // candidate for the second one and skips the first.
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let body = ok_body(serde_json::json!([
            {
                "path": "app/handlers.py",
                "line": 6,
                "cap": "SQL_QUERY",
                "rule_hint": "py.sql.exec",
                "rationale": "list_admins reuses the same SQL-string-concat pattern as the prior at line 3",
                "suggested_payload_hint": "' OR 1=1 --"
            }
        ]));
        let rt = ScriptedRuntime::new(vec![Ok(body)], tracker.clone(), 6_000);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        match outcome {
            NovelFindingDiscoveryOutcome::Discovered {
                run_id,
                repo,
                batch_id,
                output,
                prompt_version,
                spent_usd_micros,
                attempts,
                metrics,
            } => {
                assert_eq!(run_id, "run-N");
                assert_eq!(repo, "repo-1");
                assert_eq!(batch_id, "repo-1:0");
                assert_eq!(attempts, 1);
                assert_eq!(spent_usd_micros, 6_000);
                assert_eq!(prompt_version, NOVEL_FINDING_DISCOVERY_PROMPT_VERSION);
                assert_eq!(output.candidates.len(), 1);
                let c = &output.candidates[0];
                assert_eq!(c.path, "app/handlers.py");
                assert_eq!(c.line, 6);
                assert_eq!(c.cap, "SQL_QUERY");
                assert!(!c.rationale.is_empty());
                assert_eq!(metrics.usage.input_tokens, 500);
                assert_eq!(metrics.usage.output_tokens, 200);
                assert_eq!(metrics.model.as_deref(), Some("scripted-model"));
            }
            other => panic!("expected Discovered, got {other:?}"),
        }
        // Priors surface in the rendered user message so the model can
        // see what to avoid.
        let user = rt.user_messages().into_iter().next().expect("user msg");
        assert!(user.contains("py.sql.exec"), "priors must appear: {user}");
        assert!(user.contains("--- app/handlers.py ---"));
    }

    #[tokio::test]
    async fn empty_candidates_array_is_accepted() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let rt =
            ScriptedRuntime::new(vec![Ok(ok_body(serde_json::json!([])))], tracker.clone(), 1_000);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        match outcome {
            NovelFindingDiscoveryOutcome::Discovered { output, attempts, .. } => {
                assert!(output.candidates.is_empty());
                assert_eq!(attempts, 1);
            }
            other => panic!("expected Discovered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_first_attempt_retries_with_stricter_prompt() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let good = ok_body(serde_json::json!([
            {
                "path": "app/handlers.py",
                "line": 6,
                "cap": "SQL_QUERY",
                "rationale": "ok",
            }
        ]));
        // Queue popped from back: first call -> garbage, second -> good.
        let rt = ScriptedRuntime::new(
            vec![Ok(good), Ok("not json at all".to_string())],
            tracker.clone(),
            2_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        match outcome {
            NovelFindingDiscoveryOutcome::Discovered { attempts, spent_usd_micros, .. } => {
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 4_000);
            }
            other => panic!("expected Discovered after retry, got {other:?}"),
        }
        let seen = rt.prompts();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("NovelFindingDiscovery worker"));
        assert!(seen[1].contains("previous reply did not validate"));
    }

    #[tokio::test]
    async fn unknown_path_is_rejected() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let bad = ok_body(serde_json::json!([
            {"path":"made/up.py","line":1,"cap":"SQL_QUERY","rationale":"x"}
        ]));
        let good = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":6,"cap":"SQL_QUERY","rationale":"real one"}
        ]));
        // First reply names a file outside the batch; retry returns a
        // valid candidate.
        let rt = ScriptedRuntime::new(vec![Ok(good), Ok(bad)], tracker.clone(), 1_000);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        assert!(matches!(outcome, NovelFindingDiscoveryOutcome::Discovered { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn zero_line_is_rejected() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let bad = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":0,"cap":"SQL_QUERY","rationale":"bad line"}
        ]));
        let good = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":6,"cap":"SQL_QUERY","rationale":"good"}
        ]));
        let rt = ScriptedRuntime::new(vec![Ok(good), Ok(bad)], tracker.clone(), 800);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        assert!(matches!(outcome, NovelFindingDiscoveryOutcome::Discovered { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn empty_rationale_is_rejected() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let bad = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":6,"cap":"SQL_QUERY","rationale":"   "}
        ]));
        let good = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":6,"cap":"SQL_QUERY","rationale":"non-empty"}
        ]));
        let rt = ScriptedRuntime::new(vec![Ok(good), Ok(bad)], tracker.clone(), 800);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        assert!(matches!(outcome, NovelFindingDiscoveryOutcome::Discovered { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn two_malformed_attempts_yield_no_candidates() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let rt = ScriptedRuntime::new(
            vec![Ok("still nope".to_string()), Ok("nope".to_string())],
            tracker.clone(),
            1_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        match outcome {
            NovelFindingDiscoveryOutcome::NoCandidates {
                run_id,
                repo,
                batch_id,
                reason,
                spent_usd_micros,
                attempts,
                metrics,
            } => {
                assert_eq!(run_id, "run-N");
                assert_eq!(repo, "repo-1");
                assert_eq!(batch_id, "repo-1:0");
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 2_000);
                assert!(reason.contains("failed twice"), "reason: {reason}");
                assert_eq!(metrics.usage.input_tokens, 1_000);
                assert_eq!(metrics.usage.output_tokens, 400);
            }
            other => panic!("expected NoCandidates, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn code_fence_wrapper_is_tolerated() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let inner = ok_body(serde_json::json!([
            {"path":"app/handlers.py","line":6,"cap":"SQL_QUERY","rationale":"ok"}
        ]));
        let wrapped = format!("```json\n{inner}\n```");
        let rt = ScriptedRuntime::new(vec![Ok(wrapped)], tracker.clone(), 500);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 5_000_000).await.expect("ok");
        assert!(matches!(outcome, NovelFindingDiscoveryOutcome::Discovered { attempts: 1, .. }));
    }

    #[tokio::test]
    async fn upstream_error_surfaces_through() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-N", BudgetKind::OneShot, 5_000_000);
        let rt = ScriptedRuntime::new(
            vec![Err(AiError::UpstreamRefused("429 rate limit".to_string()))],
            tracker.clone(),
            1_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let err = run(&rt, &sample_input(), tx, 5_000_000).await.expect_err("upstream");
        assert!(matches!(err, AiError::UpstreamRefused(_)));
    }
}

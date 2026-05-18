//! SpecDerivation agent task.
//!
//! Given a finding whose static-pass output asked for a harness spec
//! (`Inconclusive(SpecDerivationFailed)` in the run-state vocabulary),
//! drive an `AiRuntime::one_shot` call against a strict JSON contract,
//! parse the response, validate it against the vendored `HarnessSpec`
//! schema, and produce either a [`SpecDerivationOutcome::Synthesised`]
//! envelope for the binary to persist or
//! [`SpecDerivationOutcome::Quarantined`] after two consecutive
//! validation failures.
//!
//! The task crate stays vendor-neutral. It does not depend on
//! `nyx-agent-core::store`; the binary turns a `Synthesised` outcome
//! into a `HarnessSpecRecord` at write time and stamps the parent
//! finding's `spec_id` back-link.

use nyx_agent_nyx::HarnessSpec;
use nyx_agent_types::agent::{AiError, Budget, BudgetKind, Prompt, Response};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::spec::{FileExcerpt, SpecDerivationInput, SPEC_DERIVATION_PROMPT_VERSION};

use crate::runtime::AiRuntime;

/// First-attempt system prompt. Plain JSON contract; describes the
/// `HarnessSpec` shape the verifier consumes.
const SYSTEM_PROMPT_V1: &str = "\
You are nyx-agent's SpecDerivation worker.

INPUT
You receive a sink the static analyser flagged but for which it could
not infer a harness shape. The user message names:
- `cap`     : capability tag the sink falls under (e.g. SQL_QUERY)
- `lang`    : source language (e.g. python, javascript)
- `callee`  : function or method invoked at the sink
- one or more file excerpts labelled `call_site`, `sink`, or `framework`.
  Each excerpt header carries the file path and a line marker.

TASK
Produce a `HarnessSpec` JSON the verifier can execute to exercise the
sink. The schema is:

{
  \"schema_version\": 1,
  \"cap\":            \"<same as input cap>\",
  \"lang\":           \"<same as input lang>\",
  \"entry\":          \"<module/symbol the harness should call>\",
  \"setup\":          [\"<setup statement>\", \"...\"],
  \"invoke\":         \"<call expression containing @PAYLOAD exactly once>\",
  \"payload_arg\":    <zero-based index of the arg the payload replaces>,
  \"oracle\":         \"<predicate that decides exploit success>\",
  \"teardown\":       [\"<optional teardown statement>\"]
}

RULES
- `invoke` MUST contain the literal token `@PAYLOAD` exactly once. The
  verifier substitutes the synthesised payload at that slot.
- `oracle` MUST describe a deterministic, side-effect predicate (e.g.
  `\"stdout contains '/etc/passwd'\"` or `\"row count > expected\"`).
- `setup` / `teardown` are optional; emit empty arrays when none apply.
- `entry` should reference a real symbol or module path visible from
  the supplied excerpts. Synthesise a wrapper if the sink is private.

CONTRACT
Reply with exactly one JSON object and nothing else. No prose. No code
fences. Extra fields are tolerated for forward-compat but should be
avoided.
";

/// Retry system prompt. Identical contract but with the explicit "your
/// previous reply did not validate" framing.
const SYSTEM_PROMPT_V1_STRICTER: &str = "\
You are nyx-agent's SpecDerivation worker.

The previous reply did not validate against the required `HarnessSpec`
shape.

Required shape:
{
  \"schema_version\": 1,
  \"cap\":            \"<same as input cap>\",
  \"lang\":           \"<same as input lang>\",
  \"entry\":          \"<module/symbol the harness should call>\",
  \"setup\":          [\"<setup statement>\", \"...\"],
  \"invoke\":         \"<call expression containing @PAYLOAD exactly once>\",
  \"payload_arg\":    <zero-based index of the arg the payload replaces>,
  \"oracle\":         \"<predicate that decides exploit success>\",
  \"teardown\":       []
}

Reply with ONLY that JSON object. All required string fields non-empty.
`invoke` must contain `@PAYLOAD` exactly once. No prose. No markdown.
No code fences.
";

/// Outcome of one `run` invocation. Carries enough state for the
/// caller to either persist the spec + stamp the finding or quarantine
/// the finding outright.
#[derive(Debug, Clone)]
pub enum SpecDerivationOutcome {
    /// Both deserialise + validate gates passed. The caller stores the
    /// canonical `spec_blob` under a new `harness_specs` row and
    /// stamps `findings.spec_id` + `attack_provenance = LlmSynthesised`.
    /// `spec` is boxed to keep the enum variant compact - the
    /// `HarnessSpec` body is ~300 bytes once the `extra` Map allocates.
    Synthesised {
        finding_id: String,
        cap: String,
        lang: String,
        spec: Box<HarnessSpec>,
        /// Canonical JSON serialisation of `spec`. Adapters store this
        /// blob verbatim so the verifier consumes the same bytes the
        /// agent validated.
        spec_blob: String,
        prompt_version: String,
        spent_usd_micros: i64,
        attempts: u32,
    },
    /// Both attempts failed validation. The caller flips the finding
    /// row to `status = Quarantine` and surfaces `reason` in the
    /// verdict blob so the operator sees why.
    Quarantined { finding_id: String, reason: String, spent_usd_micros: i64, attempts: u32 },
}

/// Drive one SpecDerivation call for `input`.
///
/// `cap_usd_micros` is the per-call budget. Both attempts share the
/// same `(run_id, kind)` budget bucket via the `BudgetTracker` host
/// port.
pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    input: &SpecDerivationInput,
    sink: EventSink,
    cap_usd_micros: i64,
) -> Result<SpecDerivationOutcome, AiError> {
    let task_id = format!("spec-{}", input.finding_id);
    let budget =
        || Budget { run_id: input.run_id.clone(), kind: BudgetKind::OneShot, cap_usd_micros };

    let prompt = build_prompt(SYSTEM_PROMPT_V1, &task_id, input);
    let resp1: Response = runtime.one_shot(prompt, budget(), sink.clone()).await?;
    let cost1 = resp1.cost_usd_micros;
    let first_err = match parse_and_validate(&resp1.content) {
        Ok((spec, blob)) => {
            return Ok(SpecDerivationOutcome::Synthesised {
                finding_id: input.finding_id.clone(),
                cap: input.cap.clone(),
                lang: input.lang.clone(),
                spec: Box::new(spec),
                spec_blob: blob,
                prompt_version: resp1.prompt_version,
                spent_usd_micros: cost1,
                attempts: 1,
            });
        }
        Err(msg) => msg,
    };

    let prompt2 = build_prompt(SYSTEM_PROMPT_V1_STRICTER, &task_id, input);
    let resp2: Response = runtime.one_shot(prompt2, budget(), sink).await?;
    let total_cost = cost1 + resp2.cost_usd_micros;
    match parse_and_validate(&resp2.content) {
        Ok((spec, blob)) => Ok(SpecDerivationOutcome::Synthesised {
            finding_id: input.finding_id.clone(),
            cap: input.cap.clone(),
            lang: input.lang.clone(),
            spec: Box::new(spec),
            spec_blob: blob,
            prompt_version: resp2.prompt_version,
            spent_usd_micros: total_cost,
            attempts: 2,
        }),
        Err(second_err) => Ok(SpecDerivationOutcome::Quarantined {
            finding_id: input.finding_id.clone(),
            reason: format!(
                "spec derivation failed twice (attempt 1: {first_err}; attempt 2: {second_err})"
            ),
            spent_usd_micros: total_cost,
            attempts: 2,
        }),
    }
}

fn build_prompt(system: &str, task_id: &str, input: &SpecDerivationInput) -> Prompt {
    let user = render_user_message(input);
    Prompt {
        prompt_version: SPEC_DERIVATION_PROMPT_VERSION.to_string(),
        task_id: task_id.to_string(),
        model: None,
        system: system.to_string(),
        user,
        max_output_tokens: 1024,
        temperature: 0.0,
        seed: None,
    }
}

fn render_user_message(input: &SpecDerivationInput) -> String {
    let mut out = String::new();
    out.push_str(&format!("cap = {}\n", input.cap));
    out.push_str(&format!("lang = {}\n", input.lang));
    out.push_str(&format!("callee = {}\n", input.callee));
    out.push('\n');
    for ex in &input.excerpts {
        let line_marker = ex.line.map(|l| format!(" (line {l})")).unwrap_or_default();
        out.push_str(&format!("--- {} @ {}{} ---\n", ex.kind, ex.path, line_marker));
        out.push_str("```");
        out.push_str(&input.lang);
        out.push('\n');
        out.push_str(&ex.body);
        if !ex.body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n\n");
    }
    out
}

fn parse_and_validate(raw: &str) -> Result<(HarnessSpec, String), String> {
    let body = strip_code_fence(raw.trim());
    let (spec, canonical) =
        HarnessSpec::from_json(body).map_err(|e| format!("malformed json: {e}"))?;
    spec.validate().map_err(|e| format!("validation failed: {e}"))?;
    Ok((spec, canonical))
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

/// Build a [`FileExcerpt`] by reading `path` from `workspace_root` and
/// pulling `radius` lines on each side of `line`. Returns `None` when
/// the file cannot be read or the resolved excerpt is empty. The agent
/// uses this from the binary side to pre-fetch up to three excerpts
/// (call site, sink, framework binding).
pub fn read_excerpt(
    workspace_root: &std::path::Path,
    path: &str,
    line: Option<u32>,
    kind: &str,
    radius: u32,
) -> Option<FileExcerpt> {
    let resolved = workspace_root.join(path);
    let raw = std::fs::read_to_string(&resolved).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    if lines.is_empty() {
        return None;
    }
    let (lo, hi) = match line {
        Some(l) if l > 0 => {
            let idx = (l as usize).saturating_sub(1).min(lines.len().saturating_sub(1));
            let lo = idx.saturating_sub(radius as usize);
            let hi = (idx + radius as usize + 1).min(lines.len());
            (lo, hi)
        }
        // No line marker: show the first `2*radius+1` lines so the
        // model still has a header anchor.
        _ => (0, lines.len().min((radius as usize * 2) + 1)),
    };
    let mut body = String::new();
    for (i, l) in lines[lo..hi].iter().enumerate() {
        body.push_str(&format!("{:>4}: {l}\n", lo + i + 1));
    }
    Some(FileExcerpt { path: path.to_string(), line, kind: kind.to_string(), body })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use nyx_agent_types::agent::{
        AgentResult, AgentTask, AiError, CacheStats, CostEstimate, TokenUsage,
    };
    use nyx_agent_types::event::AgentEvent;
    use tokio::sync::broadcast;

    use super::*;
    use crate::runtime::{AiRuntime, BudgetTracker, InMemoryBudgetTracker};
    use nyx_agent_types::agent::BudgetKind;

    /// Scripted runtime that replays a fixed sequence of `one_shot`
    /// responses. Same shape as the payload-synthesis test fixture.
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
                usage: TokenUsage { input_tokens: 200, output_tokens: 80 },
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

    fn sample_input() -> SpecDerivationInput {
        SpecDerivationInput {
            finding_id: "f-1".to_string(),
            run_id: "run-1".to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "python".to_string(),
            callee: "cursor.execute".to_string(),
            excerpts: vec![
                FileExcerpt {
                    path: "app/router.py".to_string(),
                    line: Some(7),
                    kind: "call_site".to_string(),
                    body: "   7: handler(request.GET['q'])\n".to_string(),
                },
                FileExcerpt {
                    path: "app/handlers.py".to_string(),
                    line: Some(19),
                    kind: "sink".to_string(),
                    body: "  19: cursor.execute('SELECT * FROM users WHERE n=' + q)\n".to_string(),
                },
            ],
        }
    }

    fn ok_spec_body() -> String {
        serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "python",
            "entry": "app.handlers:run_query",
            "setup": ["import sqlite3", "db = sqlite3.connect(':memory:')"],
            "invoke": "db.execute('SELECT * FROM users WHERE n=' + @PAYLOAD)",
            "payload_arg": 0,
            "oracle": "row count > 0",
            "teardown": ["db.close()"],
        })
        .to_string()
    }

    #[tokio::test]
    async fn finding_produces_validated_spec() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let rt = ScriptedRuntime::new(vec![Ok(ok_spec_body())], tracker.clone(), 3_000);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input(), tx, 1_000_000).await.expect("ok");
        match outcome {
            SpecDerivationOutcome::Synthesised {
                finding_id,
                cap,
                lang,
                spec,
                spec_blob,
                prompt_version,
                spent_usd_micros,
                attempts,
            } => {
                assert_eq!(finding_id, "f-1");
                assert_eq!(cap, "SQL_QUERY");
                assert_eq!(lang, "python");
                assert_eq!(spec.entry, "app.handlers:run_query");
                assert!(spec_blob.contains("@PAYLOAD"));
                assert_eq!(prompt_version, SPEC_DERIVATION_PROMPT_VERSION);
                assert_eq!(spent_usd_micros, 3_000);
                assert_eq!(attempts, 1);
            }
            other => panic!("expected Synthesised, got {other:?}"),
        }
        assert_eq!(tracker.spent("run-1", BudgetKind::OneShot), 3_000);
    }

    #[tokio::test]
    async fn validation_failure_retries_with_stricter_prompt() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        // First attempt: missing `@PAYLOAD`. Second: valid.
        let bad = serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "python",
            "entry": "app.handlers:run_query",
            "invoke": "db.execute(query)",
            "payload_arg": 0,
            "oracle": "row count > 0",
        })
        .to_string();
        let rt = ScriptedRuntime::new(vec![Ok(ok_spec_body()), Ok(bad)], tracker.clone(), 1_500);

        let (tx, _rx) = broadcast::channel::<AgentEvent>(16);
        let outcome = run(&rt, &sample_input(), tx, 1_000_000).await.expect("ok");
        match outcome {
            SpecDerivationOutcome::Synthesised { attempts, spent_usd_micros, .. } => {
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 3_000);
            }
            other => panic!("expected Synthesised after retry, got {other:?}"),
        }
        let seen = rt.prompts();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("Reply with exactly one JSON object"));
        assert!(seen[1].contains("previous reply did not validate"));
    }

    #[tokio::test]
    async fn two_invalid_specs_quarantine() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let bad =
            r#"{"schema_version":1,"cap":"x","lang":"y","entry":"e","invoke":"x","payload_arg":0,"oracle":"o"}"#
                .to_string();
        let rt = ScriptedRuntime::new(vec![Ok(bad.clone()), Ok(bad)], tracker.clone(), 1_000);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 1_000_000).await.expect("ok");
        match outcome {
            SpecDerivationOutcome::Quarantined {
                finding_id,
                reason,
                spent_usd_micros,
                attempts,
            } => {
                assert_eq!(finding_id, "f-1");
                assert_eq!(attempts, 2);
                assert_eq!(spent_usd_micros, 2_000);
                assert!(reason.contains("failed twice"), "reason: {reason}");
                assert!(reason.contains("@PAYLOAD"), "reason should cite slot: {reason}");
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_json_first_then_valid_retries() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let rt = ScriptedRuntime::new(
            vec![Ok(ok_spec_body()), Ok("not json".to_string())],
            tracker.clone(),
            1_000,
        );
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 1_000_000).await.expect("ok");
        assert!(matches!(outcome, SpecDerivationOutcome::Synthesised { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn code_fence_wrapper_is_tolerated() {
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        tracker.set_cap("run-1", BudgetKind::OneShot, 1_000_000);
        let wrapped = format!("```json\n{}\n```", ok_spec_body());
        let rt = ScriptedRuntime::new(vec![Ok(wrapped)], tracker.clone(), 500);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(8);
        let outcome = run(&rt, &sample_input(), tx, 1_000_000).await.expect("ok");
        assert!(matches!(outcome, SpecDerivationOutcome::Synthesised { attempts: 1, .. }));
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
        let err = run(&rt, &sample_input(), tx, 1_000_000).await.expect_err("upstream");
        assert!(matches!(err, AiError::UpstreamRefused(_)));
    }

    #[test]
    fn read_excerpt_returns_radius_window() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("foo.py");
        let mut f = std::fs::File::create(&p).unwrap();
        for i in 1..=20 {
            writeln!(f, "line {i}").unwrap();
        }
        let ex = read_excerpt(tmp.path(), "foo.py", Some(10), "sink", 2).expect("excerpt");
        assert_eq!(ex.path, "foo.py");
        assert_eq!(ex.line, Some(10));
        assert_eq!(ex.kind, "sink");
        // Window [10-2 ..= 10+2] = lines 8..=12 (1-indexed in body).
        assert!(ex.body.contains("   8: line 8"));
        assert!(ex.body.contains("  10: line 10"));
        assert!(ex.body.contains("  12: line 12"));
        assert!(!ex.body.contains("   7: line 7"));
        assert!(!ex.body.contains("  13: line 13"));
    }

    #[test]
    fn read_excerpt_missing_file_yields_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_excerpt(tmp.path(), "missing.py", Some(1), "sink", 3).is_none());
    }
}

//! LiveEvidenceReview agent task.
//!
//! Given a candidate, its proposed executable plan, the collected live
//! evidence, and the deterministic oracle result, drive a single
//! `AiRuntime::one_shot` critique pass and lift the response into a
//! structured decision. Persistence stays in the binary so this crate
//! remains vendor-neutral.

use nyctos_types::agent::{AgentTraceMetrics, AiError, Budget, BudgetKind, Prompt, Response};
use nyctos_types::event::EventSink;
use nyctos_types::product::PentestCandidateRecord;
use serde::{Deserialize, Serialize};

use crate::runtime::AiRuntime;

pub const LIVE_EVIDENCE_REVIEW_PROMPT_VERSION: &str = "phase24.live_evidence_review.v1";

const SYSTEM_PROMPT_V1: &str = include_str!("../prompts/live_evidence_review.v1.md");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveEvidenceReviewDecision {
    Accept,
    Downgrade,
    Block,
}

impl LiveEvidenceReviewDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Downgrade => "downgrade",
            Self::Block => "block",
        }
    }

    fn from_model(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "accept" | "accepted" | "confirmed" | "verify" | "verified" => Ok(Self::Accept),
            "downgrade" | "downgraded" | "inconclusive" | "needs_more_evidence" => {
                Ok(Self::Downgrade)
            }
            "block" | "blocked" | "reject" | "rejected" | "false_positive" => Ok(Self::Block),
            other => Err(format!("unsupported decision `{other}`")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveEvidenceReviewOutput {
    pub decision: LiveEvidenceReviewDecision,
    pub confidence: f64,
    pub rationale: String,
    #[serde(default)]
    pub evidence_strengths: Vec<String>,
    #[serde(default)]
    pub evidence_gaps: Vec<String>,
    #[serde(default)]
    pub required_followup: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LiveEvidenceReviewInput {
    pub run_id: String,
    pub candidate: PentestCandidateRecord,
    pub proposed_plan: serde_json::Value,
    pub live_evidence: serde_json::Value,
    pub oracle_result: serde_json::Value,
    pub deterministic_review: LiveEvidenceReviewOutput,
}

#[derive(Debug, Clone)]
pub struct LiveEvidenceReviewOutcome {
    pub output: LiveEvidenceReviewOutput,
    pub prompt_version: String,
    pub spent_usd_micros: i64,
    pub metrics: AgentTraceMetrics,
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    input: &LiveEvidenceReviewInput,
    sink: EventSink,
    cap_usd_micros: i64,
) -> Result<LiveEvidenceReviewOutcome, AiError> {
    let task_id = format!("evidence-review-{}", short_id(&input.candidate.id));
    let prompt = build_prompt(&task_id, input);
    let budget = Budget { run_id: input.run_id.clone(), kind: BudgetKind::OneShot, cap_usd_micros };
    let resp: Response = runtime.one_shot(prompt, budget, sink).await?;
    let output = parse_output(&resp.content).map_err(AiError::MalformedResponse)?;
    let metrics = AgentTraceMetrics::from_response(&resp);
    Ok(LiveEvidenceReviewOutcome {
        output,
        prompt_version: resp.prompt_version,
        spent_usd_micros: resp.cost_usd_micros,
        metrics,
    })
}

fn build_prompt(task_id: &str, input: &LiveEvidenceReviewInput) -> Prompt {
    let user = serde_json::to_string_pretty(&serde_json::json!({
        "run_id": &input.run_id,
        "candidate": &input.candidate,
        "proposed_plan": &input.proposed_plan,
        "live_evidence": &input.live_evidence,
        "oracle_result": &input.oracle_result,
        "deterministic_review": &input.deterministic_review,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    Prompt {
        prompt_version: LIVE_EVIDENCE_REVIEW_PROMPT_VERSION.to_string(),
        task_id: task_id.to_string(),
        model: None,
        system: SYSTEM_PROMPT_V1.to_string(),
        user,
        max_output_tokens: 1200,
        temperature: 0.0,
        seed: None,
    }
}

fn parse_output(raw: &str) -> Result<LiveEvidenceReviewOutput, String> {
    #[derive(Deserialize)]
    struct RawOutput {
        decision: String,
        #[serde(default)]
        confidence: Option<f64>,
        rationale: String,
        #[serde(default)]
        evidence_strengths: Vec<String>,
        #[serde(default)]
        evidence_gaps: Vec<String>,
        #[serde(default)]
        required_followup: Vec<String>,
    }

    let body = strip_code_fence(raw.trim());
    let raw: RawOutput = serde_json::from_str(body).map_err(|e| format!("malformed json: {e}"))?;
    if raw.rationale.trim().is_empty() {
        return Err("rationale was empty".to_string());
    }
    let decision = LiveEvidenceReviewDecision::from_model(&raw.decision)?;
    let confidence = raw.confidence.unwrap_or(0.0).clamp(0.0, 1.0);
    Ok(LiveEvidenceReviewOutput {
        decision,
        confidence,
        rationale: raw.rationale,
        evidence_strengths: non_empty_strings(raw.evidence_strengths),
        evidence_gaps: non_empty_strings(raw.evidence_gaps),
        required_followup: non_empty_strings(raw.required_followup),
    })
}

fn non_empty_strings(items: Vec<String>) -> Vec<String> {
    items.into_iter().filter(|s| !s.trim().is_empty()).collect()
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

fn short_id(id: &str) -> String {
    id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(48).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_candidate() -> PentestCandidateRecord {
        PentestCandidateRecord {
            id: "pc-run-web-xss".to_string(),
            run_id: "run-1".to_string(),
            project_id: "project-1".to_string(),
            source: "NyxSignal".to_string(),
            source_ids: vec!["sig-1".to_string()],
            title: "Reflected XSS candidate".to_string(),
            vuln_class: "XSS".to_string(),
            severity_guess: "High".to_string(),
            affected_components: vec![serde_json::json!({"repo": "web", "path": "src/app.ts"})],
            hypothesis: "Search reflects attacker-controlled query text".to_string(),
            test_plan: "{}".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: 0.6,
            trace_id: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn parse_output_accepts_structured_rationale() {
        let parsed = parse_output(
            r#"{
              "decision":"accept",
              "confidence":0.92,
              "rationale":"The response reflected the unique probe marker in a 200 page.",
              "evidence_strengths":["unique reflection"],
              "evidence_gaps":[],
              "required_followup":[]
            }"#,
        )
        .expect("valid review");
        assert_eq!(parsed.decision, LiveEvidenceReviewDecision::Accept);
        assert_eq!(parsed.confidence, 0.92);
        assert!(parsed.evidence_strengths[0].contains("reflection"));
    }

    #[test]
    fn parse_output_normalises_block_synonyms() {
        let parsed = parse_output(
            r#"{"decision":"rejected","confidence":2.0,"rationale":"Only a status check passed."}"#,
        )
        .expect("valid review");
        assert_eq!(parsed.decision, LiveEvidenceReviewDecision::Block);
        assert_eq!(parsed.confidence, 1.0);
    }

    #[test]
    fn prompt_mentions_false_positive_rejection_rules() {
        assert!(SYSTEM_PROMPT_V1.contains("status-only checks"));
        assert!(SYSTEM_PROMPT_V1.contains("static source"));
        assert!(SYSTEM_PROMPT_V1.contains("unauthenticated error pages"));
        assert!(SYSTEM_PROMPT_V1.contains("missing reflection"));
    }

    #[test]
    fn build_prompt_includes_candidate_plan_evidence_and_oracle() {
        let candidate = sample_candidate();
        let input = LiveEvidenceReviewInput {
            run_id: "run-1".to_string(),
            candidate,
            proposed_plan: serde_json::json!({"kind": "http"}),
            live_evidence: serde_json::json!({"response": {"status": 200}}),
            oracle_result: serde_json::json!({"success": true}),
            deterministic_review: LiveEvidenceReviewOutput {
                decision: LiveEvidenceReviewDecision::Accept,
                confidence: 0.75,
                rationale: "positive marker present".to_string(),
                evidence_strengths: vec!["body marker".to_string()],
                evidence_gaps: Vec::new(),
                required_followup: Vec::new(),
            },
        };
        let prompt = build_prompt("task", &input);
        assert_eq!(prompt.prompt_version, LIVE_EVIDENCE_REVIEW_PROMPT_VERSION);
        assert!(prompt.user.contains("\"candidate\""));
        assert!(prompt.user.contains("\"proposed_plan\""));
        assert!(prompt.user.contains("\"live_evidence\""));
        assert!(prompt.user.contains("\"oracle_result\""));
    }
}

//! AI-discovered candidate finding schemas.
//!
//! Phase 17 ships the on-the-wire types the NovelFindingDiscovery task
//! produces. The model is handed a batch of source files plus the nyx
//! findings that already exist on those files (so it can avoid
//! rediscovering them) and asked to identify additional candidate
//! vulnerabilities the static scanner missed.
//!
//! Like the other task envelopes ([`crate::payload`], [`crate::spec`],
//! [`crate::chain`]) these types are deliberately plain serde and do
//! not derive `ts-rs`; the UI surface lands with the quarantine view
//! (Phase 24).

use serde::{Deserialize, Serialize};

/// Source file contents passed to the model in a NovelFindingDiscovery
/// batch. `content` is already truncated by the binary so the prompt
/// fits the model's context window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileForReview {
    pub path: String,
    /// Truncated source. The binary may append a
    /// `... <N more lines truncated>` marker; the prompt instructs the
    /// model to flag findings only when the surrounding lines are
    /// actually present in the excerpt.
    pub content: String,
    /// True when [`Self::content`] was truncated. The prompt uses this
    /// to remind the model not to invent line numbers past the visible
    /// region.
    #[serde(default)]
    pub truncated: bool,
}

/// One nyx static-pass finding the model already knows about. The
/// prompt lists priors so the model is steered toward *additional*
/// candidate vulnerabilities the scanner missed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorFinding {
    pub path: String,
    pub line: u32,
    pub cap: String,
    pub rule: String,
}

/// Input envelope for the NovelFindingDiscovery task. The agent never
/// reaches back to the store; the file batch plus the priors live here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovelFindingDiscoveryInput {
    pub run_id: String,
    pub repo: String,
    /// Stable identifier for the batch (`<repo>:<batch-index>`). Echoed
    /// into the per-call `task_id` so the trace store can correlate
    /// every round trip with the batch it served.
    pub batch_id: String,
    /// Files the model should review. Length is capped at the binary
    /// side by [`DEFAULT_FILES_PER_BATCH`].
    pub files: Vec<FileForReview>,
    /// Nyx findings already known on any file in [`Self::files`]. The
    /// prompt forwards these verbatim so the model does not rediscover
    /// them.
    #[serde(default)]
    pub priors: Vec<PriorFinding>,
}

/// One candidate vulnerability the model proposes. Every field is
/// required except `rule_hint` and `suggested_payload_hint`, which are
/// freeform and may be empty. `path` MUST reference a file present in
/// the batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFinding {
    pub path: String,
    pub line: u32,
    /// Capability tag the candidate falls under (e.g. `SQL_QUERY`,
    /// `OS_COMMAND`). The validator accepts any non-empty string; an
    /// unknown cap quarantines through but the verifier may then refuse
    /// to materialise a payload for it.
    pub cap: String,
    /// Optional nyx rule id the model thinks would fire on this row if
    /// it knew about the pattern. Free-form; may be empty.
    #[serde(default)]
    pub rule_hint: Option<String>,
    /// Short explanation of why the model believes this is a candidate
    /// vulnerability. Required and non-empty.
    pub rationale: String,
    /// Optional sketch of the payload that would exercise the candidate
    /// sink. Free-form; the binary forwards it to PayloadSynthesis as a
    /// seed when the candidate gets a confirmation pass.
    #[serde(default)]
    pub suggested_payload_hint: Option<String>,
}

/// Structured output the model is asked to produce. Plain `candidates`
/// array; the validator rejects malformed JSON, unknown paths, and
/// candidates whose `rationale` is empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovelFindingDiscoveryOutput {
    #[serde(default)]
    pub candidates: Vec<CandidateFinding>,
}

/// Stable identifier for the NovelFindingDiscovery prompt template.
/// Bumped whenever the prompt body changes; the task records this on
/// every candidate row and AgentTrace so trail-back is unambiguous.
pub const NOVEL_FINDING_DISCOVERY_PROMPT_VERSION: &str = "phase17.novel_findings.v1";

/// Default ceiling on the number of files a single NovelFindingDiscovery
/// task receives. The binary partitions a repo's prioritised file list
/// into batches of this size before fan-out.
pub const DEFAULT_FILES_PER_BATCH: usize = 30;

/// Default per-run AI budget cap for the NovelFindingDiscovery pass.
/// The pass halts further batches once cumulative spend on this run's
/// `(run_id, OneShot)` bucket crosses this value. $5.00 in USD micros.
pub const DEFAULT_NOVEL_DISCOVERY_RUN_CAP_USD_MICROS: i64 = 5_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_roundtrips_through_serde() {
        let inp = NovelFindingDiscoveryInput {
            run_id: "run-1".into(),
            repo: "repo-1".into(),
            batch_id: "repo-1:0".into(),
            files: vec![FileForReview {
                path: "app/handlers.py".into(),
                content: "def f(q):\n    cursor.execute('SELECT '+q)\n".into(),
                truncated: false,
            }],
            priors: vec![PriorFinding {
                path: "app/handlers.py".into(),
                line: 2,
                cap: "SQL_QUERY".into(),
                rule: "py.sql.exec".into(),
            }],
        };
        let s = serde_json::to_string(&inp).unwrap();
        let back: NovelFindingDiscoveryInput = serde_json::from_str(&s).unwrap();
        assert_eq!(inp, back);
    }

    #[test]
    fn output_roundtrips_through_serde() {
        let out = NovelFindingDiscoveryOutput {
            candidates: vec![CandidateFinding {
                path: "app/handlers.py".into(),
                line: 9,
                cap: "SQL_QUERY".into(),
                rule_hint: Some("py.sql.exec".into()),
                rationale: "second helper builds SQL via string concat".into(),
                suggested_payload_hint: Some("' OR 1=1 --".into()),
            }],
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: NovelFindingDiscoveryOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(out, back);
    }

    #[test]
    fn output_tolerates_missing_optional_fields() {
        let raw = r#"{"candidates":[
            {"path":"a.py","line":3,"cap":"OS_COMMAND","rationale":"shell call with user input"}
        ]}"#;
        let parsed: NovelFindingDiscoveryOutput = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.candidates.len(), 1);
        assert!(parsed.candidates[0].rule_hint.is_none());
        assert!(parsed.candidates[0].suggested_payload_hint.is_none());
    }

    #[test]
    fn output_tolerates_empty_candidates_array() {
        let raw = r#"{"candidates":[]}"#;
        let parsed: NovelFindingDiscoveryOutput = serde_json::from_str(raw).unwrap();
        assert!(parsed.candidates.is_empty());
    }
}

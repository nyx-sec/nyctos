//! AI-derived harness-spec schemas.
//!
//! On-the-wire types the SpecDerivation task produces. The vendored
//! `HarnessSpec` schema itself lives in `nyctos-nyx` (close to the
//! static-scanner driver that consumes it); only the agent-side input
//! envelope and a stable prompt-version tag live here so the task
//! crate can stay vendor-neutral.
//!
//! Like [`crate::payload`], these types are plain serde and do not
//! derive `ts-rs`; the trace viewer reaches them through a separate
//! surface.

use serde::{Deserialize, Serialize};

/// One source-file excerpt attached to a SpecDerivation prompt. The
/// agent reads up to three of these (call site, sink, framework
/// binding) so the model has enough context to infer entry symbol +
/// invocation shape without re-running the static analysis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileExcerpt {
    pub path: String,
    pub line: Option<u32>,
    /// Free-form label rendered into the prompt header so the model
    /// can distinguish "this is the sink" from "this is the framework
    /// binding". Conventional values: `call_site`, `sink`, `framework`.
    pub kind: String,
    pub body: String,
}

/// Input envelope for the SpecDerivation task. The agent never reaches
/// back to the store; everything the prompt needs lives here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecDerivationInput {
    pub finding_id: String,
    pub run_id: String,
    pub cap: String,
    pub lang: String,
    pub callee: String,
    /// 0..=3 excerpts. The task does not enforce the cap (the binary
    /// that builds the input is responsible), but the prompt is sized
    /// to comfortably hold three excerpts plus the header.
    pub excerpts: Vec<FileExcerpt>,
}

/// Stable identifier for the SpecDerivation prompt template. Bumped
/// whenever the prompt body changes; the task records this on every
/// `HarnessSpec` row and AgentTrace so trail-back is unambiguous.
pub const SPEC_DERIVATION_PROMPT_VERSION: &str = "phase15.spec_derivation.v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_roundtrips_through_serde() {
        let inp = SpecDerivationInput {
            finding_id: "f-1".into(),
            run_id: "r-1".into(),
            cap: "SQL_QUERY".into(),
            lang: "python".into(),
            callee: "cursor.execute".into(),
            excerpts: vec![FileExcerpt {
                path: "sink.py".into(),
                line: Some(19),
                kind: "sink".into(),
                body: "cursor.execute(query)".into(),
            }],
        };
        let s = serde_json::to_string(&inp).unwrap();
        let back: SpecDerivationInput = serde_json::from_str(&s).unwrap();
        assert_eq!(inp, back);
    }
}

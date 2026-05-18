//! AI-synthesised payload schemas.
//!
//! Phase 14 ships the on-the-wire types the PayloadSynthesis task
//! produces. They are deliberately plain serde so the task crate
//! (`nyx-agent-ai`) does not have to pull in `nyx-agent-core::store`'s
//! SQLx surface; the binary turns a [`PayloadSynthesisOutput`] +
//! [`PayloadSynthesisInput`] into a `PayloadRecord` at persistence time.
//!
//! `ts-rs` derives are intentionally absent until a UI surface in a
//! later phase actually renders these types.

use serde::{Deserialize, Serialize};

/// Provenance tag for AI-synthesised attack artefacts (payloads + chains).
/// Persisted in the `attack_provenance` column on `payloads` /
/// `findings` / `chains` so operators can filter "what did the model
/// produce vs. what came from curated rules".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackProvenance {
    /// Hand-curated upstream payload (e.g. shipped with a nyx rule).
    Curated,
    /// Synthesised by an LLM. The agent-trace store keeps the prompt
    /// version + conversation path so verdicts remain auditable.
    LlmSynthesised,
    /// Surfaced by the Phase 23 AI exploration driver — the Claude
    /// Code agent loop ran inside the chain-lane sandbox and recorded
    /// the finding via the `record_exploration_finding` tool call.
    AiExploration,
}

impl AttackProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            AttackProvenance::Curated => "Curated",
            AttackProvenance::LlmSynthesised => "LlmSynthesised",
            AttackProvenance::AiExploration => "AiExploration",
        }
    }
}

/// Sink context attached to a PayloadSynthesis prompt: the callee at
/// the sink, its rendered argument list (best-effort), and a code
/// excerpt surrounding the sink line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkCtx {
    pub callee: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub excerpt: String,
}

/// Input envelope for the PayloadSynthesis task. Everything the prompt
/// needs lives here; the task never reaches back to the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadSynthesisInput {
    pub finding_id: String,
    pub run_id: String,
    pub cap: String,
    pub lang: String,
    pub sink_ctx: SinkCtx,
}

/// Structured payload pair the model is asked to produce. All three
/// fields are required and non-empty; an empty field is rejected the
/// same as a malformed JSON body and triggers the retry path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadSynthesisOutput {
    pub vuln_payload: String,
    pub vuln_oracle: String,
    pub benign_payload: String,
}

/// Stable identifier for the PayloadSynthesis prompt template. Bumped
/// whenever the prompt body changes; the task records this on every
/// PayloadRecord and AgentTrace so trail-back is unambiguous.
pub const PAYLOAD_SYNTHESIS_PROMPT_VERSION: &str = "phase14.payload_synthesis.v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_roundtrips_through_serde() {
        let out = PayloadSynthesisOutput {
            vuln_payload: "' OR 1=1 --".to_string(),
            vuln_oracle: "response contains row leak".to_string(),
            benign_payload: "alice".to_string(),
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: PayloadSynthesisOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(out, back);
    }

    #[test]
    fn output_rejects_missing_field() {
        let raw = r#"{"vuln_payload":"x","vuln_oracle":"y"}"#;
        let err = serde_json::from_str::<PayloadSynthesisOutput>(raw).unwrap_err();
        assert!(err.to_string().contains("benign_payload"));
    }

    #[test]
    fn attack_provenance_strings_are_stable() {
        assert_eq!(AttackProvenance::Curated.as_str(), "Curated");
        assert_eq!(AttackProvenance::LlmSynthesised.as_str(), "LlmSynthesised");
        assert_eq!(AttackProvenance::AiExploration.as_str(), "AiExploration");
    }
}

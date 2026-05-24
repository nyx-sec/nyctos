//! AI-synthesised payload schemas.
//!
//! On-the-wire types the PayloadSynthesis task produces. They are
//! plain serde so the task crate (`nyctos-ai`) does not have to
//! pull in `nyctos-core::store`'s SQLx surface; the binary turns a
//! [`PayloadSynthesisOutput`] + [`PayloadSynthesisInput`] into a
//! `PayloadRecord` at persistence time.
//!
//! `ts-rs` derives are absent until a UI surface actually renders
//! these types.

use std::fmt;

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
    /// Surfaced by the AI exploration driver: the Claude Code agent
    /// loop ran inside the chain-lane sandbox and recorded the
    /// finding via the `record_exploration_finding` tool call.
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
/// legacy fields remain required for backward compatibility. Newer
/// internal callers should also populate the contextual fields so the
/// verifier can understand transport, injection point, oracle, risk, and
/// cleanup semantics without having to infer them from free text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadSynthesisOutput {
    pub vuln_payload: String,
    pub vuln_oracle: String,
    pub benign_payload: String,
    #[serde(default)]
    pub transport: PayloadTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benign_control: Option<String>,
    #[serde(default)]
    pub state_changing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

impl PayloadSynthesisOutput {
    pub fn contextual_payload(&self) -> ContextualPayload {
        ContextualPayload {
            vuln_payload: self.vuln_payload.clone(),
            vuln_oracle: self.vuln_oracle.clone(),
            benign_payload: self.benign_payload.clone(),
            transport: self.transport,
            injection_point: self.injection_point.clone(),
            encoding: self.encoding.clone(),
            context: self.context.clone(),
            expected_signal: self.expected_signal.clone(),
            oracle: self.oracle.clone(),
            benign_control: self.benign_control.clone(),
            state_changing: self.state_changing,
            risk: self.risk.clone(),
            cleanup_hint: self.cleanup_hint.clone(),
            reset_hint: self.reset_hint.clone(),
            why_this_confirms: self.why_this_confirms.clone(),
        }
    }

    pub fn validate_contextual(&self) -> Result<(), PayloadValidationError> {
        self.contextual_payload().validate()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadTransport {
    Query,
    Path,
    Body,
    Header,
    Cookie,
    Dom,
    Form,
    Json,
    Multipart,
    #[default]
    Unknown,
}

impl PayloadTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Path => "path",
            Self::Body => "body",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Dom => "dom",
            Self::Form => "form",
            Self::Json => "json",
            Self::Multipart => "multipart",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextualPayload {
    pub vuln_payload: String,
    pub vuln_oracle: String,
    pub benign_payload: String,
    #[serde(default)]
    pub transport: PayloadTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benign_control: Option<String>,
    #[serde(default)]
    pub state_changing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

impl ContextualPayload {
    pub fn validate(&self) -> Result<(), PayloadValidationError> {
        require_non_empty("vuln_payload", &self.vuln_payload)?;
        require_non_empty("vuln_oracle", &self.vuln_oracle)?;
        require_non_empty("benign_payload", &self.benign_payload)?;
        if self.vuln_payload.trim() == self.benign_payload.trim() {
            return Err(PayloadValidationError::Degenerate(
                "vuln_payload and benign_payload must differ".to_string(),
            ));
        }
        let oracle_text =
            self.oracle.as_deref().or(self.expected_signal.as_deref()).unwrap_or(&self.vuln_oracle);
        if oracle_text.trim().len() < 4 {
            return Err(PayloadValidationError::WeakOracle(
                "oracle/expected_signal must name a specific positive signal".to_string(),
            ));
        }
        if let Some(control) = &self.benign_control {
            if control.trim() == self.vuln_payload.trim() {
                return Err(PayloadValidationError::Degenerate(
                    "benign_control repeats vuln_payload".to_string(),
                ));
            }
        }
        if self.transport == PayloadTransport::Unknown && self.injection_point.is_none() {
            return Err(PayloadValidationError::MissingContext(
                "transport or injection_point is required for contextual payloads".to_string(),
            ));
        }
        if self.why_this_confirms.as_deref().unwrap_or("").trim().len() < 8 {
            return Err(PayloadValidationError::MissingContext(
                "why_this_confirms must explain why the positive signal proves exploitability"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), PayloadValidationError> {
    if value.trim().is_empty() {
        Err(PayloadValidationError::MissingField(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadValidationError {
    MissingField(&'static str),
    MissingContext(String),
    WeakOracle(String),
    Degenerate(String),
}

impl fmt::Display for PayloadValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing payload field `{field}`"),
            Self::MissingContext(reason) => write!(f, "missing payload context: {reason}"),
            Self::WeakOracle(reason) => write!(f, "weak payload oracle: {reason}"),
            Self::Degenerate(reason) => write!(f, "degenerate payload: {reason}"),
        }
    }
}

impl std::error::Error for PayloadValidationError {}

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
            transport: PayloadTransport::Body,
            injection_point: Some("username".to_string()),
            encoding: None,
            context: Some("SQL string literal".to_string()),
            expected_signal: Some("row leak marker".to_string()),
            oracle: Some("response contains row leak".to_string()),
            benign_control: Some("normal username lookup".to_string()),
            state_changing: false,
            risk: Some("read-only".to_string()),
            cleanup_hint: None,
            reset_hint: None,
            why_this_confirms: Some(
                "The vulnerable variant returns rows the benign lookup cannot access.".to_string(),
            ),
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: PayloadSynthesisOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(out, back);
        back.validate_contextual().unwrap();
    }

    #[test]
    fn output_rejects_missing_field() {
        let raw = r#"{"vuln_payload":"x","vuln_oracle":"y"}"#;
        let err = serde_json::from_str::<PayloadSynthesisOutput>(raw).unwrap_err();
        assert!(err.to_string().contains("benign_payload"));
    }

    #[test]
    fn legacy_payload_output_deserializes_without_new_context() {
        let raw = r#"{"vuln_payload":"x","vuln_oracle":"marker","benign_payload":"y"}"#;
        let out = serde_json::from_str::<PayloadSynthesisOutput>(raw).unwrap();
        assert_eq!(out.transport, PayloadTransport::Unknown);
        assert!(out.validate_contextual().is_err());
    }

    #[test]
    fn contextual_payload_rejects_degenerate_controls() {
        let payload = ContextualPayload {
            vuln_payload: "x".to_string(),
            vuln_oracle: "marker".to_string(),
            benign_payload: "x".to_string(),
            transport: PayloadTransport::Query,
            injection_point: Some("q".to_string()),
            encoding: None,
            context: None,
            expected_signal: Some("marker".to_string()),
            oracle: None,
            benign_control: None,
            state_changing: false,
            risk: None,
            cleanup_hint: None,
            reset_hint: None,
            why_this_confirms: Some("Different outputs prove exploitability.".to_string()),
        };
        assert!(matches!(payload.validate(), Err(PayloadValidationError::Degenerate(_))));
    }

    #[test]
    fn attack_provenance_strings_are_stable() {
        assert_eq!(AttackProvenance::Curated.as_str(), "Curated");
        assert_eq!(AttackProvenance::LlmSynthesised.as_str(), "LlmSynthesised");
        assert_eq!(AttackProvenance::AiExploration.as_str(), "AiExploration");
    }
}

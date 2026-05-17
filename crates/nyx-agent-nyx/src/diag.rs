//! Wire-compatible mirror of one `nyx scan --format json` row.
//!
//! The shape tracks the public schema emitted by `nyx 0.7.0`:
//! `path / line / col / severity / id / category / message / confidence /
//! evidence / rank_score / rank_reason / finding_id / labels / symbolic`.
//!
//! Field names in the plan (`cap`, `rule`, `flow_steps`) are reconciled
//! against the upstream names via `#[serde(rename = ...)]`. `evidence`
//! stays as a raw `serde_json::Value` because its shape varies per rule;
//! later phases consume specific subfields without forcing us to model
//! every rule's evidence variant here. `flow_steps` is lifted out of
//! `evidence.flow_steps` after deserialization so callers can read it
//! directly on `Diag` regardless of where upstream nests it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diag {
    pub path: String,
    pub line: u32,
    #[serde(default)]
    pub col: Option<u32>,
    pub severity: String,
    /// Stable per-rule identifier (nyx field: `id`). The plan refers to
    /// this as `rule`.
    #[serde(rename = "id")]
    pub rule: String,
    /// Coarse capability classification (nyx field: `category`). The plan
    /// refers to this as `cap`.
    #[serde(rename = "category")]
    pub cap: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub evidence: Value,
    /// Lifted out of `evidence.flow_steps` after deserialization. Empty
    /// when the rule does not carry a flow trace.
    #[serde(skip, default)]
    pub flow_steps: Vec<FlowStep>,
}

impl Diag {
    /// Walk `evidence.flow_steps` (if any) and materialise the typed
    /// `FlowStep` vector. Idempotent; safe to call more than once.
    pub fn lift_flow_steps(&mut self) {
        if !self.flow_steps.is_empty() {
            return;
        }
        let steps_value = match &self.evidence {
            Value::Object(map) => map.get("flow_steps"),
            _ => None,
        };
        let Some(raw) = steps_value else {
            return;
        };
        if let Ok(parsed) = serde_json::from_value::<Vec<FlowStep>>(raw.clone()) {
            self.flow_steps = parsed;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStep {
    /// Source file. nyx emits this as `file`; the plan calls it `path`.
    #[serde(alias = "file")]
    pub path: String,
    pub line: u32,
    #[serde(default)]
    pub col: Option<u32>,
    /// Step kind reported by nyx (e.g. `call`, `sink`, `source`).
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub snippet: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal_row() {
        let raw = r#"{
            "path": "src/main.py",
            "line": 12,
            "severity": "Medium",
            "id": "PY-CMD-001",
            "category": "command-injection"
        }"#;
        let d: Diag = serde_json::from_str(raw).expect("parse");
        assert_eq!(d.path, "src/main.py");
        assert_eq!(d.line, 12);
        assert_eq!(d.cap, "command-injection");
        assert_eq!(d.rule, "PY-CMD-001");
        assert_eq!(d.severity, "Medium");
        assert!(d.message.is_none());
        assert!(d.flow_steps.is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let raw = r#"{
            "path": "a.py",
            "line": 1,
            "severity": "Low",
            "id": "X",
            "category": "Y",
            "future_field_we_dont_know_about": {"nested": true},
            "another_one": 42
        }"#;
        let d: Diag = serde_json::from_str(raw).expect("must tolerate unknown fields");
        assert_eq!(d.path, "a.py");
    }

    #[test]
    fn lifts_flow_steps_from_evidence() {
        let raw = r#"{
            "path": "vuln.py", "line": 19, "col": 5, "severity": "Medium",
            "id": "taint-unsanitised-flow", "category": "Security",
            "evidence": {
                "sink": {"path": "vuln.py", "line": 19, "col": 5, "kind": "sink"},
                "flow_steps": [
                    {"step": 1, "kind": "call", "file": "vuln.py", "line": 18, "col": 26,
                     "snippet": "sys.argv", "variable": "cmd"},
                    {"step": 2, "kind": "sink", "file": "vuln.py", "line": 19, "col": 5,
                     "snippet": "os.system(...)"}
                ]
            }
        }"#;
        let mut d: Diag = serde_json::from_str(raw).expect("parse");
        assert!(d.flow_steps.is_empty(), "lift only happens explicitly");
        d.lift_flow_steps();
        assert_eq!(d.flow_steps.len(), 2);
        assert_eq!(d.flow_steps[0].kind.as_deref(), Some("call"));
        assert_eq!(d.flow_steps[1].path, "vuln.py");

        d.lift_flow_steps(); // idempotency
        assert_eq!(d.flow_steps.len(), 2);
    }

    #[test]
    fn missing_evidence_lifts_to_empty() {
        let raw = r#"{
            "path": "a.py", "line": 1, "severity": "Low",
            "id": "X", "category": "Y"
        }"#;
        let mut d: Diag = serde_json::from_str(raw).expect("parse");
        d.lift_flow_steps();
        assert!(d.flow_steps.is_empty());
    }
}

//! Vendored copy of nyx's `HarnessSpec` schema.
//!
//! The upstream `nyx` scanner consumes a `HarnessSpec` JSON to build a
//! per-sink exercise harness when its built-in payload strategies cannot
//! cover a capability. Phase 15's SpecDerivation agent task produces
//! these specs from LLM output; we vendor the schema here so the agent
//! can validate the model's reply against the exact shape the verifier
//! expects without taking a source-level dependency on the upstream
//! scanner (which is GPL; see `LICENSE-GRANTS.md`).
//!
//! The wire shape mirrors `nyx 0.7.x`'s harness JSON: a small required
//! core (`schema_version`, `cap`, `lang`, `entry`, `invoke`, `oracle`)
//! plus optional `setup` / `teardown` arrays for fixtures. Unknown
//! fields are tolerated via the `extra` catch-all so a newer upstream
//! schema does not silently break the round-trip; the agent persists
//! the original blob alongside the parsed form.
//!
//! Validation = `serde_json::from_str::<HarnessSpec>` succeeds AND each
//! required string field is non-empty AND `payload_arg < invoke.len`
//! when the invoke template references a positional slot. Callers that
//! want the strict check use [`HarnessSpec::validate`]; the constructor
//! itself stays serde-only so partially-populated upstream JSON still
//! round-trips for diagnostics.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// On-the-wire harness shape. All string fields must round-trip
/// non-empty for [`HarnessSpec::validate`] to accept the spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Format version. Always `1` for the vendored shape.
    pub schema_version: u32,
    /// Capability tag the spec covers (e.g. `SQL_QUERY`).
    pub cap: String,
    /// Source language the harness compiles against (e.g. `python`).
    pub lang: String,
    /// Entry symbol the verifier should call (e.g. `app.handlers:run`).
    pub entry: String,
    /// Pre-call setup statements run in order before `invoke`.
    #[serde(default)]
    pub setup: Vec<String>,
    /// Invocation template. Must reference the payload via the literal
    /// token `@PAYLOAD` exactly once.
    pub invoke: String,
    /// Zero-based index of the argument slot the payload occupies; the
    /// verifier swaps in the synthesised vuln/benign payload here.
    #[serde(default)]
    pub payload_arg: u32,
    /// Deterministic predicate the verifier applies to the post-call
    /// state to decide success/failure (e.g. `"stdout contains '/etc/passwd'"`).
    pub oracle: String,
    /// Optional teardown statements; the verifier runs these even on
    /// `invoke` failure so each harness call is isolated.
    #[serde(default)]
    pub teardown: Vec<String>,
    /// Catch-all for forward-compatible upstream fields. Preserved so
    /// the agent's stored blob round-trips against the originating
    /// `serde_json::Value` the model produced.
    #[serde(flatten, default)]
    pub extra: Map<String, Value>,
}

/// Why a `HarnessSpec` failed [`HarnessSpec::validate`]. Surfaced in the
/// quarantine reason string the agent persists on the parent finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessSpecValidationError {
    SchemaVersionUnsupported(u32),
    EmptyField(&'static str),
    InvokeMissingPayloadSlot,
    InvokeHasMultiplePayloadSlots(usize),
}

impl std::fmt::Display for HarnessSpecValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaVersionUnsupported(v) => {
                write!(f, "unsupported schema_version {v} (only 1 supported)")
            }
            Self::EmptyField(name) => write!(f, "required field `{name}` is empty"),
            Self::InvokeMissingPayloadSlot => {
                write!(f, "invoke template must contain `@PAYLOAD` exactly once (found 0)")
            }
            Self::InvokeHasMultiplePayloadSlots(n) => {
                write!(f, "invoke template must contain `@PAYLOAD` exactly once (found {n})")
            }
        }
    }
}

impl std::error::Error for HarnessSpecValidationError {}

const PAYLOAD_SLOT: &str = "@PAYLOAD";
const CURRENT_SCHEMA_VERSION: u32 = 1;

impl HarnessSpec {
    /// Parse `body` as JSON and return the spec along with the original
    /// blob (re-serialised so callers persist a canonical, sorted-key
    /// representation rather than the model's whitespace-quirky reply).
    pub fn from_json(body: &str) -> Result<(Self, String), serde_json::Error> {
        let parsed: HarnessSpec = serde_json::from_str(body)?;
        let canonical = serde_json::to_string(&parsed)?;
        Ok((parsed, canonical))
    }

    /// Strict validation against the verifier's expectations. Adapters
    /// call this on every parsed spec; failures go to the
    /// quarantine-then-retry flow.
    pub fn validate(&self) -> Result<(), HarnessSpecValidationError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(HarnessSpecValidationError::SchemaVersionUnsupported(self.schema_version));
        }
        if self.cap.trim().is_empty() {
            return Err(HarnessSpecValidationError::EmptyField("cap"));
        }
        if self.lang.trim().is_empty() {
            return Err(HarnessSpecValidationError::EmptyField("lang"));
        }
        if self.entry.trim().is_empty() {
            return Err(HarnessSpecValidationError::EmptyField("entry"));
        }
        if self.invoke.trim().is_empty() {
            return Err(HarnessSpecValidationError::EmptyField("invoke"));
        }
        if self.oracle.trim().is_empty() {
            return Err(HarnessSpecValidationError::EmptyField("oracle"));
        }
        let slots = self.invoke.matches(PAYLOAD_SLOT).count();
        match slots {
            0 => Err(HarnessSpecValidationError::InvokeMissingPayloadSlot),
            1 => Ok(()),
            n => Err(HarnessSpecValidationError::InvokeHasMultiplePayloadSlots(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_spec_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "cap": "SQL_QUERY",
            "lang": "python",
            "entry": "app.handlers:lookup",
            "setup": ["import sqlite3", "db = sqlite3.connect(':memory:')"],
            "invoke": "db.execute('SELECT * FROM users WHERE name = ' + @PAYLOAD)",
            "payload_arg": 0,
            "oracle": "row count > expected",
            "teardown": ["db.close()"],
        })
        .to_string()
    }

    #[test]
    fn round_trip_with_extras() {
        let mut raw: Value = serde_json::from_str(&ok_spec_json()).unwrap();
        raw.as_object_mut().unwrap().insert("future_field".into(), Value::String("x".into()));
        let body = raw.to_string();
        let (spec, canonical) = HarnessSpec::from_json(&body).expect("parse");
        spec.validate().expect("valid");
        assert_eq!(spec.cap, "SQL_QUERY");
        assert!(canonical.contains("future_field"), "extras must survive: {canonical}");
    }

    #[test]
    fn validate_rejects_missing_payload_slot() {
        let mut v: Value = serde_json::from_str(&ok_spec_json()).unwrap();
        v["invoke"] = Value::String("db.execute(query)".to_string());
        let (spec, _) = HarnessSpec::from_json(&v.to_string()).expect("parse");
        let err = spec.validate().expect_err("must reject");
        assert_eq!(err, HarnessSpecValidationError::InvokeMissingPayloadSlot);
    }

    #[test]
    fn validate_rejects_duplicate_payload_slots() {
        let mut v: Value = serde_json::from_str(&ok_spec_json()).unwrap();
        v["invoke"] = Value::String(
            "db.execute('SELECT * FROM t WHERE a=' + @PAYLOAD + ' OR b=' + @PAYLOAD)".to_string(),
        );
        let (spec, _) = HarnessSpec::from_json(&v.to_string()).expect("parse");
        let err = spec.validate().expect_err("must reject");
        assert_eq!(err, HarnessSpecValidationError::InvokeHasMultiplePayloadSlots(2));
    }

    #[test]
    fn validate_rejects_unsupported_schema_version() {
        let mut v: Value = serde_json::from_str(&ok_spec_json()).unwrap();
        v["schema_version"] = Value::Number(2.into());
        let (spec, _) = HarnessSpec::from_json(&v.to_string()).expect("parse");
        let err = spec.validate().expect_err("must reject");
        assert_eq!(err, HarnessSpecValidationError::SchemaVersionUnsupported(2));
    }

    #[test]
    fn validate_rejects_empty_required_fields() {
        for field in &["cap", "lang", "entry", "invoke", "oracle"] {
            let mut v: Value = serde_json::from_str(&ok_spec_json()).unwrap();
            v[field] = Value::String("   ".to_string());
            let (spec, _) = HarnessSpec::from_json(&v.to_string()).expect("parse");
            let err = spec.validate().expect_err("must reject");
            assert!(matches!(err, HarnessSpecValidationError::EmptyField(name) if name == *field));
        }
    }

    #[test]
    fn parse_rejects_missing_required_field() {
        let bad = r#"{"schema_version":1,"cap":"x","lang":"y","entry":"e","invoke":"@PAYLOAD"}"#;
        // `oracle` missing.
        let err = HarnessSpec::from_json(bad).expect_err("must fail to deserialise");
        assert!(err.to_string().contains("oracle"), "got: {err}");
    }
}

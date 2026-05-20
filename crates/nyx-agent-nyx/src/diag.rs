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

use std::path::Path;

use nyctos_types::payload::SinkCtx;
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

/// Reason a nyx diag carries an `Unsupported(...)` marker. Parsed from
/// `evidence.unsupported` (current shape) or `evidence.reason` (fallback
/// shape). New upstream reasons land as new variants; the string at the
/// wire-shape boundary stays a tolerant lookup so unknown reasons fold
/// to `None` rather than panicking the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedReason {
    /// Static pass has no canonical payload for the diag's cap, so the
    /// PayloadSynthesis AI pass owns the row.
    NoPayloadsForCap,
}
impl UnsupportedReason {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "NoPayloadsForCap" => Some(Self::NoPayloadsForCap),
            _ => None,
        }
    }
}

/// Reason a nyx diag carries an `Inconclusive(...)` marker. Same
/// dual-key tolerance as `UnsupportedReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InconclusiveReason {
    /// Static pass could not derive a harness spec, so the
    /// SpecDerivation AI pass owns the row.
    SpecDerivationFailed,
}
impl InconclusiveReason {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "SpecDerivationFailed" => Some(Self::SpecDerivationFailed),
            _ => None,
        }
    }
}

impl Diag {
    /// Typed read of `evidence.unsupported` (current nyx shape) with
    /// `evidence.reason` as the fallback. Returns `None` when neither
    /// key carries a known reason; new reasons land as new
    /// `UnsupportedReason` variants without churning call sites.
    pub fn unsupported_reason(&self) -> Option<UnsupportedReason> {
        if let Some(r) = self
            .evidence_string("unsupported")
            .as_deref()
            .and_then(UnsupportedReason::from_str)
        {
            return Some(r);
        }
        self.evidence_string("reason")
            .as_deref()
            .and_then(UnsupportedReason::from_str)
    }

    /// Typed read of `evidence.inconclusive` with `evidence.reason` as
    /// the fallback. Mirror of `unsupported_reason`.
    pub fn inconclusive_reason(&self) -> Option<InconclusiveReason> {
        if let Some(r) = self
            .evidence_string("inconclusive")
            .as_deref()
            .and_then(InconclusiveReason::from_str)
        {
            return Some(r);
        }
        self.evidence_string("reason")
            .as_deref()
            .and_then(InconclusiveReason::from_str)
    }

    /// True when the diag carries the `Unsupported(NoPayloadsForCap)`
    /// marker. Phase 14's PayloadSynthesis fan-out fires exactly here.
    pub fn is_unsupported_no_payloads(&self) -> bool {
        matches!(self.unsupported_reason(), Some(UnsupportedReason::NoPayloadsForCap))
    }

    /// True when the diag carries the `Inconclusive(SpecDerivationFailed)`
    /// marker. Phase 15's SpecDerivation fan-out fires exactly here.
    pub fn is_spec_derivation_failed(&self) -> bool {
        matches!(self.inconclusive_reason(), Some(InconclusiveReason::SpecDerivationFailed))
    }

    /// Collect every flow-step file reference distinct from the diag's
    /// own `path`. The list is de-duplicated while preserving the order
    /// the steps appeared in the trace; the agent uses this to pull a
    /// short excerpt from each upstream file for the SpecDerivation
    /// prompt.
    pub fn flow_step_files(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for step in &self.flow_steps {
            let p = step.path.as_str();
            if p == self.path {
                continue;
            }
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    /// Best-effort sink context (callee + arg expressions + a code
    /// excerpt around the sink line) built from `evidence.sink` and a
    /// short read of the workspace source. Returns `None` only when
    /// the source file cannot be read; callers can fall back to the
    /// evidence-derived `callee` / `args` alone in that case.
    pub fn sink_ctx(&self, workspace_root: &Path) -> SinkCtx {
        let callee = self
            .evidence_object("sink")
            .and_then(|s| s.get("callee").or_else(|| s.get("name")))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let args = self
            .evidence_object("sink")
            .and_then(|s| s.get("args").or_else(|| s.get("arguments")))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let excerpt = read_excerpt(workspace_root, &self.path, self.line)
            .unwrap_or_else(|| "<source unavailable>".to_string());
        SinkCtx { callee, args, excerpt }
    }

    fn evidence_string(&self, key: &str) -> Option<String> {
        match &self.evidence {
            Value::Object(map) => map.get(key).and_then(|v| v.as_str()).map(str::to_string),
            _ => None,
        }
    }

    fn evidence_object(&self, key: &str) -> Option<&Value> {
        match &self.evidence {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

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

/// Read `±EXCERPT_RADIUS` lines around `line` from `workspace_root/path`.
/// Returns `None` on any I/O error; callers fall back to a placeholder.
fn read_excerpt(workspace_root: &Path, path: &str, line: u32) -> Option<String> {
    const EXCERPT_RADIUS: u32 = 3;
    let resolved = workspace_root.join(path);
    let raw = std::fs::read_to_string(&resolved).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    if lines.is_empty() || line == 0 {
        return None;
    }
    let idx = (line as usize).saturating_sub(1).min(lines.len().saturating_sub(1));
    let lo = idx.saturating_sub(EXCERPT_RADIUS as usize);
    let hi = (idx + EXCERPT_RADIUS as usize + 1).min(lines.len());
    let mut out = String::new();
    for (i, l) in lines[lo..hi].iter().enumerate() {
        out.push_str(&format!("{:>4}: {l}\n", lo + i + 1));
    }
    Some(out)
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
    fn unsupported_marker_detected_under_either_convention() {
        let primary: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"unsupported":"NoPayloadsForCap"}}"#,
        )
        .unwrap();
        assert!(primary.is_unsupported_no_payloads());

        let fallback: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"NoPayloadsForCap"}}"#,
        )
        .unwrap();
        assert!(fallback.is_unsupported_no_payloads());

        let neither: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"OtherThing"}}"#,
        )
        .unwrap();
        assert!(!neither.is_unsupported_no_payloads());
    }

    #[test]
    fn sink_ctx_lifts_callee_args_and_reads_excerpt() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("vuln.py");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            "def handler(q):\n    log.info(\"in\")\n    cursor.execute(\"SELECT * FROM users WHERE n='\" + q + \"'\")\n    log.info(\"out\")\n"
        )
        .unwrap();

        let diag: Diag = serde_json::from_str(
            r#"{
                "path":"vuln.py","line":3,"severity":"High","id":"py.sql","category":"SQL_QUERY",
                "evidence":{
                    "unsupported":"NoPayloadsForCap",
                    "sink":{"callee":"cursor.execute","args":["query"]}
                }
            }"#,
        )
        .unwrap();
        assert!(diag.is_unsupported_no_payloads());
        let ctx = diag.sink_ctx(tmp.path());
        assert_eq!(ctx.callee, "cursor.execute");
        assert_eq!(ctx.args, vec!["query".to_string()]);
        // Excerpt should span lines 1..=4 (line 3 +/-3, clamped to file).
        assert!(ctx.excerpt.contains("cursor.execute"), "got: {}", ctx.excerpt);
        assert!(ctx.excerpt.contains("   3:"));
    }

    #[test]
    fn sink_ctx_falls_back_when_source_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let diag: Diag = serde_json::from_str(
            r#"{"path":"missing.py","line":3,"severity":"High","id":"x","category":"SQL_QUERY"}"#,
        )
        .unwrap();
        let ctx = diag.sink_ctx(tmp.path());
        assert_eq!(ctx.callee, "unknown");
        assert!(ctx.args.is_empty());
        assert!(ctx.excerpt.contains("<source unavailable>"));
    }

    #[test]
    fn spec_derivation_marker_detected_under_either_convention() {
        let primary: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"inconclusive":"SpecDerivationFailed"}}"#,
        )
        .unwrap();
        assert!(primary.is_spec_derivation_failed());

        let fallback: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"SpecDerivationFailed"}}"#,
        )
        .unwrap();
        assert!(fallback.is_spec_derivation_failed());

        let neither: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"OtherThing"}}"#,
        )
        .unwrap();
        assert!(!neither.is_spec_derivation_failed());
    }

    #[test]
    fn flow_step_files_dedupes_and_skips_self() {
        let raw = r#"{
            "path": "sink.py", "line": 19, "severity": "Medium",
            "id": "taint-unsanitised-flow", "category": "SQL_QUERY",
            "evidence": {
                "flow_steps": [
                    {"step": 1, "kind": "source", "file": "router.py", "line": 5},
                    {"step": 2, "kind": "call",   "file": "router.py", "line": 7},
                    {"step": 3, "kind": "call",   "file": "framework/orm.py", "line": 88},
                    {"step": 4, "kind": "sink",   "file": "sink.py", "line": 19}
                ]
            }
        }"#;
        let mut d: Diag = serde_json::from_str(raw).expect("parse");
        d.lift_flow_steps();
        let files = d.flow_step_files();
        assert_eq!(files, vec!["router.py", "framework/orm.py"]);
    }

    #[test]
    fn unsupported_reason_typed_under_both_conventions() {
        let primary: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"unsupported":"NoPayloadsForCap"}}"#,
        )
        .unwrap();
        assert_eq!(primary.unsupported_reason(), Some(UnsupportedReason::NoPayloadsForCap));

        let fallback: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"NoPayloadsForCap"}}"#,
        )
        .unwrap();
        assert_eq!(fallback.unsupported_reason(), Some(UnsupportedReason::NoPayloadsForCap));

        let neither: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"OtherThing"}}"#,
        )
        .unwrap();
        assert_eq!(neither.unsupported_reason(), None);
    }

    #[test]
    fn inconclusive_reason_typed_under_both_conventions() {
        let primary: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"inconclusive":"SpecDerivationFailed"}}"#,
        )
        .unwrap();
        assert_eq!(primary.inconclusive_reason(), Some(InconclusiveReason::SpecDerivationFailed));

        let fallback: Diag = serde_json::from_str(
            r#"{"path":"a.py","line":1,"severity":"Low","id":"X","category":"Y",
                "evidence":{"reason":"SpecDerivationFailed"}}"#,
        )
        .unwrap();
        assert_eq!(fallback.inconclusive_reason(), Some(InconclusiveReason::SpecDerivationFailed));
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

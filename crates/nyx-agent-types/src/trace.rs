//! Shared agent-trace row shape.
//!
//! `AgentTraceRecord` is the on-the-wire representation of one row in
//! the `agent_traces` table. The store layer (`nyx_agent_core::store::
//! AgentTraceStore`) hydrates it via `sqlx::query_as!`; the API
//! projects it onto a slimmer [`crate::api::AgentTraceRow`] for the
//! FE.
//!
//! Lives here so the TS frontend can `import type { AgentTraceRecord }`
//! from `types.gen.ts` instead of hand-rolling a parallel interface.
//! The runtime `TaskKind` enum stays in `nyx_agent_core::store::trace`
//! because it is a convenience helper that only produces the string
//! form persisted in the `task_kind` column; the wire shape itself is
//! already a `String`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// On-the-wire shape of an `agent_traces` table row. All `i64`
/// columns carry `#[ts(type = "number")]` so the generated TS
/// declaration uses `number` rather than `bigint` (serde_json emits
/// JSON numbers for `i64`, which JS receives as `number`).
///
/// `verifier_blob` is populated only for `TaskKind::Verifier` rows
/// and carries the spec id, vuln/benign payload sha256 hex digests,
/// and per-run exit codes so the trace viewer can render the
/// verifier's inputs + outputs without joining `findings.verdict_blob`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AgentTraceRecord {
    pub id: String,
    pub finding_id: Option<String>,
    pub task_kind: String,
    pub runtime_name: String,
    pub model: String,
    pub prompt_version: Option<String>,
    pub conversation_jsonl_path: Option<String>,
    #[ts(type = "number")]
    pub tokens_in: i64,
    #[ts(type = "number")]
    pub tokens_out: i64,
    #[ts(type = "number")]
    pub cost_usd_micros: i64,
    #[ts(type = "number")]
    pub cache_hits: i64,
    #[ts(type = "number")]
    pub cache_misses: i64,
    #[ts(type = "number | null")]
    pub duration_ms: Option<i64>,
    #[ts(type = "number")]
    pub started_at: i64,
    #[ts(type = "number | null")]
    pub finished_at: Option<i64>,
    pub verifier_blob: Option<String>,
}

//! Shared run-row shape.
//!
//! `RunRecord` is the on-the-wire representation of one row in the
//! `runs` table; it crosses both crate and wire boundaries (the API
//! returns it verbatim from `GET /runs/:id` and `GET /runs?status=...`).
//! Lives here so the TS frontend can `import type { RunRecord }` from
//! `types.gen.ts` instead of hand-rolling a parallel interface.
//!
//! The runtime enums `RunStatus` and `TriggeredBy` stay in
//! `nyctos_core::store::run` because they are convenience helpers that
//! only produce the string form persisted in the `status` /
//! `triggered_by` columns; the wire shape itself is already a `String`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// On-the-wire shape of a `runs` table row. All `i64` columns carry
/// `#[ts(type = "number")]` so the generated TS declaration uses
/// `number` rather than `bigint` (`serde_json` emits a JSON number for
/// `i64`, which JS receives as `number`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct RunRecord {
    pub id: String,
    #[ts(type = "number")]
    pub started_at: i64,
    #[ts(type = "number | null")]
    pub finished_at: Option<i64>,
    pub status: String,
    pub triggered_by: String,
    pub git_ref: Option<String>,
    pub parent_run_id: Option<String>,
    #[ts(type = "number | null")]
    pub wall_clock_ms: Option<i64>,
    #[ts(type = "number")]
    pub total_ai_spend_usd_micros: i64,
}

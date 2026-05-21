//! Shared finding-row shape.
//!
//! `FindingRecord` is the on-the-wire representation of one row in the
//! `findings` table; both the API (`GET /findings`, `GET /findings/:id`,
//! `GET /runs/:id/findings`) and the SPA (`frontend/src/api/types.gen.ts`)
//! depend on this shape. Lives here so the TS frontend can
//! `import type { FindingRecord }` from `types.gen.ts` instead of
//! hand-rolling a parallel interface.
//!
//! The runtime enums `FindingStatus` / `FindingOrigin` / `TriageState`
//! stay in `nyctos_core::store::finding` because they are convenience
//! helpers that only produce the string form persisted in the
//! corresponding columns; the wire shape itself is already a `String`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// On-the-wire shape of a `findings` table row. All `i64` columns
/// carry `#[ts(type = "number")]` so the generated TS declaration uses
/// `number` rather than `bigint` (`serde_json` emits a JSON number for
/// `i64`, which JS receives as `number`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FindingRecord {
    pub id: String,
    pub run_id: String,
    pub repo: String,
    pub path: String,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub cap: String,
    pub rule: String,
    pub severity: String,
    pub status: String,
    pub finding_origin: String,
    #[ts(type = "number")]
    pub first_seen: i64,
    #[ts(type = "number")]
    pub last_seen: i64,
    pub superseded_by: Option<String>,
    pub triage_state: String,
    pub triage_assigned_to: Option<String>,
    pub verdict_blob: Option<String>,
    pub repro_path: Option<String>,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
    pub chain_id: Option<String>,
    /// Back-link to `harness_specs.id` populated by SpecDerivation.
    /// `None` for static-pass rows that never went through the AI
    /// spec pass.
    pub spec_id: Option<String>,
}

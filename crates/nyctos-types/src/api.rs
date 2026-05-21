//! Wire envelopes that don't map 1:1 to a DB row.
//!
//! Request/response shapes whose only home is the HTTP surface (e.g.
//! `GET /api/v1/health`) live here so they share the same
//! `#[derive(TS)]` codegen path as the record types in the
//! domain-specific modules. The Rust source of truth for each endpoint
//! still lives next to its handler in `crates/nyctos-api/src/router.rs`;
//! this module hosts only the wire shapes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::finding::FindingRecord;

/// Response body for `GET /api/v1/health`. `status` is always the
/// literal string `"ok"` on the wire (the daemon never returns a
/// non-200 success); the FE keeps the `"ok"` literal narrowing as an
/// ergonomic alias on top of the generated `string` shape (same
/// pattern as `RepoSourceKind`). `version` is the daemon's
/// `CARGO_PKG_VERSION` at build time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Response body for `GET /api/v1/setup/status`. The wizard polls this
/// to decide whether to render its onboarding flow or send the
/// operator into the main app. `ai_runtime` / `sandbox_backend` are
/// strings on the wire because the router maps the closed enum
/// variants through `ai_runtime_label` / `sandbox_backend_label` at
/// response time; the FE keeps the literal-union narrows
/// (`AiRuntimeChoice` / `SandboxBackendChoice`) as ergonomic aliases
/// on top of the generated `string` shape (same pattern as
/// `RepoSourceKind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SetupStatusResponse {
    /// `true` once `nyctos.toml` is on disk.
    pub complete: bool,
    /// Path the wizard would write to. Surfaced so the UI can render
    /// the operator's resolved location.
    pub config_path: String,
    /// Currently-configured AI runtime (matches `[ai].runtime`).
    pub ai_runtime: String,
    /// Currently-configured sandbox backend (matches `[sandbox].backend`).
    pub sandbox_backend: String,
}

/// Request body for `POST /api/v1/setup`. The router validates
/// `ai_runtime` / `sandbox_backend` against the closed enum sets at
/// handler time (`parse_ai_runtime` / `parse_sandbox_backend`), so the
/// wire shape carries plain `String` and the FE re-narrows to the
/// literal-union ergonomic aliases at the call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SetupRequest {
    /// Operator-typed AI runtime: `none` | `anthropic` | `local-llm` |
    /// `claude-code`. The wizard stashes the API key (when relevant)
    /// out-of-band via `secrets`, not in the TOML.
    pub ai_runtime: String,
    /// Anthropic API key. Required when `ai_runtime = "anthropic"`.
    /// Persisted to the OS keychain; never written to TOML or logs.
    #[serde(default)]
    #[ts(optional)]
    pub anthropic_api_key: Option<String>,
    /// Endpoint URL for `local-llm` runtime (OpenAI-compatible). Stored
    /// in `[ai].api_base`.
    #[serde(default)]
    #[ts(optional)]
    pub local_llm_url: Option<String>,
    /// Optional bearer attached to `local-llm` requests; persisted to
    /// the keychain.
    #[serde(default)]
    #[ts(optional)]
    pub local_llm_token: Option<String>,
    /// Sandbox backend: `auto` | `process` | `birdcage` | `libkrun`
    /// | `firecracker` | `docker`.
    pub sandbox_backend: String,
    /// Operator-attested ownership of the install. The daemon refuses
    /// to commit the config when this is `false`.
    #[serde(default)]
    pub i_own_this: bool,
}

/// Request body for `POST /api/v1/setup/doctor`. The wizard's
/// "Run checks" step posts the operator's tentative runtime +
/// backend selection; the daemon validates both against the closed
/// enum sets (`parse_ai_runtime` / `parse_sandbox_backend`) at
/// handler time and returns a [`DoctorResponse`] regardless of
/// validation outcome (validation errors surface as `ApiError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DoctorRequest {
    /// AI runtime being verified. Doctor only inspects what the chosen
    /// runtime depends on (e.g. `claude-code` looks for the binary).
    pub ai_runtime: String,
    /// Sandbox backend being verified.
    pub sandbox_backend: String,
}

/// One row in [`DoctorResponse::checks`]. `name` is a short identifier
/// the UI can key on for icons (`state-dir`, `ai`, `sandbox`, ...);
/// `message` is operator-facing remediation copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Response body for `POST /api/v1/setup/doctor`. Lightweight check
/// pass invoked by the wizard's step 3 to surface problems before the
/// operator commits a config. Reports a list of per-check results
/// rather than a single pass/fail so the UI can render targeted
/// remediation hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
}

/// Response body for `POST /api/v1/findings/:id/repro-bundle`. The
/// daemon writes a per-finding tarball under `<state>/bundles/<id>.tar`
/// and returns this index so the SPA can render the resulting path,
/// hash, and artifact list. `bundle_path` carries the on-disk location
/// as a `PathBuf` (serde serialises as a UTF-8 string on the wire,
/// matching the FE's `bundle_path: string` shape); the canonical
/// source of truth used to live in `nyctos_core::report::repro_bundle`
/// and was lifted here so the `#[derive(TS)]` codegen path owns the
/// FE shape. `byte_size` is the byte length of the produced tarball
/// (annotated `#[ts(type = "number")]` so ts-rs renders `number`
/// rather than its default `bigint` for `u64`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BundleManifest {
    pub finding_id: String,
    #[ts(type = "string")]
    pub bundle_path: PathBuf,
    pub sha256: String,
    #[ts(type = "number")]
    pub byte_size: u64,
    pub artifacts: Vec<String>,
}

/// Per-row diff classification on `GET /api/v1/runs/:id/findings`. The
/// `lowercase` rename matches the FE's literal-union narrow
/// (`"new" | "regressed" | "closed" | "unchanged"`) so ts-rs renders the
/// type as that exact union and the SPA keys into `DIFF_TONE` /
/// `DIFF_LABEL` records without casting.
///
/// - `New`: not observed during the prior run.
/// - `Regressed`: observed during both runs but the status differs
///   (e.g. was `Closed` in prior, is `Open` now).
/// - `Closed`: observed during the prior run, not observed during
///   the current run. The row body is the finding's latest-known
///   shape; the diff status flags that no observation landed under
///   the current run.
/// - `Unchanged`: observed during both runs with the same status.
///
/// Sourced from the `run_findings` join table seeded by migration
/// `0004_run_findings.sql`. Runs whose membership predates the
/// migration carry no rows in that table; the router classifier
/// degrades to `New` for them so the chip wallpapers an
/// unknown-history run rather than mislabelling it `Unchanged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
pub enum FindingDiffStatus {
    New,
    Regressed,
    Closed,
    Unchanged,
}

/// One row in [`RunFindingsResponse::items`]. Flattens
/// [`FindingRecord`] onto a single object alongside the
/// [`FindingDiffStatus`] chip; the FE's hand-rolled
/// `interface FindingWithDiff extends FindingRecord { diff_status: ... }`
/// is structurally equivalent to the `FindingRecord & { diff_status: ... }`
/// shape ts-rs generates from the `#[serde(flatten)]` directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FindingWithDiff {
    #[serde(flatten)]
    pub record: FindingRecord,
    pub diff_status: FindingDiffStatus,
}

/// Response body for `GET /api/v1/runs/:id/findings`. `prior_run_id` is
/// `null` (not absent) when this is the first run on the install, in
/// which case every entry in `items` carries
/// [`FindingDiffStatus::New`]; `#[ts(type = "string | null")]` pins the
/// wire shape so the FE keeps reading `prior_run_id: string | null`
/// rather than `string | undefined`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct RunFindingsResponse {
    pub run_id: String,
    #[ts(type = "string | null")]
    pub prior_run_id: Option<String>,
    pub items: Vec<FindingWithDiff>,
}

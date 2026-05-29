//! Wire envelopes that don't map 1:1 to a DB row.
//!
//! Request/response shapes whose only home is the HTTP surface (e.g.
//! `GET /api/v1/health`) live here so they share the same
//! `#[derive(TS)]` codegen path as the record types in the
//! domain-specific modules. The Rust source of truth for each endpoint
//! still lives next to its handler in `crates/nyx-agent-api/src/router.rs`;
//! this module hosts only the wire shapes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::finding::FindingRecord;
use crate::trace::AgentTraceRecord;

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
    /// `true` once `nyx-agent.toml` is on disk.
    pub complete: bool,
    /// Path the wizard would write to. Surfaced so the UI can render
    /// the operator's resolved location.
    pub config_path: String,
    /// Currently-configured AI runtime (matches `[ai].runtime`).
    pub ai_runtime: String,
    /// Optional non-secret AI provider label (matches `[ai].provider`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ai_provider: Option<String>,
    /// Optional model override (matches `[ai].model`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ai_model: Option<String>,
    /// Optional reasoning effort for CLI-backed runtimes (matches
    /// `[ai].effort`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ai_effort: Option<String>,
    /// Optional context-window hint in tokens for CLI-backed runtimes
    /// (matches `[ai].context_window`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ai_context_window: Option<u32>,
    /// Optional non-secret base URL for local OpenAI-compatible
    /// runtimes. Bearer tokens stay in the OS keychain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ai_api_base: Option<String>,
    /// Configured per-run AI budget cap in USD micros. `None` means
    /// runs are uncapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number | null")]
    pub default_run_budget_usd_micros: Option<i64>,
    /// Currently-configured sandbox backend (matches `[sandbox].backend`).
    pub sandbox_backend: String,
    /// Whether sandboxing is enabled globally.
    pub sandbox_enabled: bool,
    /// Whether sandboxed runs may access the network.
    pub sandbox_allow_network: bool,
    /// UI listen address (matches `[ui].listen_addr`).
    pub ui_listen_addr: String,
    /// Whether `nyx-agent serve` opens the browser by default.
    pub ui_open_browser: bool,
    /// Current log level (matches `[general].log_level`).
    pub log_level: String,
    /// Optional configured state directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub state_dir: Option<String>,
    /// Maximum number of concurrent scans.
    pub max_parallel_scans: u32,
    /// Per-scan timeout in seconds.
    pub scan_timeout_secs: u64,
}

/// Request body for `POST /api/v1/setup`. The router validates
/// `ai_runtime` / `sandbox_backend` against the closed enum sets at
/// handler time (`parse_ai_runtime` / `parse_sandbox_backend`), so the
/// wire shape carries plain `String` and the FE re-narrows to the
/// literal-union ergonomic aliases at the call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SetupRequest {
    /// Operator-typed AI runtime: `none` | `anthropic` | `local-llm` |
    /// `claude-code` | `codex`. Static/no-AI mode is valid and
    /// complete. BYOK/local secrets are stored out-of-band via
    /// `secrets`, not in the TOML.
    pub ai_runtime: String,
    /// Optional model override. Omitted leaves `[ai].model` unchanged;
    /// `null` or an empty string clears it.
    #[serde(default)]
    #[ts(optional, type = "string | null")]
    pub ai_model: Option<Option<String>>,
    /// Optional reasoning effort for CLI-backed runtimes. Omitted
    /// leaves `[ai].effort` unchanged; `null` or an empty string
    /// clears it.
    #[serde(default)]
    #[ts(optional, type = "string | null")]
    pub ai_effort: Option<Option<String>>,
    /// Optional context-window hint in tokens for CLI-backed runtimes.
    /// Omitted leaves `[ai].context_window` unchanged; `null` clears
    /// it.
    #[serde(default)]
    #[ts(optional, type = "number | null")]
    pub ai_context_window: Option<Option<u32>>,
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
    /// Optional per-run AI budget cap in USD micros. `None` disables
    /// the cap; a positive value enables it.
    #[serde(default)]
    #[ts(optional, type = "number | null")]
    pub default_run_budget_usd_micros: Option<i64>,
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
    /// runtime depends on (e.g. CLI runtimes look for their binary).
    pub ai_runtime: String,
    /// Unsaved CLI model supplied by the UI for this check. Doctor
    /// accepts but does not persist this field.
    #[serde(default)]
    #[ts(optional)]
    pub ai_model: Option<String>,
    /// Unsaved CLI reasoning effort supplied by the UI for this check.
    /// Doctor accepts but does not persist this field.
    #[serde(default)]
    #[ts(optional)]
    pub ai_effort: Option<String>,
    /// Unsaved CLI context-window hint supplied by the UI for this
    /// check. Doctor accepts but does not persist this field.
    #[serde(default)]
    #[ts(optional)]
    pub ai_context_window: Option<u32>,
    /// Unsaved Anthropic API key supplied by the UI for this check.
    /// The daemon only tests whether a non-empty key was provided; it
    /// does not persist this field from `/setup/doctor`.
    #[serde(default)]
    #[ts(optional)]
    pub anthropic_api_key: Option<String>,
    /// Unsaved local OpenAI-compatible endpoint URL supplied by the UI
    /// for this check. Persisted only by `POST /setup`.
    #[serde(default)]
    #[ts(optional)]
    pub local_llm_url: Option<String>,
    /// Unsaved local OpenAI-compatible bearer token supplied by the UI
    /// for this check. Doctor only acknowledges its presence.
    #[serde(default)]
    #[ts(optional)]
    pub local_llm_token: Option<String>,
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
/// source of truth used to live in `nyx_agent_core::report::repro_bundle`
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
/// Sourced from the `run_findings` join table. Runs with no membership
/// rows degrade to `New` so the chip wallpapers an unknown-history run
/// rather than mislabelling it `Unchanged`.
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

/// Discriminator for [`QuarantineItem`] so the SPA can pick the right
/// promote / dismiss path. `Finding` rows live in the `findings`
/// table with `status = 'Quarantine'`; `Candidate` rows live in
/// `candidate_findings` with `status = 'Pending'`. `snake_case`
/// matches the FE's existing `QuarantineKind = "finding" | "candidate"`
/// literal union so ts-rs renders the type as that exact union and
/// the SPA's `KIND_TONE` / `KIND_LABEL` keyed records continue to
/// work without casting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineKind {
    Finding,
    Candidate,
}

/// Unified row the Quarantine page renders. Combines both sources of
/// "AI-proposed, not yet dynamic-confirmed" rows so the operator sees
/// one list: `findings` rows with `status = 'Quarantine'` (kind
/// [`QuarantineKind::Finding`]) and `candidate_findings` rows with
/// `status = 'Pending'` (kind [`QuarantineKind::Candidate`]).
///
/// `line` and `last_seen` carry `#[ts(type = "number | null")]` to
/// override ts-rs's default `bigint | null` for `Option<i64>`; the FE
/// reads both as `number | null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct QuarantineItem {
    pub kind: QuarantineKind,
    pub id: String,
    pub run_id: String,
    pub repo: String,
    pub path: String,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub cap: String,
    pub rule: Option<String>,
    pub severity: Option<String>,
    pub finding_origin: Option<String>,
    pub prompt_version: Option<String>,
    pub attack_provenance: Option<String>,
    pub rationale: Option<String>,
    pub verdict_blob: Option<String>,
    #[ts(type = "number | null")]
    pub last_seen: Option<i64>,
}

/// Wire row for `GET /api/v1/findings/:id/traces` (and `/traces/:id`).
/// Projection over [`AgentTraceRecord`] that drops the persistence-only
/// `verifier_blob` field so the FE shape stays minimal; lift
/// `verifier_blob` here when the trace viewer (Phase 24) starts
/// rendering Verifier-row inputs/outputs without joining
/// `findings.verdict_blob`. All `i64` fields carry
/// `#[ts(type = "number")]` to override ts-rs's `bigint` default
/// (serde_json emits JSON numbers for `i64`, which JS receives as
/// `number`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AgentTraceRow {
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
}

impl From<AgentTraceRecord> for AgentTraceRow {
    fn from(r: AgentTraceRecord) -> Self {
        Self {
            id: r.id,
            finding_id: r.finding_id,
            task_kind: r.task_kind,
            runtime_name: r.runtime_name,
            model: r.model,
            prompt_version: r.prompt_version,
            conversation_jsonl_path: r.conversation_jsonl_path,
            tokens_in: r.tokens_in,
            tokens_out: r.tokens_out,
            cost_usd_micros: r.cost_usd_micros,
            cache_hits: r.cache_hits,
            cache_misses: r.cache_misses,
            duration_ms: r.duration_ms,
            started_at: r.started_at,
            finished_at: r.finished_at,
        }
    }
}

/// Frame variant for the SSE stream emitted by
/// `POST /api/v1/findings/:id/replay`. Mirrors the `event:` header of
/// each SSE frame. `lowercase` matches the router's hand-formatted
/// `event:` line and the FE's existing literal-union narrow so ts-rs
/// renders the type as that exact union.
///
/// - `Start`: bash spawned; carries a JSON object with `finding_id`,
///   `bundle_path`, `started_at_ms`.
/// - `Stdout` / `Stderr`: one captured line of repro.sh output.
/// - `End`: bash exited; carries a JSON object with `exit_code`,
///   `status`, `started_at_ms`, `finished_at_ms`, `duration_ms`.
/// - `Error`: spawn / IO / timeout. Aborts the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
pub enum ReplayEventKind {
    Start,
    Stdout,
    Stderr,
    End,
    Error,
}

/// FE-facing projection of one SSE frame from
/// `POST /api/v1/findings/:id/replay`. The wire format is raw SSE
/// (`event: <kind>\ndata: <line>\n\n`), not a JSON envelope; this
/// struct exists purely to give ts-rs a generated TS shape so the
/// FE can drop its hand-rolled interface. `data` is the SSE frame's
/// `data:` body verbatim (newline-joined when the frame carried
/// multiple data lines); the FE prints it into the replay log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ReplayEvent {
    pub kind: ReplayEventKind,
    pub data: String,
}

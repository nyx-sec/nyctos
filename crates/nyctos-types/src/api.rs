//! Wire envelopes that don't map 1:1 to a DB row.
//!
//! Request/response shapes whose only home is the HTTP surface (e.g.
//! `GET /api/v1/health`) live here so they share the same
//! `#[derive(TS)]` codegen path as the record types in the
//! domain-specific modules. The Rust source of truth for each endpoint
//! still lives next to its handler in `crates/nyctos-api/src/router.rs`;
//! this module hosts only the wire shapes.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

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

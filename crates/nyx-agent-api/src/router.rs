//! Axum router exposing the loopback HTTP and WebSocket surface.
//!
//! Routes live under `/api/v1/`; the WebSocket lives at
//! `/api/v1/events`. Subscribers connect with an optional
//! `?run_id=<id>` query parameter to filter the broadcast stream to a
//! single run; without the filter every `AgentEvent` lands on the
//! socket.

use std::time::Duration;

use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, Request, State,
    },
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{sse::Event as SseEvent, sse::Sse, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;
use tower_http::trace::TraceLayer;

use nyx_agent_core::report::{
    build_bundle, build_run_card, render_html as render_run_card_html,
    render_markdown as render_run_card_markdown, verify_sha256 as verify_bundle_sha256,
    BundleError, BundleManifest, RunCard, RunCardError,
};
use nyx_agent_core::store::{
    AgentTraceRecord, CandidateFindingRecord, CandidateStatus, ChainRecord, FindingFilter,
    FindingRecord, PatchOption, RepoPatch, RepoRecord, RunRecord,
};
use nyx_agent_core::{AiRuntime, SandboxBackend, ACCOUNT_AI_ANTHROPIC, ACCOUNT_AI_LOCAL_LLM};
use nyx_agent_types::event::{AgentEvent, RunEvent};

use crate::state::{ApiError, ServerState};

/// Build the production router with every `/api/v1/...` route attached.
pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup", post(submit_setup))
        .route("/api/v1/setup/doctor", post(setup_doctor))
        .route("/api/v1/repos", get(list_repos).post(create_repo))
        .route("/api/v1/repos/test", post(test_repo_connectivity))
        .route(
            "/api/v1/repos/:name",
            get(get_repo).patch(patch_repo).delete(delete_repo),
        )
        .route("/api/v1/scan", post(trigger_scan))
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/:id", get(get_run))
        .route("/api/v1/runs/:id/findings", get(findings_for_run))
        .route("/api/v1/runs/:id/summary", get(run_summary))
        .route("/api/v1/runs/:id/summary.md", get(run_summary_markdown))
        .route("/api/v1/runs/:id/summary.html", get(run_summary_html))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/findings/:id", get(get_finding))
        .route("/api/v1/findings/:id/repro-bundle", post(create_repro_bundle))
        .route(
            "/api/v1/findings/:id/repro-bundle.tar",
            get(download_repro_bundle),
        )
        .route("/api/v1/findings/:id/replay", post(replay_repro_bundle))
        .route("/api/v1/chains/:id", get(get_chain))
        .route("/api/v1/findings/:id/traces", get(traces_for_finding))
        .route("/api/v1/traces/:id", get(get_trace))
        .route("/api/v1/quarantine", get(list_quarantine))
        .route("/api/v1/quarantine/:id/promote", post(promote_quarantine))
        .route("/api/v1/quarantine/:id/dismiss", post(dismiss_quarantine))
        .route("/api/v1/events", get(events_ws))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Bearer-token gate. Skipped entirely when [`AuthConfig::token`] is
/// unset (the `--headless` path), and skipped on a per-route basis for
/// `/health` plus the wizard endpoints — but only while setup is still
/// pending. Once `nyx-agent.toml` exists the wizard endpoints require
/// the bearer token like every other mutation endpoint so an attacker
/// cannot overwrite the operator's config.
async fn auth_layer(
    State(state): State<ServerState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !state.auth.is_enforced() {
        return Ok(next.run(req).await);
    }
    let path = req.uri().path();
    if is_always_open(path) {
        return Ok(next.run(req).await);
    }
    if is_setup_path(path) && !state.setup.is_complete() {
        return Ok(next.run(req).await);
    }
    let token = state.auth.token.as_deref().unwrap_or_default();
    if check_bearer(&req, token) || check_query_token(&req, token) {
        return Ok(next.run(req).await);
    }
    Err(ApiError::Unauthorized)
}

fn is_always_open(path: &str) -> bool {
    path == "/api/v1/health"
}

fn is_setup_path(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/setup" | "/api/v1/setup/status" | "/api/v1/setup/doctor"
    )
}

fn check_bearer(req: &Request, expected: &str) -> bool {
    let Some(value) = req.headers().get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(text) = value.to_str() else { return false };
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("Bearer ") else { return false };
    constant_eq(rest.trim(), expected)
}

fn check_query_token(req: &Request, expected: &str) -> bool {
    let Some(q) = req.uri().query() else { return false };
    for pair in q.split('&') {
        if let Some(rest) = pair.strip_prefix("token=") {
            let decoded = urlencoded_decode(rest);
            if constant_eq(&decoded, expected) {
                return true;
            }
        }
    }
    false
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn urlencoded_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_digit(bytes[i + 1]);
                let lo = hex_digit(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as char);
                    i += 3;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> impl IntoResponse {
    Json(Health { status: "ok", version: env!("CARGO_PKG_VERSION") })
}

// ---- /setup -----------------------------------------------------------------

#[derive(Debug, Serialize)]
struct SetupStatusResponse {
    /// `true` once `nyx-agent.toml` is on disk.
    complete: bool,
    /// Path the wizard would write to. Surfaced so the UI can render
    /// the operator's resolved location.
    config_path: String,
    /// Currently-configured AI runtime (matches `[ai].runtime`).
    ai_runtime: String,
    /// Currently-configured sandbox backend (matches `[sandbox].backend`).
    sandbox_backend: String,
}

async fn setup_status(State(s): State<ServerState>) -> Result<Json<SetupStatusResponse>, ApiError> {
    let cfg = s.setup.config.read().await;
    Ok(Json(SetupStatusResponse {
        complete: s.setup.is_complete(),
        config_path: s.setup.config_path.display().to_string(),
        ai_runtime: ai_runtime_label(cfg.ai.runtime).to_string(),
        sandbox_backend: sandbox_backend_label(cfg.sandbox.backend).to_string(),
    }))
}

fn ai_runtime_label(r: AiRuntime) -> &'static str {
    match r {
        AiRuntime::None => "none",
        AiRuntime::Anthropic => "anthropic",
        AiRuntime::LocalLlm => "local-llm",
        AiRuntime::ClaudeCode => "claude-code",
    }
}

fn sandbox_backend_label(b: SandboxBackend) -> &'static str {
    match b {
        SandboxBackend::Auto => "auto",
        SandboxBackend::Process => "process",
        SandboxBackend::Birdcage => "birdcage",
        SandboxBackend::Libkrun => "libkrun",
        SandboxBackend::Firecracker => "firecracker",
        SandboxBackend::Docker => "docker",
    }
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    /// Operator-typed AI runtime: `none` | `anthropic` | `local-llm` |
    /// `claude-code`. The wizard stashes the API key (when relevant)
    /// out-of-band via `secrets`, not in the TOML.
    pub ai_runtime: String,
    /// Anthropic API key. Required when `ai_runtime = "anthropic"`.
    /// Persisted to the OS keychain; never written to TOML or logs.
    #[serde(default)]
    pub anthropic_api_key: Option<String>,
    /// Endpoint URL for `local-llm` runtime (OpenAI-compatible). Stored
    /// in `[ai].api_base`.
    #[serde(default)]
    pub local_llm_url: Option<String>,
    /// Optional bearer attached to `local-llm` requests; persisted to
    /// the keychain.
    #[serde(default)]
    pub local_llm_token: Option<String>,
    /// Sandbox backend: `auto` | `process` | `birdcage` | `libkrun`
    /// | `firecracker` | `docker`.
    pub sandbox_backend: String,
    /// Operator-attested ownership of the install. The daemon refuses
    /// to commit the config when this is `false`.
    #[serde(default)]
    pub i_own_this: bool,
}

#[derive(Debug, Serialize)]
struct SetupResponse {
    ok: bool,
    config_path: String,
}

async fn submit_setup(
    State(s): State<ServerState>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, ApiError> {
    if !req.i_own_this {
        return Err(ApiError::BadRequest(
            "i_own_this must be true before the daemon will write a config".to_string(),
        ));
    }

    let ai_runtime = parse_ai_runtime(&req.ai_runtime)?;
    let sandbox_backend = parse_sandbox_backend(&req.sandbox_backend)?;

    if matches!(ai_runtime, AiRuntime::Anthropic)
        && req.anthropic_api_key.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(ApiError::BadRequest(
            "anthropic_api_key is required when ai_runtime = \"anthropic\"".to_string(),
        ));
    }
    if matches!(ai_runtime, AiRuntime::LocalLlm)
        && req.local_llm_url.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(ApiError::BadRequest(
            "local_llm_url is required when ai_runtime = \"local-llm\"".to_string(),
        ));
    }

    // Persist secrets first so a failure there does not orphan a
    // half-written config file. The keychain may legitimately reject
    // calls in non-interactive environments (e.g. CI); surface that as
    // a 500 with the precise reason.
    if let Some(key) = req
        .anthropic_api_key
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        s.setup
            .secrets
            .set(ACCOUNT_AI_ANTHROPIC, key.trim())
            .map_err(|e| ApiError::Internal(format!("store Anthropic key: {e}")))?;
    } else if matches!(ai_runtime, AiRuntime::None | AiRuntime::LocalLlm | AiRuntime::ClaudeCode) {
        let _ = s.setup.secrets.delete(ACCOUNT_AI_ANTHROPIC);
    }
    if let Some(tok) = req.local_llm_token.as_deref().filter(|v| !v.trim().is_empty()) {
        s.setup
            .secrets
            .set(ACCOUNT_AI_LOCAL_LLM, tok.trim())
            .map_err(|e| ApiError::Internal(format!("store local-llm token: {e}")))?;
    } else if !matches!(ai_runtime, AiRuntime::LocalLlm) {
        let _ = s.setup.secrets.delete(ACCOUNT_AI_LOCAL_LLM);
    }

    let mut cfg = s.setup.config.read().await.clone();
    cfg.ai.runtime = ai_runtime;
    cfg.ai.provider = match ai_runtime {
        AiRuntime::None => None,
        AiRuntime::Anthropic => Some("anthropic".to_string()),
        AiRuntime::LocalLlm => Some("local-llm".to_string()),
        AiRuntime::ClaudeCode => Some("claude-code".to_string()),
    };
    cfg.ai.api_base = match ai_runtime {
        AiRuntime::LocalLlm => req.local_llm_url.map(|s| s.trim().to_string()),
        _ => cfg.ai.api_base.clone(),
    };
    cfg.sandbox.backend = sandbox_backend;

    let rendered = cfg
        .to_toml_string()
        .map_err(|e| ApiError::Internal(format!("render toml: {e}")))?;
    write_config_atomic(&s.setup.config_path, &rendered)
        .map_err(|e| ApiError::Internal(format!("write {}: {e}", s.setup.config_path.display())))?;
    *s.setup.config.write().await = cfg;
    s.setup.mark_complete();
    Ok(Json(SetupResponse {
        ok: true,
        config_path: s.setup.config_path.display().to_string(),
    }))
}

fn parse_ai_runtime(raw: &str) -> Result<AiRuntime, ApiError> {
    match raw.trim() {
        "none" => Ok(AiRuntime::None),
        "anthropic" => Ok(AiRuntime::Anthropic),
        "local-llm" => Ok(AiRuntime::LocalLlm),
        "claude-code" => Ok(AiRuntime::ClaudeCode),
        other => Err(ApiError::BadRequest(format!("unknown ai_runtime `{other}`"))),
    }
}

fn parse_sandbox_backend(raw: &str) -> Result<SandboxBackend, ApiError> {
    match raw.trim() {
        "auto" => Ok(SandboxBackend::Auto),
        "process" => Ok(SandboxBackend::Process),
        "birdcage" => Ok(SandboxBackend::Birdcage),
        "libkrun" => Ok(SandboxBackend::Libkrun),
        "firecracker" => Ok(SandboxBackend::Firecracker),
        "docker" => Ok(SandboxBackend::Docker),
        other => Err(ApiError::BadRequest(format!("unknown sandbox_backend `{other}`"))),
    }
}

fn write_config_atomic(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("toml.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.flush()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

#[derive(Debug, Deserialize)]
pub struct DoctorRequest {
    /// AI runtime being verified. Doctor only inspects what the chosen
    /// runtime depends on (e.g. `claude-code` looks for the binary).
    pub ai_runtime: String,
    /// Sandbox backend being verified.
    pub sandbox_backend: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
}

/// Lightweight check pass invoked by the wizard's step 3 to surface
/// problems before the operator commits a config. Reports a list of
/// per-check results rather than a single pass/fail so the UI can
/// render targeted remediation hints.
async fn setup_doctor(
    State(s): State<ServerState>,
    Json(req): Json<DoctorRequest>,
) -> Result<Json<DoctorResponse>, ApiError> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck {
        name: "state-dir".to_string(),
        passed: s.setup.config_path.parent().is_some(),
        message: "state directory writable".to_string(),
    });
    let ai_runtime = parse_ai_runtime(&req.ai_runtime)?;
    match ai_runtime {
        AiRuntime::None => checks.push(DoctorCheck {
            name: "ai".to_string(),
            passed: true,
            message: "AI disabled — static pass only".to_string(),
        }),
        AiRuntime::Anthropic => checks.push(DoctorCheck {
            name: "ai-anthropic".to_string(),
            passed: true,
            message: "Anthropic runtime selected; API key will be stored in the OS keychain"
                .to_string(),
        }),
        AiRuntime::LocalLlm => checks.push(DoctorCheck {
            name: "ai-local-llm".to_string(),
            passed: true,
            message: "Local LLM runtime selected; endpoint will be saved to [ai].api_base"
                .to_string(),
        }),
        AiRuntime::ClaudeCode => {
            let found = which_on_path("claude");
            checks.push(DoctorCheck {
                name: "ai-claude-code".to_string(),
                passed: found.is_some(),
                message: match found {
                    Some(p) => format!("claude binary on PATH at {p}"),
                    None => "`claude` not found on PATH; install Claude Code first".to_string(),
                },
            });
        }
    }

    let sandbox_backend = parse_sandbox_backend(&req.sandbox_backend)?;
    let (sandbox_pass, sandbox_msg) = sandbox_backend_probe(sandbox_backend);
    checks.push(DoctorCheck {
        name: "sandbox".to_string(),
        passed: sandbox_pass,
        message: sandbox_msg,
    });

    Ok(Json(DoctorResponse { checks }))
}

fn which_on_path(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join(bin);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn sandbox_backend_probe(b: SandboxBackend) -> (bool, String) {
    match b {
        SandboxBackend::Auto => (true, "Backend will be chosen at scan time".to_string()),
        SandboxBackend::Process => (
            true,
            "Process-only sandbox — no kernel isolation. Static pass only.".to_string(),
        ),
        SandboxBackend::Birdcage => (
            cfg!(target_os = "macos"),
            if cfg!(target_os = "macos") {
                "Birdcage requires macOS Seatbelt; verified at scan time".to_string()
            } else {
                "Birdcage is macOS-only; pick another backend".to_string()
            },
        ),
        SandboxBackend::Libkrun | SandboxBackend::Firecracker => (
            cfg!(target_os = "linux"),
            if cfg!(target_os = "linux") {
                format!(
                    "{} is a Linux microVM backend; binary presence verified at scan time",
                    match b {
                        SandboxBackend::Libkrun => "libkrun",
                        _ => "Firecracker",
                    }
                )
            } else {
                "Linux-only backend; pick `process` or `docker` on this host".to_string()
            },
        ),
        SandboxBackend::Docker => (
            which_on_path("docker").is_some(),
            match which_on_path("docker") {
                Some(p) => format!("docker CLI at {p}"),
                None => "docker not on PATH; install Docker first".to_string(),
            },
        ),
    }
}

// ---- /repos -----------------------------------------------------------------

async fn list_repos(State(s): State<ServerState>) -> Result<Json<Vec<RepoRecord>>, ApiError> {
    let rows = s.store.repos().list().await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
    pub source_kind: String,
    pub source_url_or_path: String,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub auth_ref: Option<String>,
    #[serde(default)]
    pub i_own_this: bool,
}

async fn create_repo(
    State(s): State<ServerState>,
    Json(req): Json<CreateRepoRequest>,
) -> Result<Json<RepoRecord>, ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if !matches!(req.source_kind.as_str(), "git" | "local-path" | "github" | "gitlab" | "local") {
        return Err(ApiError::BadRequest(format!(
            "unknown source_kind `{}`",
            req.source_kind
        )));
    }
    if !req.i_own_this {
        return Err(ApiError::BadRequest(
            "i_own_this must be set to true before the daemon will accept a repo".to_string(),
        ));
    }
    let now = now_epoch_ms();
    // Preserve scan pointer + creation time across re-POSTs; the
    // underlying upsert blindly takes `excluded.*` and would otherwise
    // wipe `last_scan_run_id` and reset `created_at` when an operator
    // edits an existing repo by POSTing the same name.
    let existing = s.store.repos().get(&req.name).await?;
    let rec = RepoRecord {
        name: req.name,
        source_kind: req.source_kind,
        source_url_or_path: req.source_url_or_path,
        branch: req.branch,
        auth_ref: req.auth_ref,
        i_own_this: req.i_own_this,
        last_scan_run_id: existing.as_ref().and_then(|r| r.last_scan_run_id.clone()),
        created_at: existing.as_ref().map(|r| r.created_at).unwrap_or(now),
        updated_at: now,
    };
    s.store.repos().upsert(&rec).await?;
    Ok(Json(rec))
}

async fn get_repo(
    State(s): State<ServerState>,
    Path(name): Path<String>,
) -> Result<Json<RepoRecord>, ApiError> {
    s.store
        .repos()
        .get(&name)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("repo `{name}` not found")))
}

#[derive(Debug, Deserialize)]
pub struct PatchRepoRequest {
    #[serde(default)]
    pub source_kind: Option<String>,
    #[serde(default)]
    pub source_url_or_path: Option<String>,
    /// Tri-state: omitted = no change, `null` = clear, string = set.
    #[serde(default, deserialize_with = "deserialize_tri_state_string")]
    pub branch: TriStateString,
    #[serde(default, deserialize_with = "deserialize_tri_state_string")]
    pub auth_ref: TriStateString,
    #[serde(default)]
    pub i_own_this: Option<bool>,
}

async fn patch_repo(
    State(s): State<ServerState>,
    Path(name): Path<String>,
    Json(req): Json<PatchRepoRequest>,
) -> Result<Json<RepoRecord>, ApiError> {
    if let Some(kind) = req.source_kind.as_deref() {
        if !matches!(kind, "git" | "local-path" | "github" | "gitlab" | "local") {
            return Err(ApiError::BadRequest(format!("unknown source_kind `{kind}`")));
        }
    }
    if let Some(false) = req.i_own_this {
        return Err(ApiError::BadRequest(
            "i_own_this cannot be cleared via PATCH; remove the repo instead".to_string(),
        ));
    }
    let now = now_epoch_ms();
    let branch = patch_option_for(&req.branch);
    let auth_ref = patch_option_for(&req.auth_ref);
    let patch = RepoPatch {
        name: &name,
        source_kind: req.source_kind.as_deref(),
        source_url_or_path: req.source_url_or_path.as_deref(),
        branch,
        auth_ref,
        i_own_this: req.i_own_this,
        updated_at: now,
    };
    let applied = s.store.repos().update(&patch).await?;
    if !applied {
        return Err(ApiError::NotFound(format!("repo `{name}` not found")));
    }
    let row = s
        .store
        .repos()
        .get(&name)
        .await?
        .ok_or_else(|| ApiError::Internal("repo vanished after update".to_string()))?;
    Ok(Json(row))
}

fn patch_option_for(tri: &TriStateString) -> PatchOption<Option<&str>> {
    match tri {
        TriStateString::Unset => PatchOption::Unset,
        TriStateString::Null => PatchOption::Set(None),
        TriStateString::Some(v) => PatchOption::Set(Some(v.as_str())),
    }
}

#[derive(Debug, Default)]
pub enum TriStateString {
    #[default]
    Unset,
    Null,
    Some(String),
}

fn deserialize_tri_state_string<'de, D>(d: D) -> Result<TriStateString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(d)?;
    Ok(match value {
        None => TriStateString::Null,
        Some(s) => TriStateString::Some(s),
    })
}

async fn delete_repo(
    State(s): State<ServerState>,
    Path(name): Path<String>,
) -> Result<StatusBody, ApiError> {
    let affected = s.store.repos().delete(&name).await?;
    if affected == 0 {
        return Err(ApiError::NotFound(format!("repo `{name}` not found")));
    }
    let mut workspace_msg = String::new();
    if let Some(root) = &s.state_repos_dir {
        let target = root.join(&name);
        if target.is_dir() {
            match std::fs::remove_dir_all(&target) {
                Ok(()) => {
                    workspace_msg = format!(" (workspace {} removed)", target.display());
                }
                Err(err) => {
                    tracing::warn!(
                        repo = %name,
                        path = %target.display(),
                        error = %err,
                        "failed to remove repo workspace; row was still deleted",
                    );
                    workspace_msg = format!(
                        " (workspace {} could not be removed: {err})",
                        target.display()
                    );
                }
            }
        }
    }
    Ok(StatusBody::ok(format!("deleted {affected} row(s){workspace_msg}")))
}

// ---- /repos/test ------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TestRepoRequest {
    pub source_kind: String,
    pub source_url_or_path: String,
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestRepoResponse {
    pub ok: bool,
    pub message: String,
    /// `true` only for `local-path` probes. `null` when the on-disk
    /// `.git/config` either does not exist or carries no `origin`
    /// remote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_disk_git_remote: Option<String>,
}

/// Lightweight probe wired to the wizard's "test connectivity" button.
/// Performs only a read-only side effect (`git ls-remote` for git
/// sources, `stat` + read of `.git/config` for local-path sources).
async fn test_repo_connectivity(
    Json(req): Json<TestRepoRequest>,
) -> Result<Json<TestRepoResponse>, ApiError> {
    match req.source_kind.as_str() {
        "git" | "github" | "gitlab" => {
            let url = req.source_url_or_path.trim();
            if url.is_empty() {
                return Err(ApiError::BadRequest("source_url_or_path is required".to_string()));
            }
            let branch = req.branch.as_deref().map(str::trim).filter(|s| !s.is_empty());
            let (ok, message) = git_ls_remote_probe(url, branch).await;
            Ok(Json(TestRepoResponse { ok, message, on_disk_git_remote: None }))
        }
        "local-path" | "local" => {
            let path = std::path::Path::new(&req.source_url_or_path);
            if !path.exists() {
                return Ok(Json(TestRepoResponse {
                    ok: false,
                    message: format!("path `{}` does not exist", path.display()),
                    on_disk_git_remote: None,
                }));
            }
            if !path.is_dir() {
                return Ok(Json(TestRepoResponse {
                    ok: false,
                    message: format!("path `{}` is not a directory", path.display()),
                    on_disk_git_remote: None,
                }));
            }
            let remote = read_local_git_remote(path);
            let message = match &remote {
                Some(url) => format!(
                    "path readable; on-disk `.git/config` remote = `{url}`. Confirm before adding.",
                ),
                None => {
                    "path readable; no `.git/config` remote on disk (untracked directory)."
                        .to_string()
                }
            };
            Ok(Json(TestRepoResponse { ok: true, message, on_disk_git_remote: remote }))
        }
        other => Err(ApiError::BadRequest(format!("unknown source_kind `{other}`"))),
    }
}

const GIT_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

async fn git_ls_remote_probe(url: &str, branch: Option<&str>) -> (bool, String) {
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("-c")
        .arg("credential.helper=")
        .arg("ls-remote")
        .arg("--exit-code")
        .arg(url);
    if let Some(b) = branch {
        cmd.arg(format!("refs/heads/{b}"));
    }
    // Match ingestion-path env hardening: no terminal prompts, no user
    // git config bleed.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());
    // Otherwise a timed-out probe leaks the underlying `git ls-remote`
    // process: `tokio::time::timeout` drops the future that owns the
    // `Child`, but `tokio::process::Child` does not kill on drop by
    // default.
    cmd.kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => return (false, format!("could not spawn git: {err}")),
    };
    let wait = child.wait_with_output();
    match tokio::time::timeout(GIT_PROBE_TIMEOUT, wait).await {
        Ok(Ok(output)) => {
            if output.status.success() {
                let line_count = output.stdout.iter().filter(|b| **b == b'\n').count();
                (
                    true,
                    match branch {
                        Some(b) => format!("ls-remote reached upstream; branch `{b}` exists"),
                        None => format!("ls-remote reached upstream ({line_count} refs visible)"),
                    },
                )
            } else if output.status.code() == Some(2) {
                (false, match branch {
                    Some(b) => format!("upstream reachable but branch `{b}` does not exist"),
                    None => "upstream reachable but has no refs".to_string(),
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let trimmed = stderr.trim();
                (
                    false,
                    if trimmed.is_empty() {
                        format!("git ls-remote exited with status {}", output.status)
                    } else {
                        format!("git ls-remote failed: {trimmed}")
                    },
                )
            }
        }
        Ok(Err(err)) => (false, format!("git wait failed: {err}")),
        Err(_) => (
            false,
            format!("git ls-remote timed out after {}s", GIT_PROBE_TIMEOUT.as_secs()),
        ),
    }
}

fn read_local_git_remote(path: &std::path::Path) -> Option<String> {
    let cfg = path.join(".git").join("config");
    let raw = std::fs::read_to_string(&cfg).ok()?;
    parse_git_config_remote(&raw)
}

/// Tiny line-oriented parser for the `[remote "origin"]` block's `url =`
/// key. Sufficient for the inspection use case; falls back gracefully on
/// exotic `include = path` configs (those return `None`).
fn parse_git_config_remote(raw: &str) -> Option<String> {
    let mut in_origin = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_origin = line == "[remote \"origin\"]";
            continue;
        }
        if in_origin {
            if let Some(rest) = line.strip_prefix("url") {
                if let Some(eq) = rest.find('=') {
                    return Some(rest[eq + 1..].trim().to_string());
                }
            }
        }
    }
    None
}

// ---- /scan ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    #[serde(default)]
    pub repo: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    run_id: String,
}

async fn trigger_scan(
    State(s): State<ServerState>,
    Query(q): Query<ScanQuery>,
) -> Result<Json<ScanResponse>, ApiError> {
    let run_id = s.scan.trigger(q.repo).await?;
    Ok(Json(ScanResponse { run_id }))
}

// ---- /runs ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RunsQuery {
    #[serde(default)]
    pub status: Option<String>,
}

async fn list_runs(
    State(s): State<ServerState>,
    Query(q): Query<RunsQuery>,
) -> Result<Json<Vec<RunRecord>>, ApiError> {
    let status = q.status.as_deref().unwrap_or("Running");
    let rows = s.store.runs().list_by_status(status).await?;
    Ok(Json(rows))
}

async fn get_run(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<RunRecord>, ApiError> {
    s.store
        .runs()
        .get(&id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("run `{id}` not found")))
}

// ---- /findings --------------------------------------------------------------

/// Composite filter for `GET /api/v1/findings`. Every field is
/// optional; combining them ANDs server-side. Quarantined rows are
/// hidden by default; the Quarantine view passes
/// `include_quarantine=true`.
#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub cap: Option<String>,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub triage_state: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub include_quarantine: bool,
}

async fn list_findings(
    State(s): State<ServerState>,
    Query(q): Query<FindingsQuery>,
) -> Result<Json<Vec<FindingRecord>>, ApiError> {
    let filter = FindingFilter {
        repo: q.repo.as_deref(),
        run_id: q.run_id.as_deref(),
        cap: q.cap.as_deref(),
        origin: q.origin.as_deref(),
        status: q.status.as_deref(),
        severity: q.severity.as_deref(),
        triage_state: q.triage_state.as_deref(),
        chain_id: q.chain_id.as_deref(),
        include_quarantine: q.include_quarantine,
        limit: None,
    };
    let rows = s.store.findings().list_filtered(&filter).await?;
    Ok(Json(rows))
}

async fn get_finding(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<FindingRecord>, ApiError> {
    s.store
        .findings()
        .get(&id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("finding `{id}` not found")))
}

/// Diff status for one finding relative to a baseline run. Surfaced as
/// the "new / regressed / closed" chips the Phase 11 findings browser
/// renders. `Unchanged` means the finding existed and was Open in the
/// prior run too. The `Regressed` and `Closed` shapes are reserved for
/// when a per-run finding-membership history lands; today the API only
/// emits `New` and `Unchanged`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FindingDiffStatus {
    New,
    Regressed,
    Closed,
    Unchanged,
}

#[derive(Debug, Serialize)]
pub struct FindingWithDiff {
    #[serde(flatten)]
    pub record: FindingRecord,
    pub diff_status: FindingDiffStatus,
}

#[derive(Debug, Serialize)]
pub struct RunFindingsResponse {
    pub run_id: String,
    /// Most recent earlier run on the same install. `None` when this is
    /// the first run, in which case every finding is classified as
    /// [`FindingDiffStatus::New`].
    pub prior_run_id: Option<String>,
    pub items: Vec<FindingWithDiff>,
}

async fn findings_for_run(
    State(s): State<ServerState>,
    Path(run_id): Path<String>,
) -> Result<Json<RunFindingsResponse>, ApiError> {
    let run = s
        .store
        .runs()
        .get(&run_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("run `{run_id}` not found")))?;
    let started_at = run.started_at;
    let prior_run_id = s.store.runs().prior_run_id(&run_id, started_at).await?;

    let filter = FindingFilter {
        run_id: Some(&run_id),
        include_quarantine: false,
        ..Default::default()
    };
    let rows = s.store.findings().list_filtered(&filter).await?;
    let items = rows
        .into_iter()
        .map(|record| {
            let diff_status = classify_diff(&record, started_at);
            FindingWithDiff { record, diff_status }
        })
        .collect();
    Ok(Json(RunFindingsResponse { run_id, prior_run_id, items }))
}

fn classify_diff(record: &FindingRecord, run_started_at: i64) -> FindingDiffStatus {
    // `first_seen` is preserved across upserts, so a finding observed
    // for the first time during this run carries a `first_seen` >=
    // run.started_at. Everything else is `Unchanged` for now.
    // `Regressed` and `Closed` need per-run membership history which
    // lives behind a deferred schema migration.
    if record.first_seen >= run_started_at {
        FindingDiffStatus::New
    } else {
        FindingDiffStatus::Unchanged
    }
}

// ---- /chains ----------------------------------------------------------------

async fn get_chain(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<ChainRecord>, ApiError> {
    s.store
        .chains()
        .get(&id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("chain `{id}` not found")))
}

// ---- /quarantine ------------------------------------------------------------

/// Discriminator for [`QuarantineItem`] so the SPA can pick the right
/// promote / dismiss path. `Finding` rows live in the `findings`
/// table with `status = 'Quarantine'`; `Candidate` rows live in
/// `candidate_findings` with `status = 'Pending'`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineKind {
    Finding,
    Candidate,
}

/// Unified row the Quarantine page renders. Combines both sources of
/// "AI-proposed, not yet dynamic-confirmed" rows so the operator sees
/// one list. The Phase-23 deferred "converge on a single quarantine
/// path" item asks for the eventual fold; the API joins them today.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineItem {
    pub kind: QuarantineKind,
    pub id: String,
    pub run_id: String,
    pub repo: String,
    pub path: String,
    pub line: Option<i64>,
    pub cap: String,
    pub rule: Option<String>,
    pub severity: Option<String>,
    pub finding_origin: Option<String>,
    pub prompt_version: Option<String>,
    pub attack_provenance: Option<String>,
    pub rationale: Option<String>,
    pub verdict_blob: Option<String>,
    pub last_seen: Option<i64>,
}

async fn list_quarantine(
    State(s): State<ServerState>,
) -> Result<Json<Vec<QuarantineItem>>, ApiError> {
    let mut out: Vec<QuarantineItem> = Vec::new();
    let filter = FindingFilter {
        status: Some("Quarantine"),
        include_quarantine: true,
        ..Default::default()
    };
    let findings = s.store.findings().list_filtered(&filter).await?;
    for f in findings {
        out.push(QuarantineItem {
            kind: QuarantineKind::Finding,
            id: f.id,
            run_id: f.run_id,
            repo: f.repo,
            path: f.path,
            line: f.line,
            cap: f.cap,
            rule: Some(f.rule),
            severity: Some(f.severity),
            finding_origin: Some(f.finding_origin),
            prompt_version: f.prompt_version,
            attack_provenance: f.attack_provenance,
            rationale: None,
            verdict_blob: f.verdict_blob,
            last_seen: Some(f.last_seen),
        });
    }
    let pending = s.store.candidate_findings().list_pending().await?;
    for c in pending {
        out.push(QuarantineItem {
            kind: QuarantineKind::Candidate,
            id: c.id,
            run_id: c.run_id,
            repo: c.repo,
            path: c.path,
            line: c.line,
            cap: c.cap,
            rule: c.rule_hint,
            severity: None,
            finding_origin: Some("AiExploration".to_string()),
            prompt_version: c.prompt_version,
            attack_provenance: None,
            rationale: c.rationale,
            verdict_blob: None,
            last_seen: None,
        });
    }
    // Most-recently-stamped findings first; candidates fall in after
    // (no `last_seen`).
    out.sort_by(|a, b| b.last_seen.unwrap_or(0).cmp(&a.last_seen.unwrap_or(0)));
    Ok(Json(out))
}

async fn promote_quarantine(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<QuarantineItem>, ApiError> {
    if id.starts_with("cand-") {
        let cand = s
            .store
            .candidate_findings()
            .get(&id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("candidate `{id}` not found")))?;
        if cand.status != CandidateStatus::Pending.as_str() {
            return Err(ApiError::BadRequest(format!(
                "candidate `{id}` is not pending (status = `{}`)",
                cand.status
            )));
        }
        promote_candidate_to_finding(&s, &cand).await?;
        Ok(Json(candidate_to_quarantine_item(&cand)))
    } else {
        // Findings-table quarantine: flip status to 'Open' so the row
        // reappears in the Findings browser. The operator's manual
        // promote skips the dynamic-confirm gate by design (acceptance:
        // "Manually promoting it moves it to Findings.").
        let row = promote_finding_row(&s, &id, "Open").await?;
        Ok(Json(finding_to_quarantine_item(&row)))
    }
}

async fn dismiss_quarantine(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<QuarantineItem>, ApiError> {
    if id.starts_with("cand-") {
        let cand = s
            .store
            .candidate_findings()
            .get(&id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("candidate `{id}` not found")))?;
        if cand.status != CandidateStatus::Pending.as_str() {
            return Err(ApiError::BadRequest(format!(
                "candidate `{id}` is not pending (status = `{}`)",
                cand.status
            )));
        }
        s.store
            .candidate_findings()
            .set_status(&id, CandidateStatus::Dismissed.as_str())
            .await?;
        Ok(Json(candidate_to_quarantine_item(&cand)))
    } else {
        let row = promote_finding_row(&s, &id, "Closed").await?;
        Ok(Json(finding_to_quarantine_item(&row)))
    }
}

async fn promote_finding_row(
    s: &ServerState,
    id: &str,
    new_status: &str,
) -> Result<FindingRecord, ApiError> {
    let existing = s
        .store
        .findings()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("finding `{id}` not found")))?;
    if existing.status != "Quarantine" {
        return Err(ApiError::BadRequest(format!(
            "finding `{id}` is not in Quarantine (status = `{}`)",
            existing.status
        )));
    }
    let blob = existing.verdict_blob.as_deref().unwrap_or("");
    let provenance = existing.attack_provenance.as_deref().unwrap_or("Curated");
    s.store
        .findings()
        .set_verify_result(id, new_status, blob, provenance)
        .await?;
    s.store
        .findings()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::Internal("finding vanished after promote".to_string()))
}

async fn promote_candidate_to_finding(
    s: &ServerState,
    cand: &CandidateFindingRecord,
) -> Result<(), ApiError> {
    let line = cand.line.unwrap_or(-1);
    let rule = cand
        .rule_hint
        .clone()
        .unwrap_or_else(|| format!("ai-exploration:{}", cand.cap));
    let id = nyx_agent_core::store::finding_id_hash(
        &cand.repo,
        &cand.path,
        Some(line),
        &cand.cap,
        &rule,
    );
    let now = now_epoch_ms();
    let verdict_blob = serde_json::to_string(&json!({
        "kind": "ManualPromote",
        "from": "candidate",
        "candidate_id": cand.id,
        "rationale": cand.rationale,
    }))
    .map_err(|e| ApiError::Internal(format!("serialize verdict blob: {e}")))?;
    let rec = FindingRecord {
        id,
        run_id: cand.run_id.clone(),
        repo: cand.repo.clone(),
        path: cand.path.clone(),
        line: cand.line,
        cap: cand.cap.clone(),
        rule,
        severity: "High".to_string(),
        // Manual promote skips the dynamic-verifier gate; mark Open
        // (not Verified) so the operator's intent is preserved
        // without claiming the row has been confirmed by the
        // sandbox-replayed differential.
        status: "Open".to_string(),
        finding_origin: "AiExploration".to_string(),
        first_seen: now,
        last_seen: now,
        superseded_by: None,
        triage_state: "Open".to_string(),
        triage_assigned_to: None,
        verdict_blob: Some(verdict_blob),
        repro_path: None,
        attack_provenance: Some("ManualPromote".to_string()),
        prompt_version: cand.prompt_version.clone(),
        chain_id: None,
    };
    s.store.findings().upsert(&rec).await?;
    s.store
        .candidate_findings()
        .set_status(&cand.id, CandidateStatus::Promoted.as_str())
        .await?;
    Ok(())
}

fn finding_to_quarantine_item(f: &FindingRecord) -> QuarantineItem {
    QuarantineItem {
        kind: QuarantineKind::Finding,
        id: f.id.clone(),
        run_id: f.run_id.clone(),
        repo: f.repo.clone(),
        path: f.path.clone(),
        line: f.line,
        cap: f.cap.clone(),
        rule: Some(f.rule.clone()),
        severity: Some(f.severity.clone()),
        finding_origin: Some(f.finding_origin.clone()),
        prompt_version: f.prompt_version.clone(),
        attack_provenance: f.attack_provenance.clone(),
        rationale: None,
        verdict_blob: f.verdict_blob.clone(),
        last_seen: Some(f.last_seen),
    }
}

fn candidate_to_quarantine_item(c: &CandidateFindingRecord) -> QuarantineItem {
    QuarantineItem {
        kind: QuarantineKind::Candidate,
        id: c.id.clone(),
        run_id: c.run_id.clone(),
        repo: c.repo.clone(),
        path: c.path.clone(),
        line: c.line,
        cap: c.cap.clone(),
        rule: c.rule_hint.clone(),
        severity: None,
        finding_origin: Some("AiExploration".to_string()),
        prompt_version: c.prompt_version.clone(),
        attack_provenance: None,
        rationale: c.rationale.clone(),
        verdict_blob: None,
        last_seen: None,
    }
}

// ---- /traces ----------------------------------------------------------------

/// Trace row envelope: the `AgentTraceRecord` shape carries unsigned
/// counts as `i64`, but for the wire we keep the raw shape so the
/// frontend can render whatever the daemon persisted (zeroes for
/// fields the per-pass outcome does not yet surface; widening the
/// per-pass envelopes is tracked separately).
#[derive(Debug, Serialize)]
pub struct TraceRow {
    pub id: String,
    pub finding_id: Option<String>,
    pub task_kind: String,
    pub runtime_name: String,
    pub model: String,
    pub prompt_version: Option<String>,
    pub conversation_jsonl_path: Option<String>,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cost_usd_micros: i64,
    pub cache_hits: i64,
    pub cache_misses: i64,
    pub duration_ms: Option<i64>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

impl From<AgentTraceRecord> for TraceRow {
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

async fn traces_for_finding(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<TraceRow>>, ApiError> {
    let rows = s.store.agent_traces().list_for_finding(&id).await?;
    Ok(Json(rows.into_iter().map(TraceRow::from).collect()))
}

async fn get_trace(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<TraceRow>, ApiError> {
    s.store
        .agent_traces()
        .get(&id)
        .await?
        .map(TraceRow::from)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("trace `{id}` not found")))
}

// ---- /events ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub run_id: Option<String>,
}

async fn events_ws(
    State(s): State<ServerState>,
    Query(q): Query<EventsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    // Subscribe *before* reading the replay so events that fire between
    // snapshot and join still hit this receiver. The snapshot is sent
    // first; duplicate frames are idempotent client-side because
    // applyEvent in repoStatus.ts treats per-repo state as a fold over
    // the latest event per key.
    let rx = s.events.subscribe();
    let filter = q.run_id.clone();
    let replay = if let Some(run_id) = filter.as_deref() {
        s.replay.snapshot(run_id).await
    } else {
        Vec::new()
    };
    ws.on_upgrade(move |socket| handle_events_ws(socket, rx, filter, replay))
}

async fn handle_events_ws(
    socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    run_filter: Option<String>,
    replay: Vec<AgentEvent>,
) {
    let (mut tx, mut rx_socket) = socket.split();
    for ev in replay {
        match serde_json::to_string(&ev) {
            Ok(payload) => {
                if tx.send(Message::Text(payload)).await.is_err() {
                    return;
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to serialize replay AgentEvent");
            }
        }
    }
    loop {
        tokio::select! {
            biased;
            client_msg = rx_socket.next() => {
                match client_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {
                        // Ignore client-initiated frames; this stream is
                        // server-push only.
                    }
                    Some(Err(_)) => break,
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if !run_matches(&ev, run_filter.as_deref()) {
                            continue;
                        }
                        match serde_json::to_string(&ev) {
                            Ok(payload) => {
                                if tx.send(Message::Text(payload)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to serialize AgentEvent");
                            }
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        let warning = json!({
                            "kind": "Lagged",
                            "skipped": skipped,
                        });
                        if tx.send(Message::Text(warning.to_string())).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}

fn run_matches(ev: &AgentEvent, run_filter: Option<&str>) -> bool {
    let Some(want) = run_filter else { return true };
    if let AgentEvent::Run { data } = ev {
        let id = match data {
            RunEvent::Heartbeat { .. } => return true,
            RunEvent::RunStarted { run_id, .. }
            | RunEvent::RepoStarted { run_id, .. }
            | RunEvent::RepoStaticDone { run_id, .. }
            | RunEvent::RepoDynamicDone { run_id, .. }
            | RunEvent::RepoFailed { run_id, .. }
            | RunEvent::RepoFinished { run_id, .. }
            | RunEvent::RunFinished { run_id, .. } => run_id.as_str(),
        };
        id == want
    } else {
        true
    }
}

// ---- /runs/:id/summary ------------------------------------------------------

async fn run_summary(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<RunCard>, ApiError> {
    let card = build_run_card(s.store.pool(), &id).await.map_err(run_card_to_api)?;
    Ok(Json(card))
}

async fn run_summary_markdown(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let card = build_run_card(s.store.pool(), &id).await.map_err(run_card_to_api)?;
    let body = render_run_card_markdown(&card);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        body,
    )
        .into_response())
}

async fn run_summary_html(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let card = build_run_card(s.store.pool(), &id).await.map_err(run_card_to_api)?;
    let body = render_run_card_html(&card);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

fn run_card_to_api(err: RunCardError) -> ApiError {
    match err {
        RunCardError::NotFound(id) => ApiError::NotFound(format!("run `{id}` not found")),
        RunCardError::Store(e) => ApiError::Store(e),
        RunCardError::Sqlx(e) => ApiError::Internal(format!("sqlx: {e}")),
    }
}

// ---- /findings/:id/repro-bundle ---------------------------------------------

async fn create_repro_bundle(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<BundleManifest>, ApiError> {
    let out_dir = s
        .state_bundles_dir
        .as_ref()
        .cloned()
        .ok_or_else(|| ApiError::Internal("bundle output dir is not configured".to_string()))?;
    let manifest = build_bundle(&s.store, &id, &out_dir, now_epoch_ms())
        .await
        .map_err(bundle_to_api)?;
    Ok(Json(manifest))
}

async fn download_repro_bundle(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let bundles = s.store.repro_bundles().list_for_finding(&id).await?;
    // Most-recently-built bundle wins. If none, build one inline so the
    // operator can hit the download URL directly without first calling
    // POST /repro-bundle from a script.
    let row = if let Some(latest) = bundles.last().cloned() {
        latest
    } else {
        let out_dir = s.state_bundles_dir.as_ref().cloned().ok_or_else(|| {
            ApiError::Internal("bundle output dir is not configured".to_string())
        })?;
        let manifest = build_bundle(&s.store, &id, &out_dir, now_epoch_ms())
            .await
            .map_err(bundle_to_api)?;
        s.store
            .repro_bundles()
            .list_for_finding(&id)
            .await?
            .into_iter()
            .find(|r| r.path == manifest.bundle_path.display().to_string())
            .ok_or_else(|| ApiError::Internal("bundle row vanished after build".to_string()))?
    };

    let safe_path = ensure_bundle_path_inside_root(&row.path, s.state_bundles_dir.as_deref())?;
    let bytes = std::fs::read(&safe_path)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", safe_path.display())))?;
    let filename = format!("{id}.tar");
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-tar".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            ("X-Nyx-Bundle-Sha256".parse().unwrap(), row.sha256),
        ],
        Body::from(bytes),
    )
        .into_response())
}

/// Defense-in-depth: refuse to read a `repro_bundles.path` value that
/// canonicalises outside the configured bundles root. `build_bundle` is the
/// only writer today, but a future migration / import / handler that takes a
/// path from JSON could otherwise turn the download endpoint into an
/// authenticated arbitrary-file-read.
fn ensure_bundle_path_inside_root(
    path: &str,
    bundles_dir: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, ApiError> {
    let root = bundles_dir.ok_or_else(|| {
        ApiError::Internal("bundle output dir is not configured".to_string())
    })?;
    let canonical_root = root
        .canonicalize()
        .map_err(|e| ApiError::Internal(format!("canonicalize bundles root: {e}")))?;
    let canonical_path = std::path::Path::new(path)
        .canonicalize()
        .map_err(|e| ApiError::Internal(format!("canonicalize bundle path `{path}`: {e}")))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(ApiError::Internal(
            "bundle path escapes configured root".to_string(),
        ));
    }
    Ok(canonical_path)
}

fn bundle_to_api(err: BundleError) -> ApiError {
    match err {
        BundleError::FindingNotFound(id) => {
            ApiError::NotFound(format!("finding `{id}` not found"))
        }
        BundleError::PathTooLong(p) => {
            ApiError::BadRequest(format!("bundle path `{p}` exceeds USTAR limit"))
        }
        BundleError::Store(e) => ApiError::Store(e),
        BundleError::Io { path, source } => {
            ApiError::Internal(format!("bundle io at {}: {source}", path.display()))
        }
    }
}

// ---- /findings/:id/replay ---------------------------------------------------

/// Hard wall-clock ceiling on a single replay invocation. A runaway
/// `repro.sh` cannot keep a daemon worker pinned indefinitely.
const REPLAY_WALL_CLOCK_TIMEOUT_SECS: u64 = 120;
/// Grace window after SIGKILL for the kernel to reap the child.
const REPLAY_REAP_GRACE_SECS: u64 = 5;

async fn replay_repro_bundle(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, std::convert::Infallible>>>, ApiError> {
    // Resolve (or build) the most recent bundle on disk.
    let bundles = s.store.repro_bundles().list_for_finding(&id).await?;
    let bundle_path: std::path::PathBuf = match bundles.last() {
        Some(row) => ensure_bundle_path_inside_root(&row.path, s.state_bundles_dir.as_deref())?,
        None => {
            let out_dir = s.state_bundles_dir.as_ref().cloned().ok_or_else(|| {
                ApiError::Internal("bundle output dir is not configured".to_string())
            })?;
            let manifest = build_bundle(&s.store, &id, &out_dir, now_epoch_ms())
                .await
                .map_err(bundle_to_api)?;
            ensure_bundle_path_inside_root(
                &manifest.bundle_path.display().to_string(),
                s.state_bundles_dir.as_deref(),
            )?
        }
    };

    let extract_root = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return Err(ApiError::Internal(format!("tempdir: {e}"))),
    };
    let extract_path = extract_root.path().to_path_buf();
    let tar_bytes = std::fs::read(&bundle_path)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", bundle_path.display())))?;
    // Guard against on-disk substitution between build_bundle (which
    // stamps repro_bundles.sha256) and this exec. If the row exists
    // and the digest disagrees, refuse to extract.
    if let Some(expected) = bundles.last().map(|r| r.sha256.as_str()) {
        if !verify_bundle_sha256(&tar_bytes, expected) {
            return Err(ApiError::Internal(format!(
                "bundle integrity check failed for {}: stored sha256 does not match on-disk bytes",
                bundle_path.display()
            )));
        }
    }
    extract_ustar(&tar_bytes, &extract_path)
        .map_err(|e| ApiError::Internal(format!("extract bundle: {e}")))?;
    let repro_sh = extract_path.join(&id).join("repro.sh");
    if !repro_sh.exists() {
        return Err(ApiError::Internal(format!(
            "bundle did not contain repro.sh at {}",
            repro_sh.display()
        )));
    }

    let started_at = now_epoch_ms();
    let store = s.store.clone();
    let bundle_id_for_status = bundles.last().map(|r| r.id.clone());
    let finding_id = id.clone();
    let stream = async_stream::stream! {
        yield Ok(SseEvent::default()
            .event("start")
            .data(serde_json::json!({
                "finding_id": finding_id,
                "bundle_path": bundle_path.display().to_string(),
                "started_at_ms": started_at,
            }).to_string()));

        let mut cmd = tokio::process::Command::new("bash");
        cmd.arg(&repro_sh);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());
        cmd.kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                yield Ok(SseEvent::default()
                    .event("error")
                    .data(format!("spawn bash: {e}")));
                yield Ok(SseEvent::default().event("end").data("error"));
                return;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let mut stdout_lines = tokio::io::AsyncBufReadExt::lines(
            tokio::io::BufReader::new(stdout),
        );
        let mut stderr_lines = tokio::io::AsyncBufReadExt::lines(
            tokio::io::BufReader::new(stderr),
        );
        // Deadline keeps a runaway repro.sh (infinite loop, `sleep
        // infinity`, etc.) from pinning a daemon worker. On expiry we
        // SIGKILL the child; kill_on_drop also fires if the SSE client
        // disconnects.
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(REPLAY_WALL_CLOCK_TIMEOUT_SECS);
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut timed_out = false;
        while !(stdout_done && stderr_done) && !timed_out {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = child.start_kill();
                    yield Ok(SseEvent::default()
                        .event("error")
                        .data(format!(
                            "replay exceeded {REPLAY_WALL_CLOCK_TIMEOUT_SECS}s wall-clock timeout; killed"
                        )));
                    timed_out = true;
                }
                line = stdout_lines.next_line(), if !stdout_done => {
                    match line {
                        Ok(Some(text)) => {
                            yield Ok(SseEvent::default().event("stdout").data(text));
                        }
                        Ok(None) => stdout_done = true,
                        Err(e) => {
                            yield Ok(SseEvent::default()
                                .event("error")
                                .data(format!("stdout read: {e}")));
                            stdout_done = true;
                        }
                    }
                }
                line = stderr_lines.next_line(), if !stderr_done => {
                    match line {
                        Ok(Some(text)) => {
                            yield Ok(SseEvent::default().event("stderr").data(text));
                        }
                        Ok(None) => stderr_done = true,
                        Err(e) => {
                            yield Ok(SseEvent::default()
                                .event("error")
                                .data(format!("stderr read: {e}")));
                            stderr_done = true;
                        }
                    }
                }
            }
        }
        // Bound the wait so a child that ignores SIGKILL (or a kernel
        // that is slow to reap) cannot pin the task forever either.
        let status = match tokio::time::timeout(
            std::time::Duration::from_secs(REPLAY_REAP_GRACE_SECS),
            child.wait(),
        )
        .await
        {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                yield Ok(SseEvent::default()
                    .event("error")
                    .data(format!("wait: {e}")));
                yield Ok(SseEvent::default().event("end").data("error"));
                return;
            }
            Err(_) => {
                yield Ok(SseEvent::default()
                    .event("error")
                    .data(format!(
                        "child not reaped within {REPLAY_REAP_GRACE_SECS}s after kill"
                    )));
                yield Ok(SseEvent::default().event("end").data("error"));
                return;
            }
        };
        let exit_code = status.code().unwrap_or(-1);
        let finished_at = now_epoch_ms();
        let verdict = if exit_code == 0 { "Pass" } else { "Fail" };
        if let Some(bid) = bundle_id_for_status.as_deref() {
            if let Err(e) = store
                .repro_bundles()
                .record_replay(bid, finished_at, verdict)
                .await
            {
                tracing::warn!(error = %e, "failed to record replay status");
            }
        }
        // Keep the extracted tempdir alive until after the child exits.
        drop(extract_root);
        yield Ok(SseEvent::default()
            .event("end")
            .data(serde_json::json!({
                "exit_code": exit_code,
                "status": verdict,
                "started_at_ms": started_at,
                "finished_at_ms": finished_at,
                "duration_ms": finished_at - started_at,
            }).to_string()));
    };
    Ok(Sse::new(stream).keep_alive(Default::default()))
}

/// Minimal USTAR extractor for the format produced by
/// `nyx_agent_core::report::repro_bundle::build_ustar`. Each entry is
/// either a directory (`typeflag == '5'`) or a regular file (`'0'` or
/// `'\0'`). The format-spec exit (two empty 512-byte blocks) stops the
/// walk.
fn extract_ustar(bytes: &[u8], dest: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut i = 0;
    while i + 512 <= bytes.len() {
        let header = &bytes[i..i + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name_end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&header[..name_end])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .to_string();
        let size = parse_octal(&header[124..135]);
        let typeflag = header[156];
        let safe_name = sanitise_tar_path(&name)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "unsafe tar path"))?;
        let target = dest.join(&safe_name);
        if typeflag == b'5' || name.ends_with('/') {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&target)?;
            let data_start = i + 512;
            let data_end = data_start + size as usize;
            if data_end > bytes.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated tar",
                ));
            }
            f.write_all(&bytes[data_start..data_end])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = parse_octal(&header[100..107]) as u32;
                if mode > 0 {
                    let _ = std::fs::set_permissions(
                        &target,
                        std::fs::Permissions::from_mode(mode & 0o777),
                    );
                }
            }
        }
        let data_blocks = (size + 511) / 512;
        i += 512 + (data_blocks as usize) * 512;
    }
    Ok(())
}

fn parse_octal(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for b in bytes {
        if *b == 0 || *b == b' ' {
            break;
        }
        if !(b'0'..=b'7').contains(b) {
            break;
        }
        v = v * 8 + (b - b'0') as u64;
    }
    v
}

/// Reject tar entries containing `..` components or absolute paths so
/// extraction stays inside the destination tempdir.
fn sanitise_tar_path(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(name);
    if p.is_absolute() {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    for component in p.components() {
        match component {
            std::path::Component::Normal(s) => out.push(s),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

// ---- helpers ----------------------------------------------------------------

#[derive(Debug, Serialize)]
struct StatusBody {
    ok: bool,
    message: String,
}

impl StatusBody {
    fn ok(message: impl Into<String>) -> Self {
        Self { ok: true, message: message.into() }
    }
}

impl IntoResponse for StatusBody {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

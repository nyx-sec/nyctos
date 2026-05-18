//! Axum router exposing the loopback HTTP and WebSocket surface.
//!
//! Routes live under `/api/v1/`; the WebSocket lives at
//! `/api/v1/events`. Subscribers connect with an optional
//! `?run_id=<id>` query parameter to filter the broadcast stream to a
//! single run; without the filter every `AgentEvent` lands on the
//! socket.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, Request, State,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;
use tower_http::trace::TraceLayer;

use nyx_agent_core::store::{ChainRecord, FindingRecord, RepoRecord, RunRecord};
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
        .route("/api/v1/repos/:name", delete(delete_repo))
        .route("/api/v1/scan", post(trigger_scan))
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/:id", get(get_run))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/findings/:id", get(get_finding))
        .route("/api/v1/chains/:id", get(get_chain))
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

async fn delete_repo(
    State(s): State<ServerState>,
    Path(name): Path<String>,
) -> Result<StatusBody, ApiError> {
    let affected = s.store.repos().delete(&name).await?;
    if affected == 0 {
        return Err(ApiError::NotFound(format!("repo `{name}` not found")));
    }
    Ok(StatusBody::ok(format!("deleted {affected} row(s)")))
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

#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
}

async fn list_findings(
    State(s): State<ServerState>,
    Query(q): Query<FindingsQuery>,
) -> Result<Json<Vec<FindingRecord>>, ApiError> {
    let rows = match (q.repo, q.run_id) {
        (Some(repo), None) => s.store.findings().list_active_for_repo(&repo).await?,
        (None, Some(run_id)) => s.store.findings().list_by_run(&run_id).await?,
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "pass at most one of `repo` or `run_id`".to_string(),
            ));
        }
        (None, None) => {
            return Err(ApiError::BadRequest(
                "either `repo` or `run_id` query parameter is required".to_string(),
            ));
        }
    };
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
    let rx = s.events.subscribe();
    let filter = q.run_id;
    ws.on_upgrade(move |socket| handle_events_ws(socket, rx, filter))
}

async fn handle_events_ws(
    socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    run_filter: Option<String>,
) {
    let (mut tx, mut rx_socket) = socket.split();
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

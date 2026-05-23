//! Axum router exposing the loopback HTTP and WebSocket surface.
//!
//! Routes live under `/api/v1/`; the WebSocket lives at
//! `/api/v1/events`. Subscribers connect with an optional
//! `?run_id=<id>` query parameter to filter the broadcast stream to a
//! single run; without the filter every `AgentEvent` lands on the
//! socket.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use axum::{
    body::{Body, Bytes},
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
use tokio::io::AsyncReadExt;
use tokio::sync::broadcast::error::RecvError;
use tower_http::trace::TraceLayer;

use nyctos_core::report::{
    build_bundle, build_run_card, render_html as render_run_card_html,
    render_markdown as render_run_card_markdown, verify_sha256 as verify_bundle_sha256,
    BundleError, BundleManifest, RunCard, RunCardError,
};
use nyctos_core::store::{
    CandidateFindingRecord, CandidateStatus, ChainRecord, FindingFilter, FindingRecord,
    ProjectPatch, ProjectPatchOption, ProjectRecord, RepoRecord, RunRecord,
};
use nyctos_core::{
    now_epoch_ms, parse_git_auth, run_event_log_path, safe_run_log_segment, AiRuntime, IngestError,
    SandboxBackend, ACCOUNT_AI_ANTHROPIC, ACCOUNT_AI_LOCAL_LLM,
};
use nyctos_types::api::{
    AgentTraceRow, DoctorCheck, DoctorRequest, DoctorResponse, FindingDiffStatus, FindingWithDiff,
    HealthResponse, QuarantineItem, QuarantineKind, RunFindingsResponse, SetupRequest,
    SetupStatusResponse,
};
use nyctos_types::event::{AgentEvent, AiEvent, ReproEvent, RunEvent, SandboxEvent};
use nyctos_types::product::{
    ProjectLaunchProfileInput, StartPentestResponse, TestLaunchTargetRequest,
    TestLaunchTargetResponse,
};
use nyctos_types::project::{
    CreateProjectRequest, PatchProjectRequest, ProjectRuntimeProfile, TriStateJson,
    TriStateProjectRuntimeProfile,
};
use nyctos_types::repo::{CreateRepoRequest, PatchRepoRequest, TestRepoRequest, TestRepoResponse};

use crate::state::{ApiError, ScanTriggerSource, ServerState};

/// Build the production router with every `/api/v1/...` route attached.
pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup", post(submit_setup))
        .route("/api/v1/setup/doctor", post(setup_doctor))
        .route("/api/v1/launch-target/test", post(test_launch_target))
        .route("/api/v1/projects", get(list_projects).post(create_project))
        .route(
            "/api/v1/projects/{project_id}",
            get(get_project).patch(patch_project).delete(delete_project),
        )
        .route(
            "/api/v1/projects/{project_id}/repos",
            get(list_project_repos).post(create_project_repo),
        )
        .route("/api/v1/projects/{project_id}/repos/test", post(test_repo_connectivity))
        .route(
            "/api/v1/projects/{project_id}/repos/{name}",
            get(get_project_repo).patch(patch_project_repo).delete(delete_project_repo),
        )
        .route("/api/v1/projects/{project_id}/scan", post(scan_project))
        .route("/api/v1/projects/{project_id}/pentest", post(start_pentest_project))
        .route(
            "/api/v1/projects/{project_id}/launch-profile/default",
            get(get_default_launch_profile).patch(patch_default_launch_profile),
        )
        .route("/api/v1/projects/{project_id}/vulnerabilities", get(project_vulnerabilities))
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/{id}", get(get_run))
        .route("/api/v1/runs/{id}/findings", get(findings_for_run))
        .route("/api/v1/runs/{id}/signals", get(signals_for_run))
        .route("/api/v1/runs/{id}/route-model", get(route_model_for_run))
        .route("/api/v1/runs/{id}/environment-runs", get(environment_runs_for_run))
        .route("/api/v1/runs/{id}/events.jsonl", get(run_event_log))
        .route("/api/v1/runs/{id}/verification-attempts", get(verification_attempts_for_run))
        .route("/api/v1/runs/{id}/vulnerabilities", get(run_vulnerabilities))
        .route("/api/v1/runs/{id}/summary", get(run_summary))
        .route("/api/v1/runs/{id}/summary.md", get(run_summary_markdown))
        .route("/api/v1/runs/{id}/summary.html", get(run_summary_html))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/vulnerabilities", get(list_vulnerabilities))
        .route("/api/v1/findings/{id}", get(get_finding))
        .route("/api/v1/findings/{id}/repro-bundle", post(create_repro_bundle))
        .route("/api/v1/findings/{id}/repro-bundle.tar", get(download_repro_bundle))
        .route("/api/v1/findings/{id}/replay", post(replay_repro_bundle))
        .route("/api/v1/chains", get(list_chains))
        .route("/api/v1/chains/{id}", get(get_chain))
        .route("/api/v1/findings/{id}/traces", get(traces_for_finding))
        .route("/api/v1/traces/{id}", get(get_trace))
        .route("/api/v1/quarantine", get(list_quarantine))
        .route("/api/v1/quarantine/{id}/promote", post(promote_quarantine))
        .route("/api/v1/quarantine/{id}/dismiss", post(dismiss_quarantine))
        .route("/api/v1/events", get(events_ws))
        .route("/webhook/git", post(crate::webhook::webhook_git))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Bearer-token gate. Skipped entirely when [`AuthConfig::token`] is
/// unset (the `--headless` path), and skipped on a per-route basis for
/// `/health` plus the read-only setup status endpoint. The mutating
/// wizard endpoints stay open only while setup is still pending. Once
/// `nyctos.toml` exists, setup writes require the bearer token like
/// every other mutation endpoint so an attacker cannot overwrite the
/// operator's config.
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
    if is_setup_status_path(path) {
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
    // `/webhook/git` carries its own HMAC auth so bypass the bearer
    // gate; the handler refuses on bad signature.
    path == "/api/v1/health" || path == "/webhook/git"
}

fn is_setup_path(path: &str) -> bool {
    matches!(path, "/api/v1/setup" | "/api/v1/setup/status" | "/api/v1/setup/doctor")
}

fn is_setup_status_path(path: &str) -> bool {
    path == "/api/v1/setup/status"
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

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn test_launch_target(
    Json(req): Json<TestLaunchTargetRequest>,
) -> Result<Json<TestLaunchTargetResponse>, ApiError> {
    let raw = req.url.trim();
    let url = local_http_url(raw).ok_or_else(|| {
        ApiError::BadRequest(
            "app URL must be local http:// or https:// (localhost, 127.0.0.1, or ::1)".to_string(),
        )
    })?;
    let timeout = Duration::from_secs(req.timeout_seconds.unwrap_or(3).clamp(1, 15));
    let started = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| ApiError::Internal(format!("build URL test client: {e}")))?;

    let response = match client.get(url.clone()).send().await {
        Ok(resp) => {
            let status = resp.status();
            let ok = status.is_success();
            TestLaunchTargetResponse {
                ok,
                url: url.to_string(),
                message: if ok {
                    format!("Reachable in {}ms", started.elapsed().as_millis())
                } else {
                    format!("Responded with HTTP {}", status.as_u16())
                },
                status: Some(status.as_u16()),
                elapsed_ms: millis_u64(started.elapsed()),
            }
        }
        Err(err) => TestLaunchTargetResponse {
            ok: false,
            url: url.to_string(),
            message: if err.is_timeout() {
                format!("Timed out after {}s", timeout.as_secs())
            } else {
                format!("Could not reach app: {err}")
            },
            status: None,
            elapsed_ms: millis_u64(started.elapsed()),
        },
    };

    Ok(Json(response))
}

fn millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

// ---- /setup -----------------------------------------------------------------

async fn setup_status(State(s): State<ServerState>) -> Result<Json<SetupStatusResponse>, ApiError> {
    let cfg = s.setup.config.read().await;
    Ok(Json(SetupStatusResponse {
        complete: s.setup.is_complete(),
        config_path: s.setup.config_path.display().to_string(),
        ai_runtime: ai_runtime_label(cfg.ai.runtime).to_string(),
        ai_provider: cfg.ai.provider.clone(),
        ai_model: cfg.ai.model.clone(),
        ai_api_base: cfg.ai.api_base.clone(),
        default_run_budget_usd_micros: cfg.ai.default_run_budget_usd_micros,
        sandbox_backend: sandbox_backend_label(cfg.sandbox.backend).to_string(),
        sandbox_enabled: cfg.sandbox.enabled,
        sandbox_allow_network: cfg.sandbox.allow_network,
        ui_listen_addr: cfg.ui.listen_addr.clone(),
        ui_open_browser: cfg.ui.open_browser,
        log_level: cfg.general.log_level.clone(),
        state_dir: cfg.general.state_dir.as_ref().map(|p| p.display().to_string()),
        max_parallel_scans: cfg.performance.max_parallel_scans,
        scan_timeout_secs: cfg.performance.scan_timeout_secs,
    }))
}

fn ai_runtime_label(r: AiRuntime) -> &'static str {
    match r {
        AiRuntime::None => "none",
        AiRuntime::Anthropic => "anthropic",
        AiRuntime::LocalLlm => "local-llm",
        AiRuntime::ClaudeCode => "claude-code",
        AiRuntime::Codex => "codex",
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
    let default_run_budget_usd_micros = parse_optional_positive_micros(
        req.default_run_budget_usd_micros,
        "default_run_budget_usd_micros",
    )?;
    let mut cfg = s.setup.config.read().await.clone();
    let anthropic_api_key =
        req.anthropic_api_key.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let local_llm_url = req.local_llm_url.as_deref().map(str::trim).filter(|v| !v.is_empty());

    if matches!(ai_runtime, AiRuntime::Anthropic) && anthropic_api_key.is_none() {
        let has_existing_key = s
            .setup
            .secrets
            .get(ACCOUNT_AI_ANTHROPIC)
            .map_err(|e| ApiError::Internal(format!("read Anthropic key: {e}")))?
            .is_some();
        if !has_existing_key {
            return Err(ApiError::BadRequest(
                "anthropic_api_key is required when ai_runtime = \"anthropic\"".to_string(),
            ));
        }
    }
    if matches!(ai_runtime, AiRuntime::LocalLlm) && local_llm_url.is_none() {
        let missing_existing_url =
            cfg.ai.api_base.as_deref().map(str::trim).unwrap_or("").is_empty();
        if missing_existing_url {
            return Err(ApiError::BadRequest(
                "local_llm_url is required when ai_runtime = \"local-llm\"".to_string(),
            ));
        }
    }

    // Persist secrets first so a failure there does not orphan a
    // half-written config file. The keychain may legitimately reject
    // calls in non-interactive environments (e.g. CI); surface that as
    // a 500 with the precise reason.
    if let Some(key) = anthropic_api_key {
        s.setup
            .secrets
            .set(ACCOUNT_AI_ANTHROPIC, key)
            .map_err(|e| ApiError::Internal(format!("store Anthropic key: {e}")))?;
    } else if matches!(
        ai_runtime,
        AiRuntime::None | AiRuntime::LocalLlm | AiRuntime::ClaudeCode | AiRuntime::Codex
    ) {
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

    cfg.ai.runtime = ai_runtime;
    cfg.ai.provider = match ai_runtime {
        AiRuntime::None => None,
        AiRuntime::Anthropic => Some("anthropic".to_string()),
        AiRuntime::LocalLlm => Some("local-llm".to_string()),
        AiRuntime::ClaudeCode => Some("claude-code".to_string()),
        AiRuntime::Codex => Some("codex".to_string()),
    };
    cfg.ai.api_base = match ai_runtime {
        AiRuntime::LocalLlm => {
            local_llm_url.map(str::to_string).or_else(|| cfg.ai.api_base.clone())
        }
        _ => cfg.ai.api_base.clone(),
    };
    cfg.ai.default_run_budget_usd_micros = default_run_budget_usd_micros;
    cfg.sandbox.backend = sandbox_backend;

    let rendered =
        cfg.to_toml_string().map_err(|e| ApiError::Internal(format!("render toml: {e}")))?;
    write_config_atomic(&s.setup.config_path, &rendered)
        .map_err(|e| ApiError::Internal(format!("write {}: {e}", s.setup.config_path.display())))?;
    *s.setup.config.write().await = cfg;
    s.setup.mark_complete();
    Ok(Json(SetupResponse { ok: true, config_path: s.setup.config_path.display().to_string() }))
}

fn parse_ai_runtime(raw: &str) -> Result<AiRuntime, ApiError> {
    match raw.trim() {
        "none" => Ok(AiRuntime::None),
        "anthropic" => Ok(AiRuntime::Anthropic),
        "local-llm" => Ok(AiRuntime::LocalLlm),
        "claude-code" => Ok(AiRuntime::ClaudeCode),
        "codex" => Ok(AiRuntime::Codex),
        other => Err(ApiError::BadRequest(format!("unknown ai_runtime `{other}`"))),
    }
}

fn parse_optional_positive_micros(raw: Option<i64>, field: &str) -> Result<Option<i64>, ApiError> {
    match raw {
        Some(v) if v <= 0 => {
            Err(ApiError::BadRequest(format!("{field} must be a positive integer or null")))
        }
        other => Ok(other),
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
        let mut f =
            std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
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
            message: "AI disabled: static pass only".to_string(),
        }),
        AiRuntime::Anthropic => checks.push(anthropic_doctor_check(&s, &req)),
        AiRuntime::LocalLlm => checks.push(local_llm_doctor_check(&s, &req).await),
        AiRuntime::ClaudeCode => {
            let found = which_on_path("claude");
            checks.push(DoctorCheck {
                name: "ai-claude-code".to_string(),
                passed: found.is_some(),
                message: match found {
                    Some(p) => format!(
                        "Claude Code binary found at {p}; one-shot enabled; agent exploration enabled. Authentication is checked by Claude Code when a task starts."
                    ),
                    None => "`claude` not found on PATH; install Claude Code first".to_string(),
                },
            });
        }
        AiRuntime::Codex => checks.push(codex_doctor_check().await),
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

fn anthropic_doctor_check(s: &ServerState, req: &DoctorRequest) -> DoctorCheck {
    let provided = req.anthropic_api_key.as_deref().map(str::trim).is_some_and(|v| !v.is_empty());
    if provided {
        return DoctorCheck {
            name: "ai-anthropic".to_string(),
            passed: true,
            message: "Anthropic API key provided for this check; save settings to store it"
                .to_string(),
        };
    }

    match s.setup.secrets.get(ACCOUNT_AI_ANTHROPIC) {
        Ok(Some(_)) => DoctorCheck {
            name: "ai-anthropic".to_string(),
            passed: true,
            message: "Anthropic API key found in the OS keychain".to_string(),
        },
        Ok(None) => DoctorCheck {
            name: "ai-anthropic".to_string(),
            passed: false,
            message: "Anthropic API key is not set; enter one before saving this runtime"
                .to_string(),
        },
        Err(e) => DoctorCheck {
            name: "ai-anthropic".to_string(),
            passed: false,
            message: format!("Could not read Anthropic API key from the OS keychain: {e}"),
        },
    }
}

async fn local_llm_doctor_check(s: &ServerState, req: &DoctorRequest) -> DoctorCheck {
    let provided_url = req.local_llm_url.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let configured_url = if provided_url.is_none() {
        let cfg = s.setup.config.read().await;
        cfg.ai.api_base.clone()
    } else {
        None
    };
    let url = provided_url.or_else(|| configured_url.as_deref().map(str::trim));
    match url.filter(|v| !v.is_empty()) {
        Some(url) => DoctorCheck {
            name: "ai-local-llm".to_string(),
            passed: true,
            message: format!("Local LLM endpoint configured at {url}"),
        },
        None => DoctorCheck {
            name: "ai-local-llm".to_string(),
            passed: false,
            message: "Local LLM endpoint is not set; enter a /v1 URL before saving this runtime"
                .to_string(),
        },
    }
}

async fn codex_doctor_check() -> DoctorCheck {
    let Some(path) = which_on_path("codex") else {
        return DoctorCheck {
            name: "ai-codex".to_string(),
            passed: false,
            message: "`codex` not found on PATH; install Codex CLI first".to_string(),
        };
    };

    let mut cmd = tokio::process::Command::new(&path);
    cmd.arg("doctor")
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return DoctorCheck {
                name: "ai-codex".to_string(),
                passed: false,
                message: format!("Codex binary found at {path}, but doctor failed to run: {err}"),
            };
        }
        Err(_) => {
            return DoctorCheck {
                name: "ai-codex".to_string(),
                passed: false,
                message: format!("Codex binary found at {path}, but doctor timed out"),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = serde_json::from_str::<serde_json::Value>(&stdout);
    let Ok(report) = parsed else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        return DoctorCheck {
            name: "ai-codex".to_string(),
            passed: false,
            message: format!(
                "Codex binary found at {path}, but doctor did not return JSON: {detail}"
            ),
        };
    };

    let version = report.get("codexVersion").and_then(|v| v.as_str()).unwrap_or("unknown version");
    let overall = report.get("overallStatus").and_then(|v| v.as_str()).unwrap_or("unknown");
    let auth = doctor_check_status(&report, "auth.credentials");
    let install = doctor_check_status(&report, "installation");
    let runtime = doctor_check_status(&report, "runtime.provenance");
    let passed = matches!(auth, Some("ok")) && matches!(install, Some("ok"));
    let auth_msg = match auth {
        Some("ok") => "auth configured",
        Some(other) => other,
        None => "auth status unavailable",
    };
    let runtime_msg = match runtime {
        Some("ok") => "runtime healthy",
        Some(other) => other,
        None => "runtime status unavailable",
    };
    DoctorCheck {
        name: "ai-codex".to_string(),
        passed,
        message: format!(
            "Codex CLI {version} found at {path}; {auth_msg}; {runtime_msg}; doctor overall {overall}; one-shot enabled; agent exploration enabled"
        ),
    }
}

fn doctor_check_status<'a>(report: &'a serde_json::Value, id: &str) -> Option<&'a str> {
    report.get("checks")?.get(id)?.get("status")?.as_str()
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
    // Auto stays advisory because the chosen backend depends on the lane
    // (chain vs fast) and is resolved at scan dispatch time. Every other
    // variant routes through `nyctos_sandbox::probe` so the wizard's
    // readiness tile shares its source of truth with the doctor and the
    // run-time auto-selector.
    if matches!(b, SandboxBackend::Auto) {
        return (true, "Backend will be chosen at scan time".to_string());
    }
    let kind = match b {
        SandboxBackend::Process => nyctos_sandbox::BackendKind::Process,
        SandboxBackend::Birdcage => nyctos_sandbox::BackendKind::Birdcage,
        SandboxBackend::Libkrun => nyctos_sandbox::BackendKind::Libkrun,
        SandboxBackend::Firecracker => nyctos_sandbox::BackendKind::Firecracker,
        SandboxBackend::Docker => nyctos_sandbox::BackendKind::Docker,
        SandboxBackend::Auto => unreachable!("Auto handled above"),
    };
    match nyctos_sandbox::probe(kind) {
        Ok(()) => (true, format!("{} ready on this host", kind.as_str())),
        Err(err) => (false, err.to_string()),
    }
}

// ---- /projects --------------------------------------------------------------

async fn list_projects(State(s): State<ServerState>) -> Result<Json<Vec<ProjectRecord>>, ApiError> {
    let rows = s.store.projects().list().await?;
    Ok(Json(rows))
}

async fn create_project(
    State(s): State<ServerState>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<Json<ProjectRecord>, ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if s.store.projects().get_by_name(name).await?.is_some() {
        return Err(ApiError::BadRequest(format!("project `{name}` already exists")));
    }
    let id = format!("proj-{}", uuid_like(name, now_epoch_ms()));
    let env_config_json = match req.env_config.as_ref() {
        Some(v) => Some(serde_json::to_string(v).map_err(|e| {
            ApiError::BadRequest(format!("env_config must serialize to JSON: {e}"))
        })?),
        None => None,
    };
    let mut runtime_profile = req.runtime_profile;
    let target_base_url =
        normalize_create_target_base_url(req.target_base_url, &mut runtime_profile)?;
    let launch_profile = req.default_launch_profile.or_else(|| {
        runtime_profile
            .as_ref()
            .map(|profile| launch_profile_input_from_runtime(profile, target_base_url.as_deref()))
    });
    let runtime_profile_json = match runtime_profile.as_ref() {
        Some(v) => Some(serde_json::to_string(v).map_err(|e| {
            ApiError::BadRequest(format!("runtime_profile must serialize to JSON: {e}"))
        })?),
        None => None,
    };
    let _rec = s
        .store
        .projects()
        .create_with_runtime_profile(
            &id,
            name,
            req.description.as_deref(),
            target_base_url.as_deref(),
            env_config_json.as_deref(),
            runtime_profile_json.as_deref(),
            now_epoch_ms(),
        )
        .await?;
    if let Some(input) = launch_profile.as_ref() {
        s.store.launch_profiles().upsert_default(&id, input, now_epoch_ms()).await?;
    }
    let rec = s
        .store
        .projects()
        .get(&id)
        .await?
        .ok_or_else(|| ApiError::Internal("project vanished after create".to_string()))?;
    Ok(Json(rec))
}

async fn get_project(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<ProjectRecord>, ApiError> {
    s.store
        .projects()
        .get(&id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("project `{id}` not found")))
}

async fn patch_project(
    State(s): State<ServerState>,
    Path(id): Path<String>,
    Json(req): Json<PatchProjectRequest>,
) -> Result<Json<ProjectRecord>, ApiError> {
    // Serialise the optional env_config value once so the patch borrow
    // can reference an owned String that outlives the call.
    let owned_env_json: Option<String> = match &req.env_config {
        TriStateJson::Value(v) => Some(serde_json::to_string(v).map_err(|e| {
            ApiError::BadRequest(format!("env_config must serialize to JSON: {e}"))
        })?),
        _ => None,
    };
    let env_config_patch: ProjectPatchOption<Option<String>> = match &req.env_config {
        TriStateJson::Unset => ProjectPatchOption::Unset,
        TriStateJson::Null => ProjectPatchOption::Set(None),
        TriStateJson::Value(_) => ProjectPatchOption::Set(owned_env_json),
    };
    let mut target_base_url_patch = project_patch_for(&req.target_base_url);
    let mut launch_profile_from_runtime: Option<ProjectLaunchProfileInput> = None;
    let runtime_profile_patch: ProjectPatchOption<Option<String>> = match req.runtime_profile {
        TriStateProjectRuntimeProfile::Unset => ProjectPatchOption::Unset,
        TriStateProjectRuntimeProfile::Null => ProjectPatchOption::Set(None),
        TriStateProjectRuntimeProfile::Value(mut profile) => {
            match &req.target_base_url {
                Some(Some(target)) => {
                    let target = normalize_optional_string(Some(target.as_str()));
                    if let (Some(profile_target), Some(top_level_target)) = (
                        normalize_optional_string(profile.target_base_url.as_deref()),
                        target.as_deref(),
                    ) {
                        if profile_target != top_level_target {
                            return Err(ApiError::BadRequest(
                                "runtime_profile.target_base_url must match target_base_url"
                                    .to_string(),
                            ));
                        }
                    }
                    profile.target_base_url = target;
                }
                Some(None) => {
                    profile.target_base_url = None;
                }
                None => {
                    if let Some(profile_target) =
                        normalize_optional_string(profile.target_base_url.as_deref())
                    {
                        target_base_url_patch = ProjectPatchOption::Set(Some(profile_target));
                    }
                }
            }
            let runtime_profile_json = serde_json::to_string(&profile).map_err(|e| {
                ApiError::BadRequest(format!("runtime_profile must serialize to JSON: {e}"))
            })?;
            let target = match &req.target_base_url {
                Some(Some(value)) => Some(value.as_str()),
                _ => profile.target_base_url.as_deref(),
            };
            launch_profile_from_runtime = Some(launch_profile_input_from_runtime(&profile, target));
            ProjectPatchOption::Set(Some(runtime_profile_json))
        }
    };
    let now = now_epoch_ms();
    let patch = ProjectPatch {
        description: project_patch_for(&req.description),
        target_base_url: target_base_url_patch,
        env_config_json: env_config_patch,
        runtime_profile_json: runtime_profile_patch,
        updated_at: now,
    };
    if !s.store.projects().update(&id, &patch).await? {
        return Err(ApiError::NotFound(format!("project `{id}` not found")));
    }
    if let Some(input) = launch_profile_from_runtime.as_ref() {
        s.store.launch_profiles().upsert_default(&id, &input, now).await?;
    }
    let row = s
        .store
        .projects()
        .get(&id)
        .await?
        .ok_or_else(|| ApiError::Internal("project vanished after update".to_string()))?;
    Ok(Json(row))
}

fn project_patch_for(opt: &Option<Option<String>>) -> ProjectPatchOption<Option<String>> {
    match opt {
        None => ProjectPatchOption::Unset,
        Some(None) => ProjectPatchOption::Set(None),
        Some(Some(v)) => ProjectPatchOption::Set(Some(v.clone())),
    }
}

fn normalize_create_target_base_url(
    target_base_url: Option<String>,
    runtime_profile: &mut Option<ProjectRuntimeProfile>,
) -> Result<Option<String>, ApiError> {
    let target_base_url = normalize_optional_string(target_base_url.as_deref());
    let profile_target = runtime_profile
        .as_ref()
        .and_then(|profile| normalize_optional_string(profile.target_base_url.as_deref()));

    if let (Some(top_level), Some(profile_target)) = (&target_base_url, &profile_target) {
        if top_level != profile_target {
            return Err(ApiError::BadRequest(
                "runtime_profile.target_base_url must match target_base_url".to_string(),
            ));
        }
    }

    let resolved = target_base_url.or(profile_target);
    if let Some(profile) = runtime_profile.as_mut() {
        profile.target_base_url = resolved.clone();
    }
    Ok(resolved)
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn launch_profile_input_from_runtime(
    profile: &ProjectRuntimeProfile,
    fallback_target: Option<&str>,
) -> ProjectLaunchProfileInput {
    let build_steps: Vec<nyctos_types::product::LaunchStep> =
        profile.build_commands.iter().map(runtime_command_to_launch_step).collect();
    let start_steps: Vec<nyctos_types::product::LaunchStep> =
        profile.start_commands.iter().map(runtime_command_to_launch_step).collect();
    let mut health_checks = Vec::new();
    if let Some(url) = normalize_optional_string(profile.health_check_url.as_deref()) {
        health_checks.push(nyctos_types::product::LaunchHealthCheck {
            kind: "http".to_string(),
            url: Some(url),
            host: None,
            port: None,
            command: None,
            timeout_seconds: profile.timeout_seconds,
        });
    }
    if let Some(cmd) = &profile.health_check_command {
        health_checks.push(nyctos_types::product::LaunchHealthCheck {
            kind: "command".to_string(),
            url: None,
            host: None,
            port: None,
            command: Some(runtime_command_to_launch_step(cmd)),
            timeout_seconds: cmd.timeout_seconds.or(profile.timeout_seconds),
        });
    }
    let mut target_urls = Vec::new();
    if let Some(target) = normalize_optional_string(profile.target_base_url.as_deref())
        .or_else(|| normalize_optional_string(fallback_target))
    {
        target_urls.push(target);
    }
    let mut env_refs = Vec::new();
    if let Some(env_file) = normalize_optional_string(profile.env_file.as_deref()) {
        env_refs.push(nyctos_types::product::LaunchEnvRef {
            kind: "env-file".to_string(),
            value: env_file,
            secret: true,
        });
    }
    for var in &profile.env_vars {
        if var.name.trim().is_empty() {
            continue;
        }
        env_refs.push(nyctos_types::product::LaunchEnvRef {
            kind: "env-var".to_string(),
            value: var.name.trim().to_string(),
            secret: var.secret,
        });
    }
    let mode = if build_steps.is_empty() && start_steps.is_empty() {
        "already-running"
    } else {
        "custom-commands"
    };
    ProjectLaunchProfileInput {
        name: Some("local dev".to_string()),
        mode: Some(mode.to_string()),
        build_steps,
        start_steps,
        stop_steps: Vec::new(),
        health_checks,
        target_urls,
        env_refs,
        working_dirs: Vec::new(),
    }
}

fn runtime_command_to_launch_step(
    cmd: &nyctos_types::project::ProjectRuntimeCommand,
) -> nyctos_types::product::LaunchStep {
    nyctos_types::product::LaunchStep {
        command: cmd.command.clone(),
        repo_id: None,
        repo_name: cmd.repo_name.clone(),
        working_directory: cmd.working_directory.clone(),
        timeout_seconds: cmd.timeout_seconds,
    }
}

async fn delete_project(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<StatusBody, ApiError> {
    let affected = s.store.projects().delete(&id).await?;
    if affected == 0 {
        return Err(ApiError::NotFound(format!("project `{id}` not found")));
    }
    Ok(StatusBody::ok(format!("deleted {affected} project row(s); repos cascaded")))
}

/// Lightweight stable id helper. Concatenates a slug of `name` with the
/// supplied epoch ms so collisions across rapid creates are vanishingly
/// rare without pulling in a UUID crate dependency.
fn uuid_like(name: &str, now_ms: i64) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let trimmed: String = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(32)
        .collect();
    format!("{trimmed}-{now_ms:x}")
}

async fn require_project(s: &ServerState, project_id: &str) -> Result<ProjectRecord, ApiError> {
    s.store
        .projects()
        .get(project_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("project `{project_id}` not found")))
}

async fn get_default_launch_profile(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
) -> Result<Json<nyctos_types::product::ProjectLaunchProfile>, ApiError> {
    require_project(&s, &project_id).await?;
    s.store.launch_profiles().get_default(&project_id).await?.map(Json).ok_or_else(|| {
        ApiError::NotFound(format!("default launch profile for project `{project_id}` not found"))
    })
}

async fn patch_default_launch_profile(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
    Json(input): Json<ProjectLaunchProfileInput>,
) -> Result<Json<nyctos_types::product::ProjectLaunchProfile>, ApiError> {
    require_project(&s, &project_id).await?;
    validate_launch_profile_input(&input)?;
    let row = s.store.launch_profiles().upsert_default(&project_id, &input, now_epoch_ms()).await?;
    Ok(Json(row))
}

fn validate_launch_profile_input(input: &ProjectLaunchProfileInput) -> Result<(), ApiError> {
    let mode = input.mode.as_deref().unwrap_or("custom-commands");
    if !matches!(mode, "already-running" | "custom-commands" | "docker-compose" | "devcontainer") {
        return Err(ApiError::BadRequest(format!("unknown launch profile mode `{mode}`")));
    }
    for url in &input.target_urls {
        if !is_local_http_url(url) {
            return Err(ApiError::BadRequest(format!(
                "target URL `{url}` must be a local http:// or https:// URL"
            )));
        }
    }
    for check in &input.health_checks {
        if let Some(url) = check.url.as_deref() {
            if !is_local_http_url(url) {
                return Err(ApiError::BadRequest(format!(
                    "health check URL `{url}` must be local"
                )));
            }
        }
    }
    Ok(())
}

fn is_local_http_url(raw: &str) -> bool {
    local_http_url(raw).is_some()
}

fn local_http_url(raw: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?;
    let allowed = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|addr| addr.is_loopback() || addr.is_unspecified())
        || host.parse::<std::net::Ipv6Addr>().is_ok_and(|addr| addr.is_loopback());
    allowed.then_some(url)
}

// ---- /projects/:project_id/repos --------------------------------------------

async fn list_project_repos(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<RepoRecord>>, ApiError> {
    require_project(&s, &project_id).await?;
    let rows = s.store.repos().list_by_project(&project_id).await?;
    Ok(Json(rows))
}

async fn create_project_repo(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
    Json(req): Json<CreateRepoRequest>,
) -> Result<Json<RepoRecord>, ApiError> {
    require_project(&s, &project_id).await?;
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if !matches!(req.source_kind.as_str(), "git" | "local-path" | "github" | "gitlab" | "local") {
        return Err(ApiError::BadRequest(format!("unknown source_kind `{}`", req.source_kind)));
    }
    if !req.i_own_this {
        return Err(ApiError::BadRequest(
            "i_own_this must be set to true before the daemon will accept a repo".to_string(),
        ));
    }
    validate_git_auth_ref(&req.source_kind, req.auth_ref.as_deref())?;
    let now = now_epoch_ms();
    let existing = s.store.repos().get_by_project_and_name(&project_id, &req.name).await?;
    // Refuse re-POST against a different project so an operator cannot
    // silently re-home an existing repo via a same-name create call.
    if let Some(row) = &existing {
        if row.project_id != project_id {
            return Err(ApiError::BadRequest(format!(
                "repo `{}` already belongs to project `{}`",
                row.name, row.project_id
            )));
        }
    }
    let rec = RepoRecord {
        id: existing.as_ref().map(|r| r.id.clone()).unwrap_or_else(|| {
            format!("repo-{}", uuid_like(&format!("{project_id}-{}", req.name), now))
        }),
        name: req.name,
        project_id: project_id.clone(),
        source_kind: req.source_kind,
        source_url_or_path: req.source_url_or_path,
        branch: req.branch,
        auth_ref: req.auth_ref,
        i_own_this: req.i_own_this,
        last_scan_run_id: existing.as_ref().and_then(|r| r.last_scan_run_id.clone()),
        last_scan_finished_at: existing.as_ref().and_then(|r| r.last_scan_finished_at),
        created_at: existing.as_ref().map(|r| r.created_at).unwrap_or(now),
        updated_at: now,
    };
    s.store.repos().upsert(&rec).await?;
    Ok(Json(rec))
}

async fn get_project_repo(
    State(s): State<ServerState>,
    Path((project_id, name)): Path<(String, String)>,
) -> Result<Json<RepoRecord>, ApiError> {
    require_project(&s, &project_id).await?;
    let row = s
        .store
        .repos()
        .get_by_project_and_name(&project_id, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("repo `{name}` not found")))?;
    if row.project_id != project_id {
        return Err(ApiError::NotFound(format!(
            "repo `{name}` not found in project `{project_id}`"
        )));
    }
    Ok(Json(row))
}

async fn patch_project_repo(
    State(s): State<ServerState>,
    Path((project_id, name)): Path<(String, String)>,
    Json(req): Json<PatchRepoRequest>,
) -> Result<Json<RepoRecord>, ApiError> {
    require_project(&s, &project_id).await?;
    let existing = s
        .store
        .repos()
        .get_by_project_and_name(&project_id, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("repo `{name}` not found")))?;
    if existing.project_id != project_id {
        return Err(ApiError::NotFound(format!(
            "repo `{name}` not found in project `{project_id}`"
        )));
    }
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
    let effective_source_kind = req.source_kind.as_deref().unwrap_or(existing.source_kind.as_str());
    let effective_auth_ref: Option<&str> = match &req.auth_ref {
        None => existing.auth_ref.as_deref(),
        Some(None) => None,
        Some(Some(v)) => Some(v.as_str()),
    };
    validate_git_auth_ref(effective_source_kind, effective_auth_ref)?;
    let now = now_epoch_ms();
    let rec = RepoRecord {
        id: existing.id,
        name: existing.name,
        project_id: existing.project_id,
        source_kind: req.source_kind.unwrap_or(existing.source_kind),
        source_url_or_path: req.source_url_or_path.unwrap_or(existing.source_url_or_path),
        branch: match req.branch {
            None => existing.branch,
            Some(next) => next,
        },
        auth_ref: match req.auth_ref {
            None => existing.auth_ref,
            Some(next) => next,
        },
        i_own_this: req.i_own_this.unwrap_or(existing.i_own_this),
        last_scan_run_id: existing.last_scan_run_id,
        last_scan_finished_at: existing.last_scan_finished_at,
        created_at: existing.created_at,
        updated_at: now,
    };
    s.store.repos().upsert(&rec).await?;
    let row = s
        .store
        .repos()
        .get_by_project_and_name(&project_id, &name)
        .await?
        .ok_or_else(|| ApiError::Internal("repo vanished after update".to_string()))?;
    Ok(Json(row))
}

/// Refuse a repo create/patch whose `auth_ref` would fail the same grammar
/// the ingestion crate expects (`ssh-key:<path>` / `token-env:<VAR>` /
/// `gh-app:<id>`). Validation runs only when the effective `source_kind`
/// is `git` / `github` / `gitlab`; other source kinds ignore `auth_ref`,
/// so we do not block on a stale value left over from a kind switch.
fn validate_git_auth_ref(source_kind: &str, auth_ref: Option<&str>) -> Result<(), ApiError> {
    if !matches!(source_kind, "git" | "github" | "gitlab") {
        return Ok(());
    }
    let Some(raw) = auth_ref else {
        return Ok(());
    };
    parse_git_auth(raw).map_err(|err| match err {
        IngestError::AuthMalformed { raw } => ApiError::BadRequest(format!(
            "auth_ref `{raw}` is malformed; expected `ssh-key:<path>`, `token-env:<VAR>`, or \
             `gh-app:<id>`"
        )),
        IngestError::AuthUnknownScheme { scheme } => ApiError::BadRequest(format!(
            "auth_ref scheme `{scheme}` is not supported; use `ssh-key`, `token-env`, or `gh-app`"
        )),
        other => ApiError::BadRequest(format!("auth_ref failed validation: {other}")),
    })?;
    Ok(())
}

async fn delete_project_repo(
    State(s): State<ServerState>,
    Path((project_id, name)): Path<(String, String)>,
) -> Result<StatusBody, ApiError> {
    require_project(&s, &project_id).await?;
    let existing = s
        .store
        .repos()
        .get_by_project_and_name(&project_id, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("repo `{name}` not found")))?;
    if existing.project_id != project_id {
        return Err(ApiError::NotFound(format!(
            "repo `{name}` not found in project `{project_id}`"
        )));
    }
    let affected = s.store.repos().delete_by_project_and_name(&project_id, &name).await?;
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
                    workspace_msg =
                        format!(" (workspace {} could not be removed: {err})", target.display());
                }
            }
        }
    }
    Ok(StatusBody::ok(format!("deleted {affected} row(s){workspace_msg}")))
}

// ---- /repos/test ------------------------------------------------------------

/// Lightweight probe wired to the wizard's "test connectivity" button.
/// Performs only a read-only side effect (`git ls-remote` for git
/// sources, `stat` + read of `.git/config` for local-path sources). The
/// `project_id` from the route is validated to exist but otherwise does
/// not affect the probe (the call is stateless).
async fn test_repo_connectivity(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
    Json(req): Json<TestRepoRequest>,
) -> Result<Json<TestRepoResponse>, ApiError> {
    require_project(&s, &project_id).await?;
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
                None => "path readable; no `.git/config` remote on disk (untracked directory)."
                    .to_string(),
            };
            Ok(Json(TestRepoResponse { ok: true, message, on_disk_git_remote: remote }))
        }
        other => Err(ApiError::BadRequest(format!("unknown source_kind `{other}`"))),
    }
}

const GIT_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

async fn git_ls_remote_probe(url: &str, branch: Option<&str>) -> (bool, String) {
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("-c").arg("credential.helper=").arg("ls-remote").arg("--exit-code").arg(url);
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
                (
                    false,
                    match branch {
                        Some(b) => format!("upstream reachable but branch `{b}` does not exist"),
                        None => "upstream reachable but has no refs".to_string(),
                    },
                )
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
        Err(_) => {
            (false, format!("git ls-remote timed out after {}s", GIT_PROBE_TIMEOUT.as_secs()))
        }
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

// ---- /projects/:project_id/scan --------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    #[serde(default)]
    pub repo: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    run_id: String,
}

async fn scan_project(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
    Query(q): Query<ScanQuery>,
) -> Result<Json<ScanResponse>, ApiError> {
    require_project(&s, &project_id).await?;
    // A `?repo=...` filter scopes the trigger to a single repo; the
    // dispatcher / config-resolver downstream is responsible for
    // rejecting unknown names so this handler stays a thin pass-through.
    let run_id = s.scan.trigger(ScanTriggerSource::Manual, Some(project_id), q.repo).await?;
    Ok(Json(ScanResponse { run_id }))
}

async fn start_pentest_project(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
) -> Result<Json<StartPentestResponse>, ApiError> {
    let project = require_project(&s, &project_id).await?;
    let profile = project.default_launch_profile.ok_or_else(|| {
        ApiError::BadRequest(
            "configure a default launch profile before starting a pentest".to_string(),
        )
    })?;
    if profile.readiness != "Ready" {
        return Err(ApiError::BadRequest(format!(
            "default launch profile is not ready ({})",
            profile.readiness
        )));
    }
    let run_id = s.scan.trigger(ScanTriggerSource::Manual, Some(project_id), None).await?;
    Ok(Json(StartPentestResponse { run_id }))
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

async fn environment_runs_for_run(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<nyctos_types::product::EnvironmentRunRecord>>, ApiError> {
    require_run(&s, &id).await?;
    Ok(Json(s.store.environment_runs().list_by_run(&id).await?))
}

async fn run_event_log(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_run(&s, &id).await?;
    let logs_dir = s
        .state_logs_dir
        .as_ref()
        .ok_or_else(|| ApiError::Internal("logs directory is not configured".to_string()))?;
    let path = run_event_log_path(logs_dir, &id);
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::NotFound(format!("event log for run `{id}` not found")));
        }
        Err(err) => {
            return Err(ApiError::Internal(format!(
                "open run event log `{}`: {err}",
                path.display()
            )));
        }
    };

    let stream = async_stream::stream! {
        let mut file = file;
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buf[..n])),
                Err(err) => {
                    yield Err(err);
                    break;
                }
            }
        }
    };
    let filename = format!("{}.events.jsonl", safe_run_log_segment(&id));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\""))
        .body(Body::from_stream(stream))
        .map_err(|err| ApiError::Internal(format!("build run event log response: {err}")))
}

async fn verification_attempts_for_run(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<nyctos_types::product::VerificationAttemptRecord>>, ApiError> {
    require_run(&s, &id).await?;
    Ok(Json(s.store.verification_attempts().list_by_run(&id).await?))
}

#[derive(Debug, Deserialize)]
struct SignalsQuery {
    #[serde(default)]
    meaningful_only: bool,
}

async fn signals_for_run(
    State(s): State<ServerState>,
    Path(id): Path<String>,
    Query(q): Query<SignalsQuery>,
) -> Result<Json<Vec<nyctos_types::product::NyxSignalRecord>>, ApiError> {
    require_run(&s, &id).await?;
    Ok(Json(s.store.nyx_signals().list_by_run(&id, q.meaningful_only).await?))
}

async fn route_model_for_run(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<nyctos_types::product::RouteModelRecord>, ApiError> {
    require_run(&s, &id).await?;
    s.store
        .route_models()
        .get_by_run(&id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("route model for run `{id}` not found")))
}

async fn run_vulnerabilities(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<nyctos_types::product::VerifiedVulnerabilityRecord>>, ApiError> {
    require_run(&s, &id).await?;
    Ok(Json(s.store.verified_vulnerabilities().list_by_run(&id).await?))
}

async fn project_vulnerabilities(
    State(s): State<ServerState>,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<nyctos_types::product::VerifiedVulnerabilityRecord>>, ApiError> {
    require_project(&s, &project_id).await?;
    Ok(Json(s.store.verified_vulnerabilities().list_by_project(&project_id).await?))
}

async fn list_vulnerabilities(
    State(s): State<ServerState>,
) -> Result<Json<Vec<nyctos_types::product::VerifiedVulnerabilityRecord>>, ApiError> {
    Ok(Json(s.store.verified_vulnerabilities().list_all().await?))
}

async fn require_run(s: &ServerState, id: &str) -> Result<RunRecord, ApiError> {
    s.store.runs().get(id).await?.ok_or_else(|| ApiError::NotFound(format!("run `{id}` not found")))
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

// `FindingDiffStatus`, `FindingWithDiff`, and `RunFindingsResponse`
// live in `nyctos_types::api`; re-imported at the top of this file.

/// Composite filter for `GET /api/v1/runs/:id/findings`. Mirrors the
/// `FindingsQuery` shape minus `run_id` (taken from the path) and
/// `include_quarantine` (the run-scoped view always excludes
/// quarantined rows; the dedicated `/quarantine` endpoint covers that
/// surface).
#[derive(Debug, Deserialize, Default)]
pub struct RunFindingsQuery {
    #[serde(default)]
    pub repo: Option<String>,
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
}

async fn findings_for_run(
    State(s): State<ServerState>,
    Path(run_id): Path<String>,
    Query(q): Query<RunFindingsQuery>,
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
        repo: q.repo.as_deref(),
        cap: q.cap.as_deref(),
        origin: q.origin.as_deref(),
        status: q.status.as_deref(),
        severity: q.severity.as_deref(),
        triage_state: q.triage_state.as_deref(),
        chain_id: q.chain_id.as_deref(),
        include_quarantine: false,
        limit: None,
    };
    let current_rows = s.store.findings().list_filtered(&filter).await?;

    let prior_membership: HashMap<String, String> = match prior_run_id.as_deref() {
        Some(prior_id) => {
            s.store.findings().list_run_membership(prior_id).await?.into_iter().collect()
        }
        None => HashMap::new(),
    };
    let prior_known = !prior_membership.is_empty();
    let current_ids: HashSet<String> = current_rows.iter().map(|r| r.id.clone()).collect();

    let mut items: Vec<FindingWithDiff> = current_rows
        .into_iter()
        .map(|record| {
            let diff_status =
                classify_current_row(&record, &prior_membership, prior_known, started_at);
            FindingWithDiff { record, diff_status }
        })
        .collect();

    // Findings observed in the prior run but absent from the current
    // run: surface as `Closed`. Their row body is the latest-known
    // shape (fetched by id from `findings`), filtered by the same
    // user-supplied facets so `?repo=X` does not bleed Closed rows
    // from other repos.
    if !prior_membership.is_empty() {
        let closed_ids: Vec<&String> = prior_membership
            .iter()
            .filter_map(|(fid, prior_status)| {
                if current_ids.contains(fid) {
                    None
                } else if prior_status.eq_ignore_ascii_case("Closed") {
                    // Already closed in the prior run — not a regression.
                    None
                } else {
                    Some(fid)
                }
            })
            .collect();
        for fid in closed_ids {
            let Some(record) = s.store.findings().get(fid).await? else {
                continue;
            };
            if !row_passes_filter(&record, &q) {
                continue;
            }
            items.push(FindingWithDiff { record, diff_status: FindingDiffStatus::Closed });
        }
    }

    Ok(Json(RunFindingsResponse { run_id, prior_run_id, items }))
}

fn classify_current_row(
    record: &FindingRecord,
    prior_membership: &HashMap<String, String>,
    prior_known: bool,
    run_started_at: i64,
) -> FindingDiffStatus {
    if let Some(prior_status) = prior_membership.get(&record.id) {
        if prior_status.eq_ignore_ascii_case(&record.status) {
            return FindingDiffStatus::Unchanged;
        }
        return FindingDiffStatus::Regressed;
    }
    // No prior membership row for this finding.
    if prior_known {
        // The prior run produced `run_findings` rows; the absence is
        // authoritative — this finding is new in the current run.
        return FindingDiffStatus::New;
    }
    // Pre-migration prior run (or no prior run at all). Fall back to
    // the legacy first-seen heuristic so freshly-observed rows still
    // surface as `New` and older rows wallpaper as `Unchanged`.
    if record.first_seen >= run_started_at {
        FindingDiffStatus::New
    } else {
        FindingDiffStatus::Unchanged
    }
}

/// Same predicate `FindingStore::list_filtered` runs at the DB level,
/// applied in-memory to a row fetched by id. Used for the `Closed`
/// path where the row does not live in the current run's filtered
/// projection. Mirrors every facet `RunFindingsQuery` accepts.
fn row_passes_filter(record: &FindingRecord, q: &RunFindingsQuery) -> bool {
    if record.status.eq_ignore_ascii_case("Quarantine") {
        return false;
    }
    if let Some(repo) = q.repo.as_deref() {
        if record.repo != repo {
            return false;
        }
    }
    if let Some(cap) = q.cap.as_deref() {
        if record.cap != cap {
            return false;
        }
    }
    if let Some(origin) = q.origin.as_deref() {
        if record.finding_origin != origin {
            return false;
        }
    }
    if let Some(status) = q.status.as_deref() {
        if record.status != status {
            return false;
        }
    }
    if let Some(severity) = q.severity.as_deref() {
        if record.severity != severity {
            return false;
        }
    }
    if let Some(triage) = q.triage_state.as_deref() {
        if record.triage_state != triage {
            return false;
        }
    }
    if let Some(chain_id) = q.chain_id.as_deref() {
        if record.chain_id.as_deref() != Some(chain_id) {
            return false;
        }
    }
    true
}

// ---- /chains ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ChainListQuery {
    run_id: Option<String>,
    #[serde(default)]
    include_proposed: bool,
}

async fn list_chains(
    State(s): State<ServerState>,
    Query(q): Query<ChainListQuery>,
) -> Result<Json<Vec<ChainRecord>>, ApiError> {
    let run_id = q
        .run_id
        .ok_or_else(|| ApiError::BadRequest("missing `run_id` query parameter".to_string()))?;
    let mut rows = s.store.chains().list_by_run(&run_id).await?;
    if !q.include_proposed {
        rows.retain(|row| row.status == "Verified");
    }
    Ok(Json(rows))
}

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
        let row = manual_promote_finding_row(&s, &id).await?;
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
        s.store.candidate_findings().set_status(&id, CandidateStatus::Dismissed.as_str()).await?;
        Ok(Json(candidate_to_quarantine_item(&cand)))
    } else {
        let row = manual_dismiss_finding_row(&s, &id).await?;
        Ok(Json(finding_to_quarantine_item(&row)))
    }
}

async fn manual_promote_finding_row(s: &ServerState, id: &str) -> Result<FindingRecord, ApiError> {
    let existing = require_quarantined_finding(s, id).await?;
    let blob = serde_json::to_string(&json!({
        "kind": "ManualPromote",
        "from": "quarantine",
        "prev_provenance": existing.attack_provenance,
        "prev_verdict_blob": existing.verdict_blob,
    }))
    .map_err(|e| ApiError::Internal(format!("serialize manual-promote blob: {e}")))?;
    s.store.findings().manual_promote(id, "Open", &blob).await?;
    s.store
        .findings()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::Internal("finding vanished after promote".to_string()))
}

async fn manual_dismiss_finding_row(s: &ServerState, id: &str) -> Result<FindingRecord, ApiError> {
    let existing = require_quarantined_finding(s, id).await?;
    let blob = serde_json::to_string(&json!({
        "kind": "ManualDismiss",
        "from": "quarantine",
        "prev_provenance": existing.attack_provenance,
        "prev_verdict_blob": existing.verdict_blob,
    }))
    .map_err(|e| ApiError::Internal(format!("serialize manual-dismiss blob: {e}")))?;
    s.store.findings().manual_dismiss(id, &blob).await?;
    s.store
        .findings()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::Internal("finding vanished after dismiss".to_string()))
}

async fn require_quarantined_finding(s: &ServerState, id: &str) -> Result<FindingRecord, ApiError> {
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
    Ok(existing)
}

async fn promote_candidate_to_finding(
    s: &ServerState,
    cand: &CandidateFindingRecord,
) -> Result<(), ApiError> {
    let line = cand.line.unwrap_or(-1);
    let rule = cand.rule_hint.clone().unwrap_or_else(|| format!("ai-exploration:{}", cand.cap));
    let id =
        nyctos_core::store::finding_id_hash(&cand.repo, &cand.path, Some(line), &cand.cap, &rule);
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
        spec_id: None,
    };
    s.store.findings().upsert(&rec).await?;
    s.store.candidate_findings().set_status(&cand.id, CandidateStatus::Promoted.as_str()).await?;
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
//
// `AgentTraceRow` lives in `nyctos_types::api`; the `From<AgentTraceRecord>`
// projection it carries drops the persistence-only `verifier_blob` field
// so the FE shape stays minimal. Lift `verifier_blob` onto the wire here
// when the trace viewer (Phase 24) starts rendering Verifier-row
// inputs/outputs without joining `findings.verdict_blob`.

async fn traces_for_finding(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AgentTraceRow>>, ApiError> {
    // Candidate ids carry a `cand-` prefix (see
    // `nyctos::ai_pipeline::candidate_id`); route those through the
    // `candidate_findings.trace_id` back-link so the trace viewer can
    // render the proposing AI call for a Pending candidate. Finding ids
    // hit the direct `agent_traces.finding_id` index as before.
    let rows = if id.starts_with("cand-") {
        s.store.agent_traces().list_for_candidate(&id).await?
    } else {
        s.store.agent_traces().list_for_finding(&id).await?
    };
    Ok(Json(rows.into_iter().map(AgentTraceRow::from).collect()))
}

async fn get_trace(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<AgentTraceRow>, ApiError> {
    s.store
        .agent_traces()
        .get(&id)
        .await?
        .map(AgentTraceRow::from)
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
                if tx.send(Message::Text(payload.into())).await.is_err() {
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
                                if tx.send(Message::Text(payload.into())).await.is_err() {
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
                        if tx.send(Message::Text(warning.to_string().into())).await.is_err() {
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
    match ev {
        AgentEvent::Run { data } => {
            let id = match data {
                RunEvent::Heartbeat { .. } => return true,
                RunEvent::RunStarted { run_id, .. }
                | RunEvent::ProjectStarted { run_id, .. }
                | RunEvent::PhaseStarted { run_id, .. }
                | RunEvent::PhaseFinished { run_id, .. }
                | RunEvent::EnvironmentStatus { run_id, .. }
                | RunEvent::AuthSessionStatus { run_id, .. }
                | RunEvent::RepoStarted { run_id, .. }
                | RunEvent::RepoStaticDone { run_id, .. }
                | RunEvent::RepoDynamicDone { run_id, .. }
                | RunEvent::RepoFailed { run_id, .. }
                | RunEvent::RepoIngestFailed { run_id, .. }
                | RunEvent::RepoFinished { run_id, .. }
                | RunEvent::ProjectFinished { run_id, .. }
                | RunEvent::RunFinished { run_id, .. } => run_id.as_str(),
            };
            id == want
        }
        AgentEvent::Ai { data: AiEvent::BudgetTick { run_id, .. } } => run_id == want,
        AgentEvent::Sandbox { data } => {
            let run_id = match data {
                SandboxEvent::VerifierStarted { run_id, .. }
                | SandboxEvent::VerifierFinished { run_id, .. } => run_id.as_str(),
            };
            run_id == want
        }
        _ => true,
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
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], body)
        .into_response())
}

async fn run_summary_html(
    State(s): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let card = build_run_card(s.store.pool(), &id).await.map_err(run_card_to_api)?;
    let body = render_run_card_html(&card);
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response())
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
    let manifest =
        build_bundle(&s.store, &id, &out_dir, now_epoch_ms()).await.map_err(bundle_to_api)?;
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
        let out_dir =
            s.state_bundles_dir.as_ref().cloned().ok_or_else(|| {
                ApiError::Internal("bundle output dir is not configured".to_string())
            })?;
        let manifest =
            build_bundle(&s.store, &id, &out_dir, now_epoch_ms()).await.map_err(bundle_to_api)?;
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
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            ("X-Nyctos-Bundle-Sha256".parse().unwrap(), row.sha256),
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
    let root = bundles_dir
        .ok_or_else(|| ApiError::Internal("bundle output dir is not configured".to_string()))?;
    let canonical_root = root
        .canonicalize()
        .map_err(|e| ApiError::Internal(format!("canonicalize bundles root: {e}")))?;
    let canonical_path = std::path::Path::new(path)
        .canonicalize()
        .map_err(|e| ApiError::Internal(format!("canonicalize bundle path `{path}`: {e}")))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(ApiError::Internal("bundle path escapes configured root".to_string()));
    }
    Ok(canonical_path)
}

fn bundle_to_api(err: BundleError) -> ApiError {
    match err {
        BundleError::FindingNotFound(id) => ApiError::NotFound(format!("finding `{id}` not found")),
        BundleError::Tar(e) => ApiError::Internal(format!("bundle tar write: {e}")),
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
    let events = s.events.clone();
    let bundle_path_str = bundle_path.display().to_string();
    let stream = async_stream::stream! {
        let _ = events.send(AgentEvent::Repro {
            data: ReproEvent::ReplayStarted {
                finding_id: finding_id.clone(),
                bundle_path: bundle_path_str.clone(),
                started_at_ms: started_at,
            },
        });
        yield Ok(SseEvent::default()
            .event("start")
            .data(serde_json::json!({
                "finding_id": finding_id,
                "bundle_path": bundle_path_str,
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
                let msg = format!("spawn bash: {e}");
                let _ = events.send(AgentEvent::Repro {
                    data: ReproEvent::ReplayError {
                        finding_id: finding_id.clone(),
                        message: msg.clone(),
                    },
                });
                yield Ok(SseEvent::default().event("error").data(msg));
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
        while (!stdout_done || !stderr_done) && !timed_out {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = child.start_kill();
                    let msg = format!(
                        "replay exceeded {REPLAY_WALL_CLOCK_TIMEOUT_SECS}s wall-clock timeout; killed"
                    );
                    let _ = events.send(AgentEvent::Repro {
                        data: ReproEvent::ReplayError {
                            finding_id: finding_id.clone(),
                            message: msg.clone(),
                        },
                    });
                    yield Ok(SseEvent::default().event("error").data(msg));
                    timed_out = true;
                }
                line = stdout_lines.next_line(), if !stdout_done => {
                    match line {
                        Ok(Some(text)) => {
                            let _ = events.send(AgentEvent::Repro {
                                data: ReproEvent::ReplayStdout {
                                    finding_id: finding_id.clone(),
                                    line: text.clone(),
                                },
                            });
                            yield Ok(SseEvent::default().event("stdout").data(text));
                        }
                        Ok(None) => stdout_done = true,
                        Err(e) => {
                            let msg = format!("stdout read: {e}");
                            let _ = events.send(AgentEvent::Repro {
                                data: ReproEvent::ReplayError {
                                    finding_id: finding_id.clone(),
                                    message: msg.clone(),
                                },
                            });
                            yield Ok(SseEvent::default().event("error").data(msg));
                            stdout_done = true;
                        }
                    }
                }
                line = stderr_lines.next_line(), if !stderr_done => {
                    match line {
                        Ok(Some(text)) => {
                            let _ = events.send(AgentEvent::Repro {
                                data: ReproEvent::ReplayStderr {
                                    finding_id: finding_id.clone(),
                                    line: text.clone(),
                                },
                            });
                            yield Ok(SseEvent::default().event("stderr").data(text));
                        }
                        Ok(None) => stderr_done = true,
                        Err(e) => {
                            let msg = format!("stderr read: {e}");
                            let _ = events.send(AgentEvent::Repro {
                                data: ReproEvent::ReplayError {
                                    finding_id: finding_id.clone(),
                                    message: msg.clone(),
                                },
                            });
                            yield Ok(SseEvent::default().event("error").data(msg));
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
                let msg = format!("wait: {e}");
                let _ = events.send(AgentEvent::Repro {
                    data: ReproEvent::ReplayError {
                        finding_id: finding_id.clone(),
                        message: msg.clone(),
                    },
                });
                yield Ok(SseEvent::default().event("error").data(msg));
                yield Ok(SseEvent::default().event("end").data("error"));
                return;
            }
            Err(_) => {
                let msg = format!(
                    "child not reaped within {REPLAY_REAP_GRACE_SECS}s after kill"
                );
                let _ = events.send(AgentEvent::Repro {
                    data: ReproEvent::ReplayError {
                        finding_id: finding_id.clone(),
                        message: msg.clone(),
                    },
                });
                yield Ok(SseEvent::default().event("error").data(msg));
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
        let _ = events.send(AgentEvent::Repro {
            data: ReproEvent::ReplayFinished {
                finding_id: finding_id.clone(),
                status: verdict.to_string(),
                exit_code,
                started_at_ms: started_at,
                finished_at_ms: finished_at,
                duration_ms: finished_at - started_at,
            },
        });
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

/// Extract the USTAR/PAX tarball produced by
/// `nyctos_core::report::repro_bundle::build_ustar`. Rejects entries
/// whose path escapes the destination via `..` or absolute components
/// so a substituted bundle cannot write outside the tempdir.
fn extract_ustar(bytes: &[u8], dest: &std::path::Path) -> std::io::Result<()> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    // Honor on-record perms but refuse path traversal. The `tar` crate
    // calls this "Overwrite" + "PreservePermissions" + "Unpack"; the
    // default unpack already rejects `..`, but we sanitise explicitly
    // so a malformed PAX `path` extension cannot smuggle one in.
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let safe = sanitise_tar_path(&path).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unsafe tar path")
        })?;
        let target = dest.join(safe);
        entry.unpack(&target)?;
    }
    Ok(())
}

/// Reject tar entries containing `..` components or absolute paths so
/// extraction stays inside the destination tempdir.
fn sanitise_tar_path(name: &std::path::Path) -> Option<std::path::PathBuf> {
    if name.is_absolute() {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    for component in name.components() {
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

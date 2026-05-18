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
        Path, Query, State,
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use nyx_agent_core::store::{ChainRecord, FindingRecord, RepoRecord, RunRecord};
use nyx_agent_types::event::{AgentEvent, RunEvent};

use crate::state::{ApiError, ServerState};

/// Build the production router with every `/api/v1/...` route attached.
pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/repos", get(list_repos).post(create_repo))
        .route("/api/v1/repos/:name", delete(delete_repo))
        .route("/api/v1/scan", post(trigger_scan))
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/:id", get(get_run))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/findings/:id", get(get_finding))
        .route("/api/v1/chains/:id", get(get_chain))
        .route("/api/v1/events", get(events_ws))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> impl IntoResponse {
    Json(Health { status: "ok", version: env!("CARGO_PKG_VERSION") })
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

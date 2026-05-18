use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;
use tokio::sync::RwLock;

use nyx_agent_core::store::StoreError;
use nyx_agent_core::{Config, SecretStore, Store};
use nyx_agent_types::event::EventSink;

/// Future returned by [`ScanTrigger::trigger`]. Boxed so the trait can be
/// object-safe.
pub type ScanFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>>;

/// Plug that lets the API hand off a manual scan request to the daemon
/// that owns the run dispatcher. The daemon wires the production impl;
/// tests substitute a stub.
pub trait ScanTrigger: Send + Sync + 'static {
    /// Kick off a scan. Returns the freshly minted run id. The repo
    /// filter, when set, restricts the run to a single configured repo.
    fn trigger<'a>(&'a self, repo: Option<String>) -> ScanFuture<'a>;
}

#[derive(Debug, Error)]
pub enum ScanTriggerError {
    #[error("scan request was rejected: {0}")]
    Rejected(String),
    #[error("daemon is shutting down")]
    Closed,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Phase-09 wizard context. Lets the API write `nyx-agent.toml` on
/// behalf of the operator, see whether setup is complete, and stash
/// API keys in the OS keychain.
#[derive(Clone)]
pub struct SetupContext {
    pub config_path: PathBuf,
    pub secrets: SecretStore,
    /// Current in-memory config. Wrapped in an `RwLock` so the
    /// `/setup` handler can hand a freshly-written config back to the
    /// rest of the API without restarting the daemon.
    pub config: Arc<RwLock<Config>>,
    /// `true` once `nyx-agent.toml` is materialised on disk. Read by
    /// `GET /api/v1/setup/status` and by the auth middleware to know
    /// whether to exempt `/setup` endpoints.
    pub completed: Arc<std::sync::atomic::AtomicBool>,
}

impl SetupContext {
    pub fn new(
        config_path: PathBuf,
        config: Config,
        completed: bool,
        secrets: SecretStore,
    ) -> Self {
        Self {
            config_path,
            secrets,
            config: Arc::new(RwLock::new(config)),
            completed: Arc::new(std::sync::atomic::AtomicBool::new(completed)),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn mark_complete(&self) {
        self.completed.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Bearer-token guard used by the API auth middleware. `None` skips
/// the check entirely (e.g. when the daemon was launched with
/// `--headless`).
#[derive(Clone, Default)]
pub struct AuthConfig {
    pub token: Option<String>,
}

impl AuthConfig {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }

    pub fn is_enforced(&self) -> bool {
        self.token.is_some()
    }
}

/// Shared state injected into every Axum handler. Cloned per request;
/// the underlying [`Store`] and broadcast sender are already cheap to
/// clone because they wrap `Arc`s internally.
#[derive(Clone)]
pub struct ServerState {
    pub store: Store,
    pub events: EventSink,
    pub scan: Arc<dyn ScanTrigger>,
    pub setup: SetupContext,
    pub auth: AuthConfig,
    /// Path that holds per-repo workspace dirs (the moral equivalent of
    /// `<state>/repos`). The repo-delete handler removes the per-repo
    /// subdir under this path so a re-add starts from a clean slate.
    /// `None` in tests that do not exercise workspace cleanup.
    pub state_repos_dir: Option<PathBuf>,
}

impl ServerState {
    pub fn new(
        store: Store,
        events: EventSink,
        scan: Arc<dyn ScanTrigger>,
        setup: SetupContext,
        auth: AuthConfig,
    ) -> Self {
        Self { store, events, scan, setup, auth, state_repos_dir: None }
    }

    /// Attach the on-disk repo workspace root so the delete handler can
    /// remove `<state_repos_dir>/<name>/` when a repo is removed.
    pub fn with_state_repos_dir(mut self, dir: PathBuf) -> Self {
        self.state_repos_dir = Some(dir);
        self
    }
}

/// Uniform error envelope. Every handler returns
/// `Result<T, ApiError>` so HTTP status codes and JSON bodies stay
/// consistent across endpoints.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("scan trigger failed: {0}")]
    Scan(#[from] ScanTriggerError),
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_error"),
            ApiError::Scan(ScanTriggerError::Rejected(_)) => {
                (StatusCode::BAD_REQUEST, "scan_rejected")
            }
            ApiError::Scan(ScanTriggerError::Closed) => {
                (StatusCode::SERVICE_UNAVAILABLE, "shutting_down")
            }
            ApiError::Scan(ScanTriggerError::Internal(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "scan_internal")
            }
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let body = Json(json!({ "error": { "code": code, "message": self.to_string() } }));
        (status, body).into_response()
    }
}

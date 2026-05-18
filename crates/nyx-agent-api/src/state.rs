use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

use nyx_agent_core::store::StoreError;
use nyx_agent_core::Store;
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

/// Shared state injected into every Axum handler. Cloned per request;
/// the underlying [`Store`] and broadcast sender are already cheap to
/// clone because they wrap `Arc`s internally.
#[derive(Clone)]
pub struct ServerState {
    pub store: Store,
    pub events: EventSink,
    pub scan: Arc<dyn ScanTrigger>,
}

impl ServerState {
    pub fn new(store: Store, events: EventSink, scan: Arc<dyn ScanTrigger>) -> Self {
        Self { store, events, scan }
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

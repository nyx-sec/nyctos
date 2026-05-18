use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use nyx_agent_core::store::StoreError;
use nyx_agent_core::{Config, SecretStore, Store};
use nyx_agent_types::event::{AgentEvent, EventSink, RunEvent};

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

/// Bounded per-run event replay buffer. Closes the broadcast race
/// described in the Phase 07 deferred item: a client that calls
/// `POST /api/v1/scan` and *then* opens the WebSocket would miss
/// `RunStarted` (and possibly the first few `RepoStarted`/`RepoFailed`)
/// frames because tokio's `broadcast::Sender` does not replay history.
/// `events_ws` reads back the snapshot here before joining the live
/// stream so the LiveScanView always sees the run's lifecycle from the
/// start.
///
/// Events that lack a `run_id` (e.g. plain heartbeats) are not buffered
/// because there is nothing for a subscriber to scope to.
///
/// Eviction is least-recently-touched: the side `order` deque tracks
/// run ids with the most recently pushed-into run at the back. When a
/// new run needs admission past `max_runs`, the front (oldest activity)
/// is evicted.
#[derive(Debug)]
pub struct EventReplay {
    inner: Mutex<ReplayInner>,
    /// Hard cap on events stored per run. The Phase 11 acceptance set
    /// is small (one RunStarted + N RepoStarted/RepoFinished pairs +
    /// RunFinished). 128 frames covers ~60 repos before the head is
    /// dropped, which is more than the static-pass budget.
    pub max_per_run: usize,
    /// Cap on tracked runs. Past this we evict the least-recently-
    /// touched tracked run. 16 covers the realistic concurrent-
    /// LiveScanView count.
    pub max_runs: usize,
}

#[derive(Debug, Default)]
struct ReplayInner {
    by_run: HashMap<String, VecDeque<AgentEvent>>,
    /// Insertion / touch order. Front is least-recently-pushed,
    /// back is most-recently-pushed.
    order: VecDeque<String>,
}

impl EventReplay {
    pub fn new() -> Self {
        Self { inner: Mutex::new(ReplayInner::default()), max_per_run: 128, max_runs: 16 }
    }

    /// Append an event to the per-run buffer. No-op for events that do
    /// not carry a `run_id`.
    pub async fn push(&self, event: &AgentEvent) {
        let Some(run_id) = run_id_for_event(event) else { return };
        let mut g = self.inner.lock().await;

        // Touch LRU position: if the run is already tracked, lift it
        // out of `order` so we can re-append at the back. If the run is
        // new and we are at capacity, evict the front (oldest).
        if let Some(pos) = g.order.iter().position(|r| r == run_id) {
            g.order.remove(pos);
        } else if g.by_run.len() >= self.max_runs {
            if let Some(victim) = g.order.pop_front() {
                g.by_run.remove(&victim);
            }
        }
        g.order.push_back(run_id.to_string());

        let buf = g.by_run.entry(run_id.to_string()).or_default();
        if buf.len() == self.max_per_run {
            buf.pop_front();
        }
        buf.push_back(event.clone());
    }

    /// Snapshot every buffered event for `run_id`. Cheap clone.
    pub async fn snapshot(&self, run_id: &str) -> Vec<AgentEvent> {
        let g = self.inner.lock().await;
        g.by_run.get(run_id).map(|q| q.iter().cloned().collect()).unwrap_or_default()
    }

    /// Number of currently tracked runs. Used in tests; cheap.
    pub async fn tracked_runs(&self) -> usize {
        self.inner.lock().await.by_run.len()
    }
}

fn run_id_for_event(ev: &AgentEvent) -> Option<&str> {
    match ev {
        AgentEvent::Run { data } => match data {
            RunEvent::Heartbeat { .. } => None,
            RunEvent::RunStarted { run_id, .. }
            | RunEvent::RepoStarted { run_id, .. }
            | RunEvent::RepoStaticDone { run_id, .. }
            | RunEvent::RepoDynamicDone { run_id, .. }
            | RunEvent::RepoFailed { run_id, .. }
            | RunEvent::RepoFinished { run_id, .. }
            | RunEvent::RunFinished { run_id, .. } => Some(run_id.as_str()),
        },
        _ => None,
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
    /// Per-run event replay buffer. Populated by a tap task the daemon
    /// runs alongside the broadcast channel and read by `events_ws` on
    /// upgrade so newly-attached LiveScanView clients catch the
    /// run's lifecycle from the start.
    pub replay: Arc<EventReplay>,
    /// Path that holds per-repo workspace dirs (the moral equivalent of
    /// `<state>/repos`). The repo-delete handler removes the per-repo
    /// subdir under this path so a re-add starts from a clean slate.
    /// `None` in tests that do not exercise workspace cleanup.
    pub state_repos_dir: Option<PathBuf>,
    /// Per-finding repro bundle output directory (`<state>/bundles`).
    /// The Phase-25 bundle handler writes one tarball per finding here
    /// and stamps a `repro_bundles` row pointing at the resulting path.
    /// `None` in tests that do not exercise bundle creation.
    pub state_bundles_dir: Option<PathBuf>,
}

impl ServerState {
    pub fn new(
        store: Store,
        events: EventSink,
        scan: Arc<dyn ScanTrigger>,
        setup: SetupContext,
        auth: AuthConfig,
    ) -> Self {
        Self {
            store,
            events,
            scan,
            setup,
            auth,
            replay: Arc::new(EventReplay::new()),
            state_repos_dir: None,
            state_bundles_dir: None,
        }
    }

    /// Attach the on-disk repo workspace root so the delete handler can
    /// remove `<state_repos_dir>/<name>/` when a repo is removed.
    pub fn with_state_repos_dir(mut self, dir: PathBuf) -> Self {
        self.state_repos_dir = Some(dir);
        self
    }

    /// Attach the on-disk repro bundle output root so the bundle
    /// handler can write `<state_bundles_dir>/<finding-id>.tar`.
    pub fn with_state_bundles_dir(mut self, dir: PathBuf) -> Self {
        self.state_bundles_dir = Some(dir);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn run_started(run_id: &str) -> AgentEvent {
        AgentEvent::Run {
            data: RunEvent::RunStarted {
                run_id: run_id.to_string(),
                repos: vec!["alpha".to_string()],
                started_at_ms: 0,
            },
        }
    }

    fn repo_started(run_id: &str, repo: &str) -> AgentEvent {
        AgentEvent::Run {
            data: RunEvent::RepoStarted {
                run_id: run_id.to_string(),
                repo: repo.to_string(),
                started_at_ms: 0,
            },
        }
    }

    fn heartbeat() -> AgentEvent {
        AgentEvent::Run { data: RunEvent::Heartbeat { ts: 0 } }
    }

    #[tokio::test]
    async fn heartbeat_is_not_buffered() {
        let replay = EventReplay::new();
        replay.push(&heartbeat()).await;
        assert_eq!(replay.tracked_runs().await, 0);
        assert!(replay.snapshot("anything").await.is_empty());
    }

    #[tokio::test]
    async fn snapshot_returns_events_in_push_order() {
        let replay = EventReplay::new();
        replay.push(&run_started("r1")).await;
        replay.push(&repo_started("r1", "alpha")).await;
        let frames = replay.snapshot("r1").await;
        assert_eq!(frames.len(), 2);
        assert!(matches!(
            frames[0],
            AgentEvent::Run { data: RunEvent::RunStarted { .. } }
        ));
        assert!(matches!(
            frames[1],
            AgentEvent::Run { data: RunEvent::RepoStarted { .. } }
        ));
    }

    #[tokio::test]
    async fn max_per_run_drops_oldest_frame() {
        let mut replay = EventReplay::new();
        replay.max_per_run = 2;
        replay.push(&run_started("r1")).await;
        replay.push(&repo_started("r1", "alpha")).await;
        replay.push(&repo_started("r1", "beta")).await;
        let frames = replay.snapshot("r1").await;
        assert_eq!(frames.len(), 2);
        // Oldest frame (RunStarted) is dropped; surviving frames are
        // the two RepoStarted entries in arrival order.
        let repos: Vec<String> = frames
            .iter()
            .filter_map(|ev| match ev {
                AgentEvent::Run { data: RunEvent::RepoStarted { repo, .. } } => {
                    Some(repo.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(repos, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn max_runs_evicts_least_recently_touched_run() {
        let mut replay = EventReplay::new();
        replay.max_runs = 2;
        replay.push(&run_started("a")).await;
        replay.push(&run_started("b")).await;
        // Touch `a` to make it most-recent; `b` is now LRU.
        replay.push(&repo_started("a", "alpha")).await;
        // Admitting `c` should evict `b`, not `a`.
        replay.push(&run_started("c")).await;

        assert_eq!(replay.tracked_runs().await, 2);
        assert!(!replay.snapshot("a").await.is_empty(), "`a` was touched, must survive");
        assert!(replay.snapshot("b").await.is_empty(), "`b` was LRU, must be evicted");
        assert!(!replay.snapshot("c").await.is_empty(), "`c` is newest");
    }

    #[tokio::test]
    async fn unknown_run_id_yields_empty_snapshot() {
        let replay = EventReplay::new();
        replay.push(&run_started("real")).await;
        assert!(replay.snapshot("ghost").await.is_empty());
    }
}

//! Parallel static-pass dispatcher and run aggregator.
//!
//! The runner crate hands the dispatcher a freshly minted [`Run`], a
//! [`ScanLane`] implementation, and a list of [`WorkspaceHandle`]s (one
//! per ingested repo). The dispatcher schedules one rayon thread-pool
//! job per workspace, enforces a per-repo timeout, publishes lifecycle
//! events through the [`EventSink`] broadcast bus, and aggregates the
//! per-repo outputs into a single [`RunBundle`].
//!
//! Fan-out width defaults to `min(num_cpus / 2, repo_count)` and is
//! overridable via `[performance] static_concurrency`. The per-repo
//! budget defaults to 30 minutes and is overridable via
//! `[performance] per_repo_timeout_secs`. A repo that exhausts its
//! budget is recorded as
//! [`RepoOutcome::Inconclusive(InconclusiveReason::StaticPassTimeout)`]
//! and never blocks the rest of the run.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nyctos_types::event::{AgentEvent, EventSink, RepoOutcomeTag, RunEvent};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};

use crate::config::PerformanceConfig;
use crate::project::Project;
use crate::repo::IngestedRepo;
use crate::time::now_epoch_ms;

mod workspace;

pub use workspace::WorkspaceHandle;

/// In-process run identifier. The dispatcher mints it before fanning
/// out per-repo work and threads it through every event and bundle the
/// run produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: String,
    pub started_at_ms: i64,
}

impl Run {
    /// Mint a fresh run id and capture the wall-clock start. The id is
    /// process-locally unique even when multiple runs collide inside a
    /// single millisecond.
    pub fn new() -> Self {
        Self { id: mint_run_id(), started_at_ms: now_epoch_ms() }
    }

    /// Build a run with a caller-supplied id. Used by tests that want
    /// to assert against a known id; not for production code.
    pub fn with_id(id: impl Into<String>) -> Self {
        Self { id: id.into(), started_at_ms: now_epoch_ms() }
    }
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a repo did not produce a full result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InconclusiveReason {
    /// Per-repo static-pass timeout fired before the scan returned.
    StaticPassTimeout,
}

impl InconclusiveReason {
    pub fn as_str(self) -> &'static str {
        match self {
            InconclusiveReason::StaticPassTimeout => "StaticPassTimeout",
        }
    }
}

/// Outcome bundled with every repo. `D` is the lane's diagnostic shape
/// (e.g. `nyx_agent_nyx::Diag` in production, `()` in unit tests).
#[derive(Debug, Clone)]
pub enum RepoOutcome<D> {
    Success(Vec<D>),
    Inconclusive(InconclusiveReason),
    Failed(String),
}

impl<D> RepoOutcome<D> {
    pub fn tag(&self) -> RepoOutcomeTag {
        match self {
            RepoOutcome::Success(_) => RepoOutcomeTag::Success,
            RepoOutcome::Inconclusive(_) => RepoOutcomeTag::Inconclusive,
            RepoOutcome::Failed(_) => RepoOutcomeTag::Failed,
        }
    }
}

/// Per-repo block emitted by the dispatcher.
#[derive(Debug, Clone)]
pub struct RepoBundle<D> {
    pub repo: String,
    pub outcome: RepoOutcome<D>,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub elapsed_ms: i64,
}

/// Cross-repo callgraph stub. Records only the participating repos
/// today; real cross-repo edges land with the cross-repo chain
/// runner. Until then this is a marker that aggregation happened.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossRepoCallgraphStub {
    pub nodes: Vec<String>,
    pub edges: Vec<CrossRepoEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRepoEdge {
    pub from_repo: String,
    pub to_repo: String,
}

/// Aggregated output for a whole run.
#[derive(Debug, Clone)]
pub struct RunBundle<D> {
    pub run_id: String,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub wall_clock_ms: i64,
    pub per_repo: Vec<RepoBundle<D>>,
    pub callgraph: CrossRepoCallgraphStub,
}

impl<D> RunBundle<D> {
    /// Count of repos by outcome tag. Useful for tests and event
    /// emission.
    pub fn counts(&self) -> RunCounts {
        let mut c = RunCounts::default();
        for b in &self.per_repo {
            match b.outcome.tag() {
                RepoOutcomeTag::Success => c.succeeded += 1,
                RepoOutcomeTag::Inconclusive => c.inconclusive += 1,
                RepoOutcomeTag::Failed => c.failed += 1,
            }
        }
        c
    }

    pub fn iter_successes(&self) -> impl Iterator<Item = (&str, &[D])> {
        self.per_repo.iter().filter_map(|b| match &b.outcome {
            RepoOutcome::Success(diags) => Some((b.repo.as_str(), diags.as_slice())),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounts {
    pub succeeded: u32,
    pub inconclusive: u32,
    pub failed: u32,
}

/// Why the lane could not return a diag list.
#[derive(Debug, Clone)]
pub enum ScanLaneError {
    /// Scan exceeded the dispatcher-provided per-repo timeout.
    Timeout,
    /// Scan failed for any other reason. The message is surfaced both
    /// to the event bus and the [`RepoBundle`].
    Failed(String),
}

/// Static-pass scan lane. The default production impl wraps
/// [`nyx_agent_nyx::NyxRunner`]; tests use synchronous stubs.
///
/// Implementations must drop into and out of any tokio runtime
/// themselves; the dispatcher invokes `scan_blocking` from a rayon
/// worker thread.
pub trait ScanLane<D>: Send + Sync + 'static {
    /// Run the static pass against the given workspace. The
    /// dispatcher passes the same `timeout` the operator configured in
    /// `[performance] per_repo_timeout_secs`; lanes that delegate to
    /// async I/O (e.g. `nyx scan`) should plumb it through their own
    /// timeout primitive.
    fn scan_blocking(
        &self,
        workspace: &WorkspaceHandle,
        timeout: Duration,
    ) -> Result<Vec<D>, ScanLaneError>;
}

impl<D, F> ScanLane<D> for F
where
    F: Fn(&WorkspaceHandle, Duration) -> Result<Vec<D>, ScanLaneError> + Send + Sync + 'static,
{
    fn scan_blocking(
        &self,
        workspace: &WorkspaceHandle,
        timeout: Duration,
    ) -> Result<Vec<D>, ScanLaneError> {
        (self)(workspace, timeout)
    }
}

/// Schedules the static pass across every workspace in parallel and
/// merges the results into a [`RunBundle`].
#[derive(Debug, Clone)]
pub struct RunDispatcher {
    static_concurrency: usize,
    per_repo_timeout: Duration,
    event_sink: Option<EventSink>,
}

impl RunDispatcher {
    /// Build a dispatcher from the operator's `[performance]` block and
    /// the planned repo count. The optional [`EventSink`] is the
    /// broadcast bus; WebSocket subscribers attach by calling
    /// [`tokio::sync::broadcast::Sender::subscribe`] on the same
    /// sender without any signature change here.
    pub fn from_config(
        cfg: &PerformanceConfig,
        repo_count: usize,
        event_sink: Option<EventSink>,
    ) -> Self {
        let concurrency = resolve_concurrency(cfg.static_concurrency_override(), repo_count);
        Self {
            static_concurrency: concurrency,
            per_repo_timeout: cfg.per_repo_timeout(),
            event_sink,
        }
    }

    /// Test-friendly constructor.
    pub fn with_explicit(
        static_concurrency: usize,
        per_repo_timeout: Duration,
        event_sink: Option<EventSink>,
    ) -> Self {
        Self { static_concurrency: static_concurrency.max(1), per_repo_timeout, event_sink }
    }

    pub fn static_concurrency(&self) -> usize {
        self.static_concurrency
    }

    pub fn per_repo_timeout(&self) -> Duration {
        self.per_repo_timeout
    }

    /// Drive a project-scoped run.
    ///
    /// The `lane` is shared across rayon workers via `Arc`. The
    /// `workspaces` list is consumed; each [`WorkspaceHandle`] is
    /// dropped when its rayon job returns, which fires the per-run
    /// snapshot cleanup installed during ingestion. The returned
    /// [`RunBundle`] carries only per-repo names + outcomes; it
    /// does **not** keep workspaces alive past dispatch. Downstream
    /// callers that need the snapshot to survive (e.g. the sandbox
    /// lane) must hold their own [`WorkspaceHandle`] clones before
    /// calling `dispatch_project`.
    ///
    /// Lifecycle event order on the bus:
    /// `RunStarted` → `ProjectStarted` → (per-repo events) →
    /// `ProjectFinished` → `RunFinished`. Every per-repo event carries
    /// the project's id so subscribers can group without a side lookup.
    pub fn dispatch_project<L, D>(
        &self,
        project: &Project,
        run: Run,
        lane: Arc<L>,
        workspaces: Vec<WorkspaceHandle>,
    ) -> RunBundle<D>
    where
        L: ScanLane<D> + ?Sized,
        D: Send + 'static,
    {
        let project_id = project.id.as_str().to_string();
        self.emit(AgentEvent::Run {
            data: RunEvent::RunStarted {
                run_id: run.id.clone(),
                project_id: project_id.clone(),
                repos: workspaces.iter().map(|w| w.name().to_string()).collect(),
                started_at_ms: run.started_at_ms,
            },
        });
        self.emit(AgentEvent::Run {
            data: RunEvent::ProjectStarted {
                run_id: run.id.clone(),
                project_id: project_id.clone(),
                project_name: project.name.clone(),
                started_at_ms: run.started_at_ms,
            },
        });

        let pool = ThreadPoolBuilder::new()
            .num_threads(self.static_concurrency)
            .thread_name(|i| format!("nyx-static-{i}"))
            .build()
            .expect("rayon thread pool");

        let wall_start = Instant::now();
        let dispatcher_view = DispatcherView {
            run_id: run.id.clone(),
            project_id: project_id.clone(),
            timeout: self.per_repo_timeout,
            event_sink: self.event_sink.clone(),
        };
        let lane_for_pool = Arc::clone(&lane);
        let bundles: Vec<RepoBundle<D>> = pool.install(|| {
            workspaces
                .into_par_iter()
                .map(|ws| run_one_repo(&ws, &lane_for_pool, &dispatcher_view))
                .collect()
        });
        let wall_clock_ms = wall_start.elapsed().as_millis() as i64;
        let finished_at_ms = now_epoch_ms();

        let mut counts = RunCounts::default();
        for b in &bundles {
            match b.outcome.tag() {
                RepoOutcomeTag::Success => counts.succeeded += 1,
                RepoOutcomeTag::Inconclusive => counts.inconclusive += 1,
                RepoOutcomeTag::Failed => counts.failed += 1,
            }
        }

        self.emit(AgentEvent::Run {
            data: RunEvent::ProjectFinished {
                run_id: run.id.clone(),
                project_id: project_id.clone(),
                finished_at_ms,
            },
        });
        self.emit(AgentEvent::Run {
            data: RunEvent::RunFinished {
                run_id: run.id.clone(),
                project_id: project_id.clone(),
                finished_at_ms,
                wall_clock_ms,
                succeeded: counts.succeeded,
                inconclusive: counts.inconclusive,
                failed: counts.failed,
            },
        });

        let callgraph = CrossRepoCallgraphStub {
            nodes: bundles
                .iter()
                .filter(|b| matches!(b.outcome.tag(), RepoOutcomeTag::Success))
                .map(|b| b.repo.clone())
                .collect(),
            edges: Vec::new(),
        };

        RunBundle {
            run_id: run.id,
            started_at_ms: run.started_at_ms,
            finished_at_ms,
            wall_clock_ms,
            per_repo: bundles,
            callgraph,
        }
    }

    fn emit(&self, ev: AgentEvent) {
        if let Some(sink) = &self.event_sink {
            // A closed bus is fine: subscribers may not be attached yet
            // (the websocket attaches lazily). Discard the send error
            // so the static pass keeps running.
            let _ = sink.send(ev);
        }
    }
}

struct DispatcherView {
    run_id: String,
    project_id: String,
    timeout: Duration,
    event_sink: Option<EventSink>,
}

impl DispatcherView {
    fn emit(&self, ev: AgentEvent) {
        if let Some(sink) = &self.event_sink {
            let _ = sink.send(ev);
        }
    }
}

fn run_one_repo<L, D>(
    workspace: &WorkspaceHandle,
    lane: &Arc<L>,
    view: &DispatcherView,
) -> RepoBundle<D>
where
    L: ScanLane<D> + ?Sized,
{
    let started_at_ms = now_epoch_ms();
    let start = Instant::now();
    view.emit(AgentEvent::Run {
        data: RunEvent::RepoStarted {
            run_id: view.run_id.clone(),
            project_id: view.project_id.clone(),
            repo: workspace.name().to_string(),
            started_at_ms,
        },
    });

    let result = lane.scan_blocking(workspace, view.timeout);
    let elapsed_ms = start.elapsed().as_millis() as i64;
    let finished_at_ms = now_epoch_ms();

    let outcome = match result {
        Ok(diags) => {
            view.emit(AgentEvent::Run {
                data: RunEvent::RepoStaticDone {
                    run_id: view.run_id.clone(),
                    project_id: view.project_id.clone(),
                    repo: workspace.name().to_string(),
                    n_diags: diags.len() as u32,
                    elapsed_ms,
                },
            });
            RepoOutcome::Success(diags)
        }
        Err(ScanLaneError::Timeout) => {
            view.emit(AgentEvent::Run {
                data: RunEvent::RepoFailed {
                    run_id: view.run_id.clone(),
                    project_id: view.project_id.clone(),
                    repo: workspace.name().to_string(),
                    message: format!("static-pass timeout after {}s", view.timeout.as_secs()),
                    elapsed_ms,
                },
            });
            RepoOutcome::Inconclusive(InconclusiveReason::StaticPassTimeout)
        }
        Err(ScanLaneError::Failed(msg)) => {
            view.emit(AgentEvent::Run {
                data: RunEvent::RepoFailed {
                    run_id: view.run_id.clone(),
                    project_id: view.project_id.clone(),
                    repo: workspace.name().to_string(),
                    message: msg.clone(),
                    elapsed_ms,
                },
            });
            RepoOutcome::Failed(msg)
        }
    };

    view.emit(AgentEvent::Run {
        data: RunEvent::RepoFinished {
            run_id: view.run_id.clone(),
            project_id: view.project_id.clone(),
            repo: workspace.name().to_string(),
            outcome: outcome.tag(),
            elapsed_ms,
        },
    });

    RepoBundle {
        repo: workspace.name().to_string(),
        outcome,
        started_at_ms,
        finished_at_ms,
        elapsed_ms,
    }
}

fn resolve_concurrency(override_value: Option<usize>, repo_count: usize) -> usize {
    if repo_count == 0 {
        return 1;
    }
    if let Some(n) = override_value {
        return n.max(1);
    }
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    std::cmp::max(1, std::cmp::min(cores / 2, repo_count))
}

static RUN_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Canonical run-id minter. Format: `run-<ms-hex>-<counter-hex>`.
///
/// The counter component keeps the id unique even when two runs
/// start inside the same millisecond. An older `as_secs()`-derived
/// id collided on the snapshot directory under
/// `<state>/repos/<name>/snapshots/<run_id>/`.
pub fn mint_run_id() -> String {
    let ms = now_epoch_ms();
    let n = RUN_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("run-{ms:013x}-{n:08x}")
}

/// Build a [`WorkspaceHandle`] from an [`IngestedRepo`]. The dispatcher
/// owns the handle for the duration of the run, but callers may clone
/// it cheaply (Arc inside) to keep the snapshot alive for downstream
/// sandbox / chain consumers.
pub fn workspace_handle_from(ingested: IngestedRepo) -> WorkspaceHandle {
    WorkspaceHandle::new(ingested)
}

/// Test helper that returns the workspace path without exposing the
/// inner [`IngestedRepo`] to callers outside the crate.
pub fn workspace_path(handle: &WorkspaceHandle) -> &Path {
    handle.workspace()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectId;
    use crate::repo::{Repo, RepoSource};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::thread::sleep;
    use tokio::sync::broadcast;

    fn handle_for(name: &str, path: &Path) -> WorkspaceHandle {
        let ingested = IngestedRepo {
            name: name.to_string(),
            workspace: path.to_path_buf(),
            source: RepoSource::LocalPath { path: path.to_path_buf() },
            snapshot_backend: None,
            on_disk_git_remote: None,
            cleanup: None,
        };
        WorkspaceHandle::new(ingested)
    }

    fn test_project() -> Project {
        Project {
            id: ProjectId::new("test-project"),
            name: "test-project".to_string(),
            description: None,
            target_base_url: None,
            env_config: None,
        }
    }

    fn _types_compile_for_repo(_: &Repo) {}

    #[test]
    fn mint_run_id_is_unique_within_one_ms() {
        let a = mint_run_id();
        let b = mint_run_id();
        assert_ne!(a, b, "counter must distinguish ids minted in the same ms");
    }

    #[test]
    fn mint_run_id_is_lexicographically_increasing_within_one_ms() {
        let a = mint_run_id();
        let b = mint_run_id();
        assert!(b > a, "minter must keep run ids monotonic within one ms");
    }

    #[test]
    fn resolve_concurrency_falls_back_to_min_of_cores_and_repos() {
        // Override always wins.
        assert_eq!(resolve_concurrency(Some(3), 8), 3);
        // Empty repo list -> 1, never 0.
        assert_eq!(resolve_concurrency(None, 0), 1);
        // Override of 0 floored to 1 by config layer; dispatcher also
        // floors defensively.
        assert_eq!(resolve_concurrency(Some(0), 4), 1);
        // Default never exceeds repo count.
        assert!(resolve_concurrency(None, 1) <= 1);
    }

    #[test]
    fn two_repos_scan_concurrently_under_sum_of_serial() {
        // Acceptance: a two-repo scan runs concurrently. We measure
        // wall clock vs sum-of-serial; with two repos sleeping 200 ms
        // each at concurrency = 2, the run should finish in ~200 ms,
        // not ~400 ms.
        let tmp_a = tempfile::tempdir().expect("a");
        let tmp_b = tempfile::tempdir().expect("b");
        let workspaces = vec![handle_for("alpha", tmp_a.path()), handle_for("beta", tmp_b.path())];

        let lane: Arc<dyn ScanLane<()>> =
            Arc::new(|_w: &WorkspaceHandle, _t: Duration| -> Result<Vec<()>, ScanLaneError> {
                sleep(Duration::from_millis(200));
                Ok(Vec::new())
            });
        let dispatcher = RunDispatcher::with_explicit(2, Duration::from_secs(5), None);
        let run = Run::with_id("run-test-concurrent");

        let start = Instant::now();
        let bundle = dispatcher.dispatch_project::<dyn ScanLane<()>, ()>(
            &test_project(),
            run,
            lane,
            workspaces,
        );
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(380),
            "expected concurrent fan-out (~200ms), got {elapsed:?}"
        );
        assert_eq!(bundle.per_repo.len(), 2);
        assert!(bundle.per_repo.iter().all(|b| matches!(b.outcome.tag(), RepoOutcomeTag::Success)));
    }

    #[test]
    fn slow_repo_timeout_does_not_block_fast_repo() {
        // Acceptance: slow-repo simulation under per_repo_timeout = 50ms
        // marks the repo timed-out without blocking the rest.
        let tmp_fast = tempfile::tempdir().expect("fast");
        let tmp_slow = tempfile::tempdir().expect("slow");
        let workspaces =
            vec![handle_for("fast", tmp_fast.path()), handle_for("slow", tmp_slow.path())];

        let timeout = Duration::from_millis(50);
        let lane: Arc<dyn ScanLane<()>> = Arc::new(
            move |w: &WorkspaceHandle, budget: Duration| -> Result<Vec<()>, ScanLaneError> {
                if w.name() == "slow" {
                    // Simulate the lane discovering it blew its budget.
                    sleep(budget + Duration::from_millis(50));
                    return Err(ScanLaneError::Timeout);
                }
                Ok(Vec::new())
            },
        );
        let dispatcher = RunDispatcher::with_explicit(2, timeout, None);
        let run = Run::with_id("run-test-timeout");

        let bundle = dispatcher.dispatch_project::<dyn ScanLane<()>, ()>(
            &test_project(),
            run,
            lane,
            workspaces,
        );

        let fast = bundle.per_repo.iter().find(|b| b.repo == "fast").expect("fast bundle");
        assert!(
            matches!(fast.outcome.tag(), RepoOutcomeTag::Success),
            "fast repo must finish despite slow neighbour timing out"
        );
        let slow = bundle.per_repo.iter().find(|b| b.repo == "slow").expect("slow bundle");
        match &slow.outcome {
            RepoOutcome::Inconclusive(InconclusiveReason::StaticPassTimeout) => {}
            other => panic!("expected StaticPassTimeout, got {other:?}"),
        }
        let counts = bundle.counts();
        assert_eq!(counts, RunCounts { succeeded: 1, inconclusive: 1, failed: 0 });
    }

    #[test]
    fn run_finished_event_is_published_when_sink_present() {
        let (tx, mut rx) = broadcast::channel::<AgentEvent>(16);
        let tmp = tempfile::tempdir().expect("tmp");
        let workspaces = vec![handle_for("solo", tmp.path())];
        let lane: Arc<dyn ScanLane<()>> =
            Arc::new(|_w: &WorkspaceHandle, _t: Duration| -> Result<Vec<()>, ScanLaneError> {
                Ok(Vec::new())
            });
        let dispatcher = RunDispatcher::with_explicit(1, Duration::from_secs(5), Some(tx.clone()));
        let run = Run::with_id("run-evt");
        let _ = dispatcher.dispatch_project::<dyn ScanLane<()>, ()>(
            &test_project(),
            run,
            lane,
            workspaces,
        );

        let mut saw_run_started = false;
        let mut saw_project_started = false;
        let mut saw_repo_started = false;
        let mut saw_repo_static_done = false;
        let mut saw_repo_finished = false;
        let mut saw_project_finished = false;
        let mut saw_run_finished = false;
        while let Ok(ev) = rx.try_recv() {
            if let AgentEvent::Run { data } = ev {
                match data {
                    RunEvent::RunStarted { .. } => saw_run_started = true,
                    RunEvent::ProjectStarted { .. } => saw_project_started = true,
                    RunEvent::RepoStarted { .. } => saw_repo_started = true,
                    RunEvent::RepoStaticDone { .. } => saw_repo_static_done = true,
                    RunEvent::RepoFinished { .. } => saw_repo_finished = true,
                    RunEvent::ProjectFinished { .. } => saw_project_finished = true,
                    RunEvent::RunFinished { .. } => saw_run_finished = true,
                    _ => {}
                }
            }
        }
        assert!(saw_run_started);
        assert!(saw_project_started);
        assert!(saw_repo_started);
        assert!(saw_repo_static_done);
        assert!(saw_repo_finished);
        assert!(saw_project_finished);
        assert!(saw_run_finished);
    }

    #[test]
    fn lane_failure_yields_failed_outcome() {
        let tmp = tempfile::tempdir().expect("tmp");
        let workspaces = vec![handle_for("broken", tmp.path())];
        let lane: Arc<dyn ScanLane<()>> =
            Arc::new(|_w: &WorkspaceHandle, _t: Duration| -> Result<Vec<()>, ScanLaneError> {
                Err(ScanLaneError::Failed("scanner crashed".to_string()))
            });
        let dispatcher = RunDispatcher::with_explicit(1, Duration::from_secs(5), None);
        let bundle = dispatcher.dispatch_project::<dyn ScanLane<()>, ()>(
            &test_project(),
            Run::with_id("run-fail"),
            lane,
            workspaces,
        );
        let b = bundle.per_repo.into_iter().next().expect("one bundle");
        match b.outcome {
            RepoOutcome::Failed(msg) => assert!(msg.contains("scanner crashed")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn callgraph_stub_lists_only_successful_repos() {
        let tmp_a = tempfile::tempdir().expect("a");
        let tmp_b = tempfile::tempdir().expect("b");
        let workspaces = vec![handle_for("ok", tmp_a.path()), handle_for("broken", tmp_b.path())];
        let lane: Arc<dyn ScanLane<u32>> =
            Arc::new(|w: &WorkspaceHandle, _t: Duration| -> Result<Vec<u32>, ScanLaneError> {
                if w.name() == "broken" {
                    Err(ScanLaneError::Failed("nope".to_string()))
                } else {
                    Ok(vec![1, 2, 3])
                }
            });
        let dispatcher = RunDispatcher::with_explicit(2, Duration::from_secs(1), None);
        let bundle = dispatcher.dispatch_project::<dyn ScanLane<u32>, u32>(
            &test_project(),
            Run::with_id("run-cg"),
            lane,
            workspaces,
        );
        assert_eq!(bundle.callgraph.nodes, vec!["ok".to_string()]);
        assert!(bundle.callgraph.edges.is_empty(), "cross-repo edges deferred");
        assert_eq!(bundle.counts().succeeded, 1);
    }

    #[test]
    fn rerun_on_identical_sources_produces_identical_finding_ids() {
        // Acceptance: re-running on identical sources produces identical
        // finding IDs. We model "the same scanner output" by returning a
        // fixed `(path, line, cap, rule)` tuple from the lane and feeding
        // it through `finding_id_hash` on both runs.
        use crate::store::finding_id_hash;
        let tmp = tempfile::tempdir().expect("tmp");
        let workspaces = vec![handle_for("solo", tmp.path())];
        let lane: Arc<dyn ScanLane<(String, i64, String, String)>> = Arc::new(
            |_w: &WorkspaceHandle,
             _t: Duration|
             -> Result<Vec<(String, i64, String, String)>, ScanLaneError> {
                Ok(vec![
                    ("src/a.rs".to_string(), 7, "sqli".to_string(), "rule-a".to_string()),
                    ("src/b.rs".to_string(), 12, "cmdi".to_string(), "rule-b".to_string()),
                ])
            },
        );
        let dispatcher = RunDispatcher::with_explicit(1, Duration::from_secs(5), None);

        let ids_from = |run_id: &str, bundle: &RunBundle<(String, i64, String, String)>| {
            let mut out = Vec::new();
            for repo_bundle in &bundle.per_repo {
                if let RepoOutcome::Success(rows) = &repo_bundle.outcome {
                    for (path, line, cap, rule) in rows {
                        out.push(finding_id_hash(&repo_bundle.repo, path, Some(*line), cap, rule));
                    }
                }
            }
            // Run id is intentionally not folded into finding_id_hash.
            let _ = run_id;
            out
        };

        let bundle_a = dispatcher.dispatch_project::<dyn ScanLane<_>, _>(
            &test_project(),
            Run::with_id("run-first"),
            Arc::clone(&lane),
            workspaces.clone(),
        );
        let bundle_b = dispatcher.dispatch_project::<dyn ScanLane<_>, _>(
            &test_project(),
            Run::with_id("run-second"),
            lane,
            workspaces,
        );
        let ids_a = ids_from("run-first", &bundle_a);
        let ids_b = ids_from("run-second", &bundle_b);
        assert_eq!(ids_a, ids_b, "finding ids must be run-id independent");
        assert!(ids_a.iter().all(|h| h.len() == 16), "ids are 16-hex-chars");
    }

    #[test]
    fn dispatch_visits_each_repo_exactly_once() {
        let tmp_a = tempfile::tempdir().expect("a");
        let tmp_b = tempfile::tempdir().expect("b");
        let tmp_c = tempfile::tempdir().expect("c");
        let workspaces = vec![
            handle_for("a", tmp_a.path()),
            handle_for("b", tmp_b.path()),
            handle_for("c", tmp_c.path()),
        ];
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_lane = Arc::clone(&counter);
        let lane: Arc<dyn ScanLane<()>> =
            Arc::new(move |_w: &WorkspaceHandle, _t: Duration| -> Result<Vec<()>, ScanLaneError> {
                counter_for_lane.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(Vec::new())
            });
        let dispatcher = RunDispatcher::with_explicit(2, Duration::from_secs(1), None);
        let bundle = dispatcher.dispatch_project::<dyn ScanLane<()>, ()>(
            &test_project(),
            Run::with_id("run-visit"),
            lane,
            workspaces,
        );
        assert_eq!(counter.load(AtomicOrdering::Relaxed), 3);
        let mut names: Vec<_> = bundle.per_repo.iter().map(|b| b.repo.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}

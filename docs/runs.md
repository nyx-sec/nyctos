# Runs

A **run** is one execution of a scan against a project's repos. The
dispatcher mints a run id, fans out the static pass per repo on a
rayon pool, aggregates the results into a `RunBundle`, and writes a
row into the `runs` SQLite table. Every event the run produces
carries the run id so subscribers can group across the bus and the
DB without a side lookup.

Source: `crates/nyctos-core/src/run/mod.rs`,
`crates/nyctos-core/src/store/run.rs`,
`crates/nyctos/src/main.rs` (the binary's `scan` subcommand).

## Run id

```
run-<unix-ms-as-13-hex>-<counter-as-8-hex>
```

The counter is a process-local `AtomicU64` bumped on every mint, so
two runs started inside the same millisecond still produce
different ids. Run ids sort lexicographically when minted from the
same process: the millisecond prefix dominates and the counter
breaks ties in order.

The minter lives at `crates/nyctos-core/src/run/mod.rs:494`.
Tests pin both the uniqueness and the monotonicity guarantee.

The id is intentionally not folded into the finding-id hash; see
[findings stability](#stability-across-runs) below.

## Lifecycle

A run walks one project at a time. `scan --project p`
(or `scan` against a single configured project) hands the
dispatcher:

- the resolved `Project`,
- a fresh `Run` (`Run::new()`),
- an `Arc<dyn ScanLane<Diag>>` (the production lane wraps
  `nyctos_nyx::NyxRunner`, which shells out to `nyx scan`),
- a `Vec<WorkspaceHandle>`, one per enabled repo.

`RunDispatcher::dispatch_project` runs synchronously on a
`tokio::task::spawn_blocking` worker. Inside, it:

1. Emits `RunStarted` then `ProjectStarted` on the event bus.
2. Builds a fresh rayon `ThreadPoolBuilder::new().num_threads(N)`
   pool where `N` is the resolved static-pass fan-out (see
   [concurrency](#concurrency)).
3. Maps every workspace into the pool with
   `into_par_iter().map(run_one_repo)`. Each `run_one_repo` call
   emits `RepoStarted`, calls the lane's `scan_blocking`, emits
   `RepoStaticDone` or `RepoFailed`, and always emits
   `RepoFinished` regardless of outcome.
4. Collects the per-repo outcomes into a `Vec<RepoBundle<D>>`.
5. Builds a `CrossRepoCallgraphStub` listing the repos that
   succeeded (edges are reserved for the cross-repo chain runner
   and stay empty today).
6. Emits `ProjectFinished` then `RunFinished` with the per-tag
   counts and wall-clock duration.

After dispatch returns, the `scan` subcommand persists every
`RepoOutcome::Success` diag through `persist_run_results`
(`crates/nyctos/src/main.rs:1243`), then calls `finalise_run`
to update the `runs` row's status, finished-at, and wall clock.

Lane errors are recoverable: a panicking rayon worker or a sqlx
failure between dispatch and finalise still flips the `runs` row
off `Running`. The `runs` row is never left wedged at `Running`
across process restart by the dispatch path.

## Concurrency

Default fan-out is `min(num_cpus / 2, repo_count)`, floored at 1.
`available_parallelism` failures fall back to 2 cores.

```toml
[performance]
# Override the per-run static-pass fan-out. Omit to let the
# dispatcher derive from CPU + repo count.
static_concurrency = 4

# Per-repo budget for the static pass. Default 1800 (30 minutes).
per_repo_timeout_secs = 600
```

A repo that exceeds its budget is recorded as
`Inconclusive(StaticPassTimeout)` and its `RepoFailed` event names
`static-pass timeout after Ns`. The slow repo never blocks the
rest of the run.

Configured `static_concurrency = 0` is floored to 1 by both the
config layer and the dispatcher. See
[`docs/config.md`](config.md) for the full `[performance]` block.

The resolver lives at
`crates/nyctos-core/src/run/mod.rs:475`.

## Per-repo outcomes

```rust
pub enum RepoOutcome<D> {
    Success(Vec<D>),
    Inconclusive(InconclusiveReason),
    Failed(String),
}
```

The only `InconclusiveReason` variant today is `StaticPassTimeout`;
the enum is shaped so the chain runner and sandbox lanes can add
their own variants without breaking serialised bundles.

The compressed `RepoOutcomeTag` (`Success` / `Inconclusive` /
`Failed`) rides on the `RepoFinished` event so a UI badge can
colour the row without deserialising the full bundle.

Counts roll up via `RunBundle::counts()` into a `RunCounts`
struct (`succeeded`, `inconclusive`, `failed`). The
`RunFinished` event carries these three numbers.

## Events

The dispatcher publishes through the shared
`broadcast::Sender<AgentEvent>` (`crates/nyctos-types/src/event.rs`).
Order is fixed:

```
RunStarted
  ProjectStarted
    RepoStarted (per repo, in pool order)
    RepoStaticDone | RepoFailed
    RepoFinished
  ProjectFinished
RunFinished
```

Per-repo events always carry the `project_id` so the WebSocket
client can group by project without a `GET /api/v1/repos/:name`
side trip. A closed bus (no subscribers) is fine: the send error
is dropped and the static pass keeps running. WebSocket
subscribers attach lazily through
[`docs/api.md`](api.md#events-websocket); the bus is created up
front with `broadcast::channel(N)` so an early subscriber sees
the very first `RunStarted`.

`RepoDynamicDone` is reserved for the sandbox publisher: the
static-pass dispatcher does not emit it. The variant lives in
`RunEvent` so the sandbox crate can publish on the same bus
without changing the event enum's shape.

## Persistence

Two tables touch each run:

| Table          | Written by                                  |
|----------------|---------------------------------------------|
| `runs`         | `finalise_run` (`status`, `finished_at`, `wall_clock_ms`) |
| `findings`     | `persist_run_results` (one row per static-pass diag) |
| `business_logic_template_runs` | Business-logic template synthesis counts and skip reasons. |
| `verification_attempts` | Live HTTP/browser verifier rows. Browser attempts attach replay artifact paths. |
| `verified_vulnerabilities` | User-facing confirmed vulnerabilities promoted from successful live attempts. |
| `attack_graph_nodes`, `attack_graph_edges` | Store dual-writes for route models, signals, candidates, verification attempts, verified vulnerabilities, and chains. |

The `runs` row schema (see
`crates/nyctos-core/src/store/run.rs:50`):

| Column                         | Notes                                  |
|--------------------------------|----------------------------------------|
| `id`                           | The minted run id.                     |
| `started_at`                   | epoch ms.                              |
| `finished_at`                  | epoch ms, NULL while running.          |
| `status`                       | `Pending` / `Running` / `Succeeded` / `Failed` / `Halted`. |
| `triggered_by`                 | `Manual` / `Cron` / `Webhook` / `PR` / `UI`. |
| `git_ref`                      | Optional git ref the scan ran against. |
| `parent_run_id`                | Optional pointer to a prior run.       |
| `wall_clock_ms`                | Dispatcher wall clock.                 |
| `total_ai_spend_usd_micros`    | Bumped by the AI runtime, not the dispatcher. |

`RunStore::list_by_status("Running")` is what
`GET /api/v1/runs?status=Running` reads; default with no query
string is `Running`. The endpoint also accepts `project_id` to keep
run lists scoped to one project. The full record shape is what
`GET /api/v1/runs/:id` returns. See
[`docs/api.md`](api.md#runs).

Graph rows are derivative and run-scoped. They let later consumers
walk from a verified vulnerability back to the evidence that produced
it, or from a route/object/role to the verified vulnerabilities that
touch it, without changing the existing finding and report shapes. See
[`attack-graph.md`](attack-graph.md).

Browser verification attempts persist replay evidence under
`<state>/traces/<run-id>/browser_verification/<attempt-id>/` and attach
those paths to the attempt row. Reports and the SPA surface those paths
through the vulnerability's `verification_attempt_ids`, so a human can
inspect screenshots, redacted DOM/console/timeline captures, and the
deterministic replay JSON/script for the proof.

## Stability across runs

Findings get stable, run-id-independent ids. Two runs over the
same source tree produce the same finding ids, so the UI's
last-seen / first-seen timestamps line up correctly and a finding
that appears once stays correlated across re-scans.

The hash domain is `(repo, path, Some(line), cap, rule)`. The run
id is intentionally **not** folded in. See
`finding_id_hash` at `crates/nyctos-core/src/store/finding.rs:79`
and the `rerun_on_identical_sources_produces_identical_finding_ids`
test in `run/mod.rs:749`.

## Workspaces and snapshots

Each repo lands inside the dispatcher as a `WorkspaceHandle`
(`crates/nyctos-core/src/run/workspace.rs`). The handle wraps
an `Arc<IngestedRepo>`, so clones are cheap and the snapshot
directory persists until the last clone drops. Production code
clones one handle into a name-keyed `HashMap` before dispatch so
the AI passes (payload synthesis, spec derivation, chain
reasoning) can read source after the dispatcher consumes the
original `Vec`. The dispatcher's bundle keeps **only** per-repo
names and outcomes; it does not extend snapshot lifetime.

Snapshot layout and cleanup live in
[`docs/state-dir.md`](state-dir.md). Repo ingestion details live
in [`docs/architecture.md`](architecture.md).

## Triggers

Runs originate from one of five surfaces. The
`triggered_by` column records which:

- `Manual`: operator ran `nyctos scan` from the CLI.
- `Cron`: in-process scheduler fired a `[[schedule]]` entry. See
  [`docs/triggers/cron.md`](triggers/cron.md).
- `Webhook`: `POST /webhook/git` was verified. See
  [`docs/triggers/webhook.md`](triggers/webhook.md).
- `PR`: the GitHub Action ran a scan against a pull request. See
  [`docs/ci/github-actions.md`](ci/github-actions.md).
- `UI`: the SPA dispatched a scan through the API.

## Related

- [`docs/cli.md#scan`](cli.md#scan): every flag the `scan`
  subcommand accepts.
- [`docs/config.md`](config.md): the full `[performance]` block.
- [`docs/api.md`](api.md): the `/runs` routes and the WebSocket
  event stream.
- [`docs/architecture.md`](architecture.md): the broader
  dispatcher + AI-pass pipeline this page details.

# Architecture

Nyx Agent ships as one binary, `nyx-agent`, that runs as a local daemon.
This page maps the workspace crates, the subprocess boundary to the
upstream `nyx` scanner, the in-process event bus, and the layout of
the tokio runtime that drives the whole thing.

If you only want operator details (paths, ports, flags) read
[`cli.md`](cli.md), [`config.md`](config.md), or
[`state-dir.md`](state-dir.md) instead.

## Crate map

The workspace lives under `crates/` and breaks into eight crates.
Dependencies fan in toward `nyx-agent-types`; nothing depends on
`nyx-agent`. There are no cycles.

| Crate                 | Role                                                                                | Depends on                                                |
|-----------------------|-------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `nyx-agent-types`        | Wire types shared across every crate: events, findings, agent task envelopes, repo + run shapes, budget rows. `ts_rs` derives generate `frontend/src/api/types.gen.ts` from these. | (leaf)                                                    |
| `nyx-agent-core`      | Persistence, config parsing, run dispatcher, repo ingestion, report rendering, state directory layout. Owns the SQLx-backed `Store`. | `nyx-agent-types`                                            |
| `nyx-agent-nyx`       | Subprocess driver for the GPL `nyx` scanner. Resolves the binary, enforces a minimum version, spawns `nyx scan --format json`, parses diagnostics. | `nyx-agent-core`, `nyx-agent-types`                          |
| `nyx-agent-ai`        | Vendor-neutral `AiRuntime` trait plus adapters (Anthropic SDK, Claude Code CLI) and task templates (exploration, novel findings). | `nyx-agent-nyx`, `nyx-agent-types`                           |
| `nyx-agent-sandbox`   | Sandbox `Sandbox` trait, five backends (process, birdcage, libkrun, firecracker, docker), chain-lane env-builder, payload runner, shim binary. | `nyx-agent-core`, `nyx-agent-types`                          |
| `nyx-agent-api`       | Axum router, `ServerState`, bearer-auth middleware, WebSocket event stream, HMAC git webhook. | `nyx-agent-core`, `nyx-agent-sandbox`, `nyx-agent-types`     |
| `nyx-agent-ui`        | SPA embed glue. `build.rs` builds the React app and `lib.rs` serves the static bundle plus `/setup.json` bootstrap. | (none)                                                    |
| `nyx-agent`           | The binary. Wires every other crate together, owns `main`, the `clap` CLI, the in-process scan worker, and the cron scheduler. | every other crate                                         |

A few invariants the crate split protects:

- Shared types belong in `nyx-agent-types`. No other crate exports a
  type that crosses a crate boundary; if you find a duplicate
  `struct Foo` in two crates, one of them is wrong.
- `nyx-agent-sandbox` does not depend on `nyx-agent-api`, and
  `nyx-agent-ai` does not depend on `nyx-agent-sandbox`. Both
  surfaces are wired together inside the binary, not by linking the
  layers directly.
- The `nyx` scanner is consumed through `nyx-agent-nyx` and only
  through `nyx-agent-nyx`. See the subprocess boundary section.

## Process model

`nyx-agent serve` is a single async process. The runtime is built
by `#[tokio::main]` at the top of `crates/nyx-agent/src/main.rs`
and drives four concurrent surfaces:

1. **HTTP server.** `axum::serve` on the listener returned by
   `tokio::net::TcpListener::bind`. The router is built in
   `nyx_agent_api::build_router` and falls back to the embedded SPA
   for unknown paths. Default bind is `127.0.0.1:8765` (see
   [`config.md`](config.md)).
2. **Scan worker.** A `tokio::sync::mpsc` channel feeds an inline
   task in `serve` (`crates/nyx-agent/src/main.rs:937`). API
   handlers and the cron scheduler push `ScanRequest`s onto the
   channel; the worker spawns one `tokio::spawn` per request that
   calls `run_scan_for_api`, which in turn drives the run
   dispatcher.
3. **Run dispatcher.** `nyx_agent_core::run::RunDispatcher`
   schedules per-repo static-pass work onto a rayon thread pool
   sized by `[performance] static_concurrency` (defaults to
   `min(num_cpus / 2, repo_count)`). Each rayon worker calls the
   `ScanLane` trait, which the binary wires to a
   `nyx_agent_nyx::NyxRunner`. See
   `crates/nyx-agent-core/src/run/mod.rs:270`.
4. **Event replay tap.** A separate `tokio::spawn` subscribes to
   the broadcast channel and feeds every event into
   `ServerState.replay`, so WebSocket clients that attach mid-run
   still see `RunStarted` and early `RepoStarted` frames.

The cron scheduler in `crates/nyx-agent/src/scheduler.rs` runs as
another spawned task when `[[schedule]]` entries are configured.
It evaluates cron expressions on a 60s tick and pushes
`ScanRequest`s onto the same mpsc channel the API uses, so a
scheduled scan and an API-triggered scan are indistinguishable
once they reach the worker.

## Subprocess boundary to `nyx`

The upstream `nyx` scanner is GPL-3.0-or-later. `nyx-agent` is
AGPL-3.0-or-later. Nyx Agent consumes `nyx` only through `fork`/`exec`,
never as a linked library, so the scanner keeps its own release and
repository boundary:

- `nyx_agent_nyx::NyxRunner::discover` resolves the binary via
  `Config::nyx.binary` (operator override) or `$PATH`, then runs
  `nyx --version` and refuses to start if the version is below
  `MINIMUM_NYX_VERSION` (currently `0.7.0`, see
  `crates/nyx-agent-nyx/src/runner.rs`).
- `NyxRunner::scan` spawns `nyx scan --format json --no-index
  <repo>` with `--verify` if the lane asks for verification.
  Stdout is redirected to a temp file (not a pipe) because the
  scanner's JSON output exceeds the kernel pipe buffer on large
  repos and would deadlock a piped reader.
- Stderr stays piped (bounded) and is captured into
  `ScanOutcome.stderr` for the run report.
- Timeouts are enforced by the runner via `tokio::time::timeout`
  on the child's `wait`; a timeout fires `start_kill` then
  `wait`, and the lane returns `ScanLaneError::Timeout`. The
  dispatcher records the repo as
  `InconclusiveReason::StaticPassTimeout` and lets the rest of
  the run finish.

If `nyx-agent` needs a scanner feature, file it against the `nyx`
repo. Never modify `nyx` from inside `nyx-agent`.

## Event bus

Every in-process event flows through a single
`tokio::sync::broadcast::Sender<AgentEvent>`, defined in
`crates/nyx-agent-types/src/event.rs`. The producer side is
`EventSink = broadcast::Sender<AgentEvent>`; consumers hold an
`EventStream` newtype around the matching receiver so the rest of
the codebase never names tokio's concrete receiver type.

Top-level variants of `AgentEvent`:

| Variant       | Producer                             | Consumer                                                      |
|---------------|--------------------------------------|---------------------------------------------------------------|
| `Run`         | `RunDispatcher` and the scan worker  | WebSocket clients, the replay buffer, the run report renderer |
| `Ai`          | Every `AiRuntime` adapter            | WebSocket clients, the `budgets` table updater                |
| `Sandbox`     | Sandbox backends (reserved today)    | (reserved)                                                    |
| `Finding`     | Finding writer (reserved today)      | (reserved)                                                    |
| `Budget`      | Budget tracker (reserved today)      | (reserved)                                                    |
| `Quarantine`  | Quarantine writer (reserved today)   | (reserved)                                                    |
| `Repro`       | Repro bundle writer (reserved today) | (reserved)                                                    |

`RunEvent` carries the full lifecycle order
`RunStarted -> ProjectStarted -> (per repo events) -> ProjectFinished -> RunFinished`,
with the project id threaded through every per-repo frame so
subscribers can group without a side lookup. See
`crates/nyx-agent-types/src/event.rs:26` for the field list.

The broadcast channel has a fixed capacity of 256 frames (set in
`serve`); a lagging subscriber sees `Lagged(_)` and resyncs from
the replay buffer.

## Storage

All persistence goes through `nyx_agent_core::store::Store`, a
SQLx + SQLite handle that wraps a per-table accessor pattern:
`store.repos()`, `store.runs()`, `store.findings()`, and so on.
Each accessor returns a stateless helper that owns no connection;
the pool is shared via `Arc` inside `Store`.

Tables live under `crates/nyx-agent-core/src/store/`: `repo`,
`run`, `finding`, `payload`, `chain`, `candidate`, `spec`,
`trace`, `budget`, `feedback`, `repro`, `project`, `schedule`,
`webhook`, `product`, and `attack_graph`. SQLx migrations live
alongside; the prepared-query cache regen flow is documented in
[`dev/sqlx.md`](dev/sqlx.md).

The attack graph is a run-scoped index over existing artifacts, not
a replacement for them. Route models, Nyx signals, pentest
candidates, verification attempts, verified vulnerabilities, and
chains dual-write graph nodes / edges so callers can ask "what
evidence led to this vuln?" and "what vulns touch this route,
object, or role?" See [`attack-graph.md`](attack-graph.md).

The state directory layout (where the SQLite file, logs, repo
workspaces, and repro bundles land) is documented in
[`state-dir.md`](state-dir.md).

## AI runtime

The `AiRuntime` trait in
`crates/nyx-agent-ai/src/runtime.rs:18` is vendor-neutral. Shipped
adapters cover the Anthropic Messages API, OpenAI-compatible local
`/v1` endpoints, Claude Code CLI, and Codex CLI. They all publish
`AgentEvent::Ai` frames into the same broadcast bus the run
dispatcher uses, keyed by a task id the caller supplies so multiple
in-flight `one_shot` calls can be demultiplexed.

Determinism: every task seeds from `BLAKE3(run_id || task_id)`,
and adapters that support deterministic sampling set
`temperature: 0`. Adapters that do not advertise via
`supports_deterministic_sampling()` returning `false`.

## Sandbox

The `Sandbox` trait in `crates/nyx-agent-sandbox/src/lib.rs:354`
runs one short-lived child process per agent task. Backends ship
in `crates/nyx-agent-sandbox/src/backend/`: `process` (no
isolation upgrade), `birdcage` (Linux landlock + seccomp, macOS
Seatbelt), `libkrun` (macOS HVF, Linux KVM), `firecracker`
(Linux KVM), `docker` (chain-lane fallback). Backend selection
runs per scan lane: see `select_backend` in
`crates/nyx-agent-sandbox/src/lib.rs:158`.

The `birdcage` backend spawns through a shim binary
(`nyx-sandbox-shim`) so seccomp profiles applied by the
`birdcage` crate cannot collide with the daemon's own syscall
needs. The shim lives at
`crates/nyx-agent-sandbox/src/bin/nyx_sandbox_shim.rs`.

## Frontend embed

`nyx-agent-ui`'s `build.rs` runs `pnpm build` against `frontend/`
in release builds and bakes the resulting `dist/` into the binary
via `rust-embed`. Debug builds skip the build step and proxy
through `frontend/`'s dev server. The two-mode behavior is
documented in [`dev/frontend.md`](dev/frontend.md).

`/setup.json` is served separately from the embedded bundle: the
SPA fetches it on boot to discover the bearer token (when auth is
enforced) and the daemon's setup state. See
`crates/nyx-agent-ui/src/lib.rs`.

## Related pages

- [`install.md`](install.md): toolchain, build flags, and the
  `nyx` binary dependency.
- [`cli.md`](cli.md): every `nyx-agent` subcommand and the
  daemon entry point.
- [`config.md`](config.md): every TOML section, including the
  `[performance]`, `[sandbox]`, and `[ai]` knobs referenced above.
- [`state-dir.md`](state-dir.md): on-disk paths the daemon
  reads and writes.
- [`api.md`](api.md): the HTTP and WebSocket surface that the
  router and event bus serve.

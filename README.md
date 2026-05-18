<!-- nyx: verbatim -->
# Nyctos

Nyctos is a self-hosted security analysis daemon that wraps the `nyx`
scanner with an AI-driven exploit-synthesis layer and a full-environment
sandbox. It runs continuously across your repositories, validates
findings inside an isolated dev environment, and emits reproducible
evidence for every exploitable finding.

The shipping binary is `nyx-agent`; the rename to `nyctos` is queued
as its own phase (see Naming below).
<!-- /nyx: verbatim -->

## Licensing

Nyctos is **source-available** software, distributed under the PolyForm
Small Business License 1.0.0. The PolyForm license is not OSI-approved,
so Nyctos is not OSS. Do not describe it as such in public
communication.

- Free for personal use, research, hobby projects, OSS contribution, and
  any organisation that qualifies as a Small Business under the license
  (fewer than 100 staff and less than $1,000,000 USD annual revenue).
- A commercial license is required for organisations above that
  threshold. See `LICENSE.md` for the verbatim license text and contact
  details.

The upstream `nyx` core scanner is a separate project under
GPL-3.0-or-later. That GPL-licensed scanner is the OSS component of the
stack; the `nyx-agent` daemon in this repository is not.

## Naming

**Nyctos** (Greek genitive of `Nyx`, "of-the-night") is the product
brand. The shipping crates, binary (`nyx-agent`), config
(`nyctos.toml`), and state directory (`~/.local/share/nyctos/`)
still carry their legacy names; the code rename to `nyctos` is queued
as its own phase. The upstream dynamic-verification engine `nyx`
(GPL-3.0-or-later) keeps its name. Full target surface at
`.pitboss/nyctos-spec.md`.

## Status

Pre-MVP. Phases 01-27 of `.pitboss/play/plan.md` have landed: the
cargo workspace, SQLite store, `nyx` subprocess driver, parallel run
aggregator, Axum HTTP/WebSocket API, the embedded SPA (first-launch
wizard, project + repo manager, findings browser, live scan view,
quarantine + AI trace viewer), two AI runtime adapters (Anthropic
SDK and Claude Code) wired to four agent tasks (PayloadSynthesis,
SpecDerivation, ChainReasoning, NovelFindingDiscovery), the sandbox
fast lane (birdcage) and chain lane (libkrun / Firecracker / Docker
with auto-selection), env-builder docker-compose spinup, the
cross-repo chain runner, reports + repro bundles, the GitHub
Actions composite for PR gating, and the cron + webhook scan
triggers. Phase 28 (end-to-end demo fixture) is in flight; phases
29 (MVP polish) and 30 (closed-beta packaging) follow before tag.

`nyx-agent doctor` prints the runtime probes the daemon uses at
startup:

![nyx-agent doctor output showing state dir, config, SQLite schema v2, resolved nyx scanner version, claude-code adapter, sandbox chain lane on docker, sandbox fast lane on birdcage, scheduler and webhook status](assets/screenshots/cli-doctor.png)

## Documentation

Operator-facing docs live under [`docs/`](docs/); the
[`docs/SUMMARY.md`](docs/SUMMARY.md) index lists every page. Start
here:

- [`docs/install.md`](docs/install.md): prerequisites, source build,
  and `nyx-agent doctor`.
- [`docs/quickstart.md`](docs/quickstart.md): first daemon, first
  project, first scan, first findings.
- [`docs/triggers/cron.md`](docs/triggers/cron.md) and
  [`docs/triggers/webhook.md`](docs/triggers/webhook.md): no-touch
  scan triggers.
- [`docs/ci/github-actions.md`](docs/ci/github-actions.md): the
  shipped composite Action for PR gating.

### Quickstart in three commands

Repos in Nyctos are always nested under a `Project`. A fresh
install reaches a first scan in three steps:

```bash
nyx-agent project create acme-app --target-base-url http://localhost:3000
nyx-agent project add-repo acme-app acme-backend --path /abs/path/backend --i-own-this
nyx-agent scan --project acme-app
```

`nyx-agent --help` shows the rest of the surface (scan, project,
pr-comment, reverify, inspect, budget, traces, doctor, serve) plus
the top-level flags every subcommand inherits:

![nyx-agent --help output listing the nine subcommands (scan, project, pr-comment, reverify, inspect, budget, traces, doctor, serve) and the top-level --config, --state-dir, --log-level flags](assets/screenshots/cli-help.png)

See [`docs/quickstart.md`](docs/quickstart.md) for the worked
walkthrough (wizard, TOML form, HTTP form, output shape) and
[`docs/cli.md#project`](docs/cli.md) for the full `project`
subcommand reference.

## Upstream `nyx` scanner

`nyx-agent` shells out to the upstream `nyx` static scanner; the agent has
no FFI link against it. The `nyx` binary must be installed and discoverable:

- by default on `PATH` (verify with `which nyx`), or
- via `[nyx].binary_path = "/abs/path/to/nyx"` in `nyctos.toml`.

`nyx-agent doctor` reports the resolved path, the detected version, and the
minimum supported version. It exits non-zero when the binary is missing or
below the minimum.

## Working with the SQLite store

`nyx-agent-core` uses SQLx's compile-time-checked query macros against a
SQLite schema shipped under `crates/nyx-agent-core/migrations/`. Recorded
query plans live in `.sqlx/` at the workspace root and are checked into
version control so the workspace builds without a database present (CI
runs with `SQLX_OFFLINE=true`).

If you add, remove, or modify a `sqlx::query!` / `sqlx::query_as!` call,
regenerate the cache:

```
cargo install sqlx-cli --no-default-features --features sqlite,rustls
rm -f /tmp/sqlx-prepare.db
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" sqlx database create
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" \
    sqlx migrate run --source crates/nyx-agent-core/migrations
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" \
    cargo sqlx prepare --workspace
```

Commit the resulting `.sqlx/` changes. CI fails if the cache is stale.

## Frontend SPA workflow

The `nyx-agent` daemon serves a single-page UI at `/`. The
`nyx-agent-ui` crate embeds the SPA assets via `rust_embed`, and the
embed contents depend on the cargo build profile.

### Release builds

`cargo build --release` (or any profile equal to `release`) runs the
real frontend build inside `crates/nyx-agent-ui/build.rs`:

1. `npm ci --silent` in `frontend/` if `node_modules/` is absent.
2. `npm run build`, producing `frontend/dist/`.
3. The dist tree is mirrored into `crates/nyx-agent-ui/dist/` so
   `rust_embed` picks it up at compile time.

A release build with a missing or broken `frontend/` checkout fails
the build script with a panic. Set `NYCTOS_SKIP_FRONTEND_BUILD=1` to
opt out and ship the stub instead (used by environments that build
the SPA separately and prepopulate `crates/nyx-agent-ui/dist/`).

### Debug builds

`cargo run` and `cargo build` (no `--release`) write a tiny stub
`index.html` into `crates/nyx-agent-ui/dist/` that explains the
situation and points at `/api/v1/health`. The stub keeps `GET /`
returning a usable page in CI environments without Node installed.

For an iterative dev loop, run two processes side by side:

```sh
# Terminal 1: daemon on 127.0.0.1:8765.
cargo run -p nyx-agent -- serve

# Terminal 2: Vite dev server on 127.0.0.1:5173, proxying /api to 8765.
cd frontend && npm install && npm run dev
```

Open `http://127.0.0.1:5173/` for the hot-reload SPA. The daemon at
`:8765` still answers `/api/v1/...` directly, so curl-based testing
against `:8765` keeps working without Vite running.

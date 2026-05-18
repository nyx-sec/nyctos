<!-- nyx: verbatim -->
# Nyctos

Nyctos is a self-hosted security analysis daemon that wraps the `nyx`
scanner with an AI-driven exploit-synthesis layer and a full-environment
sandbox. It runs continuously across your repositories, validates
findings inside an isolated dev environment, and emits reproducible
evidence for every exploitable finding.

The shipping binary is `nyx-agent` (the binary will be renamed to `nyctos` in a future phase; see Naming + rename status below).
<!-- /nyx: verbatim -->

## Naming + rename status

The product brand is **Nyctos** (Greek genitive of `Nyx`, literally "of-the-night"). The supporting cargo workspace, binary, config file, state directory, and service unit currently still use the legacy `nyx-agent` / `nyx-pro` identifiers. Renaming those to `nyctos` is queued as its own dedicated phase. Until that phase lands:

- Public-facing prose, marketing, and design docs use **Nyctos**.
- CLI invocations, file paths, and crate names in this README and in code still read as `nyx-agent` / `nyx-agent-core` / `nyx-agent.toml` / `~/.local/share/nyx-agent/` because that is what currently ships.
- The OSS dynamic verification engine (`nyx`, GPL-3.0-or-later) keeps its name. The Nyctos rename only touches the commercial product layer that wraps it.

See `.pitboss/nyctos-spec.md` for the target naming surface in full.

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

## Status

Early scaffolding. See `.pitboss/play/plan.md` for the phased delivery
plan; this commit lands Phase 01 (cargo workspace + CI guards).

## Documentation

Operator-facing docs live under [`docs/`](docs/). Start here:

- [`docs/install.md`](docs/install.md): prerequisites, source build,
  and `nyx-agent doctor`.
- [`docs/quickstart.md`](docs/quickstart.md): first daemon, first
  scan, first findings.
- [`docs/triggers/cron.md`](docs/triggers/cron.md) and
  [`docs/triggers/webhook.md`](docs/triggers/webhook.md): no-touch
  scan triggers.
- [`docs/ci/github-actions.md`](docs/ci/github-actions.md): the
  shipped composite Action for PR gating.

## Upstream `nyx` scanner

`nyx-agent` shells out to the upstream `nyx` static scanner; the agent has
no FFI link against it. The `nyx` binary must be installed and discoverable:

- by default on `PATH` (verify with `which nyx`), or
- via `[nyx].binary_path = "/abs/path/to/nyx"` in `nyx-agent.toml`.

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
the build script with a panic. Set `NYX_SKIP_FRONTEND_BUILD=1` to
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

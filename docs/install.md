# Install

This page walks through building Nyctos from source and wiring its
external dependencies. The shipping binary is `nyx-agent`; the product
brand is "Nyctos". Both names appear here for the reasons explained in
`README.md`.

Nyctos has no prebuilt packages yet. Every install is a source build
against the workspace in this repository.

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Rust toolchain | 1.83 or newer, channel `stable` | Pinned in `rust-toolchain.toml`. `rustup` picks it up automatically on first `cargo` invocation. |
| `nyx` static scanner | 0.7.0 or newer | External GPL-3.0 binary spawned as a subprocess. See [Install the `nyx` scanner](#install-the-nyx-scanner). |
| Node.js + `npm` | Node 18+ | Required only for `cargo build --release` (the release build bundles the SPA). Debug builds ship a stub page and skip Node. |
| `claude-code` CLI | recent | Optional. Required only if you intend to run the AI exploit-synthesis layer. See [Optional: claude-code](#optional-claude-code). |
| SQLite | bundled | Linked into the binary via SQLx; no system SQLite needed. |

Linux and macOS are the supported targets. Windows is untested.

## Build from source

```bash
git clone <repo-url> nyx-pro
cd nyx-pro
cargo build --release
```

`cargo build --release` runs `crates/nyx-agent-ui/build.rs`, which
invokes `npm ci --silent` and `npm run build` inside `frontend/`,
then mirrors `frontend/dist/` into `crates/nyx-agent-ui/dist/` so
`rust_embed` can pick the assets up at compile time. A release build
fails loudly if Node is missing or the frontend build errors out: we
never want to ship a release binary with a stub UI.

If you build the SPA out-of-band (e.g. a CI job that prepopulates
`crates/nyx-agent-ui/dist/`), set `NYCTOS_SKIP_FRONTEND_BUILD=1` to skip
the npm step:

```bash
NYCTOS_SKIP_FRONTEND_BUILD=1 cargo build --release
```

Debug builds (`cargo build`, `cargo run`, `cargo nextest run`) write
a tiny stub `index.html` instead, so `/` keeps returning a usable
page in CI environments without Node.

The resulting binary lives at `target/release/nyx-agent`. Copy it
onto your `PATH` or invoke it directly.

## Install the `nyx` scanner

Nyctos shells out to the `nyx` binary; it has no FFI link against it.
The agent will not start scans without a usable `nyx`.

Two ways to make `nyx` discoverable, in order of preference:

1. Place `nyx` on `PATH`. Verify with `which nyx`.
2. Set `[nyx].binary_path = "/abs/path/to/nyx"` in `nyctos.toml`.

The minimum version is `0.7.0` (the `MINIMUM_NYX_VERSION` constant in
`crates/nyctos-nyx/src/runner.rs`). The floor pins to the upstream
release that introduced `evidence.flow_steps`, which the taint flow,
spec-derivation, and chain-reasoning passes all consume. Override per
install via `[nyx].min_version = "0.8.0"` in `nyctos.toml` if a
deployment needs a newer floor than the agent default; values below the
built-in floor are clamped up silently.

The upstream `nyx` scanner is GPL-3.0-or-later, distributed
separately. It is the only GPL component in the stack. Nyctos itself
is source-available under PolyForm Small Business 1.0.0; the two
licenses coexist because Nyctos never links against `nyx`, only
spawns it.

## Optional: claude-code

The AI exploit-synthesis layer (`crates/nyx-agent-ai`) drives the
`claude-code` agent-loop CLI as a subprocess. Without it the daemon
still starts, scans complete, and findings persist; only the AI
pipeline degrades to "unavailable".

To enable it, install Anthropic's `claude-code` CLI and put it on
`PATH` as `claude` (or, for older installs, `claude-code`; the
detector accepts either). `nyx-agent doctor` reports the resolved
binary and the captured `--version` string.

## State directory

On first launch the daemon creates a per-user state directory and
chmods it `0700`. The default location is resolved from the
platform's data dir:

| Platform | Default path |
|---|---|
| Linux | `~/.local/share/nyctos/` |
| macOS | `~/Library/Application Support/nyctos/` |

Override with `--state-dir /path/to/dir` (global flag) or
`[general].state_dir = "/path"` in `nyctos.toml`. The directory
holds the SQLite database, run snapshots, ingested repos, repro
bundles, logs, and the bearer-token file (`auth_token`, mode `0600`).

## Verify the install

`nyx-agent doctor` runs every health check the daemon performs at
startup and exits non-zero on any failure:

```bash
./target/release/nyx-agent doctor
```

Sample output:

```
state dir OK at /home/op/.local/share/nyctos
logs -> /home/op/.local/share/nyctos/logs/agent.jsonl
config not found at ./nyctos.toml (using defaults)
db OK at /home/op/.local/share/nyctos/state.db (schema v1)
nyx OK at /usr/local/bin/nyx (version 0.7.0, minimum 0.7.0)
claude-code: available v1.0.0 at /usr/local/bin/claude
sandbox chain lane -> birdcage (selected by host probe) [2 simultaneous, default]
sandbox fast lane  -> process (selected by host probe) [8 simultaneous, default]
```

Each line maps to a single check:

| Line | Means |
|---|---|
| `state dir OK` | State dir exists with mode `0700` and every subdirectory is present. |
| `logs -> <path>` | JSON log file location for this run. |
| `config OK` / `config not found` | Whether `nyctos.toml` was loaded or defaults applied. A missing config is not fatal. |
| `db OK ... schema v<N>` | SQLite opened and migrations are caught up. |
| `nyx OK` / `nyx FAIL` | The scanner binary is on `PATH` (or `[nyx].binary_path` resolved), and its `--version` is at or above `MINIMUM_NYX_VERSION`. |
| `claude-code: available` / `unavailable` | Informational only. Doctor exits zero with claude-code missing. |
| `sandbox chain lane` / `sandbox fast lane` | Backend that will service each lane plus its concurrency cap. The `default` / `configured` suffix shows whether the cap is the built-in value or an operator override via `[performance] chain_lane_concurrency` / `fast_lane_concurrency`. |

Doctor exits non-zero only when `nyx` is missing or under the minimum
version. Every other check is informational.

## Common failure modes

### `nyx FAIL: nyx binary not found on PATH`

Doctor could not resolve `nyx`. Install it, put it on `PATH`, or set
`[nyx].binary_path` in `nyctos.toml`.

### `nyx FAIL: nyx version <found> below required minimum <required>`

The installed `nyx` is older than `MINIMUM_NYX_VERSION`. Upgrade it,
or raise `[nyx].min_version` only if you accept the risk for that
specific deployment.

### `error: could not resolve user data directory`

`dirs::data_dir` returned `None` (`HOME` and `XDG_DATA_HOME` both
unset). Set one of those env vars, or pass `--state-dir /abs/path`.

### Release build panics with `frontend build failed`

The `crates/nyx-agent-ui` build script could not run `npm`. Install
Node and `npm`, or set `NYCTOS_SKIP_FRONTEND_BUILD=1` and provide
prebuilt assets in `crates/nyx-agent-ui/dist/`.

### `cargo build` fails on missing `.sqlx/` query data

SQLx offline mode is enabled by default in CI. If you regenerate
queries locally, follow the `sqlx prepare` recipe in `README.md`
("Working with the SQLite store") and commit the resulting `.sqlx/`
diff.

## Related pages

- `docs/triggers/cron.md`, `docs/triggers/webhook.md` for no-touch
  scan triggers once the daemon is running.
- `docs/ci/github-actions.md` for using Nyctos as a PR gate via the
  shipped composite Action.
- `README.md` "Frontend SPA workflow" for the hot-reload dev loop
  against the daemon.

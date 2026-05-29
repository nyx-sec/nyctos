# Install

This page walks through installing Nyx Agent and wiring its external
dependencies. The shipping binary is `nyx-agent`; the product brand is
"Nyx Agent". Both names appear here for the reasons explained in
`README.md`.

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Rust toolchain | 1.88 or newer, channel `stable` | Required by `Cargo.toml`. Repository checkouts use `rust-toolchain.toml`; `rustup` picks it up automatically on first `cargo` invocation. |
| `nyx` static scanner | 0.7.0 or newer | External GPL-3.0-or-later binary spawned as a subprocess. See [Install the `nyx` scanner](#install-the-nyx-scanner). |
| Node.js + pnpm | Node 18+ | Required only when rebuilding the SPA from a repository checkout. `cargo install nyx-agent` uses packaged dashboard assets and does not need Node or pnpm. |
| AI runtime | optional | Static scans work without any model provider. Optional paths are direct BYOK APIs, local OpenAI-compatible endpoints, and provider-authorized local CLIs. |
| SQLite | bundled | Linked into the binary via SQLx; no system SQLite needed. |

Linux and macOS are the supported targets. Windows is untested.

## Install from crates.io

```bash
cargo install nyx-agent
nyx-agent doctor
nyx-agent serve
```

The published crate includes the prebuilt dashboard assets. Installing from
crates.io does not run the frontend build and does not require a `frontend/`
checkout, Node, or pnpm.

## Build from source

```bash
git clone <repo-url> nyx-agent
cd nyx-agent
cargo build --release
```

`cargo build --release` runs `crates/nyx-agent-ui/build.rs`, which
invokes `pnpm install --frozen-lockfile` when needed and
`pnpm run build` inside `frontend/`, then copies `frontend/dist/`
into Cargo's `OUT_DIR` so `rust_embed` can pick the assets up at
compile time. If the frontend build is unavailable but packaged
`crates/nyx-agent-ui/dist/` assets exist, the build uses those
prebuilt assets instead.

If you build the SPA out-of-band (e.g. a CI job that prepopulates
`crates/nyx-agent-ui/dist/`), set `NYX_AGENT_SKIP_FRONTEND_BUILD=1` to skip
the frontend build step:

```bash
NYX_AGENT_SKIP_FRONTEND_BUILD=1 cargo build --release
```

Debug builds (`cargo build`, `cargo run`, `cargo nextest run`) write
a tiny stub `index.html` into `OUT_DIR`, so `/` keeps returning a
usable page in CI environments without Node.

The resulting binary lives at `target/release/nyx-agent`. Copy it
onto your `PATH` or invoke it directly.

## Install the `nyx` scanner

Nyx Agent shells out to the `nyx` binary; it has no FFI link against it.
The agent will not start scans without a usable `nyx`.

Two ways to make `nyx` discoverable, in order of preference:

1. Place `nyx` on `PATH`. Verify with `which nyx`.
2. Set `[nyx].binary_path = "/abs/path/to/nyx"` in `nyx-agent.toml`.

The minimum version is `0.7.0` (the `MINIMUM_NYX_VERSION` constant in
`crates/nyx-agent-nyx/src/runner.rs`). The floor pins to the upstream
release that introduced `evidence.flow_steps`, which the taint flow,
spec-derivation, and chain-reasoning passes all consume. Override per
install via `[nyx].min_version = "0.8.0"` in `nyx-agent.toml` if a
deployment needs a newer floor than the agent default; values below the
built-in floor are clamped up silently.

The upstream `nyx` scanner is GPL-3.0-or-later and distributed
separately. Nyx Agent itself is AGPL-3.0-or-later. Nyx Agent still consumes
`nyx` as an external subprocess so the scanner can keep its own release
cadence and repository boundary.

## Optional: AI Runtimes

The static scanner, route modelling, live verification, evidence store,
and triage workflow do not require AI. `[ai] runtime = "none"` is the
default and is a complete local scan mode.

To enable AI one-shot helpers, use a direct BYOK API or a local
OpenAI-compatible endpoint:

- `anthropic`: store an Anthropic API key in the OS keychain.
- `local-llm`: point `[ai].api_base` at a local `/v1` endpoint such as
  LM Studio, Ollama, or vLLM. Set `[ai].model` when your server requires
  a specific model id.

Claude Code and Codex CLI support are optional local adapters for users
who have installed and authenticated those CLIs themselves. Nyx Agent does
not include, proxy, sublicense, or resell model access. Use these
adapters only with credentials and usage patterns allowed by the
provider terms.

## State directory

On first launch the daemon creates a per-user state directory and
chmods it `0700`. The default location is resolved from the
platform's data dir:

| Platform | Default path |
|---|---|
| Linux | `~/.local/share/nyx-agent/` |
| macOS | `~/Library/Application Support/nyx-agent/` |

Override with `--state-dir /path/to/dir` (global flag) or
`[general].state_dir = "/path"` in `nyx-agent.toml`. The directory
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
state dir OK at /home/op/.local/share/nyx-agent
logs -> /home/op/.local/share/nyx-agent/logs/agent.jsonl
config not found at ./nyx-agent.toml (using defaults)
db OK at /home/op/.local/share/nyx-agent/state.db (schema v1)
nyx OK at /usr/local/bin/nyx (version 0.7.0, minimum 0.7.0)
claude-code: available v1.0.0 at /usr/local/bin/claude
codex: unavailable (`codex` not on PATH)
sandbox chain lane -> birdcage (selected by host probe) [2 simultaneous, default]
sandbox fast lane  -> process (selected by host probe) [8 simultaneous, default]
webhook: secret resolved from `env:NYX_WEBHOOK_SECRET` (32 bytes)
webhook caps: 8 simultaneous [default], 30/min per IP [default]
ai exploration caps: $5.00 soft [default], $10.00 run [default]
```

Each line maps to a single check:

| Line | Means |
|---|---|
| `state dir OK` | State dir exists with mode `0700` and every subdirectory is present. |
| `logs -> <path>` | JSON log file location for this run. |
| `config OK` / `config not found` | Whether `nyx-agent.toml` was loaded or defaults applied. A missing config is not fatal. |
| `db OK ... schema v<N>` | SQLite opened and migrations are caught up. |
| `nyx OK` / `nyx FAIL` | The scanner binary is on `PATH` (or `[nyx].binary_path` resolved), and its `--version` is at or above `MINIMUM_NYX_VERSION`. |
| `claude-code: available` / `unavailable` | Informational only. Doctor exits zero with Claude Code missing. |
| `codex: available` / `unavailable` | Informational only. Doctor exits zero with Codex missing. |
| `sandbox chain lane` / `sandbox fast lane` | Backend that will service each lane plus its concurrency cap. The `default` / `configured` suffix shows whether the cap is the built-in value or an operator override via `[performance] chain_lane_concurrency` / `fast_lane_concurrency`. |
| `webhook: secret resolved` / `webhook: disabled` | Whether `[triggers] webhook_secret_ref` resolved to a non-empty value. Only present when the secret ref is set; absent on a fresh install. |
| `webhook caps` | Resolved per-handler concurrency cap and per-IP rate limit. The `default` / `configured` suffix mirrors the lane lines: built-in fallback vs. an operator override via `[triggers] webhook_max_concurrent` / `webhook_rate_limit_per_minute`. Only present when the webhook is enabled. |
| `ai exploration caps` | Resolved per-task soft cap (warning line at this spend) and per-run hard cap (halts the pass at this spend) for AI Exploration. The `default` / `configured` suffix flags an operator override via `[ai] exploration_soft_cap_usd_micros` / `exploration_run_cap_usd_micros`. |

Doctor exits non-zero only when `nyx` is missing or under the minimum
version. Every other check is informational.

## Common failure modes

### `nyx FAIL: nyx binary not found on PATH`

Doctor could not resolve `nyx`. Install it, put it on `PATH`, or set
`[nyx].binary_path` in `nyx-agent.toml`.

### `nyx FAIL: nyx version <found> below required minimum <required>`

The installed `nyx` is older than `MINIMUM_NYX_VERSION`. Upgrade it,
or raise `[nyx].min_version` only if you accept the risk for that
specific deployment.

### `error: could not resolve user data directory`

`dirs::data_dir` returned `None` (`HOME` and `XDG_DATA_HOME` both
unset). Set one of those env vars, or pass `--state-dir /abs/path`.

### Release build panics with `frontend build failed`

The `crates/nyx-agent-ui` build script could not run `npm`. Install
Node and `npm`, or set `NYX_AGENT_SKIP_FRONTEND_BUILD=1` and provide
prebuilt assets in `crates/nyx-agent-ui/dist/`.

### `cargo build` fails on missing `.sqlx/` query data

SQLx offline mode is enabled by default in CI. If you regenerate
queries locally, follow the `sqlx prepare` recipe in `README.md`
("Working with the SQLite store") and commit the resulting `.sqlx/`
diff.

## Related pages

- `docs/triggers/cron.md`, `docs/triggers/webhook.md` for no-touch
  scan triggers once the daemon is running.
- `docs/ci/github-actions.md` for using Nyx Agent as a PR gate via the
  shipped composite Action.
- `README.md` "Frontend SPA workflow" for the hot-reload dev loop
  against the daemon.

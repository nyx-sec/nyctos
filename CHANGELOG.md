# Changelog

All notable changes to Nyx Agent are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For release procedure, see the [Release guide](docs/release.md).

## [Unreleased]

Changes for the next Nyx Agent release will land here before a version is cut.

## [0.1.0] - 2026-05-29

The initial crates.io release turns Nyx Agent into the installable product layer around `nyx`: a local CLI, loopback daemon, embedded dashboard, SQLite product store, and packaged UI assets that work from `cargo install nyx-agent`.

### Highlights

- **Installable `nyx-agent` binary.** Ships the CLI and loopback daemon that run local development pentests against applications the operator controls.
- **Nyx static scanner integration.** Runs project scans through the external `nyx` binary discovered on `PATH` or configured with `[nyx].binary_path`.
- **Embedded dashboard.** Serves the bundled SPA from the released binary so run history, proof, traces, and triage can be inspected without a separate frontend process.
- **Local product store.** Persists projects, repositories, scan runs, candidates, verification attempts, vulnerabilities, traces, attack graph records, chains, schedules, integrations, and triage state in the per-user SQLite store.
- **Crates.io-ready packaging.** Includes prebuilt frontend assets in the published crate so `cargo install nyx-agent` does not require Node or pnpm.

### CLI and daemon

- **`nyx-agent serve`.** Starts the loopback HTTP/API/UI daemon, binds to the configured `[ui] listen_addr`, opens the browser by default, streams API/WebSocket events, and serves the embedded dashboard.
- **`nyx-agent scan`.** Runs one-shot project scans from the CLI, driving the static `nyx` lane, candidate generation, verification, chain reasoning, and optional local attack-agent passes according to the configured runtime gates.
- **Project and reset commands.** Provides project management and `reset db` workflows for local state bootstrap and cleanup.
- **Operator defaults.** Works with no config file for read-only commands, while `--config`, `--state-dir`, and `--log-level` remain available globally.

### Runtime and verification

- **Local target orchestration.** Supports project launch profiles with build, start, health, seed, login, reset, and stop commands for disposable development apps.
- **Guarded live verification.** Keeps destructive probes behind explicit exploit-mode and state-changing gates, with request caps, rate limits, target scope checks, dry-run support, and reset-after-state-changing handling.
- **AI/runtime adapters.** Leaves AI runtimes optional and BYOK/local, with `none` as the default runtime and provider keys stored through the OS keychain when configured.
- **Unsafe attack-agent opt-in.** Adds the explicitly gated local attack phase for disposable user-owned targets, including specialist passes, critical chain hunting, and final attack triage.

### Dashboard and API

- **Embedded SPA assets.** Packages `crates/nyx-agent-ui/dist/` into the binary and serves the dashboard from `/`.
- **HTTP API and event stream.** Exposes the `/api/v1/...` API and WebSocket run events used by the dashboard and local automation.
- **Project workspace UX.** Dashboard surfaces project setup, live pentest progress, verified vulnerabilities, evidence, reproduction details, and triage status from the product store.

### Product store

- **SQLite-backed local state.** Stores `state.db` under the resolved state directory, with migrations applied by `nyx-agent-core::Store::open`.
- **Run and evidence records.** Tracks scan runs, per-repo outcomes, candidates, verification attempts, vulnerabilities, traces, repro bundle metadata, chains, schedules, webhooks, and integration rows.
- **Safe reset path.** `nyx-agent reset db` removes only database files after checking for a running process, leaving logs, traces, repro bundles, ingested workspaces, and auth tokens alone.

### Packaging and crates

- **Published binary crate.** `nyx-agent` is the public install target for operators.
- **Internal implementation crates.** `nyx-agent-types`, `nyx-agent-ui`, `nyx-agent-core`, `nyx-agent-nyx`, `nyx-agent-sandbox`, `nyx-agent-ai`, and `nyx-agent-api` publish with versioned dependencies so Cargo can install the binary crate. They are not stable public APIs.
- **Release procedure.** Documents dependency-order publishing and frontend asset sync in `docs/release.md`.

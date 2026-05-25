# Contributing to Nyctos

Thanks for helping improve Nyctos. This repo is security-sensitive: it launches local apps, reads repos, stores proof, drives live probes, and talks to optional AI runtimes. Small changes can cross trust boundaries, so prefer focused patches with clear tests.

## Development Setup

Prerequisites:

- Rust 1.83+
- Node.js 22+
- npm
- SQLite tooling through SQLx when touching query macros or migrations
- Docker when working on env-builder or Docker-backed sandbox tests
- Nightly Rust plus `cargo-fuzz` when working on `fuzz/`

Build and run:

```bash
cargo build --workspace
cargo run --bin nyctos -- doctor
cargo run --bin nyctos -- serve
npm --prefix frontend ci
npm --prefix frontend run dev
```

## Project Layout

```text
crates/nyctos/          CLI, scan orchestration, launch profiles, live verification
crates/nyctos-api/      HTTP API, WebSocket/event routes, setup and dashboard backend
crates/nyctos-core/     config, store, repos, state dir, reports, event logs
crates/nyctos-sandbox/  sandbox backends, env-builder, payload and chain runners
crates/nyctos-nyx/      adapter for the upstream nyx scanner
crates/nyctos-ai/       AI runtime adapters and task prompts/contracts
crates/nyctos-types/    shared Rust/TypeScript DTOs and generated bindings source
crates/nyctos-ui/       embedded frontend assets for release builds
frontend/               React dashboard
xtask/                  generated TypeScript bindings and repo lints
fuzz/                   cargo-fuzz targets, excluded from the main workspace
docs/                   operator and developer documentation
```

## Quality Checks

The CI gate is intentionally broad. Run the checks that match your change.

Rust:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-features --tests
cargo nextest run --workspace --all-features
```

Frontend:

```bash
npm --prefix frontend run format:check
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Generated and policy checks:

```bash
cargo run -p xtask -- gen-ts
git diff --exit-code frontend/src/api/types.gen.ts
bash .ci/missing-instrument.sh
./.ci/license-guard.sh
./.ci/voice-lint.sh
cargo machete
cargo deny check advisories bans sources
```

Fuzz targets:

```bash
cargo +nightly fuzz build config_toml
cargo +nightly fuzz build harness_spec_json
cargo +nightly fuzz build live_plan_json
```

## Generated TypeScript

Shared API types live in `crates/nyctos-types` and are exported to `frontend/src/api/types.gen.ts` by:

```bash
cargo run -p xtask -- gen-ts
```

Commit the generated file when Rust DTOs change. If the generated shape diverges from the actual API response shape, fix the Rust type boundary rather than papering over the frontend import.

## SQLx

Nyctos uses SQLx query metadata under `.sqlx/`. If you change migrations or compile-time checked queries, refresh the cache:

```bash
rm -f /tmp/sqlx-prepare.db
export DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc"
sqlx database create
sqlx migrate run --source crates/nyctos-core/migrations
cargo sqlx prepare --workspace --check
```

See `docs/dev/sqlx.md` for more detail.

## Security-Sensitive Changes

Call out security boundary changes in the PR summary. This includes:

- API auth, CSRF, host/origin checks, token storage, and setup routes
- Sandbox backend behavior, allowlists, process execution, Docker/env-builder, and teardown
- Trace logs, repro bundles, state-dir paths, symlink handling, and file permissions
- AI prompts, tool execution, generated plans, and model-provided JSON parsing
- Live verification probes, state-changing gates, destructive attack-agent paths, and target URL normalization
- Shared DTOs that gain `Deserialize`, frontend exports, or new wire-input fields

Prefer fail-closed behavior, explicit allowlists, structured errors, and tests that exercise the bad path.

## Frontend Guidelines

Use the existing UI primitives and styling conventions. Keep operational screens dense, readable, and predictable. Prefer semantic HTML for tabular data and form controls. Run Biome before opening a PR.

## Pull Requests

Good PRs are small enough to review, explain the trust boundary they touch, and include focused tests. Include screenshots or screen recordings for dashboard changes when useful. Update docs when behavior, config, CLI flags, API responses, setup flow, or safety expectations change.

Do not commit local state, `.DS_Store`, build output, fuzz corpus growth, secrets, trace logs, or target app data.

## Reporting Bugs and Security Issues

Use GitHub issues for product bugs, false positives, missed findings, crashes, and feature requests.

Use `SECURITY.md` for vulnerabilities. Do not file public issues for sandbox escapes, auth bypasses, arbitrary file access, token disclosure, or other security bugs.

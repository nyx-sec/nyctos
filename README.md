<div align="center">
  <img src="assets/nyctos-readme-header.png" alt="Nyctos" width="640"/>

**Run a live pentest against a dev app you control. Nyctos reads the repo, drives the local target, verifies findings, and gives you proof instead of a guess list.**

  <p>
    <a href="LICENSE.md"><img alt="License: PolyForm Small Business" src="https://img.shields.io/badge/license-PolyForm%20Small%20Business-0f172a?style=flat-square" /></a>
    <a href="https://www.rust-lang.org/"><img alt="Rust 2024" src="https://img.shields.io/badge/rust-2024-f97316?style=flat-square&logo=rust&logoColor=white" /></a>
    <a href="https://pnpm.io/"><img alt="pnpm frontend" src="https://img.shields.io/badge/pnpm-frontend-facc15?style=flat-square&logo=pnpm&logoColor=111827" /></a>
    <a href="https://github.com/nyx-sec/nyx"><img alt="nyx scanner" src="https://img.shields.io/badge/scanner-nyx-2563eb?style=flat-square" /></a>
  </p>
</div>

<p align="center"><img src="assets/screenshots/demo.gif" alt="Nyctos dashboard walkthrough showing pentest options, a live local run, verified vulnerabilities, and proof details" width="900"/></p>

---

## Pentest locally, prove locally

Nyctos is the product layer around `nyx` for live, local pentesting. Point it at a repo and a dev URL. It launches or watches the app, reads the code, maps routes, sends scoped probes, and only promotes findings when it can attach evidence.

The dashboard is built for the part that usually gets messy: deciding what is real, what already has proof, and what still needs a harder look.

```bash
cargo run --bin nyctos -- scan ./apps/web --target-url http://127.0.0.1:3000
cargo run --bin nyctos -- serve
```

The target stays local. The API binds to loopback by default. The run history, traces, evidence, and triage state live in the Nyctos product store.

<p align="center"><img src="assets/screenshots/project-workspace.png" alt="Nyctos project workspace with a live pentest, verified risk, target status, repositories, and recent activity" width="900"/></p>

## What a run does

| Stage | What happens |
|---|---|
| **Scope** | Load project repos, target URLs, launch profile, previous findings, and runtime settings. |
| **Static scan** | Run `nyx` over the source tree and normalize the scanner output. |
| **Explore** | Build route, form, auth, and API context from the app and codebase. |
| **Candidate pass** | Turn scanner findings and runtime signals into concrete issues worth checking. |
| **Verification** | Send targeted live checks to the dev app and collect request, response, and trace proof. |
| **Triage** | Store verified vulnerabilities with confidence, status, evidence, and run attribution. |
| **Attack pass** | Optional destructive local pass that tries to break the app after the rest of the context is known. |

<p align="center"><img src="assets/screenshots/live-pentest.png" alt="Nyctos live pentest run with app readiness, auth sessions, repo progress, pentest phases, and live verifier proof" width="900"/></p>

## How the live pentest fits together

```mermaid
flowchart TD
    Start["Start pentest"] --> Scope["Load repos, config, target URL"]
    Scope --> Launch["Launch or attach to dev app"]
    Launch --> Static["Run nyx static scan"]
    Static --> Explore["Explore routes, forms, auth, APIs"]
    Explore --> Candidates["Create candidate vulnerabilities"]
    Candidates --> Verify["Verify against the live target"]
    Verify --> Evidence["Store proof, trace data, confidence"]
    Evidence --> Triage["Show findings in dashboard and CLI"]

    Evidence --> AttackGate{"Unsafe attack agent enabled?"}
    AttackGate -- "No" --> Triage
    AttackGate -- "Yes" --> Attack["Run destructive local attack pass"]
    Attack --> Promote["Add new findings or raise confidence"]
    Promote --> Triage

    Scope -. "code and launch context" .-> Attack
    Candidates -. "known weak spots" .-> Attack
    Verify -. "proof and failures" .-> Attack
```

The unsafe attack agent runs last because it should not waste time guessing from a blank page. By the time it starts, Nyctos has code context, target context, previous candidates, existing vulnerabilities, and live verification signals. If it breaks something new, the result is recorded as a vulnerability candidate or used to raise confidence on an existing one.

This mode is meant for disposable local state. It can mutate data, create accounts, submit payloads, corrupt fixtures, or knock the dev app over. That is the point.

## CLI first, dashboard when it matters

Use the CLI for one-off runs, CI smoke checks, and local scripts:

```bash
nyctos doctor
nyctos scan ./apps/web
nyctos scan ./apps/web --target-url http://127.0.0.1:3000
nyctos scan ./apps/web --exploit
nyctos scan ./apps/web --unsafe-attack-agent
nyctos serve
nyctos pr-comment --run-id <id>
```

Use the dashboard when you want to watch a live run, inspect proof, update triage, or keep project setup in one place.

<p align="center"><img src="assets/screenshots/verified-vulnerabilities.png" alt="Nyctos verified vulnerability list with risk scores, confidence, source location, and triage tabs" width="900"/></p>

<p align="center"><img src="assets/screenshots/vulnerability-detail.png" alt="Nyctos vulnerability detail page with live evidence, business impact, reproduction steps, and remediation" width="900"/></p>

## Local app setup

A launch profile tells Nyctos how to start the target and where to probe it:

```toml
[project]
name = "checkout-service"
root = "/Users/you/dev/checkout-service"

[project.launch]
command = "npm run dev"
cwd = "/Users/you/dev/checkout-service"
target_url = "http://127.0.0.1:3000"
health_url = "http://127.0.0.1:3000/health"
startup_timeout_secs = 45
```

For live testing, use `127.0.0.1`, `localhost`, or another dev host you control. Use seeded accounts and throwaway databases for destructive runs.

## Install from source

Nyctos is pre-MVP. The core loop works, but packaging is still moving.

```bash
cargo build --workspace
cargo run --bin nyctos -- doctor
cargo run --bin nyctos-api
npm --prefix frontend install
npm --prefix frontend run dev
```

Useful checks while working on the repo:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix frontend run check
```

## Docs

- [Configuration](docs/config.md)
- [CLI](docs/cli.md)
- [API](docs/api.md)
- [Product store](docs/product-store.md)
- [SQLx setup](docs/dev/sqlx.md)

## License

Nyctos is source-available under PolyForm Small Business License 1.0.0. See [LICENSE.md](LICENSE.md). The upstream `nyx` scanner is a separate GPL-3.0-or-later project.

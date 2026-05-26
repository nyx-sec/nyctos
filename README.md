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
| **Attack pass** | Optional destructive local phase that runs focused specialists, a cross-domain chain hunter, and final attack triage against the dev app. |
| **Chain reasoning** | Let the chain agent inspect graph evidence and, for Claude/Codex, read/search repo code to connect low-level leads into higher-impact paths. |
| **Triage** | Store verified vulnerabilities with confidence, status, evidence, and run attribution. |

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

    Evidence --> AttackGate{"Unsafe attack agent enabled?"}
    AttackGate -- "No" --> Chain["Source-aware chain reasoning"]
    AttackGate -- "Yes" --> Specialists["Run seven focused attack specialists"]
    Specialists --> Hunter["Hunt critical cross-domain chains"]
    Hunter --> AttackTriage["Deduplicate, classify dev-only noise, and refine proof"]
    AttackTriage --> Promote["Record new candidates, attempts, and verified vulns"]
    Promote --> Chain

    Chain --> ChainDecision{"Terminal live proof?"}
    ChainDecision -- "Yes" --> VerifiedChain["Promote verified chain vulnerability"]
    ChainDecision -- "No" --> NeedsChainVerify["Keep as NeedsChainVerification"]
    VerifiedChain --> Triage["Show verified vulnerabilities and proof"]
    NeedsChainVerify --> Triage

    Scope -. "code and launch context" .-> Specialists
    Candidates -. "known weak spots" .-> Specialists
    Verify -. "proof and failures" .-> Specialists
    Scope -. "workspace roots" .-> Chain
    Evidence -. "verification attempts and vulns" .-> Chain
    Promote -. "unsafe-agent findings" .-> Chain
```

The unsafe attack phase runs late because it should not waste time guessing from a blank page. By the time it starts, Nyctos has code context, target context, previous candidates, existing vulnerabilities, and live verification signals. It runs serially so each pass can inherit newly recorded findings:

| Pass | Focus |
|---|---|
| Business logic | Workflow and state-machine abuse, role transitions, invites, quotas, lifecycle edges, and order-of-operation bugs. |
| Payments and billing | Checkout, subscriptions, invoices, coupons, trials, webhooks, refunds, entitlement enforcement, and payment-status trust. |
| User data and privacy | IDORs, cross-tenant data access, exports, imports, files, logs, analytics payloads, and deleted-user remnants. |
| Auth and session | Login, reset flows, OAuth, magic links, MFA, cookies, CSRF, session lifetime, account linking, and privilege escalation. |
| API and input handling | Mass assignment, validation gaps, hidden fields, file uploads, parser confusion, SSRF-like fetches, injection, and deserialization. |
| Infra and dev/prod drift | Secrets, env config, debug routes, dev mailers, seed credentials, logs, local services, admin tooling, CORS, and deployment assumptions. |
| Abuse and automation | Rate limits, brute force, enumeration, scraping, invite/email/SMS abuse, queue flooding, resource exhaustion, and free-tier abuse. |
| Critical chain hunter | Cross-domain paths that combine smaller primitives into account takeover, cross-tenant compromise, payment bypass, persistent admin access, or secret exposure. |
| Attack triage | Deduplicate, classify dev-only noise, confirm material upgrades, and record only issues supported by live proof. |

Each pass is told it is operating in a development environment. Dev mailers, mock payment providers, localhost-only callbacks, seed credentials, debug routes, and synthetic fixtures are not production findings by themselves. They only become findings when the source, config, routing, or live behavior shows a production-relevant trust boundary or a real local-secret risk.

Chain reasoning runs after that. It sees the normalized attack graph: static signals, candidates, routes, roles, objects, authz observations, verification attempts, verified vulnerabilities, and unsafe-agent results. When the selected runtime supports agent loops, the chain worker also receives repo workspace roots and can read/search source before returning chain JSON. Chains that terminate in live proof are promoted as verified chain vulnerabilities; chains without terminal proof stay as `NeedsChainVerification`.

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

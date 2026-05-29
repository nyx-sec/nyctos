<div align="center">
  <img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/nyx-agent-readme-header.png" alt="Nyx Agent" width="640"/>

**Run a live pentest against a dev app you control. Nyx Agent reads the repo, drives the local target, verifies findings, and gives you proof instead of a guess list.**

  <p>
    <a href="https://github.com/nyx-sec/nyx-agent/blob/main/LICENSE.md"><img alt="License: AGPLv3-or-later" src="https://img.shields.io/badge/license-AGPLv3--or--later-0f172a?style=flat-square" /></a>
    <a href="https://www.rust-lang.org/"><img alt="Rust 1.88+" src="https://img.shields.io/badge/rust-1.88%2B-f97316?style=flat-square&logo=rust&logoColor=white" /></a>
    <a href="https://pnpm.io/"><img alt="pnpm frontend" src="https://img.shields.io/badge/pnpm-frontend-facc15?style=flat-square&logo=pnpm&logoColor=111827" /></a>
    <a href="https://github.com/nyx-sec/nyx"><img alt="nyx scanner" src="https://img.shields.io/badge/scanner-nyx-2563eb?style=flat-square" /></a>
  </p>
</div>

<p align="center"><img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/screenshots/demo.gif" alt="Nyx Agent dashboard walkthrough showing pentest options, a live local run, verified vulnerabilities, and proof details" width="900"/></p>

## Pentest locally, prove locally

`nyx-agent` is the CLI and loopback daemon for Nyx Agent, the product layer
around `nyx` for live, local pentesting. Point it at a repository and a dev
URL. It launches or watches the app, reads the code, maps routes, sends scoped
probes, and only promotes findings when it can attach evidence.

```bash
nyx-agent scan ./apps/web --target-url http://127.0.0.1:3000
nyx-agent serve
```

The target stays local. The API binds to loopback by default. Run history,
traces, evidence, triage state, and replay artifacts live in the Nyx Agent
product store on the operator machine.

<p align="center"><img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/screenshots/project-workspace.png" alt="Nyx Agent project workspace with a live pentest, verified risk, target status, repositories, and recent activity" width="900"/></p>

## What a run does

| Stage | What happens |
|---|---|
| **Scope** | Load project repos, target URLs, launch profile, previous findings, and runtime settings. |
| **Static scan** | Run `nyx` over the source tree and normalize the scanner output. |
| **Explore** | Build route, form, auth, and API context from the app and codebase. |
| **Candidate pass** | Turn scanner findings and runtime signals into concrete issues worth checking. |
| **Verification** | Send targeted live checks to the dev app and collect request, response, and trace proof. |
| **Attack pass** | Optional destructive local phase that runs focused specialists, a cross-domain chain hunter, and final attack triage against the dev app. |
| **Chain reasoning** | Inspect graph evidence and, when an optional provider-authorized CLI runtime is configured, read/search repo code to connect low-level leads into higher-impact paths. |
| **Triage** | Store verified vulnerabilities with confidence, status, evidence, and run attribution. |

<p align="center"><img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/screenshots/live-pentest.png" alt="Nyx Agent live pentest run with app readiness, auth sessions, repo progress, pentest phases, and live verifier proof" width="900"/></p>

## CLI first, dashboard when it matters

Use the CLI for one-off runs, CI smoke checks, and local scripts:

```bash
nyx-agent doctor
nyx-agent scan ./apps/web
nyx-agent scan ./apps/web --target-url http://127.0.0.1:3000
nyx-agent scan ./apps/web --exploit
nyx-agent scan ./apps/web --unsafe-attack-agent
nyx-agent serve
nyx-agent pr-comment --run-id <id>
```

Use the dashboard when you want to watch a live run, inspect proof, update
triage, or keep project setup in one place.

<p align="center"><img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/screenshots/verified-vulnerabilities.png" alt="Nyx Agent verified vulnerability list with risk scores, confidence, source location, and triage tabs" width="900"/></p>

<p align="center"><img src="https://raw.githubusercontent.com/nyx-sec/nyx-agent/main/assets/screenshots/vulnerability-detail.png" alt="Nyx Agent vulnerability detail page with live evidence, business impact, reproduction steps, and remediation" width="900"/></p>

## Local app setup

A launch profile tells Nyx Agent how to start the target and where to probe it:

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

For live testing, use `127.0.0.1`, `localhost`, or another dev host you
control. Use seeded accounts and throwaway databases for destructive runs.

## Install

Install the released CLI and daemon from crates.io:

```bash
cargo install nyx-agent
nyx-agent doctor
nyx-agent serve
```

The published crate includes the prebuilt dashboard assets, so installing from
crates.io does not require Node, pnpm, or a frontend build. You still need the
separate `nyx` static scanner on `PATH` or configured with
`[nyx].binary_path`.

For development from a repository checkout:

```bash
cargo build --workspace
cargo run --bin nyx-agent -- doctor
pnpm --dir frontend install
pnpm --dir frontend run dev
```

Useful checks while working on the repo:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix frontend run check
```

## Unsafe local attack mode

The optional unsafe attack phase is meant for disposable local state. It can
mutate data, create accounts, submit payloads, corrupt fixtures, or knock the
dev app over. That is the point.

Each pass is told it is operating in a development environment. Dev mailers,
mock payment providers, localhost-only callbacks, seed credentials, debug
routes, and synthetic fixtures are not production findings by themselves. They
only become findings when the source, config, routing, or live behavior shows a
production-relevant trust boundary or a real local-secret risk.

## Docs

- [Operator docs](https://nyxsec.dev/docs/agent)
- [Configuration](https://github.com/nyx-sec/nyx-agent/blob/main/docs/config.md)
- [CLI reference](https://github.com/nyx-sec/nyx-agent/blob/main/docs/cli.md)
- [HTTP API](https://github.com/nyx-sec/nyx-agent/blob/main/docs/api.md)
- [Product store](https://github.com/nyx-sec/nyx-agent/blob/main/docs/product-store.md)

## Support and commercial use

Nyx Agent is free and open source under AGPLv3-or-later. Commercial licenses,
paid support, onboarding help, private policy packs, and enterprise terms are
available for teams that need proprietary embedding, hosted resale, custom
support obligations, or license comfort.

Nyx Agent does not include or resell model access. AI runtimes are optional
BYOK/local connectors; users are responsible for complying with the terms for
their chosen API provider, local endpoint, or installed CLI.

## License

Nyx Agent is open source under AGPLv3-or-later. See the
[license](https://github.com/nyx-sec/nyx-agent/blob/main/LICENSE.md).
Contributions are accepted under the
[Nyx Agent Contributor License Agreement](https://github.com/nyx-sec/nyx-agent/blob/main/CLA.md)
so the project can remain open while commercial licenses are available for
organizations that need them. The upstream `nyx` scanner is a separate
GPL-3.0-or-later project.

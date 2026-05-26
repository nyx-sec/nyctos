# Security Policy

## Reporting a Vulnerability

Please report security issues privately. Do not open a public GitHub issue for a vulnerability.

Use [GitHub Security Advisories](https://github.com/nyx-sec/nyx-agent/security/advisories/new) to file a private report. If that link is unavailable for your fork or mirror, contact the maintainer privately and include the same information listed below.

Include:

- Affected version or commit (`nyx-agent --version` when available)
- OS and architecture
- Reproduction steps or a minimal proof of concept
- Impact, such as sandbox escape, auth bypass, local file read/write, command execution, UI XSS, CSRF, token disclosure, or unsafe live-probe behavior
- Whether AI runtimes, the dashboard, env-builder, Docker, or a specific sandbox backend were involved
- Whether you have a fix or mitigation in mind

You should receive an acknowledgement within 3 business days and a status update every 7 days until the issue is closed.

## Scope

In scope: bugs that let untrusted input reach Nyx Agent and cause harm.

- Sandbox escapes or isolation bypasses in the process, Birdcage, Docker/env-builder, libkrun, or Firecracker paths.
- Command injection, path traversal, arbitrary file read/write, or symlink/race issues in repo ingestion, launch profiles, repro bundles, trace logs, or env-builder.
- Auth bypass, CSRF, XSS, host-header, origin, or token-handling issues in the loopback API and dashboard.
- Unsafe live verification behavior that escapes the configured target, mutates outside an allowed local environment, or ignores explicit operator safety gates.
- AI/runtime handling issues that expose secrets, persist forged verifier evidence, or execute model-controlled commands outside the intended harness.
- Supply chain issues affecting published crates, release artifacts, GitHub Actions, or bundled frontend assets.
- Memory safety issues in unsafe Rust if any unsafe code is introduced.

Out of scope:

- Findings Nyx Agent reports against your own target app. That is the product working.
- False positives, missed findings, weak heuristics, or confusing risk scores. File a normal bug report with fixtures and evidence.
- Issues requiring physical access or an already-compromised local user account.
- Problems caused only by deliberately weakening local config, disabling safety gates, or scanning systems you do not own.
- Denial of service from intentionally extreme local inputs unless it crosses a trust boundary or corrupts state.
- Missing hardening headers on strictly loopback-only development endpoints with no cross-origin impact.

## Supported Versions

Nyx Agent is pre-MVP and currently supports the main development line only.

| Version | Status |
|---|---|
| main / 0.1.x | Supported |
| older commits | Best effort |

## Severity

We use CVSS 3.1 as a guide, with project-specific context.

| Severity | Examples |
|---|---|
| Critical | Unauthenticated command execution, sandbox escape during a default run, remote control of live probes |
| High | Auth bypass in the API, arbitrary file write, secret/token disclosure, forged verifier evidence |
| Medium | Stored XSS, CSRF on mutating routes, host/origin bypass, local file path disclosure that enables a follow-on attack |
| Low | Log injection, low-impact info disclosure, local denial of service without privilege change |

## Disclosure

We follow coordinated disclosure.

1. We confirm the report and assign severity.
2. A fix is developed privately when needed.
3. We backport only when there is a maintained release line to backport to.
4. A public advisory or release note is published after the fix ships.
5. Reporter credit is included unless you ask to remain anonymous.

The target window from report to fix is 90 days. If you need a different disclosure timeline, say so in the report.

## Safe Harbor

Good-faith security research is welcome. We will not pursue legal action against researchers who:

- Report privately and give a reasonable window before publishing.
- Test only installations, repos, targets, and accounts they own or are explicitly authorized to test.
- Avoid data destruction, account takeover, third-party scanning, and service disruption.
- Stop and contact us if a test begins affecting systems or data outside the agreed scope.

When in doubt, ask first.

## Security Model Recap

Nyx Agent is designed to run locally against development apps the operator controls. The API binds to loopback by default, stores state locally, and uses explicit safety gates for state-changing and unsafe attack-agent behavior. The most important security boundaries are the local API/dashboard, repo ingestion, launch/env setup, trace and repro storage, sandbox execution, AI-runtime adapters, and live verification probes.

# Nyx Agent website copy

Nyx Agent is the chosen name for the local daemon, dashboard, live verification,
evidence, CI, and optional BYOK/local AI layer built around the Nyx scanner.
Use `Nyx Agent` for the product display name and `nyx-agent` for the CLI,
binary, repository, config file, default state directory, and workspace crate
prefix.

## Homepage hero

### Headline

Nyx scans your code. Nyx Agent proves what is exploitable.

### Supporting copy

Nyx is the open-source appsec scanner. Nyx Agent is the local workbench around
it: a daemon and dashboard that launch development targets, run static scans,
verify findings live, collect evidence, and help teams triage risk without
shipping source code or test traffic to a hosted service.

Static scans and live verification work without model access. Optional AI
runtimes can be connected through BYOK or local adapters when you want assisted
setup, exploration, remediation notes, or report drafting.

### Primary CTA

Install Nyx Agent

### Secondary CTA

Read the docs

## Product architecture

### `nyx`: scanner and core engine

Nyx is the open-source scanner. It owns the static analysis identity, scanner
rules, and core appsec findings. Keep the scanner binary and scanner project
named `nyx`.

### `nyx-agent`: local workbench layer

Nyx Agent wraps Nyx with the local product experience:

- A local daemon and loopback API.
- A dashboard for projects, runs, vulnerabilities, evidence, and triage.
- Target launch profiles for development apps.
- Live verification and scoped probes against apps the operator controls.
- Evidence capture, repro bundles, PR comments, reports, and CI workflows.
- Optional BYOK/local AI connectors for setup, exploration, and remediation
  assistance.

Position Nyx Agent as the appsec workbench around Nyx, not as a hosted scanner
or bundled AI resale product.

## AI provider disclaimer

Nyx Agent does not include, proxy, sublicense, or resell access to model
providers. AI features are optional connectors that use provider-authorized
credentials or local runtimes supplied by the operator.

The static and local path is first-class: Nyx Agent can run static scans, launch
or watch a development target, perform live verification, capture evidence, and
support triage without AI model access.

Use this wording near setup, pricing, docs, and any feature list that mentions
Claude, Codex, Anthropic, OpenAI, local LLMs, or other AI runtimes:

> AI runtimes are optional BYOK/local connectors. Nyx Agent does not include or
> resell model access, and static scans plus live verification work without AI.

## Support and commercial

Nyx Agent is open source under AGPLv3-or-later. Commercial licenses, paid setup,
and paid support are available for teams that need non-AGPL terms, guided
rollouts, CI integration help, or private support.

Suggested links:

- GitHub Sponsors: fund ongoing open-source development.
- `/support`: community support, paid setup, and private support options.
- `/pricing`: commercial license and support inquiry.
- `/docs`: installation, configuration, CI, triggers, and AI runtime setup.

Suggested support copy:

> Community support happens in GitHub issues and discussions. Paid setup,
> private support, and commercial licensing are available for teams that need
> deployment help or non-AGPL terms.

## Migration note

Use this note in release notes, docs, and the `/agent` page footer:

> Nyx Agent was formerly called Nyx Agent during pre-MVP development.

Do not keep old `nyx-agent` command, config, state, crate, or environment variable
names in active setup paths. Pre-MVP users should rename local files and scripts
to the `nyx-agent` family during upgrade.

## Suggested website IA

- `/` - Nyx scanner overview, with a clear Nyx Agent section.
- `/agent` - Nyx Agent product page.
- `/docs` - docs index.
- `/support` - community and paid support.
- `/pricing` - commercial license and support inquiry.

## `/agent` page outline

### Page title

Nyx Agent - local appsec workbench for Nyx

### Sections

1. Hero: Nyx scans your code. Nyx Agent proves what is exploitable.
2. Architecture: `nyx` scanner plus `nyx-agent` local workbench.
3. Local workflow: scan, launch, verify, capture evidence, triage.
4. AI optional: BYOK/local connectors, no included model access.
5. CI and reporting: PR comments, evidence bundles, reports, schedules.
6. Support and commercial: AGPL, GitHub Sponsors, paid setup/support, commercial
   license.
7. Migration note: formerly Nyx Agent during pre-MVP development.

### CTA copy

- Install Nyx Agent
- Configure a project
- Add CI verification
- Ask about paid setup

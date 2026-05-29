# Nyx Agent docs

Operator-facing reference for `nyx-agent`, the binary that ships the
Nyx Agent product. Every page on this list describes behaviour that
currently ships; topics still in flight are tracked in
`.pitboss/play/deferred.md` and added here once the code lands.

The shipping binary is `nyx-agent`; the product brand is "Nyx Agent".
Both names appear in these pages for the reasons explained in
`README.md`.

## Get started

- [install.md](install.md): prerequisites, source build, the `nyx`
  scanner dependency, optional AI runtimes, and
  `nyx-agent doctor` line-by-line.
- [quickstart.md](quickstart.md): start the daemon, walk the
  first-launch wizard, create a project, attach repos, kick a scan,
  read findings.
- [cli.md](cli.md): every subcommand `nyx-agent` ships, the flags
  it accepts, and the exit codes it returns.
- [config.md](config.md): `nyx-agent.toml` schema, defaults, and
  failure modes section by section.
- [state-dir.md](state-dir.md): on-disk layout of the state
  directory: SQLite file, logs, repo workspaces, repro bundles,
  bearer token, plus permissions and override flags.
- [product-store.md](product-store.md): local SQLite product store
  contents, schema ownership, and reset behaviour.

## Architecture

- [architecture.md](architecture.md): crate map, the subprocess
  boundary to the GPL `nyx` scanner, the tokio + rayon process
  model, and the broadcast event bus.
- [runs.md](runs.md): per-run lifecycle, the dispatcher's
  per-repo fan-out, `RunBundle` aggregation, the `runs` SQLite
  table, and stability of finding ids across re-scans.
- [attack-graph.md](attack-graph.md): the run-scoped graph index
  over routes, endpoints, signals, candidates, verification
  attempts, verified vulnerabilities, and chains.
- [business-logic-templates.md](business-logic-templates.md):
  first-class live-test template registry, selection controls,
  dry-run behavior, provenance, and shipped business-logic probes.
- [events.md](events.md): `AgentEvent` envelope, the fixed
  per-run / per-project / per-repo ordering, the AI runtime
  stream, the WS replay buffer, and the `Lagged` warning frame.
- [ai-runtime.md](ai-runtime.md): the `AiRuntime` trait, the
  shipped Anthropic, local-LLM, Claude Code, and Codex adapters, the
  `BudgetTracker` host port, and the five typed task
  implementations layered on top.

## Projects

Nyx Agent groups one or more repos under a `Project`. Projects are the
top-level scan unit: scan, run dispatcher, sandbox env-builder, and
chain runner all operate per project, so a multi-repo product
(e.g. backend + frontend) scans, sandboxes, and chains as one unit.

- [cli.md#project](cli.md#project): `project create / list / show /
  delete / add-repo` plus the project-scoped `scan --project /
  --repo` flags.
- [quickstart.md#create-a-project](quickstart.md#create-a-project):
  worked example that creates a project and attaches a repo end to
  end.
- The TOML shape is `[[project]]` blocks that nest `[[project.repo]]`
  entries. See [`nyx-agent.toml`](../nyx-agent.toml) at the repo
  root for a populated example.

## HTTP API

- [api.md](api.md): every `/api/v1/` route, the request and
  response shape, the bearer-auth contract, the WebSocket event
  stream, and the HMAC webhook.

## Triggers

- [triggers/README.md](triggers/README.md): index of the no-touch
  scan-trigger surfaces.
- [triggers/cron.md](triggers/cron.md): `[[schedule]]` cron entries
  driven by the in-process scheduler, plus systemd / launchd units
  that keep the daemon up.
- [triggers/webhook.md](triggers/webhook.md): `POST /webhook/git`
  with HMAC-SHA256 verification and optional branch filter.

## CI integration

- [ci/github-actions.md](ci/github-actions.md): the shipped
  composite Action that runs a scan against a pull request and posts
  a dedup'd PR comment for Confirmed + cross-repo chain findings.

## Contributor docs

- [dev/sqlx.md](dev/sqlx.md): regenerating the SQLx prepared-query
  cache after editing a `sqlx::query!` / `query_as!` call.
- [dev/frontend.md](dev/frontend.md): release vs debug SPA embed
  behaviour and the two-terminal Vite dev loop.
- [release.md](release.md): crates.io preflight checks, frontend
  asset sync, and multi-crate publish order.

## Conventions

- Source pointers use the `crates/<crate>/src/<file>.rs:<line>` form
  so they render as clickable hints in viewers that link them.
- Verbatim third-party content (license excerpts, tool stdout,
  upstream error strings) sits inside `<!-- nyx: verbatim -->`
  blocks. Treat anything outside those blocks as authored prose.
- Pages describe what currently ships. If a page reads as if a
  feature is missing, the feature is queued and not yet wired.

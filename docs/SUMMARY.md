# Nyctos docs

Operator-facing reference for `nyx-agent`, the binary that ships the
Nyctos product. Every page on this list describes behaviour that
currently ships; topics still in flight are tracked in
`.pitboss/play/deferred.md` and added here once the code lands.

The shipping binary is `nyx-agent`; the product brand is "Nyctos".
Both names appear in these pages for the reasons explained in
`README.md`.

## Get started

- [install.md](install.md): prerequisites, source build, the `nyx`
  scanner dependency, the optional `claude-code` CLI, and
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

## Projects

Nyctos groups one or more repos under a `Project`. Projects are the
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
  root for a populated example, and `docs/PROJECT_ENTITY_PLAN.md`
  for the phased refactor that introduced the model.

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

## Conventions

- Source pointers use the `crates/<crate>/src/<file>.rs:<line>` form
  so they render as clickable hints in viewers that link them.
- Verbatim third-party content (license excerpts, tool stdout,
  upstream error strings) sits inside `<!-- nyx: verbatim -->`
  blocks. Treat anything outside those blocks as authored prose.
- Pages describe what currently ships. If a page reads as if a
  feature is missing, the feature is queued and not yet wired.

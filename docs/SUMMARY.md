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
  first-launch wizard, register a repo, kick a scan, read findings.

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

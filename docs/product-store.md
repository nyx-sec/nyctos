# Product Store

Nyx Agent keeps product state in a per-user SQLite database under the state
directory. The store is local to the operator machine and backs both the CLI
and the dashboard.

The product store records:

- projects and attached repositories
- scan runs and per-repo outcomes
- candidates, verification attempts, vulnerabilities, and triage status
- attack graph records, chains, payload/spec provenance, and AI traces
- schedules, webhook configuration rows, integrations, and repro bundle
  metadata

The database file is `state.db`; SQLite sidecar files may appear beside it
while the daemon is running. See [state-dir.md](state-dir.md) for platform
paths, permissions, and override flags.

The schema lives in `crates/nyx-agent-core/migrations/` and is applied on
startup by `nyx-agent-core::Store::open`. Release builds and crates.io
installs include those migrations through the Rust crate package.

Use `nyx-agent reset db` to remove only the SQLite database for the resolved
state directory. The command leaves logs, repro bundles, ingested workspaces,
and the bearer token in place.

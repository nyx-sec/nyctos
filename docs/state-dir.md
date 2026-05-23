# State directory

`nyctos` keeps every artifact that has to outlive a process under
a single root directory: the SQLite store, repo workspaces, repro
bundles, structured logs, and the local bearer token the API uses
to authenticate the embedded SPA. Resetting Nyctos on a host means
removing that one directory.

## Where it lives

On first launch the agent resolves the root in this order:

1. `--state-dir <PATH>` on the command line.
2. `[general] state_dir` in `nyctos.toml`.
3. `dirs::data_dir()/nyctos`. On macOS that's
   `~/Library/Application Support/nyctos`; on Linux,
   `$XDG_DATA_HOME/nyctos` (defaulting to `~/.local/share/nyctos`).

`nyctos doctor` prints the resolved path:

```text
state dir OK at /Users/eli/Library/Application Support/nyctos
```

If `dirs::data_dir()` cannot resolve a base (no `HOME`, no
`XDG_DATA_HOME`), startup fails with `could not resolve user data
directory (HOME/XDG_DATA_HOME unset?)`. Pass `--state-dir` to work
around it.

## Layout

```text
<state>/
├── state.db            SQLite store. Schema managed by the migrator.
├── state.db-wal        WAL journal. Present while the daemon holds the pool open.
├── state.db-shm        Shared-memory file for WAL readers.
├── auth_token          Local bearer token (mode 0600). Minted on first serve.
├── logs/
│   └── agent.jsonl     One JSON event per line, written by the tracing JSON layer.
├── repos/              Per-repo ingestion workspace, legacy flat layout.
│   └── <repo-name>/
├── projects/
│   └── <project-id>/
│       └── repos/
│           └── <repo-name>/   Project-scoped workspace. New ingestions write here.
├── bundles/            Repro bundles. One tarball per finding when the operator builds one.
├── traces/             AI conversation logs and live-verification evidence.
├── cache/              Reserved.
├── findings/           Reserved.
└── runs/               Reserved.
```

The root and every subdirectory in that list are created together
by `StateDir::ensure` on the first `nyctos` invocation; later
invocations are idempotent.

## Permissions

On Unix every directory in the tree is forced to mode `0700` on
every `ensure()` call, so a second user account on the same host
cannot read the agent's state even if the parent permissions are
loose. `auth_token` is written with mode `0600`. On non-Unix
platforms the permission step is a no-op.

If `ensure` cannot set permissions (read-only filesystem, ACL
conflict) the daemon fails to start with `failed to set permissions
on <path>: <io error>`.

## Files

### `state.db`

SQLite database. The pool opens with WAL journaling, `synchronous =
NORMAL`, `foreign_keys = ON`, `cache_size = -8000` (8 MiB), and
`temp_store = MEMORY`. The schema is managed by bundled SQLx
migrations under `crates/nyctos-core/migrations/`:

| Migration     | Adds |
|---------------|------|
| `0001_v1.sql` | Full baseline schema: product/projects, repos, runs, findings, harness specs, traces, AI budgets, quarantine data, launch profiles, Nyx signals, pentest candidates, verification attempts, vulnerabilities, phase events, and supporting indexes. |
| `0002_attack_graph.sql` | Run-scoped attack graph nodes and edges for routes, endpoints, forms, parameters, roles, objects, signals, candidates, verification attempts, verified vulnerabilities, and chains. |

The singleton `meta` row carries `schema_version` (mirrors
`MAX(_sqlx_migrations.version)`), `created_at` (epoch ms of first
install; never overwritten), and `agent_version` (the binary that
opened the file most recently). Read it back with:

```bash
sqlite3 "<state>/state.db" \
  "SELECT schema_version, agent_version, datetime(created_at/1000, 'unixepoch') FROM meta WHERE id = 1;"
```

`nyctos doctor` prints the schema version on every run:

```text
db OK at <state>/state.db (schema v3)
```

If migrations diverge (e.g. a newer binary then an older binary
opens the file), the older binary refuses to start with `failed to
apply migrations: ...`. Reverting to a newer binary fixes it; there
is no down-migration story.

### `auth_token`

64 hex characters (32 random bytes). The HTTP + WebSocket server
reads this on `serve` startup and requires every API client to
present it as `Authorization: Bearer <token>`. Loopback-only
binding makes this an additional defence in depth, not the primary
control.

`--headless` skips minting the token; the SPA is not served in that
mode, so no bearer is needed.

Rotate by deleting the file: `serve` mints a fresh one on the next
start. Live sessions invalidate at that point.

### `logs/agent.jsonl`

Newline-delimited JSON, one record per `tracing` event. The format
matches `tracing-subscriber`'s `fmt::json` layer: `timestamp`,
`level`, `target`, `fields`, and span fields the instrumented
function attached (`run_id`, `task_id`, ...). Operators tail this
file with `jq`:

```bash
tail -f "<state>/logs/agent.jsonl" | jq -c 'select(.level=="ERROR")'
```

The stderr layer mirrors the same events at the level set by
`--log-level` / `[general] log_level`; the JSON layer is always at
full verbosity so the file is the canonical record.

### `traces/<run-id>/browser_verification/<attempt-id>/`

Browser-driven verification writes durable replay evidence here when a
candidate is exercised through Playwright. The verification attempt row
stores the file paths in `verification_attempts.artifact_paths_json`.
Typical files are:

- `browser-replay.json` and `browser-replay.mjs`: deterministic,
  redacted replay inputs.
- `browser-final.png` plus any explicit screenshot-step captures.
- `browser-dom.html` and `browser-focused-html.json`: redacted DOM
  evidence.
- `browser-console.json` and `browser-timeline.json`: console output
  and action/navigation history.
- `playwright-trace.zip` when trace capture is available and safe, or
  `playwright-trace-unavailable.json` when the executor falls back to
  the redacted replay artifacts.

Session headers, cookies, bearer tokens, and token-like query/body
values are redacted before Nyctos writes JSON, HTML, console, timeline,
or replay files. Playwright traces are skipped when the plan or injected
session headers contain secret-like values because the zip is not
post-process-redacted.

## Directories

### `repos/<name>/`

Legacy flat layout. New ingestion calls land under `projects/<id>/repos/<name>/`
instead; the flat directory remains for repos created before the
project entity rolled out.

### `projects/<project-id>/repos/<repo-name>/`

Per-repo ingestion workspace. For a `git`-sourced repo this is a
shallow clone, refreshed via `git fetch` on subsequent runs. For a
`local-path` source this is a read-only snapshot rebuilt per run
and removed at end of run so concurrent IDE edits never race the
scan. The workspace path is recorded on the `IngestedRepo` returned
to the dispatcher and never assumed by anything outside the
ingestion call.

Two repos with the same name in different projects do not collide.

### `bundles/`

Repro bundles, one tarball per finding when an operator requests
one. The path is recorded in `repro_bundles.path` so the API can
serve it back over `GET /api/v1/findings/:id/repro` after verifying
the on-disk path stays under this root.

### `cache/`, `findings/`, `runs/`

Created on `ensure()` for parity with the spec but no shipping code
writes here yet. Reserved.

## Override examples

Run against a tempdir for a one-off scan:

```bash
nyctos --state-dir /tmp/nyctos-scratch doctor
nyctos --state-dir /tmp/nyctos-scratch scan --project demo
```

Pin the directory in `nyctos.toml` (handy for `systemd` /
`launchd` units that set their own `HOME`):

```toml
[general]
state_dir = "/var/lib/nyctos"
```

Either form works for any subcommand. `--state-dir` wins when both
are set.

## Failure modes

| Symptom                                                       | Cause / Fix                                                                                       |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `could not resolve user data directory (HOME/XDG_DATA_HOME unset?)` | No default base. Pass `--state-dir` or set `[general] state_dir`.                                 |
| `failed to create <path>: <io>`                               | Parent unwritable, ENOSPC, or filesystem refuses `0700`. Pick a writable root.                    |
| `failed to set permissions on <path>: <io>`                   | The filesystem cannot honour `0700` (e.g. NFS with `noexec`/ACLs). Move the state dir to a local FS, or override on Windows where the step is a no-op. |
| `failed to apply migrations: ...`                             | Older binary opening a newer database. Re-launch with the version that wrote the file.            |
| `failed to open database at <path>: ...`                      | `state.db` exists but is not a valid SQLite file, or the directory is read-only. Inspect with `sqlite3 <path>`. |
| API returns `401 unauthorized` after deleting `auth_token`    | Token was minted but the SPA still holds the previous value. Refresh the page.                    |

## Related pages

- [Install](install.md) for the runtime prerequisites that decide
  where `dirs::data_dir()` resolves.
- [Configuration](config.md) for `[general] state_dir` and every
  other section.
- [CLI](cli.md#global-flags) for `--state-dir`, `--config`, and
  `--log-level`.

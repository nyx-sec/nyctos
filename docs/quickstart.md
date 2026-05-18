# Quickstart

You have `nyx-agent` built and `nyx-agent doctor` is green. This page
takes you from a fresh state directory to a first scan and a
findings list. Five minutes if the prerequisites are already in
place; see `docs/install.md` if `doctor` reports anything missing.

The shipping binary is `nyx-agent`. The product brand is "Nyctos".
Both names appear here for the reasons explained in `README.md`.

## Start the daemon

```bash
nyx-agent serve
```

`serve` is the default subcommand, so `nyx-agent` with no arguments
does the same thing. It binds `127.0.0.1:8765` (from `[ui]
listen_addr`), opens your default browser, and prints the ready URL
on stdout:

<!-- nyx: verbatim -->
```
ready on http://127.0.0.1:8765
first launch detected — wizard at http://127.0.0.1:8765/setup
```
<!-- /nyx: verbatim -->

The "first launch detected" line only appears when `nyx-agent.toml`
is not yet on disk. The browser lands on `/setup` in that case;
once you submit the wizard, subsequent starts go to `/`.

Common flags:

| Flag | Effect |
|---|---|
| `--listen ADDR` | Override `[ui] listen_addr`. Pass `0.0.0.0:8765` for a non-loopback bind. Pair with TLS + the bearer token; see `docs/security-posture.md` (forthcoming). |
| `--no-open` | Skip the browser launch. Daemon still binds and serves. |
| `--headless` | Skip the browser launch AND disable bearer-token auth, since headless mode is intended for CI smoke tests. Do not run a public daemon in `--headless`. |
| `--open-cmd CMD` | Replace the default browser launcher. `--open-cmd /bin/echo` is the test recipe: the daemon prints the ready URL through your launcher instead of opening a window. |
| `--log-level FILTER` | Global. Passed to `tracing-subscriber`. Examples: `info`, `debug`, `nyx_agent=trace,sqlx=warn`. |

`Ctrl+C` shuts the daemon down cleanly: it closes the HTTP listener,
stops the in-process scheduler, drains any in-flight scan worker,
and closes the SQLite store.

## Walk the first-launch wizard

The SPA at `/setup` asks for five things. Each maps to a single
config field; the daemon writes `nyx-agent.toml` only after you
submit. The wizard refuses to submit until you tick
`i_own_this = true`.

| Field | Writes to | Notes |
|---|---|---|
| AI runtime | `[ai] runtime` | `none`, `anthropic`, `local-llm`, or `claude-code`. `none` keeps the AI exploit-synthesis layer off; static-pass scans still run. |
| Anthropic API key | OS keychain (not TOML) | Required only when runtime is `anthropic`. Persisted under `secrets::ACCOUNT_AI_ANTHROPIC`. |
| Local LLM URL + token | `[ai] api_base` + keychain | Required only when runtime is `local-llm`. OpenAI-compatible endpoint. |
| Sandbox backend | `[sandbox] backend` | `auto` is the default and resolves at runtime; `process` is the safe fallback that always works. See `docs/sandbox.md` (forthcoming) for the full backend matrix. |
| `i_own_this` | (consent gate) | Must be `true` to submit. |

The wizard is mounted on the same daemon, so you do not need to
restart after submitting. The SPA redirects to `/` once the POST
returns `200`.

## Configure a repo

The wizard does not register repos. Add one to `nyx-agent.toml`:

```toml
[[repo]]
name = "demo"
i_own_this = true

[repo.source]
kind = "local-path"
path = "/abs/path/to/your/checkout"
```

Or, for a remote git source:

```toml
[[repo]]
name = "demo"
i_own_this = true

[repo.source]
kind = "git"
url = "https://github.com/your-org/demo.git"
branch = "main"     # optional; defaults to the remote HEAD
# auth = "token-env:GITHUB_TOKEN"   # optional; see config.md
```

Save the file and the daemon picks up the change on the next scan.
There is no SIGHUP reload; the in-flight HTTP / WS / scheduler state
keeps running, the config struct is re-read per scan.

Field reference:

| Field | Meaning |
|---|---|
| `name` | Operator-facing identifier. Used in CLI flags, the UI, and run records. |
| `i_own_this` | Per-repo consent gate. The daemon refuses to ingest without it. |
| `enabled` | Defaults to `true`. Set `false` to keep the entry in the file but skip it during scans. |
| `[repo.source] kind` | `local-path` or `git`. |
| `[repo.source] path` | `local-path` only. Absolute path to a checkout on disk. |
| `[repo.source] url` | `git` only. Clone URL. |
| `[repo.source] branch` | `git` only. Optional branch override. |
| `[repo.source] auth` | `git` only. Credential descriptor: `ssh-key:<path>`, `token-env:<var>`, or `gh-app:<id>`. |

## Trigger a scan

Three ways to kick a scan, all using the same dispatcher.

**From the UI:** click "Scan now" in the SPA. The page subscribes
to the WebSocket and streams `RunStarted`, `RepoStarted`,
`RepoFinished`, and `RunCompleted` frames as they arrive.

**From the CLI:**

```bash
nyx-agent scan --repo demo
```

Without `--repo`, every enabled repo runs. With `--output report.json`
the scan writes a machine-readable report you can pass to
`pr-comment --report` or to an external dashboard. With
`--since-ref main` the report is filtered to findings whose `path`
the working tree changed against `main` (uses `git diff
--name-only`); the scan exits non-zero if the diff cannot be
computed.

**Via HTTP** (assumes the loopback default and an auth token):

```bash
TOKEN=$(cat ~/.local/share/nyx-agent/auth_token)
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/scans?repo=demo
```

The dispatcher responds `202` with a `run_id` you can poll on
`/api/v1/runs/<id>` or subscribe to via `/api/v1/runs/<id>/events`
(WebSocket). See `docs/api.md` (forthcoming) for the full route
reference.

## Read the results

CLI:

```
scan: run 01J... finished in 12_345ms - 1 succeeded, 0 inconclusive, 0 failed
  - demo: Succeeded (diags: 7, 12_180ms)
```

SPA: the findings table shows every persisted finding with severity,
status, repo, path, and the cap label. Filters live on the toolbar.
`Quarantine` is its own tab; findings the AI surfaced but the
dynamic verifier did not yet confirm sit there until promoted.

CLI inspectors:

```bash
nyx-agent inspect quarantine    # quarantined findings + AI candidates
nyx-agent traces                # AI conversation traces (recent first)
nyx-agent traces --finding F... # traces scoped to one finding
```

## Recurring + remote triggers

Two no-touch paths kick a scan without the daemon's UI or CLI:

- `[[schedule]]` cron entries fire from the in-process scheduler.
  See `docs/triggers/cron.md`.
- `POST /webhook/git` accepts HMAC-signed pushes from any
  self-hosted git server. See `docs/triggers/webhook.md`.

For CI gating, the shipped composite GitHub Action runs a scan and
posts a dedup'd PR comment. See `docs/ci/github-actions.md`.

## Common failure modes

### `scan: no repositories selected; configure one in nyx-agent.toml`

`[[repo]]` is empty, every entry has `enabled = false`, or `--repo
NAME` did not match a configured entry. Add a repo per the
[Configure a repo](#configure-a-repo) section.

### Browser opens but the SPA shows "needs configuration"

`nyx-agent.toml` is missing. Either complete the wizard at `/setup`
or write the file by hand and reload. The daemon does not require
a restart.

### `error: bind 127.0.0.1:8765: Address already in use`

Another `nyx-agent serve` (or another process) holds the port. Stop
the other process, or pass `--listen 127.0.0.1:0` to pick a free
port and read the actual address off the `ready on ...` line.

### Scan exits 1 with no diagnostics

The static-pass succeeded but at least one repo reported a failure
(ingest error, scanner panic, or `Inconclusive` outcome). The CLI
report lists per-repo status; the SPA's run detail view shows the
full failure path including `nyx` stderr.

## Related pages

- `docs/install.md`: building from source and verifying `nyx-agent
  doctor`.
- `docs/triggers/cron.md`: recurring scans via `[[schedule]]`.
- `docs/triggers/webhook.md`: push-driven scans via signed HTTP.
- `docs/ci/github-actions.md`: PR-gate composite Action.

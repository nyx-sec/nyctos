# CLI reference

`nyx-agent` is a single binary with eight subcommands. This page
documents every subcommand that currently ships, the flags it accepts,
and the exit codes it returns. Subcommands the binary advertises in
`--help` but that are not yet wired (`reverify`, `budget`) are called
out at the bottom so an operator knows not to script against them.

The shipping binary is `nyx-agent`; the product brand is "Nyctos".
Both names appear here for the reasons explained in `README.md`.

## Global flags

These three flags are accepted by every subcommand (including the
default `serve`). Pass them before the subcommand name, e.g.
`nyx-agent --log-level debug scan`.

| Flag | Default | Effect |
|---|---|---|
| `--config PATH` | `./nyx-agent.toml` | Path to the config file. `nyx-agent` runs with built-in defaults when the path does not exist; see `docs/config.md` (forthcoming). |
| `--state-dir PATH` | `dirs::data_dir()` plus `nyx-agent/` | Override the state directory. Persists runs, findings, repro bundles, ingested repos, logs, and the SQLite store. |
| `--log-level FILTER` | `info` | Filter passed to `tracing-subscriber`. Accepts `info`, `debug`, `nyx_agent=trace,sqlx=warn`, etc. Applied to stderr only. |

When no subcommand is given, `nyx-agent` runs `serve` with no flags.
That is the documented "double-click the binary" path.

The subcommand wiring lives in
`crates/nyx-agent/src/main.rs:209` (`match cli.command.unwrap_or(...)`).
Read that block alongside this page if you need to confirm which
subcommand a flag attaches to.

## `serve`

Run the long-lived HTTP/UI daemon. Default when no subcommand is given.

```bash
nyx-agent serve
```

Binds to `[ui] listen_addr` (default `127.0.0.1:8765`), opens the
operator's default browser at the ready URL, and streams the
`/api/v1/...` API plus the embedded SPA at `/`. The
[`docs/quickstart.md`](quickstart.md) page walks through a first run
end to end.

| Flag | Default | Effect |
|---|---|---|
| `--listen ADDR` | `[ui] listen_addr` from config | Override the listen address. Pass `0.0.0.0:8765` to bind non-loopback; pair with TLS + the bearer token. |
| `--no-open` | off | Skip the browser launch. The daemon still binds and serves. |
| `--headless` | off | Skip the browser launch AND disable bearer-token auth. Intended for CI smoke tests. Never run a public daemon in `--headless`. |
| `--open-cmd CMD` | `webbrowser::open` | Replace the default browser launcher. The ready URL is appended as the last argument. `--open-cmd /bin/echo` is the test recipe. |

Triggers wired into `serve` at startup:

- The HTTP API and WebSocket event stream (`crates/nyx-agent-api/`).
- The in-process cron scheduler, if `[[schedule]]` entries exist.
  See [`docs/triggers/cron.md`](triggers/cron.md).
- `POST /webhook/git`, if `[triggers] webhook_secret_ref` is set.
  See [`docs/triggers/webhook.md`](triggers/webhook.md).
- A bounded MPSC scan queue (depth 16). A full queue returns HTTP 429
  to the caller instead of stalling on backpressure.

`Ctrl+C` shuts the daemon down cleanly: the HTTP listener closes,
the scheduler stops, the in-flight scan worker drains, and the
SQLite store closes.

**Exit codes.** `0` on clean shutdown. `1` on bind failure or any
unrecoverable HTTP server error.

## `scan`

Run a one-shot scan from the command line. Mirrors the `POST
/api/v1/scans` path used by the SPA, but writes its output to
stdout (and optionally to a JSON report on disk).

```bash
nyx-agent scan
nyx-agent scan --repo my-service
nyx-agent scan --repo my-service --output report.json --since-ref origin/main
```

| Flag | Effect |
|---|---|
| `--repo REPO` | Scan a specific repository by name (matched against `[[repos]] name` in config). Pass `--repo` once per repo, or omit to scan every `enabled = true` repository. |
| `--headless` | Accepted for compatibility with `serve` invocations re-used in CI. `scan` never opens a browser, so the flag is a no-op. |
| `--output PATH` | Write a machine-readable JSON report to `PATH`. Consumed by `pr-comment --report` and external dashboards. |
| `--since-ref REF` | Filter the report to findings whose `path` was touched by `git diff --name-only --diff-filter=AMR REF...HEAD` in each workspace. Computed per repo; requires a git workspace. |

Each invocation drives the full pipeline: ingest, static lane via
the upstream `nyx` scanner, AI payload synthesis, spec derivation,
chain reasoning, novel-finding discovery, AI exploration, and the
deterministic payload verifier. Each AI pass is a no-op when
`[ai] runtime = "none"` or no API key is available; the static
lane always runs.

The stdout summary line, then per-repo outcome lines, are emitted
in this order:

<!-- nyx: verbatim -->
```
scan: run <run-id> finished in <ms>ms - <n> succeeded, <n> inconclusive, <n> failed
  - <repo>: <Outcome> (diags: <n>, <ms>ms)
```
<!-- /nyx: verbatim -->

When `--output PATH` is supplied, the JSON report is written after
the verifier pass completes and includes both the findings table
and any cross-repo chains discovered in the run.

**Edge cases.**

- No matching repos: stderr emits `scan: no repositories selected;
  configure one in nyx-agent.toml` and exit `1`.
- `--since-ref` starts with `-`: scan refuses, since the value
  would be parsed as a git option (`scan: --since-ref '...' must
  not start with '-'`). Exit `1`.
- `--since-ref` resolves to a ref `git diff` cannot compute (bad
  ref, shallow clone): the diff command's stderr is propagated and
  exit code is `1`. CI fails loudly rather than silently scanning
  every path.
- Repo ingest fails (auth, attestation, network): the failing repo
  is reported and `RepoFailed` is emitted on the event bus. If
  every repo fails ingest, the run is finalised `Failed` and scan
  exits `1`.

**Exit codes.** `0` if every repo succeeded and no ingest errors
occurred. `1` if any repo failed or scan refused to start.

## `pr-comment`

Post (or update) a dedup'd PR comment summarising `Verified`
findings plus cross-repo chain findings from a previous
`scan --output` run. Intended for GitHub Actions; reads its config
from flags plus the standard GHA environment variables.

```bash
nyx-agent scan --output report.json --since-ref ${{ github.base_ref }}
nyx-agent pr-comment --report report.json
```

| Flag | Default | Effect |
|---|---|---|
| `--report PATH` | (required) | Path to `report.json` produced by `scan --output`. |
| `--repo OWNER/REPO` | `$GITHUB_REPOSITORY` | Target GitHub repository. Required outside Actions. |
| `--pr N` | parsed from `$GITHUB_REF` or `$GITHUB_EVENT_PATH` | Pull request number. |
| `--ui-url URL` | none | Operator-local UI base. Each finding links back here. Trailing slash optional. |
| `--gh-api URL` | `https://api.github.com` | GitHub REST base. Override for GitHub Enterprise. |
| `--token-env ENV` | `GITHUB_TOKEN` | Name of the env var that holds the PAT or GitHub Apps token. The token never appears in argv or logs. |

Dedup is achieved by embedding a hidden HTML marker
(`<!-- nyx-agent:pr-comment v1 -->`) at the top of the comment
body. Subsequent runs list the PR's comments, locate the carrier,
and `PATCH` it in place. There is at most one Nyctos comment per
PR.

Comments are only created for `Verified` findings and cross-repo
chain members. `Open`, `Quarantine`, and `Inconclusive` findings
stay in the operator's local UI; the PR comment is intentionally
narrow so reviewers see signal, not noise.

**Edge cases.**

- Missing token: stderr emits `pr-comment: env var '<name>' is
  empty or unset` and exit `1`.
- Missing PR number: stderr emits `pr-comment: --pr not provided
  and could not be derived from $GITHUB_REF /
  $GITHUB_EVENT_PATH` and exit `1`.
- Report contains nothing post-filter: stdout reports `report
  contains no Confirmed or cross-repo chain findings; skipping
  comment` and exit `0`. No comment is created.

**Exit codes.** `0` on success or empty-report skip. `1` on bad
config, GitHub API failure, or transport error. See
[`docs/ci/github-actions.md`](ci/github-actions.md) for the
shipped composite Action that wires this together.

## `inspect`

Inspect persisted state. Subcommand-driven; each variant prints a
terse listing the operator can grep, pipe, or paste into a ticket.

```bash
nyx-agent inspect quarantine
```

### `inspect quarantine`

List AI-discovered findings and candidate findings that are still
in quarantine, i.e. not yet promoted by the dynamic-confirm
verifier or a manual operator. Output is one row per finding /
candidate plus a tally line:

<!-- nyx: verbatim -->
```
kind     id                                 cap                  repo            path:line
finding  <id>                               <cap>                <repo>          <path>:<line>
candid.  <id>                               <cap>                <repo>          <path>:<line>

<n> finding(s) + <m> candidate(s) quarantined
```
<!-- /nyx: verbatim -->

When the quarantine is empty, stdout is the single line
`quarantine: empty` and exit `0`.

**Exit codes.** `0` always (read-only).

## `traces`

Print AI conversation traces persisted by the store. Optionally
scoped to a finding.

```bash
nyx-agent traces
nyx-agent traces --finding <finding-id>
```

| Flag | Effect |
|---|---|
| `--finding FINDING` | Scope the listing to a single finding id. Omit to list every trace row currently persisted (sorted by `started_at`). |

The omitted-`--finding` form is a transitional listing built by
unioning every per-task-kind bucket
(`PayloadSynthesis`, `SpecDerivation`, `ChainReasoning`,
`NovelFindings`, `Exploration`). A dedicated global reader will
replace it once the store grows one.

Columns: `task`, `runtime`, `model`, `prompt_version`, `cost($)`,
`dur_ms`, `finding_id`. Costs are formatted from
`cost_usd_micros / 1_000_000` to four decimal places.

When the result set is empty, stdout is `traces: no rows match`
and exit `0`.

**Exit codes.** `0` always (read-only).

## `doctor`

Verify that the state directory, config, SQLite schema, upstream
`nyx` binary, optional `claude-code` CLI, and sandbox backend
selection look healthy. Runs before logging is initialised so it
prints to stdout directly.

```bash
nyx-agent doctor
```

Output, in order:

1. State directory location.
2. Log file path (`state-dir/logs/nyx-agent.log.json`).
3. Config status: `OK at <path>` or `not found at <path>
   (using defaults)`.
4. SQLite store path and current schema version.
5. Upstream `nyx`: resolved binary path, detected version, and the
   minimum supported version. Failure modes are emitted on stderr
   with one of:
   - `nyx FAIL: not found` plus an `install the upstream nyx
     scanner ...` hint.
   - `nyx FAIL: version too old (...)`.
6. `claude-code`: detected version and path, or `unavailable (...)`
   when the binary is missing or below the minimum.
7. Sandbox backend selection for the chain and fast lanes, with
   the simultaneous-job caps from
   `LaneConcurrency::defaults()`.

The `doctor` subcommand exits non-zero only when the `nyx`
discovery fails. `claude-code` and sandbox checks are
informational; they will move to gating once their respective
configuration surfaces land.

[`docs/install.md`](install.md) covers each line in more depth,
including the recovery action for every failure mode.

**Exit codes.** `0` if the upstream `nyx` binary is present and
satisfies `[nyx] min_version`. `1` if `nyx` is missing or too old.

## Stubs that are not yet wired

`nyx-agent --help` lists two further subcommands that `clap`
advertises but the binary panics on:

| Subcommand | Status |
|---|---|
| `reverify --run RUN --finding FINDING` | Stub. Calls `todo!()` at `crates/nyx-agent/src/main.rs:249`. Will surface a manual re-verification path against a previously-confirmed finding. |
| `budget` | Stub. Same `todo!()` site. Will print AI spend rolled up by run and by prompt version. |

Until those panics are replaced with real wiring, do not script
against them; the binary will abort with an `unimplemented!`
message and exit `101` (Rust's default panic exit code).

## Cross-links

- [`docs/install.md`](install.md): toolchain, `nyx` scanner setup,
  the per-line `doctor` walkthrough.
- [`docs/quickstart.md`](quickstart.md): the same surfaces in
  worked-example form.
- [`docs/triggers/cron.md`](triggers/cron.md) and
  [`docs/triggers/webhook.md`](triggers/webhook.md): scan-trigger
  surfaces baked into `serve`.
- [`docs/ci/github-actions.md`](ci/github-actions.md): the shipped
  composite Action that drives `scan --output` plus `pr-comment`.

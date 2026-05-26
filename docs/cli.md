# CLI reference

`nyctos` is a single binary with ten subcommands. This page
documents every subcommand that currently ships, the flags it accepts,
and the exit codes it returns. Subcommands the binary advertises in
`--help` but that are not yet wired (`reverify`, `budget`) are called
out at the bottom so an operator knows not to script against them.

The shipping binary is `nyctos`; the product brand is "Nyctos".
Both names appear here for the reasons explained in `README.md`.

## Global flags

These three flags are accepted by every subcommand (including the
default `serve`). Pass them before the subcommand name, e.g.
`nyctos --log-level debug scan`.

| Flag | Default | Effect |
|---|---|---|
| `--config PATH` | `./nyctos.toml` | Path to the config file. `nyctos` runs with built-in defaults when the path does not exist; see `docs/config.md` (forthcoming). |
| `--state-dir PATH` | `dirs::data_dir()` plus `nyctos/` | Override the state directory. Persists runs, findings, repro bundles, ingested repos, logs, and the SQLite store. |
| `--log-level FILTER` | `info` | Filter passed to `tracing-subscriber`. Accepts `info`, `debug`, `nyctos=trace,sqlx=warn`, etc. Applied to stderr only. |

When no subcommand is given, `nyctos` runs `serve` with no flags.
That is the documented "double-click the binary" path.

The subcommand wiring lives in `crates/nyctos/src/main.rs`
(`match cli.command.unwrap_or(...)`). Read that block alongside this
page if you need to confirm which subcommand a flag attaches to.

## `serve`

Run the long-lived HTTP/UI daemon. Default when no subcommand is given.

```bash
nyctos serve
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

- The HTTP API and WebSocket event stream (`crates/nyctos-api/`).
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

## `reset db`

Delete the local SQLite store for the resolved state directory.

```bash
nyctos reset db
nyctos reset db --yes
```

`reset db` removes `state.db`, `state.db-wal`, and `state.db-shm`.
It leaves the rest of the state directory alone, including
`auth_token`, logs, traces, bundles, ingested repos, and project
workspaces.

Before deleting files, the command checks whether `lsof` reports the
database as open and refuses to continue when a running `nyctos`
process still holds it. Without `--yes`, it prompts for `reset` on
stdin.

| Flag | Default | Effect |
|---|---|---|
| `--yes`, `-y` | off | Skip the interactive confirmation prompt. |

**Exit codes.** `0` when the files were removed or no database files
existed. `1` when the database is open or confirmation fails.

## `scan`

Run a one-shot scan from the command line. Mirrors the `POST
/api/v1/projects/:project_id/scan` path used by the SPA, but writes
its output to stdout (and optionally to a JSON report on disk).

Scan selection is project-scoped. `--project NAME` (repeatable)
targets a whole project; pair with `--repo NAME` (repeatable) to
narrow within the selected projects. Bare `--repo` without a
`--project` is rejected to keep scoping explicit.

```bash
nyctos scan
nyctos scan --project acme-app
nyctos scan --project acme-app --repo acme-backend
nyctos scan --project acme-app --output report.json --since-ref origin/main
nyctos scan --project acme-app --exploit-mode --allow-state-changing-live-probes --business-template tenant_object_isolation
nyctos scan --project acme-app --research-mode
nyctos scan --project acme-app --unsafe-attack-agent
```

| Flag | Effect |
|---|---|
| `--project PROJECT` | Project to scan, by name from `[[project]] name` in config. Pass once per project; omit to scan every enabled project. |
| `--repo REPO` | Repository to scan, narrowed within `--project`. Requires at least one `--project` to be set. Matched against `[[project.repo]] name`. Pass `--repo` once per repo. |
| `--headless` | Suppress human-readable stdout so only `--output PATH` carries machine-readable signal. Errors still go to stderr. Pair with `--output` in CI lanes that consume the JSON report and ignore console output. |
| `--output PATH` | Write a machine-readable JSON report to `PATH`. Consumed by `pr-comment --report` and external dashboards. |
| `--since-ref REF` | Filter the report to findings whose `path` was touched by `git diff --name-only --diff-filter=AMR REF...HEAD` in each workspace. Computed per repo; requires a git workspace. |
| `--exploit-mode` | Enable exploit mode for this scan without editing `nyctos.toml`. State-changing probes still also require `--allow-state-changing-live-probes`. |
| `--allow-state-changing-live-probes` | Allow mutating live probes for this scan when exploit mode is enabled. |
| `--exploit-dry-run` | Evaluate guarded live plans and write audit records without sending HTTP/browser traffic. |
| `--research-mode` | Enable Vuln Research Mode for this scan. Adds product-invariant hypotheses and deeper planning/exploration without relaxing live execution gates. |
| `--unsafe-attack-agent` | Run the final unrestricted local attack-agent phase: seven serial specialists, a critical chain hunter, and final attack triage. Intended only for disposable user-owned dev apps. |
| `--no-business-logic-templates` | Disable business-logic template candidate synthesis for this scan. |
| `--business-template ID` | Restrict business-logic template synthesis to the given id. Repeat for multiple ids. |
| `--no-orchestration` | Run the scan without starting or health-checking the project's launch profile. Static scanning and source-only analysis still run. |
| `--app-url URL` | One-shot local app URL for this scan. Requires exactly one selected project. |
| `--health-url URL` | One-shot readiness URL. Defaults to `--app-url` when omitted. |
| `--health-timeout-secs N` | Readiness timeout for the one-shot URL check. |
| `--build-command CMD` | One-shot setup command. Repeat for multiple commands. |
| `--start-command CMD` | One-shot app start command. Repeat for multiple commands. |
| `--seed-command CMD` | One-shot seed command run after readiness. Repeat for multiple commands. |
| `--login-command CMD` | One-shot login/session setup command run after seed. Repeat for multiple commands. |
| `--reset-command CMD` | One-shot reset command used after state-changing probes. Repeat for multiple commands. |
| `--stop-command CMD` | One-shot teardown command. Repeat for multiple commands. |

Each invocation drives the full pipeline per project: ingest, static
lane via the upstream `nyx` scanner, AI payload synthesis, spec
derivation, chain reasoning, novel-finding discovery, AI exploration,
and the deterministic payload verifier. Each AI pass is a no-op
when `[ai] runtime = "none"` or no API key is available; the static
lane always runs. When multiple projects are selected, the
dispatcher walks them sequentially and emits one run per project.

When a project has a default launch profile, `scan` starts the local
target app, waits for health checks, runs seed/login hooks, captures
target stdout/stderr under the state directory, and shuts the app down
after the run. Omit launch configuration, or pass `--no-orchestration`,
to keep the older static-only behavior.

The stdout summary line, then per-repo outcome lines, are emitted
in this order (one block per project):

<!-- nyx: verbatim -->
```
scan: project <project> run <run-id> finished in <ms>ms - <n> succeeded, <n> inconclusive, <n> failed
  - <repo>: <Outcome> (diags: <n>, <ms>ms)
```
<!-- /nyx: verbatim -->

When `--output PATH` is supplied, the JSON report is written after
the verifier pass completes and includes both the findings table
and any cross-repo chains discovered in the run.

**Edge cases.**

- `--repo` without `--project`: stderr emits `scan: --repo requires
  --project context (or use --project to scan whole projects)` and
  exit `2`.
- No matching repos: stderr emits `scan: no repositories selected;
  configure one in nyctos.toml` and exit `1`.
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
occurred. `1` if any repo failed or scan refused to start. `2` if
`--repo` was passed without `--project`.

## `business-logic`

Inspect business-logic pentest template metadata.

```bash
nyctos business-logic templates
nyctos business-logic templates --json
```

The JSON form returns the same registry exposed by
`GET /api/v1/business-logic/templates`, including template id,
version, category, mutability, route-pattern support, oracle
description, and whether the template is executable or metadata-only.

## `project`

Manage `Project` rows in the agent's state DB. Projects are the
top-level scan unit; repos are nested under a project via
`[[project.repo]]` in `nyctos.toml` and via a `project_id` FK in
the SQLite store. Every CLI/API/sandbox surface operates per
project, so the canonical first step in a fresh deployment is
`nyctos project create`.

```bash
nyctos project create acme-app --description "Acme web product" --target-base-url http://localhost:3000
nyctos project list
nyctos project show acme-app
nyctos project add-repo acme-app acme-backend --path /abs/path/backend --i-own-this
nyctos project add-repo acme-app acme-frontend --git-url https://github.com/acme/frontend.git --branch main --i-own-this
nyctos project delete acme-app
```

### `project create NAME`

Create a project row by name. The name must be unique; the daemon
returns an error if the name is already taken.

| Flag | Effect |
|---|---|
| `--description TEXT` | Optional free-form description shown in the SPA's project header. |
| `--target-base-url URL` | Optional base URL for the project's deployed target. Flows into the sandbox env-builder as a compose override so confirmed exploits can address the right host. |

### `project list`

List every project row, alphabetical by name.

### `project show NAME`

Print one project plus the repos attached to it. Useful as a
sanity check after `add-repo`.

### `project delete NAME`

Delete a project by name. Cascades to attached repos via the FK,
so removing a project removes the repo rows it owned as well.

### `project add-repo PROJECT NAME`

Attach a repo to an existing project. The source is either local
(`--path`) or git (`--git-url`); the two are mutually exclusive.

| Flag | Effect |
|---|---|
| `--path PATH` | Absolute path to a checkout on disk. Mutually exclusive with `--git-url`. |
| `--git-url URL` | Remote git clone URL. Mutually exclusive with `--path`. |
| `--branch REF` | Optional branch hint for git sources. Defaults to the remote HEAD. |
| `--auth DESCRIPTOR` | Optional credential descriptor for git sources. Accepts `ssh-key:<path>`, `token-env:<var>`, or `gh-app:<id>`. |
| `--i-own-this` | Required attestation. The daemon refuses to ingest a repo without it. |

**Exit codes.** `0` on success. `1` on a missing project, a
duplicate name, or a store error.

## `pr-comment`

Post (or update) a dedup'd PR comment summarising `Verified`
findings plus cross-repo chain findings from a previous
`scan --output` run. Intended for GitHub Actions; reads its config
from flags plus the standard GHA environment variables.

```bash
nyctos scan --output report.json --since-ref ${{ github.base_ref }}
nyctos pr-comment --report report.json
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
(`<!-- nyctos:pr-comment v1 -->`) at the top of the comment
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
nyctos inspect quarantine
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
nyctos traces
nyctos traces --finding <finding-id>
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
`nyx` binary, optional CLI AI adapters, and sandbox backend selection
look healthy. Runs before logging is initialised so it prints to
stdout directly.

```bash
nyctos doctor
```

Output, in order:

1. State directory location.
2. Log file path (`state-dir/logs/nyctos.log.json`).
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
7. `codex`: detected version and path, or `unavailable (...)` when
   the binary is missing or below the minimum.
8. Sandbox backend selection for the chain and fast lanes, with
   the simultaneous-job caps. Each line ends with `default` when
   the cap is the built-in fallback (chain 2 / fast 8 from
   `LaneConcurrency::defaults()`) and `configured` when the
   operator set `[performance] chain_lane_concurrency` /
   `fast_lane_concurrency` in `nyctos.toml`.

The `doctor` subcommand exits non-zero only when the `nyx`
discovery fails. CLI AI adapter and sandbox checks are informational.

[`docs/install.md`](install.md) covers each line in more depth,
including the recovery action for every failure mode.

**Exit codes.** `0` if the upstream `nyx` binary is present and
satisfies `[nyx] min_version`. `1` if `nyx` is missing or too old.

## Stubs that are not yet wired

`nyctos --help` lists two further subcommands that `clap`
advertises but the binary panics on:

| Subcommand | Status |
|---|---|
| `reverify --run RUN --finding FINDING` | Stub. Calls `todo!()` at `crates/nyctos/src/main.rs:249`. Will surface a manual re-verification path against a previously-confirmed finding. |
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

# HTTP API

The daemon serves a versioned HTTP and WebSocket API under
`/api/v1/` on the loopback address. The SPA at `/` and the
WebSocket events stream at `/api/v1/events` are the primary
consumers; every endpoint is reachable from `curl` once the bearer
token is known.

This page lists every route, the request shape, the response shape,
and the status codes the handler can emit. Routes are grouped by
concern.

## Conventions

- Base path: `/api/v1`. The daemon binds to `127.0.0.1:<port>` by
  default. See [config.md](config.md#general) for the bind
  address.
- Authentication: a bearer token (`Authorization: Bearer <token>`)
  on every route except `/api/v1/health`, the three setup wizard
  routes while setup is pending, and `POST /webhook/git` (which
  carries its own HMAC). The token lives at
  `<state_dir>/auth_token` and is minted on first daemon launch;
  see [state-dir.md](state-dir.md).
- Query-string token fallback: requests may also pass
  `?token=<token>` instead of the header. Useful for WebSocket
  clients that cannot set request headers.
- Content type: every request and response body is JSON unless
  the route is documented otherwise (markdown, HTML, tar, SSE).
- Error envelope: every non-success response is
  `{"error": {"code": "<machine_code>", "message": "<text>"}}`.
  Codes are `not_found`, `bad_request`, `unauthorized`,
  `store_error`, `scan_rejected`, `shutting_down`,
  `scan_backpressure`, `scan_internal`, `internal`.
- Timestamps: every `*_at` or `*_at_ms` field is epoch
  milliseconds. Durations carry the `_ms` suffix.

## Route summary

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/v1/health` | Liveness probe, version |
| GET    | `/api/v1/setup/status` | Wizard state, config path |
| POST   | `/api/v1/setup` | Wizard commit |
| POST   | `/api/v1/setup/doctor` | Wizard pre-commit checks |
| GET    | `/api/v1/projects` | List projects |
| POST   | `/api/v1/projects` | Create project |
| GET    | `/api/v1/projects/:id` | Get project |
| PATCH  | `/api/v1/projects/:id` | Patch project |
| DELETE | `/api/v1/projects/:id` | Delete project (cascades to repos) |
| GET    | `/api/v1/projects/:id/repos` | List repos in project |
| POST   | `/api/v1/projects/:id/repos` | Add repo to project |
| POST   | `/api/v1/projects/:id/repos/test` | Probe repo connectivity |
| GET    | `/api/v1/projects/:id/repos/:name` | Get repo |
| PATCH  | `/api/v1/projects/:id/repos/:name` | Patch repo |
| DELETE | `/api/v1/projects/:id/repos/:name` | Delete repo (clears workspace) |
| POST   | `/api/v1/projects/:id/scan` | Trigger a scan |
| POST   | `/api/v1/projects/:id/pentest` | Start a project pentest |
| GET    | `/api/v1/projects/:id/vulnerabilities` | Verified vulnerabilities for project |
| GET    | `/api/v1/runs` | List runs by status |
| GET    | `/api/v1/runs/:id` | Get run |
| GET    | `/api/v1/runs/:id/findings` | Findings for run plus diff status |
| GET    | `/api/v1/runs/:id/verification-attempts` | Live verification attempts and artifacts |
| GET    | `/api/v1/runs/:id/vulnerabilities` | Verified vulnerabilities for run |
| GET    | `/api/v1/runs/:id/events.jsonl` | Download persisted run event stream |
| GET    | `/api/v1/runs/:id/summary` | Run-card JSON |
| GET    | `/api/v1/runs/:id/summary.md` | Run-card markdown |
| GET    | `/api/v1/runs/:id/summary.html` | Run-card HTML |
| GET    | `/api/v1/findings` | List findings (filtered) |
| GET    | `/api/v1/vulnerabilities` | Verified vulnerabilities across projects |
| GET    | `/api/v1/findings/:id` | Get finding |
| POST   | `/api/v1/findings/:id/repro-bundle` | Build a repro bundle |
| GET    | `/api/v1/findings/:id/repro-bundle.tar` | Download bundle tar |
| POST   | `/api/v1/findings/:id/replay` | Replay bundle (SSE stream) |
| GET    | `/api/v1/findings/:id/traces` | AI traces for finding |
| GET    | `/api/v1/traces/:id` | Get trace |
| GET    | `/api/v1/chains` | List chains (requires `run_id`) |
| GET    | `/api/v1/chains/:id` | Get chain |
| GET    | `/api/v1/quarantine` | List quarantined items |
| POST   | `/api/v1/quarantine/:id/promote` | Promote out of quarantine |
| POST   | `/api/v1/quarantine/:id/dismiss` | Dismiss quarantined item |
| GET    | `/api/v1/events` | WebSocket event stream |
| POST   | `/webhook/git` | HMAC-authed git push webhook |

## Health

`GET /api/v1/health`

Liveness probe. Bypasses bearer auth. Response:

```json
{ "status": "ok", "version": "0.1.0" }
```

## Setup wizard

`GET /api/v1/setup/status`

Returns whether `nyctos.toml` exists on disk and where the wizard
would write it.

```json
{
  "complete": false,
  "config_path": "/Users/me/Library/Application Support/nyctos/nyctos.toml",
  "ai_runtime": "none",
  "sandbox_backend": "auto"
}
```

`POST /api/v1/setup`

Commits the wizard's three choices to disk. The handler writes
`nyctos.toml` atomically (mode 0600) and stashes secrets in the OS
keychain.

Request:

```json
{
  "ai_runtime": "anthropic | none | local-llm | claude-code",
  "anthropic_api_key": "sk-...",
  "local_llm_url": "http://127.0.0.1:8080/v1",
  "local_llm_token": null,
  "sandbox_backend": "auto | process | birdcage | libkrun | firecracker | docker",
  "i_own_this": true
}
```

`i_own_this` must be `true`. The daemon refuses to write the
config otherwise.

Response: `{ "ok": true, "config_path": "..." }`.

Errors: 400 (`i_own_this` false; unknown enum value; missing API
key for `anthropic`; missing endpoint for `local-llm`), 500
(keychain unreachable, fs write failed).

`POST /api/v1/setup/doctor`

Per-check probe used by the wizard's preflight step. Returns one
row per check rather than a single pass/fail so the UI can surface
targeted hints.

Request:

```json
{ "ai_runtime": "claude-code", "sandbox_backend": "birdcage" }
```

Response:

```json
{
  "checks": [
    { "name": "state-dir", "passed": true, "message": "state directory writable" },
    { "name": "ai-claude-code", "passed": true, "message": "claude binary on PATH at /usr/local/bin/claude" },
    { "name": "sandbox", "passed": true, "message": "birdcage ready on this host" }
  ]
}
```

The sandbox check routes through `nyctos_sandbox::probe` so its
verdict matches what the run-time auto-selector would see. `auto`
returns the advisory message `Backend will be chosen at scan time`.

## Projects

A project owns repos. Scans run against a project; a project
without repos is legal but scanning it does nothing.

`GET /api/v1/projects`

Returns `Vec<ProjectRecord>`. Fields:

| Field | Type | Notes |
|---|---|---|
| `id` | string | `proj-<slug>-<epoch-hex>` |
| `name` | string | unique |
| `description` | string \| null | operator note |
| `target_base_url` | string \| null | hint for HTTP-shaped scans |
| `env_config_json` | string \| null | serialised `nyctos-env` envelope |
| `created_at` | number | epoch ms |
| `updated_at` | number | epoch ms |

`POST /api/v1/projects`

```json
{
  "name": "alpha",
  "description": "demo project",
  "target_base_url": "http://localhost:3000",
  "env_config": { ... }
}
```

`env_config` is any JSON; the daemon re-serialises it into
`env_config_json` verbatim. Returns the created `ProjectRecord`.
400 on empty name or duplicate name.

`GET /api/v1/projects/:id`

Returns the project. 404 if absent.

`PATCH /api/v1/projects/:id`

Tri-state patch over the mutable fields:

```json
{
  "description": "new value | null | <omit>",
  "target_base_url": "...",
  "env_config": { ... } 
}
```

Each field has three modes: omit the key to leave unchanged, send
`null` to clear, send a value to set. Returns the patched record.

`DELETE /api/v1/projects/:id`

Removes the project. Cascades to every repo via the schema's
foreign-key constraint. Response:

```json
{ "ok": true, "message": "deleted 1 project row(s); repos cascaded" }
```

## Repos

A repo is the unit of scan execution. Repos live under one
project. Names are globally unique across the install (the schema
makes `repos.name` a primary key).

`GET /api/v1/projects/:id/repos`

`Vec<RepoRecord>`. Fields include `name`, `project_id`,
`source_kind`, `source_url_or_path`, `branch`, `auth_ref`,
`i_own_this`, `last_scan_run_id`, `last_scan_finished_at`,
`created_at`, `updated_at`.

`POST /api/v1/projects/:id/repos`

```json
{
  "name": "alpha",
  "source_kind": "git | local-path | github | gitlab | local",
  "source_url_or_path": "git@github.com:org/repo.git",
  "branch": "main",
  "auth_ref": "env:GITHUB_TOKEN",
  "i_own_this": true
}
```

`i_own_this` must be `true`. The handler refuses to silently
re-home a repo that already exists under a different project.

`POST /api/v1/projects/:id/repos/test`

Read-only connectivity probe. For `git` / `github` / `gitlab`,
runs `git -c credential.helper= ls-remote --exit-code <url>` with
a 15s timeout. For `local-path` / `local`, stats the path and
parses the on-disk `.git/config` to surface the existing remote.

Request:

```json
{
  "source_kind": "git",
  "source_url_or_path": "git@github.com:org/repo.git",
  "branch": "main"
}
```

Response:

```json
{
  "ok": true,
  "message": "ls-remote reached upstream; branch `main` exists",
  "on_disk_git_remote": null
}
```

`on_disk_git_remote` is populated only for local-path probes.

`GET /api/v1/projects/:id/repos/:name`

Returns the repo. 404 when the repo is missing or belongs to a
different project.

`PATCH /api/v1/projects/:id/repos/:name`

Same tri-state semantics as the project patch. `i_own_this`
cannot be cleared via PATCH; remove the repo instead.

`DELETE /api/v1/projects/:id/repos/:name`

Removes the row and the on-disk workspace at
`<state>/repos/<name>/`. Returns a status body whose message
notes whether the workspace was removed cleanly.

## Scans

`POST /api/v1/projects/:id/scan?repo=<name>`

Triggers a scan. The optional `repo` filter scopes the run to a
single repo; without it every enabled repo in the project is
scanned.

Response: `{ "run_id": "run-..." }`.

Status codes: 200 on dispatch, 400 (`scan_rejected`) on bad
input, 429 (`scan_backpressure`) when the dispatcher queue is
full, 503 (`shutting_down`) during a graceful exit.

### Business-Logic Template Registry

`GET /api/v1/business-logic/templates`

Lists registered business-logic templates. Each row includes stable
`id`, `version`, title, category, mutability, required role
descriptor, seed-data description, supported route patterns, oracle
description, default severity, and whether the template is executable
or metadata-only.

```json
[
  {
    "id": "tenant_object_isolation",
    "version": "1",
    "title": "Tenant/object isolation",
    "category": "authorization",
    "mutability": "state_changing",
    "required_roles": ["two_distinct_non_anonymous_roles"],
    "supported_route_patterns": ["POST collection route paired with GET detail route"],
    "availability": "executable"
  }
]
```

`POST /api/v1/projects/:id/pentest`

Starts a project-scoped pentest after launch-profile readiness
checks pass. The request body is optional; omitted fields default to
safe mode:

```json
{
  "exploit_mode_enabled": false,
  "allow_state_changing_live_probes": false,
  "exploit_dry_run": false,
  "business_logic_templates_enabled": true,
  "research_mode_enabled": false,
  "unsafe_attack_agent_enabled": false,
  "business_logic_template_ids": ["tenant_object_isolation"]
}
```

These fields are per-run overrides, not persistent config writes.
The project detail page's **Start pentest** button opens the same
safety options. Leave both values `false` for the default
non-destructive run. Set both to `true` only for owned, disposable
targets where state-changing probes are acceptable.

`allow_state_changing_live_probes = true` is rejected unless
`exploit_mode_enabled = true`; this prevents older clients or stale
config from enabling mutating live probes without the explicit
exploit-mode opt-in.

`business_logic_template_ids` restricts synthesis to specific
template ids for this run. Unknown ids are rejected with 400.
`exploit_dry_run = true` lets operators inspect generated candidates
and policy audit rows without sending guarded live traffic.

`research_mode_enabled = true` enables Vuln Research Mode for this run;
omit it to use `[run] research_mode_enabled` from config. It adds
`ResearchMode` product-invariant candidates, prioritizes them in AI
attack planning/exploration, and records research provenance on
candidates and research-mode exploration findings. It is not an
execution-safety override; exploit mode, state-changing, target-scope,
request-cap, rate-limit, dry-run, and reset gates still apply.

`unsafe_attack_agent_enabled = true` runs the final unrestricted local
attack-agent phase for this run. It is intended for disposable
user-owned dev apps and does not route the agent's actions through the
guarded live-verifier policy. The phase runs seven specialist agents,
then a critical chain hunter and final triage pass.

The attack-agent passes run serially in this order:
`business_logic`, `payments_billing`, `user_data_privacy`,
`auth_session`, `api_input`, `infra_dev_prod`, `abuse_automation`,
`critical_chain_hunter`, `triage`. Each pass gets the same target URLs
and workspaces, plus the current candidates and verified
vulnerabilities. Findings from earlier passes can therefore become
context for later passes. Each pass writes its own trace artifact
directory and records an `agent_profile` in the trace verifier blob.

Response: `{ "run_id": "run-..." }`.

Status codes: 200 on dispatch, 400 (`scan_rejected`) on incomplete
launch profile, missing repos, unsafe exploit options, or other bad
input; 429 (`scan_backpressure`) when the dispatcher queue is full;
503 (`shutting_down`) during a graceful exit.

## Runs

`GET /api/v1/runs?status=<status>&project_id=<project_id>`

Defaults to `status=Running`. Use `Finished`, `Failed`, etc., to
filter. `project_id` is optional; when present, the project must exist
and only that project's runs are returned. Returns `Vec<RunRecord>`.

`GET /api/v1/runs/:id`

Returns the run. 404 if absent.

`GET /api/v1/runs/:id/findings`

Findings produced by the run, each tagged with a diff status
against the most recent prior run on the install:

```json
{
  "run_id": "run-...",
  "prior_run_id": "run-...",
  "items": [
    {
      "id": "...",
      "...": "...",
      "diff_status": "new | unchanged"
    }
  ]
}
```

`diff_status` is `new` when `first_seen >= run.started_at`,
otherwise `unchanged`. The `regressed` and `closed` variants are
reserved for when a per-run finding-membership history lands.

`GET /api/v1/runs/:id/verification-attempts`

Returns `Vec<VerificationAttemptRecord>` for the run. Browser
verification attempts include `artifact_paths` pointing at durable
evidence files under the state directory: redacted replay JSON and
script files, screenshots, DOM/focused HTML captures, console logs,
action/navigation timelines, and either a Playwright trace zip or a
trace-unavailable note when trace capture could not be used safely.

`GET /api/v1/runs/:id/candidates`

Returns `Vec<PentestCandidateRecord>` for the run. Candidates are
unverified hypotheses until a live verification attempt confirms them.
`source` and `source_ids` preserve attribution across Nyx signals,
route/API discovery, OpenAPI specs, JavaScript bundle endpoint
extraction, forms, and optional scanner imports.
Business-logic template candidates also include
`affected_components[*].template_provenance` with `template_id` and
`template_version`.

`GET /api/v1/runs/:id/business-logic`

Returns per-run business-logic synthesis counts and skip reasons:

```json
{
  "run_id": "run-...",
  "templates_considered": 2,
  "candidates_generated": 1,
  "templates_skipped": 1,
  "dry_run": true,
  "templates": [
    {
      "template_id": "tenant_object_isolation",
      "template_version": "1",
      "generated_count": 1,
      "skipped_count": 0,
      "skip_reasons": [],
      "dry_run": true
    },
    {
      "template_id": "password_reset_token_misuse",
      "template_version": "1",
      "generated_count": 0,
      "skipped_count": 1,
      "skip_reasons": ["current route/auth model does not expose reset-token seed data or a safe inbox capture path"],
      "dry_run": true
    }
  ]
}
```

`GET /api/v1/runs/:id/vulnerabilities`

Returns live-verified vulnerabilities for the run. Each row carries
`verification_attempt_ids`; resolve those through
`/runs/:id/verification-attempts` to inspect replay evidence.
Business-logic verified vulnerabilities retain the candidate's
`template_provenance` in `affected_components`.

`GET /api/v1/runs/:id/events.jsonl`

Streams the persisted live-event log for the run as newline-delimited
JSON. Each line is `{ "ts_ms": <epoch-ms>, "event": <AgentEvent> }`.

`GET /api/v1/runs/:id/summary`

Run card as JSON. Carries per-repo counts, per-severity totals,
chain links, and the AI cost summary. Backed by
`nyctos_core::report::build_run_card`.

`GET /api/v1/runs/:id/summary.md`

Same run card rendered to markdown. `Content-Type:
text/markdown; charset=utf-8`.

`GET /api/v1/runs/:id/summary.html`

Same run card rendered to HTML. `Content-Type: text/html;
charset=utf-8`.

## Findings

`GET /api/v1/findings`

Composite filter; every field is optional and ANDed server-side.
Quarantined rows are hidden unless `include_quarantine=true`.

| Query | Type | Notes |
|---|---|---|
| `repo` | string | exact match |
| `run_id` | string | exact match |
| `cap` | string | capability tag |
| `origin` | string | `Static` / `AiExploration` / etc. |
| `status` | string | `Open` / `Verified` / `Closed` / `Quarantine` |
| `severity` | string | `Low` / `Medium` / `High` / `Critical` |
| `triage_state` | string | `Open` / `Triaged` / etc. |
| `chain_id` | string | restrict to chain members |
| `include_quarantine` | bool | default `false` |

Returns `Vec<FindingRecord>`.

`GET /api/v1/findings/:id`

Returns the finding. 404 if absent.

## Chains

A chain groups two or more findings whose flow steps connect
across repos. The chain runner stamps the `chain_id` field on
each member finding.

`GET /api/v1/chains?run_id=<id>`

Lists chains for the run. `run_id` is required; omit returns 400.

`GET /api/v1/chains/:id`

Returns the chain.

## Traces

Every AI-runtime invocation persists a row to `agent_traces`. The
row carries tokens-in, tokens-out, USD micros spent, cache
hit/miss counts, and the conversation jsonl path (when the
adapter recorded one).

`GET /api/v1/findings/:id/traces`

Trace rows linked to this finding via `finding_id`. Today the
linkage covers the verifier pass; payload-synthesis and
spec-derivation rows still leave `finding_id` unset.

`GET /api/v1/traces/:id`

Returns a single trace row.

## Quarantine

Quarantined items combine two sources: findings with
`status = 'Quarantine'` and candidate findings produced by AI
exploration that have not yet been dynamic-confirmed. The API
folds them into a single list so the operator sees one queue.

`GET /api/v1/quarantine`

Returns `Vec<QuarantineItem>` sorted by `last_seen` descending
(candidates fall to the bottom because they carry no
`last_seen`).

`POST /api/v1/quarantine/:id/promote`

When the id starts with `cand-`, promotes a candidate to a
finding (status `Open`, attack provenance `ManualPromote`). For a
quarantined finding row, flips the status to `Open` so the row
reappears in the Findings browser. Manual promote skips the
dynamic-confirm gate by design.

`POST /api/v1/quarantine/:id/dismiss`

Sets a candidate's status to `Dismissed`, or a finding's status
to `Closed`.

## Repro bundles

A repro bundle is a USTAR-format tar containing a `repro.sh`
script and the source files referenced by the finding's evidence.
Bundles live under `<state>/bundles/`.

`POST /api/v1/findings/:id/repro-bundle`

Builds (or rebuilds) a bundle for the finding. Returns the
manifest:

```json
{
  "finding_id": "...",
  "bundle_path": "/.../bundles/<id>.tar",
  "sha256": "...",
  "files": [ ... ]
}
```

`GET /api/v1/findings/:id/repro-bundle.tar`

Downloads the most recent bundle. Builds one inline if none
exists yet. Response headers carry
`X-Nyx-Bundle-Sha256: <hex>` so a script can verify integrity
without parsing the manifest. The handler refuses to serve a
bundle whose canonical path escapes the configured bundles root.

`POST /api/v1/findings/:id/replay`

Server-sent events stream. Extracts the bundle into a tempdir
and runs `bash repro.sh` with a 120s wall-clock ceiling. Emits:

| Event | Data |
|---|---|
| `start` | `{ finding_id, bundle_path, started_at_ms }` |
| `stdout` | raw line |
| `stderr` | raw line |
| `error` | error string |
| `end` | `{ exit_code, status: "Pass" | "Fail", started_at_ms, finished_at_ms, duration_ms }` |

The bundle's stored sha256 is compared to the on-disk bytes
before extraction. A mismatch returns 500. Tar entries containing
`..` components or absolute paths are rejected.

## Events WebSocket

`GET /api/v1/events?run_id=<id>`

WebSocket upgrade. Bearer auth is enforced; pass
`?token=<token>` if the client cannot send the header.

Without `run_id`, every `AgentEvent` lands on the socket. With
`run_id`, the server replays the buffered events for that run
first, then streams live events filtered to the same run.
Heartbeats pass through any filter.

Frames are JSON-encoded `AgentEvent` values. The replay buffer
caps at 128 frames per run across 16 tracked runs; older frames
drop silently. A `Lagged` warning frame is emitted when the
client falls behind the broadcast channel:

```json
{ "kind": "Lagged", "skipped": 42 }
```

Client-initiated frames are ignored except for `ping` (mirrored
to `pong`) and `close` (terminates the stream).

`RunEvent` variants on the stream: `Heartbeat`, `RunStarted`,
`ProjectStarted`, `RepoStarted`, `RepoStaticDone`,
`RepoDynamicDone`, `RepoFailed`, `RepoFinished`,
`ProjectFinished`, `RunFinished`. See [events.md](events.md) for
the ordering contract, AI runtime variants, and the field-by-field
shape sourced from `crates/nyctos-types/src/event.rs`.

## Git webhook

`POST /webhook/git`

HMAC-authed push trigger. Bypasses bearer auth because the HMAC
itself is the auth. See [docs/triggers/webhook.md](triggers/webhook.md)
for the operator setup.

Request:

```
X-Hub-Signature-256: sha256=<hex>
Content-Type: application/json

{ "ref": "refs/heads/main", ... }
```

The signature is computed over the raw body bytes. The handler
buffers up to 1 MiB and refuses larger bodies with 413. A
matching signature dispatches a scan; a wrong branch returns 200
with `triggered: false` so the upstream git server records a
successful delivery and stops retrying.

Response on dispatch: 202 Accepted,
`{ "triggered": true, "run_id": "run-...", "message": "" }`.

Status codes: 401 (missing or invalid signature), 503
(`webhook_secret_ref` configured but the referenced env var is
unset), 400 (body too large or unreadable), 202 (scan
dispatched), 200 (branch filter rejected the delivery).

## Related pages

- [config.md](config.md) for the operator settings the wizard
  writes.
- [state-dir.md](state-dir.md) for where `auth_token`,
  `bundles/`, and `logs/agent.jsonl` live.
- [cli.md](cli.md) for the `nyctos scan` shortcut that calls
  this API.
- [triggers/webhook.md](triggers/webhook.md) and
  [triggers/cron.md](triggers/cron.md) for the two automated
  trigger surfaces.
- [ci/github-actions.md](ci/github-actions.md) for the composite
  action that drives a scan from a GitHub workflow.

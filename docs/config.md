# Configuration

Nyctos loads its configuration from `nyctos.toml`. The file is
optional: when missing, every section falls back to defaults, so
read-only commands like `nyctos doctor` work in a fresh checkout
with no config on disk.

## Where the file lives

The agent looks for `./nyctos.toml` relative to the current
working directory. Override with `--config <PATH>` on any subcommand:

```bash
nyctos --config /etc/nyctos.toml serve
```

`nyctos doctor` prints whether the file was found and which
sections parsed.

## Schema overview

| Section          | Purpose                                                          |
|------------------|------------------------------------------------------------------|
| `[general]`      | Log level, state directory override.                             |
| `[performance]`  | Static-pass concurrency and per-repo timeout.                    |
| `[sandbox]`      | Sandbox enable + backend selection.                              |
| `[ai]`           | AI runtime, model, concurrency, per-run budget cap.              |
| `[ui]`           | HTTP listen address, browser auto-open.                          |
| `[triggers]`     | Push/PR triggers + webhook secret + branch filter.               |
| `[nyx]`          | Override the discovered `nyx` binary or its minimum version.     |
| `[run]`          | Verifier knobs and optional scanner orchestration.                |
| `[env]`          | Docker compose env-builder pull policy.                          |
| `[[project]]`    | One block per product; declares repos.                           |
| `[project.launch]` | Optional local app orchestration for one project.              |
| `[[schedule]]`   | One cron-driven scan entry; repeated for multiple schedules.     |

Unknown top-level fields and unknown fields inside any section are
rejected at parse time. A typo like `state_directory = "..."`
fails the load rather than silently going to default.

## `[general]`

| Field       | Type            | Default | Description                                                  |
|-------------|-----------------|---------|--------------------------------------------------------------|
| `log_level` | string          | `info`  | `tracing` filter for stderr (e.g. `info`, `debug`, `nyx=trace`). |
| `state_dir` | path (optional) | unset   | Override the state directory. Falls back to `dirs::data_dir()/nyctos` when unset. |

## `[performance]`

| Field                    | Type             | Default | Description                                                       |
|--------------------------|------------------|---------|-------------------------------------------------------------------|
| `max_parallel_scans`     | u32              | `4`     | Reserved for future use by the run dispatcher.                    |
| `scan_timeout_secs`      | u64              | `600`   | Reserved for future use.                                          |
| `static_concurrency`     | usize (optional) | unset   | Explicit fan-out for the static-pass. `None` lets the dispatcher compute `min(num_cpus / 2, len(repos))`. A configured `0` floors to `1`. |
| `per_repo_timeout_secs`  | u64 (optional)   | unset   | Per-repo budget for the static-pass scan. `None` resolves to 30 minutes. A repo that exceeds the budget records `Inconclusive(StaticPassTimeout)` while the rest of the run continues. |
| `scheduler_tick_secs`    | u64 (optional)   | unset   | Cadence at which the cron scheduler wakes to evaluate `[[schedule]]` entries. `None` resolves to 60 seconds; a configured `0` floors to `1`. Lower only when a sub-minute cron granularity is required; tighter polling spends more CPU. |

## `[sandbox]`

| Field           | Type           | Default | Description                                              |
|-----------------|----------------|---------|----------------------------------------------------------|
| `enabled`       | bool           | `true`  | Toggle for the sandbox layer.                            |
| `allow_network` | bool           | `false` | Whether sandboxed jobs may reach the network.            |
| `backend`       | enum           | `auto`  | Backend selector. See below.                             |

`backend` values (kebab-case):

| Value         | Lane / Platform                                                   |
|---------------|-------------------------------------------------------------------|
| `auto`        | Pick the strongest available backend at runtime.                  |
| `process`     | No kernel isolation. Static-pass only. Always works.              |
| `birdcage`    | macOS Seatbelt profile shipped with the agent.                    |
| `libkrun`     | Lightweight microVM on Linux via libkrun.                         |
| `firecracker` | Lightweight microVM on Linux via Firecracker.                     |
| `docker`      | Docker container fallback. Slowest, requires the docker daemon.   |

`nyctos doctor` prints which backends probe healthy on this host.

## `[ai]`

| Field                              | Type             | Default | Description                                                                                              |
|------------------------------------|------------------|---------|----------------------------------------------------------------------------------------------------------|
| `provider`                         | string (optional)| unset   | Free-form provider tag surfaced in the UI.                                                               |
| `model`                            | string (optional)| unset   | Model identifier (e.g. `claude-opus-4-7`).                                                               |
| `api_base`                         | string (optional)| unset   | Base URL for local OpenAI-compatible runtimes.                                                           |
| `runtime`                          | enum             | `none`  | AI runtime selection. See below.                                                                         |
| `max_concurrent_one_shot`          | u32              | `4`     | Cap on in-flight `one_shot` AI calls per run, shared across payload synthesis, spec derivation, and chain reasoning. `0` floors to `1` to avoid a deadlocked semaphore acquire. |
| `default_run_budget_usd_micros`    | i64 (optional)   | unset   | Per-run AI budget cap in USD micros stamped on new `(run_id, kind)` rows. Unset means unlimited; set a positive value to enable the cap. |
| `payload_synthesis_per_call_cap_usd_micros` | i64 (optional) | unset | Per-call cap forwarded into each PayloadSynthesis `Budget`. Clamps a single call below the shared per-run bucket. Unset means unlimited unless the shared run cap is lower. |
| `spec_derivation_per_call_cap_usd_micros`   | i64 (optional) | unset | Per-call cap for each SpecDerivation call. Same fall-back rules. |
| `chain_reasoning_per_call_cap_usd_micros`   | i64 (optional) | unset | Per-call cap for the single ChainReasoning call. Same fall-back rules. |
| `novel_discovery_per_call_cap_usd_micros`   | i64 (optional) | unset | Per-call cap for each NovelFindingDiscovery batch. Same fall-back rules. |
| `exploration_soft_cap_usd_micros`           | i64 (optional) | unset | Per-task soft cap for AI Exploration. Crossing it emits a single warning; the run continues until the hard cap below trips. Falls back to `$5.00` (`5_000_000`) when unset or non-positive. |
| `exploration_run_cap_usd_micros`            | i64 (optional) | unset | Per-run hard cap for AI Exploration. The pass halts if cumulative spend reaches this value. Falls back to `$10.00` (`10_000_000`) when unset or non-positive. |

`runtime` values (kebab-case):

| Value          | Description                                                                                                |
|----------------|------------------------------------------------------------------------------------------------------------|
| `none`         | AI features off. Static-pass only.                                                                         |
| `anthropic`    | Hosted Anthropic API. The wizard stores the API key in the OS keychain under account `ai-anthropic`.       |
| `local-llm`    | Local OpenAI-compatible runtime (LM Studio, Ollama, vLLM). Endpoint goes in `api_base`; any bearer token lives in the keychain under `ai-local-llm`. |
| `claude-code`  | Drive an already-installed `claude` CLI on `$PATH`.                                                        |

API keys never live in TOML. The wizard at first launch writes them
to the OS keychain.

## `[ui]`

| Field         | Type   | Default            | Description                                                       |
|---------------|--------|--------------------|-------------------------------------------------------------------|
| `listen_addr` | string | `127.0.0.1:8765`   | `host:port` the HTTP + WebSocket server binds to.                 |
| `open_browser`| bool   | `true`             | Open the SPA in the default browser on `serve` startup. `--no-open` / `--headless` overrides this at the CLI. |

The default address is loopback-only. Binding `0.0.0.0:...`
exposes the agent without auth and is not recommended; pair with
TLS + token auth (see `docs/security-posture.md` once it lands).

## `[triggers]`

| Field                | Type             | Default | Description                                                                                              |
|----------------------|------------------|---------|----------------------------------------------------------------------------------------------------------|
| `on_push`            | bool             | `false` | Reserved trigger flag.                                                                                   |
| `on_pr`              | bool             | `false` | Reserved trigger flag.                                                                                   |
| `schedule_cron`      | string (optional)| unset   | Reserved. Use `[[schedule]]` entries instead for current cron behavior.                                  |
| `webhook_secret_ref` | string (optional)| unset   | HMAC-SHA256 secret reference for `POST /webhook/git`. Shape: `env:<NAME>` resolves to the environment variable, anything else is treated as the literal secret. Empty secrets are rejected. When unset, the webhook handler returns 503. |
| `webhook_branch`     | string (optional)| unset   | Optional branch filter. When set, only payloads whose `ref` equals `refs/heads/<branch>` trigger a scan. |

See `docs/triggers/webhook.md` for the full handler contract.

## `[nyx]`

| Field         | Type             | Default | Description                                                                                              |
|---------------|------------------|---------|----------------------------------------------------------------------------------------------------------|
| `binary_path` | path (optional)  | unset   | Override the discovered `nyx` binary. When unset, the runner falls back to a `$PATH` lookup.             |
| `min_version` | string (optional)| unset   | Override the built-in minimum-supported `nyx` version. Useful in integration tests; the resolver clamps to the built-in floor (`MINIMUM_NYX_VERSION`) so an under-floor override does not silently weaken the check. |

## `[run]`

| Field                              | Type | Default | Description                                                                                              |
|------------------------------------|------|---------|----------------------------------------------------------------------------------------------------------|
| `replay_stable_check`              | bool | `false` | When `true`, the deterministic payload runner re-executes each `(vuln, benign)` pair a second time and stamps `replay_stable` on the resulting `VerifyResult`. Adds roughly 2x cost per verify. |
| `allow_state_changing_live_probes` | bool | `false` | Allow live verification plans to use HTTP methods likely to mutate target state (`POST`, `PUT`, `PATCH`, `DELETE`). |
| `browser_checks_enabled`           | bool | `false` | Allow browser-driven verification and auth-session acquisition when the local runtime is available. Confirmed browser attempts save redacted replay evidence under the run trace directory. |
| `exploit_mode_enabled`             | bool | `false` | Master opt-in for invasive verification. State-changing probes still require `allow_state_changing_live_probes = true`; setting that older flag by itself is not enough. |
| `exploit_dry_run`                  | bool | `false` | Evaluate guarded live plans and write audit records without sending HTTP/browser traffic where feasible. |
| `business_logic_templates_enabled` | bool | `true` | Generate first-class business-logic pentest candidates from route/auth metadata. Generated plans still pass through normal verifier safety gates. |
| `research_mode_enabled`            | bool | `false` | Enable Vuln Research Mode. This adds product-invariant hypotheses from the semantic route model and prior candidate memory, prioritizes those candidates in attack planning/exploration, and uses deeper research prompts. It does not relax live execution gates. |
| `unsafe_attack_agent_enabled`      | bool | `false` | Run the pre-MVP unrestricted local attack-agent phase after normal verification. Intended only for disposable user-owned dev apps; once invoked it does not use the guarded live-verifier policy. |
| `business_logic_template_ids`      | array of strings | `[]` | Optional allowlist of template ids. Empty means every registered template is considered. Use `nyctos business-logic templates` or `GET /api/v1/business-logic/templates` to list ids. |
| `exploit_request_cap`              | int (optional) | unset (`10`) | Per-candidate cap for guarded live HTTP/browser actions. `0` is floored to `1`. |
| `exploit_requests_per_second`      | int (optional) | unset (`5`) | Per-candidate rate limit for guarded live HTTP/browser actions. `0` is floored to `1`. |
| `exploit_reset_after_state_changing` | bool | `true` | Ask the environment orchestration layer to reset/rollback after allowed state-changing probes when the active environment supports it. |
| `enable_zap_baseline`              | bool | `true`  | Run `zap-baseline.py` against live target URLs when the binary is present on PATH. Missing binaries are skipped. |
| `enable_nuclei`                    | bool | `true`  | Run `nuclei` against live target URLs when the binary is present on PATH. Missing binaries are skipped. |
| `enable_trivy`                     | bool | `true`  | Run `trivy fs` against repo workspaces when present on PATH. Dependency, IaC, and secret findings become AI exploration context. |
| `enable_osv_scanner`               | bool | `true`  | Run `osv-scanner` against repo workspaces when present on PATH. Dependency findings become AI exploration context. |
| `enable_secret_scanning`           | bool | `true`  | Run `gitleaks` against repo workspaces when present on PATH; if absent, fall back to `detect-secrets`. Secret findings become AI exploration context. |
| `enable_katana`                    | bool | `true`  | Run `katana` against live target URLs when present on PATH. Sensitive crawled routes become live-test candidates. |
| `enable_httpx`                     | bool | `true`  | Run ProjectDiscovery `httpx` against live target URLs when present on PATH. Interesting HTTP metadata becomes live-test candidates. |
| `enable_aggressive_sqlmap`         | bool | `false` | Reserved for explicit sqlmap use. sqlmap is not auto-enabled because it is aggressive and has GPL/proprietary-integration constraints. |

Exploit mode is intentionally a two-key system. Nyctos defaults to
non-destructive live verification. State-changing HTTP methods,
browser actions that may mutate data, and aggressive external probes
are rejected unless exploit mode is enabled and the specific
state-changing gate is also enabled. The local server UI exposes the
same per-run controls in the **Start pentest** modal, so an operator
can opt into an invasive run without editing `nyctos.toml`.

Example opt-in for a disposable local target:

```toml
[run]
exploit_mode_enabled = true
allow_state_changing_live_probes = true
exploit_request_cap = 5
exploit_requests_per_second = 2
exploit_reset_after_state_changing = true
business_logic_template_ids = ["tenant_object_isolation", "file_permission_revalidation"]
```

Use `exploit_dry_run = true` to inspect generated policy audit
records before sending live traffic. With both safety keys enabled,
dry-run still generates selected business-logic candidates and records
template summary rows, but the live verifier does not send guarded
HTTP/browser traffic.

Business-logic templates that seed objects, submit coupon/price data,
change permissions, deliver webhook payloads, or send chatbot prompts
are only generated when the same two gates are enabled. They still
pass through request caps, rate limits, target URL scope checks,
auth-session acquisition, and reset-after-state-changing handling.
See [`business-logic-templates.md`](business-logic-templates.md) for
template ids, dry-run examples, skip reasons, and provenance shape.

Vuln Research Mode is separate from exploit mode:

```toml
[run]
research_mode_enabled = true
```

Research mode increases reasoning depth and candidate generation for
authorized product-logic review. It adds `ResearchMode` candidates for
invariants such as lifecycle bugs, stale access, replay, downgrade or
entitlement mismatch, invite/team/org transitions, webhook/event
consistency, AI-agent indirect actions, and background job side
effects. The candidates carry `research_mode_provenance` in
`affected_components`, and research-mode exploration findings carry the
same provenance in their verdict blob. Live HTTP/browser execution
still goes through the same target scope, request cap, rate limit,
exploit-mode, state-changing, dry-run, and reset gates.

Unsafe attack-agent mode is a separate pre-MVP local-only phase:

```toml
[run]
unsafe_attack_agent_enabled = true
```

It runs after normal verification while the configured local app is
still up. The agent receives repo workspaces, target URLs, prior
candidates, and existing vulnerabilities, then may use CLI tools to
attack the dev app directly and record `verified_vulnerabilities` with
proof artifacts. It is intentionally not routed through
`ExploitSafetyPolicy`; use it only against disposable local targets.

Optional scanner findings are persisted as pentest candidates. Live web
findings still pass live verification before surfacing as verified
vulnerabilities; source/package findings are recorded as bounded context
for AI exploration and triage. Nyctos does not bundle these scanners; it
invokes local executables on PATH when available.

| Tool | Upstream license | Commercial use note |
|------|------------------|---------------------|
| OWASP ZAP / `zap-baseline.py` | Apache-2.0 | Generally compatible with commercial products when notices and other Apache-2.0 conditions are preserved. |
| Nuclei | MIT | Generally compatible with commercial products when the MIT copyright and permission notice are preserved. |
| Trivy | Apache-2.0 | Generally compatible with commercial products when notices and other Apache-2.0 conditions are preserved. |
| OSV-Scanner | Apache-2.0 | Generally compatible with commercial products when notices and other Apache-2.0 conditions are preserved. |
| Gitleaks | MIT | Generally compatible with commercial products when the MIT copyright and permission notice are preserved. |
| detect-secrets | Apache-2.0 | Generally compatible with commercial products when notices and other Apache-2.0 conditions are preserved. |
| Katana | MIT | Generally compatible with commercial products when the MIT copyright and permission notice is preserved. |
| ProjectDiscovery httpx | MIT | Generally compatible with commercial products when the MIT copyright and permission notice is preserved. |
| sqlmap | GPL-2.0-or-later with project clarifications / optional commercial license | Internal use is usually different from redistribution, but embedding or parsing sqlmap results in proprietary software is treated by sqlmap upstream as requiring GPL compliance or a separate sqlmap commercial license. Get legal review before shipping this path. |

## `[[project]]`

Each `[[project]]` block declares one product and groups its repos
under nested `[[project.repo]]` blocks. Top-level `[[repo]]` blocks
are rejected by the parser.

| Field            | Type              | Default | Description                                                                                  |
|------------------|-------------------|---------|----------------------------------------------------------------------------------------------|
| `name`           | string            | n/a     | Unique project name. Also used as the workspace directory prefix.                            |
| `description`    | string (optional) | unset   | Free-form description surfaced in the UI.                                                    |
| `target_base_url`| string (optional) | unset   | Base URL the sandbox env-builder dials for dynamic checks against the running stack.         |
| `env_config`     | TOML value (optional)| unset| Structured env overrides merged into the project's docker-compose / sandbox runtime. Opaque to the agent. |
| `launch`         | table (optional)  | unset   | Build/start/health/seed/reset/login recipe used before scans. See below.                    |
| `runtime_profile`| table (optional)  | unset   | Auth/session metadata for live verification. Prefer env refs over raw secrets.              |
| `repo`           | `[[project.repo]]`| empty   | Repos belonging to this project. See below.                                                  |

When `[project.launch]` is omitted, scans still run. If a project has
`target_base_url` but no stored launch profile, Nyctos creates a
conservative already-running profile and health-checks the target URL.
For local-path repos, `mode = "auto"` can detect root-level Docker
Compose files or simple `package.json` / `Cargo.toml` start commands.

### `[project.launch]`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string (optional) | `local dev` | Operator label for the default launch profile. |
| `mode` | string (optional) | inferred | `auto`, `already-running`, `custom-commands`, or `docker-compose`. |
| `target_urls` | array of strings | `[target_base_url]` when set | In-scope local URLs handed to live probes and AI exploration. |
| `env_files` | array of strings | `[]` | Env files resolved relative to the command working directory. |
| `env_vars` | array of tables | `[]` | Env var names forwarded from the daemon process. |
| `build` / `start` / `seed` / `login` / `reset` / `stop` | array of command tables | `[]` | Ordered shell commands for the target lifecycle. |
| `health` | array of tables | target URL check | Readiness checks. HTTP checks retry until timeout; command checks must exit 0. |

Command table fields:

```toml
command = "npm run dev"
repo = "web"                  # alias: repo_name
working_directory = "apps/web"
timeout_secs = 120            # alias: timeout_seconds
```

HTTP health check:

```toml
[[project.launch.health]]
url = "http://localhost:3000/health"
timeout_secs = 60
```

Seed commands run after the app is healthy and before the static and
live scan phases. Login commands run after seed hooks and are intended
for local session setup. Reset commands run after state-changing live
probes when `[run] exploit_reset_after_state_changing = true`. Start,
build, seed, login, reset, and stop stdout/stderr are captured under
`<state>/logs/environment/<run-id>/`.

### `[project.runtime_profile]`

Runtime profiles describe authenticated roles that live verification can
use. Each role gets a named auth session, and authorization probes can
compare the same request as different roles.

```toml
[project.runtime_profile]
target_base_url = "http://localhost:3000"

[[project.runtime_profile.auth_profiles]]
role = "user_a"
mode = "header_injection"
bearer_token_env = "NYCTOS_USER_A_TOKEN"
tenant = "tenant-a"

  [[project.runtime_profile.auth_profiles.owned_objects]]
  name = "project"
  id = "proj-user-a-1"
  route = "/api/projects/{id}"
  marker = "nyctos-user-a-project"

[[project.runtime_profile.auth_profiles]]
role = "user_b"
mode = "header_injection"
bearer_token_env = "NYCTOS_USER_B_TOKEN"
tenant = "tenant-b"

[[project.runtime_profile.auth_profiles]]
role = "admin"
mode = "session_import"
session_import_path = "sessions/admin-storage-state.json"
```

`owned_objects` are optional pre-seeded IDs for horizontal
authorization checks. Nyctos treats the id and marker as positive live
evidence markers: `user_b` must receive the same marker from `user_a`'s
object before an IDOR-style vulnerability can verify.

`tenant` is optional metadata used in the Authorization Matrix. When a
role comparison or object ownership check runs, Nyctos records one row
for the allowed control and one row for the challenged access with the
role, tenant, resource/object, owner role, action, endpoint, expected
decision, observed HTTP/marker result, confidence, candidate id,
verification attempt id, and run id.

The local UI exposes an `AI setup` action in the auth profiles panel for
projects with local repos. Clicking it inspects the checked-out source
for login routes, object-shaped routes, and admin signals, then saves
named role profiles and any seeded owned objects into
`project.runtime_profile`. Pentests do not run this discovery step; they
only use the saved profiles selected before the run.

### `[[project.repo]]`

| Field        | Type   | Default | Description                                                                                  |
|--------------|--------|---------|----------------------------------------------------------------------------------------------|
| `name`       | string | n/a     | Unique repo name.                                                                            |
| `i_own_this` | bool   | `false` | Operator attestation. The daemon refuses to ingest a repo without `i_own_this = true`.       |
| `enabled`    | bool   | `true`  | Skip the repo when set to `false`.                                                           |
| `source`     | table  | n/a     | Repo source. Either a `git` or `local-path` variant (tag field `kind`).                      |

`source` variants:

```toml
source = { kind = "git", url = "git@github.com:org/repo.git", branch = "main", auth = "ssh-key:~/.ssh/id_ed25519" }
source = { kind = "local-path", path = "/srv/repos/monolith" }
```

`auth` accepted shapes: `ssh-key:<path>`, `token-env:<var>`,
`gh-app:<id>`. Unknown `kind` values fail the load.

## `[[schedule]]`

One cron-driven scan entry. The scheduler evaluates every entry
once per minute and fires matching ones against the configured repo
filter.

| Field   | Type             | Default       | Description                                                                                  |
|---------|------------------|---------------|----------------------------------------------------------------------------------------------|
| `cron`  | string           | n/a           | 5-field cron expression (`minute hour day-of-month month day-of-week`). Example: `0 3 * * 1` = 03:00 every Monday. |
| `repo`  | string (optional)| unset         | Limit the run to one configured repo. `None` scans every enabled repo.                       |
| `label` | string           | `"scheduled"` | Operator-readable label surfaced in tracing spans and the UI.                                |

See `docs/triggers/cron.md` for the full scheduler contract.

## Worked example

```toml
[general]
log_level = "info"

[performance]
static_concurrency = 4
per_repo_timeout_secs = 1200

[sandbox]
enabled = true
allow_network = false
backend = "auto"

[ai]
runtime = "anthropic"
model = "claude-opus-4-7"
max_concurrent_one_shot = 4
default_run_budget_usd_micros = 2_500_000  # Optional: $2.50 per run

[ui]
listen_addr = "127.0.0.1:8765"
open_browser = true

[triggers]
webhook_secret_ref = "env:NYX_WEBHOOK_SECRET"
webhook_branch = "main"

[nyx]
# binary_path = "/opt/nyx/bin/nyx"

[run]
replay_stable_check = false
business_logic_templates_enabled = true
business_logic_template_ids = []

[[project]]
name = "acme-app"
description = "Acme web product"
target_base_url = "http://localhost:3000"

  [project.launch]
  mode = "custom-commands"
  env_files = [".env.test"]

    [[project.launch.build]]
    command = "npm ci"
    repo = "acme-frontend"

    [[project.launch.start]]
    command = "npm run dev"
    repo = "acme-frontend"
    timeout_secs = 120

    [[project.launch.health]]
    url = "http://localhost:3000/health"
    timeout_secs = 60

    [[project.launch.seed]]
    command = "npm run seed:test"
    repo = "acme-backend"

    [[project.launch.reset]]
    command = "npm run db:reset"
    repo = "acme-backend"

  [[project.repo]]
  name = "acme-backend"
  i_own_this = true
  source = { kind = "local-path", path = "/srv/repos/acme-backend" }

  [[project.repo]]
  name = "acme-frontend"
  i_own_this = true
  source = { kind = "git", url = "git@github.com:acme/frontend.git", branch = "main" }

[[schedule]]
cron = "0 3 * * 1"
repo = "acme-backend"
label = "weekly-monday-3am"
```

## Failure modes

| Symptom                                                   | Cause / Fix                                                                                       |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `failed to parse config at <path>: unknown field ...`     | Typo in a field name. Sections deny unknown fields. Check the schema tables above.                |
| `failed to parse config at <path>: missing field ...`     | A required field is unset. `name` on `[[project]]` / `[[project.repo]]`, `cron` on `[[schedule]]`, `url` on a `git` source. |
| `failed to read config at <path>: ...`                    | Permission issue or the path passed to `--config` is wrong.                                       |
| `no repositories selected; configure one in nyctos.toml` | The TOML has zero `[[project.repo]]` blocks or every repo is `enabled = false`.                  |
| `invalid [[schedule]] config: ...`                        | A cron expression failed to parse or the referenced repo does not exist. The daemon refuses to start. |
| Daemon accepts webhooks but every call returns `503`      | `triggers.webhook_secret_ref` is unset, points at an unset env var, or resolves to an empty string. |

## Related pages

- [CLI reference](cli.md)
- [Quickstart](quickstart.md)
- [Cron trigger](triggers/cron.md)
- [Webhook trigger](triggers/webhook.md)

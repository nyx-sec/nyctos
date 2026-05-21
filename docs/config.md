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
| `[run]`          | Verifier knobs (e.g. replay stability check).                    |
| `[[project]]`    | One block per product; declares repos.                           |
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
| `default_run_budget_usd_micros`    | i64 (optional)   | unset   | Per-run AI budget cap in USD micros stamped on new `(run_id, kind)` rows. Falls back to `$5.00` (`5_000_000`) when unset or non-positive. |
| `payload_synthesis_per_call_cap_usd_micros` | i64 (optional) | unset | Per-call cap forwarded into each PayloadSynthesis `Budget`. Clamps a single call below the shared per-run bucket. Falls back to `$5.00` (`5_000_000`) when unset or non-positive. |
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

| Field                  | Type | Default | Description                                                                                              |
|------------------------|------|---------|----------------------------------------------------------------------------------------------------------|
| `replay_stable_check`  | bool | `false` | When `true`, the deterministic payload runner re-executes each `(vuln, benign)` pair a second time and stamps `replay_stable` on the resulting `VerifyResult`. Adds roughly 2x cost per verify. |

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
| `repo`           | `[[project.repo]]`| empty   | Repos belonging to this project. See below.                                                  |

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
default_run_budget_usd_micros = 2_500_000  # $2.50 per run

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

[[project]]
name = "acme-app"
description = "Acme web product"
target_base_url = "http://localhost:3000"

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

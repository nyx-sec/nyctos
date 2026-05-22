# Product Reset Plan

Nyctos should be an automated smart pentesting product for user-owned
local dev builds. It should not feel like a UI around Nyx output.

The primary user action is:

1. Pick a project.
2. Configure how the full local app is built and started.
3. Click **Start pentest**.
4. Receive a small, high-confidence set of verified vulnerabilities.

Nyx remains valuable, but only as one internal signal source. Raw Nyx
findings, especially Low, Info, and code-quality findings, should move
to an advanced/debug signals surface. The normal product output should
be verified vulnerabilities, ideally 5 to 10 per run.

## Audit Snapshot

The repo already has useful pieces, but they are wired around the old
"scan findings" center of gravity:

- Data model: `projects`, `repos`, `runs`, `findings`, `chains`,
  `candidate_findings`, `agent_traces`, `payloads`, `harness_specs`,
  `repro_bundles`, and `run_repo_outcomes` exist. Static Nyx diagnostics
  are persisted directly into `findings`.
- Project model: projects can contain many repos and carry
  `target_base_url` plus opaque `env_config_json`, but repo names are
  globally unique and `runs` do not persist `project_id`.
- Pipeline: `drive_scan` ingests repos, runs Nyx static scan, persists
  every static diagnostic as an open finding, then runs payload
  synthesis, spec derivation, chain reasoning, novel finding discovery,
  AI exploration, and payload verification.
- Environment: `nyctos-sandbox::env::EnvBuilder` can detect and merge
  compose files, but the main scan path does not start the project app
  before Nyx or AI work. AI exploration currently receives no live
  target endpoints.
- Verification: payload verification exists for payload/spec pairs,
  but candidate confirmation has built-in harness shortcuts, chain
  verification is not wired into the main run, and live local app
  verification is not the common gate for all surfaced output.
- Frontend: the sidebar exposes Projects, Runs, Findings, Chains, and
  Quarantine. Project detail centers repo rows with "Scan all" and
  per-repo "Scan now". Findings are the main table.
- Stubs: `/runs` is a placeholder, cancel is a UI-only action, dynamic
  verdict copy says later phases will land, `RepoDynamicDone` is
  mostly reserved, `CrossRepoCallgraphStub` has empty edges, and several
  sandbox/chain helpers intentionally return "not yet wired" messages.

## Target Vocabulary

Use these nouns consistently before changing code:

- **Project**: the user-owned local app under test. It may span one repo
  or many repos.
- **Launch profile**: the project-specific recipe for building,
  starting, health-checking, and stopping the full local app.
- **Pentest run**: one end-to-end execution of the product pipeline for
  one project.
- **Signal**: an internal clue. Nyx diagnostics are signals. Agent
  observations before verification are signals or candidates.
- **Candidate**: an unverified hypothesis produced from Nyx, agent code
  review, business-logic analysis, or chain reasoning.
- **Verification attempt**: a live test against the local build, with
  evidence and a pass/fail/errored verdict.
- **Verified vulnerability**: user-facing output. It must have at least
  one successful live verification attempt.
- **Verified chain**: a user-facing vulnerability or vulnerability group
  whose exploitability depends on multiple confirmed steps.

## Data Model Changes

### Project and repo identity

Current issue: `repos.name` is the primary key, and many tables store
only `repo` text. That makes two projects with a `backend` repo collide.

Add:

- `repos.id TEXT PRIMARY KEY`, generated as `repo-<project-slug>-<repo-slug>-<time>`.
- `UNIQUE(project_id, name)` on repos.
- `repo_id` foreign keys on new tables. Keep `repo` text as a display
  snapshot only where useful.
- `runs.project_id TEXT REFERENCES projects(id)` for every new pentest
  run.

Migration note: changing the primary key in SQLite likely requires a
new `repos_v2` table, copy, drop, rename sequence. Do this before the
new pentest tables depend on repo ids.

### Launch profiles

`projects.env_config_json` is too opaque for the primary product
workflow. Keep it temporarily, but add a normalized launch profile.

Add `project_launch_profiles`:

| Column | Purpose |
|---|---|
| `id` | Profile id. |
| `project_id` | Owning project. |
| `name` | Human label, default `local dev`. |
| `mode` | `custom-commands`, `docker-compose`, or future `devcontainer`. |
| `build_steps_json` | Ordered project/repo build commands. |
| `start_steps_json` | Ordered commands or compose descriptor to start the app. |
| `stop_steps_json` | Optional teardown commands. |
| `health_checks_json` | HTTP/TCP/process checks that prove readiness. |
| `target_urls_json` | One or more in-scope local URLs for the agent. |
| `env_refs_json` | References to test env files or keychain entries, not raw secrets. |
| `working_dirs_json` | Explicit dirs for multi-repo commands. |
| `created_at`, `updated_at` | Audit timestamps. |
| `is_default` | Project default. |

Backfill: create a default profile for each project from
`target_base_url` and `env_config_json`, but mark it incomplete until it
has a start command or compose detection result.

### Environment runs

Add `environment_runs`:

| Column | Purpose |
|---|---|
| `id` | Environment run id. |
| `run_id` | Pentest run. |
| `project_id` | Owning project. |
| `profile_id` | Launch profile used. |
| `status` | `Pending`, `Building`, `Starting`, `Ready`, `Failed`, `Stopped`. |
| `started_at`, `ready_at`, `stopped_at` | Lifecycle timestamps. |
| `target_urls_json` | Resolved URLs actually used. |
| `health_blob` | Last health-check result. |
| `logs_dir` | Directory for stdout/stderr/build logs. |
| `teardown_blob` | Teardown result and leaked-process notes. |

This becomes the live-build anchor for every verification attempt.

### Nyx signals

Stop writing every Nyx diagnostic into `findings`. Add `nyx_signals`
and store Nyx output there first.

| Column | Purpose |
|---|---|
| `id` | Stable signal id. Include `project_id` and `repo_id` in the hash. |
| `run_id`, `project_id`, `repo_id` | Scope. |
| `path`, `line`, `cap`, `rule`, `severity` | Nyx fields. |
| `message` | Short Nyx message. |
| `evidence_blob` | Raw Nyx evidence. |
| `signal_kind` | `security`, `code-quality`, `info`, etc. |
| `meaningful` | Whether it is passed to the agent by default. |
| `suppressed_reason` | `below-threshold`, `code-quality`, `duplicate`, etc. |
| `agent_candidate_id` | Optional candidate created from this signal. |
| `created_at` | Timestamp. |

Default filtering:

- Pass Medium, High, and Critical security signals to the agent.
- Suppress Low, Info, and code-quality signals by default.
- Keep all raw signals queryable through advanced/debug routes.

### Pentest candidates

Add `pentest_candidates` for unverified hypotheses.

| Column | Purpose |
|---|---|
| `id` | Candidate id. |
| `run_id`, `project_id` | Scope. |
| `source` | `NyxSignal`, `AgentCodeReview`, `AgentLiveProbe`, `BusinessLogic`, `ChainReasoning`. |
| `source_ids_json` | Nyx signal ids, trace ids, or prior candidate ids. |
| `title`, `vuln_class`, `severity_guess` | Candidate summary. |
| `affected_components_json` | Repos, files, endpoints, services. |
| `hypothesis` | Why the agent thinks it may be exploitable. |
| `test_plan` | Planned live verification steps. |
| `status` | `Proposed`, `Rejected`, `NeedsLiveTest`, `Verified`, `Errored`. |
| `rejection_reason` | Required when rejected. |
| `confidence` | Internal confidence before verification. |
| `trace_id` | Agent trace that proposed it. |
| `created_at`, `updated_at` | Audit timestamps. |

This replaces `candidate_findings` as the main internal candidate
surface. Keep `candidate_findings` as legacy until the frontend and PR
report no longer read it.

### Verification attempts

Add `verification_attempts`:

| Column | Purpose |
|---|---|
| `id` | Attempt id. |
| `run_id`, `project_id`, `environment_run_id` | Scope and live build. |
| `candidate_id` | Candidate tested, nullable for direct chain attempts. |
| `chain_id` | Chain tested, nullable. |
| `method` | `http`, `browser`, `payload-harness`, `cli`, `manual-script`. |
| `status` | `Confirmed`, `Rejected`, `Errored`, `Inconclusive`. |
| `started_at`, `finished_at`, `duration_ms` | Timing. |
| `request_blob`, `response_blob` | Redacted proof data. |
| `oracle_blob` | The predicate that made the test pass/fail. |
| `artifact_paths_json` | Screenshots, logs, repro scripts. |
| `error` | Error details when status is `Errored` or `Inconclusive`. |
| `replay_stable` | Optional second-run stability result. |

### Verified vulnerabilities

Add `verified_vulnerabilities` as the primary user-facing output.

| Column | Purpose |
|---|---|
| `id` | Stable vulnerability id. |
| `run_id`, `project_id` | Scope. |
| `title` | Human-readable title. |
| `severity` | Final severity. |
| `confidence` | Usually high after confirmation. |
| `vuln_class` | Taxonomy tag. |
| `affected_components_json` | Repos, endpoints, files, services. |
| `business_impact` | Concrete impact. |
| `evidence_summary` | Short proof. |
| `repro_steps` | User-facing reproduction steps. |
| `remediation` | Fix guidance. |
| `source_candidate_ids_json` | Candidates that merged into this vulnerability. |
| `source_signal_ids_json` | Nyx signals involved, if any. |
| `verification_attempt_ids_json` | Confirming attempts. |
| `chain_id` | Optional verified chain. |
| `status` | `Open`, `Fixed`, `AcceptedRisk`, `FalsePositive`. |
| `first_seen`, `last_seen` | Stability across runs. |

Only rows in this table should feed the default UI, reports, and PR
comments.

### Chains

The existing `chains` table can be kept, but it should no longer mean
"AI ranked a possible chain." Add fields or a companion table so the
state is explicit:

- `chain_candidates` for proposed chains.
- `verified_chains` for chains with live verification.
- Or add `status`, `verification_attempt_id`, `evidence_blob`, and
  `severity` to `chains`.

Do not show a chain as a user-facing exploit chain until the terminal
condition has been verified against the live environment.

### Traces and events

`agent_traces` should link to more than `finding_id`.

Add nullable columns:

- `run_id`
- `project_id`
- `candidate_id`
- `vulnerability_id`
- `phase`

Add `run_phase_events` or extend the event stream to persist phase
transitions:

- `EnvironmentBuildStarted`
- `EnvironmentReady`
- `NyxSignalsStarted`
- `NyxSignalsFinished`
- `AgentReviewStarted`
- `AgentReviewFinished`
- `LiveVerificationStarted`
- `LiveVerificationFinished`
- `PentestReportReady`

## Backend Pipeline Changes

Replace the current scan-first orchestration with a pentest
orchestrator. The old scan path can remain as an advanced/debug command
while the new path stabilizes.

### New top-level flow

1. Create a `runs` row with `project_id`, `kind = Pentest`, and
   `status = Running`.
2. Materialize all project repos into workspaces.
3. Build/start the project using its default launch profile.
4. Wait for health checks and record an `environment_runs` row.
5. Run Nyx static scan internally.
6. Convert Nyx diagnostics into `nyx_signals`.
7. Select meaningful signals, default Medium+ security signals.
8. Run the AI pentest agent with:
   - repo map and source access,
   - launch profile,
   - target URLs and health data,
   - meaningful Nyx signals,
   - prior verified vulnerabilities and false-positive history,
   - strict output schema for candidates and chains.
9. Persist candidates and rejected Nyx hypotheses.
10. Live-test candidates and chains against the running local app.
11. Merge confirmed attempts into `verified_vulnerabilities`.
12. Rank and cap the normal output to the highest-impact verified
    vulnerabilities.
13. Stop the environment and finalize the run.

### Environment stage

Wire `nyctos-sandbox::env::EnvBuilder` into the run path, but do not
make docker-compose the only supported mode.

Required work:

- Add a `LaunchProfileRunner` trait with implementations for
  docker-compose profiles and custom command profiles.
- Capture stdout/stderr logs for every build/start/stop command.
- Enforce readiness through health checks before live verification.
- Fail closed when test secrets are missing or production-looking
  secrets are detected.
- Track process groups and compose project names for teardown.
- Add cancellation support that stops the environment before marking
  the run halted.

The first implementation can prefer docker-compose when compose files
are detected, but the user must be able to override with explicit
commands because many local dev builds are not compose-based.

### Nyx as signal source

Change `persist_run_results` behavior:

- Persist Nyx diagnostics to `nyx_signals`, not `findings`.
- Apply the default signal filter before building AI context.
- Keep raw Nyx signal counts in run summaries, but avoid displaying
  them as vulnerabilities.
- Preserve Nyx evidence blobs for advanced drilldown and agent
  traceability.

The agent input should include only meaningful signal summaries unless
the user explicitly opts into a broader/debug run.

### Pentest agent stage

The current one-shot tasks are useful components, but they do not add
up to an expert pentester. Add a first-class `PentestAgent` stage that
can inspect the full project and produce structured candidates.

Capabilities required:

- Codebase inspection across all repos.
- Route/API discovery from source, framework conventions, OpenAPI
  files, frontend calls, and infra config.
- Review of meaningful Nyx signals as hypotheses, not truth.
- Static-missed issue discovery, including authz, tenancy, workflow,
  payment/state-machine, CORS/session, SSRF, deserialization, secret
  exposure, and unsafe local-dev defaults.
- Candidate chaining across repos and services.
- Explicit rejection of Nyx signals with reasons.
- Structured output only. Free-form text can be trace/audit data, not
  the persistence contract.

Implementation direction:

- Reuse `AiRuntime::agent_loop` where available.
- Keep `PayloadSynthesis`, `SpecDerivation`, `NovelFindings`, and
  `ChainReasoning` as subroutines or fallback helpers, not as the
  product pipeline spine.
- Add tool adapters that are actually enforced by the host: read-only
  repo access, bounded shell, local HTTP/browser probes, and evidence
  capture. Do not rely only on the model reporting tool names in text.
- Add cost/time/candidate caps per run.

### Live verification stage

Every user-facing vulnerability must be tested against the live local
build.

Verification should support:

- HTTP request/response tests.
- Browser flows for frontend-dependent vulnerabilities.
- Payload harness tests where the live app cannot exercise the sink
  directly.
- Multi-step chain tests that pass state from one step to the next.
- Replay stability where practical.

Required policy:

- `Confirmed` attempts can create or update `verified_vulnerabilities`.
- `Rejected` attempts update the candidate and can suppress the source
  Nyx signal.
- `Errored` attempts do not become vulnerabilities.
- Manual promote should move to an advanced override path and must not
  label a row verified.

### Reports and PR comments

Change reports from "all findings for a run" to "verified
vulnerabilities for a pentest run."

Required work:

- Add `GET /api/v1/runs/:id/vulnerabilities`.
- Add `GET /api/v1/projects/:id/vulnerabilities`.
- Add `GET /api/v1/runs/:id/signals` behind advanced/debug mode.
- Update `scan --output` or add `pentest --output` with a new schema
  containing `verified_vulnerabilities`, `verified_chains`, and
  aggregate signal counts.
- Keep PR comments limited to verified vulnerabilities and verified
  chains. Remove the current shortcut that treats cross-repo chain
  membership as PR-worthy without live chain verification.

## Frontend Navigation and UX Changes

### Navigation

Default navigation should be:

- Projects
- Pentest Runs
- Vulnerabilities
- Settings

Advanced/debug navigation should hide behind Settings:

- Nyx Signals
- Candidate Queue
- AI Traces
- Legacy Findings
- Raw Chains
- Repro Bundles

Rename or move:

- `Findings` becomes `Vulnerabilities` for the default route.
- Existing `Findings` table becomes `Signals` or `Legacy Findings`
  under advanced mode.
- `Chains` moves under a vulnerability detail or advanced mode until
  chains are live-verified.
- `Quarantine` becomes `Candidate Queue` and stays advanced.

### Project detail

Make the project page the main work surface:

- One prominent **Start pentest** button per project.
- Latest pentest status and latest verified vulnerability count.
- Launch profile readiness: build command, start command, target URLs,
  health checks, and last health result.
- Repos are configuration, not the main action. Remove per-row "Scan
  now" from the primary view; keep per-repo signal scans only in
  advanced/debug mode.
- Add an edit flow for launch profiles.

### Run view

Replace the static-focused live scan view with phase progress:

1. Preparing workspaces.
2. Building/starting local app.
3. Waiting for health checks.
4. Running Nyx signal scan.
5. AI pentest review.
6. Live verification.
7. Report ready.
8. Teardown.

The view should show candidate/verification counts, not raw diagnostic
counts as the primary success metric.

### Vulnerability results

The default results page should show a small curated set:

- title,
- severity,
- confidence,
- affected components,
- evidence summary,
- business impact,
- reproduction steps,
- remediation,
- source badges such as `Nyx-assisted`, `Agent-discovered`, or
  `Verified chain`.

Raw source snippets, AI trace turns, Nyx evidence blobs, and rejected
hypotheses belong in expandable advanced panels.

## Tests Required

### Data and migration tests

- Migrate an existing database with static `findings` into
  `nyx_signals` without losing legacy rows.
- Backfill `runs.project_id` where it can be inferred.
- Add repo ids and preserve existing project/repo relationships.
- Ensure two projects can each have a repo named `backend`.
- Verify signal ids include project and repo identity.
- Verify Low, Info, and code-quality Nyx diagnostics are stored but
  suppressed by default.
- Verify only `verified_vulnerabilities` feed default report endpoints.

### Pipeline unit tests

- Fake launch profile succeeds, emits environment events, and tears
  down.
- Launch failure halts before user-facing vulnerabilities are emitted.
- Fake Nyx returns mixed severities; only Medium+ security signals enter
  agent context.
- Fake agent rejects a Nyx signal; no vulnerability is created and the
  signal links to the rejection.
- Fake agent proposes a business-logic candidate with no Nyx signal;
  verification can promote it.
- Failed or errored verification never creates a verified
  vulnerability.
- Multiple candidates for the same root issue merge into one
  vulnerability.
- Verified chain requires a live terminal verification attempt.
- Cancellation stops the environment and marks the run halted.

### Integration fixtures

Create at least one multi-repo local app fixture:

- frontend repo,
- backend repo,
- optional infra/compose repo,
- seeded vulnerable endpoint,
- seeded business-logic flaw that Nyx does not find,
- seeded low/info Nyx-style noise.

End-to-end assertions:

- Start pentest builds and starts the app.
- Nyx signals are recorded internally.
- Default output contains only verified vulnerabilities.
- The business-logic flaw appears in verified output.
- Low/info signals do not appear in default output.
- Raw signals are visible only through advanced/debug routes.

### API tests

- `POST /api/v1/projects/:id/pentest` creates a project-scoped run.
- `GET /api/v1/runs/:id/vulnerabilities` returns verified rows only.
- `GET /api/v1/runs/:id/signals` is gated as advanced/debug.
- Existing `/findings` remains backward-compatible during migration,
  but is not called by the default frontend.
- WebSocket replay includes phase events for late subscribers.

### Frontend tests

- Sidebar hides raw Signals/Candidate Queue/AI Traces until advanced
  mode is enabled.
- Project detail renders exactly one primary **Start pentest** action.
- Launch profile incomplete state disables Start pentest with a clear
  configuration path.
- Run view renders phase progress and not raw Nyx diagnostic counts as
  the headline.
- Vulnerabilities page renders verified rows and empty states without
  mentioning "findings" as the main product result.
- Advanced signals page can filter Nyx signals by severity, repo, rule,
  and suppression reason.

### Safety and security tests

- Launch profiles reject production-looking secrets.
- Agent HTTP/browser tools are restricted to configured local targets.
- Evidence blobs redact configured secret patterns.
- Teardown runs on success, failure, cancellation, and panic-path drop.
- Prompt context does not include suppressed raw signals unless debug
  mode explicitly requests them.

## Migration Order

1. **Terminology and feature flag**
   - Add a `pentest` feature/path while leaving existing scan routes
     intact.
   - Update internal naming in docs and UI copy first so new work uses
     the right nouns.

2. **Repo identity and run scoping**
   - Add repo ids and `runs.project_id`.
   - Migrate code paths to pass `project_id` and `repo_id`.
   - Keep display repo names stable.

3. **Launch profiles**
   - Add launch profile CRUD APIs.
   - Backfill incomplete profiles from existing project fields.
   - Add frontend configuration UI.

4. **Environment run stage**
   - Wire launch profiles into a new pentest orchestrator.
   - Persist `environment_runs`.
   - Add phase events and teardown/cancel handling.

5. **Nyx signals table**
   - Convert Nyx output to `nyx_signals`.
   - Stop creating new `findings` rows for every static diagnostic in
     the pentest path.
   - Add advanced signal APIs.

6. **Pentest candidates**
   - Add `pentest_candidates`.
   - Build the agent input from source context, launch context, and
     meaningful Nyx signals.
   - Persist agent rejections and proposed candidates.

7. **Live verification**
   - Add `verification_attempts`.
   - Promote only confirmed attempts to `verified_vulnerabilities`.
   - Wire chain verification before showing chains as exploits.

8. **Frontend reset**
   - Replace default Findings UX with Vulnerabilities UX.
   - Move raw findings/chains/quarantine/traces behind advanced mode.
   - Replace scan buttons with Start pentest.

9. **Reports and CI**
   - Add new report schema.
   - Update PR comments to use verified vulnerabilities only.
   - Keep the old report reader for one compatibility window.

10. **Legacy cleanup**
   - Remove or clearly deprecate old static-finding paths.
   - Delete placeholder copy and phase labels.
   - Update README and operator docs from "wraps Nyx" to "automated
     smart pentesting for local dev builds."

## Risky Areas

- **Repo identity migration**: moving from global repo names to
  project-scoped repo ids touches stores, API DTOs, frontend filters,
  findings history, and reports.
- **Environment lifecycle**: user-defined commands can hang, spawn
  children, bind occupied ports, leak processes, or accidentally use
  production secrets.
- **Local app readiness**: many dev stacks have flaky readiness. Health
  checks need timeouts, retries, logs, and clear operator feedback.
- **Agent autonomy**: an agent with code, shell, browser, and HTTP tools
  must be tightly scoped to user-owned repos and configured local
  targets.
- **Verification quality**: weak oracles can create false confidence.
  Verification attempts must record the oracle and the exact evidence.
- **Cost and latency**: expert-style agent review can be expensive.
  Add caps, candidate limits, and early stopping.
- **Legacy data semantics**: existing `findings.status = Verified`
  means verifier-confirmed in some paths but may also coexist with
  manual promotion paths. Be conservative when backfilling verified
  vulnerabilities.
- **Current trace linkage**: `agent_traces` mostly links through
  `finding_id`; new artifacts need direct run/project/candidate links.
- **Current chain semantics**: existing chains are AI-ranked candidates,
  not necessarily live-verified exploit chains.
- **Current env builder gap**: compose support exists, but the main
  pipeline does not use it and custom commands are not modeled yet.

## Stubs and Placeholders to Delete or Hide

Delete or hide during the reset:

- `/runs` placeholder page.
- UI-only cancel behavior in `LiveScanView` until a real cancel
  endpoint exists.
- "Scan all" and per-repo "Scan now" as primary project actions.
- Default sidebar entries for raw `Findings`, `Chains`, and
  `Quarantine`.
- `FindingDetail` copy that says dynamic verdict/repro will land in
  later phases.
- Visible "Phase N" language in user-facing copy and comments that leak
  into UI strings.
- Setup copy that calls the product "Nyx Agent" or says AI-off means
  "nyx static analysis end-to-end" as the main product story.
- `CrossRepoCallgraphStub` as a product-facing concept.
- `RepoDynamicDone` as a fake progress phase until live verification
  emits real dynamic events.
- Candidate verifier built-in harness shortcuts as the primary
  confirmation path.
- Chain runner helper branches that surface "not yet wired" in any
  default user path.
- Raw Nyx findings in default reports and PR comments.

## Acceptance Criteria

The reset is complete when a user can:

1. Create a project with one or more repos.
2. Configure how the full local app builds, starts, and proves
   readiness.
3. Click one **Start pentest** button.
4. See Nyx run internally without being shown hundreds of raw
   diagnostics.
5. See the AI agent verify or reject Nyx hypotheses, find at least one
   static-missed/business-logic issue in a fixture, and attempt chains.
6. Receive a default result set of only verified vulnerabilities.
7. Open advanced/debug views for raw signals, rejected candidates, and
   traces when needed.


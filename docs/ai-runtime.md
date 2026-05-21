# AI runtime

`nyctos-ai` is the crate that turns a `Prompt` or `AgentTask` into
model output. It owns one trait (`AiRuntime`), two shipped adapters
(Anthropic Messages, Claude Code CLI), one host port
(`BudgetTracker`), and the five task implementations that build
typed structured prompts on top of the trait. Everything else in
the agent (the run dispatcher, the AI pipeline binary glue, the
trace viewer) sees only the trait, not the vendor SDK.

The crate stays vendor-neutral. Adapters depend on `nyctos-types`
for the wire envelope and on the `BudgetTracker` port for spend
accounting; nothing else. The binary at
`crates/nyctos/src/main.rs:1793` is the only place that picks a
concrete adapter from `[ai] runtime`, wires it to the
`BudgetStore`-backed tracker, and hands it to the dispatcher.

## The `AiRuntime` trait

```text
trait AiRuntime: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_model(&self) -> &str;
    fn supports_agent_loop(&self) -> bool;
    fn supports_prompt_cache(&self) -> bool;
    fn supports_deterministic_sampling(&self) -> bool;

    async fn one_shot(&self, prompt, budget, sink) -> Result<Response, AiError>;
    async fn agent_loop(&self, task, budget, sink) -> Result<AgentResult, AiError>;
    fn cost_estimate(&self, prompt) -> Option<CostEstimate>;
}
```

Defined at `crates/nyctos-ai/src/runtime.rs:18`. Adapters that
implement only one of the two execution modes return
`AiError::UnsupportedMode("agent_loop")` (or `"one_shot"`) from the
mode they do not support; the binary checks `supports_agent_loop`
before dispatching exploration work, so the unsupported-mode error
is a defence-in-depth, not the primary gate.

| Method                          | Behaviour                                                                 |
|---------------------------------|---------------------------------------------------------------------------|
| `name`                          | Stable adapter name persisted in trace rows (`"anthropic"`, `"claude-code"`). |
| `default_model`                 | Used when `Prompt.model` is `None`.                                       |
| `supports_agent_loop`           | `false` for one-shot-only adapters; the dispatcher uses this to route.    |
| `supports_prompt_cache`         | Affects request body shape (`system` block array with `cache_control`).   |
| `supports_deterministic_sampling` | `false` today on both shipped adapters: `temperature: 0` is the only knob. |
| `one_shot`                      | Single round trip. Streams `AiEvent::TokenReceived` plus cache + budget ticks. |
| `agent_loop`                    | Multi-turn tool-use loop. Streams `ToolCallStarted` / `Finished` plus tokens. |
| `cost_estimate`                 | Pre-call min/max bound in USD micros. Optional; `None` for adapters that can't price ahead. |

The trait is intentionally minimal. Anything richer (per-attempt
retry, prompt-version tracking, structured-output validation) lives
in `tasks/`, not in adapter implementations.

## Wire envelope: `Prompt`, `Response`, `AgentTask`, `AgentResult`

Defined in `crates/nyctos-types/src/agent.rs`. Both adapters
consume the same shape so the binary never depends on a vendor
schema.

### `Prompt`

| Field                | Type            | Notes                                                              |
|----------------------|-----------------|--------------------------------------------------------------------|
| `prompt_version`     | `String`        | Stable slug of the prompt template; persisted on every trace row.  |
| `task_id`            | `String`        | Echoed on every emitted `AiEvent` for fan-out.                     |
| `model`              | `Option<String>`| `None` falls back to `default_model()`.                            |
| `system`             | `String`        | System prompt. Adapters with prompt caching wrap it in a cache block. |
| `user`               | `String`        | User message body.                                                 |
| `max_output_tokens`  | `u32`           | Clamped to vendor limits inside the adapter.                       |
| `temperature`        | `f32`           | `0.0` for deterministic decoding.                                  |
| `seed`               | `Option<u64>`   | Honoured only by adapters that report `supports_deterministic_sampling = true`. |

### `Response`

| Field             | Type                | Notes                                                       |
|-------------------|---------------------|-------------------------------------------------------------|
| `prompt_version`  | `String`            | Echoes the request.                                         |
| `task_id`         | `String`            | Echoes the request.                                         |
| `model`           | `String`            | Vendor-reported model id (may differ from the requested alias). |
| `content`         | `String`            | Final completion text.                                      |
| `usage`           | `TokenUsage`        | Input / output token counts.                                |
| `cache`           | `Option<CacheStats>`| Set when the adapter reports cache deltas.                  |
| `cost_usd_micros` | `i64`               | Adapter-computed total in micros (1e-6 USD).                |

### `AgentTask` and `AgentResult`

`AgentTask` carries `tools: Vec<String>` and `max_turns: u32`
alongside the prompt fields; the Claude Code adapter renders this
into the markdown agent brief it pipes on stdin. `AgentResult`
carries `turns`, `extracted: Vec<ExtractedAgentResult>`, plus the
same token / cache / cost accounting as `Response`.

`ExtractedAgentResult` is the typed lift the adapter performs over
the tool-use trace. Recognised tool names are classified at
`agent.rs:261` (`classify_tool_use`):

| Tool name                       | Variant                                  |
|---------------------------------|------------------------------------------|
| `record_payload`                | `PayloadFound { rule_id, body }`         |
| `record_spec`                   | `SpecFound { capability, spec }`         |
| `record_chains`                 | `ChainsRanked { chain_ids, rationale }`  |
| `record_exploration_finding`    | `ExplorationFinding { ... }`             |
| anything else                   | `ExplorationEvent { message }`           |

The task crates consume the typed variants; the binary never
re-parses the raw transcript.

## Adapters

### Anthropic Messages (`one_shot` only)

`crates/nyctos-ai/src/adapter/anthropic.rs`.

Direct `reqwest` against `POST /v1/messages`. No third-party SDK,
so version drift on the SDK side cannot couple us to its release
cadence. Constants:

| Constant                   | Value                       |
|----------------------------|-----------------------------|
| `DEFAULT_BASE_URL`         | `https://api.anthropic.com` |
| `ANTHROPIC_VERSION`        | `2023-06-01`                |
| `DEFAULT_RANKING_MODEL`    | `claude-haiku-4-5`          |
| `DEFAULT_SYNTHESIS_MODEL`  | `claude-opus-4-7`           |

Capability flags: `supports_agent_loop = false`,
`supports_prompt_cache = true`,
`supports_deterministic_sampling = false`. `agent_loop` returns
`AiError::UnsupportedMode("agent_loop")`.

Per-model pricing lives at `anthropic.rs:65` (`pricing_for`). Match
order is prefix-based so `claude-opus-4-7-20260101` prices as the
opus alias. Unknown model names default to opus pricing so a
mis-typed model id does not silently price as the cheapest tier.

Request body:

```json
{
  "model": "claude-opus-4-7",
  "max_tokens": 4096,
  "temperature": 0.0,
  "system": [
    { "type": "text", "text": "<system prompt>",
      "cache_control": { "type": "ephemeral" } }
  ],
  "messages": [
    { "role": "user", "content": "<user>" }
  ]
}
```

The `system` field is a single-element block array (not a string)
when `supports_prompt_cache` is `true` so the `cache_control`
attachment can ride along. Adapters that do not support caching
emit a plain string for `system`.

The non-streaming path is the shipping one. The Messages API
supports SSE streaming via `stream: true`; a future revision can
flip to streaming and emit one `AiEvent::TokenReceived` per delta
without changing the trait.

### Claude Code (`agent_loop` only)

`crates/nyctos-ai/src/adapter/claude_code.rs`.

Spawns the `claude` CLI as a subprocess so the agent does not have
to embed Anthropic's tool-use loop. Detection runs
`which claude` (or `which claude-code` as a fallback alias) at
construction time; failure surfaces as
`AiError::AdapterUnavailable`. The binary path plus `--version`
output is captured into `ClaudeBinary` and surfaced by
`nyctos doctor`.

Wire shape:

1. Write `agent_task.md` into a per-task scratch directory.
2. Spawn `claude --print --output-format stream-json --verbose
   --max-turns <N>`.
3. Pipe the rendered task body on stdin and read the NDJSON event
   stream on stdout. A sibling task drains stderr into a bounded
   64 KiB trailing-window ring (`MAX_STDERR_CAPTURE_BYTES`) so a
   verbose child cannot block on a full pipe.
4. Classify each tool-use block via `classify_tool_use` into a
   typed `ExtractedAgentResult`; emit `ToolCallStarted` and
   `ToolCallFinished` events on the bus.
5. On timeout, kill the child, emit `TaskHalted { reason:
   OperatorCancelled }`, and annotate the returned
   `AiError::Transport` with the captured stderr.

Default model: `claude-opus-4-7`. Default wall-clock timeout: 15
minutes. Capability flags: `supports_agent_loop = true`,
`supports_prompt_cache = true`,
`supports_deterministic_sampling = false`. `one_shot` returns
`AiError::UnsupportedMode("one_shot")`.

### Adapters on the roadmap

OpenAI, Bedrock, Vertex, and a local-LLM driver. The
`AiRuntime::LocalLlm` enum variant in
`crates/nyctos-core/src/config.rs:243` is the configuration slot;
the adapter implementation has not landed. The
`secrets::ACCOUNT_AI_LOCAL_LLM` keychain account
(`crates/nyctos-core/src/secrets.rs:30`) is the slot for the
embedded bearer.

## Budget tracking

`BudgetTracker` (`runtime.rs:55`) is the host-side port the
adapter calls on every successful round trip. The contract is
deliberately small:

```text
async fn cap(run_id, kind) -> Result<Option<i64>, AiError>;
async fn current_spend(run_id, kind) -> Result<i64, AiError>;
async fn add_spend(run_id, kind, micros) -> Result<i64, AiError>;
```

Adapters never write a `halted` flag; the host owns that audit
trail in the `budgets` table. The boundary on both pre-call and
post-call cap checks is strictly `>`: a call landing exactly at
the cap proceeds, the call after does not.

`BudgetKind` (`agent.rs:151`) has three variants:

| Variant       | Used by                                  |
|---------------|------------------------------------------|
| `OneShot`     | `AiRuntime::one_shot` paths.             |
| `AgentLoop`   | `AiRuntime::agent_loop` paths.           |
| `Total`       | Reserved for per-run aggregate the host writes itself. |

Two implementations ship:

- `InMemoryBudgetTracker` (`runtime.rs:74`). Process-local, used
  by adapter tests and any future in-memory dispatcher.
- `BudgetStoreTracker` lives in the binary glue and forwards into
  `nyctos_core::store::BudgetStore`. The wizard picks a per-run
  cap (default `$5.00` from `AiConfig::DEFAULT_RUN_BUDGET_USD_MICROS`)
  and the tracker auto-creates the row on first `add_spend`.

`Budget` (`agent.rs:138`) is the per-call envelope:
`{ run_id, kind, cap_usd_micros }`. The `cap_usd_micros` field on
the envelope is the operator-visible per-call cap; the tracker
sees the per-run accumulated total separately.

### Per-call cap allocation ladder

Four `one_shot` tasks share a single
`(run_id, BudgetKind::OneShot)` bucket: PayloadSynthesis,
SpecDerivation, ChainReasoning, and NovelFindingDiscovery. The
binary drives them in that fixed order (see the `scan_loop`
function in `crates/nyctos/src/main.rs`), so earlier-pass spend
reduces the budget every later pass sees through the same tracker.
Each pass also carries its own per-call cap on the wire
(`payload_synthesis_per_call_cap_usd_micros`,
`spec_derivation_per_call_cap_usd_micros`,
`chain_reasoning_per_call_cap_usd_micros`,
`novel_discovery_per_call_cap_usd_micros`); each value clamps a
single call below the shared per-run bucket and falls back to
`AiConfig::DEFAULT_RUN_BUDGET_USD_MICROS` when unset.

The invariant the binary commits to is: PayloadSynthesis and
SpecDerivation get the full per-run cap to drive their fan-outs;
ChainReasoning fires a single call against whatever budget
remains after those passes finish; NovelFindingDiscovery runs
last and drains the remainder one batch at a time. The order is
intentional. The static-pass refusals that PayloadSynthesis and
SpecDerivation address are the most actionable signal in a run,
so they get first refusal on the budget; chain reasoning and
novel-discovery enrichments degrade gracefully when an earlier
pass exhausted the cap (the adapter pre-call check refuses, the
pass logs and continues). Operators who want chain reasoning or
novel-discovery to see a larger headroom should raise
`default_run_budget_usd_micros` rather than try to slice the
shared pool. The `BudgetKind` enum does not sub-bucket today, and
splitting `OneShot` into `OneShot.payload` / `OneShot.spec` /
`OneShot.chain` / `OneShot.novel` would touch every adapter and
every tracker in tree without changing the realised behaviour for
a run that finishes inside its cap.

AI Exploration is the only `agent_loop` task and lives in a
separate `(run_id, BudgetKind::AgentLoop)` row with its own
per-run hard cap (default `$10.00`). It does not draw from the
OneShot pool.

The `AgentLoop` bucket itself does not sub-bucket per adapter.
Today only the Claude Code adapter consumes the bucket, so the
question is academic. The shape that takes hold the moment a
second `agent_loop`-capable adapter ships (an OpenAI assistant
API path, a Bedrock agent path) is identical to the `OneShot`
case: the bucket is the cap the operator pays for; the
per-adapter accountability lives one layer down in the trace
store. Every adapter call writes one `agent_traces` row with
`runtime_name`, `model`, and `cost_usd_micros` columns, so an
operator dashboard that needs "how much did Claude Code burn vs
the OpenAI assistant during this run" sums `cost_usd_micros`
grouped by `runtime_name` from `agent_traces` rather than asking
the budget bucket to sub-bucket itself. Splitting
`BudgetKind::AgentLoop` into `AgentLoop.claude_code` /
`AgentLoop.openai` / etc. would touch every adapter and every
tracker in tree without changing the realised behaviour for a
run that finishes inside its cap; the per-adapter share is
already recoverable from the trace store.

## Event stream

Every model call publishes a fan-out of `AgentEvent::Ai { data:
AiEvent }` frames on the bus (`crates/nyctos-types/src/event.rs:145`).
The same `task_id` rides on every variant so subscribers can
multiplex concurrent calls.

| Variant                               | Emitted when                                                              |
|---------------------------------------|---------------------------------------------------------------------------|
| `TokenReceived { task_id, token }`    | Each token batch the adapter materialises (or the full body for non-streaming Anthropic). |
| `ToolCallStarted { task_id, name }`   | Agent loop sees a `ContentBlock::ToolUse`.                                |
| `ToolCallFinished { task_id, name, ok }` | After the tool-use block lands in `extracted`.                         |
| `CacheHit { task_id, tokens }`        | `usage.cache_read_input_tokens > 0`.                                      |
| `CacheMiss { task_id, tokens }`       | `usage.cache_creation_input_tokens > 0`.                                  |
| `BudgetTick { task_id, run_id, spent_usd_micros }` | After every successful `add_spend`.                            |
| `TaskHalted { task_id, reason }`      | Cap overrun, timeout, or upstream refusal.                                |

`HaltReason` (`agent.rs:319`) has three variants:
`BudgetCapReached`, `OperatorCancelled`, `UpstreamRefused`. See
[events.md](events.md) for the full envelope and the WebSocket
filter contract.

## Tasks

Five task modules sit on top of the trait. Each task builds a
typed `Prompt`, drives the model once (or twice on validation
retry), parses the JSON contract, validates the result, and
returns a typed outcome the binary persists.

| Task                       | File                                            | Outcome                                          |
|----------------------------|-------------------------------------------------|--------------------------------------------------|
| PayloadSynthesis           | `tasks/payload_synthesis.rs`                    | `Synthesised { output, ... }` or `Quarantined`.  |
| SpecDerivation             | `tasks/spec_derivation.rs`                      | `Synthesised { spec, spec_blob, ... }` or `Quarantined`. |
| ChainReasoning             | `tasks/chain_reasoning.rs`                      | `Ranked { output, ... }` or `NoChains`.          |
| NovelFindingDiscovery      | `tasks/novel_findings.rs`                       | `Discovered { candidates, ... }` or `NoCandidates`. |
| Exploration                | `tasks/exploration.rs`                          | `Completed { findings, ... }` plus halt reasons. |

Common rules across the four `one_shot` tasks:

- **Two attempts max.** First attempt uses the v1 prompt; the
  retry uses the `*_stricter` variant with explicit "your previous
  reply did not validate" framing.
- **Shared budget bucket.** Both attempts charge the same
  `(run_id, BudgetKind::OneShot)` row; the tracker is the gate.
- **`spent_usd_micros` and `attempts` ride on every outcome.** The
  binary persists both on the agent-trace row even on quarantine.
- **`metrics: AgentTraceMetrics`** (`agent.rs:88`) accumulates
  per-call observability across attempts via saturating add. The
  binary's `build_trace_row` lifts `usage` / `cache` / `model` from
  this envelope into the trace columns.

Exploration is the only `agent_loop` task. It runs against a
chain-lane sandbox with three guard rails:

1. **Escape suite gate.** A pre-flight `EscapeSuiteGate` check
   refuses dispatch if the escape-regression suite is red.
2. **Per-run hard cap.** Default `$10.00` USD micros, in the
   `(run_id, BudgetKind::AgentLoop)` bucket.
3. **Per-task soft cap.** A separate warning threshold emits a
   `TokenReceived` event with a `[soft-cap]` prefix but does not
   halt; the hard cap is the only ceiling that aborts.

## Determinism

`deterministic_seed(run_id, task_id)` (`runtime.rs:159`) produces a
stable 64-bit seed via `BLAKE3(run_id || "\0" || task_id)`.
Adapters that expose `random_seed` upstream pass it through;
adapters that do not ignore the value but the function is still
called so the binary's trace row carries the same number. Both
shipped adapters report `supports_deterministic_sampling = false`
today, so `temperature: 0` is the only knob; the seed becomes
load-bearing once a vendor surfaces a sampling-seed parameter.

## Prompt versions

Every prompt template lives in `crates/nyctos-ai/src/prompts/`
with a `v1.md` body and a `v1_stricter.md` retry variant. Stable
version slugs are persisted on every trace row:

| Task                  | Slug                                     |
|-----------------------|------------------------------------------|
| PayloadSynthesis      | `PAYLOAD_SYNTHESIS_PROMPT_VERSION`       |
| SpecDerivation        | `SPEC_DERIVATION_PROMPT_VERSION`         |
| ChainReasoning        | `CHAIN_REASONING_PROMPT_VERSION`         |
| NovelFindingDiscovery | `NOVEL_FINDING_DISCOVERY_PROMPT_VERSION` |
| Exploration           | `EXPLORATION_PROMPT_VERSION`             |

Slug constants live next to each task's `run` function. Rev a slug
only when the prompt body changes in a way downstream consumers
must distinguish; the trace store compares slugs verbatim.

## Configuration

Operators pick the runtime in `nyctos.toml` under the `[ai]`
section (defined at `crates/nyctos-core/src/config.rs:166`):

```toml
[ai]
provider = "anthropic"
model = "claude-opus-4-7"
runtime = "anthropic"               # none | anthropic | local-llm | claude-code
max_concurrent_one_shot = 4
default_run_budget_usd_micros = 5_000_000   # $5.00 default
```

| Field                            | Default                                | Notes                                                |
|----------------------------------|----------------------------------------|------------------------------------------------------|
| `provider`                       | `None`                                 | Free-form provider hint surfaced by the wizard.      |
| `model`                          | `None`                                 | Per-run model override; tasks may still pick a model per prompt. |
| `api_base`                       | `None`                                 | Endpoint URL for `local-llm`.                        |
| `runtime`                        | `none`                                 | One of `none`, `anthropic`, `local-llm`, `claude-code`. |
| `max_concurrent_one_shot`        | `4`                                    | In-flight one-shot fan-out. Floored to `1`.          |
| `default_run_budget_usd_micros`  | `5_000_000` (`$5.00`)                  | Per-run cap stamped on auto-created budget rows.     |

Secrets do not live in TOML. The wizard stashes the API key in the
OS keychain under `secrets::ACCOUNT_AI_ANTHROPIC` (Anthropic) or
`secrets::ACCOUNT_AI_LOCAL_LLM` (local LLM).

## Failure modes

| Error                                | When                                                                   |
|--------------------------------------|------------------------------------------------------------------------|
| `AiError::BudgetExceeded`            | Pre-call or post-call cap check fails. Emits `TaskHalted { BudgetCapReached }`. |
| `AiError::UnsupportedMode`           | Adapter does not implement the requested mode (anthropic + `agent_loop`, claude-code + `one_shot`). |
| `AiError::UpstreamRefused`           | Non-2xx HTTP status (anthropic) or non-zero exit (claude-code). Body / stderr rides in the variant string. |
| `AiError::MalformedResponse`         | JSON deserialisation failed on the response body.                      |
| `AiError::Transport`                 | Network, IO, or scratch-dir failure. Claude Code agent-loop timeout maps here with the captured stderr appended. |
| `AiError::BudgetTracker`             | The host tracker returned an error (database write failure, etc.).     |
| `AiError::AdapterUnavailable`        | Construction failed (e.g. `claude` not on `PATH`).                     |

`thiserror` variants live at `crates/nyctos-types/src/agent.rs:326`.

## Related pages

- [architecture.md](architecture.md) for where the AI runtime sits
  in the crate map.
- [events.md](events.md) for the `AiEvent` stream and the
  WebSocket filter contract.
- [config.md](config.md) for the rest of `nyctos.toml`.
- [api.md](api.md) for the `/api/v1/budgets` route and the
  `/api/v1/traces` endpoints that read the per-call trace store.

# Events

Nyx Agent publishes every observable state change to a single in-process
`tokio::sync::broadcast` channel. The HTTP server fans the channel
out over `GET /api/v1/events` as a WebSocket; the frontend's
LiveScanView reads it to drive per-repo badges, the AI trace viewer
reads it to follow per-task token spend, and tests subscribe to it
to assert ordering.

This page documents the wire shape and the ordering contract. The
typed source is `crates/nyx-agent-types/src/event.rs`.

## Wire shape

Every frame is one JSON-encoded `AgentEvent` value. The outer
envelope tags the family:

```json
{
  "kind": "Run",
  "data": { "kind": "RunStarted", "run_id": "...", "...": "..." }
}
```

`kind` carries the family (`Run`, `Ai`, `Sandbox`, `Finding`,
`Budget`, `Quarantine`, `Repro`); `data` carries a family-specific
variant that also has its own `kind` discriminant. Both layers use
serde internally-tagged enums, so a TypeScript consumer can pattern
match on `event.kind` then `event.data.kind`.

`Run` and `Ai` are the only families that publish today. The other
five are placeholder unit variants reserved for future publishers
(`SandboxEvent`, `FindingEvent`, `BudgetEvent`, `QuarantineEvent`,
`ReproEvent` are empty structs at
`crates/nyx-agent-types/src/event.rs:180-192`). Subscribers should
ignore unknown variants, not panic.

## Subscribing

`GET /api/v1/events[?run_id=<id>][&token=<token>]`

WebSocket upgrade against the daemon. Bearer auth applies; pass the
`Authorization: Bearer ...` header or the `?token=...` query param.

| Query param | Meaning |
| --- | --- |
| `run_id` | Filter the live stream to one run. The server replays the buffered events for that run first, then streams matching live events. |
| `token` | Auth fallback for clients that cannot set the header. |

Without `run_id`, every frame the broadcast channel publishes lands
on the socket unfiltered. With `run_id`, the filter applies to
every `RunEvent` variant that carries a `run_id` field (i.e. every
variant except `Heartbeat`, which passes through any filter so the
client can detect a healthy idle socket). `AiEvent` variants carry
`run_id` only on `BudgetTick`; the others are not currently
filtered.

Client-initiated frames are dropped except for `ping` (mirrored to
`pong`) and `close` (terminates the stream). The socket is
server-push only.

## `RunEvent`: per-run lifecycle

Run events fire in a fixed order. A subscriber that joins mid-run
sees the buffered prefix replayed first, then live events from the
join point onwards.

```
RunStarted
  ProjectStarted
    RepoStarted        (one per repo)
      RepoStaticDone | RepoFailed | RepoDynamicDone
    RepoFinished       (one per repo, always after the above)
    ... (more repos)
  ProjectFinished
RunFinished
```

| Variant | Fired by | Carries |
| --- | --- | --- |
| `RunStarted` | dispatcher, once per run | `run_id`, `project_id`, `repos: Vec<String>`, `started_at_ms` |
| `ProjectStarted` | dispatcher, once per project | `run_id`, `project_id`, `project_name`, `started_at_ms` |
| `RepoStarted` | rayon worker, once per repo | `run_id`, `project_id`, `repo`, `started_at_ms` |
| `RepoStaticDone` | static-pass success | `n_diags: u32`, `elapsed_ms` |
| `RepoFailed` | static-pass timeout / scanner refusal | `message: String`, `elapsed_ms` |
| `RepoDynamicDone` | reserved for the sandbox publisher | `elapsed_ms` |
| `RepoFinished` | terminator, always last per repo | `outcome: RepoOutcomeTag`, `elapsed_ms` |
| `ProjectFinished` | dispatcher, once per project | `finished_at_ms` |
| `RunFinished` | dispatcher, once per run | `finished_at_ms`, `wall_clock_ms`, `succeeded`, `inconclusive`, `failed` |
| `Heartbeat` | reserved variant; no publisher today | `ts: i64` |

`RepoFinished.outcome` is `RepoOutcomeTag::Success`,
`Inconclusive`, or `Failed`. The full typed outcome lives on the
in-process `RepoBundle`; the tag is the colour a UI badge needs.

The publishers live at:

- `crates/nyx-agent-core/src/run/mod.rs:282-348` (run / project / repo
  fan-out and terminators).
- `crates/nyx-agent-core/src/run/mod.rs:404-464` (per-repo
  `RepoStarted` / `RepoStaticDone` / `RepoFailed` /
  `RepoFinished`).
- `crates/nyx-agent/src/main.rs:578` (out-of-band `RepoFailed` when
  the API-driven scan path rejects the request before reaching the
  dispatcher).

## `AiEvent`: per-task AI runtime stream

AI adapters publish into the same bus, one frame per token, tool
call, cache event, budget tick, or halt. `task_id` is the
caller-supplied identifier from the `Prompt` or `AgentTask`;
subscribers fan out by `task_id` to multiplex concurrent calls on a
single socket.

| Variant | Fired when |
| --- | --- |
| `TokenReceived` | streaming text chunk arrives |
| `ToolCallStarted` | adapter invokes a tool |
| `ToolCallFinished` | tool returned (with `ok: bool`) |
| `CacheHit` | prompt cache served `tokens` tokens |
| `CacheMiss` | prompt cache wrote `tokens` tokens |
| `BudgetTick` | adapter charged the budget (carries `run_id` and `spent_usd_micros`) |
| `TaskHalted` | terminator; `reason: HaltReason` is `BudgetCapReached`, `OperatorCancelled`, or `UpstreamRefused` |

Adapter publishers live in
`crates/nyx-agent-ai/src/adapter/anthropic.rs` and
`crates/nyx-agent-ai/src/adapter/claude_code.rs`; the exploration task
publishes one of its own at
`crates/nyx-agent-ai/src/tasks/exploration.rs:262`.

`TaskHalted` is the only AI variant the adapter guarantees to send
on every code path. The others fire on a best-effort basis: a
backend that has no cache reports zero `CacheHit` / `CacheMiss`,
and a non-streaming completion path skips `TokenReceived`.

## Replay buffer

The HTTP server keeps a small in-memory ring per run so a
LiveScanView that opens after the dispatcher kicks off still sees
`RunStarted` and the first few `RepoStarted` frames. The buffer
shape is fixed:

| Setting | Value | Source |
| --- | --- | --- |
| Frames per run | 128 | `crates/nyx-agent-api/src/state.rs:113` |
| Tracked runs | 16 | `crates/nyx-agent-api/src/state.rs:117` |
| Eviction | least-recently-touched run | `crates/nyx-agent-api/src/state.rs:148-154` |

`Heartbeat` frames are not buffered (no `run_id` to scope to).
Every other `RunEvent` variant is. `AiEvent`, `SandboxEvent`, and
the other placeholder families are not buffered today; if the WS
client joined after the relevant frame, it is lost.

A tap task in `crates/nyx-agent/src/main.rs:989-1000` subscribes
to the broadcast channel and pushes every event into the replay
buffer. When a WS client opens with `?run_id=<id>`, the handler
calls `EventReplay::snapshot(run_id)` before joining the live
stream, emits the snapshot frames first, then forwards live
matches. Duplicate frames are harmless because frontend reducers
fold per-key (e.g. `RepoStarted` for the same repo is
idempotent).

## Bus capacity and `Lagged`

The broadcast channel is sized at startup:

- 256 frames for the serve path (`crates/nyx-agent/src/main.rs:928`).
- 16 frames for the headless wizard path
  (`crates/nyx-agent/src/main.rs:443`), since no WS clients
  attach.

When a subscriber falls more than capacity frames behind, tokio
drops the missed frames and surfaces a `RecvError::Lagged(n)` on
the next `recv`. The WS handler translates that into a synthetic
warning frame so the client can re-fetch state:

```json
{ "kind": "Lagged", "skipped": 42 }
```

`Lagged` is the only frame the WS layer fabricates; every other
frame is a serialised `AgentEvent` value. Clients should treat
`Lagged` as a hint to drop cached deltas and refetch
`/api/v1/runs/<id>` for authoritative state.

## Related pages

- [api.md](api.md): the rest of the `/api/v1/` surface, including
  the bearer-auth contract that gates the WS handshake.
- [runs.md](runs.md): the run lifecycle these events project (the
  dispatcher's per-repo fan-out and the `RunBundle` aggregation
  that produces `RepoOutcomeTag`).
- [architecture.md](architecture.md): where the broadcast channel
  sits in the wider tokio + rayon process model.

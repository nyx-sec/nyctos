// Typed event bus. Every phase publishes through `AgentEvent`; subscribers
// fan out per variant. `EventSink` is the shared producer side; each
// consumer holds its own `EventStream` newtype around a broadcast receiver
// so the rest of the codebase never names tokio's concrete receiver.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use ts_rs::TS;

use crate::agent::HaltReason;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind")]
pub enum AgentEvent {
    Run { data: RunEvent },
    Ai { data: AiEvent },
    Sandbox { data: SandboxEvent },
    Finding { data: FindingEvent },
    Budget { data: BudgetEvent },
    Quarantine { data: QuarantineEvent },
    Repro { data: ReproEvent },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind")]
pub enum RunEvent {
    Heartbeat {
        #[ts(type = "number")]
        ts: i64,
    },
    /// Run-level lifecycle: dispatcher accepted the work and is about to
    /// fan out per-repo jobs.
    RunStarted {
        run_id: String,
        project_id: String,
        repos: Vec<String>,
        #[ts(type = "number")]
        started_at_ms: i64,
    },
    /// Project-level lifecycle: emitted once per project before the
    /// per-repo fan-out begins. A run scans exactly one project today;
    /// the event carries the project's stable id and human-facing name
    /// so subscribers can group per-repo events under the right project
    /// without a side lookup.
    ProjectStarted {
        run_id: String,
        project_id: String,
        project_name: String,
        #[ts(type = "number")]
        started_at_ms: i64,
    },
    /// Per-repo lifecycle: a rayon job picked up `repo` and the static
    /// pass is running.
    RepoStarted {
        run_id: String,
        project_id: String,
        repo: String,
        #[ts(type = "number")]
        started_at_ms: i64,
    },
    /// Static pass returned (success or no findings).
    RepoStaticDone {
        run_id: String,
        project_id: String,
        repo: String,
        n_diags: u32,
        #[ts(type = "number")]
        elapsed_ms: i64,
    },
    /// Dynamic / sandbox pass returned. Reserved for the sandbox
    /// publisher; the static-pass dispatcher does not emit this yet
    /// and the variant exists so the sandbox crate can publish into
    /// the same bus without a `RunEvent` shape change.
    RepoDynamicDone {
        run_id: String,
        project_id: String,
        repo: String,
        #[ts(type = "number")]
        elapsed_ms: i64,
    },
    /// Per-repo failure: the static pass exited non-zero, panicked, or
    /// the scan lane refused to start (e.g. binary missing).
    RepoFailed {
        run_id: String,
        project_id: String,
        repo: String,
        message: String,
        #[ts(type = "number")]
        elapsed_ms: i64,
    },
    /// Ingest-time failure: the repo could not be cloned, fetched, or
    /// snapshotted before the dispatcher saw a workspace. Emitted from
    /// the caller (CLI / API drive-scan path) *before* `RunStarted`, so
    /// subscribers connected at run start time can reconstruct the full
    /// attempted-repo set from `RunStarted.repos` alone — the failing
    /// repo is included there and `RepoIngestFailed` carries the
    /// upstream error string for UI surfacing.
    RepoIngestFailed { run_id: String, project_id: String, repo: String, message: String },
    /// Per-repo terminator. Always emitted regardless of outcome so
    /// subscribers can drop bookkeeping for the repo without diffing
    /// the success / failure event streams.
    RepoFinished {
        run_id: String,
        project_id: String,
        repo: String,
        outcome: RepoOutcomeTag,
        #[ts(type = "number")]
        elapsed_ms: i64,
    },
    /// Project-level terminator. Emitted once every repo in the project
    /// has produced a `RepoFinished` but before the run-level
    /// `RunFinished`.
    ProjectFinished {
        run_id: String,
        project_id: String,
        #[ts(type = "number")]
        finished_at_ms: i64,
    },
    /// Run-level terminator. Emitted once every repo has produced a
    /// `RepoFinished`.
    RunFinished {
        run_id: String,
        project_id: String,
        #[ts(type = "number")]
        finished_at_ms: i64,
        #[ts(type = "number")]
        wall_clock_ms: i64,
        succeeded: u32,
        inconclusive: u32,
        failed: u32,
    },
}

/// Compressed flavour tag carried on `RepoFinished`. The aggregator's
/// `RepoBundle` keeps the full typed outcome; subscribers that only
/// need a colour for a UI badge read this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum RepoOutcomeTag {
    Success,
    /// Static pass did not finish (e.g. per-repo timeout).
    Inconclusive,
    /// Static pass failed outright (scanner crash, refusal, etc.).
    Failed,
}

/// AI-runtime event stream. Adapters publish one of these per token /
/// tool call / cache event / budget tick / halt as a `one_shot` or
/// `agent_loop` progresses. `task_id` is the caller-supplied
/// identifier from the `Prompt` / `AgentTask`; subscribers fan out by
/// it to multiplex concurrent calls on a single bus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind")]
pub enum AiEvent {
    TokenReceived {
        task_id: String,
        token: String,
    },
    ToolCallStarted {
        task_id: String,
        name: String,
    },
    ToolCallFinished {
        task_id: String,
        name: String,
        ok: bool,
    },
    CacheHit {
        task_id: String,
        tokens: u32,
    },
    CacheMiss {
        task_id: String,
        tokens: u32,
    },
    BudgetTick {
        task_id: String,
        run_id: String,
        #[ts(type = "number")]
        spent_usd_micros: i64,
    },
    TaskHalted {
        task_id: String,
        reason: HaltReason,
    },
}

/// Sandbox / verifier lifecycle events. Subscribers fan out by
/// `run_id`; consumers that only care about a single finding's verifier
/// progress key off `finding_id`. Today only the deterministic
/// verifier publishes here; future backends (chain-lane runner,
/// AI exploration sandbox) will add their own variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind")]
pub enum SandboxEvent {
    /// Verifier pass picked up a finding and is about to launch the
    /// vuln/benign payload pair. Emitted once per finding the pass
    /// actually drives (skipped findings produce no event).
    VerifierStarted {
        run_id: String,
        finding_id: String,
        repo: String,
        #[ts(type = "number")]
        started_at_ms: i64,
    },
    /// Verifier pass finished a finding. `verdict` mirrors
    /// `VerifyVerdict::as_str()` (`"Confirmed"` / `"NotConfirmed"` /
    /// `"Errored"`). `replay_stable` stays `None` when the
    /// `[run] replay_stable_check` knob is off; `Some(true)` when the
    /// optional second run produced an identical verdict.
    VerifierFinished {
        run_id: String,
        finding_id: String,
        repo: String,
        verdict: String,
        replay_stable: Option<bool>,
        #[ts(type = "number")]
        elapsed_ms: i64,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FindingEvent {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BudgetEvent {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct QuarantineEvent {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ReproEvent {}

pub type EventSink = broadcast::Sender<AgentEvent>;

#[derive(Debug)]
pub struct EventStream(pub broadcast::Receiver<AgentEvent>);

impl EventStream {
    pub fn new(rx: broadcast::Receiver<AgentEvent>) -> Self {
        Self(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn heartbeat_roundtrips_via_broadcast() {
        let (tx, rx) = broadcast::channel::<AgentEvent>(8);
        let mut stream = EventStream::new(rx);
        let original = AgentEvent::Run { data: RunEvent::Heartbeat { ts: 42 } };
        tx.send(original.clone()).expect("send");
        let received = stream.0.recv().await.expect("recv");
        assert_eq!(received, original);
    }

    #[test]
    fn heartbeat_serde_roundtrip() {
        let original = AgentEvent::Run { data: RunEvent::Heartbeat { ts: 7 } };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: AgentEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }
}

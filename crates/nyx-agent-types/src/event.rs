// Typed event bus. Every phase publishes through `AgentEvent`; subscribers
// fan out per variant. `EventSink` is the shared producer side; each
// consumer holds its own `EventStream` newtype around a broadcast receiver
// so the rest of the codebase never names tokio's concrete receiver.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use ts_rs::TS;

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
        ts: i64,
    },
    /// Run-level lifecycle: dispatcher accepted the work and is about to
    /// fan out per-repo jobs.
    RunStarted {
        run_id: String,
        repos: Vec<String>,
        started_at_ms: i64,
    },
    /// Per-repo lifecycle: a rayon job picked up `repo` and the static
    /// pass is running.
    RepoStarted {
        run_id: String,
        repo: String,
        started_at_ms: i64,
    },
    /// Static pass returned (success or no findings).
    RepoStaticDone {
        run_id: String,
        repo: String,
        n_diags: u32,
        elapsed_ms: i64,
    },
    /// Dynamic / sandbox pass returned. Phase 06 does not emit this
    /// yet; the variant exists so Phase 18 (sandbox) can publish into
    /// the same bus without a `RunEvent` shape change.
    RepoDynamicDone {
        run_id: String,
        repo: String,
        elapsed_ms: i64,
    },
    /// Per-repo failure: the static pass exited non-zero, panicked, or
    /// the scan lane refused to start (e.g. binary missing).
    RepoFailed {
        run_id: String,
        repo: String,
        message: String,
        elapsed_ms: i64,
    },
    /// Per-repo terminator. Always emitted regardless of outcome so
    /// subscribers can drop bookkeeping for the repo without diffing
    /// the success / failure event streams.
    RepoFinished {
        run_id: String,
        repo: String,
        outcome: RepoOutcomeTag,
        elapsed_ms: i64,
    },
    /// Run-level terminator. Emitted once every repo has produced a
    /// `RepoFinished`.
    RunFinished {
        run_id: String,
        finished_at_ms: i64,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AiEvent {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SandboxEvent {}

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

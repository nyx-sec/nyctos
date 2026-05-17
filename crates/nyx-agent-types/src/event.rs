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
    Heartbeat { ts: i64 },
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

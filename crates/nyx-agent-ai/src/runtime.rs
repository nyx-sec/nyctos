//! `AiRuntime` trait + the small `BudgetTracker` port that adapters
//! hit on every successful round-trip to land a `BudgetTick` row in the
//! Phase-03 `budgets` table. The trait stays vendor-neutral; concrete
//! adapters live under `adapter/`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nyctos_types::agent::{
    AgentResult, AgentTask, AiError, Budget, BudgetKind, CostEstimate, Prompt, Response,
};
use nyctos_types::event::EventSink;

/// Vendor-neutral AI runtime contract. Every adapter (Anthropic SDK,
/// Claude Code, OpenAI, ...) implements this trait so the rest of the
/// agent depends only on `nyx-agent-ai` and `nyctos-types`.
#[async_trait]
pub trait AiRuntime: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_model(&self) -> &str;
    fn supports_agent_loop(&self) -> bool;
    fn supports_prompt_cache(&self) -> bool;
    fn supports_deterministic_sampling(&self) -> bool;

    /// Single-prompt structured task. Streams `AgentEvent::Ai` events
    /// to `sink` as tokens / cache hits / cost ticks land. Returns the
    /// final `Response` once the model finishes.
    async fn one_shot(
        &self,
        prompt: Prompt,
        budget: Budget,
        sink: EventSink,
    ) -> Result<Response, AiError>;

    /// Multi-turn tool-use loop. Adapters that only do one-shot return
    /// `AiError::UnsupportedMode("agent_loop")`.
    async fn agent_loop(
        &self,
        task: AgentTask,
        budget: Budget,
        sink: EventSink,
    ) -> Result<AgentResult, AiError>;

    fn cost_estimate(&self, prompt: &Prompt) -> Option<CostEstimate>;
}

/// Host-side port the adapter calls on every successful round-trip.
/// The production wiring forwards into
/// `nyx_agent_core::store::BudgetStore`; tests use [`InMemoryBudgetTracker`].
///
/// The trait is intentionally minimal: cap reads + monotonic spend
/// adds. Adapters never write the `halted` flag directly - the host
/// keeps that audit trail in the budgets table.
#[async_trait]
pub trait BudgetTracker: Send + Sync {
    /// Return the cap for `(run_id, kind)` in USD micros, or `None`
    /// if no cap is configured.
    async fn cap(&self, run_id: &str, kind: BudgetKind) -> Result<Option<i64>, AiError>;

    /// Read the current `spent_usd_micros` for `(run_id, kind)`. A
    /// non-existent row reads as `0` so pre-call cap checks against a
    /// brand-new run do not need to seed the row first.
    async fn current_spend(&self, run_id: &str, kind: BudgetKind) -> Result<i64, AiError>;

    /// Atomically increment `spent_usd_micros` by `micros` and return
    /// the new total.
    async fn add_spend(&self, run_id: &str, kind: BudgetKind, micros: i64) -> Result<i64, AiError>;
}

/// Process-local budget tracker. Used by adapter tests and any future
/// in-memory dispatcher; production code wires a real
/// `BudgetStore`-backed implementation in the binary.
#[derive(Default)]
pub struct InMemoryBudgetTracker {
    inner: Mutex<Vec<Row>>,
}

#[derive(Clone)]
struct Row {
    run_id: String,
    kind: BudgetKind,
    cap_usd_micros: Option<i64>,
    spent_usd_micros: i64,
}

impl InMemoryBudgetTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed the cap for `(run_id, kind)`. Subsequent `add_spend`
    /// calls accumulate against this cap.
    pub fn set_cap(&self, run_id: &str, kind: BudgetKind, cap_usd_micros: i64) {
        let mut rows = self.inner.lock().expect("tracker poisoned");
        if let Some(row) = rows.iter_mut().find(|r| r.run_id == run_id && r.kind == kind) {
            row.cap_usd_micros = Some(cap_usd_micros);
        } else {
            rows.push(Row {
                run_id: run_id.to_string(),
                kind,
                cap_usd_micros: Some(cap_usd_micros),
                spent_usd_micros: 0,
            });
        }
    }

    pub fn spent(&self, run_id: &str, kind: BudgetKind) -> i64 {
        let rows = self.inner.lock().expect("tracker poisoned");
        rows.iter()
            .find(|r| r.run_id == run_id && r.kind == kind)
            .map(|r| r.spent_usd_micros)
            .unwrap_or(0)
    }
}

#[async_trait]
impl BudgetTracker for InMemoryBudgetTracker {
    async fn cap(&self, run_id: &str, kind: BudgetKind) -> Result<Option<i64>, AiError> {
        let rows = self.inner.lock().expect("tracker poisoned");
        Ok(rows
            .iter()
            .find(|r| r.run_id == run_id && r.kind == kind)
            .and_then(|r| r.cap_usd_micros))
    }

    async fn current_spend(&self, run_id: &str, kind: BudgetKind) -> Result<i64, AiError> {
        let rows = self.inner.lock().expect("tracker poisoned");
        Ok(rows
            .iter()
            .find(|r| r.run_id == run_id && r.kind == kind)
            .map(|r| r.spent_usd_micros)
            .unwrap_or(0))
    }

    async fn add_spend(&self, run_id: &str, kind: BudgetKind, micros: i64) -> Result<i64, AiError> {
        let mut rows = self.inner.lock().expect("tracker poisoned");
        if let Some(row) = rows.iter_mut().find(|r| r.run_id == run_id && r.kind == kind) {
            row.spent_usd_micros += micros;
            Ok(row.spent_usd_micros)
        } else {
            rows.push(Row {
                run_id: run_id.to_string(),
                kind,
                cap_usd_micros: None,
                spent_usd_micros: micros,
            });
            Ok(micros)
        }
    }
}

/// Convenience alias used by the Anthropic adapter constructor.
pub type SharedBudgetTracker = Arc<dyn BudgetTracker>;

/// Derive a deterministic 64-bit seed for sampling from `run_id` and
/// `task_id`. Adapters that expose `random_seed` upstream pass this
/// through; adapters that do not ignore it. Public so callers can mint
/// the same seed when persisting traces.
pub fn deterministic_seed(run_id: &str, task_id: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(run_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(task_id.as_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_is_stable() {
        let a = deterministic_seed("run-1", "task-a");
        let b = deterministic_seed("run-1", "task-a");
        assert_eq!(a, b);
        let c = deterministic_seed("run-1", "task-b");
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn in_memory_tracker_caps_and_adds() {
        let t = InMemoryBudgetTracker::new();
        t.set_cap("run", BudgetKind::OneShot, 10_000);
        let cap = t.cap("run", BudgetKind::OneShot).await.unwrap();
        assert_eq!(cap, Some(10_000));
        let after_a = t.add_spend("run", BudgetKind::OneShot, 4_000).await.unwrap();
        let after_b = t.add_spend("run", BudgetKind::OneShot, 1_500).await.unwrap();
        assert_eq!(after_a, 4_000);
        assert_eq!(after_b, 5_500);
        assert_eq!(t.spent("run", BudgetKind::OneShot), 5_500);
    }

    #[tokio::test]
    async fn current_spend_reads_without_mutating() {
        let t = InMemoryBudgetTracker::new();
        assert_eq!(t.current_spend("run", BudgetKind::OneShot).await.unwrap(), 0);
        t.add_spend("run", BudgetKind::OneShot, 7_500).await.unwrap();
        assert_eq!(t.current_spend("run", BudgetKind::OneShot).await.unwrap(), 7_500);
        assert_eq!(t.current_spend("run", BudgetKind::OneShot).await.unwrap(), 7_500);
        assert_eq!(t.spent("run", BudgetKind::OneShot), 7_500);
    }
}

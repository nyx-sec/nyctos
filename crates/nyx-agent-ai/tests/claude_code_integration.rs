//! Phase-13 integration test: drive `ClaudeCodeAdapter` against the
//! real `claude` CLI when it is on `PATH`. The test is skipped cleanly
//! when the binary is missing so CI without Claude Code installed
//! stays green.

use std::sync::Arc;
use std::time::Duration;

use nyctos_types::agent::{AgentTask, AiError, Budget, BudgetKind};
use nyctos_types::event::AgentEvent;
use nyx_agent_ai::{
    detect_claude_binary, AiRuntime, ClaudeCodeAdapter, InMemoryBudgetTracker, SharedBudgetTracker,
};
use tokio::sync::broadcast;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_loop_round_trips_when_claude_on_path() {
    let binary = match detect_claude_binary().await {
        Ok(b) => b,
        Err(_) => {
            eprintln!("skipping: `claude` not on PATH");
            return;
        }
    };

    let concrete = Arc::new(InMemoryBudgetTracker::new());
    concrete.set_cap("run-integration", BudgetKind::AgentLoop, 5_000_000);
    let tracker: SharedBudgetTracker = concrete.clone();
    let adapter = ClaudeCodeAdapter::new(binary, tracker).with_timeout(Duration::from_secs(120));

    let (tx, mut rx) = broadcast::channel::<AgentEvent>(64);
    let task = AgentTask {
        prompt_version: "phase13.integration.v1".to_string(),
        task_id: "task-integration".to_string(),
        system: "respond with a single sentence.".to_string(),
        objective: "reply with exactly the word OK".to_string(),
        tools: vec![],
        max_turns: 1,
    };

    let result = adapter
        .agent_loop(
            task,
            Budget {
                run_id: "run-integration".to_string(),
                kind: BudgetKind::AgentLoop,
                cap_usd_micros: 5_000_000,
            },
            tx,
        )
        .await;

    match result {
        Ok(parsed) => {
            assert_eq!(parsed.task_id, "task-integration");
            assert_eq!(parsed.prompt_version, "phase13.integration.v1");
            let mut saw_event = false;
            while rx.try_recv().is_ok() {
                saw_event = true;
            }
            assert!(saw_event, "expected at least one AgentEvent on the bus");
        }
        Err(AiError::UpstreamRefused(msg)) | Err(AiError::Transport(msg)) => {
            // `claude` is on PATH but not authenticated / not reachable.
            // Treat as a clean skip per the phase contract.
            eprintln!("skipping: claude reached but refused: {msg}");
        }
        Err(other) => panic!("unexpected adapter error: {other:?}"),
    }
}

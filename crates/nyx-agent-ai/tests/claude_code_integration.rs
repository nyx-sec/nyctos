//! Integration test: drive `ClaudeCodeAdapter` against the real
//! `claude` CLI when it is on `PATH`. The test is skipped cleanly
//! when the binary is missing so CI without Claude Code installed
//! stays green.
//!
//! Strict mode: setting `NYX_AGENT_REQUIRE_CLAUDE_CODE=1` flips the
//! `claude`-missing branch and the `UpstreamRefused` / `Transport`
//! branch from clean-skip to hard-fail. A CI lane that has known-good
//! Claude Code credentials should set this so a revoked API key on the
//! CI machine surfaces as a red test instead of a silent skip. Dev
//! boxes without the env var keep the historic skip behaviour.

use std::sync::Arc;
use std::time::Duration;

use nyx_agent_ai::{
    detect_claude_binary, AiRuntime, ClaudeCodeAdapter, InMemoryBudgetTracker, SharedBudgetTracker,
};
use nyx_agent_types::agent::{AgentTask, AiError, Budget, BudgetKind};
use nyx_agent_types::event::AgentEvent;
use tokio::sync::broadcast;

/// `true` when the CI lane has flipped strict mode on. Read once at
/// test entry; the env-var check is `==` "1" so other truthy spellings
/// (`true`, `yes`) intentionally do NOT flip the gate; CI owners
/// should be explicit.
fn require_claude_code() -> bool {
    std::env::var("NYX_AGENT_REQUIRE_CLAUDE_CODE").ok().as_deref() == Some("1")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_loop_round_trips_when_claude_on_path() {
    let strict = require_claude_code();
    let binary = match detect_claude_binary().await {
        Ok(b) => b,
        Err(err) => {
            if strict {
                panic!("NYX_AGENT_REQUIRE_CLAUDE_CODE=1 but `claude` is not on PATH: {err}",);
            }
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
        working_directory: None,
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
            // Without strict mode, treat as a clean skip per the phase
            // contract so a dev box without Anthropic credentials does
            // not red the workspace.
            if strict {
                panic!(
                    "NYX_AGENT_REQUIRE_CLAUDE_CODE=1 but adapter refused: {msg}. \
                     The CI lane shipped a `claude` binary whose credentials \
                     are invalid or whose upstream is unreachable.",
                );
            }
            eprintln!("skipping: claude reached but refused: {msg}");
        }
        Err(other) => panic!("unexpected adapter error: {other:?}"),
    }
}

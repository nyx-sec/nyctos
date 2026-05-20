//! Claude Code adapter (`agent_loop`).
//!
//! Spawns the `claude` CLI as a subprocess so the rest of the agent
//! does not have to embed Anthropic's tool-use loop. The adapter
//! detects the binary on `PATH` at construction time and refuses to
//! run if it is missing; callers fall back to the Anthropic adapter
//! for `one_shot` work.
//!
//! Wire shape per the Phase-13 contract:
//! 1. Write `agent_task.md` into a per-task scratch directory.
//! 2. Invoke `claude --print --output-format stream-json --verbose` with
//!    the instruction file content piped on stdin (the public CLI does
//!    not currently expose a `--instruction-file` flag; the scratch
//!    file still lands on disk so traces stay auditable).
//! 3. Parse the NDJSON event stream into structured events,
//!    republishing tool-use blocks as `AiEvent::ToolCallStarted`/
//!    `Finished` on the shared event bus.
//! 4. Lift recognised tool calls into `ExtractedAgentResult` variants
//!    so downstream phases (PayloadSynthesis, SpecExtraction, ChainRanking,
//!    Exploration) consume a typed agent-loop result rather than re-parsing
//!    Claude Code's raw transcript.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use nyctos_types::agent::{
    classify_tool_use, AgentResult, AgentTask, AiError, Budget, CostEstimate, ExtractedAgentResult,
    HaltReason, Prompt, Response, TokenUsage,
};
use nyctos_types::event::{AgentEvent, AiEvent, EventSink};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::runtime::{AiRuntime, SharedBudgetTracker};

/// Preferred binary name. Falls back to `claude-code` when `claude` is
/// absent so operators who installed the older alias still work.
pub const DEFAULT_CLAUDE_BINARY: &str = "claude";
const FALLBACK_CLAUDE_BINARY: &str = "claude-code";

/// Path + version string captured at adapter-construction time. Surfaced
/// by `nyx-agent doctor` so operators can confirm which binary the
/// agent will spawn.
#[derive(Clone, Debug)]
pub struct ClaudeBinary {
    pub path: PathBuf,
    pub version: String,
}

/// Resolve the Claude Code binary on `PATH` and capture its
/// `--version` output. Returns `AiError::AdapterUnavailable` when no
/// candidate is found or the version probe fails.
pub async fn detect_claude_binary() -> Result<ClaudeBinary, AiError> {
    let path = which::which(DEFAULT_CLAUDE_BINARY)
        .or_else(|_| which::which(FALLBACK_CLAUDE_BINARY))
        .map_err(|_| {
            AiError::AdapterUnavailable(format!(
                "`{DEFAULT_CLAUDE_BINARY}` (or `{FALLBACK_CLAUDE_BINARY}`) not on PATH"
            ))
        })?;

    let output = Command::new(&path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            AiError::AdapterUnavailable(format!(
                "failed to invoke {} --version: {e}",
                path.display()
            ))
        })?;

    if !output.status.success() {
        return Err(AiError::AdapterUnavailable(format!(
            "{} --version exited {}: {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(ClaudeBinary { path, version })
}

/// Claude Code agent-loop adapter.
#[derive(Clone)]
pub struct ClaudeCodeAdapter {
    binary: ClaudeBinary,
    tracker: SharedBudgetTracker,
    default_model: String,
    /// Wall-clock cap on a single agent-loop invocation. Defaults to
    /// 15 minutes; operators can override via `with_timeout`.
    timeout: Duration,
}

impl ClaudeCodeAdapter {
    /// Build an adapter from a pre-detected binary. Callers typically
    /// run [`detect_claude_binary`] first and surface the result through
    /// the doctor, then construct one of these.
    pub fn new(binary: ClaudeBinary, tracker: SharedBudgetTracker) -> Self {
        Self {
            binary,
            tracker,
            default_model: "claude-opus-4-7".to_string(),
            timeout: Duration::from_secs(15 * 60),
        }
    }

    /// Convenience: detect + construct in one shot.
    pub async fn discover(tracker: SharedBudgetTracker) -> Result<Self, AiError> {
        let binary = detect_claude_binary().await?;
        Ok(Self::new(binary, tracker))
    }

    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = model.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn binary(&self) -> &ClaudeBinary {
        &self.binary
    }
}

#[async_trait]
impl AiRuntime for ClaudeCodeAdapter {
    fn name(&self) -> &'static str {
        "claude-code"
    }

    fn default_model(&self) -> &str {
        &self.default_model
    }

    fn supports_agent_loop(&self) -> bool {
        true
    }

    fn supports_prompt_cache(&self) -> bool {
        true
    }

    fn supports_deterministic_sampling(&self) -> bool {
        false
    }

    async fn one_shot(
        &self,
        _prompt: Prompt,
        _budget: Budget,
        _sink: EventSink,
    ) -> Result<Response, AiError> {
        Err(AiError::UnsupportedMode("one_shot"))
    }

    async fn agent_loop(
        &self,
        task: AgentTask,
        budget: Budget,
        sink: EventSink,
    ) -> Result<AgentResult, AiError> {
        // Pre-call budget check uses `>` to match the post-call check
        // below; cap is the spendable ceiling, not a hard refuse-when-equal.
        let spent_before = self.tracker.current_spend(&budget.run_id, budget.kind).await?;
        if let Some(cap) = self.tracker.cap(&budget.run_id, budget.kind).await? {
            if spent_before > cap {
                let _ = sink.send(AgentEvent::Ai {
                    data: AiEvent::TaskHalted {
                        task_id: task.task_id.clone(),
                        reason: HaltReason::BudgetCapReached,
                    },
                });
                return Err(AiError::BudgetExceeded {
                    cap_usd_micros: cap,
                    spent_usd_micros: spent_before,
                });
            }
        }

        let scratch = tempfile::Builder::new()
            .prefix("nyx-claude-task-")
            .tempdir()
            .map_err(|e| AiError::Transport(format!("scratch dir: {e}")))?;
        let task_path = scratch.path().join("agent_task.md");
        let task_body = render_task_markdown(&task);
        tokio::fs::write(&task_path, &task_body)
            .await
            .map_err(|e| AiError::Transport(format!("write agent_task.md: {e}")))?;

        let mut child = Command::new(&self.binary.path)
            .arg("--print")
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .arg("--max-turns")
            .arg(task.max_turns.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Drop stderr to /dev/null: nothing in this adapter reads it,
            // and `--verbose` can easily write more than the pipe buffer
            // holds (typically 64 KiB on Linux). A piped-but-undrained
            // stderr would block the child on write and deadlock the
            // agent loop.
            .stderr(Stdio::null())
            // Ensure SIGKILL fires and the child is reaped if a future error
            // path drops `child` before `wait().await` runs. The timeout arm
            // below calls `kill().await` (which reaps), but `kill_on_drop`
            // covers panic/early-return paths too.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| AiError::Transport(format!("spawn claude: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(task_body.as_bytes())
                .await
                .map_err(|e| AiError::Transport(format!("write stdin: {e}")))?;
            stdin.shutdown().await.map_err(|e| AiError::Transport(format!("close stdin: {e}")))?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AiError::Transport("claude stdout missing".to_string()))?;
        let mut reader = BufReader::new(stdout).lines();

        let mut turns: u32 = 0;
        let mut final_message = String::new();
        let mut extracted: Vec<ExtractedAgentResult> = Vec::new();
        let mut usage = TokenUsage { input_tokens: 0, output_tokens: 0 };
        let mut cost_usd_micros: i64 = 0;

        let read_loop = async {
            while let Some(line) = reader
                .next_line()
                .await
                .map_err(|e| AiError::Transport(format!("read stdout: {e}")))?
            {
                if line.trim().is_empty() {
                    continue;
                }
                let Some(event) = parse_stream_json(&line) else {
                    continue;
                };
                match event {
                    ClaudeEvent::Assistant(msg) => {
                        turns = turns.saturating_add(1);
                        for block in msg.content {
                            match block {
                                ContentBlock::Text { text } => {
                                    final_message.push_str(&text);
                                    let _ = sink.send(AgentEvent::Ai {
                                        data: AiEvent::TokenReceived {
                                            task_id: task.task_id.clone(),
                                            token: text,
                                        },
                                    });
                                }
                                ContentBlock::ToolUse { name, input, .. } => {
                                    let _ = sink.send(AgentEvent::Ai {
                                        data: AiEvent::ToolCallStarted {
                                            task_id: task.task_id.clone(),
                                            name: name.clone(),
                                        },
                                    });
                                    if let Some(result) = classify_tool_use(&name, &input) {
                                        extracted.push(result);
                                    }
                                    let _ = sink.send(AgentEvent::Ai {
                                        data: AiEvent::ToolCallFinished {
                                            task_id: task.task_id.clone(),
                                            name,
                                            ok: true,
                                        },
                                    });
                                }
                                ContentBlock::Other => {}
                            }
                        }
                    }
                    ClaudeEvent::Result(r) => {
                        if let Some(u) = r.usage {
                            usage.input_tokens =
                                usage.input_tokens.saturating_add(u.input_tokens.unwrap_or(0));
                            usage.output_tokens =
                                usage.output_tokens.saturating_add(u.output_tokens.unwrap_or(0));
                        }
                        if let Some(c) = r.total_cost_usd {
                            cost_usd_micros = (c * 1_000_000.0).round() as i64;
                        }
                        if let Some(text) = r.result {
                            if final_message.is_empty() {
                                final_message = text;
                            }
                        }
                    }
                    ClaudeEvent::Other => {}
                }
            }
            Ok::<(), AiError>(())
        };

        match tokio::time::timeout(self.timeout, read_loop).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = sink.send(AgentEvent::Ai {
                    data: AiEvent::TaskHalted {
                        task_id: task.task_id.clone(),
                        reason: HaltReason::OperatorCancelled,
                    },
                });
                return Err(AiError::Transport(format!(
                    "claude agent_loop timed out after {}s",
                    self.timeout.as_secs()
                )));
            }
        }

        let status =
            child.wait().await.map_err(|e| AiError::Transport(format!("wait claude: {e}")))?;
        if !status.success() {
            return Err(AiError::UpstreamRefused(format!("claude exited {status}")));
        }

        let spent_after =
            self.tracker.add_spend(&budget.run_id, budget.kind, cost_usd_micros).await?;
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::BudgetTick {
                task_id: task.task_id.clone(),
                run_id: budget.run_id.clone(),
                spent_usd_micros: spent_after,
            },
        });

        if let Some(cap) = self.tracker.cap(&budget.run_id, budget.kind).await? {
            if spent_after > cap {
                let _ = sink.send(AgentEvent::Ai {
                    data: AiEvent::TaskHalted {
                        task_id: task.task_id.clone(),
                        reason: HaltReason::BudgetCapReached,
                    },
                });
                return Err(AiError::BudgetExceeded {
                    cap_usd_micros: cap,
                    spent_usd_micros: spent_after,
                });
            }
        }

        Ok(AgentResult {
            prompt_version: task.prompt_version,
            task_id: task.task_id,
            final_message,
            turns,
            usage,
            cost_usd_micros,
            extracted,
        })
    }

    fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
        None
    }
}

fn render_task_markdown(task: &AgentTask) -> String {
    let tools_block = if task.tools.is_empty() {
        "(none; answer from context)".to_string()
    } else {
        task.tools.iter().map(|t| format!("- {t}")).collect::<Vec<_>>().join("\n")
    };
    format!(
        "# Agent task\n\
         \n\
         **prompt_version**: `{pv}`  \n\
         **task_id**: `{tid}`  \n\
         **max_turns**: {max_turns}\n\
         \n\
         ## System\n{system}\n\
         \n\
         ## Objective\n{objective}\n\
         \n\
         ## Tools available\n{tools}\n",
        pv = task.prompt_version,
        tid = task.task_id,
        max_turns = task.max_turns,
        system = task.system,
        objective = task.objective,
        tools = tools_block,
    )
}

/// Parse one NDJSON line from `claude --output-format stream-json` into
/// a typed event. Unknown shapes return `None` so callers can skip
/// gracefully across Claude Code CLI revisions.
pub fn parse_stream_json(line: &str) -> Option<ClaudeEvent> {
    let raw: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let kind = raw.get("type")?.as_str()?;
    match kind {
        "assistant" => {
            let msg = raw.get("message")?;
            let content_raw = msg.get("content").cloned().unwrap_or(serde_json::json!([]));
            let content: Vec<ContentBlock> = serde_json::from_value(content_raw).ok()?;
            Some(ClaudeEvent::Assistant(AssistantMessage { content }))
        }
        "result" => {
            let parsed: ResultPayload = serde_json::from_value(raw).ok()?;
            Some(ClaudeEvent::Result(parsed))
        }
        _ => Some(ClaudeEvent::Other),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaudeEvent {
    Assistant(AssistantMessage),
    Result(ResultPayload),
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssistantMessage {
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        #[serde(default)]
        id: String,
        name: String,
        #[serde(default)]
        input: serde_json::Value,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResultPayload {
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub total_cost_usd: Option<f64>,
    #[serde(default)]
    pub usage: Option<ResultUsage>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResultUsage {
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runtime::InMemoryBudgetTracker;
    use nyctos_types::agent::BudgetKind;
    use tokio::sync::broadcast;

    fn sample_task() -> AgentTask {
        AgentTask {
            prompt_version: "phase13.test.v1".to_string(),
            task_id: "task-claude-1".to_string(),
            system: "you are a static analysis exploration agent".to_string(),
            objective: "enumerate sinks in fixture.py".to_string(),
            tools: vec!["fs.read".to_string(), "record_payload".to_string()],
            max_turns: 3,
        }
    }

    fn budget(cap_usd_micros: i64) -> Budget {
        Budget { run_id: "run-claude-1".to_string(), kind: BudgetKind::AgentLoop, cap_usd_micros }
    }

    fn fake_binary() -> ClaudeBinary {
        ClaudeBinary { path: PathBuf::from("/usr/bin/false"), version: "0.0.0-test".to_string() }
    }

    #[test]
    fn capability_flags_match_phase13_contract() {
        let tracker = Arc::new(InMemoryBudgetTracker::new()) as SharedBudgetTracker;
        let adapter = ClaudeCodeAdapter::new(fake_binary(), tracker);
        assert_eq!(adapter.name(), "claude-code");
        assert!(adapter.supports_agent_loop());
        assert!(adapter.supports_prompt_cache());
        assert!(!adapter.supports_deterministic_sampling());
    }

    #[tokio::test]
    async fn one_shot_returns_unsupported_mode() {
        let tracker = Arc::new(InMemoryBudgetTracker::new()) as SharedBudgetTracker;
        let adapter = ClaudeCodeAdapter::new(fake_binary(), tracker);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(4);
        let prompt = Prompt {
            prompt_version: "v1".to_string(),
            task_id: "t".to_string(),
            model: None,
            system: "s".to_string(),
            user: "u".to_string(),
            max_output_tokens: 8,
            temperature: 0.0,
            seed: None,
        };
        let err = adapter
            .one_shot(prompt, budget(0), tx)
            .await
            .expect_err("one_shot must be unsupported");
        assert!(matches!(err, AiError::UnsupportedMode("one_shot")));
    }

    #[tokio::test]
    async fn detect_returns_adapter_unavailable_when_binary_missing() {
        // Clear PATH so `which` fails deterministically.
        let prior = std::env::var_os("PATH");
        // SAFETY: tests run single-threaded under tokio::test; the env
        // mutation is reset before the test returns.
        unsafe {
            std::env::set_var("PATH", "");
        }
        let result = detect_claude_binary().await;
        if let Some(p) = prior {
            unsafe {
                std::env::set_var("PATH", p);
            }
        } else {
            unsafe {
                std::env::remove_var("PATH");
            }
        }
        assert!(matches!(result, Err(AiError::AdapterUnavailable(_))));
    }

    #[test]
    fn parse_stream_json_lifts_text_blocks() {
        let line = serde_json::json!({
            "type": "assistant",
            "message": {
                "content": [
                    { "type": "text", "text": "scanning fixture.py" }
                ]
            }
        })
        .to_string();
        let ev = parse_stream_json(&line).expect("parsed");
        match ev {
            ClaudeEvent::Assistant(a) => {
                assert_eq!(a.content.len(), 1);
                assert!(matches!(
                    a.content[0],
                    ContentBlock::Text { ref text } if text == "scanning fixture.py"
                ));
            }
            other => panic!("expected Assistant, got {other:?}"),
        }
    }

    #[test]
    fn parse_stream_json_lifts_tool_use_block() {
        let line = serde_json::json!({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "record_payload",
                        "input": { "rule_id": "py.cmdi.os_system", "body": "ls -la; #" }
                    }
                ]
            }
        })
        .to_string();
        let ev = parse_stream_json(&line).expect("parsed");
        let ClaudeEvent::Assistant(a) = ev else { panic!("expected Assistant") };
        let block = a.content.into_iter().next().expect("one block");
        let ContentBlock::ToolUse { name, input, .. } = block else { panic!("expected ToolUse") };
        assert_eq!(name, "record_payload");
        let extracted = classify_tool_use(&name, &input).expect("extract");
        assert!(matches!(
            extracted,
            ExtractedAgentResult::PayloadFound { ref rule_id, ref body }
                if rule_id == "py.cmdi.os_system" && body == "ls -la; #"
        ));
    }

    #[test]
    fn parse_stream_json_lifts_result_event() {
        let line = serde_json::json!({
            "type": "result",
            "subtype": "success",
            "result": "done",
            "total_cost_usd": 0.0125,
            "usage": { "input_tokens": 100, "output_tokens": 50 }
        })
        .to_string();
        let ev = parse_stream_json(&line).expect("parsed");
        let ClaudeEvent::Result(r) = ev else { panic!("expected Result") };
        assert_eq!(r.result.as_deref(), Some("done"));
        assert!((r.total_cost_usd.unwrap() - 0.0125).abs() < f64::EPSILON);
        assert_eq!(r.usage.unwrap().input_tokens, Some(100));
    }

    #[test]
    fn classify_tool_use_falls_back_to_exploration_event() {
        let input = serde_json::json!({ "path": "src/main.rs" });
        let ev = classify_tool_use("fs.read", &input).expect("extracted");
        match ev {
            ExtractedAgentResult::ExplorationEvent { message } => {
                assert!(message.starts_with("tool fs.read"));
            }
            other => panic!("expected ExplorationEvent, got {other:?}"),
        }
    }

    #[test]
    fn classify_tool_use_records_spec_and_chains() {
        let spec_input = serde_json::json!({
            "capability": "fs.write",
            "spec": "writes to /tmp"
        });
        let ev = classify_tool_use("record_spec", &spec_input).expect("extracted");
        assert!(matches!(
            ev,
            ExtractedAgentResult::SpecFound { ref capability, ref spec }
                if capability == "fs.write" && spec == "writes to /tmp"
        ));

        let chain_input = serde_json::json!({
            "chain_ids": ["c1", "c2"],
            "rationale": "shorter sink reachability"
        });
        let ev = classify_tool_use("record_chains", &chain_input).expect("extracted");
        assert!(matches!(
            ev,
            ExtractedAgentResult::ChainsRanked { ref chain_ids, .. }
                if chain_ids == &vec!["c1".to_string(), "c2".to_string()]
        ));
    }

    #[test]
    fn classify_tool_use_records_exploration_finding() {
        let input = serde_json::json!({
            "path": "<api:/api/admin/orders>",
            "line": 42,
            "cap": "AUTH_BYPASS",
            "rationale": "GET admin endpoint accepts unauthenticated requests",
            "endpoint": "GET /api/admin/orders",
            "suggested_payload_hint": "curl -i http://127.0.0.1:3000/api/admin/orders",
        });
        let ev = classify_tool_use("record_exploration_finding", &input).expect("extracted");
        assert!(matches!(
            ev,
            ExtractedAgentResult::ExplorationFinding {
                ref path, line: Some(42), ref cap, ref endpoint, ..
            } if path == "<api:/api/admin/orders>"
                && cap == "AUTH_BYPASS"
                && endpoint.as_deref() == Some("GET /api/admin/orders")
        ));
        // Empty required fields fall back to None (gating against
        // malformed tool-use blocks).
        let bad = serde_json::json!({ "path": "", "cap": "X", "rationale": "y" });
        assert!(classify_tool_use("record_exploration_finding", &bad).is_none());
    }

    #[test]
    fn render_task_markdown_includes_all_fields() {
        let md = render_task_markdown(&sample_task());
        assert!(md.contains("phase13.test.v1"));
        assert!(md.contains("task-claude-1"));
        assert!(md.contains("enumerate sinks"));
        assert!(md.contains("- fs.read"));
        assert!(md.contains("- record_payload"));
    }
}

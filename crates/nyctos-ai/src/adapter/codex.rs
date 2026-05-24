//! Codex CLI adapter.
//!
//! Spawns `codex exec` non-interactively and consumes its JSONL event
//! stream. This is intentionally a CLI backend, not an OpenAI API-key
//! backend: authentication, provider selection, and model defaults stay
//! owned by the installed Codex CLI.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use nyctos_types::agent::{
    classify_tool_use, AgentResult, AgentTask, AiError, Budget, CacheStats, CostEstimate,
    ExtractedAgentResult, HaltReason, Prompt, Response, TokenUsage,
};
use nyctos_types::event::{AgentEvent, AiEvent, EventSink};
use semver::Version;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, Command};
use tokio::task::JoinHandle;

use crate::runtime::{AiRuntime, SharedBudgetTracker};

pub const DEFAULT_CODEX_BINARY: &str = "codex";
pub const MINIMUM_CODEX_VERSION: &str = "0.133.0-alpha.1";

const CODEX_DEFAULT_MODEL_LABEL: &str = "codex-cli-default";
const MAX_STDERR_CAPTURE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct CodexBinary {
    pub path: PathBuf,
    pub version: String,
}

pub async fn detect_codex_binary() -> Result<CodexBinary, AiError> {
    let path = which::which(DEFAULT_CODEX_BINARY).map_err(|_| {
        AiError::AdapterUnavailable(format!("`{DEFAULT_CODEX_BINARY}` not on PATH"))
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
    let parsed = parse_codex_version(&version).ok_or_else(|| {
        AiError::AdapterUnavailable(format!(
            "codex version output `{version}` could not be parsed as semver"
        ))
    })?;
    let floor = Version::parse(MINIMUM_CODEX_VERSION).expect("built-in floor parses");
    if parsed < floor {
        return Err(AiError::AdapterUnavailable(format!(
            "codex-cli v{parsed} below required minimum v{floor}"
        )));
    }

    Ok(CodexBinary { path, version })
}

pub fn parse_codex_version(raw: &str) -> Option<Version> {
    raw.split_whitespace().find_map(|token| Version::parse(token).ok())
}

#[derive(Clone)]
pub struct CodexCliAdapter {
    binary: CodexBinary,
    tracker: SharedBudgetTracker,
    default_model: String,
    timeout: Duration,
}

impl CodexCliAdapter {
    pub fn new(binary: CodexBinary, tracker: SharedBudgetTracker) -> Self {
        Self {
            binary,
            tracker,
            default_model: CODEX_DEFAULT_MODEL_LABEL.to_string(),
            timeout: Duration::from_secs(15 * 60),
        }
    }

    pub async fn discover(tracker: SharedBudgetTracker) -> Result<Self, AiError> {
        let binary = detect_codex_binary().await?;
        Ok(Self::new(binary, tracker))
    }

    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        let model = model.into();
        if !model.trim().is_empty() {
            self.default_model = model;
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn binary(&self) -> &CodexBinary {
        &self.binary
    }

    fn model_for_prompt(&self, prompt_model: Option<&String>) -> Option<String> {
        prompt_model.cloned().or_else(|| {
            if self.default_model == CODEX_DEFAULT_MODEL_LABEL {
                None
            } else {
                Some(self.default_model.clone())
            }
        })
    }

    async fn run_exec(
        &self,
        prompt_body: &str,
        model: Option<&str>,
        working_directory: Option<&str>,
    ) -> Result<CodexRun, AiError> {
        let mut cmd = Command::new(&self.binary.path);
        cmd.arg("exec")
            .arg("--json")
            .arg("--color")
            .arg("never")
            .arg("--ephemeral")
            .arg("--skip-git-repo-check")
            // TODO(release-hardening): make this opt-in/configured before
            // shipping beyond local testing.
            .arg("--dangerously-bypass-approvals-and-sandbox");
        if let Some(model) = model.filter(|m| !m.trim().is_empty()) {
            cmd.arg("--model").arg(model);
        }
        if let Some(dir) = working_directory.filter(|d| !d.trim().is_empty()) {
            cmd.current_dir(dir);
        }
        cmd.arg("-");

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| AiError::Transport(format!("spawn codex: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(prompt_body.as_bytes())
                .await
                .map_err(|e| AiError::Transport(format!("write stdin: {e}")))?;
            stdin.shutdown().await.map_err(|e| AiError::Transport(format!("close stdin: {e}")))?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AiError::Transport("codex stdout missing".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AiError::Transport("codex stderr missing".to_string()))?;
        let stderr_handle = spawn_stderr_drain(stderr);
        let mut reader = BufReader::new(stdout).lines();
        let mut run = CodexRun::default();

        let read_loop = async {
            while let Some(line) = reader
                .next_line()
                .await
                .map_err(|e| AiError::Transport(format!("read stdout: {e}")))?
            {
                if line.trim().is_empty() {
                    continue;
                }
                let Some(event) = parse_codex_jsonl(&line) else {
                    continue;
                };
                run.apply(event);
            }
            Ok::<(), AiError>(())
        };

        match tokio::time::timeout(self.timeout, read_loop).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                let stderr_text = await_stderr_drain(stderr_handle).await;
                return Err(annotate_with_stderr(e, &stderr_text));
            }
            Err(_) => {
                let _ = child.kill().await;
                let stderr_text = await_stderr_drain(stderr_handle).await;
                let base = format!("codex exec timed out after {}s", self.timeout.as_secs());
                return Err(AiError::Transport(append_stderr(&base, &stderr_text)));
            }
        }

        let status =
            child.wait().await.map_err(|e| AiError::Transport(format!("wait codex: {e}")))?;
        if !status.success() {
            let stderr_text = await_stderr_drain(stderr_handle).await;
            let base = format!("codex exited {status}");
            return Err(AiError::UpstreamRefused(append_stderr(&base, &stderr_text)));
        }
        drop(stderr_handle);

        Ok(run)
    }
}

#[async_trait]
impl AiRuntime for CodexCliAdapter {
    fn name(&self) -> &'static str {
        "codex"
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
        prompt: Prompt,
        budget: Budget,
        sink: EventSink,
    ) -> Result<Response, AiError> {
        let model = self.model_for_prompt(prompt.model.as_ref());
        let spent_before = self.tracker.current_spend(&budget.run_id, budget.kind).await?;
        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
        if spent_before > cap {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TaskHalted {
                    task_id: prompt.task_id.clone(),
                    reason: HaltReason::BudgetCapReached,
                },
            });
            return Err(AiError::BudgetExceeded {
                cap_usd_micros: cap,
                spent_usd_micros: spent_before,
            });
        }

        let run = self.run_exec(&render_one_shot_prompt(&prompt), model.as_deref(), None).await?;
        for text in &run.messages {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TokenReceived {
                    task_id: prompt.task_id.clone(),
                    token: text.clone(),
                },
            });
        }
        if run.cache.cache_read_tokens > 0 {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::CacheHit {
                    task_id: prompt.task_id.clone(),
                    tokens: run.cache.cache_read_tokens,
                },
            });
        }

        let spent_after =
            self.tracker.add_spend(&budget.run_id, budget.kind, run.cost_usd_micros).await?;
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::BudgetTick {
                task_id: prompt.task_id.clone(),
                run_id: budget.run_id.clone(),
                spent_usd_micros: spent_after,
            },
        });

        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
        if spent_after > cap {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TaskHalted {
                    task_id: prompt.task_id.clone(),
                    reason: HaltReason::BudgetCapReached,
                },
            });
            return Err(AiError::BudgetExceeded {
                cap_usd_micros: cap,
                spent_usd_micros: spent_after,
            });
        }

        Ok(Response {
            prompt_version: prompt.prompt_version,
            task_id: prompt.task_id,
            model: run.model.or(model).unwrap_or_else(|| self.default_model.clone()),
            content: run.messages.join(""),
            usage: run.usage,
            cache: Some(run.cache),
            cost_usd_micros: run.cost_usd_micros,
        })
    }

    async fn agent_loop(
        &self,
        task: AgentTask,
        budget: Budget,
        sink: EventSink,
    ) -> Result<AgentResult, AiError> {
        let spent_before = self.tracker.current_spend(&budget.run_id, budget.kind).await?;
        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
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

        let run = self
            .run_exec(&render_agent_prompt(&task), None, task.working_directory.as_deref())
            .await?;
        for text in &run.messages {
            let _ = sink.send(AgentEvent::Ai {
                data: AiEvent::TokenReceived { task_id: task.task_id.clone(), token: text.clone() },
            });
        }
        let final_message = run.messages.join("");
        let mut extracted = run.extracted;
        extracted.extend(extract_tool_markers_from_text(&final_message));

        let spent_after =
            self.tracker.add_spend(&budget.run_id, budget.kind, run.cost_usd_micros).await?;
        let _ = sink.send(AgentEvent::Ai {
            data: AiEvent::BudgetTick {
                task_id: task.task_id.clone(),
                run_id: budget.run_id.clone(),
                spent_usd_micros: spent_after,
            },
        });
        let tracker_cap = self.tracker.cap(&budget.run_id, budget.kind).await?;
        let cap = effective_cap(tracker_cap, budget.cap_usd_micros);
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

        Ok(AgentResult {
            prompt_version: task.prompt_version,
            task_id: task.task_id,
            model: run.model.unwrap_or_else(|| self.default_model.clone()),
            final_message,
            turns: run.turns,
            usage: run.usage,
            cache: Some(run.cache),
            cost_usd_micros: run.cost_usd_micros,
            extracted,
        })
    }

    fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
        None
    }
}

fn render_one_shot_prompt(prompt: &Prompt) -> String {
    format!(
        "# Nyctos one-shot task\n\
         \n\
         prompt_version: {pv}\n\
         task_id: {tid}\n\
         max_output_tokens: {max_tokens}\n\
         temperature: {temperature}\n\
         \n\
         Return the requested content only. Preserve any JSON contract from the system prompt; \
         do not add explanation, Markdown fences, or surrounding prose unless the prompt explicitly \
         asks for them.\n\
         \n\
         ## System\n{system}\n\
         \n\
         ## User\n{user}\n",
        pv = prompt.prompt_version,
        tid = prompt.task_id,
        max_tokens = prompt.max_output_tokens,
        temperature = prompt.temperature,
        system = prompt.system,
        user = prompt.user,
    )
}

fn render_agent_prompt(task: &AgentTask) -> String {
    let tools_block = if task.tools.is_empty() {
        "(none; answer from context)".to_string()
    } else {
        task.tools.iter().map(|t| format!("- {t}")).collect::<Vec<_>>().join("\n")
    };
    format!(
        "# Nyctos agent task\n\
         \n\
         prompt_version: {pv}\n\
         task_id: {tid}\n\
         working_directory: {working_directory}\n\
         max_turns: {max_turns}\n\
         \n\
         ## System\n{system}\n\
         \n\
         ## Objective\n{objective}\n\
         \n\
         ## Tools available\n{tools}\n\
         \n\
         When you need to record a structured Nyctos artifact, emit a JSON object on its own line \
         using this shape: {{\"tool\":\"<listed tool name>\",\"input\":{{...}}}}. \
         Use one of the listed `record_*` tool names as the `tool` value and place its arguments \
         in `input`.\n",
        pv = task.prompt_version,
        tid = task.task_id,
        working_directory =
            task.working_directory.as_deref().unwrap_or("(adapter current directory)"),
        max_turns = task.max_turns,
        system = task.system,
        objective = task.objective,
        tools = tools_block,
    )
}

fn effective_cap(tracker_cap: Option<i64>, envelope_cap: i64) -> i64 {
    match tracker_cap {
        Some(t) => t.min(envelope_cap),
        None => envelope_cap,
    }
}

fn spawn_stderr_drain(mut stderr: ChildStderr) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > MAX_STDERR_CAPTURE_BYTES {
                        let drop_n = buf.len() - MAX_STDERR_CAPTURE_BYTES;
                        buf.drain(..drop_n);
                    }
                }
                Err(_) => break,
            }
        }
        buf
    })
}

async fn await_stderr_drain(handle: JoinHandle<Vec<u8>>) -> String {
    let bytes = match tokio::time::timeout(Duration::from_secs(1), handle).await {
        Ok(Ok(b)) => b,
        _ => return String::new(),
    };
    String::from_utf8_lossy(&bytes).trim().to_string()
}

fn append_stderr(base: &str, stderr_text: &str) -> String {
    if stderr_text.is_empty() {
        base.to_string()
    } else {
        format!("{base}: stderr: {stderr_text}")
    }
}

fn annotate_with_stderr(err: AiError, stderr_text: &str) -> AiError {
    if stderr_text.is_empty() {
        return err;
    }
    match err {
        AiError::Transport(msg) => AiError::Transport(append_stderr(&msg, stderr_text)),
        AiError::UpstreamRefused(msg) => AiError::UpstreamRefused(append_stderr(&msg, stderr_text)),
        other => other,
    }
}

#[derive(Default)]
struct CodexRun {
    messages: Vec<String>,
    usage: TokenUsage,
    cache: CacheStats,
    cost_usd_micros: i64,
    model: Option<String>,
    turns: u32,
    extracted: Vec<ExtractedAgentResult>,
}

impl CodexRun {
    fn apply(&mut self, event: CodexEvent) {
        match event {
            CodexEvent::AgentMessage(text) => self.messages.push(text),
            CodexEvent::ToolCall { name, input } => {
                if let Some(result) = classify_tool_use(&name, &input) {
                    self.extracted.push(result);
                }
            }
            CodexEvent::TurnCompleted { usage, model, cost_usd } => {
                self.turns = self.turns.saturating_add(1);
                self.usage.input_tokens =
                    self.usage.input_tokens.saturating_add(usage.input_tokens.unwrap_or(0));
                self.usage.output_tokens =
                    self.usage.output_tokens.saturating_add(usage.output_tokens.unwrap_or(0));
                self.cache.cache_read_tokens = self
                    .cache
                    .cache_read_tokens
                    .saturating_add(usage.cached_input_tokens.unwrap_or(0));
                if let Some(model) = model {
                    self.model = Some(model);
                }
                if let Some(cost) = cost_usd {
                    self.cost_usd_micros = (cost * 1_000_000.0).round() as i64;
                }
            }
            CodexEvent::Other => {}
        }
    }
}

pub fn parse_codex_jsonl(line: &str) -> Option<CodexEvent> {
    let raw: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let kind = raw.get("type")?.as_str()?;
    match kind {
        "item.completed" => parse_item_completed(raw.get("item")?),
        "turn.completed" => {
            let usage: CodexUsage =
                serde_json::from_value(raw.get("usage").cloned().unwrap_or_default()).ok()?;
            let model = raw.get("model").and_then(|v| v.as_str()).map(str::to_string);
            let cost_usd =
                raw.get("total_cost_usd").or_else(|| raw.get("cost_usd")).and_then(|v| v.as_f64());
            Some(CodexEvent::TurnCompleted { usage, model, cost_usd })
        }
        _ => Some(CodexEvent::Other),
    }
}

fn parse_item_completed(item: &serde_json::Value) -> Option<CodexEvent> {
    match item.get("type")?.as_str()? {
        "agent_message" => item
            .get("text")
            .and_then(|v| v.as_str())
            .map(|text| CodexEvent::AgentMessage(text.to_string())),
        "tool_call" | "function_call" => {
            let name = item.get("name")?.as_str()?.to_string();
            let input = item
                .get("input")
                .or_else(|| item.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            Some(CodexEvent::ToolCall { name, input: coerce_arguments(input) })
        }
        _ => Some(CodexEvent::Other),
    }
}

fn coerce_arguments(input: serde_json::Value) -> serde_json::Value {
    match input {
        serde_json::Value::String(s) => {
            serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
        }
        other => other,
    }
}

fn extract_tool_markers_from_text(text: &str) -> Vec<ExtractedAgentResult> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        extract_tool_marker_value(&value, &mut out);
    }
    out
}

fn extract_tool_marker_value(value: &serde_json::Value, out: &mut Vec<ExtractedAgentResult>) {
    if let Some(calls) = value.get("tool_calls").and_then(|v| v.as_array()) {
        for call in calls {
            extract_tool_marker_value(call, out);
        }
        return;
    }
    let Some(name) = value.get("tool").or_else(|| value.get("name")).and_then(|v| v.as_str())
    else {
        return;
    };
    let input = value.get("input").cloned().unwrap_or_else(|| serde_json::json!({}));
    if let Some(result) = classify_tool_use(name, &input) {
        out.push(result);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodexEvent {
    AgentMessage(String),
    ToolCall { name: String, input: serde_json::Value },
    TurnCompleted { usage: CodexUsage, model: Option<String>, cost_usd: Option<f64> },
    Other,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct CodexUsage {
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub cached_input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
    #[serde(default)]
    pub reasoning_output_tokens: Option<u32>,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tokio::sync::broadcast;

    use super::*;
    use crate::runtime::InMemoryBudgetTracker;
    use nyctos_types::agent::BudgetKind;

    fn fake_cli_script(body: &str) -> (tempfile::TempDir, CodexBinary) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("codex");
        std::fs::write(&path, body).expect("write fake codex");
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
        }
        let binary = CodexBinary { path, version: "codex-cli 0.133.0-alpha.1-test".to_string() };
        (dir, binary)
    }

    fn sample_prompt() -> Prompt {
        Prompt {
            prompt_version: "v1".to_string(),
            task_id: "codex-one-shot".to_string(),
            model: None,
            system: "Return JSON.".to_string(),
            user: "Say ok.".to_string(),
            max_output_tokens: 32,
            temperature: 0.0,
            seed: None,
        }
    }

    fn budget(kind: BudgetKind, cap_usd_micros: i64) -> Budget {
        Budget { run_id: "run-codex-1".to_string(), kind, cap_usd_micros }
    }

    #[test]
    fn parse_codex_version_accepts_prefixed_cli_output() {
        let v = parse_codex_version("codex-cli 0.133.0-alpha.1").expect("version");
        assert_eq!(v, Version::parse("0.133.0-alpha.1").unwrap());
    }

    #[test]
    fn parse_jsonl_lifts_observed_agent_message_shape() {
        let line = r#"{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}"#;
        let event = parse_codex_jsonl(line).expect("event");
        assert_eq!(event, CodexEvent::AgentMessage("OK".to_string()));
    }

    #[test]
    fn parse_jsonl_lifts_turn_usage_shape() {
        let line = r#"{"type":"turn.completed","usage":{"input_tokens":12179,"cached_input_tokens":9600,"output_tokens":17,"reasoning_output_tokens":10}}"#;
        let event = parse_codex_jsonl(line).expect("event");
        let CodexEvent::TurnCompleted { usage, .. } = event else {
            panic!("expected turn.completed");
        };
        assert_eq!(usage.input_tokens, Some(12179));
        assert_eq!(usage.cached_input_tokens, Some(9600));
        assert_eq!(usage.output_tokens, Some(17));
    }

    #[tokio::test]
    async fn one_shot_parses_jsonl_and_records_budget() {
        let script = r#"#!/bin/sh
cat >/dev/null
printf '%s\n' '{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"{\"ok\":true}"}}'
printf '%s\n' '{"type":"turn.completed","model":"gpt-5.5","usage":{"input_tokens":12,"cached_input_tokens":3,"output_tokens":4},"total_cost_usd":0.000321}'
"#;
        let (_dir, binary) = fake_cli_script(script);
        let tracker = Arc::new(InMemoryBudgetTracker::new());
        let adapter = CodexCliAdapter::new(binary, tracker.clone() as SharedBudgetTracker);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(4);

        let resp = adapter
            .one_shot(sample_prompt(), budget(BudgetKind::OneShot, 10_000), tx)
            .await
            .expect("one_shot");

        assert_eq!(resp.content, "{\"ok\":true}");
        assert_eq!(resp.model, "gpt-5.5");
        assert_eq!(resp.usage.input_tokens, 12);
        assert_eq!(resp.cache.unwrap().cache_read_tokens, 3);
        assert_eq!(resp.cost_usd_micros, 321);
        assert_eq!(tracker.spent("run-codex-1", BudgetKind::OneShot), 321);
    }

    #[tokio::test]
    async fn agent_loop_extracts_json_tool_markers_from_final_message() {
        let script = r#"#!/bin/sh
cat >/dev/null
printf '%s\n' '{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"{\"tool\":\"record_exploration_finding\",\"input\":{\"path\":\"src/main.rs\",\"cap\":\"http\",\"rationale\":\"shadow endpoint\"}}\nDone"}}'
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'
"#;
        let (_dir, binary) = fake_cli_script(script);
        let tracker = Arc::new(InMemoryBudgetTracker::new()) as SharedBudgetTracker;
        let adapter = CodexCliAdapter::new(binary, tracker);
        let (tx, _rx) = broadcast::channel::<AgentEvent>(4);
        let task = AgentTask {
            prompt_version: "explore.v1".to_string(),
            task_id: "explore".to_string(),
            system: "s".to_string(),
            objective: "o".to_string(),
            tools: vec!["record_exploration_finding".to_string()],
            working_directory: None,
            max_turns: 1,
        };

        let result = adapter
            .agent_loop(task, budget(BudgetKind::AgentLoop, 10_000), tx)
            .await
            .expect("agent_loop");

        assert!(matches!(
            result.extracted.as_slice(),
            [ExtractedAgentResult::ExplorationFinding { path, cap, .. }]
                if path == "src/main.rs" && cap == "http"
        ));
    }
}

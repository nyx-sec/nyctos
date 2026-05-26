use std::io::IsTerminal;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nyx_agent_ai::AiRuntime;
use nyx_agent_types::agent::{
    AgentResult, AgentTask, AiError, Budget, CostEstimate, Prompt, Response,
};
use nyx_agent_types::event::EventSink;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_GREEN: &str = "\x1b[38;2;46;160;103m";
const ANSI_RED: &str = "\x1b[38;2;220;76;76m";
const ANSI_BLUE: &str = "\x1b[38;2;88;166;255m";
const ANSI_MUTED: &str = "\x1b[38;2;159;163;173m";

static PRINT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn wrap_runtime<R>(runtime: R) -> Arc<dyn AiRuntime>
where
    R: AiRuntime + 'static,
{
    Arc::new(TerminalAiRuntime { inner: Arc::new(runtime) })
}

struct TerminalAiRuntime {
    inner: Arc<dyn AiRuntime>,
}

#[async_trait]
impl AiRuntime for TerminalAiRuntime {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn default_model(&self) -> &str {
        self.inner.default_model()
    }

    fn supports_agent_loop(&self) -> bool {
        self.inner.supports_agent_loop()
    }

    fn supports_prompt_cache(&self) -> bool {
        self.inner.supports_prompt_cache()
    }

    fn supports_deterministic_sampling(&self) -> bool {
        self.inner.supports_deterministic_sampling()
    }

    async fn one_shot(
        &self,
        prompt: Prompt,
        budget: Budget,
        sink: EventSink,
    ) -> Result<Response, AiError> {
        let task_id = prompt.task_id.clone();
        let label = task_label(&task_id, &prompt.prompt_version);
        let model = prompt.model.clone().unwrap_or_else(|| self.default_model().to_string());
        print_agent_started("one-shot", self.name(), &model, &label);
        let started = Instant::now();
        let result = self.inner.one_shot(prompt, budget, sink).await;
        match &result {
            Ok(response) => print_agent_finished(
                "one-shot",
                self.name(),
                &label,
                started.elapsed(),
                response.cost_usd_micros,
            ),
            Err(err) => print_agent_error("one-shot", self.name(), &label, started.elapsed(), err),
        }
        result
    }

    async fn agent_loop(
        &self,
        task: AgentTask,
        budget: Budget,
        sink: EventSink,
    ) -> Result<AgentResult, AiError> {
        let task_id = task.task_id.clone();
        let label = task_label(&task_id, &task.prompt_version);
        let model = self.default_model().to_string();
        print_agent_started("agent-loop", self.name(), &model, &label);
        let started = Instant::now();
        let result = self.inner.agent_loop(task, budget, sink).await;
        match &result {
            Ok(result) => print_agent_finished(
                "agent-loop",
                self.name(),
                &label,
                started.elapsed(),
                result.cost_usd_micros,
            ),
            Err(err) => {
                print_agent_error("agent-loop", self.name(), &label, started.elapsed(), err)
            }
        }
        result
    }

    fn cost_estimate(&self, prompt: &Prompt) -> Option<CostEstimate> {
        self.inner.cost_estimate(prompt)
    }
}

fn print_agent_started(mode: &str, runtime: &str, model: &str, label: &str) {
    let color = should_colorize_stdout();
    let header = paint(color, ANSI_BLUE, "agent started");
    let detail = paint(color, ANSI_MUTED, &format!("{mode} · {runtime} · {model}"));
    print_box("╭", "├", "╰", &header, label, &detail);
}

fn print_agent_finished(mode: &str, runtime: &str, label: &str, elapsed: Duration, cost: i64) {
    let color = should_colorize_stdout();
    let header = paint(color, ANSI_GREEN, "agent finished");
    let detail = paint(
        color,
        ANSI_MUTED,
        &format!("{mode} · {runtime} · {} · {}", format_elapsed(elapsed), format_cost(cost)),
    );
    print_box("╭", "├", "╰", &header, label, &detail);
}

fn print_agent_error(mode: &str, runtime: &str, label: &str, elapsed: Duration, err: &AiError) {
    let color = should_colorize_stdout();
    let header = paint(color, ANSI_RED, "agent error");
    let detail = paint(
        color,
        ANSI_MUTED,
        &format!("{mode} · {runtime} · {} · {}", format_elapsed(elapsed), one_line_error(err)),
    );
    print_box("╭", "├", "╰", &header, label, &detail);
}

fn print_box(top: &str, mid: &str, bottom: &str, header: &str, label: &str, detail: &str) {
    let lock = PRINT_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("terminal print lock poisoned");
    println!("{top}─ {header} {label}");
    println!("{mid}─ {detail}");
    println!("{bottom}─");
}

fn task_label(task_id: &str, prompt_version: &str) -> String {
    if task_id.trim().is_empty() {
        prompt_version.to_string()
    } else {
        task_id.to_string()
    }
}

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}{ANSI_RESET}")
    } else {
        text.to_string()
    }
}

fn should_colorize_stdout() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|value| value == "0") {
        return false;
    }
    !std::env::var("TERM").is_ok_and(|value| value == "dumb")
}

fn format_elapsed(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    }
}

fn format_cost(usd_micros: i64) -> String {
    if usd_micros <= 0 {
        "$0".to_string()
    } else if usd_micros < 10_000 {
        format!("${:.5}", usd_micros as f64 / 1_000_000.0)
    } else {
        format!("${:.4}", usd_micros as f64 / 1_000_000.0)
    }
}

fn one_line_error(err: &AiError) -> String {
    let mut out = err.to_string().replace('\n', " ");
    if out.len() > 180 {
        out.truncate(177);
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_formats_ms_and_seconds() {
        assert_eq!(format_elapsed(Duration::from_millis(42)), "42ms");
        assert_eq!(format_elapsed(Duration::from_millis(1_250)), "1.2s");
    }

    #[test]
    fn cost_formats_usd_micros() {
        assert_eq!(format_cost(0), "$0");
        assert_eq!(format_cost(1_234), "$0.00123");
        assert_eq!(format_cost(123_456), "$0.1235");
    }
}

//! Local repository remediation agent.
//!
//! The task gives a CLI-backed agent the verified vulnerability context
//! and writable workspace roots. The agent may edit files locally, but
//! must not stage, commit, push, or open a PR; the operator reviews the
//! resulting working tree and decides what to keep.

use nyctos_types::agent::{AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind};
use nyctos_types::event::EventSink;
use nyctos_types::product::VerifiedVulnerabilityRecord;

use crate::runtime::AiRuntime;

pub const REMEDIATION_PROMPT_VERSION: &str = "phase-pre-mvp.remediation-agent.v1";
pub const DEFAULT_REMEDIATION_MAX_TURNS: u32 = 60;
pub const DEFAULT_REMEDIATION_RUN_CAP_USD_MICROS: i64 = 2_000_000;

const REMEDIATION_TOOL_NAMES: &[&str] = &["Read", "Grep", "Bash", "Edit", "Write"];

#[derive(Debug, Clone)]
pub struct RemediationScope {
    pub task_id: String,
    pub vulnerability: VerifiedVulnerabilityRecord,
    pub workspace_roots: Vec<String>,
    pub max_turns: u32,
    pub run_cap_usd_micros: i64,
}

impl RemediationScope {
    pub fn new(vulnerability: VerifiedVulnerabilityRecord) -> Self {
        let task_id = format!("remediation-{}", vulnerability.id);
        Self {
            task_id,
            vulnerability,
            workspace_roots: Vec::new(),
            max_turns: DEFAULT_REMEDIATION_MAX_TURNS,
            run_cap_usd_micros: DEFAULT_REMEDIATION_RUN_CAP_USD_MICROS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationOutcome {
    pub summary: String,
    pub final_message: String,
    pub turns: u32,
    pub spent_usd_micros: i64,
    pub metrics: AgentTraceMetrics,
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &RemediationScope,
    sink: EventSink,
) -> Result<RemediationOutcome, AiError> {
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.vulnerability.run_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };
    let result = runtime.agent_loop(task, budget, sink).await?;
    let metrics = AgentTraceMetrics::from_agent_result(&result);
    let final_message = result.final_message.trim().to_string();
    Ok(RemediationOutcome {
        summary: summarize_final_message(&final_message),
        final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        metrics,
    })
}

fn build_agent_task(scope: &RemediationScope) -> AgentTask {
    AgentTask {
        prompt_version: REMEDIATION_PROMPT_VERSION.to_string(),
        task_id: scope.task_id.clone(),
        system: remediation_system_prompt(),
        objective: render_objective(scope),
        tools: REMEDIATION_TOOL_NAMES.iter().map(|tool| tool.to_string()).collect(),
        working_directory: scope.workspace_roots.first().cloned(),
        max_turns: scope.max_turns,
    }
}

fn remediation_system_prompt() -> String {
    r#"You are the Nyctos local remediation agent.

Your job is to make a minimal, reviewable local code change that fixes one verified vulnerability.

Rules:
- Edit only files inside the supplied workspace roots.
- Do not stage, commit, push, create branches, install global tools, or open pull requests.
- Inspect the current working tree first. If unrelated files are already dirty, avoid changing them unless they are the exact fix target.
- Prefer the smallest shared boundary that blocks the exploit while preserving legitimate behavior.
- Add or update focused regression tests when practical.
- Run focused validation commands when they are obvious and cheap. If validation cannot be run, say why.
- Do not suppress the finding with comments or test-only conditionals.
- Do not remove security evidence or Nyctos artifacts.

Final response format:
Summary:
<one short paragraph explaining the fix>

Changed files:
- <path>: <what changed>

Validation:
- <command/result or not run reason>
"#
    .to_string()
}

fn render_objective(scope: &RemediationScope) -> String {
    let vulnerability = serde_json::to_string_pretty(&scope.vulnerability)
        .unwrap_or_else(|_| scope.vulnerability.title.clone());
    format!(
        "Fix this verified vulnerability in the local repository.\n\n\
         ## Workspace roots\n{workspaces}\n\n\
         ## Verified vulnerability\n```json\n{vulnerability}\n```\n\n\
         Start by checking the working tree. Then make the smallest code/test change that addresses \
         the remediation guidance and blocks the reproduction path. Leave the final diff unstaged \
         for the operator to inspect locally.",
        workspaces = render_workspaces(&scope.workspace_roots),
    )
}

fn render_workspaces(workspaces: &[String]) -> String {
    if workspaces.is_empty() {
        return "(none supplied; stop and explain that no writable workspace is available)"
            .to_string();
    }
    workspaces.iter().map(|workspace| format!("- {workspace}")).collect::<Vec<_>>().join("\n")
}

fn summarize_final_message(final_message: &str) -> String {
    let compact = final_message.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return "Fix agent completed.".to_string();
    }
    let mut out = String::new();
    for (idx, ch) in compact.chars().enumerate() {
        if idx >= 360 {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use nyctos_types::agent::{
        AgentResult, CacheStats, CostEstimate, Prompt, Response, TokenUsage,
    };
    use nyctos_types::event::AgentEvent;
    use tokio::sync::{broadcast, Mutex};

    use super::*;

    struct FakeRuntime {
        task: Mutex<Option<AgentTask>>,
    }

    #[async_trait]
    impl AiRuntime for FakeRuntime {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn default_model(&self) -> &str {
            "fake-model"
        }

        fn supports_agent_loop(&self) -> bool {
            true
        }

        fn supports_prompt_cache(&self) -> bool {
            false
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
            _budget: Budget,
            _sink: EventSink,
        ) -> Result<AgentResult, AiError> {
            *self.task.lock().await = Some(task);
            Ok(AgentResult {
                prompt_version: REMEDIATION_PROMPT_VERSION.to_string(),
                task_id: "remediation-vuln-1".to_string(),
                model: "fake-model".to_string(),
                final_message: "Summary:\nEscaped review output.".to_string(),
                turns: 2,
                usage: TokenUsage { input_tokens: 10, output_tokens: 20 },
                cache: Some(CacheStats::default()),
                cost_usd_micros: 42,
                extracted: Vec::new(),
            })
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            None
        }
    }

    #[tokio::test]
    async fn passes_vulnerability_context_to_agent_loop() {
        let runtime = FakeRuntime { task: Mutex::new(None) };
        let mut scope = RemediationScope::new(sample_vulnerability());
        scope.workspace_roots = vec!["/tmp/app".to_string()];
        let (tx, _) = broadcast::channel::<AgentEvent>(4);

        let outcome = run(&runtime, &scope, tx).await.expect("run");

        assert!(outcome.summary.contains("Escaped review output"));
        let task = runtime.task.lock().await.clone().expect("task captured");
        assert_eq!(task.working_directory.as_deref(), Some("/tmp/app"));
        assert!(task.objective.contains("Stored XSS"));
        assert!(task.system.contains("Do not stage, commit, push"));
    }

    fn sample_vulnerability() -> VerifiedVulnerabilityRecord {
        VerifiedVulnerabilityRecord {
            id: "vuln-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "project-1".to_string(),
            title: "Stored XSS".to_string(),
            severity: "High".to_string(),
            confidence: 0.95,
            risk_score: 8.4,
            risk_rating: "High".to_string(),
            risk_score_source: "test".to_string(),
            risk_score_rationale: "confirmed".to_string(),
            vuln_class: "xss".to_string(),
            affected_components: vec![serde_json::json!("reviews.js")],
            business_impact: "script execution".to_string(),
            evidence_summary: "review rendered script".to_string(),
            repro_steps: "submit script".to_string(),
            remediation: "escape review body".to_string(),
            source_candidate_ids: Vec::new(),
            source_signal_ids: Vec::new(),
            verification_attempt_ids: Vec::new(),
            chain_id: None,
            status: "Open".to_string(),
            first_seen: 1,
            last_seen: 2,
        }
    }
}

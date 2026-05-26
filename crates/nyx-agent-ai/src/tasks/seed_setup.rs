//! Seed setup agent task.
//!
//! The seed setup agent prepares deterministic local state for live
//! pentesting: roles, owned objects, tenant boundaries, payment-like
//! fixtures, webhook fixtures, and markers that verification oracles
//! can look for. It should prefer app-native seed commands over raw DB
//! writes.

use nyx_agent_types::agent::{
    classify_tool_use, AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind,
    ExtractedAgentResult,
};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::product::{ProjectLaunchProfile, SeedSetupPlan};
use serde_json::Value;

use crate::runtime::AiRuntime;
use crate::tasks::structured_output::json_values_from_text;

pub const SEED_SETUP_PROMPT_VERSION: &str = "phase25.seed_setup.v1";
pub const DEFAULT_SEED_SETUP_RUN_CAP_USD_MICROS: i64 = 3_000_000;
pub const DEFAULT_SEED_SETUP_MAX_TURNS: u32 = 24;
pub const DEFAULT_SEED_SETUP_TOOL_NAMES: &[&str] = &["Read", "Grep", "Bash", "record_seed_setup"];

#[derive(Debug, Clone)]
pub struct SeedSetupScope {
    pub project_id: String,
    pub project_name: String,
    pub task_id: String,
    pub target_base_url: Option<String>,
    pub workspace_roots: Vec<String>,
    pub launch_profile: Option<ProjectLaunchProfile>,
    pub run_cap_usd_micros: i64,
    pub max_turns: u32,
}

impl SeedSetupScope {
    pub fn new(project_id: impl Into<String>, project_name: impl Into<String>) -> Self {
        let project_id = project_id.into();
        Self {
            task_id: format!("seed-setup-{project_id}"),
            project_id,
            project_name: project_name.into(),
            target_base_url: None,
            workspace_roots: Vec::new(),
            launch_profile: None,
            run_cap_usd_micros: DEFAULT_SEED_SETUP_RUN_CAP_USD_MICROS,
            max_turns: DEFAULT_SEED_SETUP_MAX_TURNS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedSetupOutcome {
    pub plan: SeedSetupPlan,
    pub final_message: String,
    pub turns: u32,
    pub spent_usd_micros: i64,
    pub prompt_version: String,
    pub metrics: AgentTraceMetrics,
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &SeedSetupScope,
    sink: EventSink,
) -> Result<SeedSetupOutcome, AiError> {
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.project_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };
    let result = runtime.agent_loop(task, budget, sink).await?;
    lift_agent_result(result)
}

fn build_agent_task(scope: &SeedSetupScope) -> AgentTask {
    let workspace_roots = render_list(&scope.workspace_roots, "(no repo workspace roots found)");
    let target = scope.target_base_url.as_deref().unwrap_or("(not set)");
    let launch = scope
        .launch_profile
        .as_ref()
        .and_then(|profile| serde_json::to_string_pretty(profile).ok())
        .unwrap_or_else(|| "(none)".to_string());

    let system = "You are Nyx Agent's seed setup agent.\n\
        Prepare deterministic local test fixtures for an authorized local app. Prefer app-native seed commands, fixtures, scripts, factories, or APIs over direct DB inserts. \
        Do not use production services or raw secrets. Use stable markers such as `nyx-agent-owned-by-user-a` so later verification can prove object boundaries."
        .to_string();

    let objective = format!(
        "Project: {project_name} ({project_id})\n\
         Target hint: {target}\n\
         Workspace roots:\n{workspace_roots}\n\
         Current launch profile:\n{launch}\n\
         Max turns: {max_turns}\n\
         \n\
         Work:\n\
         1. Inspect seed scripts, test fixtures, factories, migrations, local database docs, package scripts, wrangler config, payment/webhook mocks, and auth/user model code.\n\
         2. Prefer creating or reusing a local app-native seed command such as `npm run nyx-agent:seed`, `rails db:seed`, `python manage.py seed`, or a repo-provided test fixture command. If a local command requires confirmation, include `stdin` like `\"y\\n\"` on the step.\n\
         3. Emit roles that auth setup should configure, usually `user_a`, `user_b`, and `admin` when the app supports them.\n\
         4. Emit owned objects with `name`, `id`, `route`, and `marker` so IDOR/authz checks can compare owner and peer access. Include tenant/workspace/org markers when visible.\n\
         5. Emit env vars only as local deterministic fixture values. Mark passwords/tokens/cookies as secret.\n\
         6. Emit exactly one `record_seed_setup` JSON line. The input may be either a plan object or `{{\"plan\": ...}}`. Put the JSON on its own line in the final answer; do not only describe the plan in prose.\n\
         \n\
         Example:\n\
         {{\"tool\":\"record_seed_setup\",\"input\":{{\"plan\":{{\"summary\":\"Prepared deterministic users and one project owned by user_a.\",\"seed_steps\":[{{\"command\":\"npm run nyx-agent:seed\",\"timeout_seconds\":120}}],\"reset_steps\":[{{\"command\":\"npm run dev:reset\",\"timeout_seconds\":120,\"stdin\":\"y\\n\"}}],\"env_vars\":[{{\"name\":\"NYX_AGENT_USER_A_USERNAME\",\"value\":\"user-a@example.test\",\"secret\":false}},{{\"name\":\"NYX_AGENT_USER_A_PASSWORD\",\"value\":\"nyx-agent-user-a-pass\",\"secret\":true}}],\"roles\":[\"user_a\",\"user_b\"],\"seeded_objects\":[{{\"name\":\"project\",\"id\":\"nyx-agent-project-a\",\"route\":\"/api/projects/{{id}}\",\"marker\":\"nyx-agent-owned-by-user-a\"}}],\"checks\":[\"seed script found in package.json\"],\"warnings\":[]}}}}}}\n",
        project_name = scope.project_name,
        project_id = scope.project_id,
        target = target,
        workspace_roots = workspace_roots,
        launch = launch,
        max_turns = scope.max_turns,
    );

    AgentTask {
        prompt_version: SEED_SETUP_PROMPT_VERSION.to_string(),
        task_id: scope.task_id.clone(),
        system,
        objective,
        tools: DEFAULT_SEED_SETUP_TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
        working_directory: scope.workspace_roots.first().cloned(),
        max_turns: scope.max_turns,
    }
}

fn lift_agent_result(result: AgentResult) -> Result<SeedSetupOutcome, AiError> {
    let mut latest = None;
    for extracted in &result.extracted {
        if let ExtractedAgentResult::SeedSetupPlan { plan } = extracted {
            latest = Some(plan.clone());
        }
    }
    let latest = latest.or_else(|| seed_setup_from_final_message(&result.final_message));
    let Some(mut plan) = latest else {
        return Err(AiError::MalformedResponse(
            format!(
                "seed setup agent did not emit record_seed_setup or a parseable seed plan JSON; final message preview: {}",
                final_message_preview(&result.final_message)
            ),
        ));
    };
    normalise_plan(&mut plan);
    let metrics = AgentTraceMetrics::from_agent_result(&result);
    Ok(SeedSetupOutcome {
        plan,
        final_message: result.final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        prompt_version: result.prompt_version,
        metrics,
    })
}

fn seed_setup_from_final_message(message: &str) -> Option<SeedSetupPlan> {
    json_values_from_text(message).into_iter().rev().find_map(|value| seed_setup_from_value(&value))
}

fn seed_setup_from_value(value: &Value) -> Option<SeedSetupPlan> {
    if let Some(plan) = seed_setup_from_tool_value(value) {
        return Some(plan);
    }
    if let Some(input) = value.get("input").or_else(|| value.get("arguments")) {
        if let Some(plan) = seed_setup_from_value(&coerce_json_string(input)) {
            return Some(plan);
        }
    }
    if let Some(record) = value.get("record_seed_setup") {
        if let Some(plan) = seed_setup_from_value(record) {
            return Some(plan);
        }
    }
    if let Some(plan_value) = value.get("plan") {
        return serde_json::from_value(plan_value.clone()).ok();
    }
    if looks_like_seed_plan(value) {
        return serde_json::from_value(value.clone()).ok();
    }
    value
        .as_array()
        .and_then(|items| items.iter().find_map(seed_setup_from_value))
        .or_else(|| value.as_object().and_then(|obj| obj.values().find_map(seed_setup_from_value)))
}

fn seed_setup_from_tool_value(value: &Value) -> Option<SeedSetupPlan> {
    if let Some(calls) = value.get("tool_calls").and_then(|v| v.as_array()) {
        return calls.iter().find_map(seed_setup_from_value);
    }
    let name = value.get("tool").or_else(|| value.get("name"))?.as_str()?;
    let input = value
        .get("input")
        .or_else(|| value.get("arguments"))
        .map(coerce_json_string)
        .unwrap_or_else(|| serde_json::json!({}));
    match classify_tool_use(name, &input)? {
        ExtractedAgentResult::SeedSetupPlan { plan } => Some(plan),
        _ => None,
    }
}

fn looks_like_seed_plan(value: &Value) -> bool {
    value.is_object()
        && ["seed_steps", "reset_steps", "env_vars", "roles", "seeded_objects"]
            .iter()
            .any(|key| value.get(key).is_some())
}

fn coerce_json_string(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| value.clone())
}

fn final_message_preview(message: &str) -> String {
    let compact = message.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(280).collect()
}

fn normalise_plan(plan: &mut SeedSetupPlan) {
    plan.summary = plan.summary.trim().to_string();
    if plan.summary.is_empty() {
        plan.summary = "Prepared local seed fixtures.".to_string();
    }
    plan.roles = clean_strings(std::mem::take(&mut plan.roles));
    plan.seed_steps = clean_steps(std::mem::take(&mut plan.seed_steps));
    plan.reset_steps = clean_steps(std::mem::take(&mut plan.reset_steps));
    plan.checks = clean_strings(std::mem::take(&mut plan.checks));
    plan.warnings = clean_strings(std::mem::take(&mut plan.warnings));
    plan.seeded_objects.retain(|object| {
        !object.name.trim().is_empty()
            && (!object.id.trim().is_empty()
                || object.route.as_ref().is_some_and(|route| !route.trim().is_empty()))
    });
    plan.env_vars.retain(|var| !var.name.trim().is_empty());
}

fn clean_steps(
    steps: Vec<nyx_agent_types::product::LaunchStep>,
) -> Vec<nyx_agent_types::product::LaunchStep> {
    steps
        .into_iter()
        .filter_map(|mut step| {
            step.command = step.command.trim().to_string();
            if step.command.is_empty() {
                return None;
            }
            Some(step)
        })
        .collect()
}

fn clean_strings(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
    out
}

fn render_list(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter().map(|item| format!("- {item}")).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pretty_fenced_seed_setup_tool_marker() {
        let text = r#"
```json
{
  "tool": "record_seed_setup",
  "input": {
    "plan": {
      "summary": "Prepared fixtures.",
      "seed_steps": [{"command": "npm run nyx-agent:seed"}],
      "reset_steps": [{"command": "npm run dev:reset", "stdin": "y\n"}],
      "env_vars": [],
      "roles": ["user_a", "user_b"],
      "seeded_objects": [],
      "checks": [],
      "warnings": []
    }
  }
}
```
"#;
        let plan = seed_setup_from_final_message(text).expect("parsed");
        assert_eq!(plan.roles, vec!["user_a", "user_b"]);
        assert_eq!(plan.reset_steps[0].stdin.as_deref(), Some("y\n"));
    }

    #[test]
    fn parses_direct_seed_plan_object() {
        let text = r#"
{
  "summary": "Direct plan.",
  "seed_steps": [{"command": "npm run seed"}],
  "reset_steps": [],
  "env_vars": [],
  "roles": ["admin"],
  "seeded_objects": [],
  "checks": [],
  "warnings": []
}
"#;
        let plan = seed_setup_from_final_message(text).expect("parsed");
        assert_eq!(plan.seed_steps[0].command, "npm run seed");
        assert_eq!(plan.roles, vec!["admin"]);
    }
}

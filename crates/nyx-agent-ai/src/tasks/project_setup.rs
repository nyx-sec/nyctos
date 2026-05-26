//! Project setup agent task.
//!
//! This agent inspects a local project repository, tries to understand
//! the development workflow, and emits a Nyx Agent launch profile. It is
//! intentionally separate from auth setup: this task makes the app
//! startable; the auth task then learns roles and sessions against the
//! running app.

use nyx_agent_types::agent::{
    AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind, ExtractedAgentResult,
};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::product::{
    LaunchHealthCheck, LaunchStep, ProjectLaunchProfile, ProjectLaunchProfileInput,
};

use crate::runtime::AiRuntime;

pub const PROJECT_SETUP_PROMPT_VERSION: &str = "phase25.project_setup.v1";
pub const DEFAULT_PROJECT_SETUP_RUN_CAP_USD_MICROS: i64 = 3_000_000;
pub const DEFAULT_PROJECT_SETUP_MAX_TURNS: u32 = 24;
pub const DEFAULT_PROJECT_SETUP_TOOL_NAMES: &[&str] =
    &["Read", "Grep", "Bash", "record_project_setup"];

#[derive(Debug, Clone)]
pub struct ProjectSetupScope {
    pub project_id: String,
    pub project_name: String,
    pub task_id: String,
    pub target_base_url: Option<String>,
    pub workspace_roots: Vec<String>,
    pub existing_launch_profile: Option<ProjectLaunchProfile>,
    pub run_cap_usd_micros: i64,
    pub max_turns: u32,
}

impl ProjectSetupScope {
    pub fn new(project_id: impl Into<String>, project_name: impl Into<String>) -> Self {
        let project_id = project_id.into();
        Self {
            task_id: format!("project-setup-{project_id}"),
            project_id,
            project_name: project_name.into(),
            target_base_url: None,
            workspace_roots: Vec::new(),
            existing_launch_profile: None,
            run_cap_usd_micros: DEFAULT_PROJECT_SETUP_RUN_CAP_USD_MICROS,
            max_turns: DEFAULT_PROJECT_SETUP_MAX_TURNS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectSetupOutcome {
    pub profile: ProjectLaunchProfileInput,
    pub summary: String,
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub final_message: String,
    pub turns: u32,
    pub spent_usd_micros: i64,
    pub prompt_version: String,
    pub metrics: AgentTraceMetrics,
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &ProjectSetupScope,
    sink: EventSink,
) -> Result<ProjectSetupOutcome, AiError> {
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.project_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };
    let result = runtime.agent_loop(task, budget, sink).await?;
    lift_agent_result(scope, result)
}

fn build_agent_task(scope: &ProjectSetupScope) -> AgentTask {
    let workspace_roots = render_list(&scope.workspace_roots, "(no repo workspace roots found)");
    let target = scope.target_base_url.as_deref().unwrap_or("(not set)");
    let existing = scope
        .existing_launch_profile
        .as_ref()
        .and_then(|profile| serde_json::to_string_pretty(profile).ok())
        .unwrap_or_else(|| "(none)".to_string());

    let system = "You are Nyx Agent's project setup agent.\n\
        You inspect only user-owned local repositories and prepare a launch profile that Nyx Agent can run later. \
        Prefer deterministic, non-interactive commands. Do not use production services, remote databases, destructive remote flags, or raw secrets. \
        If a local command prompts for confirmation, either find a documented non-interactive flag or put the required harmless local response in the launch step's `stdin` field."
        .to_string();

    let objective = format!(
        "Project: {project_name} ({project_id})\n\
         Target hint: {target}\n\
         Workspace roots:\n{workspace_roots}\n\
         Existing launch profile:\n{existing}\n\
         Max turns: {max_turns}\n\
         \n\
         Work:\n\
         1. Inspect README files, package manager files, scripts, Docker/compose files, wrangler config, env examples, migrations, seed/reset scripts, and test/dev docs.\n\
         2. Use Bash sparingly to verify commands when safe: version checks, dependency/install hints, build scripts, migration/reset scripts, and short-lived dev-server probes. Use timeouts for commands that may keep running.\n\
         3. Produce a Nyx Agent launch profile with `mode`, `target_urls`, and command arrays named `build_steps`, `start_steps`, `seed_steps`, `reset_steps`, `login_steps`, `stop_steps`, and `health_checks`.\n\
         4. For commands that need a local confirmation prompt, set `stdin` on that launch step, for example `\"y\\n\"`. Prefer official non-interactive flags when the tool supports them.\n\
         5. Emit exactly one `record_project_setup` JSON line. Include a concise `summary`, `checks`, and `warnings`.\n\
         \n\
         Example tool line:\n\
         {{\"tool\":\"record_project_setup\",\"input\":{{\"summary\":\"Detected a Vite app with npm scripts and verified the dev server on localhost:5173.\",\"checks\":[\"package.json dev script found\",\"health check target selected\"],\"warnings\":[],\"profile\":{{\"name\":\"AI local dev\",\"mode\":\"custom-commands\",\"target_urls\":[\"http://127.0.0.1:5173\"],\"build_steps\":[{{\"command\":\"npm install\",\"timeout_seconds\":300}}],\"start_steps\":[{{\"command\":\"npm run dev -- --host 127.0.0.1\",\"timeout_seconds\":300}}],\"reset_steps\":[],\"seed_steps\":[],\"login_steps\":[],\"stop_steps\":[],\"health_checks\":[{{\"kind\":\"http\",\"url\":\"http://127.0.0.1:5173\",\"timeout_seconds\":60}}],\"env_refs\":[],\"working_dirs\":[]}}}}}}\n",
        project_name = scope.project_name,
        project_id = scope.project_id,
        target = target,
        workspace_roots = workspace_roots,
        existing = existing,
        max_turns = scope.max_turns,
    );

    AgentTask {
        prompt_version: PROJECT_SETUP_PROMPT_VERSION.to_string(),
        task_id: scope.task_id.clone(),
        system,
        objective,
        tools: DEFAULT_PROJECT_SETUP_TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
        working_directory: scope.workspace_roots.first().cloned(),
        max_turns: scope.max_turns,
    }
}

fn lift_agent_result(
    scope: &ProjectSetupScope,
    result: AgentResult,
) -> Result<ProjectSetupOutcome, AiError> {
    let mut latest = None;
    for extracted in &result.extracted {
        if let ExtractedAgentResult::ProjectSetupProfile { profile, summary, checks, warnings } =
            extracted
        {
            latest = Some((profile.clone(), summary.clone(), checks.clone(), warnings.clone()));
        }
    }
    let Some((profile, summary, checks, warnings)) = latest else {
        return Err(AiError::MalformedResponse(
            "project setup agent did not emit record_project_setup".to_string(),
        ));
    };
    let profile = finalize_profile(scope, profile);
    let metrics = AgentTraceMetrics::from_agent_result(&result);
    Ok(ProjectSetupOutcome {
        profile,
        summary,
        checks,
        warnings,
        final_message: result.final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        prompt_version: result.prompt_version,
        metrics,
    })
}

fn finalize_profile(
    scope: &ProjectSetupScope,
    mut profile: ProjectLaunchProfileInput,
) -> ProjectLaunchProfileInput {
    if profile.name.as_ref().is_none_or(|name| name.trim().is_empty()) {
        profile.name = Some("AI local dev".to_string());
    }
    if profile.mode.as_ref().is_none_or(|mode| mode.trim().is_empty()) {
        profile.mode = Some(if profile.start_steps.is_empty() {
            "already-running".to_string()
        } else {
            "custom-commands".to_string()
        });
    }
    profile.build_steps = clean_steps(profile.build_steps);
    profile.start_steps = clean_steps(profile.start_steps);
    profile.seed_steps = clean_steps(profile.seed_steps);
    profile.reset_steps = clean_steps(profile.reset_steps);
    profile.login_steps = clean_steps(profile.login_steps);
    profile.stop_steps = clean_steps(profile.stop_steps);
    profile.health_checks = clean_health_checks(profile.health_checks);
    profile.target_urls.retain(|url| !url.trim().is_empty());
    if profile.target_urls.is_empty() {
        if let Some(target) = scope.target_base_url.as_ref().filter(|url| !url.trim().is_empty()) {
            profile.target_urls.push(target.clone());
        }
    }
    profile
}

fn clean_steps(steps: Vec<LaunchStep>) -> Vec<LaunchStep> {
    steps
        .into_iter()
        .filter_map(|mut step| {
            step.command = step.command.trim().to_string();
            if step.command.is_empty() {
                return None;
            }
            step.repo_name = trim_option(step.repo_name);
            step.repo_id = trim_option(step.repo_id);
            step.working_directory = trim_option(step.working_directory);
            step.stdin = trim_option(step.stdin);
            Some(step)
        })
        .collect()
}

fn clean_health_checks(checks: Vec<LaunchHealthCheck>) -> Vec<LaunchHealthCheck> {
    checks
        .into_iter()
        .filter_map(|mut check| {
            check.kind = check.kind.trim().to_string();
            check.url = trim_option(check.url);
            check.host = trim_option(check.host);
            check.command =
                check.command.and_then(|step| clean_steps(vec![step]).into_iter().next());
            if check.kind.is_empty() {
                check.kind = if check.command.is_some() { "command" } else { "http" }.to_string();
            }
            if check.url.is_none() && check.command.is_none() && check.host.is_none() {
                return None;
            }
            Some(check)
        })
        .collect()
}

fn trim_option(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn render_list(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter().map(|item| format!("- {item}")).collect::<Vec<_>>().join("\n")
}

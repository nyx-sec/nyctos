//! Project setup agent task.
//!
//! This agent inspects a local project repository, tries to understand
//! the development workflow, and emits a Nyx Agent launch profile. It is
//! intentionally separate from auth setup: this task makes the app
//! startable; the auth task then learns roles and sessions against the
//! running app.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use nyx_agent_types::agent::{
    classify_tool_use, AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind,
    ExtractedAgentResult,
};
use nyx_agent_types::event::EventSink;
use nyx_agent_types::product::{
    LaunchHealthCheck, LaunchStep, ProjectLaunchProfile, ProjectLaunchProfileInput,
};
use serde_json::Value;

use crate::runtime::AiRuntime;
use crate::tasks::structured_output::{json_values_from_text, optional_string, string_array};

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
         5. Emit exactly one `record_project_setup` JSON line. Include a concise `summary`, `checks`, and `warnings`. Put the JSON on its own line in the final answer; do not only describe the profile in prose.\n\
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
    let latest = latest.or_else(|| {
        project_setup_from_final_message(&result.final_message)
            .map(|parsed| (parsed.profile, parsed.summary, parsed.checks, parsed.warnings))
    });
    let latest = latest.or_else(|| {
        recover_project_setup_from_agent_prose(scope, &result.final_message)
            .map(|parsed| (parsed.profile, parsed.summary, parsed.checks, parsed.warnings))
    });
    let Some((profile, summary, checks, warnings)) = latest else {
        return Err(AiError::MalformedResponse(
            format!(
                "project setup agent did not emit record_project_setup or a parseable profile JSON, and deterministic recovery could not synthesize a launch profile; full final message:\n{}",
                result.final_message
            ),
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

struct ParsedProjectSetup {
    profile: ProjectLaunchProfileInput,
    summary: String,
    checks: Vec<String>,
    warnings: Vec<String>,
}

fn project_setup_from_final_message(message: &str) -> Option<ParsedProjectSetup> {
    json_values_from_text(message)
        .into_iter()
        .rev()
        .find_map(|value| project_setup_from_value(&value))
}

fn project_setup_from_value(value: &Value) -> Option<ParsedProjectSetup> {
    if let Some(parsed) = project_setup_from_tool_value(value) {
        return Some(parsed);
    }
    if let Some(input) = value.get("input").or_else(|| value.get("arguments")) {
        if let Some(parsed) = project_setup_from_value(&coerce_json_string(input)) {
            return Some(parsed);
        }
    }
    if let Some(record) = value.get("record_project_setup") {
        if let Some(parsed) = project_setup_from_value(record) {
            return Some(parsed);
        }
    }
    if let Some(profile_value) = value.get("profile") {
        let profile: ProjectLaunchProfileInput =
            serde_json::from_value(profile_value.clone()).ok()?;
        return Some(ParsedProjectSetup {
            profile,
            summary: optional_string(value, "summary")
                .unwrap_or_else(|| "local project setup".to_string()),
            checks: string_array(value, "checks"),
            warnings: string_array(value, "warnings"),
        });
    }
    if looks_like_launch_profile(value) {
        let profile: ProjectLaunchProfileInput = serde_json::from_value(value.clone()).ok()?;
        return Some(ParsedProjectSetup {
            profile,
            summary: "local project setup".to_string(),
            checks: Vec::new(),
            warnings: Vec::new(),
        });
    }
    value.as_array().and_then(|items| items.iter().find_map(project_setup_from_value)).or_else(
        || value.as_object().and_then(|obj| obj.values().find_map(project_setup_from_value)),
    )
}

fn project_setup_from_tool_value(value: &Value) -> Option<ParsedProjectSetup> {
    if let Some(calls) = value.get("tool_calls").and_then(|v| v.as_array()) {
        return calls.iter().find_map(project_setup_from_value);
    }
    let name = value.get("tool").or_else(|| value.get("name"))?.as_str()?;
    let input = value
        .get("input")
        .or_else(|| value.get("arguments"))
        .map(coerce_json_string)
        .unwrap_or_else(|| serde_json::json!({}));
    match classify_tool_use(name, &input)? {
        ExtractedAgentResult::ProjectSetupProfile { profile, summary, checks, warnings } => {
            Some(ParsedProjectSetup { profile, summary, checks, warnings })
        }
        _ => None,
    }
}

fn looks_like_launch_profile(value: &Value) -> bool {
    value.is_object()
        && ["target_urls", "start_steps", "build_steps", "health_checks", "reset_steps"]
            .iter()
            .any(|key| value.get(key).is_some())
}

fn recover_project_setup_from_agent_prose(
    scope: &ProjectSetupScope,
    final_message: &str,
) -> Option<ParsedProjectSetup> {
    let repo_hint_text = read_repo_hint_text(&scope.workspace_roots);
    let combined_text = if repo_hint_text.is_empty() {
        final_message.to_string()
    } else {
        format!("{final_message}\n{repo_hint_text}")
    };
    let prose_commands = extract_commands_from_text(&combined_text);
    let prose_urls = extract_local_urls_from_text(&combined_text);

    let mut roots = scope
        .workspace_roots
        .iter()
        .filter_map(|root| workspace_root_path(root))
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();

    for root in &roots {
        if let Some(parsed) =
            recover_from_package_json(scope, root, &combined_text, &prose_commands, &prose_urls)
        {
            return Some(parsed);
        }
    }
    for root in &roots {
        if let Some(parsed) = recover_from_compose(scope, root, &combined_text, &prose_urls) {
            return Some(parsed);
        }
    }
    recover_from_prose_only(scope, &combined_text, &prose_commands, &prose_urls)
}

fn recover_from_package_json(
    scope: &ProjectSetupScope,
    root: &Path,
    text: &str,
    prose_commands: &[String],
    prose_urls: &[String],
) -> Option<ParsedProjectSetup> {
    for package_path in find_package_jsons(root) {
        let Ok(raw) = fs::read_to_string(&package_path) else {
            continue;
        };
        let Ok(package) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(scripts) = package_scripts(&package) else {
            continue;
        };
        let package_dir = package_path.parent().unwrap_or(root);
        let runner = detect_package_runner(package_dir);
        let start_script = choose_start_script(&scripts, prose_commands);
        let reset_script = choose_reset_script(&scripts, prose_commands);
        let start_body = start_script.and_then(|script| scripts.get(script)).map(String::as_str);
        let app_kind = infer_package_app_kind(package_dir, &package, start_body, text);
        let target_url =
            choose_recovered_target_url(scope, text, start_body, app_kind, package_dir, prose_urls);

        let mut profile = empty_profile_input();
        profile.name = Some("AI local dev (recovered)".to_string());
        profile.mode = Some(if start_script.is_some() {
            "custom-commands".to_string()
        } else {
            "already-running".to_string()
        });
        if let Some(script) = start_script {
            let command = package_script_command(&runner, script);
            let mut step = launch_step(command, Some(path_string(package_dir)), Some(300));
            if step_needs_local_migration_confirmation(
                &step.command,
                scripts.get(script).map(String::as_str),
            ) {
                step.stdin = Some("y\n".to_string());
            }
            profile.start_steps.push(step);
        }
        if let Some(script) = reset_script {
            let command = package_script_command(&runner, script);
            let mut step = launch_step(command, Some(path_string(package_dir)), Some(300));
            if step_needs_local_migration_confirmation(
                &step.command,
                scripts.get(script).map(String::as_str),
            ) {
                step.stdin = Some("y\n".to_string());
            }
            profile.reset_steps.push(step);
        }
        if let Some(url) = target_url {
            profile.target_urls.push(url.clone());
            profile.health_checks.push(http_health_check(url, Some(60)));
        }
        if profile.start_steps.is_empty()
            && profile.target_urls.is_empty()
            && profile.health_checks.is_empty()
        {
            continue;
        }

        let mut checks = recovered_base_checks();
        checks.push(format!("inspected {}", path_string(&package_path)));
        if let Some(step) = profile.start_steps.first() {
            checks.push(format!("recovered start command `{}`", step.command));
        }
        if let Some(step) = profile.reset_steps.first() {
            checks.push(format!("recovered reset command `{}`", step.command));
            if step.stdin.as_deref() == Some("y\n") {
                checks
                    .push("set stdin for local Wrangler migration confirmation prompt".to_string());
            }
        }
        if let Some(url) = profile.target_urls.first() {
            checks.push(format!("selected local target {url}"));
        }

        return Some(ParsedProjectSetup {
            profile,
            summary: format!(
                "Recovered a local dev launch profile from agent prose and {}.",
                app_kind.label()
            ),
            checks,
            warnings: recovered_warnings(),
        });
    }
    None
}

fn recover_from_compose(
    scope: &ProjectSetupScope,
    root: &Path,
    text: &str,
    prose_urls: &[String],
) -> Option<ParsedProjectSetup> {
    let compose_path = find_compose_file(root)?;
    let compose_raw = fs::read_to_string(&compose_path).unwrap_or_default();
    let target_url = scope
        .target_base_url
        .as_deref()
        .and_then(normalize_local_url)
        .or_else(|| prose_urls.first().cloned())
        .or_else(|| extract_port_from_text(&compose_raw).map(url_for_port))?;

    let mut profile = empty_profile_input();
    profile.name = Some("AI local dev (recovered)".to_string());
    profile.mode = Some("docker-compose".to_string());
    profile.target_urls.push(target_url.clone());
    profile.health_checks.push(http_health_check(target_url.clone(), Some(60)));

    let mut checks = recovered_base_checks();
    checks.push(format!("inspected {}", path_string(&compose_path)));
    checks.push(format!("selected local target {target_url}"));
    if text.to_ascii_lowercase().contains("docker compose") {
        checks.push("agent prose referenced docker compose workflow".to_string());
    }

    Some(ParsedProjectSetup {
        profile,
        summary: "Recovered a docker compose launch profile from agent prose and repo files."
            .to_string(),
        checks,
        warnings: recovered_warnings(),
    })
}

fn recover_from_prose_only(
    scope: &ProjectSetupScope,
    text: &str,
    prose_commands: &[String],
    prose_urls: &[String],
) -> Option<ParsedProjectSetup> {
    let start_command = prose_commands.iter().find(|command| command_is_start(command)).cloned();
    let target_url = scope
        .target_base_url
        .as_deref()
        .and_then(normalize_local_url)
        .or_else(|| prose_urls.first().cloned())
        .or_else(|| inferred_default_url_from_text(text));
    if start_command.is_none() && target_url.is_none() {
        return None;
    }

    let mut profile = empty_profile_input();
    profile.name = Some("AI local dev (recovered)".to_string());
    profile.mode = Some(if start_command.is_some() {
        "custom-commands".to_string()
    } else {
        "already-running".to_string()
    });
    if let Some(command) = start_command {
        profile.start_steps.push(launch_step(command, None, Some(300)));
    }
    if let Some(url) = target_url {
        profile.target_urls.push(url.clone());
        profile.health_checks.push(http_health_check(url, Some(60)));
    }
    if profile.start_steps.is_empty()
        && profile.target_urls.is_empty()
        && profile.health_checks.is_empty()
    {
        return None;
    }

    let mut checks = recovered_base_checks();
    if let Some(step) = profile.start_steps.first() {
        checks.push(format!("recovered start command `{}` from agent prose", step.command));
    }
    if let Some(url) = profile.target_urls.first() {
        checks.push(format!("selected local target {url}"));
    }

    Some(ParsedProjectSetup {
        profile,
        summary: "Recovered a local dev launch profile from agent prose.".to_string(),
        checks,
        warnings: recovered_warnings(),
    })
}

#[derive(Debug, Clone, Copy)]
enum AppKind {
    Wrangler,
    Vite,
    Next,
    ReactScripts,
    Angular,
    Astro,
    Nuxt,
    SvelteKit,
    GenericNode,
}

impl AppKind {
    fn label(self) -> &'static str {
        match self {
            AppKind::Wrangler => "Wrangler project files",
            AppKind::Vite => "Vite project files",
            AppKind::Next => "Next.js project files",
            AppKind::ReactScripts => "React scripts project files",
            AppKind::Angular => "Angular project files",
            AppKind::Astro => "Astro project files",
            AppKind::Nuxt => "Nuxt project files",
            AppKind::SvelteKit => "SvelteKit project files",
            AppKind::GenericNode => "package.json scripts",
        }
    }

    fn default_port(self) -> Option<u16> {
        match self {
            AppKind::Wrangler => Some(8787),
            AppKind::Vite | AppKind::SvelteKit => Some(5173),
            AppKind::Next | AppKind::ReactScripts | AppKind::Nuxt | AppKind::GenericNode => {
                Some(3000)
            }
            AppKind::Angular => Some(4200),
            AppKind::Astro => Some(4321),
        }
    }
}

fn empty_profile_input() -> ProjectLaunchProfileInput {
    ProjectLaunchProfileInput {
        name: None,
        mode: None,
        build_steps: Vec::new(),
        start_steps: Vec::new(),
        seed_steps: Vec::new(),
        reset_steps: Vec::new(),
        login_steps: Vec::new(),
        stop_steps: Vec::new(),
        health_checks: Vec::new(),
        target_urls: Vec::new(),
        env_refs: Vec::new(),
        working_dirs: Vec::new(),
    }
}

fn launch_step(
    command: impl Into<String>,
    working_directory: Option<String>,
    timeout_seconds: Option<u64>,
) -> LaunchStep {
    LaunchStep {
        command: command.into(),
        repo_id: None,
        repo_name: None,
        working_directory,
        timeout_seconds,
        stdin: None,
    }
}

fn http_health_check(url: String, timeout_seconds: Option<u64>) -> LaunchHealthCheck {
    LaunchHealthCheck {
        kind: "http".to_string(),
        url: Some(url),
        host: None,
        port: None,
        command: None,
        timeout_seconds,
    }
}

fn recovered_base_checks() -> Vec<String> {
    vec!["project setup agent ran but omitted record_project_setup".to_string()]
}

fn recovered_warnings() -> Vec<String> {
    vec![
        "Recovered launch profile from prose and deterministic repo inspection because the agent omitted record_project_setup; review before relying on it for unattended scans."
            .to_string(),
    ]
}

fn workspace_root_path(raw: &str) -> Option<PathBuf> {
    let path = PathBuf::from(raw);
    path.is_dir().then_some(path)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn read_repo_hint_text(workspace_roots: &[String]) -> String {
    let mut out = String::new();
    for root in workspace_roots.iter().filter_map(|root| workspace_root_path(root)) {
        for path in repo_hint_paths(&root) {
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            out.push_str("\n--- ");
            out.push_str(&path_string(&path));
            out.push_str(" ---\n");
            out.push_str(raw.chars().take(64_000).collect::<String>().as_str());
        }
    }
    out
}

fn repo_hint_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for name in ["README.md", "README", "package.json", "wrangler.toml", "wrangler.json"] {
        let path = root.join(name);
        if path.is_file() {
            paths.push(path);
        }
    }
    let workflows = root.join(".github").join("workflows");
    if let Ok(entries) = fs::read_dir(workflows) {
        for entry in entries.flatten() {
            let path = entry.path();
            if matches!(path.extension().and_then(|ext| ext.to_str()), Some("yml" | "yaml")) {
                paths.push(path);
            }
        }
    }
    paths
}

fn find_package_jsons(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    find_package_jsons_inner(root, 0, &mut found);
    found.sort();
    found.dedup();
    found
}

fn find_package_jsons_inner(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if depth > 3 || should_skip_dir(dir) {
        return;
    }
    let package = dir.join("package.json");
    if package.is_file() {
        found.push(package);
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_package_jsons_inner(&path, depth + 1, found);
        }
    }
}

fn should_skip_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            ".git"
                | ".nyx"
                | "node_modules"
                | "target"
                | "dist"
                | "build"
                | ".next"
                | ".turbo"
                | "coverage"
        )
    )
}

fn package_scripts(package: &Value) -> Option<BTreeMap<String, String>> {
    let scripts = package.get("scripts")?.as_object()?;
    let scripts = scripts
        .iter()
        .filter_map(|(name, value)| {
            value.as_str().map(|command| (name.to_string(), command.to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    (!scripts.is_empty()).then_some(scripts)
}

fn detect_package_runner(package_dir: &Path) -> String {
    if package_dir.join("pnpm-lock.yaml").is_file() {
        "pnpm".to_string()
    } else if package_dir.join("yarn.lock").is_file() {
        "yarn".to_string()
    } else if package_dir.join("bun.lockb").is_file() || package_dir.join("bun.lock").is_file() {
        "bun".to_string()
    } else {
        "npm".to_string()
    }
}

fn choose_start_script<'a>(
    scripts: &'a BTreeMap<String, String>,
    prose_commands: &[String],
) -> Option<&'a str> {
    for command in prose_commands {
        if let Some(script) = package_script_from_command(command) {
            if scripts.contains_key(script) && script_name_is_start(script) {
                return scripts.get_key_value(script).map(|(script, _)| script.as_str());
            }
        }
    }
    ["dev", "start", "serve", "preview", "wrangler:dev", "dev:wrangler", "local"]
        .into_iter()
        .find(|script| scripts.contains_key(*script) && script_name_is_start(script))
}

fn choose_reset_script<'a>(
    scripts: &'a BTreeMap<String, String>,
    prose_commands: &[String],
) -> Option<&'a str> {
    for command in prose_commands {
        if let Some(script) = package_script_from_command(command) {
            if scripts.contains_key(script) && script_name_is_reset(script) {
                return scripts.get_key_value(script).map(|(script, _)| script.as_str());
            }
        }
    }
    ["dev:reset", "reset:dev", "db:reset", "reset:db", "migrate:reset", "migrations:reset", "reset"]
        .into_iter()
        .find(|script| scripts.contains_key(*script))
        .or_else(|| scripts.keys().find(|script| script_name_is_reset(script)).map(String::as_str))
}

fn script_name_is_start(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    !(lower.contains("reset")
        || lower.contains("seed")
        || lower.contains("test")
        || lower.contains("build")
        || lower.contains("lint")
        || lower.contains("migrate"))
        && matches!(
            lower.as_str(),
            "dev" | "start" | "serve" | "preview" | "wrangler:dev" | "dev:wrangler" | "local"
        )
}

fn script_name_is_reset(script: &str) -> bool {
    script.to_ascii_lowercase().contains("reset")
}

fn package_script_command(runner: &str, script: &str) -> String {
    match (runner, script) {
        ("npm", "start") => "npm start".to_string(),
        ("npm", other) => format!("npm run {other}"),
        ("pnpm", "start") => "pnpm start".to_string(),
        ("pnpm", other) => format!("pnpm run {other}"),
        ("yarn", "start") => "yarn start".to_string(),
        ("yarn", other) => format!("yarn {other}"),
        ("bun", "start") => "bun start".to_string(),
        ("bun", other) => format!("bun run {other}"),
        (_, other) => format!("npm run {other}"),
    }
}

fn package_script_from_command(command: &str) -> Option<&str> {
    let parts = command.split_whitespace().collect::<Vec<_>>();
    match parts.as_slice() {
        ["npm", "run", script, ..] => Some(strip_command_suffix(script)),
        ["npm", "start", ..] => Some("start"),
        ["pnpm", "run", script, ..] => Some(strip_command_suffix(script)),
        ["pnpm", script, ..] if !package_runner_builtin(script) => {
            Some(strip_command_suffix(script))
        }
        ["yarn", "run", script, ..] => Some(strip_command_suffix(script)),
        ["yarn", script, ..] if !package_runner_builtin(script) => {
            Some(strip_command_suffix(script))
        }
        ["bun", "run", script, ..] => Some(strip_command_suffix(script)),
        ["bun", script, ..] if !package_runner_builtin(script) => {
            Some(strip_command_suffix(script))
        }
        _ => None,
    }
}

fn strip_command_suffix(raw: &str) -> &str {
    raw.trim_matches(|ch| matches!(ch, '`' | '\'' | '"' | ',' | ';' | '.'))
}

fn package_runner_builtin(raw: &str) -> bool {
    matches!(raw, "install" | "add" | "remove" | "exec" | "dlx" | "x" | "test" | "build" | "lint")
}

fn command_is_start(command: &str) -> bool {
    if let Some(script) = package_script_from_command(command) {
        return script_name_is_start(script);
    }
    let lower = command.to_ascii_lowercase();
    lower == "wrangler dev"
        || lower.starts_with("wrangler dev ")
        || lower == "cargo run"
        || lower.starts_with("docker compose up")
        || lower.starts_with("docker-compose up")
}

fn step_needs_local_migration_confirmation(command: &str, script_body: Option<&str>) -> bool {
    let mut lower = command.to_ascii_lowercase();
    if let Some(body) = script_body {
        lower.push('\n');
        lower.push_str(&body.to_ascii_lowercase());
    }
    lower.contains("wrangler")
        && lower.contains("migrations apply")
        && (lower.contains("--local") || lower.contains(" d1 "))
}

fn infer_package_app_kind(
    package_dir: &Path,
    package: &Value,
    start_body: Option<&str>,
    text: &str,
) -> AppKind {
    let start_lower = start_body.unwrap_or_default().to_ascii_lowercase();
    let mut combined = start_lower.clone();
    for key in ["dependencies", "devDependencies"] {
        if let Some(deps) = package.get(key).and_then(|value| value.as_object()) {
            for dep in deps.keys() {
                combined.push('\n');
                combined.push_str(&dep.to_ascii_lowercase());
            }
        }
    }
    if has_wrangler_config(package_dir)
        || start_lower.contains("wrangler")
        || (start_body.is_none() && text.to_ascii_lowercase().contains("wrangler"))
    {
        AppKind::Wrangler
    } else if combined.contains("next dev") || combined.contains("\nnext") {
        AppKind::Next
    } else if combined.contains("react-scripts start") || combined.contains("\nreact-scripts") {
        AppKind::ReactScripts
    } else if combined.contains("ng serve") || combined.contains("@angular/") {
        AppKind::Angular
    } else if combined.contains("astro dev") || combined.contains("\nastro") {
        AppKind::Astro
    } else if combined.contains("nuxt dev") || combined.contains("\nnuxt") {
        AppKind::Nuxt
    } else if combined.contains("svelte-kit") || combined.contains("@sveltejs/kit") {
        AppKind::SvelteKit
    } else if combined.contains("vite") {
        AppKind::Vite
    } else {
        AppKind::GenericNode
    }
}

fn has_wrangler_config(package_dir: &Path) -> bool {
    ["wrangler.toml", "wrangler.json", "wrangler.jsonc"]
        .iter()
        .any(|name| package_dir.join(name).is_file())
}

fn choose_recovered_target_url(
    scope: &ProjectSetupScope,
    text: &str,
    start_body: Option<&str>,
    app_kind: AppKind,
    package_dir: &Path,
    prose_urls: &[String],
) -> Option<String> {
    scope
        .target_base_url
        .as_deref()
        .and_then(normalize_local_url)
        .or_else(|| prose_urls.first().cloned())
        .or_else(|| start_body.and_then(|body| extract_local_urls_from_text(body).first().cloned()))
        .or_else(|| start_body.and_then(extract_port_from_text).map(url_for_port))
        .or_else(|| wrangler_config_port(package_dir).map(url_for_port))
        .or_else(|| extract_port_from_text(text).map(url_for_port))
        .or_else(|| app_kind.default_port().map(url_for_port))
}

fn wrangler_config_port(package_dir: &Path) -> Option<u16> {
    for name in ["wrangler.toml", "wrangler.json", "wrangler.jsonc"] {
        let Ok(raw) = fs::read_to_string(package_dir.join(name)) else {
            continue;
        };
        if let Some(port) = extract_port_from_text(&raw) {
            return Some(port);
        }
    }
    None
}

fn find_compose_file(root: &Path) -> Option<PathBuf> {
    for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"] {
        let path = root.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn inferred_default_url_from_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("wrangler") {
        Some(url_for_port(8787))
    } else if lower.contains("vite") {
        Some(url_for_port(5173))
    } else if lower.contains("next dev") || lower.contains("react-scripts") {
        Some(url_for_port(3000))
    } else if lower.contains("ng serve") {
        Some(url_for_port(4200))
    } else {
        extract_port_from_text(text).map(url_for_port)
    }
}

fn extract_commands_from_text(text: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('`') else {
            break;
        };
        let snippet = rest[..end].trim();
        if looks_like_command(snippet) {
            commands.push(clean_command(snippet));
        }
        rest = &rest[end + 1..];
    }

    let lower = text.to_ascii_lowercase();
    let mut indexed = [
        "npm run dev:reset",
        "npm run dev",
        "npm start",
        "pnpm run dev:reset",
        "pnpm run dev",
        "pnpm dev",
        "pnpm start",
        "yarn dev:reset",
        "yarn dev",
        "yarn start",
        "bun run dev:reset",
        "bun run dev",
        "bun dev",
        "wrangler dev",
        "docker compose up",
        "docker-compose up",
        "cargo run",
    ]
    .into_iter()
    .filter_map(|command| lower.find(command).map(|idx| (idx, command.to_string())))
    .collect::<Vec<_>>();
    indexed.sort_by_key(|(idx, _)| *idx);
    commands.extend(indexed.into_iter().map(|(_, command)| command));

    dedupe_preserve_order(commands)
}

fn looks_like_command(snippet: &str) -> bool {
    let lower = snippet.to_ascii_lowercase();
    [
        "npm ",
        "pnpm ",
        "yarn ",
        "bun ",
        "wrangler ",
        "docker compose ",
        "docker-compose ",
        "cargo ",
        "make ",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn clean_command(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_local_urls_from_text(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in ["http://", "https://"] {
        let mut search = 0;
        while let Some(relative) = text[search..].find(scheme) {
            let start = search + relative;
            let tail = &text[start..];
            let end = tail
                .char_indices()
                .find(|(_, ch)| {
                    ch.is_whitespace()
                        || matches!(ch, '`' | '\'' | '"' | '<' | '>' | ')' | ']' | '}')
                })
                .map(|(idx, _)| start + idx)
                .unwrap_or(text.len());
            if let Some(url) = normalize_local_url(&text[start..end]) {
                urls.push(url);
            }
            search = end.saturating_add(1).min(text.len());
        }
    }
    dedupe_preserve_order(urls)
}

fn normalize_local_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|ch| {
        matches!(ch, '`' | '\'' | '"' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '.')
    });
    let mut url = reqwest::Url::parse(trimmed).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?;
    if host.eq_ignore_ascii_case("localhost") || host == "0.0.0.0" || host == "::1" {
        url.set_host(Some("127.0.0.1")).ok()?;
    } else if !(host == "127.0.0.1" || host.starts_with("127.")) {
        return None;
    }
    let mut out = url.to_string();
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        out = out.trim_end_matches('/').to_string();
    }
    Some(out)
}

fn extract_port_from_text(text: &str) -> Option<u16> {
    let lower = text.to_ascii_lowercase();
    for pattern in ["localhost:", "127.0.0.1:", "0.0.0.0:", "--port=", "--port ", "-p ", "port "] {
        if let Some(port) = parse_port_after(&lower, pattern) {
            return Some(port);
        }
    }
    None
}

fn parse_port_after(text: &str, pattern: &str) -> Option<u16> {
    let mut search = 0;
    while let Some(relative) = text[search..].find(pattern) {
        let mut idx = search + relative + pattern.len();
        while idx < text.len() && matches!(text.as_bytes()[idx], b' ' | b'=' | b':') {
            idx += 1;
        }
        let digit_start = idx;
        while idx < text.len() && text.as_bytes()[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx > digit_start {
            if let Ok(port) = text[digit_start..idx].parse::<u16>() {
                if port > 0 {
                    return Some(port);
                }
            }
        }
        search = idx.saturating_add(1).min(text.len());
    }
    None
}

fn url_for_port(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn dedupe_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn coerce_json_string(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| value.clone())
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
            step.stdin = clean_stdin_option(step.stdin);
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

fn clean_stdin_option(value: Option<String>) -> Option<String> {
    let value = value?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
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
    use async_trait::async_trait;
    use nyx_agent_types::agent::{CostEstimate, Prompt, Response, TokenUsage};
    use tokio::sync::broadcast;

    struct ScriptedRuntime {
        result: AgentResult,
    }

    #[async_trait]
    impl AiRuntime for ScriptedRuntime {
        fn name(&self) -> &'static str {
            "scripted"
        }

        fn default_model(&self) -> &str {
            "scripted"
        }

        fn supports_agent_loop(&self) -> bool {
            true
        }

        fn supports_prompt_cache(&self) -> bool {
            false
        }

        fn supports_deterministic_sampling(&self) -> bool {
            true
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
            assert!(task.objective.contains("record_project_setup"));
            Ok(self.result.clone())
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            None
        }
    }

    fn fake_result_with_message(
        final_message: impl Into<String>,
        extracted: Vec<ExtractedAgentResult>,
    ) -> AgentResult {
        AgentResult {
            prompt_version: PROJECT_SETUP_PROMPT_VERSION.to_string(),
            task_id: "project-setup-p1".to_string(),
            model: "scripted".to_string(),
            final_message: final_message.into(),
            turns: 4,
            usage: TokenUsage { input_tokens: 100, output_tokens: 50 },
            cache: None,
            cost_usd_micros: 123,
            extracted,
        }
    }

    #[test]
    fn parses_pretty_fenced_project_setup_tool_marker() {
        let text = r#"
```json
{
  "tool": "record_project_setup",
  "input": {
    "summary": "Detected wrangler workflow.",
    "checks": ["package.json inspected"],
    "warnings": [],
    "profile": {
      "target_urls": ["http://127.0.0.1:8787"],
      "start_steps": [{"command": "npm run dev"}],
      "reset_steps": [{"command": "npm run dev:reset", "stdin": "y\n"}]
    }
  }
}
```
"#;
        let parsed = project_setup_from_final_message(text).expect("parsed");
        assert_eq!(parsed.summary, "Detected wrangler workflow.");
        assert_eq!(parsed.profile.target_urls, vec!["http://127.0.0.1:8787"]);
        assert_eq!(parsed.profile.reset_steps[0].stdin.as_deref(), Some("y\n"));
    }

    #[test]
    fn parses_direct_project_setup_profile_object() {
        let text = r#"
{
  "summary": "Direct profile",
  "profile": {
    "target_urls": ["http://localhost:3000"],
    "health_checks": [{"kind": "http", "url": "http://localhost:3000"}]
  }
}
"#;
        let parsed = project_setup_from_final_message(text).expect("parsed");
        assert_eq!(parsed.summary, "Direct profile");
        assert_eq!(parsed.profile.health_checks[0].kind, "http");
    }

    #[tokio::test]
    async fn recovers_profile_from_agent_prose_and_repo_files() {
        let repo = tempfile::tempdir().expect("tempdir");
        fs::write(
            repo.path().join("package.json"),
            r#"{"scripts":{"dev":"wrangler dev","dev:reset":"wrangler d1 migrations apply DB --local"}}"#,
        )
        .expect("write package");
        let final_message = "The project\u{2019}s own workflow confirms `npm run dev` is the local entry point: it migrates, seeds, then starts Wrangler...";
        let runtime =
            ScriptedRuntime { result: fake_result_with_message(final_message, Vec::new()) };
        let mut scope = ProjectSetupScope::new("p1", "PrismTrips");
        scope.workspace_roots = vec![path_string(repo.path())];
        let (sink, _rx) = broadcast::channel(1);

        let outcome = run(&runtime, &scope, sink).await.expect("recovered");

        assert_eq!(outcome.profile.start_steps[0].command, "npm run dev");
        assert_eq!(outcome.profile.reset_steps[0].command, "npm run dev:reset");
        assert_eq!(outcome.profile.reset_steps[0].stdin.as_deref(), Some("y\n"));
        assert_eq!(outcome.profile.target_urls, vec!["http://127.0.0.1:8787"]);
        assert_eq!(outcome.profile.health_checks[0].url.as_deref(), Some("http://127.0.0.1:8787"));
        assert!(outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("Recovered launch profile from prose")));
    }

    #[tokio::test]
    async fn recovered_wrangler_dev_reset_sets_confirmation_stdin() {
        let repo = tempfile::tempdir().expect("tempdir");
        fs::write(
            repo.path().join("package.json"),
            r#"{"scripts":{"dev":"vite --host 127.0.0.1","dev:reset":"wrangler d1 migrations apply DB --local"}}"#,
        )
        .expect("write package");
        let runtime = ScriptedRuntime {
            result: fake_result_with_message(
                "Use `npm run dev` for local development and `npm run dev:reset` to reset the local database.",
                Vec::new(),
            ),
        };
        let mut scope = ProjectSetupScope::new("p1", "wrangler-db-app");
        scope.workspace_roots = vec![path_string(repo.path())];
        let (sink, _rx) = broadcast::channel(1);

        let outcome = run(&runtime, &scope, sink).await.expect("recovered");

        assert_eq!(outcome.profile.reset_steps[0].command, "npm run dev:reset");
        assert_eq!(outcome.profile.reset_steps[0].stdin.as_deref(), Some("y\n"));
    }

    #[test]
    fn malformed_error_exposes_full_final_message() {
        let mut long_message =
            "The agent answered in prose without any usable local launch command. ".repeat(10);
        long_message.push_str("UNIQUE_FULL_FINAL_MESSAGE_TAIL");
        let err = lift_agent_result(
            &ProjectSetupScope::new("p1", "nope"),
            fake_result_with_message(long_message, Vec::new()),
        )
        .expect_err("malformed");
        let detail = err.to_string();
        assert!(detail.contains("full final message"));
        assert!(detail.contains("UNIQUE_FULL_FINAL_MESSAGE_TAIL"));
    }
}

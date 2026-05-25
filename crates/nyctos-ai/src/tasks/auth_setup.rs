//! Auth setup agent task.
//!
//! This is the agent-backed version of the "AI setup" button. It asks
//! an agent-loop runtime to inspect the project repository, identify the
//! app's own auth/session model, emit secret-safe auth profiles, and
//! record a verification summary tying those profiles back to source.

use std::time::Duration;

use nyctos_types::agent::{
    AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind, ExtractedAgentResult,
};
use nyctos_types::event::EventSink;
use nyctos_types::project::{
    AuthSetupVerification, AuthSetupVerificationStatus, ProjectAuthMode, ProjectAuthOwnedObject,
    ProjectAuthProfile,
};

use crate::runtime::AiRuntime;

pub const AUTH_SETUP_PROMPT_VERSION: &str = "phase24.auth_setup.v1";
pub const DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS: i64 = 2_000_000;
pub const DEFAULT_AUTH_SETUP_MAX_TURNS: u32 = 16;
pub const DEFAULT_AUTH_SETUP_TOOL_NAMES: &[&str] =
    &["Read", "Grep", "Bash", "record_auth_profile", "record_auth_verification"];

#[derive(Debug, Clone)]
pub struct AuthSetupScope {
    pub project_id: String,
    pub project_name: String,
    pub task_id: String,
    pub target_base_url: Option<String>,
    pub workspace_roots: Vec<String>,
    pub requested_roles: Vec<String>,
    pub seeded_objects: Vec<ProjectAuthOwnedObject>,
    pub existing_profiles: Vec<ProjectAuthProfile>,
    pub discovered_login_paths: Vec<String>,
    pub discovered_object_routes: Vec<String>,
    pub files_inspected: usize,
    pub run_cap_usd_micros: i64,
    pub max_turns: u32,
    pub max_wall_clock: Duration,
}

impl AuthSetupScope {
    pub fn new(project_id: impl Into<String>, project_name: impl Into<String>) -> Self {
        let project_id = project_id.into();
        Self {
            task_id: format!("auth-setup-{project_id}"),
            project_id,
            project_name: project_name.into(),
            target_base_url: None,
            workspace_roots: Vec::new(),
            requested_roles: Vec::new(),
            seeded_objects: Vec::new(),
            existing_profiles: Vec::new(),
            discovered_login_paths: Vec::new(),
            discovered_object_routes: Vec::new(),
            files_inspected: 0,
            run_cap_usd_micros: DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS,
            max_turns: DEFAULT_AUTH_SETUP_MAX_TURNS,
            max_wall_clock: Duration::from_secs(5 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthSetupOutcome {
    pub profiles: Vec<ProjectAuthProfile>,
    pub verification: AuthSetupVerification,
    pub login_paths: Vec<String>,
    pub object_routes: Vec<String>,
    pub final_message: String,
    pub turns: u32,
    pub spent_usd_micros: i64,
    pub prompt_version: String,
    pub metrics: AgentTraceMetrics,
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &AuthSetupScope,
    sink: EventSink,
) -> Result<AuthSetupOutcome, AiError> {
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.project_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };
    let result = runtime.agent_loop(task, budget, sink).await?;
    Ok(lift_agent_result(scope, result))
}

fn build_agent_task(scope: &AuthSetupScope) -> AgentTask {
    let workspace_roots = render_list(&scope.workspace_roots, "(no repo workspace roots found)");
    let requested_roles = render_list(&scope.requested_roles, "(none; infer app-native roles)");
    let existing_profiles = if scope.existing_profiles.is_empty() {
        "(none)".to_string()
    } else {
        scope
            .existing_profiles
            .iter()
            .map(|p| format!("- {}", p.role))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let seeded_objects = render_json_list(&scope.seeded_objects);
    let discovered_login_paths = render_list(&scope.discovered_login_paths, "(none)");
    let discovered_object_routes = render_list(&scope.discovered_object_routes, "(none)");
    let target = scope.target_base_url.as_deref().unwrap_or("(not set)");
    let max_secs = scope.max_wall_clock.as_secs();

    let system = format!(
        "You are nyctos's auth setup exploration agent.\n\
         Inspect the repository before emitting profiles. Do not invent roles, routes, or \
         credentials. Prefer roles and login/session flows that are clearly represented in the \
         codebase. Never output raw passwords, cookies, bearer tokens, or one-time codes; only \
         output env var names or secret references. Keep generated profiles specific to this repo."
    );

    let objective = format!(
        "Project: {project_name} ({project_id})\n\
         Target base URL: {target}\n\
         Workspace roots:\n{workspace_roots}\n\
         Requested roles:\n{requested_roles}\n\
         Existing profiles:\n{existing_profiles}\n\
         Seeded owned objects:\n{seeded_objects}\n\
         Static login hints from the pre-scan:\n{discovered_login_paths}\n\
         Static object-route hints from the pre-scan:\n{discovered_object_routes}\n\
         Pre-scan inspected files: {files_inspected}\n\
         Max turns: {max_turns}; max wall-clock seconds: {max_secs}\n\
         \n\
         Work:\n\
         1. Inspect source files for auth routes, login forms, session middleware, role checks, \
         seeded/test users, OTP/login-code flows, local dev-mail/mailbox routes, and object \
         ownership routes.\n\
         2. Emit one `record_auth_profile` JSON line for each useful role. Use the app's own role \
         names when they are visible. Use `user_a`/`user_b` only when the repo shows a same-role \
         ownership/IDOR workflow that needs two accounts.\n\
         3. Each profile should include `role`, `mode`, `label`, a repo-backed `login_url` or \
         other session source, env refs such as `login_email_env`, `username_env`, or \
         `password_env`, any `post_login_assertions`, and `owned_objects` when object routes are \
         visible. If the app uses email OTP/login codes and exposes a local dev-mail/mailbox UI \
         or API, use `mode\":\"otp_email_mailbox\"` and include an `otp_source` with \
         `kind\":\"mailbox\"`, `mailbox_url`, `email_env`, and a code `body_regex`.\n\
         4. Emit one `record_auth_verification` JSON line with `status` (`verified` or \
         `needs_review`), `checks`, and `warnings`, explaining how the profiles map back to code \
         and what still needs operator input.\n\
         \n\
         Example profile line:\n\
         {{\"tool\":\"record_auth_profile\",\"input\":{{\"role\":\"member\",\"mode\":\"ai_auto\",\
         \"login_url\":\"/login\",\"username_env\":\"NYCTOS_MEMBER_USERNAME\",\
         \"password_env\":\"NYCTOS_MEMBER_PASSWORD\",\"post_login_assertions\":[{{\"kind\":\"url_contains\",\
         \"value\":\"/dashboard\"}}],\"rationale\":\"member login route and dashboard assertion found\"}}}}\n\
         Example verification line:\n\
         {{\"tool\":\"record_auth_verification\",\"input\":{{\"status\":\"verified\",\
         \"checks\":[\"/login route found in src/routes.ts\"],\"warnings\":[]}}}}\n",
        project_name = scope.project_name,
        project_id = scope.project_id,
        target = target,
        workspace_roots = workspace_roots,
        requested_roles = requested_roles,
        existing_profiles = existing_profiles,
        seeded_objects = seeded_objects,
        discovered_login_paths = discovered_login_paths,
        discovered_object_routes = discovered_object_routes,
        files_inspected = scope.files_inspected,
        max_turns = scope.max_turns,
        max_secs = max_secs,
    );

    AgentTask {
        prompt_version: AUTH_SETUP_PROMPT_VERSION.to_string(),
        task_id: scope.task_id.clone(),
        system,
        objective,
        tools: DEFAULT_AUTH_SETUP_TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
        working_directory: scope.workspace_roots.first().cloned(),
        max_turns: scope.max_turns,
    }
}

fn lift_agent_result(scope: &AuthSetupScope, result: AgentResult) -> AuthSetupOutcome {
    let mut profiles = Vec::new();
    let mut verification: Option<AuthSetupVerification> = None;
    for extracted in &result.extracted {
        match extracted {
            ExtractedAgentResult::AuthProfileDiscovered { profile, .. } => {
                if let Some(profile) = finalize_profile(scope, profile.clone()) {
                    profiles.push(profile);
                }
            }
            ExtractedAgentResult::AuthSetupVerification { status, checks, warnings } => {
                verification = Some(agent_verification(status, checks.clone(), warnings.clone()));
            }
            _ => {}
        }
    }
    dedupe_profiles(&mut profiles);
    let login_paths = dedupe_strings(
        profiles
            .iter()
            .filter_map(|p| p.login_url.clone())
            .chain(scope.discovered_login_paths.clone())
            .collect(),
    );
    let object_routes = dedupe_strings(
        profiles
            .iter()
            .flat_map(|p| p.owned_objects.iter().filter_map(|o| o.route.clone()))
            .chain(scope.discovered_object_routes.clone())
            .collect(),
    );
    let verification = verification.unwrap_or_else(|| synthesized_verification(&profiles));
    let metrics = AgentTraceMetrics::from_agent_result(&result);
    AuthSetupOutcome {
        profiles,
        verification,
        login_paths,
        object_routes,
        final_message: result.final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        prompt_version: result.prompt_version,
        metrics,
    }
}

fn finalize_profile(
    scope: &AuthSetupScope,
    mut profile: ProjectAuthProfile,
) -> Option<ProjectAuthProfile> {
    profile.role = profile.role.trim().to_string();
    if profile.role.is_empty() || profile.role.eq_ignore_ascii_case("anonymous") {
        return None;
    }
    if profile.mode == ProjectAuthMode::Anonymous {
        profile.mode = ProjectAuthMode::AiAuto;
    }
    if profile.label.as_deref().is_none_or(|label| label.trim().is_empty()) {
        profile.label = Some(format!("AI setup {}", profile.role));
    }
    if profile.login_url.is_none() {
        profile.login_url = scope.discovered_login_paths.first().cloned();
    }
    if !has_auth_material(&profile) {
        let slug = env_role_slug(&profile.role);
        profile.username_env = Some(format!("NYCTOS_{slug}_USERNAME"));
        profile.password_env = Some(format!("NYCTOS_{slug}_PASSWORD"));
    }
    if profile.owned_objects.is_empty() {
        profile.owned_objects = scope.seeded_objects.clone();
    }
    Some(profile)
}

fn has_auth_material(profile: &ProjectAuthProfile) -> bool {
    profile.session_import_path.is_some()
        || profile.username_env.is_some()
        || profile.login_email_env.is_some()
        || profile.password_env.is_some()
        || profile.password_secret_ref.is_some()
        || profile.cookie_env.is_some()
        || profile.bearer_token_env.is_some()
        || !profile.headers.is_empty()
        || profile.custom_command.is_some()
}

fn agent_verification(
    status: &str,
    mut checks: Vec<String>,
    warnings: Vec<String>,
) -> AuthSetupVerification {
    if checks.is_empty() {
        checks.push("Agent completed repository auth exploration.".to_string());
    }
    let normalized = match status.trim().to_ascii_lowercase().as_str() {
        "verified" | "ok" | "passed" => AuthSetupVerificationStatus::Verified,
        "skipped" => AuthSetupVerificationStatus::Skipped,
        _ => AuthSetupVerificationStatus::NeedsReview,
    };
    let status =
        if warnings.is_empty() { normalized } else { AuthSetupVerificationStatus::NeedsReview };
    AuthSetupVerification { status, checks, warnings }
}

fn synthesized_verification(profiles: &[ProjectAuthProfile]) -> AuthSetupVerification {
    if profiles.is_empty() {
        return AuthSetupVerification {
            status: AuthSetupVerificationStatus::NeedsReview,
            checks: Vec::new(),
            warnings: vec!["Auth exploration agent did not return any profiles.".to_string()],
        };
    }
    let mut checks = vec![format!("Agent returned {} auth profile(s).", profiles.len())];
    let mut warnings = Vec::new();
    for profile in profiles {
        if profile.login_url.is_some() || profile.session_import_path.is_some() {
            checks.push(format!("{} has a login or session source.", profile.role));
        } else {
            warnings.push(format!("{} has no login_url or session_import_path.", profile.role));
        }
        if has_auth_material(profile) {
            checks.push(format!("{} uses env-backed auth material.", profile.role));
        } else {
            warnings.push(format!("{} has no auth material reference.", profile.role));
        }
    }
    AuthSetupVerification {
        status: if warnings.is_empty() {
            AuthSetupVerificationStatus::Verified
        } else {
            AuthSetupVerificationStatus::NeedsReview
        },
        checks,
        warnings,
    }
}

fn dedupe_profiles(profiles: &mut Vec<ProjectAuthProfile>) {
    let mut seen = Vec::<String>::new();
    profiles.retain(|profile| {
        let key = profile.role.to_ascii_lowercase();
        if seen.iter().any(|role| role == &key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || out.iter().any(|v: &String| v == trimmed) {
            continue;
        }
        out.push(trimmed.to_string());
    }
    out
}

fn render_list(values: &[String], empty: &str) -> String {
    if values.is_empty() {
        empty.to_string()
    } else {
        values.iter().map(|value| format!("- {value}")).collect::<Vec<_>>().join("\n")
    }
}

fn render_json_list<T: serde::Serialize>(values: &[T]) -> String {
    if values.is_empty() {
        return "(none)".to_string();
    }
    values
        .iter()
        .filter_map(|value| serde_json::to_string(value).ok())
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn env_role_slug(role: &str) -> String {
    let mut out = String::new();
    for ch in role.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let slug = out.trim_matches('_').to_string();
    if slug.is_empty() {
        "USER".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use nyctos_types::agent::{CostEstimate, Prompt, Response, TokenUsage};
    use nyctos_types::event::AgentEvent;
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
            assert!(task.objective.contains("record_auth_profile"));
            assert_eq!(task.working_directory.as_deref(), Some("/repo"));
            Ok(self.result.clone())
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            None
        }
    }

    fn fake_result(extracted: Vec<ExtractedAgentResult>) -> AgentResult {
        AgentResult {
            prompt_version: AUTH_SETUP_PROMPT_VERSION.to_string(),
            task_id: "auth-setup-p1".to_string(),
            model: "scripted".to_string(),
            final_message: "done".to_string(),
            turns: 2,
            usage: TokenUsage { input_tokens: 100, output_tokens: 20 },
            cache: None,
            cost_usd_micros: 123,
            extracted,
        }
    }

    #[tokio::test]
    async fn agent_output_becomes_secret_safe_profiles() {
        let mut scope = AuthSetupScope::new("p1", "repo app");
        scope.workspace_roots = vec!["/repo".to_string()];
        scope.discovered_login_paths = vec!["/auth/login".to_string()];
        scope.seeded_objects = vec![ProjectAuthOwnedObject {
            name: "project".to_string(),
            id: "project-a".to_string(),
            route: Some("/api/projects/{id}".to_string()),
            marker: None,
        }];
        let profile = ProjectAuthProfile {
            role: "member".to_string(),
            role_aliases: Vec::new(),
            mode: ProjectAuthMode::AiAuto,
            label: None,
            tenant: None,
            session_cache_ttl_seconds: None,
            session_import_path: None,
            login_url: None,
            username: None,
            username_env: None,
            login_email_env: None,
            password_env: None,
            password_secret_ref: None,
            cookie_env: None,
            bearer_token_env: None,
            headers: Vec::new(),
            otp_source: None,
            post_login_assertions: Vec::new(),
            post_login_assertion: None,
            custom_command: None,
            owned_objects: Vec::new(),
        };
        let rt = ScriptedRuntime {
            result: fake_result(vec![
                ExtractedAgentResult::AuthProfileDiscovered {
                    profile,
                    rationale: "route found".to_string(),
                },
                ExtractedAgentResult::AuthSetupVerification {
                    status: "verified".to_string(),
                    checks: vec!["/auth/login found".to_string()],
                    warnings: Vec::new(),
                },
            ]),
        };
        let (tx, _rx) = broadcast::channel::<AgentEvent>(4);
        let out = run(&rt, &scope, tx).await.expect("auth setup");

        assert_eq!(out.profiles.len(), 1);
        assert_eq!(out.profiles[0].role, "member");
        assert_eq!(out.profiles[0].login_url.as_deref(), Some("/auth/login"));
        assert_eq!(out.profiles[0].username_env.as_deref(), Some("NYCTOS_MEMBER_USERNAME"));
        assert_eq!(out.profiles[0].owned_objects[0].id, "project-a");
        assert_eq!(out.verification.status, AuthSetupVerificationStatus::Verified);
        assert_eq!(out.login_paths, vec!["/auth/login".to_string()]);
    }
}

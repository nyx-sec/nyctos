use std::path::PathBuf;
use std::sync::Arc;

use nyctos_ai::{
    run_auth_setup, AuthSetupScope, ClaudeCodeAdapter, CodexCliAdapter, InMemoryBudgetTracker,
    DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS,
};
use nyctos_api::{
    AuthSetupAgent, AuthSetupAgentError, AuthSetupAgentFuture, AuthSetupAgentOutput,
    AuthSetupAgentRequest,
};
use nyctos_core::{AiRuntime as ConfigAiRuntime, Config};
use nyctos_types::event::EventSink;
use tokio::sync::RwLock;

pub struct ConfiguredAuthSetupAgent {
    config: Arc<RwLock<Config>>,
    events: EventSink,
}

impl ConfiguredAuthSetupAgent {
    pub fn new(config: Arc<RwLock<Config>>, events: EventSink) -> Self {
        Self { config, events }
    }
}

impl AuthSetupAgent for ConfiguredAuthSetupAgent {
    fn explore<'a>(&'a self, req: AuthSetupAgentRequest) -> AuthSetupAgentFuture<'a> {
        Box::pin(async move {
            let config = self.config.read().await.clone();
            let runtime = build_agent_runtime(&config).await?;
            let mut scope = AuthSetupScope::new(req.project_id.clone(), req.project_name.clone());
            scope.target_base_url = req.target_base_url;
            scope.workspace_roots = req.workspace_roots.iter().map(path_to_string).collect();
            scope.requested_roles = req.requested_roles;
            scope.seeded_objects = req.seeded_objects;
            scope.existing_profiles = req.existing_profiles;
            scope.discovered_login_paths = req.static_login_paths;
            scope.discovered_object_routes = req.static_object_routes;
            scope.files_inspected = req.files_inspected;
            scope.run_cap_usd_micros = config
                .ai
                .exploration_run_cap_usd_micros_resolved(DEFAULT_AUTH_SETUP_RUN_CAP_USD_MICROS);
            let outcome = run_auth_setup(runtime.as_ref(), &scope, self.events.clone())
                .await
                .map_err(|err| AuthSetupAgentError::Failed(err.to_string()))?;
            let roles = outcome.profiles.iter().map(|profile| profile.role.clone()).collect();
            let message = auth_setup_agent_message(&outcome);
            Ok(AuthSetupAgentOutput {
                profiles: outcome.profiles,
                roles,
                login_paths: outcome.login_paths,
                object_routes: outcome.object_routes,
                files_inspected: scope.files_inspected,
                verification: outcome.verification,
                message,
            })
        })
    }
}

async fn build_agent_runtime(
    config: &Config,
) -> Result<Arc<dyn nyctos_ai::AiRuntime>, AuthSetupAgentError> {
    let tracker = Arc::new(InMemoryBudgetTracker::new());
    match config.ai.runtime {
        ConfigAiRuntime::ClaudeCode => {
            let mut adapter = ClaudeCodeAdapter::discover(tracker)
                .await
                .map_err(|err| AuthSetupAgentError::Unavailable(err.to_string()))?;
            if let Some(model) = &config.ai.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Ok(Arc::new(adapter))
        }
        ConfigAiRuntime::Codex => {
            let mut adapter = CodexCliAdapter::discover(tracker)
                .await
                .map_err(|err| AuthSetupAgentError::Unavailable(err.to_string()))?;
            if let Some(model) = &config.ai.model {
                adapter = adapter.with_default_model(model.clone());
            }
            Ok(Arc::new(adapter))
        }
        ConfigAiRuntime::Anthropic => Err(AuthSetupAgentError::Unavailable(
            "Anthropic API runtime does not support repository exploration agents yet".to_string(),
        )),
        ConfigAiRuntime::LocalLlm => Err(AuthSetupAgentError::Unavailable(
            "local-llm runtime does not support repository exploration agents yet".to_string(),
        )),
        ConfigAiRuntime::None => Err(AuthSetupAgentError::Unavailable(
            "no repository exploration runtime is configured".to_string(),
        )),
    }
}

fn path_to_string(path: &PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn auth_setup_agent_message(outcome: &nyctos_ai::AuthSetupOutcome) -> String {
    let profile_count = outcome.profiles.len();
    let status = match outcome.verification.status {
        nyctos_types::project::AuthSetupVerificationStatus::Verified => "verification passed",
        nyctos_types::project::AuthSetupVerificationStatus::NeedsReview => {
            "verification needs review"
        }
        nyctos_types::project::AuthSetupVerificationStatus::Skipped => "verification skipped",
    };
    format!("Auth exploration agent saved {profile_count} repo-specific role profile(s); {status}.")
}

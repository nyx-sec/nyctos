use std::path::PathBuf;
use std::sync::Arc;

use nyctos_ai::{run_project_setup, ProjectSetupScope, DEFAULT_PROJECT_SETUP_RUN_CAP_USD_MICROS};
use nyctos_api::{
    ProjectSetupAgent, ProjectSetupAgentError, ProjectSetupAgentFuture, ProjectSetupAgentOutput,
    ProjectSetupAgentRequest,
};
use nyctos_core::Config;
use nyctos_types::product::ProjectSetupVerificationStatus;
use tokio::sync::RwLock;

pub struct ConfiguredProjectSetupAgent {
    config: Arc<RwLock<Config>>,
    events: nyctos_types::event::EventSink,
}

impl ConfiguredProjectSetupAgent {
    pub fn new(config: Arc<RwLock<Config>>, events: nyctos_types::event::EventSink) -> Self {
        Self { config, events }
    }
}

impl ProjectSetupAgent for ConfiguredProjectSetupAgent {
    fn explore<'a>(&'a self, req: ProjectSetupAgentRequest) -> ProjectSetupAgentFuture<'a> {
        Box::pin(async move {
            let config = self.config.read().await.clone();
            let runtime = crate::auth_setup_ai::build_agent_runtime(&config)
                .await
                .map_err(|err| ProjectSetupAgentError::Unavailable(err.to_string()))?;
            let mut scope =
                ProjectSetupScope::new(req.project_id.clone(), req.project_name.clone());
            scope.target_base_url = req.target_base_url;
            scope.workspace_roots = req.workspace_roots.iter().map(path_to_string).collect();
            scope.existing_launch_profile = req.existing_launch_profile;
            scope.run_cap_usd_micros = config
                .ai
                .exploration_run_cap_usd_micros_resolved(DEFAULT_PROJECT_SETUP_RUN_CAP_USD_MICROS);
            let outcome = run_project_setup(runtime.as_ref(), &scope, self.events.clone())
                .await
                .map_err(|err| ProjectSetupAgentError::Failed(err.to_string()))?;
            let status = if outcome.warnings.is_empty() {
                ProjectSetupVerificationStatus::Verified
            } else {
                ProjectSetupVerificationStatus::NeedsReview
            };
            let message = project_setup_agent_message(&outcome);
            Ok(ProjectSetupAgentOutput {
                profile: outcome.profile,
                summary: outcome.summary,
                checks: outcome.checks,
                warnings: outcome.warnings,
                verification_status: status,
                message,
            })
        })
    }
}

fn path_to_string(path: &PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn project_setup_agent_message(outcome: &nyctos_ai::ProjectSetupOutcome) -> String {
    let warning_count = outcome.warnings.len();
    if warning_count == 0 {
        format!("Project setup agent prepared a launch profile: {}.", outcome.summary)
    } else {
        format!(
            "Project setup agent prepared a launch profile with {warning_count} warning(s): {}.",
            outcome.summary
        )
    }
}

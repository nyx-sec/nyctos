use std::path::PathBuf;
use std::sync::Arc;

use nyctos_ai::{run_seed_setup, SeedSetupScope, DEFAULT_SEED_SETUP_RUN_CAP_USD_MICROS};
use nyctos_api::{
    SeedSetupAgent, SeedSetupAgentError, SeedSetupAgentFuture, SeedSetupAgentOutput,
    SeedSetupAgentRequest,
};
use nyctos_core::Config;
use tokio::sync::RwLock;

pub struct ConfiguredSeedSetupAgent {
    config: Arc<RwLock<Config>>,
    events: nyctos_types::event::EventSink,
}

impl ConfiguredSeedSetupAgent {
    pub fn new(config: Arc<RwLock<Config>>, events: nyctos_types::event::EventSink) -> Self {
        Self { config, events }
    }
}

impl SeedSetupAgent for ConfiguredSeedSetupAgent {
    fn explore<'a>(&'a self, req: SeedSetupAgentRequest) -> SeedSetupAgentFuture<'a> {
        Box::pin(async move {
            let config = self.config.read().await.clone();
            let runtime = crate::auth_setup_ai::build_agent_runtime(&config)
                .await
                .map_err(|err| SeedSetupAgentError::Unavailable(err.to_string()))?;
            let mut scope = SeedSetupScope::new(req.project_id.clone(), req.project_name.clone());
            scope.target_base_url = req.target_base_url;
            scope.workspace_roots = req.workspace_roots.iter().map(path_to_string).collect();
            scope.launch_profile = req.launch_profile;
            scope.run_cap_usd_micros = config
                .ai
                .exploration_run_cap_usd_micros_resolved(DEFAULT_SEED_SETUP_RUN_CAP_USD_MICROS);
            let outcome = run_seed_setup(runtime.as_ref(), &scope, self.events.clone())
                .await
                .map_err(|err| SeedSetupAgentError::Failed(err.to_string()))?;
            let message = seed_setup_agent_message(&outcome);
            Ok(SeedSetupAgentOutput { plan: outcome.plan, message })
        })
    }
}

fn path_to_string(path: &PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn seed_setup_agent_message(outcome: &nyctos_ai::SeedSetupOutcome) -> String {
    let warning_count = outcome.plan.warnings.len();
    if warning_count == 0 {
        format!("Seed setup agent prepared fixtures: {}.", outcome.plan.summary)
    } else {
        format!(
            "Seed setup agent prepared fixtures with {warning_count} warning(s): {}.",
            outcome.plan.summary
        )
    }
}

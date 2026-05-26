use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nyx_agent_ai::{run_remediation, RemediationScope, DEFAULT_REMEDIATION_RUN_CAP_USD_MICROS};
use nyx_agent_api::{
    RemediationAgent, RemediationAgentError, RemediationAgentFuture, RemediationAgentOutput,
    RemediationAgentRequest, RemediationChangedFile,
};
use nyx_agent_core::Config;
use tokio::process::Command;
use tokio::sync::RwLock;

pub struct ConfiguredRemediationAgent {
    config: Arc<RwLock<Config>>,
    events: nyx_agent_types::event::EventSink,
}

impl ConfiguredRemediationAgent {
    pub fn new(config: Arc<RwLock<Config>>, events: nyx_agent_types::event::EventSink) -> Self {
        Self { config, events }
    }
}

impl RemediationAgent for ConfiguredRemediationAgent {
    fn fix<'a>(&'a self, req: RemediationAgentRequest) -> RemediationAgentFuture<'a> {
        Box::pin(async move {
            let config = self.config.read().await.clone();
            let runtime = crate::auth_setup_ai::build_agent_runtime(&config)
                .await
                .map_err(|err| RemediationAgentError::Unavailable(err.to_string()))?;
            let mut scope = RemediationScope::new(req.vulnerability.clone());
            scope.workspace_roots =
                req.workspace_roots.iter().map(|path| path_to_string(path)).collect();
            scope.run_cap_usd_micros = config
                .ai
                .exploration_run_cap_usd_micros_resolved(DEFAULT_REMEDIATION_RUN_CAP_USD_MICROS);
            let outcome = run_remediation(runtime.as_ref(), &scope, self.events.clone())
                .await
                .map_err(|err| RemediationAgentError::Failed(err.to_string()))?;
            let changed_files = collect_changed_files(&req.workspace_roots).await;
            Ok(RemediationAgentOutput {
                changed_files,
                summary: outcome.summary,
                final_message: outcome.final_message,
            })
        })
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

async fn collect_changed_files(roots: &[PathBuf]) -> Vec<RemediationChangedFile> {
    let mut out = Vec::new();
    for root in roots {
        let Some(status_output) =
            git_output(root, &["status", "--porcelain", "--untracked-files=normal"]).await
        else {
            continue;
        };
        if status_output.trim().is_empty() {
            continue;
        }
        let numstat = git_output(root, &["diff", "--numstat"]).await.unwrap_or_default();
        let stats = parse_numstat(&numstat);
        let repo =
            root.file_name().and_then(|name| name.to_str()).unwrap_or("workspace").to_string();
        for (raw_status, path) in parse_status(&status_output) {
            let (additions, deletions) = stats.get(&path).copied().unwrap_or((None, None));
            out.push(RemediationChangedFile {
                repo: repo.clone(),
                path,
                status: status_label(&raw_status).to_string(),
                additions,
                deletions,
            });
        }
    }
    out.sort_by(|a, b| a.repo.cmp(&b.repo).then_with(|| a.path.cmp(&b.path)));
    out.dedup_by(|a, b| a.repo == b.repo && a.path == b.path);
    out
}

async fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(root).args(args).output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_status(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .filter_map(|line| {
            if line.len() < 4 {
                return None;
            }
            let status = line.get(..2)?.to_string();
            let path = line.get(3..)?.trim().trim_matches('"');
            let path = path.rsplit(" -> ").next().unwrap_or(path).to_string();
            Some((status, path))
        })
        .collect()
}

fn parse_numstat(raw: &str) -> HashMap<String, (Option<i64>, Option<i64>)> {
    let mut out = HashMap::new();
    for line in raw.lines() {
        let mut parts = line.splitn(3, '\t');
        let additions = parse_numstat_cell(parts.next());
        let deletions = parse_numstat_cell(parts.next());
        let Some(path) = parts.next() else {
            continue;
        };
        out.insert(path.to_string(), (additions, deletions));
    }
    out
}

fn parse_numstat_cell(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

fn status_label(raw: &str) -> &'static str {
    if raw == "??" {
        return "added";
    }
    if raw.contains('D') {
        return "deleted";
    }
    if raw.contains('R') {
        return "renamed";
    }
    if raw.contains('A') {
        return "added";
    }
    if raw.contains('M') {
        return "modified";
    }
    if raw.contains('C') {
        return "copied";
    }
    "changed"
}

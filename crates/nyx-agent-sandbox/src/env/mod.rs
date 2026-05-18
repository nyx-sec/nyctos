//! Env-builder (Phase 20): detect docker-compose files across connected
//! repos, merge into a super-compose, spin up via `docker compose`, and
//! tear down at run completion.
//!
//! This phase is docker-compose only. Kubernetes + devcontainer
//! detection ships in a later release.
//!
//! Threat-model boundary. `EnvBuilder::up` refuses to start unless
//! `<state>/secrets/test.env` exists AND none of its lines match any of
//! the `prod-token` regexes in [`secrets`]. The intent is to prevent an
//! operator from accidentally pointing a sandboxed scan at production
//! credentials. Fail-closed: any match halts the run.

pub mod compose;
pub mod secrets;

pub use compose::{detect, merge, ComposeError, ComposeFile};
pub use secrets::{check, SecretsBundle, SecretsError};

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

const DEFAULT_DOCKER_TIMEOUT: Duration = Duration::from_secs(180);
const DOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// Failure modes that can block an env spin-up or tear-down.
#[derive(Debug, Error)]
pub enum EnvError {
    #[error(transparent)]
    Compose(#[from] ComposeError),
    #[error(transparent)]
    Secrets(#[from] SecretsError),
    #[error("`docker` binary not found on PATH; install Docker before running env-builder")]
    DockerMissing,
    #[error("`docker compose up` failed (exit {code:?}); stderr: {stderr}")]
    UpFailed { code: Option<i32>, stderr: String },
    #[error("`docker compose down` failed (exit {code:?}); stderr: {stderr}")]
    DownFailed { code: Option<i32>, stderr: String },
    #[error("`docker compose ps` failed (exit {code:?}); stderr: {stderr}")]
    PsFailed { code: Option<i32>, stderr: String },
    #[error("`docker compose logs` failed (exit {code:?}); stderr: {stderr}")]
    LogsFailed { code: Option<i32>, stderr: String },
    #[error("`docker compose ps` returned malformed JSON: {0}")]
    MalformedPs(#[source] serde_json::Error),
    #[error("docker subcommand timed out after {0:?}")]
    Timeout(Duration),
    #[error("io error invoking docker: {0}")]
    Io(#[from] std::io::Error),
}

/// A single repo entry the env-builder walks.
#[derive(Debug, Clone)]
pub struct RepoInput {
    pub name: String,
    pub root: PathBuf,
}

/// Per-service status reported by `docker compose ps --format json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceHealth {
    #[serde(rename = "Name", default)]
    pub container_name: String,
    #[serde(rename = "Service", default)]
    pub service: String,
    #[serde(rename = "State", default)]
    pub state: String,
    #[serde(rename = "Health", default)]
    pub health: String,
    #[serde(rename = "Status", default)]
    pub status: String,
}

/// Configuration for one env-build run.
#[derive(Debug, Clone)]
pub struct EnvBuilder {
    /// `docker` binary to invoke (defaults to whatever `which docker`
    /// finds at [`EnvBuilder::discover`] time).
    pub docker_binary: PathBuf,
    /// Workspace scratch directory the merged compose file is written
    /// into. Must already exist and be writable.
    pub workspace: PathBuf,
    /// Persistent state root; the secrets check resolves
    /// `<state_root>/secrets/test.env` from it.
    pub state_root: PathBuf,
    /// Project name passed to `docker compose --project-name`. The
    /// project name namespaces every container, volume, and network
    /// docker creates so a teardown does not collide with the
    /// operator's own running containers.
    pub project_name: String,
    /// Connected repos to walk for compose files. Repos with no
    /// compose file are silently skipped.
    pub repos: Vec<RepoInput>,
    /// Wall-clock cap on each docker subcommand. The `up --build` step
    /// can dominate spin-up latency; the default is generous.
    pub command_timeout: Duration,
}

impl EnvBuilder {
    /// Build with `docker` resolved from `$PATH`. Returns
    /// [`EnvError::DockerMissing`] if docker is not installed.
    pub fn discover(
        workspace: PathBuf,
        state_root: PathBuf,
        project_name: String,
        repos: Vec<RepoInput>,
    ) -> Result<Self, EnvError> {
        let docker = which_on_path("docker").ok_or(EnvError::DockerMissing)?;
        Ok(Self {
            docker_binary: docker,
            workspace,
            state_root,
            project_name,
            repos,
            command_timeout: DEFAULT_DOCKER_TIMEOUT,
        })
    }

    /// Spin the env up. Steps, in order:
    ///
    /// 1. Verify `<state>/secrets/test.env` exists and contains no prod
    ///    tokens. Fail-closed on any match.
    /// 2. Detect compose files across every connected repo.
    /// 3. Merge into `<workspace>/nyx-super-compose.yml`.
    /// 4. `docker compose --project-name <p> -f <super> --env-file <test.env> up -d --build`.
    /// 5. Capture per-service health via `docker compose ps --format json`.
    pub async fn up(&self) -> Result<RunningEnv, EnvError> {
        let secrets_bundle = check(&self.state_root)?;
        let compose_files = self.detect_compose_files();
        let super_compose = self.workspace.join("nyx-super-compose.yml");
        let services = merge(&compose_files, &super_compose)?;

        let mut cmd = self.compose_command(&super_compose, &secrets_bundle.path);
        cmd.arg("up").arg("-d").arg("--build");
        let outcome = run_command(cmd, self.command_timeout).await?;
        if !outcome.status_ok() {
            return Err(EnvError::UpFailed {
                code: outcome.exit_code,
                stderr: outcome.stderr_string(),
            });
        }

        let env = RunningEnv {
            docker_binary: self.docker_binary.clone(),
            super_compose,
            secrets_path: secrets_bundle.path.clone(),
            project_name: self.project_name.clone(),
            services,
            command_timeout: self.command_timeout,
            running: true,
        };
        Ok(env)
    }

    fn detect_compose_files(&self) -> Vec<ComposeFile> {
        let mut out = Vec::new();
        for repo in &self.repos {
            if let Some(f) = detect(&repo.root, &repo.name) {
                out.push(f);
            }
        }
        out
    }

    fn compose_command(&self, super_compose: &Path, env_file: &Path) -> Command {
        let mut cmd = Command::new(&self.docker_binary);
        cmd.arg("compose")
            .arg("--project-name")
            .arg(&self.project_name)
            .arg("-f")
            .arg(super_compose)
            .arg("--env-file")
            .arg(env_file);
        cmd
    }
}

/// A live docker-compose env. Drop without calling [`RunningEnv::down`]
/// only on error paths; the constructor stamps `running = true` and the
/// destructor logs a warning if it sees a still-running env on drop.
#[derive(Debug)]
pub struct RunningEnv {
    docker_binary: PathBuf,
    super_compose: PathBuf,
    secrets_path: PathBuf,
    project_name: String,
    services: Vec<String>,
    command_timeout: Duration,
    running: bool,
}

impl RunningEnv {
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    pub fn services(&self) -> &[String] {
        &self.services
    }

    pub fn super_compose_path(&self) -> &Path {
        &self.super_compose
    }

    /// Snapshot of `docker compose ps --format json` parsed as
    /// per-service health rows.
    pub async fn services_health(&self) -> Result<Vec<ServiceHealth>, EnvError> {
        let mut cmd = self.compose_command();
        cmd.arg("ps").arg("--format").arg("json");
        let outcome = run_command(cmd, self.command_timeout).await?;
        if !outcome.status_ok() {
            return Err(EnvError::PsFailed {
                code: outcome.exit_code,
                stderr: outcome.stderr_string(),
            });
        }
        parse_ps_json(&outcome.stdout)
    }

    /// `docker compose logs --no-color --timestamps <service>` snapshot
    /// for the named service. The plan calls for per-service log
    /// streams; the snapshot form is the safe minimum that the
    /// trace-viewer phase can upgrade to a live stream later.
    pub async fn service_logs(&self, service: &str) -> Result<Vec<u8>, EnvError> {
        let mut cmd = self.compose_command();
        cmd.arg("logs")
            .arg("--no-color")
            .arg("--timestamps")
            .arg("--no-log-prefix")
            .arg(service);
        let outcome = run_command(cmd, self.command_timeout).await?;
        if !outcome.status_ok() {
            return Err(EnvError::LogsFailed {
                code: outcome.exit_code,
                stderr: outcome.stderr_string(),
            });
        }
        Ok(outcome.stdout)
    }

    /// `docker compose down --volumes --remove-orphans`. Idempotent;
    /// safe to call after a prior error.
    pub async fn down(mut self) -> Result<(), EnvError> {
        let result = self.down_inner().await;
        self.running = false;
        result
    }

    async fn down_inner(&self) -> Result<(), EnvError> {
        let mut cmd = self.compose_command();
        cmd.arg("down").arg("--volumes").arg("--remove-orphans");
        let outcome = run_command(cmd, DOWN_TIMEOUT).await?;
        if !outcome.status_ok() {
            return Err(EnvError::DownFailed {
                code: outcome.exit_code,
                stderr: outcome.stderr_string(),
            });
        }
        Ok(())
    }

    fn compose_command(&self) -> Command {
        let mut cmd = Command::new(&self.docker_binary);
        cmd.arg("compose")
            .arg("--project-name")
            .arg(&self.project_name)
            .arg("-f")
            .arg(&self.super_compose)
            .arg("--env-file")
            .arg(&self.secrets_path);
        cmd
    }
}

impl Drop for RunningEnv {
    fn drop(&mut self) {
        if self.running {
            tracing::warn!(
                project = %self.project_name,
                "RunningEnv dropped without RunningEnv::down(); containers may leak"
            );
        }
    }
}

/// Parse `docker compose ps --format json`. Newer compose emits
/// NDJSON (one object per line); older releases emit a JSON array.
/// Tolerate both.
fn parse_ps_json(raw: &[u8]) -> Result<Vec<ServiceHealth>, EnvError> {
    let text = std::str::from_utf8(raw).unwrap_or("").trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.starts_with('[') {
        return serde_json::from_str::<Vec<ServiceHealth>>(text).map_err(EnvError::MalformedPs);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row: ServiceHealth = serde_json::from_str(line).map_err(EnvError::MalformedPs)?;
        out.push(row);
    }
    Ok(out)
}

#[derive(Debug)]
struct CommandOutcome {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CommandOutcome {
    fn status_ok(&self) -> bool {
        matches!(self.exit_code, Some(0))
    }
    fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

async fn run_command(mut cmd: Command, cap: Duration) -> Result<CommandOutcome, EnvError> {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let drain = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a?;
        b?;
        Ok::<_, std::io::Error>((out, err))
    };

    let waited = timeout(cap, async {
        let (out, err) = drain.await?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out, err))
    })
    .await;

    match waited {
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(EnvError::Timeout(cap))
        }
        Ok(Err(io)) => Err(EnvError::Io(io)),
        Ok(Ok((status, stdout, stderr))) => Ok(CommandOutcome {
            exit_code: status.code(),
            stdout,
            stderr,
        }),
    }
}

fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ps_json_ndjson() {
        let raw = b"{\"Name\":\"a_1\",\"Service\":\"a\",\"State\":\"running\",\"Health\":\"\",\"Status\":\"Up\"}\n{\"Name\":\"b_1\",\"Service\":\"b\",\"State\":\"running\",\"Health\":\"healthy\",\"Status\":\"Up\"}\n";
        let rows = parse_ps_json(raw).expect("parse");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].service, "a");
        assert_eq!(rows[1].health, "healthy");
    }

    #[test]
    fn parse_ps_json_array() {
        let raw = b"[{\"Name\":\"a_1\",\"Service\":\"a\",\"State\":\"running\",\"Health\":\"\",\"Status\":\"Up\"}]";
        let rows = parse_ps_json(raw).expect("parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service, "a");
    }

    #[test]
    fn parse_ps_json_empty() {
        let rows = parse_ps_json(b"").expect("parse empty");
        assert!(rows.is_empty());
    }
}

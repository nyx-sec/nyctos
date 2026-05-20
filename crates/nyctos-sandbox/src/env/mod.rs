//! Env-builder: detect docker-compose files across connected repos,
//! merge into a super-compose, spin up via `docker compose`, and tear
//! down at run completion.
//!
//! Project-scoped. One [`EnvBuilder`] instance operates over the repos
//! of a single [`Project`]. The super-compose filename embeds the
//! project name so two projects under the same workspace cannot
//! clobber each other, and the project's `target_base_url` /
//! `env_config` are stamped onto the merged compose document as
//! `x-nyx-*` extension keys for downstream tools to read.
//!
//! docker-compose only. Kubernetes + devcontainer detection ships in
//! a later release.
//!
//! Threat-model boundary. `EnvBuilder::up` refuses to start unless
//! `<state>/secrets/test.env` exists AND none of its lines match any of
//! the `prod-token` regexes in [`secrets`]. The intent is to prevent an
//! operator from accidentally pointing a sandboxed scan at production
//! credentials. Fail-closed: any match halts the run.

pub mod compose;
pub mod secrets;

pub use compose::{detect, merge, ComposeError, ComposeFile, ProjectOverrides};
pub use secrets::{check, SecretsBundle, SecretsError};

use std::path::{Path, PathBuf};
use std::time::Duration;

use nyctos_core::project::Project;
use serde::Deserialize;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

const DEFAULT_DOCKER_TIMEOUT: Duration = Duration::from_secs(180);
const DOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// Floor on the `docker compose` plugin version. `2.20` is the first
/// release that emits the `--format json` `docker compose ps` rows the
/// env-builder parses; older v2 releases fall back to a tab-separated
/// shape the [`parse_ps_json`] reader does not handle, and v1
/// `docker-compose` is missing the `docker compose ...` plugin
/// invocation surface entirely.
pub const MIN_COMPOSE_VERSION: &str = "2.20.0";

/// Probe outcome from `docker compose version --short`. Returned by
/// [`probe_compose_version`] so callers can log the resolved version
/// independently of the support gate.
#[derive(Debug, Clone)]
pub struct ComposeVersion {
    pub raw: String,
    pub parsed: semver::Version,
}

/// Failure modes that can block an env spin-up or tear-down.
#[derive(Debug, Error)]
pub enum EnvError {
    #[error(transparent)]
    Compose(#[from] ComposeError),
    #[error(transparent)]
    Secrets(#[from] SecretsError),
    #[error("`docker` binary not found on PATH; install Docker before running env-builder")]
    DockerMissing,
    /// The `docker compose` plugin is missing or older than the floor
    /// the env-builder requires. The reason field carries an
    /// operator-readable explanation (raw stderr, parse failure, or
    /// "saw 2.19, need >=2.20"-style summary).
    #[error("`docker compose` is unsupported: {reason}")]
    ComposeUnsupported { reason: String },
    #[error("`docker compose up` failed (exit {code:?}); stderr: {stderr}")]
    UpFailed { code: Option<i32>, stderr: String },
    /// Refuse to spin up against a compose project name that already
    /// exists on the host. Two builders sharing the name would see
    /// each other's containers and a subsequent [`RunningEnv::down`]
    /// would tear down both.
    #[error("docker compose project `{project}` is already in use; pick a different project name")]
    ProjectInUse { project: String },
    /// `docker compose ls --format json` failed or returned a body the
    /// parser could not read. The project-collision check fails closed
    /// rather than letting a malformed `ls` response wave through a
    /// collision.
    #[error("`docker compose ls` failed: {reason}")]
    LsFailed { reason: String },
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
    /// docker-compose project name. Always derived from
    /// [`Project::name`] in [`EnvBuilder::discover`] so a single
    /// operator project maps 1:1 to a `--project-name` namespace and
    /// teardown cannot collide with the operator's own containers.
    pub project_name: String,
    /// Optional target base URL the project points at; stamped onto
    /// the merged compose document as `x-nyx-target-base-url` so the
    /// trace-viewer and scanner can pick it up.
    pub target_base_url: Option<String>,
    /// Optional project-level env config (free-form JSON); stamped
    /// onto the merged compose document as `x-nyx-env-config` for
    /// downstream consumers.
    pub env_config: Option<serde_json::Value>,
    /// Connected repos to walk for compose files. Repos with no
    /// compose file are silently skipped.
    pub repos: Vec<RepoInput>,
    /// Wall-clock cap on each docker subcommand. The `up --build` step
    /// can dominate spin-up latency; the default is generous.
    pub command_timeout: Duration,
}

impl EnvBuilder {
    /// Build with `docker` resolved from `$PATH`. Returns
    /// [`EnvError::DockerMissing`] if docker is not installed and
    /// [`EnvError::ComposeUnsupported`] if the `docker compose` plugin
    /// is missing or older than [`MIN_COMPOSE_VERSION`]. The
    /// project's `name`, `target_base_url`, and `env_config` are
    /// captured and used to derive the docker-compose project name and
    /// to stamp `x-nyx-*` extension keys onto the merged compose.
    pub fn discover(
        workspace: PathBuf,
        state_root: PathBuf,
        project: &Project,
        repos: Vec<RepoInput>,
    ) -> Result<Self, EnvError> {
        let docker = which_on_path("docker").ok_or(EnvError::DockerMissing)?;
        probe_compose_version(&docker)?;
        Ok(Self {
            docker_binary: docker,
            workspace,
            state_root,
            project_name: project.name.clone(),
            target_base_url: project.target_base_url.clone(),
            env_config: project.env_config.clone(),
            repos,
            command_timeout: DEFAULT_DOCKER_TIMEOUT,
        })
    }

    /// Filename written into [`Self::workspace`]. Includes the project
    /// name so two builders sharing a workspace cannot clobber each
    /// other's super-compose.
    pub fn super_compose_filename(&self) -> String {
        format!("nyx-super-compose-{}.yml", sanitise_filename(&self.project_name))
    }

    /// Spin the env up. Steps, in order:
    ///
    /// 1. Verify `<state>/secrets/test.env` exists and contains no prod
    ///    tokens. Fail-closed on any match.
    /// 2. Detect compose files across every connected repo.
    /// 3. Merge into `<workspace>/nyx-super-compose-<project>.yml`,
    ///    folding project-level overrides into `x-nyx-*` extension keys.
    /// 4. `docker compose --project-name <p> -f <super> --env-file <test.env> up -d --build`.
    /// 5. Capture per-service health via `docker compose ps --format json`.
    pub async fn up(&self) -> Result<RunningEnv, EnvError> {
        let secrets_bundle = check(&self.state_root)?;
        let compose_files = self.detect_compose_files();
        let super_compose = self.workspace.join(self.super_compose_filename());
        let overrides = ProjectOverrides {
            target_base_url: self.target_base_url.as_deref(),
            env_config: self.env_config.as_ref(),
        };
        let services = merge(&compose_files, &super_compose, &overrides)?;

        // Refuse to start when a compose project with the same name is
        // already running on the host. Two builders that pick the same
        // name (e.g. pid recycle on default `nyx-env-<pid>`) would see
        // each other's containers and a later `down` would tear down
        // both. Run BEFORE `up --build` so we never half-start a colliding
        // project.
        self.refuse_if_project_in_use().await?;

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

    /// Run `docker compose ls --format json` and refuse with
    /// [`EnvError::ProjectInUse`] when the configured `project_name`
    /// already names a compose project on the host. Returns
    /// [`EnvError::LsFailed`] when the `ls` subcommand itself failed
    /// (so we do not silently allow a collision behind a flaky ls).
    pub async fn refuse_if_project_in_use(&self) -> Result<(), EnvError> {
        let mut cmd = Command::new(&self.docker_binary);
        cmd.arg("compose").arg("ls").arg("--all").arg("--format").arg("json");
        let outcome = run_command(cmd, self.command_timeout).await?;
        if !outcome.status_ok() {
            return Err(EnvError::LsFailed {
                reason: format!(
                    "`docker compose ls --all --format json` exited {code:?}: {stderr}",
                    code = outcome.exit_code,
                    stderr = outcome.stderr_string(),
                ),
            });
        }
        let names = parse_compose_ls_names(&outcome.stdout)?;
        if names.iter().any(|n| n == &self.project_name) {
            return Err(EnvError::ProjectInUse { project: self.project_name.clone() });
        }
        Ok(())
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

/// A live docker-compose env. Prefer [`RunningEnv::down`] for explicit
/// teardown so the caller can observe failures; the [`Drop`] impl is a
/// fallback that spawns a detached OS thread to run
/// `docker compose down --volumes --remove-orphans` for operator-cancel
/// and panic paths that bypass `down()`. The detached teardown is
/// best-effort and capped at [`DOWN_TIMEOUT`] wall-clock; failures are
/// logged via `tracing::warn!` but not surfaced to the caller.
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
        cmd.arg("logs").arg("--no-color").arg("--timestamps").arg("--no-log-prefix").arg(service);
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
        if !self.running {
            return;
        }
        // Operator-cancel and panic paths bypass `RunningEnv::down`.
        // Spawn a detached OS thread that runs a synchronous
        // `docker compose down --volumes --remove-orphans` so containers
        // do not leak past the dropped handle. Detached (not blocking)
        // because Drop runs on an arbitrary thread - possibly a tokio
        // worker we must not stall and possibly outside any runtime.
        // Best effort: log and move on if the subprocess cannot spawn.
        let docker_binary = self.docker_binary.clone();
        let super_compose = self.super_compose.clone();
        let secrets_path = self.secrets_path.clone();
        let project_name = self.project_name.clone();
        let _ = std::thread::Builder::new()
            .name(format!("nyx-env-down-{project_name}"))
            .spawn(move || {
                let mut cmd = std::process::Command::new(&docker_binary);
                cmd.arg("compose")
                    .arg("--project-name")
                    .arg(&project_name)
                    .arg("-f")
                    .arg(&super_compose)
                    .arg("--env-file")
                    .arg(&secrets_path)
                    .arg("down")
                    .arg("--volumes")
                    .arg("--remove-orphans")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            project = %project_name,
                            "docker compose down failed to spawn on RunningEnv drop; containers may leak"
                        );
                        return;
                    }
                };
                let deadline = std::time::Instant::now() + DOWN_TIMEOUT;
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => return,
                        Ok(None) => {
                            if std::time::Instant::now() >= deadline {
                                let _ = child.kill();
                                let _ = child.wait();
                                tracing::warn!(
                                    project = %project_name,
                                    timeout_secs = DOWN_TIMEOUT.as_secs(),
                                    "docker compose down timed out on RunningEnv drop; killed subprocess"
                                );
                                return;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                project = %project_name,
                                "docker compose down wait errored on RunningEnv drop"
                            );
                            return;
                        }
                    }
                }
            });
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

/// Parse `docker compose ls --format json`. Modern compose emits a
/// JSON array of `{Name, Status, ConfigFiles}` objects; older v2
/// releases also emit NDJSON in some packagings. Tolerates both and
/// returns the `Name` fields. An empty body (no projects on the host)
/// returns an empty vec.
fn parse_compose_ls_names(raw: &[u8]) -> Result<Vec<String>, EnvError> {
    #[derive(Deserialize)]
    struct ComposeLsRow {
        #[serde(rename = "Name", default)]
        name: String,
    }
    let text = std::str::from_utf8(raw).unwrap_or("").trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<ComposeLsRow> = if text.starts_with('[') {
        serde_json::from_str(text).map_err(|e| EnvError::LsFailed {
            reason: format!("malformed `docker compose ls` array: {e}"),
        })?
    } else {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let row: ComposeLsRow = serde_json::from_str(line).map_err(|e| EnvError::LsFailed {
                reason: format!("malformed `docker compose ls` ndjson row: {e}"),
            })?;
            out.push(row);
        }
        out
    };
    Ok(rows.into_iter().map(|r| r.name).filter(|n| !n.is_empty()).collect())
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
        Ok(Ok((status, stdout, stderr))) => {
            Ok(CommandOutcome { exit_code: status.code(), stdout, stderr })
        }
    }
}

/// Reduce an arbitrary project name to characters safe inside a
/// filename: ascii alphanumerics pass through; everything else becomes
/// `_`. An empty / all-punctuation name falls back to `project`.
fn sanitise_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '_') {
        "project".to_string()
    } else {
        out
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

/// Run `<docker> compose version --short` and return the parsed
/// [`ComposeVersion`]. Refuses with [`EnvError::ComposeUnsupported`]
/// when:
///
/// - the plugin is absent (`docker compose` is not a docker command),
/// - the output cannot be parsed as a semver triple, or
/// - the resolved version is below [`MIN_COMPOSE_VERSION`].
///
/// Uses a synchronous subprocess so the call is safe to make from the
/// sync [`EnvBuilder::discover`] entry point. The whole probe takes
/// well under a second on a healthy host.
pub fn probe_compose_version(docker: &Path) -> Result<ComposeVersion, EnvError> {
    let output = std::process::Command::new(docker)
        .arg("compose")
        .arg("version")
        .arg("--short")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(EnvError::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(EnvError::ComposeUnsupported {
            reason: format!(
                "`docker compose version --short` exited non-zero (status {status:?}); stderr: {stderr}",
                status = output.status.code(),
            ),
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    parse_and_gate_compose_version(&raw)
}

/// Parse the stdout of `docker compose version --short` and apply the
/// [`MIN_COMPOSE_VERSION`] floor. Split out so it can be unit-tested
/// against the assorted shapes the plugin has emitted historically.
fn parse_and_gate_compose_version(raw: &str) -> Result<ComposeVersion, EnvError> {
    // `--short` is documented to print only the version string, but
    // older builds occasionally prepended a `v` (e.g. `v2.27.1`). Strip
    // it before parsing so semver does not refuse the leading char.
    let trimmed = raw.trim();
    let candidate = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let parsed = match semver::Version::parse(candidate) {
        Ok(v) => v,
        Err(e) => {
            return Err(EnvError::ComposeUnsupported {
                reason: format!("could not parse compose version `{trimmed}`: {e}"),
            });
        }
    };
    let min = semver::Version::parse(MIN_COMPOSE_VERSION)
        .expect("MIN_COMPOSE_VERSION is a valid semver triple");
    if parsed < min {
        return Err(EnvError::ComposeUnsupported {
            reason: format!(
                "docker compose {parsed} is below the {min} floor required by the env-builder"
            ),
        });
    }
    Ok(ComposeVersion { raw: trimmed.to_string(), parsed })
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

    #[test]
    fn parse_and_gate_compose_version_accepts_floor() {
        let v = parse_and_gate_compose_version("2.20.0").expect("floor must be accepted");
        assert_eq!(v.raw, "2.20.0");
        assert_eq!(v.parsed.major, 2);
        assert_eq!(v.parsed.minor, 20);
    }

    #[test]
    fn parse_and_gate_compose_version_accepts_newer() {
        let v = parse_and_gate_compose_version("2.27.1").expect("newer must be accepted");
        assert_eq!(v.parsed.minor, 27);
    }

    #[test]
    fn parse_and_gate_compose_version_strips_v_prefix() {
        let v = parse_and_gate_compose_version("v2.27.1").expect("`v` prefix must be tolerated");
        assert_eq!(v.parsed.minor, 27);
    }

    #[test]
    fn parse_and_gate_compose_version_refuses_old_v2() {
        let err = parse_and_gate_compose_version("2.19.0").expect_err("below-floor must refuse");
        match err {
            EnvError::ComposeUnsupported { reason } => {
                assert!(reason.contains("2.19"), "reason must name the seen version: {reason}");
                assert!(reason.contains("2.20"), "reason must name the floor: {reason}");
            }
            other => panic!("expected ComposeUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn parse_and_gate_compose_version_refuses_v1_legacy_shape() {
        // `docker-compose --short` on the legacy v1 binary prints
        // `1.29.2`; the modern `docker compose version --short` shape
        // is the same but the floor check still rejects it.
        let err = parse_and_gate_compose_version("1.29.2").expect_err("v1 must refuse");
        assert!(matches!(err, EnvError::ComposeUnsupported { .. }));
    }

    #[test]
    fn parse_compose_ls_names_array() {
        let raw = br#"[{"Name":"alpha","Status":"running(1)","ConfigFiles":"/a.yml"},{"Name":"beta","Status":"exited","ConfigFiles":"/b.yml"}]"#;
        let names = parse_compose_ls_names(raw).expect("parse");
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn parse_compose_ls_names_ndjson() {
        let raw = b"{\"Name\":\"alpha\",\"Status\":\"running(1)\"}\n{\"Name\":\"beta\",\"Status\":\"exited\"}\n";
        let names = parse_compose_ls_names(raw).expect("parse");
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn parse_compose_ls_names_empty() {
        let names = parse_compose_ls_names(b"").expect("parse empty");
        assert!(names.is_empty());
        let names = parse_compose_ls_names(b"[]").expect("parse empty array");
        assert!(names.is_empty());
    }

    #[test]
    fn parse_compose_ls_names_drops_blank_rows() {
        let raw = br#"[{"Name":""},{"Name":"real"}]"#;
        let names = parse_compose_ls_names(raw).expect("parse");
        assert_eq!(names, vec!["real".to_string()]);
    }

    #[test]
    fn parse_and_gate_compose_version_refuses_garbage() {
        let err = parse_and_gate_compose_version("not-a-version")
            .expect_err("non-semver string must refuse");
        match err {
            EnvError::ComposeUnsupported { reason } => {
                assert!(reason.contains("not-a-version"), "reason must echo the input: {reason}");
            }
            other => panic!("expected ComposeUnsupported, got {other:?}"),
        }
    }
}

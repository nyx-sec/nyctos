use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nyctos_core::store::{EnvironmentRunRecord, ProjectLaunchProfile};
use nyctos_core::{now_epoch_ms, Project, StateDir, Store, WorkspaceHandle};
use nyctos_sandbox::env::{EnvBuilder, RepoInput, RunningEnv};
use nyctos_types::event::{AgentEvent, EventSink, RunEvent};
use nyctos_types::product::{LaunchHealthCheck, LaunchStep};
use tokio::fs::OpenOptions;
use tokio::process::{Child, Command};

#[derive(Debug)]
pub struct LaunchContext<'a> {
    pub store: &'a Store,
    pub state_dir: &'a StateDir,
    pub project: &'a Project,
    pub run_id: &'a str,
    pub profile: &'a ProjectLaunchProfile,
    pub workspaces: &'a HashMap<String, WorkspaceHandle>,
    pub events: EventSink,
}

#[derive(Debug)]
pub struct RunningProjectEnvironment {
    pub environment_run_id: String,
    pub target_urls: Vec<String>,
    mode: RunningMode,
    stop_steps: Vec<LaunchStep>,
    logs_dir: PathBuf,
    store: Store,
    events: EventSink,
    run_id: String,
    project_id: String,
}

#[derive(Debug)]
enum RunningMode {
    Custom { children: Vec<Child> },
    Compose { env: RunningEnv },
    None,
}

#[async_trait]
pub trait LaunchProfileRunner {
    async fn start(&self, ctx: LaunchContext<'_>) -> anyhow::Result<RunningProjectEnvironment>;
}

#[derive(Debug, Default)]
pub struct ConservativeLaunchProfileRunner;

#[async_trait]
impl LaunchProfileRunner for ConservativeLaunchProfileRunner {
    async fn start(&self, ctx: LaunchContext<'_>) -> anyhow::Result<RunningProjectEnvironment> {
        start_launch_profile(ctx).await
    }
}

async fn start_launch_profile(ctx: LaunchContext<'_>) -> anyhow::Result<RunningProjectEnvironment> {
    let env_id = format!("env-{}-{}", ctx.run_id, now_epoch_ms());
    let logs_dir = ctx.state_dir.logs().join("environment").join(ctx.run_id);
    std::fs::create_dir_all(&logs_dir)?;
    let target_urls = ctx.profile.target_urls.clone();
    let mut rec = EnvironmentRunRecord {
        id: env_id.clone(),
        run_id: ctx.run_id.to_string(),
        project_id: ctx.project.id.as_str().to_string(),
        profile_id: ctx.profile.id.clone(),
        status: "Pending".to_string(),
        started_at: Some(now_epoch_ms()),
        ready_at: None,
        stopped_at: None,
        target_urls: target_urls.clone(),
        health: None,
        logs_dir: Some(logs_dir.to_string_lossy().to_string()),
        teardown: None,
    };
    ctx.store.environment_runs().insert(&rec).await?;
    emit_env(
        &ctx.events,
        ctx.run_id,
        ctx.project.id.as_str(),
        &env_id,
        "Pending",
        Some("app launch queued"),
        &target_urls,
    );

    let start_result = match ctx.profile.mode.as_str() {
        "already-running" => use_existing_app(&ctx, &env_id, &logs_dir).await,
        "docker-compose" if ctx.profile.start_steps.is_empty() => {
            start_compose(&ctx, &env_id, &logs_dir).await
        }
        _ => start_custom(&ctx, &env_id, &logs_dir).await,
    };

    match start_result {
        Ok((mode, health)) => {
            rec.status = "Ready".to_string();
            rec.ready_at = Some(now_epoch_ms());
            rec.health = Some(health.clone());
            ctx.store
                .environment_runs()
                .update_lifecycle(&env_id, "Ready", rec.ready_at, None, Some(&health), None)
                .await?;
            emit_env(
                &ctx.events,
                ctx.run_id,
                ctx.project.id.as_str(),
                &env_id,
                "Ready",
                Some("app is reachable"),
                &target_urls,
            );
            Ok(RunningProjectEnvironment {
                environment_run_id: env_id,
                target_urls,
                mode,
                stop_steps: ctx.profile.stop_steps.clone(),
                logs_dir,
                store: ctx.store.clone(),
                events: ctx.events,
                run_id: ctx.run_id.to_string(),
                project_id: ctx.project.id.as_str().to_string(),
            })
        }
        Err(err) => {
            let health = serde_json::json!({ "ok": false, "error": err.to_string() });
            ctx.store
                .environment_runs()
                .update_lifecycle(&env_id, "Failed", None, None, Some(&health), None)
                .await?;
            emit_env(
                &ctx.events,
                ctx.run_id,
                ctx.project.id.as_str(),
                &env_id,
                "Failed",
                Some(err.to_string()),
                &target_urls,
            );
            Err(err)
        }
    }
}

async fn start_custom(
    ctx: &LaunchContext<'_>,
    env_id: &str,
    logs_dir: &Path,
) -> anyhow::Result<(RunningMode, serde_json::Value)> {
    if !ctx.profile.build_steps.is_empty() {
        ctx.store
            .environment_runs()
            .update_lifecycle(env_id, "SettingUp", None, None, None, None)
            .await?;
        emit_env(
            &ctx.events,
            ctx.run_id,
            ctx.project.id.as_str(),
            env_id,
            "SettingUp",
            Some("running setup commands"),
            &ctx.profile.target_urls,
        );
        for (index, step) in ctx.profile.build_steps.iter().enumerate() {
            run_step_to_completion(step, ctx.workspaces, logs_dir, "build", index).await?;
        }
    }

    let mut children = Vec::new();
    if !ctx.profile.start_steps.is_empty() {
        ctx.store
            .environment_runs()
            .update_lifecycle(env_id, "Starting", None, None, None, None)
            .await?;
        emit_env(
            &ctx.events,
            ctx.run_id,
            ctx.project.id.as_str(),
            env_id,
            "Starting",
            Some("starting app"),
            &ctx.profile.target_urls,
        );
        for (index, step) in ctx.profile.start_steps.iter().enumerate() {
            children.push(spawn_start_step(step, ctx.workspaces, logs_dir, index).await?);
        }
    } else {
        ctx.store
            .environment_runs()
            .update_lifecycle(env_id, "Checking", None, None, None, None)
            .await?;
        emit_env(
            &ctx.events,
            ctx.run_id,
            ctx.project.id.as_str(),
            env_id,
            "Checking",
            Some("checking app URL"),
            &ctx.profile.target_urls,
        );
    }
    let health = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    Ok((RunningMode::Custom { children }, health))
}

async fn use_existing_app(
    ctx: &LaunchContext<'_>,
    env_id: &str,
    logs_dir: &Path,
) -> anyhow::Result<(RunningMode, serde_json::Value)> {
    ctx.store
        .environment_runs()
        .update_lifecycle(env_id, "Checking", None, None, None, None)
        .await?;
    emit_env(
        &ctx.events,
        ctx.run_id,
        ctx.project.id.as_str(),
        env_id,
        "Checking",
        Some("checking app URL"),
        &ctx.profile.target_urls,
    );
    let health = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    Ok((RunningMode::None, health))
}

async fn start_compose(
    ctx: &LaunchContext<'_>,
    _env_id: &str,
    logs_dir: &Path,
) -> anyhow::Result<(RunningMode, serde_json::Value)> {
    let repos: Vec<RepoInput> = ctx
        .workspaces
        .values()
        .map(|w| RepoInput { name: w.name().to_string(), root: w.workspace().to_path_buf() })
        .collect();
    let builder = EnvBuilder::discover(
        logs_dir.to_path_buf(),
        ctx.state_dir.root().to_path_buf(),
        ctx.project,
        repos,
    )?;
    let env = builder.up().await?;
    let services = env.services_health().await.unwrap_or_default();
    let readiness = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    let health = serde_json::json!({
        "ok": true,
        "mode": "docker-compose",
        "project": env.project_name(),
        "readiness": readiness,
        "services": services.iter().map(|s| serde_json::json!({
            "service": s.service,
            "state": s.state,
            "health": s.health,
            "status": s.status,
        })).collect::<Vec<_>>(),
    });
    Ok((RunningMode::Compose { env }, health))
}

impl RunningProjectEnvironment {
    pub async fn stop(mut self) -> anyhow::Result<()> {
        let started = now_epoch_ms();
        let mut errors = Vec::new();
        for (index, step) in self.stop_steps.iter().enumerate() {
            if let Err(err) =
                run_step_to_completion(step, &HashMap::new(), &self.logs_dir, "stop", index).await
            {
                errors.push(err.to_string());
            }
        }
        match &mut self.mode {
            RunningMode::Custom { children } => {
                for child in children {
                    if let Err(err) = child.kill().await {
                        errors.push(format!("kill start process: {err}"));
                    }
                    let _ = child.wait().await;
                }
            }
            RunningMode::Compose { .. } => {
                if let RunningMode::Compose { env } =
                    std::mem::replace(&mut self.mode, RunningMode::None)
                {
                    if let Err(err) = env.down().await {
                        errors.push(err.to_string());
                    }
                }
            }
            RunningMode::None => {}
        }
        let teardown = serde_json::json!({
            "ok": errors.is_empty(),
            "errors": errors,
            "duration_ms": now_epoch_ms() - started,
        });
        let status = if teardown["ok"].as_bool().unwrap_or(false) { "Stopped" } else { "Failed" };
        self.store
            .environment_runs()
            .update_lifecycle(
                &self.environment_run_id,
                status,
                None,
                Some(now_epoch_ms()),
                None,
                Some(&teardown),
            )
            .await?;
        emit_env(
            &self.events,
            &self.run_id,
            &self.project_id,
            &self.environment_run_id,
            status,
            Some("environment teardown complete"),
            &self.target_urls,
        );
        if status == "Failed" {
            anyhow::bail!("environment teardown failed: {teardown}");
        }
        Ok(())
    }
}

async fn run_step_to_completion(
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
    phase: &str,
    index: usize,
) -> anyhow::Result<()> {
    let stdout_path = logs_dir.join(format!("{phase}-{index}-stdout.log"));
    let stderr_path = logs_dir.join(format!("{phase}-{index}-stderr.log"));
    let mut child = command_for_step(step, workspaces)
        .stdout(Stdio::from(std::fs::File::create(stdout_path)?))
        .stderr(Stdio::from(std::fs::File::create(stderr_path)?))
        .stdin(Stdio::null())
        .spawn()?;
    let timeout = Duration::from_secs(step.timeout_seconds.unwrap_or(300));
    let status = tokio::time::timeout(timeout, child.wait()).await??;
    if !status.success() {
        anyhow::bail!(
            "{} failed: `{}` exited with status {status}",
            step_label(phase),
            step.command
        );
    }
    Ok(())
}

fn step_label(phase: &str) -> &'static str {
    match phase {
        "build" => "setup command",
        "health" => "readiness command",
        "stop" => "stop command",
        _ => "command",
    }
}

async fn spawn_start_step(
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
    index: usize,
) -> anyhow::Result<Child> {
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join(format!("start-{index}-stdout.log")))
        .await?
        .into_std()
        .await;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join(format!("start-{index}-stderr.log")))
        .await?
        .into_std()
        .await;
    let child = command_for_step(step, workspaces)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

fn command_for_step(step: &LaunchStep, workspaces: &HashMap<String, WorkspaceHandle>) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-lc").arg(&step.command);
    if let Some(dir) = working_dir_for_step(step, workspaces) {
        cmd.current_dir(dir);
    }
    cmd
}

fn working_dir_for_step(
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> Option<PathBuf> {
    let base = step
        .repo_name
        .as_deref()
        .and_then(|name| workspaces.get(name))
        .map(|w| w.workspace().to_path_buf());
    match (base, step.working_directory.as_deref()) {
        (Some(base), Some(rel)) => Some(resolve_working_dir(&base, rel)),
        (Some(base), None) => Some(base),
        (None, Some(dir)) => Some(PathBuf::from(dir)),
        (None, None) => None,
    }
}

fn resolve_working_dir(base: &Path, dir: &str) -> PathBuf {
    let path = PathBuf::from(dir);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

async fn wait_for_health(
    checks: &[LaunchHealthCheck],
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    if checks.is_empty() {
        return Ok(serde_json::json!({ "ok": true, "checks": [] }));
    }
    let mut results = Vec::new();
    for (index, check) in checks.iter().enumerate() {
        let started = Instant::now();
        let timeout = Duration::from_secs(check.timeout_seconds.unwrap_or(60));
        let result = match check.kind.as_str() {
            "http" => wait_for_http(check.url.as_deref(), timeout).await,
            "command" => match &check.command {
                Some(step) => run_step_to_completion(step, workspaces, logs_dir, "health", index)
                    .await
                    .map(|_| serde_json::json!({"ok": true, "kind": "command"})),
                None => Err(anyhow::anyhow!("command health check is missing command")),
            },
            other => Err(anyhow::anyhow!("unsupported health check kind `{other}`")),
        };
        match result {
            Ok(value) => results.push(value),
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "readiness check failed after {}ms: {err}",
                    started.elapsed().as_millis()
                ));
            }
        }
    }
    Ok(serde_json::json!({ "ok": true, "checks": results }))
}

async fn wait_for_profile_health(
    profile: &ProjectLaunchProfile,
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    if profile.health_checks.is_empty() {
        let checks: Vec<LaunchHealthCheck> = profile
            .target_urls
            .iter()
            .map(|url| LaunchHealthCheck {
                kind: "http".to_string(),
                url: Some(url.clone()),
                host: None,
                port: None,
                command: None,
                timeout_seconds: Some(60),
            })
            .collect();
        return wait_for_health(&checks, workspaces, logs_dir).await;
    }
    wait_for_health(&profile.health_checks, workspaces, logs_dir).await
}

async fn wait_for_http(url: Option<&str>, timeout: Duration) -> anyhow::Result<serde_json::Value> {
    let url = url.ok_or_else(|| anyhow::anyhow!("http health check is missing URL"))?;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    while Instant::now() < deadline {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                return Ok(serde_json::json!({
                    "ok": true,
                    "kind": "http",
                    "url": url,
                    "status": resp.status().as_u16(),
                }));
            }
            Ok(resp) => {
                last_error = Some(format!("status {}", resp.status()));
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(anyhow::anyhow!(
        "http health check `{}` timed out: {}",
        url,
        last_error.unwrap_or_else(|| "no response".to_string())
    ))
}

fn emit_env(
    events: &EventSink,
    run_id: &str,
    project_id: &str,
    environment_run_id: &str,
    status: &str,
    message: Option<impl Into<String>>,
    target_urls: &[String],
) {
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::EnvironmentStatus {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            environment_run_id: environment_run_id.to_string(),
            status: status.to_string(),
            message: message.map(Into::into),
            target_urls: target_urls.to_vec(),
            ts_ms: now_epoch_ms(),
        },
    });
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nyctos_core::store::{EnvironmentRunRecord, ProjectLaunchProfile};
use nyctos_core::{now_epoch_ms, Project, StateDir, Store, WorkspaceHandle};
use nyctos_sandbox::env::{EnvBuilder, RepoInput, RunningEnv};
use nyctos_types::event::{AgentEvent, EventSink, RunEvent};
use nyctos_types::product::{LaunchEnvRef, LaunchHealthCheck, LaunchStep};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
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
    seed_steps: Vec<LaunchStep>,
    reset_steps: Vec<LaunchStep>,
    env_refs: Vec<LaunchEnvRef>,
    logs_dir: PathBuf,
    store: Store,
    events: EventSink,
    run_id: String,
    project_id: String,
    workspaces: HashMap<String, WorkspaceHandle>,
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
                seed_steps: ctx.profile.seed_steps.clone(),
                reset_steps: ctx.profile.reset_steps.clone(),
                env_refs: ctx.profile.env_refs.clone(),
                logs_dir,
                store: ctx.store.clone(),
                events: ctx.events,
                run_id: ctx.run_id.to_string(),
                project_id: ctx.project.id.as_str().to_string(),
                workspaces: ctx.workspaces.clone(),
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
            run_step_to_completion(
                step,
                &ctx.profile.env_refs,
                ctx.workspaces,
                logs_dir,
                "build",
                index,
            )
            .await?;
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
            children.push(
                spawn_start_step(step, &ctx.profile.env_refs, ctx.workspaces, logs_dir, index)
                    .await?,
            );
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
    let _ = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "seed", &ctx.profile.seed_steps)
        .await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "login", &ctx.profile.login_steps)
        .await?;
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
    let _ = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "seed", &ctx.profile.seed_steps)
        .await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "login", &ctx.profile.login_steps)
        .await?;
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
    let _ = wait_for_profile_health(ctx.profile, ctx.workspaces, logs_dir).await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "seed", &ctx.profile.seed_steps)
        .await?;
    run_profile_hooks(ctx.profile, ctx.workspaces, logs_dir, "login", &ctx.profile.login_steps)
        .await?;
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
    pub fn seed_supported(&self) -> bool {
        !self.seed_steps.is_empty() || !matches!(self.mode, RunningMode::None)
    }

    pub fn reset_supported(&self) -> bool {
        !self.reset_steps.is_empty() || matches!(self.mode, RunningMode::Compose { .. })
    }

    pub async fn reset_after_state_change(&mut self) -> anyhow::Result<bool> {
        emit_env(
            &self.events,
            &self.run_id,
            &self.project_id,
            &self.environment_run_id,
            "Resetting",
            Some("resetting environment after state-changing verification probe"),
            &self.target_urls,
        );
        match &mut self.mode {
            RunningMode::Compose { env } => {
                env.reset().await?;
                for (index, step) in self.reset_steps.iter().enumerate() {
                    run_step_to_completion(
                        step,
                        &self.env_refs,
                        &self.workspaces,
                        &self.logs_dir,
                        "reset",
                        index,
                    )
                    .await?;
                }
                let health = env.services_health().await.unwrap_or_default();
                let reset = serde_json::json!({
                    "ok": true,
                    "mode": "docker-compose",
                    "services": health.iter().map(|s| serde_json::json!({
                        "service": s.service,
                        "state": s.state,
                        "health": s.health,
                        "status": s.status,
                    })).collect::<Vec<_>>(),
                });
                self.store
                    .environment_runs()
                    .update_lifecycle(
                        &self.environment_run_id,
                        "Ready",
                        None,
                        None,
                        Some(&reset),
                        None,
                    )
                    .await?;
                emit_env(
                    &self.events,
                    &self.run_id,
                    &self.project_id,
                    &self.environment_run_id,
                    "Ready",
                    Some("environment reset complete"),
                    &self.target_urls,
                );
                Ok(true)
            }
            RunningMode::Custom { .. } | RunningMode::None => {
                if !self.reset_steps.is_empty() {
                    for (index, step) in self.reset_steps.iter().enumerate() {
                        run_step_to_completion(
                            step,
                            &self.env_refs,
                            &self.workspaces,
                            &self.logs_dir,
                            "reset",
                            index,
                        )
                        .await?;
                    }
                    self.store
                        .environment_runs()
                        .update_lifecycle(&self.environment_run_id, "Ready", None, None, None, None)
                        .await?;
                    emit_env(
                        &self.events,
                        &self.run_id,
                        &self.project_id,
                        &self.environment_run_id,
                        "Ready",
                        Some("environment reset hook complete"),
                        &self.target_urls,
                    );
                    return Ok(true);
                }
                emit_env(
                    &self.events,
                    &self.run_id,
                    &self.project_id,
                    &self.environment_run_id,
                    "Ready",
                    Some("environment reset hook unavailable for this launch mode"),
                    &self.target_urls,
                );
                Ok(false)
            }
        }
    }

    pub async fn stop(mut self) -> anyhow::Result<()> {
        let started = now_epoch_ms();
        let mut errors = Vec::new();
        for (index, step) in self.stop_steps.iter().enumerate() {
            if let Err(err) = run_step_to_completion(
                step,
                &self.env_refs,
                &self.workspaces,
                &self.logs_dir,
                "stop",
                index,
            )
            .await
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
    env_refs: &[LaunchEnvRef],
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
    phase: &str,
    index: usize,
) -> anyhow::Result<()> {
    let stdout_path = logs_dir.join(format!("{phase}-{index}-stdout.log"));
    let stderr_path = logs_dir.join(format!("{phase}-{index}-stderr.log"));
    let mut command = command_for_step(step, env_refs, workspaces)?;
    command
        .stdout(Stdio::from(std::fs::File::create(stdout_path)?))
        .stderr(Stdio::from(std::fs::File::create(stderr_path)?));
    if step.stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn()?;
    write_launch_stdin(step, &mut child).await?;
    let timeout = Duration::from_secs(step.timeout_seconds.unwrap_or(300));
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            anyhow::bail!(
                "{} timed out after {}s: `{}`",
                step_label(phase),
                timeout.as_secs(),
                step.command
            );
        }
    };
    if !status.success() {
        anyhow::bail!(
            "{} failed: `{}` exited with status {status}",
            step_label(phase),
            step.command
        );
    }
    Ok(())
}

async fn run_profile_hooks(
    profile: &ProjectLaunchProfile,
    workspaces: &HashMap<String, WorkspaceHandle>,
    logs_dir: &Path,
    phase: &str,
    steps: &[LaunchStep],
) -> anyhow::Result<()> {
    for (index, step) in steps.iter().enumerate() {
        run_step_to_completion(step, &profile.env_refs, workspaces, logs_dir, phase, index).await?;
    }
    Ok(())
}

fn step_label(phase: &str) -> &'static str {
    match phase {
        "build" => "setup command",
        "health" => "readiness command",
        "seed" => "seed command",
        "login" => "login command",
        "reset" => "reset command",
        "stop" => "stop command",
        _ => "command",
    }
}

async fn spawn_start_step(
    step: &LaunchStep,
    env_refs: &[LaunchEnvRef],
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
    let mut command = command_for_step(step, env_refs, workspaces)?;
    command.stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).kill_on_drop(true);
    if step.stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn()?;
    write_launch_stdin(step, &mut child).await?;
    Ok(child)
}

async fn write_launch_stdin(step: &LaunchStep, child: &mut Child) -> anyhow::Result<()> {
    let Some(stdin) = step.stdin.as_deref() else {
        return Ok(());
    };
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin.write_all(stdin.as_bytes()).await?;
        child_stdin.shutdown().await?;
    }
    Ok(())
}

fn command_for_step(
    step: &LaunchStep,
    env_refs: &[LaunchEnvRef],
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> anyhow::Result<Command> {
    let mut cmd = Command::new("sh");
    cmd.arg("-lc").arg(&step.command);
    if let Some(dir) = working_dir_for_step(step, workspaces) {
        cmd.current_dir(dir);
    }
    for (key, value) in resolve_launch_env(env_refs, step, workspaces)? {
        cmd.env(key, value);
    }
    Ok(cmd)
}

fn working_dir_for_step(
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> Option<PathBuf> {
    let base = match step.repo_name.as_deref() {
        Some(name) => workspaces.get(name).map(|w| w.workspace().to_path_buf()),
        None => single_workspace_root(workspaces),
    };
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
    env_refs: &[LaunchEnvRef],
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
                Some(step) => {
                    run_step_to_completion(step, env_refs, workspaces, logs_dir, "health", index)
                        .await
                        .map(|_| serde_json::json!({"ok": true, "kind": "command"}))
                }
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
        return wait_for_health(&checks, &profile.env_refs, workspaces, logs_dir).await;
    }
    wait_for_health(&profile.health_checks, &profile.env_refs, workspaces, logs_dir).await
}

fn resolve_launch_env(
    refs: &[LaunchEnvRef],
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> anyhow::Result<HashMap<String, String>> {
    let mut env = HashMap::new();
    for env_ref in refs {
        match env_ref.kind.as_str() {
            "env-file" => {
                let path = resolve_env_file_path(&env_ref.value, step, workspaces)?;
                for (key, value) in read_env_file(&path)? {
                    env.insert(key, value);
                }
            }
            "env-var" => {
                let key = env_ref.value.trim();
                if key.is_empty() {
                    continue;
                }
                validate_env_key(key)?;
                let value = std::env::var(key)
                    .map_err(|_| anyhow::anyhow!("env variable `{key}` is not set"))?;
                env.insert(key.to_string(), value);
            }
            other => anyhow::bail!("unsupported launch env ref kind `{other}`"),
        }
    }
    Ok(env)
}

fn resolve_env_file_path(
    raw: &str,
    step: &LaunchStep,
    workspaces: &HashMap<String, WorkspaceHandle>,
) -> anyhow::Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("env file path is empty");
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    let base = working_dir_for_step(step, workspaces)
        .or_else(|| single_workspace_root(workspaces))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "env file `{trimmed}` is relative, but the launch step has no code source"
            )
        })?;
    Ok(base.join(path))
}

fn single_workspace_root(workspaces: &HashMap<String, WorkspaceHandle>) -> Option<PathBuf> {
    let mut values = workspaces.values();
    let first = values.next()?;
    values.next().is_none().then(|| first.workspace().to_path_buf())
}

fn read_env_file(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|source| anyhow::anyhow!("read env file `{}`: {source}", path.display()))?;
    let mut out = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if let Some((key, value)) = parse_env_line(line).map_err(|err| {
            anyhow::anyhow!("parse env file `{}` line {}: {err}", path.display(), index + 1)
        })? {
            out.push((key, value));
        }
    }
    Ok(out)
}

fn parse_env_line(line: &str) -> anyhow::Result<Option<(String, String)>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim_start();
    let Some((key, raw_value)) = assignment.split_once('=') else {
        anyhow::bail!("expected KEY=VALUE");
    };
    let key = key.trim();
    validate_env_key(key)?;
    Ok(Some((key.to_string(), parse_env_value(raw_value)?)))
}

fn validate_env_key(key: &str) -> anyhow::Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        anyhow::bail!("env variable name is empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!("invalid env variable name `{key}`");
    }
    Ok(())
}

fn parse_env_value(raw: &str) -> anyhow::Result<String> {
    let value = raw.trim_start();
    if let Some(rest) = value.strip_prefix('"') {
        return parse_double_quoted_env_value(rest);
    }
    if let Some(rest) = value.strip_prefix('\'') {
        let Some(end) = rest.find('\'') else {
            anyhow::bail!("unterminated single-quoted value");
        };
        return Ok(rest[..end].to_string());
    }
    Ok(strip_unquoted_env_comment(value).trim_end().to_string())
}

fn parse_double_quoted_env_value(rest: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Ok(out),
            other => out.push(other),
        }
    }
    anyhow::bail!("unterminated double-quoted value")
}

fn strip_unquoted_env_comment(value: &str) -> &str {
    for (index, ch) in value.char_indices() {
        if ch == '#' && (index == 0 || value[..index].ends_with(char::is_whitespace)) {
            return &value[..index];
        }
    }
    value
}

async fn wait_for_http(url: Option<&str>, timeout: Duration) -> anyhow::Result<serde_json::Value> {
    let url = url.ok_or_else(|| anyhow::anyhow!("http health check is missing URL"))?;
    let request_timeout = timeout.min(Duration::from_secs(5)).max(Duration::from_millis(100));
    let client = reqwest::Client::builder().timeout(request_timeout).build()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use nyctos_core::project::ProjectId;
    use nyctos_core::store::{ProjectLaunchProfileInput, RunRecord};
    use tokio::sync::broadcast;

    fn launch_step(repo_name: Option<&str>) -> LaunchStep {
        LaunchStep {
            command: "printenv".to_string(),
            repo_id: None,
            repo_name: repo_name.map(str::to_string),
            working_directory: None,
            timeout_seconds: None,
            stdin: None,
        }
    }

    fn env_file_ref(path: &str) -> LaunchEnvRef {
        LaunchEnvRef { kind: "env-file".to_string(), value: path.to_string(), secret: true }
    }

    async fn fresh_store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Store::open(tmp.path()).await.expect("open store");
        (tmp, store)
    }

    fn sample_run(id: &str) -> RunRecord {
        RunRecord {
            id: id.to_string(),
            project_id: None,
            kind: "Pentest".to_string(),
            started_at: 1,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        }
    }

    fn command(command: &str) -> LaunchStep {
        LaunchStep {
            command: command.to_string(),
            repo_id: None,
            repo_name: None,
            working_directory: None,
            timeout_seconds: Some(1),
            stdin: None,
        }
    }

    #[test]
    fn parses_env_file_values() {
        assert_eq!(parse_env_line("# comment").unwrap(), None);
        assert_eq!(
            parse_env_line("export API_URL=http://localhost:3000").unwrap(),
            Some(("API_URL".to_string(), "http://localhost:3000".to_string()))
        );
        assert_eq!(
            parse_env_line("GREETING=\"hello\\nthere\"").unwrap(),
            Some(("GREETING".to_string(), "hello\nthere".to_string()))
        );
        assert_eq!(
            parse_env_line("TOKEN=abc#kept").unwrap(),
            Some(("TOKEN".to_string(), "abc#kept".to_string()))
        );
        assert_eq!(
            parse_env_line("TRIMMED=abc # dropped").unwrap(),
            Some(("TRIMMED".to_string(), "abc".to_string()))
        );
    }

    #[test]
    fn resolves_relative_env_file_against_single_workspace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join(".env.dev"),
            "API_URL=http://localhost:3000\nQUOTED='two words'\n",
        )
        .expect("write env");
        let mut workspaces = HashMap::new();
        workspaces
            .insert("web".to_string(), WorkspaceHandle::for_local_path_test("web", tmp.path()));

        let env = resolve_launch_env(&[env_file_ref(".env.dev")], &launch_step(None), &workspaces)
            .expect("resolve env");

        assert_eq!(env.get("API_URL").map(String::as_str), Some("http://localhost:3000"));
        assert_eq!(env.get("QUOTED").map(String::as_str), Some("two words"));
    }

    #[test]
    fn rejects_relative_env_file_without_repo_context_when_ambiguous() {
        let tmp_a = tempfile::tempdir().expect("tempdir a");
        let tmp_b = tempfile::tempdir().expect("tempdir b");
        let mut workspaces = HashMap::new();
        workspaces
            .insert("web".to_string(), WorkspaceHandle::for_local_path_test("web", tmp_a.path()));
        workspaces
            .insert("api".to_string(), WorkspaceHandle::for_local_path_test("api", tmp_b.path()));

        let err = resolve_launch_env(&[env_file_ref(".env.dev")], &launch_step(None), &workspaces)
            .expect_err("relative env file needs context");

        assert!(err.to_string().contains("no code source"));
    }

    #[tokio::test]
    async fn run_step_writes_configured_stdin() {
        let workspace = tempfile::tempdir().expect("workspace");
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "web".to_string(),
            WorkspaceHandle::for_local_path_test("web", workspace.path()),
        );
        let mut step = command("cat > answered");
        step.stdin = Some("y\n".to_string());

        run_step_to_completion(&step, &[], &workspaces, workspace.path(), "reset", 0)
            .await
            .expect("stdin-backed command");

        assert_eq!(std::fs::read_to_string(workspace.path().join("answered")).unwrap(), "y\n");
    }

    #[tokio::test]
    async fn launch_profile_runs_hooks_captures_logs_and_stops() {
        let (tmp, store) = fresh_store().await;
        let state_dir = StateDir::at(tmp.path());
        state_dir.ensure().expect("state dir");
        let project_rec = store
            .projects()
            .create("p-1", "acme", None, Some("http://localhost:3000"), None, 1)
            .await
            .expect("project");
        let mut run = sample_run("run-launch-hooks");
        run.project_id = Some("p-1".to_string());
        store.runs().insert(&run).await.expect("run");
        let workspace = tempfile::tempdir().expect("workspace");
        let profile = store
            .launch_profiles()
            .upsert_default(
                "p-1",
                &ProjectLaunchProfileInput {
                    name: Some("test".to_string()),
                    mode: Some("custom-commands".to_string()),
                    build_steps: vec![command("echo build; printf ready > ready")],
                    start_steps: vec![command("while true; do sleep 1; done")],
                    seed_steps: vec![command("echo seed; printf seed > seeded")],
                    reset_steps: vec![command("echo reset; printf reset > reset")],
                    login_steps: vec![command("echo login; printf login > login")],
                    stop_steps: vec![command("echo stop; printf stop > stopped")],
                    health_checks: vec![LaunchHealthCheck {
                        kind: "command".to_string(),
                        url: None,
                        host: None,
                        port: None,
                        command: Some(command("test -f ready")),
                        timeout_seconds: Some(1),
                    }],
                    target_urls: vec!["http://localhost:3000".to_string()],
                    env_refs: Vec::new(),
                    working_dirs: Vec::new(),
                },
                2,
            )
            .await
            .expect("profile");
        let project = Project {
            id: ProjectId::new(project_rec.id),
            name: project_rec.name,
            description: None,
            target_base_url: project_rec.target_base_url,
            env_config: None,
            runtime_profile: None,
            default_launch_profile: None,
        };
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "web".to_string(),
            WorkspaceHandle::for_local_path_test("web", workspace.path()),
        );
        let (events, _rx) = broadcast::channel(16);
        let mut env = start_launch_profile(LaunchContext {
            store: &store,
            state_dir: &state_dir,
            project: &project,
            run_id: "run-launch-hooks",
            profile: &profile,
            workspaces: &workspaces,
            events,
        })
        .await
        .expect("start launch profile");

        assert_eq!(std::fs::read_to_string(workspace.path().join("seeded")).unwrap(), "seed");
        assert_eq!(std::fs::read_to_string(workspace.path().join("login")).unwrap(), "login");
        assert!(std::fs::read_to_string(
            state_dir.logs().join("environment/run-launch-hooks/build-0-stdout.log")
        )
        .unwrap()
        .contains("build"));

        assert!(env.reset_after_state_change().await.expect("reset hook"));
        assert_eq!(std::fs::read_to_string(workspace.path().join("reset")).unwrap(), "reset");
        env.stop().await.expect("stop");
        assert_eq!(std::fs::read_to_string(workspace.path().join("stopped")).unwrap(), "stop");
        let rows = store.environment_runs().list_by_run("run-launch-hooks").await.unwrap();
        assert_eq!(rows[0].status, "Stopped");
    }

    #[tokio::test]
    async fn launch_profile_timeout_marks_environment_failed() {
        let (tmp, store) = fresh_store().await;
        let state_dir = StateDir::at(tmp.path());
        state_dir.ensure().expect("state dir");
        store
            .projects()
            .create("p-1", "acme", None, Some("http://localhost:3000"), None, 1)
            .await
            .unwrap();
        let mut run = sample_run("run-launch-timeout");
        run.project_id = Some("p-1".to_string());
        store.runs().insert(&run).await.unwrap();
        let workspace = tempfile::tempdir().expect("workspace");
        let profile = store
            .launch_profiles()
            .upsert_default(
                "p-1",
                &ProjectLaunchProfileInput {
                    mode: Some("already-running".to_string()),
                    health_checks: vec![LaunchHealthCheck {
                        kind: "command".to_string(),
                        url: None,
                        host: None,
                        port: None,
                        command: Some(LaunchStep {
                            command: "sleep 5".to_string(),
                            timeout_seconds: Some(1),
                            ..command("sleep 5")
                        }),
                        timeout_seconds: Some(1),
                    }],
                    target_urls: vec!["http://localhost:3000".to_string()],
                    ..empty_profile_input()
                },
                2,
            )
            .await
            .unwrap();
        let project = Project {
            id: ProjectId::new("p-1"),
            name: "acme".to_string(),
            description: None,
            target_base_url: Some("http://localhost:3000".to_string()),
            env_config: None,
            runtime_profile: None,
            default_launch_profile: None,
        };
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "web".to_string(),
            WorkspaceHandle::for_local_path_test("web", workspace.path()),
        );
        let (events, _rx) = broadcast::channel(16);
        let err = start_launch_profile(LaunchContext {
            store: &store,
            state_dir: &state_dir,
            project: &project,
            run_id: "run-launch-timeout",
            profile: &profile,
            workspaces: &workspaces,
            events,
        })
        .await
        .expect_err("health timeout should fail launch");

        assert!(err.to_string().contains("timed out"));
        let rows = store.environment_runs().list_by_run("run-launch-timeout").await.unwrap();
        assert_eq!(rows[0].status, "Failed");
        assert!(rows[0].health.as_ref().unwrap()["error"].as_str().unwrap().contains("timed out"));
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
}

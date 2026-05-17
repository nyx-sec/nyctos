use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nyx_agent_core::{
    ingest, Config, IngestError, LogConfig, Repo, RepoSource, StateDir, Store,
};
use nyx_agent_core::store::RepoRecord;
use nyx_agent_nyx::{NyxError, NyxRunner, MINIMUM_NYX_VERSION};
use semver::Version;

#[derive(Debug, Parser)]
#[command(name = "nyx-agent", version, about = "Nyx repository agent", propagate_version = true)]
struct Cli {
    /// Path to `nyx-agent.toml`. Defaults to `./nyx-agent.toml`.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Override the state directory; otherwise resolved from `dirs::data_dir`.
    #[arg(long, global = true, value_name = "PATH")]
    state_dir: Option<PathBuf>,

    /// `tracing` filter applied to stderr output (e.g. `info`, `debug`, `nyx=trace`).
    #[arg(long, global = true, value_name = "FILTER", default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan one or more repositories for findings.
    Scan {
        /// Repositories to scan (by name from `nyx-agent.toml`). Pass
        /// `--repo` once per repository, or omit to scan every enabled
        /// repo.
        #[arg(long = "repo", value_name = "REPO")]
        repos: Vec<String>,
    },
    /// Re-verify a previous finding by run/finding id.
    Reverify {
        /// Run identifier.
        #[arg(long)]
        run: String,
        /// Finding identifier.
        #[arg(long)]
        finding: String,
    },
    /// Print the stored payload for a run or finding.
    Inspect {
        /// Identifier of a run or finding.
        id: String,
    },
    /// Show budget consumption for the current configuration.
    Budget,
    /// Verify that state directory, config, and logging look healthy.
    Doctor,
    /// Run the long-lived HTTP/UI server. Default if no subcommand is given.
    Serve {
        /// Override the listen address from `[ui]`.
        #[arg(long)]
        listen: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error: tokio runtime: {err:#}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config_path = cli.config.clone().unwrap_or_else(|| PathBuf::from("nyx-agent.toml"));
    let config = Config::load_or_default(&config_path)?;

    let state_root = match cli.state_dir.clone().or_else(|| config.general.state_dir.clone()) {
        Some(p) => p,
        None => StateDir::default_root()?,
    };
    let state_dir = StateDir::at(state_root);
    state_dir.ensure()?;

    let log_cfg = LogConfig::new(state_dir.logs(), cli.log_level.clone());

    match cli.command.unwrap_or(Command::Serve { listen: None }) {
        Command::Doctor => doctor(&state_dir, &config_path, &log_cfg, &config).await,
        Command::Scan { repos } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            scan(&state_dir, &config, &repos).await
        }
        Command::Reverify { .. }
        | Command::Inspect { .. }
        | Command::Budget
        | Command::Serve { .. } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            todo!("subcommand wiring lands in a later phase")
        }
    }
}

async fn scan(
    state_dir: &StateDir,
    config: &Config,
    requested: &[String],
) -> anyhow::Result<ExitCode> {
    let selected = select_repos(config, requested)?;
    if selected.is_empty() {
        eprintln!("scan: no repositories selected; configure one in nyx-agent.toml");
        return Ok(ExitCode::from(1));
    }

    let state_repos = state_dir.repos();
    let store = Store::open(state_dir.root()).await?;
    let run_id = run_id_now();
    let mut had_error = false;

    for repo in &selected {
        match ingest(repo, &state_repos, &run_id).await {
            Ok(ingested) => {
                let now_ms = now_epoch_ms();
                let rec = RepoRecord {
                    name: ingested.name.clone(),
                    source_kind: source_kind_str(&ingested.source).to_string(),
                    source_url_or_path: source_url_or_path(&ingested.source),
                    branch: branch_of(&ingested.source),
                    auth_ref: auth_descriptor_of(&ingested.source),
                    i_own_this: true,
                    last_scan_run_id: None,
                    created_at: now_ms,
                    updated_at: now_ms,
                };
                store.repos().upsert(&rec).await?;
                println!(
                    "scan: ingested {} -> {} (backend: {})",
                    ingested.name,
                    ingested.workspace.display(),
                    match ingested.snapshot_backend {
                        Some(b) => format!("{b:?}"),
                        None => "git-clone".to_string(),
                    }
                );
                if let Some(remote) = &ingested.on_disk_git_remote {
                    println!("  on-disk git remote: {remote}");
                }
            }
            Err(err) => {
                had_error = true;
                report_ingest_error(&repo.name, &err);
            }
        }
    }

    store.close().await;
    Ok(if had_error { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn select_repos(config: &Config, requested: &[String]) -> anyhow::Result<Vec<Repo>> {
    let mut out = Vec::new();
    if requested.is_empty() {
        for c in &config.repos {
            if c.enabled {
                out.push(Repo::from_config(c)?);
            }
        }
        return Ok(out);
    }
    for name in requested {
        let cfg = config
            .repos
            .iter()
            .find(|r| &r.name == name)
            .ok_or_else(|| anyhow::anyhow!("repo `{name}` not declared in nyx-agent.toml"))?;
        if !cfg.enabled {
            anyhow::bail!("repo `{name}` is declared but `enabled = false`");
        }
        out.push(Repo::from_config(cfg)?);
    }
    Ok(out)
}

fn report_ingest_error(name: &str, err: &IngestError) {
    match err {
        IngestError::NotAttested { .. } => {
            eprintln!("scan: refusing repo `{name}`: {err}");
        }
        other => eprintln!("scan: repo `{name}` failed: {other}"),
    }
}

fn source_kind_str(src: &RepoSource) -> &'static str {
    match src {
        RepoSource::Git { .. } => "git",
        RepoSource::LocalPath { .. } => "local-path",
    }
}

fn source_url_or_path(src: &RepoSource) -> String {
    match src {
        RepoSource::Git { url, .. } => url.clone(),
        RepoSource::LocalPath { path } => path.display().to_string(),
    }
}

fn branch_of(src: &RepoSource) -> Option<String> {
    match src {
        RepoSource::Git { branch, .. } => branch.clone(),
        RepoSource::LocalPath { .. } => None,
    }
}

fn auth_descriptor_of(src: &RepoSource) -> Option<String> {
    match src {
        RepoSource::Git { auth: Some(a), .. } => Some(a.descriptor()),
        _ => None,
    }
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn run_id_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("run-{now}")
}

async fn doctor(
    state_dir: &StateDir,
    config_path: &std::path::Path,
    log_cfg: &LogConfig,
    config: &Config,
) -> anyhow::Result<ExitCode> {
    println!("state dir OK at {}", state_dir.root().display());
    println!("logs -> {}", nyx_agent_core::json_log_path(&log_cfg.log_dir).display());
    if config_path.exists() {
        println!("config OK at {}", config_path.display());
    } else {
        println!("config not found at {} (using defaults)", config_path.display());
    }
    let store = Store::open(state_dir.root()).await?;
    let version = store.schema_version().await?;
    println!("db OK at {} (schema v{})", store.path().display(), version);
    store.close().await;

    let min_version = resolve_min_nyx_version(config)?;
    let override_path = config.nyx.binary_path.as_deref();
    match NyxRunner::discover(override_path, &min_version).await {
        Ok(runner) => {
            println!(
                "nyx OK at {} (version {}, minimum {})",
                runner.binary().display(),
                runner.version(),
                min_version
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(err @ NyxError::NyxNotFound { .. }) => {
            eprintln!("nyx FAIL: {err}");
            eprintln!("  install the upstream `nyx` scanner and put it on PATH, or set [nyx].binary_path");
            Ok(ExitCode::from(1))
        }
        Err(err @ NyxError::VersionTooOld { .. }) => {
            eprintln!("nyx FAIL: {err}");
            Ok(ExitCode::from(1))
        }
        Err(err) => {
            eprintln!("nyx FAIL: {err}");
            Ok(ExitCode::from(1))
        }
    }
}

fn resolve_min_nyx_version(config: &Config) -> anyhow::Result<Version> {
    let raw = config
        .nyx
        .min_version
        .as_deref()
        .unwrap_or(MINIMUM_NYX_VERSION);
    Version::parse(raw).map_err(|e| {
        anyhow::anyhow!("[nyx].min_version `{raw}` is not a valid semver: {e}")
    })
}

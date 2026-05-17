use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nyx_agent_core::{Config, LogConfig, StateDir, Store};
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
        /// Repositories to scan (by name from `nyx-agent.toml`).
        #[arg(value_name = "REPO")]
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
        Command::Scan { .. }
        | Command::Reverify { .. }
        | Command::Inspect { .. }
        | Command::Budget
        | Command::Serve { .. } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            todo!("subcommand wiring lands in a later phase")
        }
    }
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

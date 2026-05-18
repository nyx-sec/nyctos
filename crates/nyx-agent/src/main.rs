use std::collections::HashMap;
use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use nyx_agent_api::{
    build_router, AuthConfig, ScanTrigger, ScanTriggerError, ServerState, SetupContext,
};
use nyx_agent_core::store::{finding_id_hash, FindingRecord, RepoRecord, RunRecord};
use nyx_agent_core::{
    ingest, Config, IngestError, IngestedRepo, LogConfig, Repo, RepoOutcome, RepoSource, Run,
    RunBundle, RunDispatcher, SecretStore, StateDir, Store, WorkspaceHandle,
};
use nyx_agent_nyx::{Diag, NyxError, NyxRunner, NyxScanLane, MINIMUM_NYX_VERSION};
use nyx_agent_types::event::{AgentEvent, EventSink, RunEvent};
use semver::Version;
use tokio::sync::{broadcast, mpsc, oneshot};

mod ai_pipeline;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_NYX_GREEN: &str = "\x1b[38;2;46;160;103m";
const ANSI_NYX_GOLD: &str = "\x1b[38;2;199;154;43m";
const ANSI_NYX_MUTED: &str = "\x1b[38;2;159;163;173m";
const NYX_AGENT_TAGLINE: &str = "                       automated pentesting, refined";

const NYX_AGENT_BANNER: [(&str, &str); 6] = [
    ("███╗   ██╗██╗   ██╗██╗  ██╗", "     █████╗  ██████╗ ███████╗███╗   ██╗████████╗"),
    ("████╗  ██║╚██╗ ██╔╝╚██╗██╔╝", "    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝"),
    ("██╔██╗ ██║ ╚████╔╝  ╚███╔╝", "     ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║"),
    ("██║╚██╗██║  ╚██╔╝   ██╔██╗", "     ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║"),
    ("██║ ╚████║   ██║   ██╔╝ ██╗", "    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║"),
    ("╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝", "    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝"),
];

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
        /// Do not launch a browser at startup. Overrides `[ui].open_browser`.
        #[arg(long)]
        no_open: bool,
        /// Disable the embedded UI surface entirely (no browser launch
        /// and no future auth-protected mutation endpoints).
        #[arg(long)]
        headless: bool,
        /// Override the browser launcher. The ready URL is appended as the
        /// last argument. Useful in CI smoke tests that assert the URL
        /// without launching a real browser (e.g. `--open-cmd /bin/echo`).
        #[arg(long, value_name = "CMD")]
        open_cmd: Option<String>,
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
    let config_present = config_path.exists();
    let config = Config::load_or_default(&config_path)?;

    let state_root = match cli.state_dir.clone().or_else(|| config.general.state_dir.clone()) {
        Some(p) => p,
        None => StateDir::default_root()?,
    };
    let state_dir = StateDir::at(state_root);
    state_dir.ensure()?;

    let log_cfg = LogConfig::new(state_dir.logs(), cli.log_level.clone());

    match cli.command.unwrap_or(Command::Serve {
        listen: None,
        no_open: false,
        headless: false,
        open_cmd: None,
    }) {
        Command::Doctor => doctor(&state_dir, &config_path, &log_cfg, &config).await,
        Command::Scan { repos } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            scan(&state_dir, &config, &repos, "Manual").await
        }
        Command::Serve { listen, no_open, headless, open_cmd } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            serve(
                state_dir,
                config,
                config_path,
                config_present,
                listen,
                no_open,
                headless,
                open_cmd,
            )
            .await
        }
        Command::Reverify { .. } | Command::Inspect { .. } | Command::Budget => {
            nyx_agent_core::init_logging(&log_cfg)?;
            todo!("subcommand wiring lands in a later phase")
        }
    }
}

async fn scan(
    state_dir: &StateDir,
    config: &Config,
    requested: &[String],
    triggered_by: &str,
) -> anyhow::Result<ExitCode> {
    let selected = select_repos(config, requested)?;
    if selected.is_empty() {
        eprintln!("scan: no repositories selected; configure one in nyx-agent.toml");
        return Ok(ExitCode::from(1));
    }

    let store = Store::open(state_dir.root()).await?;
    let run = Run::new();
    let run_record = build_run_record(&run, triggered_by);
    store.runs().insert(&run_record).await?;

    // CLI scan has no live subscribers; emitting into a dropped sink would
    // discard events, so build a self-owned bus to keep the event sink shape
    // identical to the API path. The receiver immediately drops, which makes
    // every send a no-op short of a clone.
    let (events_tx, _events_rx) = broadcast::channel::<AgentEvent>(16);
    let result = drive_scan(state_dir, config, &store, selected, &run, events_tx, true).await;

    match result {
        Ok(report) => {
            print_scan_report(&report);
            store.close().await;
            Ok(if report.success { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }
        Err(err) => {
            store.close().await;
            Err(err)
        }
    }
}

struct ScanReport {
    run_id: String,
    wall_clock_ms: i64,
    succeeded: u32,
    inconclusive: u32,
    failed: u32,
    success: bool,
    per_repo: Vec<RepoReport>,
}

struct RepoReport {
    repo: String,
    outcome: nyx_agent_types::event::RepoOutcomeTag,
    diags: usize,
    elapsed_ms: i64,
}

fn print_scan_report(r: &ScanReport) {
    println!(
        "scan: run {} finished in {}ms - {} succeeded, {} inconclusive, {} failed",
        r.run_id, r.wall_clock_ms, r.succeeded, r.inconclusive, r.failed,
    );
    for repo in &r.per_repo {
        println!(
            "  - {}: {:?} (diags: {}, {}ms)",
            repo.repo, repo.outcome, repo.diags, repo.elapsed_ms,
        );
    }
}

fn build_run_record(run: &Run, triggered_by: &str) -> RunRecord {
    RunRecord {
        id: run.id.clone(),
        started_at: run.started_at_ms,
        finished_at: None,
        status: "Running".to_string(),
        triggered_by: triggered_by.to_string(),
        git_ref: None,
        parent_run_id: None,
        wall_clock_ms: None,
        total_ai_spend_usd_micros: 0,
    }
}

/// Shared scan body for both the CLI `scan` subcommand and the API
/// `complete_scan` task. Owns the ingest loop, dispatcher hand-off,
/// persistence, and run-row finalisation. The `verbose` flag toggles
/// the per-repo ingest println the CLI prints; the API path stays
/// quiet because the WebSocket already streams `RepoStarted` /
/// `RepoFinished` to subscribers.
async fn drive_scan(
    state_dir: &StateDir,
    config: &Config,
    store: &Store,
    selected: Vec<Repo>,
    run: &Run,
    events: EventSink,
    verbose: bool,
) -> anyhow::Result<ScanReport> {
    let now_ms = now_epoch_ms();
    let state_repos = state_dir.repos();
    let mut ingest_failures: Vec<(String, IngestError)> = Vec::new();
    let mut workspaces: Vec<WorkspaceHandle> = Vec::new();
    for repo in &selected {
        match ingest(repo, &state_repos, &run.id).await {
            Ok(ingested) => {
                upsert_repo_record(store, &ingested, now_ms).await?;
                if verbose {
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
                let handle = WorkspaceHandle::new(ingested);
                workspaces.push(handle);
            }
            Err(err) => {
                report_ingest_error(&repo.name, &err);
                let _ = events.send(AgentEvent::Run {
                    data: RunEvent::RepoFailed {
                        run_id: run.id.clone(),
                        repo: repo.name.clone(),
                        message: format!("ingest failed: {err}"),
                        elapsed_ms: 0,
                    },
                });
                ingest_failures.push((repo.name.clone(), err));
            }
        }
    }

    if workspaces.is_empty() {
        finalise_run(store, &run.id, run.started_at_ms, 0, "Failed").await?;
        return Ok(ScanReport {
            run_id: run.id.clone(),
            wall_clock_ms: 0,
            succeeded: 0,
            inconclusive: 0,
            failed: 0,
            success: false,
            per_repo: Vec::new(),
        });
    }

    let lane = match build_scan_lane(config).await {
        Ok(lane) => Arc::new(lane),
        Err(err) => {
            eprintln!("scan: cannot build nyx lane: {err}");
            finalise_run(store, &run.id, run.started_at_ms, 0, "Failed").await?;
            return Ok(ScanReport {
                run_id: run.id.clone(),
                wall_clock_ms: 0,
                succeeded: 0,
                inconclusive: 0,
                failed: 0,
                success: false,
                per_repo: Vec::new(),
            });
        }
    };

    // Clone every handle into a name-keyed map so the Phase-14
    // payload-synthesis pass can read source after the dispatcher
    // consumes the original `workspaces` Vec.
    let workspaces_for_ai: HashMap<String, WorkspaceHandle> =
        workspaces.iter().map(|w| (w.name().to_string(), w.clone())).collect();

    let dispatcher =
        RunDispatcher::from_config(&config.performance, workspaces.len(), Some(events.clone()));
    let run_for_dispatch = run.clone();
    let dispatch_handle = tokio::task::spawn_blocking(move || {
        dispatcher.dispatch::<NyxScanLane, Diag>(run_for_dispatch, lane, workspaces)
    });

    // Guard the runs row: any failure between dispatch and finalise must still
    // flip status off "Running" before we propagate. Otherwise a panicking
    // rayon worker or a transient sqlx error leaves the row stuck forever.
    let bundle: RunBundle<Diag> = match dispatch_handle.await {
        Ok(b) => b,
        Err(join_err) => {
            let _ = finalise_run(store, &run.id, run.started_at_ms, 0, "Failed").await;
            return Err(anyhow::anyhow!("dispatch join error: {join_err}"));
        }
    };

    if let Err(err) = persist_run_results(store, &bundle).await {
        let _ =
            finalise_run(store, &run.id, run.started_at_ms, bundle.wall_clock_ms, "Failed").await;
        return Err(err);
    }

    // Phase 14: fan out PayloadSynthesis tasks against every diag the
    // static pass flagged with `Unsupported(NoPayloadsForCap)`. No-op
    // when the AI runtime is disabled or no key is configured.
    let secrets = SecretStore::from_env();
    match ai_pipeline::run_payload_synthesis_pass(
        &config.ai,
        store,
        &secrets,
        &bundle,
        &workspaces_for_ai,
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            if verbose
                && (report.synthesised > 0 || report.quarantined > 0 || report.failed > 0)
            {
                println!(
                    "scan: payload synthesis - {} synthesised, {} quarantined, {} failed ({} attempts, ${:.6})",
                    report.synthesised,
                    report.quarantined,
                    report.failed,
                    report.total_attempts,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "payload synthesis pass failed"),
    }

    // Phase 15: fan out SpecDerivation tasks against every diag the
    // static pass flagged with `Inconclusive(SpecDerivationFailed)`.
    // Same no-op gating as the payload pass; shares the run's budget
    // bucket so per-call caps stack on top of payload spend.
    match ai_pipeline::run_spec_derivation_pass(
        &config.ai,
        store,
        &secrets,
        &bundle,
        &workspaces_for_ai,
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            if verbose
                && (report.synthesised > 0 || report.quarantined > 0 || report.failed > 0)
            {
                println!(
                    "scan: spec derivation - {} synthesised, {} quarantined, {} failed ({} attempts, ${:.6})",
                    report.synthesised,
                    report.quarantined,
                    report.failed,
                    report.total_attempts,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "spec derivation pass failed"),
    }

    // Phase 16: rank cross-repo exploitable chains across the run's
    // finding graph. Single-call pass; shares the run's budget bucket
    // with payload + spec passes. No-op when no API key is configured
    // or fewer than two findings landed in the bundle.
    match ai_pipeline::run_chain_reasoning_pass(
        &config.ai,
        store,
        &secrets,
        &bundle,
        &workspaces_for_ai,
        events,
    )
    .await
    {
        Ok(report) => {
            if verbose
                && (report.chains_persisted > 0 || report.failed > 0)
            {
                println!(
                    "scan: chain reasoning - {} chains ({} cross-repo), {} members stamped, {} failed ({} attempts, ${:.6})",
                    report.chains_persisted,
                    report.cross_repo_chains,
                    report.members_stamped,
                    report.failed,
                    report.attempts,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "chain reasoning pass failed"),
    }

    let counts = bundle.counts();
    let success = counts.failed == 0 && ingest_failures.is_empty();
    finalise_run(
        store,
        &run.id,
        run.started_at_ms,
        bundle.wall_clock_ms,
        if success { "Succeeded" } else { "Failed" },
    )
    .await?;

    let per_repo = bundle
        .per_repo
        .iter()
        .map(|b| RepoReport {
            repo: b.repo.clone(),
            outcome: b.outcome.tag(),
            diags: match &b.outcome {
                RepoOutcome::Success(diags) => diags.len(),
                _ => 0,
            },
            elapsed_ms: b.elapsed_ms,
        })
        .collect();

    Ok(ScanReport {
        run_id: bundle.run_id,
        wall_clock_ms: bundle.wall_clock_ms,
        succeeded: counts.succeeded,
        inconclusive: counts.inconclusive,
        failed: counts.failed,
        success,
        per_repo,
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    state_dir: StateDir,
    config: Config,
    config_path: PathBuf,
    config_present: bool,
    listen_override: Option<String>,
    no_open: bool,
    headless: bool,
    open_cmd: Option<String>,
) -> anyhow::Result<ExitCode> {
    let listen_addr = listen_override.unwrap_or_else(|| config.ui.listen_addr.clone());
    let store = Store::open(state_dir.root()).await?;
    let (events_tx, _events_rx) = broadcast::channel::<AgentEvent>(256);

    let (scan_tx, mut scan_rx) = mpsc::channel::<ScanRequest>(16);
    let trigger: Arc<dyn ScanTrigger> = Arc::new(MpscScanTrigger { tx: scan_tx });

    let scan_state_dir = state_dir.clone();
    let scan_config = config.clone();
    let scan_events = events_tx.clone();
    let scan_worker = tokio::spawn(async move {
        while let Some(req) = scan_rx.recv().await {
            let state_dir = scan_state_dir.clone();
            let config = scan_config.clone();
            let events = scan_events.clone();
            tokio::spawn(async move {
                let outcome =
                    run_scan_for_api(&state_dir, &config, req.repo.as_deref(), events).await;
                let _ = req.reply.send(outcome);
            });
        }
    });

    let setup = SetupContext::new(
        config_path.clone(),
        config.clone(),
        config_present,
        SecretStore::from_env(),
    );
    // Headless mode skips auth entirely (deferred plan #31). When auth
    // is on, mint or load a per-install token and surface it both to
    // the API middleware and the SPA bootstrap.
    let auth_token = if headless { None } else { Some(state_dir.load_or_mint_auth_token()?) };
    let auth_config = AuthConfig::new(auth_token.clone());

    let ui_bootstrap = Arc::new(nyx_agent_ui::UiBootstrap { auth_token: auth_token.clone() });
    let server_state =
        ServerState::new(store.clone(), events_tx.clone(), trigger, setup, auth_config)
            .with_state_repos_dir(state_dir.repos());

    // Tap the broadcast channel and feed every event into the per-run
    // replay buffer so WS clients that attach after a scan kicks off
    // still receive `RunStarted` + early `RepoStarted` frames.
    let replay = Arc::clone(&server_state.replay);
    let replay_rx = events_tx.subscribe();
    let _replay_task = tokio::spawn(async move {
        let mut rx = replay_rx;
        loop {
            match rx.recv().await {
                Ok(ev) => replay.push(&ev).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    let ui_fallback = {
        let bootstrap = Arc::clone(&ui_bootstrap);
        move |uri: axum::http::Uri| {
            let bootstrap = Arc::clone(&bootstrap);
            async move { nyx_agent_ui::spa_handler_with(uri, &bootstrap).await }
        }
    };
    let app = build_router(server_state).fallback(ui_fallback);

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {listen_addr}: {e}"))?;
    let local_addr = listener.local_addr()?;
    let startup_url = if config_present {
        format!("http://{local_addr}/")
    } else {
        format!("http://{local_addr}/setup")
    };
    print_startup_banner();
    println!("ready on http://{local_addr}");
    if !config_present {
        println!("first launch detected — wizard at {startup_url}");
    }

    let url = startup_url.clone();

    if !headless && !no_open && config.ui.open_browser {
        let url_for_open = url.clone();
        // `webbrowser::open` (and any custom `--open-cmd`) shell out
        // through `xdg-open`/`open.exe` which can block while it talks
        // to a display server. Run on a blocking thread so the HTTP
        // accept loop returns to `axum::serve` without waiting.
        tokio::task::spawn_blocking(move || {
            if let Some(cmd) = open_cmd {
                match std::process::Command::new(&cmd).arg(&url_for_open).status() {
                    Ok(status) if status.success() => {}
                    Ok(status) => eprintln!("warn: open-cmd `{cmd}` exited with status {status}"),
                    Err(err) => eprintln!("warn: open-cmd `{cmd}` failed: {err}"),
                }
            } else if let Err(err) = webbrowser::open(&url_for_open) {
                eprintln!("warn: could not open browser at {url_for_open}: {err}");
            }
        });
    }

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    let serve_result = axum::serve(listener, app).with_graceful_shutdown(shutdown).await;
    scan_worker.abort();
    store.close().await;
    serve_result.map_err(|e| anyhow::anyhow!("http server: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

fn print_startup_banner() {
    if !std::io::stdout().is_terminal() {
        return;
    }
    print!("{}", startup_banner(should_colorize_stdout()));
}

fn should_colorize_stdout() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|value| value == "0") {
        return false;
    }
    !std::env::var("TERM").is_ok_and(|value| value == "dumb")
}

fn startup_banner(color: bool) -> String {
    let mut out = String::new();
    out.push('\n');
    for (nyx, agent) in NYX_AGENT_BANNER {
        if color {
            out.push_str(ANSI_NYX_GREEN);
            out.push_str(nyx);
            out.push_str(ANSI_NYX_GOLD);
            out.push_str(agent);
            out.push_str(ANSI_RESET);
        } else {
            out.push_str(nyx);
            out.push_str(agent);
        }
        out.push('\n');
    }
    if color {
        out.push_str(ANSI_NYX_MUTED);
        out.push_str(NYX_AGENT_TAGLINE);
        out.push_str(ANSI_RESET);
    } else {
        out.push_str(NYX_AGENT_TAGLINE);
    }
    out.push_str("\n\n");
    out
}

struct ScanRequest {
    repo: Option<String>,
    reply: oneshot::Sender<Result<String, ScanTriggerError>>,
}

struct MpscScanTrigger {
    tx: mpsc::Sender<ScanRequest>,
}

impl ScanTrigger for MpscScanTrigger {
    fn trigger<'a>(
        &'a self,
        repo: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            let (reply, rx) = oneshot::channel();
            self.tx
                .send(ScanRequest { repo, reply })
                .await
                .map_err(|_| ScanTriggerError::Closed)?;
            rx.await.map_err(|_| ScanTriggerError::Closed)?
        })
    }
}

async fn run_scan_for_api(
    state_dir: &StateDir,
    config: &Config,
    repo: Option<&str>,
    events: EventSink,
) -> Result<String, ScanTriggerError> {
    let requested: Vec<String> = match repo {
        Some(name) => vec![name.to_string()],
        None => Vec::new(),
    };
    let selected = select_repos(config, &requested).map_err(|e| {
        let msg = format!("{e:#}");
        if msg.contains("not declared") || msg.contains("enabled = false") {
            ScanTriggerError::Rejected(msg)
        } else {
            ScanTriggerError::Internal(msg)
        }
    })?;
    if selected.is_empty() {
        return Err(ScanTriggerError::Rejected(
            "no repositories selected; configure one in nyx-agent.toml".to_string(),
        ));
    }

    let store = Store::open(state_dir.root()).await.map_err(internal_string)?;

    let run = Run::new();
    let run_record = build_run_record(&run, "UI");
    store.runs().insert(&run_record).await.map_err(internal_string)?;

    let run_id_out = run.id.clone();
    let cfg = config.clone();
    let sd = state_dir.clone();
    tokio::spawn(async move {
        let res = drive_scan(&sd, &cfg, &store, selected, &run, events, false).await;
        store.close().await;
        if let Err(err) = res {
            eprintln!("scan (api): {err:#}");
        }
    });

    Ok(run_id_out)
}

fn internal_string<E: std::fmt::Display>(e: E) -> ScanTriggerError {
    ScanTriggerError::Internal(format!("{e}"))
}

async fn build_scan_lane(config: &Config) -> anyhow::Result<NyxScanLane> {
    let min = resolve_min_nyx_version(config)?;
    let runner = NyxRunner::discover(config.nyx.binary_path.as_deref(), &min).await?;
    Ok(NyxScanLane::new(runner))
}

async fn upsert_repo_record(
    store: &Store,
    ingested: &IngestedRepo,
    now_ms: i64,
) -> anyhow::Result<()> {
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
    Ok(())
}

async fn persist_run_results(store: &Store, bundle: &RunBundle<Diag>) -> anyhow::Result<()> {
    let now_ms = now_epoch_ms();
    for repo_bundle in &bundle.per_repo {
        store.repos().set_last_scan(&repo_bundle.repo, &bundle.run_id, now_ms).await?;
        if let RepoOutcome::Success(diags) = &repo_bundle.outcome {
            for diag in diags {
                let line = i64::from(diag.line);
                let id = finding_id_hash(
                    &repo_bundle.repo,
                    &diag.path,
                    Some(line),
                    &diag.cap,
                    &diag.rule,
                );
                let rec = FindingRecord {
                    id,
                    run_id: bundle.run_id.clone(),
                    repo: repo_bundle.repo.clone(),
                    path: diag.path.clone(),
                    line: Some(line),
                    cap: diag.cap.clone(),
                    rule: diag.rule.clone(),
                    severity: diag.severity.clone(),
                    status: "Open".to_string(),
                    finding_origin: "Static".to_string(),
                    first_seen: now_ms,
                    last_seen: now_ms,
                    superseded_by: None,
                    triage_state: "Open".to_string(),
                    triage_assigned_to: None,
                    verdict_blob: diag
                        .message
                        .as_ref()
                        .map(|m| serde_json::json!({ "message": m }).to_string()),
                    repro_path: None,
                    attack_provenance: None,
                    prompt_version: None,
                    chain_id: None,
                };
                store.findings().upsert(&rec).await?;
            }
        }
    }
    Ok(())
}

async fn finalise_run(
    store: &Store,
    run_id: &str,
    started_at_ms: i64,
    wall_clock_ms: i64,
    status: &str,
) -> anyhow::Result<()> {
    let finished_at = now_epoch_ms();
    let wall = if wall_clock_ms == 0 { finished_at - started_at_ms } else { wall_clock_ms };
    store.runs().finish(run_id, finished_at, status, wall).await?;
    Ok(())
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
    let nyx_code = match NyxRunner::discover(override_path, &min_version).await {
        Ok(runner) => {
            println!(
                "nyx OK at {} (version {}, minimum {})",
                runner.binary().display(),
                runner.version(),
                min_version
            );
            ExitCode::SUCCESS
        }
        Err(err @ NyxError::NyxNotFound { .. }) => {
            eprintln!("nyx FAIL: {err}");
            eprintln!(
                "  install the upstream `nyx` scanner and put it on PATH, or set [nyx].binary_path"
            );
            ExitCode::from(1)
        }
        Err(err @ NyxError::VersionTooOld { .. }) => {
            eprintln!("nyx FAIL: {err}");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("nyx FAIL: {err}");
            ExitCode::from(1)
        }
    };

    match nyx_agent_ai::detect_claude_binary().await {
        Ok(bin) => println!("claude-code: available v{} at {}", bin.version, bin.path.display()),
        Err(err) => println!("claude-code: unavailable ({err})"),
    }

    Ok(nyx_code)
}

fn resolve_min_nyx_version(config: &Config) -> anyhow::Result<Version> {
    let raw = config.nyx.min_version.as_deref().unwrap_or(MINIMUM_NYX_VERSION);
    Version::parse(raw)
        .map_err(|e| anyhow::anyhow!("[nyx].min_version `{raw}` is not a valid semver: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_banner_renders_plain_solid_tagline() {
        let banner = startup_banner(false);

        assert!(banner.contains("███╗   ██╗"));
        assert!(banner.contains("automated pentesting, refined"));
        assert!(!banner.contains("\x1b["));
    }

    #[test]
    fn startup_banner_can_render_with_brand_colors() {
        let banner = startup_banner(true);

        assert!(banner.contains(ANSI_NYX_GREEN));
        assert!(banner.contains(ANSI_NYX_GOLD));
        assert!(banner.contains(ANSI_NYX_MUTED));
        assert!(banner.contains("automated pentesting, refined"));
    }
}

use std::collections::HashMap;
use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use nyx_agent_api::{
    build_router, AuthConfig, EnvSecretResolver, ScanTrigger, ScanTriggerError, ServerState,
    SetupContext, WebhookConfig,
};
use nyx_agent_core::store::{finding_id_hash, FindingRecord, RepoRecord, RunRecord};
use nyx_agent_core::{
    ingest, now_epoch_ms, Config, IngestError, IngestedRepo, LogConfig, Repo, RepoOutcome,
    RepoSource, Run, RunBundle, RunDispatcher, SandboxBackend, SecretStore, StateDir, Store,
    WorkspaceHandle,
};
use nyx_agent_nyx::{Diag, NyxError, NyxRunner, NyxScanLane, MINIMUM_NYX_VERSION};
use nyx_agent_sandbox::{select_backend, BackendChoice, BackendKind, Lane, LaneConcurrency};
use nyx_agent_types::event::{AgentEvent, EventSink, RunEvent};
use semver::Version;
use tokio::sync::{broadcast, mpsc, oneshot};

mod ai_pipeline;
mod cmd;
mod scheduler;

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
enum InspectTarget {
    /// List AI-discovered findings + candidates that are still
    /// quarantined (i.e. not yet promoted by the dynamic-confirm
    /// verifier or manual operator).
    Quarantine,
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
        /// Run without opening a browser or prompting. Scan never does
        /// either, so this is accepted for compatibility with CI
        /// invocations that re-use the flag from `serve`.
        #[arg(long)]
        headless: bool,
        /// Write a machine-readable JSON report to `PATH`. Consumed by
        /// `pr-comment --report` and by external dashboards.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Filter the report to findings whose `path` differs from
        /// `REF` (i.e. only paths the PR / branch touched). Computed
        /// per workspace via `git diff --name-only REF...HEAD`. When
        /// the diff cannot be computed, scan exits non-zero so CI
        /// loudly surfaces the misconfiguration.
        #[arg(long, value_name = "REF")]
        since_ref: Option<String>,
    },
    /// Post (or update) a dedup'd PR comment summarising Confirmed +
    /// cross-repo chain findings from a previous `scan --output` run.
    ///
    /// The comment lives in the operator's GitHub PR; everything else
    /// (Open, Quarantine, Inconclusive, AI trace viewer, repro
    /// bundles) stays in the operator's local UI.
    PrComment {
        /// Path to `report.json` (produced by `scan --output`).
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
        /// GitHub repository in `owner/repo` form. Defaults to
        /// `$GITHUB_REPOSITORY` when running inside an Actions
        /// workflow.
        #[arg(long, value_name = "OWNER/REPO", env = "GITHUB_REPOSITORY")]
        repo: String,
        /// Pull request number. Defaults to the integer parsed from
        /// `$GITHUB_REF` when it matches `refs/pull/<N>/merge` or
        /// `refs/pull/<N>/head`.
        #[arg(long, value_name = "N")]
        pr: Option<u32>,
        /// Base URL of the operator's local UI. Findings link back
        /// here. Trailing slash optional.
        #[arg(long, value_name = "URL")]
        ui_url: Option<String>,
        /// GitHub REST base. Override for GHE; defaults to
        /// `https://api.github.com`.
        #[arg(long, value_name = "URL", default_value = cmd::pr_comment::DEFAULT_GH_API_BASE)]
        gh_api: String,
        /// Environment variable to read the GitHub token from. The
        /// token never appears in argv or logs.
        #[arg(long, value_name = "ENV", default_value = "GITHUB_TOKEN")]
        token_env: String,
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
    /// Inspect persisted state. Sub-commands print terse listings the
    /// operator can grep / pipe.
    Inspect {
        #[command(subcommand)]
        target: InspectTarget,
    },
    /// Show budget consumption for the current configuration.
    Budget,
    /// Print AI conversation traces (filtered by finding when supplied).
    Traces {
        /// Finding id to scope the listing to. Omit to list every trace
        /// row currently persisted.
        #[arg(long = "finding", value_name = "FINDING")]
        finding: Option<String>,
    },
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
        Command::Scan { repos, headless: _, output, since_ref } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            scan(&state_dir, &config, &repos, "Manual", output.as_deref(), since_ref.as_deref())
                .await
        }
        Command::PrComment { report, repo, pr, ui_url, gh_api, token_env } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            pr_comment_cmd(&report, repo, pr, ui_url, gh_api, &token_env).await
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
        Command::Inspect { target } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            match target {
                InspectTarget::Quarantine => inspect_quarantine(&state_dir).await,
            }
        }
        Command::Traces { finding } => {
            nyx_agent_core::init_logging(&log_cfg)?;
            inspect_traces(&state_dir, finding.as_deref()).await
        }
        Command::Reverify { .. } | Command::Budget => {
            nyx_agent_core::init_logging(&log_cfg)?;
            todo!("subcommand wiring lands in a later phase")
        }
    }
}

async fn inspect_quarantine(state_dir: &StateDir) -> anyhow::Result<ExitCode> {
    let store = Store::open(state_dir.root()).await?;
    let filter = nyx_agent_core::store::FindingFilter {
        status: Some("Quarantine"),
        include_quarantine: true,
        ..nyx_agent_core::store::FindingFilter::default()
    };
    let findings = store.findings().list_filtered(&filter).await?;
    let pending = store.candidate_findings().list_pending().await?;
    if findings.is_empty() && pending.is_empty() {
        println!("quarantine: empty");
        store.close().await;
        return Ok(ExitCode::SUCCESS);
    }
    println!("kind     id                                 cap                  repo            path:line");
    for f in &findings {
        println!(
            "finding  {:<34} {:<20} {:<15} {}:{}",
            truncate_for_column(&f.id, 34),
            truncate_for_column(&f.cap, 20),
            truncate_for_column(&f.repo, 15),
            f.path,
            f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
        );
    }
    for c in &pending {
        println!(
            "candid.  {:<34} {:<20} {:<15} {}:{}",
            truncate_for_column(&c.id, 34),
            truncate_for_column(&c.cap, 20),
            truncate_for_column(&c.repo, 15),
            c.path,
            c.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
        );
    }
    println!("\n{} finding(s) + {} candidate(s) quarantined", findings.len(), pending.len());
    store.close().await;
    Ok(ExitCode::SUCCESS)
}

async fn inspect_traces(state_dir: &StateDir, finding: Option<&str>) -> anyhow::Result<ExitCode> {
    let store = Store::open(state_dir.root()).await?;
    let rows = if let Some(fid) = finding {
        store.agent_traces().list_for_finding(fid).await?
    } else {
        // No global "list all" exists on the store; gather every task-kind
        // bucket so the CLI surface stays useful while a dedicated reader
        // lands later.
        let mut all = Vec::new();
        for kind in
            ["PayloadSynthesis", "SpecDerivation", "ChainReasoning", "NovelFindings", "Exploration"]
        {
            all.extend(store.agent_traces().list_by_task_kind(kind).await?);
        }
        all.sort_by_key(|r| r.started_at);
        all
    };
    if rows.is_empty() {
        println!("traces: no rows match");
        store.close().await;
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "task                runtime         model           prompt_version                  cost($) dur_ms finding_id"
    );
    for r in &rows {
        println!(
            "{:<19} {:<15} {:<15} {:<31} {:>7.4} {:>6} {}",
            truncate_for_column(&r.task_kind, 19),
            truncate_for_column(&r.runtime_name, 15),
            truncate_for_column(&r.model, 15),
            truncate_for_column(r.prompt_version.as_deref().unwrap_or(""), 31),
            r.cost_usd_micros as f64 / 1_000_000.0,
            r.duration_ms.unwrap_or(0),
            r.finding_id.as_deref().unwrap_or("-"),
        );
    }
    store.close().await;
    Ok(ExitCode::SUCCESS)
}

fn truncate_for_column(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut cut = max.saturating_sub(1);
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

async fn scan(
    state_dir: &StateDir,
    config: &Config,
    requested: &[String],
    triggered_by: &str,
    output_path: Option<&std::path::Path>,
    since_ref: Option<&str>,
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
    let result = drive_scan(
        state_dir,
        config,
        &store,
        selected,
        &run,
        events_tx,
        true,
        output_path,
        since_ref,
    )
    .await;

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
#[allow(clippy::too_many_arguments)]
async fn drive_scan(
    state_dir: &StateDir,
    config: &Config,
    store: &Store,
    selected: Vec<Repo>,
    run: &Run,
    events: EventSink,
    verbose: bool,
    output_path: Option<&std::path::Path>,
    since_ref: Option<&str>,
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
            if verbose && (report.synthesised > 0 || report.quarantined > 0 || report.failed > 0) {
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
            if verbose && (report.synthesised > 0 || report.quarantined > 0 || report.failed > 0) {
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
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            if verbose && (report.chains_persisted > 0 || report.failed > 0) {
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

    // Phase 17: scan repo source for candidate vulnerabilities the
    // static pass missed. Most-expensive pass; each batch is gated on a
    // per-run cap ($5 default), and every emitted CandidateFinding
    // lands in `candidate_findings.Pending` so nothing surfaces to the
    // operator until the Phase 19 verifier promotes it.
    match ai_pipeline::run_novel_finding_discovery_pass(
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
                && (report.candidates_persisted > 0
                    || report.batches_dispatched > 0
                    || report.batches_halted > 0
                    || report.failed > 0)
            {
                println!(
                    "scan: novel finding discovery - {} candidates, {} batches dispatched ({} halted), {} failed ({} attempts, ${:.6})",
                    report.candidates_persisted,
                    report.batches_dispatched,
                    report.batches_halted,
                    report.failed,
                    report.attempts,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "novel finding discovery pass failed"),
    }

    // Phase 23: drive the Claude Code agent loop against the running
    // chain-lane sandbox so the model can probe shadow APIs, CORS
    // misconfig, business-logic skips, etc. Gated by the Phase 18
    // escape suite (a red fixture halts the driver) and capped by a
    // per-run hard cap (default $10) plus a soft warning threshold.
    // Findings land in `findings` with `finding_origin =
    // AiExploration` and `status = Quarantine`; the verifier below
    // promotes them on Confirmed.
    let escape_gate = ai_pipeline::StaticEscapeSuiteGate::green();
    match ai_pipeline::run_ai_exploration_pass(
        &config.ai,
        store,
        &bundle,
        &workspaces_for_ai,
        &escape_gate,
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            if verbose
                && (report.explorations_dispatched > 0
                    || report.findings_quarantined > 0
                    || report.halted_escape_suite_red > 0
                    || report.halted_budget_exhausted > 0
                    || report.failed > 0)
            {
                println!(
                    "scan: ai exploration - {} dispatched, {} findings quarantined, {} halted (escape) / {} halted (budget), {} failed (${:.6})",
                    report.explorations_dispatched,
                    report.findings_quarantined,
                    report.halted_escape_suite_red,
                    report.halted_budget_exhausted,
                    report.failed,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "ai exploration pass failed"),
    }

    // Phase 19: drive the deterministic payload runner across every
    // finding (and AI-discovered candidate) that has a payload+spec
    // pair ready. Confirms or rejects each row under differential
    // rule v1; Quarantined candidates flip to Promoted on Confirmed.
    match ai_pipeline::run_payload_verification_pass(
        &config.run,
        &config.sandbox,
        store,
        &bundle,
        &workspaces_for_ai,
        events,
    )
    .await
    {
        Ok(report) => {
            if verbose
                && (report.confirmed > 0
                    || report.not_confirmed > 0
                    || report.errored > 0
                    || report.candidates_promoted > 0
                    || report.failed > 0)
            {
                println!(
                    "scan: verifier - {} confirmed, {} not-confirmed, {} errored, {} candidates promoted, {} failed ({} skipped no-payload)",
                    report.confirmed,
                    report.not_confirmed,
                    report.errored,
                    report.candidates_promoted,
                    report.failed,
                    report.skipped_no_payload,
                );
            }
        }
        Err(err) => tracing::warn!(error = %err, "verifier pass failed"),
    }

    let counts = bundle.counts();
    let success = counts.failed == 0 && ingest_failures.is_empty();
    let final_status = if success { "Succeeded" } else { "Failed" };
    finalise_run(store, &run.id, run.started_at_ms, bundle.wall_clock_ms, final_status).await?;

    if let Some(path) = output_path {
        let changed = match since_ref {
            Some(ref_name) => Some(collect_changed_files(&workspaces_for_ai, ref_name).await?),
            None => None,
        };
        let started_at = run.started_at_ms;
        let finished_at = started_at + bundle.wall_clock_ms;
        let meta = cmd::scan_report::RunMeta {
            started_at,
            finished_at: Some(finished_at),
            status: final_status,
            triggered_by: "Manual",
        };
        let report =
            cmd::scan_report::build_report(store, &run.id, meta, since_ref, changed.as_ref())
                .await?;
        report.write(path)?;
        if verbose {
            println!(
                "scan: wrote report to {} ({} finding(s), {} chain(s))",
                path.display(),
                report.findings.len(),
                report.chains.len()
            );
        }
    }

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
    let mut server_state =
        ServerState::new(store.clone(), events_tx.clone(), trigger.clone(), setup, auth_config)
            .with_state_repos_dir(state_dir.repos())
            .with_state_bundles_dir(state_dir.bundles());

    // Phase 27: enable `POST /webhook/git` when the operator has
    // configured a shared secret. Resolves the env-backed ref on each
    // request so a wizard rotate flow does not require a daemon
    // restart.
    if config.triggers.webhook_secret_ref.is_some() {
        let resolver =
            Arc::new(EnvSecretResolver { spec: config.triggers.webhook_secret_ref.clone() });
        server_state = server_state.with_webhook(WebhookConfig {
            secret: resolver,
            branch: config.triggers.webhook_branch.clone(),
            repo: None,
        });
    }

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

    // Phase 27: spawn the cron scheduler when at least one
    // `[[schedule]]` entry is configured. The watch channel is the
    // shutdown signal — flipping it to `true` ends the loop.
    let (scheduler_shutdown_tx, scheduler_shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_handle = if config.schedules.is_empty() {
        None
    } else {
        match scheduler::Scheduler::from_config(&config.schedules, trigger.clone()) {
            Ok(s) => {
                let rx = scheduler_shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    s.run(scheduler::DEFAULT_TICK_INTERVAL, rx).await;
                }))
            }
            Err(err) => {
                eprintln!("warn: scheduler refused config: {err}");
                None
            }
        }
    };

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    let serve_result = axum::serve(listener, app).with_graceful_shutdown(shutdown).await;
    scan_worker.abort();
    let _ = scheduler_shutdown_tx.send(true);
    if let Some(h) = scheduler_handle {
        h.abort();
    }
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
            // Phase 27: non-blocking submit so an external scheduler /
            // webhook / CI loop sees a fast HTTP 429 instead of stalling
            // on `send().await` when the dispatcher is saturated. The
            // bound is set in `serve()`; raise it there if a real load
            // profile demands a deeper queue.
            self.tx.try_send(ScanRequest { repo, reply }).map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => ScanTriggerError::Backpressure(
                    "scan request queue is full; retry after the current run completes".to_string(),
                ),
                mpsc::error::TrySendError::Closed(_) => ScanTriggerError::Closed,
            })?;
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
        let res = drive_scan(&sd, &cfg, &store, selected, &run, events, false, None, None).await;
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

/// Run `git diff --name-only --diff-filter=AMR REF...HEAD` in each
/// workspace and collect the resulting paths keyed by repo name.
async fn collect_changed_files(
    workspaces: &HashMap<String, WorkspaceHandle>,
    since_ref: &str,
) -> anyhow::Result<HashMap<String, std::collections::HashSet<String>>> {
    if since_ref.starts_with('-') {
        anyhow::bail!(
            "scan: --since-ref `{since_ref}` must not start with `-` (would be parsed as a git option)"
        );
    }
    let mut out: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for (name, handle) in workspaces {
        let workspace = handle.workspace().to_path_buf();
        let ref_name = since_ref.to_string();
        let output = tokio::process::Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .arg("diff")
            .arg("--name-only")
            .arg("--diff-filter=AMR")
            .arg("--end-of-options")
            .arg(format!("{ref_name}...HEAD"))
            .output()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "scan: failed to spawn `git diff` in workspace {} for repo `{name}`: {e}",
                    workspace.display()
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "scan: `git diff {ref_name}...HEAD` in workspace {} for repo `{name}` failed: {stderr}",
                workspace.display()
            );
        }
        let set = out.entry(name.clone()).or_default();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_string());
            }
        }
    }
    Ok(out)
}

async fn pr_comment_cmd(
    report_path: &std::path::Path,
    repo: String,
    pr: Option<u32>,
    ui_url: Option<String>,
    gh_api: String,
    token_env: &str,
) -> anyhow::Result<ExitCode> {
    let token = match std::env::var(token_env) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("pr-comment: env var `{token_env}` is empty or unset");
            return Ok(ExitCode::from(1));
        }
    };
    let pr_number = match pr.or_else(detect_pr_from_env) {
        Some(n) => n,
        None => {
            eprintln!(
                "pr-comment: --pr not provided and could not be derived from $GITHUB_REF / $GITHUB_EVENT_PATH"
            );
            return Ok(ExitCode::from(1));
        }
    };
    let cfg = cmd::pr_comment::PrCommentConfig { repo, pr: pr_number, token, ui_url, gh_api };
    match cmd::pr_comment::run(report_path, cfg).await {
        Ok(outcome) => {
            if outcome.skipped_empty {
                println!(
                    "pr-comment: report contains no Confirmed or cross-repo chain findings; skipping comment"
                );
            } else if outcome.updated_existing {
                println!(
                    "pr-comment: updated existing comment ({} finding(s), {} chain(s))",
                    outcome.posted_findings, outcome.posted_chains
                );
            } else {
                println!(
                    "pr-comment: created comment ({} finding(s), {} chain(s))",
                    outcome.posted_findings, outcome.posted_chains
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            eprintln!("pr-comment: {err}");
            Ok(ExitCode::from(1))
        }
    }
}

/// Best-effort PR number recovery from the GitHub Actions environment.
/// Honours `$GITHUB_REF` of the shape `refs/pull/<N>/{merge,head}` —
/// the standard `pull_request` trigger sets it — and falls back to
/// parsing `pull_request.number` from the JSON payload at
/// `$GITHUB_EVENT_PATH` (the `workflow_dispatch` /
/// `pull_request_review` triggers only expose the PR number there).
fn detect_pr_from_env() -> Option<u32> {
    if let Ok(r) = std::env::var("GITHUB_REF") {
        if let Some(rest) = r.strip_prefix("refs/pull/") {
            if let Some((num, _)) = rest.split_once('/') {
                if let Ok(n) = num.parse() {
                    return Some(n);
                }
            }
        }
    }
    let event_path = std::env::var("GITHUB_EVENT_PATH").ok()?;
    let bytes = std::fs::read(&event_path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let n = v.get("pull_request")?.get("number")?.as_u64()?;
    u32::try_from(n).ok()
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

    report_sandbox_backends(config);

    Ok(nyx_code)
}

fn report_sandbox_backends(config: &Config) {
    let choice = match config.sandbox.backend {
        SandboxBackend::Auto => BackendChoice::Auto,
        SandboxBackend::Process => BackendChoice::Pinned(BackendKind::Process),
        SandboxBackend::Birdcage => BackendChoice::Pinned(BackendKind::Birdcage),
        SandboxBackend::Libkrun => BackendChoice::Pinned(BackendKind::Libkrun),
        SandboxBackend::Firecracker => BackendChoice::Pinned(BackendKind::Firecracker),
        SandboxBackend::Docker => BackendChoice::Pinned(BackendKind::Docker),
    };
    let chain = select_backend(choice, Lane::Chain);
    let fast = select_backend(choice, Lane::Fast);
    let cap = LaneConcurrency::defaults();
    println!(
        "sandbox chain lane -> {} ({}) [{} simultaneous]",
        chain.backend.as_str(),
        chain.reason,
        cap.chain
    );
    println!(
        "sandbox fast lane  -> {} ({}) [{} simultaneous]",
        fast.backend.as_str(),
        fast.reason,
        cap.fast
    );
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use nyctos_ai::{LiveEvidenceReviewDecision, LiveEvidenceReviewOutput};
use nyctos_api::{
    build_router, AuthConfig, EnvSecretResolver, ScanRunOverrides, ScanTrigger, ScanTriggerError,
    ScanTriggerSource, ServerState, SetupContext, WebhookConfig, WebhookSecretResolver,
};
use nyctos_core::store::{
    finding_id_hash, CandidateFindingRecord, FindingRecord, NyxSignalRecord,
    PentestCandidateRecord, ProjectRecord, RepoOutcomeLabel, RepoRecord, RouteModelRecord,
    RunRecord, RunRepoOutcomeRecord, VerificationAttemptRecord, VerifiedVulnerabilityRecord,
};
use nyctos_core::{
    ingest, now_epoch_ms, repo_from_config, AiConfig, Config, InconclusiveReason, IngestError,
    IngestedRepo, LogConfig, Project, ProjectConfig, ProjectId, Repo, RepoOutcome, RepoSource,
    RepoSourceConfig, Run, RunBundle, RunCounts, RunDispatcher, RunEventLogWriter, SandboxBackend,
    SecretStore, StateDir, Store, WorkspaceHandle,
};
use nyctos_nyx::{Diag, NyxError, NyxRunner, NyxScanLane, MINIMUM_NYX_VERSION};
use nyctos_sandbox::{select_backend, BackendChoice, BackendKind, Lane};
use nyctos_types::event::{AgentEvent, AiEvent, EventSink, RunEvent, SandboxEvent};
use nyctos_types::product::{
    canonical_risk_rating, clamp_risk_score, risk_rating_for_score, LaunchHealthCheck, LaunchStep,
    ProjectLaunchProfileInput,
};
use nyctos_types::project::{ProjectRuntimeCommand, ProjectRuntimeProfile};
use regex::Regex;
use semver::Version;
use tokio::sync::{broadcast, mpsc, oneshot};

mod ai_pipeline;
mod attacker_playbooks;
mod auth_sessions;
mod auth_setup_ai;
mod banner;
mod business_logic_templates;
mod candidate_sources;
mod cmd;
mod launch;
mod live_planning;
mod node_runtime;
mod pentest_tools;
mod route_model;
mod scheduler;

use banner::print_startup_banner;
use launch::{ConservativeLaunchProfileRunner, LaunchContext, LaunchProfileRunner};

#[derive(Debug, Parser)]
#[command(name = "nyctos", version, about = "Nyctos repository agent", propagate_version = true)]
struct Cli {
    /// Path to `nyctos.toml`. Defaults to `./nyctos.toml`.
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
enum ProjectAction {
    /// Create a project row by name. Fails if the name already exists.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        target_base_url: Option<String>,
    },
    /// List every project row, alphabetical by name.
    List,
    /// Show one project plus the repos attached to it.
    Show { name: String },
    /// Delete a project by name. Cascades to repos via the FK.
    Delete { name: String },
    /// Attach a repo to a project. The source is either local
    /// (`--path`) or git (`--git-url`).
    AddRepo {
        /// Project name the repo will belong to.
        project: String,
        /// Unique repo name.
        name: String,
        /// Local path to snapshot. Mutually exclusive with `--git-url`.
        #[arg(long, value_name = "PATH", conflicts_with = "git_url")]
        path: Option<PathBuf>,
        /// Remote git URL to clone. Mutually exclusive with `--path`.
        #[arg(long, value_name = "URL", conflicts_with = "path")]
        git_url: Option<String>,
        /// Branch hint for git sources.
        #[arg(long)]
        branch: Option<String>,
        /// Auth descriptor (`ssh-key:<path>`, `token-env:<var>`,
        /// `gh-app:<id>`) for git sources.
        #[arg(long)]
        auth: Option<String>,
        /// Operator attestation. The daemon refuses to ingest a repo
        /// without this flag set.
        #[arg(long)]
        i_own_this: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BusinessLogicAction {
    /// List registered business-logic pentest templates.
    Templates {
        /// Emit JSON instead of the operator-friendly table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan one or more repositories for findings. Selection is
    /// project-scoped: `--project NAME` (repeatable) targets a whole
    /// project; pair with `--repo NAME` (repeatable) to narrow within
    /// the selected projects. Bare `--repo` without `--project` is
    /// rejected to keep scoping explicit.
    Scan {
        /// Projects to scan (by name from `nyctos.toml`). Pass
        /// `--project` once per project, or omit to scan every enabled
        /// project.
        #[arg(long = "project", value_name = "PROJECT")]
        projects: Vec<String>,
        /// Repositories to scan, narrowed within `--project`. Requires
        /// at least one `--project` to be set.
        #[arg(long = "repo", value_name = "REPO")]
        repos: Vec<String>,
        /// Suppress human-readable progress on stdout so only
        /// `--output PATH` carries machine-readable signal. Errors still
        /// go to stderr. Use in CI lanes that only want the report file.
        #[arg(long)]
        headless: bool,
        /// Write a machine-readable JSON report to `PATH`. Consumed by
        /// `pr-comment --report` and by external dashboards.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// When `--output` is set, drop every row `pr-comment` would
        /// not render before writing: keep only `Verified` findings and
        /// the members of cross-repo chains. Bounds the on-disk report
        /// for CI artefact size limits at the cost of losing the
        /// local-only triage rows.
        #[arg(long, requires = "output")]
        output_only_pr_worthy: bool,
        /// Filter the report to findings whose `path` differs from
        /// `REF` (i.e. only paths the PR / branch touched). Computed
        /// per workspace via `git diff --name-only REF...HEAD`. When
        /// the diff cannot be computed, scan exits non-zero so CI
        /// loudly surfaces the misconfiguration.
        #[arg(long, value_name = "REF")]
        since_ref: Option<String>,
        /// Enable exploit mode for this scan without editing
        /// `nyctos.toml`. State-changing probes still also require
        /// `--allow-state-changing-live-probes`.
        #[arg(long)]
        exploit_mode: bool,
        /// Allow state-changing live probes for this scan. Requires
        /// exploit mode through config or `--exploit-mode`.
        #[arg(long)]
        allow_state_changing_live_probes: bool,
        /// Evaluate guarded live probes and write audit records without
        /// sending HTTP/browser traffic.
        #[arg(long)]
        exploit_dry_run: bool,
        /// Enable browser-driven verification for this scan without
        /// editing `nyctos.toml`.
        #[arg(long)]
        browser_checks: bool,
        /// Disable business-logic template candidate synthesis for this
        /// scan.
        #[arg(long)]
        no_business_logic_templates: bool,
        /// Enable deeper authorized product-logic research for this
        /// scan. This adds invariant-focused hypotheses and deeper AI
        /// planning/exploration, without relaxing live safety gates.
        #[arg(long)]
        research_mode: bool,
        /// Run the unrestricted local attack-agent phase at the end of
        /// the pentest. Intended only for disposable user-owned dev
        /// environments.
        #[arg(long)]
        unsafe_attack_agent: bool,
        /// Restrict business-logic candidate synthesis to specific
        /// template ids. Repeat for multiple templates.
        #[arg(long = "business-template", value_name = "ID")]
        business_logic_template_ids: Vec<String>,
        /// Skip launch-profile orchestration for this scan, even when
        /// the project has a default launch profile.
        #[arg(long)]
        no_orchestration: bool,
        /// One-shot local app URL for this scan. Requires a single
        /// project target and creates a run-scoped launch profile.
        #[arg(long, value_name = "URL")]
        app_url: Option<String>,
        /// Override the app readiness URL for a one-shot launch profile.
        #[arg(long, value_name = "URL")]
        health_url: Option<String>,
        /// Timeout in seconds for `--health-url` / default URL readiness.
        #[arg(long, value_name = "SECONDS")]
        health_timeout_secs: Option<u64>,
        /// Build/setup command for a one-shot launch profile. Repeat
        /// for multiple commands.
        #[arg(long = "build-command", value_name = "CMD")]
        build_commands: Vec<String>,
        /// Start command for a one-shot launch profile. Repeat for
        /// multiple commands.
        #[arg(long = "start-command", value_name = "CMD")]
        start_commands: Vec<String>,
        /// Seed command for a one-shot launch profile. Repeat for
        /// multiple commands.
        #[arg(long = "seed-command", value_name = "CMD")]
        seed_commands: Vec<String>,
        /// Reset command used after state-changing probes. Repeat for
        /// multiple commands.
        #[arg(long = "reset-command", value_name = "CMD")]
        reset_commands: Vec<String>,
        /// Login/session setup command for a one-shot launch profile.
        /// Repeat for multiple commands.
        #[arg(long = "login-command", value_name = "CMD")]
        login_commands: Vec<String>,
        /// Stop command for a one-shot launch profile. Repeat for
        /// multiple commands.
        #[arg(long = "stop-command", value_name = "CMD")]
        stop_commands: Vec<String>,
    },
    /// Inspect business-logic pentest template metadata.
    BusinessLogic {
        #[command(subcommand)]
        action: BusinessLogicAction,
    },
    /// Manage `Project` rows in the agent's state DB. Projects own
    /// repos; the daemon's scan/run pipeline operates per project.
    Project {
        #[command(subcommand)]
        action: ProjectAction,
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
    let config_path = cli.config.clone().unwrap_or_else(|| PathBuf::from("nyctos.toml"));
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
        Command::Scan {
            projects,
            repos,
            headless,
            output,
            output_only_pr_worthy,
            since_ref,
            exploit_mode,
            allow_state_changing_live_probes,
            exploit_dry_run,
            browser_checks,
            no_business_logic_templates,
            research_mode,
            unsafe_attack_agent,
            business_logic_template_ids,
            no_orchestration,
            app_url,
            health_url,
            health_timeout_secs,
            build_commands,
            start_commands,
            seed_commands,
            reset_commands,
            login_commands,
            stop_commands,
        } => {
            nyctos_core::init_logging(&log_cfg)?;
            let mut run_config = config.clone();
            if exploit_mode {
                run_config.run.exploit_mode_enabled = true;
            }
            if allow_state_changing_live_probes {
                run_config.run.allow_state_changing_live_probes = true;
            }
            if exploit_dry_run {
                run_config.run.exploit_dry_run = true;
            }
            if browser_checks {
                run_config.run.browser_checks_enabled = true;
            }
            if no_business_logic_templates {
                run_config.run.business_logic_templates_enabled = false;
            }
            if research_mode {
                run_config.run.research_mode_enabled = true;
            }
            if unsafe_attack_agent {
                run_config.run.unsafe_attack_agent_enabled = true;
            }
            if !business_logic_template_ids.is_empty() {
                run_config.run.business_logic_template_ids = business_logic_template_ids;
            }
            let orchestration = ScanOrchestrationOverrides {
                enabled: !no_orchestration,
                app_url,
                health_url,
                health_timeout_secs,
                build_commands,
                start_commands,
                seed_commands,
                reset_commands,
                login_commands,
                stop_commands,
            };
            scan(
                &state_dir,
                &run_config,
                &projects,
                &repos,
                "Manual",
                output.as_deref(),
                output_only_pr_worthy,
                since_ref.as_deref(),
                headless,
                orchestration,
            )
            .await
        }
        Command::BusinessLogic { action } => business_logic_command(action),
        Command::Project { action } => {
            nyctos_core::init_logging(&log_cfg)?;
            project_command(&state_dir, action).await
        }
        Command::PrComment { report, repo, pr, ui_url, gh_api, token_env } => {
            nyctos_core::init_logging(&log_cfg)?;
            pr_comment_cmd(&report, repo, pr, ui_url, gh_api, &token_env).await
        }
        Command::Serve { listen, no_open, headless, open_cmd } => {
            nyctos_core::init_logging(&log_cfg)?;
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
            nyctos_core::init_logging(&log_cfg)?;
            match target {
                InspectTarget::Quarantine => inspect_quarantine(&state_dir).await,
            }
        }
        Command::Traces { finding } => {
            nyctos_core::init_logging(&log_cfg)?;
            inspect_traces(&state_dir, finding.as_deref()).await
        }
        Command::Reverify { .. } | Command::Budget => {
            nyctos_core::init_logging(&log_cfg)?;
            todo!("subcommand wiring lands in a later phase")
        }
    }
}

async fn inspect_quarantine(state_dir: &StateDir) -> anyhow::Result<ExitCode> {
    let store = Store::open(state_dir.root()).await?;
    let filter = nyctos_core::store::FindingFilter {
        status: Some("Quarantine"),
        include_quarantine: true,
        ..nyctos_core::store::FindingFilter::default()
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

#[allow(clippy::too_many_arguments)]
async fn scan(
    state_dir: &StateDir,
    config: &Config,
    requested_projects: &[String],
    requested_repos: &[String],
    triggered_by: &str,
    output_path: Option<&std::path::Path>,
    output_only_pr_worthy: bool,
    since_ref: Option<&str>,
    headless: bool,
    orchestration: ScanOrchestrationOverrides,
) -> anyhow::Result<ExitCode> {
    if !requested_repos.is_empty() && requested_projects.is_empty() {
        eprintln!(
            "scan: --repo requires --project context (or use --project to scan whole projects)"
        );
        return Ok(ExitCode::from(2));
    }

    let store = Store::open(state_dir.root()).await?;
    let targets =
        match select_scan_targets(&store, config, requested_projects, requested_repos).await {
            Ok(t) => t,
            Err(err) => {
                store.close().await;
                return Err(err);
            }
        };
    if targets.is_empty() {
        eprintln!("scan: no repositories selected; add a repo in the web UI or nyctos.toml");
        store.close().await;
        return Ok(ExitCode::from(1));
    }

    // CLI scan has no live subscribers; emitting into a dropped sink would
    // discard events, so build a self-owned bus to keep the event sink shape
    // identical to the API path. The receiver immediately drops, which makes
    // every send a no-op short of a clone.
    let (events_tx, _events_rx) = broadcast::channel::<AgentEvent>(16);

    if orchestration.has_profile_override() && targets.len() != 1 {
        store.close().await;
        anyhow::bail!("scan orchestration overrides require exactly one selected project");
    }

    let mut overall_success = true;
    let mut reports: Vec<ScanReport> = Vec::with_capacity(targets.len());
    for (project, repos) in targets {
        let run = Run::new();
        let run_record = build_run_record(&run, Some(project.id.as_str()), "Pentest", triggered_by);
        store.runs().insert(&run_record).await?;

        let result = drive_scan(
            state_dir,
            config,
            &store,
            &project,
            repos,
            &run,
            events_tx.clone(),
            !headless,
            output_path,
            output_only_pr_worthy,
            since_ref,
            orchestration.clone(),
        )
        .await;

        match result {
            Ok(report) => {
                overall_success &= report.success;
                if !headless {
                    print_scan_report(&project, &report);
                }
                reports.push(report);
            }
            Err(err) => {
                store.close().await;
                return Err(err);
            }
        }
    }

    store.close().await;
    Ok(if overall_success { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn business_logic_command(action: BusinessLogicAction) -> anyhow::Result<ExitCode> {
    match action {
        BusinessLogicAction::Templates { json } => {
            let templates = nyctos_types::business_logic::business_logic_template_metadata();
            if json {
                println!("{}", serde_json::to_string_pretty(&templates)?);
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "{:<38} {:<7} {:<18} {:<15} {:<13} {}",
                "id", "version", "category", "mutability", "availability", "title"
            );
            for template in templates {
                println!(
                    "{:<38} {:<7} {:<18} {:<15} {:<13} {}",
                    template.id,
                    template.version,
                    template.category,
                    format!("{:?}", template.mutability).to_ascii_lowercase(),
                    format!("{:?}", template.availability).to_ascii_lowercase(),
                    template.title,
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
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

#[derive(Debug, Clone)]
struct ScanOrchestrationOverrides {
    enabled: bool,
    app_url: Option<String>,
    health_url: Option<String>,
    health_timeout_secs: Option<u64>,
    build_commands: Vec<String>,
    start_commands: Vec<String>,
    seed_commands: Vec<String>,
    reset_commands: Vec<String>,
    login_commands: Vec<String>,
    stop_commands: Vec<String>,
}

impl Default for ScanOrchestrationOverrides {
    fn default() -> Self {
        Self {
            enabled: true,
            app_url: None,
            health_url: None,
            health_timeout_secs: None,
            build_commands: Vec::new(),
            start_commands: Vec::new(),
            seed_commands: Vec::new(),
            reset_commands: Vec::new(),
            login_commands: Vec::new(),
            stop_commands: Vec::new(),
        }
    }
}

impl ScanOrchestrationOverrides {
    fn has_profile_override(&self) -> bool {
        self.app_url.as_ref().is_some_and(|s| !s.trim().is_empty())
            || self.health_url.as_ref().is_some_and(|s| !s.trim().is_empty())
            || !self.build_commands.is_empty()
            || !self.start_commands.is_empty()
            || !self.seed_commands.is_empty()
            || !self.reset_commands.is_empty()
            || !self.login_commands.is_empty()
            || !self.stop_commands.is_empty()
    }
}

async fn insert_scan_override_profile(
    store: &Store,
    project: &Project,
    run_id: &str,
    overrides: &ScanOrchestrationOverrides,
) -> anyhow::Result<nyctos_core::store::ProjectLaunchProfile> {
    let target = overrides
        .app_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(project.target_base_url.as_deref());
    let target_urls = target.map(|s| vec![s.to_string()]).unwrap_or_default();
    let health_url =
        overrides.health_url.as_deref().map(str::trim).filter(|s| !s.is_empty()).or(target);
    let health_checks = health_url
        .map(|url| LaunchHealthCheck {
            kind: "http".to_string(),
            url: Some(url.to_string()),
            host: None,
            port: None,
            command: None,
            timeout_seconds: overrides.health_timeout_secs,
        })
        .into_iter()
        .collect();
    let input = ProjectLaunchProfileInput {
        name: Some("scan override".to_string()),
        mode: Some(if overrides.start_commands.is_empty() {
            "already-running".to_string()
        } else {
            "custom-commands".to_string()
        }),
        build_steps: command_strings_to_steps(&overrides.build_commands),
        start_steps: command_strings_to_steps(&overrides.start_commands),
        seed_steps: command_strings_to_steps(&overrides.seed_commands),
        reset_steps: command_strings_to_steps(&overrides.reset_commands),
        login_steps: command_strings_to_steps(&overrides.login_commands),
        stop_steps: command_strings_to_steps(&overrides.stop_commands),
        health_checks,
        target_urls,
        env_refs: Vec::new(),
        working_dirs: Vec::new(),
    };
    let profile_id = format!("lp-{run_id}-cli");
    Ok(store
        .launch_profiles()
        .insert_run_profile(&profile_id, project.id.as_str(), &input, now_epoch_ms())
        .await?)
}

fn command_strings_to_steps(commands: &[String]) -> Vec<LaunchStep> {
    commands
        .iter()
        .map(|command| command.trim())
        .filter(|command| !command.is_empty())
        .map(|command| LaunchStep {
            command: command.to_string(),
            repo_id: None,
            repo_name: None,
            working_directory: None,
            timeout_seconds: None,
        })
        .collect()
}

struct RepoReport {
    repo: String,
    outcome: nyctos_types::event::RepoOutcomeTag,
    diags: usize,
    elapsed_ms: i64,
}

fn print_scan_report(project: &Project, r: &ScanReport) {
    println!(
        "scan: project {} run {} finished in {}ms - {} succeeded, {} inconclusive, {} failed",
        project.name, r.run_id, r.wall_clock_ms, r.succeeded, r.inconclusive, r.failed,
    );
    for repo in &r.per_repo {
        println!(
            "  - {}: {:?} (diags: {}, {}ms)",
            repo.repo, repo.outcome, repo.diags, repo.elapsed_ms,
        );
    }
}

fn build_run_record(
    run: &Run,
    project_id: Option<&str>,
    kind: &str,
    triggered_by: &str,
) -> RunRecord {
    RunRecord {
        id: run.id.clone(),
        project_id: project_id.map(str::to_string),
        kind: kind.to_string(),
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
    project: &Project,
    selected: Vec<Repo>,
    run: &Run,
    events: EventSink,
    verbose: bool,
    output_path: Option<&std::path::Path>,
    output_only_pr_worthy: bool,
    since_ref: Option<&str>,
    orchestration: ScanOrchestrationOverrides,
) -> anyhow::Result<ScanReport> {
    let now_ms = now_epoch_ms();
    // Every selected repo belongs to `project`; the orchestrator emits
    // project/run lifecycle events while the static dispatcher emits
    // per-repo signal-scan events. Workspace dirs land under
    // `<state>/projects/<project_id>/repos/<name>/`.
    let attempted_repo_names: Vec<String> = selected.iter().map(|r| r.name.clone()).collect();
    emit_run_started(
        &events,
        &run.id,
        project.id.as_str(),
        &project.name,
        attempted_repo_names.clone(),
        run.started_at_ms,
    );
    let mut ingest_failures: Vec<(String, IngestError)> = Vec::new();
    let mut workspaces: Vec<WorkspaceHandle> = Vec::new();
    for repo in &selected {
        let state_repos = state_dir.project_repos(repo.project_id.as_str());
        match ingest(repo, &state_repos, &run.id).await {
            Ok(ingested) => {
                upsert_repo_record(store, &ingested, &repo.project_id, now_ms).await?;
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
                // Emit the typed ingest-failure frame BEFORE the
                // dispatcher publishes `RunStarted`. Subscribers that
                // attach at run-start time then see the failing repo
                // in `RunStarted.repos` and the matching
                // `RepoIngestFailed` frame in the replay buffer.
                let _ = events.send(AgentEvent::Run {
                    data: RunEvent::RepoIngestFailed {
                        run_id: run.id.clone(),
                        project_id: repo.project_id.as_str().to_string(),
                        repo: repo.name.clone(),
                        message: format!("ingest failed: {err}"),
                    },
                });
                ingest_failures.push((repo.name.clone(), err));
            }
        }
    }

    if workspaces.is_empty() {
        finalise_and_emit_run(
            store,
            &events,
            &run.id,
            project.id.as_str(),
            run.started_at_ms,
            0,
            "Failed",
            RunCounts::default(),
        )
        .await?;
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
            finalise_and_emit_run(
                store,
                &events,
                &run.id,
                project.id.as_str(),
                run.started_at_ms,
                0,
                "Failed",
                RunCounts::default(),
            )
            .await?;
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

    // Clone every handle into a name-keyed map so the
    // payload-synthesis pass can read source after the dispatcher
    // consumes the original `workspaces` Vec.
    let workspaces_for_ai: HashMap<String, WorkspaceHandle> =
        workspaces.iter().map(|w| (w.name().to_string(), w.clone())).collect();

    emit_phase(&events, &run.id, project.id.as_str(), "EnvironmentBuildStarted", true, None);
    let launcher = ConservativeLaunchProfileRunner;
    let profile_override = if orchestration.has_profile_override() {
        Some(insert_scan_override_profile(store, project, &run.id, &orchestration).await?)
    } else {
        None
    };
    let selected_profile = if !orchestration.enabled {
        None
    } else if let Some(profile) = profile_override {
        Some(profile)
    } else {
        store.launch_profiles().get_default(project.id.as_str()).await?
    };
    let mut environment = match selected_profile {
        Some(profile) => match launcher
            .start(LaunchContext {
                store,
                state_dir,
                project,
                run_id: &run.id,
                profile: &profile,
                workspaces: &workspaces_for_ai,
                events: events.clone(),
            })
            .await
        {
            Ok(env) => {
                emit_phase(
                    &events,
                    &run.id,
                    project.id.as_str(),
                    "EnvironmentReady",
                    false,
                    Some("local app is ready".to_string()),
                );
                Some(env)
            }
            Err(err) => {
                emit_phase(
                    &events,
                    &run.id,
                    project.id.as_str(),
                    "EnvironmentBuildStarted",
                    false,
                    Some(err.to_string()),
                );
                finalise_and_emit_run(
                    store,
                    &events,
                    &run.id,
                    project.id.as_str(),
                    run.started_at_ms,
                    0,
                    "Failed",
                    RunCounts::default(),
                )
                .await?;
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
        },
        None => {
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "EnvironmentBuildStarted",
                false,
                Some("no default launch profile; running static-only scan".to_string()),
            );
            None
        }
    };
    let live_target_urls =
        environment.as_ref().map(|env| env.target_urls.clone()).unwrap_or_default();

    emit_phase(&events, &run.id, project.id.as_str(), "NyxSignalsStarted", true, None);
    let dispatcher =
        RunDispatcher::from_config(&config.performance, workspaces.len(), Some(events.clone()))
            .with_attempted_repos(attempted_repo_names.clone())
            .without_run_lifecycle();
    let run_for_dispatch = run.clone();
    let project_for_dispatch = project.clone();
    let dispatch_handle = tokio::task::spawn_blocking(move || {
        dispatcher.dispatch_project::<NyxScanLane, Diag>(
            &project_for_dispatch,
            run_for_dispatch,
            lane,
            workspaces,
        )
    });

    // Guard the runs row: any failure between dispatch and finalise must still
    // flip status off "Running" before we propagate. Otherwise a panicking
    // rayon worker or a transient sqlx error leaves the row stuck forever.
    let bundle: RunBundle<Diag> = match dispatch_handle.await {
        Ok(b) => b,
        Err(join_err) => {
            if let Some(env) = environment.take() {
                let _ = env.stop().await;
            }
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "NyxSignalsStarted",
                false,
                Some(format!("static dispatcher failed: {join_err}")),
            );
            let _ = finalise_and_emit_run(
                store,
                &events,
                &run.id,
                project.id.as_str(),
                run.started_at_ms,
                0,
                "Failed",
                RunCounts::default(),
            )
            .await;
            return Err(anyhow::anyhow!("dispatch join error: {join_err}"));
        }
    };

    if let Err(err) = persist_run_results(store, &bundle).await {
        if let Some(env) = environment.take() {
            let _ = env.stop().await;
        }
        emit_phase(
            &events,
            &run.id,
            project.id.as_str(),
            "NyxSignalsStarted",
            false,
            Some(format!("failed to persist static signals: {err}")),
        );
        let _ = finalise_and_emit_run(
            store,
            &events,
            &run.id,
            project.id.as_str(),
            run.started_at_ms,
            0,
            "Failed",
            bundle.counts(),
        )
        .await;
        return Err(err);
    }
    let signal_count = bundle
        .per_repo
        .iter()
        .map(|b| match &b.outcome {
            RepoOutcome::Success(diags) => diags.len(),
            _ => 0,
        })
        .sum::<usize>();
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "NyxSignalsStarted",
        false,
        Some(format!("recorded {signal_count} signal(s)")),
    );

    emit_phase(&events, &run.id, project.id.as_str(), "RouteModelStarted", true, None);
    let route_workspaces: BTreeMap<String, WorkspaceHandle> =
        workspaces_for_ai.iter().map(|(name, ws)| (name.clone(), ws.clone())).collect();
    let route_model = route_model::extract_route_model(&route_workspaces);
    let route_summary = route_model::route_model_summary(&route_model);
    let route_record = RouteModelRecord {
        id: format!("routes-{}", run.id),
        run_id: run.id.clone(),
        project_id: project.id.as_str().to_string(),
        model: route_model.clone(),
        created_at: now_epoch_ms(),
    };
    match store.route_models().upsert(&route_record).await {
        Ok(()) => emit_phase(
            &events,
            &run.id,
            project.id.as_str(),
            "RouteModelStarted",
            false,
            Some(route_summary.clone()),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "failed to persist route model");
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "RouteModelStarted",
                false,
                Some(format!("route model extraction failed to persist: {err}")),
            );
        }
    }

    emit_phase(&events, &run.id, project.id.as_str(), "OptionalScannersStarted", true, None);
    let scanner_summary = match pentest_tools::run_optional_scanners(
        store,
        &run.id,
        project.id.as_str(),
        &live_target_urls,
        &workspaces_for_ai,
        &config.run,
    )
    .await
    {
        Ok(report) => report.summary(),
        Err(err) => {
            tracing::warn!(error = %err, "optional scanner pass failed");
            format!("optional scanner pass failed: {err}")
        }
    };
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "OptionalScannersStarted",
        false,
        Some(scanner_summary),
    );

    let auth_profiles = pentest_tools::configured_auth_profiles(project.runtime_profile.as_ref());

    emit_phase(&events, &run.id, project.id.as_str(), "CandidateSynthesisStarted", true, None);
    let synthesis_summary = match candidate_sources::synthesize_weak_signal_candidates(
        store,
        &run.id,
        project.id.as_str(),
        &route_model,
        &config.run,
    )
    .await
    {
        Ok(count) => format!("weak-signal synthesis persisted or updated {count} candidate(s)"),
        Err(err) => {
            tracing::warn!(error = %err, "weak-signal candidate synthesis failed");
            format!("weak-signal candidate synthesis failed: {err}")
        }
    };
    let business_logic_summary =
        match business_logic_templates::synthesize_business_logic_template_candidates(
            store,
            &run.id,
            project.id.as_str(),
            &route_model,
            &auth_profiles,
            &config.run,
        )
        .await
        {
            Ok(report) => report.summary(),
            Err(err) => {
                tracing::warn!(error = %err, "business-logic template synthesis failed");
                format!("business-logic template synthesis failed: {err}")
            }
        };
    let attacker_playbook_summary =
        match attacker_playbooks::synthesize_attacker_playbook_candidates(
            store,
            &run.id,
            project.id.as_str(),
            &route_model,
        )
        .await
        {
            Ok(report) => report.summary(),
            Err(err) => {
                tracing::warn!(error = %err, "attacker playbook synthesis failed");
                format!("attacker playbook synthesis failed: {err}")
            }
        };
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "CandidateSynthesisStarted",
        false,
        Some(format!(
            "{synthesis_summary}; attacker playbooks: {attacker_playbook_summary}; business templates: {business_logic_summary}"
        )),
    );

    emit_phase(&events, &run.id, project.id.as_str(), "AgentReviewStarted", true, None);
    let mut agent_review_notes: Vec<String> = Vec::new();
    agent_review_notes
        .push(format!("configured AI runtime: {}", ai_runtime_label(config.ai.runtime)));
    agent_review_notes.push(pentest_tools::auth_profiles_summary(&auth_profiles));
    if matches!(config.ai.runtime, nyctos_core::AiRuntime::None | nyctos_core::AiRuntime::LocalLlm)
    {
        agent_review_notes.push(format!(
            "one-shot helpers skipped for configured runtime {:?}",
            config.ai.runtime
        ));
    }

    // Fan out PayloadSynthesis tasks against every diag the static
    // pass flagged with `Unsupported(NoPayloadsForCap)`. No-op when
    // the selected AI runtime is disabled, unsupported, or unavailable.
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
            agent_review_notes.push(format!(
                "payload synthesis: {} synthesised, {} quarantined, {} failed",
                report.synthesised, report.quarantined, report.failed
            ));
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
        Err(err) => {
            agent_review_notes.push(format!("payload synthesis failed: {err}"));
            tracing::warn!(error = %err, "payload synthesis pass failed");
        }
    }

    // Fan out SpecDerivation tasks against every diag the static pass
    // flagged with `Inconclusive(SpecDerivationFailed)`. Same no-op
    // gating as the payload pass; shares the run's budget bucket so
    // per-call caps stack on top of payload spend.
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
            agent_review_notes.push(format!(
                "spec derivation: {} synthesised, {} quarantined, {} failed",
                report.synthesised, report.quarantined, report.failed
            ));
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
        Err(err) => {
            agent_review_notes.push(format!("spec derivation failed: {err}"));
            tracing::warn!(error = %err, "spec derivation pass failed");
        }
    }

    // Rank cross-repo exploitable chains across the run's finding
    // graph. Single-call pass; shares the run's budget bucket with
    // payload + spec passes. No-op when the selected runtime is
    // unavailable or fewer than two findings landed in the bundle.
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
            agent_review_notes.push(format!(
                "chain reasoning: {} chain(s), {} failed",
                report.chains_persisted, report.failed
            ));
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
        Err(err) => {
            agent_review_notes.push(format!("chain reasoning failed: {err}"));
            tracing::warn!(error = %err, "chain reasoning pass failed");
        }
    }

    // Scan repo source for candidate vulnerabilities the static pass
    // missed. Most-expensive pass; each batch is gated on a per-run
    // cap ($5 default), and every emitted CandidateFinding lands in
    // `candidate_findings.Pending` so nothing surfaces to the operator
    // until the payload verifier promotes it.
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
            agent_review_notes.push(format!(
                "novel discovery: {} candidate(s), {} batch(es), {} failed",
                report.candidates_persisted, report.batches_dispatched, report.failed
            ));
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
        Err(err) => {
            agent_review_notes.push(format!("novel finding discovery failed: {err}"));
            tracing::warn!(error = %err, "novel finding discovery pass failed");
        }
    }

    // Drive the selected CLI agent loop against the running chain-lane
    // sandbox so the model can probe shadow APIs, CORS misconfig,
    // business-logic skips, etc. Gated by the static escape suite (a
    // red fixture halts the driver) and capped by a per-run hard cap
    // (default $10) plus a soft warning threshold. Findings land in
    // `findings` with `finding_origin = AiExploration` and `status =
    // Quarantine`; the verifier below promotes them on Confirmed.
    let escape_gate = ai_pipeline::StaticEscapeSuiteGate::green();
    let exploration_traces_dir = state_dir.traces();
    match ai_pipeline::run_ai_exploration_pass(
        &config.ai,
        &config.run,
        store,
        &bundle,
        &workspaces_for_ai,
        &live_target_urls,
        &escape_gate,
        events.clone(),
        &exploration_traces_dir,
    )
    .await
    {
        Ok(report) => {
            agent_review_notes.push(format!(
                "exploration: {} dispatched, {} quarantined, {} failed",
                report.explorations_dispatched, report.findings_quarantined, report.failed
            ));
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
        Err(err) => {
            agent_review_notes.push(format!("exploration failed: {err}"));
            tracing::warn!(error = %err, "ai exploration pass failed");
        }
    }

    emit_phase(&events, &run.id, project.id.as_str(), "AiAttackPlanningStarted", true, None);
    let mut attack_plan_context: Option<String> = None;
    match ai_pipeline::run_attack_planning_pass(
        &config.ai,
        &config.run,
        store,
        &secrets,
        &bundle,
        &workspaces_for_ai,
        &route_model,
        &auth_profiles,
        &live_target_urls,
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            attack_plan_context = report.plan_context.clone();
            agent_review_notes.push(format!(
                "attack planning: {} planned, {} skipped, {} failed",
                report.candidates_planned, report.skipped, report.failed
            ));
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "AiAttackPlanningStarted",
                false,
                Some(format!(
                    "{} candidate(s) planned, {} skipped, {} failed",
                    report.candidates_planned, report.skipped, report.failed
                )),
            );
        }
        Err(err) => {
            agent_review_notes.push(format!("attack planning failed: {err}"));
            tracing::warn!(error = %err, "attack planning pass failed");
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "AiAttackPlanningStarted",
                false,
                Some(format!("attack planning failed: {err}")),
            );
        }
    }

    match materialize_ai_review_items_for_live_verification(
        store,
        &run.id,
        project.id.as_str(),
        now_epoch_ms(),
    )
    .await
    {
        Ok(count) if count > 0 => {
            agent_review_notes.push(format!(
                "live verifier queued {count} AI review item(s) for deterministic planning"
            ));
        }
        Ok(_) => {}
        Err(err) => {
            agent_review_notes.push(format!("AI review item live-queueing failed: {err}"));
            tracing::warn!(error = %err, "failed to queue AI review items for live verification");
        }
    }

    // Static candidates need an executable HTTP plan before the live
    // verifier can touch the already-running app. This pass is the
    // bridge from "Nyx found a risky source location" to "try this
    // concrete method/url/body/oracle against localhost".
    match ai_pipeline::run_live_test_plan_synthesis_pass(
        &config.ai,
        store,
        &secrets,
        &bundle,
        &workspaces_for_ai,
        &live_target_urls,
        Some(&route_model),
        &auth_profiles,
        config.run.browser_checks_enabled,
        config.run.state_changing_live_probes_allowed(),
        attack_plan_context.as_deref(),
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            agent_review_notes.push(format!(
                "live test planning: {} planned, {} no-plan, {} failed",
                report.planned, report.no_plan, report.failed
            ));
            if verbose && (report.planned > 0 || report.no_plan > 0 || report.failed > 0) {
                println!(
                    "scan: live test planning - {} candidates seen, {} planned, {} no-plan, {} failed ({} attempts, ${:.6})",
                    report.candidates_seen,
                    report.planned,
                    report.no_plan,
                    report.failed,
                    report.attempts,
                    report.spend_usd_micros as f64 / 1_000_000.0,
                );
            }
        }
        Err(err) => {
            agent_review_notes.push(format!("live test planning failed: {err}"));
            tracing::warn!(error = %err, "live test planning pass failed");
        }
    }
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "AgentReviewStarted",
        false,
        Some(agent_review_notes.join("; ")),
    );

    // Drive the deterministic payload runner across every finding
    // (and AI-discovered candidate) that has a payload+spec pair
    // ready. Confirms or rejects each row under differential rule v1;
    // Quarantined candidates flip to Promoted on Confirmed.
    emit_phase(&events, &run.id, project.id.as_str(), "LiveVerificationStarted", true, None);
    let mut verification_notes: Vec<String> = Vec::new();
    match ai_pipeline::run_payload_verification_pass(
        &config.run,
        &config.sandbox,
        store,
        &bundle,
        &workspaces_for_ai,
        events.clone(),
    )
    .await
    {
        Ok(report) => {
            verification_notes.push(format!(
                "payload verifier: {} confirmed, {} not-confirmed, {} errored, {} skipped no-payload",
                report.confirmed, report.not_confirmed, report.errored, report.skipped_no_payload
            ));
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
        Err(err) => {
            verification_notes.push(format!("payload verifier failed: {err}"));
            tracing::warn!(error = %err, "verifier pass failed");
        }
    }

    let mut browser_attempts_executed = 0_u32;
    if let Some(env) = environment.as_mut() {
        let auth_workspace_paths = workspaces_for_ai
            .values()
            .map(|workspace| workspace.workspace().to_path_buf())
            .collect::<Vec<_>>();
        match verify_pentest_candidates(
            &config.ai,
            store,
            &secrets,
            &run.id,
            project.id.as_str(),
            env,
            &live_target_urls,
            Some(&route_model),
            &config.run,
            &auth_profiles,
            &state_dir.traces_for_run(&run.id).join("auth_sessions"),
            &state_dir.traces_for_run(&run.id).join("browser_verification"),
            &state_dir.traces_for_run(&run.id).join("exploit_audit"),
            &auth_workspace_paths,
            events.clone(),
        )
        .await
        {
            Ok(report) => {
                verification_notes.push(format!(
                    "candidate verifier: {} confirmed, {} rejected, {} policy-blocked, {} inconclusive, {} skipped no-plan, {} errored ({} HTTP, {} browser)",
                    report.confirmed,
                    report.rejected,
                    report.blocked,
                    report.inconclusive,
                    report.skipped_no_plan,
                    report.errored,
                    report.http_attempts,
                    report.browser_attempts
                ));
                browser_attempts_executed = report.browser_attempts;
                if verbose
                    && (report.confirmed > 0
                        || report.rejected > 0
                        || report.blocked > 0
                        || report.inconclusive > 0
                        || report.skipped_no_plan > 0
                        || report.errored > 0)
                {
                    println!(
                        "pentest verification - {} confirmed, {} rejected, {} policy-blocked, {} inconclusive, {} skipped no-plan, {} errored",
                        report.confirmed, report.rejected, report.blocked, report.inconclusive, report.skipped_no_plan, report.errored,
                    );
                }
            }
            Err(err) => {
                verification_notes.push(format!("candidate verifier failed: {err}"));
                tracing::warn!(error = %err, "pentest candidate verification failed");
            }
        }
    } else {
        verification_notes
            .push("candidate verifier skipped: no running app environment".to_string());
    }
    emit_phase(&events, &run.id, project.id.as_str(), "BrowserVerificationStarted", true, None);
    let browser_msg = if browser_attempts_executed > 0 {
        format!("browser verification executed {browser_attempts_executed} browser plan(s)")
    } else if config.run.browser_checks_enabled {
        "browser verification: no executable browser plans were available or Playwright was unavailable"
            .to_string()
    } else {
        "browser verification skipped: disabled by run config".to_string()
    };
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "BrowserVerificationStarted",
        false,
        Some(browser_msg.clone()),
    );
    verification_notes.push(browser_msg);
    if config.run.unsafe_attack_agent_enabled {
        emit_phase(&events, &run.id, project.id.as_str(), "UnsafeAttackAgentStarted", true, None);
        if let Some(env) = environment.as_ref() {
            match ai_pipeline::run_attack_agent_pass(
                &config.ai,
                store,
                &bundle,
                &workspaces_for_ai,
                &live_target_urls,
                &env.environment_run_id,
                &state_dir.traces_for_run(&run.id).join("unsafe_attack_agent"),
                events.clone(),
            )
            .await
            {
                Ok(report) => {
                    verification_notes.push(format!(
                        "unsafe attack agent: {} dispatched, {} vulnerabilities recorded, {} candidates promoted, {} failed",
                        report.dispatched,
                        report.vulnerabilities_recorded,
                        report.candidates_promoted,
                        report.failed
                    ));
                    if verbose
                        && (report.dispatched > 0
                            || report.vulnerabilities_recorded > 0
                            || report.failed > 0)
                    {
                        println!(
                            "unsafe attack agent - {} dispatched, {} vulnerabilities recorded, {} candidates promoted, {} failed (${:.6})",
                            report.dispatched,
                            report.vulnerabilities_recorded,
                            report.candidates_promoted,
                            report.failed,
                            report.spend_usd_micros as f64 / 1_000_000.0,
                        );
                    }
                    emit_phase(
                        &events,
                        &run.id,
                        project.id.as_str(),
                        "UnsafeAttackAgentStarted",
                        false,
                        Some(format!(
                            "{} vulnerabilities recorded, {} candidates promoted, {} failed",
                            report.vulnerabilities_recorded,
                            report.candidates_promoted,
                            report.failed
                        )),
                    );
                }
                Err(err) => {
                    verification_notes.push(format!("unsafe attack agent failed: {err}"));
                    tracing::warn!(error = %err, "unsafe attack agent pass failed");
                    emit_phase(
                        &events,
                        &run.id,
                        project.id.as_str(),
                        "UnsafeAttackAgentStarted",
                        false,
                        Some(format!("unsafe attack agent failed: {err}")),
                    );
                }
            }
        } else {
            let message = "unsafe attack agent skipped: no running app environment".to_string();
            verification_notes.push(message.clone());
            emit_phase(
                &events,
                &run.id,
                project.id.as_str(),
                "UnsafeAttackAgentStarted",
                false,
                Some(message),
            );
        }
    }
    match materialize_review_vulnerabilities(store, &run.id, project.id.as_str(), now_epoch_ms())
        .await
    {
        Ok(report) if report.total() > 0 => {
            verification_notes.push(format!(
                "review surface: {} needs-review vulnerabilit{} surfaced ({} quarantined finding{}, {} pending AI candidate{})",
                report.total(),
                if report.total() == 1 { "y" } else { "ies" },
                report.quarantined_findings,
                if report.quarantined_findings == 1 { "" } else { "s" },
                report.pending_ai_candidates,
                if report.pending_ai_candidates == 1 { "" } else { "s" },
            ));
        }
        Ok(_) => {}
        Err(err) => {
            verification_notes.push(format!("review surface failed: {err}"));
            tracing::warn!(error = %err, "failed to surface needs-review vulnerabilities");
        }
    }
    emit_phase(
        &events,
        &run.id,
        project.id.as_str(),
        "LiveVerificationStarted",
        false,
        Some(verification_notes.join("; ")),
    );

    let counts = bundle.counts();
    let success = counts.failed == 0 && ingest_failures.is_empty();
    let final_status = if success { "Succeeded" } else { "Failed" };
    if let Some(env) = environment.take() {
        if let Err(err) = env.stop().await {
            tracing::warn!(error = %err, "environment teardown failed");
        }
    }
    let (_finished_at, final_wall_clock_ms) = finalise_and_emit_run(
        store,
        &events,
        &run.id,
        project.id.as_str(),
        run.started_at_ms,
        0,
        final_status,
        counts,
    )
    .await?;

    if let Some(path) = output_path {
        let changed = match since_ref {
            Some(ref_name) => Some(collect_changed_files(&workspaces_for_ai, ref_name).await?),
            None => None,
        };
        let started_at = run.started_at_ms;
        let finished_at = started_at + final_wall_clock_ms;
        let meta = cmd::scan_report::RunMeta {
            started_at,
            finished_at: Some(finished_at),
            status: final_status,
            triggered_by: "Manual",
        };
        let mut report =
            cmd::scan_report::build_report(store, &run.id, meta, since_ref, changed.as_ref())
                .await?;
        if output_only_pr_worthy {
            report.retain_pr_worthy();
        }
        report.write(path)?;
        if verbose {
            println!(
                "scan: wrote report to {} ({} vulnerabilit{}, {} verified chain(s){})",
                path.display(),
                report.verified_vulnerabilities.len(),
                if report.verified_vulnerabilities.len() == 1 { "y" } else { "ies" },
                report.verified_chains.len(),
                if output_only_pr_worthy { ", pr-worthy filter" } else { "" },
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
        wall_clock_ms: final_wall_clock_ms,
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
    let setup = SetupContext::new(
        config_path.clone(),
        config.clone(),
        config_present,
        SecretStore::from_env(),
    );

    let scan_state_dir = state_dir.clone();
    let scan_setup = setup.clone();
    let scan_events = events_tx.clone();
    let scan_worker = tokio::spawn(async move {
        while let Some(req) = scan_rx.recv().await {
            let state_dir = scan_state_dir.clone();
            let config = scan_setup.config.read().await.clone();
            let events = scan_events.clone();
            tokio::spawn(async move {
                let outcome = run_scan_for_api(
                    &state_dir,
                    &config,
                    &req.source,
                    req.project_id.as_deref(),
                    req.repo.as_deref(),
                    req.run_overrides,
                    events,
                )
                .await;
                let _ = req.reply.send(outcome);
            });
        }
    });

    // Headless mode skips auth entirely (deferred plan #31). When auth
    // is on, mint or load a per-install token and surface it both to
    // the API middleware and the SPA bootstrap.
    let auth_token = if headless { None } else { Some(state_dir.load_or_mint_auth_token()?) };
    let auth_config = AuthConfig::new(auth_token.clone());

    let ui_bootstrap = Arc::new(nyctos_ui::UiBootstrap { auth_token: auth_token.clone() });
    let auth_setup_agent = Arc::new(auth_setup_ai::ConfiguredAuthSetupAgent::new(
        setup.config.clone(),
        events_tx.clone(),
    ));
    let mut server_state =
        ServerState::new(store.clone(), events_tx.clone(), trigger.clone(), setup, auth_config)
            .with_auth_setup_agent(auth_setup_agent)
            .with_state_repos_dir(state_dir.repos())
            .with_state_bundles_dir(state_dir.bundles())
            .with_state_logs_dir(state_dir.logs());

    // Enable `POST /webhook/git` when the operator has configured a
    // shared secret. Resolves the env-backed ref on each request so a
    // wizard rotate flow does not require a daemon restart.
    if config.triggers.webhook_secret_ref.is_some() {
        let resolver =
            Arc::new(EnvSecretResolver { spec: config.triggers.webhook_secret_ref.clone() });
        let extractor = nyctos_api::webhook::extractor_for_provider(
            config.triggers.webhook_provider.as_deref(),
        );
        let max_concurrent = config
            .triggers
            .webhook_max_concurrent_resolved(nyctos_api::DEFAULT_WEBHOOK_MAX_CONCURRENT);
        let rate_per_minute = config.triggers.webhook_rate_limit_per_minute_resolved(
            nyctos_api::DEFAULT_WEBHOOK_RATE_LIMIT_PER_MINUTE,
        );
        let concurrency = Arc::new(nyctos_api::WebhookConcurrencyLimit::new(max_concurrent));
        let rate_limit = Arc::new(nyctos_api::WebhookRateLimiter::per_minute(
            rate_per_minute,
            nyctos_api::DEFAULT_WEBHOOK_RATE_LIMIT_MAX_IPS,
        ));
        let cfg = WebhookConfig::with_extractor(
            resolver,
            config.triggers.webhook_branch.clone(),
            None,
            extractor,
        )
        .with_concurrency_limit(concurrency)
        .with_rate_limit(rate_limit);
        server_state = server_state.with_webhook(cfg);
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
    let _event_log_task = spawn_run_event_log_task(events_tx.clone(), state_dir.logs());
    let _integration_delivery_task =
        nyctos_api::spawn_integration_delivery_task(store.clone(), events_tx.clone());
    let ui_fallback = {
        let bootstrap = Arc::clone(&ui_bootstrap);
        move |uri: axum::http::Uri| {
            let bootstrap = Arc::clone(&bootstrap);
            async move { nyctos_ui::spa_handler_with(uri, &bootstrap).await }
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
        println!("first launch detected; wizard at {startup_url}");
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

    // Spawn the cron scheduler when at least one `[[schedule]]` entry
    // is configured. The watch channel is the shutdown signal:
    // flipping it to `true` ends the loop. A refused `[[schedule]]`
    // config aborts startup so an operator who fat-fingers a cron
    // expression cannot run a daemon with the trigger surface
    // silently disabled.
    let (scheduler_shutdown_tx, scheduler_shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_handle = if config.schedules.is_empty() {
        None
    } else {
        let s = scheduler::Scheduler::from_config(&config.schedules, trigger.clone())
            .map_err(|err| anyhow::anyhow!("invalid [[schedule]] config: {err}"))?;
        let rx = scheduler_shutdown_rx.clone();
        let tick = config.performance.scheduler_tick();
        Some(tokio::spawn(async move {
            s.run(tick, rx).await;
        }))
    };

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    // Launch with `into_make_service_with_connect_info` so the
    // webhook handler can read the peer socket address from the
    // request's `ConnectInfo` extension and apply per-IP rate
    // limits before HMAC verification.
    let serve_result =
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(shutdown)
            .await;
    scan_worker.abort();
    let _ = scheduler_shutdown_tx.send(true);
    if let Some(h) = scheduler_handle {
        h.abort();
    }
    store.close().await;
    serve_result.map_err(|e| anyhow::anyhow!("http server: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

struct ScanRequest {
    source: ScanTriggerSource,
    project_id: Option<String>,
    repo: Option<String>,
    run_overrides: Option<ScanRunOverrides>,
    reply: oneshot::Sender<Result<String, ScanTriggerError>>,
}

struct MpscScanTrigger {
    tx: mpsc::Sender<ScanRequest>,
}

impl ScanTrigger for MpscScanTrigger {
    fn trigger<'a>(
        &'a self,
        source: ScanTriggerSource,
        project_id: Option<String>,
        repo: Option<String>,
        run_overrides: Option<ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            let (reply, rx) = oneshot::channel();
            // Non-blocking submit so an external scheduler / webhook /
            // CI loop sees a fast HTTP 429 instead of stalling on
            // `send().await` when the dispatcher is saturated. The
            // bound is set in `serve()`; raise it there if a real load
            // profile demands a deeper queue.
            self.tx
                .try_send(ScanRequest { source, project_id, repo, run_overrides, reply })
                .map_err(|err| match err {
                    mpsc::error::TrySendError::Full(_) => ScanTriggerError::Backpressure(
                        "scan request queue is full; retry after the current run completes"
                            .to_string(),
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
    source: &ScanTriggerSource,
    project_id: Option<&str>,
    repo: Option<&str>,
    run_overrides: Option<ScanRunOverrides>,
    events: EventSink,
) -> Result<String, ScanTriggerError> {
    let store = Store::open(state_dir.root()).await.map_err(internal_string)?;

    // Resolve the project name the API route asked for. With no
    // explicit id, fall back to scanning every configured project (the
    // CLI's `--project` omitted shape).
    let requested_projects: Vec<String> = match project_id {
        Some(id) => match store.projects().get(id).await.map_err(internal_string)? {
            Some(p) => vec![p.name],
            None => {
                store.close().await;
                return Err(ScanTriggerError::Rejected(format!("project `{id}` not found")));
            }
        },
        None => Vec::new(),
    };
    let requested_repos: Vec<String> = match repo {
        Some(name) => vec![name.to_string()],
        None => Vec::new(),
    };

    let targets =
        match select_scan_targets(&store, config, &requested_projects, &requested_repos).await {
            Ok(t) => t,
            Err(err) => {
                store.close().await;
                let msg = format!("{err:#}");
                return Err(if msg.contains("not declared") || msg.contains("enabled = false") {
                    ScanTriggerError::Rejected(msg)
                } else {
                    ScanTriggerError::Internal(msg)
                });
            }
        };
    if targets.is_empty() {
        store.close().await;
        return Err(ScanTriggerError::Rejected(
            "no repositories selected; add a repo in the web UI or nyctos.toml".to_string(),
        ));
    }

    // First-run UI semantics: synthesise one run row, kick the
    // dispatcher per project in sequence on a background task.
    let run = Run::new();
    let triggered_by = source.as_run_record_string();
    let project_id_for_run = targets.first().map(|(project, _)| project.id.as_str());
    let run_record = build_run_record(&run, project_id_for_run, "Pentest", &triggered_by);
    store.runs().insert(&run_record).await.map_err(internal_string)?;

    let run_id_out = run.id.clone();
    let mut cfg = config.clone();
    if let Some(overrides) = run_overrides {
        cfg.run.exploit_mode_enabled = overrides.exploit_mode_enabled;
        cfg.run.allow_state_changing_live_probes = overrides.allow_state_changing_live_probes;
        if let Some(dry_run) = overrides.exploit_dry_run {
            cfg.run.exploit_dry_run = dry_run;
        }
        if let Some(enabled) = overrides.browser_checks_enabled {
            cfg.run.browser_checks_enabled = enabled;
        }
        if let Some(enabled) = overrides.business_logic_templates_enabled {
            cfg.run.business_logic_templates_enabled = enabled;
        }
        if let Some(enabled) = overrides.research_mode_enabled {
            cfg.run.research_mode_enabled = enabled;
        }
        if let Some(enabled) = overrides.unsafe_attack_agent_enabled {
            cfg.run.unsafe_attack_agent_enabled = enabled;
        }
        if let Some(ids) = overrides.business_logic_template_ids {
            cfg.run.business_logic_template_ids = ids;
        }
    }
    let sd = state_dir.clone();
    tokio::spawn(async move {
        for (project, repos) in targets {
            let res = drive_scan(
                &sd,
                &cfg,
                &store,
                &project,
                repos,
                &run,
                events.clone(),
                false,
                None,
                false,
                None,
                ScanOrchestrationOverrides::default(),
            )
            .await;
            if let Err(err) = res {
                eprintln!("scan (api) project `{}`: {err:#}", project.name);
            }
        }
        store.close().await;
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
    project_id: &ProjectId,
    now_ms: i64,
) -> anyhow::Result<()> {
    let existing =
        store.repos().get_by_project_and_name(project_id.as_str(), &ingested.name).await?;
    let rec = RepoRecord {
        id: existing.as_ref().map(|r| r.id.clone()).unwrap_or_else(|| {
            format!(
                "repo-{}",
                project_id_slug(&format!("{}-{}", project_id.as_str(), ingested.name), now_ms)
            )
        }),
        name: ingested.name.clone(),
        project_id: project_id.as_str().to_string(),
        source_kind: source_kind_str(&ingested.source).to_string(),
        source_url_or_path: source_url_or_path(&ingested.source),
        branch: branch_of(&ingested.source),
        auth_ref: auth_descriptor_of(&ingested.source),
        i_own_this: true,
        last_scan_run_id: existing.as_ref().and_then(|r| r.last_scan_run_id.clone()),
        last_scan_finished_at: None,
        created_at: existing.as_ref().map(|r| r.created_at).unwrap_or(now_ms),
        updated_at: now_ms,
    };
    store.repos().upsert(&rec).await?;
    Ok(())
}

/// Hydrate a `Project` from its persisted `ProjectRecord`. Returned by
/// every CLI/API path that needs the live row's metadata (env overrides,
/// target base URL) flowing into the dispatcher and downstream phases.
fn project_from_record(rec: ProjectRecord) -> Project {
    Project {
        id: ProjectId::new(rec.id),
        name: rec.name,
        description: rec.description,
        target_base_url: rec.target_base_url,
        env_config: rec.env_config_json.as_deref().and_then(|s| serde_json::from_str(s).ok()),
        runtime_profile: rec.runtime_profile,
        default_launch_profile: rec.default_launch_profile,
    }
}

async fn persist_run_results(store: &Store, bundle: &RunBundle<Diag>) -> anyhow::Result<()> {
    let now_ms = now_epoch_ms();
    for repo_bundle in &bundle.per_repo {
        store
            .repos()
            .set_last_scan_for_project(
                &bundle.project_id,
                &repo_bundle.repo,
                &bundle.run_id,
                now_ms,
            )
            .await?;
        let (outcome_label, reason) = match &repo_bundle.outcome {
            RepoOutcome::Success(_) => (RepoOutcomeLabel::Success, None),
            RepoOutcome::Inconclusive(InconclusiveReason::StaticPassTimeout) => {
                (RepoOutcomeLabel::Inconclusive, Some("StaticPassTimeout".to_string()))
            }
            RepoOutcome::Failed(msg) => (RepoOutcomeLabel::Failed, Some(msg.clone())),
        };
        store
            .run_repo_outcomes()
            .upsert(&RunRepoOutcomeRecord {
                run_id: bundle.run_id.clone(),
                repo: repo_bundle.repo.clone(),
                outcome: outcome_label.as_str().to_string(),
                reason,
                elapsed_ms: repo_bundle.elapsed_ms,
            })
            .await?;
        if let RepoOutcome::Success(diags) = &repo_bundle.outcome {
            let repo = store
                .repos()
                .get_by_project_and_name(&bundle.project_id, &repo_bundle.repo)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "repo `{}` in project `{}` vanished before signal persistence",
                        repo_bundle.repo,
                        bundle.project_id
                    )
                })?;
            for diag in diags {
                let line = i64::from(diag.line);
                let signal_id = nyx_signal_id(
                    &bundle.project_id,
                    &repo.id,
                    &repo_bundle.repo,
                    &diag.path,
                    Some(line),
                    &diag.cap,
                    &diag.rule,
                );
                let (signal_kind, meaningful, suppressed_reason) = classify_nyx_signal(diag);
                let rec = NyxSignalRecord {
                    id: signal_id.clone(),
                    run_id: bundle.run_id.clone(),
                    project_id: bundle.project_id.clone(),
                    repo_id: repo.id.clone(),
                    repo: repo_bundle.repo.clone(),
                    path: diag.path.clone(),
                    line: Some(line),
                    cap: diag.cap.clone(),
                    rule: diag.rule.clone(),
                    severity: diag.severity.clone(),
                    message: diag.message.clone(),
                    evidence: Some(render_static_evidence_value(diag)),
                    signal_kind,
                    meaningful,
                    suppressed_reason,
                    agent_candidate_id: None,
                    created_at: now_ms,
                };
                store.nyx_signals().insert(&rec).await?;
                if meaningful {
                    let candidate = candidate_from_signal(&rec, diag, now_ms);
                    store.pentest_candidates().insert(&candidate).await?;
                    store.nyx_signals().set_candidate(&rec.id, &candidate.id).await?;
                }
            }
        }
    }
    Ok(())
}

/// Serialise the static-pass `Diag.evidence` payload into the
/// `findings.verdict_blob` column, stamping a typed `kind` discriminator
/// so the API/UI can distinguish it from payload-verifier output and
/// the AI candidate/exploration blobs without sniffing fields.
/// The frontend's `Evidence` parser already reads `source`/`sink`/
/// `flow_steps`/`notes`/`source_excerpt`/`symbolic` directly off the
/// top-level object, which mirrors the upstream `nyx scan` evidence
/// shape, so we surface the full payload here rather than dropping
/// everything except `message`.
#[cfg(test)]
fn render_static_verdict_blob(diag: &Diag) -> String {
    serde_json::to_string(&render_static_evidence_value(diag)).expect("serialize verdict blob")
}

fn render_static_evidence_value(diag: &Diag) -> serde_json::Value {
    let mut value = match diag.evidence.clone() {
        serde_json::Value::Object(map) => serde_json::Value::Object(map),
        serde_json::Value::Null => serde_json::Value::Object(serde_json::Map::new()),
        other => {
            let mut map = serde_json::Map::new();
            map.insert("evidence".to_string(), other);
            serde_json::Value::Object(map)
        }
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert("kind".to_string(), serde_json::Value::String("StaticDiag".to_string()));
        if let Some(msg) = &diag.message {
            obj.entry("message").or_insert_with(|| serde_json::Value::String(msg.clone()));
        }
    }
    value
}

fn nyx_signal_id(
    project_id: &str,
    repo_id: &str,
    repo: &str,
    path: &str,
    line: Option<i64>,
    cap: &str,
    rule: &str,
) -> String {
    format!("sig-{}-{}-{}", project_id, repo_id, finding_id_hash(repo, path, line, cap, rule))
}

fn classify_nyx_signal(diag: &Diag) -> (String, bool, Option<String>) {
    let severity = diag.severity.to_ascii_lowercase();
    let cap_rule = format!("{} {}", diag.cap, diag.rule).to_ascii_lowercase();
    let signal_kind = if severity == "info" {
        "info"
    } else if cap_rule.contains("quality")
        || cap_rule.contains("lint")
        || cap_rule.contains("style")
        || cap_rule.contains("dead-code")
    {
        "code-quality"
    } else {
        "security"
    };
    let meaningful =
        signal_kind == "security" && matches!(severity.as_str(), "medium" | "high" | "critical");
    let suppressed_reason = if meaningful {
        None
    } else if signal_kind == "code-quality" {
        Some("code-quality".to_string())
    } else {
        Some("below-threshold".to_string())
    };
    (signal_kind.to_string(), meaningful, suppressed_reason)
}

#[derive(Debug, Clone)]
struct NyxExploitClassification {
    vuln_class: String,
    reason: String,
    route: Option<String>,
    method: Option<String>,
    param: Option<String>,
    sink: Option<String>,
    sink_path: Option<String>,
    sink_line: Option<i64>,
    source: Option<String>,
    source_path: Option<String>,
    source_line: Option<i64>,
    confidence: f64,
}

impl NyxExploitClassification {
    fn is_reclassified_from(&self, cap: &str) -> bool {
        self.vuln_class != cap
    }
}

fn candidate_from_signal(
    signal: &NyxSignalRecord,
    diag: &Diag,
    now_ms: i64,
) -> PentestCandidateRecord {
    let id = format!("pc-{}", signal.id.trim_start_matches("sig-"));
    let classification = classify_nyx_candidate(diag);
    let mut component = serde_json::json!({
        "kind": "nyx_signal",
        "repo_id": signal.repo_id,
        "repo": signal.repo,
        "path": signal.path,
        "line": signal.line,
        "rule": signal.rule,
        "cap": signal.cap,
        "original_cap": signal.cap,
        "nyx_signal_id": signal.id,
        "nyx_signal": {
            "id": signal.id,
            "cap": signal.cap,
            "rule": signal.rule,
            "severity": signal.severity,
            "message": signal.message,
        },
    });
    if let Some(obj) = component.as_object_mut() {
        insert_json_string(obj, "exploit_class", Some(classification.vuln_class.clone()));
        insert_json_string(obj, "classification_reason", Some(classification.reason.clone()));
        insert_json_string(obj, "route", classification.route.clone());
        insert_json_string(obj, "url_path", classification.route.clone());
        insert_json_string(obj, "method", classification.method.clone());
        insert_json_string(obj, "param", classification.param.clone());
        if let Some(param) = &classification.param {
            obj.insert(
                "params".to_string(),
                serde_json::Value::Array(vec![serde_json::Value::String(param.clone())]),
            );
        }
        insert_json_string(obj, "sink", classification.sink.clone());
        insert_json_string(obj, "sink_path", classification.sink_path.clone());
        insert_json_i64(obj, "sink_line", classification.sink_line);
        insert_json_string(obj, "source", classification.source.clone());
        insert_json_string(obj, "source_path", classification.source_path.clone());
        insert_json_i64(obj, "source_line", classification.source_line);
    }
    PentestCandidateRecord {
        id,
        run_id: signal.run_id.clone(),
        project_id: signal.project_id.clone(),
        source: "NyxSignal".to_string(),
        source_ids: vec![signal.id.clone()],
        title: nyx_candidate_title(signal, &classification),
        vuln_class: classification.vuln_class.clone(),
        severity_guess: signal.severity.clone(),
        affected_components: vec![component],
        hypothesis: nyx_candidate_hypothesis(signal, &classification),
        test_plan: format!(
            "Use the deterministic {} live planner when possible; otherwise retain a structured no-plan reason. Do not report without exploit-specific live evidence.",
            classification.vuln_class
        ),
        status: "NeedsLiveTest".to_string(),
        rejection_reason: None,
        confidence: classification.confidence,
        trace_id: None,
        created_at: now_ms,
        updated_at: now_ms,
    }
}

fn classify_nyx_candidate(diag: &Diag) -> NyxExploitClassification {
    let text = nyx_diag_text(diag);
    let route = extract_route_from_diag(diag, &text);
    let method = extract_method_from_diag(diag);
    let param = extract_param_from_diag(diag, &text);
    let sink = extract_sink_from_diag(diag);
    let (sink_path, sink_line) = extract_evidence_location(diag, "sink");
    let source = extract_source_from_diag(diag);
    let (source_path, source_line) = extract_evidence_location(diag, "source");
    let (vuln_class, reason) = classify_nyx_exploit_class(
        diag,
        &text,
        route.as_deref(),
        param.as_deref(),
        sink.as_deref(),
    )
    .unwrap_or_else(|| {
        (
            diag.cap.clone(),
            "Nyx did not expose enough exploit-shaping evidence to reclassify the signal"
                .to_string(),
        )
    });
    let mut confidence: f64 = if vuln_class == diag.cap { 0.55 } else { 0.62 };
    if route.is_some() {
        confidence += 0.04;
    }
    if param.is_some() {
        confidence += 0.03;
    }
    if sink.is_some() {
        confidence += 0.03;
    }
    if diag.confidence.as_deref().is_some_and(|c| c.eq_ignore_ascii_case("high")) {
        confidence += 0.03;
    }
    NyxExploitClassification {
        vuln_class,
        reason,
        route,
        method,
        param,
        sink,
        sink_path,
        sink_line,
        source,
        source_path,
        source_line,
        confidence: confidence.min(0.78),
    }
}

fn classify_nyx_exploit_class(
    diag: &Diag,
    text: &str,
    route: Option<&str>,
    param: Option<&str>,
    sink: Option<&str>,
) -> Option<(String, String)> {
    if let Some(class) =
        canonical_nyx_exploit_class(&diag.cap).or_else(|| canonical_nyx_exploit_class(&diag.rule))
    {
        return Some((class.to_string(), format!("Nyx cap/rule maps directly to {class}")));
    }

    let sink_l = sink.unwrap_or_default().to_ascii_lowercase();
    let route_l = route.unwrap_or_default().to_ascii_lowercase();
    let param_l = param.unwrap_or_default().to_ascii_lowercase();

    if text_contains_any(
        text,
        &[
            "dom xss",
            "cross-site scripting",
            "client-side xss",
            "innerhtml",
            "insertadjacenthtml",
            "dangerouslysetinnerhtml",
            "document.write",
            "location.hash",
            "postmessage",
        ],
    ) {
        return Some((
            "DOM_XSS".to_string(),
            "Nyx evidence references a browser-controlled source or DOM HTML/script sink"
                .to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            "open redirect",
            "unsafe redirect",
            "redirect_uri",
            "return_url",
            "returnurl",
            "next=",
            "next parameter",
            "location header",
            "res.redirect",
            "response.redirect",
        ],
    ) || (text_contains_any(text, &["redirect", "location"])
        && text_contains_any(&param_l, &["url", "next", "redirect", "return", "callback"]))
    {
        return Some((
            "OPEN_REDIRECT".to_string(),
            "Nyx evidence ties attacker-controlled navigation input to a redirect sink".to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            "ssrf",
            "server-side request",
            "server side request",
            "url fetch",
            "fetch user supplied url",
            "http client",
            "requests.get",
            "axios.get",
            "urlopen",
            "curl",
        ],
    ) || (text_contains_any(&sink_l, &["fetch", "request", "axios", "urlopen", "curl"])
        && text_contains_any(
            &param_l,
            &["url", "uri", "endpoint", "target", "callback", "webhook"],
        ))
    {
        return Some((
            "SSRF".to_string(),
            "Nyx evidence shows attacker-controlled URL input reaching a server-side fetch sink"
                .to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            ".env",
            "config exposure",
            "configuration exposure",
            "exposed config",
            "secret key",
            "credential",
            "api key",
            "settings leak",
        ],
    ) || route_l.contains("config")
    {
        return Some((
            "CONFIG_EXPOSURE".to_string(),
            "Nyx evidence points at configuration or secret-bearing material exposed through a reachable component"
                .to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            "debug exposure",
            "debug route",
            "debug endpoint",
            "diagnostic",
            "stack trace",
            "traceback",
            "actuator",
            "dev mail",
            "dev_mail",
            "metrics endpoint",
        ],
    ) || text_contains_any(&route_l, &["debug", "actuator", "metrics", "/dev/"])
    {
        return Some((
            "DEBUG_EXPOSURE".to_string(),
            "Nyx evidence points at a diagnostic/debug surface with potentially sensitive output"
                .to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            "auth bypass",
            "authentication bypass",
            "missing authentication",
            "without authentication",
            "unauthenticated",
            "unprotected route",
            "trusted header",
            "x-forwarded-user",
            "x-original-user",
        ],
    ) {
        return Some((
            "AUTH_BYPASS".to_string(),
            "Nyx evidence indicates a route may be reachable without the expected authentication boundary"
                .to_string(),
        ));
    }
    if text_contains_any(
        text,
        &[
            "idor",
            "insecure direct object",
            "object isolation",
            "tenant isolation",
            "ownership check",
            "missing authorization",
            "access control",
            "authorization check",
            "account id",
            "user id",
            "tenant id",
        ],
    ) {
        let idor = param_l.ends_with("id")
            || param_l == "id"
            || text_contains_any(&param_l, &["account", "user", "tenant", "org", "project"])
            || text_contains_any(&route_l, &[":id", "{id}", "/users/", "/accounts/", "/tenants/"])
            || text_contains_any(text, &["idor", "insecure direct object", "object isolation"]);
        let class = if idor { "IDOR" } else { "ACCESS_CONTROL" };
        return Some((
            class.to_string(),
            "Nyx evidence suggests an authorization boundary around object or tenant data"
                .to_string(),
        ));
    }
    None
}

fn canonical_nyx_exploit_class(raw: &str) -> Option<&'static str> {
    let normalized =
        raw.trim().to_ascii_uppercase().replace('-', "_").replace(' ', "_").replace('.', "_");
    match normalized.as_str() {
        "DOM_XSS" | "CLIENT_SIDE_XSS" => Some("DOM_XSS"),
        "XSS" | "CROSS_SITE_SCRIPTING" if !normalized.contains("STORED") => Some("DOM_XSS"),
        "IDOR" | "INSECURE_DIRECT_OBJECT_REFERENCE" => Some("IDOR"),
        "ACCESS_CONTROL" | "BROKEN_ACCESS_CONTROL" | "AUTHZ_BYPASS" => Some("ACCESS_CONTROL"),
        "OPEN_REDIRECT" | "UNVALIDATED_REDIRECT" | "UNSAFE_REDIRECT" => Some("OPEN_REDIRECT"),
        "SSRF" | "SERVER_SIDE_REQUEST_FORGERY" => Some("SSRF"),
        "DEBUG_EXPOSURE" | "DIAGNOSTIC_EXPOSURE" => Some("DEBUG_EXPOSURE"),
        "CONFIG_EXPOSURE" | "CONFIGURATION_EXPOSURE" => Some("CONFIG_EXPOSURE"),
        "AUTH_BYPASS" | "AUTHENTICATION_BYPASS" => Some("AUTH_BYPASS"),
        "SECURITY" | "SECURITY_WARNING" | "TAINT_UNSANITISED_FLOW" => None,
        _ => None,
    }
}

fn nyx_candidate_title(
    signal: &NyxSignalRecord,
    classification: &NyxExploitClassification,
) -> String {
    let target = classification.route.as_deref().unwrap_or(signal.path.as_str());
    let mut detail = String::new();
    if let Some(param) = &classification.param {
        detail.push_str(&format!(" via `{param}`"));
    } else if let Some(sink) = &classification.sink {
        detail.push_str(&format!(" into `{sink}`"));
    }
    let class_title = match classification.vuln_class.as_str() {
        "DOM_XSS" => "Potential DOM XSS",
        "IDOR" => "Potential IDOR",
        "ACCESS_CONTROL" => "Potential access-control bypass",
        "OPEN_REDIRECT" => "Potential open redirect",
        "SSRF" => "Potential SSRF",
        "DEBUG_EXPOSURE" => "Potential debug exposure",
        "CONFIG_EXPOSURE" => "Potential configuration exposure",
        "AUTH_BYPASS" => "Potential authentication bypass",
        other => other,
    };
    format!("{class_title}: {target}{detail}")
}

fn nyx_candidate_hypothesis(
    signal: &NyxSignalRecord,
    classification: &NyxExploitClassification,
) -> String {
    let line = signal.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string());
    let mut parts = vec![format!(
        "Nyx reported {} `{}`/`{}` at {}:{}.",
        signal.severity, signal.cap, signal.rule, signal.path, line
    )];
    if classification.is_reclassified_from(&signal.cap) {
        parts.push(format!(
            "Nyctos reclassified the generic/static signal as {} because {}.",
            classification.vuln_class, classification.reason
        ));
    } else {
        parts.push(format!("Nyctos kept the Nyx class because {}.", classification.reason));
    }
    let route = classification.route.as_deref().unwrap_or("the inferred affected route");
    match classification.vuln_class.as_str() {
        "DOM_XSS" => parts.push(format!(
            "Attacker hypothesis: input{} reaches DOM sink{} on {route} and can execute script in a victim browser.",
            classification.param.as_deref().map(|p| format!(" `{p}`")).unwrap_or_default(),
            classification.sink.as_deref().map(|s| format!(" `{s}`")).unwrap_or_default(),
        )),
        "OPEN_REDIRECT" => parts.push(format!(
            "Attacker hypothesis: redirect parameter{} on {route} can send users to an attacker-controlled origin.",
            classification.param.as_deref().map(|p| format!(" `{p}`")).unwrap_or_default(),
        )),
        "SSRF" => parts.push(format!(
            "Attacker hypothesis: URL parameter{} reaches server-side fetch sink{} and could make the server request attacker-selected resources.",
            classification.param.as_deref().map(|p| format!(" `{p}`")).unwrap_or_default(),
            classification.sink.as_deref().map(|s| format!(" `{s}`")).unwrap_or_default(),
        )),
        "IDOR" | "ACCESS_CONTROL" => parts.push(format!(
            "Attacker hypothesis: object or tenant selector{} on {route} may expose another user's data without proper authorization.",
            classification.param.as_deref().map(|p| format!(" `{p}`")).unwrap_or_default(),
        )),
        "AUTH_BYPASS" => parts.push(format!(
            "Attacker hypothesis: {route} may return protected functionality or data to an unauthenticated or lower-privileged request."
        )),
        "DEBUG_EXPOSURE" | "CONFIG_EXPOSURE" => parts.push(format!(
            "Attacker hypothesis: {route} may expose debug, configuration, secret, or operational markers to an unintended requester."
        )),
        _ => parts.push(
            "Static analysis found a security-relevant flow; live verification must derive an exploit-specific oracle before reporting."
                .to_string(),
        ),
    }
    parts.push(
        "This is still only a pentest lead; Nyctos must collect exploit evidence or keep it as review-only."
            .to_string(),
    );
    parts.join(" ")
}

fn nyx_diag_text(diag: &Diag) -> String {
    let evidence = serde_json::to_string(&diag.evidence).unwrap_or_default();
    let flow = diag
        .flow_steps
        .iter()
        .map(|step| {
            format!(
                "{} {} {} {}",
                step.path,
                step.kind.as_deref().unwrap_or_default(),
                step.snippet.as_deref().unwrap_or_default(),
                step.note.as_deref().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {} {} {}",
        diag.cap,
        diag.rule,
        diag.message.as_deref().unwrap_or_default(),
        diag.path,
        evidence,
        flow
    )
    .to_ascii_lowercase()
}

fn extract_route_from_diag(diag: &Diag, text: &str) -> Option<String> {
    for path in [
        &["route"][..],
        &["route", "path"],
        &["request", "path"],
        &["request", "url"],
        &["http", "path"],
        &["http", "url"],
        &["endpoint"],
        &["url_path"],
        &["url"],
        &["uri"],
        &["action"],
        &["matched_at"],
    ] {
        if let Some(route) =
            json_string_at(&diag.evidence, path).and_then(|raw| normalise_route_candidate(&raw))
        {
            return Some(route);
        }
    }
    json_string_for_key(
        &diag.evidence,
        &["route", "url_path", "endpoint", "url", "uri", "action", "matched_at"],
    )
    .and_then(|raw| normalise_route_candidate(&raw))
    .or_else(|| extract_route_like_path(text))
}

fn extract_method_from_diag(diag: &Diag) -> Option<String> {
    json_string_at(&diag.evidence, &["method"])
        .or_else(|| json_string_at(&diag.evidence, &["request", "method"]))
        .or_else(|| json_string_for_key(&diag.evidence, &["method", "http_method"]))
        .map(|method| method.trim().to_ascii_uppercase())
        .filter(|method| {
            matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            )
        })
}

fn extract_param_from_diag(diag: &Diag, text: &str) -> Option<String> {
    for path in [
        &["param"][..],
        &["parameter"],
        &["query_param"],
        &["query", "param"],
        &["request", "param"],
        &["request", "parameter"],
        &["source", "param"],
        &["source", "parameter"],
        &["source", "name"],
        &["source", "variable"],
    ] {
        if let Some(param) =
            json_string_at(&diag.evidence, path).and_then(|raw| normalise_param_candidate(&raw))
        {
            return Some(param);
        }
    }
    json_string_for_key(
        &diag.evidence,
        &["param", "parameter", "query_param", "request_param", "field"],
    )
    .and_then(|raw| normalise_param_candidate(&raw))
    .or_else(|| extract_param_from_text(text))
}

fn extract_sink_from_diag(diag: &Diag) -> Option<String> {
    for path in [
        &["sink", "callee"][..],
        &["sink", "name"],
        &["sink", "function"],
        &["sink", "method"],
        &["sink", "snippet"],
        &["sink"],
    ] {
        if let Some(sink) = json_string_at(&diag.evidence, path).filter(|s| !s.trim().is_empty()) {
            return Some(sink);
        }
    }
    diag.flow_steps
        .iter()
        .find(|step| step.kind.as_deref().is_some_and(|kind| kind.eq_ignore_ascii_case("sink")))
        .and_then(|step| step.snippet.clone().or_else(|| step.note.clone()))
}

fn extract_source_from_diag(diag: &Diag) -> Option<String> {
    for path in [
        &["source", "name"][..],
        &["source", "param"],
        &["source", "parameter"],
        &["source", "variable"],
        &["source", "snippet"],
        &["source"],
    ] {
        if let Some(source) = json_string_at(&diag.evidence, path).filter(|s| !s.trim().is_empty())
        {
            return Some(source);
        }
    }
    diag.flow_steps
        .iter()
        .find(|step| step.kind.as_deref().is_some_and(|kind| kind.eq_ignore_ascii_case("source")))
        .and_then(|step| step.snippet.clone().or_else(|| step.note.clone()))
}

fn extract_evidence_location(diag: &Diag, key: &str) -> (Option<String>, Option<i64>) {
    let path = json_string_at(&diag.evidence, &[key, "path"])
        .or_else(|| json_string_at(&diag.evidence, &[key, "file"]));
    let line = json_i64_at(&diag.evidence, &[key, "line"]);
    if path.is_some() || line.is_some() {
        return (path, line);
    }
    let matching = diag
        .flow_steps
        .iter()
        .find(|step| step.kind.as_deref().is_some_and(|kind| kind.eq_ignore_ascii_case(key)));
    (matching.map(|step| step.path.clone()), matching.map(|step| i64::from(step.line)))
}

fn extract_route_like_path(text: &str) -> Option<String> {
    let re = Regex::new(
        r#"(?P<path>https?://[^\s"'<>]+|/(?:api|admin|debug|dev|config|settings|auth|login|logout|oauth|redirect|callback|proxy|fetch|webhook|user|users|account|accounts|tenant|tenants|search|profile|internal|actuator|metrics)[A-Za-z0-9_./:{}?=&%+-]*)"#,
    )
    .expect("route inference regex");
    let route = re
        .captures_iter(text)
        .filter_map(|captures| captures.name("path").map(|m| m.as_str()))
        .filter_map(normalise_route_candidate)
        .next();
    route
}

fn extract_param_from_text(text: &str) -> Option<String> {
    for pattern in [
        r#"(?i)(?:param(?:eter)?|query|field|key)\s*[:=]?\s*[`'"]?([a-z_][a-z0-9_.-]{0,63})"#,
        r#"(?i)req\.query\.([a-z_][a-z0-9_]{0,63})"#,
        r#"(?i)searchparams\.get\([`'"]([a-z_][a-z0-9_.-]{0,63})[`'"]\)"#,
        r#"(?i)request\.args\[[`'"]([a-z_][a-z0-9_.-]{0,63})[`'"]\]"#,
        r#"(?i)params\[[`'"]([a-z_][a-z0-9_.-]{0,63})[`'"]\]"#,
    ] {
        let re = Regex::new(pattern).expect("param inference regex");
        if let Some(param) = re
            .captures(text)
            .and_then(|captures| captures.get(1))
            .and_then(|m| normalise_param_candidate(m.as_str()))
        {
            return Some(param);
        }
    }
    None
}

fn normalise_route_candidate(raw: &str) -> Option<String> {
    let route = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}'));
    if route.starts_with("http://") || route.starts_with("https://") {
        return Some(route.to_string());
    }
    if route.starts_with('/') && route.len() > 1 && !route.contains(char::is_whitespace) {
        return Some(route.to_string());
    }
    None
}

fn normalise_param_candidate(raw: &str) -> Option<String> {
    let param = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}'));
    if param.is_empty()
        || param.len() > 64
        || param.contains('/')
        || param.contains('\\')
        || param.chars().any(char::is_whitespace)
    {
        return None;
    }
    let lower = param.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "request" | "response" | "params" | "query" | "body" | "headers" | "sink" | "source"
    ) {
        return None;
    }
    Some(param.to_string())
}

fn json_string_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    json_scalar_to_string(cursor)
}

fn json_i64_at(value: &serde_json::Value, path: &[&str]) -> Option<i64> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_i64().or_else(|| cursor.as_u64().and_then(|v| i64::try_from(v).ok()))
}

fn json_string_for_key(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key).and_then(json_scalar_to_string) {
                    return Some(found);
                }
            }
            map.values().find_map(|child| json_string_for_key(child, keys))
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|child| json_string_for_key(child, keys))
        }
        _ => None,
    }
}

fn json_scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn insert_json_string(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        obj.insert(key.to_string(), serde_json::Value::String(value));
    }
}

fn insert_json_i64(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<i64>,
) {
    if let Some(value) = value {
        obj.insert(key.to_string(), serde_json::Value::Number(value.into()));
    }
}

fn text_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[derive(Debug, Default)]
struct CandidateVerificationReport {
    confirmed: u32,
    rejected: u32,
    blocked: u32,
    inconclusive: u32,
    skipped_no_plan: u32,
    errored: u32,
    http_attempts: u32,
    browser_attempts: u32,
}

async fn materialize_ai_review_items_for_live_verification(
    store: &Store,
    run_id: &str,
    project_id: &str,
    now_ms: i64,
) -> anyhow::Result<u32> {
    let mut queued = 0_u32;

    for finding in store.findings().list_by_run(run_id).await? {
        if finding.status != "Quarantine" || finding.finding_origin != "AiExploration" {
            continue;
        }
        let candidate = pentest_candidate_from_review_finding(&finding, project_id, now_ms);
        store.pentest_candidates().insert(&candidate).await?;
        queued += 1;
    }

    for candidate in store.candidate_findings().list_pending().await? {
        if candidate.run_id != run_id {
            continue;
        }
        let pentest_candidate = pentest_candidate_from_ai_candidate(&candidate, project_id, now_ms);
        store.pentest_candidates().insert(&pentest_candidate).await?;
        queued += 1;
    }

    Ok(queued)
}

fn pentest_candidate_from_review_finding(
    finding: &FindingRecord,
    project_id: &str,
    now_ms: i64,
) -> PentestCandidateRecord {
    let verdict = exploration_verdict_blob(finding.verdict_blob.as_deref());
    let endpoint = verdict.as_ref().and_then(|v| json_string_field(v, "endpoint"));
    let hint = verdict.as_ref().and_then(|v| json_string_field(v, "suggested_payload_hint"));
    let rationale = verdict
        .as_ref()
        .and_then(|v| json_string_field(v, "rationale"))
        .unwrap_or_else(|| "AI exploration produced a review finding.".to_string());
    let mut component = serde_json::json!({
        "kind": "ai_exploration_finding",
        "repo": &finding.repo,
        "path": &finding.path,
        "line": finding.line,
        "rule": &finding.rule,
        "cap": &finding.cap,
        "finding_id": &finding.id,
    });
    if let Some(obj) = component.as_object_mut() {
        insert_json_string(obj, "endpoint", endpoint.clone());
        insert_json_string(obj, "route", endpoint_path_from_label(endpoint.as_deref()));
        insert_json_string(obj, "url_path", endpoint_path_from_label(endpoint.as_deref()));
        insert_json_string(obj, "suggested_payload_hint", hint.clone());
    }
    let vuln_class =
        live_vuln_class_from_ai(&finding.cap, Some(&finding.rule), Some(&rationale), &finding.path);
    PentestCandidateRecord {
        id: format!("pc-finding-{}", finding.id),
        run_id: finding.run_id.clone(),
        project_id: project_id.to_string(),
        source: "AiExplorationFinding".to_string(),
        source_ids: vec![finding.id.clone()],
        title: format_location_title(&vuln_class, &finding.path, finding.line),
        vuln_class,
        severity_guess: finding.severity.clone(),
        affected_components: vec![component],
        hypothesis: ai_hypothesis(&rationale, hint.as_deref()),
        test_plan: "Use the first-class live verifier to derive and execute a safe HTTP/browser confirmation for this AI exploration finding.".to_string(),
        status: "NeedsLiveTest".to_string(),
        rejection_reason: None,
        confidence: 0.78,
        trace_id: None,
        created_at: now_ms,
        updated_at: now_ms,
    }
}

fn pentest_candidate_from_ai_candidate(
    candidate: &CandidateFindingRecord,
    project_id: &str,
    now_ms: i64,
) -> PentestCandidateRecord {
    let rationale = candidate
        .rationale
        .clone()
        .unwrap_or_else(|| "AI novel-finding discovery proposed this issue.".to_string());
    let vuln_class = live_vuln_class_from_ai(
        &candidate.cap,
        candidate.rule_hint.as_deref(),
        Some(&rationale),
        &candidate.path,
    );
    let mut component = serde_json::json!({
        "kind": "ai_novel_candidate",
        "repo": &candidate.repo,
        "path": &candidate.path,
        "line": candidate.line,
        "cap": &candidate.cap,
        "rule_hint": &candidate.rule_hint,
        "candidate_id": &candidate.id,
    });
    if let Some(obj) = component.as_object_mut() {
        insert_json_string(obj, "suggested_payload_hint", candidate.suggested_payload_hint.clone());
    }
    PentestCandidateRecord {
        id: format!("pc-{}", candidate.id),
        run_id: candidate.run_id.clone(),
        project_id: project_id.to_string(),
        source: "AiNovelFinding".to_string(),
        source_ids: vec![candidate.id.clone()],
        title: candidate
            .rule_hint
            .as_deref()
            .map(human_title_from_rule)
            .unwrap_or_else(|| format_location_title(&vuln_class, &candidate.path, candidate.line)),
        vuln_class,
        severity_guess: "High".to_string(),
        affected_components: vec![component],
        hypothesis: ai_hypothesis(&rationale, candidate.suggested_payload_hint.as_deref()),
        test_plan: "Use the first-class live verifier to derive and execute a safe HTTP/browser confirmation for this AI candidate.".to_string(),
        status: "NeedsLiveTest".to_string(),
        rejection_reason: None,
        confidence: 0.7,
        trace_id: candidate.trace_id.clone(),
        created_at: now_ms,
        updated_at: now_ms,
    }
}

fn live_vuln_class_from_ai(
    cap: &str,
    rule_hint: Option<&str>,
    rationale: Option<&str>,
    path: &str,
) -> String {
    let text = format!(
        "{} {} {} {}",
        cap,
        rule_hint.unwrap_or_default(),
        rationale.unwrap_or_default(),
        path
    )
    .to_ascii_lowercase();
    if text.contains("cf-access")
        || text.contains("trusted_header")
        || text.contains("trusted header")
        || text.contains("client_header")
    {
        "AUTH_BYPASS".to_string()
    } else if text.contains("dev_mail")
        || text.contains("dev mail")
        || text.contains("/api/dev/mail")
    {
        "DEBUG_EXPOSURE".to_string()
    } else if text.contains("xss") || text.contains("innerhtml") || text.contains("inline_event") {
        "DOM_XSS".to_string()
    } else if cap.eq_ignore_ascii_case("OTHER") {
        rule_hint
            .and_then(|rule| rule.split(['.', ':']).next_back())
            .map(|rule| rule.to_ascii_uppercase().replace('-', "_"))
            .filter(|class| !class.trim().is_empty())
            .unwrap_or_else(|| "OTHER".to_string())
    } else {
        cap.to_string()
    }
}

fn ai_hypothesis(rationale: &str, hint: Option<&str>) -> String {
    match hint.filter(|hint| !hint.trim().is_empty()) {
        Some(hint) => format!("{rationale}\nSuggested verification hint: {hint}"),
        None => rationale.to_string(),
    }
}

fn endpoint_path_from_label(endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint?.trim();
    let path = endpoint
        .split(',')
        .next()
        .unwrap_or(endpoint)
        .split_whitespace()
        .find(|part| part.starts_with('/'))?;
    Some(path.trim_end_matches([',', ';']).to_string())
}

async fn verify_pentest_candidates(
    ai_config: &AiConfig,
    store: &Store,
    secrets: &SecretStore,
    run_id: &str,
    project_id: &str,
    environment: &mut launch::RunningProjectEnvironment,
    target_urls: &[String],
    route_model: Option<&nyctos_types::product::RouteModel>,
    run_config: &nyctos_core::RunConfig,
    auth_profiles: &[nyctos_types::project::ProjectAuthProfile],
    auth_artifact_dir: &std::path::Path,
    browser_artifact_root: &std::path::Path,
    policy_audit_root: &std::path::Path,
    auth_workspace_paths: &[std::path::PathBuf],
    events: EventSink,
) -> anyhow::Result<CandidateVerificationReport> {
    let candidates = store.pentest_candidates().list_by_run(run_id).await?;
    let mut report = CandidateVerificationReport::default();
    let auth_session_manager = auth_sessions::AuthSessionManager::default();
    emit_phase(&events, run_id, project_id, "AuthSessionAcquisitionStarted", true, None);
    let auth_message = preflight_auth_sessions(
        &auth_session_manager,
        run_id,
        project_id,
        target_urls,
        auth_profiles,
        auth_artifact_dir,
        auth_workspace_paths,
        run_config.browser_checks_enabled,
        &events,
    )
    .await;
    emit_phase(
        &events,
        run_id,
        project_id,
        "AuthSessionAcquisitionStarted",
        false,
        Some(auth_message),
    );
    for candidate in
        candidates.into_iter().filter(|c| matches!(c.status.as_str(), "Proposed" | "NeedsLiveTest"))
    {
        if !candidate_has_runnable_test_plan(
            &candidate,
            target_urls,
            run_config.browser_checks_enabled,
        ) {
            report.skipped_no_plan += 1;
            let reason =
                match pentest_tools::normalise_live_test_plan(&candidate.test_plan, target_urls) {
                    Ok(None) => {
                        "candidate has structured no-plan reason or no executable plan".to_string()
                    }
                    Err(err) => format!("no executable live test plan: {err}"),
                    Ok(Some(_)) => "candidate has no runnable live test plan".to_string(),
                };
            store
                .pentest_candidates()
                .set_status(&candidate.id, "NeedsReview", Some(&reason), now_epoch_ms())
                .await?;
            continue;
        }
        let started = now_epoch_ms();
        let attempt_id = format!("va-{}-{}", candidate.id, started);
        let browser_artifact_dir = browser_artifact_root.join(safe_artifact_segment(&attempt_id));
        let audit_log = pentest_tools::ExploitAuditLog::default();
        let options = pentest_tools::LiveVerifierOptions {
            target_urls: target_urls.to_vec(),
            auth_profiles: auth_profiles.to_vec(),
            auth_session_manager: auth_session_manager.clone(),
            auth_artifact_dir: auth_artifact_dir.to_path_buf(),
            auth_workspace_paths: auth_workspace_paths.to_vec(),
            browser_artifact_dir: Some(browser_artifact_dir),
            browser_checks_enabled: run_config.browser_checks_enabled,
            policy: pentest_tools::ExploitSafetyPolicy::from_run_config(run_config),
            audit_log: audit_log.clone(),
        };
        let mut outcome = execute_candidate_test_plan(&candidate, &options).await;
        let mut replan_meta = None;
        if let Some(model) = route_model {
            if let Some(failure_code) = outcome_failure_code(outcome.as_ref().ok()) {
                let synthesizer = live_planning::LiveTestPlanSynthesizer::new(
                    live_planning::LiveTestPlanSynthesisContext {
                        route_model: Some(model),
                        target_urls,
                        auth_profiles,
                        browser_checks_enabled: run_config.browser_checks_enabled,
                        allow_state_changing: run_config.state_changing_live_probes_allowed(),
                    },
                );
                if let Some(replan) =
                    synthesizer.replan_after_failure(&candidate, Some(failure_code.as_str()))
                {
                    let replan_blob = serde_json::to_string(&replan)?;
                    if replan_blob != candidate.test_plan {
                        let retry_candidate = PentestCandidateRecord {
                            test_plan: replan_blob.clone(),
                            ..candidate.clone()
                        };
                        let retry_outcome =
                            execute_candidate_test_plan(&retry_candidate, &options).await;
                        replan_meta = Some(serde_json::json!({
                            "attempted": true,
                            "trigger_failure_code": failure_code,
                            "plan_kind": replan.kind_str(),
                            "accepted": retry_outcome.as_ref().ok().is_some_and(|o| matches!(o, VerificationOutcome::Confirmed { .. })),
                        }));
                        outcome = retry_outcome;
                    }
                }
            }
        }
        let finished = now_epoch_ms();
        let (mut status, mut request, response, mut oracle, mut error) = match outcome {
            Ok(VerificationOutcome::Confirmed { request, response, oracle }) => {
                ("Confirmed", Some(request), Some(response), Some(oracle), None)
            }
            Ok(VerificationOutcome::Rejected { request, response, oracle }) => {
                report.rejected += 1;
                ("Rejected", Some(request), Some(response), Some(oracle), None)
            }
            Ok(VerificationOutcome::Blocked { reason, trace }) => {
                report.blocked += 1;
                ("Blocked", trace, None, None, Some(reason))
            }
            Ok(VerificationOutcome::Inconclusive { reason, trace }) => {
                report.inconclusive += 1;
                ("Inconclusive", trace, None, None, Some(reason))
            }
            Err(err) => {
                report.errored += 1;
                ("Errored", None, None, None, Some(err.to_string()))
            }
        };
        if status == "Rejected" {
            if let Some(reason) = non_dispositive_rejection_reason(oracle.as_ref()) {
                report.rejected = report.rejected.saturating_sub(1);
                report.inconclusive += 1;
                status = "Inconclusive";
                error = Some(reason.clone());
                if let Some(oracle_value) = oracle.as_mut().and_then(|v| v.as_object_mut()) {
                    oracle_value
                        .insert("non_dispositive".to_string(), serde_json::Value::Bool(true));
                    oracle_value.insert("operator_reason".to_string(), reason.into());
                }
            }
        }
        if let Some(meta) = replan_meta {
            attach_replan_meta(&mut request, &mut oracle, meta);
        }
        if let Some(provenance) = business_logic_provenance_from_candidate(&candidate) {
            if let Some(request_value) = request.take() {
                request = Some(with_business_logic_provenance(request_value, provenance.clone()));
            }
            if let Some(oracle_value) = oracle.take() {
                oracle = Some(with_business_logic_provenance(oracle_value, provenance));
            }
        }
        let mut accepted_review: Option<LiveEvidenceReviewOutput> = None;
        if status == "Confirmed" {
            if let (Some(request_value), Some(response_value), Some(oracle_value)) =
                (request.clone(), response.clone(), oracle.clone())
            {
                let deterministic_review = review_confirmed_live_evidence(
                    &candidate,
                    &request_value,
                    &response_value,
                    &oracle_value,
                );
                let proposed_plan = proposed_plan_for_review(&candidate, target_urls);
                let mut ai_review = None;
                let mut reviewer_error = None;
                if deterministic_review.decision == LiveEvidenceReviewDecision::Accept {
                    match ai_pipeline::run_live_evidence_review_pass(
                        ai_config,
                        store,
                        secrets,
                        run_id,
                        &candidate,
                        proposed_plan,
                        serde_json::json!({
                            "request": &request_value,
                            "response": &response_value,
                        }),
                        oracle_value.clone(),
                        deterministic_review.clone(),
                        events.clone(),
                    )
                    .await
                    {
                        Ok(review) => ai_review = review,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                candidate = %candidate.id,
                                "live evidence reviewer failed; falling back to deterministic review"
                            );
                            reviewer_error = Some(err.to_string());
                        }
                    }
                }
                let final_review =
                    ai_review.clone().unwrap_or_else(|| deterministic_review.clone());
                oracle = Some(oracle_with_evidence_review(
                    oracle_value,
                    &deterministic_review,
                    ai_review.as_ref(),
                    reviewer_error.as_deref(),
                    &final_review,
                ));
                match final_review.decision {
                    LiveEvidenceReviewDecision::Accept => {
                        report.confirmed += 1;
                        accepted_review = Some(final_review);
                    }
                    LiveEvidenceReviewDecision::Downgrade => {
                        status = "Inconclusive";
                        report.inconclusive += 1;
                        error = Some(format!(
                            "evidence reviewer downgraded: {}",
                            final_review.rationale
                        ));
                    }
                    LiveEvidenceReviewDecision::Block => {
                        status = "Rejected";
                        report.rejected += 1;
                        error =
                            Some(format!("evidence reviewer blocked: {}", final_review.rationale));
                    }
                }
            } else {
                status = "Inconclusive";
                report.inconclusive += 1;
                error = Some(
                    "confirmed attempt lacked request, response, or oracle evidence".to_string(),
                );
            }
        }
        let method = verification_attempt_method(request.as_ref());
        let artifact_paths = if method == "browser" {
            pentest_tools::artifact_paths_from_response(response.as_ref())
        } else {
            Vec::new()
        };
        if method == "browser" {
            report.browser_attempts += 1;
        } else {
            report.http_attempts += 1;
        }
        let mut artifact_paths = artifact_paths;
        if audit_log.has_executed_state_changing_action()
            && run_config.exploit_reset_after_state_changing
        {
            audit_log.record_reset(
                "started",
                "state-changing action executed; requesting environment reset hook",
                &options.policy,
            );
            match environment.reset_after_state_change().await {
                Ok(true) => audit_log.record_reset(
                    "finished",
                    "environment reset hook completed",
                    &options.policy,
                ),
                Ok(false) => audit_log.record_reset(
                    "skipped",
                    "environment reset hook unavailable for this launch mode",
                    &options.policy,
                ),
                Err(err) => {
                    tracing::warn!(error = %err, "environment reset hook failed after guarded action");
                    audit_log.record_reset(
                        "failed",
                        format!("environment reset hook failed: {err}"),
                        &options.policy,
                    );
                }
            }
        }
        if let Some(path) = write_exploit_audit_jsonl(policy_audit_root, &attempt_id, &audit_log) {
            artifact_paths.push(path);
        }
        let attempt = VerificationAttemptRecord {
            id: attempt_id.clone(),
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            environment_run_id: environment.environment_run_id.clone(),
            candidate_id: Some(candidate.id.clone()),
            chain_id: None,
            method,
            status: status.to_string(),
            started_at: started,
            finished_at: Some(finished),
            duration_ms: Some(finished - started),
            request,
            response,
            oracle,
            artifact_paths,
            error: error.clone(),
            replay_stable: None,
        };
        store.verification_attempts().insert(&attempt).await?;
        match status {
            "Confirmed" => {
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "Verified", None, finished)
                    .await?;
                mark_source_review_items_verified(store, &candidate, &attempt_id).await?;
                let vuln = vulnerability_from_candidate(
                    &candidate,
                    &attempt_id,
                    finished,
                    accepted_review.as_ref(),
                );
                store.verified_vulnerabilities().upsert(&vuln).await?;
            }
            "Rejected" => {
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "Rejected", error.as_deref(), finished)
                    .await?;
            }
            "Blocked" => {
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "Rejected", error.as_deref(), finished)
                    .await?;
            }
            "Errored" => {
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "Errored", error.as_deref(), finished)
                    .await?;
            }
            "Inconclusive" => {
                store
                    .pentest_candidates()
                    .set_status(&candidate.id, "NeedsLiveTest", error.as_deref(), finished)
                    .await?;
            }
            _ => {}
        }
    }
    Ok(report)
}

async fn mark_source_review_items_verified(
    store: &Store,
    candidate: &PentestCandidateRecord,
    attempt_id: &str,
) -> anyhow::Result<()> {
    for source_id in &candidate.source_ids {
        if source_id.starts_with("cand-") {
            store.candidate_findings().set_status(source_id, "Promoted").await?;
        } else {
            let verdict = serde_json::json!({
                "kind": "LiveVerification",
                "source": candidate.source,
                "candidate_id": candidate.id,
                "verification_attempt_id": attempt_id,
                "title": candidate.title,
            });
            store
                .findings()
                .set_verify_result(
                    source_id,
                    "Open",
                    &serde_json::to_string(&verdict)?,
                    "LiveVerifier",
                )
                .await?;
        }
    }
    Ok(())
}

async fn preflight_auth_sessions(
    manager: &auth_sessions::AuthSessionManager,
    run_id: &str,
    project_id: &str,
    target_urls: &[String],
    auth_profiles: &[nyctos_types::project::ProjectAuthProfile],
    auth_artifact_dir: &std::path::Path,
    auth_workspace_paths: &[std::path::PathBuf],
    browser_checks_enabled: bool,
    events: &EventSink,
) -> String {
    let Some(target_url) = target_urls.first() else {
        return "auth session acquisition skipped: no target URL available".to_string();
    };
    if auth_profiles.is_empty() {
        emit_auth_session_status(
            events,
            run_id,
            project_id,
            "anonymous",
            "acquired",
            "anonymous",
            None,
        );
        return "auth sessions: anonymous acquired".to_string();
    }

    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for profile in auth_profiles {
        let result = manager
            .acquire_session(
                &profile.role,
                auth_profiles,
                target_url,
                auth_artifact_dir,
                &auth_sessions::AuthSessionOptions {
                    browser_checks_enabled,
                    workspace_paths: auth_workspace_paths.to_vec(),
                },
            )
            .await;
        *counts.entry(result.status.as_str().to_string()).or_default() += 1;
        let acquired_by =
            result.session.as_ref().map(|s| s.acquired_by.as_str()).unwrap_or("unknown");
        emit_auth_session_status(
            events,
            run_id,
            project_id,
            &profile.role,
            result.status.as_str(),
            acquired_by,
            result.reason.as_deref(),
        );
    }
    format!(
        "auth sessions: {} acquired, {} reused, {} skipped, {} failed",
        counts.get("acquired").copied().unwrap_or(0),
        counts.get("reused").copied().unwrap_or(0),
        counts.get("skipped").copied().unwrap_or(0),
        counts.get("failed").copied().unwrap_or(0)
    )
}

enum VerificationOutcome {
    Confirmed { request: serde_json::Value, response: serde_json::Value, oracle: serde_json::Value },
    Rejected { request: serde_json::Value, response: serde_json::Value, oracle: serde_json::Value },
    Inconclusive { reason: String, trace: Option<serde_json::Value> },
    Blocked { reason: String, trace: Option<serde_json::Value> },
}

async fn execute_candidate_test_plan(
    candidate: &PentestCandidateRecord,
    options: &pentest_tools::LiveVerifierOptions,
) -> anyhow::Result<VerificationOutcome> {
    Ok(match pentest_tools::execute_live_test_plan(&candidate.test_plan, options).await? {
        pentest_tools::ToolVerificationOutcome::Confirmed { request, response, oracle } => {
            VerificationOutcome::Confirmed { request, response, oracle }
        }
        pentest_tools::ToolVerificationOutcome::Rejected { request, response, oracle } => {
            VerificationOutcome::Rejected { request, response, oracle }
        }
        pentest_tools::ToolVerificationOutcome::Inconclusive { reason, trace } => {
            VerificationOutcome::Inconclusive { reason, trace }
        }
        pentest_tools::ToolVerificationOutcome::Blocked { reason, trace } => {
            VerificationOutcome::Blocked { reason, trace }
        }
    })
}

fn outcome_failure_code(outcome: Option<&VerificationOutcome>) -> Option<String> {
    match outcome? {
        VerificationOutcome::Confirmed { .. } => None,
        VerificationOutcome::Rejected { oracle, .. } => oracle_failure_code(oracle),
        VerificationOutcome::Inconclusive { reason, trace }
        | VerificationOutcome::Blocked { reason, trace } => trace
            .as_ref()
            .and_then(oracle_failure_code)
            .or_else(|| classify_failure_reason_text(reason)),
    }
}

fn oracle_failure_code(value: &serde_json::Value) -> Option<String> {
    value
        .get("failure_reason")
        .or_else(|| value.get("failure"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            value
                .get("failure_reason")
                .and_then(|v| v.as_array())
                .and_then(|items| items.first())
                .and_then(|v| v.get("code"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
}

fn classify_failure_reason_text(reason: &str) -> Option<String> {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("outside") && lower.contains("target") {
        Some("target_out_of_scope".to_string())
    } else if lower.contains("browser") && lower.contains("disabled") {
        Some("browser_disabled".to_string())
    } else if lower.contains("playwright") || lower.contains("runtime unavailable") {
        Some("runtime_unavailable".to_string())
    } else if lower.contains("auth") {
        Some("auth_missing".to_string())
    } else if lower.contains("no explicit oracle") || lower.contains("weak") {
        Some("weak_oracle".to_string())
    } else if lower.contains("404") || lower.contains("bad endpoint") {
        Some("bad_endpoint".to_string())
    } else {
        Some("no_executable_plan".to_string())
    }
}

fn non_dispositive_rejection_reason(oracle: Option<&serde_json::Value>) -> Option<String> {
    let code = oracle.and_then(oracle_failure_code)?;
    if matches!(
        code.as_str(),
        "bad_endpoint"
            | "no_executable_plan"
            | "weak_oracle"
            | "runtime_unavailable"
            | "browser_disabled"
            | "auth_missing"
            | "missing_seed_data"
            | "route_not_inferred"
            | "target_out_of_scope"
    ) {
        Some(format!(
            "live verification was inconclusive, not a rejection: verifier failure code `{code}` indicates plan/setup weakness rather than disproving the finding"
        ))
    } else {
        None
    }
}

fn attach_replan_meta(
    request: &mut Option<serde_json::Value>,
    oracle: &mut Option<serde_json::Value>,
    meta: serde_json::Value,
) {
    if let Some(request) = request.as_mut().and_then(|v| v.as_object_mut()) {
        request.insert("replan".to_string(), meta.clone());
    }
    if let Some(oracle) = oracle.as_mut().and_then(|v| v.as_object_mut()) {
        oracle.insert("replan".to_string(), meta);
    }
}

fn candidate_has_runnable_test_plan(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
    _browser_checks_enabled: bool,
) -> bool {
    pentest_tools::normalise_live_test_plan(&candidate.test_plan, target_urls)
        .ok()
        .flatten()
        .is_some()
}

fn verification_attempt_method(request: Option<&serde_json::Value>) -> String {
    if matches!(
        request.and_then(|v| v.get("kind")).and_then(|v| v.as_str()),
        Some("authz_browser_role_comparison") | Some("browser_role_comparison")
    ) {
        return "authz_browser_role_comparison".to_string();
    }
    if let Some(tool) = request
        .and_then(|v| v.get("policy_audit"))
        .and_then(|v| v.as_array())
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("tool"))
        .and_then(|v| v.as_str())
    {
        if tool.starts_with("browser.") || tool == "browser.workflow" {
            return "browser".to_string();
        }
    }
    match request.and_then(|v| v.get("kind")).and_then(|v| v.as_str()) {
        Some("browser") | Some("browser_workflow") => "browser".to_string(),
        Some("http_workflow") | Some("multi_step_http") => "http_workflow".to_string(),
        Some("differential_http") => "differential_http".to_string(),
        Some("authz_role_comparison") | Some("role_comparison") => {
            "authz_role_comparison".to_string()
        }
        Some("authz_object_ownership") | Some("object_ownership") => {
            "authz_object_ownership".to_string()
        }
        Some("authz_browser_role_comparison") | Some("browser_role_comparison") => {
            "authz_browser_role_comparison".to_string()
        }
        Some("single_http") | Some("http") => "http".to_string(),
        Some(other) => other.to_string(),
        None => "http".to_string(),
    }
}

fn business_logic_provenance_from_candidate(
    candidate: &PentestCandidateRecord,
) -> Option<serde_json::Value> {
    candidate.affected_components.iter().find_map(|component| {
        component.get("template_provenance").cloned().or_else(|| {
            component.get("template_id").map(|id| {
                serde_json::json!({
                    "template_id": id,
                    "template_version": component
                        .get("template_version")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!("unknown")),
                    "title": component
                        .get("template_name")
                        .cloned()
                        .unwrap_or_else(|| id.clone()),
                })
            })
        })
    })
}

fn with_business_logic_provenance(
    mut value: serde_json::Value,
    provenance: serde_json::Value,
) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("business_logic_template".to_string(), provenance);
        value
    } else {
        serde_json::json!({
            "value": value,
            "business_logic_template": provenance,
        })
    }
}

fn write_exploit_audit_jsonl(
    audit_root: &std::path::Path,
    attempt_id: &str,
    audit_log: &pentest_tools::ExploitAuditLog,
) -> Option<String> {
    let entries = audit_log.entries();
    if entries.is_empty() {
        return None;
    }
    if let Err(err) = std::fs::create_dir_all(audit_root) {
        tracing::warn!(error = %err, path = %audit_root.display(), "failed to create exploit audit directory");
        return None;
    }
    let path = audit_root.join(format!("{}.jsonl", safe_artifact_segment(attempt_id)));
    let mut body = Vec::new();
    for entry in entries {
        match serde_json::to_vec(&entry) {
            Ok(mut line) => {
                line.push(b'\n');
                body.extend(line);
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to serialise exploit audit entry");
            }
        }
    }
    match std::fs::write(&path, body) {
        Ok(()) => Some(path.display().to_string()),
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "failed to write exploit audit log");
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReviewSurfaceReport {
    quarantined_findings: u32,
    pending_ai_candidates: u32,
}

impl ReviewSurfaceReport {
    fn total(self) -> u32 {
        self.quarantined_findings + self.pending_ai_candidates
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VerifiedRiskScore {
    score: f64,
    rating: String,
    source: String,
    rationale: String,
}

fn agent_risk_from_candidate(candidate: &PentestCandidateRecord) -> Option<VerifiedRiskScore> {
    agent_risk_from_values(&candidate.affected_components)
        .or_else(|| agent_risk_from_json_str(&candidate.test_plan))
}

fn agent_risk_from_values(values: &[serde_json::Value]) -> Option<VerifiedRiskScore> {
    values.iter().find_map(agent_risk_from_value)
}

fn agent_risk_from_json_str(raw: &str) -> Option<VerifiedRiskScore> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| agent_risk_from_value(&value))
}

fn agent_risk_from_value(value: &serde_json::Value) -> Option<VerifiedRiskScore> {
    let raw_score = json_number_field_recursive(
        value,
        &[
            "risk_score",
            "riskScore",
            "nyctos_risk_score",
            "security_risk_score",
            "cvss",
            "cvss_score",
            "cvssScore",
            "cvss_v3_score",
        ],
    )?;
    let score = round_risk_score(clamp_risk_score(raw_score));
    let rating = json_string_field_recursive(
        value,
        &["risk_rating", "riskRating", "risk_level", "riskLevel", "rating"],
    )
    .map(|rating| canonical_risk_rating(&rating, score))
    .unwrap_or_else(|| risk_rating_for_score(score).to_string());
    let source = json_string_field_recursive(
        value,
        &["risk_score_source", "riskScoreSource", "score_source", "scoreSource", "risk_model"],
    )
    .unwrap_or_else(|| "nyctos-agent".to_string());
    let rationale = json_string_field_recursive(
        value,
        &[
            "risk_score_rationale",
            "riskScoreRationale",
            "risk_rationale",
            "riskRationale",
            "score_rationale",
            "scoreRationale",
            "rationale",
            "explanation",
        ],
    )
    .unwrap_or_else(|| "Agent supplied a risk score in vulnerability evidence.".to_string());
    Some(VerifiedRiskScore {
        score,
        rating,
        source: non_empty_trimmed(&source, "nyctos-agent"),
        rationale: non_empty_trimmed(
            &rationale,
            "Agent supplied a risk score in vulnerability evidence.",
        ),
    })
}

fn fallback_verified_risk_score(
    severity: &str,
    confidence: f64,
    live_verified: bool,
    texts: &[&str],
    components: &[serde_json::Value],
) -> VerifiedRiskScore {
    let confidence = if confidence.is_finite() { confidence.clamp(0.0, 1.0) } else { 0.0 };
    let (base, min_score, max_score) = severity_score_band(severity);
    let mut score = base;
    let mut factors = Vec::new();

    if confidence >= 0.9 {
        score += 0.4;
        factors.push("high confidence".to_string());
    } else if confidence >= 0.75 {
        score += 0.2;
        factors.push("moderate confidence".to_string());
    } else if confidence < 0.5 {
        score -= 0.5;
        factors.push("low confidence".to_string());
    }

    if live_verified {
        score += 0.4;
        factors.push("live verification evidence".to_string());
    }

    let mut evidence_text = texts.join(" ");
    for component in components {
        evidence_text.push(' ');
        evidence_text.push_str(&compact_json(component));
    }
    let lower = evidence_text.to_ascii_lowercase();
    if text_contains_any(
        &lower,
        &["auth", "admin", "tenant", "session", "token", "protected", "privilege"],
    ) {
        score += 0.3;
        factors.push("identity or access-control impact".to_string());
    }
    if text_contains_any(
        &lower,
        &[
            "sql",
            "command",
            "rce",
            "ssrf",
            "secret",
            "password",
            "payment",
            "state-changing",
            "delete",
            "write",
        ],
    ) {
        score += 0.3;
        factors.push("exploitability or sensitive-impact hints".to_string());
    }
    if text_contains_any(
        &lower,
        &["needs review", "unverified", "no deterministic", "not confirmed", "source evidence"],
    ) {
        score -= 0.6;
        factors.push("unconfirmed evidence".to_string());
    }

    let score = round_risk_score(score.clamp(min_score, max_score));
    let factor_summary = if factors.is_empty() {
        "no additional exploitability hints".to_string()
    } else {
        factors.join(", ")
    };
    VerifiedRiskScore {
        score,
        rating: risk_rating_for_score(score).to_string(),
        source: "heuristic".to_string(),
        rationale: format!(
            "Backend fallback heuristic based on severity `{severity}`, confidence {}%, and {factor_summary}.",
            (confidence * 100.0).round() as u8
        ),
    }
}

fn severity_score_band(severity: &str) -> (f64, f64, f64) {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => (9.0, 9.0, 10.0),
        "high" => (7.0, 7.0, 8.9),
        "medium" | "moderate" => (4.0, 4.0, 6.9),
        "low" => (1.0, 1.0, 3.9),
        "info" | "informational" => (0.0, 0.0, 0.9),
        _ => (0.0, 0.0, 3.9),
    }
}

fn round_risk_score(score: f64) -> f64 {
    (clamp_risk_score(score) * 10.0).round() / 10.0
}

fn normalized_json_key(raw: &str) -> String {
    raw.chars().filter(|ch| ch.is_ascii_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn json_number_field_recursive(value: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    let keys = keys.iter().map(|key| normalized_json_key(key)).collect::<Vec<_>>();
    json_number_field_recursive_normalized(value, &keys)
}

fn json_number_field_recursive_normalized(
    value: &serde_json::Value,
    keys: &[String],
) -> Option<f64> {
    match value {
        serde_json::Value::Object(obj) => {
            for (key, value) in obj {
                if keys.iter().any(|target| target == &normalized_json_key(key)) {
                    if let Some(score) = value.as_f64() {
                        return Some(score);
                    }
                    if let Some(text) = value.as_str().and_then(|text| text.parse::<f64>().ok()) {
                        return Some(text);
                    }
                }
            }
            obj.values().find_map(|value| json_number_field_recursive_normalized(value, keys))
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|value| json_number_field_recursive_normalized(value, keys))
        }
        _ => None,
    }
}

fn json_string_field_recursive(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    let keys = keys.iter().map(|key| normalized_json_key(key)).collect::<Vec<_>>();
    json_string_field_recursive_normalized(value, &keys)
}

fn json_string_field_recursive_normalized(
    value: &serde_json::Value,
    keys: &[String],
) -> Option<String> {
    match value {
        serde_json::Value::Object(obj) => {
            for (key, value) in obj {
                if keys.iter().any(|target| target == &normalized_json_key(key)) {
                    if let Some(text) = value.as_str().filter(|text| !text.trim().is_empty()) {
                        return Some(text.to_string());
                    }
                }
            }
            obj.values().find_map(|value| json_string_field_recursive_normalized(value, keys))
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|value| json_string_field_recursive_normalized(value, keys))
        }
        _ => None,
    }
}

fn non_empty_trimmed(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

async fn materialize_review_vulnerabilities(
    store: &Store,
    run_id: &str,
    project_id: &str,
    now_ms: i64,
) -> anyhow::Result<ReviewSurfaceReport> {
    let mut report = ReviewSurfaceReport::default();
    let live_verified_source_ids = store
        .pentest_candidates()
        .list_by_run(run_id)
        .await?
        .into_iter()
        .filter(|candidate| candidate.status == "Verified")
        .flat_map(|candidate| candidate.source_ids)
        .collect::<HashSet<_>>();

    for finding in
        store.findings().list_by_run(run_id).await?.into_iter().filter(|f| f.status == "Quarantine")
    {
        if live_verified_source_ids.contains(&finding.id) {
            continue;
        }
        let vuln = review_vulnerability_from_finding(&finding, project_id, now_ms);
        store.verified_vulnerabilities().upsert(&vuln).await?;
        report.quarantined_findings += 1;
    }

    for candidate in
        store.candidate_findings().list_pending().await?.into_iter().filter(|c| c.run_id == run_id)
    {
        if live_verified_source_ids.contains(&candidate.id) {
            continue;
        }
        let vuln = review_vulnerability_from_ai_candidate(&candidate, project_id, now_ms);
        store.verified_vulnerabilities().upsert(&vuln).await?;
        report.pending_ai_candidates += 1;
    }

    Ok(report)
}

fn review_vulnerability_from_finding(
    finding: &FindingRecord,
    project_id: &str,
    now_ms: i64,
) -> VerifiedVulnerabilityRecord {
    let verdict = exploration_verdict_blob(finding.verdict_blob.as_deref());
    let rationale = verdict
        .as_ref()
        .and_then(|v| json_string_field(v, "rationale"))
        .unwrap_or_else(|| "AI exploration produced a quarantined finding.".to_string());
    let endpoint = verdict.as_ref().and_then(|v| json_string_field(v, "endpoint"));
    let hint = verdict.as_ref().and_then(|v| json_string_field(v, "suggested_payload_hint"));
    let title = format_location_title(&finding.cap, &finding.path, finding.line);
    let affected_components = vec![serde_json::json!({
        "kind": "quarantined_finding",
        "repo": &finding.repo,
        "path": &finding.path,
        "line": finding.line,
        "finding_id": &finding.id,
        "finding_origin": &finding.finding_origin,
    })];
    let risk = verdict.as_ref().and_then(agent_risk_from_value).unwrap_or_else(|| {
        fallback_verified_risk_score(
            &finding.severity,
            0.74,
            false,
            &[&rationale, &finding.cap, &finding.path, "unverified review item"],
            &affected_components,
        )
    });
    VerifiedVulnerabilityRecord {
        id: format!("vuln-review-{}-{}", finding.run_id, finding.id),
        run_id: finding.run_id.clone(),
        project_id: project_id.to_string(),
        title,
        severity: finding.severity.clone(),
        confidence: 0.74,
        risk_score: risk.score,
        risk_rating: risk.rating,
        risk_score_source: risk.source,
        risk_score_rationale: risk.rationale,
        vuln_class: finding.cap.clone(),
        affected_components,
        business_impact: rationale.clone(),
        evidence_summary: format!(
            "Needs review: AI exploration produced source or live evidence, but deterministic verification has not confirmed it yet. {rationale}"
        ),
        repro_steps: review_repro_steps(endpoint.as_deref(), hint.as_deref(), Some(&rationale)),
        remediation: review_remediation(&finding.cap),
        source_candidate_ids: Vec::new(),
        source_signal_ids: Vec::new(),
        verification_attempt_ids: Vec::new(),
        chain_id: finding.chain_id.clone(),
        status: "NeedsReview".to_string(),
        first_seen: now_ms,
        last_seen: now_ms,
    }
}

fn review_vulnerability_from_ai_candidate(
    candidate: &CandidateFindingRecord,
    project_id: &str,
    now_ms: i64,
) -> VerifiedVulnerabilityRecord {
    let title =
        candidate.rule_hint.as_deref().map(human_title_from_rule).unwrap_or_else(|| {
            format_location_title(&candidate.cap, &candidate.path, candidate.line)
        });
    let rationale = candidate
        .rationale
        .clone()
        .unwrap_or_else(|| "AI novel-finding discovery proposed this issue.".to_string());
    let affected_components = vec![serde_json::json!({
        "kind": "pending_ai_candidate",
        "repo": &candidate.repo,
        "path": &candidate.path,
        "line": candidate.line,
        "candidate_id": &candidate.id,
        "rule_hint": &candidate.rule_hint,
    })];
    let risk = fallback_verified_risk_score(
        "High",
        0.68,
        false,
        &[&rationale, &candidate.cap, &candidate.path, "unverified pending AI candidate"],
        &affected_components,
    );
    VerifiedVulnerabilityRecord {
        id: format!("vuln-review-{}-{}", candidate.run_id, candidate.id),
        run_id: candidate.run_id.clone(),
        project_id: project_id.to_string(),
        title,
        severity: "High".to_string(),
        confidence: 0.68,
        risk_score: risk.score,
        risk_rating: risk.rating,
        risk_score_source: risk.source,
        risk_score_rationale: risk.rationale,
        vuln_class: candidate.cap.clone(),
        affected_components,
        business_impact: rationale.clone(),
        evidence_summary: format!(
            "Needs review: AI discovery proposed this candidate, but no deterministic live verification has confirmed it yet. {rationale}"
        ),
        repro_steps: review_repro_steps(
            None,
            candidate.suggested_payload_hint.as_deref(),
            Some(&rationale),
        ),
        remediation: review_remediation(&candidate.cap),
        source_candidate_ids: vec![candidate.id.clone()],
        source_signal_ids: Vec::new(),
        verification_attempt_ids: Vec::new(),
        chain_id: None,
        status: "NeedsReview".to_string(),
        first_seen: now_ms,
        last_seen: now_ms,
    }
}

fn exploration_verdict_blob(raw: Option<&str>) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(raw?).ok()?;
    if value.get("kind").and_then(|v| v.as_str()) == Some("AiExploration") {
        Some(value)
    } else {
        None
    }
}

fn json_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field).and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(str::to_string)
}

fn format_location_title(cap: &str, path: &str, line: Option<i64>) -> String {
    match line {
        Some(line) if line > 0 => format!("{cap} in {path}:{line}"),
        _ => format!("{cap} in {path}"),
    }
}

fn human_title_from_rule(rule: &str) -> String {
    let mut out = String::new();
    for (idx, part) in rule.split(['.', '_', '-']).filter(|p| !p.is_empty()).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        rule.to_string()
    } else {
        out
    }
}

fn review_repro_steps(
    endpoint: Option<&str>,
    hint: Option<&str>,
    rationale: Option<&str>,
) -> String {
    let mut steps = Vec::new();
    if let Some(endpoint) = endpoint.filter(|s| !s.trim().is_empty()) {
        steps.push(format!("Endpoint or surface: {endpoint}"));
    }
    if let Some(hint) = hint.filter(|s| !s.trim().is_empty()) {
        steps.push(format!("Suggested verification hint: {hint}"));
    }
    if let Some(rationale) = rationale.filter(|s| !s.trim().is_empty()) {
        steps.push(format!("Review context: {rationale}"));
    }
    if steps.is_empty() {
        "Review the source location and derive a safe HTTP or browser verification plan."
            .to_string()
    } else {
        steps.join("\n")
    }
}

fn review_remediation(cap: &str) -> String {
    format!(
        "Review the affected component, confirm exploitability, then apply the framework-specific fix for `{cap}` before marking this item verified or dismissed."
    )
}

fn safe_artifact_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches(['.', '_', '-']);
    if trimmed.is_empty() {
        "attempt".to_string()
    } else {
        trimmed.to_string()
    }
}

fn spawn_run_event_log_task(events: EventSink, logs_dir: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = events.subscribe();
        let mut writer = RunEventLogWriter::new(logs_dir);
        let mut active_runs = HashSet::<String>::new();
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "run event-log writer lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            let target_run_ids = event_log_run_ids(&ev, &active_runs);
            for run_id in &target_run_ids {
                if let Err(err) = writer.append(run_id, &ev).await {
                    tracing::warn!(run_id = %run_id, error = %err, "failed to append run event log");
                }
            }

            match &ev {
                AgentEvent::Run { data: RunEvent::RunStarted { run_id, .. } } => {
                    active_runs.insert(run_id.clone());
                }
                AgentEvent::Run { data: RunEvent::RunFinished { run_id, .. } } => {
                    active_runs.remove(run_id);
                    if let Err(err) = writer.finish_run(run_id).await {
                        tracing::warn!(run_id = %run_id, error = %err, "failed to finish run event log");
                    }
                }
                _ => {}
            }
        }
    })
}

fn event_log_run_ids(ev: &AgentEvent, active_runs: &HashSet<String>) -> Vec<String> {
    if let Some(run_id) = event_run_id(ev) {
        return vec![run_id.to_string()];
    }
    active_runs.iter().cloned().collect()
}

fn event_run_id(ev: &AgentEvent) -> Option<&str> {
    match ev {
        AgentEvent::Run { data } => match data {
            RunEvent::Heartbeat { .. } => None,
            RunEvent::RunStarted { run_id, .. }
            | RunEvent::ProjectStarted { run_id, .. }
            | RunEvent::PhaseStarted { run_id, .. }
            | RunEvent::PhaseFinished { run_id, .. }
            | RunEvent::EnvironmentStatus { run_id, .. }
            | RunEvent::AuthSessionStatus { run_id, .. }
            | RunEvent::RepoStarted { run_id, .. }
            | RunEvent::RepoStaticDone { run_id, .. }
            | RunEvent::RepoDynamicDone { run_id, .. }
            | RunEvent::RepoFailed { run_id, .. }
            | RunEvent::RepoIngestFailed { run_id, .. }
            | RunEvent::RepoFinished { run_id, .. }
            | RunEvent::ProjectFinished { run_id, .. }
            | RunEvent::RunFinished { run_id, .. } => Some(run_id.as_str()),
        },
        AgentEvent::Ai { data: AiEvent::BudgetTick { run_id, .. } } => Some(run_id.as_str()),
        AgentEvent::Sandbox { data } => match data {
            SandboxEvent::VerifierStarted { run_id, .. }
            | SandboxEvent::VerifierFinished { run_id, .. } => Some(run_id.as_str()),
        },
        AgentEvent::Ai { .. }
        | AgentEvent::Finding { .. }
        | AgentEvent::Budget { .. }
        | AgentEvent::Quarantine { .. }
        | AgentEvent::Repro { .. } => None,
    }
}

fn vulnerability_from_candidate(
    candidate: &PentestCandidateRecord,
    attempt_id: &str,
    now_ms: i64,
    accepted_review: Option<&LiveEvidenceReviewOutput>,
) -> VerifiedVulnerabilityRecord {
    let source_signal_ids: Vec<String> =
        candidate.source_ids.iter().filter(|id| id.starts_with("sig-")).cloned().collect();
    let evidence_summary = accepted_review
        .map(|review| {
            format!(
                "Live verification and evidence review confirmed the candidate: {}",
                review.rationale
            )
        })
        .unwrap_or_else(|| {
            "Live verification attempt confirmed the candidate against the running local app."
                .to_string()
        });
    let risk = agent_risk_from_candidate(candidate).unwrap_or_else(|| {
        fallback_verified_risk_score(
            &candidate.severity_guess,
            0.95,
            true,
            &[&evidence_summary, &candidate.hypothesis, &candidate.test_plan],
            &candidate.affected_components,
        )
    });
    VerifiedVulnerabilityRecord {
        id: format!("vuln-{}", candidate.id.trim_start_matches("pc-")),
        run_id: candidate.run_id.clone(),
        project_id: candidate.project_id.clone(),
        title: candidate.title.clone(),
        severity: candidate.severity_guess.clone(),
        confidence: 0.95,
        risk_score: risk.score,
        risk_rating: risk.rating,
        risk_score_source: risk.source,
        risk_score_rationale: risk.rationale,
        vuln_class: candidate.vuln_class.clone(),
        affected_components: candidate.affected_components.clone(),
        business_impact: candidate.hypothesis.clone(),
        evidence_summary,
        repro_steps: candidate.test_plan.clone(),
        remediation: "Review the affected component and apply the framework-specific fix for this vulnerability class."
            .to_string(),
        source_candidate_ids: vec![candidate.id.clone()],
        source_signal_ids,
        verification_attempt_ids: vec![attempt_id.to_string()],
        chain_id: None,
        status: "Open".to_string(),
        first_seen: now_ms,
        last_seen: now_ms,
    }
}

fn ai_runtime_label(runtime: nyctos_core::AiRuntime) -> &'static str {
    match runtime {
        nyctos_core::AiRuntime::None => "none",
        nyctos_core::AiRuntime::Anthropic => "anthropic",
        nyctos_core::AiRuntime::LocalLlm => "local-llm",
        nyctos_core::AiRuntime::ClaudeCode => "claude-code",
        nyctos_core::AiRuntime::Codex => "codex",
    }
}

fn emit_run_started(
    events: &EventSink,
    run_id: &str,
    project_id: &str,
    project_name: &str,
    repos: Vec<String>,
    started_at_ms: i64,
) {
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::RunStarted {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            repos,
            started_at_ms,
        },
    });
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::ProjectStarted {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            project_name: project_name.to_string(),
            started_at_ms,
        },
    });
}

fn emit_phase(
    events: &EventSink,
    run_id: &str,
    project_id: &str,
    phase: &str,
    started: bool,
    message: Option<String>,
) {
    let data = if started {
        RunEvent::PhaseStarted {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            phase: phase.to_string(),
            started_at_ms: now_epoch_ms(),
        }
    } else {
        RunEvent::PhaseFinished {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            phase: phase.to_string(),
            status: if message.is_some() { "Finished".to_string() } else { "Finished".to_string() },
            message,
            finished_at_ms: now_epoch_ms(),
        }
    };
    let _ = events.send(AgentEvent::Run { data });
}

fn emit_auth_session_status(
    events: &EventSink,
    run_id: &str,
    project_id: &str,
    role: &str,
    status: &str,
    acquired_by: &str,
    message: Option<&str>,
) {
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::AuthSessionStatus {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            role: role.to_string(),
            status: status.to_string(),
            acquired_by: acquired_by.to_string(),
            message: message.map(str::to_string),
            ts_ms: now_epoch_ms(),
        },
    });
}

fn proposed_plan_for_review(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
) -> serde_json::Value {
    match pentest_tools::normalise_live_test_plan(&candidate.test_plan, target_urls) {
        Ok(Some(plan)) => plan,
        Ok(None) => serde_json::json!({ "raw": candidate.test_plan, "normalised": null }),
        Err(err) => serde_json::json!({ "raw": candidate.test_plan, "normalise_error": err }),
    }
}

fn review_confirmed_live_evidence(
    candidate: &PentestCandidateRecord,
    request: &serde_json::Value,
    response: &serde_json::Value,
    oracle: &serde_json::Value,
) -> LiveEvidenceReviewOutput {
    if !oracle.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        return blocked_evidence_review(
            "The deterministic oracle did not report success.",
            vec!["hard verifier result was not confirming".to_string()],
        );
    }

    let positive = positive_oracle_evidence(oracle);
    if positive.is_empty() {
        return blocked_evidence_review(
            "The oracle is status-only and has no exploit-specific live marker.",
            vec!["missing body/header/reflection/sensitive-data evidence".to_string()],
        );
    }

    if let Some(status) = confirmed_error_status(response, oracle) {
        return blocked_evidence_review(
            format!("The confirming evidence came from HTTP {status}, which is an error or blocked page."),
            vec!["unauthenticated or generic error response treated as success".to_string()],
        );
    }

    if static_source_evidence(request, &positive) {
        return blocked_evidence_review(
            "The evidence only proves a static source asset or served bundle contains the marker.",
            vec!["static source hit is not live exploit evidence".to_string()],
        );
    }

    if let Some(marker) = missing_body_marker(response, oracle) {
        return blocked_evidence_review(
            format!("The recorded response does not contain the required live reflection marker `{marker}`."),
            vec!["missing reflection in captured response".to_string()],
        );
    }

    LiveEvidenceReviewOutput {
        decision: LiveEvidenceReviewDecision::Accept,
        confidence: candidate.confidence.max(0.75).min(0.95),
        rationale: "Deterministic oracle found positive, vulnerability-specific live evidence."
            .to_string(),
        evidence_strengths: positive,
        evidence_gaps: Vec::new(),
        required_followup: Vec::new(),
    }
}

fn blocked_evidence_review(
    rationale: impl Into<String>,
    evidence_gaps: Vec<String>,
) -> LiveEvidenceReviewOutput {
    LiveEvidenceReviewOutput {
        decision: LiveEvidenceReviewDecision::Block,
        confidence: 0.95,
        rationale: rationale.into(),
        evidence_strengths: Vec::new(),
        evidence_gaps,
        required_followup: vec![
            "collect live evidence tied to attacker-controlled input or sensitive data".to_string(),
        ],
    }
}

fn positive_oracle_evidence(oracle: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for marker in json_string_or_array(oracle.get("body_contains")) {
        out.push(format!("body_contains `{}`", marker));
    }
    if let Some(obj) = oracle.get("header_contains").and_then(|v| v.as_object()) {
        for (name, value) in obj {
            if let Some(marker) = value.as_str().filter(|s| !s.trim().is_empty()) {
                out.push(format!("header `{name}` contains `{marker}`"));
            }
        }
    }
    for marker in json_string_or_array(oracle.get("markers_found")) {
        out.push(format!("sensitive marker `{}`", marker));
    }
    for key in [
        "text_contains",
        "html_contains",
        "selector_exists",
        "selector_text_contains",
        "url_contains",
        "title_contains",
        "console_contains",
        "alert_contains",
        "dialog_contains",
    ] {
        if let Some(value) = oracle.get(key).filter(|v| !v.is_null()) {
            out.push(format!("{key} {}", compact_json(value)));
        }
    }
    out
}

fn confirmed_error_status(response: &serde_json::Value, oracle: &serde_json::Value) -> Option<u16> {
    let statuses = response_statuses(response);
    if statuses.is_empty() {
        return None;
    }
    let target_status = oracle
        .get("step")
        .and_then(|v| v.as_u64())
        .and_then(|idx| statuses.get(idx as usize).copied())
        .or_else(|| statuses.last().copied());
    target_status.filter(|s| matches!(*s, 401 | 403 | 404) || *s >= 500)
}

fn response_statuses(value: &serde_json::Value) -> Vec<u16> {
    let mut out = Vec::new();
    if let Some(status) = value
        .get("response")
        .and_then(|v| v.get("status"))
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
    {
        out.push(status);
    }
    if let Some(steps) = value.get("steps").and_then(|v| v.as_array()) {
        for step in steps {
            if let Some(status) =
                step.get("status").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok())
            {
                out.push(status);
            }
        }
    }
    out
}

fn static_source_evidence(request: &serde_json::Value, positive_markers: &[String]) -> bool {
    request_urls(request).iter().any(|url| url_points_to_static_source_asset(url))
        && positive_markers.iter().any(|marker| marker_looks_like_source_code(marker))
}

fn request_urls(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(url) = value
        .get("request")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        out.push(url.to_string());
    }
    if let Some(steps) = value.get("steps").and_then(|v| v.as_array()) {
        for step in steps {
            if let Some(url) =
                step.get("url").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())
            {
                out.push(url.to_string());
            }
        }
    }
    if let Some(url) = value
        .get("plan")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        out.push(url.to_string());
    }
    out
}

fn url_points_to_static_source_asset(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    let path = url.path().to_ascii_lowercase();
    let Some((_, ext)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(ext, "js" | "mjs" | "cjs" | "map" | "ts" | "tsx" | "jsx" | "css" | "scss" | "sass")
}

fn marker_looks_like_source_code(marker: &str) -> bool {
    let marker = marker.to_ascii_lowercase();
    [
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "escapehtml",
        "dompurify",
        "addeventlistener",
        "queryselector",
        "document.",
        "window.",
        "function ",
        "const ",
        "let ",
        "var ",
        ".map(",
        ".join(",
        "=>",
        "${",
        "onclick=",
        "class=",
    ]
    .iter()
    .any(|needle| marker.contains(needle))
}

fn missing_body_marker(response: &serde_json::Value, oracle: &serde_json::Value) -> Option<String> {
    let markers = json_string_or_array(oracle.get("body_contains"));
    if markers.is_empty() {
        return None;
    }
    let previews = response_body_previews(response);
    if previews.is_empty() {
        return None;
    }
    for marker in markers {
        let seen = previews.iter().any(|preview| preview.body.contains(&marker));
        let complete = previews.iter().any(|preview| preview.complete);
        if !seen && complete {
            return Some(marker);
        }
    }
    None
}

struct BodyPreview {
    body: String,
    complete: bool,
}

fn response_body_previews(value: &serde_json::Value) -> Vec<BodyPreview> {
    let mut out = Vec::new();
    if let Some(response) = value.get("response") {
        push_body_preview(response, &mut out);
    }
    if let Some(steps) = value.get("steps").and_then(|v| v.as_array()) {
        for step in steps {
            push_body_preview(step, &mut out);
        }
    }
    out
}

fn push_body_preview(value: &serde_json::Value, out: &mut Vec<BodyPreview>) {
    let Some(body) = value.get("body_preview").and_then(|v| v.as_str()) else {
        return;
    };
    let body_len = value.get("body_len").and_then(|v| v.as_u64()).unwrap_or(body.len() as u64);
    out.push(BodyPreview { body: body.to_string(), complete: body_len <= body.len() as u64 });
}

fn json_string_or_array(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "unknown".to_string())
}

fn oracle_with_evidence_review(
    oracle: serde_json::Value,
    deterministic_review: &LiveEvidenceReviewOutput,
    ai_review: Option<&LiveEvidenceReviewOutput>,
    reviewer_error: Option<&str>,
    final_review: &LiveEvidenceReviewOutput,
) -> serde_json::Value {
    let review = serde_json::json!({
        "kind": "LiveEvidenceReview",
        "final_decision": final_review.decision.as_str(),
        "deterministic": deterministic_review,
        "ai": ai_review,
        "ai_error": reviewer_error,
    });
    match oracle {
        serde_json::Value::Object(mut obj) => {
            obj.insert("evidence_review".to_string(), review);
            serde_json::Value::Object(obj)
        }
        other => serde_json::json!({
            "oracle": other,
            "evidence_review": review,
        }),
    }
}

async fn finalise_and_emit_run(
    store: &Store,
    events: &EventSink,
    run_id: &str,
    project_id: &str,
    started_at_ms: i64,
    wall_clock_ms: i64,
    status: &str,
    counts: RunCounts,
) -> anyhow::Result<(i64, i64)> {
    let (finished_at, wall) =
        finalise_run(store, run_id, started_at_ms, wall_clock_ms, status).await?;
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::ProjectFinished {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            finished_at_ms: finished_at,
        },
    });
    let _ = events.send(AgentEvent::Run {
        data: RunEvent::RunFinished {
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            finished_at_ms: finished_at,
            wall_clock_ms: wall,
            succeeded: counts.succeeded,
            inconclusive: counts.inconclusive,
            failed: counts.failed,
        },
    });
    Ok((finished_at, wall))
}

async fn finalise_run(
    store: &Store,
    run_id: &str,
    started_at_ms: i64,
    wall_clock_ms: i64,
    status: &str,
) -> anyhow::Result<(i64, i64)> {
    let finished_at = now_epoch_ms();
    let wall = if wall_clock_ms == 0 { finished_at - started_at_ms } else { wall_clock_ms };
    store.runs().finish(run_id, finished_at, status, wall).await?;
    Ok((finished_at, wall))
}

/// Resolve the project rows + repos a scan should walk.
///
/// TOML projects remain supported for CLI/config-driven installs, but
/// the daemon is also local-server-first: projects and repos created
/// through the web UI live in the state DB and must be scannable even
/// when they do not appear in `nyctos.toml`.
async fn select_scan_targets(
    store: &Store,
    config: &Config,
    requested_projects: &[String],
    requested_repos: &[String],
) -> anyhow::Result<Vec<(Project, Vec<Repo>)>> {
    let wants_project =
        |name: &str| requested_projects.is_empty() || requested_projects.iter().any(|n| n == name);
    let wants_repo =
        |name: &str| requested_repos.is_empty() || requested_repos.iter().any(|n| n == name);

    let mut out: Vec<(Project, Vec<Repo>)> = Vec::new();
    let mut matched_projects: HashSet<String> = HashSet::new();
    let mut seen_repos: HashSet<String> = HashSet::new();
    let mut toml_project_names: HashSet<String> = HashSet::new();

    for project_cfg in config.projects.iter().filter(|p| wants_project(&p.name)) {
        toml_project_names.insert(project_cfg.name.clone());
        matched_projects.insert(project_cfg.name.clone());
        let rec = sync_project_row_from_config(store, project_cfg).await?;
        let project = project_from_record(rec);
        let project_id = project.id.clone();
        let mut repos: Vec<Repo> = Vec::new();
        let mut toml_repo_names: HashSet<String> = HashSet::new();
        for r in &project_cfg.repos {
            toml_repo_names.insert(r.name.clone());
            if !wants_repo(&r.name) {
                continue;
            }
            seen_repos.insert(r.name.clone());
            if !r.enabled {
                anyhow::bail!("repo `{}` is declared but `enabled = false`", r.name);
            }
            repos.push(repo_from_config(r, project_id.clone())?);
        }

        for row in store.repos().list_by_project(project.id.as_str()).await? {
            if toml_repo_names.contains(&row.name) || !wants_repo(&row.name) {
                continue;
            }
            seen_repos.insert(row.name.clone());
            repos.push(repo_from_record(&row)?);
        }

        if repos.is_empty() {
            continue;
        }
        out.push((project, repos));
    }

    for rec in store.projects().list().await? {
        if toml_project_names.contains(&rec.name) || !wants_project(&rec.name) {
            continue;
        }
        matched_projects.insert(rec.name.clone());
        let project = project_from_record(rec);
        let mut repos: Vec<Repo> = Vec::new();
        for row in store.repos().list_by_project(project.id.as_str()).await? {
            if !wants_repo(&row.name) {
                continue;
            }
            seen_repos.insert(row.name.clone());
            repos.push(repo_from_record(&row)?);
        }
        if repos.is_empty() {
            continue;
        }
        out.push((project, repos));
    }

    for name in requested_projects {
        if !matched_projects.contains(name) {
            anyhow::bail!("project `{name}` not declared in nyctos.toml or local project store");
        }
    }
    for name in requested_repos {
        if !seen_repos.contains(name) {
            anyhow::bail!(
                "repo `{name}` not declared under the selected project(s) in nyctos.toml or local project store"
            );
        }
    }

    Ok(out)
}

fn repo_from_record(rec: &RepoRecord) -> anyhow::Result<Repo> {
    let source = match rec.source_kind.as_str() {
        "git" | "github" | "gitlab" => RepoSource::Git {
            url: rec.source_url_or_path.clone(),
            branch: rec.branch.clone(),
            auth: rec.auth_ref.as_deref().map(nyctos_core::repo::parse_git_auth).transpose()?,
        },
        "local" | "local-path" => {
            RepoSource::LocalPath { path: PathBuf::from(&rec.source_url_or_path) }
        }
        other => anyhow::bail!("repo `{}` has unknown source_kind `{other}`", rec.name),
    };
    Ok(Repo {
        name: rec.name.clone(),
        source,
        i_own_this: rec.i_own_this,
        project_id: ProjectId::new(rec.project_id.clone()),
    })
}

/// Lookup-or-create a project row keyed by `name`, then sync the
/// config-authored launch/runtime profile into SQLite so the shared
/// scan path can use the same orchestration model as API-created
/// projects.
async fn sync_project_row_from_config(
    store: &Store,
    cfg: &ProjectConfig,
) -> anyhow::Result<ProjectRecord> {
    let now = now_epoch_ms();
    let env_config_json = cfg.env_config.as_ref().map(serde_json::to_string).transpose()?;
    let runtime_profile_json =
        cfg.runtime_profile.as_ref().map(serde_json::to_string).transpose()?;
    let rec = if let Some(existing) = store.projects().get_by_name(&cfg.name).await? {
        let patch = nyctos_core::store::ProjectPatch {
            description: match &cfg.description {
                Some(value) => nyctos_core::store::ProjectPatchOption::Set(Some(value.clone())),
                None => nyctos_core::store::ProjectPatchOption::Unset,
            },
            target_base_url: match &cfg.target_base_url {
                Some(value) => nyctos_core::store::ProjectPatchOption::Set(Some(value.clone())),
                None => nyctos_core::store::ProjectPatchOption::Unset,
            },
            env_config_json: match env_config_json {
                Some(value) => nyctos_core::store::ProjectPatchOption::Set(Some(value)),
                None => nyctos_core::store::ProjectPatchOption::Unset,
            },
            runtime_profile_json: match runtime_profile_json {
                Some(value) => nyctos_core::store::ProjectPatchOption::Set(Some(value)),
                None => nyctos_core::store::ProjectPatchOption::Unset,
            },
            updated_at: now,
        };
        store.projects().update(&existing.id, &patch).await?;
        store
            .projects()
            .get(&existing.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("project `{}` vanished after update", cfg.name))?
    } else {
        let id = format!("proj-{}", project_id_slug(&cfg.name, now));
        store
            .projects()
            .create_with_runtime_profile(
                &id,
                &cfg.name,
                cfg.description.as_deref(),
                cfg.target_base_url.as_deref(),
                env_config_json.as_deref(),
                runtime_profile_json.as_deref(),
                now,
            )
            .await?
    };

    let default_profile = store.launch_profiles().get_default(&rec.id).await?;
    if let Some(input) = launch_profile_input_from_config(cfg, default_profile.is_some()) {
        store.launch_profiles().upsert_default(&rec.id, &input, now_epoch_ms()).await?;
    }
    store
        .projects()
        .get(&rec.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("project `{}` vanished after launch sync", cfg.name))
}

fn launch_profile_input_from_config(
    cfg: &ProjectConfig,
    default_profile_exists: bool,
) -> Option<ProjectLaunchProfileInput> {
    if let Some(launch) = &cfg.launch {
        let mut input = launch.to_profile_input(cfg.target_base_url.as_deref());
        if launch.mode.as_deref() == Some("auto") {
            apply_auto_launch_detection(cfg, &mut input);
        }
        return Some(input);
    }
    if let Some(profile) = &cfg.runtime_profile {
        return Some(launch_profile_input_from_runtime_profile(
            profile,
            cfg.target_base_url.as_deref(),
        ));
    }
    if default_profile_exists || cfg.target_base_url.is_none() {
        return None;
    }
    let mut input = ProjectLaunchProfileInput {
        name: Some("local dev".to_string()),
        mode: Some("already-running".to_string()),
        build_steps: Vec::new(),
        start_steps: Vec::new(),
        seed_steps: Vec::new(),
        reset_steps: Vec::new(),
        login_steps: Vec::new(),
        stop_steps: Vec::new(),
        health_checks: cfg
            .target_base_url
            .iter()
            .map(|url| LaunchHealthCheck {
                kind: "http".to_string(),
                url: Some(url.clone()),
                host: None,
                port: None,
                command: None,
                timeout_seconds: Some(60),
            })
            .collect(),
        target_urls: cfg.target_base_url.iter().cloned().collect(),
        env_refs: Vec::new(),
        working_dirs: Vec::new(),
    };
    apply_auto_launch_detection(cfg, &mut input);
    Some(input)
}

fn apply_auto_launch_detection(cfg: &ProjectConfig, input: &mut ProjectLaunchProfileInput) {
    if input.mode.as_deref() == Some("auto") && !input.start_steps.is_empty() {
        input.mode = Some("custom-commands".to_string());
        return;
    }
    if input.mode.as_deref() == Some("docker-compose") || !input.start_steps.is_empty() {
        return;
    }
    if project_has_compose_file(cfg) {
        input.mode = Some("docker-compose".to_string());
        return;
    }
    if let Some(step) = detect_start_step(cfg) {
        input.mode = Some("custom-commands".to_string());
        input.start_steps.push(step);
    } else if input.mode.as_deref() == Some("auto") || input.mode.is_none() {
        input.mode = Some("already-running".to_string());
    }
}

fn project_has_compose_file(cfg: &ProjectConfig) -> bool {
    cfg.repos.iter().any(|repo| match &repo.source {
        RepoSourceConfig::LocalPath { path } => {
            ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
                .iter()
                .any(|name| path.join(name).is_file())
        }
        RepoSourceConfig::Git { .. } => false,
    })
}

fn detect_start_step(cfg: &ProjectConfig) -> Option<LaunchStep> {
    cfg.repos.iter().find_map(|repo| {
        let RepoSourceConfig::LocalPath { path } = &repo.source else {
            return None;
        };
        detect_package_start_command(path).or_else(|| detect_cargo_start_command(path)).map(
            |command| LaunchStep {
                command,
                repo_id: None,
                repo_name: Some(repo.name.clone()),
                working_directory: None,
                timeout_seconds: None,
            },
        )
    })
}

fn detect_cargo_start_command(path: &std::path::Path) -> Option<String> {
    path.join("Cargo.toml").is_file().then(|| "cargo run".to_string())
}

fn detect_package_start_command(path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(path.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let scripts = json.get("scripts")?.as_object()?;
    let script = if scripts.contains_key("dev") {
        "dev"
    } else if scripts.contains_key("start") {
        "start"
    } else {
        return None;
    };
    let runner = if path.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else if path.join("yarn.lock").is_file() {
        "yarn"
    } else if path.join("bun.lockb").is_file() || path.join("bun.lock").is_file() {
        "bun"
    } else {
        "npm"
    };
    let command = match (runner, script) {
        ("npm", "start") => "npm start".to_string(),
        ("npm", other) => format!("npm run {other}"),
        ("yarn", "start") => "yarn start".to_string(),
        ("yarn", other) => format!("yarn {other}"),
        ("pnpm", "start") => "pnpm start".to_string(),
        ("pnpm", other) => format!("pnpm {other}"),
        ("bun", "start") => "bun start".to_string(),
        ("bun", other) => format!("bun run {other}"),
        _ => return None,
    };
    Some(command)
}

fn launch_profile_input_from_runtime_profile(
    profile: &ProjectRuntimeProfile,
    fallback_target: Option<&str>,
) -> ProjectLaunchProfileInput {
    let build_steps =
        profile.build_commands.iter().map(runtime_command_to_launch_step).collect::<Vec<_>>();
    let start_steps =
        profile.start_commands.iter().map(runtime_command_to_launch_step).collect::<Vec<_>>();
    let target = profile.target_base_url.as_deref().or(fallback_target).map(str::to_string);
    let mut health_checks = Vec::new();
    if let Some(url) = profile.health_check_url.as_ref().filter(|url| !url.trim().is_empty()) {
        health_checks.push(LaunchHealthCheck {
            kind: "http".to_string(),
            url: Some(url.clone()),
            host: None,
            port: None,
            command: None,
            timeout_seconds: profile.timeout_seconds,
        });
    }
    if let Some(cmd) = &profile.health_check_command {
        health_checks.push(LaunchHealthCheck {
            kind: "command".to_string(),
            url: None,
            host: None,
            port: None,
            command: Some(runtime_command_to_launch_step(cmd)),
            timeout_seconds: cmd.timeout_seconds.or(profile.timeout_seconds),
        });
    }
    let mode = if build_steps.is_empty() && start_steps.is_empty() {
        "already-running"
    } else {
        "custom-commands"
    };
    ProjectLaunchProfileInput {
        name: Some("local dev".to_string()),
        mode: Some(mode.to_string()),
        build_steps,
        start_steps,
        seed_steps: Vec::new(),
        reset_steps: Vec::new(),
        login_steps: Vec::new(),
        stop_steps: Vec::new(),
        health_checks,
        target_urls: target.into_iter().collect(),
        env_refs: Vec::new(),
        working_dirs: Vec::new(),
    }
}

fn runtime_command_to_launch_step(cmd: &ProjectRuntimeCommand) -> LaunchStep {
    LaunchStep {
        command: cmd.command.clone(),
        repo_id: None,
        repo_name: cmd.repo_name.clone(),
        working_directory: cmd.working_directory.clone(),
        timeout_seconds: cmd.timeout_seconds,
    }
}

/// Slugify `name` and append a hex `now_ms` so re-running with the same
/// project name still yields a recognisable id. Matches the
/// `nyctos-api` helper of the same shape so a CLI-created row and an
/// API-created row converge on the same prefix.
fn project_id_slug(name: &str, now_ms: i64) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let trimmed: String = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(32)
        .collect();
    format!("{trimmed}-{now_ms:x}")
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
/// Honours `$GITHUB_REF` of the shape `refs/pull/<N>/{merge,head}`
/// (the standard `pull_request` trigger sets it) and falls back to
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

async fn project_command(state_dir: &StateDir, action: ProjectAction) -> anyhow::Result<ExitCode> {
    let store = Store::open(state_dir.root()).await?;
    let result = match action {
        ProjectAction::Create { name, description, target_base_url } => {
            project_create(&store, &name, description.as_deref(), target_base_url.as_deref()).await
        }
        ProjectAction::List => project_list(&store).await,
        ProjectAction::Show { name } => project_show(&store, &name).await,
        ProjectAction::Delete { name } => project_delete(&store, &name).await,
        ProjectAction::AddRepo { project, name, path, git_url, branch, auth, i_own_this } => {
            project_add_repo(
                &store,
                &project,
                &name,
                path.as_deref(),
                git_url.as_deref(),
                branch.as_deref(),
                auth.as_deref(),
                i_own_this,
            )
            .await
        }
    };
    store.close().await;
    result
}

async fn project_create(
    store: &Store,
    name: &str,
    description: Option<&str>,
    target_base_url: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        eprintln!("project create: name must not be empty");
        return Ok(ExitCode::from(2));
    }
    if store.projects().get_by_name(trimmed).await?.is_some() {
        eprintln!("project create: `{trimmed}` already exists");
        return Ok(ExitCode::from(1));
    }
    let now = now_epoch_ms();
    let id = format!("proj-{}", project_id_slug(trimmed, now));
    let rec =
        store.projects().create(&id, trimmed, description, target_base_url, None, now).await?;
    println!("created project {} (id: {})", rec.name, rec.id);
    Ok(ExitCode::SUCCESS)
}

async fn project_list(store: &Store) -> anyhow::Result<ExitCode> {
    let rows = store.projects().list().await?;
    if rows.is_empty() {
        println!("projects: none");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "name                             id                                       target_base_url"
    );
    for p in &rows {
        println!(
            "{:<32} {:<40} {}",
            truncate_for_column(&p.name, 32),
            truncate_for_column(&p.id, 40),
            p.target_base_url.as_deref().unwrap_or("-"),
        );
    }
    Ok(ExitCode::SUCCESS)
}

async fn project_show(store: &Store, name: &str) -> anyhow::Result<ExitCode> {
    let Some(rec) = store.projects().get_by_name(name).await? else {
        eprintln!("project show: `{name}` not found");
        return Ok(ExitCode::from(1));
    };
    println!("name:            {}", rec.name);
    println!("id:              {}", rec.id);
    println!("description:     {}", rec.description.as_deref().unwrap_or("-"));
    println!("target_base_url: {}", rec.target_base_url.as_deref().unwrap_or("-"));
    let repos = store.repos().list_by_project(&rec.id).await?;
    if repos.is_empty() {
        println!("repos:           (none)");
        return Ok(ExitCode::SUCCESS);
    }
    println!("repos:");
    for r in &repos {
        println!("  - {} [{}] {}", r.name, r.source_kind, r.source_url_or_path,);
    }
    Ok(ExitCode::SUCCESS)
}

async fn project_delete(store: &Store, name: &str) -> anyhow::Result<ExitCode> {
    let Some(rec) = store.projects().get_by_name(name).await? else {
        eprintln!("project delete: `{name}` not found");
        return Ok(ExitCode::from(1));
    };
    let affected = store.projects().delete(&rec.id).await?;
    if affected == 0 {
        eprintln!("project delete: `{name}` vanished before delete");
        return Ok(ExitCode::from(1));
    }
    println!("deleted project {} (repos cascaded)", rec.name);
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
async fn project_add_repo(
    store: &Store,
    project_name: &str,
    repo_name: &str,
    path: Option<&std::path::Path>,
    git_url: Option<&str>,
    branch: Option<&str>,
    auth: Option<&str>,
    i_own_this: bool,
) -> anyhow::Result<ExitCode> {
    if !i_own_this {
        eprintln!(
            "project add-repo: --i-own-this is required before the daemon will accept a repo"
        );
        return Ok(ExitCode::from(2));
    }
    let (source_kind, source_value) = match (path, git_url) {
        (Some(p), None) => ("local-path", p.display().to_string()),
        (None, Some(url)) => ("git", url.to_string()),
        (None, None) => {
            eprintln!("project add-repo: provide either --path or --git-url");
            return Ok(ExitCode::from(2));
        }
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
    };
    let Some(project) = store.projects().get_by_name(project_name).await? else {
        eprintln!("project add-repo: project `{project_name}` not found");
        return Ok(ExitCode::from(1));
    };
    let existing = store.repos().get_by_project_and_name(&project.id, repo_name).await?;
    let now = now_epoch_ms();
    let rec = RepoRecord {
        id: existing.as_ref().map(|r| r.id.clone()).unwrap_or_else(|| {
            format!("repo-{}", project_id_slug(&format!("{}-{repo_name}", project.id), now))
        }),
        name: repo_name.to_string(),
        project_id: project.id.clone(),
        source_kind: source_kind.to_string(),
        source_url_or_path: source_value,
        branch: branch.map(str::to_string),
        auth_ref: auth.map(str::to_string),
        i_own_this,
        last_scan_run_id: existing.as_ref().and_then(|r| r.last_scan_run_id.clone()),
        last_scan_finished_at: None,
        created_at: existing.as_ref().map(|r| r.created_at).unwrap_or(now),
        updated_at: now,
    };
    store.repos().upsert(&rec).await?;
    println!("attached repo {} to project {}", rec.name, project.name);
    Ok(ExitCode::SUCCESS)
}

async fn doctor(
    state_dir: &StateDir,
    config_path: &std::path::Path,
    log_cfg: &LogConfig,
    config: &Config,
) -> anyhow::Result<ExitCode> {
    println!("state dir OK at {}", state_dir.root().display());
    println!("logs -> {}", nyctos_core::json_log_path(&log_cfg.log_dir).display());
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

    match nyctos_ai::detect_claude_binary().await {
        Ok(bin) => println!("claude-code: available v{} at {}", bin.version, bin.path.display()),
        Err(err) => println!("claude-code: unavailable ({err})"),
    }

    report_sandbox_backends(config);
    report_sandbox_shim();
    report_scheduler(config);
    report_webhook(config);
    report_run(config);
    report_ai(config);

    Ok(nyx_code)
}

fn report_ai(config: &Config) {
    let soft_cap = config.ai.exploration_soft_cap_usd_micros_resolved(
        nyctos_ai::DEFAULT_EXPLORATION_SOFT_CAP_USD_MICROS,
    );
    let run_cap = config
        .ai
        .exploration_run_cap_usd_micros_resolved(nyctos_ai::DEFAULT_EXPLORATION_RUN_CAP_USD_MICROS);
    let soft_origin =
        if config.ai.exploration_soft_cap_usd_micros.is_some() { "configured" } else { "default" };
    let run_origin =
        if config.ai.exploration_run_cap_usd_micros.is_some() { "configured" } else { "default" };
    println!(
        "ai exploration caps: ${:.2} soft [{}], ${:.2} run [{}]",
        soft_cap as f64 / 1_000_000.0,
        soft_origin,
        run_cap as f64 / 1_000_000.0,
        run_origin,
    );
}

fn report_run(config: &Config) {
    if config.run.replay_stable_check {
        println!(
            "verifier: replay_stable_check enabled (each (vuln, benign) pair re-executes; ~2x cost per verify)"
        );
    } else {
        println!(
            "verifier: replay_stable_check disabled (default; set [run].replay_stable_check = true to enable)"
        );
    }
    println!(
        "exploit mode: {} (state-changing probes {}, dry-run {}, cap {} request/action(s), rate {}/s, reset hook {})",
        if config.run.exploit_mode_enabled { "enabled" } else { "disabled" },
        if config.run.state_changing_live_probes_allowed() { "allowed" } else { "blocked" },
        if config.run.exploit_dry_run { "enabled" } else { "disabled" },
        config.run.exploit_request_cap_resolved(),
        config.run.exploit_requests_per_second_resolved(),
        if config.run.exploit_reset_after_state_changing { "enabled" } else { "disabled" },
    );
}

fn report_scheduler(config: &Config) {
    if config.schedules.is_empty() {
        println!("scheduler: no [[schedule]] entries configured");
        return;
    }
    // The trigger is irrelevant for a parse-only probe; build a sink
    // that refuses any actual call so a doctor run cannot fire a scan
    // by accident if the scheduler's parse path ever starts touching
    // the trigger eagerly.
    let probe_trigger: Arc<dyn ScanTrigger> = Arc::new(DoctorScanTrigger);
    match scheduler::Scheduler::from_config(&config.schedules, probe_trigger) {
        Ok(_) => println!(
            "scheduler: {} entr{} parsed cleanly (in-process; runs only under `serve`)",
            config.schedules.len(),
            if config.schedules.len() == 1 { "y" } else { "ies" }
        ),
        Err(err) => println!("scheduler FAIL: {err}"),
    }
}

fn report_webhook(config: &Config) {
    let Some(spec) = config.triggers.webhook_secret_ref.as_deref() else {
        println!("webhook: disabled (set [triggers].webhook_secret_ref to enable)");
        return;
    };
    let resolver = EnvSecretResolver { spec: Some(spec.to_string()) };
    match WebhookSecretResolver::resolve(&resolver) {
        Some(secret) => {
            println!("webhook: secret resolved from `{spec}` ({} bytes)", secret.len());
        }
        None => println!(
            "webhook FAIL: `{spec}` did not resolve to a non-empty secret (check env var or literal)"
        ),
    }
    let max_concurrent =
        config.triggers.webhook_max_concurrent_resolved(nyctos_api::DEFAULT_WEBHOOK_MAX_CONCURRENT);
    let rate_per_minute = config
        .triggers
        .webhook_rate_limit_per_minute_resolved(nyctos_api::DEFAULT_WEBHOOK_RATE_LIMIT_PER_MINUTE);
    let max_origin =
        if config.triggers.webhook_max_concurrent.is_some() { "configured" } else { "default" };
    let rate_origin = if config.triggers.webhook_rate_limit_per_minute.is_some() {
        "configured"
    } else {
        "default"
    };
    println!(
        "webhook caps: {max_concurrent} simultaneous [{max_origin}], {rate_per_minute}/min per IP [{rate_origin}]"
    );
}

struct DoctorScanTrigger;

impl ScanTrigger for DoctorScanTrigger {
    fn trigger<'a>(
        &'a self,
        _source: ScanTriggerSource,
        _project_id: Option<String>,
        _repo: Option<String>,
        _run_overrides: Option<ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            Err(ScanTriggerError::Internal("doctor probe must not fire a scan".to_string()))
        })
    }
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
    let chain_cap = config.performance.chain_lane_concurrency_resolved();
    let fast_cap = config.performance.fast_lane_concurrency_resolved();
    let chain_origin =
        if config.performance.chain_lane_concurrency.is_some() { "configured" } else { "default" };
    let fast_origin =
        if config.performance.fast_lane_concurrency.is_some() { "configured" } else { "default" };
    println!(
        "sandbox chain lane -> {} ({}) [{} simultaneous, {}]",
        chain.backend.as_str(),
        chain.reason,
        chain_cap,
        chain_origin,
    );
    println!(
        "sandbox fast lane  -> {} ({}) [{} simultaneous, {}]",
        fast.backend.as_str(),
        fast.reason,
        fast_cap,
        fast_origin,
    );
}

/// Report whether the `nyx-sandbox-shim` helper binary resolves. Birdcage
/// only runs when this binary is reachable (via `$NYX_SANDBOX_SHIM` or as
/// a sibling of the running `nyctos`); a missing shim silently
/// downgrades the chain + fast lane selectors to `Process`, so the
/// doctor surface should call out the gap explicitly.
fn report_sandbox_shim() {
    match nyctos_sandbox::probe(BackendKind::Birdcage) {
        Ok(()) => println!("sandbox shim: nyx-sandbox-shim reachable"),
        Err(err) => println!("sandbox shim: unavailable ({err})"),
    }
}

fn resolve_min_nyx_version(config: &Config) -> anyhow::Result<Version> {
    // The built-in `MINIMUM_NYX_VERSION` is a true floor, not a default: an
    // operator may raise the requirement via `[nyx].min_version` but cannot
    // lower it below what the agent's schema-tolerance contract guarantees.
    let floor = Version::parse(MINIMUM_NYX_VERSION).expect("built-in floor parses");
    let Some(raw) = config.nyx.min_version.as_deref() else {
        return Ok(floor);
    };
    let configured = Version::parse(raw)
        .map_err(|e| anyhow::anyhow!("[nyx].min_version `{raw}` is not a valid semver: {e}"))?;
    Ok(configured.max(floor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review_candidate(class: &str) -> PentestCandidateRecord {
        PentestCandidateRecord {
            id: "pc-review".to_string(),
            run_id: "run-review".to_string(),
            project_id: "project-review".to_string(),
            source: "NyxSignal".to_string(),
            source_ids: vec!["sig-review".to_string()],
            title: format!("{class} candidate"),
            vuln_class: class.to_string(),
            severity_guess: "High".to_string(),
            affected_components: vec![serde_json::json!({
                "repo": "web",
                "path": "src/routes.ts",
                "line": 12,
            })],
            hypothesis: "Attacker-controlled input reaches the response.".to_string(),
            test_plan: "{}".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: 0.6,
            trace_id: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn pending_ai_candidate() -> CandidateFindingRecord {
        CandidateFindingRecord {
            id: "cand-review".to_string(),
            run_id: "run-review".to_string(),
            repo: "web".to_string(),
            path: "src/routes.ts".to_string(),
            line: Some(12),
            cap: "AUTH_BYPASS".to_string(),
            rule_hint: Some("auth.trusted_forwarded_identity_header".to_string()),
            rationale: Some("A trusted identity header is accepted from the request.".to_string()),
            suggested_payload_hint: Some(
                "Cf-Access-Authenticated-User-Email: admin@example.com".to_string(),
            ),
            status: "Pending".to_string(),
            prompt_version: Some("novel.v1".to_string()),
            trace_id: None,
        }
    }

    #[test]
    fn verifier_skips_non_json_placeholder_plans() {
        let mut candidate = review_candidate("XSS");
        candidate.test_plan =
            "Derive a live HTTP/browser test from the affected route before confirmation."
                .to_string();

        assert!(!candidate_has_runnable_test_plan(
            &candidate,
            &["http://localhost:8787".to_string()],
            false
        ));
    }

    #[test]
    fn review_surface_marks_ai_candidates_as_needs_review() {
        let vuln = review_vulnerability_from_ai_candidate(
            &pending_ai_candidate(),
            "project-review",
            1_000,
        );

        assert_eq!(vuln.status, "NeedsReview");
        assert_eq!(vuln.confidence, 0.68);
        assert_eq!(vuln.risk_rating, "High");
        assert_eq!(vuln.risk_score_source, "heuristic");
        assert!(vuln.risk_score_rationale.contains("unconfirmed evidence"));
        assert!(vuln.verification_attempt_ids.is_empty());
        assert!(vuln.evidence_summary.contains("Needs review"));
    }

    #[test]
    fn candidate_risk_score_prefers_agent_evidence_and_clamps() {
        let mut candidate = review_candidate("XSS");
        candidate.affected_components = vec![serde_json::json!({
            "repo": "web",
            "path": "src/routes.ts",
            "risk_score": 99.0,
            "risk_rating": "Critical",
            "risk_score_source": "nyctos-agent",
            "risk_score_rationale": "Agent assessed exploitable stored XSS with session impact.",
        })];

        let vuln = vulnerability_from_candidate(&candidate, "va-1", 1_000, None);

        assert_eq!(vuln.risk_score, 10.0);
        assert_eq!(vuln.risk_rating, "Critical");
        assert_eq!(vuln.risk_score_source, "nyctos-agent");
        assert!(vuln.risk_score_rationale.contains("stored XSS"));
    }

    #[test]
    fn ai_candidate_is_queued_as_live_verifiable_pentest_candidate() {
        let candidate =
            pentest_candidate_from_ai_candidate(&pending_ai_candidate(), "project-review", 2_000);

        assert_eq!(candidate.source, "AiNovelFinding");
        assert_eq!(candidate.source_ids, vec!["cand-review"]);
        assert_eq!(candidate.vuln_class, "AUTH_BYPASS");
        assert_eq!(candidate.status, "NeedsLiveTest");
        assert!(candidate.hypothesis.contains("Cf-Access-Authenticated-User-Email"));
    }

    #[test]
    fn non_dispositive_rejection_codes_stay_inconclusive() {
        let reason = non_dispositive_rejection_reason(Some(&serde_json::json!({
            "failure_reason": {
                "code": "bad_endpoint",
                "message": "endpoint returned HTTP 404 during verification"
            }
        })));

        assert!(reason.expect("reason").contains("inconclusive"));
    }

    #[tokio::test]
    async fn review_surface_does_not_promote_observed_scanner_candidates() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let store = Store::open(state.path()).await?;
        let project =
            store.projects().create("project-review", "Review", None, None, None, 1_000).await?;
        let run = RunRecord {
            id: "run-review".to_string(),
            project_id: Some(project.id.clone()),
            kind: "Scan".to_string(),
            started_at: 2_000,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        };
        store.runs().insert(&run).await?;

        let mut scanner_candidate = review_candidate("DEPENDENCY_VULN");
        scanner_candidate.source = "Trivy".to_string();
        scanner_candidate.status = "Observed".to_string();
        store.pentest_candidates().insert(&scanner_candidate).await?;

        let report =
            materialize_review_vulnerabilities(&store, &run.id, &project.id, 3_000).await?;
        let vulnerabilities = store.verified_vulnerabilities().list_by_run(&run.id).await?;

        assert_eq!(report.total(), 0);
        assert!(vulnerabilities.is_empty());
        store.close().await;
        Ok(())
    }

    fn single_http_request(url: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "single_http",
            "request": {
                "method": "GET",
                "url": url,
                "role": "anonymous",
                "headers": {},
            },
            "tool_calls": [],
        })
    }

    fn single_http_response(status: u16, body: &str) -> serde_json::Value {
        serde_json::json!({
            "response": {
                "status": status,
                "headers": {},
                "body_preview": body,
                "body_len": body.len(),
            }
        })
    }

    #[test]
    fn evidence_review_rejects_status_only_confirmation() {
        let review = review_confirmed_live_evidence(
            &review_candidate("ACCESS_CONTROL"),
            &single_http_request("http://localhost:3000/admin"),
            &single_http_response(200, "admin dashboard"),
            &serde_json::json!({
                "type": "single_http",
                "status_ok": true,
                "success": true,
            }),
        );

        assert_eq!(review.decision, LiveEvidenceReviewDecision::Block);
        assert!(review.rationale.contains("status-only"));
    }

    #[test]
    fn evidence_review_rejects_static_source_hits() {
        let review = review_confirmed_live_evidence(
            &review_candidate("XSS"),
            &single_http_request("http://localhost:3000/assets/app.js"),
            &single_http_response(200, "const sink = element.innerHTML"),
            &serde_json::json!({
                "type": "single_http",
                "status_ok": true,
                "body_contains": ["innerHTML"],
                "body_contains_ok": true,
                "success": true,
            }),
        );

        assert_eq!(review.decision, LiveEvidenceReviewDecision::Block);
        assert!(review.rationale.contains("static source"));
    }

    #[test]
    fn evidence_review_rejects_unauthenticated_error_pages() {
        let review = review_confirmed_live_evidence(
            &review_candidate("AUTH_BYPASS"),
            &single_http_request("http://localhost:3000/admin"),
            &single_http_response(401, "Unauthorized"),
            &serde_json::json!({
                "type": "single_http",
                "expect_status": [401],
                "status_ok": true,
                "body_contains": ["Unauthorized"],
                "body_contains_ok": true,
                "success": true,
            }),
        );

        assert_eq!(review.decision, LiveEvidenceReviewDecision::Block);
        assert!(review.rationale.contains("401"));
    }

    #[test]
    fn evidence_review_rejects_missing_reflection_marker() {
        let review = review_confirmed_live_evidence(
            &review_candidate("XSS"),
            &single_http_request("http://localhost:3000/search?q=nyctos-probe"),
            &single_http_response(200, "no reflected input here"),
            &serde_json::json!({
                "type": "single_http",
                "status_ok": true,
                "body_contains": ["nyctos-probe"],
                "body_contains_ok": true,
                "success": true,
            }),
        );

        assert_eq!(review.decision, LiveEvidenceReviewDecision::Block);
        assert!(review.rationale.contains("nyctos-probe"));
    }

    #[test]
    fn evidence_review_accepts_specific_live_reflection() {
        let review = review_confirmed_live_evidence(
            &review_candidate("XSS"),
            &single_http_request("http://localhost:3000/search?q=nyctos-probe"),
            &single_http_response(200, "<div>nyctos-probe</div>"),
            &serde_json::json!({
                "type": "single_http",
                "status_ok": true,
                "body_contains": ["nyctos-probe"],
                "body_contains_ok": true,
                "success": true,
            }),
        );

        assert_eq!(review.decision, LiveEvidenceReviewDecision::Accept);
        assert!(review.evidence_strengths.iter().any(|s| s.contains("nyctos-probe")));
    }

    #[test]
    fn static_verdict_blob_lifts_full_evidence_with_kind_discriminator() {
        let mut diag = Diag {
            path: "src/vuln.py".into(),
            line: 19,
            col: Some(5),
            severity: "Medium".into(),
            rule: "taint-unsanitised-flow".into(),
            cap: "Security".into(),
            message: Some("os.system reachable from sys.argv".into()),
            confidence: None,
            evidence: serde_json::json!({
                "source": {"path": "src/vuln.py", "line": 18, "kind": "source"},
                "sink": {"path": "src/vuln.py", "line": 19, "kind": "sink"},
                "flow_steps": [
                    {"file": "src/vuln.py", "line": 18, "kind": "call"},
                    {"file": "src/vuln.py", "line": 19, "kind": "sink"}
                ],
                "notes": ["sanitiser bypassed via shell substitution"]
            }),
            flow_steps: Vec::new(),
        };
        diag.lift_flow_steps();

        let rendered = render_static_verdict_blob(&diag);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("blob is valid JSON");

        assert_eq!(parsed.get("kind").and_then(|v| v.as_str()), Some("StaticDiag"));
        assert_eq!(
            parsed.get("message").and_then(|v| v.as_str()),
            Some("os.system reachable from sys.argv"),
        );
        assert_eq!(parsed.get("flow_steps").and_then(|v| v.as_array()).map(|a| a.len()), Some(2),);
        assert!(parsed.get("source").is_some(), "source field preserved");
        assert!(parsed.get("sink").is_some(), "sink field preserved");
        assert!(parsed.get("notes").is_some(), "notes preserved");
    }

    #[test]
    fn static_verdict_blob_handles_missing_evidence() {
        let diag = Diag {
            path: "a.rs".into(),
            line: 1,
            col: None,
            severity: "Low".into(),
            rule: "X".into(),
            cap: "Y".into(),
            message: Some("short note".into()),
            confidence: None,
            evidence: serde_json::Value::Null,
            flow_steps: Vec::new(),
        };
        let rendered = render_static_verdict_blob(&diag);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed.get("kind").and_then(|v| v.as_str()), Some("StaticDiag"));
        assert_eq!(parsed.get("message").and_then(|v| v.as_str()), Some("short note"));
        assert!(parsed.get("flow_steps").is_none());
    }

    #[test]
    fn static_verdict_blob_preserves_existing_message_in_evidence() {
        let diag = Diag {
            path: "a.rs".into(),
            line: 1,
            col: None,
            severity: "Low".into(),
            rule: "X".into(),
            cap: "Y".into(),
            message: Some("outer".into()),
            confidence: None,
            evidence: serde_json::json!({"message": "inner"}),
            flow_steps: Vec::new(),
        };
        let rendered = render_static_verdict_blob(&diag);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        // Existing evidence.message wins over Diag.message so the upstream
        // payload remains authoritative.
        assert_eq!(parsed.get("message").and_then(|v| v.as_str()), Some("inner"));
    }

    #[test]
    fn generic_nyx_security_signal_becomes_attacker_shaped_dom_xss_candidate() {
        let mut diag = Diag {
            path: "src/app/search.tsx".to_string(),
            line: 24,
            col: Some(13),
            severity: "High".to_string(),
            rule: "taint-unsanitised-flow".to_string(),
            cap: "Security".to_string(),
            message: Some(
                "location.search parameter q flows into element.innerHTML on /search".to_string(),
            ),
            confidence: Some("high".to_string()),
            evidence: serde_json::json!({
                "route": "/search",
                "method": "GET",
                "source": {
                    "name": "q",
                    "path": "src/app/search.tsx",
                    "line": 18
                },
                "sink": {
                    "callee": "element.innerHTML",
                    "path": "src/app/search.tsx",
                    "line": 24
                },
                "flow_steps": [
                    {"kind": "source", "file": "src/app/search.tsx", "line": 18, "snippet": "new URLSearchParams(location.search).get('q')"},
                    {"kind": "sink", "file": "src/app/search.tsx", "line": 24, "snippet": "element.innerHTML = q"}
                ]
            }),
            flow_steps: Vec::new(),
        };
        diag.lift_flow_steps();
        let signal = NyxSignalRecord {
            id: "sig-dom-xss".to_string(),
            run_id: "run-dom-xss".to_string(),
            project_id: "project-dom-xss".to_string(),
            repo_id: "repo-web".to_string(),
            repo: "web".to_string(),
            path: diag.path.clone(),
            line: Some(i64::from(diag.line)),
            cap: diag.cap.clone(),
            rule: diag.rule.clone(),
            severity: diag.severity.clone(),
            message: diag.message.clone(),
            evidence: Some(render_static_evidence_value(&diag)),
            signal_kind: "security".to_string(),
            meaningful: true,
            suppressed_reason: None,
            agent_candidate_id: None,
            created_at: 1_000,
        };

        let candidate = candidate_from_signal(&signal, &diag, 2_000);

        assert_eq!(candidate.source, "NyxSignal");
        assert_eq!(candidate.source_ids, vec!["sig-dom-xss".to_string()]);
        assert_eq!(candidate.vuln_class, "DOM_XSS");
        assert!(candidate.title.contains("Potential DOM XSS"));
        assert!(!candidate.title.starts_with("Security"));
        assert!(candidate.hypothesis.contains("reclassified"));
        assert!(candidate.hypothesis.contains("exploit evidence"));
        let component = candidate.affected_components[0].as_object().expect("component object");
        assert_eq!(component["cap"], "Security");
        assert_eq!(component["rule"], "taint-unsanitised-flow");
        assert_eq!(component["nyx_signal_id"], "sig-dom-xss");
        assert_eq!(component["route"], "/search");
        assert_eq!(component["url_path"], "/search");
        assert_eq!(component["param"], "q");
        assert_eq!(component["sink"], "element.innerHTML");
        assert_eq!(component["sink_line"], 24);
    }

    #[tokio::test]
    async fn persist_run_results_populates_attack_graph_for_static_leads() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let store = Store::open(state.path()).await?;
        let project =
            store.projects().create("proj-graph", "Graph", None, None, None, 1_000).await?;
        let repo = RepoRecord {
            id: "repo-proj-graph-web".to_string(),
            name: "web".to_string(),
            project_id: project.id.clone(),
            source_kind: "local-path".to_string(),
            source_url_or_path: "/tmp/web".to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: 1_001,
            updated_at: 1_001,
        };
        store.repos().upsert(&repo).await?;
        let run = RunRecord {
            id: "run-graph".to_string(),
            project_id: Some(project.id.clone()),
            kind: "Scan".to_string(),
            started_at: 2_000,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        };
        store.runs().insert(&run).await?;
        let diag = Diag {
            path: "src/routes/users.ts".to_string(),
            line: 42,
            col: Some(9),
            severity: "High".to_string(),
            rule: "sql-injection".to_string(),
            cap: "SQLI".to_string(),
            message: Some("query uses request-controlled id".to_string()),
            confidence: Some("high".to_string()),
            evidence: serde_json::json!({"sink": {"callee": "db.query"}}),
            flow_steps: Vec::new(),
        };
        let bundle = RunBundle {
            run_id: run.id.clone(),
            project_id: project.id.clone(),
            started_at_ms: 2_000,
            finished_at_ms: 2_500,
            wall_clock_ms: 500,
            per_repo: vec![nyctos_core::RepoBundle {
                repo: "web".to_string(),
                outcome: RepoOutcome::Success(vec![diag]),
                started_at_ms: 2_000,
                finished_at_ms: 2_500,
                elapsed_ms: 500,
            }],
            callgraph: nyctos_core::CrossRepoCallgraphStub::default(),
        };

        persist_run_results(&store, &bundle).await?;

        let signal_id = nyx_signal_id(
            &project.id,
            &repo.id,
            "web",
            "src/routes/users.ts",
            Some(42),
            "SQLI",
            "sql-injection",
        );
        let candidate_id = format!("pc-{}", signal_id.trim_start_matches("sig-"));
        let graph = store.attack_graph();
        let signal = graph
            .get_node_by_ref("run-graph", nyctos_types::attack_graph::NODE_SIGNAL, &signal_id)
            .await?
            .expect("signal graph node");
        let candidate = graph
            .get_node_by_ref("run-graph", nyctos_types::attack_graph::NODE_CANDIDATE, &candidate_id)
            .await?
            .expect("candidate graph node");
        assert_eq!(signal.properties["path"], "src/routes/users.ts");
        assert_eq!(candidate.properties["source"], "NyxSignal");
        let edges = graph.list_edges_by_run("run-graph").await?;
        assert!(edges.iter().any(|edge| {
            edge.kind == nyctos_types::attack_graph::EDGE_DERIVED_CANDIDATE
                && edge.from_node_id == signal.id
                && edge.to_node_id == candidate.id
        }));

        store.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn scan_targets_include_db_only_project_repos() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let repo_dir = tempfile::tempdir()?;
        let store = Store::open(state.path()).await?;
        let project =
            store.projects().create("proj-prism", "PrismTrips", None, None, None, 1_000).await?;
        store
            .repos()
            .upsert(&RepoRecord {
                id: "repo-proj-prism-website".to_string(),
                name: "website".to_string(),
                project_id: project.id.clone(),
                source_kind: "local-path".to_string(),
                source_url_or_path: repo_dir.path().display().to_string(),
                branch: None,
                auth_ref: None,
                i_own_this: true,
                last_scan_run_id: None,
                last_scan_finished_at: None,
                created_at: 1_001,
                updated_at: 1_001,
            })
            .await?;

        let targets =
            select_scan_targets(&store, &Config::default(), &[project.name.clone()], &[]).await?;

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0.id.as_str(), project.id);
        assert_eq!(targets[0].0.name, "PrismTrips");
        assert_eq!(targets[0].1.len(), 1);
        assert_eq!(targets[0].1[0].name, "website");
        assert_eq!(targets[0].1[0].project_id.as_str(), project.id);
        match &targets[0].1[0].source {
            RepoSource::LocalPath { path } => assert_eq!(path, &repo_dir.path().to_path_buf()),
            other => panic!("expected local path repo, got {other:?}"),
        }

        store.close().await;
        Ok(())
    }
}

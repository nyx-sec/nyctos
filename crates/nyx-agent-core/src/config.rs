//! Typed configuration loaded from `nyx-agent.toml`.
//!
//! Missing sections fall back to defaults so that `nyx-agent doctor` and
//! other read-only operations work in a fresh checkout with no config
//! file on disk.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialise config: {0}")]
    Serialise(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: GeneralConfig,
    pub performance: PerformanceConfig,
    pub sandbox: SandboxConfig,
    pub ai: AiConfig,
    pub ui: UiConfig,
    pub triggers: TriggersConfig,
    pub nyx: NyxConfig,
    pub run: RunConfig,
    /// Projects own repos. Each `[[project]]` block declares one
    /// product (e.g. backend + frontend) and groups its repos under
    /// `[[project.repo]]`. The top-level `[[repo]]` shape is rejected;
    /// every repo must live under a project.
    #[serde(rename = "project", default)]
    pub projects: Vec<ProjectConfig>,
    /// Cron-driven scan schedule entries. Each entry pairs a 5-field
    /// cron expression with an optional repo filter (`None` scans
    /// every enabled repo). The daemon's scheduler task evaluates
    /// every entry once per minute.
    #[serde(rename = "schedule", default)]
    pub schedules: Vec<ScheduleConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    pub log_level: String,
    pub state_dir: Option<PathBuf>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self { log_level: "info".to_string(), state_dir: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceConfig {
    pub max_parallel_scans: u32,
    pub scan_timeout_secs: u64,
    /// Explicit override for the per-run static-pass fan-out.
    /// `None` -> dispatcher computes `min(num_cpus / 2, len(repos))`.
    /// `Some(n)` -> use exactly `n.max(1)` parallel jobs.
    #[serde(default)]
    pub static_concurrency: Option<usize>,
    /// Per-repo budget for the static-pass scan. A scan that exceeds
    /// the budget is killed and its repo bundle records
    /// `Inconclusive(StaticPassTimeout)` while the rest of the run
    /// continues. `None` -> 30 minutes.
    #[serde(default)]
    pub per_repo_timeout_secs: Option<u64>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_parallel_scans: 4,
            scan_timeout_secs: 600,
            static_concurrency: None,
            per_repo_timeout_secs: None,
        }
    }
}

impl PerformanceConfig {
    /// Resolved per-repo timeout. Falls back to 30 minutes when the
    /// operator has not set `[performance] per_repo_timeout_secs`.
    pub fn per_repo_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.per_repo_timeout_secs.unwrap_or(30 * 60))
    }

    /// Resolved static-pass fan-out. Returns `None` when the operator
    /// has not set `[performance] static_concurrency`; the dispatcher
    /// then derives the default from CPU count and repo count.
    pub fn static_concurrency_override(&self) -> Option<usize> {
        self.static_concurrency.map(|n| n.max(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub allow_network: bool,
    /// The first-launch wizard records the operator's preferred
    /// sandbox backend here; the launcher reads it to pick a backend.
    #[serde(default)]
    pub backend: SandboxBackend,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self { enabled: true, allow_network: false, backend: SandboxBackend::default() }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxBackend {
    /// Pick the strongest available backend at runtime.
    #[default]
    Auto,
    /// No kernel isolation. Static-pass only. Always works.
    Process,
    /// macOS Seatbelt profile shipped with the agent.
    Birdcage,
    /// Lightweight microVM on Linux via libkrun.
    Libkrun,
    /// Lightweight microVM on Linux via Firecracker.
    Firecracker,
    /// Docker container fallback. Slowest, requires the docker daemon.
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_base: Option<String>,
    /// Operator-selected AI runtime. The wizard writes this; the run
    /// dispatcher reads it to pick which provider client to build.
    /// The API key itself is stored in the OS keychain, not in TOML.
    #[serde(default)]
    pub runtime: AiRuntime,
    /// Maximum number of in-flight `one_shot` AI calls per run.
    /// PayloadSynthesis / SpecDerivation / ChainReasoning all share
    /// this cap. `0` is floored to `1` by
    /// [`AiConfig::max_concurrent_one_shot_resolved`].
    #[serde(default = "default_max_concurrent_one_shot")]
    pub max_concurrent_one_shot: u32,
    /// Per-run AI budget cap (in USD micros) stamped on brand-new
    /// `(run_id, kind)` rows the `BudgetStoreTracker` auto-creates.
    /// `None` falls back to the built-in
    /// [`AiConfig::DEFAULT_RUN_BUDGET_USD_MICROS`]. Operators raise or
    /// lower this via `[ai] default_run_budget_usd_micros` in
    /// `nyx-agent.toml`.
    #[serde(default)]
    pub default_run_budget_usd_micros: Option<i64>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: None,
            model: None,
            api_base: None,
            runtime: AiRuntime::default(),
            max_concurrent_one_shot: default_max_concurrent_one_shot(),
            default_run_budget_usd_micros: None,
        }
    }
}

fn default_max_concurrent_one_shot() -> u32 {
    4
}

impl AiConfig {
    /// Built-in fallback per-run AI budget cap ($5.00 in USD micros).
    /// Used when the operator did not set
    /// `[ai] default_run_budget_usd_micros`.
    pub const DEFAULT_RUN_BUDGET_USD_MICROS: i64 = 5_000_000;

    /// Floored fan-out used by run-time dispatchers. A configured `0`
    /// would deadlock a semaphore acquire so we floor to `1`.
    pub fn max_concurrent_one_shot_resolved(&self) -> usize {
        self.max_concurrent_one_shot.max(1) as usize
    }

    /// Resolved per-run AI budget cap, honouring the operator override
    /// when set. Negative or zero overrides fall back to the built-in
    /// default rather than disabling the cap.
    pub fn default_run_budget_usd_micros_resolved(&self) -> i64 {
        match self.default_run_budget_usd_micros {
            Some(v) if v > 0 => v,
            _ => Self::DEFAULT_RUN_BUDGET_USD_MICROS,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AiRuntime {
    /// AI features off. Static-pass only.
    #[default]
    None,
    /// Hosted Anthropic API. The wizard prompts for an API key and
    /// stashes it in the OS keychain under `secrets::ACCOUNT_AI_ANTHROPIC`.
    Anthropic,
    /// Local OpenAI-compatible runtime (LM Studio, Ollama, vLLM, ...).
    /// The endpoint URL goes in `api_base`; any embedded bearer goes
    /// in the keychain under `secrets::ACCOUNT_AI_LOCAL_LLM`.
    LocalLlm,
    /// Drive an already-installed `claude` CLI on `$PATH`.
    ClaudeCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub listen_addr: String,
    pub open_browser: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        // Plan: serve opens a browser on startup unless --no-open /
        // --headless. Default this to true so users who never write
        // `[ui].open_browser` keep the documented behaviour, and those
        // who set it to false in nyx-agent.toml suppress the launch.
        Self { listen_addr: "127.0.0.1:8765".to_string(), open_browser: true }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NyxConfig {
    /// Override the discovered `nyx` binary. When `None`, the runner falls
    /// back to a `PATH` lookup.
    pub binary_path: Option<PathBuf>,
    /// Override the built-in minimum-supported `nyx` version. Useful in
    /// integration tests; production deployments should leave it unset.
    pub min_version: Option<String>,
}

/// `[run]` section: verifier knobs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunConfig {
    /// When `true`, the deterministic payload runner re-executes each
    /// (vuln, benign) pair a second time and stamps `replay_stable` on
    /// the resulting `VerifyResult`. Adds ~2× cost per verify; default
    /// is `false` so the verifier stays fast on the happy path.
    pub replay_stable_check: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TriggersConfig {
    pub on_push: bool,
    pub on_pr: bool,
    pub schedule_cron: Option<String>,
    /// HMAC-SHA256 secret for `POST /webhook/git`. When
    /// unset, the webhook handler returns 503 so a misconfigured host
    /// cannot accept unauthenticated triggers.
    #[serde(default)]
    pub webhook_secret_ref: Option<String>,
    /// Optional branch filter for the webhook. When set, the handler
    /// only triggers a scan if the payload's branch ref matches.
    /// `None` accepts any branch.
    #[serde(default)]
    pub webhook_branch: Option<String>,
}

/// One `[[schedule]]` entry. A 5-field cron expression plus
/// an optional repo filter. When `repo` is `None` the scheduler runs
/// against every enabled repo (i.e. the same shape as the API's
/// manual-scan endpoint with no `repo=` query).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    /// 5-field cron expression (minute hour day-of-month month day-of-week).
    /// Example: `0 3 * * 1` = 03:00 every Monday.
    pub cron: String,
    /// Limit the run to a single configured repo. `None` scans every
    /// enabled repo.
    #[serde(default)]
    pub repo: Option<String>,
    /// Operator-readable label surfaced in tracing spans and the UI.
    /// Default `"scheduled"`.
    #[serde(default = "default_schedule_label")]
    pub label: String,
}

fn default_schedule_label() -> String {
    "scheduled".to_string()
}

/// A project groups one or more repos that belong to the same
/// product. Scan/run/env-builder/chain-runner operate per-project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Unique project name. Used as the human-facing identifier and
    /// as the workspace directory prefix.
    pub name: String,
    /// Optional free-form description surfaced in the UI.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional base URL the sandbox env-builder dials when running
    /// dynamic checks against the running stack.
    #[serde(default)]
    pub target_base_url: Option<String>,
    /// Optional structured env overrides merged into the project's
    /// docker-compose / sandbox runtime. Stored as opaque TOML so each
    /// stack can carry whatever keys it needs.
    #[serde(default)]
    pub env_config: Option<toml::Value>,
    /// Repos that belong to this project. Use `[[project.repo]]`
    /// blocks in TOML.
    #[serde(rename = "repo", default)]
    pub repos: Vec<RepoConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    /// Operator attestation that they own this repo and consent to scanning.
    /// The daemon refuses to ingest a repo without `i_own_this = true`.
    #[serde(default)]
    pub i_own_this: bool,
    pub source: RepoSourceConfig,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RepoSourceConfig {
    /// Read-only clone of a remote git URL into `<state>/repos/<name>/`.
    Git {
        url: String,
        #[serde(default)]
        branch: Option<String>,
        /// Auth descriptor: `ssh-key:<path>`, `token-env:<var>`, `gh-app:<id>`.
        #[serde(default)]
        auth: Option<String>,
    },
    /// Read-only snapshot of a directory already present on disk.
    LocalPath { path: PathBuf },
}

fn default_true() -> bool {
    true
}

impl Config {
    #[tracing::instrument(skip_all, fields(path = %path.display()))]
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        Self::parse(&raw, path)
    }

    #[tracing::instrument(skip_all, fields(path = %path.display()))]
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Self::parse(&raw, path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read { path: path.to_path_buf(), source }),
        }
    }

    pub fn parse(raw: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(raw)
            .map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source })
    }

    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn defaults_roundtrip_through_toml() {
        let cfg = Config::default();
        let rendered = cfg.to_toml_string().expect("serialise defaults");
        let parsed = Config::parse(&rendered, &PathBuf::from("<test>")).expect("parse defaults");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn populated_config_roundtrips() {
        let cfg = Config {
            general: GeneralConfig {
                log_level: "debug".to_string(),
                state_dir: Some(PathBuf::from("/tmp/nyx")),
            },
            performance: PerformanceConfig {
                max_parallel_scans: 8,
                scan_timeout_secs: 1200,
                static_concurrency: Some(2),
                per_repo_timeout_secs: Some(45),
            },
            sandbox: SandboxConfig {
                enabled: false,
                allow_network: true,
                backend: SandboxBackend::Birdcage,
            },
            ai: AiConfig {
                provider: Some("anthropic".to_string()),
                model: Some("claude-opus-4-7".to_string()),
                api_base: None,
                runtime: AiRuntime::Anthropic,
                max_concurrent_one_shot: 2,
                default_run_budget_usd_micros: None,
            },
            ui: UiConfig { listen_addr: "0.0.0.0:9999".to_string(), open_browser: true },
            triggers: TriggersConfig {
                on_push: true,
                on_pr: true,
                schedule_cron: Some("0 * * * *".to_string()),
                webhook_secret_ref: Some("env:NYX_WEBHOOK_SECRET".to_string()),
                webhook_branch: Some("main".to_string()),
            },
            nyx: NyxConfig {
                binary_path: Some(PathBuf::from("/opt/nyx/bin/nyx")),
                min_version: Some("0.2.0".to_string()),
            },
            run: RunConfig { replay_stable_check: true },
            projects: vec![ProjectConfig {
                name: "acme-app".to_string(),
                description: Some("Acme web product".to_string()),
                target_base_url: Some("http://localhost:3000".to_string()),
                env_config: None,
                repos: vec![
                    RepoConfig {
                        name: "nyx-pro".to_string(),
                        i_own_this: true,
                        source: RepoSourceConfig::Git {
                            url: "git@github.com:nyx/nyx-pro.git".to_string(),
                            branch: Some("main".to_string()),
                            auth: Some("ssh-key:~/.ssh/work_ed25519".to_string()),
                        },
                        enabled: true,
                    },
                    RepoConfig {
                        name: "monolith".to_string(),
                        i_own_this: true,
                        source: RepoSourceConfig::LocalPath {
                            path: PathBuf::from("/Users/eli/code/monolith"),
                        },
                        enabled: true,
                    },
                ],
            }],
            schedules: vec![ScheduleConfig {
                cron: "0 3 * * 1".to_string(),
                repo: Some("nyx-pro".to_string()),
                label: "weekly-monday-3am".to_string(),
            }],
        };
        let rendered = cfg.to_toml_string().expect("serialise");
        let parsed = Config::parse(&rendered, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn missing_file_returns_default() {
        let path = PathBuf::from("/definitely/does/not/exist/nyx-agent.toml");
        let cfg = Config::load_or_default(&path).expect("missing file -> default");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn empty_string_parses_to_default() {
        let cfg = Config::parse("", &PathBuf::from("<test>")).expect("empty parses");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn repo_enabled_defaults_to_true_when_omitted() {
        let raw = "[[project]]\nname = \"p\"\n\n[[project.repo]]\nname = \"nyx-pro\"\n\
                   i_own_this = true\n\
                   source = { kind = \"local-path\", path = \"/srv/repos/nyx-pro\" }\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.projects.len(), 1);
        assert_eq!(cfg.projects[0].repos.len(), 1);
        assert!(
            cfg.projects[0].repos[0].enabled,
            "declared repo without explicit enabled must default to true"
        );
    }

    #[test]
    fn repo_source_git_parses_with_inline_table() {
        let raw = "[[project]]\nname = \"p\"\n\n[[project.repo]]\nname = \"billing\"\n\
                   i_own_this = true\n\
                   source = { kind = \"git\", url = \"git@github.com:org/billing.git\", \
                              branch = \"main\", auth = \"ssh-key:~/.ssh/work_ed25519\" }\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        match &cfg.projects[0].repos[0].source {
            RepoSourceConfig::Git { url, branch, auth } => {
                assert_eq!(url, "git@github.com:org/billing.git");
                assert_eq!(branch.as_deref(), Some("main"));
                assert_eq!(auth.as_deref(), Some("ssh-key:~/.ssh/work_ed25519"));
            }
            other => panic!("expected git source, got {other:?}"),
        }
    }

    #[test]
    fn repo_source_local_path_parses() {
        let raw = "[[project]]\nname = \"p\"\n\n[[project.repo]]\nname = \"monolith\"\n\
                   i_own_this = true\n\
                   source = { kind = \"local-path\", path = \"/home/eli/code/monolith\" }\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        match &cfg.projects[0].repos[0].source {
            RepoSourceConfig::LocalPath { path } => {
                assert_eq!(path, &PathBuf::from("/home/eli/code/monolith"));
            }
            other => panic!("expected local-path source, got {other:?}"),
        }
    }

    #[test]
    fn repo_source_unknown_kind_rejected() {
        let raw = "[[project]]\nname = \"p\"\n\n[[project.repo]]\nname = \"x\"\n\
                   i_own_this = true\n\
                   source = { kind = \"hg\", path = \"/srv/x\" }\n";
        let err = Config::parse(raw, &PathBuf::from("<test>")).expect_err("must reject");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn repo_i_own_this_defaults_to_false_when_omitted() {
        let raw = "[[project]]\nname = \"p\"\n\n[[project.repo]]\nname = \"x\"\n\
                   source = { kind = \"local-path\", path = \"/srv/x\" }\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert!(
            !cfg.projects[0].repos[0].i_own_this,
            "i_own_this must default to false so the daemon refuses unattested repos"
        );
    }

    #[test]
    fn top_level_repo_block_rejected() {
        // Bare `[[repo]]` is no longer accepted. The TOML must
        // declare a `[[project]]` first and nest repos under it.
        let raw = "[[repo]]\nname = \"x\"\ni_own_this = true\n\
                   source = { kind = \"local-path\", path = \"/srv/x\" }\n";
        let err = Config::parse(raw, &PathBuf::from("<test>")).expect_err("must reject");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn project_groups_multiple_repos() {
        let raw = "[[project]]\nname = \"acme\"\ndescription = \"Acme product\"\n\
                   target_base_url = \"http://localhost:3000\"\n\n\
                   [[project.repo]]\nname = \"acme-backend\"\ni_own_this = true\nenabled = true\n\
                   source = { kind = \"local-path\", path = \"/p/backend\" }\n\n\
                   [[project.repo]]\nname = \"acme-frontend\"\ni_own_this = true\nenabled = true\n\
                   source = { kind = \"local-path\", path = \"/p/frontend\" }\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.projects.len(), 1);
        let p = &cfg.projects[0];
        assert_eq!(p.name, "acme");
        assert_eq!(p.description.as_deref(), Some("Acme product"));
        assert_eq!(p.target_base_url.as_deref(), Some("http://localhost:3000"));
        assert_eq!(p.repos.len(), 2);
        assert_eq!(p.repos[0].name, "acme-backend");
        assert_eq!(p.repos[1].name, "acme-frontend");
    }

    #[test]
    fn unknown_field_rejected() {
        let raw = "garbage_field = true\n";
        let err = Config::parse(raw, &PathBuf::from("<test>")).expect_err("must reject");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn performance_static_concurrency_and_per_repo_timeout_round_trip() {
        let raw = "[performance]\nstatic_concurrency = 3\nper_repo_timeout_secs = 5\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.performance.static_concurrency, Some(3));
        assert_eq!(cfg.performance.per_repo_timeout_secs, Some(5));
        assert_eq!(cfg.performance.per_repo_timeout(), std::time::Duration::from_secs(5));
        assert_eq!(cfg.performance.static_concurrency_override(), Some(3));
    }

    #[test]
    fn performance_omitted_overrides_fall_back() {
        let cfg = Config::parse("", &PathBuf::from("<test>")).expect("parse");
        assert!(cfg.performance.static_concurrency.is_none());
        assert!(cfg.performance.per_repo_timeout_secs.is_none());
        assert_eq!(cfg.performance.per_repo_timeout(), std::time::Duration::from_secs(30 * 60));
        assert!(cfg.performance.static_concurrency_override().is_none());
    }

    #[test]
    fn ai_max_concurrent_one_shot_default_is_four() {
        let cfg = Config::parse("", &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.ai.max_concurrent_one_shot, 4);
        assert_eq!(cfg.ai.max_concurrent_one_shot_resolved(), 4);
    }

    #[test]
    fn ai_max_concurrent_one_shot_zero_floors_to_one() {
        let raw = "[ai]\nmax_concurrent_one_shot = 0\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.ai.max_concurrent_one_shot, 0);
        assert_eq!(cfg.ai.max_concurrent_one_shot_resolved(), 1);
    }

    #[test]
    fn ai_max_concurrent_one_shot_roundtrips_through_toml() {
        let raw = "[ai]\nmax_concurrent_one_shot = 8\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.ai.max_concurrent_one_shot, 8);
        let rendered = cfg.to_toml_string().expect("ser");
        let back = Config::parse(&rendered, &PathBuf::from("<test>")).expect("roundtrip");
        assert_eq!(back.ai.max_concurrent_one_shot, 8);
    }

    #[test]
    fn performance_static_concurrency_zero_floors_to_one() {
        let cfg = Config {
            performance: PerformanceConfig {
                static_concurrency: Some(0),
                ..PerformanceConfig::default()
            },
            ..Config::default()
        };
        assert_eq!(cfg.performance.static_concurrency_override(), Some(1));
    }
}

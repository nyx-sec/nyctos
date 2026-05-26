//! Config, state, logging, and persistence surface shared by every binary.

pub mod config;
pub mod event_log;
pub mod ids;
pub mod log_init;
pub mod project;
pub mod repo;
pub mod report;
pub mod run;
pub mod secrets;
pub mod state;
pub mod store;
pub mod time;

pub use config::{
    AiConfig, AiRuntime, Config, ConfigError, EnvConfig, EnvPullPolicy, GeneralConfig, NyxConfig,
    PerformanceConfig, ProjectConfig, RepoConfig, RepoSourceConfig, RunConfig, SandboxBackend,
    SandboxConfig, ScheduleConfig, TriggersConfig, UiConfig,
};
pub use event_log::{run_event_log_path, safe_run_log_segment, RunEventLogWriter};
pub use log_init::{init as init_logging, json_log_path, LogConfig, LogInitError};
pub use project::{Project, ProjectId};
pub use repo::{
    ingest, parse_git_auth, repo_from_config, GitAuth, IngestError, IngestedRepo, Repo, RepoSource,
    SnapshotBackend,
};
pub use run::{
    mint_run_id, CrossRepoCallgraphStub, CrossRepoEdge, InconclusiveReason, RepoBundle,
    RepoOutcome, Run, RunBundle, RunCounts, RunDispatcher, ScanLane, ScanLaneError,
    WorkspaceHandle,
};
pub use secrets::{
    SecretError, SecretStore, ACCOUNT_AI_ANTHROPIC, ACCOUNT_AI_LOCAL_LLM, DEFAULT_SERVICE,
    ENV_BACKEND as SECRETS_ENV_BACKEND,
};
pub use state::{mint_token, StateDir, StateError};
pub use store::{Store, StoreError, CURRENT_SCHEMA_VERSION};
pub use time::now_epoch_ms;

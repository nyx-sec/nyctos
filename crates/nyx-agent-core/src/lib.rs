//! Config, state, logging, and persistence surface shared by every binary.

pub mod config;
pub mod log_init;
pub mod report;
pub mod repo;
pub mod run;
pub mod secrets;
pub mod state;
pub mod store;

pub use config::{
    AiConfig, AiRuntime, Config, ConfigError, GeneralConfig, NyxConfig, PerformanceConfig,
    RepoConfig, RepoSourceConfig, RunConfig, SandboxBackend, SandboxConfig, TriggersConfig,
    UiConfig,
};
pub use log_init::{init as init_logging, json_log_path, LogConfig, LogInitError};
pub use repo::{ingest, GitAuth, IngestError, IngestedRepo, Repo, RepoSource, SnapshotBackend};
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

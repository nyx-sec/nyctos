//! Config, state, logging, and persistence surface shared by every binary.

pub mod config;
pub mod log_init;
pub mod repo;
pub mod run;
pub mod state;
pub mod store;

pub use config::{
    AiConfig, Config, ConfigError, GeneralConfig, NyxConfig, PerformanceConfig, RepoConfig,
    RepoSourceConfig, SandboxConfig, TriggersConfig, UiConfig,
};
pub use log_init::{init as init_logging, json_log_path, LogConfig, LogInitError};
pub use repo::{ingest, GitAuth, IngestError, IngestedRepo, Repo, RepoSource, SnapshotBackend};
pub use run::{
    mint_run_id, CrossRepoCallgraphStub, CrossRepoEdge, InconclusiveReason, RepoBundle,
    RepoOutcome, Run, RunBundle, RunCounts, RunDispatcher, ScanLane, ScanLaneError,
    WorkspaceHandle,
};
pub use state::{StateDir, StateError};
pub use store::{Store, StoreError, CURRENT_SCHEMA_VERSION};

//! Config, state, logging, and persistence surface shared by every binary.

pub mod config;
pub mod log_init;
pub mod state;
pub mod store;

pub use config::{
    AiConfig, Config, ConfigError, GeneralConfig, PerformanceConfig, RepoConfig, SandboxConfig,
    TriggersConfig, UiConfig,
};
pub use log_init::{init as init_logging, json_log_path, LogConfig, LogInitError};
pub use state::{StateDir, StateError};
pub use store::{Store, StoreError, CURRENT_SCHEMA_VERSION};

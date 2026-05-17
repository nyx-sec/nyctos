//! Config, state, and logging surface shared by every binary.

pub mod config;
pub mod log_init;
pub mod state;

pub use config::{
    AiConfig, Config, ConfigError, GeneralConfig, PerformanceConfig, RepoConfig, SandboxConfig,
    TriggersConfig, UiConfig,
};
pub use log_init::{init as init_logging, json_log_path, LogConfig, LogInitError};
pub use state::{StateDir, StateError};

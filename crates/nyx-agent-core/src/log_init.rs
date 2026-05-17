//! `tracing` initialisation shared by every binary entry point.
//!
//! Two layers are installed:
//!
//! * a JSON layer writing one event per line to `<state>/logs/agent.jsonl`,
//!   used downstream by replay and CI inspection tools;
//! * a human-readable layer writing to stderr, gated by `--log-level` so
//!   stdout stays clean for tools that pipe agent output.
//!
//! Span fields `run_id`, `repo`, `task_id`, `prompt_version` are surfaced
//! by every later phase. Tracing records whichever of those are present
//! on the current span; nothing here forces them.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum LogInitError {
    #[error("failed to open log file at {path}: {source}")]
    OpenLog {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid log level {0:?}")]
    InvalidLevel(String),
    #[error("global tracing subscriber already installed")]
    AlreadyInstalled,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub log_dir: PathBuf,
    pub level: String,
    pub file_name: String,
}

impl LogConfig {
    pub fn new(log_dir: impl Into<PathBuf>, level: impl Into<String>) -> Self {
        Self { log_dir: log_dir.into(), level: level.into(), file_name: "agent.jsonl".to_string() }
    }
}

/// Install the global subscriber. Returns an error if the global
/// subscriber is already set or the JSON log file cannot be opened.
pub fn init(cfg: &LogConfig) -> Result<(), LogInitError> {
    install(cfg, std::io::stderr)
}

/// Variant that lets callers redirect the human-readable layer (used by
/// tests). The JSON layer always writes to `<log_dir>/<file_name>`.
pub fn install<W>(cfg: &LogConfig, human_writer: W) -> Result<(), LogInitError>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter = EnvFilter::try_new(&cfg.level)
        .map_err(|_| LogInitError::InvalidLevel(cfg.level.clone()))?;

    std::fs::create_dir_all(&cfg.log_dir)
        .map_err(|source| LogInitError::OpenLog { path: cfg.log_dir.clone(), source })?;
    let log_path = cfg.log_dir.join(&cfg.file_name);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|source| LogInitError::OpenLog { path: log_path.clone(), source })?;
    let file = Arc::new(file);
    let json_writer = BoxMakeWriter::new(move || -> Box<dyn std::io::Write + Send> {
        Box::new(FileHandle(Arc::clone(&file)))
    });

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_writer(json_writer);

    let human_layer = tracing_subscriber::fmt::layer().with_target(false).with_writer(human_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .with(human_layer)
        .try_init()
        .map_err(|_| LogInitError::AlreadyInstalled)
}

/// Inspect-only helper used by `nyx-agent doctor` so it can confirm the
/// JSON sink path without actually installing a subscriber.
pub fn json_log_path(log_dir: &Path) -> PathBuf {
    log_dir.join("agent.jsonl")
}

struct FileHandle(Arc<std::fs::File>);

impl std::io::Write for FileHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_log_path_appends_filename() {
        assert_eq!(
            json_log_path(Path::new("/var/state/logs")),
            PathBuf::from("/var/state/logs/agent.jsonl")
        );
    }

    #[test]
    fn install_writes_json_file_and_is_idempotent_in_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = LogConfig::new(tmp.path(), "info");
        // First install in this test process succeeds; a second call must
        // fail rather than silently double-register the global subscriber.
        // We can't rely on ordering across tests, so guard with try_init's
        // own contract: either branch is acceptable.
        let first = install(&cfg, std::io::sink);
        let second = install(&cfg, std::io::sink);
        assert!(first.is_ok() || matches!(first, Err(LogInitError::AlreadyInstalled)));
        assert!(matches!(second, Err(LogInitError::AlreadyInstalled)));
        let log_path = json_log_path(tmp.path());
        assert!(log_path.exists(), "{} should exist", log_path.display());
    }
}

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
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::secrets::looks_like_secret;

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
    let json_writer = BoxMakeWriter::new(move || -> Box<dyn io::Write + Send> {
        Box::new(RedactingWriter::new(FileHandle(Arc::clone(&file))))
    });

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_writer(json_writer);

    // Wrap the human-readable layer's writer in the same redactor so a
    // stray `tracing::info!(token = %secret)` does not leak via stderr
    // either. `MakeWriter` is hand-implemented because the std closure
    // signature does not satisfy the `Sync` bound on its own.
    let human_writer = RedactingMakeWriter::new(human_writer);
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

impl io::Write for FileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// Replacement bytes substituted in place of anything matching a known
/// secret pattern.
const REDACTED: &[u8] = b"<redacted>";

/// `Write` wrapper that scans every line for token-shaped substrings and
/// rewrites them to `<redacted>` before forwarding. Cheap by design:
/// the inner buffer is bounded to one log line, and the matching is a
/// linear pass through ASCII-shaped runs of `[A-Za-z0-9_\-]`.
pub(crate) struct RedactingWriter<W: io::Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: io::Write> RedactingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, buf: Vec::with_capacity(512) }
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(idx) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=idx).collect();
            let scrubbed = redact_line(&line);
            self.inner.write_all(&scrubbed)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let scrubbed = redact_line(&self.buf);
            self.inner.write_all(&scrubbed)?;
            self.buf.clear();
        }
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn redact_line(line: &[u8]) -> Vec<u8> {
    let Ok(s) = std::str::from_utf8(line) else {
        // Non-UTF8 log lines are unexpected; pass them through verbatim
        // because the redactor can only reason about ASCII tokens.
        return line.to_vec();
    };
    let mut out = String::with_capacity(s.len());
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if is_token_char(c) {
            let mut end = i + 1;
            while end < bytes.len() && is_token_char(bytes[end]) {
                end += 1;
            }
            let candidate = &s[i..end];
            if looks_like_secret(candidate) {
                out.push_str(&s[start..i]);
                out.push_str(std::str::from_utf8(REDACTED).unwrap());
                start = end;
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out.push_str(&s[start..]);
    out.into_bytes()
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[derive(Clone)]
struct RedactingMakeWriter<W> {
    inner: W,
}

impl<W> RedactingMakeWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<'a, W> tracing_subscriber::fmt::MakeWriter<'a> for RedactingMakeWriter<W>
where
    W: tracing_subscriber::fmt::MakeWriter<'a> + 'static,
{
    type Writer = RedactingWriter<W::Writer>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer())
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
    fn redact_line_replaces_anthropic_key_shape() {
        let scrubbed = redact_line(b"calling api with token=sk-ant-api03-aaaaabbbbbcccccddddd\n");
        let out = String::from_utf8(scrubbed).unwrap();
        assert!(!out.contains("sk-ant"), "redacted output still contains secret: {out:?}");
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn redact_line_leaves_non_secret_text_intact() {
        let input = b"GET /api/v1/health status=200\n";
        let scrubbed = redact_line(input);
        assert_eq!(scrubbed, input);
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

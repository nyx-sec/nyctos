//! Durable per-run event logs for the UI's live stream.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;

use nyctos_types::event::AgentEvent;

use crate::now_epoch_ms;

#[derive(Serialize)]
struct BorrowedRunEventLogEntry<'a> {
    ts_ms: i64,
    event: &'a AgentEvent,
}

/// Stable path for the event-log artifact belonging to one run.
pub fn run_event_log_path(logs_dir: impl AsRef<Path>, run_id: &str) -> PathBuf {
    logs_dir.as_ref().join("runs").join(format!("{}.events.jsonl", safe_run_log_segment(run_id)))
}

/// Filesystem-safe segment for a run-scoped log artifact.
pub fn safe_run_log_segment(run_id: &str) -> String {
    let mut out = String::with_capacity(run_id.len());
    for ch in run_id.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let mut safe = out.trim_matches(['.', '_', '-']).to_string();
    if safe.is_empty() {
        safe = "run".to_string();
    }
    if safe.len() > 80 {
        let mut end = 80;
        while end > 0 && !safe.is_char_boundary(end) {
            end -= 1;
        }
        safe.truncate(end);
        safe = safe.trim_matches(['.', '_', '-']).to_string();
        if safe.is_empty() {
            safe = "run".to_string();
        }
    }
    let hash = blake3::hash(run_id.as_bytes());
    let hex = hash.to_hex();
    format!("{safe}-{}", &hex.as_str()[..8])
}

/// Append-only writer that keeps file handles open while a run is active.
#[derive(Debug)]
pub struct RunEventLogWriter {
    logs_dir: PathBuf,
    files: HashMap<String, File>,
}

impl RunEventLogWriter {
    pub fn new(logs_dir: impl Into<PathBuf>) -> Self {
        Self { logs_dir: logs_dir.into(), files: HashMap::new() }
    }

    pub async fn append(&mut self, run_id: &str, event: &AgentEvent) -> anyhow::Result<()> {
        let path = run_event_log_path(&self.logs_dir, run_id);
        if !self.files.contains_key(run_id) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await?;
            }
            let file = OpenOptions::new().create(true).append(true).open(&path).await?;
            self.files.insert(run_id.to_string(), file);
        }

        let entry = BorrowedRunEventLogEntry { ts_ms: now_epoch_ms(), event };
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        if let Some(file) = self.files.get_mut(run_id) {
            file.write_all(&line).await?;
        }
        Ok(())
    }

    pub async fn finish_run(&mut self, run_id: &str) -> anyhow::Result<()> {
        if let Some(mut file) = self.files.remove(run_id) {
            file.flush().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyctos_types::event::RunEvent;

    #[test]
    fn safe_run_log_segment_is_stable_and_filesystem_safe() {
        let got = safe_run_log_segment("../run one");
        assert!(got.starts_with("run_one-"));
        assert!(!got.contains('/'));
        assert!(!got.contains(' '));
    }

    #[tokio::test]
    async fn writer_appends_jsonl_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let mut writer = RunEventLogWriter::new(tmp.path());
        let event = AgentEvent::Run {
            data: RunEvent::RunStarted {
                run_id: "run-1".to_string(),
                project_id: "project-1".to_string(),
                repos: vec!["repo".to_string()],
                started_at_ms: 1,
            },
        };
        writer.append("run-1", &event).await.unwrap();
        writer.finish_run("run-1").await.unwrap();

        let body = fs::read_to_string(run_event_log_path(tmp.path(), "run-1")).await.unwrap();
        assert!(body.contains("\"ts_ms\""));
        assert!(body.contains("\"RunStarted\""));
    }
}

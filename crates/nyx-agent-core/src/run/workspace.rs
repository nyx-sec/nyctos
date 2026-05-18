//! Per-run ownership handle around an [`IngestedRepo`].
//!
//! Local-path snapshots install a drop hook on the [`IngestedRepo`]
//! that removes the snapshot directory; the dispatcher and any
//! downstream consumer (sandbox, chain reasoning) must keep the same
//! handle alive so the snapshot survives until end-of-run rather than
//! being re-snapshotted per stage. The Phase-05 deferred item asks us
//! to formalise that with a `WorkspaceHandle` owned by the run; this
//! is the type.

use std::path::Path;
use std::sync::Arc;

use crate::repo::{IngestedRepo, RepoSource, SnapshotBackend};

/// Run-scoped, cheaply clonable handle to an ingested repo workspace.
///
/// The inner [`IngestedRepo`] is held inside an `Arc`; cloning the
/// handle bumps the refcount and never re-snapshots. The original
/// snapshot is removed only when the last handle drops.
#[derive(Clone, Debug)]
pub struct WorkspaceHandle {
    inner: Arc<IngestedRepo>,
}

impl WorkspaceHandle {
    pub fn new(ingested: IngestedRepo) -> Self {
        Self { inner: Arc::new(ingested) }
    }

    /// Build a synthetic handle pointing at `path`, with no cleanup
    /// hook attached. Intended for binary / integration tests that
    /// need to fan out per-repo work without going through `ingest`.
    /// Production code paths always go through [`ingest`] +
    /// [`WorkspaceHandle::new`].
    pub fn for_local_path_test(name: impl Into<String>, path: impl Into<std::path::PathBuf>) -> Self {
        let path: std::path::PathBuf = path.into();
        let ingested = IngestedRepo {
            name: name.into(),
            workspace: path.clone(),
            source: RepoSource::LocalPath { path },
            snapshot_backend: None,
            on_disk_git_remote: None,
            cleanup: None,
        };
        Self::new(ingested)
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn workspace(&self) -> &Path {
        &self.inner.workspace
    }

    pub fn source(&self) -> &RepoSource {
        &self.inner.source
    }

    pub fn snapshot_backend(&self) -> Option<SnapshotBackend> {
        self.inner.snapshot_backend
    }

    pub fn on_disk_git_remote(&self) -> Option<&str> {
        self.inner.on_disk_git_remote.as_deref()
    }
}

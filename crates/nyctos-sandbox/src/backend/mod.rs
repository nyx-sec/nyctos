//! Concrete [`crate::Sandbox`] implementations.

pub mod birdcage;
pub mod firecracker;
pub mod libkrun;
pub mod process;

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::process::Command;

use crate::{SandboxError, SandboxOpts};

/// Workspace subdirectory inside the snapshot tempdir. Putting the
/// snapshot one level below the tempdir root means
/// [`crate::workspace::snapshot`] sees a non-existent destination
/// (`tempdir/workspace`), which is its required precondition. The
/// tempdir itself owns the cleanup.
const SCRATCH_SNAPSHOT_SUBDIR: &str = "workspace";

/// If `opts.snapshot_from` is set, materialise a COW snapshot of the
/// source under a fresh tempdir, override `opts.workspace` to point at
/// the new copy, and return the owning [`TempDir`] handle so the
/// caller can stash it on `RunningChild.scratch_snapshot`. Dropping
/// the [`TempDir`] removes the snapshot. Returns `Ok(None)` when no
/// snapshot was requested. Clears `opts.snapshot_from` on the way out
/// so a re-entrant `run()` cannot double-snapshot the same opts.
pub(crate) fn apply_snapshot_from(
    opts: &mut SandboxOpts,
) -> Result<Option<TempDir>, SandboxError> {
    let Some(src) = opts.snapshot_from.take() else {
        return Ok(None);
    };
    if !src.exists() {
        return Err(SandboxError::Config(format!(
            "snapshot_from source {} does not exist",
            src.display()
        )));
    }
    let tempdir = TempDir::new().map_err(SandboxError::Workspace)?;
    let dst = tempdir.path().join(SCRATCH_SNAPSHOT_SUBDIR);
    crate::workspace::snapshot(&src, &dst).map_err(SandboxError::Workspace)?;
    opts.workspace = dst;
    Ok(Some(tempdir))
}

/// Resolve `bin` against `$PATH`, returning the first hit. Shared by
/// the top-level `probe(Docker)` check and the libkrun/firecracker
/// runner resolvers.
pub(crate) fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build a [`tokio::process::Command`] from `opts` with the workspace as
/// cwd, no inherited environment, and piped stdio. Backends overlay their
/// sandbox-specific setup on top.
pub(crate) fn build_command(opts: &SandboxOpts) -> io::Result<Command> {
    let program = opts
        .argv
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "argv is empty"))?;
    let mut cmd = Command::new(program);
    cmd.args(opts.argv.iter().skip(1));
    let cwd: &Path = opts.cwd.as_deref().unwrap_or(&opts.workspace);
    cmd.current_dir(cwd);
    cmd.env_clear();
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn apply_snapshot_from_none_is_passthrough() {
        let scratch = tempdir().unwrap();
        let workspace = scratch.path().join("ws");
        fs::create_dir(&workspace).unwrap();
        let mut opts = SandboxOpts::new(workspace.clone(), vec!["/bin/true".into()]);
        let handle = apply_snapshot_from(&mut opts).expect("ok");
        assert!(handle.is_none(), "no snapshot requested, no tempdir handed back");
        assert_eq!(opts.workspace, workspace, "workspace untouched");
    }

    #[test]
    fn apply_snapshot_from_materialises_and_overrides_workspace() {
        let scratch = tempdir().unwrap();
        let src = scratch.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("sentinel.txt"), b"hello").unwrap();

        let mut opts = SandboxOpts::new(PathBuf::from("/unused"), vec!["/bin/true".into()])
            .with_snapshot_from(src.clone());
        let handle = apply_snapshot_from(&mut opts).expect("snapshot ok");
        let snapshot_dir = handle.as_ref().expect("tempdir handed back").path().to_path_buf();
        assert_eq!(opts.workspace, snapshot_dir.join("workspace"));
        assert!(
            opts.workspace.join("sentinel.txt").is_file(),
            "snapshot must reproduce the source's sentinel"
        );
        // opts.snapshot_from is cleared so a second pass through the
        // backend cannot double-snapshot.
        assert!(opts.snapshot_from.is_none());

        // Drop the tempdir handle and confirm the snapshot directory
        // is removed; this is the RAII contract the backends rely on
        // to keep the snapshot alive for exactly the lifetime of the
        // RunningChild.
        drop(handle);
        assert!(!snapshot_dir.exists(), "tempdir must remove snapshot on drop");
    }

    #[test]
    fn apply_snapshot_from_refuses_missing_source() {
        let mut opts =
            SandboxOpts::new(PathBuf::from("/unused"), vec!["/bin/true".into()])
                .with_snapshot_from(PathBuf::from("/nyx-snapshot-from-does-not-exist"));
        match apply_snapshot_from(&mut opts) {
            Err(SandboxError::Config(reason)) => {
                assert!(reason.contains("snapshot_from"), "reason names the field: {reason}");
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }
}

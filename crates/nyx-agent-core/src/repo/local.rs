//! Local-path source ingestion: per-run read-only snapshot of an
//! existing on-disk directory.
//!
//! Three snapshot backends are supported. They differ only in how the
//! snapshot is produced; from the caller's perspective the result is
//! always a path that can be read while the original tree continues to
//! receive uncommitted edits in an IDE.
//!
//! | Backend | Mechanism | Requirements |
//! |---|---|---|
//! | [`SnapshotBackend::BindMount`] | Linux `mount --bind -o ro` | Linux + root |
//! | [`SnapshotBackend::ApfsSnapshot`] | macOS `tmutil localsnapshot` + `mount_apfs -s ... -o ro` | macOS + root |
//! | [`SnapshotBackend::Copy`] | Recursive copy followed by `chmod -R -w` | None |
//!
//! [`Copy`] is the universal fallback and the only backend that runs
//! without elevated privileges. The other two are selected explicitly
//! via [`select_backend`] or [`ingest_local_with_backend`].
//!
//! Snapshots live under `<state>/repos/<name>/snapshots/<run_id>/` and
//! are removed on [`super::IngestedRepo`] drop. The original on-disk
//! tree is never touched.

use std::path::{Path, PathBuf};

use super::{install_snapshot_cleanup, IngestError, IngestedRepo, RepoSource};

const SNAPSHOTS_SUBDIR: &str = "snapshots";

/// Backend used to take a read-only snapshot of a local-path source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotBackend {
    /// Linux `mount --bind -o ro,bind`. Requires root.
    BindMount,
    /// macOS APFS local snapshot mounted read-only. Requires root.
    ApfsSnapshot,
    /// Recursive copy plus `chmod -R -w`. Always available.
    Copy,
}

pub(super) async fn ingest_local(
    name: &str,
    src: &Path,
    per_repo_dir: &Path,
    run_id: &str,
) -> Result<IngestedRepo, IngestError> {
    let backend = select_backend();
    ingest_local_with_backend(name, src, per_repo_dir, run_id, backend).await
}

/// Pick a snapshot backend. Honours the `NYX_SNAPSHOT_BACKEND` env var
/// (values `copy` / `bind-mount` / `apfs`) for tests and operator
/// overrides; otherwise returns [`SnapshotBackend::Copy`] since the
/// privileged backends require root that the daemon does not have by
/// default.
pub fn select_backend() -> SnapshotBackend {
    match std::env::var("NYX_SNAPSHOT_BACKEND").ok().as_deref() {
        Some("bind-mount") => SnapshotBackend::BindMount,
        Some("apfs") => SnapshotBackend::ApfsSnapshot,
        _ => SnapshotBackend::Copy,
    }
}

/// Take a snapshot of `src` into `<per_repo_dir>/snapshots/<run_id>/`
/// using `backend`. Returns the populated [`IngestedRepo`] with a
/// cleanup hook that removes the snapshot at drop time.
pub async fn ingest_local_with_backend(
    name: &str,
    src: &Path,
    per_repo_dir: &Path,
    run_id: &str,
    backend: SnapshotBackend,
) -> Result<IngestedRepo, IngestError> {
    if !src.exists() {
        return Err(IngestError::LocalPathMissing {
            name: name.to_string(),
            path: src.to_path_buf(),
        });
    }
    if !src.is_dir() {
        return Err(IngestError::LocalPathNotDir {
            name: name.to_string(),
            path: src.to_path_buf(),
        });
    }
    let snapshots = per_repo_dir.join(SNAPSHOTS_SUBDIR);
    std::fs::create_dir_all(&snapshots).map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: snapshots.clone(),
        source: e,
    })?;
    let snapshot_dir = snapshots.join(run_id);
    if snapshot_dir.exists() {
        force_remove_dir(&snapshot_dir).map_err(|e| IngestError::Io {
            name: name.to_string(),
            path: snapshot_dir.clone(),
            source: e,
        })?;
    }

    let chosen = match backend {
        SnapshotBackend::Copy => take_copy_snapshot(name, src, &snapshot_dir)?,
        SnapshotBackend::BindMount => take_bind_mount(name, src, &snapshot_dir)?,
        SnapshotBackend::ApfsSnapshot => take_apfs_snapshot(name, src, &snapshot_dir)?,
    };

    let on_disk_git_remote = read_local_git_remote(&snapshot_dir);

    let mut ingested = IngestedRepo {
        name: name.to_string(),
        workspace: snapshot_dir.clone(),
        source: RepoSource::LocalPath { path: src.to_path_buf() },
        snapshot_backend: Some(chosen),
        on_disk_git_remote,
        cleanup: None,
    };
    install_snapshot_cleanup(&mut ingested, snapshot_dir);
    Ok(ingested)
}

fn take_copy_snapshot(name: &str, src: &Path, dst: &Path) -> Result<SnapshotBackend, IngestError> {
    std::fs::create_dir_all(dst).map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: dst.to_path_buf(),
        source: e,
    })?;
    copy_recursive(src, dst).map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: dst.to_path_buf(),
        source: e,
    })?;
    chmod_minus_w_recursive(dst).map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: dst.to_path_buf(),
        source: e,
    })?;
    Ok(SnapshotBackend::Copy)
}

#[cfg(target_os = "linux")]
fn take_bind_mount(name: &str, src: &Path, dst: &Path) -> Result<SnapshotBackend, IngestError> {
    std::fs::create_dir_all(dst).map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: dst.to_path_buf(),
        source: e,
    })?;
    run_blocking(
        name,
        std::process::Command::new("mount").args(["--bind", "-o", "ro"]).arg(src).arg(dst),
    )?;
    Ok(SnapshotBackend::BindMount)
}

#[cfg(not(target_os = "linux"))]
fn take_bind_mount(name: &str, _src: &Path, _dst: &Path) -> Result<SnapshotBackend, IngestError> {
    Err(IngestError::Git {
        name: name.to_string(),
        message: "bind-mount snapshot backend is only available on Linux".to_string(),
    })
}

#[cfg(target_os = "macos")]
fn take_apfs_snapshot(
    name: &str,
    _src: &Path,
    _dst: &Path,
) -> Result<SnapshotBackend, IngestError> {
    // tmutil creates a volume-wide snapshot; mounting that snapshot as a
    // bind under a specific source path requires `mount_apfs -s` plus
    // root. Wiring the full sequence is gated on the operator opting in
    // by running the daemon with elevated privileges, which the MVP
    // does not require. For now we surface a clear error so the caller
    // falls back to `Copy`.
    Err(IngestError::Git {
        name: name.to_string(),
        message: "APFS snapshot backend requires root + mount_apfs wiring; \
                  unset NYX_SNAPSHOT_BACKEND to fall back to copy"
            .to_string(),
    })
}

#[cfg(not(target_os = "macos"))]
fn take_apfs_snapshot(
    name: &str,
    _src: &Path,
    _dst: &Path,
) -> Result<SnapshotBackend, IngestError> {
    Err(IngestError::Git {
        name: name.to_string(),
        message: "APFS snapshot backend is only available on macOS".to_string(),
    })
}

#[cfg(target_os = "linux")]
fn run_blocking(name: &str, cmd: &mut std::process::Command) -> Result<(), IngestError> {
    let output = cmd.output().map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: PathBuf::from("<snapshot-backend>"),
        source: e,
    })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(IngestError::Git {
            name: name.to_string(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn copy_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let src_child = entry.path();
        let dst_child = dst.join(entry.file_name());
        if ft.is_symlink() {
            let target = std::fs::read_link(&src_child)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_child)?;
            #[cfg(not(unix))]
            {
                let _ = target;
                std::fs::write(&dst_child, b"")?;
            }
        } else if ft.is_dir() {
            copy_recursive(&src_child, &dst_child)?;
        } else {
            std::fs::copy(&src_child, &dst_child)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn chmod_minus_w_recursive(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(path: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                walk(&entry?.path(), files, dirs)?;
            }
            dirs.push(path.to_path_buf());
        } else {
            files.push(path.to_path_buf());
        }
        Ok(())
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    walk(root, &mut files, &mut dirs)?;
    for f in files {
        let mut perms = std::fs::metadata(&f)?.permissions();
        let mode = perms.mode() & !0o222;
        perms.set_mode(mode);
        std::fs::set_permissions(&f, perms)?;
    }
    // Dirs are not stripped of write because that would block the
    // post-run cleanup of the snapshot tree. The point of the
    // read-only treatment is to keep `nyx scan` from accidentally
    // mutating sources, which is satisfied by read-only files.
    Ok(())
}

#[cfg(not(unix))]
fn chmod_minus_w_recursive(root: &Path) -> std::io::Result<()> {
    fn walk(path: &Path) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                walk(&entry?.path())?;
            }
        } else {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
    walk(root)
}

/// Recursively remove a directory whose contents may have been marked
/// read-only by [`chmod_minus_w_recursive`]. Restores write permission
/// before delegating to `std::fs::remove_dir_all` so the unlink does
/// not fail on platforms where read-only files are protected.
pub fn force_remove_dir(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    restore_writable_recursive(path)?;
    std::fs::remove_dir_all(path)
}

#[cfg(unix)]
fn restore_writable_recursive(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o700);
        let _ = std::fs::set_permissions(root, perms);
        for entry in std::fs::read_dir(root)? {
            restore_writable_recursive(&entry?.path())?;
        }
    } else {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o200);
        let _ = std::fs::set_permissions(root, perms);
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_writable_recursive(root: &Path) -> std::io::Result<()> {
    fn walk(path: &Path) -> std::io::Result<()> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        let mut perms = meta.permissions();
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                walk(&entry?.path())?;
            }
        }
        Ok(())
    }
    walk(root)
}

fn read_local_git_remote(workspace: &Path) -> Option<String> {
    let config = workspace.join(".git").join("config");
    let raw = std::fs::read_to_string(&config).ok()?;
    let mut in_origin = false;
    for line in raw.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l.eq_ignore_ascii_case("[remote \"origin\"]");
            continue;
        }
        if in_origin {
            if let Some(rest) = l.strip_prefix("url") {
                let v = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{ingest, Repo, RepoSource};

    #[tokio::test]
    async fn local_path_snapshot_copies_tree_readonly() {
        let src = tempfile::tempdir().expect("src");
        std::fs::create_dir_all(src.path().join("sub")).expect("subdir");
        std::fs::write(src.path().join("a.txt"), b"hello").expect("write a");
        std::fs::write(src.path().join("sub").join("b.txt"), b"world").expect("write b");

        let state = tempfile::tempdir().expect("state");
        let repo = Repo {
            name: "demo".to_string(),
            source: RepoSource::LocalPath { path: src.path().to_path_buf() },
            i_own_this: true,
        };

        let ingested = ingest(&repo, state.path(), "run-1").await.expect("ingest");
        assert_eq!(ingested.snapshot_backend, Some(SnapshotBackend::Copy));
        assert!(ingested.workspace.starts_with(state.path().join("demo").join(SNAPSHOTS_SUBDIR)));
        assert_eq!(std::fs::read(ingested.workspace.join("a.txt")).expect("read"), b"hello");
        assert_eq!(
            std::fs::read(ingested.workspace.join("sub").join("b.txt")).expect("read"),
            b"world"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ingested.workspace.join("a.txt"))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o222, 0, "snapshot files must be read-only, got mode {mode:o}");
        }
    }

    #[tokio::test]
    async fn local_path_snapshot_drops_on_drop() {
        let src = tempfile::tempdir().expect("src");
        std::fs::write(src.path().join("a.txt"), b"hi").expect("write");
        let state = tempfile::tempdir().expect("state");
        let repo = Repo {
            name: "demo".to_string(),
            source: RepoSource::LocalPath { path: src.path().to_path_buf() },
            i_own_this: true,
        };
        let workspace_path = {
            let ingested = ingest(&repo, state.path(), "run-1").await.expect("ingest");
            ingested.workspace.clone()
        };
        assert!(
            !workspace_path.exists(),
            "snapshot {} must be removed at end of run",
            workspace_path.display()
        );
    }

    #[tokio::test]
    async fn local_path_missing_returns_structured_error() {
        let state = tempfile::tempdir().expect("state");
        let repo = Repo {
            name: "ghost".to_string(),
            source: RepoSource::LocalPath { path: PathBuf::from("/definitely/missing/path") },
            i_own_this: true,
        };
        let err = ingest(&repo, state.path(), "run").await.expect_err("must fail");
        assert!(matches!(err, IngestError::LocalPathMissing { .. }));
    }

    #[tokio::test]
    async fn local_path_file_target_rejected() {
        let state = tempfile::tempdir().expect("state");
        let f = state.path().join("not-a-dir.txt");
        std::fs::write(&f, b"x").expect("write");
        let repo = Repo {
            name: "wrong".to_string(),
            source: RepoSource::LocalPath { path: f.clone() },
            i_own_this: true,
        };
        let err = ingest(&repo, state.path(), "run").await.expect_err("must fail");
        assert!(matches!(err, IngestError::LocalPathNotDir { .. }));
    }

    #[tokio::test]
    async fn snapshot_surfaces_local_git_remote_when_present() {
        let src = tempfile::tempdir().expect("src");
        let git_dir = src.path().join(".git");
        std::fs::create_dir_all(&git_dir).expect("mk .git");
        std::fs::write(
            git_dir.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [remote \"origin\"]\n\turl = git@github.com:org/repo.git\n",
        )
        .expect("write config");

        let state = tempfile::tempdir().expect("state");
        let repo = Repo {
            name: "with-remote".to_string(),
            source: RepoSource::LocalPath { path: src.path().to_path_buf() },
            i_own_this: true,
        };
        let ingested = ingest(&repo, state.path(), "run-1").await.expect("ingest");
        assert_eq!(
            ingested.on_disk_git_remote.as_deref(),
            Some("git@github.com:org/repo.git"),
            "operator must see the on-disk remote to confirm ownership at first run"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn apfs_backend_errors_without_root_wiring() {
        let src = tempfile::tempdir().expect("src");
        std::fs::write(src.path().join("a.txt"), b"x").expect("write");
        let state = tempfile::tempdir().expect("state");
        let per_repo = state.path().join("demo");
        let res = ingest_local_with_backend(
            "demo",
            src.path(),
            &per_repo,
            "run-1",
            SnapshotBackend::ApfsSnapshot,
        )
        .await;
        assert!(res.is_err(), "APFS backend must error until root + mount_apfs is wired");
    }

    #[test]
    fn select_backend_honours_env_override() {
        // SAFETY: cargo runs each test binary single-threaded under nextest;
        // even with default test threading, this var is short-lived and
        // the assertions read it synchronously.
        std::env::set_var("NYX_SNAPSHOT_BACKEND", "bind-mount");
        assert_eq!(select_backend(), SnapshotBackend::BindMount);
        std::env::set_var("NYX_SNAPSHOT_BACKEND", "apfs");
        assert_eq!(select_backend(), SnapshotBackend::ApfsSnapshot);
        std::env::set_var("NYX_SNAPSHOT_BACKEND", "copy");
        assert_eq!(select_backend(), SnapshotBackend::Copy);
        std::env::remove_var("NYX_SNAPSHOT_BACKEND");
        assert_eq!(select_backend(), SnapshotBackend::Copy);
    }
}

//! Workspace snapshot setup for sandboxed runs.
//!
//! The sandboxed child must not mutate the source-of-truth workspace
//! checkout; every run gets its own copy. Where the OS supports
//! copy-on-write at the filesystem layer we use it (macOS APFS
//! `clonefile(2)` and Linux btrfs/xfs `FICLONE`), falling back to
//! `std::fs::copy` everywhere else.
//!
//! The fallback path is recursive: it walks the source tree, recreates
//! the directory structure, and copies regular files. Symlinks are
//! reproduced as symlinks (not followed) so a symlink pointing outside
//! the workspace stays an unreachable pointer rather than getting
//! materialised into a real file under the snapshot.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// How the snapshot was produced. Returned so callers (and tests) can
/// assert that the COW fast path actually fired on supporting hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    /// `clonefile(2)` on macOS.
    Clonefile,
    /// `ioctl(FICLONE)` on Linux btrfs/xfs.
    Reflink,
    /// Plain recursive `fs::copy`.
    Copy,
}

/// Materialise `src` under `dst`. `dst` must not already exist. Returns
/// the snapshot mechanism that the implementation chose.
pub fn snapshot(src: &Path, dst: &Path) -> io::Result<SnapshotKind> {
    if dst.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("snapshot destination {} already exists", dst.display()),
        ));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(()) = clonefile(src, dst) {
            return Ok(SnapshotKind::Clonefile);
        }
    }

    #[cfg(target_os = "linux")]
    {
        match reflink_tree(src, dst) {
            Ok(()) => return Ok(SnapshotKind::Reflink),
            Err(_) => {
                // best-effort: tear down a partial reflink tree so the
                // fallback copy_tree can start clean.
                let _ = fs::remove_dir_all(dst);
            }
        }
    }

    copy_tree(src, dst)?;
    Ok(SnapshotKind::Copy)
}

/// Recursive `fs::copy` fallback. Public so the escape-fixture tests can
/// stage workspaces deterministically without going through the
/// platform-specific paths.
pub fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src)?;
        symlink(&target, dst)?;
        return Ok(());
    }
    if meta.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
        return Ok(());
    }
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            let child_src = entry.path();
            let child_dst: PathBuf = dst.join(&name);
            copy_tree(&child_src, &child_dst)?;
        }
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("unsupported file type at {}", src.display()),
    ))
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "symlinks not supported on this platform"))
}

#[cfg(target_os = "macos")]
fn clonefile(src: &Path, dst: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32)
            -> libc::c_int;
    }

    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: both pointers are valid C strings owned by this stack
    // frame; clonefile only reads them.
    let rc = unsafe { clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn reflink_tree(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src)?;
        symlink(&target, dst)?;
        return Ok(());
    }
    if meta.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        reflink_file(src, dst)?;
        return Ok(());
    }
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            reflink_tree(&entry.path(), &dst.join(&name))?;
        }
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("unsupported file type at {}", src.display()),
    ))
}

#[cfg(target_os = "linux")]
fn reflink_file(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // FICLONE = _IOW(0x94, 9, int) = 0x40049409. We hard-code rather than
    // depending on the `linux-raw-sys` crate; this ioctl number has been
    // stable since 4.5.
    const FICLONE: libc::c_ulong = 0x4004_9409;

    let src_file = fs::File::open(src)?;
    let dst_file = fs::OpenOptions::new().write(true).create_new(true).open(dst)?;

    // SAFETY: both fds remain live for the duration of the ioctl call;
    // FICLONE only reads from src and writes into dst.
    let rc = unsafe { libc::ioctl(dst_file.as_raw_fd(), FICLONE, src_file.as_raw_fd()) };
    if rc == 0 {
        // Preserve mode so the snapshot matches the source.
        let perms = src_file.metadata()?.permissions();
        fs::set_permissions(dst, perms)?;
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        // Clean up the half-written dst so the caller's fallback can
        // start fresh.
        let _ = fs::remove_file(dst);
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snapshot_materialises_file_tree() {
        let scratch = tempdir().unwrap();
        let src = scratch.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"hello").unwrap();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub").join("b.txt"), b"world").unwrap();

        let dst = scratch.path().join("snapshot");
        let kind = snapshot(&src, &dst).unwrap();
        // any backend is fine, but the operation must produce the tree.
        let _ = kind;

        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join("sub").join("b.txt")).unwrap(), b"world");
    }

    #[test]
    fn snapshot_refuses_existing_dst() {
        let scratch = tempdir().unwrap();
        let src = scratch.path().join("src");
        fs::create_dir(&src).unwrap();
        let dst = scratch.path().join("dst");
        fs::create_dir(&dst).unwrap();

        let err = snapshot(&src, &dst).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_preserves_symlinks_without_following_them() {
        let scratch = tempdir().unwrap();
        let outside = scratch.path().join("outside.txt");
        fs::write(&outside, b"sensitive").unwrap();

        let src = scratch.path().join("src");
        fs::create_dir(&src).unwrap();
        std::os::unix::fs::symlink(&outside, src.join("link")).unwrap();

        let dst = scratch.path().join("snapshot");
        snapshot(&src, &dst).unwrap();

        let meta = fs::symlink_metadata(dst.join("link")).unwrap();
        assert!(meta.file_type().is_symlink());
    }
}

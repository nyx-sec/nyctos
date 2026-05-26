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

        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join("sub").join("b.txt")).unwrap(), b"world");

        // On macOS the snapshot root lives under `tempfile::tempdir()`,
        // which is always an APFS volume on modern darwin. The
        // `clonefile(2)` fast path must fire there; a regression that
        // silently falls back to recursive `fs::copy` would be a
        // performance cliff that this assertion catches.
        #[cfg(target_os = "macos")]
        assert_eq!(
            kind,
            SnapshotKind::Clonefile,
            "macOS tempdir is APFS; clonefile(2) must succeed",
        );
        #[cfg(not(target_os = "macos"))]
        let _ = kind;
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

    // Pins the contract that whichever backend the host picks (Clonefile
    // on macOS, FICLONE reflink on Linux btrfs/xfs, or the Copy fallback
    // everywhere else) preserves the `.git` subtree. The sandbox's COW
    // snapshot is the only path through which a running repo's git
    // metadata reaches a sandboxed child; a backend that silently dropped
    // `.git` would surface as "git" calls inside the sandbox failing with
    // "not a git repository" instead of as a snapshot error.
    // Pins the FICLONE reflink fast path on a btrfs volume. Ignored by
    // default because the body requires CAP_SYS_ADMIN to run `losetup`,
    // `mkfs.btrfs`, and `mount`; the only CI lane today is unprivileged.
    // Run manually on a root shell or a self-hosted Linux runner that
    // has btrfs-progs installed:
    //
    //     sudo -E cargo test -p nyx-agent-sandbox \
    //         --test-threads=1 -- --ignored snapshot_uses_reflink_on_btrfs
    //
    // Setup tears down via a Drop guard so a panic on any assertion
    // still releases the loop device and unmounts the filesystem.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN (losetup/mkfs.btrfs/mount) and btrfs-progs"]
    fn snapshot_uses_reflink_on_btrfs() {
        use std::process::Command;

        fn run(cmd: &mut Command) -> String {
            let out = cmd.output().expect("spawn external tool");
            assert!(
                out.status.success(),
                "{:?} failed: stdout={} stderr={}",
                cmd,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        struct LoopMount {
            mountpoint: PathBuf,
            loopdev: String,
            backing: PathBuf,
        }
        impl Drop for LoopMount {
            fn drop(&mut self) {
                let _ = Command::new("umount").arg(&self.mountpoint).status();
                let _ = Command::new("losetup").arg("-d").arg(&self.loopdev).status();
                let _ = fs::remove_file(&self.backing);
                let _ = fs::remove_dir(&self.mountpoint);
            }
        }

        let scratch = tempdir().unwrap();
        let backing = scratch.path().join("btrfs.img");
        // 100 MiB sparse file is the minimum mkfs.btrfs accepts.
        {
            let f = fs::File::create(&backing).unwrap();
            f.set_len(100 * 1024 * 1024).unwrap();
        }

        let loopdev = run(Command::new("losetup").arg("--show").arg("-f").arg(&backing));
        let mountpoint = scratch.path().join("mnt");
        fs::create_dir(&mountpoint).unwrap();
        let _guard = LoopMount {
            mountpoint: mountpoint.clone(),
            loopdev: loopdev.clone(),
            backing: backing.clone(),
        };

        run(Command::new("mkfs.btrfs").arg("-f").arg(&loopdev));
        run(Command::new("mount").arg(&loopdev).arg(&mountpoint));

        let src = mountpoint.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"hello btrfs").unwrap();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub").join("b.txt"), b"world btrfs").unwrap();

        let dst = mountpoint.join("snapshot");
        let kind = snapshot(&src, &dst).expect("snapshot under btrfs mount");

        assert_eq!(
            kind,
            SnapshotKind::Reflink,
            "FICLONE must succeed on a btrfs volume; got {:?}",
            kind,
        );
        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"hello btrfs");
        assert_eq!(fs::read(dst.join("sub").join("b.txt")).unwrap(), b"world btrfs",);
    }

    #[test]
    fn snapshot_preserves_dotgit_tree() {
        let scratch = tempdir().unwrap();
        let src = scratch.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("README.md"), b"workspace").unwrap();

        let git_dir = src.join(".git");
        fs::create_dir(&git_dir).unwrap();
        fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(git_dir.join("config"), b"[core]\n\trepositoryformatversion = 0\n").unwrap();
        let refs = git_dir.join("refs").join("heads");
        fs::create_dir_all(&refs).unwrap();
        fs::write(refs.join("main"), b"deadbeefcafef00d\n").unwrap();

        let dst = scratch.path().join("snapshot");
        snapshot(&src, &dst).unwrap();

        let dst_git = dst.join(".git");
        assert!(dst_git.is_dir(), "snapshot dropped the .git directory entirely",);
        assert_eq!(fs::read(dst_git.join("HEAD")).unwrap(), b"ref: refs/heads/main\n",);
        let config = fs::read(dst_git.join("config")).unwrap();
        assert!(config.starts_with(b"[core]"));
        assert_eq!(
            fs::read(dst_git.join("refs").join("heads").join("main")).unwrap(),
            b"deadbeefcafef00d\n",
        );
    }
}

//! birdcage backend: Linux landlock + seccomp / macOS Seatbelt.
//!
//! Implementation note. The `birdcage` crate sandboxes the *current*
//! process before spawning a sandboxee. Calling it from the daemon would
//! permanently lock the daemon down, so we always go through a
//! single-purpose helper binary (`nyx-sandbox-shim`). The backend pipes
//! a JSON [`crate::shim::ShimConfig`] to the shim's stdin; the shim
//! then applies birdcage exceptions and `spawn`s the real target.
//!
//! Configuration of `allow_loopback` maps onto birdcage's
//! `Exception::Networking`, which is all-or-none: there is no
//! loopback-only carve-out at the seccomp/Seatbelt layer.

use std::path::PathBuf;
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::backend::apply_snapshot_from;
use crate::backend::process::{drive_to_completion, RunningChild};
use crate::shim::ShimConfig;
use crate::{permits_loopback, BackendKind, Sandbox, SandboxError, SandboxOpts, SandboxOutcome};

const SHIM_PATH_ENV: &str = "NYX_SANDBOX_SHIM";

/// Backend wired to the `birdcage` crate via the `nyx-sandbox-shim`
/// helper. On hosts where birdcage cannot run (anything except Linux +
/// macOS), every call returns [`SandboxError::BackendUnavailable`].
pub struct BirdcageSandbox {
    shim_path: PathBuf,
    inner: Option<RunningChild>,
    last_logs: (Vec<u8>, Vec<u8>),
}

impl BirdcageSandbox {
    /// Construct a backend that locates the shim via `$NYX_SANDBOX_SHIM`
    /// or, failing that, as a sibling of `std::env::current_exe()`.
    pub fn new() -> Result<Self, SandboxError> {
        let shim_path = resolve_shim_path()?;
        Ok(Self { shim_path, inner: None, last_logs: (Vec::new(), Vec::new()) })
    }

    /// Construct a backend with an explicit shim binary path. The
    /// regression tests use this to point at the cargo-built shim.
    pub fn with_shim_path(shim_path: PathBuf) -> Self {
        Self { shim_path, inner: None, last_logs: (Vec::new(), Vec::new()) }
    }
}

impl Sandbox for BirdcageSandbox {
    fn backend(&self) -> BackendKind {
        BackendKind::Birdcage
    }

    async fn run(&mut self, mut opts: SandboxOpts) -> Result<(), SandboxError> {
        if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
            return Err(SandboxError::BackendUnavailable {
                backend: "birdcage",
                reason: "requires Linux landlock or macOS Seatbelt".into(),
            });
        }
        if self.inner.is_some() {
            return Err(SandboxError::State("a child is already running"));
        }
        if opts.argv.is_empty() {
            return Err(SandboxError::Config("argv is empty".into()));
        }
        let scratch_snapshot = apply_snapshot_from(&mut opts)?;
        if !opts.workspace.exists() {
            return Err(SandboxError::Config(format!(
                "workspace {} does not exist",
                opts.workspace.display()
            )));
        }
        if !self.shim_path.is_file() {
            return Err(SandboxError::Config(format!(
                "nyx-sandbox-shim not found at {}",
                self.shim_path.display()
            )));
        }
        if let Some(lane) = opts.lane {
            if opts.allow_loopback && !permits_loopback(lane, BackendKind::Birdcage) {
                return Err(SandboxError::Config(format!(
                    "lane policy refuses allow_loopback on {} lane with birdcage backend; \
                     birdcage cannot scope loopback any tighter than all-network-or-none",
                    lane.as_str()
                )));
            }
        }

        let program = resolve_program(&opts.argv[0])?;

        let mut allow_read: Vec<PathBuf> = opts.allow_read.clone();
        for p in default_system_read_paths() {
            allow_read.push(PathBuf::from(p));
        }
        allow_read.push(program.clone());

        let mut allow_write: Vec<PathBuf> = opts.allow_write.clone();
        allow_write.push(opts.workspace.clone());

        let cfg = ShimConfig {
            program,
            args: opts.argv.iter().skip(1).cloned().collect(),
            cwd: Some(opts.cwd.clone().unwrap_or_else(|| opts.workspace.clone())),
            env: opts.env.clone(),
            allow_read,
            allow_write,
            allow_env: opts.env.iter().map(|(k, _)| k.clone()).collect(),
            allow_network: opts.allow_loopback,
            write_status_fd: true,
        };
        let cfg_json = serde_json::to_vec(&cfg)
            .map_err(|e| SandboxError::Config(format!("serialise shim config: {e}")))?;

        let mut cmd = Command::new(&self.shim_path);
        cmd.env_clear();
        // The shim itself needs PATH to resolve dyld libraries on
        // macOS and ld.so on Linux; preserve a minimal subset.
        for k in ["PATH", "HOME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        // Out-of-band status pipe: the shim collapses signal-killed
        // sandboxees into the 128+signum exit-code convention, so the
        // parent cannot recover `SandboxStatus::Signaled(sig)` from the
        // shim's own ExitStatus. We allocate a pipe, dup2 the write end
        // to fd 3 in the shim's pre_exec, then close our copy of the
        // write end. The shim writes a JSON `ShimStatus` frame to fd 3
        // after wait, and the parent reads the read end in
        // `drive_to_completion`. Status reporting is unix-only because
        // birdcage itself only runs on linux/macos.
        #[cfg(unix)]
        let (mut child, status_read_fd) = {
            use std::os::fd::{FromRawFd, OwnedFd};

            let (read_fd, write_fd) = unsafe { open_status_pipe()? };
            unsafe {
                cmd.pre_exec(move || {
                    // Move write end onto fd 3 so the shim has a stable
                    // place to write. dup2 clears CLOEXEC on the new fd
                    // (so it survives the shim's own exec from the fork);
                    // we leave it that way so the shim retains fd 3
                    // through its lifetime. The shim's own pre_exec for
                    // the sandboxee closes fd 3 so the sandboxee cannot
                    // forge a status frame.
                    //
                    // SAFETY: dup2 / close are async-signal-safe.
                    if libc::dup2(write_fd, 3) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if write_fd != 3 {
                        libc::close(write_fd);
                    }
                    Ok(())
                });
            }
            // Wrap the read end now so it is closed on any error path
            // before spawn.
            let read = unsafe { OwnedFd::from_raw_fd(read_fd) };

            let spawned = cmd.spawn().map_err(SandboxError::Spawn);
            // Whether the spawn succeeded or failed, our copy of the
            // write end is no longer useful here. On success the shim
            // owns its dup'd fd 3; on failure no shim ever ran but the
            // write end still needs closing so we do not leak it.
            unsafe { libc::close(write_fd) };
            let child = spawned?;
            (child, read)
        };
        #[cfg(not(unix))]
        let mut child = cmd.spawn().map_err(SandboxError::Spawn)?;

        // Write the JSON config to the shim's stdin, then close it so
        // the shim's `read_to_string` returns.
        {
            let mut stdin =
                child.stdin.take().ok_or(SandboxError::State("shim stdin unavailable"))?;
            stdin.write_all(&cfg_json).await.map_err(SandboxError::Io)?;
            stdin.shutdown().await.map_err(SandboxError::Io)?;
        }

        self.inner = Some(RunningChild {
            child,
            started_at: Instant::now(),
            timeout: opts.timeout,
            max_output_bytes: opts.max_output_bytes,
            killed_by_operator: false,
            #[cfg(unix)]
            status_fd: Some(status_read_fd),
            scratch_snapshot,
        });
        Ok(())
    }

    async fn kill(&mut self) -> Result<(), SandboxError> {
        if let Some(state) = self.inner.as_mut() {
            state.killed_by_operator = true;
            // The shim calls setsid() at startup so it is its own pgrp
            // leader; killpg(shim_pid, SIGKILL) reaps the shim AND the
            // sandboxee in one syscall. This is the macOS-portable kill
            // path (PR_SET_PDEATHSIG does not exist on Darwin) and is
            // additive to the Linux PDEATHSIG fallback. If setsid has
            // not completed yet (tiny window between fork+exec and the
            // shim's first instruction), no pgrp with this pgid exists
            // and killpg returns ESRCH; we then fall through to
            // start_kill on the shim alone (no sandboxee has been
            // spawned yet in that window, so nothing to leak).
            #[cfg(unix)]
            if let Some(pid) = state.child.id() {
                let ret = unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) };
                if ret == 0 {
                    return Ok(());
                }
            }
            let _ = state.child.start_kill();
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError> {
        let mut state = self.inner.take().ok_or(SandboxError::State("no child to wait on"))?;
        let outcome = drive_to_completion(&mut state, BackendKind::Birdcage).await?;
        self.last_logs = (outcome.stdout.clone(), outcome.stderr.clone());
        Ok(outcome)
    }

    fn logs(&self) -> (&[u8], &[u8]) {
        (&self.last_logs.0, &self.last_logs.1)
    }
}

fn resolve_shim_path() -> Result<PathBuf, SandboxError> {
    if let Some(env) = std::env::var_os(SHIM_PATH_ENV) {
        return Ok(PathBuf::from(env));
    }
    let current = std::env::current_exe().map_err(SandboxError::Io)?;
    if let Some(dir) = current.parent() {
        let candidate = dir.join("nyx-sandbox-shim");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(SandboxError::Config(format!(
        "nyx-sandbox-shim not found via ${SHIM_PATH_ENV} or alongside current_exe"
    )))
}

fn resolve_program(arg: &str) -> Result<PathBuf, SandboxError> {
    let p = PathBuf::from(arg);
    if p.is_absolute() {
        if p.is_file() {
            return Ok(p);
        }
        return Err(SandboxError::Config(format!("program {arg} does not exist")));
    }
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let candidate = dir.join(&p);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(SandboxError::Config(format!("program {arg} not found on PATH")))
}

/// Open an anonymous pipe and return `(read_fd, write_fd)` raw file
/// descriptors. The read end is marked `FD_CLOEXEC` so it does not
/// leak into the forked shim child; the write end is intentionally
/// inheritable so `pre_exec` can `dup2` it onto fd 3 before the shim
/// exec runs.
///
/// # Safety
///
/// Calls `pipe` and `fcntl` which are async-signal-safe and have no
/// preconditions beyond a valid pointer for `pipe`'s out array.
#[cfg(unix)]
unsafe fn open_status_pipe() -> Result<(libc::c_int, libc::c_int), SandboxError> {
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    let read_fd = fds[0];
    let write_fd = fds[1];
    if libc::fcntl(read_fd, libc::F_SETFD, libc::FD_CLOEXEC) == -1 {
        let err = std::io::Error::last_os_error();
        libc::close(read_fd);
        libc::close(write_fd);
        return Err(SandboxError::Io(err));
    }
    Ok((read_fd, write_fd))
}

fn default_system_read_paths() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        &[
            "/bin",
            "/sbin",
            "/usr",
            "/lib",
            "/lib64",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/alternatives",
            "/etc/nsswitch.conf",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/proc/self",
            "/proc/sys/kernel/version",
            "/dev/null",
            "/dev/urandom",
            "/dev/random",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            "/bin",
            "/sbin",
            "/usr",
            "/System",
            "/Library",
            "/private/etc",
            "/private/var/db/dyld",
            "/private/var/db/timezone",
            "/dev/null",
            "/dev/urandom",
            "/dev/random",
        ]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Lane;
    use std::path::Path;
    use tempfile::tempdir;

    fn fast_lane_loopback_opts(workspace: &Path, shim_path: &Path) -> SandboxOpts {
        let mut opts = SandboxOpts::new(workspace.to_path_buf(), vec!["/bin/true".into()]);
        opts.allow_loopback = true;
        opts.lane = Some(Lane::Fast);
        // The lane gate fires before the shim path is exec'd; passing
        // any path here just gets us past the shim-missing branch.
        let _ = shim_path;
        opts
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn fast_lane_birdcage_refuses_allow_loopback() {
        let scratch = tempdir().expect("tempdir");
        // Create a dummy shim file so the shim-not-found branch is
        // skipped and we exercise the lane gate immediately after.
        let shim = scratch.path().join("nyx-sandbox-shim-stub");
        std::fs::write(&shim, b"#!/bin/sh\nexit 0\n").expect("write stub");
        let mut sb = BirdcageSandbox::with_shim_path(shim.clone());
        let opts = fast_lane_loopback_opts(scratch.path(), &shim);
        let err = sb.run(opts).await.expect_err("fast-lane loopback must refuse");
        match err {
            SandboxError::Config(reason) => {
                assert!(reason.contains("fast lane"), "reason must name the lane: {reason}");
                assert!(reason.contains("loopback"), "reason must name the flag: {reason}");
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }
}

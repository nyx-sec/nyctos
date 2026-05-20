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

use crate::backend::process::{drive_to_completion, RunningChild};
use crate::shim::ShimConfig;
use crate::{BackendKind, Sandbox, SandboxError, SandboxOpts, SandboxOutcome};

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

    async fn run(&mut self, opts: SandboxOpts) -> Result<(), SandboxError> {
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

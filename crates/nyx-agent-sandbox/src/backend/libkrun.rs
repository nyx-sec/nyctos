//! libkrun backend: macOS-first microVM via libkrun + HVF.
//!
//! libkrun is a lightweight VMM (https://github.com/containers/libkrun)
//! that boots a kernel under macOS Hypervisor.framework or Linux KVM.
//! On macOS it is the strongest isolation tier we ship — birdcage's
//! Seatbelt sandboxes only the calling process, while libkrun gives the
//! sandboxee a separate kernel and a private FS namespace via virtio-fs.
//!
//! Phase 21 wires the backend selection + invocation skeleton:
//!
//! * Construction probes for `libkrun-runner` on `$PATH` (or
//!   `$NYX_LIBKRUN_RUNNER` for tests). The runner is a thin helper
//!   binary that owns the `libkrun_sys` FFI surface; the agent shells
//!   out to it so dyld errors / unresolved symbols cannot crash the
//!   daemon.
//! * `run` materialises a `LibkrunSpec` JSON describing the workspace
//!   to virtio-fs export, the optional env image to attach as a block
//!   device, the boot kernel/initrd hint, argv, env, and timeout. The
//!   helper boots a fresh microVM per call, execs the target inside,
//!   and prints captured stdout/stderr on the parent's pipes.
//!
//! The full VM boot is owned by `libkrun-runner` — out of scope for
//! Phase 21 source. The acceptance test "on macOS with libkrun
//! installed, a chain-lane run boots a microVM with the customer's
//! compose env inside" requires the helper to be present; without it,
//! [`LibkrunSandbox::new`] returns [`SandboxError::BackendUnavailable`].

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::backend::process::{drive_to_completion, RunningChild};
use crate::{BackendKind, Sandbox, SandboxError, SandboxOpts, SandboxOutcome};

const RUNNER_PATH_ENV: &str = "NYX_LIBKRUN_RUNNER";
const RUNNER_BINARY: &str = "libkrun-runner";

/// Backend wired to a `libkrun-runner` helper binary. The helper owns
/// the `libkrun_sys` FFI; the agent feeds it a JSON spec on stdin and
/// reads the captured guest stdio on stdout/stderr.
pub struct LibkrunSandbox {
    runner_path: PathBuf,
    env_image: Option<PathBuf>,
    inner: Option<RunningChild>,
    last_logs: (Vec<u8>, Vec<u8>),
}

/// Spec piped to `libkrun-runner` on stdin. The helper boots a fresh
/// microVM per invocation.
#[derive(Debug, Clone, Serialize)]
pub struct LibkrunSpec {
    /// Workspace exported into the guest via virtio-fs at `/workspace`.
    pub workspace: PathBuf,
    /// Optional disk image attached as a block device. Holds the
    /// chain-lane env (docker-compose-merged rootfs). When `None`, the
    /// guest gets only the workspace export.
    pub env_image: Option<PathBuf>,
    /// argv to exec inside the guest. `argv[0]` resolves against the
    /// guest's `$PATH` unless absolute.
    pub argv: Vec<String>,
    /// Working directory inside the guest. Defaults to `/workspace`.
    pub cwd: Option<PathBuf>,
    /// Environment passed to the guest exec. The guest's `env` is not
    /// inherited from the host.
    pub env: Vec<(String, String)>,
    /// Wall-clock cap; the runner SIGKILLs the guest and exits non-zero
    /// when the deadline trips.
    pub timeout_secs: u64,
    /// Whether to attach a tap device for loopback connectivity. False
    /// gives the guest a host-isolated network namespace.
    pub allow_loopback: bool,
    /// Cap captured stdout/stderr at this many bytes each.
    pub max_output_bytes: usize,
}

impl LibkrunSandbox {
    /// Construct a backend that locates `libkrun-runner` via
    /// `$NYX_LIBKRUN_RUNNER`, then by `$PATH`. Returns
    /// [`SandboxError::BackendUnavailable`] when neither resolves.
    pub fn new() -> Result<Self, SandboxError> {
        let runner_path = resolve_runner_path()?;
        Ok(Self {
            runner_path,
            env_image: None,
            inner: None,
            last_logs: (Vec::new(), Vec::new()),
        })
    }

    /// Construct a backend with an explicit runner path. Used by tests
    /// that script `libkrun-runner` with a deterministic fixture.
    pub fn with_runner_path(runner_path: PathBuf) -> Self {
        Self {
            runner_path,
            env_image: None,
            inner: None,
            last_logs: (Vec::new(), Vec::new()),
        }
    }

    /// Attach a built env image (e.g. the chain-lane's merged
    /// docker-compose rootfs) for the next `run`. Persists across runs
    /// until cleared.
    pub fn with_env_image(mut self, env_image: PathBuf) -> Self {
        self.env_image = Some(env_image);
        self
    }

    /// Path the backend will exec.
    pub fn runner_path(&self) -> &Path {
        &self.runner_path
    }
}

impl Sandbox for LibkrunSandbox {
    fn backend(&self) -> BackendKind {
        BackendKind::Libkrun
    }

    async fn run(&mut self, opts: SandboxOpts) -> Result<(), SandboxError> {
        if !libkrun_host_supported() {
            return Err(SandboxError::BackendUnavailable {
                backend: "libkrun",
                reason: "requires macOS with Hypervisor.framework or Linux with KVM".into(),
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
        if !self.runner_path.is_file() {
            return Err(SandboxError::Config(format!(
                "{RUNNER_BINARY} not found at {}",
                self.runner_path.display()
            )));
        }
        if let Some(img) = &self.env_image {
            if !img.exists() {
                return Err(SandboxError::Config(format!(
                    "libkrun env image {} does not exist",
                    img.display()
                )));
            }
        }

        let spec = LibkrunSpec {
            workspace: opts.workspace.clone(),
            env_image: self.env_image.clone(),
            argv: opts.argv.clone(),
            cwd: opts.cwd.clone(),
            env: opts.env.clone(),
            timeout_secs: opts.timeout.as_secs(),
            allow_loopback: opts.allow_loopback,
            max_output_bytes: opts.max_output_bytes,
        };
        let spec_json = serde_json::to_vec(&spec)
            .map_err(|e| SandboxError::Config(format!("serialise libkrun spec: {e}")))?;

        let mut cmd = Command::new(&self.runner_path);
        cmd.env_clear();
        // libkrun-runner needs the host's PATH (to resolve dyld libs on
        // macOS) plus HOME for any per-user runtime caches; nothing else
        // is inherited.
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
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(SandboxError::State("libkrun-runner stdin unavailable"))?;
            stdin
                .write_all(&spec_json)
                .await
                .map_err(SandboxError::Io)?;
            stdin.shutdown().await.map_err(SandboxError::Io)?;
        }

        self.inner = Some(RunningChild {
            child,
            started_at: Instant::now(),
            timeout: opts.timeout,
            max_output_bytes: opts.max_output_bytes,
        });
        Ok(())
    }

    async fn kill(&mut self) -> Result<(), SandboxError> {
        if let Some(state) = self.inner.as_mut() {
            let _ = state.child.start_kill();
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError> {
        let mut state = self
            .inner
            .take()
            .ok_or(SandboxError::State("no child to wait on"))?;
        let outcome = drive_to_completion(&mut state, BackendKind::Libkrun).await?;
        self.last_logs = (outcome.stdout.clone(), outcome.stderr.clone());
        Ok(outcome)
    }

    fn logs(&self) -> (&[u8], &[u8]) {
        (&self.last_logs.0, &self.last_logs.1)
    }
}

/// True if the host *kernel surface* libkrun needs is present. The
/// final readiness check (helper binary + image) is enforced by
/// [`LibkrunSandbox::new`] / `run`; this only gates "could libkrun in
/// principle launch a microVM here".
pub fn libkrun_host_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        // Every Apple-silicon and recent Intel mac ships HVF; the only
        // failure mode would be a stripped-down macOS install. Treat as
        // supported and let the runner produce the canonical error if
        // HVF is unavailable.
        true
    }
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/kvm").exists()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn resolve_runner_path() -> Result<PathBuf, SandboxError> {
    if let Some(env) = std::env::var_os(RUNNER_PATH_ENV) {
        let p = PathBuf::from(env);
        if p.is_file() {
            return Ok(p);
        }
        return Err(SandboxError::BackendUnavailable {
            backend: "libkrun",
            reason: format!("${RUNNER_PATH_ENV}={} is not a file", p.display()),
        });
    }
    if let Some(p) = which_on_path(RUNNER_BINARY) {
        return Ok(p);
    }
    Err(SandboxError::BackendUnavailable {
        backend: "libkrun",
        reason: format!("{RUNNER_BINARY} not found via ${RUNNER_PATH_ENV} or PATH"),
    })
}

fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_serialises_round_trip() {
        let spec = LibkrunSpec {
            workspace: PathBuf::from("/tmp/ws"),
            env_image: Some(PathBuf::from("/tmp/env.img")),
            argv: vec!["python3".into(), "harness.py".into()],
            cwd: None,
            env: vec![("RUN_ID".into(), "abc".into())],
            timeout_secs: 30,
            allow_loopback: false,
            max_output_bytes: 1 << 20,
        };
        let json = serde_json::to_string(&spec).expect("ser");
        assert!(json.contains("/tmp/ws"));
        assert!(json.contains("/tmp/env.img"));
        assert!(json.contains("RUN_ID"));
    }

    #[test]
    fn missing_runner_returns_backend_unavailable() {
        // Clear env override to a path we know does not exist so the
        // resolver hits its env-set-but-missing branch.
        std::env::set_var(RUNNER_PATH_ENV, "/definitely/does/not/exist/libkrun-runner");
        let result = LibkrunSandbox::new();
        std::env::remove_var(RUNNER_PATH_ENV);
        match result {
            Err(SandboxError::BackendUnavailable { backend, .. }) => {
                assert_eq!(backend, "libkrun");
            }
            Err(other) => panic!("expected BackendUnavailable, got {other:?}"),
            Ok(_) => panic!("must fail when env-pointed runner is missing"),
        }
    }
}

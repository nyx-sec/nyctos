//! Firecracker backend: Linux+KVM microVM via a thin `nyx-fc-runner`
//! subprocess.
//!
//! Firecracker (https://github.com/firecracker-microvm/firecracker) is
//! AWS's minimal VMM, built on top of KVM. It boots a guest kernel +
//! rootfs in tens of milliseconds and isolates the sandboxee in a
//! separate kernel, network namespace, and devices set.
//!
//! Agent-side selection + invocation skeleton. The real boot path
//! lives in a separate `nyx-fc-runner` helper binary (out-of-tree;
//! the established skeleton is the one nyx-engine already vendors and
//! we shell out to avoid pulling its source into nyctos's build
//! graph). The backend feeds the runner a JSON spec on stdin and
//! reads captured guest stdio on stdout/stderr.
//!
//! On hosts without `/dev/kvm` or without `nyx-fc-runner`, every call
//! returns [`SandboxError::BackendUnavailable`] with a structured
//! reason the doctor surfaces.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::backend::process::{drive_to_completion, RunningChild};
use crate::{BackendKind, Sandbox, SandboxError, SandboxOpts, SandboxOutcome};

const RUNNER_PATH_ENV: &str = "NYX_FC_RUNNER";
const RUNNER_BINARY: &str = "nyx-fc-runner";

/// Backend wired to a `nyx-fc-runner` helper binary. The helper owns
/// the Firecracker API socket lifecycle and the JSON config the VMM
/// consumes.
pub struct FirecrackerSandbox {
    runner_path: PathBuf,
    env_image: Option<PathBuf>,
    kernel: Option<PathBuf>,
    inner: Option<RunningChild>,
    last_logs: (Vec<u8>, Vec<u8>),
}

/// Spec piped to `nyx-fc-runner` on stdin. The helper synthesises the
/// Firecracker API requests from the fields here.
#[derive(Debug, Clone, Serialize)]
pub struct FirecrackerSpec {
    /// Workspace exported to the guest. The runner sets up a
    /// virtio-fs / virtio-vsock channel so the guest can read it.
    pub workspace: PathBuf,
    /// Rootfs / env image bound to the guest as a block device. The
    /// chain-lane builds this from the merged docker-compose env.
    pub env_image: Option<PathBuf>,
    /// Boot kernel (uncompressed). When `None` the runner picks the
    /// default kernel it ships with.
    pub kernel: Option<PathBuf>,
    /// argv inside the guest.
    pub argv: Vec<String>,
    /// Working directory inside the guest. Defaults to `/workspace`.
    pub cwd: Option<PathBuf>,
    /// Guest environment. Host env is not inherited.
    pub env: Vec<(String, String)>,
    /// Wall-clock cap; the runner SIGKILLs the guest if exceeded.
    pub timeout_secs: u64,
    /// Attach a tap device for loopback connectivity. Mapped onto a
    /// per-VM bridge so the host network is not exposed.
    pub allow_loopback: bool,
    /// Cap captured stdout/stderr at this many bytes each.
    pub max_output_bytes: usize,
}

impl FirecrackerSandbox {
    /// Construct a backend that locates `nyx-fc-runner` via
    /// `$NYX_FC_RUNNER`, then by `$PATH`. Returns
    /// [`SandboxError::BackendUnavailable`] when neither resolves or
    /// when `/dev/kvm` is missing.
    pub fn new() -> Result<Self, SandboxError> {
        if !firecracker_host_supported() {
            return Err(SandboxError::BackendUnavailable {
                backend: "firecracker",
                reason: "requires Linux with /dev/kvm".into(),
            });
        }
        let runner_path = resolve_runner_path()?;
        Ok(Self {
            runner_path,
            env_image: None,
            kernel: None,
            inner: None,
            last_logs: (Vec::new(), Vec::new()),
        })
    }

    /// Construct with an explicit runner path. Used by tests that
    /// script `nyx-fc-runner` with a deterministic fixture.
    pub fn with_runner_path(runner_path: PathBuf) -> Self {
        Self {
            runner_path,
            env_image: None,
            kernel: None,
            inner: None,
            last_logs: (Vec::new(), Vec::new()),
        }
    }

    /// Attach a built env image (the chain-lane's merged
    /// docker-compose rootfs) for the next `run`. Persists across runs
    /// until cleared.
    pub fn with_env_image(mut self, env_image: PathBuf) -> Self {
        self.env_image = Some(env_image);
        self
    }

    /// Override the guest kernel for the next `run`.
    pub fn with_kernel(mut self, kernel: PathBuf) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Path the backend will exec.
    pub fn runner_path(&self) -> &Path {
        &self.runner_path
    }
}

impl Sandbox for FirecrackerSandbox {
    fn backend(&self) -> BackendKind {
        BackendKind::Firecracker
    }

    async fn run(&mut self, opts: SandboxOpts) -> Result<(), SandboxError> {
        if !firecracker_host_supported() {
            return Err(SandboxError::BackendUnavailable {
                backend: "firecracker",
                reason: "requires Linux with /dev/kvm".into(),
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
                    "firecracker env image {} does not exist",
                    img.display()
                )));
            }
        }
        if let Some(k) = &self.kernel {
            if !k.exists() {
                return Err(SandboxError::Config(format!(
                    "firecracker kernel {} does not exist",
                    k.display()
                )));
            }
        }

        let spec = FirecrackerSpec {
            workspace: opts.workspace.clone(),
            env_image: self.env_image.clone(),
            kernel: self.kernel.clone(),
            argv: opts.argv.clone(),
            cwd: opts.cwd.clone(),
            env: opts.env.clone(),
            timeout_secs: opts.timeout.as_secs(),
            allow_loopback: opts.allow_loopback,
            max_output_bytes: opts.max_output_bytes,
        };
        let spec_json = serde_json::to_vec(&spec)
            .map_err(|e| SandboxError::Config(format!("serialise firecracker spec: {e}")))?;

        let mut cmd = Command::new(&self.runner_path);
        cmd.env_clear();
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
            let mut stdin =
                child.stdin.take().ok_or(SandboxError::State("nyx-fc-runner stdin unavailable"))?;
            stdin.write_all(&spec_json).await.map_err(SandboxError::Io)?;
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
            let _ = state.child.start_kill();
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError> {
        let mut state = self.inner.take().ok_or(SandboxError::State("no child to wait on"))?;
        let outcome = drive_to_completion(&mut state, BackendKind::Firecracker).await?;
        self.last_logs = (outcome.stdout.clone(), outcome.stderr.clone());
        Ok(outcome)
    }

    fn logs(&self) -> (&[u8], &[u8]) {
        (&self.last_logs.0, &self.last_logs.1)
    }
}

/// True if the host kernel surface Firecracker needs is present.
pub fn firecracker_host_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/kvm").exists()
    }
    #[cfg(not(target_os = "linux"))]
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
            backend: "firecracker",
            reason: format!("${RUNNER_PATH_ENV}={} is not a file", p.display()),
        });
    }
    if let Some(p) = super::which_on_path(RUNNER_BINARY) {
        return Ok(p);
    }
    Err(SandboxError::BackendUnavailable {
        backend: "firecracker",
        reason: format!("{RUNNER_BINARY} not found via ${RUNNER_PATH_ENV} or PATH"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_serialises_round_trip() {
        let spec = FirecrackerSpec {
            workspace: PathBuf::from("/tmp/ws"),
            env_image: Some(PathBuf::from("/srv/env.ext4")),
            kernel: None,
            argv: vec!["python3".into(), "harness.py".into()],
            cwd: None,
            env: vec![("RUN_ID".into(), "abc".into())],
            timeout_secs: 30,
            allow_loopback: false,
            max_output_bytes: 1 << 20,
        };
        let json = serde_json::to_string(&spec).expect("ser");
        assert!(json.contains("/tmp/ws"));
        assert!(json.contains("/srv/env.ext4"));
        assert!(json.contains("RUN_ID"));
    }
}

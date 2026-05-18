//! Sandbox layer. Each backend isolates a single short-lived child process
//! that runs an agent task (a dynamic verify, a payload-runner, an ai-tool
//! call). The trait stays independent of every other nyx-agent crate so a
//! future VM backend can ship without dragging core/api/ai changes along.
//!
//! Two backends ship in this phase:
//!
//! * `process` — fork+exec with no isolation upgrade. The unhardened
//!   default used when an operator picks the `process` backend, or when
//!   the host kernel cannot support `birdcage`.
//! * `birdcage` — wraps the `birdcage` crate, which compiles to Linux
//!   landlock + seccomp or macOS Seatbelt. FS deny-by-default plus a
//!   single workspace-write exception; network deny unless
//!   [`SandboxOpts::allow_loopback`] is set.
//!
//! Chain-lane VM backends (libkrun, Firecracker) land in Phase 21.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

pub mod backend;
pub mod payload_runner;
pub mod shim;
pub mod workspace;

pub use backend::birdcage::BirdcageSandbox;
pub use backend::process::ProcessSandbox;
pub use payload_runner::{
    HarnessSource, HarnessSpecInput, PayloadRun, PayloadRunner, PayloadRunnerError,
};

/// Which backend produced (or is about to produce) a [`SandboxOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// `fork`/`exec` only; no kernel isolation upgrade.
    Process,
    /// Landlock+seccomp on Linux, Seatbelt on macOS.
    Birdcage,
}

impl BackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendKind::Process => "process",
            BackendKind::Birdcage => "birdcage",
        }
    }
}

/// Options for a single sandboxed child.
#[derive(Debug, Clone)]
pub struct SandboxOpts {
    /// Path the child can read and write. Must already exist.
    pub workspace: PathBuf,
    /// `argv[0]` plus arguments. `argv[0]` is the program to exec.
    pub argv: Vec<String>,
    /// Working directory. Defaults to `workspace`.
    pub cwd: Option<PathBuf>,
    /// Environment variables passed to the child. The parent's `env` is
    /// not inherited.
    pub env: Vec<(String, String)>,
    /// Wall-clock timeout. Backends that miss it report
    /// [`SandboxStatus::TimedOut`].
    pub timeout: Duration,
    /// Allow loopback network traffic. birdcage cannot scope further than
    /// "all network or none" — when set, all egress is allowed.
    pub allow_loopback: bool,
    /// Extra read-only paths visible to the sandboxed child (defaults
    /// like `/lib`, `/usr` are added by the backend).
    pub allow_read: Vec<PathBuf>,
    /// Extra read-write paths visible to the sandboxed child (in addition
    /// to `workspace`).
    pub allow_write: Vec<PathBuf>,
    /// Cap captured stdout/stderr at this many bytes each. The child is
    /// not killed when its output exceeds the cap; further bytes are
    /// silently dropped.
    pub max_output_bytes: usize,
}

impl SandboxOpts {
    /// New options with sane defaults for a short-lived agent task.
    pub fn new(workspace: PathBuf, argv: Vec<String>) -> Self {
        Self {
            workspace,
            argv,
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_secs(30),
            allow_loopback: false,
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            max_output_bytes: 1 << 20,
        }
    }
}

/// Final state of a sandboxed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Child exited with the recorded code.
    Exited(i32),
    /// Child died from a signal (Unix only; on other platforms reported as
    /// `Exited(-1)`).
    Signaled(i32),
    /// Backend tore the child down because [`SandboxOpts::timeout`] fired.
    TimedOut,
    /// Caller invoked [`Sandbox::kill`].
    Killed,
}

impl SandboxStatus {
    /// Did the sandbox successfully contain the child? A `contained`
    /// child either failed to exec, exited non-zero, was killed by the
    /// kernel, or was torn down by the harness — anything except a clean
    /// `exit(0)`. The escape regression suite asserts this.
    pub fn contained(&self) -> bool {
        !matches!(self, SandboxStatus::Exited(0))
    }
}

/// The captured result of a single sandboxed run.
#[derive(Debug, Clone)]
pub struct SandboxOutcome {
    pub backend: BackendKind,
    pub status: SandboxStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration: Duration,
}

/// Sandbox error surface. Backend-specific failures are folded into the
/// closest matching variant so callers can program against the trait
/// without reaching for downcasts.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The backend cannot run on this host (e.g. birdcage on Windows).
    #[error("backend {backend} unavailable: {reason}")]
    BackendUnavailable {
        backend: &'static str,
        reason: String,
    },
    /// `fork`/`exec` failed before any sandbox lock was applied.
    #[error("spawn failed: {0}")]
    Spawn(#[source] std::io::Error),
    /// Workspace setup (the COW snapshot) failed.
    #[error("workspace setup failed: {0}")]
    Workspace(#[source] std::io::Error),
    /// Misconfigured opts (empty argv, non-existent workspace, etc.).
    #[error("sandbox config rejected: {0}")]
    Config(String),
    /// Caller invoked `kill`/`wait` in an order the backend cannot honour.
    #[error("invalid sandbox state: {0}")]
    State(&'static str),
    /// Generic I/O failure while running the child.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The sandbox surface used by every consumer (chain lane, payload runner,
/// dynamic verifier). Implementors own a single child at a time: call
/// [`Sandbox::run`] once, then either [`Sandbox::wait`] or
/// [`Sandbox::kill`] before another `run`.
#[allow(async_fn_in_trait)]
pub trait Sandbox: Send {
    fn backend(&self) -> BackendKind;

    /// Spawn the child described by `opts`. Returns once the kernel has
    /// accepted the new process. The child may still be sandboxing
    /// itself when this returns (birdcage runs its `lock()` in a
    /// `pre_exec` hook, so the sandbox is in place by the time the
    /// target binary's `main` runs).
    async fn run(&mut self, opts: SandboxOpts) -> Result<(), SandboxError>;

    /// SIGKILL the running child. Idempotent: calling on an already-exited
    /// child returns `Ok(())`.
    async fn kill(&mut self) -> Result<(), SandboxError>;

    /// Block until the child exits, honouring the opts.timeout passed to
    /// [`Sandbox::run`]. After this returns, [`Sandbox::logs`] yields the
    /// captured output and the backend is ready for another `run`.
    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError>;

    /// Stdout, then stderr, captured from the most recent run. Only
    /// meaningful after [`Sandbox::wait`].
    fn logs(&self) -> (&[u8], &[u8]);
}

/// Lightweight readiness probe: returns the static set of backends that
/// could run on this host. Backends that depend on optional kernel
/// features (KVM, landlock LSM) are not surfaced here — those are checked
/// at scan time.
pub fn available_backends() -> &'static [BackendKind] {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        &[BackendKind::Process, BackendKind::Birdcage]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        &[BackendKind::Process]
    }
}

/// Return `Ok(())` if `backend` can be constructed on this host, else
/// describe why it cannot. Callers use this to short-circuit a doctor
/// check or to fall back to `process`.
pub fn probe(backend: BackendKind) -> Result<(), SandboxError> {
    match backend {
        BackendKind::Process => Ok(()),
        BackendKind::Birdcage => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Err(SandboxError::BackendUnavailable {
                    backend: "birdcage",
                    reason: "requires Linux landlock or macOS Seatbelt".into(),
                })
            }
        }
    }
}

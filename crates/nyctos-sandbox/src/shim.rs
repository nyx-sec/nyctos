//! Wire format shared between [`crate::BirdcageSandbox`] and the
//! `nyx-sandbox-shim` helper binary.
//!
//! The shim cannot be invoked safely from inside the daemon process
//! (birdcage sandboxes the *current* process before spawning) so we
//! always exec a fresh shim and pass it the full sandbox configuration
//! as a single JSON blob on stdin.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_env: Vec<String>,
    pub allow_network: bool,
    /// When `true`, the shim writes a JSON [`ShimStatus`] frame to fd 3
    /// after the sandboxee exits and then closes fd 3. The parent uses
    /// this out-of-band channel to recover the sandboxee's real status
    /// (signal vs exit code) because the shim's own [`std::process::ExitCode`]
    /// collapses signal-killed children to the `128 + signum` convention
    /// (see `exit_code_from` in `nyx_sandbox_shim`). Defaults to `false`
    /// so older callers that did not allocate a status pipe still parse.
    #[serde(default)]
    pub write_status_fd: bool,
}

/// Out-of-band status frame the shim writes inside [`ShimReport`].
/// Lets the parent reconstruct `SandboxStatus::Signaled(sig)` the same
/// way `ProcessSandbox` already does via `ExitStatusExt::signal()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ShimStatus {
    /// Sandboxee exited normally with this exit code.
    Exited(i32),
    /// Sandboxee was killed by this signal number.
    Signaled(i32),
}

/// Out-of-band report the shim writes to fd 3 once, after the sandboxee
/// exits. Wraps the structured [`ShimStatus`] plus the list of birdcage
/// exception refusals collected during sandbox setup. A `refusals` line
/// is a human-readable description of an exception the shim asked
/// birdcage to honour but birdcage rejected (typical reason: the
/// allow_read path does not exist on the host, or the kernel does not
/// expose the requested seccomp filter). The parent surfaces them on
/// [`crate::SandboxOutcome::refusals`] so callers can flag a sandbox
/// whose declared exceptions did not all take effect.
///
/// The shim also emits the same refusals on stderr for older parents
/// (pre-status-fd builds) and for operators running the shim by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimReport {
    pub status: ShimStatus,
    #[serde(default)]
    pub refusals: Vec<String>,
}

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

/// Out-of-band status frame the shim writes to fd 3 after the sandboxee
/// exits. Lets the parent reconstruct `SandboxStatus::Signaled(sig)`
/// the same way `ProcessSandbox` already does via `ExitStatusExt::signal()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ShimStatus {
    /// Sandboxee exited normally with this exit code.
    Exited(i32),
    /// Sandboxee was killed by this signal number.
    Signaled(i32),
}

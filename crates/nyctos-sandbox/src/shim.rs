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
}

//! Concrete [`crate::Sandbox`] implementations.

pub mod birdcage;
pub mod firecracker;
pub mod libkrun;
pub mod process;

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use crate::SandboxOpts;

/// Resolve `bin` against `$PATH`, returning the first hit. Shared by
/// the top-level `probe(Docker)` check and the libkrun/firecracker
/// runner resolvers.
pub(crate) fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build a [`tokio::process::Command`] from `opts` with the workspace as
/// cwd, no inherited environment, and piped stdio. Backends overlay their
/// sandbox-specific setup on top.
pub(crate) fn build_command(opts: &SandboxOpts) -> io::Result<Command> {
    let program = opts
        .argv
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "argv is empty"))?;
    let mut cmd = Command::new(program);
    cmd.args(opts.argv.iter().skip(1));
    let cwd: &Path = opts.cwd.as_deref().unwrap_or(&opts.workspace);
    cmd.current_dir(cwd);
    cmd.env_clear();
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    Ok(cmd)
}

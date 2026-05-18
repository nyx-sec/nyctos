//! birdcage shim. Reads a JSON sandbox config on stdin, applies birdcage
//! exceptions in this process, then `birdcage::Sandbox::spawn`s the
//! requested child and exits with the child's status.
//!
//! Why a shim: `birdcage::Sandbox::spawn` sandboxes the *current* process
//! before spawning the sandboxee, so calling it from the daemon would
//! permanently lock the daemon down. A single-purpose helper process
//! contains the side-effects and is the pattern birdcage's own docs
//! recommend.

use std::io::{self, Read};
use std::process::{Command, ExitCode};

use nyx_agent_sandbox::shim::ShimConfig;

fn main() -> ExitCode {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("nyx-sandbox-shim: failed to read config: {e}");
        return ExitCode::from(2);
    }
    let cfg: ShimConfig = match serde_json::from_str(&buf) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nyx-sandbox-shim: invalid config: {e}");
            return ExitCode::from(2);
        }
    };
    run(cfg)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(cfg: ShimConfig) -> ExitCode {
    use birdcage::{Birdcage, Exception, Sandbox};

    let mut cmd = Command::new(&cfg.program);
    cmd.args(&cfg.args);
    if let Some(cwd) = &cfg.cwd {
        cmd.current_dir(cwd);
    }
    cmd.env_clear();
    for (k, v) in &cfg.env {
        cmd.env(k, v);
    }
    // Inherit stdio so the parent (daemon) sees the sandboxee's output
    // directly through the pipes it already attached to the shim.
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut sb = Birdcage::new();
    for p in &cfg.allow_read {
        let _ = sb.add_exception(Exception::ExecuteAndRead(p.into()));
    }
    for p in &cfg.allow_write {
        let _ = sb.add_exception(Exception::WriteAndRead(p.into()));
    }
    for k in &cfg.allow_env {
        let _ = sb.add_exception(Exception::Environment(k.into()));
    }
    if cfg.allow_network {
        let _ = sb.add_exception(Exception::Networking);
    }

    let mut child = match sb.spawn(cmd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nyx-sandbox-shim: birdcage spawn failed: {e}");
            return ExitCode::from(3);
        }
    };

    match child.wait() {
        Ok(status) => exit_code_from(status),
        Err(e) => {
            eprintln!("nyx-sandbox-shim: wait failed: {e}");
            ExitCode::from(4)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_cfg: ShimConfig) -> ExitCode {
    eprintln!("nyx-sandbox-shim: birdcage is unavailable on this platform");
    ExitCode::from(5)
}

#[cfg(unix)]
fn exit_code_from(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        // Convention: 128 + signum so the parent can distinguish a
        // signal-killed child from a normal nonzero exit.
        let raw = 128 + (sig as u32).min(127);
        return ExitCode::from(raw as u8);
    }
    let code = status.code().unwrap_or(1);
    ExitCode::from(code.clamp(0, 255) as u8)
}

#[cfg(not(unix))]
fn exit_code_from(status: std::process::ExitStatus) -> ExitCode {
    let code = status.code().unwrap_or(1);
    ExitCode::from(code.clamp(0, 255) as u8)
}

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
use std::process::ExitCode;

use nyctos_sandbox::shim::ShimConfig;

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
    use birdcage::process::{Command, Stdio};
    use birdcage::{Birdcage, Exception, Sandbox};

    // Become our own process-group leader so the daemon's
    // BirdcageSandbox::kill can issue killpg(shim_pid, SIGKILL) and reap
    // the shim AND the sandboxee (and any helpers the sandboxee spawned)
    // in one syscall. EPERM here means the shim was already a pgrp leader
    // (rare; the daemon would have to explicitly place us in our own
    // group), which is the state we wanted anyway.
    unsafe {
        if libc::setsid() == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("nyx-sandbox-shim: setsid failed: {err}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Err(e) = prepare_linux_process_state(&cfg) {
        eprintln!("nyx-sandbox-shim: {e}");
        return ExitCode::from(3);
    }

    if cfg.write_status_fd {
        // The shim still writes fd 3 after wait(), but the sandboxee must
        // not inherit it and forge its own status frame.
        set_status_fd_cloexec();
    }

    let mut cmd = Command::new(&cfg.program);
    cmd.args(&cfg.args);
    #[cfg(target_os = "macos")]
    if let Some(cwd) = &cfg.cwd {
        cmd.current_dir(cwd);
    }
    #[cfg(target_os = "macos")]
    {
        cmd.env_clear();
        for (k, v) in &cfg.env {
            cmd.env(k, v);
        }
    }
    // Inherit stdio so the parent (daemon) sees the sandboxee's output
    // directly through the pipes it already attached to the shim.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut sb = Birdcage::new();
    let mut refused: Vec<String> = Vec::new();
    for p in &cfg.allow_read {
        if let Err(e) = sb.add_exception(Exception::ExecuteAndRead(p.into())) {
            refused.push(format!("ExecuteAndRead({}): {e}", p.display()));
        }
    }
    for p in &cfg.allow_write {
        if let Err(e) = sb.add_exception(Exception::WriteAndRead(p.into())) {
            refused.push(format!("WriteAndRead({}): {e}", p.display()));
        }
    }
    for k in &cfg.allow_env {
        if let Err(e) = sb.add_exception(Exception::Environment(k.into())) {
            refused.push(format!("Environment({k}): {e}"));
        }
    }
    if cfg.allow_network {
        if let Err(e) = sb.add_exception(Exception::Networking) {
            refused.push(format!("Networking: {e}"));
        }
    }
    // Birdcage refuses some exceptions (path does not exist, filesystem
    // the kernel cannot landlock, Seatbelt-incompatible pattern). The
    // refusals also ride the fd-3 ShimReport envelope so the parent can
    // surface them on SandboxOutcome.refusals; the stderr copy here
    // stays for operators running the shim by hand and for older
    // parents that did not allocate a status pipe.
    for line in &refused {
        eprintln!("nyx-sandbox-shim: exception refused {line}");
    }

    let mut child = match sb.spawn(cmd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nyx-sandbox-shim: birdcage spawn failed: {e}");
            if cfg.write_status_fd {
                write_report_status_to_fd3(nyctos_sandbox::shim::ShimStatus::Exited(3), &refused);
            }
            return ExitCode::from(3);
        }
    };

    match child.wait() {
        Ok(status) => {
            if cfg.write_status_fd {
                write_report_status_to_fd3(shim_status_from(status), &refused);
            }
            exit_code_from(status)
        }
        Err(e) => {
            eprintln!("nyx-sandbox-shim: wait failed: {e}");
            ExitCode::from(4)
        }
    }
}

#[cfg(target_os = "linux")]
fn prepare_linux_process_state(cfg: &ShimConfig) -> Result<(), String> {
    if let Some(cwd) = &cfg.cwd {
        std::env::set_current_dir(cwd)
            .map_err(|e| format!("failed to set cwd to {}: {e}", cwd.display()))?;
    }

    let keys: Vec<_> = std::env::vars_os().map(|(key, _)| key).collect();
    for key in keys {
        std::env::remove_var(key);
    }
    for (k, v) in &cfg.env {
        std::env::set_var(k, v);
    }

    Ok(())
}

#[cfg(unix)]
fn set_status_fd_cloexec() {
    unsafe {
        let flags = libc::fcntl(3, libc::F_GETFD);
        if flags != -1 {
            let _ = libc::fcntl(3, libc::F_SETFD, flags | libc::FD_CLOEXEC);
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

#[cfg(unix)]
fn shim_status_from(status: std::process::ExitStatus) -> nyctos_sandbox::shim::ShimStatus {
    use std::os::unix::process::ExitStatusExt;

    if let Some(sig) = status.signal() {
        nyctos_sandbox::shim::ShimStatus::Signaled(sig)
    } else {
        nyctos_sandbox::shim::ShimStatus::Exited(status.code().unwrap_or(-1))
    }
}

#[cfg(unix)]
fn write_report_status_to_fd3(status: nyctos_sandbox::shim::ShimStatus, refusals: &[String]) {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    use nyctos_sandbox::shim::ShimReport;

    let report = ShimReport { status, refusals: refusals.to_vec() };
    let json = match serde_json::to_vec(&report) {
        Ok(b) => b,
        Err(_) => return,
    };
    // SAFETY: the parent (BirdcageSandbox::run) installs a pre_exec
    // closure that dup2s the pipe's write end onto fd 3 before exec'ing
    // this shim. If fd 3 is closed for any reason the write returns
    // EBADF and the parent falls back to the legacy 128+signum convention.
    let mut file = unsafe { std::fs::File::from_raw_fd(3) };
    let _ = file.write_all(&json);
    // file dropped here -> close(3) -> parent's read end EOFs.
}

#[cfg(not(unix))]
fn write_report_status_to_fd3(_status: nyctos_sandbox::shim::ShimStatus, _refusals: &[String]) {}

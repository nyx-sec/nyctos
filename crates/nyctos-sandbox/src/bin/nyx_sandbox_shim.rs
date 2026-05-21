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
    use birdcage::{Birdcage, Exception, Sandbox};

    // Become our own process-group leader so the daemon's
    // BirdcageSandbox::kill can issue killpg(shim_pid, SIGKILL) and reap
    // the shim AND the sandboxee (and any helpers the sandboxee spawned)
    // in one syscall. This is the macOS-portable half of the kill story;
    // on Linux it composes with the PR_SET_PDEATHSIG block below as a
    // defence-in-depth measure. EPERM here means the shim was already a
    // pgrp leader (rare; the daemon would have to explicitly place us in
    // our own group), which is the state we wanted anyway.
    unsafe {
        if libc::setsid() == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("nyx-sandbox-shim: setsid failed: {err}");
            }
        }
    }

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

    // Make the sandboxee die with the shim. Without this, a SIGKILL on
    // the shim (issued by `BirdcageSandbox::kill` when the daemon
    // cancels or a per-run timeout fires) reparents the grandchild to
    // init/launchd and the sandboxee keeps running after the kill path
    // returned. The pre_exec closure runs after fork in the child;
    // PR_SET_PDEATHSIG survives the subsequent exec.
    //
    // Same closure also closes fd 3 in the sandboxee when the parent
    // wired up a status pipe: fd 3 is the shim's own write end for the
    // out-of-band ShimStatus frame and must not be visible to the
    // sandboxee (otherwise the sandboxee could forge its own exit
    // classification).
    let close_status_fd = cfg.write_status_fd;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                if close_status_fd {
                    // SAFETY: close is async-signal-safe. EBADF (already
                    // closed) is acceptable; we ignore the return code.
                    libc::close(3);
                }
                #[cfg(target_os = "linux")]
                {
                    // SAFETY: prctl is async-signal-safe; pre_exec requires
                    // we avoid the allocator and any non-async-signal-safe
                    // call, which a bare FFI prctl satisfies.
                    let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                    if ret == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

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
            return ExitCode::from(3);
        }
    };

    match child.wait() {
        Ok(status) => {
            if cfg.write_status_fd {
                write_report_to_fd3(status, &refused);
            }
            exit_code_from(status)
        }
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

#[cfg(unix)]
fn write_report_to_fd3(status: std::process::ExitStatus, refusals: &[String]) {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::ExitStatusExt;

    use nyctos_sandbox::shim::{ShimReport, ShimStatus};

    let status = if let Some(sig) = status.signal() {
        ShimStatus::Signaled(sig)
    } else {
        ShimStatus::Exited(status.code().unwrap_or(-1))
    };
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
fn write_report_to_fd3(_status: std::process::ExitStatus, _refusals: &[String]) {}

//! Sandbox-escape probe binary used by the regression test suite.
//!
//! Each subcommand drives a single classic escape attempt (write outside
//! the workspace, read a secret file, open a socket, ...). Exits 0 when
//! the operation *succeeded* — i.e. the sandbox failed to contain the
//! probe — and non-zero (or via a signal) when the kernel rejected it.
//!
//! This binary is intentionally minimal and stdlib-only so it has no
//! dynamic dependencies birdcage's default exception list needs to
//! cover beyond libc / dyld.

use std::io::{Read, Write};
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(sub) = args.next() else {
        eprintln!("escape-attempt: missing subcommand");
        return ExitCode::from(2);
    };
    match sub.as_str() {
        "write-outside" => write_outside(args.next()),
        "read-outside" => read_outside(args.next()),
        "connect-tcp" => connect_tcp(args.next()),
        "udp-send" => udp_send(args.next()),
        "fork-write-outside" => fork_write_outside(args.next()),
        "symlink-write" => symlink_write(args.next(), args.next()),
        "noop" => ExitCode::SUCCESS,
        other => {
            eprintln!("escape-attempt: unknown subcommand `{other}`");
            ExitCode::from(2)
        }
    }
}

fn write_outside(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return ExitCode::from(2);
    };
    let path = PathBuf::from(path);
    match std::fs::File::create(&path) {
        Ok(mut f) => {
            // even if create succeeded the write may fail under a
            // write-deny rule; treat full-success as escape.
            if f.write_all(b"escaped").is_ok() && f.sync_all().is_ok() {
                eprintln!("escape-attempt: wrote {}", path.display());
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("escape-attempt: create denied: {e}");
            ExitCode::from(1)
        }
    }
}

fn read_outside(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return ExitCode::from(2);
    };
    let path = PathBuf::from(path);
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                // print bytes to stdout so the test can assert on them
                // if it wants to.
                let _ = std::io::stdout().write_all(&buf);
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("escape-attempt: open denied: {e}");
            ExitCode::from(1)
        }
    }
}

fn connect_tcp(addr: Option<String>) -> ExitCode {
    let Some(addr) = addr else {
        return ExitCode::from(2);
    };
    let sockaddr = match addr.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(a) => a,
            None => return ExitCode::from(1),
        },
        Err(_) => return ExitCode::from(1),
    };
    match std::net::TcpStream::connect_timeout(&sockaddr, std::time::Duration::from_millis(500)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("escape-attempt: tcp denied: {e}");
            ExitCode::from(1)
        }
    }
}

fn udp_send(addr: Option<String>) -> ExitCode {
    let Some(addr) = addr else {
        return ExitCode::from(2);
    };
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => match sock.send_to(b"x", addr) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("escape-attempt: udp send denied: {e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("escape-attempt: udp bind denied: {e}");
            ExitCode::from(1)
        }
    }
}

fn fork_write_outside(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return ExitCode::from(2);
    };
    // Exec ourselves with `write-outside <path>` so the child inherits the
    // sandbox via fork+exec. The escape succeeds only if the child wrote
    // the file; we propagate the child's exit code.
    let me = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("escape-attempt: current_exe: {e}");
            return ExitCode::from(1);
        }
    };
    let status = Command::new(me).arg("write-outside").arg(path).status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(e) => {
            eprintln!("escape-attempt: fork denied: {e}");
            ExitCode::from(1)
        }
    }
}

fn symlink_write(link: Option<String>, target: Option<String>) -> ExitCode {
    let (Some(link), Some(target)) = (link, target) else {
        return ExitCode::from(2);
    };
    let link = PathBuf::from(link);
    let target = PathBuf::from(target);

    #[cfg(unix)]
    {
        if let Err(e) = std::os::unix::fs::symlink(&target, &link) {
            eprintln!("escape-attempt: symlink denied: {e}");
            return ExitCode::from(1);
        }
    }
    #[cfg(not(unix))]
    {
        return ExitCode::from(1);
    }

    match std::fs::File::create(&link) {
        Ok(mut f) => {
            if f.write_all(b"escaped via symlink").is_ok() && f.sync_all().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("escape-attempt: write-via-symlink denied: {e}");
            ExitCode::from(1)
        }
    }
}

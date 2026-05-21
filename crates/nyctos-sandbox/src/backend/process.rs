//! Process backend: spawn the child and watch it. No isolation upgrade.
//!
//! This is the unhardened default. It exists so the rest of the daemon
//! can speak the [`Sandbox`] trait everywhere (even when birdcage is
//! unavailable or the operator opts out) without forking on the call
//! site. Static-pass scanning runs on this backend in CI today.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::process::Child;
use tokio::time::timeout;

use crate::backend::{apply_snapshot_from, build_command};
use crate::{BackendKind, Sandbox, SandboxError, SandboxOpts, SandboxOutcome, SandboxStatus};

#[derive(Default)]
pub struct ProcessSandbox {
    inner: Option<RunningChild>,
    last_logs: (Vec<u8>, Vec<u8>),
}

pub(crate) struct RunningChild {
    pub(crate) child: Child,
    pub(crate) started_at: Instant,
    pub(crate) timeout: std::time::Duration,
    pub(crate) max_output_bytes: usize,
    /// Set by `Sandbox::kill` so the subsequent `wait()` can report
    /// `SandboxStatus::Killed` instead of folding into the kernel's
    /// `Signaled(SIGKILL)` / shim's `128+SIGKILL` exit code. Lets a
    /// caller distinguish operator cancel from spontaneous death.
    pub(crate) killed_by_operator: bool,
    /// Optional read end of the shim's out-of-band report pipe.
    /// Backends that wrap their sandboxee in a helper shim
    /// (`BirdcageSandbox`) cannot read the sandboxee's real
    /// `ExitStatus` because the shim collapses signal-killed children
    /// into the `128+signum` exit-code convention. The shim instead
    /// writes a JSON `ShimReport` envelope to fd 3 carrying both the
    /// real status and the list of birdcage exception refusals; the
    /// backend hands the read end here and `drive_to_completion`
    /// reads it after wait, overriding `classify(status)` and
    /// populating `SandboxOutcome.refusals`. `None` means "use the
    /// kernel `ExitStatus` directly" (the unwrapped path used by
    /// `ProcessSandbox`).
    #[cfg(unix)]
    pub(crate) status_fd: Option<std::os::fd::OwnedFd>,
    /// Backing tempdir for a `SandboxOpts.snapshot_from` request.
    /// Held until the child is reaped so the COW snapshot survives
    /// the run; dropped (along with the snapshot directory) when the
    /// outer `RunningChild` falls out of scope at the end of
    /// `Sandbox::wait` or `Sandbox::kill`. `None` when the caller did
    /// not request a snapshot. The field is intentionally only ever
    /// written: its job is RAII over the snapshot directory, and the
    /// drop happens at end-of-scope.
    #[allow(dead_code)]
    pub(crate) scratch_snapshot: Option<TempDir>,
    /// Post-`apply_snapshot_from` workspace path. `drive_to_completion`
    /// joins each [`Self::capture_files`] entry against this root to
    /// read the captured bytes after wait but before the snapshot tempdir
    /// drops. Stored here (not derived from opts at drive time) because
    /// `SandboxOpts` is consumed during `run()`.
    pub(crate) workspace: PathBuf,
    /// Workspace-relative paths the backend reads at capture time. Empty
    /// when the caller declared no captures.
    pub(crate) capture_files: Vec<PathBuf>,
}

impl ProcessSandbox {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Sandbox for ProcessSandbox {
    fn backend(&self) -> BackendKind {
        BackendKind::Process
    }

    async fn run(&mut self, mut opts: SandboxOpts) -> Result<(), SandboxError> {
        if self.inner.is_some() {
            return Err(SandboxError::State("a child is already running"));
        }
        if opts.argv.is_empty() {
            return Err(SandboxError::Config("argv is empty".into()));
        }
        let scratch_snapshot = apply_snapshot_from(&mut opts)?;
        if !opts.workspace.exists() {
            return Err(SandboxError::Config(format!(
                "workspace {} does not exist",
                opts.workspace.display()
            )));
        }
        let mut cmd = build_command(&opts).map_err(SandboxError::Spawn)?;
        let child = cmd.spawn().map_err(SandboxError::Spawn)?;
        self.inner = Some(RunningChild {
            child,
            started_at: Instant::now(),
            timeout: opts.timeout,
            max_output_bytes: opts.max_output_bytes,
            killed_by_operator: false,
            #[cfg(unix)]
            status_fd: None,
            scratch_snapshot,
            workspace: opts.workspace,
            capture_files: opts.capture_files,
        });
        Ok(())
    }

    async fn kill(&mut self) -> Result<(), SandboxError> {
        if let Some(state) = self.inner.as_mut() {
            state.killed_by_operator = true;
            // start_kill is fire-and-forget; the kernel SIGKILLs the child
            // and we reap it in the wait() call. An already-exited child
            // returns Ok.
            let _ = state.child.start_kill();
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError> {
        let mut state = self.inner.take().ok_or(SandboxError::State("no child to wait on"))?;
        let outcome = drive_to_completion(&mut state, BackendKind::Process).await?;
        self.last_logs = (outcome.stdout.clone(), outcome.stderr.clone());
        Ok(outcome)
    }

    fn logs(&self) -> (&[u8], &[u8]) {
        (&self.last_logs.0, &self.last_logs.1)
    }
}

pub(crate) async fn drive_to_completion(
    state: &mut RunningChild,
    backend: BackendKind,
) -> Result<SandboxOutcome, SandboxError> {
    let stdout = state.child.stdout.take();
    let stderr = state.child.stderr.take();
    let cap = state.max_output_bytes;
    let stdout_task = tokio::spawn(async move { read_capped(stdout, cap).await });
    let stderr_task = tokio::spawn(async move { read_capped(stderr, cap).await });

    let wait_fut = state.child.wait();
    let wait_result = timeout(state.timeout, wait_fut).await;

    let (status, timed_out) = match wait_result {
        Ok(Ok(status)) => (status, false),
        Ok(Err(err)) => return Err(SandboxError::Io(err)),
        Err(_elapsed) => {
            let _ = state.child.start_kill();
            let status = state.child.wait().await.map_err(SandboxError::Io)?;
            (status, true)
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    let duration = state.started_at.elapsed();

    // The shim's fd-3 report channel covers BOTH the real status and
    // any birdcage exception refusals collected during sandbox setup.
    // Read it unconditionally on unix so refusals reach
    // SandboxOutcome.refusals even when the kernel ExitStatus is the
    // path we would have chosen anyway (TimedOut / Killed branches
    // still win against the report's status field).
    #[cfg(unix)]
    let (status_override, refusals) = read_report_fd(&mut state.status_fd);
    #[cfg(not(unix))]
    let (status_override, refusals): (Option<SandboxStatus>, Vec<String>) = (None, Vec::new());

    let sandbox_status = if timed_out {
        SandboxStatus::TimedOut
    } else if state.killed_by_operator {
        SandboxStatus::Killed
    } else {
        status_override.unwrap_or_else(|| classify(status))
    };

    // Capture declared sentinel paths from the live workspace before
    // returning. The backend's RunningChild still owns `scratch_snapshot`
    // at this point, so a `with_snapshot_from` workspace is still on
    // disk. The drop of `state` after this function returns reaps both
    // the snapshot tempdir and the captured-files vec.
    let captured_files = capture_files(&state.workspace, &state.capture_files);

    Ok(SandboxOutcome {
        backend,
        status: sandbox_status,
        stdout,
        stderr,
        duration,
        refusals,
        captured_files,
    })
}

fn capture_files(
    workspace: &std::path::Path,
    paths: &[PathBuf],
) -> HashMap<PathBuf, Option<Vec<u8>>> {
    let mut out: HashMap<PathBuf, Option<Vec<u8>>> = HashMap::with_capacity(paths.len());
    for rel in paths {
        let abs = workspace.join(rel);
        out.insert(rel.clone(), std::fs::read(&abs).ok());
    }
    out
}

#[cfg(unix)]
fn read_report_fd(
    slot: &mut Option<std::os::fd::OwnedFd>,
) -> (Option<SandboxStatus>, Vec<String>) {
    use std::io::Read;

    use crate::shim::{ShimReport, ShimStatus};

    let Some(fd) = slot.take() else {
        return (None, Vec::new());
    };
    let mut file = std::fs::File::from(fd);
    let mut buf = Vec::with_capacity(128);
    if file.read_to_end(&mut buf).is_err() || buf.is_empty() {
        return (None, Vec::new());
    }
    let Ok(report) = serde_json::from_slice::<ShimReport>(&buf) else {
        return (None, Vec::new());
    };
    let status = Some(match report.status {
        ShimStatus::Exited(c) => SandboxStatus::Exited(c),
        ShimStatus::Signaled(s) => SandboxStatus::Signaled(s),
    });
    (status, report.refusals)
}

#[cfg(unix)]
fn classify(status: std::process::ExitStatus) -> SandboxStatus {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        return SandboxStatus::Signaled(sig);
    }
    SandboxStatus::Exited(status.code().unwrap_or(-1))
}

#[cfg(not(unix))]
fn classify(status: std::process::ExitStatus) -> SandboxStatus {
    SandboxStatus::Exited(status.code().unwrap_or(-1))
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: Option<R>, cap: usize) -> Vec<u8> {
    let Some(mut reader) = reader else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(cap.min(8 * 1024));
    let mut buf = [0u8; 8 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let take = n.min(cap - out.len());
                    out.extend_from_slice(&buf[..take]);
                }
                // continue draining so the child does not block on a
                // full pipe even after we stop appending.
            }
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sandbox, SandboxOpts};
    use std::time::Duration;
    use tempfile::tempdir;

    fn opts_for(workspace: &std::path::Path, argv: Vec<String>) -> SandboxOpts {
        SandboxOpts {
            workspace: workspace.to_path_buf(),
            argv,
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_secs(5),
            allow_loopback: false,
            lane: None,
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            max_output_bytes: 1 << 16,
            snapshot_from: None,
            capture_files: Vec::new(),
        }
    }

    #[tokio::test]
    async fn kill_marks_status_as_killed_not_signaled() {
        let scratch = tempdir().unwrap();
        let mut sb = ProcessSandbox::new();
        sb.run(opts_for(scratch.path(), vec!["sleep".into(), "30".into()])).await.unwrap();
        // Give the child a moment to start so start_kill targets a
        // running process rather than racing the spawn.
        tokio::time::sleep(Duration::from_millis(50)).await;
        sb.kill().await.unwrap();
        let outcome = sb.wait().await.unwrap();
        assert!(
            matches!(outcome.status, SandboxStatus::Killed),
            "expected Killed after operator kill, got {:?}",
            outcome.status
        );
    }

    #[tokio::test]
    async fn natural_exit_does_not_report_killed() {
        let scratch = tempdir().unwrap();
        let mut sb = ProcessSandbox::new();
        sb.run(opts_for(scratch.path(), vec!["true".into()])).await.unwrap();
        let outcome = sb.wait().await.unwrap();
        assert!(
            matches!(outcome.status, SandboxStatus::Exited(0)),
            "expected Exited(0) on natural exit, got {:?}",
            outcome.status
        );
    }

    // Acceptance for SandboxOpts::capture_files: the backend reads each
    // declared workspace-relative path after `wait` returns and stamps
    // the bytes on `outcome.captured_files`. Files that did not exist
    // surface as `Some(rel) -> None` so the caller can distinguish
    // "harness did not write the sentinel" from "caller never asked".
    // This is the path PayloadRunner relies on for SinkProbe oracle
    // observation after a `with_snapshot_from` snapshot dropped the
    // live workspace before the caller gets the outcome back.
    #[tokio::test]
    async fn capture_files_round_trip_present_and_missing_paths() {
        let scratch = tempdir().unwrap();
        let workspace = scratch.path().join("ws");
        std::fs::create_dir(&workspace).unwrap();

        let mut opts = SandboxOpts::new(
            workspace.clone(),
            vec!["/bin/sh".into(), "-c".into(), "printf hit > present.flag".into()],
        );
        opts.capture_files.push(std::path::PathBuf::from("present.flag"));
        opts.capture_files.push(std::path::PathBuf::from("absent.flag"));

        let mut sb = ProcessSandbox::new();
        sb.run(opts).await.expect("run");
        let outcome = sb.wait().await.expect("wait");

        let present = outcome
            .captured_files
            .get(std::path::Path::new("present.flag"))
            .expect("present declared");
        assert_eq!(present.as_deref(), Some(b"hit".as_slice()), "present must carry harness bytes");
        let absent = outcome
            .captured_files
            .get(std::path::Path::new("absent.flag"))
            .expect("absent declared");
        assert!(absent.is_none(), "absent declared path must capture as None, not omitted");
    }

    // Acceptance for SandboxOpts::with_snapshot_from(...): the sandbox
    // child runs against a fresh COW copy of the source workspace, and
    // any writes the child makes do not bleed back into the source.
    // This is the contract Phase 19's verifier and Phase 22's chain
    // runner will lean on when they ask for a per-run / per-step
    // snapshot.
    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_from_isolates_writes_from_source() {
        let scratch = tempdir().unwrap();
        let src = scratch.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("sentinel.txt"), b"original").unwrap();

        // The workspace value is overridden by apply_snapshot_from;
        // pass a placeholder so the SandboxOpts::new pre-condition is
        // satisfied without staging a real directory.
        let opts = SandboxOpts::new(
            scratch.path().join("placeholder-ignored"),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "cat sentinel.txt && printf mutation > sentinel.txt".into(),
            ],
        )
        .with_snapshot_from(src.clone());

        let mut sb = ProcessSandbox::new();
        sb.run(opts).await.expect("snapshot+run");
        let outcome = sb.wait().await.expect("wait");

        assert!(
            matches!(outcome.status, SandboxStatus::Exited(0)),
            "child must exit cleanly, got {:?} stderr={}",
            outcome.status,
            String::from_utf8_lossy(&outcome.stderr),
        );
        assert_eq!(
            outcome.stdout, b"original",
            "child must see the snapshotted sentinel content"
        );
        assert_eq!(
            std::fs::read(src.join("sentinel.txt")).unwrap(),
            b"original",
            "source sentinel must NOT have been mutated by the sandboxed write"
        );
    }
}

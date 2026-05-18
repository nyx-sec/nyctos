//! Process backend: spawn the child and watch it. No isolation upgrade.
//!
//! This is the unhardened default. It exists so the rest of the daemon
//! can speak the [`Sandbox`] trait everywhere — even when birdcage is
//! unavailable or the operator opts out — without forking on the call
//! site. Static-pass scanning runs on this backend in CI today.

use std::time::Instant;

use tokio::io::AsyncReadExt;
use tokio::process::Child;
use tokio::time::timeout;

use crate::backend::build_command;
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

    async fn run(&mut self, opts: SandboxOpts) -> Result<(), SandboxError> {
        if self.inner.is_some() {
            return Err(SandboxError::State("a child is already running"));
        }
        if opts.argv.is_empty() {
            return Err(SandboxError::Config("argv is empty".into()));
        }
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
        });
        Ok(())
    }

    async fn kill(&mut self) -> Result<(), SandboxError> {
        if let Some(state) = self.inner.as_mut() {
            // start_kill is fire-and-forget; the kernel SIGKILLs the child
            // and we reap it in the wait() call. An already-exited child
            // returns Ok.
            let _ = state.child.start_kill();
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<SandboxOutcome, SandboxError> {
        let mut state = self
            .inner
            .take()
            .ok_or(SandboxError::State("no child to wait on"))?;
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

    let sandbox_status = if timed_out {
        SandboxStatus::TimedOut
    } else {
        classify(status)
    };

    Ok(SandboxOutcome {
        backend,
        status: sandbox_status,
        stdout,
        stderr,
        duration,
    })
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

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    reader: Option<R>,
    cap: usize,
) -> Vec<u8> {
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

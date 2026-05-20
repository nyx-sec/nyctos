//! `ScanLane` adapter wrapping the upstream `nyx` subprocess driver.
//!
//! The Phase 06 dispatcher calls `scan_blocking` on a rayon worker
//! thread. The underlying `NyxRunner::scan` is `async` (it shells out
//! through `tokio::process::Command` for stdout streaming + timeout),
//! so the adapter spins up a current-thread tokio runtime for the
//! duration of one scan and translates the typed `NyxError` into the
//! `ScanLaneError` flavours the dispatcher consumes.

use std::sync::Arc;
use std::time::Duration;

use nyctos_core::{ScanLane, ScanLaneError, WorkspaceHandle};
use tokio::runtime::Builder;

use crate::diag::Diag;
use crate::error::NyxError;
use crate::runner::{NyxRunner, ScanOptions};

#[derive(Clone, Debug)]
pub struct NyxScanLane {
    runner: Arc<NyxRunner>,
    verify: bool,
}

impl NyxScanLane {
    pub fn new(runner: NyxRunner) -> Self {
        Self { runner: Arc::new(runner), verify: false }
    }

    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    pub fn runner(&self) -> &NyxRunner {
        &self.runner
    }
}

impl ScanLane<Diag> for NyxScanLane {
    fn scan_blocking(
        &self,
        workspace: &WorkspaceHandle,
        timeout: Duration,
    ) -> Result<Vec<Diag>, ScanLaneError> {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ScanLaneError::Failed(format!("nyx lane runtime: {e}")))?;
        let opts = ScanOptions { verify: self.verify, timeout: Some(timeout) };
        let outcome = rt.block_on(self.runner.scan(workspace.workspace(), &opts));
        match outcome {
            Ok(o) => Ok(o.diags),
            Err(NyxError::ScanTimeout { .. }) => Err(ScanLaneError::Timeout),
            Err(other) => Err(ScanLaneError::Failed(other.to_string())),
        }
    }
}

//! Typed errors for the `nyx` subprocess driver.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NyxError {
    #[error("nyx binary not found on PATH (tried override: {tried:?})")]
    NyxNotFound { tried: Option<PathBuf> },

    #[error("nyx version {found} is below the minimum supported version {required}")]
    VersionTooOld { found: semver::Version, required: semver::Version },

    #[error("could not parse nyx version output: {raw:?}")]
    UnparseableVersion { raw: String },

    #[error("nyx scan exceeded {timeout_secs}s timeout")]
    ScanTimeout { timeout_secs: u64 },

    #[error("nyx exited with status {status}: {stderr}")]
    NonZeroExit { status: i32, stderr: String },

    #[error("malformed nyx output: {0}")]
    MalformedOutput(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

//! Pure subprocess driver around the upstream `nyx` static scanner.
//!
//! No FFI. No source-level dependency on the scanner. The agent only ever
//! talks to `nyx` through `argv` + `stdout`, which keeps the
//! GPL-licensed scanner cleanly outside the agent's link graph (see
//! `LICENSE-GRANTS.md`).

pub mod diag;
pub mod error;
pub mod harness_spec;
pub mod lane;
pub mod runner;

pub use diag::{Diag, FlowStep};
pub use error::NyxError;
pub use harness_spec::{HarnessSpec, HarnessSpecValidationError};
pub use lane::NyxScanLane;
pub use runner::{NyxRunner, ScanOptions, ScanOutcome, MINIMUM_NYX_VERSION};

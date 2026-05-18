//! Time helpers shared across the workspace.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in milliseconds, saturated to `0` if the system
/// clock is set before the epoch.
pub fn now_epoch_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

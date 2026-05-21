//! Wire envelopes that don't map 1:1 to a DB row.
//!
//! Request/response shapes whose only home is the HTTP surface (e.g.
//! `GET /api/v1/health`) live here so they share the same
//! `#[derive(TS)]` codegen path as the record types in the
//! domain-specific modules. The Rust source of truth for each endpoint
//! still lives next to its handler in `crates/nyctos-api/src/router.rs`;
//! this module hosts only the wire shapes.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Response body for `GET /api/v1/health`. `status` is always the
/// literal string `"ok"` on the wire (the daemon never returns a
/// non-200 success); the FE keeps the `"ok"` literal narrowing as an
/// ergonomic alias on top of the generated `string` shape (same
/// pattern as `RepoSourceKind`). `version` is the daemon's
/// `CARGO_PKG_VERSION` at build time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

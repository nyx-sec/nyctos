//! Subcommand glue isolated from `main.rs`.
//!
//! Phase 26 ships two surfaces here:
//!
//! * [`scan_report`] - shared `report.json` schema written by
//!   `scan --output` and read by `pr-comment --report`.
//! * [`pr_comment`] - reads a report, filters to Confirmed + cross-repo
//!   chain findings, groups by file + severity, and posts (or updates)
//!   a single PR comment via the GitHub REST API.

pub mod pr_comment;
pub mod scan_report;

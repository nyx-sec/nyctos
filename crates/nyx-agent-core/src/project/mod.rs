//! Project entity: groups multiple repos into a single logical product.
//!
//! A `Project` owns repos (backend, frontend, infra, etc.) that compose
//! into one deployable app. Scans, runs, env-builder merges, and chain
//! validation hang off the project. The `ProjectId` newtype keeps the
//! id distinct from arbitrary strings at the type level.
//!
//! Types live in `nyx-agent-types::project` so other workspace crates can
//! name them without depending on all of `nyx-agent-core`. Re-exported here
//! for back-compat with existing `crate::project::{Project, ProjectId}`
//! call sites.

pub use nyx_agent_types::project::{
    Project, ProjectId, ProjectRuntimeCommand, ProjectRuntimeEnvVar, ProjectRuntimeProfile,
};

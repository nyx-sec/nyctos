//! Project entity: groups multiple repos into a single logical product.
//!
//! A `Project` owns repos (backend, frontend, infra, etc.) that compose
//! into one deployable app. Scans, runs, env-builder merges, and chain
//! validation hang off the project. The `ProjectId` newtype keeps the
//! id distinct from arbitrary strings at the type level.

use serde::{Deserialize, Serialize};

/// Stable identifier for a [`Project`]. Wraps the row id from the
/// `projects` table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

impl ProjectId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// In-memory descriptor of a configured project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub target_base_url: Option<String>,
    pub env_config: Option<serde_json::Value>,
}

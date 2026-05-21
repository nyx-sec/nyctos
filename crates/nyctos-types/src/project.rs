//! Shared project descriptor types.
//!
//! The cross-crate `ProjectId` newtype and the in-memory `Project`
//! descriptor live here so other workspace crates can name them without
//! pulling all of `nyctos-core` into their dep graph. `nyctos-core`
//! re-exports both under `nyctos_core::project::{Project, ProjectId}`
//! for the existing call sites.

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

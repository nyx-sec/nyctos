//! Shared project descriptor types.
//!
//! The cross-crate `ProjectId` newtype and the in-memory `Project`
//! descriptor live here so other workspace crates can name them without
//! pulling all of `nyctos-core` into their dep graph. `nyctos-core`
//! re-exports both under `nyctos_core::project::{Project, ProjectId}`
//! for the existing call sites.
//!
//! [`ProjectRecord`] is the on-the-wire shape of one row in the
//! `projects` table. Both the API (`GET /projects`, `POST /projects`,
//! `PATCH /projects/:id`) and the SPA (`frontend/src/api/types.gen.ts`)
//! depend on this shape; it lives here so the TS frontend can
//! `import type { ProjectRecord }` from `types.gen.ts` instead of
//! hand-rolling a parallel interface.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

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

/// On-the-wire shape of a `projects` table row. `created_at` and
/// `updated_at` carry `#[ts(type = "number")]` so the generated TS
/// declaration uses `number` rather than `bigint` (`serde_json` emits
/// a JSON number for `i64`, which JS receives as `number`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub target_base_url: Option<String>,
    pub env_config_json: Option<String>,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

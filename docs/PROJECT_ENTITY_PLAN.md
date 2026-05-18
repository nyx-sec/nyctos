# Project Entity Implementation Plan

Phased refactor introducing a `Project` entity that groups multiple repos into a single logical app (e.g. backend + frontend belonging to one product). Pre-1.0, no published DBs — clean break, no legacy compat layer.

## How to use this document

To execute a phase, ask:

> implement phase N from docs/PROJECT_ENTITY_PLAN.md

Each phase is self-contained: scope, exact file paths, schema/code snippets, exit criteria, and which prior phases must be complete. Execute phases in numeric order unless explicitly told otherwise. After a phase completes, commit before starting the next.

## Architecture summary

**Today:** `Repo` is the top-level scan unit. `nyx-agent.toml` has flat `[[repo]]` blocks. Scan/run/chain-runner/env-builder iterate per-repo with no concept of which repos belong together.

**Target:** `Project` is the top-level entity. Repos are nested under projects (`project_id NOT NULL FK`). Scan/run/env-builder/chain-runner take a project and operate over its repos. Compose merge, target URLs, env config all hang off the project.

**Schema:**
```sql
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  target_base_url TEXT,
  env_config_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_projects_name ON projects(name);

-- repos table gains:
project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE
-- with INDEX idx_repos_project ON repos(project_id)
```

**Config:**
```toml
[[project]]
name = "acme-app"
description = "Acme web product"
target_base_url = "http://localhost:3000"

  [[project.repo]]
  name = "acme-backend"
  i_own_this = true
  enabled = true
  source = { kind = "local-path", path = "/path/backend" }

  [[project.repo]]
  name = "acme-frontend"
  i_own_this = true
  enabled = true
  source = { kind = "local-path", path = "/path/frontend" }
```

**Phase dependency graph:**
```
0 (schema) → 1 (types) → 2 (store) → 3 (config) → 4 (dispatcher)
                                                       ↓
                                       5 (API), 6 (CLI), 7 (sandbox) — parallel-safe after 4
                                                       ↓
                                                  8 (frontend)
                                                       ↓
                                                  9 (docs)
```

---

## Phase 0 — Wipe schema baseline

**Goal:** Rewrite `0001_v1.sql` in place with `projects` table + `repos.project_id` FK. No chained migration since no published DBs exist.

**Files:**
- `crates/nyx-agent-core/migrations/0001_v1.sql` — modify `repos` table to add `project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE`; insert `projects` table definition above it
- `crates/nyx-agent-core/migrations/0002_specs.sql` — audit for any `repo_name` references; if specs are project-scoped conceptually, add `project_id` column too (otherwise leave)
- `crates/nyx-agent-core/src/store/schema.rs:16` — confirm `sqlx::migrate!("./migrations")` picks up changes; no code change unless schema.rs hardcodes column lists

**Schema to add (before existing repos table):**
```sql
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  target_base_url TEXT,
  env_config_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_projects_name ON projects(name);
```

**Schema to modify on `repos` table:**
```sql
project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE
-- and:
CREATE INDEX idx_repos_project ON repos(project_id);
```

**Exit criteria:**
- `cargo sqlx prepare --workspace` succeeds (or equivalent if not using offline mode)
- `cargo build -p nyx-agent-core` green
- Delete any local `.sqlite` state files (dev DBs need recreating)

**Commit message:** `feat(core): introduce projects table; repos FK project_id`

---

## Phase 1 — Core types

**Depends on:** Phase 0.

**Goal:** Add `Project` struct and `ProjectId` newtype. Add `project_id` field to `Repo`.

**Files:**
- `crates/nyx-agent-core/src/project/mod.rs` — NEW file:
  ```rust
  use serde::{Deserialize, Serialize};

  #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
  pub struct ProjectId(pub String);

  impl ProjectId {
      pub fn new(id: impl Into<String>) -> Self { Self(id.into()) }
      pub fn as_str(&self) -> &str { &self.0 }
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct Project {
      pub id: ProjectId,
      pub name: String,
      pub description: Option<String>,
      pub target_base_url: Option<String>,
      pub env_config: Option<serde_json::Value>,
  }
  ```
- `crates/nyx-agent-core/src/repo/mod.rs:30-36` — add `pub project_id: ProjectId` field to `Repo` struct
- `crates/nyx-agent-core/src/lib.rs:19` — add `pub mod project; pub use project::{Project, ProjectId};`

**Exit criteria:**
- `cargo build -p nyx-agent-core` green (call sites for `Repo` constructor will break — fix in Phase 2 where store builds them)
- Allow temporary `Default::default()` or `todo!()` only inside test fixtures, not production paths

**Commit message:** `feat(core): add Project type, ProjectId newtype; Repo.project_id`

---

## Phase 2 — Store layer

**Depends on:** Phase 1.

**Goal:** New `ProjectStore`. Update `RepoStore` for FK semantics.

**Files:**
- `crates/nyx-agent-core/src/store/project.rs` — NEW:
  ```rust
  pub struct ProjectRecord { pub id: String, pub name: String, pub description: Option<String>, pub target_base_url: Option<String>, pub env_config_json: Option<String>, pub created_at: i64, pub updated_at: i64 }

  pub struct ProjectStore { pool: SqlitePool }

  impl ProjectStore {
      pub async fn create(&self, name: &str, description: Option<&str>, target_base_url: Option<&str>, env_config_json: Option<&str>) -> Result<ProjectRecord>;
      pub async fn list(&self) -> Result<Vec<ProjectRecord>>;
      pub async fn get(&self, id: &str) -> Result<Option<ProjectRecord>>;
      pub async fn get_by_name(&self, name: &str) -> Result<Option<ProjectRecord>>;
      pub async fn update(&self, id: &str, /* fields */) -> Result<ProjectRecord>;
      pub async fn delete(&self, id: &str) -> Result<()>;
  }
  ```
- `crates/nyx-agent-core/src/store/repo.rs:28-39` — add `pub project_id: String` to `RepoRecord`
- `crates/nyx-agent-core/src/store/repo.rs` — update ALL queries: INSERT (include project_id), SELECT (return project_id), add `list_by_project(project_id: &str) -> Result<Vec<RepoRecord>>`, modify `list()` to include project_id
- `crates/nyx-agent-core/src/store/mod.rs:47` — add `pub use project::{ProjectStore, ProjectRecord};`
- `crates/nyx-agent-core/src/store/testutil.rs` — fixture must create a default project first, then attach repos to it; helper `seed_default_project() -> ProjectRecord`

**Exit criteria:**
- `cargo test -p nyx-agent-core` green
- All `RepoStore` tests pass with the new FK

**Commit message:** `feat(core): ProjectStore + RepoRecord project_id`

---

## Phase 3 — Config

**Depends on:** Phase 2.

**Goal:** TOML schema groups repos under projects. Top-level `repos` array removed.

**Files:**
- `crates/nyx-agent-core/src/config.rs:308-335` — add:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct ProjectConfig {
      pub name: String,
      #[serde(default)]
      pub description: Option<String>,
      #[serde(default)]
      pub target_base_url: Option<String>,
      #[serde(default)]
      pub env_config: Option<toml::Value>,
      #[serde(default, rename = "repo")]
      pub repos: Vec<RepoConfig>,
  }
  ```
- `crates/nyx-agent-core/src/config.rs:41-42` — replace `pub repos: Vec<RepoConfig>` with `#[serde(default, rename = "project")] pub projects: Vec<ProjectConfig>`
- `crates/nyx-agent-core/src/config.rs:384-475` — rewrite roundtrip tests to use new `[[project]]` blocks
- `nyx-agent.toml` — replace `repo = []` with empty `# [[project]]` example comment; keep file minimal
- `crates/nyx-agent/tests/scan_cli.rs:49-52` — update fixture TOML:
  ```toml
  [[project]]
  name = "demo-project"

    [[project.repo]]
    name = "demo"
    i_own_this = true
    enabled = true
    source = { kind = "local-path", path = "..." }
  ```

**Exit criteria:**
- `cargo test -p nyx-agent-core` green
- TOML roundtrip test asserts new shape

**Commit message:** `feat(core): config schema with [[project]] grouping repos`

---

## Phase 4 — Run dispatcher

**Depends on:** Phase 3.

**Goal:** `RunDispatcher` operates per project. Workspace layout includes project. Events carry project_id.

**Files:**
- `crates/nyx-agent-core/src/run/mod.rs:210-234` — `RunDispatcher::from_config` and `with_explicit` unchanged signature; new entry point `dispatch_project(project: &Project, repos: &[Repo])`
- `crates/nyx-agent-core/src/run/mod.rs:264-341` — `dispatch()` adds `ProjectStarted { project_id, project_name }` event before per-repo loop, `ProjectFinished { project_id }` after
- `crates/nyx-agent-core/src/run/mod.rs:367-441` — per-repo events gain `project_id` field
- `crates/nyx-agent-core/src/run/workspace.rs:14` — path: `<state>/projects/<project_id>/repos/<repo_name>/` (was `<state>/repos/<repo_name>/`)
- `crates/nyx-agent-core/src/run/mod.rs:485` — test updates: build a project, attach repos, dispatch project

**Exit criteria:**
- `cargo test -p nyx-agent-core` green
- Workspace dir tree shows `projects/<id>/repos/<name>/` layout

**Commit message:** `feat(core): run dispatcher scoped to project`

---

## Phase 5 — API routes

**Depends on:** Phase 4.

**Goal:** Replace flat `/repos` routes with nested `/projects/:project_id/repos`. Add project CRUD.

**Files:**
- `crates/nyx-agent-api/src/router.rs:52-54` — replace existing repo routes with:
  ```rust
  .route("/api/v1/projects", get(list_projects).post(create_project))
  .route("/api/v1/projects/:project_id", get(get_project).patch(patch_project).delete(delete_project))
  .route("/api/v1/projects/:project_id/repos", get(list_project_repos).post(create_project_repo))
  .route("/api/v1/projects/:project_id/repos/test", post(test_repo_connectivity))
  .route("/api/v1/projects/:project_id/repos/:name", get(get_repo).patch(patch_repo).delete(delete_repo))
  .route("/api/v1/projects/:project_id/scan", post(scan_project))
  ```
- `crates/nyx-agent-api/src/router.rs:521-766` — rewrite handlers: `list_repos` → `list_project_repos(Path(project_id))`; `create_repo` → `create_project_repo(Path(project_id), Json(req))`; etc. Add `list_projects`, `create_project`, `get_project`, `patch_project`, `delete_project`, `scan_project`
- Request types: `CreateProjectRequest { name, description, target_base_url, env_config }`, `PatchProjectRequest { description, target_base_url, env_config }`
- `crates/nyx-agent-api/tests/api.rs` — rewrite all 78 repo-touching assertions. Pattern: each test creates project first, then repos under it

**Exit criteria:**
- `cargo test -p nyx-agent-api` green
- Manual: `curl /api/v1/projects` returns array; `curl /api/v1/projects/:id/repos` returns nested

**Commit message:** `feat(api): nested project/repo routes; project CRUD`

---

## Phase 6 — CLI

**Depends on:** Phase 4 (can run parallel with Phase 5).

**Goal:** New `project` subcommand. `scan` takes `--project` or `--repo` (latter requires project context).

**Files:**
- `crates/nyx-agent/src/main.rs:60-162` — add subcommand:
  ```rust
  Project { #[command(subcommand)] action: ProjectAction },
  ```
  with:
  ```rust
  enum ProjectAction {
      Create { name: String, #[arg(long)] description: Option<String>, #[arg(long)] target_base_url: Option<String> },
      List,
      Show { name: String },
      Delete { name: String },
      AddRepo { project: String, name: String, /* source flags */ },
  }
  ```
- `crates/nyx-agent/src/main.rs:62-84` — `Scan` gains:
  ```rust
  #[arg(long)] projects: Vec<String>,
  #[arg(long)] repos: Vec<String>,  // requires --project context or scoped scan
  ```
  Default (no flags): scan all enabled projects
- `crates/nyx-agent/src/main.rs:1130-1152` — `select_repos()` → `select_scan_targets() -> Vec<(Project, Vec<Repo>)>`. Logic: if `--projects` set, scan those; else scan all enabled projects. `--repos` filters within selected projects
- `crates/nyx-agent/src/main.rs:336-384` — `scan()` iterates `(project, repos)` tuples, calls `dispatch_project` per tuple
- `crates/nyx-agent/src/main.rs:203-207` — add `Command::Project` dispatch
- `crates/nyx-agent/tests/scan_cli.rs` — rewrite

**Decision (per plan discussion):** Bare `--repo NAME` without `--project` is REJECTED with error: `--repo requires --project context (or use --projects to scan whole projects)`. Forces explicit scoping; no ambiguous global repo lookup.

**Exit criteria:**
- `cargo test -p nyx-agent` green
- `nyx-agent project create foo` works end-to-end with `nyx-agent project list`

**Commit message:** `feat(cli): project subcommand; scan --project/--repo scoping`

---

## Phase 7 — Sandbox env-builder + chain runner

**Depends on:** Phase 4 (can run parallel with Phases 5/6).

**Goal:** `EnvBuilder` and `ChainRunner` take project context. Super-compose name derived from project. Chain steps validated same-project.

**Files:**
- `crates/nyx-agent-sandbox/src/env/mod.rs:81-122` — `EnvBuilder::discover` signature: `discover(workspace: PathBuf, state_root: PathBuf, project: &Project, repos: Vec<RepoInput>)`. Super-compose filename: `nyx-super-compose-<project_name>.yml`. Project's `target_base_url` and `env_config` flow into compose merge as overrides
- `crates/nyx-agent-sandbox/src/chain_runner.rs:73-94` — `ChainRun` gains `pub project_id: ProjectId`. `ChainRun::new` validates all `members[].repo_name` belong to the project; reject with `ChainError::CrossProjectStep`
- `crates/nyx-agent-sandbox/src/chain_runner.rs:98-110` — `ChainRunner` constructor unchanged; validation lives on `ChainRun`
- `crates/nyx-agent-sandbox/tests/env_builder.rs:17` — update fixtures to construct a `Project` and pass to `EnvBuilder`

**Exit criteria:**
- `cargo test -p nyx-agent-sandbox` green
- Multi-repo compose merge produces `nyx-super-compose-<project>.yml` reflecting both repos' compose files

**Commit message:** `feat(sandbox): env-builder + chain-runner project-scoped`

---

## Phase 8 — Frontend

**Depends on:** Phase 5 (API must be live).

**Goal:** React UI restructured around projects. Repos nested under project detail pages.

**Files:**
- `frontend/src/pages/Projects/ProjectList.tsx` — NEW. Lists projects, "+ New Project" button
- `frontend/src/pages/Projects/ProjectDetail.tsx` — NEW. Shows project metadata + nested repo list (replaces standalone RepoList)
- `frontend/src/pages/Projects/ProjectAddModal.tsx` — NEW. Form: name, description, target_base_url
- `frontend/src/pages/Repos/RepoList.tsx` — DELETE (replaced)
- `frontend/src/pages/Repos/RepoAddModal.tsx` — move into ProjectDetail context; accepts `projectId` prop, POSTs to `/api/v1/projects/:id/repos`
- `frontend/src/pages/Repos/repoStatus.ts` — keep
- `frontend/src/App.tsx` (or router config) — routes:
  - `/projects` → ProjectList
  - `/projects/:projectId` → ProjectDetail
  - Remove standalone `/repos`
- `frontend/src/api/` — update all fetch URLs to nested form; add `projectsApi.ts`

**Exit criteria:**
- `npm run build` (or `npm run lint && npm run typecheck`) green
- Manual browser test: create project → add two repos under it → see them grouped on ProjectDetail

**Commit message:** `feat(ui): project tree, nested repos under project detail`

---

## Phase 9 — Docs + cleanup

**Depends on:** All prior phases.

**Goal:** Docs reflect new model. Example config demonstrates backend+frontend grouping.

**Files:**
- `docs/cli.md:77-87` — rewrite repo section as project section; new examples for `project create`, `project add-repo`, `scan --project`
- `docs/SUMMARY.md` — add `Projects` section, link to project concept doc
- `docs/quickstart.md` — update walkthrough to start with `project create`
- `nyx-agent.toml` — concrete example with one project containing backend + frontend:
  ```toml
  [[project]]
  name = "example-app"
  description = "Example multi-repo product"
  target_base_url = "http://localhost:3000"

    [[project.repo]]
    name = "example-backend"
    i_own_this = true
    enabled = true
    source = { kind = "local-path", path = "/path/to/backend" }

    [[project.repo]]
    name = "example-frontend"
    i_own_this = true
    enabled = true
    source = { kind = "local-path", path = "/path/to/frontend" }
  ```
- `README.md` — update Quickstart snippet
- `crates/nyx-agent-core/src/repo/mod.rs:1-3` — update phase header comment
- `crates/nyx-agent-sandbox/src/env/mod.rs:1-6` — update phase header comment; document that env-builder now operates per project
- `docs/PROJECT_ENTITY_PLAN.md` (this file) — append "Status: COMPLETE — merged YYYY-MM-DD" footer

**Exit criteria:**
- `mdbook build docs/` (or whatever docs build is) green
- `nyx-agent.toml` validated by `cargo test -p nyx-agent-core` config roundtrip

**Commit message:** `docs: project entity model; updated examples`

---

## Risk hotspots

- **Phase 0:** Local dev DBs need wiping. Add note to delete `*.sqlite` after pulling.
- **Phase 5:** Largest test churn (~78 repo assertions in `api.rs`). Budget extra time.
- **Phase 6:** Bare `--repo NAME` rejection is a UX choice — confirms explicitness. Revisit if friction.
- **Phase 8:** React routes change breaks any bookmarks. Acceptable pre-1.0.

## Out of scope (future phases)

- Project-level RBAC / multi-tenant
- Cross-project finding correlation
- Project templates (canned configs for common stacks)
- Project import from `docker-compose.yml` discovery (auto-create project from compose file)

---

**Status: COMPLETE — merged 2026-05-18.** All nine phases landed:
schema baseline, core types, store layer, config grouping, run
dispatcher scoping, API nesting, CLI `project` subcommand, sandbox
env-builder + chain-runner project scoping, frontend project tree,
and the docs/cleanup pass that produced this footer.

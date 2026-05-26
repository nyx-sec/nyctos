//! Filesystem layout for the agent's persistent state.
//!
//! Creates `~/.local/share/nyx-agent/{runs,repos,findings,logs,cache,bundles,secrets}`
//! on first use. On Unix the root directory and its subdirectories are
//! restricted to mode `0700` so other local users cannot read run state.

use std::path::{Path, PathBuf};

use thiserror::Error;

const SUBDIRS: &[&str] =
    &["runs", "repos", "findings", "logs", "cache", "bundles", "secrets", "traces"];

#[derive(Debug, Error)]
pub enum StateError {
    #[error("could not resolve user data directory (HOME/XDG_DATA_HOME unset?)")]
    NoDataDir,
    #[error("failed to create {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set permissions on {path}: {source}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    pub fn default_root() -> Result<PathBuf, StateError> {
        let base = dirs::data_dir().ok_or(StateError::NoDataDir)?;
        Ok(base.join("nyx-agent"))
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn discover() -> Result<Self, StateError> {
        Ok(Self::at(Self::default_root()?))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }

    pub fn repos(&self) -> PathBuf {
        self.root.join("repos")
    }

    /// Project-scoped repos directory at
    /// `<root>/projects/<project_id>/repos`. Ingestion writes per-repo
    /// workspace subdirs under this path so two repos with the same
    /// name in different projects never collide.
    pub fn project_repos(&self, project_id: &str) -> PathBuf {
        self.root.join("projects").join(project_id).join("repos")
    }

    pub fn findings(&self) -> PathBuf {
        self.root.join("findings")
    }

    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// Per-finding repro bundle output directory (`<state>/bundles`).
    /// One tarball per finding is written here when the operator
    /// requests a repro bundle.
    pub fn bundles(&self) -> PathBuf {
        self.root.join("bundles")
    }

    /// Per-AI-task trace artefact directory (`<state>/traces`). The
    /// exploration pass writes one `<task_id>.jsonl` per run under
    /// [`Self::traces_for_run`] and stamps the path on the matching
    /// `agent_traces.conversation_jsonl_path` row.
    pub fn traces(&self) -> PathBuf {
        self.root.join("traces")
    }

    /// Per-run trace directory at `<state>/traces/<run_id>`. Created
    /// on demand by the pass that writes into it; callers should
    /// `std::fs::create_dir_all` before opening files.
    pub fn traces_for_run(&self, run_id: &str) -> PathBuf {
        self.traces().join(run_id)
    }

    /// Secrets directory at `<state>/secrets`, created with mode `0700`
    /// by [`Self::ensure`]. The env-builder reads
    /// `<state>/secrets/test.env` (and the optional `test.env.allow`
    /// sibling) from this path. Surfaced as a single canonical accessor
    /// so the wizard, doctor, and env-builder name the same location.
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// Path of the env-builder test secrets file
    /// (`<state>/secrets/test.env`). Absent until the operator drops a
    /// file at this path; the env-builder fails closed when it is
    /// missing.
    pub fn secrets_test_env_path(&self) -> PathBuf {
        self.secrets().join("test.env")
    }

    /// Path of the optional env-builder secrets allowlist
    /// (`<state>/secrets/test.env.allow`). Absent on a fresh install;
    /// the env-builder treats a missing file as an empty allowlist.
    pub fn secrets_test_env_allow_path(&self) -> PathBuf {
        self.secrets().join("test.env.allow")
    }

    /// Bearer-token file consumed by the API auth middleware. Stored
    /// at `<state>/auth_token` with mode `0600`. Absent before the
    /// daemon's first launch.
    pub fn auth_token_path(&self) -> PathBuf {
        self.root.join("auth_token")
    }

    /// Create the root and every subdirectory if missing; idempotent. On
    /// Unix every directory created or already present is forced to mode
    /// `0700`.
    #[tracing::instrument(skip_all, fields(root = %self.root.display()))]
    pub fn ensure(&self) -> Result<(), StateError> {
        create_secure_dir(&self.root)?;
        for sub in SUBDIRS {
            create_secure_dir(&self.root.join(sub))?;
        }
        Ok(())
    }

    /// Load the bearer token from `auth_token`, generating + persisting
    /// a fresh one if absent. The minted file is `0o600` so a second
    /// user on the box cannot read it. Callers that have already
    /// invoked [`Self::ensure`] do not need to repeat it.
    pub fn load_or_mint_auth_token(&self) -> Result<String, StateError> {
        let path = self.auth_token_path();
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|source| StateError::Create { path: path.clone(), source })?;
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        let token = mint_token();
        write_secure_file(&path, token.as_bytes())?;
        Ok(token)
    }
}

/// Mint a 256-bit URL-safe token. Surfaced for tests; the daemon
/// always goes through [`StateDir::load_or_mint_auth_token`].
pub fn mint_token() -> String {
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn write_secure_file(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|source| StateError::Create { path: parent.to_path_buf(), source })?;
    }
    write_with_mode(path, bytes)
        .map_err(|source| StateError::Create { path: path.to_path_buf(), source })?;
    Ok(())
}

#[cfg(unix)]
fn write_with_mode(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()
}

#[cfg(not(unix))]
fn write_with_mode(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn create_secure_dir(path: &Path) -> Result<(), StateError> {
    std::fs::create_dir_all(path)
        .map_err(|source| StateError::Create { path: path.to_path_buf(), source })?;
    set_secure_perms(path)
}

#[cfg(unix)]
fn set_secure_perms(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|source| StateError::Permissions { path: path.to_path_buf(), source })
}

#[cfg(not(unix))]
fn set_secure_perms(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn ensure_creates_all_subdirs() {
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("ensure once");
        for sub in SUBDIRS {
            let p = sd.root().join(sub);
            assert!(p.is_dir(), "{} should exist", p.display());
        }
    }

    #[test]
    fn ensure_is_idempotent() {
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("first");
        sd.ensure().expect("second");
        sd.ensure().expect("third");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_sets_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("ensure");
        for p in std::iter::once(sd.root().to_path_buf())
            .chain(SUBDIRS.iter().map(|s| sd.root().join(s)))
        {
            let mode = std::fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} mode {:o}", p.display(), mode);
        }
    }

    #[test]
    fn paths_match_layout() {
        let sd = StateDir::at("/var/state");
        assert_eq!(sd.runs(), Path::new("/var/state/runs"));
        assert_eq!(sd.repos(), Path::new("/var/state/repos"));
        assert_eq!(sd.project_repos("acme"), Path::new("/var/state/projects/acme/repos"));
        assert_eq!(sd.findings(), Path::new("/var/state/findings"));
        assert_eq!(sd.logs(), Path::new("/var/state/logs"));
        assert_eq!(sd.cache(), Path::new("/var/state/cache"));
        assert_eq!(sd.bundles(), Path::new("/var/state/bundles"));
        assert_eq!(sd.traces(), Path::new("/var/state/traces"));
        assert_eq!(sd.traces_for_run("run-abc"), Path::new("/var/state/traces/run-abc"));
        assert_eq!(sd.secrets(), Path::new("/var/state/secrets"));
        assert_eq!(sd.secrets_test_env_path(), Path::new("/var/state/secrets/test.env"));
        assert_eq!(
            sd.secrets_test_env_allow_path(),
            Path::new("/var/state/secrets/test.env.allow"),
        );
        assert_eq!(sd.auth_token_path(), Path::new("/var/state/auth_token"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_creates_secrets_dir_at_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("ensure");
        let secrets = sd.secrets();
        assert!(secrets.is_dir(), "secrets dir should exist at {}", secrets.display());
        let mode = std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "secrets dir mode {mode:o}");
    }

    #[test]
    fn load_or_mint_auth_token_persists_idempotently() {
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("ensure");
        let first = sd.load_or_mint_auth_token().expect("mint first");
        assert_eq!(first.len(), 64, "32 random bytes -> 64 hex chars");
        let second = sd.load_or_mint_auth_token().expect("mint second");
        assert_eq!(first, second, "second call must return the persisted token");
        let raw = std::fs::read_to_string(sd.auth_token_path()).expect("read file");
        assert_eq!(raw.trim(), first);
    }

    #[cfg(unix)]
    #[test]
    fn auth_token_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tmp_root();
        let sd = StateDir::at(tmp.path().join("nyx-agent"));
        sd.ensure().expect("ensure");
        sd.load_or_mint_auth_token().expect("mint");
        let mode = std::fs::metadata(sd.auth_token_path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file mode {mode:o}");
    }
}

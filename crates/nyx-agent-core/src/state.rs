//! Filesystem layout for the agent's persistent state.
//!
//! Creates `~/.local/share/nyx-agent/{runs,repos,findings,logs,cache}` on
//! first use. On Unix the root directory and its subdirectories are
//! restricted to mode `0700` so other local users cannot read run state.

use std::path::{Path, PathBuf};

use thiserror::Error;

const SUBDIRS: &[&str] = &["runs", "repos", "findings", "logs", "cache"];

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

    pub fn findings(&self) -> PathBuf {
        self.root.join("findings")
    }

    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// Create the root and every subdirectory if missing; idempotent. On
    /// Unix every directory created or already present is forced to mode
    /// `0700`.
    pub fn ensure(&self) -> Result<(), StateError> {
        create_secure_dir(&self.root)?;
        for sub in SUBDIRS {
            create_secure_dir(&self.root.join(sub))?;
        }
        Ok(())
    }
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
        assert_eq!(sd.findings(), Path::new("/var/state/findings"));
        assert_eq!(sd.logs(), Path::new("/var/state/logs"));
        assert_eq!(sd.cache(), Path::new("/var/state/cache"));
    }
}

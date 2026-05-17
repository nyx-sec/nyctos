//! Typed configuration loaded from `nyx-agent.toml`.
//!
//! Missing sections fall back to defaults so that `nyx-agent doctor` and
//! other read-only operations work in a fresh checkout with no config
//! file on disk.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialise config: {0}")]
    Serialise(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: GeneralConfig,
    pub performance: PerformanceConfig,
    pub sandbox: SandboxConfig,
    pub ai: AiConfig,
    pub ui: UiConfig,
    pub triggers: TriggersConfig,
    #[serde(rename = "repo", default)]
    pub repos: Vec<RepoConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    pub log_level: String,
    pub state_dir: Option<PathBuf>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self { log_level: "info".to_string(), state_dir: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceConfig {
    pub max_parallel_scans: u32,
    pub scan_timeout_secs: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self { max_parallel_scans: 4, scan_timeout_secs: 600 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub allow_network: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self { enabled: true, allow_network: false }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_base: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub listen_addr: String,
    pub open_browser: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self { listen_addr: "127.0.0.1:7878".to_string(), open_browser: false }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TriggersConfig {
    pub on_push: bool,
    pub on_pr: bool,
    pub schedule_cron: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        Self::parse(&raw, path)
    }

    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Self::parse(&raw, path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read { path: path.to_path_buf(), source }),
        }
    }

    pub fn parse(raw: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(raw)
            .map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source })
    }

    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn defaults_roundtrip_through_toml() {
        let cfg = Config::default();
        let rendered = cfg.to_toml_string().expect("serialise defaults");
        let parsed = Config::parse(&rendered, &PathBuf::from("<test>")).expect("parse defaults");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn populated_config_roundtrips() {
        let cfg = Config {
            general: GeneralConfig {
                log_level: "debug".to_string(),
                state_dir: Some(PathBuf::from("/tmp/nyx")),
            },
            performance: PerformanceConfig { max_parallel_scans: 8, scan_timeout_secs: 1200 },
            sandbox: SandboxConfig { enabled: false, allow_network: true },
            ai: AiConfig {
                provider: Some("anthropic".to_string()),
                model: Some("claude-opus-4-7".to_string()),
                api_base: None,
            },
            ui: UiConfig { listen_addr: "0.0.0.0:9999".to_string(), open_browser: true },
            triggers: TriggersConfig {
                on_push: true,
                on_pr: true,
                schedule_cron: Some("0 * * * *".to_string()),
            },
            repos: vec![RepoConfig {
                name: "nyx-pro".to_string(),
                path: PathBuf::from("/srv/repos/nyx-pro"),
                default_branch: Some("main".to_string()),
                enabled: true,
            }],
        };
        let rendered = cfg.to_toml_string().expect("serialise");
        let parsed = Config::parse(&rendered, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn missing_file_returns_default() {
        let path = PathBuf::from("/definitely/does/not/exist/nyx-agent.toml");
        let cfg = Config::load_or_default(&path).expect("missing file -> default");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn empty_string_parses_to_default() {
        let cfg = Config::parse("", &PathBuf::from("<test>")).expect("empty parses");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn repo_enabled_defaults_to_true_when_omitted() {
        let raw = "[[repo]]\nname = \"nyx-pro\"\npath = \"/srv/repos/nyx-pro\"\n";
        let cfg = Config::parse(raw, &PathBuf::from("<test>")).expect("parse");
        assert_eq!(cfg.repos.len(), 1);
        assert!(
            cfg.repos[0].enabled,
            "declared repo without explicit enabled must default to true"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let raw = "garbage_field = true\n";
        let err = Config::parse(raw, &PathBuf::from("<test>")).expect_err("must reject");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }
}

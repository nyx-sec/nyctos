//! OS-keychain backed secret storage.
//!
//! Phase 09 stores AI provider API keys in the platform keychain via the
//! `keyring` crate (Keychain on macOS, libsecret/secret-service on Linux,
//! Credential Manager on Windows) so the operator's tokens never land
//! in `nyx-agent.toml` or the JSON log. The keychain entry name is
//! `<service>:<account>` where `service` defaults to `nyx-agent` and the
//! account is a stable identifier such as `ai-anthropic`.
//!
//! Tracing redaction lives in [`super::log_init`] so even a stray
//! `tracing::info!(token = ?secret)` cannot leak the bytes.
//!
//! In addition to the keyring backend, the store also supports an
//! in-process [`SecretStore::memory`] backend for CI / unattended
//! environments where the platform keychain is unavailable. The runtime
//! selector is `NYX_SECRETS_BACKEND`: set to `memory` to make
//! [`SecretStore::from_env`] return the in-process backend instead of
//! the keyring.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

/// Account-name slot for the Anthropic API key.
pub const ACCOUNT_AI_ANTHROPIC: &str = "ai-anthropic";
/// Account-name slot for a local OpenAI-compatible runtime endpoint.
/// Stored as a secret because operators commonly include a bearer
/// token in the URL itself.
pub const ACCOUNT_AI_LOCAL_LLM: &str = "ai-local-llm";

/// Default keychain service identifier used by every entry. Operators
/// running multiple installations can override via
/// [`SecretStore::with_service`].
pub const DEFAULT_SERVICE: &str = "nyx-agent";

/// Environment variable that selects the secret backend at startup.
/// Recognised values: `keyring` (default) and `memory`.
pub const ENV_BACKEND: &str = "NYX_SECRETS_BACKEND";

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret not found for account `{0}`")]
    NotFound(String),
    #[error("keyring backend rejected access to `{account}`: {source}")]
    Backend {
        account: String,
        #[source]
        source: keyring::Error,
    },
}

#[derive(Debug, Clone)]
enum Backend {
    Keyring(String),
    Memory(Arc<Mutex<HashMap<String, String>>>),
}

/// Thin wrapper around `keyring::Entry` (or an in-process `HashMap` for
/// CI / unattended environments) that scopes every secret under a
/// single namespace. Cloning is cheap: the keyring variant clones the
/// service string, the memory variant clones the `Arc`.
#[derive(Debug, Clone)]
pub struct SecretStore {
    backend: Backend,
}

impl Default for SecretStore {
    fn default() -> Self {
        Self { backend: Backend::Keyring(DEFAULT_SERVICE.to_string()) }
    }
}

impl SecretStore {
    /// Override the keyring service identifier. Useful in tests where
    /// the suite wants its own namespace so it never clobbers a real
    /// operator install.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self { backend: Backend::Keyring(service.into()) }
    }

    /// In-process backend that stores secrets in a `HashMap` shared
    /// between clones via an `Arc<Mutex<_>>`. Intended for CI and the
    /// integration test suite, where the platform keychain is either
    /// unavailable (Linux containers without `secret-service`) or
    /// would prompt for unlock (macOS).
    pub fn memory() -> Self {
        Self { backend: Backend::Memory(Arc::new(Mutex::new(HashMap::new()))) }
    }

    /// Select the backend from the `NYX_SECRETS_BACKEND` environment
    /// variable: `memory` returns the in-process backend, anything else
    /// (including unset) falls back to the keyring under the default
    /// service name.
    pub fn from_env() -> Self {
        match std::env::var(ENV_BACKEND).ok().as_deref() {
            Some("memory") => Self::memory(),
            _ => Self::default(),
        }
    }

    pub fn service(&self) -> &str {
        match &self.backend {
            Backend::Keyring(s) => s.as_str(),
            Backend::Memory(_) => "memory",
        }
    }

    /// Persist `value` under `account`. Overwrites any existing value.
    pub fn set(&self, account: &str, value: &str) -> Result<(), SecretError> {
        match &self.backend {
            Backend::Keyring(service) => {
                let entry = keyring_entry(service, account)?;
                entry
                    .set_password(value)
                    .map_err(|source| SecretError::Backend { account: account.to_string(), source })
            }
            Backend::Memory(map) => {
                let mut g = map.lock().expect("memory secret store poisoned");
                g.insert(account.to_string(), value.to_string());
                Ok(())
            }
        }
    }

    /// Fetch the stored value, or `Ok(None)` if no entry exists yet.
    pub fn get(&self, account: &str) -> Result<Option<String>, SecretError> {
        match &self.backend {
            Backend::Keyring(service) => {
                let entry = keyring_entry(service, account)?;
                match entry.get_password() {
                    Ok(value) => Ok(Some(value)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(source) => {
                        Err(SecretError::Backend { account: account.to_string(), source })
                    }
                }
            }
            Backend::Memory(map) => {
                let g = map.lock().expect("memory secret store poisoned");
                Ok(g.get(account).cloned())
            }
        }
    }

    /// Remove the entry. Idempotent: missing entries are not an error.
    pub fn delete(&self, account: &str) -> Result<(), SecretError> {
        match &self.backend {
            Backend::Keyring(service) => {
                let entry = keyring_entry(service, account)?;
                match entry.delete_credential() {
                    Ok(()) => Ok(()),
                    Err(keyring::Error::NoEntry) => Ok(()),
                    Err(source) => {
                        Err(SecretError::Backend { account: account.to_string(), source })
                    }
                }
            }
            Backend::Memory(map) => {
                let mut g = map.lock().expect("memory secret store poisoned");
                g.remove(account);
                Ok(())
            }
        }
    }
}

fn keyring_entry(service: &str, account: &str) -> Result<keyring::Entry, SecretError> {
    keyring::Entry::new(service, account)
        .map_err(|source| SecretError::Backend { account: account.to_string(), source })
}

/// Returns true if the given byte sequence looks like an Anthropic-style
/// API key (`sk-ant-...`, `sk-...`, or any high-entropy `xxx_xxxxxxxx`).
/// Used by the tracing redaction layer as a cheap pre-filter; callers
/// that already know a value is a secret should redact it unconditionally.
pub fn looks_like_secret(s: &str) -> bool {
    let trimmed = s.trim_matches(|c: char| c == '"' || c == '\'');
    trimmed.starts_with("sk-")
        || trimmed.starts_with("sk_")
        || (trimmed.len() >= 32 && trimmed.contains('_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_secret_recognises_common_shapes() {
        assert!(looks_like_secret("sk-ant-api03-aaaaa"));
        assert!(looks_like_secret("sk-test-1234"));
        assert!(looks_like_secret("ghp_abcdefghijklmnopqrstuvwxyz0123"));
        assert!(!looks_like_secret("hello"));
        assert!(!looks_like_secret("nyx-agent"));
    }

    #[test]
    fn memory_backend_round_trips_values() {
        let store = SecretStore::memory();
        assert_eq!(store.get(ACCOUNT_AI_ANTHROPIC).unwrap(), None);
        store.set(ACCOUNT_AI_ANTHROPIC, "sk-ant-test").unwrap();
        assert_eq!(
            store.get(ACCOUNT_AI_ANTHROPIC).unwrap().as_deref(),
            Some("sk-ant-test"),
        );
        store.delete(ACCOUNT_AI_ANTHROPIC).unwrap();
        assert_eq!(store.get(ACCOUNT_AI_ANTHROPIC).unwrap(), None);
    }

    #[test]
    fn memory_backend_is_shared_across_clones() {
        let a = SecretStore::memory();
        let b = a.clone();
        a.set(ACCOUNT_AI_LOCAL_LLM, "bearer-xyz").unwrap();
        assert_eq!(b.get(ACCOUNT_AI_LOCAL_LLM).unwrap().as_deref(), Some("bearer-xyz"));
    }

    #[test]
    fn from_env_honours_memory_selector() {
        // Save and restore the env var so we don't pollute sibling tests.
        let prior = std::env::var(ENV_BACKEND).ok();
        std::env::set_var(ENV_BACKEND, "memory");
        let s = SecretStore::from_env();
        assert_eq!(s.service(), "memory");
        match prior {
            Some(v) => std::env::set_var(ENV_BACKEND, v),
            None => std::env::remove_var(ENV_BACKEND),
        }
    }
}

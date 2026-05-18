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

/// Thin wrapper around `keyring::Entry` that scopes every secret under
/// a single service namespace. Cloning is cheap (just a `String`).
#[derive(Debug, Clone)]
pub struct SecretStore {
    service: String,
}

impl Default for SecretStore {
    fn default() -> Self {
        Self { service: DEFAULT_SERVICE.to_string() }
    }
}

impl SecretStore {
    /// Override the keyring service identifier. Useful in tests where
    /// the suite wants its own namespace so it never clobbers a real
    /// operator install.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    /// Persist `value` under `account`. Overwrites any existing value.
    pub fn set(&self, account: &str, value: &str) -> Result<(), SecretError> {
        let entry = self.entry(account)?;
        entry
            .set_password(value)
            .map_err(|source| SecretError::Backend { account: account.to_string(), source })
    }

    /// Fetch the stored value, or `Ok(None)` if no entry exists yet.
    pub fn get(&self, account: &str) -> Result<Option<String>, SecretError> {
        let entry = self.entry(account)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(source) => {
                Err(SecretError::Backend { account: account.to_string(), source })
            }
        }
    }

    /// Remove the entry. Idempotent: missing entries are not an error.
    pub fn delete(&self, account: &str) -> Result<(), SecretError> {
        let entry = self.entry(account)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(source) => {
                Err(SecretError::Backend { account: account.to_string(), source })
            }
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry, SecretError> {
        keyring::Entry::new(&self.service, account)
            .map_err(|source| SecretError::Backend { account: account.to_string(), source })
    }
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
}

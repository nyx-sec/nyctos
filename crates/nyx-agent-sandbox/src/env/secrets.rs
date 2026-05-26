//! Prod-token regex scan for `<state>/secrets/test.env`.
//!
//! Threat model. The env-builder is a dev-env replay surface. An
//! operator who hands it production credentials by accident (a real
//! Stripe live key, an AWS prod ARN, a working GitHub PAT) risks the
//! sandboxed services touching production from inside the harness. The
//! check refuses to start when any line of `test.env` matches a
//! prod-token shape. Fail-closed: a single match halts the run with a
//! clear error message that names the file, the line number, and the
//! token kind that matched.
//!
//! The regex set is deliberately conservative; it favours false
//! positives over false negatives. Operators that hit a false positive
//! on a synthetic test value can rename it (e.g.
//! `STRIPE_TEST_KEY=sk_test_...` instead of `sk_live_...`) or list a
//! tighter regex in `<state>/secrets/test.env.allow` (one regex per
//! line, `#` for comments) to whitelist values matched verbatim by the
//! allow regex on the offending line.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error(
        "secrets file missing: {path}; create the file with the test-only credentials \
         the dev env needs before running env-builder"
    )]
    Missing { path: PathBuf },
    #[error("secrets file unreadable: {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "prod-shaped credential detected in {path} on line {line}: matches the {kind} \
         regex. nyx-agent refuses to start with production secrets in test.env; remove \
         the credential (or replace it with a test-mode equivalent) and try again."
    )]
    ProdToken { path: PathBuf, line: usize, kind: &'static str },
    #[error("malformed allowlist entry in {path} on line {line}: {source}")]
    Allowlist {
        path: PathBuf,
        line: usize,
        #[source]
        source: regex::Error,
    },
}

/// Parsed contents of a validated `test.env`. The runner forwards
/// [`SecretsBundle::path`] to `docker compose --env-file` so the
/// services see the same values the scan already vetted.
#[derive(Debug, Clone)]
pub struct SecretsBundle {
    pub path: PathBuf,
    pub entries: Vec<(String, String)>,
}

/// Verify `<state_root>/secrets/test.env` exists and contains no
/// prod-shaped credentials. Returns a [`SecretsBundle`] the caller can
/// hand to `docker compose --env-file`.
///
/// An optional sibling `<state_root>/secrets/test.env.allow` may carry
/// one regex per line; any line in `test.env` that matches a prod-token
/// regex AND the allow regex covers the same byte range is permitted
/// through. The allowlist file is optional - a missing file means an
/// empty allowlist.
pub fn check(state_root: &Path) -> Result<SecretsBundle, SecretsError> {
    let path = state_root.join("secrets").join("test.env");
    if !path.is_file() {
        return Err(SecretsError::Missing { path });
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|source| SecretsError::Read { path: path.clone(), source })?;
    let allow_path = state_root.join("secrets").join("test.env.allow");
    let allowlist = load_allowlist(&allow_path)?;
    scan(&path, &raw, &allowlist)
}

fn scan(path: &Path, raw: &str, allowlist: &[Regex]) -> Result<SecretsBundle, SecretsError> {
    let regexes = prod_token_regexes();
    let mut entries = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        for (kind, re) in regexes {
            let Some(m) = re.find(line) else { continue };
            if allowlist_covers(allowlist, line, m.range()) {
                continue;
            }
            return Err(SecretsError::ProdToken { path: path.to_path_buf(), line: line_no, kind });
        }
        if let Some((k, v)) = parse_env_line(line) {
            entries.push((k, v));
        }
    }
    Ok(SecretsBundle { path: path.to_path_buf(), entries })
}

/// Read `<state>/secrets/test.env.allow` if it exists. One regex per
/// line; blank lines and `#`-prefixed comments are ignored. A missing
/// file yields an empty list (no allowlist active).
fn load_allowlist(path: &Path) -> Result<Vec<Regex>, SecretsError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|source| SecretsError::Read { path: path.to_path_buf(), source })?;
    let mut out = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let re = Regex::new(trimmed).map_err(|source| SecretsError::Allowlist {
            path: path.to_path_buf(),
            line: line_no,
            source,
        })?;
        out.push(re);
    }
    Ok(out)
}

/// True when some allow regex matches a byte range on `line` that
/// covers the prod-token match's byte range. Requiring containment
/// (not just any match on the line) prevents an allowlist entry from
/// laundering an unrelated prod token that happens to share a line
/// with a synthetic value.
fn allowlist_covers(allowlist: &[Regex], line: &str, prod_range: std::ops::Range<usize>) -> bool {
    for allow in allowlist {
        for am in allow.find_iter(line) {
            if am.start() <= prod_range.start && am.end() >= prod_range.end {
                return true;
            }
        }
    }
    false
}

fn parse_env_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let eq = trimmed.find('=')?;
    let key = trimmed[..eq].trim();
    if key.is_empty() {
        return None;
    }
    let mut val = trimmed[eq + 1..].trim().to_string();
    if val.len() >= 2 {
        let first = val.chars().next().unwrap();
        let last = val.chars().last().unwrap();
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            val = val[1..val.len() - 1].to_string();
        }
    }
    Some((key.to_string(), val))
}

fn prod_token_regexes() -> &'static Vec<(&'static str, Regex)> {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            ("Stripe live key (sk_live_...)", Regex::new(r"sk_live_[0-9a-zA-Z]{16,}").unwrap()),
            (
                "GitHub personal access token (ghp_<40>)",
                Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
            ),
            (
                "GitHub fine-grained PAT (github_pat_...)",
                Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b").unwrap(),
            ),
            ("GitHub OAuth token (gho_<36>)", Regex::new(r"\bgho_[A-Za-z0-9]{36}\b").unwrap()),
            ("AWS access key id (AKIA...)", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("AWS ARN", Regex::new(r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s'\x22]+").unwrap()),
            (
                "Slack token (xox[abprs]-...)",
                Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}").unwrap(),
            ),
            (
                "Google Cloud service account key (private_key)",
                Regex::new(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----").unwrap(),
            ),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_state(root: &Path, body: &str) -> PathBuf {
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let p = secrets_dir.join("test.env");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn write_allowlist(root: &Path, body: &str) -> PathBuf {
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let p = secrets_dir.join("test.env.allow");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn missing_file_is_fail_closed() {
        let tmp = tempdir().unwrap();
        let err = check(tmp.path()).unwrap_err();
        assert!(matches!(err, SecretsError::Missing { .. }));
    }

    #[test]
    fn clean_file_parses_entries() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "# comment\nDB_USER=test\nDB_PASS=\"shh\"\nEMPTY=\n");
        let bundle = check(tmp.path()).expect("clean");
        let map: std::collections::HashMap<_, _> = bundle.entries.into_iter().collect();
        assert_eq!(map.get("DB_USER").unwrap(), "test");
        assert_eq!(map.get("DB_PASS").unwrap(), "shh");
        assert_eq!(map.get("EMPTY").unwrap(), "");
    }

    #[test]
    fn stripe_live_key_blocks_run() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "DB_USER=test\nSTRIPE_KEY=sk_live_abcDEF0123456789xyz\n");
        let err = check(tmp.path()).unwrap_err();
        let SecretsError::ProdToken { kind, line, .. } = err else {
            panic!("expected ProdToken");
        };
        assert!(kind.contains("Stripe"));
        assert_eq!(line, 2);
    }

    #[test]
    fn github_pat_blocks_run() {
        let tmp = tempdir().unwrap();
        let token = format!("GH_TOKEN=ghp_{}", "A".repeat(36));
        write_state(tmp.path(), &token);
        let err = check(tmp.path()).unwrap_err();
        assert!(matches!(err, SecretsError::ProdToken { .. }));
    }

    #[test]
    fn aws_access_key_blocks_run() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
        let err = check(tmp.path()).unwrap_err();
        assert!(matches!(err, SecretsError::ProdToken { .. }));
    }

    #[test]
    fn aws_arn_blocks_run() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "ROLE=arn:aws:iam::123456789012:role/prod-admin\n");
        let err = check(tmp.path()).unwrap_err();
        assert!(matches!(err, SecretsError::ProdToken { .. }));
    }

    #[test]
    fn sk_test_key_is_allowed() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "STRIPE_KEY=sk_test_abc123\n");
        check(tmp.path()).expect("sk_test_ is fine");
    }

    #[test]
    fn allowlist_lets_synthetic_arn_through() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "ROLE=arn:aws:iam::000000000000:role/test-only\n");
        write_allowlist(tmp.path(), "arn:aws:iam::000000000000:role/test-only\n");
        check(tmp.path()).expect("allowlisted synthetic ARN must pass");
    }

    #[test]
    fn allowlist_does_not_launder_unrelated_prod_token() {
        let tmp = tempdir().unwrap();
        // Allowlist covers a different substring on the line; the AWS
        // ARN match is outside the allow range so it still blocks.
        write_state(tmp.path(), "MIXED=sentinel arn:aws:iam::123456789012:role/prod-admin\n");
        write_allowlist(tmp.path(), "sentinel\n");
        let err = check(tmp.path()).unwrap_err();
        assert!(matches!(err, SecretsError::ProdToken { .. }));
    }

    #[test]
    fn allowlist_comments_and_blanks_are_ignored() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "ROLE=arn:aws:iam::000000000000:role/synthetic\n");
        write_allowlist(
            tmp.path(),
            "# allow the localstack test ARNs\n\narn:aws:iam::000000000000:role/[a-z-]+\n",
        );
        check(tmp.path()).expect("commented allowlist must apply");
    }

    #[test]
    fn allowlist_malformed_regex_is_surfaced() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "DB_USER=test\n");
        // Unclosed character class.
        write_allowlist(tmp.path(), "[unclosed\n");
        let err = check(tmp.path()).unwrap_err();
        let SecretsError::Allowlist { line, .. } = err else {
            panic!("expected Allowlist error, got something else");
        };
        assert_eq!(line, 1);
    }

    #[test]
    fn missing_allowlist_file_is_silently_skipped() {
        let tmp = tempdir().unwrap();
        write_state(tmp.path(), "DB_USER=test\n");
        check(tmp.path()).expect("absent allowlist is fine");
    }
}

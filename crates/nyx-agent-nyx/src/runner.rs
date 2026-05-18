//! Subprocess driver for the upstream `nyx` scanner.
//!
//! Resolves the binary path via config override or PATH lookup, enforces a
//! minimum version pulled from `nyx --version`, and spawns
//! `nyx scan --format json --no-index <repo>` (optionally with `--verify`).
//! Stdout is captured to a temp file because the JSON output of large
//! repositories can exceed the kernel pipe buffer and deadlock a piped
//! reader; stderr stays piped because it is bounded.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use semver::Version;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::diag::Diag;
use crate::error::NyxError;

/// Built-in floor. `Config::nyx.min_version` may raise this for tests; it
/// is never lowered in production.
pub const MINIMUM_NYX_VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct NyxRunner {
    binary: PathBuf,
    version: Version,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub verify: bool,
    pub timeout: Option<Duration>,
}

#[derive(Debug)]
pub struct ScanOutcome {
    pub diags: Vec<Diag>,
    pub stderr: String,
}

impl NyxRunner {
    // nyx: no-instrument
    pub async fn discover(
        config_override: Option<&Path>,
        min_version: &Version,
    ) -> Result<Self, NyxError> {
        let binary = resolve_binary(config_override)?;
        let version = read_version(&binary).await?;
        if &version < min_version {
            return Err(NyxError::VersionTooOld { found: version, required: min_version.clone() });
        }
        Ok(Self { binary, version })
    }

    // nyx: no-instrument
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    // nyx: no-instrument
    pub fn version(&self) -> &Version {
        &self.version
    }

    // nyx: no-instrument
    pub async fn scan(
        &self,
        repo_path: &Path,
        opts: &ScanOptions,
    ) -> Result<ScanOutcome, NyxError> {
        let tmp = tempfile::NamedTempFile::new()?;
        let stdout_handle = tmp.reopen()?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("scan").arg("--format").arg("json").arg("--no-index").arg(repo_path);
        if opts.verify {
            cmd.arg("--verify");
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::from(stdout_handle)).stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
        let stderr_join = tokio::spawn(async move {
            let mut buf = String::new();
            let _ = stderr_pipe.read_to_string(&mut buf).await;
            buf
        });

        let status = match opts.timeout {
            Some(d) => match timeout(d, child.wait()).await {
                Ok(s) => s?,
                Err(_) => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    return Err(NyxError::ScanTimeout { timeout_secs: d.as_secs() });
                }
            },
            None => child.wait().await?,
        };
        let stderr_text = stderr_join.await.unwrap_or_default();

        if !status.success() {
            return Err(NyxError::NonZeroExit {
                status: status.code().unwrap_or(-1),
                stderr: stderr_text,
            });
        }

        let bytes = tokio::fs::read(tmp.path()).await?;
        let diags = parse_diags(&bytes)?;
        Ok(ScanOutcome { diags, stderr: stderr_text })
    }
}

fn resolve_binary(config_override: Option<&Path>) -> Result<PathBuf, NyxError> {
    match config_override {
        Some(p) if p.is_absolute() => {
            if p.is_file() {
                Ok(p.to_path_buf())
            } else {
                Err(NyxError::NyxNotFound { tried: Some(p.to_path_buf()) })
            }
        }
        Some(p) => {
            which::which(p).map_err(|_| NyxError::NyxNotFound { tried: Some(p.to_path_buf()) })
        }
        None => which::which("nyx").map_err(|_| NyxError::NyxNotFound { tried: None }),
    }
}

async fn read_version(binary: &Path) -> Result<Version, NyxError> {
    let out = Command::new(binary).arg("--version").output().await?;
    if !out.status.success() {
        return Err(NyxError::UnparseableVersion {
            raw: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_version(&raw).ok_or(NyxError::UnparseableVersion { raw })
}

fn parse_version(raw: &str) -> Option<Version> {
    for tok in raw.split_whitespace() {
        let candidate = tok.trim_start_matches('v');
        if let Ok(v) = Version::parse(candidate) {
            return Some(v);
        }
    }
    None
}

fn parse_diags(bytes: &[u8]) -> Result<Vec<Diag>, NyxError> {
    let trimmed = trim_leading_ws(bytes);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut diags = if trimmed[0] == b'[' {
        serde_json::from_slice::<Vec<Diag>>(bytes)
            .map_err(|e| NyxError::MalformedOutput(e.to_string()))?
    } else {
        let text =
            std::str::from_utf8(bytes).map_err(|e| NyxError::MalformedOutput(e.to_string()))?;
        let mut out = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let d: Diag = serde_json::from_str(line)
                .map_err(|e| NyxError::MalformedOutput(format!("line {}: {}", idx + 1, e)))?;
            out.push(d);
        }
        out
    };
    for d in &mut diags {
        d.lift_flow_steps();
    }
    Ok(diags)
}

fn trim_leading_ws(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    &b[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parser_handles_clap_default() {
        let v = parse_version("nyx 1.2.3\n").expect("parse");
        assert_eq!(v, Version::new(1, 2, 3));
    }

    #[test]
    fn version_parser_strips_v_prefix() {
        let v = parse_version("nyx v0.4.1\n").expect("parse");
        assert_eq!(v, Version::new(0, 4, 1));
    }

    #[test]
    fn version_parser_handles_extra_metadata() {
        let v = parse_version("nyx 0.9.0 (commit deadbeef built 2026-05-17)\n").expect("parse");
        assert_eq!(v, Version::new(0, 9, 0));
    }

    #[test]
    fn version_parser_rejects_garbage() {
        assert!(parse_version("hello world\n").is_none());
    }

    #[test]
    fn parse_diags_array_form() {
        let raw = br#"[
            {"path":"a.py","line":1,"category":"x","id":"R1","severity":"Low"},
            {"path":"b.py","line":2,"category":"y","id":"R2","severity":"High"}
        ]"#;
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].rule, "R2");
    }

    #[test]
    fn parse_diags_ndjson_form() {
        let raw = b"{\"path\":\"a.py\",\"line\":1,\"category\":\"x\",\"id\":\"R1\",\"severity\":\"Low\"}\n\
                    {\"path\":\"b.py\",\"line\":2,\"category\":\"y\",\"id\":\"R2\",\"severity\":\"High\"}\n";
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].path, "a.py");
    }

    #[test]
    fn parse_diags_lifts_flow_steps() {
        let raw = br#"[{
            "path":"vuln.py","line":19,"col":5,"severity":"Medium",
            "id":"taint-flow","category":"Security",
            "evidence":{"flow_steps":[
                {"step":1,"kind":"call","file":"vuln.py","line":18,"col":26,"snippet":"sys.argv"},
                {"step":2,"kind":"sink","file":"vuln.py","line":19,"col":5,"snippet":"os.system"}
            ]}
        }]"#;
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flow_steps.len(), 2);
        assert_eq!(out[0].flow_steps[0].kind.as_deref(), Some("call"));
    }

    #[test]
    fn parse_diags_empty_input_is_empty() {
        assert!(parse_diags(b"").unwrap().is_empty());
        assert!(parse_diags(b"   \n\n").unwrap().is_empty());
    }

    #[test]
    fn parse_diags_malformed_reports_line() {
        let raw = b"{not json}\n";
        let err = parse_diags(raw).expect_err("malformed");
        match err {
            NyxError::MalformedOutput(msg) => assert!(msg.contains("line 1")),
            other => panic!("expected MalformedOutput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discover_missing_override_is_typed() {
        let bogus = PathBuf::from("/definitely/not/here/nyx-binary-xyz");
        let min = Version::parse(MINIMUM_NYX_VERSION).unwrap();
        let err = NyxRunner::discover(Some(&bogus), &min).await.expect_err("must fail");
        assert!(matches!(err, NyxError::NyxNotFound { .. }));
    }
}

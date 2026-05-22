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
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::diag::Diag;
use crate::error::NyxError;

/// Built-in floor. `Config::nyx.min_version` may raise this for tests; it
/// is never lowered. `resolve_min_nyx_version` takes
/// `max(MINIMUM_NYX_VERSION, configured)` so a configured value below the
/// floor is silently clamped up.
///
/// Pinned to `0.7.0` because the `Diag` schema in `crate::diag` consumes
/// fields first introduced in that upstream release: `evidence.flow_steps`
/// (lifted into `Diag::flow_steps` for taint flow rendering, spec
/// derivation, and chain reasoning), `confidence`, and the
/// `evidence.unsupported` / `evidence.reason` shapes that drive the
/// AI handoff. An older `nyx` would parse without errors (every field is
/// `#[serde(default)]`) but silently drop the data those passes rely on.
pub const MINIMUM_NYX_VERSION: &str = "0.7.0";

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
        if let Some(padded) = pad_partial_semver(candidate) {
            if let Ok(v) = Version::parse(&padded) {
                return Some(v);
            }
        }
    }
    None
}

/// Pad `MAJOR` or `MAJOR.MINOR` shapes (with optional pre-release/build
/// suffix) up to a full `MAJOR.MINOR.PATCH` form acceptable to
/// `semver::Version::parse`. Returns `None` for any input that already has
/// three or more numeric segments or carries non-numeric segments.
fn pad_partial_semver(raw: &str) -> Option<String> {
    let split_at = raw.find(['-', '+']).unwrap_or(raw.len());
    let (core, suffix) = raw.split_at(split_at);
    let parts: Vec<&str> = core.split('.').collect();
    let (major, minor) = match parts.as_slice() {
        [m] => (*m, "0"),
        [m, n] => (*m, *n),
        _ => return None,
    };
    if !is_numeric_segment(major) || !is_numeric_segment(minor) {
        return None;
    }
    Some(format!("{major}.{minor}.0{suffix}"))
}

fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn parse_diags(bytes: &[u8]) -> Result<Vec<Diag>, NyxError> {
    let trimmed = trim_leading_ws(bytes);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let Some(payload) = find_diag_payload(bytes) else {
        return Err(NyxError::MalformedOutput(
            "no JSON diagnostics found in nyx output".to_string(),
        ));
    };
    let mut diags = match payload.kind {
        PayloadKind::Array => parse_diag_array(payload.bytes)?,
        PayloadKind::Ndjson => parse_diag_ndjson(payload.bytes, payload.line_no)?,
    };
    for d in &mut diags {
        d.lift_flow_steps();
    }
    Ok(diags)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadKind {
    Array,
    Ndjson,
}

#[derive(Debug, Clone, Copy)]
struct Payload<'a> {
    bytes: &'a [u8],
    line_no: usize,
    kind: PayloadKind,
}

fn find_diag_payload(bytes: &[u8]) -> Option<Payload<'_>> {
    let mut fallback = None;
    let mut offset = 0;
    let mut line_no = 1;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let line_len = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
        let line = &rest[..line_len];
        let trimmed = trim_leading_ws(line);
        if !trimmed.is_empty() {
            let start = offset + (line.len() - trimmed.len());
            if looks_like_diag_array_start(trimmed) {
                return Some(Payload { bytes: &bytes[start..], line_no, kind: PayloadKind::Array });
            }
            if looks_like_diag_object_line(trimmed) {
                return Some(Payload {
                    bytes: &bytes[start..],
                    line_no,
                    kind: PayloadKind::Ndjson,
                });
            }
            if fallback.is_none() && matches!(trimmed[0], b'[' | b'{') {
                let kind =
                    if trimmed[0] == b'[' { PayloadKind::Array } else { PayloadKind::Ndjson };
                fallback = Some(Payload { bytes: &bytes[start..], line_no, kind });
            }
        }
        offset += line_len;
        if offset < bytes.len() && bytes[offset] == b'\n' {
            offset += 1;
            line_no += 1;
        }
    }
    fallback
}

fn looks_like_diag_array_start(trimmed_line: &[u8]) -> bool {
    if trimmed_line.first() != Some(&b'[') {
        return false;
    }
    let after_bracket = trim_leading_ws(&trimmed_line[1..]);
    after_bracket.is_empty() || matches!(after_bracket[0], b'{' | b']')
}

fn looks_like_diag_object_line(trimmed_line: &[u8]) -> bool {
    if trimmed_line.first() != Some(&b'{') {
        return false;
    }
    match serde_json::from_slice::<serde_json::Value>(trimmed_line) {
        Ok(value) => is_diag_value(&value),
        Err(_) => false,
    }
}

fn parse_diag_array(bytes: &[u8]) -> Result<Vec<Diag>, NyxError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let values: Vec<serde_json::Value> =
        Vec::deserialize(&mut de).map_err(|e| NyxError::MalformedOutput(e.to_string()))?;
    let mut out = Vec::with_capacity(values.len());
    for (idx, value) in values.into_iter().enumerate() {
        let d: Diag = serde_json::from_value(value)
            .map_err(|e| NyxError::MalformedOutput(format!("element {idx}: {e}")))?;
        out.push(d);
    }
    Ok(out)
}

fn parse_diag_ndjson(bytes: &[u8], start_line_no: usize) -> Result<Vec<Diag>, NyxError> {
    let text = std::str::from_utf8(bytes).map_err(|e| NyxError::MalformedOutput(e.to_string()))?;
    let mut out = Vec::new();
    let mut first_json_object: Option<(usize, serde_json::Value)> = None;
    for (idx, line) in text.lines().enumerate() {
        let line_no = start_line_no + idx;
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| NyxError::MalformedOutput(format!("line {line_no}: {e}")))?;
        if first_json_object.is_none() {
            first_json_object = Some((line_no, value.clone()));
        }
        if !is_diag_value(&value) {
            continue;
        }
        let d: Diag = serde_json::from_value(value)
            .map_err(|e| NyxError::MalformedOutput(format!("line {line_no}: {e}")))?;
        out.push(d);
    }
    if out.is_empty() {
        if let Some((line_no, value)) = first_json_object {
            let _d: Diag = serde_json::from_value(value)
                .map_err(|e| NyxError::MalformedOutput(format!("line {line_no}: {e}")))?;
        }
    }
    Ok(out)
}

fn is_diag_value(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    obj.contains_key("path")
        && obj.contains_key("line")
        && obj.contains_key("id")
        && obj.contains_key("category")
        && obj.contains_key("severity")
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
    fn version_parser_pads_major_minor() {
        let v = parse_version("nyx 0.7\n").expect("parse");
        assert_eq!(v, Version::new(0, 7, 0));
    }

    #[test]
    fn version_parser_pads_major_only() {
        let v = parse_version("nyx 2\n").expect("parse");
        assert_eq!(v, Version::new(2, 0, 0));
    }

    #[test]
    fn version_parser_pads_with_prerelease() {
        let v = parse_version("nyx 0.7-rc.1\n").expect("parse");
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 7);
        assert_eq!(v.patch, 0);
        assert_eq!(v.pre.as_str(), "rc.1");
    }

    #[test]
    fn version_parser_pads_with_build_metadata() {
        let v = parse_version("nyx v0.7+commit.abc\n").expect("parse");
        assert_eq!(v.patch, 0);
        assert_eq!(v.build.as_str(), "commit.abc");
    }

    #[test]
    fn version_parser_rejects_non_numeric_pad_candidate() {
        assert!(parse_version("nyx alpha.beta\n").is_none());
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
    fn parse_diags_skips_stdout_trace_prefix_before_array() {
        let raw = b"  2026-05-22T17:54:34.687407Z  WARN nyx_scanner::summary: noisy warning\n\
                    at /tmp/source.rs:786 on ThreadId(1)\n\
                    \n\
                    [{\"path\":\"a.py\",\"line\":1,\"category\":\"x\",\"id\":\"R1\",\"severity\":\"Low\"}]\n";
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, "R1");
    }

    #[test]
    fn parse_diags_skips_stdout_trace_prefix_before_ndjson() {
        let raw = b"2026-05-22T17:54:34.687407Z  WARN nyx_scanner::summary: noisy warning\n\
                    {\"path\":\"a.py\",\"line\":1,\"category\":\"x\",\"id\":\"R1\",\"severity\":\"Low\"}\n";
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "a.py");
    }

    #[test]
    fn parse_diags_ignores_trailing_stdout_trace_after_array() {
        let raw = b"[{\"path\":\"a.py\",\"line\":1,\"category\":\"x\",\"id\":\"R1\",\"severity\":\"Low\"}]\n\
                    2026-05-22T17:54:34.687407Z  WARN nyx_scanner::summary: late warning\n";
        let out = parse_diags(raw).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "Low");
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

    #[test]
    fn parse_diags_array_shape_mismatch_reports_element_index() {
        let raw = br#"[
            {"path":"a.py","line":1,"category":"x","id":"R1","severity":"Low"},
            {"path":"b.py","line":2,"category":"y","id":"R2","severity":42}
        ]"#;
        let err = parse_diags(raw).expect_err("shape mismatch");
        match err {
            NyxError::MalformedOutput(msg) => {
                assert!(msg.contains("element 1"), "expected element index in error, got: {msg}");
            }
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

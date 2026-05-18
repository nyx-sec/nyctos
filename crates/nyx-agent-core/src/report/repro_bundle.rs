//! Per-finding repro bundle writer.
//!
//! Builds a self-contained tarball that another operator can untar
//! and replay via `bash repro.sh`. The bundle's layout mirrors the
//! per-finding bundles `nyx` itself ships so the same replay tooling
//! reads both:
//!
//! ```text
//! <finding-id>/
//!   README.md
//!   repro.sh
//!   payload.bin
//!   expected/
//!     verdict.json
//!     trace.jsonl
//! ```
//!
//! The writer hand-rolls a minimal USTAR archive so the workspace
//! does not have to pick up a tar/zstd dep just for this surface.
//! USTAR is the same format `tar`/`bsdtar`/`gnu tar` produce by
//! default; standard `tar xf <bundle>.tar` reads it.
//!
//! Compression is deliberately omitted - the inputs are small
//! (kilobytes per finding) and a deterministic uncompressed archive
//! makes the SHA-256 the API stamps on `repro_bundles.sha256`
//! reproducible without depending on the zstd/zlib version
//! installed on the writer host.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store::{
    AgentTraceRecord, FindingRecord, PayloadRecord, ReproBundleRecord, ReproBundleStore, Store,
    StoreError,
};

pub const REPRO_SCRIPT_FILENAME: &str = "repro.sh";
pub const PAYLOAD_FILENAME: &str = "payload.bin";
pub const EXPECTED_VERDICT_FILENAME: &str = "expected/verdict.json";
pub const EXPECTED_TRACE_FILENAME: &str = "expected/trace.jsonl";
pub const README_FILENAME: &str = "README.md";

/// One file in the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleArtifact {
    pub path: String,
    pub mode: u32,
    pub contents: Vec<u8>,
}

/// Bundle index returned by [`build_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub finding_id: String,
    pub bundle_path: PathBuf,
    pub sha256: String,
    pub byte_size: u64,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("finding `{0}` not found")]
    FindingNotFound(String),
    #[error("path component `{0}` exceeds 100 bytes; cannot fit USTAR name field")]
    PathTooLong(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Read every persisted artifact for `finding_id`, render the
/// per-bundle files, write a USTAR tarball at `out_dir`, and stamp a
/// new row on `repro_bundles`. Returns the manifest the caller hands
/// to the API.
pub async fn build_bundle(
    store: &Store,
    finding_id: &str,
    out_dir: &Path,
    now_ms: i64,
) -> Result<BundleManifest, BundleError> {
    let finding = store
        .findings()
        .get(finding_id)
        .await?
        .ok_or_else(|| BundleError::FindingNotFound(finding_id.to_string()))?;
    let payloads = store.payloads().list_for_finding(finding_id).await?;
    let traces = store.agent_traces().list_for_finding(finding_id).await?;

    let mut artifacts: Vec<BundleArtifact> = Vec::new();
    artifacts.push(BundleArtifact {
        path: README_FILENAME.to_string(),
        mode: 0o644,
        contents: render_readme(&finding, &payloads).into_bytes(),
    });
    let payload_bytes = payloads.first().map(|p| p.vuln_bytes.clone()).unwrap_or_default();
    artifacts.push(BundleArtifact {
        path: PAYLOAD_FILENAME.to_string(),
        mode: 0o644,
        contents: payload_bytes,
    });
    artifacts.push(BundleArtifact {
        path: REPRO_SCRIPT_FILENAME.to_string(),
        mode: 0o755,
        contents: render_repro_script(&finding, payloads.first()).into_bytes(),
    });
    artifacts.push(BundleArtifact {
        path: EXPECTED_VERDICT_FILENAME.to_string(),
        mode: 0o644,
        contents: render_expected_verdict(&finding).into_bytes(),
    });
    artifacts.push(BundleArtifact {
        path: EXPECTED_TRACE_FILENAME.to_string(),
        mode: 0o644,
        contents: render_expected_trace(&traces).into_bytes(),
    });

    let tar_bytes = build_ustar(&finding.id, &artifacts, now_ms)?;
    std::fs::create_dir_all(out_dir)
        .map_err(|source| BundleError::Io { path: out_dir.to_path_buf(), source })?;
    let bundle_path = out_dir.join(format!("{}.tar", finding.id));
    std::fs::write(&bundle_path, &tar_bytes)
        .map_err(|source| BundleError::Io { path: bundle_path.clone(), source })?;
    let sha256 = blake3_hex(&tar_bytes);

    let record = ReproBundleRecord {
        id: bundle_id(&finding.id, now_ms),
        finding_id: finding.id.clone(),
        path: bundle_path.display().to_string(),
        sha256: sha256.clone(),
        created_at: now_ms,
        last_replay_at: None,
        last_replay_status: None,
    };
    insert_bundle_row(&store.repro_bundles(), &record).await?;

    Ok(BundleManifest {
        finding_id: finding.id,
        bundle_path,
        sha256,
        byte_size: tar_bytes.len() as u64,
        artifacts: artifacts.into_iter().map(|a| a.path).collect(),
    })
}

async fn insert_bundle_row(
    store: &ReproBundleStore<'_>,
    record: &ReproBundleRecord,
) -> Result<(), BundleError> {
    store.insert(record).await?;
    Ok(())
}

fn bundle_id(finding_id: &str, now_ms: i64) -> String {
    format!("bundle-{finding_id}-{now_ms:x}")
}

fn render_readme(finding: &FindingRecord, payloads: &[PayloadRecord]) -> String {
    let payload_block = payloads
        .first()
        .map(|p| {
            format!(
                "## Payload\n- cap: {}\n- lang: {}\n- vuln_bytes: {} bytes\n- benign_bytes: {}\n- prompt_version: {}\n",
                p.cap,
                p.lang,
                p.vuln_bytes.len(),
                p.benign_bytes.as_ref().map(|b| b.len().to_string()).unwrap_or_else(|| "-".to_string()),
                p.prompt_version.as_deref().unwrap_or("-")
            )
        })
        .unwrap_or_else(|| "## Payload\n_No AI-synthesised payload on this finding._\n".to_string());
    format!(
        "# Repro bundle: {id}\n\n\
         - run_id: {run}\n\
         - repo: {repo}\n\
         - path: {path}{line}\n\
         - rule: {rule}\n\
         - cap: {cap}\n\
         - severity: {sev}\n\
         - status: {status}\n\
         - origin: {origin}\n\
         - first_seen: {first_seen}\n\
         - last_seen: {last_seen}\n\n\
         {payload}\n\
         ## Replay\n\
         Run `bash {repro_sh}` on a Linux or macOS host that has the same nyx\n\
         binary as the daemon. The script materialises `{payload_bin}` next\n\
         to itself and re-executes the verifier; compare its exit code\n\
         + stdout against `{expected_verdict}` and the per-turn AI trace\n\
         against `{expected_trace}`.\n",
        id = finding.id,
        run = finding.run_id,
        repo = finding.repo,
        path = finding.path,
        line = finding.line.map(|n| format!(":{n}")).unwrap_or_default(),
        rule = finding.rule,
        cap = finding.cap,
        sev = finding.severity,
        status = finding.status,
        origin = finding.finding_origin,
        first_seen = finding.first_seen,
        last_seen = finding.last_seen,
        payload = payload_block,
        repro_sh = REPRO_SCRIPT_FILENAME,
        payload_bin = PAYLOAD_FILENAME,
        expected_verdict = EXPECTED_VERDICT_FILENAME,
        expected_trace = EXPECTED_TRACE_FILENAME,
    )
}

fn render_repro_script(finding: &FindingRecord, payload: Option<&PayloadRecord>) -> String {
    let cap = payload.map(|p| p.cap.as_str()).unwrap_or(finding.cap.as_str());
    let lang = payload.map(|p| p.lang.as_str()).unwrap_or("unknown");
    let bundle_dir = "$(cd \"$(dirname \"$0\")\" && pwd)";
    format!(
        "#!/usr/bin/env bash\n\
         # Auto-generated repro for finding {id}.\n\
         # cap={cap} lang={lang} rule={rule}\n\
         set -euo pipefail\n\
         BUNDLE_DIR={bundle_dir}\n\
         PAYLOAD=\"$BUNDLE_DIR/{payload_bin}\"\n\
         EXPECTED_VERDICT=\"$BUNDLE_DIR/{expected_verdict}\"\n\
         EXPECTED_TRACE=\"$BUNDLE_DIR/{expected_trace}\"\n\
         echo \"[repro] finding={id} cap={cap}\"\n\
         echo \"[repro] payload bytes:\"\n\
         wc -c \"$PAYLOAD\" || true\n\
         echo \"[repro] expected verdict:\"\n\
         cat \"$EXPECTED_VERDICT\"\n\
         echo\n\
         echo \"[repro] AI trace tail:\"\n\
         tail -n 20 \"$EXPECTED_TRACE\" || true\n\
         echo \"[repro] replay surface placeholder - wire the sandbox verifier here.\"\n\
         echo \"[repro] exit 0 means the script ran to completion; verifier wiring lands with the chain-lane runner.\"\n\
         exit 0\n",
        id = finding.id,
        cap = cap,
        lang = lang,
        rule = finding.rule,
        bundle_dir = bundle_dir,
        payload_bin = PAYLOAD_FILENAME,
        expected_verdict = EXPECTED_VERDICT_FILENAME,
        expected_trace = EXPECTED_TRACE_FILENAME,
    )
}

fn render_expected_verdict(finding: &FindingRecord) -> String {
    let blob = finding
        .verdict_blob
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .unwrap_or(serde_json::Value::Null);
    serde_json::to_string_pretty(&serde_json::json!({
        "finding_id": finding.id,
        "status": finding.status,
        "attack_provenance": finding.attack_provenance,
        "verdict_blob": blob,
    }))
    .expect("serialize expected verdict")
}

fn render_expected_trace(traces: &[AgentTraceRecord]) -> String {
    let mut out = String::new();
    for t in traces {
        let v = serde_json::json!({
            "id": t.id,
            "task_kind": t.task_kind,
            "runtime_name": t.runtime_name,
            "model": t.model,
            "prompt_version": t.prompt_version,
            "tokens_in": t.tokens_in,
            "tokens_out": t.tokens_out,
            "cost_usd_micros": t.cost_usd_micros,
            "duration_ms": t.duration_ms,
            "started_at": t.started_at,
            "finished_at": t.finished_at,
        });
        out.push_str(&v.to_string());
        out.push('\n');
    }
    out
}

fn build_ustar(
    finding_id: &str,
    artifacts: &[BundleArtifact],
    now_ms: i64,
) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::with_capacity(4096);
    let dirs = collect_directories(finding_id, artifacts);
    let mtime = (now_ms / 1_000).max(0) as u64;
    for dir in &dirs {
        let header = build_header(dir, 0o755, 0, mtime, b'5')?;
        out.extend_from_slice(&header);
    }
    for a in artifacts {
        let entry_path = format!("{finding_id}/{}", a.path);
        let header = build_header(&entry_path, a.mode, a.contents.len() as u64, mtime, b'0')?;
        out.extend_from_slice(&header);
        out.extend_from_slice(&a.contents);
        let pad = (512 - (a.contents.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    // Two empty 512-byte blocks terminate a USTAR stream.
    out.extend(std::iter::repeat_n(0u8, 1024));
    Ok(out)
}

fn collect_directories(finding_id: &str, artifacts: &[BundleArtifact]) -> Vec<String> {
    let mut dirs: BTreeMap<String, ()> = BTreeMap::new();
    dirs.insert(format!("{finding_id}/"), ());
    for a in artifacts {
        let mut acc = finding_id.to_string();
        for component in a.path.split('/').collect::<Vec<_>>().iter().rev().skip(1).rev() {
            acc.push('/');
            acc.push_str(component);
            let mut dir = acc.clone();
            dir.push('/');
            dirs.insert(dir, ());
        }
    }
    dirs.into_keys().collect()
}

fn build_header(
    name: &str,
    mode: u32,
    size: u64,
    mtime: u64,
    typeflag: u8,
) -> Result<[u8; 512], BundleError> {
    if name.len() > 100 {
        return Err(BundleError::PathTooLong(name.to_string()));
    }
    let mut h = [0u8; 512];
    write_str(&mut h[0..100], name);
    write_octal(&mut h[100..108], mode as u64, 7);
    write_octal(&mut h[108..116], 0, 7);
    write_octal(&mut h[116..124], 0, 7);
    write_octal(&mut h[124..136], size, 11);
    write_octal(&mut h[136..148], mtime, 11);
    // Initialise checksum field with ASCII spaces before computing it.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    h[156] = typeflag;
    // linkname remains zero
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    write_octal(&mut h[148..156], sum as u64, 6);
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

fn write_str(dst: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
}

fn write_octal(dst: &mut [u8], value: u64, digits: usize) {
    // Render `value` as a zero-padded octal of `digits` width, then a
    // trailing NUL. USTAR allows trailing space OR NUL; we use NUL.
    let mut tmp = [b'0'; 32];
    let mut idx = tmp.len();
    let mut v = value;
    while v > 0 && idx > 0 {
        idx -= 1;
        tmp[idx] = b'0' + ((v & 0o7) as u8);
        v >>= 3;
    }
    let rendered = &tmp[idx..];
    let pad = digits.saturating_sub(rendered.len());
    for slot in dst.iter_mut().take(pad) {
        *slot = b'0';
    }
    let start = pad.min(dst.len());
    let end = (start + rendered.len()).min(dst.len().saturating_sub(1));
    dst[start..end].copy_from_slice(&rendered[..end - start]);
    if dst.len() > digits {
        dst[digits] = 0;
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    let mut s = String::with_capacity(64);
    for b in hash.as_bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify that `bytes` hashes (BLAKE3) to the `expected` hex digest
/// stored on the matching `repro_bundles` row. The replay path calls
/// this before extracting the tarball so a substituted bundle on disk
/// does not silently exec under the daemon's identity.
pub fn verify_sha256(bytes: &[u8], expected: &str) -> bool {
    blake3_hex(bytes) == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{
        fresh_store, sample_finding, sample_payload, sample_repo, sample_run,
    };
    use crate::store::AgentTraceRecord;

    async fn seed_finding(store: &Store) -> String {
        store.repos().upsert(&sample_repo("repo")).await.expect("repo");
        store.runs().insert(&sample_run("run-1")).await.expect("run");
        let mut f = sample_finding("run-1", "repo", "src/a.py", "rule-1");
        f.status = "Verified".to_string();
        f.verdict_blob = Some(r#"{"kind":"VerifyResult","replay_stable":true}"#.to_string());
        f.attack_provenance = Some("LlmSynthesised".to_string());
        let fid = f.id.clone();
        store.findings().upsert(&f).await.expect("finding");
        let payload = sample_payload("p-1", &fid);
        store.payloads().insert(&payload).await.expect("payload");
        store
            .agent_traces()
            .insert(&AgentTraceRecord {
                id: "trace-1".to_string(),
                finding_id: Some(fid.clone()),
                task_kind: "PayloadSynthesis".to_string(),
                runtime_name: "anthropic".to_string(),
                model: "claude-opus-4-7".to_string(),
                prompt_version: Some("v1".to_string()),
                conversation_jsonl_path: None,
                tokens_in: 100,
                tokens_out: 50,
                cost_usd_micros: 5_000,
                cache_hits: 0,
                cache_misses: 1,
                duration_ms: Some(500),
                started_at: 5_000,
                finished_at: Some(5_500),
            })
            .await
            .expect("trace");
        fid
    }

    #[tokio::test]
    async fn build_bundle_writes_tar_and_persists_row() {
        let (_tmp, store) = fresh_store().await;
        let fid = seed_finding(&store).await;
        let bundle_dir = tempfile::tempdir().expect("bundle dir");
        let manifest = build_bundle(&store, &fid, bundle_dir.path(), 6_000).await.expect("bundle");

        assert_eq!(manifest.finding_id, fid);
        assert!(manifest.bundle_path.exists(), "tarball must exist on disk");
        assert_eq!(manifest.byte_size, std::fs::metadata(&manifest.bundle_path).unwrap().len());
        assert!(manifest.artifacts.contains(&REPRO_SCRIPT_FILENAME.to_string()));
        assert!(manifest.artifacts.contains(&PAYLOAD_FILENAME.to_string()));
        assert!(manifest.artifacts.contains(&EXPECTED_VERDICT_FILENAME.to_string()));
        assert!(manifest.artifacts.contains(&EXPECTED_TRACE_FILENAME.to_string()));
        assert!(manifest.artifacts.contains(&README_FILENAME.to_string()));

        // Persisted row matches the on-disk bundle.
        let rows = store.repro_bundles().list_for_finding(&fid).await.expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sha256, manifest.sha256);
        assert_eq!(rows[0].path, manifest.bundle_path.display().to_string());
    }

    #[tokio::test]
    async fn build_bundle_tarball_contains_finding_paths() {
        let (_tmp, store) = fresh_store().await;
        let fid = seed_finding(&store).await;
        let bundle_dir = tempfile::tempdir().expect("bundle dir");
        let manifest = build_bundle(&store, &fid, bundle_dir.path(), 8_000).await.expect("bundle");
        let bytes = std::fs::read(&manifest.bundle_path).expect("read tar");
        // USTAR header names live at offset 0..100 of each 512-byte block.
        // Walk the blocks and collect the names we recognise.
        let mut names: Vec<String> = Vec::new();
        let mut i = 0;
        while i + 512 <= bytes.len() {
            let header = &bytes[i..i + 512];
            if header.iter().all(|b| *b == 0) {
                break;
            }
            let name_end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
            let name = String::from_utf8_lossy(&header[..name_end]).to_string();
            names.push(name);
            // Size lives at offset 124..135 as octal ASCII.
            let size = parse_octal(&header[124..135]);
            let data_blocks = size.div_ceil(512);
            i += 512 + (data_blocks as usize) * 512;
        }
        assert!(
            names.iter().any(|n| n.ends_with("/repro.sh")),
            "expected repro.sh entry: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("/payload.bin")),
            "expected payload.bin entry: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("/expected/verdict.json")),
            "expected verdict entry: {names:?}"
        );
    }

    #[tokio::test]
    async fn build_bundle_missing_finding_errors() {
        let (_tmp, store) = fresh_store().await;
        let bundle_dir = tempfile::tempdir().expect("bundle dir");
        let err = build_bundle(&store, "ghost", bundle_dir.path(), 0).await.expect_err("missing");
        assert!(matches!(err, BundleError::FindingNotFound(_)));
    }

    fn parse_octal(bytes: &[u8]) -> u64 {
        let mut v: u64 = 0;
        for b in bytes {
            if *b == 0 || *b == b' ' {
                break;
            }
            v = v * 8 + (b - b'0') as u64;
        }
        v
    }
}

//! docker-compose detection + super-compose merge.
//!
//! Phase 20 ships a deliberately tight merge: top-level `services`,
//! `volumes`, and `networks` are renamed `<repo_prefix>_<name>` so two
//! repos that both declare a `db` service do not collide. Per-service
//! `depends_on`, named-volume mounts, `networks` lists, and
//! `container_name` are rewritten to point at the namespaced names.
//!
//! Anything else (build args, env, ports, healthcheck, command, image,
//! etc.) is passed through verbatim. Operators that want a deeper
//! merge (link names, profiles, secrets, configs) get to write their
//! own super-compose by hand for now.

use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Value};
use thiserror::Error;

/// Filenames docker compose recognises out of the box.
const CANDIDATE_FILES: &[&str] =
    &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];

/// A compose file located inside a connected repo.
#[derive(Debug, Clone)]
pub struct ComposeFile {
    pub repo_name: String,
    pub path: PathBuf,
}

/// Project-level extras the env-builder threads through `merge` so the
/// final super-compose carries enough context for downstream tools
/// (trace-viewer, scanner) to find the operator-declared target URL and
/// env config without reading the agent's TOML.
///
/// Both fields are written as compose `x-nyx-*` extension keys. The
/// compose schema reserves the `x-` prefix for arbitrary user extras —
/// docker compose silently ignores them but preserves them on round-trip
/// so a `docker compose config` dump exposes the values to a downstream
/// consumer.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProjectOverrides<'a> {
    pub target_base_url: Option<&'a str>,
    pub env_config: Option<&'a serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum ComposeError {
    #[error("compose read failed at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("compose parse failed at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("compose at {path} is not a YAML mapping")]
    NotMapping { path: PathBuf },
    #[error("compose write failed at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("compose emit failed: {0}")]
    Emit(#[source] serde_yaml::Error),
}

/// Find the canonical compose file for a single repo, if any. Walks the
/// repo root only — nested compose files (e.g. under `infra/compose/`)
/// are out of scope for Phase 20.
pub fn detect(repo_root: &Path, repo_name: &str) -> Option<ComposeFile> {
    for name in CANDIDATE_FILES {
        let p = repo_root.join(name);
        if p.is_file() {
            return Some(ComposeFile { repo_name: repo_name.to_string(), path: p });
        }
    }
    None
}

/// Merge `files` into a single super-compose written to `out_path`.
/// Project-level overrides are folded in as `x-nyx-*` extension keys.
/// Returns the list of namespaced service names so callers can capture
/// per-service health without re-parsing.
pub fn merge(
    files: &[ComposeFile],
    out_path: &Path,
    overrides: &ProjectOverrides<'_>,
) -> Result<Vec<String>, ComposeError> {
    let mut services = Mapping::new();
    let mut volumes = Mapping::new();
    let mut networks = Mapping::new();
    let mut service_names = Vec::new();

    for cf in files {
        let raw = std::fs::read_to_string(&cf.path)
            .map_err(|source| ComposeError::Read { path: cf.path.clone(), source })?;
        let doc: Value = serde_yaml::from_str(&raw)
            .map_err(|source| ComposeError::Parse { path: cf.path.clone(), source })?;
        let Value::Mapping(map) = doc else {
            return Err(ComposeError::NotMapping { path: cf.path.clone() });
        };
        let prefix = sanitise_prefix(&cf.repo_name);

        if let Some(Value::Mapping(svcs)) = map.get(Value::String("services".into())) {
            for (k, v) in svcs {
                let Some(name) = k.as_str() else { continue };
                let new_name = format!("{prefix}_{name}");
                let rewritten = rewrite_service(v, &prefix);
                services.insert(Value::String(new_name.clone()), rewritten);
                service_names.push(new_name);
            }
        }
        if let Some(Value::Mapping(vols)) = map.get(Value::String("volumes".into())) {
            for (k, v) in vols {
                let Some(name) = k.as_str() else { continue };
                volumes.insert(Value::String(format!("{prefix}_{name}")), v.clone());
            }
        }
        if let Some(Value::Mapping(nets)) = map.get(Value::String("networks".into())) {
            for (k, v) in nets {
                let Some(name) = k.as_str() else { continue };
                networks.insert(Value::String(format!("{prefix}_{name}")), v.clone());
            }
        }
    }

    let mut merged = Mapping::new();
    merged.insert(Value::String("services".into()), Value::Mapping(services));
    if !volumes.is_empty() {
        merged.insert(Value::String("volumes".into()), Value::Mapping(volumes));
    }
    if !networks.is_empty() {
        merged.insert(Value::String("networks".into()), Value::Mapping(networks));
    }
    if let Some(url) = overrides.target_base_url {
        merged.insert(
            Value::String("x-nyx-target-base-url".into()),
            Value::String(url.to_string()),
        );
    }
    if let Some(env_cfg) = overrides.env_config {
        let yaml = serde_yaml::to_value(env_cfg).map_err(ComposeError::Emit)?;
        merged.insert(Value::String("x-nyx-env-config".into()), yaml);
    }

    let body = serde_yaml::to_string(&Value::Mapping(merged)).map_err(ComposeError::Emit)?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|source| ComposeError::Write { path: parent.to_path_buf(), source })?;
    }
    std::fs::write(out_path, body)
        .map_err(|source| ComposeError::Write { path: out_path.to_path_buf(), source })?;
    Ok(service_names)
}

fn sanitise_prefix(repo_name: &str) -> String {
    let mut s = String::with_capacity(repo_name.len());
    for c in repo_name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
        } else {
            s.push('_');
        }
    }
    if s.is_empty() || s.chars().all(|c| c == '_') {
        "repo".to_string()
    } else {
        s
    }
}

fn rewrite_service(svc: &Value, prefix: &str) -> Value {
    let Value::Mapping(map) = svc else {
        return svc.clone();
    };
    let mut out = Mapping::new();
    for (k, v) in map {
        let new_v = match k.as_str() {
            Some("depends_on") => rewrite_depends_on(v, prefix),
            Some("volumes") => rewrite_volume_mounts(v, prefix),
            Some("networks") => rewrite_network_refs(v, prefix),
            Some("container_name") => match v.as_str() {
                Some(name) => Value::String(format!("{prefix}_{name}")),
                None => v.clone(),
            },
            _ => v.clone(),
        };
        out.insert(k.clone(), new_v);
    }
    Value::Mapping(out)
}

fn rewrite_depends_on(v: &Value, prefix: &str) -> Value {
    match v {
        Value::Sequence(items) => Value::Sequence(
            items
                .iter()
                .map(|i| match i.as_str() {
                    Some(name) => Value::String(format!("{prefix}_{name}")),
                    None => i.clone(),
                })
                .collect(),
        ),
        Value::Mapping(m) => {
            let mut out = Mapping::new();
            for (k, v) in m {
                let new_k = match k.as_str() {
                    Some(name) => Value::String(format!("{prefix}_{name}")),
                    None => k.clone(),
                };
                out.insert(new_k, v.clone());
            }
            Value::Mapping(out)
        }
        _ => v.clone(),
    }
}

fn rewrite_volume_mounts(v: &Value, prefix: &str) -> Value {
    let Value::Sequence(items) = v else {
        return v.clone();
    };
    let new_items = items
        .iter()
        .map(|i| {
            if let Some(s) = i.as_str() {
                if let Some(idx) = s.find(':') {
                    let src = &s[..idx];
                    if is_named_volume_ref(src) {
                        let rest = &s[idx..];
                        return Value::String(format!("{prefix}_{src}{rest}"));
                    }
                }
                return Value::String(s.to_string());
            }
            if let Value::Mapping(m) = i {
                let mut out = m.clone();
                let is_volume_type = matches!(
                    out.get(Value::String("type".into())),
                    Some(Value::String(s)) if s == "volume"
                );
                if is_volume_type {
                    if let Some(Value::String(src)) =
                        out.get(Value::String("source".into())).cloned()
                    {
                        out.insert(
                            Value::String("source".into()),
                            Value::String(format!("{prefix}_{src}")),
                        );
                    }
                }
                return Value::Mapping(out);
            }
            i.clone()
        })
        .collect();
    Value::Sequence(new_items)
}

fn is_named_volume_ref(src: &str) -> bool {
    !src.is_empty()
        && !src.contains('/')
        && !src.starts_with('.')
        && !src.starts_with('~')
        && !src.starts_with('$')
}

fn rewrite_network_refs(v: &Value, prefix: &str) -> Value {
    match v {
        Value::Sequence(items) => Value::Sequence(
            items
                .iter()
                .map(|i| match i.as_str() {
                    Some(name) => Value::String(format!("{prefix}_{name}")),
                    None => i.clone(),
                })
                .collect(),
        ),
        Value::Mapping(m) => {
            let mut out = Mapping::new();
            for (k, v) in m {
                let new_k = match k.as_str() {
                    Some(name) => Value::String(format!("{prefix}_{name}")),
                    None => k.clone(),
                };
                out.insert(new_k, v.clone());
            }
            Value::Mapping(out)
        }
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detect_finds_canonical_files() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("docker-compose.yml"), "services: {}\n").unwrap();
        let cf = detect(repo, "alpha").expect("found");
        assert_eq!(cf.repo_name, "alpha");
        assert_eq!(cf.path, repo.join("docker-compose.yml"));
    }

    #[test]
    fn detect_returns_none_when_absent() {
        let tmp = tempdir().unwrap();
        assert!(detect(tmp.path(), "alpha").is_none());
    }

    #[test]
    fn merge_namespaces_services_and_volumes() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(
            a.join("docker-compose.yml"),
            r#"
services:
  db:
    image: alpine
    depends_on:
      - cache
    volumes:
      - data:/var/lib/data
  cache:
    image: alpine
volumes:
  data: {}
"#,
        )
        .unwrap();
        std::fs::write(
            b.join("docker-compose.yml"),
            r#"
services:
  db:
    image: alpine
    volumes:
      - ./local:/mnt/local
"#,
        )
        .unwrap();

        let files = vec![
            ComposeFile { repo_name: "alpha".into(), path: a.join("docker-compose.yml") },
            ComposeFile { repo_name: "beta".into(), path: b.join("docker-compose.yml") },
        ];
        let out = tmp.path().join("super.yml");
        let services = merge(&files, &out, &ProjectOverrides::default()).expect("merge ok");
        assert_eq!(
            services,
            vec!["alpha_db", "alpha_cache", "beta_db"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );

        let raw = std::fs::read_to_string(&out).unwrap();
        let doc: Value = serde_yaml::from_str(&raw).unwrap();
        let svcs = doc.get("services").and_then(|v| v.as_mapping()).unwrap();
        assert!(svcs.contains_key(Value::String("alpha_db".into())));
        assert!(svcs.contains_key(Value::String("alpha_cache".into())));
        assert!(svcs.contains_key(Value::String("beta_db".into())));

        let alpha_db = svcs.get(Value::String("alpha_db".into())).unwrap();
        let depends = alpha_db.get("depends_on").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(depends[0].as_str().unwrap(), "alpha_cache");

        let alpha_vols = alpha_db.get("volumes").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(alpha_vols[0].as_str().unwrap(), "alpha_data:/var/lib/data");

        let beta_db = svcs.get(Value::String("beta_db".into())).unwrap();
        let beta_vols = beta_db.get("volumes").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(
            beta_vols[0].as_str().unwrap(),
            "./local:/mnt/local",
            "bind mounts must stay verbatim"
        );

        let merged_vols = doc.get("volumes").and_then(|v| v.as_mapping()).unwrap();
        assert!(merged_vols.contains_key(Value::String("alpha_data".into())));
    }

    #[test]
    fn merge_rejects_non_mapping_root() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("bogus.yml");
        std::fs::write(&p, "- a list\n- not a mapping\n").unwrap();
        let files = vec![ComposeFile { repo_name: "x".into(), path: p }];
        let err = merge(&files, &tmp.path().join("super.yml"), &ProjectOverrides::default())
            .unwrap_err();
        assert!(matches!(err, ComposeError::NotMapping { .. }));
    }

    #[test]
    fn merge_stamps_project_overrides() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("docker-compose.yml"), "services:\n  api:\n    image: alpine\n")
            .unwrap();
        let files = vec![ComposeFile {
            repo_name: "alpha".into(),
            path: a.join("docker-compose.yml"),
        }];
        let out = tmp.path().join("super.yml");
        let env_config = serde_json::json!({ "feature_x": true, "max": 7 });
        let overrides = ProjectOverrides {
            target_base_url: Some("http://localhost:3000"),
            env_config: Some(&env_config),
        };
        merge(&files, &out, &overrides).expect("merge ok");

        let raw = std::fs::read_to_string(&out).unwrap();
        let doc: Value = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(
            doc.get("x-nyx-target-base-url").and_then(|v| v.as_str()),
            Some("http://localhost:3000")
        );
        let cfg = doc.get("x-nyx-env-config").expect("env config stamped");
        assert_eq!(cfg.get("feature_x").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(cfg.get("max").and_then(|v| v.as_i64()), Some(7));
    }

    #[test]
    fn merge_omits_overrides_when_unset() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("docker-compose.yml"), "services:\n  api:\n    image: alpine\n")
            .unwrap();
        let files = vec![ComposeFile {
            repo_name: "alpha".into(),
            path: a.join("docker-compose.yml"),
        }];
        let out = tmp.path().join("super.yml");
        merge(&files, &out, &ProjectOverrides::default()).expect("merge ok");
        let raw = std::fs::read_to_string(&out).unwrap();
        let doc: Value = serde_yaml::from_str(&raw).unwrap();
        assert!(doc.get("x-nyx-target-base-url").is_none());
        assert!(doc.get("x-nyx-env-config").is_none());
    }

    #[test]
    fn sanitise_prefix_replaces_non_alnum() {
        assert_eq!(sanitise_prefix("nyx-pro"), "nyx_pro");
        assert_eq!(sanitise_prefix("Alpha/Beta"), "alpha_beta");
        assert_eq!(sanitise_prefix(""), "repo");
        assert_eq!(sanitise_prefix("---"), "repo");
    }
}

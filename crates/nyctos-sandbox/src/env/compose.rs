//! docker-compose detection + super-compose merge.
//!
//! The env-builder ships a deliberately tight merge: top-level `services`,
//! `volumes`, `networks`, `secrets`, and `configs` are renamed
//! `<repo_prefix>_<name>` so two repos that both declare a `db` service
//! (or a `db_password` secret) do not collide. Per-service `depends_on`,
//! named-volume mounts, `networks` lists, `secrets` / `configs` refs, and
//! `container_name` are rewritten to point at the namespaced names.
//!
//! Anything else (build args, env, ports, healthcheck, command, image,
//! etc.) is passed through verbatim. Operators that want a deeper merge
//! (link names, profiles) get to write their own super-compose by hand
//! for now.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Value};
use thiserror::Error;

/// Filenames docker compose recognises out of the box. Order is also
/// the priority order used when two siblings live in the same directory.
const CANDIDATE_FILES: &[&str] =
    &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];

/// Maximum directory depth `detect` descends from the repo root when
/// looking for a compose file. Root is depth 0. The walk is bounded so
/// a misplaced `node_modules/` (which the skip set excludes anyway)
/// cannot stall ingestion on a deep monorepo.
const DETECT_MAX_DEPTH: usize = 3;

/// Directory names skipped during the nested compose walk. Same shape
/// as the static-pass source walker: hot vendor / build / cache dirs
/// plus the `.git` worktree. Dotfile dirs are skipped via a separate
/// `starts_with('.')` predicate so an operator who parks compose under
/// `~/repo/.devops/` still gets picked up at the repo root level but
/// not from nested dotdirs deeper in the tree.
const DETECT_SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "_vendor",
    "dist",
    "build",
    "out",
    ".venv",
    "venv",
    "env",
    ".next",
    ".nuxt",
    "site-packages",
    "third_party",
    "__pycache__",
];

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
/// compose schema reserves the `x-` prefix for arbitrary user extras;
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

/// Find the canonical compose file for a single repo, if any. Walks
/// the repo root first and then descends up to [`DETECT_MAX_DEPTH`]
/// levels through non-hot, non-dot subdirectories so compose files
/// parked under `infra/`, `docker/`, or `deploy/compose/` still get
/// picked up. Hot vendor / build directories listed in
/// [`DETECT_SKIP_DIRS`] are skipped to keep the walk bounded on
/// monorepos.
///
/// Priority order:
/// 1. Shallowest depth wins (root beats `infra/`, `infra/` beats
///    `infra/compose/`).
/// 2. Within a depth, the canonical filename order in
///    [`CANDIDATE_FILES`] applies (so `docker-compose.yml` wins over
///    `compose.yaml` parked next to it).
/// 3. Within a depth, sibling directories are visited in lexicographic
///    order so the choice is deterministic across hosts.
pub fn detect(repo_root: &Path, repo_name: &str) -> Option<ComposeFile> {
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((repo_root.to_path_buf(), 0));
    while let Some((dir, depth)) = queue.pop_front() {
        for name in CANDIDATE_FILES {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(ComposeFile { repo_name: repo_name.to_string(), path: candidate });
            }
        }
        if depth >= DETECT_MAX_DEPTH {
            continue;
        }
        let mut children: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
                .map(|entry| entry.path())
                .filter(|path| {
                    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                        return false;
                    };
                    !name.starts_with('.') && !DETECT_SKIP_DIRS.contains(&name)
                })
                .collect(),
            Err(_) => continue,
        };
        children.sort();
        for child in children {
            queue.push_back((child, depth + 1));
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
    let mut secrets = Mapping::new();
    let mut configs = Mapping::new();
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
        if let Some(Value::Mapping(secs)) = map.get(Value::String("secrets".into())) {
            for (k, v) in secs {
                let Some(name) = k.as_str() else { continue };
                secrets.insert(Value::String(format!("{prefix}_{name}")), v.clone());
            }
        }
        if let Some(Value::Mapping(cfgs)) = map.get(Value::String("configs".into())) {
            for (k, v) in cfgs {
                let Some(name) = k.as_str() else { continue };
                configs.insert(Value::String(format!("{prefix}_{name}")), v.clone());
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
    if !secrets.is_empty() {
        merged.insert(Value::String("secrets".into()), Value::Mapping(secrets));
    }
    if !configs.is_empty() {
        merged.insert(Value::String("configs".into()), Value::Mapping(configs));
    }
    if let Some(url) = overrides.target_base_url {
        merged
            .insert(Value::String("x-nyx-target-base-url".into()), Value::String(url.to_string()));
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
            Some("secrets") => rewrite_named_refs(v, prefix),
            Some("configs") => rewrite_named_refs(v, prefix),
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

/// Rewrite a per-service `secrets:` or `configs:` reference list. The
/// compose schema accepts two shapes per entry:
///   * short-form bare name string `db_password`,
///   * long-form mapping with a `source: <name>` key (plus optional
///     `target` / `uid` / `gid` / `mode`).
///
/// Both shapes name a top-level entry by symbol, so the rewrite mirrors
/// the namespacing applied to the top-level mappings.
fn rewrite_named_refs(v: &Value, prefix: &str) -> Value {
    let Value::Sequence(items) = v else {
        return v.clone();
    };
    let new_items = items
        .iter()
        .map(|i| {
            if let Some(name) = i.as_str() {
                return Value::String(format!("{prefix}_{name}"));
            }
            if let Value::Mapping(m) = i {
                let mut out = m.clone();
                if let Some(Value::String(src)) = out.get(Value::String("source".into())).cloned() {
                    out.insert(
                        Value::String("source".into()),
                        Value::String(format!("{prefix}_{src}")),
                    );
                }
                return Value::Mapping(out);
            }
            i.clone()
        })
        .collect();
    Value::Sequence(new_items)
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
    fn detect_finds_nested_compose_under_infra() {
        let tmp = tempdir().unwrap();
        let nested = tmp.path().join("infra").join("compose");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("docker-compose.yml"), "services: {}\n").unwrap();
        let cf = detect(tmp.path(), "alpha").expect("found nested");
        assert_eq!(cf.path, nested.join("docker-compose.yml"));
    }

    #[test]
    fn detect_prefers_repo_root_over_nested() {
        let tmp = tempdir().unwrap();
        let nested = tmp.path().join("deploy");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "services: {}\n").unwrap();
        std::fs::write(nested.join("docker-compose.yml"), "services: {}\n").unwrap();
        let cf = detect(tmp.path(), "alpha").expect("found");
        assert_eq!(cf.path, tmp.path().join("docker-compose.yml"));
    }

    #[test]
    fn detect_skips_hot_directories() {
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules").join("vendor-pkg");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("docker-compose.yml"), "services: {}\n").unwrap();
        assert!(detect(tmp.path(), "alpha").is_none(), "must not descend into node_modules");
    }

    #[test]
    fn detect_skips_dot_directories() {
        let tmp = tempdir().unwrap();
        let dotdir = tmp.path().join(".cache");
        std::fs::create_dir_all(&dotdir).unwrap();
        std::fs::write(dotdir.join("docker-compose.yml"), "services: {}\n").unwrap();
        assert!(detect(tmp.path(), "alpha").is_none(), "must not descend into dot dirs");
    }

    #[test]
    fn detect_honours_max_depth() {
        let tmp = tempdir().unwrap();
        let too_deep = tmp.path().join("a").join("b").join("c").join("d");
        std::fs::create_dir_all(&too_deep).unwrap();
        std::fs::write(too_deep.join("docker-compose.yml"), "services: {}\n").unwrap();
        assert!(
            detect(tmp.path(), "alpha").is_none(),
            "depth 4 files must not be picked up (max depth 3)",
        );
    }

    #[test]
    fn detect_picks_canonical_name_first() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "services: {}\n").unwrap();
        std::fs::write(tmp.path().join("compose.yaml"), "services: {}\n").unwrap();
        let cf = detect(tmp.path(), "alpha").expect("found");
        assert_eq!(cf.path.file_name().unwrap(), "docker-compose.yml");
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
        let err =
            merge(&files, &tmp.path().join("super.yml"), &ProjectOverrides::default()).unwrap_err();
        assert!(matches!(err, ComposeError::NotMapping { .. }));
    }

    #[test]
    fn merge_stamps_project_overrides() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("docker-compose.yml"), "services:\n  api:\n    image: alpine\n")
            .unwrap();
        let files =
            vec![ComposeFile { repo_name: "alpha".into(), path: a.join("docker-compose.yml") }];
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
        let files =
            vec![ComposeFile { repo_name: "alpha".into(), path: a.join("docker-compose.yml") }];
        let out = tmp.path().join("super.yml");
        merge(&files, &out, &ProjectOverrides::default()).expect("merge ok");
        let raw = std::fs::read_to_string(&out).unwrap();
        let doc: Value = serde_yaml::from_str(&raw).unwrap();
        assert!(doc.get("x-nyx-target-base-url").is_none());
        assert!(doc.get("x-nyx-env-config").is_none());
    }

    #[test]
    fn merge_namespaces_secrets_and_configs_across_repos() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(
            a.join("docker-compose.yml"),
            r#"
services:
  api:
    image: alpine
    secrets:
      - db_password
    configs:
      - source: app_cfg
        target: /etc/app.cfg
secrets:
  db_password:
    file: ./pwd
configs:
  app_cfg:
    file: ./app.cfg
"#,
        )
        .unwrap();
        std::fs::write(
            b.join("docker-compose.yml"),
            r#"
services:
  api:
    image: alpine
    secrets:
      - db_password
secrets:
  db_password:
    file: ./pwd
"#,
        )
        .unwrap();

        let files = vec![
            ComposeFile { repo_name: "alpha".into(), path: a.join("docker-compose.yml") },
            ComposeFile { repo_name: "beta".into(), path: b.join("docker-compose.yml") },
        ];
        let out = tmp.path().join("super.yml");
        merge(&files, &out, &ProjectOverrides::default()).expect("merge ok");

        let raw = std::fs::read_to_string(&out).unwrap();
        let doc: Value = serde_yaml::from_str(&raw).unwrap();

        let top_secrets = doc.get("secrets").and_then(|v| v.as_mapping()).unwrap();
        assert!(top_secrets.contains_key(Value::String("alpha_db_password".into())));
        assert!(top_secrets.contains_key(Value::String("beta_db_password".into())));
        assert!(!top_secrets.contains_key(Value::String("db_password".into())));

        let top_configs = doc.get("configs").and_then(|v| v.as_mapping()).unwrap();
        assert!(top_configs.contains_key(Value::String("alpha_app_cfg".into())));

        let svcs = doc.get("services").and_then(|v| v.as_mapping()).unwrap();
        let alpha_api = svcs.get(Value::String("alpha_api".into())).unwrap();
        let alpha_secrets = alpha_api.get("secrets").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(alpha_secrets[0].as_str().unwrap(), "alpha_db_password");
        let alpha_configs = alpha_api.get("configs").and_then(|v| v.as_sequence()).unwrap();
        let cfg_entry = alpha_configs[0].as_mapping().unwrap();
        assert_eq!(
            cfg_entry.get(Value::String("source".into())).and_then(|v| v.as_str()),
            Some("alpha_app_cfg"),
        );
        assert_eq!(
            cfg_entry.get(Value::String("target".into())).and_then(|v| v.as_str()),
            Some("/etc/app.cfg"),
            "non-source fields must pass through",
        );

        let beta_api = svcs.get(Value::String("beta_api".into())).unwrap();
        let beta_secrets = beta_api.get("secrets").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(beta_secrets[0].as_str().unwrap(), "beta_db_password");
    }

    #[test]
    fn sanitise_prefix_replaces_non_alnum() {
        assert_eq!(sanitise_prefix("acme-app"), "acme_app");
        assert_eq!(sanitise_prefix("Alpha/Beta"), "alpha_beta");
        assert_eq!(sanitise_prefix(""), "repo");
        assert_eq!(sanitise_prefix("---"), "repo");
    }
}

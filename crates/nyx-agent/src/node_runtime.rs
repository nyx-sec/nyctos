use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn playwright_available(extra_roots: &[PathBuf]) -> bool {
    let mut command = Command::new("node");
    apply_node_path(&mut command, extra_roots);
    command
        .args(["-e", "require.resolve('playwright')"])
        .output()
        .is_ok_and(|out| out.status.success())
}

pub fn apply_node_path(command: &mut Command, extra_roots: &[PathBuf]) {
    if let Some(node_path) = node_path_env(extra_roots) {
        command.env("NODE_PATH", node_path);
    }
}

pub fn node_path_env(extra_roots: &[PathBuf]) -> Option<std::ffi::OsString> {
    let paths = node_module_paths(extra_roots);
    if paths.is_empty() {
        None
    } else {
        std::env::join_paths(paths).ok()
    }
}

fn node_module_paths(extra_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();

    for var in ["NYX_AGENT_PLAYWRIGHT_NODE_MODULES", "NYX_AGENT_NODE_MODULES", "NODE_PATH"] {
        if let Some(raw) = std::env::var_os(var) {
            for path in std::env::split_paths(&raw) {
                insert_existing(&mut paths, path);
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        add_root_candidates(&mut paths, &cwd);
        for ancestor in cwd.ancestors().take(4) {
            add_root_candidates(&mut paths, ancestor);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    add_root_candidates(&mut paths, &manifest_dir);
    for ancestor in manifest_dir.ancestors().take(5) {
        add_root_candidates(&mut paths, ancestor);
    }

    for root in extra_roots {
        add_root_candidates(&mut paths, root);
        for ancestor in root.ancestors().take(4) {
            add_root_candidates(&mut paths, ancestor);
        }
    }

    paths.into_iter().collect()
}

fn add_root_candidates(paths: &mut BTreeSet<PathBuf>, root: &Path) {
    insert_existing(paths, root.join("node_modules"));
    insert_existing(paths, root.join("frontend").join("node_modules"));
}

fn insert_existing(paths: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if path.is_dir() {
        paths.insert(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_module_paths_include_frontend_node_modules_under_extra_root() {
        let tmp = tempfile::tempdir().unwrap();
        let frontend_modules = tmp.path().join("frontend").join("node_modules");
        std::fs::create_dir_all(&frontend_modules).unwrap();

        let paths = node_module_paths(&[tmp.path().to_path_buf()]);

        assert!(paths.iter().any(|path| path == &frontend_modules));
    }
}

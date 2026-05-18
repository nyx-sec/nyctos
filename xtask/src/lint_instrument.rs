//! `lint-instrument` subcommand. Parses every tracked Rust source under
//! `crates/` with `syn` and warns on a public function (free-standing or
//! inherent-impl method) that lacks `#[tracing::instrument]`. The lint
//! exists because Rust offers no native clippy rule that ties an
//! attribute requirement to a visibility modifier; we want every public
//! entry-point to carry a structured-tracing span so production logs
//! reconstruct the call tree.
//!
//! Mirrors the prior `.ci/missing-instrument.sh` awk script but handles:
//! - signatures split across multiple source lines (long generic bounds,
//!   multi-line return types) since syn walks the AST rather than greps
//!   one line at a time,
//! - the `Visibility::Public` vs `Visibility::Restricted` distinction
//!   (so `pub(crate) fn ...` is correctly skipped),
//! - trait-impl methods (whose visibility is implied by the trait, not
//!   the impl, and therefore should not be flagged),
//! - `#[cfg(test)]` modules and `tests/` directories.
//!
//! The lint is warn-only: every warning lands on stderr and the binary
//! exits 0. Phase 29's promotion to a hard error flips the exit status
//! once every workspace public fn is either instrumented or carries a
//! `// nyx: no-instrument` exempt comment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use syn::visit::Visit;
use syn::{Attribute, ImplItemFn, ItemFn, ItemImpl, ItemMod, Meta, Visibility};
use walkdir::WalkDir;

pub fn run() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let files = collect_files(&workspace_root);
    for path in files {
        lint_file(&workspace_root, &path);
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask Cargo.toml is not in a workspace".to_string())
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    if let Some(tracked) = git_ls_files(root) {
        return tracked;
    }
    let mut files = Vec::new();
    let crates_dir = root.join("crates");
    for entry in WalkDir::new(&crates_dir).into_iter().flatten() {
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|e| e == "rs") {
            files.push(entry.path().to_path_buf());
        }
    }
    files
}

fn git_ls_files(root: &Path) -> Option<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files", "crates/*.rs", "crates/**/*.rs"])
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    Some(stdout.lines().filter(|l| !l.is_empty()).map(|l| root.join(l)).collect())
}

fn should_skip_path(relative: &Path) -> bool {
    let mut saw_tests = false;
    for comp in relative.components() {
        if let std::path::Component::Normal(s) = comp {
            if s == "tests" {
                saw_tests = true;
            }
        }
    }
    if saw_tests {
        return true;
    }
    matches!(relative.file_name().and_then(|s| s.to_str()), Some("main.rs") | Some("build.rs"))
}

fn lint_file(root: &Path, abs_path: &Path) {
    let relative = abs_path.strip_prefix(root).unwrap_or(abs_path);
    if should_skip_path(relative) {
        return;
    }
    let src = match fs::read_to_string(abs_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ast = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(_) => return,
    };
    let display_path = relative.to_string_lossy().into_owned();
    let mut linter = Linter::new(display_path, &src);
    linter.visit_file(&ast);
}

struct Linter<'src> {
    display_path: String,
    lines: Vec<&'src str>,
    impl_depth_trait: Vec<bool>,
}

impl<'src> Linter<'src> {
    fn new(display_path: String, src: &'src str) -> Self {
        Self { display_path, lines: src.lines().collect(), impl_depth_trait: Vec::new() }
    }

    fn in_trait_impl(&self) -> bool {
        self.impl_depth_trait.last().copied().unwrap_or(false)
    }

    fn check_fn(&self, name: &str, vis: &Visibility, attrs: &[Attribute], line_1based: usize) {
        if !matches!(vis, Visibility::Public(_)) {
            return;
        }
        if attrs.iter().any(is_instrument_attr) {
            return;
        }
        if attrs.iter().any(is_test_attr) {
            return;
        }
        if self.has_exempt_marker(line_1based) {
            return;
        }
        eprintln!(
            "warning: {}:{}: pub fn `{}` missing #[tracing::instrument]",
            self.display_path, line_1based, name
        );
    }

    fn has_exempt_marker(&self, line_1based: usize) -> bool {
        let mut idx = line_1based.saturating_sub(1);
        while idx > 0 {
            idx -= 1;
            let line = match self.lines.get(idx) {
                Some(l) => l.trim_start(),
                None => return false,
            };
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("//") {
                let payload = rest.trim_start();
                if payload.starts_with("nyx:") {
                    let after = payload.trim_start_matches("nyx:").trim_start();
                    if after.starts_with("no-instrument") {
                        return true;
                    }
                }
                continue;
            }
            if line.starts_with("#[") || line.starts_with("#![") {
                continue;
            }
            return false;
        }
        false
    }
}

impl<'ast, 'src> Visit<'ast> for Linter<'src> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let line = node.sig.fn_token.span.start().line;
        self.check_fn(&node.sig.ident.to_string(), &node.vis, &node.attrs, line);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.impl_depth_trait.push(node.trait_.is_some());
        for item in &node.items {
            if let syn::ImplItem::Fn(f) = item {
                self.visit_impl_item_fn(f);
            }
        }
        self.impl_depth_trait.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if self.in_trait_impl() {
            return;
        }
        let line = node.sig.fn_token.span.start().line;
        self.check_fn(&node.sig.ident.to_string(), &node.vis, &node.attrs, line);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        if let Some((_, items)) = &node.content {
            for item in items {
                self.visit_item(item);
            }
        }
    }
}

fn is_instrument_attr(attr: &Attribute) -> bool {
    let path = attr.path();
    if path.is_ident("instrument") {
        return true;
    }
    let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    matches!(segments.as_slice(), [a, b] if a == "tracing" && b == "instrument")
}

fn is_test_attr(attr: &Attribute) -> bool {
    let path = attr.path();
    path.is_ident("test")
        || matches!(
            path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().as_slice(),
            [a, b] if (a == "tokio" || a == "test") && b == "test"
        )
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        if let Meta::List(list) = &attr.meta {
            list.tokens.to_string().split_whitespace().any(|t| t == "test")
        } else {
            false
        }
    })
}

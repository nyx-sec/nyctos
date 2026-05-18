//! Build script that produces the embedded SPA asset tree.
//!
//! Behaviour by profile:
//!
//! * In `release` profile (and only there) invoke
//!   `npm ci --silent` + `npm run build` from `<repo>/frontend/`,
//!   then mirror `frontend/dist/` into `crates/nyx-agent-ui/dist/`
//!   so the `rust_embed` macro picks them up at compile time.
//! * In any other profile (or when the env var
//!   `NYCTOS_SKIP_FRONTEND_BUILD=1` is set) write a tiny stub
//!   `index.html` that points the operator at `npm run dev`. Debug
//!   builds are common in CI where Node is not guaranteed; we still
//!   want a non-empty asset tree so the agent's `/` route returns
//!   a usable page instead of 404.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NYCTOS_SKIP_FRONTEND_BUILD");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crate dir has parent")
        .parent()
        .expect("crates/ dir has parent")
        .to_path_buf();
    let frontend_dir = workspace_root.join("frontend");
    let crate_dist_dir = manifest_dir.join("dist");

    for source in ["package.json", "vite.config.ts", "tsconfig.json", "index.html", "src"] {
        let entry = frontend_dir.join(source);
        if entry.exists() {
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }

    let profile = env::var("PROFILE").unwrap_or_default();
    let skip = env::var("NYCTOS_SKIP_FRONTEND_BUILD").ok().as_deref() == Some("1");
    let want_real_build = profile == "release" && !skip;

    fs::create_dir_all(&crate_dist_dir).expect("create crate dist dir");

    if want_real_build {
        match build_real_spa(&frontend_dir, &crate_dist_dir) {
            Ok(()) => return,
            Err(err) => {
                // Surface as a hard error in release; debug profile
                // falls through to the stub. We never want to ship a
                // release binary with a stub UI.
                panic!("frontend build failed: {err}");
            }
        }
    }

    write_stub_index(&crate_dist_dir).expect("write stub index.html");
}

fn build_real_spa(frontend_dir: &Path, crate_dist_dir: &Path) -> Result<(), String> {
    if !frontend_dir.join("package.json").is_file() {
        return Err(format!(
            "missing {}/package.json — frontend not scaffolded",
            frontend_dir.display(),
        ));
    }

    let node_modules = frontend_dir.join("node_modules");
    if !node_modules.is_dir() {
        run_npm(frontend_dir, &["ci", "--silent"])?;
    }

    run_npm(frontend_dir, &["run", "build"])?;

    let built = frontend_dir.join("dist");
    if !built.is_dir() {
        return Err(format!("expected {} to exist after build", built.display()));
    }

    wipe_dir_keep(crate_dist_dir, &[".gitkeep", ".gitignore"])
        .map_err(|e| format!("wipe crate dist: {e}"))?;
    copy_dir_recursive(&built, crate_dist_dir)
        .map_err(|e| format!("copy {} -> {}: {e}", built.display(), crate_dist_dir.display()))?;
    Ok(())
}

fn run_npm(cwd: &Path, args: &[&str]) -> Result<(), String> {
    let status = Command::new("npm")
        .args(args)
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("spawn npm {args:?}: {e}"))?;
    if !status.success() {
        return Err(format!("npm {args:?} exited with status {status}"));
    }
    Ok(())
}

fn write_stub_index(crate_dist_dir: &Path) -> std::io::Result<()> {
    let stub = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>nyx-agent (dev build)</title>
    <style>
      body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
           background:#0b0d12;color:#e6e9f0;margin:0;
           display:flex;align-items:center;justify-content:center;min-height:100vh;}
      main{max-width:38rem;padding:2rem;text-align:center;}
      code{background:#161a23;padding:.1em .35em;border-radius:.25em;}
      a{color:#7c8cff;}
    </style>
  </head>
  <body>
    <main>
      <h1>nyx-agent</h1>
      <p>This binary was built with the <code>debug</code> profile so the
         single-page UI was not bundled. Use <code>npm run dev</code> from
         <code>frontend/</code> for a hot-reload session, or rebuild the
         agent with <code>cargo build --release</code> to embed the SPA.</p>
      <p><a href="/api/v1/health">/api/v1/health</a></p>
    </main>
  </body>
</html>
"#;
    fs::write(crate_dist_dir.join("index.html"), stub)?;
    // Preserve the existing .gitkeep so a fresh checkout still has the
    // marker the runner committed.
    let gitkeep = crate_dist_dir.join(".gitkeep");
    if !gitkeep.exists() {
        fs::write(gitkeep, b"")?;
    }
    Ok(())
}

fn wipe_dir_keep(dir: &Path, keep_names: &[&str]) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if keep_names.iter().any(|name| entry.file_name() == *name) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if ft.is_file() {
            fs::copy(entry.path(), &target)?;
        }
        // ignore symlinks; vite output is files only
    }
    Ok(())
}

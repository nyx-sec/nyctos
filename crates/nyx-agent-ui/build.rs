//! Build script that prepares embedded SPA assets under `OUT_DIR`.
//!
//! Behaviour by profile:
//!
//! * Release builds from a repository checkout rebuild `frontend/`
//!   unless `NYX_AGENT_SKIP_FRONTEND_BUILD=1` is set.
//! * Release builds from a published crate copy the packaged `dist/`
//!   tree, so `cargo install nyx-agent` does not need Node or pnpm.
//! * Debug builds write a tiny stub `index.html`. Debug builds are
//!   common in CI where Node is not guaranteed; we still want a
//!   non-empty asset tree so the daemon's `/` route returns a usable
//!   page instead of 404.
//!
//! The script never writes into the package source directory. Cargo's
//! publish verifier rejects build scripts that mutate anything outside
//! `OUT_DIR`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const OUT_DIST_DIR: &str = "nyx-agent-ui-dist";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=dist");
    println!("cargo:rerun-if-env-changed=NYX_AGENT_SKIP_FRONTEND_BUILD");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crate dir has parent")
        .parent()
        .expect("crates/ dir has parent")
        .to_path_buf();
    let frontend_dir = workspace_root.join("frontend");
    let packaged_dist_dir = manifest_dir.join("dist");
    let out_dist_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo")).join(OUT_DIST_DIR);

    for source in [
        "package.json",
        "../pnpm-lock.yaml",
        "vite.config.ts",
        "tsconfig.json",
        "index.html",
        "public",
        "src",
    ] {
        let entry = frontend_dir.join(source);
        if entry.exists() {
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }

    let profile = env::var("PROFILE").unwrap_or_default();
    let skip = env::var("NYX_AGENT_SKIP_FRONTEND_BUILD").ok().as_deref() == Some("1");
    let want_real_build = profile == "release" && !skip;

    fresh_dir(&out_dist_dir).expect("prepare OUT_DIR asset tree");

    if want_real_build {
        match build_real_spa(&frontend_dir, &out_dist_dir) {
            Ok(()) => return,
            Err(err) => {
                if packaged_dist_dir.join("index.html").is_file() {
                    eprintln!("frontend build failed ({err}); falling back to packaged SPA assets",);
                } else {
                    panic!("frontend build failed and no packaged SPA assets were found: {err}");
                }
            }
        }
    }

    if profile == "release" {
        copy_packaged_spa(&packaged_dist_dir, &out_dist_dir)
            .expect("copy packaged SPA assets for release build");
    } else {
        write_stub_index(&out_dist_dir).expect("write stub index.html");
    }
}

fn build_real_spa(frontend_dir: &Path, out_dist_dir: &Path) -> Result<(), String> {
    if !frontend_dir.join("package.json").is_file() {
        return Err(format!(
            "missing {}/package.json: frontend not scaffolded",
            frontend_dir.display(),
        ));
    }

    let package_manager = PackageManager::detect(frontend_dir)?;
    let node_modules = frontend_dir.join("node_modules");
    if !node_modules.is_dir() {
        package_manager.install(frontend_dir)?;
    }

    package_manager.build(frontend_dir)?;

    let built = frontend_dir.join("dist");
    if !built.is_dir() {
        return Err(format!("expected {} to exist after build", built.display()));
    }

    fresh_dir(out_dist_dir).map_err(|e| format!("prepare output dist: {e}"))?;
    copy_dir_recursive(&built, out_dist_dir)
        .map_err(|e| format!("copy {} -> {}: {e}", built.display(), out_dist_dir.display()))?;
    Ok(())
}

fn copy_packaged_spa(packaged_dist_dir: &Path, out_dist_dir: &Path) -> Result<(), String> {
    if !packaged_dist_dir.join("index.html").is_file() {
        return Err(format!(
            "missing packaged SPA assets at {}; run `pnpm --dir frontend run build` and mirror \
             frontend/dist into crates/nyx-agent-ui/dist before publishing",
            packaged_dist_dir.display(),
        ));
    }
    fresh_dir(out_dist_dir).map_err(|e| format!("prepare output dist: {e}"))?;
    copy_dir_recursive(packaged_dist_dir, out_dist_dir).map_err(|e| {
        format!("copy {} -> {}: {e}", packaged_dist_dir.display(), out_dist_dir.display())
    })
}

#[derive(Debug, Clone, Copy)]
enum PackageManager {
    Pnpm,
    CorepackPnpm,
    Npm,
}

impl PackageManager {
    fn detect(frontend_dir: &Path) -> Result<Self, String> {
        if command_exists("pnpm") {
            return Ok(Self::Pnpm);
        }
        if frontend_dir.join("node_modules").is_dir() {
            return Ok(Self::Npm);
        }
        if command_exists("corepack") {
            return Ok(Self::CorepackPnpm);
        }
        if frontend_dir.join("package-lock.json").is_file() {
            return Ok(Self::Npm);
        }
        Err("pnpm is required to build the frontend from source; install pnpm or set \
             NYX_AGENT_SKIP_FRONTEND_BUILD=1 to use packaged dist assets"
            .to_string())
    }

    fn install(self, cwd: &Path) -> Result<(), String> {
        match self {
            Self::Pnpm => run("pnpm", &["install", "--frozen-lockfile"], cwd),
            Self::CorepackPnpm => run("corepack", &["pnpm", "install", "--frozen-lockfile"], cwd),
            Self::Npm => run("npm", &["ci", "--silent"], cwd),
        }
    }

    fn build(self, cwd: &Path) -> Result<(), String> {
        match self {
            Self::Pnpm => run("pnpm", &["run", "build"], cwd),
            Self::CorepackPnpm => run("corepack", &["pnpm", "run", "build"], cwd),
            Self::Npm => run("npm", &["run", "build"], cwd),
        }
    }
}

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run(cmd: &str, args: &[&str], cwd: &Path) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("spawn {cmd} {args:?}: {e}"))?;
    if !status.success() {
        return Err(format!("{cmd} {args:?} exited with status {status}"));
    }
    Ok(())
}

fn write_stub_index(out_dist_dir: &Path) -> std::io::Result<()> {
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
         <code>frontend/</code> for a hot-reload session, or install/build a
         release binary to use the embedded SPA.</p>
      <p><a href="/api/v1/health">/api/v1/health</a></p>
    </main>
  </body>
</html>
"#;
    fs::write(out_dist_dir.join("index.html"), stub)
}

fn fresh_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".gitkeep" || name == ".gitignore" {
            continue;
        }
        let target = dst.join(name);
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

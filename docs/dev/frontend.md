# Frontend SPA workflow

The `nyx-agent` daemon serves a single-page UI at `/`. The
`nyx-agent-ui` crate embeds the SPA assets via `rust_embed`. The build
script prepares the asset tree under Cargo's `OUT_DIR` so normal builds
and Cargo's publish verifier never mutate the package source directory.

## Release builds

`cargo build --release` (or any profile equal to `release`) from a
repository checkout runs the real frontend build inside
`crates/nyx-agent-ui/build.rs`:

1. `pnpm install --frozen-lockfile` in `frontend/` if dependencies are absent.
2. `pnpm run build`, producing `frontend/dist/`.
3. The dist tree is copied into `OUT_DIR/nyx-agent-ui-dist/` so
   `rust_embed` picks it up at compile time.

Published crates include prebuilt assets under `crates/nyx-agent-ui/dist/`.
When a release build runs without a repository-level `frontend/` checkout
or when `NYX_AGENT_SKIP_FRONTEND_BUILD=1` is set, the build script copies
those packaged assets instead. A release build never ships the debug stub.

## Debug builds

`cargo run` and `cargo build` (no `--release`) write a tiny stub
`index.html` into `OUT_DIR/nyx-agent-ui-dist/` that explains the
situation and points at `/api/v1/health`. The stub keeps `GET /`
returning a usable page in CI environments without Node installed.

## Iterative dev loop

For an iterative dev loop, run two processes side by side:

```sh
# Terminal 1: daemon on 127.0.0.1:8765.
cargo run -p nyx-agent -- serve

# Terminal 2: Vite dev server on 127.0.0.1:5173, proxying /api to 8765.
cd frontend && pnpm install && pnpm run dev
```

Open `http://127.0.0.1:5173/` for the hot-reload SPA. The daemon at
`:8765` still answers `/api/v1/...` directly, so curl-based testing
against `:8765` keeps working without Vite running.

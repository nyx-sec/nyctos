# Frontend SPA workflow

The `nyx-agent` daemon serves a single-page UI at `/`. The
`nyx-agent-ui` crate embeds the SPA assets via `rust_embed`, and the
embed contents depend on the cargo build profile.

## Release builds

`cargo build --release` (or any profile equal to `release`) runs the
real frontend build inside `crates/nyx-agent-ui/build.rs`:

1. `npm ci --silent` in `frontend/` if `node_modules/` is absent.
2. `npm run build`, producing `frontend/dist/`.
3. The dist tree is mirrored into `crates/nyx-agent-ui/dist/` so
   `rust_embed` picks it up at compile time.

A release build with a missing or broken `frontend/` checkout fails
the build script with a panic. Set `NYCTOS_SKIP_FRONTEND_BUILD=1` to
opt out and ship the stub instead (used by environments that build
the SPA separately and prepopulate `crates/nyx-agent-ui/dist/`).

## Debug builds

`cargo run` and `cargo build` (no `--release`) write a tiny stub
`index.html` into `crates/nyx-agent-ui/dist/` that explains the
situation and points at `/api/v1/health`. The stub keeps `GET /`
returning a usable page in CI environments without Node installed.

## Iterative dev loop

For an iterative dev loop, run two processes side by side:

```sh
# Terminal 1: daemon on 127.0.0.1:8765.
cargo run -p nyx-agent -- serve

# Terminal 2: Vite dev server on 127.0.0.1:5173, proxying /api to 8765.
cd frontend && npm install && npm run dev
```

Open `http://127.0.0.1:5173/` for the hot-reload SPA. The daemon at
`:8765` still answers `/api/v1/...` directly, so curl-based testing
against `:8765` keeps working without Vite running.

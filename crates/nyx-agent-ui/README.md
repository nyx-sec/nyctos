# nyx-agent-ui

Implementation-detail embedded single-page dashboard assets for
`nyx-agent`.

The published crate includes prebuilt dashboard assets under `dist/`.
During `cargo install nyx-agent`, the build script copies those assets
into `OUT_DIR` for embedding, so users do not need Node, pnpm, or a
frontend checkout.

This crate is not intended as a stable public API; downstream users should
install and run `nyx-agent` instead.

Repository: <https://github.com/nyx-sec/nyx-agent>

# Release

Nyx Agent publishes the `nyx-agent` binary crate plus several internal
implementation crates. The internal crates are visible on crates.io only so
Cargo can install the binary with versioned dependencies; they are not stable
public APIs.

## Preflight

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm --dir frontend run check
pnpm --dir frontend test
pnpm --dir frontend run build
rsync -a --delete frontend/dist/ crates/nyx-agent-ui/dist/
```

`cargo install nyx-agent` uses the packaged
`crates/nyx-agent-ui/dist/` assets, so keep that directory in sync with
the current frontend build before publishing.

## Publish Order

Publish in dependency order:

1. `nyx-agent-types`
2. `nyx-agent-ui`
3. `nyx-agent-core`
4. `nyx-agent-nyx`
5. `nyx-agent-sandbox`
6. `nyx-agent-ai`
7. `nyx-agent-api`
8. `nyx-agent`

Cargo dry-runs for dependent crates can fail with `no matching package
named nyx-agent-* found` until the earlier crates in this list are
actually published and visible in the crates.io index. That is expected.
The publish command for each crate is:

```bash
cargo publish -p <crate-name>
```

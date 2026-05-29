# SQLx prepared-query cache

`nyx-agent-core` uses SQLx's compile-time-checked query macros against a
SQLite schema shipped under `crates/nyx-agent-core/migrations/`. Recorded
query plans live in `crates/nyx-agent-core/.sqlx/` and are checked into
version control so the workspace builds without a database present and the
published crate can verify without `DATABASE_URL` (CI runs with
`SQLX_OFFLINE=true`).

## Regenerating the cache

If you add, remove, or modify a `sqlx::query!` / `sqlx::query_as!` call,
regenerate the cache:

```sh
cargo install sqlx-cli --no-default-features --features sqlite,rustls
rm -f /tmp/sqlx-prepare.db
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" sqlx database create
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" \
    sqlx migrate run --source crates/nyx-agent-core/migrations
cd crates/nyx-agent-core
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" cargo sqlx prepare
```

Commit the resulting `crates/nyx-agent-core/.sqlx/` changes. CI fails if
the cache is stale.

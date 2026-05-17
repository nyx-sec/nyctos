<!-- nyx: verbatim -->
# Nyx Pro

Nyx Pro is a self-hosted security analysis daemon that wraps the `nyx`
scanner with an AI-driven exploit-synthesis layer and a full-environment
sandbox. It runs continuously across your repositories, validates
findings inside an isolated dev environment, and emits reproducible
evidence for every exploitable finding.

The shipping binary is `nyx-agent`.
<!-- /nyx: verbatim -->

## Licensing

Nyx Pro is **source-available** software, distributed under the PolyForm
Small Business License 1.0.0. The PolyForm license is not OSI-approved,
so Nyx Pro is not OSS. Do not describe it as such in public
communication.

- Free for personal use, research, hobby projects, OSS contribution, and
  any organisation that qualifies as a Small Business under the license
  (fewer than 100 staff and less than $1,000,000 USD annual revenue).
- A commercial license is required for organisations above that
  threshold. See `LICENSE.md` for the verbatim license text and contact
  details.

The upstream `nyx` core scanner is a separate project under
GPL-3.0-or-later. That GPL-licensed scanner is the OSS component of the
stack; the `nyx-agent` daemon in this repository is not.

## Status

Early scaffolding. See `.pitboss/play/plan.md` for the phased delivery
plan; this commit lands Phase 01 (cargo workspace + CI guards).

## Working with the SQLite store

`nyx-agent-core` uses SQLx's compile-time-checked query macros against a
SQLite schema shipped under `crates/nyx-agent-core/migrations/`. Recorded
query plans live in `.sqlx/` at the workspace root and are checked into
version control so the workspace builds without a database present (CI
runs with `SQLX_OFFLINE=true`).

If you add, remove, or modify a `sqlx::query!` / `sqlx::query_as!` call,
regenerate the cache:

```
cargo install sqlx-cli --no-default-features --features sqlite,rustls
rm -f /tmp/sqlx-prepare.db
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" sqlx database create
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" \
    sqlx migrate run --source crates/nyx-agent-core/migrations
DATABASE_URL="sqlite:///tmp/sqlx-prepare.db?mode=rwc" \
    cargo sqlx prepare --workspace
```

Commit the resulting `.sqlx/` changes. CI fails if the cache is stale.

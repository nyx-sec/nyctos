#!/usr/bin/env bash
# missing-instrument.sh: warn-level lint for public functions that
# forgot `#[tracing::instrument]`.
#
# Rust has no native clippy lint that ties an attribute requirement to a
# visibility modifier. Phase 02 expresses the rule as a CI lint instead;
# Phase 29 promotes it to a hard error (dylint-driven) once every public
# function in the workspace is either instrumented or explicitly
# exempted via `// nyx: no-instrument`.
#
# Implementation lives in the `xtask` crate as a syn-based AST walker:
# it parses each `crates/**/*.rs` file, walks free functions and
# inherent-impl methods, and warns on `Visibility::Public` items
# lacking `#[tracing::instrument]`. The previous awk script over-fired
# on multi-line signatures and could not see `pub(crate)` distinctly;
# the syn walker handles both.
#
# Exit code is always 0; the rule warns, does not fail.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build quietly so a clean tree gets one fast invocation. Pass-through
# the warnings on stderr verbatim. `cargo run` is used (rather than a
# pre-built binary) so the lint stays consistent with whatever code is
# checked out.
cargo run -p xtask --quiet -- lint-instrument

# Always succeed: this is Phase 02 warn-only behaviour. Phase 29 will
# replace this trailing exit with `cargo run -p xtask -- lint-instrument
# --deny`.
exit 0

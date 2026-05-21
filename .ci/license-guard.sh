#!/usr/bin/env bash
# License-string guard. Nyctos must not be described as "open source" or
# "open-source" anywhere outside the LICENSE / PolyForm / CHANGELOG
# surfaces. ripgrep returns non-zero (no matches) on a clean tree; we
# invert the exit code so CI fails on a hit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if rg \
    "open[ -]source" \
    --type rust \
    --type md \
    --type ts \
    --glob '!**/LICENSE*' \
    --glob '!**/PolyForm*' \
    --glob '!**/CHANGELOG.md'
then
    echo "license-guard: forbidden \"open source\" phrasing found above." >&2
    exit 1
fi
exit 0

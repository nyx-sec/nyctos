#!/usr/bin/env bash
# License-string guard. Nyctos is AGPLv3-or-later now; fail if old
# source-available / PolyForm positioning sneaks back into operator
# docs or product surfaces. ripgrep returns non-zero (no matches) on a
# clean tree; we invert the exit code so CI fails on a hit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if rg \
    'PolyForm Small Business|source-available|source available|fair-source|public-source|100 employees|\$1M annual revenue' \
    --type rust \
    --type md \
    --type ts \
    --glob '!**/CHANGELOG.md'
then
    echo "license-guard: old Nyctos licensing posture found above." >&2
    exit 1
fi
exit 0

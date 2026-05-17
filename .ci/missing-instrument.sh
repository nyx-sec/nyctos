#!/usr/bin/env bash
# missing-instrument.sh: warn-level lint for public functions that
# forgot `#[tracing::instrument]`.
#
# Rust has no native clippy lint that ties an attribute requirement to a
# visibility modifier. Phase 02 expresses the rule as a CI grep instead;
# Phase 29 promotes it to a hard error (dylint-driven) once every public
# function in the workspace is either instrumented or explicitly
# exempted via `// nyx: no-instrument`.
#
# Exit code is always 0 in Phase 02; the rule warns, does not fail.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Collect Rust sources under crates/, preferring git's view so renamed
# but tracked files stay in scope.
FILES=()
while IFS= read -r line; do
    FILES+=("$line")
done < <(git ls-files 'crates/*.rs' 'crates/**/*.rs' 2>/dev/null \
            || find crates -name '*.rs' -type f)

if [[ ${#FILES[@]} -eq 0 ]]; then
    exit 0
fi

for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || continue
    # Skip the lint helper itself and obvious entry points.
    case "$f" in
        */main.rs|*/build.rs|*/tests/*) continue ;;
    esac

    # Look at each line that begins with `pub fn` / `pub async fn` / `pub const fn`,
    # ignoring trait impls (covered by trait signature) and macros.
    awk -v file="$f" '
        function flush(   line, n, i) {
            n = length(prev)
            for (i = 1; i <= n; i++) prev[i] = ""
        }
        /^[[:space:]]*\/\/[[:space:]]*nyx:[[:space:]]*no-instrument/ { exempt = 1; next }
        /^[[:space:]]*#\[tracing::instrument/ { instrumented = 1; next }
        /^[[:space:]]*pub[[:space:]]+(async[[:space:]]+|const[[:space:]]+)?fn[[:space:]]/ {
            if (!instrumented && !exempt) {
                printf("warning: %s:%d: pub fn missing #[tracing::instrument]\n",
                       file, NR) > "/dev/stderr"
                warns++
            }
            instrumented = 0; exempt = 0; next
        }
        /^[[:space:]]*$/ { instrumented = 0; exempt = 0; next }
        END { exit (warns > 0 ? 0 : 0) }
    ' "$f" || true
done

exit 0

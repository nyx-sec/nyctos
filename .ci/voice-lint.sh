#!/usr/bin/env bash
# Voice-lint guard for nyctos. Scans human-authored sources (`.rs`,
# `.md`, `.ts`, `.tsx`, `.txt`) for em-dashes, en-dashes, and any phrase
# listed in `.ci/banned-phrases.txt`. A `<!-- nyx: verbatim -->` ...
# `<!-- /nyx: verbatim -->` block exempts its enclosed lines.
#
# Exit code: 0 if clean, 1 if any violation was found.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BANNED_FILE="$SCRIPT_DIR/banned-phrases.txt"

if [ ! -f "$BANNED_FILE" ]; then
    echo "voice-lint: missing $BANNED_FILE" >&2
    exit 2
fi

cd "$REPO_ROOT"

found=0

strip_verbatim() {
    awk '
        /<!-- nyx: verbatim -->/ { skip=1; next }
        /<!-- \/nyx: verbatim -->/ { skip=0; next }
        !skip { print }
    ' "$1"
}

scan_file() {
    file="$1"
    stripped="$(strip_verbatim "$file")"

    if printf '%s' "$stripped" | grep -nF -- '—' >/dev/null 2>&1; then
        line="$(printf '%s' "$stripped" | grep -nF -- '—' | head -1)"
        echo "voice-lint: em-dash in $file: $line" >&2
        found=1
    fi
    if printf '%s' "$stripped" | grep -nF -- '–' >/dev/null 2>&1; then
        line="$(printf '%s' "$stripped" | grep -nF -- '–' | head -1)"
        echo "voice-lint: en-dash in $file: $line" >&2
        found=1
    fi

    while IFS= read -r phrase; do
        [ -z "$phrase" ] && continue
        case "$phrase" in '#'*) continue;; esac
        # Lines prefixed with `regex:` are treated as extended regex
        # patterns (case-insensitive) so phrases like "leverage" can be
        # restricted to verb usage without flagging the noun form
        # ("leverage point"). Plain lines stay literal substring greps.
        case "$phrase" in
            'regex:'*)
                pattern="${phrase#regex:}"
                if printf '%s' "$stripped" | grep -niE -- "$pattern" >/dev/null 2>&1; then
                    line="$(printf '%s' "$stripped" | grep -niE -- "$pattern" | head -1)"
                    echo "voice-lint: banned pattern \"$pattern\" in $file: $line" >&2
                    found=1
                fi
                ;;
            *)
                if printf '%s' "$stripped" | grep -niF -- "$phrase" >/dev/null 2>&1; then
                    line="$(printf '%s' "$stripped" | grep -niF -- "$phrase" | head -1)"
                    echo "voice-lint: banned phrase \"$phrase\" in $file: $line" >&2
                    found=1
                fi
                ;;
        esac
    done < "$BANNED_FILE"
}

# Candidate files: source files outside vendored / generated / pitboss
# directories. The generated TS bindings file, LICENSE / CHANGELOG
# files, and the banned-phrases list itself are skipped (they would
# otherwise self-match).
while IFS= read -r file; do
    [ -z "$file" ] && continue
    scan_file "$file"
done < <(find . \
        -type f \
        \( -name '*.rs' -o -name '*.md' -o -name '*.ts' -o -name '*.tsx' -o -name '*.txt' \) \
        -not -path './target/*' \
        -not -path './.git/*' \
        -not -path './.pitboss/*' \
        -not -path './.idea/*' \
        -not -path './node_modules/*' \
        -not -path './frontend/node_modules/*' \
        -not -path './frontend/src/api/types.gen.ts' \
        -not -name 'LICENSE*' \
        -not -name 'CHANGELOG.md' \
        -not -name 'banned-phrases.txt' \
        | sort)

exit "$found"

#!/usr/bin/env bash
# AEC-1 read-only boundary check — thin wrapper around check_aec_readonly.py.
#
# Read-only by construction: verifies pinned sha256s and classifies changed
# paths against the read-only contract. It never stages, commits, pushes,
# checks out, resets or cleans anything, and it writes nothing unless you pass
# --generate (which rewrites aec/readonly_manifest.json on purpose).
#
# Usage:
#   scripts/check-aec-readonly.sh              # verify the current worktree
#   scripts/check-aec-readonly.sh --json       # machine-readable
#   scripts/check-aec-readonly.sh --generate   # re-pin the manifest (S1 only)
#
# Exit codes: 0 clean · 1 violation · 2 usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECKER="$SCRIPT_DIR/check_aec_readonly.py"

python_bin() {
    if [[ -n "${WATCH_PYTHON:-}" && -x "${WATCH_PYTHON}" ]]; then
        printf '%s' "$WATCH_PYTHON"
        return 0
    fi
    local candidate
    for candidate in \
        "$REPO_ROOT/venv/bin/python3" \
        "/opt/watch/venv/bin/python3" \
        "$(command -v python3 2>/dev/null || true)"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

if [[ ! -f "$CHECKER" ]]; then
    echo "check-aec-readonly.sh: missing $CHECKER" >&2
    exit 2
fi

PYTHON="$(python_bin)" || {
    echo "check-aec-readonly.sh: no python3 interpreter found (set WATCH_PYTHON)" >&2
    exit 2
}

if [[ "${NO_COLOR:-}" == "" ]]; then
    : # the checker prints plain text; colour is intentionally not added here
fi

exec "$PYTHON" "$CHECKER" --root "$REPO_ROOT" "$@"

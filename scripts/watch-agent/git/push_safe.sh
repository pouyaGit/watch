#!/usr/bin/env bash
#
# git/push_safe.sh — authenticated push wrapper (Epic 0.2).
#
# Credentialless Git Operations v1: run the auth readiness check before every
# push and refuse force/bypass flags unconditionally.
#
# Usage:
#   scripts/watch-agent/git/push_safe.sh [--repo DIR] [--dry-run] <remote> <branch>
#
# Behavior:
#   - rejects any dash-leading argument except --dry-run/--repo (this rules
#     out --force, --force-with-lease, --no-verify and -f by construction)
#   - runs check_auth.py for the target repo; BLOCKED aborts the push
#   - otherwise runs: git push [--dry-run] <remote> <branch>
#   - never changes git configuration (no `git config` invocation exists here)
#
# Environment overrides:
#   GIT_AUTH_SSH / GIT_AUTH_GH  probed binaries (default: ssh / gh)
set -u

GIT_BIN_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECK_AUTH="$GIT_BIN_DIR/check_auth.py"

REPO=""; DRY_RUN=0; REMOTE=""; BRANCH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)    REPO="${2:-}"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    --force|--force-with-lease|--no-verify|-f)
      printf 'BLOCKED\n  reason: force/bypass flags are never allowed: %s\n' "$1" >&2
      exit 1;;
    --*)
      printf 'BLOCKED\n  reason: unknown flag (only --repo/--dry-run accepted): %s\n' "$1" >&2
      exit 1;;
    -*)
      printf 'BLOCKED\n  reason: dash-leading argument refused: %s\n' "$1" >&2
      exit 1;;
    *)
      if [ -z "$REMOTE" ]; then REMOTE="$1";
      elif [ -z "$BRANCH" ]; then BRANCH="$1";
      else
        printf 'BLOCKED\n  reason: unexpected argument: %s\n' "$1" >&2
        exit 1
      fi
      shift;;
  esac
done

[ -n "$REMOTE" ] && [ -n "$BRANCH" ] || {
  printf 'FAIL: usage: push_safe.sh [--repo DIR] [--dry-run] <remote> <branch>\n' >&2
  exit 2
}

python_bin() {
  local candidate
  for candidate in \
    "${WATCH_PYTHON:-}" \
    "/opt/watch/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON="$(python_bin)" || {
  printf 'BLOCKED\n  reason: no python interpreter for the auth check\n' >&2
  exit 1
}
[ -f "$CHECK_AUTH" ] || {
  printf 'BLOCKED\n  reason: auth checker missing: %s\n' "$CHECK_AUTH" >&2
  exit 1
}

auth_args=()
[ -n "$REPO" ] && auth_args+=(--repo "$REPO")
auth_out="$("$PYTHON" "$CHECK_AUTH" "${auth_args[@]}" 2>&1 || true)"
if ! printf '%s' "$auth_out" | grep -qm1 '^READY'; then
  printf 'BLOCKED\n  reason: git authentication not ready\n'
  printf '%s\n' "$auth_out"
  exit 1
fi

git_cmd=(git)
[ -n "$REPO" ] && git_cmd+=(-C "$REPO")
git_cmd+=(push)
[ "$DRY_RUN" -eq 1 ] && git_cmd+=(--dry-run)
git_cmd+=("$REMOTE" "$BRANCH")

"${git_cmd[@]}"
rc=$?
if [ "$rc" -ne 0 ]; then
  printf 'FAIL: git push exited %s\n' "$rc" >&2
  exit "$rc"
fi
printf 'pushed %s %s\n' "$REMOTE" "$BRANCH"
exit 0

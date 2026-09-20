#!/usr/bin/env bash
#
# _context.sh — shared context detection for the scripts/watch-agent helpers.
#
# This file is SOURCED (not executed) by start.sh, status.sh, review.sh and
# sync.sh. It is read-only: it only resolves paths and inspects Git refs. It
# never pushes, merges, rebases, resets, cleans, deletes files, or modifies
# any checkout.
#
# It answers one question for every helper: is the running helper attached to
# the production checkout or to the autonomous agent worktree?
#
# Sets:
#   WATCH_MODE            PRODUCTION | AGENT | UNKNOWN
#   WATCH_SCRIPT_DIR      directory that contains the running helper
#   WATCH_WORKTREE_ROOT   repository root of the running helper
#   WATCH_PRODUCTION_DIR  production checkout      (WATCH_PROD_DIR)
#   WATCH_AGENT_DIR       agent worktree           (WATCH_AGENT_DIR)
#   WATCH_INVOKED_FROM    directory the command was invoked from (pwd -P)
#
# Environment overrides:
#   WATCH_PROD_DIR        production checkout   (default: /opt/watch)
#   WATCH_AGENT_DIR       agent worktree        (default: <prod>/.worktrees/watch-agent)
#   WATCH_AGENT_BRANCH    agent branch          (default: agent/daily-development)

# Resolve a path to its canonical form when it exists; otherwise echo it as-is.
# Never fails under `set -u` and never creates anything.
_watch_realpath() {
  local path="$1" real
  real="$(cd -- "$path" 2>/dev/null && pwd -P || true)"
  if [ -n "$real" ]; then
    printf '%s' "$real"
  else
    printf '%s' "$path"
  fi
}

if [ -z "${SCRIPT_DIR:-}" ]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi

WATCH_SCRIPT_DIR="$(_watch_realpath "$SCRIPT_DIR")"
WATCH_WORKTREE_ROOT="$(_watch_realpath "$WATCH_SCRIPT_DIR/../..")"
WATCH_PRODUCTION_DIR="$(_watch_realpath "${WATCH_PROD_DIR:-/opt/watch}")"
WATCH_AGENT_DIR="$(_watch_realpath "${WATCH_AGENT_DIR:-$WATCH_PRODUCTION_DIR/.worktrees/watch-agent}")"
WATCH_INVOKED_FROM="$(pwd -P 2>/dev/null || pwd)"

if [ "$WATCH_WORKTREE_ROOT" = "$WATCH_PRODUCTION_DIR" ]; then
  WATCH_MODE="PRODUCTION"
elif [ "$WATCH_WORKTREE_ROOT" = "$WATCH_AGENT_DIR" ]; then
  WATCH_MODE="AGENT"
else
  WATCH_MODE="UNKNOWN"
fi

# Fallback: an unrecognised checkout that is on the agent branch is treated as
# an agent workspace. This keeps copies/clones of the worktree usable.
if [ "$WATCH_MODE" = "UNKNOWN" ] && [ -e "$WATCH_WORKTREE_ROOT/.git" ]; then
  _watch_branch="$(command git -C "$WATCH_WORKTREE_ROOT" branch --show-current 2>/dev/null || true)"
  if [ "$_watch_branch" = "${WATCH_AGENT_BRANCH:-agent/daily-development}" ]; then
    WATCH_MODE="AGENT"
  fi
  unset _watch_branch
fi

watch_mode_is_production() { [ "$WATCH_MODE" = "PRODUCTION" ]; }
watch_mode_is_agent()      { [ "$WATCH_MODE" = "AGENT" ]; }

# Print the canonical operator guidance for the production checkout. Callers
# must have defined the shared colour variables; this function itself adds no
# colour so it is safe to call after the helper has set them up.
watch_print_production_hint() {
  printf '  Production checkout detected.\n'
  printf '  Agent workspace:\n    %s\n' "$WATCH_AGENT_DIR"
  printf '  Suggested command:\n    cd %s\n' "$WATCH_AGENT_DIR"
}

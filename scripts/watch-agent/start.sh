#!/usr/bin/env bash
#
# start.sh — prepare and enter the Watch autonomous development environment.
#
# Visibility/preparation only. This script NEVER pushes, merges, rebases,
# resets, cleans, deletes files, or touches the production checkout.
#
# Usage:
#   scripts/watch-agent/start.sh [--attach]
#
#   --attach   attach to the tmux session when it already exists
#
# Environment overrides:
#   WATCH_PROD_DIR       production checkout      (default: /opt/watch)
#   WATCH_AGENT_BRANCH   expected agent branch    (default: agent/daily-development)
#   WATCH_TMUX_SESSION   tmux session name        (default: watch-agent)
#
# See docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md for the full workflow.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
PRODUCTION_DIR="${WATCH_PROD_DIR:-/opt/watch}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
SESSION_NAME="${WATCH_TMUX_SESSION:-watch-agent}"

ATTACH=0
[ "${1:-}" = "--attach" ] && ATTACH=1

git_() { command git -C "$WORKTREE_ROOT" "$@"; }

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && command -v tput >/dev/null 2>&1 \
   && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"; BLUE="$(tput setaf 4)"
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; BLUE=""
fi

section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }
ok()      { printf '  %sOK%s    %s\n' "$GREEN" "$RESET" "$1"; }
warn()    { printf '  %sWARN%s  %s\n' "$YELLOW" "$RESET" "$1"; }
err()     { printf '  %sERROR%s %s\n' "$RED" "$RESET" "$1" >&2; }
item()    { printf '  %-16s %s\n' "$1" "$2"; }

section "Environment"
item "worktree"      "$WORKTREE_ROOT"
item "production"    "$PRODUCTION_DIR"
item "invoked from"  "$(pwd)"

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  err "not a git checkout/worktree: $WORKTREE_ROOT"
  exit 1
fi
[ -d "$PRODUCTION_DIR" ] || warn "production checkout not found: $PRODUCTION_DIR"

prod_real="$(cd -- "$PRODUCTION_DIR" 2>/dev/null && pwd -P || true)"
if [ -n "$prod_real" ] && [ "$(pwd -P)" = "$prod_real" ]; then
  warn "you are inside the production checkout; run this from $WORKTREE_ROOT"
fi

section "Repository state"
branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"
item "branch" "${branch:-<detached HEAD>}"
item "HEAD"   "${head_sha:-?}  ${head_subject}"

if [ -n "$branch" ] && [ "$branch" != "$AGENT_BRANCH" ]; then
  warn "expected agent branch '$AGENT_BRANCH' (use --attach after checking out the right branch)"
fi

if [ -z "$(git_ status --porcelain)" ]; then
  ok "working tree clean"
else
  warn "working tree has uncommitted changes:"
  git_ status --short | sed 's/^/        /'
fi

section "tmux"
if command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    ok "session '$SESSION_NAME' is running"
    item "attach" "tmux attach -t $SESSION_NAME"
    if [ "$ATTACH" -eq 1 ]; then
      if [ -t 1 ]; then
        printf '\n%sAttaching to tmux session %s...%s\n' "$DIM" "$SESSION_NAME" "$RESET"
        exec tmux attach -t "$SESSION_NAME"
      else
        warn "--attach ignored: stdout is not a terminal"
      fi
    fi
  else
    item "create" "tmux new -s $SESSION_NAME -c $WORKTREE_ROOT"
    item "then"   "scripts/watch-agent/start.sh"
  fi
else
  warn "tmux is not installed"
fi

section "Next steps"
item "status" "scripts/watch-agent/status.sh"
item "review" "scripts/watch-agent/review.sh"
item "sync"   "scripts/watch-agent/sync.sh"
item "docs"   "docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md"

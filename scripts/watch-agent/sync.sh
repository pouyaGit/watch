#!/usr/bin/env bash
#
# sync.sh — safe synchronization helper for the agent worktree.
#
# It only fetches and reports branch relationships. This script NEVER
# merges, rebases, resets, cleans, deletes files, pushes, or touches the
# production checkout.
#
# Usage:
#   scripts/watch-agent/sync.sh
#
# Environment overrides:
#   WATCH_MAIN_BRANCH    integration branch (default: main)
#   WATCH_AGENT_BRANCH   agent branch       (default: agent/daily-development)
#   WATCH_REMOTE         git remote         (default: origin)
#
# See docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md for the full workflow.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
REMOTE="${WATCH_REMOTE:-origin}"

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
item()    { printf '  %-18s %s\n' "$1" "$2"; }

ahead_behind() {
  # ahead_behind <ref> -> "behind N, ahead M"
  local ref="$1" counts behind ahead
  git_ rev-parse --verify --quiet "$ref" >/dev/null 2>&1 || return 0
  counts="$(git_ rev-list --left-right --count "$ref...HEAD" 2>/dev/null || true)"
  [ -n "$counts" ] || return 0
  behind="${counts%%[[:space:]]*}"
  ahead="${counts##*[[:space:]]}"
  printf 'behind %s, ahead %s' "$behind" "$ahead"
}

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  err "not a git checkout/worktree: $WORKTREE_ROOT"
  exit 1
fi

section "Fetch $REMOTE"
if ! command -v git >/dev/null 2>&1; then
  err "git is not installed"
  exit 1
fi
if git_ remote get-url "$REMOTE" >/dev/null 2>&1; then
  if git_ fetch "$REMOTE"; then
    ok "fetched $REMOTE (no local branches changed)"
  else
    err "git fetch $REMOTE failed (network/credentials?) — continuing with local refs"
  fi
else
  warn "remote '$REMOTE' is not configured"
fi

section "Branch relationships"
branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
item "branch" "${branch:-<detached HEAD>}"
item "commit" "${head_sha:-?}"

for ref in "origin/$MAIN_BRANCH" "$MAIN_BRANCH" "$AGENT_BRANCH"; do
  rel="$(ahead_behind "$ref")"
  if [ -n "$rel" ]; then
    item "vs $ref" "$rel"
  else
    warn "unknown ref: $ref"
  fi
done

if git_ rev-parse --verify --quiet "origin/$MAIN_BRANCH" >/dev/null 2>&1; then
  section "Unpushed commits on $branch (vs origin/$MAIN_BRANCH)"
  graph="$(git_ log --oneline --left-right "origin/$MAIN_BRANCH...HEAD" 2>/dev/null | head -20 || true)"
  if [ -n "$graph" ]; then
    printf '%s\n' "$graph" | sed 's/^/  /'
  else
    ok "nothing to push"
  fi
fi

section "Summary"
printf '  %sNo merge, rebase, reset, clean or push was performed.%s\n' "$DIM" "$RESET"
printf '  %sPush is always manual.%s\n' "$DIM" "$RESET"

#!/usr/bin/env bash
#
# status.sh — one-command operational overview for the agent worktree.
#
# Read-only. This script NEVER pushes, merges, rebases, resets, cleans,
# deletes files, or touches the production checkout.
#
# Usage:
#   scripts/watch-agent/status.sh
#
# Environment overrides:
#   WATCH_PROD_DIR       production checkout   (default: /opt/watch)
#   WATCH_AGENT_BRANCH   agent branch          (default: agent/daily-development)
#   WATCH_MAIN_BRANCH    integration branch    (default: main)
#
# See docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md for the full workflow.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
PRODUCTION_DIR="${WATCH_PROD_DIR:-/opt/watch}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REPORT_DIR="$WORKTREE_ROOT/agent-reports"

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
  # ahead_behind <ref> -> "behind N, ahead M" (empty when ref is unknown)
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

branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"
upstream="$(git_ rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"

section "Branch"
item "worktree" "${WORKTREE_ROOT}  ${DIM}(production: ${PRODUCTION_DIR})${RESET}"
item "branch"   "${branch:-<detached HEAD>}"
item "commit"   "${head_sha:-?}  ${head_subject}"
if [ -n "$branch" ] && [ "$branch" != "$AGENT_BRANCH" ]; then
  warn "expected agent branch '$AGENT_BRANCH'"
fi

section "Remote tracking"
if [ -n "$upstream" ]; then
  item "upstream" "$upstream"
  rel="$(ahead_behind "$upstream")"
  [ -n "$rel" ] && item "vs upstream" "$rel"
else
  warn "no upstream configured for '${branch:-HEAD}'"
fi
for ref in "origin/$MAIN_BRANCH" "$MAIN_BRANCH"; do
  rel="$(ahead_behind "$ref")"
  [ -n "$rel" ] && item "vs $ref" "$rel"
done

section "Working tree"
if [ -z "$(git_ status --porcelain)" ]; then
  ok "clean"
else
  warn "uncommitted changes:"
  git_ status --short | sed 's/^/        /'
fi

section "Latest commits"
git_ log --oneline -10 2>/dev/null | sed 's/^/  /'

section "Pending agent reports"
pending="$(git_ status --porcelain -- agent-reports/ 2>/dev/null || true)"
if [ -z "$pending" ]; then
  ok "none pending (all reports committed)"
else
  printf '%s\n' "$pending" | sed 's/^/        /'
fi

section "Recent agent reports"
if [ -d "$REPORT_DIR" ]; then
  ls -1t "$REPORT_DIR"/*.md 2>/dev/null | head -5 | while IFS= read -r f; do
    printf '  %s\n' "$(basename -- "$f")"
  done
else
  warn "no agent-reports/ directory"
fi

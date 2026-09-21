#!/usr/bin/env bash
#
# delivery/status.sh — delivery state overview for the agent workspace.
#
# Autonomous Delivery Pipeline v1 (Epic 0).
#
# Shows: current branch, latest commit, remote status, unpushed commits, merge
# readiness, test status and a changed-files summary.
#
# READ-ONLY. This script performs no fetch, no push, no merge, no rebase, no
# reset, no clean and writes no file. It reads local refs only, so the remote
# view is "as of the last fetch" — run scripts/watch-agent/sync.sh to refresh.
#
# Usage:
#   scripts/watch-agent/delivery/status.sh
#
# Environment overrides:
#   WATCH_PROD_DIR       production checkout   (default: /opt/watch)
#   WATCH_AGENT_DIR      agent worktree        (default: <prod>/.worktrees/watch-agent)
#   WATCH_AGENT_BRANCH   agent branch          (default: agent/daily-development)
#   WATCH_MAIN_BRANCH    integration branch    (default: main)
set -u

# _context.sh resolves the worktree root as <helper dir>/../.., so point
# SCRIPT_DIR at scripts/watch-agent (the parent of this delivery/ directory).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"
DELIVERY_DIR="$WATCH_SCRIPT_DIR/delivery"

WORKTREE_ROOT="$WATCH_WORKTREE_ROOT"
PRODUCTION_DIR="$WATCH_PRODUCTION_DIR"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REMOTE="${WATCH_REMOTE:-origin}"
REPORT_DIR="$WORKTREE_ROOT/agent-reports/delivery"

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
note()    { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }

ahead_behind() {
  # ahead_behind <ref> -> "behind N, ahead M" (empty when the ref is unknown)
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

if watch_mode_is_production; then
  printf '\n  %sDelivery status is an agent-workspace view.%s\n' "$DIM" "$RESET"
  watch_print_production_hint
  exit 0
fi

branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"
upstream="$(git_ rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
base="$(git_ merge-base "$MAIN_BRANCH" HEAD 2>/dev/null || true)"

section "Delivery context"
item "mode"        "$WATCH_MODE"
item "checkout"    "$WORKTREE_ROOT"
item "branch"      "${branch:-<detached HEAD>}"
item "commit"      "${head_sha:-?}  ${head_subject}"
item "policy"      "$(basename -- "$DELIVERY_DIR") v1"

section "Remote status"
if [ -n "$upstream" ]; then
  item "upstream" "$upstream"
  rel="$(ahead_behind "$upstream")"
  if [ -n "$rel" ]; then
    item "vs upstream" "$rel"
  else
    warn "cannot compare with $upstream"
  fi
else
  warn "no upstream configured for '${branch:-HEAD}'"
fi
for ref in "$REMOTE/$AGENT_BRANCH" "$REMOTE/$MAIN_BRANCH" "$MAIN_BRANCH"; do
  rel="$(ahead_behind "$ref")"
  if [ -n "$rel" ]; then
    item "vs $ref" "$rel"
  else
    warn "unknown ref: $ref"
  fi
done
note "no fetch performed: remote view is as of the last fetch"

section "Unpushed commits"
if git_ rev-parse --verify --quiet "$REMOTE/$AGENT_BRANCH" >/dev/null 2>&1; then
  unpushed="$(git_ log --oneline "$REMOTE/$AGENT_BRANCH..HEAD" 2>/dev/null || true)"
  if [ -z "$unpushed" ]; then
    ok "agent branch is fully pushed to $REMOTE/$AGENT_BRANCH"
  else
    printf '%s\n' "$unpushed" | sed 's/^/        /'
    warn "$(printf '%s\n' "$unpushed" | grep -c . ) commit(s) not yet pushed"
  fi
else
  warn "$REMOTE/$AGENT_BRANCH not present locally (never pushed or not fetched)"
fi

section "Changed files summary"
if [ -n "$base" ]; then
  item "base" "${base:0:12} ($MAIN_BRANCH)"
  shortstat="$(git_ diff --shortstat "$base...HEAD" 2>/dev/null || true)"
  if [ -n "$shortstat" ]; then
    item "vs $MAIN_BRANCH" "$shortstat"
  else
    ok "no committed difference from $MAIN_BRANCH"
  fi
  dirty="$(git_ status --porcelain | grep -c . || true)"
  item "uncommitted" "$dirty entr(y/ies)"
  if [ -x "$DELIVERY_DIR/diff_guard.py" ]; then
    note "diff guard is a python module; run check.sh for the path-level verdict"
  fi
else
  warn "no merge base with $MAIN_BRANCH"
fi

section "Merge readiness"
if [ -x "$DELIVERY_DIR/check.sh" ]; then
  if readiness="$(bash "$DELIVERY_DIR/check.sh" --no-tests --quiet 2>&1)"; then
    ok "$readiness"
    note "tests not run in this view; run check.sh (no flag) before promoting"
  else
    err "$readiness"
    note "run check.sh for the full reason list"
  fi
else
  warn "check.sh not found next to status.sh"
fi

section "Test status"
latest="$(ls -1t "$REPORT_DIR"/DELIVERY-REPORT-*.json 2>/dev/null | head -1 || true)"
if [ -n "$latest" ]; then
  tests_state="$(grep -o '"tests_state":"[^"]*"' "$latest" 2>/dev/null | head -1 | sed 's/^"[^"]*"://; s/"//g')"
  tests_summary="$(grep -o '"tests_summary":"[^"]*"' "$latest" 2>/dev/null | head -1 | sed 's/^"[^"]*"://; s/"//g')"
  item "report" "$(basename -- "$latest")"
  item "tests" "${tests_state:-unknown}"
  if [ -n "$tests_summary" ]; then
    item "result" "$tests_summary"
  fi
else
  warn "no delivery report yet — run report.sh to record a test result"
fi

exit 0

#!/usr/bin/env bash
#
# promotion/status.sh — promotion state overview for the agent workspace.
#
# Autonomous Promotion Operator v1 (Epic 0.1).
#
# Shows: current branch, current commit, remote branch state, the pending
# promotion request, the approval state and the last promotion event.
#
# READ-ONLY. No fetch, no push, no merge, no rebase, no reset, no clean, no
# file written. Remote state is read from local refs only ("as of last fetch").
#
# Usage:
#   scripts/watch-agent/promotion/status.sh
#
# Environment overrides:
#   PROMOTION_WORKTREE_ROOT  worktree under inspection (default: this checkout)
#   PROMOTION_OUTPUT_DIR     promotions directory (default: agent-reports/promotions)
#   WATCH_PROD_DIR / WATCH_AGENT_DIR / WATCH_AGENT_BRANCH / WATCH_MAIN_BRANCH
set -u

# _context.sh resolves the worktree root as <helper dir>/../.., so point
# SCRIPT_DIR at scripts/watch-agent (the parent of this promotion/ directory).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"

WORKTREE_ROOT="${PROMOTION_WORKTREE_ROOT:-$WATCH_WORKTREE_ROOT}"
OUTPUT_DIR="${PROMOTION_OUTPUT_DIR:-$WORKTREE_ROOT/agent-reports/promotions}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REMOTE="${WATCH_REMOTE:-origin}"
AUDIT_LOG="$OUTPUT_DIR/AUDIT.log"

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
item()    { printf '  %-18s %s\n' "$1" "$2"; }
note()    { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  printf '  %sERROR%s not a git repository/worktree: %s\n' "$RED" "$RESET" "$WORKTREE_ROOT" >&2
  exit 1
fi

branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_full="$(git_ rev-parse HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"

section "Branch"
item "branch" "$branch"
item "commit" "$head_sha $head_subject"
if [ "$branch" = "$AGENT_BRANCH" ]; then
  item "workspace" "on $AGENT_BRANCH (agent workspace)"
else
  item "workspace" "on $branch (expected $AGENT_BRANCH)"
fi

section "Remote state (as of last fetch)"
if git_ rev-parse --verify --quiet "$REMOTE/$AGENT_BRANCH" >/dev/null 2>&1; then
  counts="$(git_ rev-list --left-right --count "$REMOTE/$AGENT_BRANCH...HEAD" 2>/dev/null || true)"
  behind="${counts%%[[:space:]]*}"; ahead="${counts##*[[:space:]]}"
  item "$AGENT_BRANCH" "behind $behind, ahead $ahead of $REMOTE/$AGENT_BRANCH"
else
  item "$AGENT_BRANCH" "no $REMOTE tracking ref (never pushed or fetched)"
fi
if git_ rev-parse --verify --quiet "$REMOTE/$MAIN_BRANCH" >/dev/null 2>&1; then
  item "$MAIN_BRANCH" "$(git_ rev-parse --short "$REMOTE/$MAIN_BRANCH" 2>/dev/null || true) at $REMOTE/$MAIN_BRANCH"
else
  item "$MAIN_BRANCH" "no $REMOTE tracking ref"
fi
unpushed="$(git_ log --oneline "$MAIN_BRANCH..HEAD" 2>/dev/null | wc -l | tr -d ' ' || true)"
item "unpushed" "$unpushed commit(s) ahead of $MAIN_BRANCH"

section "Pending promotion request"
latest_request=""
if [ -d "$OUTPUT_DIR" ]; then
  latest_request="$(ls -1 "$OUTPUT_DIR"/PROMOTION-REQUEST-*.md 2>/dev/null | grep -v '\.approval\.json' | sort | tail -1 || true)"
fi
if [ -n "$latest_request" ] && [ -f "$latest_request" ]; then
  req_commit="$(grep -m1 '^- Commit: ' "$latest_request" 2>/dev/null | sed 's/^- Commit: //' || true)"
  item "request" "$(basename "$latest_request")"
  item "req commit" "${req_commit:-unknown}"
  if [ -n "$head_full" ] && [ "$req_commit" = "$head_full" ]; then
    item "freshness" "request matches HEAD"
  else
    item "freshness" "STALE — branch moved since the request"
  fi
  if [ -f "$latest_request.approval.json" ]; then
    approver="$(grep -o '"operator": "[^"]*"' "$latest_request.approval.json" 2>/dev/null | head -1 || true)"
    item "approval" "APPROVED ($approver)"
  else
    item "approval" "none — waiting for operator"
  fi
else
  note "no promotion request (run promotion/request.sh)"
fi

section "Approval state"
approved_count=0; pending_count=0
if [ -d "$OUTPUT_DIR" ]; then
  for req in "$OUTPUT_DIR"/PROMOTION-REQUEST-*.md; do
    [ -e "$req" ] || continue
    case "$req" in *.approval.json) continue;; esac
    if [ -f "$req.approval.json" ]; then
      approved_count=$((approved_count + 1))
    else
      pending_count=$((pending_count + 1))
    fi
  done
fi
item "approved" "$approved_count request(s)"
item "pending" "$pending_count request(s)"

section "Last promotion event"
if [ -f "$AUDIT_LOG" ]; then
  last_line="$(tail -1 "$AUDIT_LOG" 2>/dev/null || true)"
  last_event="$(printf '%s' "$last_line" | grep -o '"event": "[^"]*"' | head -1 || true)"
  last_seq="$(printf '%s' "$last_line" | grep -o '"seq": [0-9]*' | head -1 || true)"
  item "audit" "$last_event ($last_seq)"
else
  note "no audit log yet"
fi

exit 0

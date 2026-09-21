#!/usr/bin/env bash
#
# promotion/promote.sh — gated promotion of the agent branch into main.
#
# Autonomous Promotion Operator v1 (Epic 0.1).
#
# This is the ONLY command allowed to merge main, and only after every gate
# passes:
#
#   1. the request exists and carries a Commit
#   2. a matching APPROVED approval record exists (no approval -> BLOCK)
#   3. the agent branch HEAD still equals the approved commit (stale -> BLOCK)
#   4. the Epic 0 delivery check verdict is exactly READY FOR PROMOTION
#   5. the Epic 0 diff guard verdict over the change set is PASS
#   6. the operator passed --yes on this invocation (no automation -> BLOCK)
#
# Then: fetch the agent branch into the main checkout, verify the fetched
# commit equals the approved commit, merge with --no-ff, and push through
# git/push_safe.sh (Epic 0.2 re-checks auth, refuses force flags).
# Any failure before the merge aborts with BLOCK and records
# PROMOTION_BLOCKED in the audit log. Success records PROMOTION_COMPLETED.
#
# --dry-run evaluates every gate and prints WOULD MERGE without writing to any
# git repository or to the audit log.
#
# Never force-pushes, and never resets, cleans, checks out other branches,
# or rebases. Never handles credentials.
#
# Usage:
#   scripts/watch-agent/promotion/promote.sh --request FILE --yes [--dry-run]
#     [--delivery-result FILE] [--main-checkout DIR]
#
# Environment overrides:
#   PROMOTION_WORKTREE_ROOT / PROMOTION_OUTPUT_DIR / PROMOTION_DELIVERY_DIR
#   PROMOTION_MAIN_CHECKOUT / WATCH_AGENT_BRANCH / WATCH_MAIN_BRANCH /
#   WATCH_REMOTE / WATCH_PYTHON
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"

WORKTREE_ROOT="${PROMOTION_WORKTREE_ROOT:-$WATCH_WORKTREE_ROOT}"
OUTPUT_DIR="${PROMOTION_OUTPUT_DIR:-$WORKTREE_ROOT/agent-reports/promotions}"
DELIVERY_DIR="${PROMOTION_DELIVERY_DIR:-$WORKTREE_ROOT/scripts/watch-agent/delivery}"
MAIN_CHECKOUT="${PROMOTION_MAIN_CHECKOUT:-$WATCH_PRODUCTION_DIR}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REMOTE="${WATCH_REMOTE:-origin}"
CHECK_SH="$DELIVERY_DIR/check.sh"
GUARD_PY="$DELIVERY_DIR/diff_guard.py"
PROMOTION_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GIT_OPS_DIR="$(cd -- "$PROMOTION_DIR/../git" && pwd)"
PUSH_SAFE="$GIT_OPS_DIR/push_safe.sh"
AUDIT_PY="$PROMOTION_DIR/audit.py"
AUDIT_LOG="$OUTPUT_DIR/AUDIT.log"

REQUEST=""; YES=0; DRY_RUN=0; DELIVERY_RESULT=""; MAIN_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --request)         REQUEST="${2:-}"; shift 2;;
    --yes)             YES=1; shift;;
    --dry-run)         DRY_RUN=1; shift;;
    --delivery-result) DELIVERY_RESULT="${2:-}"; shift 2;;
    --main-checkout)   MAIN_OVERRIDE="${2:-}"; shift 2;;
    -h|--help)         sed -n '2,/^set -u/p' "${BASH_SOURCE[0]}"; exit 0;;
    *) printf 'FAIL: unknown argument: %s\n' "$1" >&2; exit 2;;
  esac
done
[ -n "$MAIN_OVERRIDE" ] && MAIN_CHECKOUT="$MAIN_OVERRIDE"

git_() { command git -C "$WORKTREE_ROOT" "$@"; }
git_main() { command git -C "$MAIN_CHECKOUT" "$@"; }

python_bin() {
  local candidate
  for candidate in \
    "${WATCH_PYTHON:-}" \
    "$WORKTREE_ROOT/venv/bin/python3" \
    "/opt/watch/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

first_json_value() {
  grep -o "\"$2\": *\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/^"[^"]*": *"//; s/"$//'
}

audit_event() {
  # audit_event <event> <request-base> <commit> <detail> — real runs only
  [ "$DRY_RUN" -eq 0 ] || return 0
  if command -v python3 >/dev/null 2>&1 && [ -f "$AUDIT_PY" ]; then
    python3 "$AUDIT_PY" --log "$AUDIT_LOG" record --event "$1" \
      --request "$2" --commit "$3" --actor "promotion/promote.sh" \
      --detail "$4" >/dev/null 2>&1 || true
  fi
}

block() {
  # block <reason> — print BLOCK, audit it on real runs, exit 1
  printf 'BLOCKED\n  reason: %s\n' "$1"
  if [ "$DRY_RUN" -eq 0 ] && [ -n "${REQUEST_BASE:-}" ]; then
    audit_event "PROMOTION_BLOCKED" "$REQUEST_BASE" "${REQ_COMMIT:-}" "$1"
  fi
  exit 1
}

[ -n "$REQUEST" ] || { printf 'FAIL: --request is required\n' >&2; exit 2; }
[ -f "$REQUEST" ] || block "APPROVAL: request not found: $REQUEST"
REQUEST_BASE="$(basename "$REQUEST")"

REQ_COMMIT="$(grep -m1 '^- Commit: ' "$REQUEST" 2>/dev/null | sed 's/^- Commit: //' || true)"
[ -n "$REQ_COMMIT" ] || block "APPROVAL: request has no Commit line"

APPROVAL="$REQUEST.approval.json"
[ -f "$APPROVAL" ] || block "APPROVAL: no approval record for $REQUEST_BASE (run approve.sh)"
approval_decision="$(grep -o '"decision": *"[^"]*"' "$APPROVAL" 2>/dev/null | head -1 | sed 's/^"decision": *"//; s/"$//')"
[ "$approval_decision" = "APPROVED" ] || block "APPROVAL: decision is not APPROVED ($approval_decision)"
approval_commit="$(grep -o '"commit": *"[^"]*"' "$APPROVAL" 2>/dev/null | head -1 | sed 's/^"commit": *"//; s/"$//')"
[ "$approval_commit" = "$REQ_COMMIT" ] || block "APPROVAL: approval commit mismatch ($approval_commit != $REQ_COMMIT)"

agent_head="$(git_ rev-parse HEAD 2>/dev/null || true)"
[ -n "$agent_head" ] || block "COMMIT: cannot resolve agent branch HEAD"
[ "$agent_head" = "$REQ_COMMIT" ] || block "COMMIT: branch moved since approval (HEAD $agent_head != approved $REQ_COMMIT)"

delivery_json=""
if [ -n "$DELIVERY_RESULT" ]; then
  [ -f "$DELIVERY_RESULT" ] || block "DELIVERY: missing --delivery-result file"
  delivery_json="$(cat "$DELIVERY_RESULT")"
elif [ -x "$CHECK_SH" ]; then
  delivery_json="$("$CHECK_SH" --json 2>/dev/null || true)"
else
  block "DELIVERY: no delivery check available ($CHECK_SH missing)"
fi
delivery_tmp="$(mktemp)"
printf '%s' "$delivery_json" > "$delivery_tmp"
delivery_verdict="$(first_json_value "$delivery_tmp" verdict)"
rm -f "$delivery_tmp"
[ "$delivery_verdict" = "READY FOR PROMOTION" ] || block "DELIVERY: verdict is not READY FOR PROMOTION ($delivery_verdict)"

PYTHON="$(python_bin)" || block "DELIVERY: no python interpreter for the diff guard"
[ -f "$GUARD_PY" ] || block "DELIVERY: diff guard missing ($GUARD_PY)"
base="$(git_ merge-base "$MAIN_BRANCH" "$agent_head" 2>/dev/null \
  || git_ merge-base "$REMOTE/$MAIN_BRANCH" "$agent_head" 2>/dev/null || true)"
[ -n "$base" ] || block "DELIVERY: cannot resolve merge-base with $MAIN_BRANCH"
guard_out="$("$PYTHON" "$GUARD_PY" \
  --name-status <(git_ diff --name-status "$base...$agent_head") \
  --diff <(git_ diff "$base...$agent_head") --json 2>/dev/null || true)"
guard_tmp="$(mktemp)"
printf '%s' "$guard_out" > "$guard_tmp"
guard_verdict="$(first_json_value "$guard_tmp" verdict)"
guard_kinds="$(grep -o '"kind": "[A-Z_]*"' "$guard_tmp" 2>/dev/null | sort -u | tr '\n' ' ' || true)"
rm -f "$guard_tmp"
[ "$guard_verdict" = "PASS" ] || block "FORBIDDEN: diff guard verdict is $guard_verdict ($guard_kinds)"

if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$YES" -eq 1 ]; then
    printf 'WOULD MERGE\n'
    printf '  source: %s @ %s\n' "$AGENT_BRANCH" "$REQ_COMMIT"
    printf '  target: %s in %s\n' "$MAIN_BRANCH" "$MAIN_CHECKOUT"
    printf '  gates: approval, commit, delivery, diff guard all PASS\n'
    exit 0
  fi
  block "CONFIRM: refusing to merge without --yes on this invocation"
fi

[ "$YES" -eq 1 ] || block "CONFIRM: refusing to merge without --yes on this invocation"

[ -e "$MAIN_CHECKOUT/.git" ] || block "MAIN: not a git repository: $MAIN_CHECKOUT"
main_branch_now="$(command git -C "$MAIN_CHECKOUT" branch --show-current 2>/dev/null || true)"
[ "$main_branch_now" = "$MAIN_BRANCH" ] || block "MAIN: checkout is on $main_branch_now, expected $MAIN_BRANCH"

git_main fetch --quiet "$REMOTE" "$AGENT_BRANCH" 2>/dev/null \
  || block "MAIN: cannot fetch $AGENT_BRANCH from $REMOTE"
fetched="$(git_main rev-parse FETCH_HEAD 2>/dev/null || true)"
[ "$fetched" = "$REQ_COMMIT" ] || block "MAIN: fetched $AGENT_BRANCH ($fetched) != approved $REQ_COMMIT"

git_main merge --no-ff -m "Merge branch '$AGENT_BRANCH'" FETCH_HEAD >/dev/null 2>&1 \
  || block "MAIN: merge failed"
merged="$(git_main rev-parse HEAD 2>/dev/null || true)"
# Credentialless push (Epic 0.2): the safe wrapper re-checks auth readiness
# and refuses force/bypass flags. Auth logic lives there, not here.
"$PUSH_SAFE" --repo "$MAIN_CHECKOUT" "$REMOTE" "$MAIN_BRANCH" >/dev/null 2>&1 \
  || block "MAIN: safe push to $REMOTE $MAIN_BRANCH failed"

audit_event "PROMOTION_COMPLETED" "$REQUEST_BASE" "$merged" \
  "merged $AGENT_BRANCH @ $REQ_COMMIT into $MAIN_BRANCH"
printf 'PROMOTION_COMPLETED\n  merged %s @ %s into %s (%s)\n' \
  "$AGENT_BRANCH" "$REQ_COMMIT" "$MAIN_BRANCH" "$merged"
exit 0

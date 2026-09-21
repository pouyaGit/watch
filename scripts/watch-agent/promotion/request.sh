#!/usr/bin/env bash
#
# promotion/request.sh — prepare a promotion request for the agent branch.
#
# Autonomous Promotion Operator v1 (Epic 0.1).
#
# Creates agent-reports/promotions/PROMOTION-REQUEST-YYYYMMDD-HHMM.md recording
# the source branch, commit, changed files, test result, delivery check result
# and a risk summary derived from the Epic 0 diff guard.
#
# Preparation only: No merge. No push. Approval and promotion are separate
# commands (approve.sh, promote.sh). An existing request file is never
# overwritten.
#
# Usage:
#   scripts/watch-agent/promotion/request.sh [--now YYYYMMDD-HHMM]
#     [--epic TEXT] [--delivery-result FILE] [--tests-summary TEXT]
#     [--diff-result FILE]
#
# Overrides exist so tests and operators can pin inputs; by default the script
# runs the Epic 0 delivery check, the promotion operator test suite and the
# diff guard live.
#
# Environment overrides:
#   PROMOTION_WORKTREE_ROOT / PROMOTION_OUTPUT_DIR / PROMOTION_DELIVERY_DIR
#   WATCH_AGENT_BRANCH / WATCH_MAIN_BRANCH / WATCH_PYTHON
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"

WORKTREE_ROOT="${PROMOTION_WORKTREE_ROOT:-$WATCH_WORKTREE_ROOT}"
OUTPUT_DIR="${PROMOTION_OUTPUT_DIR:-$WORKTREE_ROOT/agent-reports/promotions}"
DELIVERY_DIR="${PROMOTION_DELIVERY_DIR:-$WORKTREE_ROOT/scripts/watch-agent/delivery}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REMOTE="${WATCH_REMOTE:-origin}"
CHECK_SH="$DELIVERY_DIR/check.sh"
GUARD_PY="$DELIVERY_DIR/diff_guard.py"
AUDIT_PY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/audit.py"
AUDIT_LOG="$OUTPUT_DIR/AUDIT.log"

NOW="${PROMOTION_NOW:-}"; EPIC="n/a"; DELIVERY_RESULT=""; TESTS_SUMMARY=""; DIFF_RESULT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --now)             NOW="${2:-}"; shift 2;;
    --epic)            EPIC="${2:-}"; shift 2;;
    --delivery-result) DELIVERY_RESULT="${2:-}"; shift 2;;
    --tests-summary)   TESTS_SUMMARY="${2:-}"; shift 2;;
    --diff-result)     DIFF_RESULT="${2:-}"; shift 2;;
    -h|--help)         sed -n '2,/^set -u/p' "${BASH_SOURCE[0]}"; exit 0;;
    *) printf 'FAIL: unknown argument: %s\n' "$1" >&2; exit 2;;
  esac
done

git_() { command git -C "$WORKTREE_ROOT" "$@"; }

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

# first_json_value <file> <key> -> first "key": "value" string (never greedy)
first_json_value() {
  grep -o "\"$2\": *\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/^"[^"]*": *"//; s/"$//'
}

[ -e "$WORKTREE_ROOT/.git" ] || { printf 'FAIL: not a git repository: %s\n' "$WORKTREE_ROOT" >&2; exit 1; }

branch="$(git_ branch --show-current 2>/dev/null || true)"
[ "$branch" = "$AGENT_BRANCH" ] || {
  printf 'FAIL: not on %s (on %s)\n' "$AGENT_BRANCH" "${branch:-unknown}" >&2
  exit 1
}
head_sha="$(git_ rev-parse HEAD 2>/dev/null || true)"
head_short="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"
base="$(git_ merge-base "$MAIN_BRANCH" HEAD 2>/dev/null \
  || git_ merge-base "$REMOTE/$MAIN_BRANCH" HEAD 2>/dev/null || true)"
[ -n "$head_sha" ] && [ -n "$base" ] || { printf 'FAIL: cannot resolve refs\n' >&2; exit 1; }

if [ -z "$NOW" ]; then
  NOW="$(date -u +%Y%m%d-%H%M 2>/dev/null || echo unknown)"
fi
mkdir -p "$OUTPUT_DIR" || { printf 'FAIL: cannot create %s\n' "$OUTPUT_DIR" >&2; exit 1; }
request_file="$OUTPUT_DIR/PROMOTION-REQUEST-$NOW.md"
[ -e "$request_file" ] && {
  printf 'FAIL: request already exists (refusing to overwrite): %s\n' "$request_file" >&2
  exit 1
}

# ---- delivery verdict ------------------------------------------------------
delivery_json=""
if [ -n "$DELIVERY_RESULT" ]; then
  [ -f "$DELIVERY_RESULT" ] || { printf 'FAIL: missing --delivery-result file\n' >&2; exit 1; }
  delivery_json="$(cat "$DELIVERY_RESULT")"
elif [ -x "$CHECK_SH" ]; then
  delivery_json="$("$CHECK_SH" --json 2>/dev/null || true)"
else
  printf 'FAIL: no delivery check available (%s missing)\n' "$CHECK_SH" >&2
  exit 1
fi
delivery_tmp="$(mktemp)"
printf '%s' "$delivery_json" > "$delivery_tmp"
delivery_verdict="$(first_json_value "$delivery_tmp" verdict)"
[ -n "$delivery_verdict" ] || delivery_verdict="UNPARSEABLE"
rm -f "$delivery_tmp"

# ---- test summary ----------------------------------------------------------
if [ -z "$TESTS_SUMMARY" ]; then
  if PYTHON="$(python_bin)"; then
    tests_raw="$(cd "$WORKTREE_ROOT" && "$PYTHON" -m unittest tests.test_promotion_operator 2>&1 | tail -4 || true)"
    # strip timing so repeated runs stay comparable
    TESTS_SUMMARY="$(printf '%s' "$tests_raw" | sed 's/in [0-9][0-9.]*s//')"
  else
    TESTS_SUMMARY="test runner unavailable"
  fi
fi

# ---- risk from the diff guard ----------------------------------------------
guard_verdict=""; guard_kinds=""
if [ -n "$DIFF_RESULT" ]; then
  [ -f "$DIFF_RESULT" ] || { printf 'FAIL: missing --diff-result file\n' >&2; exit 1; }
  guard_verdict="$(first_json_value "$DIFF_RESULT" verdict)"
  guard_kinds="$(grep -o '"kind": "[A-Z_]*"' "$DIFF_RESULT" 2>/dev/null | sort -u | tr '\n' ' ' || true)"
elif PYTHON="$(python_bin)" && [ -f "$GUARD_PY" ]; then
  guard_out="$("$PYTHON" "$GUARD_PY" \
    --name-status <(git_ diff --name-status "$base...HEAD") \
    --diff <(git_ diff "$base...HEAD") --json 2>/dev/null || true)"
  guard_tmp="$(mktemp)"
  printf '%s' "$guard_out" > "$guard_tmp"
  guard_verdict="$(first_json_value "$guard_tmp" verdict)"
  guard_kinds="$(grep -o '"kind": "[A-Z_]*"' "$guard_tmp" 2>/dev/null | sort -u | tr '\n' ' ' || true)"
  rm -f "$guard_tmp"
else
  guard_verdict="GUARD UNAVAILABLE"
fi
risk="HIGH"
if [ "$guard_verdict" = "PASS" ]; then
  if [ -z "$(printf '%s' "$guard_kinds" | tr -d ' ')" ]; then risk="LOW"; else risk="MEDIUM"; fi
fi

changed_files="$(git_ diff --name-status "$base...HEAD" 2>/dev/null || true)"
changed_count="$(printf '%s' "$changed_files" | grep -c . || true)"

{
  printf '# Promotion Request — PROMOTION-REQUEST-%s\n\n' "$NOW"
  printf -- '- Source branch: %s\n' "$AGENT_BRANCH"
  printf -- '- Commit: %s\n' "$head_sha"
  printf -- '- Commit subject: %s\n' "$head_subject"
  printf -- '- Base (%s merge-base): %s\n' "$MAIN_BRANCH" "$base"
  printf -- '- Epic: %s\n' "$EPIC"
  printf -- '- Delivery verdict: %s\n' "$delivery_verdict"
  printf -- '- Tests: %s\n' "$(printf '%s' "$TESTS_SUMMARY" | tr '\n' ' ')"
  printf -- '- Risk: %s (diff guard: %s %s)\n' "$risk" "${guard_verdict:-unknown}" "$guard_kinds"
  printf -- '- Files changed: %s\n' "$changed_count"
  printf '\n## Changed files\n\n'
  printf '%s\n' "$changed_files"
  printf '\n## Notes\n\n'
  printf 'No merge. No push. This request prepares promotion only.\n'
  printf 'Promotion requires: operator approval (approve.sh), a fresh delivery\n'
  printf 'check, and promote.sh --yes. The request is stale once the branch\n'
  printf 'moves past the commit recorded above.\n'
} > "$request_file"

if PYTHON_AUDIT="$(python_bin)" && [ -f "$AUDIT_PY" ]; then
  "$PYTHON_AUDIT" --log "$AUDIT_LOG" record --event PROMOTION_REQUESTED \
    --request "$(basename "$request_file")" --commit "$head_sha" \
    --actor "promotion/request.sh" --now "$NOW" >/dev/null 2>&1 || true
fi

printf 'created %s\n' "$request_file"
exit 0

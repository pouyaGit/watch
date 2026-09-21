#!/usr/bin/env bash
#
# delivery/report.sh — machine-readable delivery report for the agent workspace.
#
# Autonomous Delivery Pipeline v1 (Epic 0).
#
# Writes two artifacts under agent-reports/delivery/:
#   DELIVERY-REPORT-<date>.md     human report (Commit / Files changed / Tests /
#                                 Risk / Recommendation + Telegram block)
#   DELIVERY-REPORT-<date>.json   the same facts, machine readable
# and refreshes production-baseline.json (the reference the PRODUCTION_UNTOUCHED
# check compares against).
#
# It never pushes, merges, rebases, resets or deploys, and it writes nothing
# outside agent-reports/delivery/. The promotion itself stays manual.
#
# Usage:
#   scripts/watch-agent/delivery/report.sh [--date YYYY-MM-DD] [--base REF]
#                                          [--tests "mod1 mod2"] [--no-tests]
#                                          [--stdout] [--telegram]
#
# Environment overrides: WATCH_PROD_DIR, WATCH_AGENT_DIR, WATCH_AGENT_BRANCH,
#                        WATCH_MAIN_BRANCH, WATCH_PYTHON
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"
DELIVERY_DIR="$WATCH_SCRIPT_DIR/delivery"

WORKTREE_ROOT="$WATCH_WORKTREE_ROOT"
PRODUCTION_DIR="$WATCH_PRODUCTION_DIR"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
REPORT_DIR="$WORKTREE_ROOT/agent-reports/delivery"
BASELINE_FILE="$REPORT_DIR/production-baseline.json"
DEFAULT_TESTS="tests.test_delivery_policy tests.test_delivery_guard"

REPORT_DATE="$(date -u +%Y-%m-%d)"
BASE_OVERRIDE=""
TEST_MODULES="$DEFAULT_TESTS"
RUN_TESTS=1
TO_STDOUT=0
TELEGRAM_ONLY=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --date)     shift; REPORT_DATE="${1:-$REPORT_DATE}" ;;
    --base)     shift; BASE_OVERRIDE="${1:-}" ;;
    --tests)    shift; TEST_MODULES="${1:-}" ;;
    --no-tests) RUN_TESTS=0 ;;
    --stdout)   TO_STDOUT=1 ;;
    --telegram) TELEGRAM_ONLY=1 ;;
    -h|--help)  sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'report.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

git_() { command git -C "$WORKTREE_ROOT" "$@"; }
git_prod() { command git -C "$PRODUCTION_DIR" "$@"; }

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  printf 'report.sh: not a git checkout/worktree: %s\n' "$WORKTREE_ROOT" >&2
  exit 1
fi

branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
head_full="$(git_ rev-parse HEAD 2>/dev/null || true)"
head_subject="$(git_ log -1 --pretty=%s 2>/dev/null || true)"
head_author="$(git_ log -1 --pretty='%an <%ae>' 2>/dev/null || true)"
head_date="$(git_ log -1 --pretty=%cI 2>/dev/null || true)"
if [ -n "$BASE_OVERRIDE" ]; then
  base="$BASE_OVERRIDE"
else
  base="$(git_ merge-base "$MAIN_BRANCH" HEAD 2>/dev/null || true)"
fi

python_bin() {
  if [ -n "${WATCH_PYTHON:-}" ] && [ -x "${WATCH_PYTHON}" ]; then
    printf '%s' "$WATCH_PYTHON"; return 0
  fi
  if [ -x "$PRODUCTION_DIR/venv/bin/python3" ]; then
    printf '%s' "$PRODUCTION_DIR/venv/bin/python3"; return 0
  fi
  if [ -x "$WORKTREE_ROOT/venv/bin/python3" ]; then
    printf '%s' "$WORKTREE_ROOT/venv/bin/python3"; return 0
  fi
  command -v python3 2>/dev/null || true
}
PYTHON="$(python_bin)"

# ---- facts from check.sh (single source of truth for the verdict) --------
check_args=(--json)
[ "$RUN_TESTS" -eq 0 ] && check_args+=(--no-tests)
[ -n "$BASE_OVERRIDE" ] && check_args+=(--base "$BASE_OVERRIDE")
[ -n "$TEST_MODULES" ] && check_args+=(--tests "$TEST_MODULES")

check_json="$(bash "$DELIVERY_DIR/check.sh" "${check_args[@]}" 2>/dev/null || true)"
field() {
  # field <key> -> scalar value from the single-line check.sh JSON payload
  printf '%s' "$check_json" \
    | grep -o "\"$1\":\"[^\"]*\"\|\"$1\":[0-9]*" \
    | head -1 \
    | sed 's/^"[^"]*"://; s/^"//; s/"$//'
}

verdict="$(field verdict)"
checks_raw="$(printf '%s' "$check_json" | sed 's/.*"checks"://; s/,"verdict".*//')"
commits_ahead="$(field commits_ahead)"
tests_state="$(field tests_state)"
tests_summary="$(printf '%s' "$check_json" | sed 's/.*"tests_summary":"//; s/","dirty.*//')"
dirty_epic="$(field dirty_epic)"
dirty_other="$(field dirty_other)"
production_head="$(field production_head)"
production_dirty="$(field production_dirty)"

# ---- files changed + risk ------------------------------------------------
files_total=0
files_list=""
guard_verdict="unknown"
guard_kinds=""
guard_findings=0
if [ -n "$base" ]; then
  files_total="$(git_ diff --name-only "$base...HEAD" 2>/dev/null | grep -c . || true)"
  files_list="$(git_ diff --name-status "$base...HEAD" 2>/dev/null | sed 's/\t/  /' | head -60 || true)"
  guard_json="$(git_ diff --name-status "$base...HEAD" 2>/dev/null \
    | "$PYTHON" "$DELIVERY_DIR/diff_guard.py" --json 2>/dev/null || true)"
  if [ -n "$guard_json" ]; then
    guard_verdict="$(printf '%s' "$guard_json" | grep -m1 '"verdict"' | sed 's/.*: *"//; s/".*//')"
    guard_kinds="$(printf '%s' "$guard_json" | grep -o '"kind": "[A-Z_]*"' | sed 's/.*"\([A-Z_]*\)"$/\1/' | sort -u | tr '\n' ',' | sed 's/,$//')"
    guard_findings="$(printf '%s' "$guard_json" | grep -c '"kind"' || true)"
  fi
fi

policy_fingerprint=""
if [ -n "$PYTHON" ] && [ -f "$DELIVERY_DIR/policy.py" ]; then
  policy_fingerprint="$("$PYTHON" "$DELIVERY_DIR/policy.py" --fingerprint 2>/dev/null | tail -1 || true)"
fi

recommendation="Hold: fix the blocking checks, then re-run report.sh."
case "$verdict" in
  "READY FOR PROMOTION")
    recommendation="Promote manually: review the diff, push the agent branch, open a pull request, merge in the GitHub UI, then update the production checkout. The delivery layer never pushes or merges by itself."
    ;;
  "READY FOR PROMOTION"*)
    recommendation="Promote manually, but note the skipped check(s): $verdict. Re-run check.sh without skipping before the pull request."
    ;;
  *)
    recommendation="Hold. Nothing is promoted while a required check is blocked ($checks_raw)."
    ;;
esac

telegram_block="DELIVERY ${REPORT_DATE}
branch: ${branch:-?} @ ${head_sha:-?}
commit: ${head_subject:-?}
files: ${files_total} changed
tests: ${tests_state:-unknown} $(printf '%s' "$tests_summary" | sed 's/  */ /g' | cut -c1-60)
risk: ${guard_verdict} (${guard_findings} finding(s)${guard_kinds:+, $guard_kinds})
verdict: ${verdict}
next: manual review + pull request"

if [ "$TELEGRAM_ONLY" -eq 1 ]; then
  printf '%s\n' "$telegram_block"
  exit 0
fi

# ---- report body ---------------------------------------------------------
report_md="# Delivery Report — ${REPORT_DATE}

Generated by \`scripts/watch-agent/delivery/report.sh\` (Epic 0, Autonomous Delivery Pipeline v1).
This report prepares a promotion; it performs none.

## Commit

- Branch: \`${branch:-?}\`
- Commit: \`${head_full:-?}\` (\`${head_sha:-?}\`)
- Subject: ${head_subject:-?}
- Author: ${head_author:-?}
- Committed: ${head_date:-?}
- Integration base: \`${base:-?}\` (${MAIN_BRANCH}), ${commits_ahead:-0} commit(s) ahead

## Files changed

- Files in \`${MAIN_BRANCH}...HEAD\`: ${files_total}
- Uncommitted epic files: ${dirty_epic:-0}; unrelated uncommitted entries: ${dirty_other:-0}

\`\`\`
${files_list:-<no committed changes>}
\`\`\`

## Tests

- Modules: ${TEST_MODULES}
- State: ${tests_state:-unknown}
- Result: $(printf '%s' "$tests_summary" | sed 's/  */ /g')

## Risk

- Diff guard verdict: ${guard_verdict}
- Findings: ${guard_findings}${guard_kinds:+ (${guard_kinds})}
- Policy: delivery-policy/v1 \`${policy_fingerprint:-?}\`
- Checks: ${checks_raw}
- Production checkout: ${production_head:-?} with ${production_dirty:-0} dirty entries

## Recommendation

${recommendation}

## Telegram-ready summary

\`\`\`
${telegram_block}
\`\`\`
"

report_json="{\"report_version\":\"delivery-report/v1\",\"date\":\"${REPORT_DATE}\",\"branch\":\"${branch}\",\"commit\":\"${head_full}\",\"commit_short\":\"${head_sha}\",\"commit_subject\":\"$(printf '%s' "$head_subject" | sed 's/"/\\"/g')\",\"base\":\"${base}\",\"commits_ahead\":${commits_ahead:-0},\"files_changed\":${files_total},\"dirty_epic\":${dirty_epic:-0},\"dirty_other\":${dirty_other:-0},\"tests_modules\":\"${TEST_MODULES}\",\"tests_state\":\"${tests_state}\",\"tests_summary\":\"$(printf '%s' "$tests_summary" | sed 's/  */ /g' | sed 's/"/\\"/g')\",\"risk_verdict\":\"${guard_verdict}\",\"risk_findings\":${guard_findings},\"risk_kinds\":\"${guard_kinds}\",\"readiness\":\"${verdict}\",\"checks\":${checks_raw},\"policy_fingerprint\":\"${policy_fingerprint}\",\"production_head\":\"${production_head}\",\"production_dirty\":${production_dirty:-0}}"

baseline_json="{
  \"baseline_version\": \"delivery-baseline/v1\",
  \"recorded_at_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"production_head\": \"${production_head}\",
  \"production_dirty\": ${production_dirty:-0},
  \"recorded_by\": \"scripts/watch-agent/delivery/report.sh\"
}"

if [ "$TO_STDOUT" -eq 1 ]; then
  printf '%s\n' "$report_md"
  printf '\n%s\n' "$report_json"
  exit 0
fi

mkdir -p "$REPORT_DIR"
printf '%s' "$report_md" > "$REPORT_DIR/DELIVERY-REPORT-${REPORT_DATE}.md"
printf '%s\n' "$report_json" > "$REPORT_DIR/DELIVERY-REPORT-${REPORT_DATE}.json"
printf '%s\n' "$baseline_json" > "$BASELINE_FILE"

printf '%s\n' "$report_md"
printf '\n  wrote: %s\n' "$REPORT_DIR/DELIVERY-REPORT-${REPORT_DATE}.md"
printf '  wrote: %s\n' "$REPORT_DIR/DELIVERY-REPORT-${REPORT_DATE}.json"
printf '  wrote: %s\n' "$BASELINE_FILE"
printf '  %sNothing was pushed, merged or deployed.%s\n' "${DIM:-}" "${RESET:-}"

#!/usr/bin/env bash
#
# delivery/check.sh — pre-promotion validation for the agent workspace.
#
# Autonomous Delivery Pipeline v1 (Epic 0).
#
# Runs the six required checks from scripts/watch-agent/delivery/policy.py and
# prints a verdict:
#
#   READY FOR PROMOTION            every required check passed
#   READY FOR PROMOTION (X SKIPPED) a required check was explicitly skipped
#   BLOCKED                        at least one check failed, with reasons
#
# Checks: BRANCH, COMMIT, TESTS, PATH_GUARD, REPORT, PRODUCTION_UNTOUCHED.
#
# READ-ONLY with respect to the repository and to production: no fetch, no
# push, no merge, no rebase, no reset, no clean, no file written, no systemd
# change, no credential access. It reads Git state, runs tests and prints.
#
# Usage:
#   scripts/watch-agent/delivery/check.sh [--no-tests] [--json] [--quiet]
#                                         [--base REF] [--tests "mod1 mod2"]
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

RUN_TESTS=1
AS_JSON=0
QUIET=0
BASE_OVERRIDE=""
TEST_MODULES="$DEFAULT_TESTS"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-tests) RUN_TESTS=0 ;;
    --json)     AS_JSON=1 ;;
    --quiet)    QUIET=1 ;;
    --base)     shift; BASE_OVERRIDE="${1:-}" ;;
    --tests)    shift; TEST_MODULES="${1:-}" ;;
    -h|--help)  sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'check.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

git_() { command git -C "$WORKTREE_ROOT" "$@"; }
git_prod() { command git -C "$PRODUCTION_DIR" "$@"; }

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && command -v tput >/dev/null 2>&1 \
   && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""
fi
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }
pass()    { printf '  %sPASS%s  %s\n' "$GREEN" "$RESET" "$1"; }
blocked() { printf '  %sBLOCK%s %s\n' "$RED" "$RESET" "$1"; }
skipped() { printf '  %sSKIP%s  %s\n' "$YELLOW" "$RESET" "$1"; }
item()    { printf '  %-18s %s\n' "$1" "$2"; }

# --quiet is used by status.sh for the merge-readiness line: one line only.
# --json is a machine mode: JSON on stdout and nothing else.
if [ "$QUIET" -eq 1 ] || [ "$AS_JSON" -eq 1 ]; then
  section() { :; }; pass() { :; }; blocked() { :; }; skipped() { :; }; item() { :; }
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
POLICY_PY="$DELIVERY_DIR/policy.py"
GUARD_PY="$DELIVERY_DIR/diff_guard.py"

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  printf 'BLOCKED\n  reason: not a git checkout/worktree: %s\n' "$WORKTREE_ROOT" >&2
  exit 1
fi

branch="$(git_ branch --show-current 2>/dev/null || true)"
if [ -n "$BASE_OVERRIDE" ]; then
  base="$BASE_OVERRIDE"
else
  base="$(git_ merge-base "$MAIN_BRANCH" HEAD 2>/dev/null || true)"
fi

BRANCH_STATE="BLOCK"; BRANCH_REASON="not on the agent branch"
COMMIT_STATE="BLOCK"; COMMIT_REASON="no commit between $MAIN_BRANCH and HEAD"
TESTS_STATE="SKIPPED"; TESTS_REASON="--no-tests"
PATH_STATE="BLOCK"; PATH_REASON="diff guard did not run"
REPORT_STATE="BLOCK"; REPORT_REASON="no agent report in the change set"
PROD_STATE="SKIPPED"; PROD_REASON="production baseline not recorded"

changed_files=0
dirty_epic=0
dirty_other=0
tests_summary=""
tests_ran=0
guard_summary=""
guard_findings="0"
prod_head=""
prod_dirty=""

section "Delivery checks"
item "workspace" "$WORKTREE_ROOT"
item "branch" "${branch:-<detached HEAD>}"
item "base" "${base:-<none>}"

# ---- BRANCH -------------------------------------------------------------
if [ "$branch" = "$AGENT_BRANCH" ] && [ "$branch" != "$MAIN_BRANCH" ]; then
  BRANCH_STATE="PASS"; BRANCH_REASON="on $AGENT_BRANCH"
fi

dirty_epic="$(git_ status --porcelain -- \
  scripts/watch-agent/delivery tests/test_delivery_policy.py \
  tests/test_delivery_guard.py agent-reports/autonomous-delivery-pipeline-v1.md \
  2>/dev/null | grep -c . || true)"
dirty_other="$(git_ status --porcelain 2>/dev/null | grep -c . || true)"
dirty_other=$(( dirty_other - dirty_epic ))

if [ "$BRANCH_STATE" = "PASS" ] && [ "$dirty_epic" -gt 0 ]; then
  BRANCH_STATE="BLOCK"
  BRANCH_REASON="$dirty_epic uncommitted delivery file(s) — commit before promoting"
fi
pass_or_block() { # pass_or_block <state> <message>
  case "$1" in
    PASS)    pass "$2" ;;
    SKIPPED) skipped "$2" ;;
    *)       blocked "$2" ;;
  esac
}
pass_or_block "$BRANCH_STATE" "BRANCH      $BRANCH_REASON"
if [ "$dirty_other" -gt 0 ] && [ "$QUIET" -eq 0 ] && [ "$AS_JSON" -eq 0 ]; then
  printf '        %sWARN: %s unrelated uncommitted entr(y/ies) stay behind (not promoted)%s\n' \
    "$YELLOW" "$dirty_other" "$RESET"
fi

# ---- COMMIT -------------------------------------------------------------
if [ -n "$base" ]; then
  changed_files="$(git_ rev-list --count "$base..HEAD" 2>/dev/null || echo 0)"
  if [ "${changed_files:-0}" -ge 1 ]; then
    COMMIT_STATE="PASS"; COMMIT_REASON="$changed_files commit(s) ahead of $MAIN_BRANCH"
  fi
fi
pass_or_block "$COMMIT_STATE" "COMMIT      $COMMIT_REASON"

# ---- TESTS --------------------------------------------------------------
if [ "$RUN_TESTS" -eq 1 ]; then
  if [ -z "$PYTHON" ]; then
    TESTS_STATE="BLOCK"; TESTS_REASON="no python interpreter found"
  else
    tests_summary="$( cd "$WORKTREE_ROOT" && PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m unittest $TEST_MODULES 2>&1 | tail -3 | tr '\n' ' ' || true )"
    tests_ran=1
    case "$tests_summary" in
      *"OK"*) TESTS_STATE="PASS"; TESTS_REASON="$(printf '%s' "$tests_summary" | sed 's/  */ /g')" ;;
      *)      TESTS_STATE="BLOCK"; TESTS_REASON="$(printf '%s' "$tests_summary" | sed 's/  */ /g')" ;;
    esac
  fi
fi
pass_or_block "$TESTS_STATE" "TESTS       $TESTS_REASON"

# ---- PATH_GUARD ---------------------------------------------------------
if [ -n "$base" ] && [ -x "$PYTHON" ] && [ -f "$GUARD_PY" ]; then
  guard_json="$("$PYTHON" "$GUARD_PY" --name-status <(git_ diff --name-status "$base...HEAD") \
    --diff <(git_ diff "$base...HEAD") --json 2>/dev/null || true)"
  if [ -n "$guard_json" ]; then
    guard_verdict="$(printf '%s' "$guard_json" | grep -m1 '"verdict"' | sed 's/.*: *"//; s/".*//')"
    guard_findings="$(printf '%s' "$guard_json" | grep -c '"kind"' || true)"
    guard_kinds="$(printf '%s' "$guard_json" | grep -o '"kind": "[A-Z_]*"' | sed 's/.*"\([A-Z_]*\)"$/\1/' | sort -u | tr '\n' ',' | sed 's/,$//')"
    if [ "$guard_verdict" = "PASS" ]; then
      PATH_STATE="PASS"
      PATH_REASON="no forbidden path, secret, environment or system file in $changed_files commit(s)"
      [ "$guard_findings" -gt 0 ] && PATH_REASON="$PATH_REASON (warnings: $guard_kinds)"
    else
      PATH_STATE="BLOCK"
      PATH_REASON="diff guard found $guard_findings blocking/warning finding(s): $guard_kinds"
    fi
  else
    PATH_STATE="BLOCK"; PATH_REASON="diff guard produced no output"
  fi
fi
pass_or_block "$PATH_STATE" "PATH_GUARD  $PATH_REASON"

# ---- REPORT -------------------------------------------------------------
if [ -n "$base" ]; then
  report_hit="$(git_ diff --name-only "$base...HEAD" -- agent-reports/ 2>/dev/null | head -1 || true)"
  if [ -n "$report_hit" ]; then
    REPORT_STATE="PASS"; REPORT_REASON="report included: $report_hit"
  fi
fi
pass_or_block "$REPORT_STATE" "REPORT      $REPORT_REASON"

# ---- PRODUCTION_UNTOUCHED ----------------------------------------------
if [ -d "$PRODUCTION_DIR" ] && git_prod rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
  prod_head="$(git_prod rev-parse --short HEAD 2>/dev/null || true)"
  prod_dirty="$(git_prod status --porcelain 2>/dev/null | grep -c . || true)"
  if [ -f "$BASELINE_FILE" ]; then
    base_head="$(grep -m1 '"production_head"' "$BASELINE_FILE" 2>/dev/null | sed 's/.*: *"//; s/".*//')"
    base_dirty="$(grep -m1 '"production_dirty"' "$BASELINE_FILE" 2>/dev/null | sed 's/.*: *//; s/[^0-9].*//')"
    if [ "$base_head" = "$prod_head" ] && [ "${base_dirty:-0}" = "$prod_dirty" ]; then
      PROD_STATE="PASS"
      PROD_REASON="production unchanged since baseline ($prod_head, $prod_dirty dirty entries)"
    else
      PROD_STATE="BLOCK"
      PROD_REASON="production moved since baseline: head ${base_head:-?} -> ${prod_head:-?}, dirty ${base_dirty:-?} -> ${prod_dirty:-?}"
    fi
  else
    PROD_STATE="SKIPPED"
    PROD_REASON="no baseline recorded yet (run report.sh); production is $prod_head with $prod_dirty dirty entries"
  fi
fi
pass_or_block "$PROD_STATE" "PRODUCTION  $PROD_REASON"

# ---- Verdict ------------------------------------------------------------
checks_json="$(printf '{"BRANCH":"%s","COMMIT":"%s","TESTS":"%s","PATH_GUARD":"%s","REPORT":"%s","PRODUCTION_UNTOUCHED":"%s"}' \
  "$BRANCH_STATE" "$COMMIT_STATE" "$TESTS_STATE" "$PATH_STATE" "$REPORT_STATE" "$PROD_STATE")"

verdict_json=""
if [ -x "$PYTHON" ] && [ -f "$POLICY_PY" ]; then
  verdict_json="$(printf '{"checks":%s}' "$checks_json" | "$PYTHON" "$POLICY_PY" --verdict 2>/dev/null || true)"
fi

verdict="BLOCKED"
blocking=""
if [ -n "$verdict_json" ]; then
  verdict="$(printf '%s' "$verdict_json" | grep -m1 '"verdict"' | sed 's/.*: *"//; s/".*//')"
  blocking="$(printf '%s' "$verdict_json" | grep -o '"[A-Z_]*:[A-Z_]*"' | tr -d '"' | sort -u | tr '\n' ' ')"
else
  blocking="POLICY_UNAVAILABLE"
fi

if [ "$AS_JSON" -eq 1 ]; then
  printf '{"checks":%s,"verdict":"%s","blocking":"%s","branch":"%s","base":"%s","commits_ahead":%s,"tests_state":"%s","tests_summary":"%s","dirty_epic":%s,"dirty_other":%s,"production_head":"%s","production_dirty":"%s"}\n' \
    "$checks_json" "$verdict" "$(printf '%s' "$blocking" | sed 's/ *$//')" "$branch" "$base" \
    "${changed_files:-0}" "$TESTS_STATE" "$(printf '%s' "$TESTS_REASON" | sed 's/  */ /g; s/"/\\"/g')" \
    "$dirty_epic" "$dirty_other" "$prod_head" "$prod_dirty"
else
  section "Verdict"
  if [ "$QUIET" -eq 1 ]; then
    printf '%s\n' "$verdict"
  else
    if printf '%s' "$verdict" | grep -q '^READY FOR PROMOTION'; then
      printf '  %s%s%s\n' "$GREEN$BOLD" "$verdict" "$RESET"
    else
      printf '  %s%s%s\n' "$RED$BOLD" "$verdict" "$RESET"
      printf '  reasons: %s\n' "$(printf '%s' "$blocking" | sed 's/ *$//')"
    fi
    printf '\n  %sThis script prepares promotion only: no push, no merge, no deploy.%s\n' "$DIM" "$RESET"
    printf '  %sOperator next step: review, then push the agent branch and open a PR.%s\n' "$DIM" "$RESET"
  fi
fi

if printf '%s' "$verdict" | grep -q '^READY FOR PROMOTION'; then
  exit 0
fi
exit 1

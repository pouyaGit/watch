#!/usr/bin/env bash
#
# review.sh — pre-merge / pre-push review helper for the agent worktree.
#
# Read-only. This script NEVER pushes, merges, rebases, resets, cleans,
# deletes files, or touches the production checkout. It only reports.
#
# Usage:
#   scripts/watch-agent/review.sh
#
# Environment overrides:
#   WATCH_BASE_BRANCH    review base        (default: origin/main, else main)
#   WATCH_MAIN_BRANCH    integration branch (default: main)
#   WATCH_AGENT_BRANCH   agent branch       (default: agent/daily-development)
#
# See docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md for the full workflow.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MAIN_BRANCH="${WATCH_MAIN_BRANCH:-main}"
AGENT_BRANCH="${WATCH_AGENT_BRANCH:-agent/daily-development}"
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

resolve_base() {
  local candidate
  for candidate in "${WATCH_BASE_BRANCH:-}" "origin/$MAIN_BRANCH" "$MAIN_BRANCH"; do
    [ -n "$candidate" ] || continue
    if git_ rev-parse --verify --quiet "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

report_field() {
  # report_field <report> <FIELD NAME> -> first non-empty value after the label.
  # Matches a line that starts with "LABEL:" (ignoring leading whitespace) and
  # skips markdown headers such as "## 10. READY TO PUSH". Handles both an
  # inline value and a value on the following line.
  local report="$1" label="$2"
  awk -v label="$label" '
    {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^#/) next
      if (index(line, label ":") == 1) {
        val = substr(line, length(label) + 2)
        sub(/^[[:space:]]+/, "", val)
        if (val ~ /[A-Za-z]/) { print val; exit }
        getline nxt
        gsub(/^[[:space:]]+/, "", nxt)
        if (nxt ~ /[A-Za-z]/) { print nxt }
        exit
      }
    }
  ' "$report" 2>/dev/null
}

if [ ! -e "$WORKTREE_ROOT/.git" ]; then
  err "not a git checkout/worktree: $WORKTREE_ROOT"
  exit 1
fi

branch="$(git_ branch --show-current 2>/dev/null || true)"
head_sha="$(git_ rev-parse --short HEAD 2>/dev/null || true)"
base="$(resolve_base || true)"

section "Review context"
item "worktree" "$WORKTREE_ROOT"
item "branch"   "${branch:-<detached HEAD>}"
item "commit"   "${head_sha:-?}"
if [ -n "$base" ]; then
  item "base" "$base"
else
  warn "no base branch found (looked for origin/$MAIN_BRANCH, $MAIN_BRANCH)"
fi

section "Working tree"
if [ -z "$(git_ status --porcelain)" ]; then
  ok "clean"
else
  warn "uncommitted changes (a push should include only committed work):"
  git_ status --short | sed 's/^/        /'
fi

commit_count=0
if [ -n "$base" ]; then
  commit_count="$(git_ rev-list --count "$base"..HEAD 2>/dev/null || echo 0)"
  section "Commits since $base ($commit_count)"
  if [ "$commit_count" -gt 0 ]; then
    git_ log --oneline "$base"..HEAD 2>/dev/null | sed 's/^/  /'
  else
    warn "no commits since $base (already integrated, or base is HEAD)"
  fi

  section "Changed files since $base"
  changed="$(git_ diff --name-status "$base"...HEAD 2>/dev/null || true)"
  if [ -n "$changed" ]; then
    printf '%s\n' "$changed" | sed 's/^/  /'
  else
    warn "no file changes since $base"
  fi

  section "Diff stat since $base"
  git_ diff --stat "$base"...HEAD 2>/dev/null | sed 's/^/  /'

  section "Tests changed since $base"
  tests_changed="$(printf '%s\n' "$changed" | awk '{print $NF}' | grep -Ei '(^|/)(test_|tests/).*\.py$' || true)"
  if [ -n "$tests_changed" ]; then
    printf '%s\n' "$tests_changed" | sed 's/^/  /'
  else
    warn "no test files changed in this range"
  fi

  section "Agent reports changed since $base"
  reports_changed="$(printf '%s\n' "$changed" | awk '{print $NF}' | grep -E '^agent-reports/' || true)"
  if [ -n "$reports_changed" ]; then
    printf '%s\n' "$reports_changed" | sed 's/^/  /'
  else
    warn "no agent reports changed in this range"
  fi
fi

section "Latest agent report"
latest_report=""
if [ -d "$REPORT_DIR" ]; then
  latest_report="$(ls -1t "$REPORT_DIR"/*.md 2>/dev/null | head -1 || true)"
fi
if [ -n "$latest_report" ]; then
  item "file" "$(basename -- "$latest_report")"
  for field in "COMMIT STATUS" "PUSH STATUS" "READY TO PUSH"; do
    value="$(report_field "$latest_report" "$field")"
    [ -n "$value" ] && item "$field" "$value"
  done
else
  warn "no agent report found under agent-reports/"
fi

section "Assessment"
reasons=()
if [ -n "$(git_ status --porcelain)" ]; then
  reasons+=("working tree is dirty")
fi
if [ "$commit_count" -eq 0 ]; then
  reasons+=("no commits since ${base:-<no base>}")
fi
if [ -z "$latest_report" ]; then
  reasons+=("no agent report found")
else
  ready_value="$(report_field "$latest_report" "READY TO PUSH")"
  case "$(printf '%s' "$ready_value" | tr '[:lower:]' '[:upper:]')" in
    YES) : ;;
    *)   reasons+=("latest report says READY TO PUSH: ${ready_value:-<unset>}") ;;
  esac
fi

if [ "${#reasons[@]}" -eq 0 ]; then
  ok "READY TO PUSH: YES (review the diff above, then push manually)"
else
  printf '  %sREADY TO PUSH: NO%s\n' "$YELLOW" "$RESET"
  for reason in "${reasons[@]}"; do
    printf '        - %s\n' "$reason"
  done
fi
printf '\n  %sThis helper does not merge or push. Push is always manual.%s\n' "$DIM" "$RESET"

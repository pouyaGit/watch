#!/usr/bin/env bash
#
# promotion/approve.sh — record a human approval for a promotion request.
#
# Autonomous Promotion Operator v1 (Epic 0.1).
#
# The operator reviews the request file, then runs:
#
#   promotion/approve.sh --request <file> --operator <name> --confirm APPROVE
#
# This writes <file>.approval.json pinning the request and its commit. The
# approval is consumed exactly once by promote.sh; it never merges, never
# pushes, and never approves anything by itself.
#
# By design there is no approval token, no password and no secret of any kind:
# authority comes from the operator typing the explicit confirmation word on a
# trusted terminal, not from a stored credential. Double approval is refused.
#
# Usage:
#   scripts/watch-agent/promotion/approve.sh --request FILE --operator NAME
#     --confirm APPROVE [--now YYYYMMDD-HHMM]
#
# Environment overrides:
#   PROMOTION_WORKTREE_ROOT / PROMOTION_OUTPUT_DIR
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"

WORKTREE_ROOT="${PROMOTION_WORKTREE_ROOT:-$WATCH_WORKTREE_ROOT}"
OUTPUT_DIR="${PROMOTION_OUTPUT_DIR:-$WORKTREE_ROOT/agent-reports/promotions}"
PROMOTION_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_PY="$PROMOTION_DIR/audit.py"

REQUEST=""; OPERATOR=""; CONFIRM=""; NOW="${PROMOTION_NOW:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --request)  REQUEST="${2:-}"; shift 2;;
    --operator) OPERATOR="${2:-}"; shift 2;;
    --confirm)  CONFIRM="${2:-}"; shift 2;;
    --now)      NOW="${2:-}"; shift 2;;
    -h|--help)  sed -n '2,/^set -u/p' "${BASH_SOURCE[0]}"; exit 0;;
    *) printf 'FAIL: unknown argument: %s\n' "$1" >&2; exit 2;;
  esac
done

[ -n "$REQUEST" ] || { printf 'FAIL: --request is required\n' >&2; exit 2; }
[ -n "$OPERATOR" ] || { printf 'FAIL: --operator is required\n' >&2; exit 2; }
[ "$CONFIRM" = "APPROVE" ] || {
  printf 'FAIL: explicit confirmation required (--confirm APPROVE)\n' >&2
  exit 1
}
[ -f "$REQUEST" ] || { printf 'FAIL: request not found: %s\n' "$REQUEST" >&2; exit 1; }

req_commit="$(grep -m1 '^- Commit: ' "$REQUEST" 2>/dev/null | sed 's/^- Commit: //' || true)"
[ -n "$req_commit" ] || { printf 'FAIL: request has no Commit line\n' >&2; exit 1; }

approval_file="$REQUEST.approval.json"
[ -e "$approval_file" ] && {
  printf 'FAIL: request already approved (refusing double approval): %s\n' "$approval_file" >&2
  exit 1
}

if [ -z "$NOW" ]; then
  NOW="$(date -u +%Y%m%d-%H%M 2>/dev/null || echo unknown)"
fi

# operator name allowlist: plain identifier, no paths, no shell
case "$OPERATOR" in
  *[^A-Za-z0-9._-]*|"")
    printf 'FAIL: operator must be a plain identifier ([A-Za-z0-9._-])\n' >&2
    exit 1;;
esac

{
  printf '{\n'
  printf '  "request": "%s",\n' "$(basename "$REQUEST")"
  printf '  "commit": "%s",\n' "$req_commit"
  printf '  "operator": "%s",\n' "$OPERATOR"
  printf '  "decision": "APPROVED",\n'
  printf '  "timestamp": "%s"\n' "$NOW"
  printf '}\n'
} > "$approval_file"

if command -v python3 >/dev/null 2>&1 && [ -f "$AUDIT_PY" ]; then
  python3 "$AUDIT_PY" --log "$OUTPUT_DIR/AUDIT.log" record \
    --event PROMOTION_APPROVED --request "$(basename "$REQUEST")" \
    --commit "$req_commit" --actor "$OPERATOR" --now "$NOW" >/dev/null 2>&1 || true
fi

printf 'approved %s (commit %s) by %s\n' "$(basename "$REQUEST")" "$req_commit" "$OPERATOR"
printf 'This approval merges nothing and pushes nothing. Run promote.sh --yes.\n'
exit 0

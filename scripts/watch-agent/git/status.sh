#!/usr/bin/env bash
#
# git/status.sh — Git authentication and remote state overview.
#
# Credentialless Git Operations v1 (Epic 0.2).
#
# Shows authentication (SSH, credential helper, gh) and remote (origin URL,
# protocol, push capability) state.
#
# READ-ONLY. No fetch, no push, no merge, no config change, no file written.
# Remote reachability is NOT probed here (that would be network I/O): push
# capability is reported from local auth readiness only. Secrets are never
# printed: userinfo in remote URLs is redacted before display.
#
# Usage:
#   scripts/watch-agent/git/status.sh [--repo DIR]
#
# Environment overrides:
#   GIT_AUTH_REPO   repository under inspection (default: this checkout)
#   GIT_AUTH_SSH / GIT_AUTH_GH  probed binaries (default: ssh / gh)
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/watch-agent/_context.sh
. "$SCRIPT_DIR/_context.sh"

REPO="${GIT_AUTH_REPO:-$WATCH_WORKTREE_ROOT}"
GIT_DIR_BIN="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECK_AUTH="$GIT_DIR_BIN/check_auth.py"

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

if [ ! -e "$REPO/.git" ]; then
  printf '  %sERROR%s not a git repository: %s\n' "$RED" "$RESET" "$REPO" >&2
  exit 1
fi

# Never print credentials: strip userinfo (user[:secret]@) from any URL.
redact_url() {
  printf '%s' "$1" | sed 's#://[^@]*@#://[redacted]@#'
}

python_bin() {
  local candidate
  for candidate in \
    "${WATCH_PYTHON:-}" \
    "$REPO/venv/bin/python3" \
    "/opt/watch/venv/bin/python3" \
    "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

SSH_BIN="${GIT_AUTH_SSH:-ssh}"
GH_BIN="${GIT_AUTH_GH:-gh}"

section "Authentication"
if "$SSH_BIN" -T -o BatchMode=yes -o ConnectTimeout=8 git@github.com >/dev/null 2>&1; then
  item "ssh" "available"
else
  # ssh -T returns 1 on successful auth (no shell); re-probe for the message.
  if "$SSH_BIN" -T -o BatchMode=yes -o ConnectTimeout=8 git@github.com 2>&1 \
      | grep -qi "successfully authenticated"; then
    item "ssh" "available"
  else
    item "ssh" "unavailable"
  fi
fi

helper="$(command git -C "$REPO" config --get credential.helper 2>/dev/null || true)"
if [ -z "$helper" ]; then
  item "cred helper" "none configured"
elif [ "$helper" = "store" ] || [[ "$helper" == "store "* ]]; then
  item "cred helper" "store (plaintext — not accepted)"
else
  item "cred helper" "$helper"
fi

if ! command -v "$GH_BIN" >/dev/null 2>&1 && [ "$GH_BIN" = "gh" ]; then
  item "gh" "not installed"
elif "$GH_BIN" auth status >/dev/null 2>&1; then
  item "gh" "authenticated"
else
  item "gh" "not authenticated"
fi

section "Remote"
origin_raw="$(command git -C "$REPO" config --get remote.origin.url 2>/dev/null || true)"
if [ -z "$origin_raw" ]; then
  item "origin" "no origin remote"
  item "protocol" "unknown"
else
  item "origin" "$(redact_url "$origin_raw")"
  case "$origin_raw" in
    git@*|ssh://*) item "protocol" "ssh";;
    https://*)     item "protocol" "https";;
    *)             item "protocol" "other";;
  esac
fi

section "Push capability (local readiness only)"
if PYTHON="$(python_bin)" && [ -f "$CHECK_AUTH" ]; then
  auth_out="$("$PYTHON" "$CHECK_AUTH" --repo "$REPO" 2>&1 || true)"
  if printf '%s' "$auth_out" | grep -qm1 '^READY'; then
    method="$(printf '%s' "$auth_out" | grep -m1 'method:' | sed 's/^ *method: //' || true)"
    item "push" "ready via ${method:-unknown method}"
  else
    item "push" "blocked — run git/check_auth.py for reasons"
  fi
else
  item "push" "unknown — checker unavailable"
fi

exit 0

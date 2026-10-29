#!/usr/bin/env bash
# HERMES CLI — maps 1:1 to Telegram commands.
set -euo pipefail
BASE="/root/hermes-recon"; STATE="$BASE/state"
CMD="${1:-status}"; ARG="${2:-}"
send_tg() { hermes send --to telegram "$1" 2>/dev/null || echo "(telegram unavailable)"; }
case "$CMD" in
  status|health|targets|findings|high|today|report|daily|jobs)
    python3 "$BASE/scripts/reporter.py" "$CMD" ;;
  pause) touch "$STATE/PAUSED"; send_tg "HERMES paused by operator. State preserved." ;;
  resume|start) rm -f "$STATE/PAUSED" "$STATE/STOPPED" "$STATE/EMERGENCY_STOP"; send_tg "HERMES resumed." ;;
  stop) touch "$STATE/STOPPED"; send_tg "HERMES stopped. State preserved." ;;
  emergency) touch "$STATE/EMERGENCY_STOP"; send_tg "HERMES EMERGENCY STOP." ;;
  cycle) shift; python3 "$BASE/scripts/cycle.py" "$@" ;;
  flags) ls "$STATE" | grep -E 'PAUSED|STOPPED|EMERGENCY' || echo "no flags (running)" ;;
  *) echo "usage: hermes-recon <status|health|targets|findings|high|today|report|jobs|pause|resume|stop|emergency|cycle|flags>"; exit 1 ;;
esac

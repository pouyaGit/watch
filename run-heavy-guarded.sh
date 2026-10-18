#!/bin/bash

set -euo pipefail

# --------------------------------------------------
# Robust tool PATH for systemd / heavy jobs.
#
# systemd units run with a minimal PATH and never source ~/.zshrc,
# so Go tool directories (e.g. alterx) must be explicit here.
# Do NOT hardcode an interactive user's home (e.g. do not hardcode
# /home/pouya_behnia/go/bin): it is covered dynamically via $HOME/go/bin,
# so when HOME=/home/pouya_behnia the resolved PATH includes
# /home/pouya_behnia/go/bin without any username baked into the repo.
# /root/go/bin + /usr/local/go/bin cover the production systemd PATH
# (see setup-weekly-jobs.sh Environment=PATH and utils/common.py
# WATCH_TOOL_PATH for the canonical dir set).
# --------------------------------------------------

HEAVY_TOOL_DIRS="/opt/watch/venv/bin"
if [ -n "${HOME:-}" ]; then
    HEAVY_TOOL_DIRS="$HEAVY_TOOL_DIRS:$HOME/go/bin"
fi
HEAVY_TOOL_DIRS="$HEAVY_TOOL_DIRS:/root/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
export PATH="$HEAVY_TOOL_DIRS:${PATH:-}"

LOCKFILE="/run/watch-pipeline.lock"

# --------------------------------------------------
# Heavy-job execution window
#
# Allowed:
#   06:00 <= time < 11:30
#
# Not allowed:
#   00:00-05:59
#   11:30-23:59
# --------------------------------------------------

HOUR=$(TZ=Asia/Tehran date +%H)
MINUTE=$(TZ=Asia/Tehran date +%M)

CURRENT_MINUTES=$((10#$HOUR * 60 + 10#$MINUTE))

WINDOW_START=360   # 06:00
WINDOW_END=690     # 11:30

if (( CURRENT_MINUTES < WINDOW_START || CURRENT_MINUTES >= WINDOW_END )); then
    echo "Heavy job blocked: outside allowed window."
    echo "Tehran time: $(TZ=Asia/Tehran date)"
    exit 0
fi

if (( $# == 0 )); then
    echo "ERROR: no command supplied."
    exit 2
fi

echo "=================================================="
echo "Watch Heavy Job"
echo "Tehran time : $(TZ=Asia/Tehran date)"
echo "Command     : $*"
echo "=================================================="

# --------------------------------------------------
# Shared lock
#
# If Core Pipeline is running, do NOT start.
# If another Heavy Job is running, do NOT start.
# --------------------------------------------------

exec 200>"$LOCKFILE"

if ! flock -n 200; then
    echo "Another Watch pipeline/heavy job is already running."
    echo "Skipping this heavy job."
    exit 0
fi

# --------------------------------------------------
# Re-check time AFTER acquiring lock.
# --------------------------------------------------

HOUR=$(TZ=Asia/Tehran date +%H)
MINUTE=$(TZ=Asia/Tehran date +%M)
CURRENT_MINUTES=$((10#$HOUR * 60 + 10#$MINUTE))

if (( CURRENT_MINUTES < WINDOW_START || CURRENT_MINUTES >= WINDOW_END )); then
    echo "Heavy job blocked after lock: outside allowed window."
    exit 0
fi

echo "Lock acquired."
echo "Starting heavy job..."

exec "$@"
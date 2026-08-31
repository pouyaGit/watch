#!/bin/bash

set -euo pipefail

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
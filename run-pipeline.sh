#!/bin/bash

cd /opt/watch
[ -f ~/.zshrc ] && source ~/.zshrc
source venv/bin/activate

# Load .env so bash can send Telegram messages directly (same TOKEN/CHAT_ID
# python's config.py already reads via dotenv)
set -a
[ -f .env ] && source .env
set +a

LOG_DIR="/opt/watch/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/pipeline_$TIMESTAMP.log"

# Show in terminal AND write to file
exec > >(tee -a "$LOG_FILE") 2>&1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Preflight: fail fast & loud on missing dependencies -----------------
# Two environment gaps previously made the pipeline silently no-op (missing
# pipeline_lib.sh -> undefined step/send_telegram) or produce zero results
# (missing zsh -> every recon tool spawn fails). Check them up front so a
# broken box is obvious in seconds instead of after hours of empty runs.
preflight_alert() {
    # Standalone sender -- pipeline_lib.sh may not be loaded yet, so this
    # cannot rely on send_telegram. .env was sourced above.
    local text="$1"
    echo "PREFLIGHT ERROR: $text"
    [ -z "${TELEGRAM_BOT_TOKEN:-}" ] && return
    [ -z "${TELEGRAM_CHAT_ID:-}" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=Pipeline preflight failed: ${text}" > /dev/null
}

# zsh is the shell every recon tool is invoked through (see utils/common.py
# run_command_in_zsh*). Without it enum/ns/http all fail. Install if absent.
if ! command -v zsh > /dev/null 2>&1; then
    echo "zsh not found -- attempting install..."
    command -v apt-get > /dev/null 2>&1 && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y zsh > /dev/null 2>&1 || true
fi
if ! command -v zsh > /dev/null 2>&1; then
    preflight_alert "zsh is not installed and could not be auto-installed; recon steps cannot run"
    exit 1
fi

# Shared step runner + failure accumulator (defines send_telegram, step,
# PIPELINE_FAILED, pipeline_exit_code). Sourcing keeps a single
# implementation so failure propagation stays testable.
if [ ! -f "$LIB_DIR/pipeline_lib.sh" ]; then
    preflight_alert "pipeline_lib.sh missing from $LIB_DIR; cannot run"
    exit 1
fi
source "$LIB_DIR/pipeline_lib.sh"

echo "=================================================="
echo "Watch Pipeline Started - $(date)"
echo "Server Time : $(date)"
echo "Tehran Time : $(TZ=Asia/Tehran date)"
echo "Log File    : $LOG_FILE"
echo "=================================================="

TOTAL_START=$(date +%s)
send_telegram "Pipeline run started -- $(TZ=Asia/Tehran date)"

step "Sync Programs"   python3 programs/watch_sync_programs.py
step "Enumeration"     python3 enum/watch_enum_all.py
step "DNS Resolution"  python3 ns/watch_ns_all.py
step "HTTP Scanning"   python3 http/watch_http_all.py

TOTAL_DURATION=$(( $(date +%s) - TOTAL_START ))

echo "=================================================="
if pipeline_exit_code; then
    echo "Pipeline Finished in ${TOTAL_DURATION} seconds"
    echo "Tehran Time : $(TZ=Asia/Tehran date)"
    echo "Log saved to: $LOG_FILE"
    echo "=================================================="

    send_telegram "Pipeline run finished in ${TOTAL_DURATION}s total -- $(TZ=Asia/Tehran date)"
    exit 0
else
    echo "Pipeline Finished WITH FAILURES in ${TOTAL_DURATION} seconds"
    echo "Tehran Time : $(TZ=Asia/Tehran date)"
    echo "Log saved to: $LOG_FILE"
    echo "=================================================="

    send_telegram "Pipeline run finished WITH FAILURES in ${TOTAL_DURATION}s total -- $(TZ=Asia/Tehran date) -- check logs"
    exit 1
fi
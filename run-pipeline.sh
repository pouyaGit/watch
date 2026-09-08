#!/bin/bash

cd /opt/watch
source ~/.zshrc
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

send_telegram() {
    local text="$1"
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    [ -z "$TELEGRAM_CHAT_ID" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${text}" \
        > /dev/null
}

echo "=================================================="
echo "Watch Pipeline Started - $(date)"
echo "Server Time : $(date)"
echo "Tehran Time : $(TZ=Asia/Tehran date)"
echo "Log File    : $LOG_FILE"
echo "=================================================="

step() {
    local NAME="$1"
    shift
    echo
    echo "===== $NAME ====="
    send_telegram "Pipeline: starting $NAME"
    local START=$(date +%s)
    "$@"
    local EXIT_CODE=$?
    local END=$(date +%s)
    local DURATION=$((END - START))
    echo "===== $NAME Finished in ${DURATION} sec (exit: $EXIT_CODE) ====="
    echo
    if [ $EXIT_CODE -eq 0 ]; then
        send_telegram "Pipeline: $NAME finished in ${DURATION}s"
    else
        send_telegram "Pipeline: $NAME FAILED (exit $EXIT_CODE) after ${DURATION}s -- check logs"
    fi
    return $EXIT_CODE
}

TOTAL_START=$(date +%s)
send_telegram "Pipeline run started -- $(TZ=Asia/Tehran date)"

step "Sync Programs"   python3 programs/watch_sync_programs.py
step "Enumeration"     python3 enum/watch_enum_all.py
step "DNS Resolution"  python3 ns/watch_ns_all.py
step "HTTP Scanning"   python3 http/watch_http_all.py
step "Crawl Fresh"     python3 /opt/watch/crawl/watch_crawl_fresh.py

TOTAL_DURATION=$(( $(date +%s) - TOTAL_START ))

echo "=================================================="
echo "Pipeline Finished in ${TOTAL_DURATION} seconds"
echo "Tehran Time : $(TZ=Asia/Tehran date)"
echo "Log saved to: $LOG_FILE"
echo "=================================================="

send_telegram "Pipeline run finished in ${TOTAL_DURATION}s total -- $(TZ=Asia/Tehran date)"
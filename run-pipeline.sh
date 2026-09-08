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

# Shared step runner + failure accumulator (defines send_telegram, step,
# PIPELINE_FAILED, pipeline_exit_code). Sourcing keeps a single
# implementation so failure propagation stays testable.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
step "Crawl Fresh"     python3 /opt/watch/crawl/watch_crawl_fresh.py

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
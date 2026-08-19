#!/bin/bash

cd /opt/watch
source ~/.zshrc
source venv/bin/activate

LOG_DIR="/opt/watch/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/pipeline_$TIMESTAMP.log"

# هم توی ترمینال نشون بده هم توی فایل بنویس
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================="
echo "🚀 Watch Pipeline Started - $(date)"
echo "Server Time : $(date)"
echo "Tehran Time : $(TZ=Asia/Tehran date)"
echo "Log File    : $LOG_FILE"
echo "=================================================="

step() {
    local NAME="$1"
    shift
    echo
    echo "===== $NAME ====="
    local START=$(date +%s)
    "$@"
    local EXIT_CODE=$?
    local END=$(date +%s)
    local DURATION=$((END - START))
    echo "===== $NAME Finished in ${DURATION} sec (exit: $EXIT_CODE) ====="
    echo
    return $EXIT_CODE
}

TOTAL_START=$(date +%s)

step "Sync Programs"   python3 programs/watch_sync_programs.py
step "Enumeration"     python3 enum/watch_enum_all.py
step "DNS Resolution"  python3 ns/watch_ns_all.py
step "HTTP Scanning"   python3 http/watch_http_all.py
step "Crawl Fresh" python3 /opt/watch/crawl/watch_crawl_fresh.py

TOTAL_DURATION=$(( $(date +%s) - TOTAL_START ))

echo "=================================================="
echo "✅ Pipeline Finished in ${TOTAL_DURATION} seconds"
echo "Tehran Time : $(TZ=Asia/Tehran date)"
echo "Log saved to: $LOG_FILE"
echo "=================================================="
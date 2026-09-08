#!/bin/bash
# pipeline_lib.sh -- shared step runner for run-pipeline.sh
#
# Sourced, never executed directly. Sourcing has no side effects beyond
# defining functions and (re)setting PIPELINE_FAILED=0.
#
# Failure contract:
#   - step() runs one child job, reports its exit code, sends the same
#     Telegram notifications run-pipeline.sh always sent, and returns the
#     child's exit code unchanged.
#   - Any child failure sets PIPELINE_FAILED=1. Independent jobs still run
#     (existing scheduling behavior), but the pipeline's final exit status
#     is non-zero so systemd sees the run as failed.
#   - No failure is ever masked: no `|| true`, no ignored return codes.

# Accumulates child failures for the current pipeline run.
PIPELINE_FAILED=0

send_telegram() {
    local text="$1"
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    [ -z "$TELEGRAM_CHAT_ID" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${text}" \
        > /dev/null
}

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
        PIPELINE_FAILED=1
    fi
    return $EXIT_CODE
}

# Final pipeline status: 0 when every step succeeded, 1 otherwise.
pipeline_exit_code() {
    if [ "${PIPELINE_FAILED:-0}" -ne 0 ]; then
        return 1
    fi
    return 0
}

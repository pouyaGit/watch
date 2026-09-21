# PROMOTION_REQUEST_TEMPLATE.md — Telegram-ready promotion request format

Autonomous Promotion Operator v1 (Epic 0.1).

`request.sh` writes the full machine record to
`agent-reports/promotions/PROMOTION-REQUEST-YYYYMMDD-HHMM.md`. When the
operator needs a human ping, copy this template, fill the `{{fields}}` from
that record, and send it. Telegram API integration is explicitly out of scope:
this file is the output format only.

---

```text
🚀 Watch Promotion Request

Epic:        {{EPIC}}
Request:     {{REQUEST_FILE}}
Source:      {{AGENT_BRANCH}} @ {{COMMIT_SHORT}}
             {{COMMIT_SUBJECT}}
Delivery:    {{DELIVERY_VERDICT}}
Tests:       {{TESTS_SUMMARY}}
Risk:        {{RISK}}
Files:       {{CHANGED_COUNT}} changed (see request file)

{{APPROVAL_LINE}}

Waiting approval — reply with the approve.sh command from the request file.
```

`{{APPROVAL_LINE}}` is either `Approved by {{OPERATOR}} at {{TIMESTAMP}}` or
`No approval yet`.

---

## Filled example (illustrative values only)

```text
🚀 Watch Promotion Request

Epic:        AEC-1 T4
Request:     PROMOTION-REQUEST-20260921-1200.md
Source:      agent/daily-development @ 4d14498
             feat(aec): add deterministic budget ledger
Delivery:    READY FOR PROMOTION
Tests:       15 tests, OK
Risk:        LOW
Files:       4 changed (see request file)

No approval yet.

Waiting approval — reply with the approve.sh command from the request file.
```

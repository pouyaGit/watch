---
name: bb-logic
description: "bb-logic — Business-Logic & Race Testing Reference. Companion to `bb-ops/playbooks/{business-logic,race-condition}.yaml`. Load in logic-analyzer tasks. Every finding needs an observable state change."
---

# bb-logic — Business-Logic & Race Testing Reference

Companion to `bb-ops/playbooks/{business-logic,race-condition}.yaml`.
Load in logic-analyzer tasks. Every finding needs an observable state change.

## Numeric / pricing abuse
```
# boundaries on amount/price/quantity/size/days/credits
{"amount":-1} {"amount":0} {"amount":1.7976931348623157e308} {"quantity":999999999}
# long-term pricing: extend period, exploit per-period billing
{"billing_period_days":0} {"billing_period_days":-30}
# volume clone / resize with negative or huge size
```

## Workflow / state confusion
- Skip a required step (pay -> skip, directly activate).
- Replay a completed transition (terminate instance -> reuse, delete + recreate same id).
- Idempotency keys: same key + different amount; key reuse across users.
- Change a field mid-flow that should be immutable (price captured at checkout vs at charge).

## Race conditions
```
# python concurrent race harness (test accounts only)
for _ in range(50): threading.Thread(target=redeem, args=(TOKEN,CODE)).start()
```
- Targets: redeem/coupon/transfer/withdraw/register/reset/terminate while billing.
- Signal: >1 success for a logically single-use op.
- Never race production money ops without explicit human go-ahead → manual task.

## Rate-limit bypass
- `X-Forwarded-For: <spoofed>`, `X-Real-IP`, case/encoding of resource path, batch APIs.
- Only reportable if the bypass enables a security impact (e.g., unlimited brute-force of a
  login with no lockout — but note program rules on brute-force).

## Output
- Evidence: HTTP pair(s) + timing file. For races include request counts + result set.
- Never self-confirm.

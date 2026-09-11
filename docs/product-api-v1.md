# Watch Product API v1 — Research Intelligence

**API v1 · Read-only · Research Intelligence**

## Purpose

The Product API exposes Watch's existing research intelligence as a clean,
consumer-oriented, read-only contract for:

- a bug bounty researcher,
- a browser extension,
- a CLI client,
- another security platform,
- a future paid SaaS frontend.

The public resource is a **Research Opportunity**: a CVE plus asset
relevance, research evidence, economic priority and a recommended action.

A Research Opportunity is a **research candidate**, never a confirmed
vulnerability, a bounty prediction, exploitability against a target, or a
target scan result. Watch performs no security testing.

## API base

```
GET /api/v1/opportunities
GET /api/v1/opportunities/{lead_id}
GET /api/v1/opportunities/summary
GET /api/v1/research/status
```

Full interactive reference: `/docs` (OpenAPI) and `/openapi.json`.
Every route description states: *"Read-only research intelligence. Does not
perform security testing."*

## Authentication concept

Current v1 API = the **single existing API-key boundary**:

- header `X-API-Key: <key>`, or
- query parameter `?api_key=<key>`.

There are no user accounts, no OAuth, no billing and no payment. The same
`verify_api_key` dependency gates every v1 route. Future multi-user auth is
out of scope for v1.

## Endpoints

### List opportunities

```
GET /api/v1/opportunities?limit=50&offset=0&cve=CVE-2026-1557
    &program=dell&class=BLOCKED&action=VERIFY_ASSET_MATCH
    &status=BLOCKED&min_money_score=0
```

| Parameter | Meaning | Bounds |
|---|---|---|
| `limit` | max items returned | 1–100 (default 50) |
| `offset` | items to skip | ≥ 0 (default 0) |
| `cve` | exact CVE id filter | `CVE-YYYY-NNNN` |
| `program` | exact program filter | non-empty string |
| `class` | opportunity class filter | e.g. `BLOCKED`, `HIGH_VALUE` |
| `action` | recommended-action filter | e.g. `VERIFY_ASSET_MATCH` |
| `status` | current-status filter | e.g. `BLOCKED`, `READY` |
| `min_money_score` | Money Score floor | 0–100 (default 0) |

Ordering follows the internal R26.2 queue (status → class → Money Score
descending → …); v1 introduces no second ranking algorithm.

### Detail

```
GET /api/v1/opportunities/{lead_id}
```

`lead_id` looks like `rl-af7ecfba1a86fc83`. Unknown or malformed ids
return `404` with the v1 error envelope.

### Summary

```
GET /api/v1/opportunities/summary
```

Returns `total`, `by_class`, `by_action`, `by_status`, the top 3
opportunities, `research_only` and `api_version`. No additional score.

### Research status

```
GET /api/v1/research/status
```

High-level system state: `product_api_version`, `opportunity_count`,
`ready_count`, `blocked_count`, `in_progress_count`, `completed_count`,
`evidence_available`, `outcomes_available`, `sessions_available`.
Contains no secrets, no target data, no provider keys.

## Response examples

```json
{
  "api_version": "v1",
  "research_only": true,
  "total": 2,
  "offset": 0,
  "limit": 50,
  "items": [
    {
      "opportunity_id": "op-27deff4809384156",
      "lead_id": "rl-af7ecfba1a86fc83",
      "cve_id": "CVE-2026-1557",
      "program": "dell",
      "opportunity_class": "BLOCKED",
      "money_score": 53,
      "money_priority": "P3_MEDIUM",
      "confidence": "HIGH",
      "evidence_quality": "HIGH",
      "estimated_minutes": 90,
      "current_status": "BLOCKED",
      "recommended_action": "VERIFY_ASSET_MATCH",
      "why_now": ["PUBLIC_POC", "EXPLOIT_AVAILABLE", "..."],
      "why_valuable": ["research priority score 80", "..."],
      "blockers": ["only generic technology match", "..."],
      "next_step": "Confirm affected component/plugin presence.",
      "research_status": "RESEARCH_COMPLETED",
      "outcome_status": "NONE",
      "session_status": "NONE",
      "research_only": true,
      "api_version": "v1"
    }
  ]
}
```

## Error format

Every v1 failure returns a deterministic envelope (never stack traces,
file paths, credentials, environment variables, Mongo URIs or provider
keys):

```json
{
  "api_version": "v1",
  "error": {"code": "NOT_FOUND", "message": "research opportunity not found"},
  "research_only": true
}
```

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_REQUEST` | 400 | malformed filter or id |
| `NOT_FOUND` | 404 | unknown lead |
| `UNAUTHORIZED` | 401 | missing/invalid API key (existing boundary) |
| `INTERNAL_READ_ERROR` | 500 | reserved; local read failure |

## Research-only meaning

- `research_only: true` is present on every response.
- A Research Opportunity tells a researcher **where to look next**, not
  what is vulnerable.
- Watch never asserts "vulnerability detected", "bug confirmed" or
  "bounty opportunity guaranteed".

## Versioning

`api_version` is `"v1"` on every response and is **independent** of the
internal rule versions (`r25-1`, `r26-1`, `r26-2`, `r26-3`), which this
stage does not change. Future breaking API changes require `v2`.

The v1 response is an explicit mapping of the internal R26.1/R26.2 objects;
internal-only fields (subscores, rates, counts, templates, provenance) are
deliberately dropped so internal refactors never leak into the contract.

## Limitations

- Read-only: no creation, execution, scanning, validation or alerting.
- Bounded: `limit` 1–100, capped filters, no unbounded responses.
- No payouts, billing, user accounts; no rate-limit service (bounds only).
- No statistical claims about findings or bounties.
- Coverage reflects only CVEs Watch has researched locally.

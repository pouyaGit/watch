# Watch Product API v1 — External Client Guide

**Read-only research intelligence — does not perform security testing.**

## External consumer concept

Watch's Product API v1 is designed to be consumed by an external process
that shares **no Python code** with Watch: a bug bounty researcher's script,
a browser extension, a CLI client, another security platform, or a future
SaaS frontend. The consumer talks HTTP JSON only and validates responses
against the pinned public v1 contract.

Two artifacts live outside Watch internals (under `clients/`):

- `clients/product_api_client.py` — `ProductAPIClient` (stdlib HTTP).
- `clients/product_api_contract.py` — the pinned v1 field set + validators.

Neither imports `backend.*`, `ai.knowledge.*` or `ai.schemas.*`.

## Client setup

```python
from clients.product_api_client import ProductAPIClient

client = ProductAPIClient(
    base_url="https://watch.example",
    api_key_env="WATCH_PRODUCT_API_KEY",  # or api_key="..." explicitly
    timeout=10.0,
)

envelope = client.list_opportunities(limit=50, program="dell")
for item in envelope["items"]:
    print(item["cve_id"], item["money_score"], item["recommended_action"])
```

Every response is validated against the v1 contract before it is returned;
unexpected fields, wrong `api_version`, or `research_only != true` raise
`ProductAPIContractError`.

## Authentication

- Send the existing Watch API key as the `X-API-Key` header.
- The client reads the key from an argument or from an environment variable
  (`WATCH_PRODUCT_API_KEY` by default).
- The key is **never** placed in a URL, logged, printed, or included in any
  exception message. There is a single existing API-key boundary; no user
  accounts or OAuth exist in v1.

## Base URL

Supplied explicitly, e.g. `http://127.0.0.1:5000` for a local Watch
instance. The client appends the v1 paths below.

## Endpoints

| Method | Path | Client method |
|---|---|---|
| GET | `/api/v1/opportunities` | `list_opportunities(...)` |
| GET | `/api/v1/opportunities/{lead_id}` | `get_opportunity(...)` |
| GET | `/api/v1/opportunities/summary` | `get_summary()` |
| GET | `/api/v1/research/status` | `get_research_status()` |

List query parameters: `limit` (1–100), `offset` (≥ 0), `cve`, `program`,
`class`, `action`, `status`, `min_money_score` (0–100).

## Example request

```
GET /api/v1/opportunities?limit=50&program=dell HTTP/1.1
Host: watch.example
Accept: application/json
X-API-Key: <configured>
```

## Example response

```json
{
  "api_version": "v1",
  "research_only": true,
  "total": 1,
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
      "why_now": ["PUBLIC_POC", "EXPLOIT_AVAILABLE"],
      "why_valuable": ["research priority score 80"],
      "blockers": ["only generic technology match"],
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

## Errors

Every failure is a deterministic envelope:

```json
{
  "api_version": "v1",
  "error": {"code": "NOT_FOUND", "message": "research opportunity not found"},
  "research_only": true
}
```

Codes: `INVALID_REQUEST` (400), `NOT_FOUND` (404), `UNAUTHORIZED` (401),
`INTERNAL_READ_ERROR` (500). The client maps these to:
`ProductAPIRequestError`, `ProductAPINotFoundError`, `ProductAPIAuthError`,
`ProductAPIServerError`; malformed/invalid bodies raise
`ProductAPIContractError`, and timeouts raise `ProductAPITimeoutError`.
None of these messages contain the API key or server internals.

## Versioning

`api_version` is pinned to `"v1"` and is independent of internal rule
versions (`r25-1`, `r26-1`, `r26-2`, `r26-3`). v1 fields are frozen: the
client rejects extra/missing fields. Breaking changes require a `v2` API and
a matching client.

## Local vs remote CLI

| Command | Data source | Network |
|---|---|---|
| `python -m ai.research_cli product opportunities` | in-process local projection of the same schema | none |
| `python -m ai.research_cli product remote-opportunities --base-url ...` | `GET /api/v1/opportunities` via the external client | HTTP to the supplied base URL |

`remote-opportunities` has **no fallback** to local functions — it is the
proof that the public API is actually consumable.

```
python -m ai.research_cli product remote-opportunities \
  --base-url http://127.0.0.1:5000 \
  --api-key-env WATCH_PRODUCT_API_KEY \
  --program dell --limit 50
```

## Research-only limitation

Responses describe research candidates and economic priority only. Watch
never asserts a confirmed vulnerability, exploitability against a target, a
target scan result, or a bounty/payout prediction. The API performs no
security testing, and the client transmits no target, credential, cookie,
payout or execution fields.

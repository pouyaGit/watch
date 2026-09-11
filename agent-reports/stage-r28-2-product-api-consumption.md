# Stage R28.2 — Product API Consumption Proof

## Status
**IMPLEMENTED (external consumption proof).** An external, dependency-light,
read-only client now consumes the R28.1 Product API v1 over HTTP and
validates responses against a pinned public contract. No server behavior,
formula, endpoint, database, or lifecycle changed.

## 1. External client architecture (`clients/`)

```
clients/
  __init__.py                 package boundary statement
  product_api_contract.py     pinned v1 field set + validators (stdlib only)
  product_api_client.py       ProductAPIClient (stdlib urllib, GET only)
```

- The package imports **only the Python standard library** (verified by an
  AST import scan in tests): no `backend.*`, `ai.knowledge.*`, or
  `ai.schemas.*`.
- `ProductAPIClient(base_url, api_key=None, api_key_env=..., timeout=...,
  transport=None)` — the default transport uses stdlib `urllib`; tests inject
  a fake transport, so no real network is ever used in the suite.
- Methods call exactly one endpoint each: `list_opportunities`, `get_opportunity`,
  `get_summary`, `get_research_status`.
- Read-only by construction: the client issues `GET` requests only.
- HTTP handled: 400 → `ProductAPIRequestError`, 401 → `ProductAPIAuthError`,
  404 → `ProductAPINotFoundError`, 500 → `ProductAPIServerError`, malformed
  JSON / contract violation → `ProductAPIContractError`, timeout →
  `ProductAPITimeoutError`, connection failure → `ProductAPIConnectionError`.

## 2. Contract validation (`clients/product_api_contract.py`)

- `PRODUCT_API_VERSION = "v1"` pinned client-side (not imported from server).
- `REQUIRED_FIELDS` = the exact 21 public fields; `FIELD_SET` is the same, so
  **extra fields are rejected** and missing fields are rejected.
- Typed validation: `money_score` int 0–100, `estimated_minutes` int ≥ 0,
  `money_priority` matches `P[1-5]_[A-Z]+`, `opportunity_class` /
  `recommended_action` / `current_status` / `confidence` /
  `evidence_quality` are closed enums, id patterns for `opportunity_id`
  (`op-…`), `lead_id` (`rl-…`), `cve_id`, `program`.
- `research_only` must be `True`; `api_version` must be `"v1"`.
- Forbidden fields (payout/bounty/reward/target/credentials/cookies/
  exploit-command/execution-command/finding/scan) can never appear — the
  exact-field-set check rejects them by construction.
- Envelope validators for list, detail, summary, research status and the v1
  error envelope (`INVALID_REQUEST` / `NOT_FOUND` / `UNAUTHORIZED` /
  `INTERNAL_READ_ERROR`).

## 3. CLI

Added (existing `product` command extended; no new top-level command):

```
python -m ai.research_cli product opportunities            # local projection (R28.1)

python -m ai.research_cli product remote-opportunities \
  --base-url <url> --api-key-env WATCH_PRODUCT_API_KEY \
  [--limit --offset --cve --program --class --action --status \
   --min-money-score --timeout --json]
```

`remote-opportunities` constructs `ProductAPIClient`, calls
`GET /api/v1/opportunities`, validates, and renders. It has **no local
fallback**: a transport failure exits 1 with an `ERROR:` line and never
prints local data. Observed human output (fake transport):

```
REMOTE PRODUCT OPPORTUNITIES

#1 BLOCKED
CVE-2026-1557 → dell
Money: 53 / P3_MEDIUM
Confidence: HIGH
Action: VERIFY_ASSET_MATCH

NEXT:
Confirm affected component/plugin presence.
```

The API key is read only from the named environment variable and is never
placed in argv, URLs, output, or errors.

## 4. Documentation (`docs/product-api-v1-client.md`)

Explains the external-consumer concept, client setup, authentication, base
URL, endpoints, example request/response, error format, versioning, the
local-vs-remote CLI distinction, and the research-only limitation. Contains
no secrets and no real API key.

## 5. Fake-transport tests

`tests/test_product_api_client.py` — **33 tests, all OK**:

- endpoints: list, detail, summary, research status; read-only (all calls
  `GET`); query parameters and pagination (`limit/offset/cve/program/class/
  action/status/min_money_score`); base-url and lead-id guards.
- auth: `X-API-Key` header present when configured, absent when unset, env
  lookup works.
- HTTP: 400/401/404/500 mapped to typed exceptions; malformed JSON and
  invalid responses (extra field, wrong version, `research_only=false`)
  rejected.
- timeout: injected `ProductAPITimeoutError` propagates; the default
  transport maps `socket.timeout` to `ProductAPITimeoutError` and
  `URLError` to `ProductAPIConnectionError`; unexpected exceptions are
  wrapped.
- secret hygiene: a distinctive API key never appears in any exception
  message or in `repr(client)`.
- CLI: remote JSON + human output via fake transport, no-local-fallback on
  error, `--base-url` required, local command still present.

`tests/test_product_api_contract.py` — **25 tests, all OK**: exact field set,
missing/extra rejection, forbidden fields, wrong `api_version`, falsy
`research_only`, invalid money score/priority/class/action/status/quality,
id/list validation, deterministic parsing, envelope/summary/status/error
validators, and an AST check that the clients package imports no internals.

Total new: **58 tests OK**. Combined regression run (R28.1 + R28.2 + R25.2
through R27.1): **672 tests OK**.

## 6. Real consumption smoke

No reachable Watch API environment exists in this workspace:

```
listener on :5000 = 0
WATCH_PRODUCT_API_KEY set = no
WATCH_PRODUCT_API_BASE_URL set = no
```

Per the stage rules this is reported honestly and no fake server was started:

```
REAL_REMOTE_SMOKE: NOT_RUN
```

The consumption path is instead proven end-to-end in-process with a fake
transport (CLI `remote-opportunities` → `ProductAPIClient` → contract
validation → rendered v1 fields), which exercises every layer except the
network socket.

## 7. Compatibility

- No server endpoint or response shape changed; `api.py` registration and the
  R28.1 router are untouched by this stage (R28.1 changes remain as-is).
- Pinned versions verified unchanged: `r25-1` (Money), `r26-1`, `r26-2`,
  `r26-3`, and Product API `v1`. Money scores still `[53, 53]`; calibration
  still `INSUFFICIENT_DATA` with `weights_unchanged=True`.
- No v1 field was added or removed; the client rejects unexpected changes by
  design.

## 8. Security audit

- **No server behavior change, no new endpoints, no write API.** The client
  issues GET only.
- **No database/Mongo/LLM/subprocess/Nuclei/browser/target interaction**, no
  findings, no alerts, no payout prediction, no billing/users/OAuth/webhooks,
  no workers, no systemd/`.env` changes.
- **No credentials logged**: API key never in URLs, argv, output, exceptions,
  or `repr`; tests assert this with a distinctive key.
- **Only v1 fields transmitted**: target/host/IP/credential/cookie/exploit/
  execution/payout fields are absent from the contract and rejected as extra
  fields.
- `git diff --check` clean; no commit/push.

## 9. Limitations

- The real remote smoke could not run (no reachable instance); it is not
  faked. Once a Watch API is reachable, rerun
  `product remote-opportunities --base-url ... --api-key-env ...`.
- The default transport is stdlib `urllib`; no retries, backoff, connection
  pooling, or async support (v1 keeps dependencies minimal).
- Contract validation is structural only; semantic freshness of the data is
  the server's responsibility.
- `--json` for `remote-opportunities` emits the validated list envelope
  (with `api_version`/`total`), whereas the local command emits items only —
  documented difference.

## 10. Exact next-stage recommendation

**R28.3 — Contract Pinning + Reachable Smoke (read-only).**

1. On a host where the Watch API is reachable, run the single read-only
   smoke (`GET /api/v1/opportunities`, optionally `/api/v1/research/status`)
   and record only status, schema validity, count, `api_version`,
   `research_only` — never the key or server internals.
2. Add a CI-safe contract conformance check that diffs the server's live
   `/openapi.json` v1 field set against `REQUIRED_FIELDS`, failing loudly on
   drift before it can leak.
3. Keep v1 frozen; any extension requires an explicit `v2` design stage with
   a matching client contract. Never silently add fields to v1.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R28.2
- Role: Product API Consumption Proof

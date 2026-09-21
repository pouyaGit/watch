# WATCH AI SOC UI — SOC-1..SOC-5

## Status: IMPLEMENTATION COMPLETE

## Objective

Transform Watch from a technical dashboard into a Security Operations
Center interface. UI / read-model work only — every rule honored:
no AEC runtime, evidence-pipeline, authorization, finding-verification,
database-schema, route-removal or recon-pipeline changes. The engine is
untouched; the problem addressed is visibility.

## What was built

New `backend/soc/` package — read-only UI adapters (projections):
- `agents.py` — agent index + per-agent page (identity from the real
  registry, knowledge from memory/KB, history from research loop records
  + KB docs + memory, target cases from the AEC case explorer)
- `cases.py` — case index + case detail (target, hypothesis, suggested
  analysis, evidence artifacts, authorization, audit; verdict only ever
  NOT_CLAIMED unless the verification layer confirms)
- `activity.py` — mission control (real runtime observability +
  research-loop + investigation-report + AEC transition events; counts
  never fabricated)
- `handoff.py` — external analyst handoff (read-only report package:
  target, context, evidence summary, agent reasoning, suggested tests,
  questions), structured so a tokenized variant can be added later
  WITHOUT an authentication bypass
- `overview.py` — SOC home aggregate (agents/cases/evidence/reports/
  knowledge/runtime)

New `backend/routers/soc.py` — 8 GET-only UI routes:
- `/ui/soc/`  `/ui/soc/agents`  `/ui/soc/agents/{slug}`
- `/ui/soc/cases`  `/ui/soc/cases/{case_id}`
- `/ui/soc/activity`  `/ui/soc/handoff`  `/ui/soc/handoff/{job_id}`

New templates `web/templates/soc/` (8 pages) + `web/static/css/soc/`.
`base.html`: new **AI SOC** sidebar group at the top; all pre-existing
pages moved under **Legacy / Engineering** (nothing deleted; every legacy
template variable still rendered).

## Security / boundaries (verified)

- Auth: unchanged — pages sit behind the existing global API-key gate;
  `api_key_qs` propagates exactly like the EPIC8 fix (internal links keep
  the key, static assets never do).
- Read-only: AST guards prove no write calls, no network/pymongo/subprocess
  imports, and no private `aec._*` access in the SOC package/router.
- No schema changes, no route removals, no AEC core modifications:
  read-only guard PASS, AEC regression unchanged at 2149 tests.
- Handoff never renders bodies/cookies/auth headers — evidence summary is
  aggregate metadata only (type/status/label/hash).

## Tests

- 61 new tests in `tests/test_soc_ui_*.py` (routes, read-only contract,
  agents, cases, activity, handoff, overview, navigation, api-key
  propagation). RED observed (38 failing) before implementation.
- Full AEC regression: **2149 tests OK** (unchanged — no core touched).
- Read-only guard: READ-ONLY VERIFIED · whitespace clean.
- Mounted-app smoke test: all 8 pages return 200, unknown agent/case
  return 404, api_key propagates on internal links.

## Files changed

- `backend/soc/` (7 modules) · `backend/routers/soc.py` (new)
- `web/templates/soc/` (8 templates) · `web/static/css/soc/soc.css` (new)
- `web/templates/base.html` (SOC nav group + Legacy / Engineering label)
- `tests/test_soc_ui_*.py` (7 new modules, 61 tests)

## Note for the operator

The SOC router is **inert until mounted** — same as the AEC router.
Mounting requires the operator to add to api.py:
`from backend.routers import soc as soc_router` and
`app.include_router(soc_router.router)`.

## READY FOR PROMOTION: YES
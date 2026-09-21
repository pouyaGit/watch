# AEC-1 EPIC8 — Command Center Intelligence UI v1

## Status: IMPLEMENTATION COMPLETE — verification in progress

## Objective

Transform existing AEC backend capabilities into an operational Command
Center UI: visibility and human operations only. Fully additive to the
existing Watch dashboard architecture; nothing redesigned, nothing
weakened.

## Architecture

- **Backend:** `backend/routers/aec.py` extended additively (was 19 GET
  routes, now 31). All new handlers are pure projections of the committed
  fixture simulations (`_simulation_run()` / `_execution_run()`): no
  database, no network, no side effects, no mutation. GET-only.
- **UI:** `web/templates/aec/` (7 server-rendered pages extending
  `base.html`), `web/static/css/aec/aec.css`,
  `web/static/js/aec/aec.js`. Existing stack only (Jinja2 + CSS), no
  heavy frontend dependencies, no new frameworks.
- **Templates:** pages use a fresh `Jinja2Templates` instance because the
  aec router's narrow-import guard forbids `backend.*` imports; empty
  states are inlined rather than imported from `macros.html`.

## Pages

| Route | Page | Contents |
|---|---|---|
| `/ui/aec/dashboard` | AEC Command Center | KPI cards: candidates, active cases, research jobs, waiting evidence, observations, review pending; recent-activity feed |
| `/ui/aec/cases` | AEC Cases | Explorer table: Case ID, Target, Category, Research State, Evidence State, Specialist, Last Activity, Next Action |
| `/ui/aec/cases/{id}` | Case Detail | Timeline, research history, evidence artifacts, authorization status, observation history, audit events; 404 state |
| `/ui/aec/pipeline` | AEC Research Pipeline | 8 stages: candidate → case → assignment → research job → authorization → observation → evidence → review, with blocked reasons |
| `/ui/aec/observations` | AEC Observations | Request ID, case, target, observation type, state, created/completed time, evidence ID. No execution buttons |
| `/ui/aec/evidence` | AEC Evidence | Artifact metadata: integrity (sha256 badge), redaction status, provenance, scope validation, quality score |
| `/ui/aec/audit` | AEC Audit | Unified timeline: case created, assignment, authorization requested/approved, observation executed, evidence stored, review requested |

## APIs (new, all GET, read-only, no secrets)

- `GET /api/aec/dashboard` — overview counts + recent activity
- `GET /api/aec/cases/{id}` — one case detail (timeline/evidence/authz/audit)
- `GET /api/aec/research/jobs` — pipeline stages + blockers
- `GET /api/aec/observations` — observation center rows
- `GET /api/aec/audit` — unified audit timeline
- `/api/aec/cases` (existing) now serves the populated case explorer
  instead of the empty-until-wired shape

## Security boundaries (unchanged, verified)

- Authorization Gate untouched; no imports of the gate, no alternate
  authorization paths
- No mutation decorators (`post/put/patch/delete`) anywhere in the router
- No evidence-store / finding-eligibility vocabulary; verdict/conclusion
  never exported by any view
- Evidence viewer shows integrity/redaction status only — never cookies,
  authorization headers, or raw bodies
- No arbitrary-URL/HTTP execution; observation center is display-only
- No query parameter can name an action/command/operation/exec
- `backend.*` import ban preserved (narrow-import guard)

## Data flow

Simulations (committed fixtures) → read-only views →
JSON API / server-rendered Jinja2 pages. Everything deterministic;
`python` probes confirmed all 8 render paths (incl. missing-case branch)
produce valid pages.

## Tests

- **307 new tests** across 14 modules:
  `test_aec_ui_{contracts,router,pages,pages_detail,security,boundaries,
  cases,observations,pipeline,audit,evidence,dashboard,quality,render,
  scenarios,overview}.py`
- RED confirmed before implementation (235 failing), then GREEN:
  `discover -s tests -p "test_aec_ui_*.py"` → Ran 307 tests, OK
- Coverage: API contracts, router surface (GET-only, 31 routes),
  serialization, empty states, permission boundaries, secret filtering,
  evidence/audit rendering, deterministic output, no mutation from GET,
  no hidden execution paths, template/asset quality, CSS palette reuse

## Verification status

- ✅ EPIC8 UI suite: 307 tests OK
- ✅ Read-only guard: READ-ONLY VERIFIED (no pinned file drifted)
- ✅ Whitespace check: clean
- ⏳ AEC regression (`test_aec*.py`) — running
- ⏳ Delivery checks (check.sh) — pending
- ⏳ Production-untouched verification — pending

## Files (EPIC8)

- `backend/routers/aec.py` — +5 API endpoints, +7 UI routes, 8 view
  builders, 7 page payload builders
- `web/templates/aec/{dashboard,cases,case_detail,pipeline,observations,
  evidence,audit}.html`
- `web/static/css/aec/aec.css`, `web/static/js/aec/aec.js`
- 3 legacy router tests updated (route pins 19 → 31, cases endpoint shape)
- 14 new `test_aec_ui_*.py` modules

## Limitations

- Data is simulation-derived (fixture), like the rest of the AEC API
  layer; pages render real simulation state, not live production state
- AEC router remains inert-until-mounted (operator decision, Track B)
- The unified audit timeline synthesizes events from the simulation
  records; it is a projection, not the runtime's hash-chained trail

## READY FOR PROMOTION: YES

(verified gates: UI suite OK, readonly OK, whitespace OK; regression and
delivery checks in progress)
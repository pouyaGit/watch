# R82 — Researcher Dashboard UI

Date: 2026-09-16
Base commit: `21b9d3ec88a9bb44200867aab33247c3966733f2` (R81)
**UI only. No backend, API or research-layer changes. REAL case is read-only;
no evidence was submitted by this milestone.**

## 1. Frontend architecture inspected

- `web/templates/*.html` — server-rendered Jinja2 pages with a shared
  `base.html` shell (fixed sidebar, top bar, `active` nav marker,
  `api_key_qs` propagated on every link).
- Styling: Tailwind via CDN (config in `base.html`) plus one shared
  stylesheet `web/static/css/custom.css` (design tokens `--bg/--panel/--accent/
  --ok/--warn/--err`, `.panel`, `.tbl`, `.badge-*`, `.btn-primary`, …).
- `web/static/js/app.js` — small vanilla JS; no SPA framework, no build
  system, no Node test runner.
- Pages live in `backend/routers/*.py` (Jinja routes behind `verify_api_key`);
  `/static/*` assets are served unauthenticated and the dashboard JS reads the
  API key from `window.location.search` (documented in `api.py`).

Architecture decision: because HTML page routes require backend changes (which
the mission forbids), R82 implements the dashboard as a **static frontend
app** under the existing `/static` convention, linked from the existing
Research sidebar. No backend file, no `api.py`, no template route added.
Documented as an implementation note (§12).

## 2. API integration

The UI calls only the R81 contract, with the API key appended exactly like the
existing dashboard (`?api_key=` from `location.search`):

- `GET /api/research/cases` — case list
- `GET /api/research/cases/{case_id}` — R77 workbench
- `POST /api/research/cases/{case_id}/evidence` — R80 envelope

No R70–R80 module is called from the frontend; there is exactly one POST
target (`.../{case_id}/evidence`), no other endpoint, no WebSocket, no
external host, and no hardcoded credential (`openrouter`, `Bearer` and the
configured key are absent from every asset; enforced by test).

## 3. Case list (`web/static/research/index.html`)

Columns aligned with the R81 summary: Case, Program, Category, Status,
Readiness, Decision, Evidence, Missing evidence, Human review, Next iteration.
Status badges reuse the existing palette without implying severity
(`WAITING_FOR_EVIDENCE` neutral, `ACTIVE` running, `READY_FOR_HUMAN_REVIEW`
warn, `STOPPED` err; readiness INSUFFICIENT/PARTIALLY/SUFFICIENT distinct).
Client-side search (case id/program/category/gap), status filter, human-review
filter and sort by existing API fields only — no new ranking.

## 4. Case detail (`web/static/research/case.html`)

Breadcrumb/back link, case header with program/category/gap chips plus status
and readiness badges, refresh button (no polling, no WebSockets), the
workbench container and the evidence form. Loading/empty/unavailable/
unauthorized/unknown-case states are rendered in a bounded status panel.

## 5. Workbench mapping (R77 authority)

Sections are rendered strictly in the mandated order, each from the R81
workbench payload: **Current state** (status/readiness/decision/feedback/
hypothesis state/next iteration/human review/iterations), **What we know**
(available kinds, counts, evidence states, provenance state, supporting
canonical refs), **What is missing** (missing kinds, decision-critical chips,
per-requirement description, acquisition method, expected result, stopping
condition), **What to do next** (objective, recommended action, method,
sources, bounded steps, expected result, stopping condition, max three
`next_steps` with reason and kinds), **Human review** (prominent
`HUMAN REVIEW REQUIRED` box with bounded reasons), then Hypotheses, Why
interesting, Conflicts (NOT RESOLVED), History (bounded, truncation shown) and
Safety (compact Yes/No panel). The UI re-renders nothing itself; it only draws
the R77 payload.

## 6. Evidence submission UI

`#evidence-form` builds the exact R80 envelope (`submission_version: "r80-1"`,
`case_ref` from the URL case, optional non-personal `submitted_by`, one
bounded `items` entry) with requirement (populated from the workbench's
decision-critical missing kinds), source (existing R80 vocabulary), effect
(PROVIDES/CONTRADICTS/INVALIDATES → `observations` or `invalidates_refs`),
canonical `kind:value` reference and bounded observation text. The form warns
against URLs, credentials, tokens, cookies, IPs, Mongo ids, bodies and
execution instructions; the backend remains authoritative.

## 7. Validation

Client-side checks are UX-only (required reference field, non-empty selection).
No client-side acceptance logic exists. Backend rejection codes are displayed
verbatim from the API `detail` (HTTP status + code) with a bounded hint map:
`MALFORMED_ENVELOPE`, `UNSUPPORTED_SUBMISSION_VERSION`, `CASE_REF_REQUIRED`,
`UNKNOWN_CASE`, `CASE_MISMATCH`, `CASE_STATE_UNAVAILABLE`,
`UNKNOWN_REQUIREMENT_FOR_CASE`, `HYPOTHESIS_NOT_IN_CASE`,
`SUBMITTER_NOT_ALLOWED`, `SENSITIVE_SUBMISSION_REJECTED`,
`EXECUTION_CONTENT_REJECTED`, `SUBMISSION_TOO_LARGE`,
`INVALID_EVIDENCE_SOURCE`, `DUPLICATE_EVIDENCE`,
`INTERNAL_PROCESSING_FAILURE`.

## 8. Error states

Implements loading, empty (`no cases match the filters`), API unavailable,
unauthorized (`API key required` with the existing `?api_key=` hint), unknown
case, submission rejected (bounded code, no stack traces/bodies) and
submission success (intake status, accepted count, rejection codes, conflict
summary, and a "What changed" list computed by comparing the previous and
returned workbench snapshots — presentation only, no client-side state
machine).

## 9. Real Case (REAL, read-only)

Against the real R81 API the dashboard renders
`case-indeed-a1-endpoint-behavior` with status `WAITING_FOR_EVIDENCE`, WHAT WE
KNOW `ENDPOINT_PURPOSE`, `WATCH_SIGNAL`; WHAT IS MISSING `METHOD_AUTH`,
`RESPONSE_BEHAVIOR`; WHAT TO DO NEXT `PROVIDE_EVIDENCE`,
`CONTINUE_RESEARCH`; human review not required; safety `NOT_CONFIRMED`. No
evidence was submitted and the artifact bytes are unchanged (tested).

## 10. Security / safety

- No secret in any asset; no hardcoded key; the existing runtime `?api_key=`
  convention is reused and the API key is only forwarded to same-origin
  `/api/...` calls.
- Rendering uses `textContent`/`createElement` exclusively; `innerHTML` never
  appears in the dashboard JS (no HTML injection from API strings).
- No external network target in the JS; no WebSocket/polling; no target
  interaction; no scanner, payload, subprocess, shell or Mongo writes.
- Safety panel always visible: Research only, Execution performed: No,
  Vulnerability confirmed: No, Exploit authorized: No, Confirmation state
  `NOT_CONFIRMED`, Human authority required: Yes.
- Conflicts show `NOT RESOLVED`; no winner is ever selected and no security
  verdict is displayed.

## 11. Tests

`tests/test_r82_research_dashboard_ui.py` — **18 passed**: static pages/JS/CSS
served; list controls and status options; detail anchors; R81-only endpoints;
runtime API key convention; no `innerHTML`; no external hosts; section order
(current state → … → safety); terminology (workflow actions, `NOT_CONFIRMED`,
`NOT RESOLVED`, safety labels); R80 envelope + source vocabulary; error-state
implementation; no hardcoded secrets; sidebar link present in `base.html` and
on the rendered dashboard; REAL API payloads matching the UI contract; and
read-only artifact check.

Existing suites: `pytest tests/local_e2e -q` — **328 passed, 63 subtests**;
`tests.test_research_cases_api` — **26 passed** (R81 unchanged);
`pytest tests/test_ui_redesign.py -q` — **19 passed** (existing UI unchanged).

## 12. Visual verification

Assets were served and inspected through the real FastAPI app (`/static/...`
200s, correct lengths, sidebar link rendered on `/`), and the exact API
payloads the UI consumes were verified. A rendered screenshot/browser run is
**not available** in this environment (no headless browser installed); DOM
behaviour is covered by static structure/JS assertions rather than a browser
test. Recorded as a limitation.

## 13. Implementation gaps

1. No browser-based rendering test (no headless browser in the environment);
   covered by static assertions + API payload tests.
2. The dashboard is a static integration under `/static` (linked from the
   existing sidebar) because adding Jinja page routes would require backend
   changes, which the mission forbids. This is the documented deviation from
   the server-rendered page convention; it uses the existing styling system,
   API-key convention and does not introduce a second framework.
3. POST results are in-memory per the R81 contract: refreshing the page shows
   the persisted (unchanged) case. No persistence was added.

## 14. Files changed

- `web/static/research/index.html` (new, case list)
- `web/static/research/case.html` (new, case detail + evidence form)
- `web/static/js/research_dashboard.js` (new, R81 client + renderers)
- `web/static/css/custom.css` (+125 lines, R82 styles reusing the theme)
- `web/templates/base.html` (+2 lines, Research → Research Cases link)
- `tests/test_r82_research_dashboard_ui.py` (new)
- `agent-reports/r82-research-dashboard-ui.md` (this report)

No `backend/`, no `api.py`, no research-layer changes; `web/` only.

## 15. Commit

One local commit: `feat(web): add research dashboard`
(hash reported in the final task response). No push.

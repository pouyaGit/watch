# Stage R19 — Research Intelligence Dashboard

## 1. Objective

Integrate the existing R12–R18 research intelligence into the existing Watch
Flask/Jinja2/HTMX-style dashboard (FastAPI + Jinja2 + HTMX/Alpine). UI/API
integration only: no new frontend framework, no build tooling, read-only local
research data.

## 2. Exact files changed

- `ai/knowledge/queue.py` — **additive** shared local orchestration
  (`cve_from_document`, `load_research_payload`, `vulnerability_profile`,
  `relevance_inputs`, `local_cve_context`, `build_local_research_queue`) so the
  CLI, UI and API all call the same R15–R18 engines/loaders. No engine logic
  duplicated; pure core unchanged.
- `ai/research_cli.py` — `relevance`/`queue` commands now call the shared
  functions (deduplicated orchestration; output unchanged).
- `backend/research_data.py` — read-only data layer additions:
  `research_intelligence_stats()`, `list_research_queue()`,
  `cve_intelligence()`, `cve_relevance()`, bounded/compacted queue rows, and a
  10s dir-aware cache (no per-request corpus scan).
- `backend/routers/research_pages.py` — overview strip data, new
  `/ui/research/queue` page, CVE-detail intelligence panels, `queue_url` in the
  shared context.
- `backend/routers/research.py` — read-only queue/relevance API endpoints.
- `backend/routers/pages.py`, `runs.py`, `programs.py` — add `queue_url` to the
  shared sidebar context (nav on every page).
- `web/templates/base.html` — "Research Queue" sidebar link.
- `web/templates/research.html` — R16 priority-class + R18 queue overview strip.
- `web/templates/research_detail.html` — Exploitability / CVSS Structural /
  Research Priority / Asset Relevance / Research Queue Candidates panels.
- `web/templates/research_queue.html` — **new** ranked queue page.
- `tests/test_research_intelligence_ui.py` — **new**, 19 tests.

## 3. Routes added (HTML)

- `GET /ui/research` — extended with priority-class counts, queue count, CVEs
  with asset relevance, and a queue link.
- `GET /ui/research/queue` — ranked R18 queue (rank, CVE, program, priority,
  relevance, queue score, reasons, blockers, unknowns), persistent
  `RESEARCH PLANNING — NOT VERIFIED` banner, CVE filter, pagination, empty
  state, mobile-friendly table.
- `GET /ui/research/{cve}` — extended with R15 exploitability + CVSS structural
  metrics, R16 priority, R17 asset relevance (per program), R18 queue
  candidates, all research-only labelled.

## 4. API endpoints (read-only)

- `GET /api/research/queue?limit&offset&cve` — ranked queue, bounded
  (limit ≤ 100), deterministic order, compact rows (no unbounded evidence).
- `GET /api/research/queue/{cve}` — queue items for one CVE.
- `GET /api/research/{cve}/relevance` — R17 relevance slice.

All are behind `verify_api_key` and the global `APIKeyMiddleware`, return JSON
only, and never mutate state or expose secrets. Invalid ids → 400; missing
artifacts → 404 (same convention as the existing research API).

## 5. UI description

- **Overview**: existing KPI grid plus a research-intelligence strip
  (`Critical/High/Medium/Low Research` counts and a `Research Queue` card that
  links to the queue and shows CVEs with asset relevance). Links to XSS, KB and
  Reports are unchanged (no data duplication).
- **Queue page**: single ranked table with the persistent not-verified banner.
  Priority/relevance are neutral badges; blockers render as chips; unknowns are
  a muted list. Empty state explains that a candidate requires a deterministic
  overlap.
- **CVE detail**: new panels keep the same `.panel`/`.kv`/`.tbl`/`badge-sm`
  visual language and each carries a "research only / not verified" label;
  program names link to the existing `/ui/program/{name}` view, labelled
  "research relevance only".

## 6. Real queue displayed

`python3 -m ai.research_cli queue` / `/api/research/queue` over the local
corpus (unchanged by R19):

```
#1  CVE-2026-1557 -> dell    queue_score=56  (priority=CRITICAL_RESEARCH/80, relevance=LOW/20)
    reasons:  critical research priority; public proof-of-concept available; exploit availability reported; no authentication required; …; technology match: wordpress
    blockers: only generic technology match; affected plugin not observed; asset component not observed; asset version unknown
#2  CVE-2026-1557 -> indeed  queue_score=56  (priority=CRITICAL_RESEARCH/80, relevance=LOW/20)
```

Only CVE-2026-1557 yields deterministic candidates; the other five produce no
items (no local matched asset intelligence). Unknowns and blockers are shown
deliberately.

## 7. Tests

- New focused suite `tests/test_research_intelligence_ui.py`: **19 tests, OK**
  covering overview, queue page, deterministic ordering, empty state, CVE
  detail, exploitability/priority/relevance/blocker display, API auth,
  pagination/limit, API determinism, HTML escaping, bounded evidence/truncation,
  no-mutation, and schema/legacy compatibility.
- Existing research API `tests/test_research_api.py`: **29 tests, OK**.
- AI R12–R18 regression (`ai.test_intelligence`,
  `test_parameter_component_intelligence`, `test_exploitability_intelligence`,
  `test_research_priority`, `test_asset_relevance`, `test_research_queue`,
  `test_research_ingestion`, `test_knowledge_store`, `test_knowledge_ingestion`,
  `test_research_cli`, `test_reports_renderer`): **280 tests, OK**.
- AI XSS/KB regression (`test_body_extraction`, `test_research_kb_xss_e2e`,
  `test_xss_researcher`, `test_xss_llm_researcher`, `test_openrouter`,
  `test_xss_agent`): **122 tests, OK**.
- `tests/test_xss_llm_dashboard.py`: **14 tests, OK**.
- Template syntax: all four touched templates load.

### Pre-existing failures (not caused by R19, documented)

- `tests/test_research_ui.py::test_research_sort_toggle_inverts_order` fails
  purely in `research_data.list_research`: five corpus CVEs have no title, and
  the missing-title bucket is appended in the same order for both directions,
  so `desc != reversed(asc)`. Reproduced by direct data-layer calls with no R19
  code involved.
- `tests/test_page_render.py`, `tests/test_dashboard_logic.py`,
  `tests/test_ui_redesign.py`, `tests/test_routers_fixes.py`, and
  `test_research_ui.py::test_dashboard_xss_status_breakdown_humanized` error on
  `pymongo.errors.ServerSelectionTimeoutError` against the remote production
  Mongo (`35.202.201.30:27017`) which is unreachable from WSL. Environment-only;
  R19 does not query Mongo.

## 8. Security review

- **Read-only**: no writes, no Mongo for new intelligence logic, no subprocess,
  no network, no LLM, no Nuclei, no browser, no active validation, no findings,
  no alerts.
- **Autoescaping**: the shared `Jinja2Templates` keeps autoescaping on; a
  hostile queue payload test asserts `<script>` is escaped
  (`&lt;script&gt;`) and never emitted raw.
- **Bounded display**: queue rows are compacted in the data layer (reasons ≤
  240 chars, ≤ 12 items each, no evidence bodies); API responses never include
  unbounded evidence; long strings are clipped with `…`.
- **Path handling**: CVE/knowledge ids are validated with the existing
  `normalize_cve` regex; no path is built from raw user input.
- **No secrets**: responses carry only research intelligence; pages use the
  existing `?api_key=` link convention.

## 9. Performance notes

- Queue/relevance are computed once and cached for 10s with a key that includes
  the data directories, so pages/APIs do not re-scan the corpus per request
  (matches the existing `get_overview`/`research_stats` TTL pattern).
- Queue responses are bounded (default 50, max 100); the queue page and API
  slice a cached ranked list; no expensive computation in templates.
- The new R19 suite runs in ~1.6s thanks to the cache.

## 10. Explicit confirmation

- **No active validation.**
- **No Nuclei.**
- **No LLM.**
- **No external network.**
- **No production mutation.**
- **No alerts.**
- **No Git operations** (no add/commit/push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R19
- Role: Research Intelligence Dashboard

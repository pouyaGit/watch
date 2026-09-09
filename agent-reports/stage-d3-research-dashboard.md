# Stage D3 — Watch Research Dashboard UI — Implementation Report

## Summary

Built the first server-rendered Research Dashboard on top of the Stage
D2 read-only data layer (`backend/research_data.py`). No SPA, no new
packages, no self-HTTP: the UI router calls the same read-only helper
functions the D2 JSON API uses. Existing Jinja2 + HTMX + Tailwind
(CDN, already loaded by `base.html`) stack reused throughout.

## Implemented pages

| Route | Template | Description |
| --- | --- | --- |
| GET /ui/research | research.html | CVE research table + stats cards + search/severity/status filters + sortable CVE/title/CVSS + pagination |
| GET /ui/research/{cve} | research_detail.html | Full persisted research: header (CVE/title/severity/CVSS/status/authoritative), Summary, Vulnerability (type/endpoints/params/auth/product/versions), Evidence (marked "persisted research notes"), References (plain text, not fetched, not links), Nuclei (candidate/decision/reason/template metadata/validation summary), Report link, prominent RESEARCH ONLY banner |
| GET /ui/xss | xss.html | Candidate table: id, status badge, confidence meter, XSS type, context, query, top evidence; status/type/context/search filters; "RESEARCH CANDIDATES — NOT PRODUCTION FINDINGS" banner |
| GET /ui/xss/{id} | xss_detail.html | Full candidate: status, confidence, pattern, injection context, evidence table (knowledge/title/score/reasons), sinks/sources with KB ids, preconditions, unknowns, KB reference links, disclaimer; test idea inside a dashed-red **quarantine panel** labelled "UNTESTED RESEARCH IDEA — NEVER EXECUTED", rendered escaped in `<pre>` |
| GET /ui/kb | kb.html | Metadata table: knowledge id, title, source URL (plain text), source type, CVE tag (links to filtered research), evidence quality, confidence, tags; q/cve/tag filters; pagination |
| GET /ui/kb/{id} | kb_detail.html | Title, summary, tags/technologies chips, plain-text content in escaped `<pre class="md-report">`, per-source provenance with claim-level confidence/evidence attribution; CVE → research link |
| GET /ui/reports | reports.html | List: CVE, artifact name, size, availability, view/download actions; CVE search; pagination |
| GET /ui/reports/{cve} | report_detail.html | Raw Markdown in `<pre class="md-report">` (escaped, scrollable, max-height), back-to-reports, research link, Download .md |
| GET /ui/reports/{cve}/download | — | `PlainTextResponse` (text/markdown) with `Content-Disposition: attachment`; strictly read-only, path confined to `ai_data/reports` |
| GET / (extended) | dashboard.html | Compact "Research" strip below recon KPIs: Research CVEs, KB Documents, XSS Candidates + status breakdown, Reports, API link — each card links to its page; banner note "offline artifacts — not production findings" |
| (errors) | error.html (NEW) | Shared styled 400/404 page via new `error_panel` macro |

## Navigation changes

- `web/templates/base.html`: new sidebar group **Research** between
  Changes and System with Research / CVEs, XSS, Knowledge Base,
  Reports. Mobile off-canvas toggle untouched (same `side-link`
  pattern, `@click="navOpen = false"`).
- `_ctx()` in pages.py / programs.py / runs.py + new router each
  gained the four `build_url(...)` nav entries (api_key propagation
  identical to existing links). No other recon logic touched.
- Active markers: `research`, `xss`, `kb`, `reports`.

## API / data sources used

- All pages import `backend.research_data` **directly in-process**
  (no HTTP to its own API, no duplicated parsing):
  `list_research` / `research_stats` / `get_research` /
  `list_kb` / `get_kb` / `list_xss` / `get_xss` / `list_reports` /
  `get_report` / `has_report` / `get_overview` / `nuclei_summary` /
  `severity_bucket`.
- Files read (read-only): `ai_data/research/*.cli.json`,
  `ai_data/research/xss/xss-*.json`, `ai_data/knowledge/` (via
  KnowledgeStore read APIs only), `ai_data/reports/<CVE>.md`,
  `ai_data/nuclei/{generated,results,findings}` (metadata only).
- Legacy Mongo `XssFindings`: never queried by any UI route or the
  data layer.
- Dashboard overview uses the 10-second cached `get_overview()`;
  wrapped in try/except so a research-file problem can never break
  the recon dashboard.
- New data-layer helpers (read-only additions):
  `severity_bucket`, `research_stats`, `has_report`,
  `nuclei_summary`, `nuclei artifacts`, `list_xss(q=…)`,
  `list_research(sort=…, direction=…)` with deterministic tie-break
  on CVE, `_xss_compact.top_evidence`.

## Visual design decisions

- Kept the dark recon palette and every existing component:
  `panel`, `tbl`, `stat-card`, `badge`, `pill`, `filter-bar`,
  `search-bar`, `pager`, `empty-state`, `back-link`, `mono`.
- New primitives (additions to custom.css only; existing rules
  untouched): severity badges (`sev-critical/high/medium/low/unknown`),
  XSS status mapping onto existing badges (CANDIDATE→running-blue,
  INSUFFICIENT→warn, REJECTED→idle), confidence micro-meter, amber
  left-rule research banner, dashed-red quarantine panel, `md-report`
  escaped-pre view, `detail-grid` two-column layout, key/value tables,
  provenance blocks, error panel.
- Monospace everywhere for CVE / xss- / kb- ids, endpoints, params,
  source URLs; tables use existing horizontal scroll (`table-wrap`).
- Severity badge colours match the platform accent set
  (err/accent2/warn/accent/muted) — no gradients, no animations,
  no hero sections, no marketing copy.

## Security controls

- Every UI route carries `dependencies=[Depends(verify_api_key)]`,
  identical to existing routers; global `APIKeyMiddleware` unchanged
  (verified 401 without key on all new pages).
- Jinja autoescaping everywhere; zero `|safe` in any new template
  (verified by grep: no matches in the nine new templates).
- Raw Markdown and KB content displayed in escaped `<pre>`; there is
  no Markdown→HTML renderer and none was added.
- References rendered as plain escaped text — never anchors — so
  untrusted persisted URLs cannot be click-through targets and are
  never fetched.
- CVE ids validated with the existing `CVE_RE` (same pattern as the
  reports renderer); report/download paths confined via
  `_confined()` resolve-under check → traversal impossible
  (unit + HTTP tests).
- Detail pages render *fixed* message strings for 400/404; exception
  text never reaches the browser. Verified no `/opt/watch`,
  `ai_data`, `.env`, `openrouter`, `sk-or-`, or tracebacks appear in
  page bodies (the pre-existing `?api_key=` link propagation
  convention, which is how every dashboard link already works, is
  unchanged).
- Test ideas visibly quarantined + escaped; every research surface
  states it is not a production finding; no view implies
  confirmation.
- No subprocess, no network, no LLM, no Nuclei execution, no Mongo
  reads/writes, no KB mutation in any new code path.

## Responsive behavior

- Detail grid: two columns ≥1100px, single column below.
- Research KPI strip: 2 columns mobile / 4 ≥640px / 5 ≥1280px,
  matching existing `kpi-grid` conventions.
- Tables reuse `.table-wrap` horizontal scroll; banner and badges
  wrap; mobile burger navigation untouched.

## Tests (exact)

New: `tests/test_research_ui.py` — **26 tests, all pass**, covering:
auth on all 9 routes (incl. download), research page/empty/filters/
detail/404/400, xss page/filter/detail/malformed/missing, kb page/
search/detail/malformed/missing, reports page/detail-escaped/
missing/download/traversal, sidebar nav presence, dashboard research
section, hostile `<script>` payloads escaped on research/xss/report
pages (tmp-dir data layer), no-secret scan, generic error pages,
filter-preserving pagination.

Regressions run (all pass):

| Suite | Count |
| --- | --- |
| tests.test_research_api (D2) | 27 |
| tests.test_routers_fixes + test_dashboard_logic + test_page_render + test_change_events + test_tz + test_ui_redesign + test_research_ui | 128 |
| ai.test_research_cli + test_research_ingestion + test_xss_researcher + test_xss_agent + test_reports_renderer + test_knowledge_store + test_xss_llm_researcher + test_openrouter | 149 |
| **Total executed** | **277 + 26 UI (within 128)** |

No unrelated pre-existing failures were touched (and none appeared).

## Changed files

- `backend/routers/research_pages.py` — NEW (UI router).
- `web/templates/{research,research_detail,xss,xss_detail,kb,kb_detail,reports,report_detail,error}.html` — NEW.
- `web/templates/base.html` — sidebar Research group.
- `web/templates/macros.html` — 4 new macros (error_panel, research_banner, sev_badge, xss_status_badge).
- `web/templates/dashboard.html` — compact Research strip.
- `web/static/css/custom.css` — appended Stage D3 section only.
- `backend/routers/pages.py` — nav URLs in `_ctx` + fail-soft `research_overview` in dashboard().
- `backend/routers/programs.py`, `backend/routers/runs.py` — nav URLs in `_ctx` only.
- `backend/research_data.py` — new read-only helpers (stats, buckets, has_report, nuclei_summary, q/sort params, top_evidence).
- `api.py` — one import + one `include_router` line for research_pages.
- `tests/test_research_ui.py` — NEW.
- `agent-reports/stage-d3-research-dashboard.md` — this report.

## Sample navigation

```
/ui/research                      → Research / CVEs
/ui/research/CVE-2026-1557        → detail (banner + nuclei + report link)
/ui/xss                           → candidates
/ui/xss/xss-60edf609e21c6b41      → candidate + quarantined idea
/ui/kb                            → knowledge index
/ui/kb/kb-609f38e9c57c0592        → document + provenance
/ui/reports                       → report list
/ui/reports/CVE-2026-1557         → escaped Markdown
/ui/reports/CVE-2026-1557/download → attachment
```

## Screenshots

Not available — this is a headless WSL CLI environment with no browser
tooling; page content was instead verified via TestClient HTML
assertions (escaping, banners, nav, empty/error states).

## Known limitations

- Research severity distribution is derived from the persisted free-text
  severity string via `severity_bucket` (critical/high/medium/moderate/
  low/unknown); it is presentation-only and never rewrites stored data.
- No HTMX partials on the new pages yet (plain link/form navigation,
  which is the dominant existing pattern); HTMX is already loaded for
  later stages to layer fragment endpoints on the same helpers.
- Report list shows availability only for existing files; it never
  generates a missing report (generation stays with the offline
  renderer).
- KB detail shows at most 5 claims per provenance source (explicit
  "…N more" note) to keep pages bounded.
- XSS detail does not deep-link `source_evidence` knowledge ids (plain
  monospace text) to avoid building per-row authed URLs client-side;
  KB links exist for top-level references.

## Untouched-code confirmation

Explicitly untouched: database schema and `database/`; `ns/`;
`crawl/`; collectors; `ai/execution/`, `ai/finding/`,
`ai/verification/`, `ai/live_validation/`, `ai/researcher/`,
`ai/schemas/` (5B–5J and live-validation surfaces); Nuclei execution;
task runner/registry; authentication implementation (`verify_api_key`,
`APIKeyMiddleware` semantics identical); existing recon page routes
(other than additive nav keys); no research execution behaviour
changed; no Git operations performed (no commit/push).

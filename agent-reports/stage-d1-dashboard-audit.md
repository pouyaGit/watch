# Stage D1 — Watch Dashboard Audit & UI Architecture

Audit + design only. No code modified, no endpoints added, no packages
installed, no schema/auth/behavior changes. All claims below were read
directly from `/opt/watch` sources cited per section.

## 1. Current architecture

Server-rendered dashboard, no SPA and no build system:

- `api.py` (103 lines) is entrypoint-only: creates the FastAPI app,
  adds `APIKeyMiddleware`, mounts `/static/` (unauthenticated) and
  `/logs/tasks` (key-gated), includes 5 routers, runs uvicorn on
  `0.0.0.0:5000`. All handlers live in `backend/routers/`.
- `backend/`: `dashboard.py` (462 lines, aggregation + 10s TTL cache +
  pure row merge/sort/filter), `deps.py` (key, `paginate` clamp 500,
  `build_url`), `templating.py` (single Jinja2 env + Tehran/number/
  slug filters), `models.py` (TaskRun/TaskSchedule only; recon models
  stay in `database/db.py`), `routers/`: `pages` (6 HTML pages),
  `programs` (recon HTML + full JSON API), `runs`, `system`, `tasks`.
  47 routes total: ~24 HTML (`/`, `/ui/*`), ~23 JSON (`/api/*`), 1 POST
  (`/api/tasks/{task_id}/run`, registry-allowlisted).
- `web/`: 17 Jinja templates + `macros.html` (badges, pager,
  `empty_state`, sort links), `app.js` (30 lines, htmx event wiring
  only), `custom.css` (814 lines, dark recon theme). Tailwind, htmx
  1.9.12 and Alpine 3.13.3 load from CDN; no charts, no `fetch`
  API client, no client state store. Interactivity = htmx polls
  (task badges, system stats) + Alpine mobile-nav toggle.
- Data: Mongo (recon + changes + tasks) plus file track R1–R5
  (`ai_data/research|knowledge|reports|nuclei`, `ai_data/research/xss`)
  with **zero** backend exposure (grep over `backend/`, `api.py`,
  `app.py` finds no research/KB/XSS/Nuclei/report route).

## 2. Frontend audit

- Structure: `base.html` shell (sidebar groups Overview / Discovery /
  Operations / Changes / System, topbar with global GET search +
  Tehran chip, footer). 16 content templates extend it.
- Routes/pages: `/` (KPIs, system health, latest runs, recent changes,
  top programs), `/ui/programs` (sortable/filterable/searchable,
  paginated), `/ui/program/{name}` (stats, live-domain preview with
  Http join, tech/provider chips, changes), `/ui/domains|http|urls|
  endpoints|parameters` (global tables, server search/sort/filter/
  pagination), `/ui/search` (capped 12/15-per-section multi-search),
  `/ui/changes`, `/ui/runs`, `/ui/tasks`, `/ui/dns-bruteforce/status`.
- Components/layouts/styling: macro-based badges/tables/pagers;
  single-column panels + stat-card grids; Tailwind-CDN + custom.css.
- API clients/state/charts: none (strength for auditability; weakness
  for research UX — every new view needs a backend route).
- Auth: key propagated as `?api_key=` in every link (`build_url`) and
  a hidden topbar field; JS reads it from `location.search`.
- Loading/empty/error: `empty_state` macro used consistently; htmx
  regions show "…" placeholders; **no error states** for failed polls
  or 500s (browser-default/blank). No skeletons.

## 3. Backend/API audit

- Routes: pages (6), programs recon HTML (~14) + JSON API (~19:
  subdomains/lives/http/urls/endpoints/wordlist/dns/stats), runs (2),
  system (2), tasks (5). Full list verified in §1 counts.
- DB access: mongoengine via `database/db.py` side-effect connect;
  models Programs/Subdomains/LiveSubdomains/Http/Urls/Endpoints/
  DnsBruteStatus/ChangeEvent(+legacy XssFindings, TaskRun/TaskSchedule).
- Serialization: ad-hoc dicts per route (no schemas); datetimes to
  `.isoformat()` in JSON, Tehran filters in HTML.
- Pagination/filtering/search: `paginate()` (limit clamp 1–500);
  list pages clamp 10–200; whitelisted sort maps (`SORT_KEYS`,
  `_DOMAIN_SORTS`, `_HTTP_SORTS`, `_ENDPOINT_SORTS`, `_PARAM_SORTS`);
  user regex always `re.escape`d; programs-table paginates in Python
  over small row sets (fine).
- Dashboard endpoints: `/api/stats`, `/api/stats/by-program`
  (cached aggregations), `/api/system/stats(.json)`,
  `/api/runs/recent`, task history/status.
- AuthN/Z: global middleware (header or query key; `/docs`, `/redoc`,
  `/openapi.json`, `/static/*` exempt) + `verify_api_key` dependency
  on tasks/system/runs routes. Single shared key, no users/roles.
  No CORS middleware (same-origin by default).

## 4. Current data availability matrix

| Item | Status | Source today |
|---|---|---|
| Domains (live + providers) | AVAILABLE NOW | `/api/lives/*`, `/ui/domains` ($lookup+$facet) |
| Programs (+scopes) | AVAILABLE NOW | `/api/programs/all`, `/api/stats/by-program` |
| Assets (HTTP: status/title/tech/URL/ips) | AVAILABLE NOW | `/api/http/*`, `/ui/http` |
| Endpoints (+params/hits/x8) | AVAILABLE NOW | `/api/endpoints`, `/ui/endpoints` |
| Parameters (distinct + counts) | AVAILABLE NOW | `/ui/parameters` aggregation (no JSON twin) |
| Crawl data (URLs + sources) | AVAILABLE NOW | `/api/urls`, `/ui/urls` |
| DNS data (bruteforce status, cdn/ips) | AVAILABLE NOW | `/api/dns-bruteforce/status`, domains table |
| HTTP data (headers/favicon/final_url) | PARTIALLY | Stored in `Http` model, never rendered/returned |
| Research/CVEs | NOT AVAILABLE | Files only (`ai_data/research/*.cli.json`) |
| Knowledge Base | NOT AVAILABLE | Files only (`ai_data/knowledge/`, 1 doc) |
| XSS candidates | NOT AVAILABLE | Files only (`ai_data/research/xss/`, 3 files) |
| Reports | NOT AVAILABLE | Files only (`ai_data/reports/*.md`) |
| Nuclei artifacts | NOT AVAILABLE | Files only (`ai_data/nuclei/*`) |

Nothing invented: every AVAILABLE row names an existing route above.
`XssFindings` (Mongo) exists but is documented legacy/non-authoritative
and must never feed dashboard findings UI.

## 5. Proposed information architecture

Keep the existing sidebar; add a **Research** group after Changes:

Overview | Programs | Assets (= today's Domains+HTTP) | Recon
(URLs/Endpoints/Parameters/DNS) | Research | XSS | Knowledge Base |
Reports | (existing Operations/Changes/System unchanged).

## 6. Page-by-page UX specification

Conventions for all new pages: reuse `macros.html` pager/badges/
`empty_state`; server search/sort/pagination like `/ui/domains`;
prominent `research-only — NOT a finding` banner on every research
surface; no client state.

- **Overview (extend `/`)**: add "Research" stat-cards (researched
  CVEs, KB docs, XSS candidates by status) fed by new cached counts;
  "latest activity" stays ChangeEvent-based. Metrics split: existing
  (programs/domains/HTTP/URLs/endpoints/params/runs) vs new-API
  (research counts). Empty: "No research artifacts yet — run the
  research CLI". Loading: current full-page render (fine); error:
  add a shared error panel (new, also fixes §2 gap).
- **Research list** (`/ui/research`): table CVE | severity/CVSS |
  type | product | status | Nuclei decision | report link; filters
  severity/status, search CVE/product, sort severity/CVE, paginate 50,
  drill to detail. Detail: summary table (mirror R2 §1), evidence
  list, references (code-span URLs, no fetching), Nuclei block with
  trust-boundary banner, "view deterministic report" link.
- **XSS** (`/ui/xss`, `/ui/xss/{candidate_id}`): table status |
  confidence | type | context | top evidence | refs; status filter;
  detail shows evidence+reasons, sinks/sources with KB ids, unknowns,
  test idea in a quarantined panel ("never executed"), disclaimer
  footer. Payload patterns render escaped text, never live HTML.
- **Knowledge Base** (`/ui/kb`): table knowledge_id | title | source |
  type | CVE tag | quality | confidence | tags; search title/tag/URL;
  detail = content preview + provenance (source URL, artifact, ids).
- **Reports** (`/ui/reports`): list CVE | status | preview; detail =
  server-rendered Markdown → sanitized HTML (allowlist, no `|safe`
  raw) + download link serving the `.md` bytes. No generated dates —
  only persisted content. CVE id validated against
  `^CVE-\d{4}-\d{4,7}$`, path confined to `ai_data/reports`
  (reuse `ai/reports/renderer.py:CVE_RE`).

## 7. API gap matrix

- A) Existing endpoint suffices: all Recon/Overview-recon metrics
  (`/api/stats*`, `/api/*` lists), changes, tasks, system.
- B) Adapt existing: `/ui/parameters` needs a JSON twin for reuse;
  `Http.headers` needs an opt-in field on a detail route (never in
  list payloads).
- C) New read-only endpoints required: `GET /api/research`
  (list from `*.cli.json`), `GET /api/research/{cve}`,
  `GET /api/kb` + `GET /api/kb/{id}` (KnowledgeStore readback),
  `GET /api/xss/candidates` + `GET /api/xss/candidates/{id}`,
  `GET /api/reports` + `GET /api/reports/{cve}` (markdown + rendered),
  `GET /api/research/overview` (cached counts for Overview cards).
  All file-backed, capped/paginated, key-gated like other `/api/*`.

## 8. Security findings (from actual code)

1. **Key in URL everywhere** (`deps.build_url`, hidden search field,
   footer admits it): leaks to history, access logs, proxies, Referer.
   Recommend header-preferred auth for new JSON endpoints; keep query
   compat for HTML links only.
2. **Binds `0.0.0.0:5000` over plain HTTP** (`api.py:104`) — sniffable
   key. Recommend localhost bind or TLS termination.
3. **`/docs` exempt from auth** — publishes the mutating
   `POST /api/tasks/{task_id}/run` shape. Low risk (allowlisted
   scripts, `shell=False`), but keep in mind with (2).
4. **No CSRF** on the task-run POST (htmx, key-in-query). Acceptable on
   localhost; reassess if network-exposed.
5. **Reflected `q` is safe today**: zero `|safe`/`Markup` hits in
   templates; autoescape on; regex inputs `re.escape`d; sorts
   whitelisted; `cdn_slug` allowlists CSS tokens. Preserve these
   invariants in new pages — especially Markdown report rendering
   (sanitize, never `|safe` raw converter output) and XSS
   `payload_patterns` (escaped text only).
6. **Path traversal (future reports route)**: validate CVE id format
   and confine reads to `ai_data/reports/`; reuse renderer `CVE_RE`.
7. **`/logs/tasks` correctly gated** (not in EXEMPT_PATHS); keep any
   research-artifact routes equally gated; expose summaries, never raw
   LLM/prompt residue or secrets.
8. **Pre-existing working-tree risk (not mine)**: `database/db.py`
   carries a hardcoded credentialed Mongo URI in the dirty tree —
   must never be committed (flagged, untouched).

## 9. Performance findings (no optimization yet)

- Unbounded Python-side pulls: `ui_http/program/{p}` and
  `ui_http/fresh` (`programs.py:635,675` load ALL subdomains then
  re-query); `/api/wordlist/{program}` scans all endpoint params;
  `raw=1` variants stream whole collections as plaintext.
- Fine as-is: `$facet` domains/endpoints/parameters pipelines,
  10s dashboard cache, indexed per-program detail queries, capped
  global search, `only()` projections.
- New research endpoints: file-backed and small today (1 KB doc,
  3 candidates, 1 report); cap lists (default 50), cache overview
  counts, never load all `context_chunks` into list payloads
  (detail-only).

## 10. Recommended implementation order

1. C) read-only research/KB/XSS/reports JSON endpoints + overview
   counts (new `backend/routers/research.py`, key-gated, capped).
2. Sidebar + Research/XSS/KB/Reports pages reusing macros/pager/
   empty-state conventions.
3. Sanitized Markdown report view + download; shared error panel.
4. Overview research cards wired to cached counts.
5. B) parameters JSON twin + opt-in HTTP detail fields (only if a
   designed page needs them).

## 11. Files the next stage would modify

- ADD `backend/routers/research.py`; register in `api.py`
  (one `include_router` line).
- `web/templates/base.html` (sidebar group only),
  ADD `research*.html`, `xss*.html`, `kb*.html`, `reports*.html`
  (+ shared error-panel macro in `macros.html`).
- `backend/dashboard.py` (cached research counts) and/or a small
  `backend/research_data.py` file-reader used by the new router.
- Read-only reuse, no changes: `ai/reports/renderer.py` (CVE_RE,
  report paths), `ai/knowledge/store.py`, `ai/researcher/xss_agent.py`
  (seed/pool already union store docs).

## 12. Files that must NOT be touched

`database/db.py` + `database/` schema, `ns/`, `crawl/`, collectors,
5B–5J (`ai/execution/`, `ai/finding/`, `ai/verification/`,
`ai/live_validation/`), Nuclei execution (`ai/researcher/nuclei_*`),
research/LLM behavior, `verify_api_key`/middleware semantics,
`XssFindings` reads-as-findings, task registry/runner, pipeline
scripts, `.env`/credentials.

```
Report generated:
agent-reports/stage-d1-dashboard-audit.md
```

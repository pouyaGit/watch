# Stage D6 — Research Navigation & Dashboard Integration

## 1. Objective

Expose the research-intelligence features clearly from the main dashboard and
add strong cross-navigation between Research / Queue / Tasks / XSS / KB /
Reports — server-rendered Jinja only, no new frontend/JS/API, no changes to
R15–R20 intelligence.

## 2. Exact files changed

Backend (display/navigation only):

- `backend/routers/pages.py` — dashboard route also loads `research_intel`
  (`research_data.research_intelligence_stats()`) and `task_summary`
  (`research_tasks.task_summary()`); both cached/bounded and fail-soft.
- `backend/research_tasks.py` — added read-only `task_summary()` (status counts)
  for the dashboard; no state-machine or persistence change.
- `backend/research_data.py` — `cve_intelligence()` now also returns the
  already-computed `vulnerability_types` / `cwes` (read-only display fields) so
  the CVE page can decide when XSS is applicable. No algorithm/projection logic
  changed.
- `backend/routers/research_pages.py` — cross-navigation URLs on CVE detail,
  `cve` filter on the tasks page, validated CVE→research link on XSS detail,
  queue/tasks links on KB detail, and a validated non-anchored CVE scan.

Templates (existing design language; autoescaping unchanged):

- `web/templates/dashboard.html` — new **Research Intelligence** section
  (6 requested cards + Public Exploits/Nuclei, counts, CTAs, empty state).
- `web/templates/research_detail.html` — cross-nav quick actions
  (Queue / Tasks / XSS-when-applicable / KB / Report).
- `web/templates/research_queue.html` — `← Research / CVEs` back link.
- `web/templates/research_task_detail.html` — cross-nav (CVE / Queue / Program).
- `web/templates/research_tasks.html` — `← Research / CVEs` back link + CVE filter.
- `web/templates/xss_detail.html` — "Related research (CVE-…)" link when a CVE is
  literally present.
- `web/templates/kb_detail.html` — `research →` / `queue →` / `tasks →` links.

Tests:

- `tests/test_research_navigation.py` — **new**, 14 tests.

No new files under `ai/` (R15–R20 untouched).

## 3. Routes added / used

No new routes were added; only existing routes are linked and two read-only
filters/fields were extended:

- `GET /` (dashboard) — new Research Intelligence section data.
- `GET /ui/research/{cve}` — cross-nav links (queue/tasks/kb/report/xss).
- `GET /ui/research/queue` — back link (Start Research/Open Task already existed).
- `GET /ui/research/tasks` — new optional `?cve=` filter (route already existed).
- `GET /ui/research/tasks/{task_id}` — cross-nav links.
- `GET /ui/xss/{id}` — validated related-research link.
- `GET /ui/kb/{id}` — research/queue/tasks links.
- `GET /ui/reports/{cve}` — already linked to research (unchanged).

## 4. Dashboard section

Added a compact **Research Intelligence** strip:
Research CVEs · Public Exploits · Nuclei Candidates · Research Queue ·
Research Tasks · XSS Candidates · KB Documents · Reports.

Each card shows a live local count (from the already-cached
`get_overview()` / `research_intelligence_stats()` and a bounded task count) and
links to its page. The Research Queue card adds CVEs-with-relevance and
critical/high counts; the Research Tasks card adds a TODO/active/blocked/done
breakdown; the XSS card keeps the humanized status breakdown. When the local
research data is unavailable the section renders a graceful empty state and the
recon dashboard is unaffected.

No new network call and no duplicated expensive query: the two research
summaries are the existing 10s-cached local projections; the task count is a
bounded local JSON scan. The recon (Mongo) half of the page is unchanged.

## 5. Cross-navigation

- CVE detail → Queue (filtered), Research Tasks (filtered), XSS (only when the
  CVE is XSS-related), Knowledge Base (filtered), Report (when present).
- Queue → `← Research / CVEs`; each candidate keeps `Start Research` /
  `Open task` (R20).
- Task detail → CVE research, Queue view, Program; DONE wording stays
  "research completed", never "vulnerability confirmed".
- XSS candidate → related research when a CVE id is literally present (validated
  by regex, then linked through `build_url`); deterministic candidate stays
  authoritative and the "NOT A PRODUCTION FINDING" banner is unchanged.
- KB detail → research / queue / tasks for the document's CVE when available.
- Report detail → research/CVE (pre-existing link).

## 6. Sidebar

The sidebar structure is unchanged: the existing **Research** group keeps the
six links in order (Research / CVEs, Research Queue, Research Tasks, XSS,
Knowledge Base, Reports) with consistent per-page `active` highlighting.

## 7. Security

- All links are built from trusted route/template parameters via the existing
  `build_url` / `_ui_link` helpers (no user-supplied path construction).
- The XSS→CVE link is created only from a regex-validated `CVE-\d{4}-\d{4,7}`
  match found in persisted text; nothing is invented.
- Jinja autoescaping remains enabled; a D6 test asserts hostile persisted
  values stay escaped (also covered by existing suites).
- No new network calls, no new external API, no new JS dependency.

The dashboard's established `?api_key=` link-propagation convention is
unchanged (pre-existing `build_url` behaviour); D6 introduces no new secret
material and does not embed keys in any new place beyond that helper.

## 8. Tests

`tests/test_research_navigation.py` (14 tests, offline):
dashboard Research Intelligence section + card links + empty state; sidebar
active state per research page; CVE → queue/tasks/report links; CVE → XSS only
when applicable; queue back link + Start/Open task; task → CVE/queue links;
XSS → related research; KB → research/queue/tasks; Reports → research.

Results:
- `tests.test_research_navigation` — **14 OK**.
- `tests.test_research_intelligence_ui`, `tests.test_research_workflow`,
  `tests.test_research_api`, `tests.test_xss_llm_dashboard`,
  `ai.test_reports_renderer` — **122 OK** combined.
- AI R12–R18 intelligence regression
  (`ai.test_research_queue`, `ai.test_asset_relevance`,
  `ai.test_research_priority`, `ai.test_exploitability_intelligence`,
  `ai.test_knowledge_store`, `ai.test_intelligence`) — **169 OK**.
- `git diff --check` — clean.

### Pre-existing failures (not caused by D6)

`tests/test_research_ui.py` has **two pre-existing corpus-dependent failures**,
unchanged by D6:
- `test_research_sort_toggle_inverts_order` — five newer corpus CVEs have no
  title, so the missing-title bucket is not reversed (confirmed in R19 as a
  `list_research` data-layer issue).
- `test_dashboard_xss_status_breakdown_humanized` — asserts old counts
  (`>4<`, `>3<`, `>1<`) from the 4-CVE corpus; the corpus now holds 9 CVEs /
  7 XSS / 24 KB / 6 reports, so `>4<` no longer exists. This became visible only
  now that the local Mongo is reachable again; it is a stale-count assertion,
  not a D6 regression.

## 9. Confirmation that R15–R20 logic was not modified

No changes to R15 exploitability, R16 prioritization, R17 relevance, R18 queue
scoring, or the R20 task state machine / persistence / schemas. The only backend
additions are read-only display helpers/projections consumed by the dashboard
(`task_summary()` and two already-computed display fields on
`cve_intelligence()`); no algorithm, score, schema, or stored format changed.

## 10. Explicit confirmation

- No network calls added.
- No Git operations performed.
- No push performed.
- No screenshots required (server-rendered pages described above).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: D6
- Role: Research Navigation & Dashboard Integration

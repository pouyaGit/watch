# Stage D4 — Dashboard Security, UX & Regression Review

## Scope

Focused security + UX + regression review of the Stage D3 research
dashboard (and its D2 data/API layer). Review/fix only — no
architecture change, no new packages, no auth semantics change, no
research/execution modification.

## Findings

### Fixed (this stage)

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| F1 | Medium (API/UI contract) | `list_research` accepted a `sort`/`direction` pair (title/cvss) but the `direction` was ignored — only `cve` honored `desc`. The D3 sortable-column header advertised an asc/desc toggle that did nothing for Title / Severity-CVSS. | Rewrote the sort tail of `list_research` to apply `direction` to every column with deterministic tie-break on CVE and "missing values sort last" semantics. Verified end-to-end: `/ui/research?sort=title&direction=desc` now inverts the order. |
| F2 | Low (UX consistency) | New list pages nested the full `.empty-state` block (with its own padding/centering) inside `td.empty`, unlike every existing dashboard table which uses plain muted text. | Standardized table empty cells in research/xss/kb/reports.html to the existing convention (plain text + a small `.empty-hint` line). |
| F3 | Low (data correctness) | `nuclei_candidate` / `public_exploit` were rendered via `is true`/`is false`, which mislabels a non-boolean persisted value (e.g. the string `"True"`) as `no`. The deterministic report renderer uses tri-state yes/no/unknown. | Added a `tri_bool` macro (whitelisted yes/no/unknown, aligned with the renderer) and used it for Public exploit, Nuclei candidate, and the research-list Nuclei column. |
| F4 | Low (data correctness) | Research-detail Nuclei "Decision" rendered a blank cell when a results artifact lacked a `decision` key. | Use `.get('decision')` with a `—` fallback. |

### Audited — no change needed

- **Reflected XSS via query params**: all list pages echo `q`,
  `severity`, `status`, `type`, `context`, `cve`, `tag`, `sort`,
  `direction` into attributes; Jinja autoescape + the `sort_link`
  macro's `urlencode` handle them. Empirical probe with
  `"><script>...` across all endpoints → none reflected raw, all
  HTML-entity-escaped.
- **XSS via persisted content**: hostile KB content, research text,
  report Markdown, and XSS candidate fields (incl. test idea, sinks,
  sources, evidence, references) rendered into a temp data dir →
  all pages 200 and raw `<script>` never present.
- **`|safe`**: zero occurrences in all 9 new templates (matches were
  only comments saying "no |safe").
- **Markdown safety**: report/KB content shown in escaped `<pre>`
  only; no Markdown→HTML renderer exists or was added; no
  `|safe`; `Content-Disposition` filename is a `CVE_RE`-validated id.
- **Path/traversal**: CVE validated with existing `CVE_RE`; report
  path confined under `ai_data/reports`; XSS ids `^xss-[0-9a-f]{16}$`;
  KB ids `^kb-[0-9a-f]{16}$` and resolved only through the
  KnowledgeStore index (never built into a filesystem path). Verified
  HTTP-level `..` and malformed ids → 400/404, no file served.
- **Secrets / internal paths**: no `.env`, `openrouter`, `sk-or-`,
  traceback, or absolute path in any page body (test-enforced).
  The pre-existing `?api_key=` link-propagation convention is
  unchanged.
- **Legacy XssFindings**: not imported/queried anywhere in D2/D3
  code; no `XssFindings`/Mongo read in the new files (grep-verified).

## Security review

Every new route carries `Depends(verify_api_key)` and the global
`APIKeyMiddleware` still gates `/api/*` and `/ui/*` (401 verified on
all new routes without a key). No control was weakened. Escaping,
traversal confinement, and secret hygiene are confirmed above. No
subprocess/network/LLM/Nuclei-execution/Mongo-write present in new
code (AST/string audit clean).

## Trust-boundary review

Verified each research surface carries an explicit distinction:

- Research list/detail: banner `RESEARCH ONLY — NOT A PRODUCTION
  FINDING`; evidence badge `persisted research notes — not verified
  output`; Nuclei badge `offline artifacts only — nothing executed
  here`; detail footer restates the requirement of production
  verification.
- XSS list: `RESEARCH CANDIDATES — NOT PRODUCTION FINDINGS`; detail:
  banner + per-candidate disclaimer; test idea rendered inside a
  dashed-red **quarantine panel** labelled `UNTESTED RESEARCH IDEA —
  NEVER EXECUTED`, escaped, with an explicit "not executed/scanned"
  note.
- Reports list/detail: `RESEARCH REPORTS — NOT PRODUCTION FINDINGS`.
- Legacy Mongo `XssFindings` never surfaced (grep + no route).

## API/UI contract review

- Templates reference only fields the D2 layer actually returns
  (research list/detail, KB metadata/content/provenance, XSS
  compact/detail, report metadata/markdown). No missing or
  misspelled fields found; `cvss_vector`, `nuclei_decision`,
  `attack_requirements`, `root_cause`, `summary`, `provenance`,
  `source_evidence`, `sinks`, `sources`, `preconditions`,
  `unknowns`, `test_idea`, `references` all wired correctly.
- Link integrity: crawled every internal `/ui/...` href emitted by
  the four list pages → zero broken links (research detail, KB
  detail, XSS detail, report view/download all resolve).
- Pagination/filters preserved: `_pagination`/`sort_link` carry
  `q`, `severity`, `status`, `type`, `context`, `cve`, `tag`,
  `sort`, `direction`; filter value is re-rendered into the form on
  re-submit (tested).

## Data-correctness review

- Persisted values shown verbatim (escaped); missing values render
  `—` / `Unknown` / `unknown`, never invented.
- Severity badge colours are derived for presentation only; the
  original severity string is always shown unchanged.
- KB provenance preserved (per-source id/url/type + per-claim
  confidence/evidence); XSS evidence/sinks/sources/KB references
  preserved; report bytes returned unchanged (UI + download).
- No fake timestamps/metrics; KB `indexed_at`/`published_at` shown as
  stored.

## Performance review

- List pages are metadata-only: reports list never reads bodies;
  KB list never reads document content; XSS list reads only the
  candidate JSON heads; pagination always capped at 100 and offset-
  sliced.
- Per-row work is bounded (`has_report` is an existence check per
  visible row; `nuclei_summary` reads ≤3 small confined files).
- `get_overview()` is 10-second cached; dashboard call is fail-soft.
- **Known (low, not fixed — per non-premature-optimization policy)**:
  the `/ui/research` list does a full research-corpus scan in
  `list_research`, a second full scan in `research_stats`, and
  `get_overview()` re-globs the dir — only `get_overview` is cached.
  At the current corpus (single-digit CVEs) this is negligible;
  recommend caching `research_stats()` (10s, same pattern) if the
  corpus grows. No N+1 over large collections anywhere.

## Error / empty-state review

- Empty states: research, XSS, KB, reports each render a clear
  "no … match / no persisted …" message (standardized to the
  existing table convention) — verified via `?q=zzz` and empty
  corpus.
- Missing artifacts: missing CVE / candidate / KB doc / report →
  404 page; malformed identifiers → 400 page. Both render a generic
  `error_panel` with **no** filesystem path, stack trace, or secret
  (test-enforced).
- One pre-existing semantic nit (not fixed): a corrupt/over-budget KB
  store causes `list_kb` to surface "knowledge store unavailable" as
  a 400 (client-oriented) rather than 500; message stays generic.
  Changing it would alter the shared D2 error taxonomy → out of
  scope for a review fix.

## Existing-dashboard regression

Ran the full existing suite (`test_routers_fixes`, `test_dashboard_logic`,
`test_page_render`, `test_change_events`, `test_tz`, `test_ui_redesign`)
— all green. D3 touched existing pages only additively (nav keys in
three `_ctx` functions, a fail-soft research panel on the dashboard,
sidebar group). No behavior change to Overview/Programs/Domains/HTTP/
URLs/Endpoints/Parameters/DNS/Changes/Runs/Tasks/System was introduced
or observed.

## Visual verification

No browser or screenshot tooling is available in this headless WSL
environment. Explicitly stated per the task. All UI assertions rely on
TestClient + HTML inspection: dark-console theme classes reused
(`panel`, `tbl`, `badge`, `stat-card`, `kpi-grid`, `search-bar`,
`pager`, `empty-state`), monospace CVE/ids, severity/status badges,
banners, quarantine panel, and horizontal-scroll tables all confirmed
in rendered markup.

## Fixes summary — files changed (this stage)

- `backend/research_data.py` — F1 sort-direction fix (untracked file,
  modified).
- `web/templates/macros.html` — added `tri_bool` macro (F3).
- `web/templates/research.html`, `research_detail.html` — F2 empty
  state, F3 tri-bool, F4 Nuclei decision fallback.
- `web/templates/xss.html`, `kb.html`, `reports.html` — F2 empty
  state (and unused-macro import cleanup).
- `tests/test_research_api.py` — no net change (added then removed
  invalid API-sort tests; API does not expose sort).
- `tests/test_research_ui.py` — added end-to-end sort-toggle
  regression test; adjusted empty-state assertion.

## Exact tests run

| Suite | Result |
| --- | --- |
| tests.test_research_api | pass |
| tests.test_research_ui | pass |
| tests.test_routers_fixes | pass |
| tests.test_dashboard_logic | pass |
| tests.test_page_render | pass |
| tests.test_change_events | pass |
| tests.test_tz | pass |
| tests.test_ui_redesign | pass |
| **Backend/API/UI total** | **155** |
| ai.test_research_cli | pass |
| ai.test_research_ingestion | pass |
| ai.test_xss_researcher | pass |
| ai.test_xss_agent | pass |
| ai.test_reports_renderer | pass |
| ai.test_knowledge_store | pass |
| ai.test_xss_llm_researcher | pass |
| ai.test_openrouter | pass |
| **AI total** | **149** |

`git diff --check` → clean.

## Known remaining issues

1. Research-page stats triple directory scan (low; recommend caching
   `research_stats()` when corpus grows). Not changed per fix policy.
2. `build_url` does not URL-encode values (pre-existing, dashboard-
   wide; self-link URL quality only, not XSS — autoescaping prevents
   attribute breakout). Not changed.
3. Corrupt KB store surfaces as 400 "knowledge store unavailable"
   (semantic misclassification, generic message; out-of-scope to
   alter shared error taxonomy).
4. Reports list "Availability" column is always `yes` by construction
   (list only contains existing reports) — benign, kept for spec
   column parity.

## Untouched-code confirmation

Explicitly NOT modified: `database/` schema; `ns/`; `crawl/`;
collectors; `ai/execution/`, `ai/finding/`, `ai/verification/`,
`ai/live_validation/`, `ai/researcher/`, `ai/schemas/` (5B–5J and
live-validation surfaces); Nuclei execution; task runner/registry;
authentication semantics (`verify_api_key`, `APIKeyMiddleware`);
research execution logic (only read-only data-layer helpers and a
sort fix were touched). No Git operations performed (no commit/push).

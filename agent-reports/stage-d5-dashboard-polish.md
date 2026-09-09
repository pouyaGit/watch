# Stage D5 — Dashboard Polish & Real Research Data Integration — Report

## Summary

Stage D5 turned the D3 research dashboard (reviewed GO in D4) into a
polished operator-facing surface over the real persisted data in
`ai_data/`. This was a product/polish stage: no architecture change, no
auth change, no new packages, no Markdown rendering, no write/execution
paths. The dashboard was already strong, so changes are deliberately
surgical — three template presentation tweaks plus three focused tests.
HTMX was explicitly left unchanged (see § HTMX).

Pre-existing D5 groundwork found in the working tree (Stage D5 CSS
section, filter chips, detail grids, evidence cards, quarantine panel,
and 12 screenshots in `agent-reports/stage-d5-screenshots/`) was
verified rather than rebuilt; this stage's edits layer on top of it.

## What changed (this stage only)

1. **Dashboard research strip — humanized XSS status breakdown**
   (`web/templates/dashboard.html`, one line).
   The strip rendered raw persisted status tokens
   (`insufficient_evidence: 1 · rejected: 1 · research_candidate: 1`).
   It now renders `st | lower | replace('_', ' ')`, i.e.
   `insufficient evidence: 1 · rejected: 1 · research candidate: 1`.
   Presentation-only; persisted values and the D2 API are untouched.

2. **Research detail — Nuclei panel scannability**
   (`web/templates/research_detail.html`, two rows).
   - Decision (`GOOD_CANDIDATE`) now renders in the existing `badge-sm`
     chip instead of plain text (same fallback chain as before:
     `nuclei_decision`, else results-artifact `decision`, else `—`).
   - Validation booleans now render via the existing `tri_bool` macro
     (`semantic=yes · template=yes`) instead of Python `True`/`False`.
     Missing values still render `—`. No CSS added, no macro added.

3. **Report detail — download action prominence**
   (`web/templates/report_detail.html`, one class).
   The `⬇ Download .md` action was `btn-ghost`; it is now
   `btn-primary`. The Markdown itself is still escaped plain text in
   `<pre>` — no rendering change.

4. **Tests** (`tests/test_research_ui.py`, new `TestResearchUiPolish`
   class, 3 tests — existing tests untouched):
   - dashboard XSS breakdown contains no raw snake_case tokens and
     shows the humanized breakdown plus real strip counts;
   - research detail shows the `GOOD_CANDIDATE` badge chip and
     `semantic=yes` / `template=yes` with no `True`/`False` leak;
   - report detail keeps the escaped `<pre>` view with a prominent
     `btn-primary` download action.

## Files changed (this stage)

- `web/templates/dashboard.html` — 1-line XSS status humanization.
- `web/templates/research_detail.html` — Nuclei decision chip +
  yes/no validation rendering.
- `web/templates/report_detail.html` — download `btn-ghost` →
  `btn-primary`.
- `tests/test_research_ui.py` — appended `TestResearchUiPolish`
  (3 tests); no existing test modified.

## Real-data surfaces verified (TestClient, no mocks)

Persisted corpus: 4 research CVEs (`CVE-2026-1557`, `CVE-2026-78203`,
`CVE-2026-78205`, `CVE-2026-78207`), 3 XSS candidates
(`xss-0df9…` REJECTED / `xss-488f…` INSUFFICIENT_EVIDENCE /
`xss-60ed…` RESEARCH_CANDIDATE 0.90), 1 KB document
(`kb-609f38e9c57c0592`), 1 report (`CVE-2026-1557.md`, 5620 B),
Nuclei artifacts 1 generated / 1 results / 1 findings.

- `/` strip: `Research CVEs 4`, `Public Exploits 2`, `Nuclei
  Candidates 1` (+ `1 gen · 1 res · 1 find`), `XSS Candidates 3` (+
  humanized per-status breakdown), `KB Documents 1`, `Reports 1`.
- `/ui/research`: all 4 CVE ids, titles, severity strings
  (`High (CVSS 7.5)`, `Critical`), CVSS scores (7.5, 9.3), `report`
  link only for CVE-2026-1557, `completed` status for CVE-2026-78205,
  severity/status filters + removable chips + pagination intact.
- `/ui/research/CVE-2026-1557`: title, `CVSS:3.1/AV:N/…` vector,
  CWE-22, `image_handler.php` endpoint, `src` parameter, programs
  (dell/indeed), `discovered 5 · fetched 5`, assessments 4,
  `GOOD_CANDIDATE` chip, `semantic=yes · template=yes · runs=4 ·
  findings=4`, `0 record(s)` findings artifact (real empty persisted
  list), deterministic-report link, scope/limitations panel.
- `/ui/xss`: 3 ids, REJECTED / INSUFFICIENT / CANDIDATE badges,
  confidence meters incl. 0.90, type/context/query/top-evidence
  columns, filters + chips.
- `/ui/xss/xss-60edf609e21c6b41`: confidence 0.90, reflected /
  html_attribute, quarantined `UNTESTED RESEARCH IDEA — NEVER
  EXECUTED` test idea in escaped `<pre>`, KB evidence refs
  (`kb-0958da2bb9935000`), sinks/sources, preconditions/unknowns.
- `/ui/kb` + `/ui/kb/kb-609f38e9c57c0592`: id, mixed-case title as
  stored, `local://ai_data/research/CVE-2026-1557.cli.json` source,
  `UNKNOWN` evidence quality, `cve:CVE-2026-1557` tag, 1 provenance
  source with `1 claim(s)` and `confidence=0.0`, plain-text content
  block (no HTML rendering).
- `/ui/reports` + `/ui/reports/CVE-2026-1557` (+ `/download`):
  artifact name + byte size, escaped `<pre>` Markdown, prominent
  download returning `attachment` with identical bytes.
- No fabricated values anywhere: missing statuses render `—`,
  missing booleans `unknown`, empty findings `0 record(s)`.

## UX improvements (incl. pre-existing D5 groundwork verified)

- Research overview strip: 6 real-metric cards, fail-soft
  (`pages.py` try/except → strip hidden if data unavailable), offline
  note + API link; XSS breakdown now human-readable.
- Research list: severity/CVSS badges + numeric CVSS, tri-state
  exploit, Nuclei decision-or-tri-state, report-availability badge,
  date + full-timestamp tooltip, sortable CVE/Title/CVSS/Researched
  with direction arrows, removable active-filter chips, top+bottom
  pagers, existing-table empty convention.
- Research detail: summary-first hierarchy, Vulnerability / Watch
  Relevance / Evidence / Detection / References / Nuclei / Report /
  Scope panels, prominent RESEARCH ONLY banner + footer disclaimer,
  Nuclei decision chip + yes/no validation (this stage).
- XSS: status badges + confidence meters scannable; test idea
  quarantined in dashed-red panel, escaped; KB provenance links kept.
- KB: metadata vs summary vs plain-text content vs per-source
  provenance visually separated; exact persisted values preserved.
- Reports: list shows artifact + size with view/download; detail keeps
  escaped `<pre>` with max-height scroll; download now primary.
- Layout: existing `table-wrap` horizontal scroll on all tables,
  `detail-grid` 2-col ≥1100px / stacked below, existing CSS classes
  reused throughout — zero new CSS rules added this stage, zero new
  packages, zero SPA/build tooling.

## HTMX

Left unchanged, deliberately. List pages use plain link/form
navigation (the dominant existing dashboard pattern); the only HTMX on
the dashboard is the pre-existing system-health poll. No fragment
endpoint was small and useful enough to justify new surface here.

## Security boundaries preserved

- Auth: `verify_api_key` + `APIKeyMiddleware` untouched; all UI routes
  still `Depends(verify_api_key)`; 401-without-key covered by tests.
- Read-only: no new imports (no subprocess/network/LLM/Nuclei
  execution/Mongo/KB writes); no 5B–5J, `ai/execution/`,
  `ai/verification/`, `ai/live_validation/` contact.
- Escaping: zero real `|safe` filters in any touched template (only
  the word appears inside header comments); Markdown/KB content stays
  escaped `<pre>`; references plain text, never anchors; report
  download filename is `CVE_RE`-validated.
- Trust boundaries: RESEARCH ONLY / NOT A PRODUCTION FINDING banners
  on every surface; XSS quarantine panel intact; legacy Mongo
  `XssFindings` never read or surfaced.
- Visual verification: prior screenshots
  (`agent-reports/stage-d5-screenshots/01–12`) re-inspected for
  dashboard, research list/detail, XSS list/detail, KB detail,
  report detail, and mobile overlay; remaining surfaces verified via
  TestClient HTML assertions (no browser tooling in this environment
  beyond image inspection).

## Tests run (exact results)

| Suite | Result |
| --- | --- |
| tests.test_research_ui (incl. 3 new D5 polish tests) | 39 pass |
| tests.test_research_api + test_routers_fixes + test_dashboard_logic | 61 pass |
| tests.test_page_render + test_ui_redesign | 26 pass |
| ai.test_research_cli + test_research_ingestion + test_xss_researcher + test_xss_agent + test_reports_renderer + test_knowledge_store | 87 pass |
| ai.test_xss_llm_researcher + ai.test_openrouter | 62 pass |
| AI total | 149 pass (matches D4 exactly) |

`git diff --check` → clean.

## Remaining low-priority issues (unchanged from D4, still out of scope)

1. Research-list stats do a full corpus scan per render
   (`research_stats()` is 10s-cached; negligible at 4 CVEs).
2. `build_url` does not percent-encode values (dashboard-wide,
   pre-existing; research UI uses its own encoding `_ui_link`).
3. Corrupt KB store surfaces as generic 400 (shared D2 error taxonomy;
   message stays generic, no leak).
4. Reports "Available: yes" is tautological by construction (kept for
   column parity).

## Untouched-code confirmation

Explicitly NOT modified or added this stage: authentication semantics
(`verify_api_key`, `APIKeyMiddleware`); 5B–5J; `ai/execution/`,
`ai/verification/`, `ai/live_validation/`; research execution logic;
database; `ns/`; `crawl/`; Nuclei/CVE functionality; Markdown
rendering (none exists, none added); React/Vue/SPA/build systems
(none added); legacy Mongo `XssFindings` (not surfaced); packages
(none added). No Git operations performed (no commit, no push).

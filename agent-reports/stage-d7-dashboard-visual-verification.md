# Stage D7 — Research Dashboard Visual Verification

## 1. Scope

Visual/UX verification of the completed D6 Research Navigation &
Dashboard Integration. No R15-R20 intelligence, scoring, state-machine,
persistence, API, DNS, or pipeline logic was modified. No Git operations
performed. No push. No new dependencies. No new frontend framework.

D6 baseline commit: `ac5fad8 feat(ui): integrate research intelligence navigation`.

Working tree was verified clean of D6-area changes before and after this
stage (`git diff --check` clean; the only unstaged modification in the
repo is the pre-existing, unrelated `database/db.py` Mongo connection
string, which was left untouched).

## 2. Pages inspected (rendered HTML via TestClient + template/CSS review)

All pages returned HTTP 200 with the real local research corpus:

| # | Page | Status | Intelligence visible | Sidebar active | Cross-navigation |
|---|---|---|---|---|---|
| 1 | `/` (Dashboard) | 200 | Yes - Research Intelligence, 8 cards | `dashboard` (1 link) | All 8 cards link out |
| 2 | `/ui/research` | 200 | Yes - KPI + R16/R18 strip + banner | `research` | XSS/Reports/Queue links |
| 3 | `/ui/research/queue` | 200 | Yes - PLANNING banner | `research-queue` | back link, Start/Open task |
| 4 | `/ui/research/tasks` | 200 | Yes - WORKFLOW banner | `research-tasks` | back link, CVE filter, row links |
| 5 | `/ui/research/CVE-2026-1557` | 200 | Yes - RESEARCH ONLY banner | `research` | Queue/Tasks(+count)/KB/Report; XSS absent (non-XSS CVE) |
| 6 | `/ui/xss` | 200 | Yes - CANDIDATES banner | `xss` | rows link to detail, chips work |
| 7 | `/ui/xss/xss-66d4b40bc1570361` | 200 | Yes - candidate banner | `xss` | Related research + Queue (validated CVE); none on CVE-less candidate |
| 8 | `/ui/kb` | 200 | Metadata table (see N2) | `kb` | per-row CVE links, Clear/chips |
| 9 | `/ui/kb/kb-609f38e9c57c0592` | 200 | Metadata + provenance | `kb` | research/queue/tasks links |
| 10 | `/ui/reports` | 200 | Yes - REPORTS banner | `reports` | view/download per CVE |
| 11 | `/ui/reports/CVE-2026-1557` | 200 | Yes - REPORT banner | `reports` | Research + Download .md |

Empty-state path verified: with `get_overview()` raising, `/` still
returns 200, shows "Research intelligence unavailable" in a compact
panel, and the Recon Overview KPI grid is unaffected.
## 3. Checklist results

- Research Intelligence section visible: PASS (8 cards, live counts).
- All cards have working links: PASS (all 6 research destinations found
  in dashboard HTML; every research page returns 200).
- Active sidebar state correct: PASS (exactly one `side-link active`
  per page; dashboard resolves to the Dashboard entry).
- Cards aligned and compact: PASS with note N1 (see section 4).
- Empty states look intentional: PASS (dashboard fail-soft panel,
  queue/tasks/reports empty copy, CVE no-report state).
- Status badges readable: PASS (whitelisted badge/sev/xss classes;
  amber research banners are high-contrast).
- CTA wording consistent: PASS (Start Research / Open task /
  CVE research / Queue view / Related research / research/queue/tasks
  arrows / View deterministic report / Download .md).
- Cross-navigation obvious: PASS (quick-action bars on CVE/task/XSS
  detail, back links on queue/tasks, inline links on KB/report).
- Broken links: NONE FOUND in the D6 link set (a full crawl of every
  internal href timed out in this sandbox, so verification was scoped
  to the D6 link set asserted by tests/test_research_navigation.py
  plus per-page 200 checks - all green).
- Raw HTML escaping: PASS (no `|safe` in research templates;
  report/XSS/KB bodies render in escaped `<pre>`; no raw
  `<script>alert` in rendered CVE detail).
- API key exposure: NO NEW EXPOSURE. `?api_key=` propagation is the
  pre-existing dashboard-wide `build_url` convention (recon pages too,
  documented in the footer). D6 added no secret material and no new
  propagation mechanism (47 occurrences in dashboard HTML, all
  conventional).
- Mobile/narrow layout: NO CATASTROPHIC BREAKAGE. `viewport` meta
  present; `kpi-grid` collapses 8/6/4/2 columns at breakpoints;
  `table-wrap` scrolls wide tables; `quick-actions` wraps; sidebar is
  off-canvas with overlay + burger toggle.

## 4. Issues found

### N1 (cosmetic note, NOT fixed - no churn per D7 rules)
The Research Intelligence strip renders 8 cards inside a `kpi-6` grid
(`repeat(6, 1fr)` at >=1280px), so the last two cards wrap to a second
row of 2. This is the deliberate D6 content decision (8 destinations;
4+4 / 2-column stacking below the breakpoint) and reads as an
intentional two-row strip, not a break. Dropping two cards or adding a
`kpi-8` variant would be cosmetic churn with information-loss
trade-offs. Left as-is.

### N2 (informational, NOT a defect - NOT fixed)
`/ui/kb` (KB index table) carries no `research_banner`. This matches the
pre-existing D3 design: the KB index is metadata-only with source URLs
as non-clickable plain text, and banners sit on detail/candidate
surfaces where misinterpretation risk is higher. Not a D6 regression.
Left as-is.

### Pre-existing dashboard quirk (NOT a defect - NOT fixed)
The Dashboard sidebar entry highlights by matching the `href` including
the propagated `?api_key=` string; emitted HTML shows a single correct
active link, so there is no user-visible issue. Changing `build_url`
matching would touch shared recon navigation outside D7 scope.

### Pre-existing test failures (NOT caused by D6/D7, NOT fixed)
`tests/test_research_ui.py` has 2 corpus-dependent failures
(`test_research_sort_toggle_inverts_order`,
`test_dashboard_xss_status_breakdown_humanized`), confirmed present on
the clean tree without D6 changes during the D6 checkpoint (stash test).
Untouched per D7 scope rules.
## 5. Fixes made

None. Everything verified good; per the D7 brief ("If everything is
already good: DO NOT make cosmetic churn"), no template, CSS, route,
or logic file was modified. `git diff --check` is clean and the working
tree contains zero D7-area modifications.

## 6. Screenshots

No browser screenshots were captured: this environment has no running
HTTP server or browser tooling wired to it, and all verification was
done against server-rendered HTML via TestClient plus direct
template/CSS inspection, which is the authoritative output of the
Jinja architecture. Rendered lengths observed (full renders):

- `/` -> 200, ~14.9 KB; `/ui/research` -> 200, ~22.3 KB
- `/ui/research/queue` -> 200, ~13.7 KB; `/ui/research/tasks` -> 200, ~9.3 KB
- `/ui/research/CVE-2026-1557` -> 200, ~26.9 KB
- `/ui/xss` -> 200, ~15.9 KB; `/ui/kb` -> 200, ~42.2 KB
- `/ui/reports` -> 200, ~13.0 KB
- `/ui/xss/xss-66d4b40bc1570361` -> 200, ~22.0 KB
- `/ui/kb/kb-609f38e9c57c0592` -> 200, ~14.9 KB
- `/ui/reports/CVE-2026-1557` -> 200, ~13.8 KB

## 7. Tests

- `git diff --check` - clean (before and after; no D7 edits).
- `tests.test_research_navigation` - 14/14 OK (D6 focused suite).
- `tests.test_research_workflow` - 32/32 OK (regression).
- `tests.test_research_intelligence_ui` - 19/19 OK (regression).
- Manual render checks (TestClient): all 11 pages 200, exactly one
  active sidebar link each, all 8 dashboard cards + links present,
  empty-state fail-soft confirmed, no unescaped payload HTML,
  responsive CSS rules confirmed.

## 8. Final verdict

PASS - ship D6 as-is. The Research Intelligence section is visible
with 8 correctly linked cards; sidebar highlighting is
exactly-one-active on every research page; cross-navigation (CVE to queue/tasks/KB/report, CVE -> XSS only when applicable, XSS ->
research only for validated CVEs) is obvious and consistent; empty
states, badges, banners, CTAs, escaping, and narrow-layout behavior
all meet the brief. Notes N1/N2 are consciously left unfixed to avoid
cosmetic churn. No code changes were required or made.

## Agent / Model

- Stage: D7
- Role: Research Dashboard Visual Verification
- Git operations: none performed. Push: none.

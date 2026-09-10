# Stage D8 — Fix Research Navigation and Recent Operations

## 1. Scope

Fixed only the dashboard UI/navigation integration defects identified in D8:

- broken Research sidebar destinations on pages rendered by some routers
- the "Recent Operations" panel not being resilient to per-operation
  data-source failures

No R15–R22 intelligence/algorithm/state-machine/persistence code was
touched. No LLM, network, Nuclei, active validation, production findings,
alerts, or Git operations were performed.

## 2. Reproduction (before the fix)

Reproduced with the existing `TestClient`/routes/templates. Mongo-backed
dashboard queries were mocked so renders are offline and deterministic.

### 2.1 Sidebar href audit (rendered HTML)

Every Research sidebar `<a class="side-link" ...>` was extracted from the
rendered pages. Findings:

| Page (router) | Research / CVEs | Queue | Tasks | Leads | **Plans** | XSS | KB | Reports |
|---|---|---|---|---|---|---|---|---|
| `/` (pages.py) | OK | OK | OK | OK | **OK** | OK | OK | OK |
| `/ui/research` (research_pages.py) | OK | OK | OK | OK | **OK** | OK | OK | OK |
| `/ui/runs` (runs.py) | OK | OK | OK | OK | **`href=""`** | OK | OK | OK |
| `/ui/domains` (programs.py) | OK | OK | OK | OK | **`href=""`** | OK | OK | OK |

Concrete pre-fix rendering on `/ui/runs`:

```
Research Leads   href='/ui/research/leads?api_key=<key>'
Research Plans   href=''
```

An empty `href` resolves to the current page, so "Research Plans" did
nothing on any page rendered by `backend/routers/runs.py` and
`backend/routers/programs.py` (Runs, Live Domains, HTTP, URLs, Endpoints,
Parameters, DNS Bruteforce status, per-program/detail pages, fresh/provider/
tech pages).

### 2.2 Route resolution / precedence

All eight destinations exist and resolve:

```
200 /ui/research
200 /ui/research/queue
200 /ui/research/tasks
200 /ui/research/leads
200 /ui/research/plans
200 /ui/xss
200 /ui/kb
200 /ui/reports
```

The specific routes are declared before the generic dynamic routes in both
routers, so precedence was already correct:

- `backend/routers/research_pages.py`: `/ui/research/queue`, `/tasks`,
  `/tasks/{id}`, `/leads`, `/leads/{id}`, `/plans`, `/plans/{id}` are all
  declared before `/ui/research/{cve}`; the handler comment for the generic
  route notes this ordering.
- `backend/routers/research.py`: `/api/research/tasks|queue|leads|plans`
  are declared before `/api/research/{cve}`.

No route duplication was introduced.

### 2.3 Recent Operations

`backend/routers/pages.py::dashboard()` builds the panel from
`backend/dashboard.py::latest_runs()`. That function looped over the six
registered operations and called `get_task_status()` / `get_last_run()`
without guarding individual rows. A single failure in any operation's
status/run source raised out of `latest_runs()`; the dashboard's outer
`try/except` then replaced the entire list with `[]`, so the panel rendered
"No tasks registered." instead of the real six-operation state.

The six registered operations (source of truth:
`backend/tasks_registry.py`) are:

- `crawl_all` — Crawl All (full corpus)
- `crawl_fresh` — Crawl Fresh (last 24h live subs)
- `param_discovery` — Parameter Discovery (x8)
- `dns_precheck` — DNS Bruteforce Precheck
- `dns_static` — DNS Bruteforce (static wordlist)
- `dns_dynamic` — DNS Bruteforce (dynamic / AlterX)

## 3. Root causes

1. **Research sidebar links.** The R22 commit added
   `<a ... href="{{ plans_url }}">Research Plans</a>` to `base.html`, but
   `plans_url` was only added to the `_ctx()` builders in
   `backend/routers/pages.py` and `backend/routers/research_pages.py`.
   `backend/routers/programs.py` and `backend/routers/runs.py` each keep
   their own `_ctx()` copy without `plans_url`, so Jinja2 rendered the
   undefined variable as an empty string on every page those routers render.

2. **Recent Operations.** `backend/dashboard.py::latest_runs()` was not
   fail-soft per operation. Any one operation's missing/malformed/erroring
   status or run source propagated up and blanked the whole panel. Rendering
   itself was correct (status/last run/duration/NEVER were already wired via
   `_run_to_dict` and the `status_badge` macro); the data assembly was the
   fragile part.

## 4. Exact fix

`backend/routers/programs.py`
- added `"plans_url": build_url("/ui/research/plans")` to `_ctx()`.

`backend/routers/runs.py`
- added `"plans_url": build_url("/ui/research/plans")` to `_ctx()`.

`backend/dashboard.py::latest_runs()`
- made assembly fail-soft **per operation**: `get_task_status()` and
  `get_last_run()` are wrapped individually; a failure falls back to the
  no-run state (`status="idle"`, `last_run=None`) for that row only.
- `_run_to_dict()` is also guarded, so a malformed run payload degrades to
  an empty run rather than raising.
- no timestamps are invented; a fallen-back row renders as
  status `NEVER`, last run `—`, duration `—` (existing template behaviour).

`tests/test_dashboard_navigation.py` (new)
- focused D8 regression suite (see section 7).

The shared trusted URL builder `backend/deps.py::build_url()` is used for
the added links, preserving the existing `?api_key=` propagation convention.

## 5. Routes verified

Pages (all HTTP 200, real local research corpus):

- `/ui/research`, `/ui/research/queue`, `/ui/research/tasks`,
  `/ui/research/leads`, `/ui/research/plans`
- `/ui/xss`, `/ui/kb`, `/ui/reports`
- `/ui/runs` (offline render, task/DNS queries mocked)
- `/` dashboard (offline render, recon queries mocked)

Detail / cross-navigation:

- lead `rl-af7ecfba1a86fc83` → 200, links to plan `r22-38d26f10681e9a0f`
- plan `r22-38d26f10681e9a0f` → 200, `CVE-2026-1557 → dell`,
  `recommended_start = REVIEW_PUBLIC_POC`, banner "NOT VERIFIED" (no
  vulnerability claim)
- CVE `CVE-2026-1557` → links to queue, tasks, KB, its lead, its plan;
  no XSS link (non-XSS CVE, existing safe applicability rule preserved);
  XSS link present for `CVE-2024-5376`

Sidebar hrefs on `/`, `/ui/runs`, `/ui/domains`, `/ui/research` all point at
the exact eight destinations and are non-empty.

## 6. Recent Operations verification

With the real six-operation registry and mocked run data,
`latest_runs()` returns exactly:

```
crawl_all       Crawl All (full corpus)
crawl_fresh     Crawl Fresh (last 24h live subs)
param_discovery Parameter Discovery (x8)
dns_precheck    DNS Bruteforce Precheck
dns_static      DNS Bruteforce (static wordlist)
dns_dynamic     DNS Bruteforce (dynamic / AlterX)
```

Rendering verified for:

- successful operation → `✓ SUCCESS` + real duration (`2h 14m`)
- failed operation → `✗ FAILED` + real duration (`5m`)
- never-run operation → `NEVER`, last run `—`, duration `—`
- API-key / malformed row: a row claiming a run but with `last_run=None`
  renders `SUCCESS` + `—`/`—` without error (no fabricated timestamp)
- fail-soft: with `get_task_status`/`get_last_run` raising, all six rows are
  still returned in registry order with `status="idle"`, `last_run=None`

"All runs →" resolves to `/ui/runs` (the real HTML Runs page), never
`/api/runs/recent`.

## 7. Tests / results

New suite: `tests/test_dashboard_navigation.py` — 21 tests, all passing.

Coverage:

- Sidebar: all eight Research destinations present + non-empty href +
  exact path; every destination route returns 200; specific routes not
  swallowed by `/ui/research/{cve}` (UI and API); "no dead Research links".
- Cross navigation: dashboard → leads/plans; lead → plan + CVE;
  plan → CVE + lead + `REVIEW_PUBLIC_POC`; CVE → queue/tasks/KB/lead/plan;
  CVE → XSS only when applicable.
- Recent Operations: all registered operations; fail-soft per operation;
  success/failed/never + duration; malformed run data; no fabricated
  timestamp for never-run.
- All Runs: href points at `/ui/runs` (not an API/dead URL); page renders.
- Security: `api_key` never on external hrefs; hostile operation name
  escaped; no open redirect; invalid plan/lead ids rejected (no arbitrary
  path generation).

Required existing suites (single combined run):

```
Ran 192 tests in 30.081s
OK
```

including `tests.test_research_navigation`,
`tests.test_research_intelligence_ui`, `tests.test_research_workflow`,
`tests.test_research_api`, `tests.test_research_leads`,
`tests.test_research_execution`, plus the new D8 suite.

Additional dashboard regression run
(`test_dashboard_logic`, `test_page_render`, `test_routers_fixes`,
`test_ui_redesign`): 58 tests, 55 pass, 3 pre-existing errors — all
`ServerSelectionTimeoutError` from un-mocked Mongo calls
(`test_domains_page_200`, `test_program_detail_200`,
`test_lookup_matches_program_name`), unrelated to this change.

`tests.test_research_ui`: 39 tests, 37 pass, the 2 pre-existing
corpus-dependent failures already documented in the D7 report
(`test_research_sort_toggle_inverts_order`,
`test_dashboard_xss_status_breakdown_humanized`). Not modified.

`git diff --check`: clean.

## 8. Security review

- **API-key propagation.** The existing dashboard-wide convention
  (`build_url` appends `?api_key=`) is preserved unchanged. The two added
  links use `build_url`, so their context matches every other nav link.
- **No key leakage to external URLs.** All rendered `<a href>` values on
  the dashboard were audited: there are no absolute external `<a href>`s
  carrying `api_key`; external resources (Tailwind/htmx/Alpine) are
  `<script src>` with no key. API docs (`/docs`) is a local path.
- **Escaping.** Operation names come from the static registry and still
  pass through Jinja autoescaping; a hostile `name` renders escaped
  (`&lt;script&gt;`), verified.
- **No open redirect.** Research GET pages ignore `next`/`redirect`
  parameters; no 3xx/`Location` is emitted.
- **No arbitrary path generation.** Plan/lead ids are regex-validated
  (`^r22-[0-9a-f]{16}$`, `^rl-[0-9a-f]{16}$`); invalid ids return 400/404
  and never leak filesystem paths.
- No credential material was printed or logged during testing.

## 9. Limitations

- `latest_runs()` still performs one status + one run query per operation,
  i.e. up to 12 Mongo round-trips (2 per registered operation) on every
  dashboard render. This is the existing data-source shape; D8 only made the
  assembly fail-soft and did not change query behaviour or performance.
- Fail-soft degrades a row to the no-run state when its source errors; it
  does not retry or reconcile a partially-readable run.
- The per-router `_ctx()` nav builders remain duplicated across
  `pages.py`, `programs.py`, `runs.py`, and `research_pages.py` (existing
  pattern). D8 restored the missing `plans_url` key in the two that lacked
  it; a future refactor could centralize nav context to prevent this class
  of drift.
- Local verification ran without a live MongoDB; Mongo-backed dashboard and
  Runs-page paths were verified with mocked data using the real registry.
  Research pages were verified against the real on-disk corpus.

## 10. Explicit confirmations

- No R15–R22 logic changes.
- No LLM usage.
- No network requests.
- No Nuclei execution.
- No active validation.
- No production findings.
- No alerts.
- No Git operations (no commit, no push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: D8
- Role: Dashboard Navigation and Recent Operations

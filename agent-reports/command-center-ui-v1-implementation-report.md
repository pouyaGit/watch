# WATCH Command Center UI v1 — Implementation Report

## 1. TASK

Build the first real operational Command Center UI for Watch, consuming
real Watch data exposed by the existing project. The UI must not be a mock
dashboard and must not fabricate metrics, activity, or security states.

Scope of this task:

- Phase 1: understand the existing frontend/backend architecture.
- Phase 2: implement a Command Center with (A) system/runtime status,
  (B) research/watchlist status, (C) candidates, (D) recent activity.
- Phase 3: serious operations-dashboard UX with honest loading/empty/error
  states.
- Phase 4: prefer existing APIs; only a minimal, tested extension if needed.
- Phase 5: reuse the existing frontend stack.
- Phase 6: verify with real data, tests and build/render checks.
- Phase 7: no visual mock — the page must be connected to real data.

## 2. SUMMARY

The existing application is a FastAPI + Jinja2 + htmx + Alpine + Tailwind
(CDN) server-rendered dashboard (`api.py`, `backend/routers/*`,
`web/templates/*`, `web/static/*`). The recon dashboard at `/` already
surfaces recon KPIs, research intelligence and system health. The standing
CVE watchlist (`ai/research_agent/watchlist*.py`) had no UI at all.

A new **read-only Command Center page at `/ui/command`** was added. It
composes existing authorities only:

- **Runtime status** — the existing R83 bounded AI activity contract
  (`backend.research_activity.collect_activity`), the existing recon
  operation status (`backend.dashboard.latest_runs`), and the existing live
  host-resource htmx fragment (`/api/system/stats`). The Watch API status is
  `ONLINE` because the page was served by that API.
- **Watchlist status** — the latest persisted sweep snapshot per program,
  with CVE count, delta counts (NEW/CHANGED/UNCHANGED), asset-match state
  counts and deterministic evidence-readiness counts.
- **Candidates** — one row per watchlist candidate with the R30.1
  asset-match state/confidence, strongest observed match signal, component,
  version, version-association state, research status, evidence readiness,
  the concrete missing/partial evidence dimensions, delta, and snapshot time.
- **Recent activity** — a real timeline built only from persisted artifacts
  (watchlist sweeps, delta artifacts, acquired evidence) plus recon
  operations and research runs.

No security vocabulary was introduced or upgraded. Match states
(`CONFIRMED`/`SUPPORTED`/`WEAK`/`UNKNOWN`), readiness states
(`EVIDENCE_READY`/`EVIDENCE_PARTIAL`/`INSUFFICIENT_EVIDENCE`), blockers and
gap dimensions are surfaced verbatim from the existing stages. The page
carries an explicit `WATCHLIST RESEARCH ONLY — NOT CONFIRMED FINDINGS`
banner and never renders the words "Vulnerable" or "Exploitable".

The implementation is **additive**: the existing `/` dashboard, routes,
templates and behaviour are unchanged. The Command Center is reachable from
a new first-item sidebar link under "Overview".

## 3. FILES CHANGED

New files:

- `backend/watchlist_data.py` — read-only watchlist data layer.
- `backend/routers/command_center.py` — `/ui/command` page and
  `/api/command/overview` JSON projection.
- `web/templates/command_center.html` — the Command Center page.
- `tests/test_command_center.py` — focused offline tests.

Modified files:

- `api.py` — register the new router.
- `backend/routers/pages.py` — add `command_url` to the shared context.
- `backend/routers/programs.py` — add `command_url` to the shared context.
- `backend/routers/runs.py` — add `command_url` to the shared context.
- `backend/routers/research_pages.py` — add `command_url` to the shared
  context.
- `web/templates/base.html` — add the "Command Center" sidebar link.
- `web/static/css/custom.css` — append the `cc-*` Command Center styles.

No `ns/`, `crawl/`, `database/`, Nuclei/CVE, schema, or `ai/` source file
was modified.

## 4. IMPLEMENTATION DETAILS

### 4.1 Read-only data layer — `backend/watchlist_data.py`

Single place for watchlist-artifact filesystem logic, mirroring the existing
`backend/research_data.py` conventions (bounded, deterministic, fail-soft,
path-validated).

Artifacts read (existing writer conventions):

- `ai_data/research/watchlist/<program>/watch-<UTC>.json` — sweep snapshots.
- `ai_data/research/watchlist/<program>/delta-*.json` — delta artifacts.
- `ai_data/research/watchlist/evidence/<program>/wev-*.json` — acquired
  evidence results.

Root resolution honors the same environment overrides the watchlist CLI
uses (`WATCH_RESEARCH_WATCHLIST_DIR`, else
`WATCH_RESEARCH_RESEARCH_DIR/watchlist`), falling back to the local default.
Every snapshot/delta/evidence basename is validated against a fixed regex
before it is read.

Key functions:

- `parse_utc` — parses persisted `...Z` stamps to aware UTC; unparseable
  values return `None` (never an invented time).
- `list_programs` / `snapshot_paths` / `read_snapshots` — bounded discovery.
- `program_view` — latest snapshot state + candidate views.
- `overview` — bounded multi-program payload with honest
  `available`/`root_available` flags.
- `recent_activity` — newest-first activity from persisted artifacts only.

Evidence readiness is the **existing deterministic**
`ai.research_agent.watchlist_evidence_gaps.analyze_candidate/analyze_snapshot`
projection. Snapshot-to-snapshot changes reuse the existing
`ai.research_agent.watchlist_delta.compare_snapshots`. Nothing is
re-implemented and no new vocabulary is created.

### 4.2 Router — `backend/routers/command_center.py`

- `GET /ui/command` — server-rendered page (`verify_api_key` gated).
- `GET /api/command/overview` — bounded JSON projection of the same data
  (deliberately no credential-bearing URLs).

Composition is fail-soft per source: an unavailable activity collector
renders `UNKNOWN`, an unavailable Mongo-backed operation list renders no
operation rows. The HTML route attaches api-key-propagating research links
per candidate; the JSON route does not.

### 4.3 Template — `web/templates/command_center.html`

Extends `base.html` and reuses `macros.html` (`empty_state`,
`research_banner`). Sections:

- Runtime status KPI strip (Watch API, research runtime status/basis, last
  successful recon run, scheduler window) + live host resources via the
  existing htmx `/api/system/stats` fragment + the R83 daily-window rollup.
- Watchlist totals strip + per-program cards with delta / asset-match /
  readiness chip rows and non-`UNCHANGED` changes vs the previous snapshot.
- Candidates table with conservative state badges and explicit
  `missing:` / `partial:` evidence-gap chips.
- Real operational timeline with relative + absolute (Tehran) timestamps.

Empty states are explicit: no watchlist root → "No watchlist snapshots
available"; no candidates → "No candidates to show"; no activity → "No
activity observed".

### 4.4 API strategy

No existing endpoint was changed and `api.py` was not rewritten. The only
addition is the single read-only `/api/command/overview` route on the new
router. The page reuses the existing `/api/system/stats` htmx endpoint for
live host polling.

### 4.5 Evidence presentation

- Asset-match column header/comment scopes the R30.1 state as an asset
  match, not a vulnerability conclusion.
- Readiness uses the existing `INSUFFICIENT_EVIDENCE` /
  `EVIDENCE_PARTIAL` / `EVIDENCE_READY` vocabulary.
- Missing component identity, missing version identity, missing version
  association and missing watch signal remain individually visible as
  separate evidence dimensions.
- The page never emits "Vulnerable" or "Exploitable", and the banner marks
  all content as research-only.

## 5. TESTS RUN

Focused new tests:

```
python3 -m unittest tests.test_command_center
```

Existing regression tests:

```
python3 -m unittest tests.test_ui_redesign tests.test_dashboard_logic tests.test_routers_fixes
python3 -m unittest tests.test_research_api
python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
```

Real-data render verification (read-only, production watchlist dir):

```
WATCH_RESEARCH_WATCHLIST_DIR=/opt/watch/ai_data/research/watchlist \
  python3 -c "... TestClient(api.app).get('/ui/command') ..."
```

Compile / hygiene:

```
python3 -m py_compile backend/watchlist_data.py backend/routers/command_center.py tests/test_command_center.py
git diff --check
```

## 6. TEST RESULTS

- `tests.test_command_center` — **13 tests, OK**. Covers `parse_utc`,
  program discovery, honest empty root, candidate/evidence-gap merge,
  delta/match-state count fallback, malformed-artifact tolerance, real
  activity ordering, page render with real data, forbidden confirmation
  words absent, honest empty state, fail-soft activity collector, bounded
  link-free JSON projection, sidebar navigation, route resolution.
- `tests.test_ui_redesign + tests.test_dashboard_logic + tests.test_routers_fixes`
  — **51 tests, OK**.
- `tests.test_research_api` (isolated) — **29 tests, OK**.
- `ai.test_knowledge_store + ai.test_xss_researcher + ai.test_xss_llm_researcher + ai.test_openrouter`
  — **96 tests, OK**.
- Real-data render against `/opt/watch/ai_data/research/watchlist` —
  **HTTP 200**, the real snapshot `watch-20260919T203013Z` and the real
  candidates (`CVE-2020-11022`, `CVE-2025-22288`, ...) rendered with their
  real `VERSION_MATCH_WITHIN_SAME_FAMILY` association and
  `INSUFFICIENT_EVIDENCE` readiness; `missing: COMPONENT_IDENTITY` and
  `missing: TECHNOLOGY_IDENTITY` visible; no forbidden words. The three
  production snapshot files were unchanged after the read (read-only
  verified).
- `python3 -m py_compile` — OK. `git diff --check` — clean.

Known data-dependent failures **not caused by this change** (dev worktree
does not contain the gitignored production research artifacts):

- `tests.test_r82_research_dashboard_ui::TestRealCaseContract::*` — the
  referenced `ai_data/research/r77/...` case artifact is absent in the
  worktree (`ai_data/research/` is gitignored).
- `tests.test_component_binding::...test_15_real_local_dell_snapshot_unresolved`
  — `ai_data/research/watchlist/dell/watch-20260918T144218Z.json` is absent
  in the worktree.

These modules do not touch any file changed by this task.

Note on the existing test suite: several modules hard-code
`sys.path.insert(0, "/opt/watch")` and import `api`/`backend`, so a combined
`unittest` run mixes production and worktree modules. This is pre-existing;
the focused tests above were run in isolation to avoid that mixing.

## 7. REVIEW / VERIFICATION

- [x] Work performed only in `/opt/watch/.worktrees/watch-agent`.
- [x] Production checkout `/opt/watch` not modified (`git -C /opt/watch
      rev-parse HEAD` == `e671601...`, branch `main`, pre-existing
      uncommitted files untouched).
- [x] Existing production services not touched; no deploy, no push.
- [x] Real Watch data used (watchlist snapshots + R83 activity + recon
      operations + live host stats).
- [x] No fake metrics/activity introduced; empty/unavailable states are
      honest.
- [x] Existing frontend architecture reused (base shell, macros, CSS
      tokens, htmx, Tailwind CDN); no frontend framework replacement.
- [x] Existing backend architecture preserved; `api.py` not rewritten.
- [x] Conservative evidence model preserved; no confirmation inference.
- [x] Only intended files changed; `git diff --check` clean.
- [x] Build: this project has no JS/CSS build step (Tailwind CDN, static
      assets); the functional equivalent was verified by rendering the real
      page and all modified shell pages through `TestClient`.

Design decision: the Command Center is added as a new route
(`/ui/command`) rather than replacing `/`. The existing `/` dashboard is
covered by existing tests and remains the recon landing page; the Command
Center is the operational watchlist/runtime view, linked as the first
sidebar item. This keeps the change additive and backward compatible.

## 8. COMMIT STATUS

```
COMMIT STATUS:
  COMMITTED — 4f46a6cb33c9137434d3e6c78258eab2b00dd701
```

## 9. PUSH STATUS

```
PUSH STATUS:
  NOT PUSHED — MANUAL PUSH REQUIRED
```

## 10. READY TO PUSH

```
READY TO PUSH:
  YES
```

Implementation is complete, focused and regression tests pass, review is
complete, no blocker remains, only intended files were committed, and the
production checkout was not modified.

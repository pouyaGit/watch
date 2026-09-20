# Command Center Intelligence Layer v1 — Implementation Report

## TASK

Evolve the Watch Command Center (`/ui/command`) from a passive watchlist
dashboard into an operational security-research control center. Add five
intelligence focus areas without fabricating data and without duplicating
existing logic:

1. **Agent Operations Panel** — agent status, workspace, branch, latest
   mission/report, tmux/session state when available.
2. **Research Operations Panel** — watchlist status, latest snapshots, CVE
   states, evidence gaps, blockers, confidence levels.
3. **Findings Lifecycle View** — the Discovery → Metadata → Evidence →
   Verification → Review pipeline.
4. **Activity Timeline** — a normalized recent activity feed that now also
   includes agent report events.
5. **Backend/API** — reuse the existing Command Center architecture and data
   authorities; no duplicated logic.
6. **Tests** for all new functionality.
7. **Documentation** — this report.

Rules respected: only the agent workspace was modified; `/opt/watch` was never
touched; nothing was pushed or merged; all new logic is read-only.

## SUMMARY

The Command Center now composes three additional read-only projections on top
of the existing `backend.watchlist_data` candidate views, the existing R83
runtime activity contract, the existing recon operation status and the
existing htmx host-stats fragment.

Two new, single-responsibility data modules were added:

- **`backend/agent_operations.py`** — resolves the autonomous workspace
  (`WATCH_AGENT_DIR` else `<project root>/.worktrees/watch-agent` else the
  project root), reads the current branch directly from `.git/HEAD` (handles
  both a normal `.git` directory and a linked-worktree `.git` file), discovers
  the bounded `agent-reports/*.md` set, parses the existing report
  convention (`TASK`, `COMMIT STATUS`, `PUSH STATUS`, `READY TO PUSH`),
  normalizes report events for the timeline, and performs a best-effort
  read-only tmux server-socket probe. No subprocess, no network, no writes.
- **`backend/command_intelligence.py`** — deterministic aggregations over the
  existing candidate views:
  - `research_operations()` counts match states, confidence levels, research
    status, evidence readiness/state, evidence-gap dimensions and remaining
    blockers, and lists the latest per-program snapshot summaries.
  - `candidate_lifecycle()` maps one existing candidate onto the five research
    pipeline stages. Stage states describe research *progress only*
    (`COMPLETE` / `IN_PROGRESS` / `PENDING` / `BLOCKED` / `NOT_STARTED`); a
    persisted Markdown report marks the Review stage as `COMPLETE`. Nothing is
    a vulnerability verdict and the module never emits "confirmed",
    "exploitable" or "vulnerability".
  - `report_cves_for()` reuses the existing `backend.research_data.has_report`
    authority so the Review stage reflects a real persisted report artifact.

The existing `backend/routers/command_center.py` router was extended (not
rewritten): its payload now carries `agent`, `research_ops` and `lifecycle`,
and the timeline merges the new `AGENT_REPORT` events. The server-rendered
page attaches api-key-propagating links to lifecycle candidates; the JSON
projection deliberately does not. The existing watchlist, runtime, candidate
and activity sections are unchanged.

The Command Center page gained three panels (Agent Operations, Research
Operations, Findings Lifecycle). The page keeps its
`WATCHLIST RESEARCH ONLY — NOT CONFIRMED FINDINGS` banner and still never
renders "Vulnerable" or "Exploitable".

### Lifecycle mapping (deterministic, evidence-based)

| Stage | Source | Mapping |
|-------|--------|---------|
| Discovery | candidate presence in a persisted snapshot | `COMPLETE` when a CVE id exists, else `NOT_STARTED` |
| Metadata | existing `gap_dimensions` (`TECHNOLOGY_IDENTITY`, `COMPONENT_IDENTITY`, `VERSION_IDENTITY`) | `COMPLETE` when component **and** version identity are `PRESENT`; `IN_PROGRESS` when any identity dimension is `PRESENT`/`PARTIAL`; else `BLOCKED` |
| Evidence | existing `finding_readiness` | `EVIDENCE_READY` → `COMPLETE`, `EVIDENCE_PARTIAL` → `IN_PROGRESS`, `INSUFFICIENT_EVIDENCE` → `BLOCKED` |
| Verification | evidence stage | `PENDING` only when evidence is `COMPLETE`, else `BLOCKED` (this view never performs verification) |
| Review | persisted report existence + evidence stage | `COMPLETE` when a persisted report exists, else `PENDING` when evidence is `COMPLETE`, else `BLOCKED` |

## FILES CHANGED

New:

- `backend/agent_operations.py` — read-only agent workspace/report/tmux data.
- `backend/command_intelligence.py` — research-operations + lifecycle
  projections.
- `tests/test_command_center_intelligence.py` — focused offline tests.
- `agent-reports/command-center-intelligence-layer-v1.md` — this report.

Modified:

- `backend/routers/command_center.py` — extended payload (`agent`,
  `research_ops`, `lifecycle`), agent report events in the timeline,
  lifecycle research links on the HTML route, updated docstring.
- `web/templates/command_center.html` — Agent Operations, Research
  Operations and Findings Lifecycle panels.
- `web/static/css/custom.css` — additive `cc-*` styles for the new panels
  (agent key/value rows and report card, lifecycle pipeline + stage chips).

No `ai/`, `ns/`, `crawl/`, `database/`, Nuclei/CVE, schema or application
behaviour file was modified. `api.py` was not changed (the existing
`command_center` router registration already covers the new payload).

## TESTS

New focused tests:

```bash
python3 -m unittest tests.test_command_center_intelligence
# -> 16 tests, OK
```

New + existing Command Center tests together:

```bash
python3 -m unittest tests.test_command_center tests.test_command_center_intelligence
# -> 29 tests, OK
```

Existing regression tests:

```bash
python3 -m unittest tests.test_ui_redesign tests.test_dashboard_logic tests.test_routers_fixes
# -> 51 tests, OK

python3 -m unittest tests.test_research_api
# -> 29 tests, OK

python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
# -> 96 tests, OK
```

Real-data read-only render against the production watchlist directory:

```bash
WATCH_RESEARCH_WATCHLIST_DIR=/opt/watch/ai_data/research/watchlist \
  python3 - <<'PY'
# TestClient(api.app).get("/ui/command") + /api/command/overview
PY
# -> page HTTP 200
#    contains: Agent Operations, Research Operations, Findings Lifecycle, Discovery
#    forbidden words ("Vulnerable"/"Exploitable") absent
#    json keys: activity, agent, last_successful_run, lifecycle,
#               research_ops, runs, timeline, watchlist
#    agent mode AGENT, branch agent/daily-development, 25 reports observed
#    research_ops available with real candidates and 5 lifecycle stages
```

Compile / hygiene:

```bash
python3 -m py_compile backend/agent_operations.py \
  backend/command_intelligence.py backend/routers/command_center.py \
  tests/test_command_center_intelligence.py
git diff --check
```

## RESULTS

- `tests.test_command_center_intelligence` — **16 tests, OK**. Covers agent
  workspace mode/branch resolution, production fallback, report discovery and
  field parsing (inline and heading conventions), normalized newest-first
  report activity, honest tmux probe, research-operations aggregation and
  empty state, all five lifecycle mappings (ready/partial/blocked), the
  report probe, the lifecycle summary, and the route payload keys.
- `tests.test_command_center` (existing) still **13 tests, OK** — no
  regression from the new panels.
- `tests.test_ui_redesign + tests.test_dashboard_logic + tests.test_routers_fixes`
  — **51 tests, OK**.
- `tests.test_research_api` — **29 tests, OK**.
- `ai.test_knowledge_store + ai.test_xss_researcher + ai.test_xss_llm_researcher + ai.test_openrouter`
  — **96 tests, OK**.
- Real-data render — **HTTP 200**; the Agent Operations panel showed the real
  agent branch (`agent/daily-development`) and real persisted reports; the
  Research Operations panel showed real watchlist candidates; the Findings
  Lifecycle panel rendered all five stages; no confirmation word appeared.
- `python3 -m py_compile` — OK. `git diff --check` — clean.
- Production checkout `/opt/watch` was not modified (read-only data access
  only); no merge, rebase, reset or push was performed.

Known limitation: tmux session state is not persisted anywhere, so the panel
reports only a read-only tmux **server socket probe**
(`SERVER_PRESENT`/`SERVER_ABSENT`) and marks `verified: false`; it never claims
a specific session is running. This is intentional honesty, not a fabricated
status.

## COMMIT STATUS

COMMIT STATUS: committed on `agent/daily-development`.

## PUSH STATUS

PUSH STATUS: not pushed. Push is always manual.

## READY TO PUSH

READY TO PUSH: YES

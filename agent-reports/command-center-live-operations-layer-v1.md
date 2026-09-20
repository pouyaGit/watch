# Command Center Live Operations Layer v1 — Implementation Report

## TASK

Extend the Watch Command Center from an intelligence dashboard into a live
operations dashboard that answers **"What is Watch doing right now?"** without
fabricating data and without changing the existing intelligence layer.

Deliverables:

1. A read-only system operations provider (`backend/operations_status.py`):
   systemd service/timer state, last execution, runtime duration, exit status
   and enabled state for the primary units.
2. Read-only host resource status: CPU, memory, disk and uptime.
3. API integration reusing the existing Command Center backend (no duplicated
   intelligence logic).
4. UI sections: System Operations, Resource Status and a Live Timeline.
5. Tests for the service parser, missing-service handling, the API response
   and UI rendering.
6. This report.

Rules respected: only the agent workspace was modified; `/opt/watch` was never
touched; nothing was pushed or merged; all new data access is read-only.

## SUMMARY

A new single-responsibility module, `backend/operations_status.py`, collects the
live operational state from safe local sources:

- **systemd units** via a bounded, read-only `systemctl show` (argv list,
  `shell=False`, no writes). Primary units: `watch-api.service`,
  `watch-dell-watchlist.service`, `watch-dell-watchlist.timer`. For services it
  projects `ActiveState`/`SubState`, `UnitFileState` (enabled), `Result`,
  `ExecMainStatus`, start/finish timestamps and duration (from the monotonic
  timestamps). For timers it projects the last trigger and next elapse.
  Missing units become an honest `NOT INSTALLED` row; an unreachable systemd
  becomes `available: false` with `UNAVAILABLE` rows.
- **resources**: CPU / RAM / disk / load are reused from the existing
  `backend.system_stats.collect`, augmented with uptime from
  `psutil.boot_time` (no new monitoring daemon, no background process).

`collect_operations` accepts an injectable `runner` and `collect_resources`
accepts an injectable `collector`, so tests never touch the real system.

The existing Command Center backend was extended additively:

- `_command_payload` now includes `operations` and `resources`, and merges the
  new `SERVICE_RUN` / `SERVICE_START` / `TIMER_TRIGGER` events into the
  activity timeline.
- New endpoint `GET /api/command/operations` returns the deterministic
  `{operations, resources, events}` projection.

The existing intelligence modules (`backend/command_intelligence.py`,
`backend/agent_operations.py`) were **not modified**. Only the composition
router and the presentation layer changed.

The Command Center page gained three sections, reusing the existing tokens,
`.panel`, `.tbl`, `.badge` and `.kpi-grid` primitives:

1. **System Operations** — a table of the primary units with state badge,
   enabled flag, last run, exit code, duration and next elapse.
2. **Resource Status** — CPU / memory / disk / uptime cards.
3. **Live Timeline** — the existing real activity timeline, now also carrying
   systemd service/timer execution events (the example
   "Dell Watchlist completed" / "Snapshot generated" is covered by the
   `SERVICE_RUN` and `WATCHLIST_RUN` events).

The page keeps its `WATCHLIST RESEARCH ONLY — NOT CONFIRMED FINDINGS` banner
and still never renders "Vulnerable" or "Exploitable".

### Read-only / safety boundary

- The only subprocess is `systemctl show` with an argv list and `shell=False`;
  it cannot start, stop, restart, enable, disable, mask or write anything.
- No network, no Mongo writes, no LLM, no target interaction, no matcher
  invocation, no background process.

## FILES CHANGED

New:

- `backend/operations_status.py` — read-only live operations provider.
- `tests/test_command_center_operations.py` — focused offline tests.
- `agent-reports/command-center-live-operations-layer-v1.md` — this report.

Modified:

- `backend/routers/command_center.py` — added the `operations`/`resources`
  payload slice, systemd events in the timeline, the
  `GET /api/command/operations` route and an updated docstring.
- `web/templates/command_center.html` — System Operations, Resource Status and
  Live Timeline sections.
- `web/static/css/custom.css` — one additive `.cc-note` rule.

Unchanged (explicitly): `backend/command_intelligence.py`,
`backend/agent_operations.py`, `backend/watchlist_data.py`,
`backend/system_stats.py`, `api.py`. No `ai/`, `ns/`, `crawl/`, `database/`,
Nuclei/CVE or schema file was modified.

## TESTS

New focused tests (project uses `unittest`; see LIMITATIONS re pytest):

```bash
python3 -m unittest tests.test_command_center_operations
# -> 15 tests, OK
```

Existing Command Center tests still pass with the new panels:

```bash
python3 -m unittest tests.test_command_center tests.test_command_center_intelligence
# -> 29 tests, OK
```

Regression:

```bash
python3 -m unittest tests.test_ui_redesign tests.test_dashboard_logic tests.test_routers_fixes
# -> 51 tests, OK

python3 -m unittest tests.test_research_api
# -> 29 tests, OK

python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
# -> 96 tests, OK
```

Real-data read-only verification (real systemd + production watchlist dir):

```bash
WATCH_RESEARCH_WATCHLIST_DIR=/opt/watch/ai_data/research/watchlist \
  python3 - <<'PY'
# TestClient(api.app).get("/ui/command") + /api/command/operations
PY
# -> page HTTP 200
#    contains: System Operations, Resource Status, Live Timeline,
#              watch-dell-watchlist.service, LAST RUN SUCCESS, Uptime
#    forbidden words absent
#    /api/command/operations HTTP 200 with keys operations/resources/events
#      watch-api.service            -> RUNNING            (enabled: True)
#      watch-dell-watchlist.service -> LAST RUN SUCCESS   (enabled: False)
#      watch-dell-watchlist.timer   -> SCHEDULED          (enabled: True)
#      resources available, uptime "5d 0h 9m", 3 timeline events
```

Compile / hygiene:

```bash
python3 -m py_compile backend/operations_status.py \
  backend/routers/command_center.py tests/test_command_center_operations.py
git diff --check
```

## RESULTS

- `tests.test_command_center_operations` — **15 tests, OK**. Covers
  `systemctl show` parsing, timestamp parsing (valid + invalid), duration /
  uptime formatting, every service/timer status mapping, the service + timer
  projection (status, enabled, last run, exit, duration), missing-unit
  (`NOT INSTALLED`) handling, unavailable-systemd handling, a missing
  `systemctl` binary, operation-event normalization, resource collection with
  an injected collector, the `/api/command/operations` JSON shape and the
  rendered UI panels.
- `tests.test_command_center + tests.test_command_center_intelligence` —
  **29 tests, OK** (no regression).
- `tests.test_ui_redesign + tests.test_dashboard_logic + tests.test_routers_fixes`
  — **51 tests, OK**.
- `tests.test_research_api` — **29 tests, OK**.
- `ai.test_knowledge_store + ai.test_xss_researcher + ai.test_xss_llm_researcher + ai.test_openrouter`
  — **96 tests, OK**.
- Real-data render — **HTTP 200** with the real service states, real resource
  values and real timeline events; no confirmation word rendered.
- `python3 -m py_compile` — OK. `git diff --check` — clean.
- `/opt/watch` was not modified; no merge, rebase, reset or push was
  performed.

## LIMITATIONS

- **pytest is not installed** in this environment; the project's convention
  (per `AGENTS.md`) is `unittest`, so all tests above were run with
  `python3 -m unittest`. The test modules are standard `unittest` and will run
  under `pytest` unchanged if it is later installed.
- **systemd is required** for the full System Operations panel. Where systemd
  or `systemctl` is unavailable (containers, other hosts), the provider
  returns `available: false` and `UNAVAILABLE` unit rows and the UI shows an
  honest empty state. Nothing is fabricated.
- The unit set is the mission's primary set, defined by the
  `PRIMARY_UNITS` constant. Adding units is a one-line constant change; no
  runtime configuration surface was introduced.
- systemd timestamp strings are parsed with the common
  `Www YYYY-MM-DD HH:MM:SS [TZ]` formats. An unrecognized format yields
  `None` (the row shows an em-dash) rather than an invented time.
- Resource collection reuses `system_stats.collect`, whose CPU sample blocks
  for ~0.3s per call (pre-existing behaviour); no background sampler was
  added, consistent with the mission's "no heavy monitoring daemon".
- The service `last_run` fields are reported as systemd exposes them. For a
  currently-running service, the timeline emits a `SERVICE_START` event
  ("running now") rather than reusing a previous run's exit/result values.
- The tmux/session state is unchanged from the intelligence layer and is only
  a read-only socket probe; it is not part of this operations layer.

## COMMIT STATUS

COMMIT STATUS: committed on `agent/daily-development`.

## PUSH STATUS

PUSH STATUS: not pushed. Push is always manual.

## READY TO PUSH

READY TO PUSH: YES

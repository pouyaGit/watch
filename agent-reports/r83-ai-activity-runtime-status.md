# R83 — AI Activity & Runtime Status

Date: 2026-09-16
Base commit: `5e611e5aa38944d4cce60dac7a5b34df8d657541` (R82)
Rule version: `r83-1`
**REAL only: every field is derived from existing persisted execution state.
No fake heartbeat, no simulated progress, no invented stages. UNKNOWN means
"not observable", never failure.**

## 1. Existing execution architecture inspected

- **Executor**: `systemd/watch-research.service` — `Type=oneshot`, runs
  `/opt/watch/venv/bin/python3 -m ai.research_cli agent run` hourly
  (`watch-research.timer`, `OnCalendar=hourly`), under `flock` service/app
  locks with a 330-minute start bound; private `RuntimeDirectory` and
  `WATCH_RESEARCH_*` env policy. In this environment the timer is
  **inactive/not-found** (no run is scheduled right now).
- **Scheduler**: `ai/research_agent/scheduler.py` — one-shot bounded runs,
  `SchedulerConfig` window defaults `12:00`–`00:00` `Asia/Tehran`, single
  worker flock, `run_once` returns a real record.
- **Persistence**: `ai/research_agent/storage.py` —
  `ai_data/research/agent/runs/<run_id>.json` per run (`started_at`,
  `completed_at`, status, plans, results, failures) and per-plan result
  artifacts; plus R64–R77 research case envelopes under
  `ai_data/research/*/*.json`.
- **Existing status/log mechanisms**: `ai.research_cli agent status` prints
  the scheduler policy (window/enabled/eligible plans); `logs/tasks/` exists
  for crawl tasks only (empty); systemd journal is outside the app.
- **Telegram/reporting** (`TELEGRAM_*` in `.env`, `config()`): present but not
  wired into the research runtime — reusable later by R84, not needed here.
- **Derivable facts**: run records (16 real records present, newest
  `run-20260911T200012Z`), case artifact summaries + real mtimes (4 records,
  newest `case-indeed-a1-endpoint-behavior`), lock liveness, scheduler window
  policy. In-flight case/stage is **not** persisted → reported unknown.

## 2. Actual source of runtime/activity truth

| Fact | Real source |
| --- | --- |
| RUNNING | shared non-blocking flock probe on `WATCH_RESEARCH_LOCK`, `/run/watch-research/research.lock`, `/run/watch-research.lock` (the running service holds it) |
| last run / duration / plans / failures | `ai_data/research/agent/runs/*.json` via `ai.research_agent.storage.list_runs` |
| current case / evidence counts | R64–R77 envelope summaries + real artifact mtimes |
| window / timezone | `SchedulerConfig.from_env()` (`WATCH_RESEARCH_*`, code defaults 12:00–00:00 Asia/Tehran) |
| stage while running | **not observable** (no in-flight record) → `null` + documented |

No other source was invented. The lock probe opens read-only, takes a shared
non-blocking lock and releases it immediately; it never creates or writes a
file.

## 3. New contract / schema

`ai/knowledge/ai_activity_status.py` (pure) + `backend/research_activity.py`
(read-only collector) produce:

- `status` ∈ `IDLE`, `RUNNING`, `WAITING_FOR_EVIDENCE`, `COMPLETED`,
  `COMPLETED_WITH_REJECTIONS`, `ERROR`, `UNKNOWN` + `status_basis`;
- `server_time_tehran`, `window` (start/end/timezone/in_window/current bounds/
  scheduler_enabled);
- `current_run` (null; in-flight record does not exist), `last_run`
  (run_id, status, agent_status, skipped, started/finished, duration_seconds,
  in_window, plans, results, evidence/sources counts, failures, cve/program),
  `current_case` (case/status/sufficiency/decision/counts/accepted/rejected),
  `current_stage` (null, documented);
- `daily` (12:00–00:00 Tehran): runs, plans_processed, results,
  evidence_acquired, cases_processed, accepted/rejected hypotheses,
  evidence available/missing, actions_generated;
- `totals`, `last_error` (bounded identifier only), `observability`
  (`unavailable_fields`, notes, `unknown_is_not_failure=true`), safety block.

Status precedence (documented): lock held → RUNNING; latest run failed →
ERROR; latest run partial → COMPLETED_WITH_REJECTIONS; latest case waiting →
WAITING_FOR_EVIDENCE; latest run completed → COMPLETED; no data + lock free →
IDLE; nothing observable → UNKNOWN.

## 4. API changes

- New router `backend/routers/research_activity.py`:
  `GET /api/research/activity` behind the existing `verify_api_key`
  dependency/middleware; fail-soft (collector failure → bounded `UNKNOWN`,
  HTTP 200, no stack traces).
- `api.py` +2 lines (import + include), registered **before** the generic
  `/api/research/{cve}` route so the path is matched correctly.
- R81 routes and behavior unchanged (regression-tested).

## 5. UI changes

- `web/static/research/index.html`: new "AI Runtime Activity" panel on the
  dashboard (status badge, Tehran time, daily window, in-window, last run
  details incl. duration, current case, daily window summary, last error,
  observability note) with a manual **Refresh** button — no polling, no
  WebSocket, no fake progress.
- `web/static/js/research_dashboard.js`: `initActivity()`/`renderActivity()`
  calling only the new endpoint, `textContent` rendering (no `innerHTML`),
  status colors distinguishing RUNNING / WAITING_FOR_EVIDENCE / COMPLETED /
  COMPLETED_WITH_REJECTIONS / ERROR / IDLE / UNKNOWN.
- No CSS changes needed: the existing R82 panel/state/chip classes are reused.

## 6. Tehran timezone handling

All window math runs on `zoneinfo.ZoneInfo("Asia/Tehran")` in the core:
ISO timestamps are parsed and converted (naive values treated as Tehran,
matching `backend/tz.py`), and the daily window is computed as the current
12:00 → next 00:00 Tehran interval (crossing midnight; 12:00 inclusive,
00:00 exclusive; before noon it resolves to the previous day's window). The
server's local timezone is never used.

## 7. Real validation result (REAL)

Live call in this environment (2026-09-16 12:31 Tehran, inside the window):

- `status = WAITING_FOR_EVIDENCE` (`latest_case_waiting_for_evidence`) —
  no run is active (lock probe: free; systemd timer inactive), the newest
  persisted run completed, and the newest case is waiting for evidence.
- Last run: `run-20260911T200012Z` COMPLETED, 2026-09-11 23:30:12 →
  23:32:16 Tehran, duration 124.367s, 2 selected / 1 processed,
  1 evidence / 5 sources, 0 failures.
- Current case: `case-indeed-a1-endpoint-behavior`, WAITING_FOR_EVIDENCE,
  INSUFFICIENT / NEEDS_EVIDENCE, available 2 / missing 2, 1 action,
  accepted 1 / rejected 2 — real artifact mtime 2026-09-16 10:33:33 Tehran.
- Daily window (12:00–00:00 Tehran, in_window=true): all zeros — honest,
  no AI run has happened today.
- Totals: 16 runs / 19 results / 26 evidence / 4 cases persisted.
- `current_stage = null`, `unavailable_fields=[in_flight_case_and_stage]`,
  `last_error = null`.

No AI run was triggered to make the status look active.

## 8. Tests

- `ai/test_ai_activity_status.py` — **20 passed**: closed status vocabulary;
  UNKNOWN when unobservable; IDLE with no data; RUNNING via lock;
  COMPLETED; COMPLETED_WITH_REJECTIONS; ERROR with bounded last_error;
  WAITING precedence over a completed run; case-only IDLE; Tehran window
  bounds/boundaries (12:00 inclusive, 00:00 exclusive, pre-noon previous
  day); UTC→Tehran conversion; naive-as-Tehran; daily aggregation; duration;
  unparseable timestamps; bounded text; determinism; safety flags; no
  sensitive content in notes/errors.
- `tests/test_research_activity_api.py` — **14 passed**: lock probe
  free/held/unavailable; bounded newest-first run records and read-only
  fixture check; case projection hides raw URLs; hermetic collect; UNKNOWN
  path; per-source fail-soft; no forbidden primitives in the new modules;
  API auth gate; bounded contract + hygiene (no `://`, `sk-`, `Bearer`,
  `_id`, `Traceback`); read-only run files; fail-soft route; R81/R82 still
  working.
- Regressions: `pytest tests/local_e2e -q` — **328 passed, 63 subtests**;
  `tests.test_research_cases_api` — **26 passed**; 
  `tests.test_r82_research_dashboard_ui` — **18 passed**;
  `tests.test_research_api` — passed.

## 9. Known observability gaps

1. **In-flight case and stage**: the agent persists nothing while running, so
   `current_run`, `current_case` and `current_stage` are `null` during
   RUNNING (lock is the only live signal). Documented in
   `observability.unavailable_fields`.
2. **Scheduler enabled flag**: the API process environment may not carry the
   systemd `WATCH_RESEARCH_ENABLED` value, so `window.scheduler_enabled` can
   read `false` while the systemd service is the real executor
   (window/timezone themselves match the real policy).
3. **Run records are completion-time**: a crashed process leaves no record
   (the lock release is then the only evidence); `UNKNOWN`/`IDLE` are used
   rather than guessing.
4. **Lock probing requires read access** to the service RuntimeDirectory; if
   unavailable the lock state is reported as unobservable.
5. **Systemd timer state is not read** (no subprocess/journal access), so
   "scheduled but idle" and "not scheduled" are not distinguished — the
   honest contract reports activity state, not schedule state.

## 10. Security / safety review

- Read-only: no Mongo, no network, no process spawning, no LLM, no writes.
  Only `os.open(..., O_RDONLY)` + `flock` on lock paths and file reads.
- Endpoint is behind the existing API-key middleware; bounded JSON only.
- Never returned: API keys/provider credentials, raw prompts or model
  responses, raw URLs/IPs, Mongo identifiers, tokens/cookies, stack traces
  (errors are reduced to token-shaped identifiers). Confirmed by tests.
- Safety block unchanged: `advisory=true`, `research_only=true`,
  `execution_performed=false`, `vulnerability_confirmed=false`,
  `exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
  `human_authority_required=true`; no execution control (starting/stopping
  AI is impossible through this layer).

## 11. Exact files changed

- `ai/knowledge/ai_activity_status.py` (new, pure core)
- `ai/test_ai_activity_status.py` (new)
- `backend/research_activity.py` (new, read-only collector)
- `backend/routers/research_activity.py` (new router)
- `api.py` (+2 lines: import + include)
- `web/static/research/index.html` (AI Activity panel)
- `web/static/js/research_dashboard.js` (activity renderer + manual refresh)
- `tests/test_research_activity_api.py` (new)
- `agent-reports/r83-ai-activity-runtime-status.md` (this report)

Research planners (R70–R81), evidence validation and safety/authorization
boundaries are untouched.

## 12. Exact local commit hash

One local commit: `feat(ai): add ai activity runtime status`
(hash reported in the final task response). No push.

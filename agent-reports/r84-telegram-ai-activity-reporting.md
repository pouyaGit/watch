# R84 — Telegram AI Activity Reporting

Date: 2026-09-16
Base commit: `e4c05ba68811491402bd07e20368f7eca2e556b3` (R83)
Rule version: `r84-1`

**Reporting/observability only. The report is rendered from the real R83
activity snapshot; nothing is started, stopped, executed or mutated. Zero
activity is reported as zero, `UNKNOWN` is never turned into `ERROR`, and
"AI is RUNNING" is claimed only when the R83 status is actually `RUNNING`.**

## 1. Existing Telegram infrastructure inspected

| Piece | Location | Reused how |
| --- | --- | --- |
| Config | `config.py` → `config()` reads `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` from env (`.env` via `python-dotenv`) | `telegram_config_status()` reads booleans only; no second config layer |
| Transport | `database/telegram.py` → `send_message()` / `send_telegram_message()` using `python-telegram-bot` 22.6, `parse_mode='HTML'`, bounded retries (3, backoff on `TimedOut`), returns `bool`, never raises on network errors | R84 default sender delegates to `send_message`; no transport duplication |
| Notification helpers | `database/notifications.py` (crawl/enum notifications) | untouched |
| Existing scheduler units | `systemd/watch-research.{service,timer}` — oneshot, hourly, `flock`, `WATCH_RESEARCH_*` policy, user `pouya_behnia` | style/least-privilege conventions copied; research units untouched |
| Existing report/Telegram timers | none found (no WatchTower/AI report timer; no scheduled Telegram report code) | R84 adds a new reporting-only timer |

No duplicate Telegram configuration was introduced; there was no prior
reporting abstraction to extend.

## 2. Existing AI activity source inspected

- R83 collector: `backend/research_activity.py` → `collect_activity()`
  (read-only: run records, case summaries + real mtimes, flock liveness probe,
  `SchedulerConfig.from_env()` window policy).
- R83 pure core: `ai/knowledge/ai_activity_status.py` →
  `build_activity_status()` (status vocabulary, daily window math, bounded
  contract, `observability.unavailable_fields`).
- R83 API: `GET /api/research/activity` (`backend/routers/research_activity.py`).

The collector is fail-soft per source; the contract is bounded and already
sanitized (`_bounded_failure`, no stacks/paths, no URLs).

## 3. R83 integration

`backend/telegram_reporting.py` imports `backend.research_activity` and calls
`collect_activity()` **directly in-process** (no localhost HTTP, no second
activity calculation). The dashboard API and Telegram render the same R83
snapshot. When the caller injects an activity mapping (tests, future reuse),
the collector is not called at all.

## 4. Daily report design

Pure formatter: `ai/knowledge/ai_activity_report.py::build_daily_report`
(no I/O, no clock of its own). Renders, when available:

```
🤖 WATCH AI DAILY REPORT
━━━━━━━━━━━━━━━━━━
📅 <window start date>
⏱ 12:00 → 00:00 Asia/Tehran

<status emoji> Status
<STATUS>
basis: <status_basis>
observed: <server_time_tehran, minutes precision>
last run: <status> <run_id> (<duration>s)   | "none recorded"

📊 Activity
Runs / Plans processed / Results / Cases processed /
Hypotheses accepted / Hypotheses rejected / Evidence acquired / Actions generated

🔎 Research
• latest case id [program / category]: status, sufficiency, missing N
• cases persisted: N
• "No AI run was recorded during the <date> 12:00–00:00 Tehran window." (when runs = 0)

⏳ Pending
• missing decision-critical evidence (when > 0)
• case is WAITING_FOR_EVIDENCE (human-supplied evidence)

⚠️ Issues
• last error (bounded) / rejected hypotheses / unavailable observability fields

━━━━━━━━━━━━━━━━━━
Research only · No execution · Not confirmed
```

Zero activity stays zero (verified with the real collector: today's window
currently has `Runs/Plans/Results/Cases/Hypotheses/Evidence/Actions = 0`).
The window label/date come from the R83 `window.current_start`, so a
non-default `WATCH_RESEARCH_WINDOW_*` policy is reflected, not hardcoded.

## 5. Event report design

`event_reports(activity, previous_snapshot)` renders only real transitions of
the R83 contract, bounded to `MAX_EVENTS = 3` per invocation:

| Event | Detection | Deterministic dedup key |
| --- | --- | --- |
| `RUN_STARTED` | status `RUNNING` after a non-RUNNING snapshot | `event:RUN_STARTED:<window_start>` |
| `RUN_COMPLETED` | latest run id/status changed, status `COMPLETED` | `event:RUN_COMPLETED:<run_id>` |
| `RUN_COMPLETED_WITH_REJECTIONS` | idem, status `COMPLETED_WITH_REJECTIONS` | `event:RUN_COMPLETED_WITH_REJECTIONS:<run_id>` |
| `RUN_FAILED` | idem, status `ERROR` | `event:RUN_FAILED:<run_id>` |
| `CASE_WAITING_FOR_EVIDENCE` | case status/modified changed to waiting | `event:CASE_WAITING_FOR_EVIDENCE:<case_id>:<case_modified_at>` |
| `HUMAN_REVIEW_REQUIRED` | decision state changed to `READY_FOR_HUMAN_REVIEW` | `event:HUMAN_REVIEW_REQUIRED:<case_id>:<case_modified_at>` |

No fake events: the first observation of a state writes a **silent baseline**
and emits nothing, so nothing is replayed merely because the reporter ran.
No per-step spam; a message is emitted only on a real transition.

## 6. Deduplication mechanism

- Tiny JSON state file (no project mechanism existed to reuse):
  `ai_data/research/ai_reports/telegram_state.json`, overridable with
  `WATCH_TELEGRAM_REPORT_STATE` (also used by tests/validation).
- Deterministic keys only (`daily:<window_start>`,
  `event:<type>:<run_id>`, `event:<type>:<case_id>:<case_modified_at>`);
  timestamps are never used as identity on their own.
- Keys are recorded **only after a successful send**, so a failed send is
  retried once on the next invocation (one attempt per invocation, no retry
  storm). Bounded to `MAX_KEYS = 24`, atomic `os.replace` write.
- Persisted content is restricted to the sanitized transition snapshot
  (status, run/case ids, case status/decision, bounded error token) — no
  prompts, responses, URLs, IPs, Mongo ids or credentials.

## 7. Tehran timezone handling

All window math stays in R83 (`Asia/Tehran`); R84 never uses the server
timezone. The daily date and `12:00 → 00:00 Asia/Tehran` label come from
`window.current_start/start/end/timezone`; `observed` is
`server_time_tehran`. Boundary semantics (tested):

- `12:00` Tehran is **inside** the window (`start` inclusive) and the daily
  key is `daily:<same-day 12:00+03:30>`;
- `00:00` Tehran is **outside** (end exclusive) and closes the previous day's
  window: key `daily:<previous-day 12:00+03:30>`, date label previous day.

## 8. Scheduling / invocation design

Added (repository files only, **not installed or enabled**):

- `systemd/watch-ai-report.service` — `Type=oneshot`, runs
  `/opt/watch/venv/bin/python3 -m backend.telegram_reporting --mode auto`,
  180 s start bound, `ReadWritePaths=/opt/watch/ai_data` (state file),
  network ordering, same least-privilege pattern as `watch-research.service`.
- `systemd/watch-ai-report.timer` — `OnCalendar=hourly`, `Persistent=true`,
  `AccuracySec=1min`.

Behavior: the first hourly tick after `00:00` Tehran closes the window and
sends the deduplicated daily summary; during the window only real transitions
produce event messages. The existing research unit, cadence and window are
untouched; the report timer never starts/stops AI. The service user follows
the existing `watch-research.service` convention (`pouya_behnia`) and must
match the deployment account before enabling.

## 9. Telegram configuration handling

- `telegram_config_status()` returns only booleans
  (`token_configured`, `chat_configured`, `configured`); values are never
  read out, logged or stored.
- Missing/partial config → fail-safe early return with reason
  `telegram_not_configured`, zero sends, no exception; tests pass without
  config. No credentials are invented or committed; `.env` untouched.
- `--dry-run` builds reports without a transport call and without state
  writes, for safe inspection in unconfigured environments.

## 10. Real validation result

Telegram configuration was present in `.env` (boolean check only; the token
and chat id are never printed or written anywhere). Validation used a
temporary dedup state (`/tmp/opencode/r84-validation/...`) so the production
state path was never created/modified (`ai_data/research/ai_reports/` does
not exist afterwards).

Messages actually sent (2, to the configured chat):

1. First send before the fix below — content was the R84 daily summary, but
   it exposed a real bug: the transport argument was passed through a
   whitespace-collapsing helper, so the delivered message was a single line.
   Fixed in `backend/telegram_reporting.py` (the bounded message is passed
   unchanged; the 4096 slice is a second safety bound only). No secrets, URLs,
   IPs or target data were involved.
2. Re-validation after the fix: `sent=1`; the transport received the full
   35-line message (860 UTF-16 units, < 3900 bound):

```
🤖 WATCH AI DAILY REPORT · 📅 2026-09-16 · ⏱ 12:00 → 00:00 Asia/Tehran
⏳ Status: WAITING_FOR_EVIDENCE (basis: latest_case_waiting_for_evidence)
observed: 2026-09-16 12:54 · last run: COMPLETED run-20260911T200012Z (124.4s)
📊 Activity: Runs 0 / Plans 0 / Results 0 / Cases 0 / Accepted 0 / Rejected 0 /
Evidence 0 / Actions 0
🔎 Research: case case-indeed-a1-endpoint-behavior [indeed / RECON]:
WAITING_FOR_EVIDENCE, INSUFFICIENT, missing 2 · cases persisted: 4 ·
"No AI run was recorded during the 2026-09-16 12:00–00:00 Tehran window."
⏳ Pending: 2 missing decision-critical evidence · WAITING_FOR_EVIDENCE
⚠️ Issues: unavailable: in_flight_case_and_stage
Research only · No execution · Not confirmed
```

(Reproduced here with `·` for newlines; the delivered message preserved the
line breaks.)

Safety of the sent content: it is the exact R84 daily summary — date/window,
status, counters, one project case slug/program ("case-indeed…", "indeed"),
observability limitation, footer. It contains no credentials, no raw
URLs/IPs, no Mongo ids, no prompts/model responses, no payloads and no stack
traces. No AI run was triggered and no target was contacted; the only network
call was the existing Telegram transport.

Deduplication on the real transport path was verified: a repeat invocation
with the same state returned `sent=0, skipped=1`. An in-process recorder run
confirmed the transport receives the multi-line message while the production
state path remains untouched.

## 11. Tests

New focused tests (all mocked/fake transport, no real Telegram send, temp
state dirs):

- `ai/test_ai_activity_report.py` — 31 tests: daily formatting (zero activity,
  completed, `COMPLETED_WITH_REJECTIONS`, `ERROR`, `WAITING_FOR_EVIDENCE`,
  `RUNNING`, `IDLE`, `UNKNOWN`), Tehran timezone, 12:00/00:00 boundaries,
  bounded message (UTF-16), deterministic dedup keys, baseline events, each
  event type, non-repeat, secret/URL/IP/ObjectId/path/trace redaction, HTML
  escaping, prompt/response exclusion, sanitized snapshot.
- `tests/test_telegram_reporting.py` — 24 tests: missing/partial config,
  boolean-only config status, default-sender delegation, dedup (daily,
  events, bounded keys, deterministic case key), transport exception/false
  bounded + retry, activity-unavailable is bounded (not error), injected
  activity skips collector, auto/daily/events/dry-run modes, state-write
  failure, no secrets in result/messages/state, CLI dry-run/failure exit 0,
  forbidden-primitive scan of the new modules, real-collector dry-run
  contract, first-observation silence, multi-line transport check.

Regression runs (all pass):

- `ai.test_ai_activity_status` + `tests.test_research_activity_api` (R83) — 34
- `tests.test_r82_research_dashboard_ui` (R82) — 18
- `ai.test_knowledge_store`, `ai.test_xss_researcher`,
  `ai.test_xss_llm_researcher`, `ai.test_openrouter` — 96
- `tests.test_pipeline_tooling_failfast` — pass

Pre-existing, unrelated: `ai/test_p1_security_hardening.py` has 6 failures in
Nuclei legacy-surface docstring checks; reproduced identically on base
`e4c05ba` in a clean worktree, untouched by R84.

Total new + relevant regression: 203 passing.

## 12. Security / safety review

- **Read-only source**: R83 collector — no Mongo, no network, no process
  spawning, no LLM; lock probe opens read-only and releases immediately.
- **No execution control**: R84 cannot start/stop AI, submit evidence, change
  authorization, run scanners or touch targets; the only outbound call is the
  existing Telegram transport.
- **No research writes**: only the bounded dedup state file is written
  (outside research artifacts; systemd `ReadWritePaths` limited to
  `ai_data`).
- **No Mongo writes**: none, by construction (verified by source scan test).
- **Message safety**: URLs/paths withheld, credential pairs/bearer/ObjectId
  redacted, IPv4 withheld, HTML escaped, whitespace-normalized, bounded to
  ≤ 3900 UTF-16 units (< Telegram's 4096).
- **Secret hygiene**: config values never logged/stored; boolean-only config
  status; token/chat id absent from code, tests, report and state; `.env` not
  committed.
- **Fail-safe**: public entry point is a totality wrapper; transport failure,
  activity failure, report-build failure and state-write failure all return
  bounded results and cannot break the AI pipeline.

## 13. Known limitations

1. Event detection is tick-sampled (hourly): runs shorter than the tick may
   never be observed as `RUNNING`, and a start/finish between ticks yields
   only the completion event. Daily counters still include them.
2. `RUN_STARTED` identity is the window (the in-flight run is not persisted —
   R83 limitation), so a second start within the same window is deduplicated.
3. The first observation is a silent baseline; transitions that happened
   before the reporter's first tick are not replayed.
4. Activity source unavailable → **no** message is sent (deliberate anti-noise
   choice); the result records `activity_unavailable_<Type>`.
5. At most 3 events per invocation; transitions beyond that bound in the same
   tick are absorbed by the advanced snapshot (bounded volume over
   completeness).
6. The dedup state keeps the last 24 keys; this is sufficient because event
   emission also requires a real transition from the stored snapshot.
7. systemd units are repository-only here: not installed/enabled, service
   user must be aligned with the deployment account.
8. Reporting is English + emoji, Telegram HTML parse mode only.

## 14. Exact files changed

New files (no existing/tracked file modified):

- `ai/knowledge/ai_activity_report.py` — pure R84 formatter/event builder
- `backend/telegram_reporting.py` — orchestration, dedup state, CLI
- `ai/test_ai_activity_report.py` — formatter tests
- `tests/test_telegram_reporting.py` — orchestration tests
- `systemd/watch-ai-report.service` — reporting-only oneshot unit
- `systemd/watch-ai-report.timer` — hourly report tick
- `agent-reports/r84-telegram-ai-activity-reporting.md` — this report

Nothing was committed from the pre-existing untracked worktree items
(`install.sh`, `watch.zip`, the `utils.zip` deletion, older untracked
`agent-reports/*`). R81/R82/R83 tracked files are byte-identical.

## 15. Exact local commit hash

One local commit: `feat(ai): add telegram ai activity reporting`
(hash reported in the final task response). No push.

## 16. READY TO PUSH

READY TO PUSH: YES

- implementation complete; real R83 source reused, no duplicate calculation
- daily Tehran `12:00–00:00` window correct (boundaries tested)
- deduplication deterministic; missing config fails safely; transport
  failures cannot break research
- no secrets; no sensitive target data; no target interaction; no Mongo
  writes; no AI run triggered
- R81/R82/R83 behavior unchanged (no tracked file modified)
- focused tests pass; relevant regressions pass
- report exists under `agent-reports/`; exactly one local commit; no push

## Git policy confirmations

- No unrelated files committed; no secrets committed.
- No target interaction; no Mongo writes; no AI execution started.
- R81 unchanged, R82 unchanged, R83 unchanged (all tracked files unmodified).

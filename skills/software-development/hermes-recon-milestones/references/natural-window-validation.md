# Passive cross-day / natural-window validation

Use when a brief mandates observing ONLY the Scheduler's natural event — no manual
trigger, no forced window, no timestamp or retry-row edits, no daemon restart — and
promises INCOMPLETE if the natural window has not arrived (e.g. Cross-Day Recovery
after the scheduler stamp fix).

## 1. Compute the window BEFORE watching anything

Read the interval constant and the persisted stamp, derive the edge, and state how
far away it is in the report:

- interval: `RESEARCH_INTERVAL_S` in `scripts/daemon.py` (default 86400 s); the
  parent spawn gate is `time.time() - last_research_agent_planned < RESEARCH_INTERVAL_S`.
- stamp: `SELECT v FROM kv WHERE k='last_research_agent_planned'` (read-only URI).
  The `kv` table's value column is `v`, not `value` — the wrong name errors loudly.
- short backoff marker: `last_research_agent_attempt` in `kv` — written by the
  parent ONLY at a real launch attempt (`RESEARCH_SPAWN_BACKOFF_S`, 300 s). Its
  ABSENCE after daemon start is positive evidence of no hot-loop and no attempt
  yet; its presence with a recent value means the 300 s backoff is active.

If `now < stamp + interval`, the natural opportunity has not arrived. Do not
manufacture it. Take the captures (section 2), diff them, and report INCOMPLETE
with the window edge spelled out — that IS the deliverable of the session.

## 2. Capture / diff protocol (all read-only)

Three captures minimum: A before the window, B during the watch, C at the end.
Persist each as JSON under `state/validation_tmp/` (test artifact, not a
production record) and diff with Python, not by eye. Each capture carries:

- the scheduler stamps from `kv` (planned / attempt, with human-readable UTC),
- daemon PID + uptime (`/proc/<pid>` stat ctime),
- lock files (`state/research_daily.lock`, `cycle.lock`) — record contents but
  treat a PID in the file as stale trivia: `research_daily._Lock` uses
  `fcntl.flock(LOCK_EX|LOCK_NB)` and overwrites the file with its own PID after
  acquiring, so a dead child leaves a stale PID forever. `flock` is the
  authority, not the bytes. Do not clean the file and do not cite its contents
  as proof of a live process,
- row counts of the research funnel (`research_agent_runs`, `_articles`,
  `_analysis`, `_retry_state`, `_patterns`, `_skills`, `_candidates`) plus
  `findings`, `alert_queue`, `jobs`, `jev_requests`,
- the full identity set of the pending retry rows (article_id, url, revision,
  status, attempts, exhausted, next_retry_at, analysis count per article).

Corroborate with the daemon log: today's `logs/daemon_YYYY-MM-DD.log` must show
no `research daily spawn` line for a NOT_OBSERVED verdict; the previous day's
spawn line establishes when the last natural child ran.

## 3. Verdict, report shape, integrity

- Window not reached → the brief's INCOMPLETE template: NOT_OBSERVED / UNKNOWN /
  NOT_VALIDATED per field, DUPLICATE counts 0, integrity counters 0/NONE, and
  READY TO PUSH: YES with READY FOR PRODUCTION: NO / READY FOR NEXT STAGE: NO.
  State the exact UTC window edge so the follow-up session knows when evidence
  becomes possible.
- Never claim recovery PASS from source-tree correctness or fixture tests alone;
  those prove the contract, not the live path. The first natural spawn after the
  fix-carrying daemon start is the only admissible live evidence.
- Integrity section: separate live-daemon churn (a running daemon keeps growing
  `findings`, `alert_queue`, `jobs` during any watch) from validation effects —
  report those deltas as unattributed churn with direction and magnitude, and
  count only rows created by the validation itself against counters like
  TARGET_RECON_REQUESTS.
- A PASS verdict here is about the WATCH, not about the code: passive validation
  never proves the live path executes the new logic. Pair it with the reload check
  in `references/live-daemon-verification.md`, or the report will claim readiness
  for a code path production has not loaded yet.

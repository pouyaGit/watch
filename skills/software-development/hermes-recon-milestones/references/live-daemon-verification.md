# Proving a change is live, and runtime forensics

Use when a milestone changes `lib/` or `scripts/` code the running daemon has
already imported, when a brief asks whether production really does X, or when a
status message reports `idle` / `Running: 0` while work is pending.

## 1. Module caching makes edits invisible

`/usr/bin/python3 scripts/daemon.py` imports `lib/*` once at start. Editing a
module afterwards changes nothing in production until the service restarts
(`systemctl --user restart hermes-recon`). Check this EVERY milestone:

- Compare service start against edited-file mtimes:
  `systemctl --user status hermes-recon` for the start time, then
  `ls -l --time-style=full-iso <file>` for each edited file. A file with
  mtime > start time is NOT loaded yet.
- Find a side effect only the new code produces and look for it in the live DB.
  The strongest tell is a table the new module creates on its first tick; a
  missing table proves the code never ran, whatever the unit tests say.
- Trace the ACTIVE path, not the modified file: `grep -rn` the entry function and
  its callers in the daemon. A replaced formatter often still has a caller in a
  dead API, so production keeps emitting the OLD text and the report is wrong
  about what is live.

## 2. Live-evidence protocol

- Tie the artifact to the process: a delivery/run row's timestamp must be after
  the current PID's start time and the PID must own it.
- Restart only when the brief authorises it. Before restarting, check for in-flight
  children (`pgrep -f scripts/research_daily.py`) and read the unit's `KillSignal`:
  SIGTERM propagates to the cycle subprocess and to any `systemd-run --scope` PD
  run, which records `rc=-15`.
- A restart costs, and all of it must be disclosed: the in-flight cycle ends
  `rc=-15`, an in-flight PD run is marked FAILED mid-stage, and the daemon enters
  `FAIL_BACKOFF`. The PD daily window may then be consumed by a failed run.

## 3. Diagnosing Pending > 0 with Running = 0

Work the evidence in order before suspecting a bug:

1. Process tree `pstree -p <pid>` / `ps --ppid`. The executor is a PERIODIC
   subprocess (`cycle.py`), so between cycles there is genuinely no executor;
   `idle` can be the truthful state, not an instrumentation gap.
2. Duty cycle and dead zones from the daemon log: pair `cycle start` with the next
   `cycle end rc=` and sum the gaps. Healthy gaps are tens of seconds;
   `FAIL_BACKOFF` slots (300/900/1800/3600 s) are the long dead zones.
3. Eligibility of the pending rows: `scheduled_at <= now` plus `attempt_count = 0`
   rules out a timing gate and job-level retry backoff.
4. Resource gate: `state/heartbeat.json` against the `safety` thresholds
   (load / RAM% / disk%). Green thresholds rule the gate out.
5. Arrival vs completion per bucket: a persistent backlog with Pending growing is
   a throughput/structural finding, not a stall.
6. `scheduler_domains` can be metadata only — an `ACTIVE` domain with
   `claims_total = 0` means no executor is attached, not that work was balanced.

## 4. The unconditional write in `store.conn()`

`lib/store.py::conn()` runs an `UPDATE xss_candidates SET severity = ...` backfill
with no guard on EVERY connection, so even a read opens a write transaction. Under
concurrent workers plus the Telegram layer this surfaces as
`sqlite3.OperationalError: database is locked` attributed to whichever call site
was first (`recover_jobs`, `planner.plan`, the telegram layer).

- When a lock traceback points into `store.py::conn()` itself, the call site is a
  red herring — the defect is the per-connection backfill. Say so rather than
  blaming the caller.
- Before attributing a lock failure to a milestone, count its rate in the OLD
  daemon window and the NEW one from the same log (bucket by the PID in each
  line); equal rates mean PRE_EXISTING.
- An idempotent backfill belongs in the migration path guarded by a version or
  column-existence check, not on every connect.

## 5. Pre-existing traps when auditing

- `worker_registry` rows sit `STOPPED` between cycles; `worker_events`
  start/complete pairs are the proof work ran. A zero live-worker count is not
  evidence of a broken observer.
- Always separate live-daemon churn from milestone effects, and classify every
  failure as INTRODUCED / PRE_EXISTING / ENVIRONMENTAL / UNKNOWN with the count
  that justifies the label.

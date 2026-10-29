# Live worker observability layer

Use for milestones that add visibility into the running worker fleet: registry,
heartbeat, state machine, stale detection, restart reconciliation, live/queue/process
snapshots. Observability NEVER changes worker behaviour — every write is wrapped so a
DB failure returns None and never reaches the job executor; a worker is never killed
or restarted because of its observed state.

Existing architecture to reuse — do NOT build parallel systems:

- `lib/worker_observability.py` (added in the Stage 4 milestone) carries the worker
  registry (`worker_registry`), bounded lifecycle events (`worker_events`, capped per
  worker, never unbounded), heartbeats (throttled same-row UPDATE), `reconcile()`,
  `mark_stale()`, and read-only `live_snapshot()` / `queue_snapshot()` /
  `process_snapshot()`. Extend it rather than re-deriving.
- `lib/scheduler.py` `WorkerPool` is a thread pool: `run_job(wid)` returns a result
  dict when a job ran and None when nothing was claimable (idle, not waiting).
  `JOB_RUNTIME_TIMEOUT_S` (180 s) is the architectural runtime ceiling — derive the
  stale threshold from it, never invent a number.
- The daemon main loop is the right place for `reconcile()` + `mark_stale()` — they
  belong in the same non-blocking, exception-wrapped tick as the other periodic
  checks, never in the job executor.

## Rules that cost time when missed

- Instrument the pool callable by WRAPPING it (`instrument_worker` returns a closure
  that calls the real `run_job`), never by editing the executor internals — the
  contract (None = nothing claimed, dict = job ran) stays byte-identical, so M5
  concurrency tests keep passing unchanged.
- STALE is a computed state, not a death sentence: `last_heartbeat + threshold < now`
  moves the row to STALE and nothing else. STALE ≠ FAILED and a stale worker is
  never killed. A worker that heartbeats again returns to live on its next update.
- Worker ids must carry the owning pid (e.g. `cycle-worker-0-p<pid>`) so a daemon
  restart can deterministically reconcile thread-workers that cannot have survived
  it — orphans must never stay BUSY forever.
- Registration under concurrency needs `INSERT OR IGNORE` then `UPDATE` — a
  SELECT-then-INSERT check is a TOCTOU race that flakes only when several workers
  register at once; the test that catches it (N parallel registrations -> N rows)
  fails intermittently, so run the suite more than once before trusting it green.
- Secret redaction must handle `Key: value` with a space, not only `Key=value`:
  `Authorization: Bearer abc123` leaks the token if the regex stops at the first
  non-space after the separator. Cover both shapes and self-test the redactor.
- The process snapshot reads `/proc/<pid>` for Hermes processes only and filters by
  cmdline substring (`hermes`, `cycle.py`, `daemon.py`) — a bare test interpreter is
  not a Hermes process, so verify the reader against the live daemon (pgrep for
  `scripts/daemon.py`), not against the test's own pid.
- Heartbeats are same-row UPDATEs, never event rows — per-heartbeat events would
  grow the events table unboundedly inside one shift.
- Live verification is read-only against the production DB (registry rows, event
  counts by type) — a cycle that already ran provides real evidence; never spin up
  synthetic workload against a target to prove observability works.

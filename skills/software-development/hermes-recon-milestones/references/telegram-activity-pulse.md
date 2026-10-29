# Telegram activity pulse (10-minute) layer

Use for milestones that change the periodic Telegram pulse: exactly-once delivery,
window aggregation, Tehran/Shamsi presentation. Existing architecture to reuse —
do NOT build parallel systems:

- `lib/findings_state.py` — `log_activity_event()` writes the durable
  `activity_events` table (event_id, timestamp, target, module, job_type,
  items_processed, items_created, status, duration); instrumented from
  `scripts/cycle.py` at job finish. This IS the event store; add fields via
  additive ALTER, never a second events table.
- `lib/notify.py` `send_due_status()` is the ONE arbitration point for the 10m
  pulse and 30m full status. A second scheduler anywhere is exactly how a
  duplicate status stream starts — wire new pulse logic INSIDE it.
- `lib/activity_pulse.py` (added in the Stage 3 milestone) carries window
  semantics, the `activity_pulse_deliveries` idempotency table, and the Persian
  renderer; extend it rather than re-deriving.

## Enriching the pulse with worker/domain/queue data (bridge milestone)

The pulse should show RECON / RESEARCH / WORKERS / QUEUES / current-activity
sections built ONLY from already-persisted state — never a new scheduler, sender,
executor, or delivery table:

- Domain grouping comes from job_type/module metadata
  (`concurrent_domains.RECON_JOB_TYPES` / `RESEARCH_JOB_TYPES`, then the pulse's own
  module sets), and an unknown module is OTHER — never inferred from the target name.
- Render each section in its own try/except: a failed worker snapshot renders
  `unavailable`, a failed queue snapshot drops just that section, and the activity
  body always goes out. One broken data source must never fail the whole message.
- Worker states come from the Stage 4 registry; stale workers are labelled stale,
  never Failed. Counts come from registry state only — never inferred from job
  counts (busy workers != jobs run).
- Bound the message: cap items per section and current workers (e.g. 5) with an
  explicit `… +N` overflow line so the total counts stay truthful without flooding
  Telegram.
- Keep the job summary: enrich it (domain split + window totals) rather than
  replacing it, and keep every number scoped to `[win_start, win_end)`.
- Malformed events must be counted as skipped even when the row's timestamp is the
  bad field: select `timestamp IS NULL` rows too, or a NULL-timestamp insert is
  invisible to the isolation counter and the test passes for the wrong reason.
- Changing the pulse format invalidates format assertions in the pulse test file —
  update those assertions (label strings, colon placement) in the same milestone;
  the underlying exactly-once/idempotency checks must stay untouched.

## Rules that cost time when missed

- Exactly-once per aligned window: key is `activity_pulse:<win_start>:<win_end>`,
  claimed with BEGIN IMMEDIATE + INSERT, payload stored on the row so a retry
  sends the SAME text. Retry is bounded (5 attempts, backoff 60..900 s) and
  expired after ~30 min — an old failed window is dropped, not resent.
- Modules status/telegram/notify/report/heartbeat are NEVER activity; Telegram
  sends write no events. Filter them in the aggregation query, not the renderer.
- Never render lifetime counters (jobs/findings totals) as window activity; the
  pulse reads only events with timestamp inside [win_start, win_end).
- Presentation is Tehran fixed UTC+03:30 (no DST) + Shamsi date with Persian
  digits. The Jalali conversion is the exact jalaali-js port in
  `lib/activity_pulse.py::_gregorian_to_shamsi` — do not hand-derive a shorter
  algorithm: naive 33-year-cycle formulas drift by one day on leap-year edges
  (Esfand 30 / 1 Farvardin boundaries). Anchor-test any change:
  2026-03-21 == 1405-01-01 and 2026-09-24 == 1405-07-02 (2 Mehr 1405).
- Test the layer on a throwaway SQLite DB + mock sender; the real Telegram sink
  and any target/recon traffic are forbidden in tests. `send_due_pulse` must
  swallow DB exceptions and return an action dict — a raising pulse path
  crash-loops the daemon tick.
- daemon changes do not take effect until the daemon is reloaded; if the brief
  forbids restart, verify by direct dry-run against the read-only DB and report
  the pending reload as a limitation, not a failure. Prove it instead of assuming:
  compare the service start time with the mtime of the files you edited and look
  for a side effect only the new code creates — this layer's
  `activity_pulse_deliveries` table is the canonical tell, and its absence from the
  live DB means the pulse never ran through this code whatever the tests say.
- do NOT read the daemon log's `telegram status sent: <kind>` line as proof a send
  happened or failed. The in-cycle path (the daemon's cycle-poll loop) calls
  `send_due_status()` and discards its return value, so sends fired from inside a
  cycle write NO log line. Diagnose delivery from the delivery row instead:
  `activity_pulse_deliveries.status='DELIVERED'` with `attempts` and a
  `delivered_at` after the daemon start time IS the evidence.

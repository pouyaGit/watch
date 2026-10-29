# Telegram intelligence layer (status + alerting)

Depth notes for the operator-facing layer. Recon behaviour, rate ceilings and
budgets are NOT changed by this layer.

## Two message classes

- **Operational status** — interval-gated (default 600 s), exactly one message
  per interval, informational, never a security alert. Built by ONE function
  (`lib/status.py`-equivalent) that both the periodic sender and the `/status`
  command call; do not grow a second status implementation.
- **Security alerts** — event-driven, immediate, deduplicated, persisted.
  A high-severity finding must never wait for the next status tick.

One Telegram message per finding-status change, never per job: worker logs belong
in files and the DB. Keep a single direct-message guard for server-level
warnings (resource threshold crossed) — that is not a per-job message.

## Status content (all values real, omit rather than invent)

Header and state (RUNNING / PAUSED / STOPPED / EMERGENCY); current target and
current activity (from a persisted activity row: target, module, host, job id,
started_at, updated by the existing worker path — never a second execution
system); progress counters per module (checked / new today / live); queue
pending, running, completed; findings: new today, unacknowledged, and counts by
severity plus alert-queue state; resources from the EXISTING monitor (CPU%,
load vs cores, RAM used/total GB, disk) — do not add a second monitor; and a
timestamp in the system's configured timezone (never hard-code UTC).

Build status with no network access at all: pure reads of SQLite plus the
resource monitor. A test that patches `socket.socket` to raise and still gets a
status proves it.

## Schema (extend the existing DB, do not fork it)

Finding rows (both the generic findings table and the analysis-specific
candidate table) gain: title, description, evidence_ref, alert_status, acked_at,
source, severity, dedup_key, updated_at. Plus:

- `alert_queue(alert_id, ref_kind, ref_id, target, severity, confidence,
  message, dedup_key, status, attempts, last_attempt, next_attempt, created_at,
  delivered_at, grouped)` — statuses PENDING / DELIVERED / FAILED / SUPPRESSED.
- `activity(id=1, target, module, host, job_id, started_at, updated_at)`.

Lifecycle: NEW → ALERTED → ACKNOWLEDGED → VERIFYING → CONFIRMED/DISMISSED.
Acknowledgement changes notification state only and never deletes the finding.
An important finding stays visible until acknowledged or closed.

## Severity policy

HIGH → immediate individual alert. MEDIUM → immediate alert when there is real
evidence. LOW → queued SUPPRESSED: it appears in the periodic digest, the
findings summary and the `/unread` command, but pushes no message. Derive
severity from the existing confidence model; do not invent a parallel scale.

## Dedup and when a new alert is justified

Dedup key = `kind:id:severity:confidence`. Consequences:
- identical re-observation → same key → nothing queued (never alert because
  `last_seen` changed);
- confidence/severity increase → new key → an UPDATE alert
  ("FINDING UPDATED", showing old → new).

Baseline question: an UPDATE requires knowing the finding was already known, so
match against ANY prior alert row for that id — including a suppressed LOW one —
or a LOW→HIGH strengthening is announced as if it were new.

## Delivery loop

Drain due alerts oldest-first. HIGH individually; MEDIUM grouped when more than
a few arrive in one drain (single "SECURITY ALERTS" message listing ids, then
`/unread` for detail); cap the number of messages per drain. A failed send keeps
the row PENDING with escalating backoff and a bounded attempt count, and the
finding itself stays in SQLite untouched — Telegram is not the source of truth.
On startup, if unacknowledged important findings exist, send ONE recovery
summary (counts by severity + `/unread`), suppressed by a signature so it cannot
repeat every loop.

## Publishing during long work

The supervisor must not block on the cycle subprocess: poll it and call the
alert drain, the interval status and the watchdog ping from the polling loop,
otherwise alerts and status are delayed by the entire cycle duration. Also
deliver once immediately after the cycle returns.

## Commands

`/status` (same builder as the periodic message), `/unread` (unacknowledged
important findings), `/finding <id>` (full record: target, type, severity,
confidence, status, alert status, acknowledgement, source/sink, first/last seen,
evidence reference, exploitation NOT PERFORMED, manual verification REQUIRED),
`/ack <id>` (acknowledge, non-destructive), `/high` (unacknowledged HIGH),
`/findings` (counts summary). Wire them through the same CLI the Telegram agent
invokes so there is one code path.

## Test matrix (file sink, throwaway DB)

Point the notifier at a file and the store at a temp DB (`HERMES_NOTIFY_SINK`,
`HERMES_DB`-style overrides) so tests never send Telegram traffic and never
touch live findings. Cover: status content and interval gating; status makes no
network calls; current target/activity rendered from the activity row; new HIGH
and MEDIUM deliver; LOW sends nothing yet appears in the summary; duplicate
registration queues nothing; strengthening yields the UPDATE text; acknowledgement
persists and removes the finding from `/unread`; an unwritable sink preserves the
finding and retries boundedly; recovery delivers the pending alert and does not
flood afterwards; a real second process still sees unacknowledged findings and
the pending queue (true restart, not a module reload); bulk MEDIUM grouped into
one message.

# HERMES Telegram renderer map

Who owns which message class, what backs it, and what must not move.

## Modules

| Module | Owns | Load-bearing state |
|---|---|---|
| `lib/status.py` | compact status, digest | reads `snapshot()`; must not gain new queries' *meaning* |
| `lib/notify.py` | the sender, cadence, every `register_*_alert` gate, alert renderers | `alert_queue` |
| `lib/activity_pulse.py` | the 10-minute window, aggregation, delivery claim | `activity_pulse_deliveries` |
| `lib/pdreport.py` | per-target daily report, run-scoped diff | `pd_telegram_reports` |
| `lib/intelligence_impact.py`, `lib/intelligence_observability.py`, `lib/learning_signals.py` | verbose stage blocks | read-only; may gain a `compact` variant |

## Freeze list

Not modified by a UX change: `lib/store.py`, `lib/safety.py`, `lib/scope_guard.py`,
`lib/scheduler.py`, `lib/workers.py`, `lib/execplane.py`, `lib/planner.py`,
`lib/expert_hunters.py`, `lib/jev_director.py`, `lib/day5_experience.py`,
`lib/day6_investigation_path.py`, `lib/evidence.py`, `lib/decisionclosure.py`,
`lib/casemgr.py`, `lib/findings_state.py`, `scripts/cycle.py`.

No DDL. `alert_queue`, `activity_pulse_deliveries`, `pd_telegram_reports` keep
their columns.

## Gate functions whose predicates are frozen

`register_finding_alert`, `register_exposure_alert`, `register_evidence_alert`,
`register_learning_alert`, `register_plan_alert`, `register_calibration_alert`,
`register_confidence_alert`, `register_research_alert`, `register_case_alert`,
`register_decision_alert`, `enqueue_*`. Same for `EVIDENCE_ALERT_REASONS`,
`EVIDENCE_ALERT_PRIORITIES`, `EXPOSURE_ALERT_PRIORITIES`, `CASE_ALERT_REASONS`,
`DECISION_ALERT_STATES`, `PLAN_ALERT_REASONS`, `ORCH_ALERT_REASONS` and every
`*_MIN_SAMPLE` / `*_MIN_PRIORITY` threshold.

Their **rendered text** may change. Their `if` conditions may not.

## Read-only count sources

- human-confirmed → `day5_evidence_outcomes.human_verdict IN
  ('CONFIRMED_BY_HUMAN','CONFIRMED')`
- human review → `hunt_cases.status='WAITING_HUMAN'` and
  `decision_closures.decision_state='HUMAN_REVIEW_REQUIRED'`
- evidence outcomes → `day5_evidence_outcomes.outcome`
- intelligence impact → `intelligence_impact.collect()` (feedback / proposals /
  priorities_influenced)

If a query or column does not exist, mark the value `NOT OBSERVED` and continue —
never substitute a plausible number.

## Two canonical date/time contracts, and the host-tz trap

`lib/activity_pulse.py` owns the canonical Shamsi conversion:
`SHAMSI_MONTHS`, `_jdn_gregorian`, `_jal_cal` (jalaali-js `jalCal`),
`_gregorian_to_shamsi`, `tehran_fmt`, `shamsi_date`, `fa_digits`, `TEHRAN_TZ`.
Any other surface that renders a Tehran clock or a Shamsi date **must agree with
it by value** — including `web/db.py`, which carries the algorithm by value
(importing `lib/` from `web/` risks an import cycle into the daemon's module
graph) and is held to it by a 900-day equivalence test.

**The host runs in Asia/Tehran.** So both of these are wrong, in opposite
directions, and both look plausible:

- `datetime.fromtimestamp(e + offset)` — correct only on a **UTC** host; here it
  applies +03:30 **twice** and every timestamp is 3h30m ahead. Wrong clock, and
  the wrong **date** after 20:30 local. (This was `web/db.py`.)
- `datetime.fromtimestamp(e)` treated as if it were UTC — correct only on a
  **UTC** host; here it silently renders already-Tehran wall time as UTC. (This
  was `lib/activity_pulse.shamsi_date` / `tehran_fmt`.)

Use `datetime.fromtimestamp(e, TEHRAN_TZ)` with an explicit tz object:
host-independent, and it is what the contract means. Prove it with
`tehran_clock(now) == date +%H:%M`, not by reasoning about the offset.

A day-of-year-shaped Shamsi date (`۲۲۶۳۸۲ اسفند ۱۴۰۵`) is the signature of a
formatter that never consulted `jalCal` and printed the day-of-year as the day.
Assert the shape `^[۰-۹]{1,2} (<month>) [۰-۹]{4}$` across a long span, not just
today's date.

## Suppression ladder

1. empty window → no message, window still marked DELIVERED
2. zero-impact Intelligence → absent from pulse/status, one line in digest
3. byte-identical periodic payload → sender drops it, returns success
4. event-driven → existing dedup key decides, never the periodic filter

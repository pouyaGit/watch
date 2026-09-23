# AI Operations Window — Autonomous Operations (EPIC9)

## 1. What this is

A **bounded, recurring AI operations dispatcher** for Watch. Once per
hour during the configured window it wakes, discovers executable work
from the *existing* authoritative stores, executes **one bounded unit
of work** through the existing architecture, records truthful runtime
state, and exits. There is **no persistent worker and no daemon**.

```
watch-research.timer (hourly, OnCalendar, Persistent=true)
    -> watch-research.service (Type=oneshot, flock, TimeoutStartSec=330min)
        -> python -m ai.research_cli agent run
             (a) research scheduler pass   (R23/R92/R93, unchanged)
             (b) AI Operations Dispatcher  (EPIC9, opt-in per tick)
        -> process exits
    -> next hourly tick
```

## 2. The window (one authority)

`backend/ai_ops/window.py` is the **single** definition:

| Field     | Value          |
|-----------|----------------|
| timezone  | Asia/Tehran    |
| start     | 12:00 inclusive |
| end       | 00:00 exclusive |

Semantics: 11:59 CLOSED · 12:00 OPEN · 18:00 OPEN · 23:59 OPEN ·
00:00 CLOSED. A zero-length window (start == end) is always closed.
Conversion is `ZoneInfo`-based (DST-safe for any configured zone).

The research scheduler **consumes** this authority: `SchedulerConfig`
defaults come from `DEFAULT_WINDOW`, and `in_window` /
`next_window_start` / `parse_hhmm` delegate to the same module, so no
second copy of the semantics exists.

## 3. Dispatcher lifecycle (one tick)

1. acquire the tick lock (flock on `runtime/.ai_ops.lock` — same
   mechanism the stores already use; a concurrent tick reports
   `CONTENDED` and exits without touching state)
2. window check — outside the window the tick records `OFF_WINDOW`
   (outcome `SKIPPED_OUT_OF_WINDOW`) and performs **no** work
3. `sweep()` — existing stale-lease recovery (expired leases requeue)
4. discovery over existing stores (no new queue)
5. fail-closed eligibility classification per item
6. deterministic prioritization + bounded fairness selection
7. execute up to the budget, one bounded unit at a time (checks wall
   budget and window closure **between** units — never kills
   mid-transition)
8. persist state, emit truthful activity events, release lock, exit

Budgets (env-overridable, `WATCH_AI_OPS_*`):

| Var                       | Default | Meaning                      |
|---------------------------|---------|------------------------------|
| `WATCH_AI_OPS_ENABLED`    | `false` | dispatch allowed at all      |
| `WATCH_AI_OPS_MAX_SECONDS`| 600     | wall-clock budget per tick   |
| `WATCH_AI_OPS_MAX_WORK`   | 4       | max work units per tick      |
| `WATCH_AI_OPS_MAX_PER_TARGET` | 2   | per-target fairness cap      |
| `WATCH_AI_OPS_MAX_PER_CAMPAIGN` | 1 | per-campaign fairness cap    |
| `WATCH_AI_OPS_TICK_MINUTE`| 30      | next-tick display alignment  |

The dispatcher itself **never calls an LLM**. Executors run their
existing deterministic paths; no advisor callbacks are wired in.

## 4. Work classes and eligibility

| Class                | Source store            | Executable when                           |
|----------------------|-------------------------|-------------------------------------------|
| `RUNTIME_JOB`        | RuntimeStore jobs       | status QUEUED (after sweep)               |
| `FINDING_VERIFICATION`| FindingStore candidates | pipeline lifecycle up to verification, source job COMPLETED |
| `CAMPAIGN_OBJECTIVE` | CampaignStore           | campaign READY/RUNNING + objective READY (`OBJECTIVE_EXECUTABLE`) + deps ready + lease free + not in retry backoff |
| `HUNT_OBJECTIVE`     | HuntStore               | **report-only** — executed inside job/campaign execution |

Honest non-executable reasons (persisted per item):
`NOT_AUTHORIZED`, `WAITING_FOR_EVIDENCE`, `DEPENDENCY_BLOCKED`,
`ALREADY_RUNNING`, `TERMINAL`, `RETRY_NOT_DUE`, `OUT_OF_WINDOW`,
`INVALID_STATE`, `BUDGET_DEFERRED` (fairness).

## 5. NEEDS_EVIDENCE semantics

An objective in `NEEDS_EVIDENCE` is classified
`WAITING_FOR_EVIDENCE` and is **never** selected, reclassified,
downgraded, or fabricated. A blocked objective does **not** stall the
window: other executable items are still executed in the same tick.

## 6. Prioritization (deterministic, documented)

Total order (ascending):

1. class rank — `RUNTIME_JOB(0)`, `FINDING_VERIFICATION(1)`,
   `CAMPAIGN_OBJECTIVE(2)`
2. explicit priority descending (existing persisted priority; 50 when
   the store row has none)
3. age ascending (oldest first, `created`/`started`/`updated`)
4. scope/target ascending, then work id (stable tie-break)

Fairness: the selector walks that order enforcing
`MAX_PER_TARGET` / `MAX_PER_CAMPAIGN` / `MAX_WORK`; items that lose a
slot are reported `BUDGET_DEFERRED` with the cap that deferred them,
and run on a later tick. No opaque score, no security-quality
ranking, no LLM ranking.

## 7. Runtime state: process vs operations

Two separate facts, persisted in two separate files:

* **Process liveness** — `RuntimeStore` `worker.json`, TTL 120 s.
  `alive` only while a bounded worker heartbeat is fresh.
* **AI operations state** — `runtime/ai_ops_state.json`:
  `OFF_WINDOW`, `IDLE`, `DISCOVERING`, `EXECUTING`,
  `WAITING_FOR_EVIDENCE`, `BLOCKED`, `COMPLETED_TICK`, `FAILED`
  (`UNAVAILABLE` only when the source itself cannot be read).

Between ticks the healthy condition is: **process NOT RUNNING +
operations IDLE/WAITING_FOR_EVIDENCE**. The SOC overview and
`/api/intel/ai-ops` show both side by side.

State precedence when nothing is executable: any blocked item →
`BLOCKED`; only waiting items → `WAITING_FOR_EVIDENCE`; nothing at
all → `IDLE`. Successful in-tick completion → `COMPLETED_TICK`
(displayed as `IDLE`).

## 8. Activity events

Emitted through the existing audit stream (`RuntimeStore.record_audit_event`),
taxonomy-registered in `backend/prod_intel/activity.py`:
`ai_window_opened`, `ai_window_closed`, `ai_tick_started`,
`work_discovered`, `work_selected`, `work_started`, `work_completed`,
`work_blocked`, `waiting_for_evidence`, `tick_budget_exhausted`,
`ai_tick_completed`. Every event carries timestamp, tick id, work
type, target/scope, source object, state and reason where applicable.
Nothing fake is ever emitted: no heartbeat without a heartbeat, no
"active" without a real running process.

## 9. Recovery & concurrency

* stale leases: `RuntimeStore.sweep()` at tick start (existing
  semantics; nothing is deleted)
* interrupted tick: an operations state stuck in `DISCOVERING`/
  `EXECUTING` with a free lock is recorded as
  `recovered_interrupted` on the next tick
* duplicate/concurrent ticks: the flock lets exactly one tick run;
  the loser exits `CONTENDED`. Work claiming stays with the existing
  per-store lease/claim mechanisms, so no duplicate execution even
  across entrypoints
* window closing mid-tick: remaining units stop with
  `WINDOW_CLOSED`; already-started units are never killed
* crashed worker process: TTL expires the heartbeat, next tick
  sweeps and continues — no lost state, no fake success

## 10. Production operations

* Enablement (NO unit-file change — `systemd/watch-research.service`
  is a pinned AEC read-only contract file and stays byte-identical):
  `WATCH_AI_OPS_ENABLED=true` in `/opt/watch/.env`, which the unit
  already loads via its `EnvironmentFile=/opt/watch/.env` line.
  Manual `agent run` without that env never dispatches work.
* Read-only status: `python -m backend.ai_ops.cli status`
  (`--at ISO` is a labeled what-if projection, never executes).
* One tick on demand: `python -m backend.ai_ops.cli tick`.
* Restarting `watch-api` is only needed to pick up SOC UI changes;
  the research unit is a oneshot and runs the new code on its next
  tick with no restart.

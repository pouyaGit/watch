# The coverage / refresh scheduling layer

Use this when a milestone's job is to decide **what to refresh next** over an existing
inventory: which assets to (re-)cover, in what order, how much per pass, and when to
stop pushing. It is a *scheduling* layer, not a scoring layer: its unit is an
(`entity`, `stage`) slot and its output is bounded, fair, idempotent work requests handed
to workers that already exist.

Reach for this before inventing a scheduler. It does not replace
`planning-layer-model.md` (a layer that emits auditable REQUESTS for another component)
or `outcome-calibration-layer.md` (a layer that closes a loop); a coverage layer is the
thing that decides WHICH requests are worth emitting at all.

## The entity × stage model

- One record per `(entity, stage)` — e.g. `(host, dns|http|tech|js|local)`. The stage
  set is a CLOSED vocabulary and a pipeline ORDER: a stage may not be attempted before
  its prerequisite is satisfied, and each stage has exactly ONE module that closes it.
- **A stage is COMPLETE only from its own persisted observation.** Never from a scheduler
  timestamp, a queue row, a planned job, or a neighbouring stage. Store the stage's own
  `evidence_at` plus the source that produced it, and assert the invariant
  (`evidence_at IS NULL` for any COMPLETE row is a hard failure).
- **A recorded NEGATIVE is an observation.** "We looked and it does not resolve" is
  complete DNS evidence; treating it as pending makes the entity permanently uncovered.
  Reserve the pending state for "never attempted".
- **Mark the genuinely UNATTEMPTABLE state separately** (`BLOCKED`): an entity that fails
  a prerequisite — no resolution, so it cannot be fetched — is not outstanding work to
  schedule, and counting it as a gap makes the backlog permanently non-zero and the idle
  check meaningless.
- **Audit the evidence column before trusting it.** A convenient pre-existing field may
  be a sentinel rather than evidence: a column non-NULL for every row while the real
  coverage count is an order of magnitude smaller is a default/never-touched marker, not
  a measurement. Cross-check a count derived from the field against the count of real
  stored samples, and derive state from the sample table.

## Freshness

- Every stage has an explicit refresh window; freshness is computed from the stage's OWN
  observation timestamp, never from the pass clock.
- **Do not set your windows tighter than the existing system's.** Read the live staleness
  constants first: a new layer quietly re-checking hosts faster than the current planner
  is a rate-limit change delivered as a feature.
- **A failed attempt is a fact with its own retry cadence, and it is NOT "never tried".**
  Distinguish success / failure / timeout / blocked / cooldown; a timeout may succeed on a
  retry while a defensive block means slow down. Give each its own retry window, and
  record the attempt so the state carries evidence of what happened.
- A content-addressed asset (e.g. a script whose hash changed after analysis) is a real
  re-analysis gap: compare the analysed hash to the current one rather than treating the
  asset's presence as analysed.

## Priority

- Priority answers **"what should be refreshed next"**, never "how vulnerable is this". A
  scheduling layer must take no severity/CVE/exploit input at all — assert that.
- Build it from COUNTED dimensions with an explicit weight vector that sums to exactly
  1.0 (assert it): e.g. fully-unanalysed, stage weight, how far past the freshness window,
  upstream priority signals, recency of discovery, queue pressure.
- **`unanalysed` is a distinct dimension from `stale`** — an entity with no coverage
  anywhere is worth more than one whose single stage aged out.
- **An absent upstream signal is NEUTRAL, never a penalty.** Missing intelligence must not
  demote an entity; supply the neutral midpoint and say so in the reason string.
- Persist the reason AND the detail that produced it (which stage, which state, which
  upstream inputs), so a decision is explainable after the fact.

## Fairness, and the stamp that makes it work

- Score selection on **time since served**, clamped to a fixed ceiling, with outstanding
  need as the tiebreak inside that band. Uncapped idle time explodes to ~10^7 for any
  never-served entity and the need signal stops mattering.
- **Stamp every entity the pass serves.** The rotation only advances because the stamp is
  written; without it, every pass re-selects the same "never served" set forever.
- Apportion the per-pass budget by largest-remainder over health-weighted need, so a huge
  inventory gets more work without taking all of it, and every healthy entity in play gets
  at least one slot when the budget allows.
- Prove fairness as a PROPERTY OF REPEATED PASSES, not of one pass: after N passes the
  entities were served equally often, with zero consecutive overlap. A single-pass
  screenshot of a priority list proves nothing.
- Bound the expensive derivation to the same N the ranking selected — a gate that derives
  everything to serve a fraction costs more than the work it gates.

## Health and backpressure

- Model `HEALTHY / DEGRADED / COOLDOWN / BLOCKED` with a scheduling WEIGHT per state, so a
  struggling entity keeps making reduced progress instead of being silently dropped. A
  cooldown of zero weight is a suspend, not a delete.
- **Derive health from a RECENT window of counted outcomes, never a lifetime counter.**
  Cumulative totals over a long-lived entity's whole history make every veteran look
  permanently degraded. Use the failure ratio over the newest N attempts, and let a run of
  recent successes recover it — recovery outranks history.
- Prefer reusing the system's persisted health record for the hard signals (an explicit
  cooldown timestamp) and derive the rest from the entity's own job outcomes.
- Backpressure: when the downstream class queue is already at its cap for this entity,
  DEFER and record the reason — never enqueue and hope. Measure pressure per
  (`entity`, `stage`): a per-class pending count measured GLOBALLY against a per-entity
  ceiling pins every stage at full pressure and closes the gate permanently.
- A layer that schedules work must bound its OWN footprint: cap how many of its jobs may
  be open at once, or it fills the shared queue with its own requests.

## Ceilings

Declare one ceiling per stage, one per pass, one for the entity count, one for open
footprint, and one for the audit trail. Then:

- **Every ceiling must be REACHABLE.** A per-stage bound set above the global per-pass cap
  or above the cap the downstream component already publishes can never fire, so the bound
  is fiction and its `ceilings_hit` entry is dead code. Set production values so each is
  the binding one somewhere; in tests, raise the outer bounds out of the way so the bound
  under test binds.
- An env override may only TIGHTEN; verify both directions plus a malformed value falling
  back to the default.
- **Exempt the SELECTED decision from the audit-row budget.** Bound the deferral trail
  separately and count the overflow, but always write the row for a request that really
  was emitted — otherwise a row budget exhausts itself and a live job has no audit trail.
- Reconcile the counts: enqueued + deferred + skipped must equal the candidates
  considered, and the run must report the overflow rather than dropping it silently.

## The fixture recipe for boundedness

A bound is only proven when the corpus can exceed it.

1. Stage the fixture so the entity's FIRST outstanding stage is the stage under test.
   Walk the chain in order: satisfy every earlier stage through the REAL evidence tables
   (resolution row, fetched sample, ledger entries) — a fixture that leaves entities at
   stage 1 exercises stage 1's bound only.
2. Do NOT insert the evidence the stage under test is supposed to produce.
3. Return the ELIGIBLE-CANDIDATE count from the fixture and assert it exceeds the cap.
4. Require the observed value to equal the effective bound (see the skill's
   `bound_observed <= bound_declared` rule), and remove any other ceiling that would
   shadow the one under test.
5. Drive idempotency separately: a repeat pass must add ZERO rows and ZERO jobs, with
   pass 1 proven to have done real work.

## Integration rules

- **Reuse the existing worker's payload shape EXACTLY** so your requests deduplicate
  against the component's own pending work; keep your bookkeeping in your own rows.
- Re-derive the scope/safety verdict for the concrete work item immediately before the
  enqueue — not once at discovery, and never on the target's LABEL (a wildcard entry does
  not cover the bare apex, so a label check rejects every wildcard entity).
- Register one bounded scheduler class for the layer with a single slot, and gate it with
  the standard order: cheap read-only work check first, cadence stamp last.
- One pass for the whole system (the layer selects its own entities internally) beats a
  per-entity job, which re-selects the same entity every cycle.

## Pass performance

- **Profile before accepting a slow pass.** A per-entity helper that opens a fresh store
  connection re-runs the entire schema on every call, so most of a pass's wall time can be
  schema reloads rather than work. `cProfile` first; then give the check/write path ONE
  shared batch connection behind a `(conn, owned)` accessor so no statement is duplicated
  and behaviour outside the batch is unchanged.

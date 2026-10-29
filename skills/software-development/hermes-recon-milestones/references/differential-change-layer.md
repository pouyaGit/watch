# The differential / change-intelligence layer

Use this when a milestone's job is to answer **"what materially changed since the
previous trusted observation?"** over evidence another component already persists: a
recon diff, a config drift detector, a regression watch. It is an *observation-diff*
layer, not an acquisition or scoring layer: its input is two observations of the same
entity, its output is a bounded set of typed change events.

Reach for this before inventing a change model. It does not replace
`coverage-scheduling-layer.md` (what to refresh next) or `outcome-calibration-layer.md`
(did the action help); it is the layer that CONSUMES what those produce.

## The division of authority

The upstream acquisition component stays authoritative for **what was observed and
when**. The diff layer is authoritative only for **what changed between two
observations**. State that separation explicitly in the module docstring and enforce
it: the diff layer reads the upstream tables and never writes them, and it never
decides when to look again — that is the scheduler's call.

## Content-addressed observations

- One fingerprint per **semantic dimension**, each with its own normalizer. A dimension
  is the unit of comparison, so a change in one never masks a change in another.
- **Normalize before hashing**, and treat normalization as the feature it is: header
  name case and order, JSON key order, set ordering, query strings, and a documented
  list of volatile tokens (clock, per-request ids, session cookies, hop-by-hop
  transport headers) all get removed before the hash. The list of ignored tokens is
  itself part of the contract — export it as a constant and test it.
- **Never put a volatile field in a fingerprint**: run id, row id, queue id, scheduler
  timestamp. The observation's own timestamp travels BESIDE the fingerprint, not inside
  it.
- Separate the two timestamps the layer needs, because they mean different things:
  `observed_at` is the EVIDENCE's own time (the fact), and a second `compared_at` is
  when the diff layer last looked at this row (the bookkeeping). Only the second one
  may drive rotation. See the rotation rule below.

## Baselines, and the states around them

A closed set: `NO_BASELINE · BASELINE_CREATED · BASELINE_VALID · BASELINE_SUPERSEDED`.

- **The first observation of an entity is never a change.** It creates the baseline and
  emits nothing. A `NEW_ASSET`-style event requires a prior trusted inventory that did
  NOT contain the entity, plus a current observation that does — hence the inventory set
  belongs in its own dimension at the PARENT level, not per entity.
- **A superseded baseline must be EXCLUDED from every later comparison, not merely
  labelled.** Marking the row and leaving it in the comparison set makes the same event
  re-emit on every subsequent pass, forever. The filter belongs wherever the comparison
  set is built, and the same exclusion is needed in the absence scan.
- **A removal is consumed exactly once.** Freeze the counter at the threshold on the
  pass that observes it, then fetch the persisted row at write time and skip anything
  already superseded. Recomputing a fresh count from the same observed facts each pass
  makes "3 consecutive misses" fire forever. An entity that reappears later goes back to
  BASELINE_VALID — that is a valid state transition, not a new baseline.

## The comparison window

- Two observations too far apart may not be compared as if simultaneous: emit an
  explicit `STALE_COMPARISON`, refresh the baseline, and manufacture nothing. Measured
  from the two EVIDENCE timestamps, never the run clock.
- An undateable observation is stale by definition.
- **Set the window LOOSER than the upstream component's refresh cadence**, or the diff
  refuses comparisons the acquisition layer considers fresh and the layer silently stops
  working. Read the upstream window from the module and state the deviation.

## Removal policy, and what may not testify about absence

- Never a removal from one failed fetch, one DNS blip, a cooldown, or a skipped pass.
  Require: the parent observation is COMPLETE (it produced real children), the entity has
  a prior trusted baseline, AND it has been absent for N consecutive complete
  observations. Persist N and the counter so the policy survives a restart, and report
  the count and the threshold with the event.
- **Count one miss per pass per entity, not per row you happen to scan.** If the same
  entity appears under two keys (a presence record and a dimension record) and the scan
  visits both, incrementing per match halves the documented threshold. Advance on the
  first match of the pass and carry the rest through unchanged.

## The rotation is the fairness mechanism — and its key must advance

- Order the work by **how long since the diff layer itself last compared it**, i.e. the
  bookkeeping stamp, and write that stamp for everything the pass really compared.
- **Never order by the evidence's own timestamp.** An unchanged observation keeps its
  source timestamp forever, so the same first N rows win every pass, the tail of a large
  inventory is never reached, and the run reports healthy throughput while covering a
  fixed slice. This is the single easiest way to build a diff layer that looks busy and
  converges on nothing.
- Unknown / never-seen work comes first so discovery is not starved; then the known work
  in the advancing order, with a stable name tiebreak to keep the order total.
- **Stamp only rows that were really compared.** Stamping an entity the budget skipped
  sends it to the back of the queue with nothing done, and it starves on the next pass.

## The per-pass budget is GLOBAL, not apportioned per entity

- A global budget plus the advancing rotation is what gives every entity its turn:
  an entity whose work did not fit keeps an old stamp and comes back first.
- **Do not also apportion the budget per entity** — with eighteen entities and sixty
  rows that is three rows each, so a pass advances about one item per entity and most of
  the corpus is never reached. A bound that quietly defines the covered set instead of
  bounding it is worse than no bound. Apportionment belongs to the SELECTION layer
  (which entities get a slot at all), not to the intra-entity walk.
- Predict the unserved remainder from counts (total items versus the budget) and record
  it as deferred work. Deriving it from the walk instead is wrong in both directions:
  the walk has no observation for an item the upstream component could not produce, so a
  corpus full of unobserved items reads as healthy progress and is indistinguishable from
  a finished one.
- Backpressure may ration how many entities are **opened**; it must never make a pass
  refuse to work. "In flight" means STARTED AND NOT FINISHED — if it means "has a
  remainder", an unopened entity counts as busy, the opening budget is spent before
  anything starts, and the layer deadlocks.

## Backpressure must never discard a change

**A change the budget cannot persist must hold its baseline back.** If the new trusted
observation is written while its change event was dropped, the change is undetectable on
the next pass and is lost forever. Process changes before baselines for each entity, have
the dropped pairs travel on the result, and skip those baselines at write time. Freezing
a baseline FORWARD is the one failure mode backpressure must not have; deferring is fine.

## Record shape

- **Build every event in ONE constructor.** Predicate layers that return bare detail
dicts while the callers re-stamp the type, identity and significance guarantee that one
caller eventually forgets a field and the consumer raises `KeyError` on a path the
engine considers normal. The constructor sets the type, derives the identity, and looks
up the band, so those three can never disagree.
- Keep the type vocabulary CLOSED and assert the closure at import: every dimension's
  emitted types are a subset of the vocabulary, and every real type has exactly one
  predicate. An unknown type is REJECTED, never silently stored.
- **Scope the audit-row granularity to what the brief names** (entity, not
experimental-condition). One audit row per (entity, condition) exhausts a per-run row
budget after a handful of entities and the audit trail then describes a fraction of the
work it claims to bound. Roll the per-condition outcomes into a detail field and one
summary reason on a single row per entity.
- Bound the audit trail separately from the work, route EVERY write branch of it through
one budget-checking funnel (so a trailing per-row branch cannot bypass the cap), and have
a pass whose shared budgets are spent stop before the next entity rather than half-process
it.

## Significance, versus severity

The band answers "how operationally meaningful is this change?" and must never answer
"how vulnerable is this target?". Keep the vocabulary free of severity words so a reader
cannot infer a capability that does not exist, and assert that in the suite. Escalate a
band only on a documented structural fact (a content hash moving on a large asset), and
make the escalation reason explicit.

## Alerting

Gate on significance and on an existing upstream attention signal, and keep the
type-to-alert mapping an EXPLICIT allow-list: a type outside it is never alerted, so
adding a type to the vocabulary cannot start notifying by accident. Routine
re-observation is silent. Dedup on the deterministic change id so the same change can
never notify twice, and reuse the existing alert gate rather than adding a second.

## The fixture recipe

- Build fixtures **through the real store API and the real schema**, and clear the table
  (or the natural key) first so a fixture write cannot accumulate rows the real writer
  would upsert.
- **Give the fixture entity a host/name that is genuinely IN SCOPE for the target**, by
  deriving it from the scope ENTRY (`*.x.co` -> `sub.x.co`), never from the target
directory label — a per-entity scope check correctly rejects the bare apex and the
  fixture silently produces no data, which reads as an engine bug.
- **Pin the rotation** so the fixture's own passes are not competing for a slot: stamp
  every other entity, and be aware the idle term is clamped so a stamp in the fixture's
  future is what actually holds the slot.
- Drive to a state where the property must hold rather than asserting it on a quiet
  corpus: a removal policy needs passes BEYOND the threshold, an idempotency claim needs
  saturation first.

## A diff layer with no consumers is HALF a layer — and is the next seam

Detecting and persisting changes is only half the job. The other half is that something
downstream must act differently because of them, and that half is easy to leave unbuilt
because nothing fails when it is missing: the engine passes every suite, the change table
fills, and no finding, case, priority or report ever reflects it.

- **Enumerate the consumers in the docstring, then IMPLEMENT them.** A diff module that
  names its downstream authorities (case manager, prioritizer, orchestration, learning)
  as prose while making no cross-milestone write has documented a capability it does not
  have — worse than omitting it, because a reader believes it.
- **Route, never recompute.** The consumption hop attaches the change to the downstream
  component through that component's EXISTING public API (attach a member, supply a
  scoring dimension, expose a candidate) and lets it keep its authority. The diff layer
  never invents its own priortizer, its own case, or its own finding.
- **The landing point is an ownership fork** — attach to cases, feed the prioritizer,
  expose an orchestrator candidate, or record a learning observation, each already owned
  by a different milestone. Surface the options rather than silently picking one, and
  never write another milestone's table to "close" the loop.
- **A dead table is a signal, not a target.** An output table sitting at zero rows in
  production may be a deliberate limitation to disclose rather than something to
  populate; say which, and do not write another milestone's owned surface to fix it.
- Verify the seam by COUNTING CONSUMERS (see the consumption-audit section of SKILL.md
  and `scripts/audit_layer_consumption.py`), not by reading the docstring that claims
  them.

## The verification suite set a diff layer needs

Six suites, each answering a different question. A green functional suite proves almost
nothing on its own — it is the one that passes while the layer is unwired.

1. **Functional** (`test_<m>_diff`) — one check per change type, the baseline states, the
   removal policy, the freeze, the reader/writer key agreement. Derive the type list FROM
   the module's vocabulary constant so a new type cannot be added without a check.
2. **Safety** — derive every check MECHANICALLY from the source (AST for imports and
   calls, collected write targets for the table set): no network library imported, no
   subprocess, the executor refuses, the table set is a SUBSET of the owned set, no
   previous milestone's authority is re-implemented. Prove the probe can report a real
   break rather than scanning for its own name.
3. **Bounded storage** — one check per declared ceiling, each with a corpus sized
   against THAT bound, plus the repeated-pass storage claim. Distinguish a working bound
   (must be reachable) from an audit safety net (assert ENFORCEMENT, and assert the
   ordering between them).
4. **Commands / wiring** — invoke every subcommand through the real CLI and assert exit
   status and output, plus the planner gate and the cycle dispatch. "Appears in the
   dispatcher" is not "reachable".
5. **Live verification** — READ the real production database, but perform every bounded
   write into an ISOLATED tree, and state that no write reached production. Prove the
   live property that a throwaway DB cannot: the gate sees real pending work, the scope
   guard rejects a real out-of-scope host, and the daemon's own run row appears in the
   live table. Choose the probe entity by MEASURED size against the per-run bound (a
   rotating walk skips a large entity, so a correctly-working layer looks broken).
6. **Snapshot** — zero deletions, with the milestone-caused verdict kept separate from
   the all-actors live diff; every protected table non-decreasing; no schema mutation
   outside the milestone's own region; the snapshot itself leaving live state unchanged.

Report the suite counts as `N/N` read from the CURRENT run log, and re-run all six
against the frozen final code — a count from before the last engine fix is not evidence.

## Milestone delivery rules for this layer — the ones that cost a debugging cycle each

- **A dimension's rotation key must be the DIFF layer's own comparison stamp, never the
  evidence's timestamp.** An unchanged observation keeps its source timestamp forever, so
  ordering by it re-selects the same first N rows every pass and the tail of the inventory
  is never reached — while the run reports healthy throughput. Stamp what you compared and
  order by that; and stamp ONLY entities you really compared, or a skipped one sinks with
  nothing done and starves.
- **One budget, global — do not also apportion it per entity.** Eighteen entities sharing
  sixty rows is three rows each, so a pass advances about one item per entity and most of
  the corpus is never reached. Apportionment belongs to entity SELECTION; the intra-entity
  walk needs a global budget plus the advancing rotation.
- **A change the budget cannot persist must hold its BASELINE back.** Writing the new
  trusted observation while its change row was dropped makes that change undetectable on
  the next pass — lost forever. Process changes before baselines and let the dropped pairs
  skip their baseline write. Freezing a baseline forward is the one thing backpressure must
  never do; deferring is fine.
- **A superseded baseline must be EXCLUDED from later comparisons, not merely labelled.**
  Leaving it in the comparison set re-emits the same event every pass, forever. An absent
  entity's EVERY dimension baseline is superseded, not just its presence record — no
  per-dimension diff runs for an entity that is not there.
- **Consume a removal exactly once.** Freeze the counter at the threshold on the pass that
  observes it and fetch the persisted row at write time, skipping anything already
  superseded. Recomputing a fresh count from the same observed facts makes "N consecutive
  misses" fire on every later pass.
- **One key, written and read as the SAME constant.** Writing the parent-level record under
  `inventory` while the reader looked up `#inventory` meant the parent-level `NEW_ASSET`
  path never ran at all, and the pseudo-key was diffed as if it were an entity. Assert the
  reader and writer agree on the key, not just that two constants exist.
- **Build every change event in ONE constructor.** Predicates that return bare detail
  dicts while callers re-stamp type/identity/significance guarantee that one caller
  eventually forgets, and the consumer raises `KeyError` on a normal path.
- **Scope the audit-row granularity to what the brief names.** One row per
  (entity, condition) exhausted a 400-row budget after ~50 of 392 entities, so the audit
  trail described a fraction of the work it claimed to bound. Roll the per-condition
  outcomes into one summary row per entity, and route every audit write through one
  budget-checking funnel.
- **A module-level loop variable can shadow a helper you defined above it.** A name bound
  by a top-level `for` (even in an import-time assert) rebinds the module global, so the
  helper becomes a tuple and every later call raises `TypeError: 'tuple' object is not
  callable`. Name loop variables unambiguously (`_dim_key`, `_ct`) and never reuse a
  helper's name.
- **A column list and its argument tuple are two hand-maintained lists; assert the
  arity at the write helper.** A column removed from the DDL but left in the list, or a
  value added to one and not the other, is a `ProgrammingError` at RUN time on a path a
  suite may never exercise.
- **A fixture entity must be genuinely IN SCOPE for the target, derived from the scope
  ENTRY.** A disappearing-host fixture built from the target directory label
  (`gone.odesli`) is correctly rejected by the per-entity scope check — the engine was
  right and the test was wrong, which cost a full debugging detour. Derive from the
  wildcard base (`gone-sub.odesli.co`), and pin the rotation so the fixture's own passes
  are not competing for a slot.
- **Namespace a new env-var override with the milestone.** A ceiling override read a
  BARE name (`MAX_CHANGES_PER_RUN`), so any unrelated variable of that name in the
  environment could silently tighten the bound — and the safety suite that probes the
  override then fails against an env var the code was never meant to read. Grep for
  existing readers before naming one, prefer `M21_MAX_CHANGES_PER_RUN`, and keep the
  open override so a suite can pull a bound down (never raise it).
- **Choose a live probe's subject by MEASURED size against the per-run bound, not by
  convenience.** A probe that mutates a host and then re-runs only proves itself if that
  host fits inside one pass: with a rotating walk bounded by `MAX_ASSETS_PER_RUN`, the
  changed host sits at the back of a queue of ninety-odd and the probe reports "no change"
  for correct behaviour. Pick the smallest populated entity whose inventory fits one pass,
  and require its scope to be a WILDCARD (an exact-host scope may match a single label).
- **An AST check beats a substring check for "this function reads no clock".**
  `"time" not in src` matches `unknown` inside the function's own error message and reports
  a defect that does not exist — as useless as a check that cannot fire. Walk `Name` and
  `Attribute` nodes for banned identifiers instead, and prove the probe can report a real
  break.

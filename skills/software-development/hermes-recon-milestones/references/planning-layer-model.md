# The planning-layer model (routing layers, M10 / M12 style)

A reusable shape for any HERMES layer that turns stored context into bounded,
auditable REQUESTS for another component to execute. Use it as a starting model,
not a spec: adapt field names to the existing conventions of the milestone, and
reuse the previous layer's taxonomy rather than declaring a parallel one.

## Division of authority

```
M9 exposure   -> context: what was correlated, at what priority
M10 evidence  -> what is MISSING (gaps) and which safe actions exist
M11 learning  -> historical yield of each action (supporting evidence only)
PLANNER       -> bounded plans: what, why, expected evidence, who owns it
owner gates   -> M10 executes local/HEAD/GET, M6 owns Nuclei, M8 owns research,
                 HUMAN owns anything not auto-resolvable
outcome       -> back into the previous layer's existing learning engine
```

The planner never executes. It revalidates, marks the plan routed, and stops. The
owner's own gate decides whether the work actually happens — the planner cannot
bypass it, cannot create or promote a template, cannot classify trust, and cannot
widen scope.

## Plan fields worth keeping

Identity, provenance and explanation (never optional):
`plan_id` (deterministic), `created_at`, `updated_at`, `dedup_key`, `created_by`,
`model_version`, `provenance` (which layers contributed, which actions were
considered, which was preferred vs alternate).

Subject: `target`, `host`, `product`, `version`, `exposure_id`, `correlation_id`,
`evidence_gap_id`, `intelligence_id`.

Action: `action_type`, `action_owner`, `safety_class`, `expected_evidence`,
`preconditions`, `dependencies` / `depends_on_plan_id`, `cost_rank`,
`attempt_ceiling`, `cooldown`, `attempts`.

Reasoning (keep the derivation visible, never collapse into one score):
`plan_reason` (semicolon-joined explicit clauses), `base_priority` (upstream's),
`learning_hint` (previous layer's), `plan_priority` (this layer's), `priority_reason`,
`estimated_value` + `value_reason`, `confidence`, `sample_size`, `sample_band`.

Lifecycle: `status`, `expires_at`, `alternate_action`, `chain_depth`.

## Bounded status vocabulary

`PROPOSED, READY, BLOCKED, DEFERRED, SENT_TO_<OWNER>, HUMAN_REVIEW, COMPLETED,
FAILED, EXPIRED, CANCELLED`

Omit any stronger state by construction — a plan state that implies a confirmed
vulnerability must not exist in the tuple at all, so it cannot be set or inferred.
Keep the tuple as a single named constant and assert against it.

## Ceilings (hard constants, environment may only LOWER them)

- actions per dependency chain, e.g. 5
- plans per exposure, e.g. 10
- plans generated per run, e.g. 25
- plans queued globally, e.g. 100
- planner runtime bound, e.g. 60 s

Resolve every ceiling through a helper that takes `(env_name, default, hard_max)`
and clamps to `hard_max`, so an environment variable can tighten a bound but never
raise it. Assert the clamp — a ceiling helper that trusts its input is not a ceiling.

## Time and expiry

Every plan has a lifetime; a default (e.g. 6 h) with a permitted extension for
high-priority work (e.g. 12 h) capped by a hard maximum. Never unlimited. Sweep
expired plans at the START of each run and skip terminal states when sweeping — a
completed/cancelled plan is a historical record and is never rewritten.

## Dependencies

- Support bounded chains via `depends_on_plan_id` (plus a join table for auditing).
- Refuse a link that would create a cycle, and refuse one that would exceed the
  chain ceiling — returning a REASON, not a silent failure.
- A dependent is satisfied only when its dependency reached a SUCCESS state; an
  expired or failed dependency leaves the dependent unroutable.
- Assert no self-dependency.

## Analyst decisions

`APPROVE, REJECT, DEFER, CANCEL, REPLAN` — plus the rule that a decision is never
silently overwritten by a later automated run, and that `REPLAN` mints a new
deterministic version while preserving the original row and its decision.

## Competition between candidate actions

When several actions could resolve the same gap, pick one as `preferred` and keep
the next as `alternate`, persisting BOTH with an explicit rank and a preferred flag.
Persist the losers for AUDIT, but only the selected one may hold an ACTIVE/routable
status: storing every candidate as live work multiplies rows by the candidate count
and blows the per-loop step ceiling (six active steps against a cap of five).
Rank by the upstream mapping's declared order, not by a local cost heuristic, and
never eliminate a competitor silently. A historically low-yield action becomes a
lower preference WITH a reason — only safety policy may disable it.

## Learning integration

The planner does NOT grow a second learning engine. It normalises its outcomes into
the existing event vocabulary and contributes ONE event per outcome, with the
existing layer's own identity function so both sides agree on the same id and a
re-run cannot inflate sample sizes. Carry `sample_size` and the sample band on the
plan; a small sample stays small and is never presented as proof. Pin the time
bucket so identity is independent of WHEN it is computed — and note that a
time-bucketing helper divides by its bucket, so a zero bucket is unusable.

## Human-facing surface

Two views minimum: a LIST that states its own ceiling and a DETAIL view that shows
the subject, the gap, the chosen action and its owner, the expected evidence, the
priority derivation (base → hint → plan, with the reason), the value with its
reason, the learning sample, the precondition checklist with pass/fail, and the
competing actions. Include an explicit "nothing to route / no actionable plan"
answer rather than an empty result, and state plainly that a plan is a PROPOSAL and
that the highest state it may describe is potential exposure.

## Notification gate

Alerts are SIGNIFICANCE-gated, not activity-gated: a new high-priority actionable
plan, a high-priority plan that just became blocked, a plan needing a human, or a
new plan of genuinely high value. A routine run that merely re-confirms existing
plans emits nothing. Dedup on (plan, reason, status, owner) so a repeated run never
re-alerts, and never phrase a plan as a confirmed vulnerability. Apply the
IMPORTANCE bar to the 'new item appeared' reason too, not only to the
'high-priority' reason: gating only the latter lets a routine pass emit one message
per newly-seen item — a message storm built out of individually defensible rules.

## When the plan is a QUESTION, not an action

A loop-closing layer (M15 style) plans RESEARCH, so the unit is an uncertainty to
reduce rather than an action to take. The routing model above still applies, with
these deltas.

- **Keep the uncertainty taxonomy separate from the confidence vocabulary.** The
  upstream layer's states (UNKNOWN / LOW / CONFLICT / STALE) describe how much is
  known; the planner's states describe WHAT KIND of gap it is (identity unknown,
  version ambiguous, evidence stale, sources conflicting, correlation weak, human
  required). Deriving a question type from a confidence state is the mapping in one
  direction only — never mutate the upstream state, and never let the planner's own
  state stand in for it.
- **Expected information gain is 'how much uncertainty could this reduce', never a
  probability of vulnerability.** Class it in bounded bands and derive it
  STRUCTURALLY from what the action's owner can actually return for that question
  type (a HEAD can yield an exact version banner; another generic banner cannot).
  Say so in the alert text, so the number cannot be read as risk.
- **Cost is planning metadata only.** Local re-reads cheapest, then network reads,
  then a trusted-scanner request, then research, then a human. Cost never overrides
  safety, and the layer must not be able to raise a ceiling because a step looks
  valuable.
- **Every selection records WHY_SELECTED, from named ranking inputs.** Persist the
  priority, the information gain, the cost, the historical support and the selection
  reason as separate fields — never a single opaque score, and never a number with no
  derivation behind it.
- **Historical support is quoted with its sample size and band, in non-committal
  language.** 'Historically resolved similar gaps' plus n and the window; never a
  guarantee, and a small sample stays labelled small rather than becoming a weak
  preference.
- **An alternative that never ran is UNKNOWN.** Record the unexecuted alternate for
  the audit trail and classify its counterfactual as UNKNOWN — never 'would have
  worked', and never a simulated outcome for something that did not execute.
- **Re-evaluate the question after new evidence; do not equate completion with
  resolution.** An action finishing is not the uncertainty improving: classify
  RESOLVED / PARTIALLY_RESOLVED / UNCHANGED / WORSENED / CONFLICTED / STALE from the
  uncertainty itself, after the upstream confidence layer has re-run. The planner
  never edits upstream confidence; new evidence flows back through it.
- **Stop conditions are enumerated and reported, not implied.** Uncertainty
  resolved, confidence sufficient, no safe action left, action ceiling, loop ceiling,
  conflict needing a human, state changed, evidence now stale, precondition failed.
  Reaching one yields HUMAN_REVIEW with the reason, and exceeding a loop ceiling must
  never silently truncate.
- **Patterns are advisory.** Detecting recurring shapes (repeated unknowns, repeated
  low-yield actions) must not suppress or auto-demote anything — surface it and leave
  the decision where it was.
- **'No safe action exists' is a claim about the world, not about this run.** Before
  recording it, check whether the same question already has a step ROUTED elsewhere and
  awaiting its outcome. When a planning window rolls over, a fresh pass for an in-flight
  thread finds no new step to create and — if that branch writes NO_USEFUL_SAFE_ACTION —
  records a confident, false reason and raises a human review with nothing to decide.
  Distinguish 'nothing can be done' from 'it is already being done' as separate statuses
  with separate reasons, and route the subject to a WAITING_OUTCOME state rather than
  HUMAN_REVIEW.
- **A ceiling stop must be REPORTED as well as honoured.** Breaking out of the per-loop
  step loop is not enough: the ceiling never appears in `ceilings_hit`, so a suite
  asserting 'a ceiling that was hit is recorded' sees nothing while the bound held
  perfectly. Append the ceiling AND an explicit result row with its stop reason at every
  break, so a held bound is externally observable.
- **A new window must not open a second thread; and a closed one must not hold the
  budget.** Identity on `(subject, window)` dedups within a window and duplicates across
  rollovers — continue the subject's OPEN thread instead of minting a fresh one, and
  count only non-terminal threads against the per-subject ceiling so abandoned attempts
  do not ratchet the subject shut. Prove both directions: after a rollover the subject
  still has exactly one open thread, and an exposure with three cancelled threads can
  still be planned.
- **Re-validate against the REAL upstream rows, and record which precondition failed.**
  Handing the revalidator `None` for the subject row makes it assert 'the row is gone'
  for every step, so everything reads STALE with an untrue reason and the audit trail
  fills with confident fiction. Build the lookup and pass the rows; on failure, persist
  the failed precondition text so a blocked step is diagnosable rather than mysterious.

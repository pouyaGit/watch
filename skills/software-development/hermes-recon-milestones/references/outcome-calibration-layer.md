# Outcome, calibration and feedback layer

The reusable shape for a layer that CLOSES a loop: something else plans and executes,
this layer measures what actually happened and feeds the result back to the planner and
the learner. It is a MEASUREMENT layer — it creates no actions, executes nothing, and
touches the network zero times.

## Canonical outcome record

One row per (plan, action, execution, result). Concretely: `outcome_id`, `plan_id`,
`action_id`, `target`, the correlation and gap ids it came from, `action_type`,
`action_owner`, `started_at`/`finished_at`/`duration_ms`, `status`, `result_class`,
`expected_evidence`, `observed_evidence`, `evidence_yield`, `gap_before`, `gap_after`,
`resolution`, `confidence`, `failure_reason`, `blocking_reason`, `provenance`,
`content_hash`, `model_version`.

**Keep YOUR closed result-class set even when an upstream model has its own.** The
upstream learner may lack a class you need (a cancelled or never-executed action).
Reviewers will check that the upstream's own vocabulary is not being redefined —
reuse the shared constants, then MAP at the boundary into the upstream's set. One
layer's closed vocabulary, one mapping function, and a test that every class maps.

Result classes used here: USEFUL, PARTIALLY_USEFUL, NO_NEW_EVIDENCE, CONTRADICTORY,
FAILED, BLOCKED, EXPIRED, CANCELLED, NOT_EXECUTED. Do not invent states outside it.

## Expected vs observed, yield, resolution

| Expected | Observed | Class |
|---|---|---|
| X | X | USEFUL, resolution RESOLVED |
| X | Y (another real evidence type) | PARTIALLY_USEFUL |
| X | conflict | CONTRADICTORY |
| X | nothing after a real attempt | NO_NEW_EVIDENCE |

**"The action succeeded" and "the gap resolved" are DIFFERENT facts** and must be
separate columns. A 200/exit-0/completed job that produced no new evidence is
NO_NEW_EVIDENCE, not success. Resolution vocabulary: RESOLVED, PARTIALLY_RESOLVED,
UNCHANGED, CONTRADICTED, NOT_APPLICABLE.

**Yield is a small ordered set, never an opaque score**: 0.0 no useful evidence, 0.5
partial, 1.0 expected evidence acquired and the gap resolved. Persist `yield_value`
AND `yield_reason`.

## Effectiveness and sample size

Per action type: attempts, executed, useful, partial, no_new_evidence, contradictory,
failed, blocked, cancelled, plus evidence_yield, resolution_rate,
contradiction_rate, failure_rate — and `sample_size` on EVERY row. Bands: `<5`
LOW_SAMPLE, 5–19 EMERGING, `>=20` ESTABLISHED. Never treat a tiny sample as strong
evidence, and state the band beside the rate everywhere it is printed.

## Contextual dimensions and data leakage

Segment by bounded dimensions (action_type, evidence_type, product family,
technology, correlation state, target class, source module) — capped (20 is plenty).
No uncontrolled high-cardinality keys.

**Never use an outcome that postdates the decision to justify that decision.** Each
calibration carries the decision timestamp, the outcome timestamp and the window it
covered, and only data available before the decision may be used to evaluate it.

## States, drift and versioning

Calibration states: INSUFFICIENT_DATA, LOW_YIELD, MEDIUM_YIELD, HIGH_YIELD,
HIGH_CONTRADICTION, HIGH_FAILURE, UNSTABLE. **A state is an observation about past
outcomes, never a safety permission** — a poor state means lower preference at most,
and only the existing safety policy may block anything. Say that in the record's own
`limitations` text so a reader cannot mistake calibration for authority.

Keep recent (7d) and historical (30d) windows separately, never delete history.
Drift compares them and reports the difference with BOTH sample sizes — and never
claims causality; "recent yield is lower than historical" is the strongest claim
allowed. Refresh on a minimum-change threshold (e.g. N new outcomes) or an explicit
scheduled recalibration, not on every single outcome.

Version the model (`m13-v1`) so a past calibration stays reproducible and a future
change is a visible v2 rather than a silent reinterpretation.

## Feedback and replanning

Feedback TO the planner is ADVISORY and carries signal, support, sample_size,
confidence and reason. The planner still owns planning; this layer never promotes a
template, source, technology, product or action, and exposes no suppression surface.

Replanning returns a REQUEST toward the planner — this layer creates no action. A
replan is justified only on stated triggers (expected evidence unresolved, plan
expired, contradictory evidence, materially changed correlation, failure with a valid
alternate). Ceilings: per exposure, per gap and total — on exhaustion the outcome is
HUMAN_REVIEW, never another retry.

**Counterfactuals are UNKNOWN.** If an alternate was never executed, say UNKNOWN.
Historical observations may be compared; an alternative is NEVER run to compare it,
and no outcome is simulated.

Plan quality is judged separately from action quality: a low outcome does not mean a
desirable plan if the target simply lacked the evidence.

## Scheduler and safety posture

Local class, concurrency 1, low priority, registered as a reserved singleton so it
cannot be starved and cannot starve target work. Gate it with a bounded cooldown AND
a work check, and order the read-only work check BEFORE the cadence getter that
stamps the window. Ceilings (adapt names to the project): outcomes/run,
calibrations/run, replan requests/run, context dimensions, replans/exposure,
attempts/gap, plans/exposure, feedback/run, runtime seconds.

Zero target network — and prove it with a socket-level watcher scoped to your own
process, not a claim about the source. No subprocess, no scanner invocation, no
template promotion, no scope or rate-ceiling change, no automatic vulnerability
confirmation.

## Persisting EXPERIENCE distilled from outcomes

When the layer's job is not just to record outcomes but to distil reusable EXPERIENCE
from them (an evidence/experience loop), the record needs a different identity discipline
from the outcome record itself.

**Identity is the SUBJECT, never the direction.** Derive the experience id from
(type, pattern/fingerprint, family, Skill id, Skill version). If the outcome label or
direction is in the identity, each direction owns its own row, the two can never meet,
and a genuine contradiction is structurally undetectable. Assert it directly: the same
subject observed in BOTH directions must resolve to ONE record with both sides populated.

**Counters count DISTINCT observations, not calls.** Incrementing per call means
re-recording the same outcome inflates the sample size without bound, and (once the
counters live only in the returned payload rather than being derived from the stored
evidence refs) can never exist on one row at all. Keep the evidence refs on the row, cap
their length, derive `supporting_count`/`counter_count` from the DISTINCT refs, and report
when the cap saturates instead of hiding it. Re-recording the identical input then
UPDATES and is provably idempotent.

**Precedence: a measured disagreement outranks a low sample.**
`CONTRADICTED` > `INSUFFICIENT_EVIDENCE` > `OBSERVED`. Checking the sample floor FIRST
reports a live contradiction as merely "not enough data" — hiding the one fact that
matters most. Record the contradiction and PRESERVE the opposite-side evidence; never
resolve it by discarding the loser.

**Confidence below the minimum sample is `None`, not a small number.** Reuse the project's
own band thresholds and return no confidence at all under the emerging threshold. Derive it
from counts (`supporting / (supporting+counter)`), never a constant, and assert it equals
that ratio rather than merely lying in `0..1`.

**Separate the two token classes.** Execution/authority shapes are REJECTED; credential
shapes are REDACTED and the redaction counted. Screen the RAW input before redacting, or a
partially-masked token passes the screen. A rejection is an in-process counter and is never
persisted as a fact about a target.

**Reuse map — check these before creating anything.** In this project the stores already
exist: `learning_feedback` (the one feedback table, written via the expert-hunter helper),
M13's `calibration.RESULT_CLASSES` / `RESOLUTIONS` (canonical outcome vocabulary), M11's
`learning.sample_band` / `MIN_EMERGING` / `MIN_ESTABLISHED`, `evidence.redact_secrets`,
`investigation._append_lineage` (canonical case events), and the Jev Director's bounded
`prior_feedback` parameter — which is the seam an experience record is CONSUMED through.
Own a small local enum only where the upstream genuinely lacks the concept, and MAP into
the upstream constants with a total mapping you assert over every value.

**Consumption is the deliverable, not storage.** Prove a later decision actually reads the
experience (the record id appears in the consumer's bounded context) and that the consumer
still decides through its own unchanged contract. Keep the influence advisory: an
experience signal may order or annotate, never widen scope, promote a Skill, or confirm
anything — report `skill_promoted: False` / `skill_status_changed: False` explicitly rather
than leaving the reader to infer it.

## Verification shape

- A focused suite covering the brief's numbered checks against a THROWAWAY DB,
  including one fixture per scenario (yield, resolution, contradiction, failure,
  blocked, expired, cancelled, not-executed, sample bands, drift, ceilings, dedup).
- A runtime suite driving the real scheduler path (enqueue -> claim -> execute),
  proving the reserved singleton and the bounded gate.
- A bounded-storage suite with MORE inputs than every ceiling, asserting the caps
  hold AND are reported as hit, and that a second pass creates nothing.
- An AST safety verifier asserting the ABSENCE of network/subprocess/scanner/
  promotion surfaces, plus behavioural checks for advisory-only, no auto-suppression
  and no auto-promotion.
- A live verifier over a COPY of production (never the live DB) with a socket watcher
  reporting **TARGET NETWORK REQUESTS = 0**.

**When production holds no completed execution, report
`INSUFFICIENT_LIVE_OUTCOME_DATA` and PROVE the layer handles the empty corpus**
(no fabricated calibration, no manufactured sample size). Did the plans actually run?
If the planner's plans are still awaiting dispatch or expired unexecuted, the honest
verdict for the outcomes they produce is NOT_EXECUTED/EXPIRED — never invent evidence
they did not acquire, and say so plainly in the report.

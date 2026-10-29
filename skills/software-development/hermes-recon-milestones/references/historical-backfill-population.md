# Backfilling a historical population through an existing pipeline

Depth for milestones whose subject is "run everything already in the database
through the decision/investigation path once". The trap: the eligible population
is almost never what the brief assumes, and the honest result is usually
INCOMPLETE with most units declined by a domain guard that is working as designed.

## Census first, and make it a script

Never discover the population ad hoc inside the executor. Write
`scripts/<task>_census.py` as a read-only artifact that emits JSON, and run it
BEFORE any mutation so the report can quote a population that predates the work.

- The unit of work must be whatever the existing pipeline can actually process —
  read the pipeline's own work-item constructor and use its kinds verbatim. Do not
  invent a unit the pipeline has no path for.
- Per record record: source, source_id, target/host, discovery type, created_at,
  current state, JEV/LLM/expert status, already-processed flag, eligible flag, and
  a REASON when excluded. Every exclusion needs a reason; a bare "skipped" is not
  a census.
- Group the exclusion reasons and report the tally. The dominant reason is the
  answer to "why is the population smaller than expected".
- Order the population deterministically (oldest first, then id) so a re-run is
  comparable and a resume is well defined.

## Join on the same identity the pipeline uses

This is where a census silently lies. A join that looks reasonable can be wrong
because the pipeline keys on a different column.

- Read the pipeline's lookup call and use its exact key. An exposure was joined
  by `host` in a first pass and reported 5 units as "no record at all"; the
  pipeline actually keys on `evidence_plans.correlation_id ->
  exposure_correlations.dedup_key`, and all 5 resolved. NULL hosts are common;
  a host join silently drops them.
- After a census classification, spot-check a few records against the raw table
  with a second, independent query. If the census and the table disagree, the
  census is wrong.
- Disclose the correction in the report. A census that changed conclusion after a
  fix must show both, or the reader cannot audit the classification.

## Exclude what is already covered, by state not by age

Idempotency is the requirement, and "already processed" has several real shapes:
a decision exists, an outcome exists, the case is terminal, or a human-review
case owns the host. Check all of them per candidate; a single check under-counts
the excluded population and produces duplicate work.

## Let the existing guard decide; report the decline

When the pipeline declines a record, the decline is a result. Do not reclassify
it, retry it, or route around it.

- Name the exact function and line that produced the decline, and quote the
  module's own test if one asserts the same refusal. A guard whose own suite
  asserts "no case is created for this shape" is working as designed, and that
  citation is what turns "we failed" into "the population is outside the contract".
- Read the guard's justification expression and evaluate each axis per record, so
  the report can show why each unit failed rather than asserting all of them
  failed for the same unexamined reason.
- Distinguish the four useful outcomes: LEGITIMATE (guard correct), RECONCILABLE
  (existing case/plan already owns it — reuse, never duplicate), MISSING_PREREQUISITE
  (the justification exists in persisted data but is not attached to this
  identity), OUTSIDE_CONTRACT (nothing in persisted data can justify it). No
  UNKNOWN: if the gate inputs cannot be read, say which field could not be read.
- When every unit is LEGITIMATE, the deliverable is the INCOMPLETE report plus a
  named population limitation. The two ways to grow the population are design
  decisions (a plan-first identity without a case, or new justification signals);
  state them and stop. Do not implement either inside a backfill.

## Drive the existing entry point per unit

Do not call the whole-batch driver once per unit hoping the filter selects the
right work item — the batch driver's window is global and shared.

- A global queue bounded by a cap (`limit=MAX_WORK_ITEMS`) competes for slots, so
  a per-unit filter through that path can silently select a DIFFERENT host and
  cycle on nothing. Symptom: `ok=None`, no steps, no error.
- The correct shape is: build the same work-item dict the queue constructor would
  have produced, from the same real state, and pass it to the per-item cycle
  function directly. No production constant changes, no new executor.
- Process one unit per host per pass so two units on one host cannot race, and
  keep the remainder durable for a resume instead of dropping them.
- If the suite can run in a frozen/offline mode, use it for a mechanics dry run on
  a DB COPY before touching production. This catches wrong entry-point names, wrong
  call shapes, and selector bugs at zero provider cost.

## Before touching production, dry-run the executor

Every runner written in this shape has at least one wrong assumption on the first
run (a guessed function name, a selector that matches nothing, a builder that
needs a column you assumed). A copy-based dry run surfaces all of them in seconds
and costs nothing.

- Copy the DB, point `HERMES_DB` at the copy, run a couple of units, read the
  per-unit result records, and delete the copy.
- A dry run that "succeeds" with `ok=False` on every unit is a finding: read the
  REJECTED reason on each one and decide whether it is a real domain decline or
  your own bug before going near production.

## Report the value metrics honestly

- Measure before/after with a window boundary derived from the run's own recorded
  start time, not from wall-clock memory.
- Increased call counts are not value. Report the work-product counters
  (outcomes by verdict, supports, human-confirmed, useful signals) and if they are
  0, say 0.
- Name the three counters separately that are easy to conflate: a JEV decision is
  a decision, an evidence outcome is an observation, and only a human confirmation
  is a finding.
- Skill/expert coverage of 0 for a category is a real result: do not widen routing
  to populate it.

## The follow-on milestone: "can upstream data produce better attribution?"

When a backfill ends with most units declined by a *correct* guard, the next brief
usually asks whether data upstream of that guard can yield stronger evidence.
Answer by tracing the decision, not by trying to widen the guard.

- Locate the exact line that emits the negative state and read what it tests. A
  "no product match" verdict often means "the observed token did not resolve to a
  product" — a statement about the INPUT, not about attribution quality or the
  downstream guard. Do not conflate the two in the report.
- Enumerate the resolution order the identity function actually uses (alias table →
  authoritative stored set → embedded match → unknown) and determine which rule each
  observed token enters by. Tokens entering via the alias rule have bypassed the
  authoritative set entirely; check whether they are present in it at all.
- Classify a resolved token by what it identifies: a product the target *sells*, or
  the infrastructure it is *hosted on*. Web-server, CDN and cloud-vendor tokens
  resolving at high confidence are shared infrastructure, not product identity.
- Quantify the shared-infrastructure baseline before judging any single host: a
  fingerprint spanning many targets and hosts (count DISTINCT targets, not
  occurrences) cannot attribute one host to one target. Report those counts.
- Third-party software on a sibling host of the same target is NOT target product
  attribution. A CMS on one subdomain of a SaaS property is evidence about that
  subdomain. Record it; do not act on it.
- If no existing signal answers "why does Hermes believe this host runs this
  product?", the deliverable is the audit plus a named gap, and an honest
  INCOMPLETE. Do not design a contract that manufactures the missing signal, and do
  not create a synthetic production example to prove a contract works.

## Designing a bounded justification contract that nothing qualifies

When a brief asks for a new conservative gate (justify / corroborate / qualify)
rather than a fix, and the real population is empty:

- Ship the contract as a PURE function (no I/O, no DB, no network) so it is
  trivially testable, with rules written as a numbered checkable list mirroring the
  code.
- Order rules OWNERSHIP FIRST: if any existing case owns the subject, return the
  ownership verdict before corroboration is considered. This makes duplication
  structurally impossible rather than merely unlikely.
- Prove the positive branch with an explicit synthetic fixture and label it as
  proving reachability, not production reach. If the real population yields zero
  positives, say so plainly in the report.
- Name the exclusion in the report (`<POPULATION>_LIMITATION: YES`) and state the
  design changes that would enlarge it, without implementing either.
- Unit-test each forbidden justification as its own check, and assert the closed
  verdict vocabulary contains no UNKNOWN before the suite can pass.

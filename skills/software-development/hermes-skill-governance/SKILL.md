---
name: hermes-skill-governance
description: "Use when seeding or reviewing Hermes Registry Skills."
---

# Hermes Skill Registry — seeding, review and approval

Governs the canonical Skill Registry in `/root/hermes-recon` (`skills`,
`skill_versions`, `skill_sources`, `skill_factory_runs`, `skill_factory_events`).
Distinct from platform agent skills (`/root/.hermes/skills`, operating
procedures — never count them as security Skills) and from legacy
`research_agent_*` tables (migratable, not canonical). Enumerate the namespaces
before counting any of them.

## Activation order

1. Read the architecture and confirm the Skill tables exist. If a `_has_table(c,
   "skills")` guard is returning False, the registry was never installed — a
   defensive guard is a capability gap wearing the costume of robustness.
2. Migrate with the DDL the factory module ALREADY defines, via `ensure_schema(c)`
   in an idempotent script. Do not invent a schema, and do not call it once and
   move on — a module never wired into init is the whole defect. Apply on a DB
   copy first, then re-apply to prove the no-op.
3. Seed candidates through `create_candidate()`. The factory rejects shallow
   content, validates provenance, derives confidence from real evidence, dedups
   on a canonical key, and never auto-approves.
4. Verify with a live call, not by reading the call site (§17 of
   `hermes-verification-discipline`).

## Context vs execution is a two-function split, not one relaxed query

| Function | Statuses | Meaning |
|---|---|---|
| `deterministic_retrieval()` | `APPROVED` only | execution-eligible |
| `retrieval_context()` | `APPROVED` + `REVIEW_REQUIRED` | context only, each row carries `execution_eligible` |

Never widen the execution query to make a test or a hunter return rows. While
nothing is approved the execution path correctly returns 0 — that is the review
model working, not a bug to fix. Retrieval stays bounded, deterministic, and
free of embeddings/vector search.

Retrieval helpers must not depend on `row_factory`: `dict(row)` raises on a plain
`sqlite3` connection. Read `cur.description` and zip, or the Skill path fails for
only some callers.

## Lineage must never claim a status the skill does not have

Attribution rides the existing canonical case EVENT STREAM
(`_append_lineage` -> `case_events` with `object_type='skill'`), not a bespoke
lineage table. Field mapping: `skill_id` -> `object_id`, `status` ->
`metadata.classification`, `skill_version` + `execution_eligible` ->
`metadata.detail`.

Hardcoding `classification="APPROVED"` there fabricates human sign-off for every
unreviewed skill — record the TRUE status. Assert no event claims APPROVED while
the registry holds none.

Map each hunter family to a skill family from the actual implementation, and let
the general hunter take all families so no hunter starves when its own family is
empty. A family with no dedicated hunter is reported as reachable only by the
general hunter — never widened to look more complete than it is.

## Review gate

`scripts/skill_review_gate.py`: mandatory boolean gates, AND semantics, **no
aggregate score that can outvote a critical failure**. Gates cover provenance,
source support, family, trigger meaning, observable indicators, testable
hypotheses, bounded strategy, safe checks, concrete evidence, false positives,
negative indicators, target types, technology hints, chain consistency, and live
locator resolution. A live HTTP check belongs in a separate script so the gate
itself stays offline and reproducible.

The gate may recommend; it may never grant. See the tuning rules and the
reject-corpus requirement in `hermes-verification-discipline` §20.

## The human-approval boundary is executable

Architecture: `Human = Verify / Confirm Impact / Submit`. An agent recommending
APPROVE is correct; an agent WRITING `APPROVED` is manufacturing authorisation.

- Enforce in code: the status setter raises unless an explicit human actor is
  supplied, and rejects every agent identity including `None`. Allow the agent
  `REVIEW_REQUIRED`/`REJECTED`, recorded with the actor.
- If the table has no reviewer metadata, do NOT invent a reviewer identity and do
  NOT add columns the brief did not authorise. Leave the row `REVIEW_REQUIRED`
  and report the milestone INCOMPLETE — a technically successful milestone may
  still be blocked on genuine human approval. Naming the exact blocker is the
  deliverable.
- `APPROVED` becoming execution-eligible must flow only through the existing
  eligibility mechanism, never by editing a flag.

## Applying a real human approval that arrives after the review

The INCOMPLETE verdict is a resting state, not a permanent one: the operator may
authorise the pending skills in a later turn. Treat that as the genuine
authorisation it is, and apply it through the same guarded setter.

- **Bind names to ids explicitly and assert 1:1.** Fuzzy title matching resolved
  fewer than half of the operator's names; the rest only mapped by reading each
  title. Build an explicit name -> exact-title map, then assert the bound count
  equals the approval count, the ids are unique, and the set of skills NOT
  covered is empty. Never approve "the rest" by position.
- **Record the operator's own words as the reason**, plus the specific name
  approved, so each audit row is self-explaining later.
- **Commit in one transaction and verify the rollback path.** A first attempt
  that guessed the event table's columns failed closed and rolled back with
  nothing written — check that it wrote nothing, then fix. Write status-change
  audit rows through the module's OWN event writer, never a hand-rolled INSERT:
  a guessed column set fails on the real schema, and the same brittleness that
  broke it may have broken the read paths too.
- **Approval changes knowledge availability, not execution policy.** State this
  explicitly in the report: exploitation stays disabled, safe checks stay
  passive, every skill still routes through JEV plus human review. Do not let
  "APPROVED" read as "trusted to act".
- **Flip the tests, do not delete them.** After approval, every test asserting
  the pre-approval state ("zero APPROVED skills", "execution-eligible retrieval
  is empty") fails legitimately. Retarget each to the CORRELATION rather than a
  count: every `APPROVED` row carries a human approval event, and
  `execution_eligible == (status == 'APPROVED')` for every row. This is
  stronger than the count it replaces, because it still catches an approval
  that was not human-made.
- **Report the supersession, do not erase the earlier verdict.** The first
  report said INCOMPLETE and was correct at the time; when approval lands, state
  that the earlier verdict was the accurate one for the state it described and
  is now superseded. Editing history out of a governance report destroys the
  audit value the INCOMPLETE verdict created.

## Approval governs RUNTIME USE, not just retrieval

Once approved Skills are wired into a real path, the approval boundary has a
second enforcement point: what the approved content is ALLOWED to influence.
The stored-status gate is necessary and not sufficient — a consumer that reads a
Skill row and merges its text into a plan must re-check eligibility itself.

- Keep `execution_eligible == (status == 'APPROVED')` as a single invariant and
  assert it over every row, not per-call. A consumer that trusts a `status`
  string it read earlier can act on a row whose eligibility has since changed.
- **A non-eligible Skill must produce zero effect, not a smaller effect.** Assert
  the resulting plan is BYTE-IDENTICAL to the no-skill plan, and that selection
  itself refuses a non-eligible candidate — otherwise a refused Skill can still
  win a ranking and merely be ignored downstream.
- **What approval unlocks is guidance, never authority.** An approved Skill's
  content may shape a hypothesis, an objective, a bounded strategy, safe checks
  and evidence requirements. It may not set scope, rate limits, exploitation
  state, the human gate, or the decision layer. Write that boundary down as a
  precedence list and assert the protected levels are unchanged with the Skill
  present and absent.
- **A Skill's own hypotheses are candidates, not conclusions.** Carrying them
  into a plan is correct; letting one resolve to a confirmed state is not. Keep
  them labelled as under-review and let the existing decision layer and human
  gate resolve them.
- **A merged field can vanish at the validator.** Consumers that return a
  whitelisted dict drop anything added upstream, so a feature can be reported as
  integrated while contributing nothing. Persist what the whitelist discards in
  the lineage/provenance record and assert it survives the round-trip.
- When the approval milestone and a later wiring milestone both exist, the
  effectiveness question moves from "is the content retrievable" to "does the
  guidance move the outcome distribution". Keep those verdicts separate; see
  `hermes-verification-discipline` §24 for the sampling discipline and the
  integration-vs-effectiveness split.

## Proving there is no confirmed population yet

An audit finding 9 candidates rejected for attribution is a RESULT, not a gap:
report the declines with the function and line that produced them. Widening a
guard, or inventing an eligibility category to admit excluded units, converts a
correct refusal into a false PASS.

## Corrections to seeded content

Verify provenance URLs with real HTTP status before trusting a seed — vendor docs
get reorganised and stale paths rot into 404s while a content check still passes
informally. Fix by creating a NEW VERSION (the store is immutable); never
overwrite, and never edit the prior version, which is the evidence of what was
believed when. See `references/provenance-verification.md`.

## Retirement

Suspect artifacts stay in place with a status banner and are never promoted.
Confirm they have zero registry rows and no production reader before calling them
inert; record what each declares (`synthetic`, disputed CVE refs) against what the
knowledge base actually contains.

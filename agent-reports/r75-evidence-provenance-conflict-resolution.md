# R75 — Evidence Provenance & Conflict Resolution

Date: 2026-09-16
Base commit: `b08c0711726bd8fd08e6aa963b3dcdb245455a78` (R74)
Rule version: `r75-1`
**REAL vs SYNTHETIC: §13–§15 are clearly labelled. No synthetic evidence was
persisted in any real artifact.**

## 1. Objective

R74 lets externally acquired evidence enter Watch. R75 answers:

    "How should Watch understand the provenance and consistency of this
     evidence without deciding whether a vulnerability exists?"

It adds a bounded deterministic provenance + consistency layer that tracks
evidence source, origin, requirement association, relationship to previous
evidence (supporting / contradicting / invalidating / duplicate / conflicting),
provenance completeness, and whether human review is required because
evidence conflicts. It is not a confidence scorer, not a vulnerability
verdict, and never resolves conflicts.

## 2. Architecture inspected first

| Component | Stage | Reuse |
| --- | --- | --- |
| `research_evidence_intake.py` | R74 | Intake authority: accepted items (`EI` ids), rejections, package status; R75 consumes its result or calls its public `normalize_evidence_package` |
| `research_feedback_loop.py` | R73 | Feedback authority; R75 reuses its `PROVIDES`/`CONTRADICTS`/`INVALIDATES` effect vocabulary and does not alter feedback output |
| `research_decision_readiness_planner.py` | R72 | Readiness authority; R75 never recomputes readiness |
| `research_evidence_acquisition_planner.py` | R71 | Previous requirement statuses + evidence refs used as internal previous evidence |
| `research_outcome_planner.py` | R70 | Outcome observations used as previous evidence context; safety block reused |
| `tests/local_e2e/r64_research.py` | R68 | Canonical `kind:value` evidence identity; unchanged |

## 3. Reuse / composition

R75 creates no hypothesis model, confidence framework, readiness planner,
feedback planner or acquisition planner. It composes:

- **R74** for accepted/rejected evidence identity and package status,
- **R73**'s closed effect vocabulary for compatibility decisions,
- **R70/R71** state for the previous-evidence context,
- its own closed vocabularies for provenance state, relationship and conflict.

When handed a raw package, R75 calls R74's public `normalize_evidence_package`
so intake validation stays R74-authoritative. R75 never modifies R72 readiness
or R73 feedback output.

## 4. Provenance model

Per evidence item, R75 emits a bounded `provenance_id` (`PR1`...) record:
`evidence_id` (`EI1`...), `evidence_ref`/`evidence_refs`,
`hypothesis_ref`, `requirement_kind`, `source`, `effect`,
`provenance_state`, `relation_to_previous`, `conflict_state`,
`conflict_basis`, `human_review_required`, `reason`, `safety`. Rejected items
produce bounded records carrying only the rejection code — never the body.

## 5. Provenance states (closed)

`COMPLETE` (canonical refs or explicit invalidated refs + source +
hypothesis + requirement + effect), `PARTIAL` (accepted but identity is
signal-only), `MISSING` (rejected because the required association is
absent: unknown hypothesis/requirement/invalidated ref), `INVALID` (rejected
or malformed provenance). No confidence levels are used.

## 6. Evidence relationships (closed)

`NEW`, `DUPLICATE`, `SUPPORTS_EXISTING`, `CONTRADICTS_EXISTING`,
`INVALIDATES_EXISTING`, `CONFLICTING`, plus `NONE` used only for
rejection-derived records where no relationship can be evaluated without the
rejected body. Relationships are computed only from structured fields: same
hypothesis, same requirement, canonical refs, explicit effect and explicit
invalidation. Wording similarity is never used.

## 7. Conflict model

- New `CONTRADICTS` against existing positive evidence (internal available
  refs or previous `PROVIDES`) -> `CONTRADICTS_EXISTING` +
  `conflict_state=CONFLICTING` + `human_review_required=true`.
- New `PROVIDES` when a previous explicit `CONTRADICTS` exists for the same
  hypothesis+requirement -> `CONFLICTING` + `human_review_required=true`.
- Conflicting items in the same package are detected sequentially and flagged
  deterministically.
- `conflict_basis` preserves **both** sides (`existing_evidence_refs`,
  `new_evidence_refs`) with the note "conflict preserved for human review; no
  automatic resolution". No winner, no recency rule, no source preference, no
  model wording.

## 8. Duplicate handling

Identical canonical identity (same hypothesis, requirement, effect and refs)
against previous provenance -> `DUPLICATE`; in-package identical items are
rejected by R74 (`DUPLICATE_EVIDENCE`) and appear as `INVALID` provenance
records with relation `DUPLICATE`. Different refs with compatible effects ->
`SUPPORTS_EXISTING`. Duplicates never create a new semantic evidence state.

## 9. Invalidation

An explicit `INVALIDATES` item with canonical `invalidates_refs` (validated by
R74 against the previous evidence) -> `INVALIDATES_EXISTING`, the exact
invalidated ref is recorded in `evidence_refs`, and no conflict is raised.
The old evidence is preserved; nothing is deleted and no historical artifact
is rewritten.

## 10. R68 compatibility

R75 reuses canonical `kind:value` references and the R68 vocabulary covered by
R74; no new evidence namespace is introduced and R68 is unchanged.

## 11. R72 / R73 integration

Pipeline position: R74 accepted evidence -> R75 provenance/conflict analysis
-> R73 feedback (unchanged) -> R72 readiness (unchanged). R75 does not alter
`readiness_after` or the feedback delta; conflicts are preserved and marked
for human review instead of changing readiness.

## 12. Correlation

The whole chain stays one research unit: R70 correlated action -> R71 plan ->
R72 record -> R73 iteration -> R74 package -> R75 provenance records. Items
for different hypotheses of the same correlated action produce one provenance
record each without splitting the research unit.

## 13. Safety

Unchanged safety block: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`. No HTTP, socket, subprocess, shell, scanner,
target interaction, Mongo writes or authorization semantics; rejected bodies
are never persisted and sensitive/execution content is rejected upstream by
R74.

## 14. Focused tests

`ai/test_research_evidence_provenance.py` — **29 passed**: complete/partial/
missing/invalid provenance, package-rejection provenance, all six
relationships, duplicate via previous provenance and via R74 rejection,
supports-existing vs previous and vs internal evidence, contradicts-existing,
conflicting prior contradiction, in-package conflict, invalidation identity,
cross-hypothesis isolation, correlated hypotheses, sensitive/malformed
fail-closed, no auto-resolution, human-review-on-conflict, deterministic
output, stable `PR`/`EI` ids, input immutability, raw-package vs intake-result
equivalence, limit validation, rule versions, canonical refs, safety flags and
no confirmation semantics.

## 15. Local E2E

- `tests/local_e2e/test_r64_research.py` — **133 passed** (includes 5 new R75
  envelope/provenance/conflict/persistence integration tests).
- `pytest tests/local_e2e -q` — **275 passed, 63 subtests**.
- Adjacent suites (R70–R74 engines, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12–R31.14 planners) —
  **486 passed** in the combined run.

---

## REAL RESULTS

## 16. Real fixture run

Provider/model: real `openrouter` /
`nvidia/nemotron-3-ultra-550b-a55b:free`; runtime-only 900s timeout wrapper at
`/tmp/opencode/r71_live_run.py`; repository unchanged. One real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (2 accepted / 2 rejected).
- Artifact: `ai_data/research/r75/r64-indeed-2ea29240244dcf5b.json`
  (44,862 bytes), `research_run_version = r75-1`.
- Intake `NOT_PROVIDED`; provenance `NOT_PROVIDED` with 0 records,
  0 conflicts, `human_review_required=false` — honest: no external evidence
  exists to analyse.
- Hygiene: no `://`, no `sk-`, no `Bearer`.

## 17. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged. Disclosed attempts: attempt 1
`ERROR` (no hypothesis survived validation); attempt 2 succeeded.

- Status: `COMPLETED_WITH_REJECTIONS` (1 accepted / 2 rejected).
- Artifact: `ai_data/research/r75/r64-indeed-b1ebaaf9f2211f82.json`
  (27,651 bytes), `research_run_version = r75-1`.
- Chain: R70 `A1` -> R71 `P1 ENDPOINT_BEHAVIOR` -> R72 `R1 INSUFFICIENT` ->
  R73 `I1 EVIDENCE_GAP_REMAINS` -> R74 `NOT_PROVIDED` -> R75 `NOT_PROVIDED`
  (0 provenance records, 0 conflicts).
- Zero writes: 11 collections identical before and after.

---

## SYNTHETIC / OFFLINE (clearly labelled; not real target results)

## 18. Synthetic demonstrations

Run offline against the **real** R75 chain state (plans/readiness from the
Mongo artifact) with synthetic bounded packages; nothing was acquired from any
target and nothing synthetic was persisted:

| # | Scenario | Result |
| --- | --- | --- |
| 1 | new `METHOD_AUTH / PROVIDES` | `NEW` (COMPLETE provenance) |
| 2 | same evidence again (previous provenance) | `DUPLICATE` |
| 3 | different compatible `METHOD_AUTH / PROVIDES` | `SUPPORTS_EXISTING` |
| 4 | explicit `METHOD_AUTH / CONTRADICTS` vs prior support | `CONTRADICTS_EXISTING` + `CONFLICTING` + `human_review_required=true`; both refs preserved |
| 5 | new `PROVIDES` after prior explicit `CONTRADICTS` | `CONFLICTING` + `human_review_required=true` |
| 6 | explicit invalidation of the internal endpoint ref | `INVALIDATES_EXISTING` (COMPLETE) |

## 19. Actual quality improvement

- Watch can now distinguish `NEW`, `DUPLICATE`, `SUPPORTS_EXISTING`,
  `CONTRADICTS_EXISTING`, `INVALIDATES_EXISTING` and `CONFLICTING` purely from
  structured evidence fields.
- Conflicts become `CONFLICTING` + `human_review_required=true` with both
  sides preserved — never an automated winner, never `CONFIRMED` /
  `VULNERABLE` / `EXPLOITABLE`.
- Provenance completeness (COMPLETE/PARTIAL/MISSING/INVALID) makes the
  evidence chain auditable without touching readiness or feedback authority.

## 20. Limitations

- Real runs have no externally supplied evidence, so real provenance output is
  empty by design; all relationship/conflict paths are covered by focused
  tests and the labelled synthetic demonstrations.
- R71 stores corroborating refs in the previous layer's redacted form, so
  exact-duplicate detection against internal evidence is limited to
  non-redacted kinds; external-vs-external comparisons are unaffected.
- R75 analyses only structured evidence; it does not judge evidential weight
  or resolve conflicts (human review owns that).

## 21. Files changed

- `ai/knowledge/research_evidence_provenance.py` (new)
- `ai/test_research_evidence_provenance.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r75-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r75-evidence-provenance-conflict-resolution.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner, R72 readiness planner, R73 feedback loop,
R74 intake adapter and the safety boundary are unchanged.

## 22. Commit

One local commit: `feat(ai): add evidence provenance and conflict resolution`
(hash reported in the final task response). No push.

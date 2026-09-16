# R78 — First Real Research Case Walkthrough

Date: 2026-09-16
Base commit: `cf04c4ef3f1afc217f5ac6d2cde6c808c699beea` (R77)
Rule version: `r78-1` (walkthrough module)
**REAL vs SYNTHETIC: §2–§4, §15 and §19 are REAL; §6–§14 are
SYNTHETIC/OFFLINE. No synthetic evidence was persisted into any real artifact
or Mongo.**

## 1. Objective

Prove the complete human research workflow on ONE existing real Watch case:

    real R77 artifact -> researcher action -> externally supplied evidence
      -> R74 intake -> R75 provenance -> R72 readiness -> R73 feedback
      -> R76 case update -> R77 workbench

R78 adds no planner, no intelligence layer and no new state machine. It is an
offline validation/demo module that composes the existing authorities.

## 2. Real case identity (REAL)

| Field | Value |
| --- | --- |
| Case | `case-indeed-a1-endpoint-behavior` |
| Program | `indeed` |
| Artifact | `ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json` (`r77-1`) |
| Action | `A1` (`MEDIUM`, RECON / `ENDPOINT_BEHAVIOR`) |
| Acquisition plan | `P1` (`HTTP_BEHAVIOR_REVIEW`) |
| Readiness | `R1` |
| Iteration | `I1` |
| Hypothesis | `H1` "Versioned internal REST API surface" (STRUCTURE_AND_SIGNAL) |

The artifact carries all stage outputs; no LLM call was made for R78 and no
Mongo data was re-read beyond the existing artifact.

## 3. Before state (REAL)

- Status `WAITING_FOR_EVIDENCE`; sufficiency `INSUFFICIENT`; decision
  `NEEDS_EVIDENCE`; feedback `EVIDENCE_GAP_REMAINS`; hypothesis `UNRESOLVED`;
  next `CONTINUE`; human review not required.
- WHAT WE KNOW: `ENDPOINT_PURPOSE`, `WATCH_SIGNAL`.
- WHAT IS MISSING: `METHOD_AUTH`, `RESPONSE_BEHAVIOR` (both decision
  critical).
- WHAT TO DO NEXT: `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH`.

## 4. Researcher action (REAL)

From the existing R71/R72 outputs only:

- Objective: "Determine the purpose, authentication requirement and response
  behavior of the observed surface."
- Method: `HTTP_BEHAVIOR_REVIEW`; sources: `EXISTING_EVIDENCE`,
  `RESPONSE_OBSERVATION`, `DOCUMENTATION`, `AUTHORIZED_TEST_CONTEXT`,
  `HUMAN_REVIEW`.
- Expected result and stopping condition copied from the R71 plan; decision
  basis `NO_DECISION_EVIDENCE`.

## 5. Evidence requirements (REAL)

| Requirement | Status | Why decision-critical |
| --- | --- | --- |
| `METHOD_AUTH` | MISSING | R72 blocking code: endpoint method/authentication evidence is required for a meaningful review |
| `RESPONSE_BEHAVIOR` | MISSING | R72 blocking code: stored response/status behavior evidence is required |

No new requirements were invented.

## 6. Synthetic evidence package (SYNTHETIC/OFFLINE)

Bounded, clearly labelled, in-memory only:

- Partial: `METHOD_AUTH` PROVIDES, ref
  `response:synth-offline-method-auth-1`, source `HUMAN_REVIEW`, fact prefixed
  `SYNTHETIC/OFFLINE`.
- Complete: the partial item re-supplied plus `RESPONSE_BEHAVIOR` PROVIDES,
  ref `response:synth-offline-response-behavior-1`.
- Conflict: `METHOD_AUTH` CONTRADICTS, ref
  `response:synth-offline-method-auth-contradiction-1`.
- Stop: `METHOD_AUTH` CONTRADICTS, ref
  `response:synth-offline-stop-basis-removed-1`.

No URLs, IPs, credentials, tokens, request bodies, scanner output or payloads;
each item is labelled `SYNTHETIC/OFFLINE abstract observation ...`.

## 7. R74 intake result (SYNTHETIC via REAL contract)

- Partial: `ACCEPTED`, 1 accepted, 0 rejections, normalized `EI1` with the
  canonical ref and source.
- Complete: `ACCEPTED`, 2 accepted (re-supplied `METHOD_AUTH` is a legitimate
  duplicate; see R75).
- Conflict/stop: `ACCEPTED` with canonical refs.
- Deterministic normalization and sensitive-data rejection were already
  covered by the R74 suite and still pass (`ai.test_research_evidence_intake`,
  32 tests).

## 8. R75 provenance result (SYNTHETIC via REAL contract)

- Partial: `NEW` (COMPLETE provenance).
- Complete: `DUPLICATE` for the re-supplied `METHOD_AUTH` (same canonical
  identity as the previous round's accepted evidence) and `NEW` for
  `RESPONSE_BEHAVIOR`.
- Conflict: `CONTRADICTS_EXISTING` → `CONFLICTING` with both sides preserved
  (`existing_evidence_refs: [response:synth-offline-method-auth-1]`,
  `new_evidence_refs: [response:synth-offline-method-auth-contradiction-1]`).
  No winner, `resolved=false`.

## 9. R72 before/after (SYNTHETIC via REAL authority)

| Step | Sufficiency | Decision |
| --- | --- | --- |
| Before (REAL) | `INSUFFICIENT` | `NEEDS_EVIDENCE` |
| After `METHOD_AUTH` | `PARTIALLY_SUFFICIENT` | `NEEDS_EVIDENCE` |
| After `METHOD_AUTH` + `RESPONSE_BEHAVIOR` | `SUFFICIENT_FOR_REVIEW` | `READY_FOR_HUMAN_REVIEW` |

## 10. R73 feedback (SYNTHETIC via REAL authority)

- Partial: `EVIDENCE_GAP_REDUCED` / `REFINE` / `CONTINUE`
  (`MISSING_EVIDENCE_ACQUIRED`).
- Complete: `HYPOTHESIS_REQUIRES_REVIEW` / `STOP` / `HUMAN_REVIEW`
  (`DECISION_EVIDENCE_COMPLETE`).
- Conflict: `NEW_CONTRADICTING_EVIDENCE` / `WEAKEN` / `CONTINUE`, while
  remaining decision evidence keeps readiness at `PARTIALLY_SUFFICIENT`.

## 11. R76 case update (SYNTHETIC via REAL contract)

- Identity preserved: same `case_id`, `action_ref`, `gap_id`, hypothesis
  correlation (`H1`).
- Bounded history appended without rerunning the pipeline:
  `[WAITING_FOR_EVIDENCE, ACTIVE]` after the partial round (iteration count 2);
  the complete and conflict rounds update the snapshot and history under the
  same identity.
- No identity mutation; inputs are never mutated (tested).

## 12. R77 before/after (REAL renderer)

| Section | BEFORE (REAL) | AFTER partial (SYNTHETIC) | AFTER complete (SYNTHETIC) |
| --- | --- | --- | --- |
| WHAT WE KNOW | `ENDPOINT_PURPOSE`, `WATCH_SIGNAL` | + `METHOD_AUTH` | + `METHOD_AUTH`, `RESPONSE_BEHAVIOR` |
| WHAT IS MISSING | `METHOD_AUTH`, `RESPONSE_BEHAVIOR` | `RESPONSE_BEHAVIOR` | none |
| WHAT TO DO NEXT | `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH` | `PROVIDE_EVIDENCE`, `CONTINUE_RESEARCH` | `HUMAN_REVIEW`, `REVIEW_EVIDENCE` |
| HUMAN REVIEW | not required | not required | required (`READINESS_READY_FOR_HUMAN_REVIEW`) |

The workbench was produced by the real R77 renderer, not hand-built.

## 13. Conflict scenario (SYNTHETIC/OFFLINE)

Against the partial state, a contradicting `METHOD_AUTH` item yields:

- R75: `CONTRADICTS_EXISTING` + `CONFLICTING`, both evidence sides preserved.
- R72: unchanged by R78 — readiness remains `PARTIALLY_SUFFICIENT`
  (`METHOD_AUTH` retained, `RESPONSE_BEHAVIOR` missing).
- R76: `READY_FOR_HUMAN_REVIEW` / `CONFLICT_REQUIRES_HUMAN_REVIEW`,
  `human_review_required=true`.
- R77: conflicts 1, `resolved=false`, review reason
  `CONFLICT_REQUIRES_HUMAN_REVIEW`, next steps
  `PROVIDE_EVIDENCE, REVIEW_CONFLICT, HUMAN_REVIEW`.
- No automatic winner, no security verdict.

## 14. Stopped scenario (SYNTHETIC/OFFLINE)

An explicit contradicting item against the structural state exercises the
existing R73 rules: `current_state=STOP`, `next_iteration=STOP`. R76 shows
`STOPPED` / `RESEARCH_BASIS_REMOVED`; R77 shows `STOPPED` with next steps
`PROVIDE_EVIDENCE, HUMAN_REVIEW, STOP` and human review required. No new
stopping rule was created.

## 15. Real / synthetic boundary

- REAL: the Indeed case, its artifact (`r77-1`), all stage outputs and the R77
  renderer. The artifact bytes are unchanged by the walkthrough (tested).
- SYNTHETIC/OFFLINE: every evidence package, the partial/complete/conflict
  transitions and the stopped demonstration; all live in memory and are never
  persisted; no target interaction of any kind.

## 16. Safety

No HTTP request to Indeed, no scanner, no payload, no exploitation, no
authentication attempt, no Mongo write. The module contains no network,
socket, subprocess, shell, Mongo or persistence call. Safety block unchanged:
`advisory=true`, `research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`.

## 17. Tests

- `tests/local_e2e/test_r78_case_walkthrough.py` — **14 passed** (hermetic
  chain + real-artifact tests incl. artifact-untouched and boundary labels).
- `pytest tests/local_e2e -q` — **300 passed, 63 subtests**.
- Adjacent suites (R70–R77 engines, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12–R31.14 planners) —
  **544 passed**.

## 18. Actual workflow value

A researcher receives one real case, sees exactly what is known, what is
missing, what to investigate and what to provide; they return evidence through
the existing R74 contract; Watch processes it through R74 → R75 → R72 → R73 →
R76 → R77 and the researcher sees the case change from
`WAITING_FOR_EVIDENCE` to `ACTIVE` to `READY_FOR_HUMAN_REVIEW`, with conflicts,
stops and human-review requirements surfaced — all without target automation,
exploitation or a new planner.

## 19. Implementation gaps

One genuine integration gap was found and fixed with the smallest additive
change:

- **Gap**: R74's `reevaluation` exposed the post-intake `readiness_after` and
  `feedback` but not the projected R71 acquisition plan. In a multi-round
  evidence chain, a second round therefore re-projected the *original* plan
  and lost the first round's accepted evidence (observed: the complete round
  briefly showed `METHOD_AUTH` missing again).
- **Fix (additive only)**: `intake_and_reevaluate` now also returns
  `reevaluation.acquisition_after` — the same projected plan it already
  computed internally, with the authoritative R73 delta applied. No existing
  value changed, no authority moved; R78 chains via this key. A safety-scan
  test scrub was updated to account for the plan's negation phrase
  ("nothing is confirmed"). Documented here before/with the change.

No other engine changes were needed.

## 20. Files changed

- `tests/local_e2e/r78_case_walkthrough.py` (new)
- `tests/local_e2e/test_r78_case_walkthrough.py` (new)
- `ai/knowledge/research_evidence_intake.py` (additive
  `reevaluation.acquisition_after` + docstring)
- `ai/test_research_evidence_intake.py` (safety scrub updated for the new key)
- `agent-reports/r78-first-real-research-case-walkthrough.md` (this report)

## 21. Commit

One local commit: `feat(ai): add first real research case walkthrough`
(hash reported in the final task response). No push.

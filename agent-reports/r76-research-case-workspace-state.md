# R76 — Research Case Workspace & Investigation State

Date: 2026-09-16
Base commit: `bff4ff4b07a53f2bbc4c96dc3121dc139431b91a` (R75)
Rule version: `r76-1`
**REAL vs SYNTHETIC: §16–§19 are clearly labelled. No synthetic evidence was
persisted in any real artifact.**

## 1. Objective

R70–R75 each answer one question about an investigation. R76 makes them usable
as ONE bounded research case:

    "Where exactly are we in this investigation?"

R76 is an aggregation/state layer only — not another planner, not another
intelligence layer, not a new authority. It re-runs no stage, changes no stage
output, and never produces a security verdict.

## 2. Architecture inspected first

| Stage | Authority consumed read-only |
| --- | --- |
| `research_outcome_planner.py` | R70 action (`action_ref`, category, gap, hypotheses) |
| `research_evidence_acquisition_planner.py` | R71 plan (`plan_ref`, method, sources, steps) |
| `research_decision_readiness_planner.py` | R72 record (`readiness_ref`, sufficiency, decision, blockers) |
| `research_feedback_loop.py` | R73 iteration (`iteration_ref`, feedback/hypothesis state, next) |
| `research_evidence_intake.py` | R74 package state + accepted/rejected counts + post-intake projections |
| `research_evidence_provenance.py` | R75 records/conflicts + `human_review_required` |
| `tests/local_e2e/r64_research.py` | R70–R75 integration envelope |

## 3. Reuse / composition

R76 duplicates no stage logic. Every field is either a reference, a bounded
count/kind, or a closed code copied from the owning stage. When an R74 intake
result exists, its `reevaluation.readiness_after` and
`reevaluation.feedback` (the current R72/R73 projections) are used as the
effective readiness/feedback, so the case reflects the post-intake state
without R76 recomputing anything. R76 never alters readiness or feedback.

## 4. Case model

New deterministic engine `ai/knowledge/research_case_workspace.py`:
`case_id`, `case_version`, `program`, `action_ref`, `hypothesis_refs`,
`hypothesis_count`, `category`, `gap_id`, `status`, `stopping_reason`,
`action`/`acquisition`/`readiness`/`feedback` reference blocks, `evidence`
summary, `provenance` summary, `human_review_required`, `iteration_count`,
`current_iteration`, bounded `history`, `history_truncated`, `history_limit`,
`safety`, advisory flags. JSON-compatible, no UI, no backend/api changes.

Public functions: `build_research_case(...)`, `build_research_cases(...)`,
`update_research_case(...)`, `summarize_research_case(...)`,
`summarize_research_cases(...)`.

## 5. Case identity

Deterministic and dateless: `case-<program>-<action>-<gap>` (slugged, bounded),
e.g. `case-indeed-a1-endpoint-behavior`. No Mongo ids, no timestamps, no
randomness. One correlated R70 action is always one case.

## 6. Case status (closed)

`ACTIVE`, `WAITING_FOR_EVIDENCE`, `READY_FOR_HUMAN_REVIEW`, `STOPPED`. No
`CONFIRMED`/`VULNERABLE`/`EXPLOITABLE` state exists. Deterministic ladder:
R73 `next_iteration=STOP` -> `STOPPED` (with reason `RESEARCH_BASIS_REMOVED`
when the basis was removed, else `DECISION_EVIDENCE_COMPLETE`); R72
`READY_FOR_HUMAN_REVIEW` or R73 `HUMAN_REVIEW` -> `READY_FOR_HUMAN_REVIEW`;
R75 conflict -> `READY_FOR_HUMAN_REVIEW` with `CONFLICT_REQUIRES_HUMAN_REVIEW`;
partial/material progress -> `ACTIVE`; otherwise `WAITING_FOR_EVIDENCE`
(`ACQUISITION_UNAVAILABLE` when no acquisition path exists).

## 7. Stage relationships

Explicit refs only: R70 `action_ref` (A1), R71 `plan_ref` (P1), R72
`readiness_ref` (R1), R73 `iteration_ref` (I1), plus R74 `intake_state` and
R75 record/conflict counts. Complete stage outputs are never copied into the
case.

## 8. Evidence summary

From the effective R72 record: `required_count`, `available_count`,
`missing_count`, `decision_missing_count`, bounded canonical
`available_requirement_kinds`/`missing_requirement_kinds`; plus R74
`accepted_evidence_count`, `rejected_evidence_count`, `intake_state`. No raw
refs, URLs, IPs, Mongo ids, credentials, tokens, request bodies or payloads.

## 9. Conflict summary

From R75: `conflict_count`, `conflicting_requirement_kinds`,
`human_review_required`. Conflicts are exposed, never resolved; no winner is
chosen and readiness is not changed because of a conflict.

## 10. Iteration history

Bounded, configurable (`limit`, default 8, hard cap 32). Each entry carries
iteration number, refs, sufficiency/decision/feedback/hypothesis states, next
iteration, accepted-evidence count, conflict count, status and stopping
reason. When the limit is exceeded the oldest entries are dropped and
`history_truncated=true` is set — history is never silently dropped.

## 11. Update behavior

`update_research_case(...)` preserves the case identity and fails closed on a
different program, gap or hypothesis set; it appends exactly one bounded
iteration, updates references/counts and recomputes only the aggregation
status. It never re-runs R70–R75.

## 12. Correlation

One correlated R70 action -> one case; `H1 + H2` in one action yields
`hypothesis_count = 2` and one case (verified by tests and the fixture run's
two independent actions producing two cases).

## 13. Safety

Unchanged safety block: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`. No HTTP, socket, subprocess, shell, scanner,
target interaction, Mongo writes or authorization semantics. R76 imports only
`re`, `typing` and pure stage modules.

## 14. Focused tests

`ai/test_research_case_workspace.py` — **27 passed**: case creation and refs,
deterministic case identity, deterministic output, initial
`WAITING_FOR_EVIDENCE`, `ACTIVE` transition, `READY_FOR_HUMAN_REVIEW`,
`STOPPED` on removed basis, conflict -> human review without changing
readiness, evidence/intake counts, conflict summary, update appends and
preserves identity, history truncation and renumbering, program/gap mismatch,
orphan readiness/feedback/provenance, unknown action ref, malformed input,
sensitive program rejection, limit validation, workspace/case summaries,
closed vocabularies, input immutability, safety flags and no confirmation
semantics.

## 15. Local E2E

- `tests/local_e2e/test_r64_research.py` — **139 passed** (includes 6 new R76
  envelope/case/transition/conflict/persistence integration tests).
- `pytest tests/local_e2e -q` — **281 passed, 63 subtests**.
- Adjacent suites (R70–R75 engines, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12–R31.14 planners) —
  **513 passed** in the combined run.

---

## REAL RESULTS

## 16. Real fixture run

Provider/model: real `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`;
runtime-only 900s timeout wrapper; repository unchanged. One real call, no
retry.

- Status: `COMPLETED` (2 accepted / 0 rejected).
- Artifact: `ai_data/research/r76/r64-indeed-2ea29240244dcf5b.json`
  (50,511 bytes), `research_run_version = r76-1`.
- Workspace: `BUILT`, **2 cases**, both `WAITING_FOR_EVIDENCE`:
  - `case-indeed-a1-object-authorization` (H1, A1/P1/R1/I1)
  - `case-indeed-a2-endpoint-behavior` (H2, A2/P2/R2/I2)
- Intake/provenance `NOT_PROVIDED`, conflicts 0, `human_review_required=false`.
- Hygiene: no `://`, no `sk-`, no `Bearer`.

## 17. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged. Disclosed attempts: attempt 1
`ERROR` (IDOR grounding), attempt 2 succeeded.

- Status: `COMPLETED_WITH_REJECTIONS` (1 accepted / 2 rejected).
- Artifact: `ai_data/research/r76/r64-indeed-b1ebaaf9f2211f82.json`
  (31,549 bytes), `research_run_version = r76-1`.
- Workspace: `BUILT`, **1 case**
  `case-indeed-a1-endpoint-behavior` -> `WAITING_FOR_EVIDENCE`,
  readiness `INSUFFICIENT / NEEDS_EVIDENCE`, feedback
  `EVIDENCE_GAP_REMAINS / UNRESOLVED -> CONTINUE`, available 2 / missing 2 /
  decision-missing 2, conflicts 0, iterations 1. This is the expected correct
  state for a structural bounded dataset.

Mongo write disclosure: 9 of 11 collections were identical before/after. Two
collections changed during the window (`live_subdomains` +5,910;
`change_event` +5,910) and were stable immediately afterwards. The research
path has no write capability: R76 is pure and the R61 snapshot path issues
only `find`/`find_one` reads with `_id` excluded. The delta is therefore
attributed to a concurrent external pipeline writer, not to this run; the
research/R76 path itself performed zero writes.

---

## SYNTHETIC / OFFLINE (clearly labelled; not real target results)

## 18. Synthetic/offline demonstrations

Run offline against the **real** R76 chain state (plans/readiness/feedback
from the Mongo artifact) with synthetic bounded packages; nothing was acquired
from any target and nothing synthetic was persisted:

| # | Scenario | Result |
| --- | --- | --- |
| 1 | initial case | `WAITING_FOR_EVIDENCE` (INSUFFICIENT, CONTINUE) |
| 2 | after synthetic partial evidence | `ACTIVE` (PARTIALLY_SUFFICIENT, EVIDENCE_GAP_REDUCED, REFINE) |
| 3 | after synthetic complete evidence | `READY_FOR_HUMAN_REVIEW` / `DECISION_EVIDENCE_COMPLETE` (SUFFICIENT_FOR_REVIEW, HUMAN_REVIEW) |
| 4 | synthetic conflict | `READY_FOR_HUMAN_REVIEW` / `CONFLICT_REQUIRES_HUMAN_REVIEW`, `human_review_required=true`, conflict count 1; readiness reported from R72 (`PARTIALLY_SUFFICIENT`) and **not altered by R76** |
| 5 | update with new evidence | identity preserved; history `[WAITING_FOR_EVIDENCE, ACTIVE]`, iteration count 2, not truncated |

## 19. Actual quality improvement

- The distributed R70–R75 state is now one readable, bounded case per research
  unit: status, refs, readiness/feedback states, evidence/conflict summaries,
  next iteration and human-review flag in a single JSON-compatible object.
- The research status vs security verdict separation is explicit and enforced
  by closed vocabularies; conflicts surface as human review, never as a winner.
- Iteration history makes "what changed since the previous iteration"
  answerable without touching any stage authority.

## 20. Limitations

- Real runs have no externally supplied evidence, so all real cases stay
  `WAITING_FOR_EVIDENCE`; the other statuses are covered by tests and the
  labelled synthetic demonstrations.
- Per-case rejection attribution is exact for single-case runs; in multi-case
  runs, unattributable rejections are not assigned to an arbitrary case
  (single-case runs attribute them fully).
- R76 reports what R72/R73/R75 computed; it deliberately does not judge
  sufficiency, conflict weight or next actions beyond the aggregation status.

## 21. Files changed

- `ai/knowledge/research_case_workspace.py` (new)
- `ai/test_research_case_workspace.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r76-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r76-research-case-workspace-state.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner, R72 readiness planner, R73 feedback loop,
R74 intake adapter, R75 provenance layer and the safety boundary are
unchanged.

## 22. Commit

One local commit: `feat(ai): add research case workspace state`
(hash reported in the final task response). No push.

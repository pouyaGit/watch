# R77 — Human Research Workbench

Date: 2026-09-16
Base commit: `acb3cbe05d724d3e6f398d194ec82ee2eb75209a` (R76)
Rule version: `r77-1`
**REAL vs SYNTHETIC: §14–§16 are clearly labelled. No synthetic evidence was
persisted in any real artifact.**

## 1. Objective

R70–R76 form the bounded research state pipeline. R77 makes it usable by a
human researcher: it turns one R76 Research Case into a concise workbench that
answers

    "What do I need to know right now, what evidence do I have, what is
     missing, and what can I do next?"

R77 is presentation/workflow composition only — not another planner, another
intelligence engine or an execution engine. It produces a JSON-compatible
structure plus a bounded CLI-oriented view; no UI, no backend/api changes.

## 2. Architecture inspected

| Stage | Authority consumed read-only |
| --- | --- |
| `research_outcome_planner.py` | R70 action + outcomes (objective, recommended action, per-hypothesis details, reasons) |
| `research_evidence_acquisition_planner.py` | R71 plan (method, sources, steps, expected result, stopping condition) |
| `research_decision_readiness_planner.py` | R72 readiness/decision/blockers (via R76 case) |
| `research_feedback_loop.py` | R73 feedback/hypothesis state/next iteration (via R76 case) |
| `research_evidence_intake.py` | R74 intake counts/state (via R76 case) |
| `research_evidence_provenance.py` | R75 conflicts + preserved refs |
| `research_case_workspace.py` | R76 case (primary input) |

## 3. Authority boundaries

R70 = action, R71 = acquisition, R72 = readiness, R73 = feedback, R74 =
intake, R75 = provenance/conflict, R76 = case state. R77 copies bounded fields
and references only; it re-derives nothing, re-ranks nothing, re-validates
nothing, resolves nothing and executes nothing. Confirmed by a focused test
that greps the module source for any stage-engine call (none exist).

## 4. Workbench model

New deterministic engine `ai/knowledge/research_workbench.py`:
`build_research_workbench(case, action_plan=, acquisition_plan=,
evidence_provenance=, limit=8)`, `build_workbench_set(cases, ...)` (one
workbench per case + summary) and `summarize_workbenches(...)`. Five primary
sections: `current_state`, `what_we_know`, `what_is_missing`,
`what_to_do_next`, `human_review`; secondary: `hypotheses`, `why_interesting`,
`conflicts`, `history`, `evidence_input`, `workflow_actions`, `safety`.

## 5. Current state

Copied from the R76 case: status, stopping reason, readiness (sufficiency),
decision, feedback, hypothesis research state, next iteration, human-review
flag, iteration count, history truncation. Nothing recomputed.

## 6. Known evidence

`available_requirement_kinds`, `available_count`, R70 evidence states, R74
`accepted_evidence_count`, provenance state, and bounded canonical
`supporting_evidence_refs` from R75 accepted PROVIDES records. No raw stage
outputs, no URLs/IPs/Mongo ids/credentials/tokens/request bodies/payloads.

## 7. Missing evidence

From R76/R72/R71: `missing_requirement_kinds`, `missing_count`,
`decision_missing_count`, `decision_critical_missing` (R72 blocking codes),
`acquisition_plan_ref`, bounded per-requirement descriptions from the R71
plan, its `expected_result` and `stopping_condition`. No new requirements are
invented; absent stage inputs produce an explicit `UNAVAILABLE` detail state.

## 8. Next steps

A bounded ordered list (max 3) assembled from existing outputs with no new
scoring: 1) `PROVIDE_EVIDENCE` for decision-critical missing requirements,
2) `REVIEW_CONFLICT` for unresolved conflicts, 3) `HUMAN_REVIEW` when review is
required, 4) `CONTINUE_RESEARCH` for the existing R71 acquisition step, or
`REVIEW_EVIDENCE` when the decision-critical set is complete, and `STOP` for a
stopped case. Workflow actions are labels only and execute nothing.

## 9. Human review

`human_review.required` with closed reasons: `READINESS_READY_FOR_HUMAN_REVIEW`
(R72 decision / R73 next), `CONFLICT_REQUIRES_HUMAN_REVIEW` (R75), or the case
stop condition. The workbench explains *why* review is required using existing
bounded codes and never makes a security verdict.

## 10. Hypothesis presentation

Per hypothesis (correlated hypotheses preserved): `hypothesis_ref`, title,
category, priority, confidence, evidence state (from R70 outcomes),
`hypothesis_state` (R73 via R76) and `detail_state`
(`AVAILABLE`/`UNAVAILABLE`). No raw model output, no revalidation — R65/R66
remain authoritative.

## 11. Why interesting

Reuses R70 `reason_for_action` / action `reason` only. If unavailable it
returns the explicit bounded absence state `{"state": "UNAVAILABLE",
"reasons": []}`; no rationale is ever inferred from names.

## 12. Conflicts

R75 conflicts are displayed: count, requirement kinds, human-review flag and
the preserved `existing_evidence_refs` / `new_evidence_refs` (canonical refs).
`resolved` is always `false`; no winner is chosen.

## 13. History and safety

Bounded history (default 8, never unlimited) copied from R76, respecting R76
truncation and re-truncating to the requested limit with
`history_truncated=true`. Safety block unchanged: `advisory=true`,
`research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`. No HTTP,
socket, subprocess, shell, scanner, target interaction, Mongo writes or
authorization semantics. External evidence entry is a bounded placeholder
only ("External evidence must be supplied through the R74 intake contract");
the real path stays R74 -> R75 -> R73 -> R72 -> R76.

## 14. Focused tests

`ai/test_research_workbench.py` — **31 passed**: workbench creation, current
state, known evidence, supporting refs, missing evidence (+reduction),
what-to-do-next, action/acquisition references, hypotheses presentation,
correlated hypotheses, unavailable-detail state, why-interesting reuse and
absence, review on ready case, conflict display without resolution, stopped
case, next-steps composition and cap, closed workflow actions, evidence-input
placeholder, bounded history and truncation, malformed case, limit validation,
workbench set/summary, safety flags, sensitive-data exclusion, no security
verdict/execution semantics, and no stage-engine calls in the module.

## 15. Local E2E

- `tests/local_e2e/test_r64_research.py` — **144 passed** (includes 5 new R77
  envelope/workbench/transition/conflict/persistence integration tests).
- `pytest tests/local_e2e -q` — **286 passed, 63 subtests**.
- Adjacent suites (R70–R76 engines, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12–R31.14 planners) —
  **544 passed** in the combined run.

---

## REAL RESULTS

## 16. Real fixture run

Provider/model: real `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`;
runtime-only 900s timeout wrapper; repository unchanged. One real call, no
retry.

- Status: `COMPLETED_WITH_REJECTIONS` (1 accepted / 1 rejected).
- Artifact: `ai_data/research/r77/r64-indeed-2ea29240244dcf5b.json`
  (37,073 bytes), `research_run_version = r77-1`.
- Workbench: case `case-indeed-a1-object-authorization`,
  `WAITING_FOR_EVIDENCE`; WHAT WE KNOW `OBJECT_REFERENCE`, `WATCH_SIGNAL`;
  WHAT IS MISSING `AUTHORIZATION_OUTCOME`, `OWNERSHIP_BINDING`; WHAT TO DO
  NEXT objective + `AUTHORIZATION_BEHAVIOR_REVIEW` + sources + stop
  condition; NEXT STEPS `PROVIDE_EVIDENCE, CONTINUE_RESEARCH`; HUMAN REVIEW
  not required.
- Hygiene: no `://`, no `sk-`, no `Bearer`.

## 17. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged; one real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (1 accepted / 2 rejected).
- Artifact: `ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json`
  (36,230 bytes), `research_run_version = r77-1`.
- Workbench: case `case-indeed-a1-endpoint-behavior`,
  `WAITING_FOR_EVIDENCE`; WHAT WE KNOW `ENDPOINT_PURPOSE`, `WATCH_SIGNAL`;
  WHAT IS MISSING `METHOD_AUTH`, `RESPONSE_BEHAVIOR`; WHAT TO DO NEXT
  `HTTP_BEHAVIOR_REVIEW` + sources + stop condition; NEXT STEPS
  `PROVIDE_EVIDENCE, CONTINUE_RESEARCH`; HUMAN REVIEW not required.
- Zero writes: all 11 collections identical before and after (verified).

---

## SYNTHETIC / OFFLINE (clearly labelled; not real target results)

## 18. Synthetic/offline demonstrations

Run offline against the **real** R77 chain state (plans/readiness/feedback
from the Mongo artifact) with synthetic bounded packages; nothing was acquired
from any target and nothing synthetic was persisted:

| # | Scenario | Workbench view |
| --- | --- | --- |
| 1 | real WAITING case | `WAITING_FOR_EVIDENCE`; know `[ENDPOINT_PURPOSE, WATCH_SIGNAL]`; missing `[METHOD_AUTH, RESPONSE_BEHAVIOR]`; next `[PROVIDE_EVIDENCE, CONTINUE_RESEARCH]` |
| 2 | synthetic partial evidence | `ACTIVE`; missing reduced to `[RESPONSE_BEHAVIOR]`; next `[PROVIDE_EVIDENCE, CONTINUE_RESEARCH]` |
| 3 | synthetic complete evidence | `READY_FOR_HUMAN_REVIEW`; review required, reason `READINESS_READY_FOR_HUMAN_REVIEW`; next `[HUMAN_REVIEW, REVIEW_EVIDENCE]` |
| 4 | synthetic conflicting evidence | `READY_FOR_HUMAN_REVIEW`; conflicts 1, `resolved=false`; review reason `CONFLICT_REQUIRES_HUMAN_REVIEW`; next `[PROVIDE_EVIDENCE, REVIEW_CONFLICT, HUMAN_REVIEW]` |

## 19. Actual quality improvement

- A researcher can now open ONE object and immediately see where the
  investigation stands, what evidence exists, what is missing, what to do
  next, and whether human review is required — without reading seven internal
  artifacts.
- The workbench remains strictly non-authoritative: it copies state, surfaces
  conflicts for review, and never resolves them or produces a verdict.

## 20. Limitations

- Real runs contain no externally supplied evidence, so real workbenches show
  the `WAITING_FOR_EVIDENCE` view; the other statuses are covered by tests and
  the labelled synthetic demonstrations.
- The workbench intentionally exposes only bounded summaries and canonical
  refs; deep stage detail remains in the underlying artifacts.
- The evidence-input placeholder is informational only; submission stays with
  the R74 intake contract.

## 21. Files changed

- `ai/knowledge/research_workbench.py` (new)
- `ai/test_research_workbench.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r77-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r77-human-research-workbench.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner, R72 readiness planner, R73 feedback loop,
R74 intake adapter, R75 provenance layer, R76 case workspace and the safety
boundary are unchanged.

## 22. Commit

One local commit: `feat(ai): add human research workbench`
(hash reported in the final task response). No push.

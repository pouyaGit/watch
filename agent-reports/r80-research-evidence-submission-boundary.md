# R80 — Research Evidence Submission Boundary

Date: 2026-09-16
Base commit: `572534864849b177895a121afdf084aa8e9354a2` (R79)
Rule version: `r80-1` (submission boundary) / `r74-1` (delegated intake)
**All evidence packages in this milestone are clearly labelled
`NON-REAL/OFFLINE`. No target interaction, no Mongo writes, no persistence.**

## 1. Objective

Define and validate how an authorized researcher safely submits externally
acquired evidence to Watch. R80 is a small **submission-boundary adapter
around the existing R74 contract** — not a planner, ranking engine,
intelligence layer, readiness algorithm or state machine. Watch still never
acquires evidence.

## 2. R74 contract inspected

`ai/knowledge/research_evidence_intake.py`: `package_version = "r74-1"`,
bounded `items` (≤16), per-item `hypothesis_ref`, `requirement_kind`,
`effect` (`PROVIDES`/`CONTRADICTS`/`INVALIDATES`), `source` (existing closed
vocabulary incl. `AUTHORIZED_TEST_CONTEXT`), canonical `kind:value` refs via
`observations`/`evidence_ref`, bounded facts/signals, closed rejection codes,
sensitive/execution gates, and `intake_and_reevaluate` for the R72/R73
projections. No competing schema was invented.

## 3. Submission envelope

    {
      "submission_version": "r80-1",
      "case_ref": "<case_id>",
      "submitted_by": "<optional bounded label>",
      "items": [ <existing R74 item shape> ]
    }

Minimal fields only; item shape is exactly R74's.

## 4. Case binding

`case_ref` is required and must equal the target case's `case_id`; a missing
ref yields `CASE_REF_REQUIRED`, a different value `CASE_MISMATCH`, an invalid
case `UNKNOWN_CASE`. Evidence is never silently redirected to another case.

## 5. Requirement binding

Every item's `requirement_kind` must be one of the case's current
required-evidence kinds (resolved read-only from its R71 plan and R72 record);
otherwise `UNKNOWN_REQUIREMENT_FOR_CASE`. Every `hypothesis_ref` must belong
to the case (`HYPOTHESIS_NOT_IN_CASE`). A case without resolvable state yields
`CASE_STATE_UNAVAILABLE`.

## 6. Source handling

No second source taxonomy: item sources use R74's closed vocabulary and are
validated by R74. An unsupported source surfaces as R74's
`INVALID_EVIDENCE_SOURCE` in the delegated result.

## 7. Submitter handling

`submitted_by` is optional, bounded (≤64 chars) and non-personal. Email,
phone, URL/IP and credential-like labels are rejected with
`SUBMITTER_NOT_ALLOWED`; the label is never an identity store and is only
echoed back in the bounded result.

## 8. Evidence restrictions

A boundary pre-scan rejects sensitive content (`SENSITIVE_SUBMISSION_REJECTED`)
and execution instructions (`EXECUTION_CONTENT_REJECTED`) before R74 is
invoked: raw URLs, IPs, Mongo ids, credentials, tokens, bearer values,
shell/scanner/exploit commands. Canonical ref kinds (e.g. `authorization:`) are
scanned only on their value part, as in the previous stages. R74 remains the
authoritative gate and re-validates everything.

## 9. Bounds

R74's own item bound (`MAX_PACKAGE_ITEMS = 16`) is imported and reused — never
larger; an oversized submission yields `SUBMISSION_TOO_LARGE`. No unlimited
evidence or history is introduced.

## 10. R74 delegation

`submit_research_evidence(submission, case=..., hypotheses=..., action_plan=...,
acquisition_plan=..., readiness_plan=...)` validates the envelope, binds case
and requirements, runs the safety pre-scan, then delegates the bounded package
to R74's `intake_and_reevaluate` and returns that result under `intake` (the
R74 `package_status` becomes the submission `status`). On boundary rejection
the result is `SUBMISSION_REJECTED` with body-free `rejections` and
`intake = None`.

## 11. Downstream composition

R80 is not an authority for readability/feedback/provenance/case/workbench:
the local E2E module composes the unchanged authorities (R75 provenance → R76
update via R78's helpers → R77 workbench) using the delegated R74 result.

## 12. Negative validation (all `NON-REAL/OFFLINE`, in memory)

| # | Case | Result |
| --- | --- | --- |
| 1 | valid case-bound submission | `ACCEPTED` |
| 2 | wrong `case_ref` | `CASE_MISMATCH` (case untouched) |
| 3 | unknown requirement (`TOKEN_VALIDATION`) | `UNKNOWN_REQUIREMENT_FOR_CASE` |
| 4 | requirement not belonging to case | `UNKNOWN_REQUIREMENT_FOR_CASE` |
| 5 | malformed envelope | `MALFORMED_ENVELOPE` |
| 6 | unsupported source | `INVALID_EVIDENCE_SOURCE` (delegated to R74) |
| 7 | sensitive evidence | `SENSITIVE_SUBMISSION_REJECTED` (before R74) |
| 8 | execution instruction | `EXECUTION_CONTENT_REJECTED` |
| 9 | duplicate evidence | `DUPLICATE_EVIDENCE` (delegated) |
| 10 | contradictory evidence | `CONTRADICTS_EXISTING → CONFLICTING` preserved, not resolved |

## 13. Real Indeed status

R79's honest result is preserved: `REAL_EVIDENCE_NOT_AVAILABLE`
(0 method observations, 0 response observations; the read-only probe copies no
values). No real run is claimed and no evidence was fabricated.

## 14. REAL vs SYNTHETIC

- REAL: the case, the artifact, the archive availability status.
- NON-REAL/OFFLINE: every submission package in this milestone (valid, all
  negatives, partial/complete/conflict chains); all in memory, labelled,
  never written to the artifact or Mongo, never relabelled as real.

## 15. Safety

No HTTP, socket, subprocess, shell, scanner, target interaction or Mongo
write; no LLM call. Safety block unchanged: `advisory=true`,
`research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`.

## 16. Tests

- `ai/test_research_evidence_submission.py` — **22 passed** (valid/complete
  delegation, case/requirement/hypothesis binding, envelope/version/size
  rejections, submitter, sensitive/execution pre-scan, delegated source and
  duplicate rejections, determinism, immutability, safety, adapter-only source
  scan).
- `tests/local_e2e/test_r80_research_evidence_submission.py` — **12 passed**
  (downstream composition partial/complete, rejected submission leaves the
  case untouched, conflict preserved, all ten negatives, real-artifact run,
  artifact untouched).
- `pytest tests/local_e2e -q` — **328 passed, 63 subtests**.
- Adjacent suites (R70–R79 engines, R69 skills, OpenRouter, LLM, priorities,
  R31 planners) — **608 passed**.

## 17. Implementation gaps

None. R74 already provides everything the boundary needs; **no production
engine was modified beyond adding the new boundary module** (R74/R75/R72/R73/
R76/R77 unchanged). One interface note: R80 imports R74's public
`MAX_PACKAGE_ITEMS` and `intake_and_reevaluate`; no private access, no
duplication of validation rules.

## 18. Actual product value

A researcher now has a safe, explicit submission contract: evidence must name
the case, the requirement and the source; identity-like or dangerous content
is rejected at the boundary; accepted evidence flows through the existing
authorities and the case/workbench visibly change. The boundary is the piece a
future UI/API can call without granting Watch any acquisition capability.

## 19. Files changed

- `ai/knowledge/research_evidence_submission.py` (new)
- `ai/test_research_evidence_submission.py` (new)
- `tests/local_e2e/r80_research_evidence_submission.py` (new)
- `tests/local_e2e/test_r80_research_evidence_submission.py` (new)
- `agent-reports/r80-research-evidence-submission-boundary.md` (this report)

R65/R66/R68–R79 remain untouched.

## 20. Commit

One local commit: `feat(ai): add research evidence submission boundary`
(hash reported in the final task response). No push.

# R74 — Research Evidence Intake & Re-evaluation

Date: 2026-09-16
Base commit: `92a1855e9631bc3a4ee7ca68360eaf1af973d1c9` (R73)
Rule version: `r74-1`
Package version: `r74-1`
**REAL vs SYNTHETIC: §14–§18 are clearly labelled. No synthetic evidence was
persisted in any real artifact.**

## 1. Objective

Add the missing practical bridge between evidence obtained **outside** Watch
and the existing bounded research loop:

    EXTERNALLY ACQUIRED EVIDENCE
      -> Evidence intake (validate / normalize)
      -> R68-compatible canonical evidence
      -> R72 re-evaluation
      -> R73 feedback
      -> CONTINUE / HUMAN_REVIEW / STOP

Watch itself never acquires evidence. R74 is an **intake adapter**: the human
researcher or another explicitly authorized external process obtains the
evidence; Watch only validates, normalizes and bounds it, then feeds it into
the existing engines.

## 2. Architecture inspected first

| Component | Stage | Finding |
| --- | --- | --- |
| `research_feedback_loop.py` | R73 | Owns effect/source/ref-kind/rejection vocabularies, the authoritative delta + feedback engine; `evaluate_research_iteration` is the feedback authority |
| `research_decision_readiness_planner.py` | R72 | Readiness authority; `plan_decision_readiness(action_plan, acquisition_plan)` recomputes readiness from plan requirement statuses |
| `research_evidence_acquisition_planner.py` | R71 | Acquisition authority; plan shape, requirement statuses, `AUTHORIZED_TEST_CONTEXT` source |
| `research_outcome_planner.py` | R70 | Action authority; outcomes carry the raw canonical refs used for invalidation matching |
| `tests/local_e2e/r64_research.py` | R68 | Evidence contract: `evidence_index`, `evidence_catalog`, canonical `kind:value` refs, `REF_KINDS`/`CORROBORATING_REF_KINDS` |

## 3. Reuse / composition

R74 does **not** implement a parallel R72/R73 algorithm, and is not a scanner,
HTTP client, exploitation engine, payload generator, request executor,
authorization mechanism, hypothesis model, confidence model or planner.

- Item validation reuses the **closed R73 vocabularies** (`PROVIDES` /
  `CONTRADICTS` / `INVALIDATES`, `EVIDENCE_SOURCES`, `EVIDENCE_REF_KINDS`) and
  the **R73 rejection codes** where identical; R74 adds only intake-specific
  codes (package version, package size, duplicates, execution content,
  invalid refs).
- The accepted bundle is fed to **R73** (`evaluate_research_iteration`), which
  computes the authoritative evidence delta/feedback.
- R74 then applies that authoritative delta to a bounded status projection of
  the R71 plan and calls **R72** (`plan_decision_readiness`) for the updated
  readiness; it does not re-derive sufficiency itself.
- No Mongo change; results live in the existing research artifact envelope.

## 4. Input contract

    {
      "package_version": "r74-1",
      "items": [{
        "hypothesis_ref": "H1",
        "requirement_kind": "METHOD_AUTH",
        "effect": "PROVIDES",
        "source": "HUMAN_REVIEW",
        "evidence_ref": "response:stored-method-auth-1",
        "observations": [{"ref": "response:stored-method-auth-1", "fact": "..."}],
        "derived_signals": [{"signal": "...", "detail": "..."}],
        "invalidates_refs": ["path:..."]
      }]
    }

Explicit hypothesis association, explicit requirement association, explicit
source, explicit effect, canonical evidence identity, bounded observations and
no hidden inference. Accepted items receive stable `EI1`, `EI2`, ... ids
assigned in canonical sorted order; the normalized bundle is returned as part
of the artifact.

## 5. Validation rules (fail-closed)

Package: mapping shape, exact `package_version`, `items` list, at most 16
items, no rejection bodies persisted. Item: known hypothesis, known
requirement kind (PROVIDES/CONTRADICTS; optional for INVALIDATES), closed
effect and source, canonical `kind:value` refs with non-empty values from the
R68 vocabulary, bounded observations (≤4) and signals (≤4), duplicate
detection, invalidation refs must exist in the previous evidence, redaction
ambiguity rejected, sensitive content rejected (URLs, IPs, Mongo ids,
credentials, bearer tokens, secrets) and execution content rejected (shell,
scanner and exploit-command markers). Rejection records are bounded
`{"index", "code"}` entries; package-level failures yield
`package_rejections` with no body.

Statuses: `NOT_PROVIDED` (no package), `ACCEPTED`, `PARTIAL`, `REJECTED`.

Sources: `EXISTING_CONTEXT`, `STORED_RESPONSE`, `HUMAN_REVIEW`,
`WATCH_DERIVED` plus the existing R71 `AUTHORIZED_TEST_CONTEXT`, which is
mapped to `STORED_RESPONSE` for the R73 bundle (no new authorization model).

## 6. Normalization

Bounded strings (facts/signals truncated, refs rejected if over-long),
canonical refs preserved, sorted/deduplicated ref lists, stable canonical
item ordering, stable `EI` ids, no timestamps, no arbitrary metadata, no
randomness. Repeated runs are byte-identical and inputs are never mutated.

## 7. R68 compatibility

Accepted evidence uses the same canonical `kind:value` identity as the R68
evidence contract; the R64 `REF_KINDS` + `CORROBORATING_REF_KINDS` vocabulary
is fully covered by R74's accepted ref kinds (unit-tested). Items that cannot
map to the canonical vocabulary are rejected; no new evidence namespace is
invented. R68 itself is unchanged.

## 8. R72 integration

`reevaluation.readiness_after` is produced by the real
`plan_decision_readiness(action_plan, updated_acquisition_plan)`, where the
updated plan is the original R71 plan with the **R73-authoritative delta**
applied to requirement statuses. `readiness_before_summary` plus
`transitions` report the before/after sufficiency and decision states.

## 9. R73 integration

`reevaluation.feedback` is the real `evaluate_research_iteration` result over
the accepted bundle: evidence delta, feedback state, hypothesis research
state and next-iteration decision. R73 remains the feedback authority.

## 10. Correlation

One evidence package may contain items for several hypotheses of the same
correlated R70 action; R74 preserves the single R71 plan / R72 record / R73
iteration and attributes each delta to its `hypothesis_ref`. Evidence
referencing unknown hypotheses is rejected.

## 11. Safety

Unchanged safety block: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`. No target interaction, no HTTP client, no
socket, no subprocess, no shell execution, no Mongo writes, no authorization
semantics. The module imports only `re`, `typing` and the previous pure
stage modules (verified at git level).

## 12. Focused tests

`ai/test_research_evidence_intake.py` — **32 passed**: valid PROVIDES /
CONTRADICTS / INVALIDATES intake, full completion to human review, empty and
NOT_PROVIDED packages, malformed/unsupported-version/oversized packages,
partial and all-rejected packages, unknown hypothesis/requirement/effect/
source/invalidated ref/ambiguous ref, invalid ref format, sensitive and
execution content, duplicate evidence, bounded strings and refs, canonical
`EI` ids, deterministic ordering and output, R68 vocabulary compatibility,
R72 re-evaluation, R73 transitions, correlation preservation, input
immutability, safety flags, no confirmation/execution semantics.

## 13. Local E2E

- `tests/local_e2e/test_r64_research.py` — **128 passed** (includes 6 new R74
  envelope/intake/transition/correlation/persistence integration tests).
- `pytest tests/local_e2e -q` — **270 passed, 63 subtests**.
- Adjacent suites (R70/R71/R72/R73 engines, R69 skills, OpenRouter, LLM,
  research priority, evidence confidence aggregator, R31.12–R31.14 planners)
  — **457 passed** in the combined run.

---

## REAL RESULTS (no external package exists in either real run)

## 14. Real fixture run

Provider/model: real `openrouter` /
`nvidia/nemotron-3-ultra-550b-a55b:free`; runtime-only 900s timeout wrapper at
`/tmp/opencode/r71_live_run.py` (loads `.env`, replaces only `_real_provider`);
repository unchanged. One real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (2 accepted / 1 rejected).
- Artifact: `ai_data/research/r74/r64-indeed-2ea29240244dcf5b.json`
  (44,036 bytes), `research_run_version = r74-1`.
- Intake: `NOT_PROVIDED` (accepted 0, rejected 0) — honest: no external
  evidence was supplied, so no transition is invented.
- Readiness: `P1 OBJECT_AUTHORIZATION` and `P2 COMPONENT_MAPPING` both
  `INSUFFICIENT / NEEDS_EVIDENCE`; R73: `EVIDENCE_GAP_REMAINS / UNRESOLVED ->
  CONTINUE`.
- Hygiene: no `://`, no `sk-`, no `Bearer`.

## 15. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged; one real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (2 accepted / 4 rejected).
- Artifact: `ai_data/research/r74/r64-indeed-b1ebaaf9f2211f82.json`
  (30,501 bytes), `research_run_version = r74-1`.
- Chain: R70 `A1` (H1, H2) -> R71 `P1 ENDPOINT_BEHAVIOR` -> R72
  `R1 INSUFFICIENT / NEEDS_EVIDENCE` (blocking `METHOD_AUTH`,
  `RESPONSE_BEHAVIOR`) -> R73 `I1 EVIDENCE_GAP_REMAINS / UNRESOLVED`.
- Intake: `NOT_PROVIDED` (accepted 0) — the bounded Indeed dataset does **not**
  contain newly acquired behavioral evidence, and R74 does not pretend it
  does.
- Zero writes: 11 collections identical before and after.

---

## SYNTHETIC / OFFLINE (clearly labelled; not a real target result)

## 16. Offline synthetic demonstration

Command context: a synthetic `r74-1` package with one PROVIDES item for
`METHOD_AUTH` (`response:stored-method-and-auth-1`, source `HUMAN_REVIEW`) was
fed offline to `intake_and_reevaluate` together with the **real** R70/R71/R72
state from the Mongo artifact above. No evidence was acquired from any
target; nothing was persisted as real target evidence.

- Package: `ACCEPTED`, `EI1`, 0 rejections.
- Evidence delta: `METHOD_AUTH MISSING -> AVAILABLE` (`NEW_EVIDENCE`, H1).
- Readiness transition: `INSUFFICIENT -> PARTIALLY_SUFFICIENT`
  (`NEEDS_EVIDENCE` unchanged).
- R73: `EVIDENCE_GAP_REDUCED / REFINE -> CONTINUE`.
- Remaining decision requirement: `RESPONSE_BEHAVIOR`.

A second deterministic demonstration (covered by tests) provides both
`METHOD_AUTH` and `RESPONSE_BEHAVIOR`: readiness becomes
`SUFFICIENT_FOR_REVIEW`, feedback `HYPOTHESIS_REQUIRES_REVIEW`, state `STOP`,
next iteration `HUMAN_REVIEW`.

## 17. Before / after readiness state

| View | Sufficiency | Decision | Feedback | State | Next |
| --- | --- | --- | --- | --- | --- |
| REAL before (Mongo) | `INSUFFICIENT` | `NEEDS_EVIDENCE` | `EVIDENCE_GAP_REMAINS` | `UNRESOLVED` | `CONTINUE` |
| SYNTHETIC after intake | `PARTIALLY_SUFFICIENT` | `NEEDS_EVIDENCE` | `EVIDENCE_GAP_REDUCED` | `REFINE` | `CONTINUE` |
| SYNTHETIC after full intake | `SUFFICIENT_FOR_REVIEW` | `READY_FOR_HUMAN_REVIEW` | `HYPOTHESIS_REQUIRES_REVIEW` | `STOP` | `HUMAN_REVIEW` |

The transition comes only from structured evidence items and their explicit
requirement/effect fields — never from model interpretation.

## 18. Actual quality improvement

- The loop can now consume externally acquired evidence without any Watch-side
  acquisition capability: validate, normalize, store in the artifact and
  re-evaluate through the existing authorities.
- The before/after readiness and the exact deterministic delta are explicit,
  and rejected evidence is bounded and body-free.
- Nothing is overstated: with no external package the real runs keep
  `INSUFFICIENT / EVIDENCE_GAP_REMAINS`; synthetic demonstrations are labelled
  and never persisted as real evidence.

## 19. Limitations

- R74 consumes only explicit structured evidence; it does not parse free-form
  reports, files or model output into evidence.
- The R71 plan's redacted corroborating refs limit invalidation of genuinely
  ambiguous redacted groups (rejected fail-closed).
- The bounded Indeed dataset contains no new behavioral evidence, so real
  runs remain `NOT_PROVIDED` by design.
- R74 does not judge whether accepted evidence is convincing; that stays with
  human review.

## 20. Files changed

- `ai/knowledge/research_evidence_intake.py` (new)
- `ai/test_research_evidence_intake.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r74-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r74-research-evidence-intake-reevaluation.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner, R72 readiness planner, R73 feedback loop
and the safety boundary are unchanged.

## 21. Commit

One local commit: `feat(ai): add research evidence intake and reevaluation`
(hash reported in the final task response). No push.

# R73 — Research Feedback & Iteration Loop

Date: 2026-09-16
Base commit: `b3c68e51fab5355e7f0f07772c2e4a45153d3d7e` (R72)
Rule version: `r73-1`

## 1. Objective

Close the bounded research loop. When new evidence becomes available, R73
compares the previous R70/R71/R72 state with the explicit new evidence and
answers:

    "What changed in our understanding of this hypothesis: which requirements
     moved MISSING -> AVAILABLE (or were explicitly invalidated), is the
     hypothesis retained, refined, weakened or unresolved, and is another
     automated research iteration justified?"

    Evidence -> Hypothesis -> R70 action -> R71 acquisition plan
             -> R72 readiness -> NEW EVIDENCE -> R73 feedback
             -> continue / revise / stop

R73 is feedback-only and advisory. It never confirms a vulnerability, never
creates a finding, never executes, never contacts a target, never authorizes
anything, never modifies Mongo and never calls an LLM.

## 2. Architecture inspected first

| Concept | Stage | Finding |
| --- | --- | --- |
| `research_outcome_planner.py` | R70 | Outcomes/actions and gap correlation; source of truth for actions |
| `research_evidence_acquisition_planner.py` | R71 | Requirement statuses, sources, steps, stopping conditions; source of truth for acquisition |
| `research_decision_readiness_planner.py` | R72 | Readiness/sufficiency, blockers, decision basis; source of truth for readiness |
| `hypothesis_correlator.py` | R43.3 | Cross-agent duplicate/related/independent/conflicting correlation; not a feedback model |
| `evidence_confidence_aggregator.py` | R31.15 | Confidence level over R31.13/R31.14; input-coupled to the Asset<->CVE chain |
| `research_prioritization.py` | R55.4 | Finding-intelligence priority ranking ("priority is not confidence") |
| `security_skills/` | R69 | Skill methodology with `required_evidence`/`watch_signals`; already carried by R71 plans |

## 3. Reuse / composition decision

R73 does **not** create a second hypothesis model, a second confidence
framework or a second acquisition planner. It composes the existing chain:

- previous validated hypotheses (read-only, for reference discovery),
- previous R70 action plan, R71 acquisition plan, R72 readiness records,
- explicit new evidence,
- R69 skill references are propagated read-only from the R71 plan (skills are
  never re-sent or invented).

R43.3 correlation is not duplicated; R73 preserves R70/R71/R72 correlation by
producing exactly one iteration record per R72 readiness record. R31.15
confidence is not recomputed; R72 remains the readiness authority and R73 only
reports the delta.

## 4. Iteration model

New deterministic engine `ai/knowledge/research_feedback_loop.py`:

- `build_iteration_records(hypotheses, action_plan=, acquisition_plan=,
  readiness_plan=, new_evidence=)` — one bounded record per R72 readiness
  record.
- `summarize_iterations(iterations)` — bounded summary (counts, bands, top
  record).
- `evaluate_research_iteration(hypotheses, ..., new_evidence=, limit=8)` — the
  composed result (`rule_version="r73-1"`, source rule versions consumed).

Per record: `iteration_id` (`I1`...), `order`, `plan_ref`, `action_ref`,
`hypothesis_refs`, `hypothesis_count`, `category`, `gap_id`, `previous_state`,
`current_state`, `feedback_state`, `evidence_delta`, `newly_available_requirements`,
`newly_missing_requirements`, `invalidated_requirements`,
`unchanged_requirements`, `remaining_decision_requirements`,
`changed_evidence_refs`, `evidence_items` (per-item hypothesis attribution),
`reason`, `reason_text`, `next_iteration`, `human_review_required`,
`skill_refs`, `safety`, advisory flags.

Integration in `tests/local_e2e/r64_research.py` (rule version `r73-1`): after
R72, `evaluate_research_iteration(...)` is added to the envelope as top-level
`iteration_plan`; the CLI prints a bounded
`RESEARCH ITERATION FEEDBACK (advisory only)` section. The pipeline runs its
first iteration with no new evidence, so the real output honestly reports no
change (see §14/§15).

## 5. Evidence delta model

New evidence is an explicit bundle:

    {"items": [{
        "hypothesis_ref": "H1",
        "requirement_kind": "AUTHORIZATION_OUTCOME",
        "effect": "PROVIDES" | "CONTRADICTS" | "INVALIDATES",
        "source": "EXISTING_CONTEXT" | "STORED_RESPONSE" | "HUMAN_REVIEW" | "WATCH_DERIVED",
        "observations": [{"ref": "authorization:...", "fact": "..."}],
        "derived_signals": [{"signal": "...", "detail": "..."}],
        "invalidates_refs": ["path:..."]
    }]}

Delta entries are `{"requirement_kind", "from_status", "to_status", "cause",
"hypothesis_ref"}` with the closed causes `NEW_EVIDENCE` / `INVALIDATION`.
`MISSING -> AVAILABLE` requires an explicit PROVIDES item;
`AVAILABLE -> MISSING` requires an explicit INVALIDATES item whose reference
is actually part of the previous R71 evidence — evidence is never silently
invalidated. A CONTRADICTS item is recorded without changing the availability
status.

Evidence identity: refs must be canonical `kind:value` references from the
closed R64/R68 vocabulary. Raw URLs, IPs, Mongo ids, credentials and tokens
are rejected (`SENSITIVE_EVIDENCE_REJECTED`); unknown hypotheses,
requirements, invalidated refs, malformed items and ambiguous references fail
closed as bounded `rejections`. R71 stores some corroborating refs in the
previous layer's redacted form (`authorization=[redacted]`); R73 matches
invalidations against the raw R70 outcome refs and the redacted storage form,
and rejects redaction-ambiguous groups (`AMBIGUOUS_EVIDENCE_REF`) instead of
guessing.

## 6. Feedback states (closed)

`NO_CHANGE`, `NEW_SUPPORTING_EVIDENCE`, `NEW_CONTRADICTING_EVIDENCE`,
`EVIDENCE_GAP_REDUCED`, `EVIDENCE_GAP_REMAINS`, `EVIDENCE_INVALIDATED`,
`HYPOTHESIS_REQUIRES_REVIEW`. No `CONFIRMED`/`VULNERABLE`/`EXPLOITABLE` state
exists.

## 7. Hypothesis research states (closed)

`RETAIN`, `REFINE`, `WEAKEN`, `UNRESOLVED`, `STOP`. These are research states,
not vulnerability verdicts. `STOP` means only that the automated loop stops
and hands the state to human review. States are never inferred from priority,
confidence, names or model wording.

## 8. Next-iteration logic (closed: CONTINUE / HUMAN_REVIEW / STOP)

Deterministic ladder (first match wins), per R72 record:

1. no relevant new evidence + all decision requirements available ->
   `NO_CHANGE` + `RETAIN` + `HUMAN_REVIEW`;
2. no relevant new evidence + decision requirements missing ->
   `EVIDENCE_GAP_REMAINS` + `UNRESOLVED` + `CONTINUE` when an acquisition plan
   exists, else `ACQUISITION_UNAVAILABLE` + `HUMAN_REVIEW`;
3. invalidation and no available decision evidence remains ->
   `EVIDENCE_INVALIDATED` + `UNRESOLVED` + `STOP`;
4. invalidation with remaining evidence -> `EVIDENCE_INVALIDATED` + `REFINE` +
   `CONTINUE` (human review required);
5. contradiction and no available decision evidence -> 
   `NEW_CONTRADICTING_EVIDENCE` + `STOP` + `STOP`;
6. contradiction with remaining evidence -> `NEW_CONTRADICTING_EVIDENCE` +
   `WEAKEN` + `CONTINUE`;
7. all decision requirements available after the delta ->
   `HYPOTHESIS_REQUIRES_REVIEW` + `STOP` + `HUMAN_REVIEW`;
8. some `MISSING -> AVAILABLE` -> `EVIDENCE_GAP_REDUCED` + `REFINE` +
   `CONTINUE`;
9. PROVIDES on an already-available requirement ->
   `NEW_SUPPORTING_EVIDENCE` + `RETAIN` + `CONTINUE`;
10. fallback -> `EVIDENCE_GAP_REMAINS` + `UNRESOLVED` + `CONTINUE`.

Record-level states are consolidated by documented severity/precedence
(`STOP > WEAKEN > UNRESOLVED > REFINE > RETAIN`; feedback precedence
`INVALIDATED > CONTRADICTING > REQUIRES_REVIEW > GAP_REDUCED > SUPPORTING >
GAP_REMAINS > NO_CHANGE`; next-iteration `STOP > HUMAN_REVIEW > CONTINUE`).

## 9. Correlation

One R70 action -> one R71 plan -> one R72 record -> one R73 iteration record.
Correlated hypotheses are never split: delta entries and evidence items carry
the contributing `hypothesis_ref`, while the record keeps the shared
`hypothesis_refs`/`hypothesis_count`.

## 10. Skill integration

R73 does not create or re-send skills. Each iteration record carries the
`skill_refs` already selected by the R71 plan (e.g. `idor-bola`), so feedback
stays tied to the same bounded R69 methodology that framed the requirement.

## 11. Safety

Safety block unchanged: `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`.

- No execution engine, no target interaction, no authorization.
- Mongo read-only (verified: identical collection counts before/after),
  Indeed only, R61 caps unchanged.
- No raw URLs/IPs/Mongo ids/credentials/tokens in generated output; sensitive
  evidence items are rejected, and remaining strings are bounded and
  redacted.
- No payloads, exploit strings, scanner commands or request bodies exist in
  the module.

## 12. Focused tests

`ai/test_research_feedback_loop.py` — **25 passed**: no-change iteration,
no-change on a ready record, gap reduction (`MISSING -> AVAILABLE` delta),
gap completion to human review, new supporting evidence, contradiction with
remaining evidence (`WEAKEN`), contradiction removing the basis (`STOP`),
invalidation with remaining basis (`REFINE`), invalidation removing the
decision basis (`STOP`), redacted-form matching, ambiguous refs rejected,
correlated hypotheses preserved, skill refs propagated, unknown
hypothesis/requirement/invalidated-ref rejected, sensitive evidence rejected,
malformed fail-closed, evidence identity preserved, empty/malformed inputs,
limit validation, closed vocabularies, safety flags, no
confirmation/execution semantics, summary bands, determinism.

## 13. Local E2E

- `tests/local_e2e/test_r64_research.py` — **122 passed** (includes 4 new R73
  envelope/iteration/correlation/persistence integration tests).
- `pytest tests/local_e2e -q` — **264 passed, 63 subtests**.
- Adjacent suites (R70/R71/R72 planners, R69 skills, OpenRouter, LLM,
  research priority, evidence confidence aggregator, R31.12/R31.13/R31.14
  planners) — **425 passed** in the combined run.

## 14. Real fixture run

Provider/model: real `openrouter` /
`nvidia/nemotron-3-ultra-550b-a55b:free`; runtime-only 900s timeout wrapper
at `/tmp/opencode/r71_live_run.py` (loads `.env`, replaces only
`_real_provider`); repository unchanged. Disclosed attempts: attempt 1 hit a
model-side size bound (`MODEL_OUTPUT_TOO_LARGE`, no artifact); attempt 2
succeeded.

- Status: `COMPLETED_WITH_REJECTIONS` (3 accepted / 1 rejected).
- Artifact: `ai_data/research/r73/r64-indeed-2ea29240244dcf5b.json`
  (45,900 bytes), `research_run_version = r73-1`.
- Iterations: `I1 [IDOR] OBJECT_AUTHORIZATION`, `I2 [RECON]
  ENDPOINT_BEHAVIOR`, `I3 [CVE_RESEARCH] COMPONENT_MAPPING` — all
  `EVIDENCE_GAP_REMAINS / UNRESOLVED -> CONTINUE`, reason
  `NO_RELEVANT_EVIDENCE`, no delta (no new evidence exists in this run).
- Hygiene: no `://`, no `sk-`, no `Bearer`; safety block unchanged.

## 15. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged; one real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (1 accepted / 2 rejected).
- Artifact: `ai_data/research/r73/r64-indeed-b1ebaaf9f2211f82.json`
  (19,701 bytes), `research_run_version = r73-1`.
- Chain: R70 `A1 [LOW] RECON` -> R71 `P1 ENDPOINT_BEHAVIOR` -> R72
  `R1 INSUFFICIENT / NEEDS_EVIDENCE` (blocking `METHOD_AUTH`,
  `RESPONSE_BEHAVIOR`) -> R73 `I1 EVIDENCE_GAP_REMAINS / UNRESOLVED ->
  CONTINUE`, reason `NO_RELEVANT_EVIDENCE`.
- Zero writes: 11 collections identical before and after.

This is the expected honest result for a mostly structural bounded dataset:
no new evidence exists, so the loop reports no change and keeps the hypothesis
unresolved instead of manufacturing progress.

### Synthetic delta demonstration (clearly labelled, offline, not a real run)

To demonstrate the loop's actual transition behavior on real-shaped state,
the persisted real Mongo artifact was re-evaluated offline with a *synthetic*
PROVIDES item for `METHOD_AUTH` (`response:stored-method-and-auth-1`):

    feedback_state: EVIDENCE_GAP_REDUCED
    current_state:  REFINE
    next_iteration: CONTINUE
    reason:         MISSING_EVIDENCE_ACQUIRED
    delta:          METHOD_AUTH MISSING -> AVAILABLE (NEW_EVIDENCE, H1)
    remaining:      RESPONSE_BEHAVIOR

No real new evidence was fabricated or persisted in the artifact.

## 16. R70/R71/R72 relationship

- R70: "What should I investigate?" -> ranked, correlated actions.
- R71: "What evidence should I acquire?" -> bounded acquisition plans.
- R72: "Do I have enough evidence to decide yet?" -> sufficiency state,
  decision state, blockers.
- R73: "What changed since then, and what should the loop do?" -> evidence
  delta, research-state transition, next-iteration decision.

## 17. Actual quality improvement

- The chain is now a closed loop: new evidence can be consumed explicitly and
  its effect is reported as deterministic requirement transitions rather than
  being left implicit.
- Honesty is enforced: no new evidence produces `EVIDENCE_GAP_REMAINS` /
  `UNRESOLVED`; invalidation is never silent; contradictions that remove the
  research basis stop the automated loop for human review; `STOP` never
  implies confirmation.
- Correlation and skill context survive the full chain; correlated
  hypotheses stay one record.
- Evidence identity is preserved and sensitive/ambiguous input fails closed.

## 18. Limitations

- Real bounded Indeed data contains no new evidence, so both real artifacts
  show the honest no-change path; all transitions are covered by synthetic,
  bounded tests and the labelled offline demonstration.
- R71 stores corroborating refs in the previous layer's redacted form; R73
  compensates with raw-outcome matching plus ambiguity rejection, but a
  genuinely ambiguous redacted group cannot be invalidated (fail-closed).
- R73 does not decide whether acquired evidence is convincing; that remains
  human review (`HUMAN_REVIEW`/`STOP`).
- No probabilities, severity, exploitability or CVSS are produced, by design.

## 19. Files changed

- `ai/knowledge/research_feedback_loop.py` (new)
- `ai/test_research_feedback_loop.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r73-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r73-research-feedback-iteration-loop.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner, R72 readiness planner and the safety
boundary are unchanged.

## 20. Commit

One local commit: `feat(ai): add research feedback iteration loop`
(hash reported in the final task response). No push.

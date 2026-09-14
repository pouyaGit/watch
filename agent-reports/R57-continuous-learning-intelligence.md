# R57 Continuous Learning Intelligence

## 1. Summary

R57 adds a deterministic, research-only continuous-learning intelligence
layer over the structured history of the research workflow:

```
R39–R50 Specialist Research
        ↓
R52 Orchestrator
        ↓
R53 Finding
        ↓
R54 Correlation
        ↓
R55 Prioritization
        ↓
R56 Human Decision Boundary
        ↓
R57 Continuous Learning          ← this stage
        ↓
future R58 Controlled Execution
```

R57 answers: **"Given accumulated research outcomes and human decisions,
what stable learning patterns and calibration recommendations can be
extracted for future research?"**

It consumes R42 evaluations, R43 collaboration, R44 feedback, R53 findings,
R54 correlation, R55 prioritization and R56 human decisions; it produces
normalized learning signals, conservative learning patterns and advisory
calibration recommendations with full provenance, governance and
limitations. It never executes anything, never confirms a vulnerability,
never authorizes execution or exploitation and never modifies agents,
specialist logic, rules, scoring formulas, thresholds, prompts, models or
orchestration policies. There is no autonomous background learning process,
no persistence and no production-execution connection.

## 2. Architecture

Three schema layers and two pure engines, all additive:

| File | Rule version | Role |
|---|---|---|
| `ai/schemas/continuous_learning.py` | `r57-1` | Learning signal contract, source layers, observations, strength, authority context, limitations |
| `ai/schemas/learning_pattern.py` | `r57-2` | Learning pattern contract, closed pattern types and calibration indicators |
| `ai/schemas/calibration_recommendation.py` | `r57-3` | Calibration recommendation contract, closed codes, scopes, rationales |
| `ai/schemas/continuous_learning_result.py` | `r57-4` | Result container, statuses, skips, errors, summary/provenance/governance |
| `ai/knowledge/continuous_learning_rules.py` | `r57-5` | Pure extraction/aggregation: ids, safety gate, per-layer signals, patterns, recommendations, summary |
| `ai/knowledge/continuous_learning.py` | `r57-6` | Builder/public API and input validation |

Public API:

- `build_continuous_learning_result(...)` — full result
- `build_learning_signals(...)` — signals stage
- `aggregate_learning_patterns(...)` — signals + patterns stage
- `build_calibration_recommendations(...)` — signals + patterns + recommendations
- `export_continuous_learning(**kwargs)` — alias

Inputs (all optional, validated fail-closed): `orchestration_result` (R52,
carrying R42/R43/R44) **or** standalone `evaluation_results`,
`collaboration_result`, `feedback_result`, plus any of
`finding_intelligence` (R53), `correlation_result` (R54),
`prioritization_result` (R55) and `human_review_result` (R56). Supplying
both the orchestration result and the standalone R42/R43/R44 inputs is
rejected as ambiguous.

Reuse (never duplication): R42 diagnostic/severity vocabulary, R43 conflict
and duplicate-group vocabulary, R44 classification and learning-signal
vocabulary, R53 finding/evidence/governance contracts, R54 relationship
vocabulary and correlation identity, R55 priority plans/governance, R56
human decision authority context.

## 3. New files

```
ai/schemas/continuous_learning.py
ai/schemas/learning_pattern.py
ai/schemas/calibration_recommendation.py
ai/schemas/continuous_learning_result.py
ai/knowledge/continuous_learning_rules.py
ai/knowledge/continuous_learning.py
tests/test_continuous_learning_rules.py
tests/test_continuous_learning.py
tests/test_continuous_learning_safety.py
agent-reports/R57-continuous-learning-intelligence.md
```

## 4. Existing files modified

**None.** No R38–R56 file, backend file, Docker/systemd/deployment/VM file
was modified. R57 is purely additive.

(One implementation detail: `ai/knowledge/continuous_learning.py` mirrors the
R52 orchestration-result rule version as a documented local constant instead
of importing the R52 schema module, because the existing R42–R52 static
contract forbids the orchestrator module name inside `ai/knowledge`
specialist modules. This preserves that contract unchanged.)

## 5. Learning signal model

`ContinuousLearningSignalPlan` (`r57-1`, `extra="forbid"`):

- `signal_id` (`cls-<16 hex>`, content-derived), `signal_type`,
  `source_layer`
- `category`, `specialist_name`, `agent_id`, `finding_id`, `decision_id`,
  `subject_reference`
- `observation`, `feedback_kind`, `evidence_strength`, `confidence`,
  `supporting_references`
- `workflow_feedback`, `truth_label = False`,
  `confirmation_state = NOT_CONFIRMED`, `execution_authorized = False`
- `decision_context` — preserved R56 authority context
  (`decision_source`, `decision_authority`, `human_authority`, and forced
  non-authorization flags)
- `provenance`, `governance`, `limitations`, `research_only`,
  `deterministic`

Closed signal types: repeated evidence/context gap, repeated weak
hypothesis, recurring confidence over/underestimation, repeated duplication,
recurring conflict, repeated governance/provenance/safety/quality issue,
successful research pattern, specialist reliability, prioritization
mismatch, and the six human workflow-feedback signals (approved, requested
evidence, deferred, rejected, escalated, review required).

Closed source layers: `R42_EVALUATION`, `R43_COLLABORATION`,
`R44_FEEDBACK`, `R53_FINDING`, `R54_CORRELATION`, `R55_PRIORITIZATION`,
`R56_HUMAN_DECISION`.

## 6. Learning pattern model

`LearningPatternPlan` (`r57-2`):

- `pattern_id` (`clp-<16 hex>`), `pattern_type`, `source_layers`,
  `category`, `specialist_name`, `agent_id`
- `frequency`, `cross_layer_support`
- `supporting_signal_ids`, `supporting_finding_ids`,
  `supporting_decision_ids`, `supporting_decision_types`
- `calibration_indicator`, `calibration_recommendation_codes`
- `evidence_strength` (`WEAK`/`MODERATE`/`STRONG`), `confidence`
- `decision_context` (human workflow feedback context)
- `provenance`, `governance`, `limitations`
- forced `advisory = True`, `auto_applies = False`,
  `modifies_agents = False`, `modifies_rules = False`,
  `research_only = True`, `deterministic = True`

Conservative emission rule: a pattern is only emitted when supported by
**recurrence** (`frequency >= 2`) or **cross-layer corroboration**
(`cross_layer_support >= 2`). A single observation from a single layer
produces a signal but no pattern. Compatibility is a closed family mapping
(no semantic guesses, no causal claims). Strength derives deterministically
from cross-layer support and frequency; safety patterns are always `STRONG`.

## 7. Calibration recommendation model

`CalibrationRecommendationPlan` (`r57-3`):

- `recommendation_id` (`clc-<16 hex>`), `recommendation_code`,
  `target_scope`, `category`, `specialist_name`
- `pattern_id`, `supporting_pattern_ids`, `supporting_signal_ids`,
  `recommendation_rank`
- `rationale_codes`, `evidence_strength`, `confidence`,
  `human_feedback_basis`
- forced `advisory = True`, `auto_applies = False`,
  `modifies_agents/rules/thresholds/strategies = False`,
  `execution_authorized = False`, `vulnerability_confirmed = False`,
  `confirmation_state = NOT_CONFIRMED`,
  `safety_boundary_preserved = True`, `human_authority_preserved = True`
- `provenance`, `governance`, `limitations`, `research_only`,
  `deterministic`

Closed codes: `REQUEST_MORE_EVIDENCE`, `INCREASE_CONTEXT_COLLECTION`,
`REDUCE_CONFIDENCE`, `REVIEW_CONFIDENCE_CALIBRATION`, `REVIEW_HYPOTHESIS`,
`REVIEW_DUPLICATION`, `REVIEW_CONFLICT`, `REVIEW_GOVERNANCE`,
`REVIEW_PROVENANCE`, `REVIEW_SAFETY_BOUNDARY`,
`PRESERVE_SUCCESS_PATTERN`, `REVIEW_HUMAN_FEEDBACK`,
`REVIEW_PRIORITY_ALIGNMENT`, `REVIEW_RESEARCH_QUALITY`,
`REVIEW_SPECIALIST_RELIABILITY`. Ranking is deterministic with safety
recommendations first, then strength, frequency, code order and pattern id.
Every recommendation carries `FUTURE_STAGE_REQUIRED`,
`HUMAN_REVIEW_REQUIRED` and `NO_AUTOMATIC_BEHAVIOR_CHANGE` limitations.

## 8. R42 integration

R42 evaluation results contribute: safety failures
(`REPEATED_SAFETY_ISSUE`, strong), weak/critical ratings
(`REPEATED_QUALITY_ISSUE`), strong ratings with `PASS` safety
(`SPECIALIST_RELIABILITY`, success observation) and every R42 diagnostic via
a closed mapping using the R42 diagnostic constants (`CONFIDENCE_OVERSTATED`,
`CONFIDENCE_UNDERSPECIFIED`, `MISSING_EVIDENCE_REQUIREMENT`,
`CONTEXT_TOO_SPARSE`, `UNSUPPORTED_HYPOTHESIS`, `PROVENANCE_INCOMPLETE`,
`GOVERNANCE_UNKNOWN`, `EXECUTION_CLAIM_DETECTED`, and the rest of the R42
catalogue). Diagnostic severity maps deterministically to signal strength.

## 9. R43 integration

R43 collaboration conflicts contribute `RECURRING_CONFLICT` signals with
the conflict type, resolution state and subject agents; duplicate hypothesis
groups contribute `REPEATED_DUPLICATION` signals with participating agents.
Both preserve the R43 result rule version in provenance.

## 10. R44 integration

R44 feedback classifications are the preferred source (closed mapping:
quality improvement, confidence calibration, evidence gap, hypothesis
weakness, duplication, conflict, governance, provenance, safety, success).
When no classifications are present, R44 learning signals are used through
the closed fallback mapping (`REQUIRE_MORE_EVIDENCE`, `REDUCE_CONFIDENCE`,
`IMPROVE_CONTEXT_COLLECTION`, `PRESERVE_SUCCESS_PATTERN`,
`AVOID_DUPLICATION`, `REVIEW_GOVERNANCE`, `REVIEW_PROVENANCE`,
`IMPROVE_HYPOTHESIS_QUALITY`, `IMPROVE_SAFETY_BOUNDARY`). R44 recommendations
are not reinterpreted; R57 never modifies learning memory.

## 11. R53 integration

R53 finding intelligence contributes evidence gaps, weak hypotheses, context
gaps, confidence over/underestimation, duplication, conflict, governance
issues, provenance issues, defensive safety issues and evaluation-rating
quality issues. The R53 finding/evidence/assessment/governance contracts are
read through their sanitized shapes; provenance preserves the R53 rule
version and orchestration id.

## 12. R54 integration

R54 correlation results contribute `RECURRING_CONFLICT` and
`REPEATED_DUPLICATION` signals per relationship, with source/target finding
ids, agent ids, category lookup from finding references, the correlation id
and the R54 relationship rule version (`r54-1`). Correlation is never
treated as causality.

## 13. R55 integration

R55 prioritization plans contribute conflict context, duplicate context,
governance context (unknown reference state or a governance band cap),
missing provenance and `PRIORITIZATION_MISMATCH` (strong evidence and a
strong research state ranked `LOW`). The immutable R55 priority is read
only; R57 never rewrites scores, bands or ranking.

## 14. R56 human-feedback integration

R56 becomes a first-class learning source. Every decision type maps to a
closed workflow-feedback signal:

| Human decision | R57 signal | Observation |
|---|---|---|
| `APPROVE_RESEARCH` | `HUMAN_APPROVED_RESEARCH` | `SUCCESS` |
| `REQUEST_MORE_EVIDENCE` | `HUMAN_REQUESTED_EVIDENCE` | `WORKFLOW_FEEDBACK` |
| `DEFER` | `HUMAN_DEFERRED_RESEARCH` | `WORKFLOW_FEEDBACK` |
| `REJECT` | `HUMAN_REJECTED_WORKFLOW` | `WORKFLOW_FEEDBACK` |
| `ESCALATE` | `HUMAN_ESCALATED_RESEARCH` | `WORKFLOW_FEEDBACK` |
| `NEEDS_REVIEW` | `HUMAN_REVIEW_REQUIRED` | `WORKFLOW_FEEDBACK` |

Rationale codes that structurally name a family (`EVIDENCE_INCOMPLETE`,
`HYPOTHESIS_NEEDS_STRENGTHENING`, `CONFLICT_REQUIRES_RESOLUTION`,
`DUPLICATE_RESEARCH_OVERLAP`, `GOVERNANCE_REVIEW_REQUIRED`,
`PROVENANCE_INCOMPLETE`) add corroborating workflow-feedback signals, which
is how R53/R54/R55 observations and human decisions combine into one
stronger cross-layer pattern.

**Human decisions are workflow feedback, never truth labels.**
`APPROVE_RESEARCH` never becomes "finding is true" and `REJECT` never
becomes "finding is false": every decision-derived signal forces
`feedback_kind = WORKFLOW_FEEDBACK`, `truth_label = False`,
`confirmation_state = NOT_CONFIRMED`, `execution_authorized = False`, and
preserves `decision_source`, `decision_authority`, `human_authority`,
`vulnerability_confirmed` and `exploit_authorized` in the decision context.

## 15. Safety boundary

- No execution/network/DNS/subprocess/browser/scanner/database/LLM
  capability exists in any R57 module (AST static tests).
- Forbidden autonomous/execution requests are rejected fail-closed:
  true-valued `execution_authorized`, `vulnerability_confirmed`,
  `exploit_authorized`, `auto_applies`, `modifies_agents/rules/thresholds/
  strategies` or `auto_execute` anywhere in an input, plus forbidden claims
  (`GENERATE_PAYLOAD`, `BYPASS_HUMAN`, `DISABLE_SAFETY`,
  `AUTONOMOUS_EXECUTION`, `VULNERABILITY_CONFIRMED`, ...). Rejected inputs
  are preserved as structured `SAFETY_BLOCKED` skips; they produce no
  signals and no recommendations.
- Negative safety codes (`NO_PAYLOAD_GENERATION`,
  `ATTACK_PLANNING_NOT_AUTHORIZED`, `EXECUTION_NOT_AUTHORIZED`, ...) are
  explicitly recognized as safe and are never flagged (negation-aware,
  string-content-only scanning avoids false positives on structural flags).
- Unsafe learning signals can never outrank safety: `REVIEW_SAFETY_BOUNDARY`
  recommendations always rank first, and safety patterns are always
  `STRONG`.
- Every output is advisory: no auto-apply, no behavior change, no agent or
  rule modification. Human authority is preserved everywhere.

## 16. Determinism guarantees

- Content-derived ids only: `cls-` (signal), `clp-` (pattern), `clc-`
  (calibration recommendation), `clr-` (learning result), all
  `sha256(canonical JSON)[:16]`.
- Signals are deduplicated by id, then canonically sorted; truncation
  happens after sorting, so results are independent of input ordering.
- Patterns group by `(family, category)` in a fixed enum order; members,
  ids, layers, decision ids and support lists are sorted.
- Recommendations are ranked by `(safety-first, strength, frequency, code
  order, pattern id)`.
- No timestamps, UUIDs, pids, randomness or wall-clock dependence; AST
  tests forbid `random`, `uuid`, `time`, `datetime` imports/calls.
- Byte-identical repeated output and shuffled-input equivalence are tested.

## 17. Test results

Focused R57 tests (all offline, `unittest` style):

```
python -m pytest tests/test_continuous_learning_rules.py -q -p no:cacheprovider
62 passed

python -m pytest tests/test_continuous_learning.py -q -p no:cacheprovider
46 passed

python -m pytest tests/test_continuous_learning_safety.py -q -p no:cacheprovider
22 passed

combined: 130 passed
```

Coverage includes the signal/pattern/recommendation schemas, deterministic
signal generation, deterministic pattern aggregation, human decision
integration for all six decision types, workflow-feedback vs truth-label
separation, provenance and governance preservation, safety rejection,
duplicate/conflict/evidence/confidence/hypothesis/priority learning,
successful-pattern preservation, specialist and category aggregation,
deterministic ids, stable ordering, empty input, malformed and
unsupported input, advisory-only/no-autonomous-modification invariants,
input immutability, R42→R57 and full R42–R56 integration, and AST static
safety checks.

Relevant regression (all passed):

```
R42/R43/R44/R52/R53/R54/R55/R56 + finding/priority/human-loop suite:
  792 passed

AI safety (knowledge_store/xss_researcher/xss_llm_researcher/openrouter):
  96 passed
```

## 18. Full-suite result

```
python -m pytest tests/ -q -p no:cacheprovider
5546 passed, 40 failed, 1 warning, 376 subtests passed in 55.10s
```

Baseline (R56): `5416 passed, 40 failed, 376 subtests`.

- passed growth: `5546 - 5416 = 130` — exactly the 130 new R57 tests;
- failed count unchanged at 40; subtests unchanged at 376;
- the sorted failure list is byte-identical to the R56 baseline set and no
  failure references R57 (the single "calibration" substring match is the
  pre-existing `test_research_economics_calibration.py` failure).

## 19. Git diff/stat

```
 agent-reports/R57-continuous-learning-intelligence.md |  411 +
 ai/schemas/continuous_learning.py                     |  703 +
 ai/schemas/learning_pattern.py                        |  521 +
 ai/schemas/calibration_recommendation.py              |  592 +
 ai/schemas/continuous_learning_result.py              |  719 +
 ai/knowledge/continuous_learning_rules.py             | 2204 +
 ai/knowledge/continuous_learning.py                   |  536 +
 tests/test_continuous_learning_rules.py               | 1250 +
 tests/test_continuous_learning.py                     | 1097 +
 tests/test_continuous_learning_safety.py              |  627 +
 10 files changed, 8660 insertions(+)
```

All changes are additions (0 deletions), and `git diff --check` is clean.

## 20. Git status

```
 D utils.zip
?? agent-reports/R31-final-github-audit.md
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/continuous_learning.py
?? ai/knowledge/continuous_learning_rules.py
?? ai/schemas/calibration_recommendation.py
?? ai/schemas/continuous_learning.py
?? ai/schemas/continuous_learning_result.py
?? ai/schemas/learning_pattern.py
?? tests/test_continuous_learning.py
?? tests/test_continuous_learning_rules.py
?? tests/test_continuous_learning_safety.py
?? watch.zip
```

The pre-existing unrelated worktree items (` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`) remain untouched and
outside the R57 commit. No existing tracked file was modified.

## 21. Commit hash

One local commit was created:

- Subject: `feat(learning): add r57 continuous learning intelligence`
- Parent: `3787460` (R56 Human-in-the-Loop)
- Exact commit hash is reported in the final task response (a commit cannot
  embed its own hash; this report is part of that single R57 commit).

## 22. Push confirmation

**NO push was performed.** Nothing was pushed to GitHub; no remote branch or
remote-tracking state was modified. The commit exists locally only.

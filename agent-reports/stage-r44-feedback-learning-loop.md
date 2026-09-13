# Stage R44 — Research Feedback Learning Loop

A deterministic, research-only feedback learning layer. R44 closes the
intelligence cycle by converting previous structured research outcomes
(R42 evaluations, R43 collaborations) into structured learning signals,
pattern memory and advisory recommendations. It does not execute anything,
does not test security, and does not modify agents, rules, strategy or
runtime behavior.

- Stage: R44
- Rule versions: `r44-1` … `r44-5`
- Commit: `feat(research): add r44 feedback learning loop` (local only, not
  pushed; hash reported in the final response)

## 1. Objective

Answer: **"What did previous research teach us?"** — while making clear it
does NOT answer "How do we exploit the target?", "How do we execute
attacks?" or "How do we modify agents automatically?" R44 is a learning
signal extraction layer only.

## 2. Architecture

```
Research Result
      ↓
R42 Evaluation
      ↓
R43 Collaboration
      ↓
R44.1 Feedback event          ai/schemas|knowledge/research_feedback_event.py
      ↓
R44.2 Feedback classification ai/schemas|knowledge/research_feedback_classification.py
      ↓                                              research_feedback_classifier.py
R44.3 Learning signals        ai/schemas|knowledge/learning_signal.py
      ↓                                              learning_signal_extractor.py
R44.4 Pattern memory          ai/schemas|knowledge/research_learning_memory.py
      ↓                                              research_learning_memory_export.py
R44.5 Recommendations         ai/schemas|knowledge/learning_recommendation.py
                                                     learning_recommendation_generator.py
```

All components are deterministic, pure/offline, stateless, JSON
serializable and pydantic validated (`extra="forbid"`, forced rule versions,
`research_only=True`).

## 3. Feedback model

`ResearchFeedbackEventPlan` (`r44-1`): `rule_version`, `feedback_id`,
`source_agent`, `source_category`, `evaluation_reference`,
`collaboration_reference`, `outcome_type`, `observed_issue`,
`observed_success`, `confidence`, `provenance`, `governance_reference`,
`research_only`, `structural_flags`.

- `feedback_id` is a deterministic content token (`fb-<16 hex>`) or a
  caller-supplied validated token; no timestamps, random UUIDs or runtime
  ids.
- `outcome_type` is a closed observation vocabulary (`QUALITY_OBSERVATION`,
  `CONFIDENCE_OBSERVATION`, `EVIDENCE_OBSERVATION`, … `UNKNOWN`).
- `observed_issue` and `observed_success` are closed observation codes
  (`ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE`, `ISSUE_MISSING_PROVENANCE`,
  `SUCCESS_STRONG_EVALUATION`, …).
- Malformed inputs produce structural flags (`MALFORMED_*`,
  `MISSING_REQUIRED_FIELD`, `INVALID_ENUM_VALUE`,
  `UNKNOWN_SOURCE_CATEGORY`, `NON_DETERMINISTIC_INPUT`); nothing is silently
  accepted.
- Missing provenance/governance stays `{}` so "no record" is distinguishable
  from "recorded as UNKNOWN".

## 4. Classification model

`ResearchFeedbackClassificationPlan` (`r44-2`): `classification`, `subject`,
`source_agent`, `feedback_id`, `reasons`, `supporting_signals`,
`confidence`, `limitations`.

Closed classifications: `QUALITY_IMPROVEMENT`, `CONFIDENCE_CALIBRATION`,
`EVIDENCE_GAP`, `HYPOTHESIS_WEAKNESS`, `DUPLICATION_PATTERN`,
`CONFLICT_PATTERN`, `GOVERNANCE_ISSUE`, `PROVENANCE_ISSUE`, `SAFETY_ISSUE`,
`SUCCESS_PATTERN`, `UNKNOWN`.

Deterministic priority: SAFETY → CONFLICT → DUPLICATION → CONFIDENCE →
EVIDENCE → HYPOTHESIS → SUCCESS → GOVERNANCE → PROVENANCE → QUALITY →
UNKNOWN. Specific structured signals (confidence diagnostics, evidence
diagnostics, observed codes) are evaluated before generic unknown
governance/provenance, so a concrete calibration or evidence gap is not
masked by default unknowns. `SUCCESS_PATTERN` requires an entirely clean
structured result (no evaluation diagnostics, no conflicts, no duplicates).
No LLM and no semantic inference is used.

## 5. Learning signals

`LearningSignalPlan` (`r44-3`): `signal_type`, `subject`, `source_agent`,
`source_classification`, `recommendation`, `supporting_signals`,
`confidence`, `limitations`, `research_only`.

Closed signal types: `REQUIRE_MORE_EVIDENCE`, `REDUCE_CONFIDENCE`,
`IMPROVE_CONTEXT_COLLECTION`, `PRESERVE_SUCCESS_PATTERN`,
`AVOID_DUPLICATION`, `REVIEW_GOVERNANCE`, `REVIEW_PROVENANCE`,
`IMPROVE_HYPOTHESIS_QUALITY`, `IMPROVE_SAFETY_BOUNDARY`, `UNKNOWN`.

Signals map deterministically from classifications and carry fixed
recommendation text. They are recommendations only: they never modify
agents, rules or runtime behavior. Preservation of subject, agent,
classification and supporting signals is verified by tests.

## 6. Pattern memory

`ResearchLearningMemoryPlan` (`r44-4`): `patterns`, `memory_state`,
`limitations`, `research_only`. Each `LearningPatternPlan` has `pattern_id`
(`pat-<16 hex>`), `source_category`, `pattern_type`, `occurrence_count`,
`confidence`, `supporting_events`, `limitations`.

Events aggregate by (source category, classification); occurrence counts and
supporting feedback ids are deterministic. Confidence escalates (3+
occurrences with a HIGH classification → HIGH; 2+ → MEDIUM; else LOW) and
`memory_state` is `COMPLETE` / `PARTIAL` / `UNKNOWN`. There are no automatic
rule changes and no automatic agent tuning; pattern limitations include
`NO_AUTOMATIC_AGENT_TUNING`, `NO_RULE_MODIFICATION` and `ADVISORY_ONLY`.

## 7. Recommendation model

`LearningRecommendationPlan` (`r44-5`): `recommendation_id`,
`recommendation_type`, `related_agent`, `related_category`,
`source_classification`, `supporting_signals`, `recommendation`,
`confidence`, `limitations`, `research_only`.

Closed recommendation types: `PRIORITIZE_EVIDENCE_PLANNING`,
`CALIBRATE_CONFIDENCE`, `IMPROVE_CONTEXT_CAPTURE`,
`PRESERVE_SUCCESSFUL_PATTERN`, `DEDUPLICATE_HYPOTHESES`,
`REVIEW_GOVERNANCE_REFERENCES`, `PRESERVE_PROVENANCE`,
`STRENGTHEN_HYPOTHESES`, `RESTORE_SAFETY_BOUNDARY`, `UNKNOWN`.

Recommendations are advisory only, deduplicated by (type, agent, category,
classification) and emitted in canonical order. Limitations include
`NO_AGENT_MODIFICATION`, `NO_RULE_MODIFICATION`,
`NO_AUTOMATIC_STRATEGY_CHANGE` and `ADVISORY_ONLY`.

## 8. R42 integration

R44 consumes R42 evaluation results through the R42 result sanitizer:
overall score/rating, hard-gate state, safety state, per-dimension scores
(structural, safety, evidence, confidence) and diagnostic codes. R42 is
never recomputed, and R42's scoring rules are not duplicated. Diagnostic
codes such as `CONFIDENCE_OVERSTATED`, `MISSING_EVIDENCE_REQUIREMENT`,
`UNSUPPORTED_HYPOTHESIS`, safety violations and governance/provenance
diagnostics drive deterministic classification.

## 9. R43 integration

R44 consumes R43 collaboration results through the R43 result sanitizer:
participants, conflict count and types, duplicate/related group counts,
merged evidence state and ranking count. R43 correlation logic is not
duplicated; duplicate and conflict patterns are read from the supplied
collaboration result. A participant's provenance contributes to the feedback
event when present.

## 10. Safety boundary

- R44 modules import only `__future__`, `re`, `hashlib`, `json`, `pydantic`
  and `ai.schemas`/`ai.knowledge`. No network client, DNS, socket,
  subprocess, shell, browser automation, SQL/database client,
  sqlmap/nuclei, LLM, embedding, filesystem state, persistence, worker or
  scheduler.
- R44 transforms structured historical outcomes only. It does not execute
  agents, run security tests, generate payloads or attack instructions,
  self-update, modify rules/strategy, or persist uncontrolled runtime state.

## 11. Determinism

The same input produces the same feedback events, classifications, learning
signals, patterns and recommendations. Tests assert byte-identical JSON
across repeated runs and the absence of `timestamp`, `uuid` and
`runtime_id`. Feedback ids, pattern ids and recommendation ids are
deterministic content tokens.

## 12. Tests

| Suite | Tests |
|---|---|
| `tests/test_research_feedback_event.py` (R44.1) | 16 |
| `tests/test_feedback_classifier.py` (R44.2) | 21 |
| `tests/test_learning_signal_extractor.py` (R44.3) | 14 |
| `tests/test_research_learning_memory.py` (R44.4) | 13 |
| `tests/test_learning_recommendation.py` (R44.5) | 17 |
| **R44 total** | **81 passed** |

Coverage includes valid/malformed input, extra-field rejection, deterministic
ids, attribution, save/sparse references, every classification branch,
confidence calibration, evidence gap, duplication, conflict, safety,
governance, provenance, success and unknown, learning-signal mapping and
text, pattern aggregation and confidence escalation, recommendation mapping,
deduplication, ordering, advisory limitations, XSS/SSRF/SQLi examples,
serialization determinism and the R44 AST safety scan.

## 13. Regression results

```
R44 focused suites                                         81 passed
R38 suites                                                132 passed
R39 suites                                                100 passed
R40 suites                                                122 passed
R41 suites                                                131 passed
R42 suites                                                 91 passed
R43 suites                                                102 passed
All tests referencing r31- … r43- (80 files)  2036 passed, 27 subtests
```

## 14. Full-suite results

The full suite could not complete on this host: `database/db.py` connects at
import to a hardcoded external MongoDB (`35.202.201.30:27017`) which became
unreachable during this session, so the 29 tests that call
`build_matches`/`evaluate_inventory` block on connection retries. This is a
pre-existing environment dependency, unrelated to R44, and no code or config
was changed to work around it.

Instead, the full non-DB suite was run:

```
python -m pytest <104 non-DB test files> -q
2793 passed, 40 failed, 325 subtests passed
```

The sorted `FAILED` set is byte-identical to the corresponding non-DB subset
of the R43 full-suite baseline (0 differences): no new failure and no
existing failure altered. The 40 failures are the pre-existing
money-score/economics corpus-drift failures.

## 15. Existing failure comparison

R43 baseline non-DB failing entries vs R44 non-DB failing entries:
`only-in-R43 = 0`, `only-in-R44 = 0`. The 40 pre-existing failures are
unchanged; none was modified or "fixed".

## 16. Backend decision

R44 is a standalone intelligence layer initially. `backend/asset_cve_matching.py`
was not modified (`git diff` clean), and a test asserts the backend does not
import or call the feedback/learning modules.

## 17. Git status

Unrelated pre-existing worktree items remain outside the R44 commit and were
not modified: ` D utils.zip`, `?? watch.zip`,
`?? agent-reports/R31-final-github-audit.md`,
`?? agent-reports/stage-r31-5-planning-audit.md`. Only new R44 files are
added; `git diff --check` is clean.

## 18. Commit hash

Commit message: `feat(research): add r44 feedback learning loop`. Hash is
reported in the final response after the local commit (the report is part of
the same commit; no amend and no push).

## 19. Limitations

- R44 learns only from structured indicators already present in R42/R43
  outputs; it cannot infer lessons from unrepresented context.
- Classification priority is a fixed design choice; simultaneous issues are
  represented by the highest-priority classification only.
- Pattern confidence is a function of occurrence count and per-event
  classification confidence, not statistical significance.
- Recommendations are advisory text with fixed wording; they are not
  executed, scheduled or applied.
- The full-suite metric is environment-constrained (external MongoDB
  unreachable); the non-DB full run is the authoritative comparison here.

## 20. Explicit no-execution statement

Explicitly: R44 contains no execution capability of any kind. There is no
agent execution, security testing, network request, DNS resolution,
database connection, SQL execution, JavaScript execution, payload
generation or execution, nuclei/sqlmap invocation, scanner, external API
call, LLM call, rule/agent modification, self-update, persistence, worker or
scheduler anywhere in R44. The feedback learning loop reads structured
artifacts, classifies them deterministically, and emits advisory learning
signals, patterns and recommendations.

## Agent / Model

- Model: deepseek-v4.1-flash
- Stage: R44
- Role: coding agent

# R31.19 Evidence Feedback Calibration Planner

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Feedback Calibration Planner that converts the
current R31.18 research outcome into a reusable feedback signal, answering:

- What feedback signal does this outcome produce?
- Which research dimension needs improvement?
- What should future planning stages be aware of?

The planner analyzes outcome signals only. It never executes research, never
acquires evidence, never recomputes previous stages, never inspects CVE data,
never calculates the Money Score, never modifies the R29 queue and never
changes existing planner semantics.

## 2. Files Changed

- `ai/schemas/evidence_feedback_calibration.py` — **new** pydantic schema
  module (362 lines): `EvidenceFeedbackCalibrationPlan`, closed feedback/
  strength/improvement vocabularies, imported outcome/confidence/blocker
  vocabularies, bounds and sanitization for all six embedded source-plan
  snapshots.
- `ai/knowledge/evidence_feedback_calibration_planner.py` — **new** pure
  module (296 lines, `r31-19`): deterministic outcome→feedback table and
  `plan_evidence_feedback_calibration()`.
- `backend/asset_cve_matching.py` — **modified additively** (+20/-0):
  `summary["evidence_feedback_calibration_plan"]` and
  `summary["evidence_feedback_calibration_plan_rule_version"]` attached after
  the R31.18 block. No existing field renamed, removed or changed.
- `tests/test_evidence_feedback_calibration_planner.py` — **new** focused
  suite (47 tests, 1136 lines).
- `agent-reports/stage-r31-19-evidence-feedback-calibration.md` — this report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced.

## 3. Architecture Decisions

- **Consume R31.13-R31.18 only.** The planner reads the R31.18 `outcome` and
  `remaining_need` (plus passed-through confidence/blockers) and embeds
  bounded snapshots of all six upstream plans. It never calls an upstream
  engine and never recomputes any previous stage.
- **Single authoritative feedback table.** `OUTCOME_FEEDBACK` maps each of the
  five closed R31.18 outcomes to exactly one feedback-type/strength pair;
  completed cycles are fixed to improvement area `NONE`, in-progress/gap/
  deferred outcomes derive the area from `remaining_need`, and an
  unrecognized or missing outcome yields the terminal
  `UNKNOWN`/`UNKNOWN`/`PROCESS` signal.
- **Remaining-need derives the improvement area.** The closed
  `REMAINING_NEED_TO_IMPROVEMENT` table maps all ten R31.18 remaining needs;
  unknown or invalid values map to `UNKNOWN`. `PROCESS` is reserved for
  malformed/unrecognized outcome state (a planning-process issue).
- **Schema-validated output.** The R31.19 schema rejects unknown fields
  (`extra="forbid"`), fixes `rule_version` to `r31-19`, forces
  `research_only=True`, bounds every list/string and sanitizes all six
  embedded snapshots (reusing the R31.14-R31.18 sanitizers).
- **Plan-only and additive.** No field, code path or dependency can execute
  research or change prior planner behavior; new backend keys only.

## 4. Closed Vocabularies

- `feedback_type`: `SUCCESS_SIGNAL`, `CONTINUE_SIGNAL`,
  `EVIDENCE_GAP_SIGNAL`, `DEFER_SIGNAL`, `UNKNOWN`.
- `signal_strength`: `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
- `improvement_area`: `NONE`, `IDENTITY`, `VERSION`, `SCOPE`, `PATH`,
  `PARAMETER`, `HTTP_BEHAVIOR`, `TECHNOLOGY`, `HUMAN_RESEARCH`, `PROCESS`,
  `UNKNOWN`.
- `outcome` / `confidence_level` / `blockers[]`: imported closed
  R31.15/R31.18 vocabularies.

Bounds: `MAX_BLOCKERS = 8`, `MAX_ITEMS = 8`, `MAX_VALUE_LEN = 160`. All six
source snapshots use fixed key sets and are redacted (`_safe_text`).

## 5. Deterministic Feedback Mapping

| R31.18 outcome | feedback_type | signal_strength | improvement_area |
|---|---|---|---|
| `COMPLETED` | `SUCCESS_SIGNAL` | `HIGH` | `NONE` |
| `IN_PROGRESS` | `CONTINUE_SIGNAL` | `MEDIUM` | from `remaining_need` |
| `WAITING_FOR_EVIDENCE` | `EVIDENCE_GAP_SIGNAL` | `HIGH` | from `remaining_need` |
| `DEFERRED` | `DEFER_SIGNAL` | `LOW` | from `remaining_need` |
| `UNKNOWN` / unrecognized / missing | `UNKNOWN` | `UNKNOWN` | `PROCESS` |

Remaining need → improvement area: `NONE`→`NONE`, `IDENTITY`→`IDENTITY`,
`VERSION`→`VERSION`, `SCOPE`→`SCOPE`, `PATH`→`PATH`, `PARAMETER`→`PARAMETER`,
`HTTP_BEHAVIOR`→`HTTP_BEHAVIOR`, `TECHNOLOGY`→`TECHNOLOGY`,
`HUMAN_RESEARCH`→`HUMAN_RESEARCH`, `UNKNOWN`→`UNKNOWN` (and any invalid value
→ `UNKNOWN`). In the normal deferred path the remaining need is `UNKNOWN`, so
`DEFERRED` reports improvement area `UNKNOWN`.

## 6. Output Shape

```json
{
  "rule_version": "r31-19",
  "feedback_type": "EVIDENCE_GAP_SIGNAL",
  "signal_strength": "HIGH",
  "improvement_area": "VERSION",
  "outcome": "WAITING_FOR_EVIDENCE",
  "confidence_level": "MEDIUM",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "source_outcome_plan": { "...bounded R31.18 snapshot..." },
  "source_loop_plan": { "...bounded R31.17 snapshot..." },
  "source_decision_plan": { "...bounded R31.16 snapshot..." },
  "source_confidence_plan": { "...bounded R31.15 snapshot..." },
  "source_priority_plan": { "...bounded R31.14 snapshot..." },
  "source_acquisition_plan": { "...bounded R31.13 snapshot..." },
  "research_only": true
}
```

## 7. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_evidence_feedback_calibration_planner -v
./venv/bin/python -m unittest tests.test_evidence_feedback_calibration_planner \
    tests.test_evidence_research_outcome_tracker \
    tests.test_evidence_research_loop_planner \
    tests.test_evidence_decision_planner \
    tests.test_evidence_confidence_aggregator \
    tests.test_evidence_prioritization_planner \
    tests.test_evidence_acquisition_planner tests.test_hunt_action_planner \
    tests.test_hunt_actionability tests.test_hunt_priority \
    tests.test_evidence_quality tests.test_path_parameter_relevance \
    tests.test_version_normalization tests.test_component_evidence_provenance \
    tests.test_component_identity tests.test_component_inference \
    tests.test_component_plugin_wiring tests.test_observed_inventory \
    tests.test_asset_cve_matching tests.test_version_component_association \
    tests.test_hunt_queue -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/schemas/evidence_feedback_calibration.py \
    ai/knowledge/evidence_feedback_calibration_planner.py \
    backend/asset_cve_matching.py \
    tests/test_evidence_feedback_calibration_planner.py
git diff --check
```

Results:

```
tests.test_evidence_feedback_calibration_planner Ran 47 tests   OK  (new)
combined R31.10-R31.19 + R29/R30/R31 regression  Ran 992 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)          Ran 2574 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2527-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.19
py_compile                                       OK
git diff --check                                 clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndMutation.test_1_repeated_output_is_byte_identical`, `...test_1_key_insertion_order_does_not_matter`, `...test_1_stable_feedback_across_all_methods` |
| 2 | all feedback mappings | `TestFeedbackMappings` (7 tests: success/continue/evidence-gap/defer/unknown, real-engine chain, closed table) |
| 3 | remaining_need mapping | `TestRemainingNeedMapping` (4 tests: all ten needs, invalid need, completed forces NONE, closed table) |
| 4 | unknown handling | `TestUnknownAndMalformed.test_4_unknown_outcome` |
| 5 | malformed input | `...test_5_missing_inputs`, `...test_5_unrecognized_outcome`, `...test_5_lowercase_outcome_is_normalized`, `...test_5_confidence_level_falls_back_to_confidence_plan` |
| 6 | no input mutation | `TestDeterminismAndMutation.test_6_*` (3 tests, including snapshot aliasing) |
| 7 | closed vocabulary validation | `TestClosedVocabulary` (12 tests: output sets + pydantic rejection paths, fixed rule version, bounded blockers, blocker flow/filtering) |
| 8 | JSON serialization | `TestOutputShape.test_8_json_serializable` |
| 9 | research_only always true | `TestOutputShape.test_9_research_only_always_true` |
| 10 | no operational attack content | `TestOutputShape.test_10_no_operational_attack_content`, `...test_10_source_snapshots_are_sanitized`, `...test_10_source_snapshots_are_bounded` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions (r31-10..r31-19), immediate plan
yields `SUCCESS_SIGNAL`/`HIGH`/`NONE` while `hunt_priority` stays P0/96,
blocked plan yields `DEFER_SIGNAL`/`LOW`, no existing field overwritten,
Money Score canary. The R29 projection contains no feedback field;
R31.13-R31.18 plans are unchanged by the calibration.

## 8. Baseline Regression Comparison

- Baseline (before R31.19): `unittest discover` ran **2527 tests / 37
  failures / 3 errors**. After R31.19: **2574 tests / 37 failures / 3 errors**
  (+47 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.19.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13-R31.18 outputs are deep-copy equal after calibration.

## 9. Performance

```
1 candidate     ->   0.44 ms  (438.2 us/candidate, fixed overhead)
100 candidates  ->  28.61 ms  (286.1 us/candidate)
1000 candidates -> 222.97 ms  (223.0 us/candidate)
```

Cost is O(bounded snapshots + one pydantic model construction with nested
validation); no corpus, URL, endpoint, HTTP or Mongo access occurs at this
layer. The module is pure and stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- `improvement_area` derives from the R31.18 remaining need for
  `IN_PROGRESS`, `WAITING_FOR_EVIDENCE` and `DEFERRED`; only `PROCESS` is
  reserved for malformed/unrecognized outcome state. `UNKNOWN` remains
  reachable for deferred/invalid remaining-need cases.
- The feedback signal is a pure projection of one outcome; it does not
  aggregate across candidates, persist history or adjust any future planner
  weights. Any consumption of this signal by a later stage would be a new,
  separately reviewed step.
- `blockers[]` merges the R31.18, R31.17 and R31.15 closed blocker sets; it is
  explanatory only and never changes the feedback signal.
- Wiring the calibration plan into the R29 queue schema/projection or UI is
  out of scope: R29 must not be modified by this stage.
- The calibration plan is advisory and is never executed. No HTTP request,
  browser action, Nuclei run, crawl, fuzzing, scan, exploitation, LLM call,
  Mongo access or target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.19
- Role: coding agent

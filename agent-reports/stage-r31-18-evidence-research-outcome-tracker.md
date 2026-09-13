# R31.18 Evidence Research Outcome Tracker

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Research Outcome Tracker that converts the
current R31.17 research loop state into a tracked outcome state, answering:

- What is the current research outcome?
- Is the research cycle complete?
- Is evidence still required?
- Is the candidate deferred?

The tracker records outcome state only. It never executes research, never
collects evidence, never recalculates previous planner outputs, never
inspects CVE data, never calculates the Money Score and never modifies the R29
queue or any previous planner semantics.

## 2. Files Changed

- `ai/schemas/evidence_research_outcome.py` — **new** pydantic schema module
  (363 lines): `EvidenceResearchOutcomePlan`, closed outcome/category/
  completion/remaining-need vocabularies, imported blocker vocabulary, bounds
  and sanitization for all five embedded source-plan snapshots.
- `ai/knowledge/evidence_research_outcome_tracker.py` — **new** pure module
  (272 lines, `r31-18`): deterministic lifecycle→outcome table and
  `track_evidence_research_outcome()`.
- `backend/asset_cve_matching.py` — **modified additively** (+19/-0):
  `summary["evidence_research_outcome_plan"]` and
  `summary["evidence_research_outcome_plan_rule_version"]` attached after the
  R31.17 block. No existing field renamed, removed or changed.
- `tests/test_evidence_research_outcome_tracker.py` — **new** focused suite
  (48 tests, 1136 lines).
- `agent-reports/stage-r31-18-evidence-research-outcome-tracker.md` — this
  report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced.

## 3. Architecture Decisions

- **Consume R31.13-R31.17 only.** The tracker reads the R31.17
  `lifecycle_state` (and the passed-through confidence/blockers) and embeds
  bounded snapshots of all five upstream plans. It never calls an upstream
  engine and never recomputes acquisition, priority, confidence, decision or
  loop state.
- **Single authoritative outcome table.** `LIFECYCLE_OUTCOMES` maps each
  emitted R31.17 lifecycle state to exactly one outcome/category/completion
  triple. Reserved lifecycle values (`INITIAL`, `EVIDENCE_READY`, `UNKNOWN`)
  and any unexpected value yield the terminal `UNKNOWN` / `INVALID_STATE`
  outcome.
- **Remaining need derives from the R31.15 limiting factor.** The closed
  `LIMITING_TO_REMAINING_NEED` table maps all ten R31.15 limiting factors to
  the ten R31.18 remaining-need values; `UPSTREAM_PLAN` and any invalid value
  map to `UNKNOWN`. A completed cycle always reports `NONE`.
- **Schema-validated output.** The R31.18 schema rejects unknown fields
  (`extra="forbid"`), fixes `rule_version` to `r31-18`, forces
  `research_only=True`, bounds every list/string and sanitizes all five
  embedded snapshots (reusing the R31.14/R31.15/R31.16/R31.17 sanitizers).
- **Plan-only and additive.** No field, code path or dependency can execute
  research or collect evidence; new backend keys only.

## 4. Closed Vocabularies

- `outcome`: `COMPLETED`, `IN_PROGRESS`, `WAITING_FOR_EVIDENCE`, `DEFERRED`,
  `UNKNOWN`.
- `outcome_category`: `EVIDENCE_ACCEPTED`, `RESEARCH_CONTINUING`,
  `MORE_EVIDENCE_REQUIRED`, `RESEARCH_PAUSED`, `INVALID_STATE`.
- `completion_state`: `COMPLETE`, `PARTIAL`, `INCOMPLETE`, `NONE`, `UNKNOWN`.
- `remaining_need`: `NONE`, `IDENTITY`, `VERSION`, `SCOPE`, `PATH`,
  `PARAMETER`, `HTTP_BEHAVIOR`, `TECHNOLOGY`, `HUMAN_RESEARCH`, `UNKNOWN`.
- `blockers[]`: imported closed R31.15 blocker vocabulary.

Bounds: `MAX_BLOCKERS = 8`, `MAX_ITEMS = 8`, `MAX_VALUE_LEN = 160`. All five
source snapshots use fixed key sets and are redacted (`_safe_text`).

## 5. Deterministic Outcome Mapping

| R31.17 lifecycle_state | outcome | outcome_category | completion_state | remaining_need |
|---|---|---|---|---|
| `COMPLETED` | `COMPLETED` | `EVIDENCE_ACCEPTED` | `COMPLETE` | `NONE` |
| `RESEARCH_ACTIVE` | `IN_PROGRESS` | `RESEARCH_CONTINUING` | `PARTIAL` | from R31.15 limiting factor |
| `WAITING_FOR_EVIDENCE` | `WAITING_FOR_EVIDENCE` | `MORE_EVIDENCE_REQUIRED` | `INCOMPLETE` | from R31.15 limiting factor |
| `DEFERRED` | `DEFERRED` | `RESEARCH_PAUSED` | `NONE` | from R31.15 limiting factor |
| missing / reserved / unexpected | `UNKNOWN` | `INVALID_STATE` | `UNKNOWN` | `UNKNOWN` |

Limiting-factor → remaining-need mapping: `NONE`→`NONE`,
`COMPONENT_IDENTITY`→`IDENTITY`, `VERSION`→`VERSION`, `SCOPE`→`SCOPE`,
`PATH`→`PATH`, `PARAMETER`→`PARAMETER`, `HTTP_BEHAVIOR`→`HTTP_BEHAVIOR`,
`TECHNOLOGY`→`TECHNOLOGY`, `HUMAN_RESEARCH`→`HUMAN_RESEARCH`,
`UPSTREAM_PLAN`→`UNKNOWN` (and any invalid value → `UNKNOWN`). In the normal
deferred path the limiting factor is `UPSTREAM_PLAN`, so `DEFERRED` reports
`remaining_need = UNKNOWN`.

## 6. Output Shape

```json
{
  "rule_version": "r31-18",
  "outcome": "IN_PROGRESS",
  "outcome_category": "RESEARCH_CONTINUING",
  "completion_state": "PARTIAL",
  "remaining_need": "VERSION",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
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
./venv/bin/python -m unittest tests.test_evidence_research_outcome_tracker -v
./venv/bin/python -m unittest tests.test_evidence_research_outcome_tracker \
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
./venv/bin/python -m py_compile ai/schemas/evidence_research_outcome.py \
    ai/knowledge/evidence_research_outcome_tracker.py \
    backend/asset_cve_matching.py \
    tests/test_evidence_research_outcome_tracker.py
git diff --check
```

Results:

```
tests.test_evidence_research_outcome_tracker    Ran 48 tests   OK  (new)
combined R31.10-R31.18 + R29/R30/R31 regression Ran 945 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)         Ran 2527 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2479-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.18
py_compile                                      OK
git diff --check                                clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndMutation.test_1_repeated_output_is_byte_identical`, `...test_1_key_insertion_order_does_not_matter`, `...test_1_stable_outcomes_across_all_methods` |
| 2 | COMPLETED outcome | `TestOutcomes.test_2_completed_outcome`, `...test_2_completed_via_real_engine_chain` |
| 3 | IN_PROGRESS outcome | `...test_3_in_progress_outcome`, `...test_3_in_progress_via_real_engine_chain` |
| 4 | WAITING_FOR_EVIDENCE outcome | `...test_4_waiting_for_evidence_outcome`, `...test_4_waiting_via_real_engine_chain` |
| 5 | DEFERRED outcome | `...test_5_deferred_outcome`, `...test_5_deferred_via_real_engine_chain` |
| 6 | UNKNOWN handling | `TestUnknownAndMalformed` (5 tests: unknown lifecycle, forged loop, missing inputs, reserved states, lowercase normalization) |
| 7 | remaining_need mapping | `TestRemainingNeedMapping` (4 tests: all ten limiting factors, invalid factor, completed forces NONE, closed table) |
| 8 | no input mutation | `TestDeterminismAndMutation.test_8_*` (3 tests, including snapshot aliasing) |
| 9 | closed vocabulary validation | `TestClosedVocabulary` (12 tests: output sets + pydantic rejection paths, fixed rule version, bounded blockers, blocker flow/filtering, closed tables) |
| 10 | JSON serialization | `TestOutputShape.test_10_json_serializable` |
| 11 | research_only always true | `TestOutputShape.test_11_research_only_always_true` |
| 12 | no operational attack content | `TestOutputShape.test_12_no_operational_attack_content`, `...test_12_source_snapshots_are_sanitized`, `...test_12_source_snapshots_are_bounded` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions (r31-10..r31-18), immediate plan
yields `COMPLETED`/`EVIDENCE_ACCEPTED`/`COMPLETE`/`NONE` while `hunt_priority`
stays P0/96, blocked plan yields
`DEFERRED`/`RESEARCH_PAUSED`/`NONE`, no existing field overwritten, Money
Score canary. The R29 projection contains no outcome field; R31.13-R31.17
plans are unchanged by the tracker.

## 8. Baseline Regression Comparison

- Baseline (before R31.18): `unittest discover` ran **2479 tests / 37
  failures / 3 errors**. After R31.18: **2527 tests / 37 failures / 3 errors**
  (+48 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.18.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13-R31.17 outputs are deep-copy equal after tracking.

## 9. Performance

```
1 candidate     ->   0.51 ms  (505.6 us/candidate, fixed overhead)
100 candidates  ->  25.28 ms  (252.8 us/candidate)
1000 candidates -> 186.01 ms  (186.0 us/candidate)
```

Cost is O(bounded snapshots + one pydantic model construction with nested
validation); no corpus, URL, endpoint, HTTP or Mongo access occurs at this
layer. The module is pure and stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- `remaining_need` is derived from the R31.15 limiting factor for every
  non-complete outcome, including `DEFERRED`; the normal deferred path reports
  `UNKNOWN` because its limiting factor is `UPSTREAM_PLAN`.
- The tracker is a pure projection of the R31.17 lifecycle state; it does not
  persist history, track multiple cycles, or compare outcomes across runs.
- `blockers[]` merges the R31.17, R31.16 and R31.15 closed blocker sets; it is
  explanatory only and never changes the outcome.
- Wiring the outcome plan into the R29 queue schema/projection or UI is out of
  scope: R29 must not be modified by this stage.
- The outcome plan is advisory and is never executed. No HTTP request,
  browser action, Nuclei run, crawl, fuzzing, scan, exploitation, LLM call,
  Mongo access or target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.18
- Role: coding agent

# R31.14 Evidence Prioritization Planner

Local WSL implementation. Plan-only stage: no acquisition, HTTP, crawl, scan,
Nuclei, fuzz, browser automation, exploit validation, Mongo access or LLM call
is executed. No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Prioritization Planner that converts one R31.13
Evidence Acquisition Plan into a prioritized evidence roadmap, answering:

    "Of the evidence this candidate still needs, which piece should I
     prioritize, why, what uncertainty does it reduce, how dependent is it
     on earlier evidence, and how important is completing it?"

The planner decides **priority order only**. It never recalculates R31.12
gaps, never re-derives an acquisition method, never inspects CVE data, never
modifies the Money Score or the R29 hunt queue, and never changes any previous
planner's semantics. Terminal R31.13 plans (`NONE` acquisition) produce an
empty priority list.

## 2. Files Changed

- `ai/schemas/evidence_prioritization.py` — **new** pydantic schema module
  (387 lines): `EvidencePriorityItem`, `EvidencePrioritizationPlan`, closed
  R31.14 vocabularies, bounds and privacy sanitization.
- `ai/knowledge/evidence_prioritization_planner.py` — **new** pure module
  (282 lines, `r31-14`): deterministic method→priority mapping table and
  `plan_evidence_prioritization()`.
- `backend/asset_cve_matching.py` — **modified additively** (+17/-0):
  `summary["evidence_prioritization_plan"]` and
  `summary["evidence_prioritization_plan_rule_version"]` attached after the
  R31.13 block. No existing field renamed, removed or changed.
- `tests/test_evidence_prioritization_planner.py` — **new** focused suite
  (44 tests, 973 lines).
- `agent-reports/stage-r31-14-evidence-prioritization-planner.md` — this
  report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced. No systemd/VM file was
touched.

## 3. Architecture Decisions

- **Consume R31.13 only.** The planner takes one R31.13 result dict and reads
  exactly `acquisition_method` and `evidence_target` (plus a bounded,
  sanitized snapshot for traceability). It never calls the R31.10/R31.11/
  R31.12/R31.13 engines and never re-derives a gap.
- **Schema-validated output.** R31.14 is the first planner with an explicit
  pydantic schema (per the stage request). The schema owns the R31.14-specific
  closed vocabularies and bounds; the R31.13 method/target vocabularies remain
  owned by R31.13 and are imported by the planner, so the two cannot drift.
  Unknown fields are rejected (`extra="forbid"`), `rule_version` is fixed to
  `r31-14` and `research_only` is forced `True`.
- **One prioritized item.** R31.13 selects exactly one acquisition method for
  the R31.12-selected gap, so the roadmap contains exactly one item (or none
  for terminal plans). Nothing downstream is invented; the `items[]` shape
  keeps the schema forward-compatible.
- **Defensive handling, never reinterpretation.** A missing plan, a `NONE`
  method, an unknown method, or a method whose `evidence_target` does not
  match the R31.13 method→target pair yields an empty priority list. Upstream
  data is never silently rewritten into a priority item.
- **Plan-only.** No field, code path or dependency can acquire evidence. The
  output contains only closed codes, a bounded snapshot and a boolean.
- **Additive integration.** New backend keys only; all R29/R30/R31 fields are
  passed through untouched.

## 4. Closed Vocabularies

- `evidence_target` / `acquisition_method`: the R31.13 closed vocabularies
  (imported constants), never redefined.
- `priority_reason` (`PRIORITY_REASONS`): `PRIORITY_EXISTING_EVIDENCE`,
  `PRIORITY_IDENTITY`, `PRIORITY_VERSION`, `PRIORITY_SCOPE`, `PRIORITY_PATH`,
  `PRIORITY_PARAMETER`, `PRIORITY_HTTP_BEHAVIOR`, `PRIORITY_TECHNOLOGY`,
  `PRIORITY_MANUAL_RESEARCH`.
- `uncertainty_category` (`UNCERTAINTY_CATEGORIES`):
  `EXISTING_EVIDENCE_UNCERTAINTY`, `IDENTITY_UNCERTAINTY`,
  `VERSION_UNCERTAINTY`, `SCOPE_UNCERTAINTY`, `PATH_UNCERTAINTY`,
  `PARAMETER_UNCERTAINTY`, `HTTP_BEHAVIOR_UNCERTAINTY`,
  `TECHNOLOGY_UNCERTAINTY`, `HUMAN_JUDGEMENT_UNCERTAINTY`.
- `dependency_level` (`DEPENDENCY_LEVELS`): `0` independent, `1` one upstream
  layer, `2` two upstream layers, `3` behavioral (requires path/parameter
  context).
- `completion_importance` (`COMPLETION_IMPORTANCE_LEVELS`): `CRITICAL`,
  `HIGH`, `MEDIUM`, `LOW`.
- `priority_rank`: bounded integer `1..8`.

`source_acquisition_plan` is a fixed-key (`SOURCE_PLAN_KEYS`) bounded, redacted
snapshot of the R31.13 plan; unknown upstream keys are dropped. Bounds:
`MAX_ITEMS = 8`, `MAX_REASON_CODES = 8`, `MAX_VALUE_LEN = 160`.

## 5. Deterministic Priority Mapping

| R31.13 method | Rank | Priority reason | Uncertainty | Dependency | Completion importance |
|---|---|---|---|---|---|
| `EXISTING_EVIDENCE_REVIEW` | 1 | `PRIORITY_EXISTING_EVIDENCE` | `EXISTING_EVIDENCE_UNCERTAINTY` | 0 | HIGH |
| `COMPONENT_IDENTITY_LOOKUP` | 2 | `PRIORITY_IDENTITY` | `IDENTITY_UNCERTAINTY` | 0 | CRITICAL |
| `VERSION_LOOKUP` | 3 | `PRIORITY_VERSION` | `VERSION_UNCERTAINTY` | 1 | CRITICAL |
| `SCOPE_EVIDENCE_REVIEW` | 4 | `PRIORITY_SCOPE` | `SCOPE_UNCERTAINTY` | 1 | HIGH |
| `PATH_EVIDENCE_REVIEW` | 5 | `PRIORITY_PATH` | `PATH_UNCERTAINTY` | 2 | MEDIUM |
| `PARAMETER_EVIDENCE_REVIEW` | 5 | `PRIORITY_PARAMETER` | `PARAMETER_UNCERTAINTY` | 2 | MEDIUM |
| `HTTP_BEHAVIOR_REVIEW` | 6 | `PRIORITY_HTTP_BEHAVIOR` | `HTTP_BEHAVIOR_UNCERTAINTY` | 3 | MEDIUM |
| `TECHNOLOGY_EVIDENCE_REVIEW` | 7 | `PRIORITY_TECHNOLOGY` | `TECHNOLOGY_UNCERTAINTY` | 2 | LOW |
| `MANUAL_RESEARCH` | 8 | `PRIORITY_MANUAL_RESEARCH` | `HUMAN_JUDGEMENT_UNCERTAINTY` | 0 | HIGH |
| `NONE` / missing / unknown / mismatched | — | (empty list) | — | — | — |

The tier order follows the stage request exactly. `PRIORITY_ORDER` fixes a
stable tie-break sequence (path before parameter) for any future multi-item
plan. Ranks are non-decreasing along `PRIORITY_ORDER`; identical input always
produces byte-identical output.

## 6. Output Shape

```json
{
  "rule_version": "r31-14",
  "items": [
    {
      "evidence_target": "VERSION",
      "acquisition_method": "VERSION_LOOKUP",
      "priority_rank": 3,
      "priority_reason": "PRIORITY_VERSION",
      "uncertainty_category": "VERSION_UNCERTAINTY",
      "dependency_level": 1,
      "completion_importance": "CRITICAL"
    }
  ],
  "source_acquisition_plan": { "...bounded R31.13 snapshot..." },
  "research_only": true
}
```

## 7. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_evidence_prioritization_planner -v
./venv/bin/python -m unittest tests.test_evidence_prioritization_planner \
    tests.test_evidence_acquisition_planner tests.test_hunt_action_planner \
    tests.test_hunt_actionability tests.test_hunt_priority \
    tests.test_evidence_quality tests.test_path_parameter_relevance \
    tests.test_version_normalization tests.test_component_evidence_provenance \
    tests.test_component_identity tests.test_component_inference \
    tests.test_component_plugin_wiring tests.test_observed_inventory \
    tests.test_asset_cve_matching tests.test_version_component_association \
    tests.test_hunt_queue -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/schemas/evidence_prioritization.py \
    ai/knowledge/evidence_prioritization_planner.py \
    backend/asset_cve_matching.py \
    tests/test_evidence_prioritization_planner.py
git diff --check
```

Results:

```
tests.test_evidence_prioritization_planner      Ran 44 tests   OK  (new)
combined R31.10-R31.14 + R29/R30/R31 regression Ran 752 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)         Ran 2334 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2290-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.14
py_compile                                      OK
git diff --check                                clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndOrdering.test_1_repeated_output_is_byte_identical`, `...test_1_repeated_call_after_mutation_of_copy` |
| 2 | stable ordering | `...test_2_priority_order_is_documented_sequence`, `...test_2_ranks_are_non_decreasing_along_priority_order`, `...test_2_single_item_rank_matches_mapping`, `...test_2_item_ordering_is_stable_across_calls` |
| 3 | terminal NONE handling | `TestTerminalHandling` (7 tests: NONE, blocked, deferred, missing, unknown, target mismatch, NONE target) |
| 4 | every R31.13 method mapping | `TestMethodMapping` (3 tests, includes real R31.10→R31.14 engine chains for all 9 non-NONE methods) |
| 5 | no mutation of input plan | `TestNoMutation` (3 tests, including snapshot aliasing) |
| 6 | closed vocabulary validation | `TestClosedVocabulary` (11 tests: planner output + pydantic rejection paths, fixed rule version, bounded items, unknown-key dropping) |
| 7 | JSON serializable output | `TestOutputShape.test_7_json_serializable` |
| 8 | research_only always true | `TestOutputShape.test_8_research_only_always_true` |
| 9 | no operational attack content | `TestOutputShape.test_9_no_operational_attack_content`, `...test_9_source_fields_are_sanitized`, `...test_9_bounded_source_snapshot` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions, immediate-plan prioritization
(`PRIORITY_EXISTING_EVIDENCE`, rank 1) with `hunt_priority` still P0/96,
blocked-plan empty prioritization, no existing field overwritten, Money Score
canary. R29 projection contains no R31.14 field; R31.13 rule version and plan
are unchanged by prioritization.

## 8. Baseline Regression Comparison

- Baseline (before R31.14): `unittest discover` ran **2290 tests / 37
  failures / 3 errors**. After R31.14: **2334 tests / 37 failures / 3 errors**
  (+44 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.14.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13 rule version (`r31-13`) and equation outputs are untouched; the R31.13
  plan dict is deep-copy equal after prioritization.

## 9. Performance

```
1 candidate     ->  0.19 ms  (192.6 us/candidate, fixed overhead)
100 candidates  ->  6.07 ms  (60.7 us/candidate)
1000 candidates -> 67.12 ms  (67.1 us/candidate)
```

Cost is O(bounded snapshot + one pydantic model construction); no corpus, URL,
endpoint, HTTP or Mongo access occurs at this layer. The module is pure and
stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- The roadmap contains at most one item because R31.13 selects one acquisition
  method per candidate. `items[]`, `PRIORITY_ORDER` and `METHOD_PRIORITY`
  already encode the deterministic multi-item ordering should a future stage
  supply multiple acquisition steps.
- The `dependency_level` ladder (0–3) is a deterministic classification of how
  many earlier evidence layers the selected method depends on. It is not a
  scheduling engine and does not fetch or check prerequisites.
- Wiring the prioritization plan into the R29 queue schema/projection or UI is
  deliberately out of scope: R29 must not be modified by this stage.
- The plan is advisory and is never executed. No HTTP request, browser action,
  Nuclei run, crawl, fuzzing, scan, exploitation, LLM call, Mongo access or
  target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.14
- Role: coding agent

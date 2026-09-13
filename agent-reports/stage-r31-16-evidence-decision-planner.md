# R31.16 Evidence Decision Planner

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Decision Planner that converts the R31.13
Evidence Acquisition Plan, R31.14 Evidence Prioritization Plan and R31.15
Evidence Confidence Plan into a final research decision state, answering:

- Is the current evidence sufficient?
- Should research continue?
- Is more evidence planning required?
- Should this candidate be deferred?

The planner decides the next research state only. It never executes an
action, never recalculates confidence/priority/acquisition, never recomputes
R31.12 gaps, never inspects CVE data, never calculates the Money Score and
never modifies the R29 queue or any previous planner semantics.

## 2. Files Changed

- `ai/schemas/evidence_decision.py` — **new** pydantic schema module (354
  lines): `EvidenceDecisionPlan`, closed decision/reason/next-state
  vocabularies, imported confidence/limiting/blocker vocabularies, bounds and
  sanitization for all three embedded source-plan snapshots.
- `ai/knowledge/evidence_decision_planner.py` — **new** pure module (416
  lines, `r31-16`): deterministic decision rules and
  `plan_evidence_decision()`.
- `backend/asset_cve_matching.py` — **modified additively** (+16/-0):
  `summary["evidence_decision_plan"]` and
  `summary["evidence_decision_plan_rule_version"]` attached after the R31.15
  block. No existing field renamed, removed or changed.
- `tests/test_evidence_decision_planner.py` — **new** focused suite (54 tests,
  1185 lines).
- `agent-reports/stage-r31-16-evidence-decision-planner.md` — this report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced.

## 3. Architecture Decisions

- **Consume R31.13/R31.14/R31.15 only.** The planner reads the acquisition
  method/target, the prioritization items and the confidence level/category/
  limiting factor/blockers. It never calls an upstream engine and never
  recalculates confidence, priority or acquisition.
- **Reuse, don't duplicate, authority.** The method→target pairing is read
  from the R31.14 `METHOD_PRIORITY` table (which mirrors R31.13); the
  confidence level/category/limiting/blocker vocabularies are imported from
  the R31.15 schema. The R31.15 rows are also consumed by the R31.15
  aggregator, so no rule is re-implemented.
- **Terminal-first.** A terminal `NONE` acquisition maps to
  `DEFER_RESEARCH` / `DEFERRED` before any confidence interpretation, so a
  forged `HIGH` confidence cannot bypass a terminal defer. Method/target
  mismatches and unknown/missing methods yield `UNKNOWN`.
- **Acceptance is doubly gated.** `ACCEPT_EVIDENCE` / `COMPLETE` /
  `EVIDENCE_SUFFICIENT` requires both R31.15 `HIGH` *and*
  `SUFFICIENT_EVIDENCE`. `HIGH` with any other category is treated as an
  internally inconsistent upstream reading and yields `UNKNOWN`; it is never
  accepted.
- **Evidence-path guard.** `CONTINUE_RESEARCH` (MEDIUM) and
  `REQUIRE_MORE_EVIDENCE` (LOW) additionally require at least one R31.14
  prioritized evidence item; otherwise the decision is `UNKNOWN` with
  `MISSING_PRIORITIZATION_ITEM`. In the normal pipeline R31.14 always emits
  the aligned item, so this guard only fires on malformed/forged input.
- **Schema-validated output.** The R31.16 schema rejects unknown fields
  (`extra="forbid"`), fixes `rule_version` to `r31-16`, forces
  `research_only=True`, bounds every list/string and sanitizes all three
  embedded snapshots (reusing the R31.14/R31.15 sanitizers for the
  acquisition/priority plans).
- **Plan-only and additive.** No field, code path or dependency can execute
  an action; new backend keys only.

## 4. Closed Vocabularies

- `decision`: `ACCEPT_EVIDENCE`, `CONTINUE_RESEARCH`,
  `REQUIRE_MORE_EVIDENCE`, `DEFER_RESEARCH`, `UNKNOWN`.
- `next_state`: `COMPLETE`, `ACTIVE_RESEARCH`, `WAITING_FOR_EVIDENCE`,
  `DEFERRED`, `UNKNOWN`.
- `decision_reason`: `EVIDENCE_SUFFICIENT`, `HIGH_CONFIDENCE`,
  `MISSING_IDENTITY`, `MISSING_VERSION`, `MISSING_SCOPE`, `MISSING_PATH`,
  `MISSING_PARAMETER`, `MISSING_HTTP_BEHAVIOR`, `MISSING_TECHNOLOGY`,
  `HUMAN_RESEARCH_REQUIRED`, `NO_PLAN_AVAILABLE`.
- `confidence_level` / `required_evidence` / `blockers[]`: imported closed
  R31.15 vocabularies (`required_evidence` uses the R31.15 limiting-factor
  set; blockers use the R31.15 blocker set).

Bounds: `MAX_BLOCKERS = 8`, `MAX_ITEMS = 8`, `MAX_VALUE_LEN = 160`. All three
source snapshots use fixed key sets and are redacted (`_safe_text`).

`HIGH_CONFIDENCE` is a legal closed reason value reserved for a future accept
variant; the current deterministic accept path emits `EVIDENCE_SUFFICIENT`
(the R31.15 category gate). No rule ever emits an out-of-vocabulary reason.

## 5. Deterministic Decision Rules

Evaluation order (first match wins):

1. Acquisition method missing → `UNKNOWN` / `NO_PLAN_AVAILABLE` / `UNKNOWN`
   (`MALFORMED_ACQUISITION_PLAN`).
2. Acquisition method unknown → `UNKNOWN` / `NO_PLAN_AVAILABLE` / `UNKNOWN`
   (`UNKNOWN_ACQUISITION_METHOD`).
3. Method/target mismatch → `UNKNOWN` / `NO_PLAN_AVAILABLE` / `UNKNOWN`
   (`MALFORMED_ACQUISITION_PLAN`).
4. Terminal `NONE` → `DEFER_RESEARCH` / `NO_PLAN_AVAILABLE` / `DEFERRED`
   (`NO_ACQUISITION_PLANNED`).
5. Missing/invalid confidence level or category → `UNKNOWN` /
   `NO_PLAN_AVAILABLE` / `UNKNOWN`.
6. R31.15 `HIGH` + `SUFFICIENT_EVIDENCE` → `ACCEPT_EVIDENCE` /
   `EVIDENCE_SUFFICIENT` / `COMPLETE`, `required_evidence = NONE`.
7. R31.15 `HIGH` + other category → `UNKNOWN` (never accepted).
8. R31.15 `MEDIUM` + ≥1 prioritized item → `CONTINUE_RESEARCH` /
   `ACTIVE_RESEARCH` / category-derived reason, `required_evidence` = limiting
   factor.
9. R31.15 `MEDIUM` + no prioritized item → `UNKNOWN`
   (`MISSING_PRIORITIZATION_ITEM`).
10. R31.15 `LOW` + ≥1 prioritized item → `REQUIRE_MORE_EVIDENCE` /
    `WAITING_FOR_EVIDENCE` / category-derived reason.
11. R31.15 `LOW` + no prioritized item → `UNKNOWN`
    (`MISSING_PRIORITIZATION_ITEM`).
12. R31.15 `UNKNOWN` (or any unrecognized state) → `UNKNOWN` /
    `NO_PLAN_AVAILABLE` / `UNKNOWN`.

Category → reason mapping (rule 7 of the required tests): `SUFFICIENT_EVIDENCE`
→ `EVIDENCE_SUFFICIENT`; `IDENTITY_LIMITED` → `MISSING_IDENTITY`;
`VERSION_LIMITED` → `MISSING_VERSION`; `SCOPE_LIMITED` → `MISSING_SCOPE`;
`PATH_LIMITED` → `MISSING_PATH`; `PARAMETER_LIMITED` → `MISSING_PARAMETER`;
`BEHAVIOR_LIMITED` → `MISSING_HTTP_BEHAVIOR`; `TECHNOLOGY_LIMITED` →
`MISSING_TECHNOLOGY`; `RESEARCH_INCOMPLETE` → `HUMAN_RESEARCH_REQUIRED` when
the method is `MANUAL_RESEARCH`, otherwise `NO_PLAN_AVAILABLE`.

## 6. Output Shape

```json
{
  "rule_version": "r31-16",
  "decision": "CONTINUE_RESEARCH",
  "decision_reason": "MISSING_VERSION",
  "confidence_level": "MEDIUM",
  "next_state": "ACTIVE_RESEARCH",
  "required_evidence": "VERSION",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "source_confidence_plan": { "...bounded R31.15 snapshot..." },
  "source_priority_plan": { "...bounded R31.14 snapshot..." },
  "source_acquisition_plan": { "...bounded R31.13 snapshot..." },
  "research_only": true
}
```

## 7. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_evidence_decision_planner -v
./venv/bin/python -m unittest tests.test_evidence_decision_planner \
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
./venv/bin/python -m py_compile ai/schemas/evidence_decision.py \
    ai/knowledge/evidence_decision_planner.py \
    backend/asset_cve_matching.py tests/test_evidence_decision_planner.py
git diff --check
```

Results:

```
tests.test_evidence_decision_planner            Ran 54 tests   OK  (new)
combined R31.10-R31.16 + R29/R30/R31 regression Ran 852 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)         Ran 2434 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2380-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.16
py_compile                                      OK
git diff --check                                clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndMutation.test_1_repeated_output_is_byte_identical`, `...test_1_key_insertion_order_does_not_matter`, `...test_1_stable_decisions_across_all_methods` |
| 2 | ACCEPT_EVIDENCE path | `TestDecisionPaths.test_2_accept_evidence_path`, `...test_2_accept_via_real_engine_chain` |
| 3 | CONTINUE_RESEARCH path | `...test_3_continue_research_path`, `...test_3_continue_via_real_engine_chain` |
| 4 | REQUIRE_MORE_EVIDENCE path | `...test_4_require_more_evidence_path`, `...test_4_require_more_evidence_manual_research`, `...test_4_require_via_real_engine_chain` |
| 5 | DEFER_RESEARCH path | `...test_5_defer_research_path`, `...test_5_defer_via_real_engine_chain`, `...test_5_none_acquisition_beats_forged_high_confidence` |
| 6 | malformed inputs | `TestMalformedInputs` (10 tests: missing all, unknown method, mismatch, missing confidence, invalid level/category, inconsistent HIGH, medium/low without item, RESEARCH_INCOMPLETE without manual) |
| 7 | all blocker mappings | `TestBlockerMappings` (4 tests: all nine category→reason mappings, all 13 confidence blockers flow through, unknown blockers dropped, closed reason set) |
| 8 | no input mutation | `TestDeterminismAndMutation.test_8_*` (3 tests, including snapshot aliasing) |
| 9 | closed vocabulary validation | `TestClosedVocabulary` (12 tests: output sets + pydantic rejection paths, fixed rule version, bounded blockers) |
| 10 | JSON serialization | `TestOutputShape.test_10_json_serializable` |
| 11 | research_only always true | `TestOutputShape.test_11_research_only_always_true` |
| 12 | no operational attack content | `TestOutputShape.test_12_no_operational_attack_content`, `...test_12_source_snapshots_are_sanitized`, `...test_12_source_snapshots_are_bounded` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions (r31-10..r31-16), immediate plan
yields `ACCEPT_EVIDENCE`/`COMPLETE` with `required_evidence = NONE` while
`hunt_priority` stays P0/96, blocked plan yields
`DEFER_RESEARCH`/`DEFERRED`, no existing field overwritten, Money Score
canary. The R29 projection contains no decision field; R31.13-R31.15 plans
are unchanged by the decision.

## 8. Baseline Regression Comparison

- Baseline (before R31.16): `unittest discover` ran **2380 tests / 37
  failures / 3 errors**. After R31.16: **2434 tests / 37 failures / 3 errors**
  (+54 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.16.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13/R31.14/R31.15 outputs are deep-copy equal after the decision.

## 9. Performance

```
1 candidate     ->   0.14 ms  (144.4 us/candidate, fixed overhead)
100 candidates  ->  15.78 ms  (157.8 us/candidate)
1000 candidates -> 130.85 ms  (130.8 us/candidate)
```

Cost is O(bounded snapshots + one pydantic model construction with nested
validation); no corpus, URL, endpoint, HTTP or Mongo access occurs at this
layer. The module is pure and stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- `HIGH_CONFIDENCE` is part of the closed `decision_reason` vocabulary but the
  current deterministic accept path emits `EVIDENCE_SUFFICIENT`. A future
  stage may define an accept variant that uses it without changing the
  current rules.
- `CONTINUE_RESEARCH`/`REQUIRE_MORE_EVIDENCE` require an R31.14 prioritized
  item. A valid R31.15 confidence plan paired with a missing/empty
  prioritization plan therefore yields `UNKNOWN`; this is deliberate
  (evidence path required) and documented.
- `required_evidence` reuses the R31.15 limiting-factor vocabulary; it is a
  dimension label, not a new gap, and never overrides R31.13's
  `evidence_gap`.
- Wiring the decision plan into the R29 queue schema/projection or UI is out
  of scope: R29 must not be modified by this stage.
- The decision is advisory and is never executed. No HTTP request, browser
  action, Nuclei run, crawl, fuzzing, scan, exploitation, LLM call, Mongo
  access or target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.16
- Role: coding agent

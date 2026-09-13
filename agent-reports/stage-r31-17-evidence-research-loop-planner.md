# R31.17 Evidence Research Loop Planner

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Research Loop Planner that converts the
current R31.16 evidence decision state into the next research lifecycle
state, answering:

- What is the current research lifecycle state?
- Should the loop continue?
- What is the next allowed planning phase?
- Why is this transition valid?

The planner defines the loop state only. It never executes research, never
recomputes acquisition/priority/confidence/decision, never inspects CVE data,
never calculates the Money Score and never modifies the R29 queue or any
previous planner semantics.

## 2. Files Changed

- `ai/schemas/evidence_research_loop.py` — **new** pydantic schema module (347
  lines): `EvidenceResearchLoopPlan`, closed lifecycle/phase/reason
  vocabularies, imported decision/confidence/blocker vocabularies, bounds and
  sanitization for all four embedded source-plan snapshots.
- `ai/knowledge/evidence_research_loop_planner.py` — **new** pure module (246
  lines, `r31-17`): deterministic decision→transition table and
  `plan_evidence_research_loop()`.
- `backend/asset_cve_matching.py` — **modified additively** (+18/-0):
  `summary["evidence_research_loop_plan"]` and
  `summary["evidence_research_loop_plan_rule_version"]` attached after the
  R31.16 block. No existing field renamed, removed or changed.
- `tests/test_evidence_research_loop_planner.py` — **new** focused suite (45
  tests, 1079 lines).
- `agent-reports/stage-r31-17-evidence-research-loop-planner.md` — this
  report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced.

## 3. Architecture Decisions

- **Consume R31.13-R31.16 only.** The planner reads the R31.16 `decision` (and
  the passed-through confidence/blockers) and embeds bounded snapshots of the
  R31.13/R31.14/R31.15/R31.16 plans. It never calls an upstream engine and
  never recomputes acquisition, priority, confidence or decision.
- **Single authoritative transition table.** `DECISION_TRANSITIONS` maps each
  accepted R31.16 decision to exactly one lifecycle state/phase/reason triple.
  `DECISION_LIFECYCLE_STATES` exposes the closed decision→state mapping for
  direct assertion.
- **Decision-only state machine.** A missing, unrecognized or `UNKNOWN`
  R31.16 decision yields the terminal `UNKNOWN` / `UNKNOWN` /
  `INVALID_INPUT` state; no lifecycle state is ever inferred from the
  upstream plans directly. A lowercase valid decision string is normalized
  (uppercased) deterministically.
- **Schema-validated output.** The R31.17 schema rejects unknown fields
  (`extra="forbid"`), fixes `rule_version` to `r31-17`, forces
  `research_only=True`, bounds every list/string and sanitizes all four
  embedded snapshots (reusing the R31.14/R31.15/R31.16 sanitizers).
- **Plan-only and additive.** No field, code path or dependency can execute
  research; new backend keys only.

## 4. Closed Vocabularies

- `lifecycle_state`: `INITIAL`, `RESEARCH_ACTIVE`, `EVIDENCE_READY`,
  `WAITING_FOR_EVIDENCE`, `COMPLETED`, `DEFERRED`, `UNKNOWN`.
- `next_phase`: `NONE`, `EVIDENCE_REVIEW`, `EVIDENCE_COLLECTION_PLANNING`,
  `DECISION_REVIEW`, `HUMAN_REVIEW`, `UNKNOWN`.
- `transition_reason`: `START_RESEARCH`,
  `CONTINUE_AFTER_MEDIUM_CONFIDENCE`, `NEED_MORE_EVIDENCE`,
  `EVIDENCE_ACCEPTED`, `RESEARCH_DEFERRED`, `INVALID_INPUT`.
- `decision` / `confidence_level` / `blockers[]`: imported closed
  R31.15/R31.16 vocabularies.

Bounds: `MAX_BLOCKERS = 8`, `MAX_ITEMS = 8`, `MAX_VALUE_LEN = 160`. All four
source snapshots use fixed key sets and are redacted (`_safe_text`).

`INITIAL`, `EVIDENCE_READY`, `EVIDENCE_REVIEW`, `DECISION_REVIEW`,
`HUMAN_REVIEW` and `START_RESEARCH` are legal closed values reserved for
future loop entry/exit transitions; the current deterministic table never
emits an out-of-vocabulary value.

## 5. Deterministic Lifecycle Transitions

| R31.16 decision | lifecycle_state | next_phase | transition_reason |
|---|---|---|---|
| `ACCEPT_EVIDENCE` | `COMPLETED` | `NONE` | `EVIDENCE_ACCEPTED` |
| `CONTINUE_RESEARCH` | `RESEARCH_ACTIVE` | `EVIDENCE_COLLECTION_PLANNING` | `CONTINUE_AFTER_MEDIUM_CONFIDENCE` |
| `REQUIRE_MORE_EVIDENCE` | `WAITING_FOR_EVIDENCE` | `EVIDENCE_COLLECTION_PLANNING` | `NEED_MORE_EVIDENCE` |
| `DEFER_RESEARCH` | `DEFERRED` | `NONE` | `RESEARCH_DEFERRED` |
| missing / unknown / `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `INVALID_INPUT` |

The output `decision` field mirrors the consumed R31.16 decision (or
`UNKNOWN` for malformed/unknown input). The output `confidence_level` uses
the R31.16 plan's valid level first, then the R31.15 plan's, else `UNKNOWN`.
`blockers[]` merges the R31.16 and R31.15 blocker lists, de-duplicated,
filtered to the closed R31.15 blocker vocabulary and bounded.

## 6. Output Shape

```json
{
  "rule_version": "r31-17",
  "lifecycle_state": "RESEARCH_ACTIVE",
  "next_phase": "EVIDENCE_COLLECTION_PLANNING",
  "transition_reason": "CONTINUE_AFTER_MEDIUM_CONFIDENCE",
  "decision": "CONTINUE_RESEARCH",
  "confidence_level": "MEDIUM",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "source_decision_plan": { "...bounded R31.16 snapshot..." },
  "source_confidence_plan": { "...bounded R31.15 snapshot..." },
  "source_priority_plan": { "...bounded R31.14 snapshot..." },
  "source_acquisition_plan": { "...bounded R31.13 snapshot..." },
  "research_only": true
}
```

## 7. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_evidence_research_loop_planner -v
./venv/bin/python -m unittest tests.test_evidence_research_loop_planner \
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
./venv/bin/python -m py_compile ai/schemas/evidence_research_loop.py \
    ai/knowledge/evidence_research_loop_planner.py \
    backend/asset_cve_matching.py tests/test_evidence_research_loop_planner.py
git diff --check
```

Results:

```
tests.test_evidence_research_loop_planner       Ran 45 tests   OK  (new)
combined R31.10-R31.17 + R29/R30/R31 regression Ran 897 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)         Ran 2479 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2434-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.17
py_compile                                      OK
git diff --check                                clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndMutation.test_1_repeated_output_is_byte_identical`, `...test_1_key_insertion_order_does_not_matter`, `...test_1_stable_transitions_across_all_methods` |
| 2 | ACCEPT_EVIDENCE transition | `TestTransitions.test_2_accept_evidence_completes_loop`, `...test_2_accept_via_real_engine_chain` |
| 3 | CONTINUE_RESEARCH transition | `...test_3_continue_research_activates_loop`, `...test_3_continue_via_real_engine_chain` |
| 4 | REQUIRE_MORE_EVIDENCE transition | `...test_4_require_more_evidence_waits`, `...test_4_require_via_real_engine_chain` |
| 5 | DEFER_RESEARCH transition | `...test_5_defer_research_defers_loop`, `...test_5_defer_via_real_engine_chain` |
| 6 | UNKNOWN handling | `TestUnknownAndMalformed.test_6_unknown_decision_yields_invalid_input`, `...test_6_unknown_decision_via_real_engine_chain` |
| 7 | malformed input handling | `...test_7_missing_inputs_yield_invalid_input`, `...test_7_unrecognized_decision_yields_invalid_input`, `...test_7_lowercase_decision_is_normalized` |
| 8 | no input mutation | `TestDeterminismAndMutation.test_8_*` (3 tests, including snapshot aliasing) |
| 9 | closed vocabulary validation | `TestClosedVocabulary` (12 tests: output sets + pydantic rejection paths, fixed rule version, bounded blockers, blocker flow/filtering, closed transition table) |
| 10 | JSON serialization | `TestOutputShape.test_10_json_serializable` |
| 11 | research_only always true | `TestOutputShape.test_11_research_only_always_true` |
| 12 | no operational attack content | `TestOutputShape.test_12_no_operational_attack_content`, `...test_12_source_snapshots_are_sanitized`, `...test_12_source_snapshots_are_bounded` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions (r31-10..r31-17), immediate plan
yields `COMPLETED`/`NONE`/`EVIDENCE_ACCEPTED` while `hunt_priority` stays
P0/96, blocked plan yields `DEFERRED`/`NONE`/`RESEARCH_DEFERRED`, no existing
field overwritten, Money Score canary. The R29 projection contains no loop
field; R31.13-R31.16 plans are unchanged by the loop.

## 8. Baseline Regression Comparison

- Baseline (before R31.17): `unittest discover` ran **2434 tests / 37
  failures / 3 errors**. After R31.17: **2479 tests / 37 failures / 3 errors**
  (+45 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.17.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13/R31.14/R31.15/R31.16 outputs are deep-copy equal after the loop.

## 9. Performance

```
1 candidate     ->   0.37 ms  (374.0 us/candidate, fixed overhead)
100 candidates  ->  15.40 ms  (154.0 us/candidate)
1000 candidates -> 160.87 ms  (160.9 us/candidate)
```

Cost is O(bounded snapshots + one pydantic model construction with nested
validation); no corpus, URL, endpoint, HTTP or Mongo access occurs at this
layer. The module is pure and stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- `INITIAL`, `EVIDENCE_READY`, `EVIDENCE_REVIEW`, `DECISION_REVIEW`,
  `HUMAN_REVIEW` and `START_RESEARCH` are legal closed values but are not
  emitted by the current decision-driven transition table. A future stage that
  introduces loop entry (no prior decision) or human-review exits can use them
  without changing the current rules.
- The loop state is a projection of the R31.16 decision, not an independent
  scheduler: it does not iterate, persist state across runs, or enqueue work.
- `blockers[]` merges the R31.16 and R31.15 closed blocker sets; it is
  explanatory only and never changes the transition.
- Wiring the loop plan into the R29 queue schema/projection or UI is out of
  scope: R29 must not be modified by this stage.
- The loop plan is advisory and is never executed. No HTTP request, browser
  action, Nuclei run, crawl, fuzzing, scan, exploitation, LLM call, Mongo
  access or target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.17
- Role: coding agent

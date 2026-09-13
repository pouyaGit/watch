# R31.15 Evidence Confidence Aggregator

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Build a deterministic Evidence Confidence Aggregator that converts one R31.13
Evidence Acquisition Plan and one R31.14 Evidence Prioritization Plan into a
confidence assessment for the current research candidate, answering:

- How confident are we that the current evidence is sufficient?
- What confidence level does the candidate currently have?
- What evidence dimension limits confidence?
- What prevents higher confidence?

The aggregator evaluates evidence readiness only. It never acquires evidence,
never recomputes R31.12 gaps, never inspects CVE data, never calculates the
Money Score and never modifies the R29 queue or any previous planner
semantics.

## 2. Files Changed

- `ai/schemas/evidence_confidence.py` — **new** pydantic schema module (402
  lines): `EvidenceConfidencePlan`, closed confidence/category/completeness/
  limiting/alignment/blocker vocabularies, bounds and privacy sanitization for
  both embedded source-plan snapshots.
- `ai/knowledge/evidence_confidence_aggregator.py` — **new** pure module (384
  lines, `r31-15`): deterministic per-method confidence mapping and
  `aggregate_evidence_confidence()`.
- `backend/asset_cve_matching.py` — **modified additively** (+17/-0):
  `summary["evidence_confidence_plan"]` and
  `summary["evidence_confidence_plan_rule_version"]` attached after the
  R31.14 block. No existing field renamed, removed or changed.
- `tests/test_evidence_confidence_aggregator.py` — **new** focused suite (46
  tests, 1181 lines).
- `agent-reports/stage-r31-15-evidence-confidence-aggregator.md` — this
  report.

No dependency was added (stdlib plus the project's existing pydantic). No
network/LLM/subprocess/Mongo call was introduced.

## 3. Architecture Decisions

- **Consume R31.13 + R31.14 only.** The aggregator reads the R31.13
  `acquisition_method`/`evidence_target` and the R31.14 `items`. It never
  calls any upstream engine and never re-derives a gap, method or rank.
- **Reuse, don't duplicate, authority.** The method→target/rank pairing is
  read from the R31.14 `METHOD_PRIORITY` table (which mirrors R31.13), so a
  malformed/unknown/mismatched acquisition plan is detected without a second
  copy of the rule. The schema reuses the R31.14 sanitizers (`sanitize_source_plan`,
  `EvidencePriorityItem`) for both embedded snapshots.
- **Schema-validated output.** The R31.15 schema owns the new closed
  vocabularies, rejects unknown fields (`extra="forbid"`), fixes
  `rule_version` to `r31-15`, forces `research_only=True` and bounds every
  list/string.
- **HIGH is doubly gated.** `HIGH` / `SUFFICIENT_EVIDENCE` / `COMPLETE`
  requires `EXISTING_EVIDENCE_REVIEW` **and** the aligned R31.14 rank-1
  priority item. Missing or misaligned prioritization degrades the existing
  review path to `UNKNOWN`; it is never silently upgraded.
- **MEDIUM/LOW are method-anchored.** A valid R31.13 method yields its
  documented level/category/completeness/limiting factor even when the R31.14
  plan is absent (`priority_alignment = NOT_APPLICABLE`). A present but
  misaligned/missing prioritization item sets `MISALIGNED` and adds a blocker
  without changing the method-anchored level.
- **Terminal/malformed = UNKNOWN.** `NONE`, missing/unknown methods and
  method/target mismatches all yield `UNKNOWN` / `RESEARCH_INCOMPLETE` /
  `NONE` completeness with closed blocker codes.
- **Plan-only and additive.** No field, code path or dependency can acquire
  evidence; new backend keys only.

## 4. Closed Vocabularies

- `confidence_level`: `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
- `confidence_category`: `SUFFICIENT_EVIDENCE`, `IDENTITY_LIMITED`,
  `VERSION_LIMITED`, `SCOPE_LIMITED`, `PATH_LIMITED`, `PARAMETER_LIMITED`,
  `BEHAVIOR_LIMITED`, `TECHNOLOGY_LIMITED`, `RESEARCH_INCOMPLETE`.
- `evidence_completeness`: `COMPLETE`, `PARTIAL`, `MINIMAL`, `NONE`.
- `limiting_factor`: `NONE`, `COMPONENT_IDENTITY`, `VERSION`, `SCOPE`, `PATH`,
  `PARAMETER`, `HTTP_BEHAVIOR`, `TECHNOLOGY`, `HUMAN_RESEARCH`,
  `UPSTREAM_PLAN`.
- `priority_alignment`: `ALIGNED`, `MISALIGNED`, `NOT_APPLICABLE`.
- `blockers[]` (13 closed codes): `IDENTITY_EVIDENCE_MISSING`,
  `VERSION_EVIDENCE_MISSING`, `SCOPE_EVIDENCE_MISSING`,
  `PATH_EVIDENCE_MISSING`, `PARAMETER_EVIDENCE_MISSING`,
  `HTTP_BEHAVIOR_EVIDENCE_MISSING`, `TECHNOLOGY_EVIDENCE_MISSING`,
  `HUMAN_RESEARCH_REQUIRED`, `NO_ACQUISITION_PLANNED`,
  `MALFORMED_ACQUISITION_PLAN`, `UNKNOWN_ACQUISITION_METHOD`,
  `MISSING_PRIORITIZATION_ITEM`, `PRIORITY_MISALIGNMENT`.

Bounds: `MAX_BLOCKERS = 8`, `MAX_ITEMS = 8`, `MAX_VALUE_LEN = 160`. Both
source snapshots use fixed key sets and are redacted (`_safe_text`).

## 5. Deterministic Confidence Mapping

| R31.13 method | Level | Category | Completeness | Limiting factor | Blocker |
|---|---|---|---|---|---|
| `EXISTING_EVIDENCE_REVIEW` + aligned rank 1 | HIGH | `SUFFICIENT_EVIDENCE` | COMPLETE | `NONE` | — |
| `COMPONENT_IDENTITY_LOOKUP` | MEDIUM | `IDENTITY_LIMITED` | PARTIAL | `COMPONENT_IDENTITY` | `IDENTITY_EVIDENCE_MISSING` |
| `VERSION_LOOKUP` | MEDIUM | `VERSION_LIMITED` | PARTIAL | `VERSION` | `VERSION_EVIDENCE_MISSING` |
| `SCOPE_EVIDENCE_REVIEW` | MEDIUM | `SCOPE_LIMITED` | PARTIAL | `SCOPE` | `SCOPE_EVIDENCE_MISSING` |
| `PATH_EVIDENCE_REVIEW` | LOW | `PATH_LIMITED` | MINIMAL | `PATH` | `PATH_EVIDENCE_MISSING` |
| `PARAMETER_EVIDENCE_REVIEW` | LOW | `PARAMETER_LIMITED` | MINIMAL | `PARAMETER` | `PARAMETER_EVIDENCE_MISSING` |
| `HTTP_BEHAVIOR_REVIEW` | LOW | `BEHAVIOR_LIMITED` | MINIMAL | `HTTP_BEHAVIOR` | `HTTP_BEHAVIOR_EVIDENCE_MISSING` |
| `TECHNOLOGY_EVIDENCE_REVIEW` | LOW | `TECHNOLOGY_LIMITED` | MINIMAL | `TECHNOLOGY` | `TECHNOLOGY_EVIDENCE_MISSING` |
| `MANUAL_RESEARCH` | LOW | `RESEARCH_INCOMPLETE` | MINIMAL | `HUMAN_RESEARCH` | `HUMAN_RESEARCH_REQUIRED` |
| `NONE` (terminal) | UNKNOWN | `RESEARCH_INCOMPLETE` | NONE | `UPSTREAM_PLAN` | `NO_ACQUISITION_PLANNED` |
| missing method | UNKNOWN | `RESEARCH_INCOMPLETE` | NONE | `UPSTREAM_PLAN` | `MALFORMED_ACQUISITION_PLAN` |
| unknown method | UNKNOWN | `RESEARCH_INCOMPLETE` | NONE | `UPSTREAM_PLAN` | `UNKNOWN_ACQUISITION_METHOD` |
| method/target mismatch | UNKNOWN | `RESEARCH_INCOMPLETE` | NONE | `UPSTREAM_PLAN` | `MALFORMED_ACQUISITION_PLAN` |
| `EXISTING_EVIDENCE_REVIEW` without aligned rank 1 | UNKNOWN | `RESEARCH_INCOMPLETE` | NONE | `UPSTREAM_PLAN` | `MISSING_PRIORITIZATION_ITEM` or `PRIORITY_MISALIGNMENT` |

`priority_alignment`: `ALIGNED` when the R31.14 plan contains an item with the
matching method/target and the documented rank; `MISALIGNED` when the
prioritization is present but the item is missing or ranked differently;
`NOT_APPLICABLE` for terminal/malformed inputs or when no R31.14 plan is
provided. Identical inputs always produce byte-identical output.

## 6. Output Shape

```json
{
  "rule_version": "r31-15",
  "confidence_level": "MEDIUM",
  "confidence_category": "VERSION_LIMITED",
  "limiting_factor": "VERSION",
  "evidence_completeness": "PARTIAL",
  "priority_alignment": "ALIGNED",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "source_acquisition_plan": { "...bounded R31.13 snapshot..." },
  "source_prioritization_plan": { "...bounded R31.14 snapshot..." },
  "research_only": true
}
```

## 7. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_evidence_confidence_aggregator -v
./venv/bin/python -m unittest tests.test_evidence_confidence_aggregator \
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
./venv/bin/python -m py_compile ai/schemas/evidence_confidence.py \
    ai/knowledge/evidence_confidence_aggregator.py \
    backend/asset_cve_matching.py \
    tests/test_evidence_confidence_aggregator.py
git diff --check
```

Results:

```
tests.test_evidence_confidence_aggregator       Ran 46 tests   OK  (new)
combined R31.10-R31.15 + R29/R30/R31 regression Ran 798 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue
complete project suite (discover tests)         Ran 2380 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2334-test baseline (40 sorted lines, diff clean); no new
    failure attributable to R31.15
py_compile                                      OK
git diff --check                                clean
```

Required coverage mapping:

| # | Required case | Test(s) |
|---|---|---|
| 1 | deterministic output | `TestDeterminismAndStability.test_1_repeated_output_is_byte_identical`, `...test_1_key_insertion_order_does_not_matter` |
| 2 | stable confidence result | `...test_2_stable_confidence_result`, `...test_2_high_requires_aligned_rank_one` |
| 3 | all acquisition method mappings | `TestMethodMappings` (3 tests, including real R31.10→R31.15 engine chains for all 10 methods) |
| 4 | terminal NONE handling | `TestTerminalNone` (3 tests: NONE, stale prioritization ignored, blocked chain) |
| 5 | malformed input handling | `TestMalformedInput` (10 tests: missing/unknown/mismatch, missing/wrong-rank/empty prioritization, malformed items) |
| 6 | no mutation of inputs | `TestNoMutation` (3 tests, including snapshot aliasing) |
| 7 | closed vocabulary validation | `TestClosedVocabulary` (11 tests: output sets + pydantic rejection paths, fixed rule version, bounded blockers) |
| 8 | JSON serialization | `TestOutputShape.test_8_json_serializable` |
| 9 | research_only always true | `TestOutputShape.test_9_research_only_always_true` |
| 10 | no operational attack content | `TestOutputShape.test_10_no_operational_attack_content`, `...test_10_source_snapshots_are_sanitized`, `...test_10_source_snapshots_are_bounded` |

Additional hermetic backend integration tests (mocked inventory/contexts, no
live Mongo): additive fields/rule versions, immediate plan yields HIGH /
`SUFFICIENT_EVIDENCE` / `ALIGNED` while `hunt_priority` stays P0/96, blocked
plan yields UNKNOWN / `NO_ACQUISITION_PLANNED`, no existing field overwritten,
Money Score canary. The R29 projection contains no confidence field; R31.13
and R31.14 rule versions and plans are unchanged by aggregation.

## 8. Baseline Regression Comparison

- Baseline (before R31.15): `unittest discover` ran **2334 tests / 37
  failures / 3 errors**. After R31.15: **2380 tests / 37 failures / 3 errors**
  (+46 new tests). The sorted `FAIL:`/`ERROR:` line sets are byte-identical
  (`diff` clean): no new failure or error is attributable to R31.15.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  other 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from earlier baselines.
- R31.13/R31.14 outputs are deep-copy equal after aggregation.

## 9. Performance

```
1 candidate     ->   0.15 ms  (154.5 us/candidate, fixed overhead)
100 candidates  ->  15.55 ms  (155.5 us/candidate)
1000 candidates -> 155.38 ms  (155.4 us/candidate)
```

Cost is O(bounded snapshots + one pydantic model construction with nested
item validation); no corpus, URL, endpoint, HTTP or Mongo access occurs at
this layer. The module is pure and stateless.

## 10. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- `HIGH` intentionally requires the aligned R31.14 rank-1 item. If a future
  R31.14 semantic change removes that item for an existing-evidence plan, the
  aggregator conservatively reports `UNKNOWN` rather than guessing.
- When the R31.14 plan is entirely absent, MEDIUM/LOW method mappings still
  apply with `priority_alignment = NOT_APPLICABLE`. This is documented and
  deterministic; a missing R31.14 plan is not treated as evidence of a lower
  method-level confidence.
- `limiting_factor` describes the evidence dimension that limits confidence;
  it is not a new gap and never overrides R31.13's `evidence_gap`.
- Wiring the confidence plan into the R29 queue schema/projection or UI is out
  of scope: R29 must not be modified by this stage.
- The plan is advisory and is never executed. No HTTP request, browser action,
  Nuclei run, crawl, fuzzing, scan, exploitation, LLM call, Mongo access or
  target interaction exists anywhere in the new modules.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.15
- Role: coding agent

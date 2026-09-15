# R63 — Offline Evaluation & Quality Gate

- **Date:** 2026-09-15
- **Repository:** `/opt/watch`
- **Parent HEAD:** `48597eb` (R62 offline R31–R60 snapshot bridge)
- **Task type:** Additive implementation, new files only. No production file
  changed, no R61/R62 change, no R59/R60 change. No push.
- **Scope:** Evaluate the deterministic output of the R62 offline pipeline
  (R61 snapshot -> inventory -> R30.1/R31–R38 -> R59 -> R60) against the
  current structural, sampling, safety, boundedness, specialist-signal,
  CVE-integrity, program-isolation and determinism contracts.

---

## 1. Architecture

```
tests/local_e2e/fixtures/indeed_raw_sample.json       (R61 fixture, sampled)
        |  build_snapshot -> records_for_inventory -> build_inventory (R30.2)
        v
backend.asset_cve_matching.build_matches(inventories=...)   (R30.1, R31-R38)
        v
tests/local_e2e/r62_bridge.py    bounded research_context / intelligence_context
        v
R59 build_security_research_workflow      (unchanged)
        v
R60 build_bug_bounty_copilot              (unchanged, advisory only)
        v
tests/local_e2e/r63_evaluation.py         (this stage)
        |
        +-- evaluate_pipeline / quality_gate   full gate
        +-- evaluate_r31                      R31-R38 layer consistency
        +-- evaluate_context                  bounds + hygiene
        +-- evaluate_sampling                 sampling honesty
        +-- evaluate_safety                   R59/R60 invariants
        +-- evaluate_specialist_signals       category/eligibility/evidence
        +-- evaluate_program_isolation        program identity + ref scope
        +-- evaluate_determinism              double-run comparison
        +-- canonical_json                    canonical representation
```

R63 is an evaluator only. It never fixes, normalizes, removes or recomputes
pipeline values; it inspects and reports. A PASS means "the offline research
pipeline output is structurally and semantically consistent with the current
safety and boundedness contracts" — never "the target is secure", "a
vulnerability exists", or "research is complete".

Result contract (deterministic, bounded, no timestamps):

```json
{
  "rule_version": "r63-1",
  "status": "PASS",
  "checks": {"<check_name>": {"status": "PASS", "reason": "ok"}},
  "summary": {"passed": 29, "failed": 0}
}
```

Reasons are fixed, single-line, length-bounded strings; no URLs, IPs, secrets
or Mongo identifiers are emitted.

---

## 2. Files Changed

Created:

- `tests/local_e2e/r63_evaluation.py` (evaluation module, rule version `r63-1`)
- `tests/local_e2e/test_r63_evaluation.py` (contract + 18 negative mutations)
- `tests/local_e2e/test_r63_pipeline.py` (full offline chain gate)
- `agent-reports/r63-offline-evaluation-quality-gate.md`

Modified: **none**. R61, R62, R59, R60, `backend/`, `ai/`, `database/`,
`crawl/`, `ns/` and all existing tests are untouched. No fixture change.

---

## 3. Evaluation Contract

`evaluate_pipeline(result, *, snapshot=None, foreign_programs=(), require_r31=True)`
runs the full gate. Checks (29 for the fixture pipeline):

| Check | Purpose |
|---|---|
| `pipeline_structure` | input is a mapping; fail closed otherwise |
| `stage_snapshot_reference` | R61 identity (`snapshot_version`, `snapshot_rule_version`) present in both contexts |
| `stage_inventory` | R62 inventory present with a program |
| `stage_r31` | R31/R38 matcher item present (required by default) |
| `stage_workflow` | R59 stage present and `rule_version == "r59-4"` |
| `stage_copilot` | R60 stage present and `rule_version == "r60-4"` |
| `sampling_flag`, `sampling_claims`, `sampling_counters` | sampling honesty |
| `research_context_bounds/_hygiene`, `intelligence_context_bounds/_hygiene` | R59/R60 limits + URL/IP/identifier hygiene |
| `safety_workflow`, `safety_copilot`, `safety_boundary`, `safety_recommendations`, `no_confirmation_claims` | advisory/no-execution/no-confirmation invariants |
| `specialist_categories`, `specialist_eligibility`, `specialist_evidence` | specialist signal correctness |
| `r31_item`, `r31_match_vocabulary`, `r31_layer_consistency` | R31-R38 consistency |
| `program_identity`, `program_isolation`, `record_ref_scope` | program isolation |
| `cve_integrity` | CVE ids only from actual matcher output |
| `no_fabricated_outputs` | no findings/opportunities without artifacts |

`quality_gate(...)` is the documented alias for the same deterministic
evaluation. All individual evaluators return the same result shape.

---

## 4. Safety Checks

Asserted on the fixture pipeline (R59 result + R60 result + boundary):

- `advisory == true`; `auto_execute == false` (workflow next action and every
  copilot recommendation).
- `execution_performed == false`, `external_executor_present == false`,
  `vulnerability_confirmed == false`, `exploit_authorized == false`.
- `confirmation_state == "NOT_CONFIRMED"` at workflow, copilot and
  `non_execution_boundary`.
- `human_authority_preserved == true`.
- `non_execution_boundary`: `advisory_only == true`,
  `r58_gate_required == true`, `human_authority_required == true`.
- `no_confirmation_claims` recursively rejects any true execution/confirmation
  flag anywhere in the workflow or copilot documents.
- Copilot status must be one of `COMPLETED`, `PARTIAL`, `NO_CONTEXT`; a
  `FAILED` status is a gate failure.

R63 never interprets advisory output as a finding, authorization or execution
permission; the fixture pipeline has zero opportunities and the gate asserts
that.

---

## 5. Sampling Checks

- Both contexts must carry `sampled: true`.
- Any completeness/coverage/absence claim key (`complete`, `completeness`,
  `coverage`, `full_coverage`, `program_coverage`, `complete_program`,
  `absence`, ...) anywhere in either context fails the gate.
- `research_context.collection_stats` must be a mapping whose entries carry an
  integer `selected` and boolean `cap_reached`.
- `cap_reached` is evaluated as a fact, never as a completeness proof; R63
  makes no claim that `selected < cap` implies full coverage.

---

## 6. Specialist Checks

- Only `RECON`, `CVE_RESEARCH`, `IDOR` may appear; anything else fails
  (`specialist_categories`).
- Every signal must be accepted by the existing R52 eligibility engine
  (`specialist_is_eligible`), otherwise `specialist_eligibility` fails.
- Evidence cross-checks (`specialist_evidence`, when snapshot/inventory are
  supplied):
  - `RECON api_type=REST` requires an observed API path;
  - `RECON api_type=GRAPHQL` requires an observed GraphQL path;
  - `api_versioning=VERSIONED_OBSERVED` requires an observed `/vN/` path and is
    never asserted from absence;
  - `CVE_RESEARCH cve_metadata` requires an actual matcher item whose
    `asset_match_state` is `CONFIRMED`/`SUPPORTED`/`WEAK` and whose `cve_id`
    matches exactly;
  - `IDOR object_reference=PATH_PARAMETER` requires an observed normalized
    object-reference path (`{id}`/`{uuid}`/`{hash}`) on an endpoint that also
    carries parameter evidence (params or `param_records`).
- XSS/SSRF/SQLi/JWT/OAuth are never accepted or fabricated.

---

## 7. Negative Mutation Tests (18)

Each mutation deep-copies the passing fixture pipeline, applies exactly one
change, and asserts `FAIL` on the named check:

| # | Mutation | Expected failing check |
|---|---|---|
| 1 | `sampled=false` | `sampling_flag` |
| 2 | `complete=true` in a context | `sampling_claims` |
| 3 | `advisory=false` (workflow) | `safety_workflow` |
| 4 | `auto_execute=true` (next action) | `safety_workflow` |
| 5 | `execution_performed=true` (workflow) | `safety_workflow` |
| 6 | `vulnerability_confirmed=true` (copilot) | `safety_copilot` |
| 7 | `exploit_authorized=true` (copilot) | `safety_copilot` |
| 8 | `confirmation_state="CONFIRMED"` | `safety_workflow` |
| 9 | 25-element context list | `research_context_bounds` |
| 10 | 5-level nested mapping | `research_context_bounds` |
| 11 | 33-key mapping | `intelligence_context_bounds` |
| 12 | fabricated CVE id in context | `cve_integrity` |
| 13 | fabricated IDOR signal (evidence stripped) | `specialist_evidence` |
| 14 | GraphQL signal without GraphQL evidence | `specialist_evidence` |
| 15 | `VERSIONED_OBSERVED` without `/vN/` evidence | `specialist_evidence` |
| 16 | foreign program in context | `program_isolation` |
| 17 | unsupported specialist category (`XSS`) | `specialist_categories` |
| 18 | fabricated opportunity in the brief | `no_fabricated_outputs` |

A read-only test also proves the evaluator never mutates the input: after
evaluating a failing (mutated) pipeline, the input is byte-identical to the
mutated form and still contains the bad value.

---

## 8. Determinism Result

- Cross-process comparison (two separate interpreter runs of the fixture
  pipeline + gate):

```
gate_status: PASS passed: 29 failed: 0
r31:                   c5bd0adab67e829b
research_context:      947acc8d98a58448
intelligence_context:  8ab1556cbd0654d2
workflow:              8f0017e76098cbc7
copilot:               75f627172dbc75f8
gate:                  31da7a093f8f1138
CROSS-PROCESS DETERMINISTIC: identical
```

- `evaluate_determinism` reproduces the pipeline twice and compares canonical
  JSON, then evaluates both results and compares those too; both checks PASS.
- No timestamps, UUIDs, randomness, environment values, network or Mongo calls
  exist in R63.

---

## 9. Test Counts

```
./venv/bin/python -m pytest tests/local_e2e/test_r63_evaluation.py \
    tests/local_e2e/test_r63_pipeline.py -q -p no:cacheprovider
46 passed, 9 subtests passed in 2.83s
```

- R63 tests: 46 (contract/positive checks + 18 mutations + full chain).
- Full `tests/local_e2e` (R61 + R62 + R63):
  `142 passed, 26 subtests passed in 3.44s`.
- Relevant existing pure suites (no live Mongo):

```
pytest tests/test_hunt_priority.py tests/test_component_plugin_wiring.py ...... 60 passed
pytest <R59/R60 eight files> ................................................ 242 passed
pytest tests/test_observed_inventory.py (pure subset) ....................... 36 passed, 25 deselected
pytest tests/test_asset_cve_matching.py (pure subset) ....................... 56 passed, 23 deselected
pytest tests/test_version_component_association.py -k "not BackendAdapter" .. 36 passed, 5 deselected
pytest ai/test_target_intelligence.py ai/test_target_matcher.py tests/test_component_inference.py . 189 passed
```

Live-Mongo-dependent tests were intentionally **skipped** (they read the
reachable Google DB unmocked, documented in
`agent-reports/real-data-mapping-audit.md`; e.g. `TestBackendRealCorpus`,
`TestBackendAdapter`, `TestSafety::test_money_not_touched`).

---

## 10. Git Status

Before the commit (only pre-existing items plus the R63 files):

```text
$ git status --short
 D utils.zip
?? watch.zip
?? agent-reports/R31-final-github-audit.md
?? agent-reports/local-testing-readiness-audit.md
?? agent-reports/r61-design-risk-review.md
?? agent-reports/real-data-mapping-audit.md
?? agent-reports/stage-r31-5-planning-audit.md
?? tests/local_e2e/r63_evaluation.py
?? tests/local_e2e/test_r63_evaluation.py
?? tests/local_e2e/test_r63_pipeline.py
```

`utils.zip`, `watch.zip` and the older untracked reports are unrelated and are
not staged.

---

## 11. Commit

One local commit created with only the R63 files:

- message: `feat(test): add offline r63 evaluation quality gate`
- hash: reported in the final task response.

No push.

---

## 12. Safety Confirmations

- **No Mongo writes occurred.**
- **No live Mongo reads occurred during the R63 pipeline tests:** the full
  chain runs through the R62 injected-inventory seam; a guard test patches
  `backend.observed_inventory.get_inventory`, `_fetch_documents` and
  `pymongo.MongoClient` to raise while building and evaluating the pipeline.
- **No network calls**, no LLM, no external providers.
- **No target activity:** no scans, crawling, fuzzing, exploitation, DNS or
  requests.
- **No VPS or Google VM access.**
- **No push performed.**

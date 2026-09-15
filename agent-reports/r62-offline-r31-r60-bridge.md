# R62 — Offline R31–R60 Snapshot Bridge

- **Date:** 2026-09-15
- **Repository:** `/opt/watch`
- **Parent HEAD:** `3a519ac` (R61 real recon snapshot normalization)
- **Task type:** Additive implementation. One minimal injection seam in
  `backend/asset_cve_matching.py`; all other changes are new files. No push.
- **Scope:** Connect the R61 snapshot offline to R30.2 → R30.1/R31–R38 →
  bounded R59/R60 contexts → R59 workflow → R60 copilot. No redesign of R61,
  no refactor of R31–R60, no MongoDB access, no target activity.

---

## 1. Architecture

```
R61 snapshot fixture (tests/local_e2e/fixtures/indeed_raw_sample.json)
        |  load_snapshot (offline)
        v
records_for_inventory  (unchanged R61 API)
        |  build_inventory(program, records=...)   (unchanged R30.2 API)
        v
ObservedAssetInventory projection (technologies, versions, associations,
parameters, paths, parameter->path evidence, sources)
        |  backend.asset_cve_matching.build_matches(
        |        cve=..., program=..., inventories={program: inventory})
        |  <- new optional keyword-only injection seam
        v
R30.1 matching + R31-R38 plan chain (unchanged engines)
        |
        +-- tests/local_e2e/r62_bridge.py
        |      build_research_context(...)    (bounded, sampled)
        |      build_intelligence_context(...)
        |      specialist_signals(...)        (RECON / CVE_RESEARCH / IDOR only)
        v
R59 build_security_research_workflow  (unchanged)
        v
R60 build_bug_bounty_copilot          (unchanged, advisory only)
```

New module: `tests/local_e2e/r62_bridge.py` (`RULE_VERSION = "r62-1"`).
Public API:

```python
inventory_from_snapshot(snapshot) -> dict
match_summary_for(inventory, *, cve, program=None) -> dict | None
build_research_context(snapshot, inventory, *, r31=None) -> dict
build_intelligence_context(snapshot, inventory, *, r31=None, signals=None) -> dict
specialist_signals(snapshot, inventory, *, r31=None) -> dict
validate_context(value) -> None
run_workflow(research_context) -> dict
run_copilot(research_context, intelligence_context, workflow_result, *, copilot_id) -> dict
pipeline(snapshot, *, cve=None, copilot_id=None) -> dict
canonical_json(value) -> str
```

---

## 2. R31 Injection Seam

File: `backend/asset_cve_matching.py` (only production file touched).

Changes (43 lines, 32 insertions / 11 deletions including docstrings):

1. `from typing import Any, Mapping, Optional`.
2. `_inventory_values(program, inventory: Optional[Mapping] = None)`:
   - when `inventory is None`, the existing
     `backend.observed_inventory.get_inventory(program)` path runs exactly as
     before (`try/except -> {}`);
   - when injected, the same value-extraction logic runs over the injected
     projection (no duplicated matching logic);
   - a non-mapping or empty injected value fails soft to `{}` (`isinstance`
     guard) — malformed injection cannot crash or fabricate data.
3. `build_matches(cve=None, program=None, *, inventories=None)`:
   - `inventories` is keyword-only and optional, so every existing positional
     caller and all existing behavior is unchanged;
   - the single call site becomes `_inventory_values(group_name,
     inventories.get(group_name) if isinstance(inventories, Mapping) else None)`;
   - no global mutable state, no monkeypatching, no writes, no matching-rule
     change.

Backward compatibility is proven by test
`TestR31InjectionSeam.test_default_read_path_unchanged`: with the existing
read path stubbed to return a synthetic inventory, the default call and the
injected call produce byte-identical match results.

---

## 3. Snapshot -> Inventory Mapping

`inventory_from_snapshot(snapshot)` = `records_for_inventory(snapshot)` (R61)
-> `build_inventory(program, records=...)` (existing `records=` injection,
unmodified) -> exactly one inventory projection. No new mapping logic.

Fixture result (`indeed`): 5 technologies, 5 versions (incl. 1.24.0 / 3.5.1),
5 parameters, 4 paths, version associations, parameter->path evidence,
sources `TECHNOLOGY_INVENTORY` / `PARAMETER_INVENTORY` / `ENDPOINT_INVENTORY`.

Malformed or incomplete snapshots fail closed through the existing R61
`load_snapshot`/`records_for_inventory` validation (`SnapshotError`).

---

## 4. R31–R38 Execution Path

`match_summary_for(inventory, cve=...)` calls the existing hub with the
injected inventory only. For the fixture and `CVE-2024-27956` the matcher
returns a real item (`asset_match_state=UNKNOWN`, `confidence=NONE`, because
the sampled fixture carries no WordPress evidence); a test-local WordPress
inventory produces a real `WEAK` / `MEDIUM` / `TECHNOLOGY` match with the
matcher's own evidence strings.

The item exposes the complete existing chain (all unchanged engines): R31.1
hunt priority/actionability/action, R31.9 evidence quality, R31.13–R31.22
acquisition/prioritization/confidence/decision/loop/outcome/calibration/
summary/validation/export, R32 memory snapshot/history/patterns/export, R33
pattern intelligence/ranking/efficiency/learning export, R34 strategy/path/
budget/export, R35 roles/workflow graph/coordination/orchestration export,
R36 policy/authorization/scope gate/risk/approval/boundary/authorization
export, R37 provenance/rule trace/audit/explanation/governance export, R38
framework export. The bridge projects only bounded facts and layer rule
versions from this item; it never re-derives matching.

---

## 5. R59/R60 Context Bridge

`build_research_context` (inventory facts, sampled):

- `program`, `snapshot_version`, `snapshot_rule_version`, `sampled: true`;
- `collection_stats`: per collection `{selected, fetched, cap, cap_reached}`
  (cap keys present only when R61 recorded a cap; `cap_reached` is a factual
  flag, never a completeness claim);
- `inventory_counts`: bounded counts per inventory category;
- `technologies`, `versions`, `parameters`, `paths`: each capped at 24 values,
  taken in the inventory's deterministic order;
- `record_refs`: up to 6 opaque `record_ref` values per collection
  (endpoints/http/urls/subdomains), filtered to the snapshot program;
- R31-derived fields only when a matcher item is supplied:
  `asset_match_state`, `asset_match_confidence`, `hunt_priority_band`,
  `hunt_priority_rank`, `hunt_priority_blocked`, `evidence_quality`,
  `evidence_strength`, `cve_ids` (only for matched states), and
  `r31_rule_versions` (from the real `*_rule_version` keys present).

`build_intelligence_context` (layer references + specialist signals):
same identity/sampling fields, the same R31-derived facts, `r31_rule_versions`
(14 real layer rule versions when present) and `specialist_signals`.

No full inventories, no full URLs, no endpoint lists, no raw `_id`, no IPs,
no scope/ooscope fields, no re-derived confidence or priority values.

`validate_context` mirrors the R59/R60 limits exactly
(`MAX_DEPTH=4`, `MAX_LIST=24`, `MAX_MAPPING_KEYS=32`) and raises
`BridgeError`; every emitted context is validated before it leaves the bridge.

`run_workflow` / `run_copilot` call the existing builders unchanged; the
copilot receives `{"copilot_id": ...}` plus `target_reference`,
`research_context`, `intelligence_context` and the R59 `workflow_result`.

---

## 6. Sampling Semantics

- Both contexts always carry `sampled: true`.
- `collection_stats` exposes `selected`, `fetched`, `cap` and `cap_reached`
  so a reader can see that selection hit a cap; `cap_reached=false` does NOT
  mean complete (the fetch window may still have been smaller than the
  program).
- The bridge never emits totals, coverage percentages, "complete" flags, or
  absence claims. It never asserts that a technology or path is absent from
  the real program — only what the sample contains.
- R61's design-review caveats are respected: the snapshot is a bounded
  sample; `record_ref` is slot identity, not content identity; URL
  canonicalization representation caveats are unchanged and are not
  re-interpreted by R62.

---

## 7. Specialist Signal Rules

Only three categories can ever be produced; all others stay absent (no
UNKNOWN-invented categories, no keyword guessing):

| Category | Derivation | Values |
|---|---|---|
| RECON | any observed endpoint/URL path matching `/api/` or `/graphql` | `api_type = REST` or `GRAPHQL` (GraphQL wins); `api_versioning = VERSIONED_OBSERVED` only when a `/vN/` segment is positively observed |
| CVE_RESEARCH | actual matcher item whose `asset_match_state` is `CONFIRMED`/`SUPPORTED`/`WEAK` | `cve_metadata = <matched CVE id>` |
| IDOR | an endpoint whose stored normalized path contains `{id}`/`{uuid}`/`{hash}`/`{id}-slug` AND that endpoint carries parameter evidence (`params`, `params_from_crawl`, `params_from_x8`, or `param_records`) | `object_reference = PATH_PARAMETER` |

- No signals are derived for XSS, SSRF, SQLi, JWT, OAuth.
- `api_versioning` is never asserted from absence (sampling semantics); only a
  positive `/vN/` observation sets it.
- Every emitted signal is verified through the existing R52
  `specialist_is_eligible` engine before being returned, so the bridge cannot
  produce false-positive eligibility even if its derivation slips.
- Signals are computed from snapshot records filtered to the snapshot
  program, so mixed/tampered rows cannot contribute.

---

## 8. Safety Invariants

Observed in the offline pipeline (asserted by tests):

- R59 result: `advisory=true`, `execution_performed=false`,
  `external_executor_present=false`, `vulnerability_confirmed=false`,
  `exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
  `human_authority_preserved=true`, `safety_status=RESEARCH_ONLY`, next action
  `advisory=true` / `auto_execute=false`.
- R60 result: same invariants plus the fixed `non_execution_boundary`
  (`r58_gate_required=true`, `human_authority_required=true`,
  `advisory_only=true`) and `opportunity_count=0` (no findings are invented).
- The bridge never bypasses R56/R58/R59/R60; it calls their public APIs only.
- Scope and ooscope fields are never read or emitted by R62 — no scope field
  can become authorization.
- Recon observations (technologies, parameters, paths, hit counts) remain
  observations; no severity, confidence, vulnerability or authorization value
  is created.

---

## 9. Determinism

- Same snapshot + same arguments produce identical canonical JSON for
  `r31`, `research_context`, `intelligence_context`, `workflow` and `copilot`
  (asserted in-process).
- Cross-process check (two separate interpreter runs, fixture pipeline):

```
r31:                   c5bd0adab67e829b
research_context:      947acc8d98a58448
intelligence_context:  8ab1556cbd0654d2
workflow:              8f0017e76098cbc7
copilot:               75f627172dbc75f8
CROSS-PROCESS DETERMINISTIC: identical
```

- No timestamps, randomness, environment values, network calls or unordered
  iteration are introduced; the bridge re-uses existing content-derived ids
  (`wfr-*`, `bbr-*`) from R59/R60.

---

## 10. Tests

New focused tests (all offline, no Mongo, no network):

```text
./venv/bin/python -m pytest tests/local_e2e/test_r62_bridge.py \
    tests/local_e2e/test_r62_pipeline.py -q -p no:cacheprovider
37 passed, 3 subtests passed in 1.76s
```

Coverage A–T:

- A `TestSnapshotToInventory` (fixture -> injected inventory, determinism,
  malformed snapshot fail-closed)
- B `TestR31InjectionSeam.test_injected_inventory_produces_match_item`
- C `test_default_read_path_unchanged` (default vs injected byte-identical)
- D `test_injected_path_does_not_read_mongo` + full-pipeline Mongo/network guard
- E `TestSafetyAndSampling.test_r31_output_is_deterministic` + pipeline determinism
- F/G/H/I/J `TestContextBounds` (depth, lists, keys, validator)
- K `test_contexts_are_explicitly_sampled`, `test_cap_reached_flag_is_factual`
- L/M/N `test_r59_safety_invariants`, `test_r60_safety_invariants`
- O `test_signals_are_deterministic`
- P `test_unsupported_categories_remain_absent`
- Q `test_cve_signal_only_when_matcher_matches`
- R `test_idor_from_normalized_path_with_params`,
  `test_idor_requires_parameter_evidence`
- S `test_malformed_snapshot_fails_closed`, `test_empty_snapshot_pipeline_is_safe`
- T `test_mixed_program_data_cannot_cross`

Full offline integration test:
`tests/local_e2e/test_r62_pipeline.py` drives fixture -> inventory ->
R31/R38 (43 plan keys and 10 real layer rule versions asserted) -> R59
(`RESEARCH_READY`, `RESEARCH_ONLY`) -> R60 (advisory-only brief) with
determinism and Mongo/network guards.

Relevant existing suites (no live Mongo):

```text
pytest tests/local_e2e ........................................ 96 passed, 17 subtests
pytest tests/test_hunt_priority.py tests/test_component_plugin_wiring.py ... 60 passed
pytest tests/test_observed_inventory.py (pure subset) ......... 36 passed, 25 deselected
pytest tests/test_asset_cve_matching.py (pure subset) ......... 56 passed, 23 deselected
pytest tests/test_version_component_association.py -k "not BackendAdapter" . 36 passed
pytest <12 R31 chain files> ................................... 516 passed
pytest <28 R32-R38 files> ..................................... 543 passed
pytest <R59/R60 eight files> .................................. 242 passed
pytest ai/test_target_intelligence.py ai/test_target_matcher.py tests/test_component_inference.py 189 passed
```

Live-DB-dependent tests were intentionally not executed (they read the
reachable Google DB unmocked; documented in
`agent-reports/real-data-mapping-audit.md`).

---

## 11. Files Changed

Created:

- `tests/local_e2e/r62_bridge.py`
- `tests/local_e2e/test_r62_bridge.py`
- `tests/local_e2e/test_r62_pipeline.py`
- `agent-reports/r62-offline-r31-r60-bridge.md`

Modified (minimal seam only):

- `backend/asset_cve_matching.py` (43 lines; keyword-only optional
  `inventories`; default path unchanged; no matching semantics changed)

Not modified: `ai/`, `database/`, `crawl/`, `ns/`, R59/R60, existing R61
files, existing tests, configuration.

---

## 12. Git Status

Before the commit (only pre-existing items plus the R62 work):

```text
$ git status --short
 M backend/asset_cve_matching.py
?? tests/local_e2e/r62_bridge.py
?? tests/local_e2e/test_r62_bridge.py
?? tests/local_e2e/test_r62_pipeline.py
?? agent-reports/r62-offline-r31-r60-bridge.md
 D utils.zip
?? watch.zip
... (older untracked audit reports unchanged)
```

`utils.zip` (pre-existing working-tree deletion), `watch.zip` and the older
untracked audit reports are unrelated and are not staged.

---

## 13. Commit Status

One local commit was created with only the R62 files:

- message: `feat(test): add offline r31-r60 snapshot bridge`
- hash: reported in the final task response (the commit cannot embed its own
  hash).

No push was performed. No MongoDB writes and no live MongoDB reads occurred
(all matching ran through the injected-inventory seam; the guard tests patch
`get_inventory`, `_fetch_documents` and `pymongo.MongoClient` to raise). No
target activity, no VPS/Google VM access.

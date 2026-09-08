# Phase 4F — Deterministic TestPlan → Artifact Readiness Report: Implementation Report

## 1. Verdict

**IMPLEMENTED.** Phase 4F establishes the deterministic,
read-only readiness-report layer exactly as specified:

```
TestPlan -> Artifact Retrieval -> readiness checks
    -> TestPlanReadinessReport (INFORMATIONAL ONLY)
```

Strictly read-only: no generation, execution, verification,
findings, verdicts, LLM calls, network access, subprocess,
scheduling, or executor integration. READY never authorizes
execution. All new tests pass (39/39) and all regression suites
pass with zero new failures.

## 2. Actual repository findings

Inspected before writing any code (no prior report was trusted):

- `ai/schemas/test_plan.py` — `TestPlan` carries
  `test_plan_id`/`hypothesis_id`, optional `match_id`/
  `snapshot_hash` (absent = pre-4B shape, never fabricated),
  and the closed `TestCategory` (8 values) / `ExecutionType`
  (4 values) vocabularies. Not modified.
- `ai/researcher/test_plan_builder.py::_derive_triple` — the
  only deterministic source of category/execution semantics.
  Emittable triples confirmed: `nuclei_cve/nuclei_scan`,
  `http_probe/http_probe`, `xss_reflected/http_verification`,
  `xss_dom|stored/browser_verification`,
  `xss_generic/http_verification`. The requirement mapping
  encodes exactly these semantics; nothing invented.
- `ai/researcher/artifact_retrieval.py` — `get_by_test_plan_id`
  (raises fail-closed on corruption), `audit_provenance`
  (PASS/FAIL/INCONCLUSIVE), `verify_all` (non-raising sweep).
  All three reused verbatim. Not modified.
- `ai/knowledge/artifact_store.py` — immutable; plan-category
  consistency is deliberately NOT a storage concern (a
  structurally VALID artifact stores under any plan), which is
  precisely why type-mismatch detection belongs in readiness.
  Not modified.
- `ai/test_artifact_store.py` helpers (`_bound_plan`,
  `_valid_*`, `_forge`, fixtures) reused by import; confirmed
  `_bound_plan` yields `http_probe` (requires
  `http_request_spec`), so nuclei/xss plan builders were added
  locally in the new test module. No existing file modified.

## 3. Exact files created / modified

Created (2), modified (0):

- `ai/researcher/test_plan_readiness.py` (new) —
  `build_readiness_report(store, test_plan)`,
  `required_artifact_types_for(category, execution)`, frozen
  `TestPlanReadinessReport` / `ArtifactReadinessEntry` results.
  Imports only `dataclasses`, the store read API, the three
  Phase 4E functions, and `TestPlan`. No `open()` calls, no
  writes, no hash/identity logic of its own.
- `ai/test_test_plan_readiness.py` (new) — 39-test A–AP matrix.

## 4. Readiness schema / API

```python
build_readiness_report(store, test_plan) -> TestPlanReadinessReport
TestPlanReadinessReport(
    test_plan_id, outcome, artifact_count,
    artifacts: tuple[ArtifactReadinessEntry, ...],  # id-ordered
    required_artifact_types, available_artifact_types,
    missing_artifact_types,                          # all sorted
    binding_failures, integrity_failures,
    provenance_failures,                             # all sorted
)
ArtifactReadinessEntry(artifact_id, artifact_type, content_hash,
                       binding_ok, provenance_outcome, failures)
outcome ∈ {READY, NOT_READY, INCONCLUSIVE}
```

Input contract: `ArtifactStore` + `TestPlan` instances only;
dicts, JSON, paths, filenames, and non-string bindings raise
`TypeError`. The schema contains no execution, scope,
authorization, verdict, or finding fields under any name
(AST-proven).

## 5. Deterministic artifact requirement mapping

Closed tables over the category/execution literals only —
prose (`objective`, `expected_behavior`, evidence,
preconditions) is never read, no LLM participates:

| Category | Execution | Required |
|---|---|---|
| `nuclei_cve`, `nuclei_generic` | `nuclei_scan` | `nuclei_template` |
| `xss_reflected/stored/dom/generic` | `http/browser_verification` | `xss_payload` |
| `http_probe`, `http_signature` | `http_probe` | `http_request_spec` |

Category-derived ∪ execution-derived (sorted); empty result =
unsupported → INCONCLUSIVE, never a guess. Hostile prose
("REQUIRE shell_script…") proven inert (AD).

## 6. Binding validation

Exact comparison per retrieved artifact:
`reference.test_plan_id == plan.test_plan_id` (always),
hypothesis equality (always — both required fields),
match/snapshot equality only where the plan carries them
(absent plan bindings are never fabricated and never
mismatch). Any contradiction → explicit failure → NOT_READY.
Artifacts of a non-required type under the plan are type
mismatches → NOT_READY (storage accepts them; readiness
judges them).

## 7. Provenance / integrity handling

Both reused, never duplicated: `audit_provenance()` per
artifact (FAIL entries → `provenance_failures` → NOT_READY;
INCONCLUSIVE with no FAIL caps the report at INCONCLUSIVE),
and store/sweep integrity via retrieval exceptions plus an
always-attempted `verify_all` attribution (plan-relevant
subjects named). Corruption — required or unrelated — always
prevents READY and is named explicitly; nothing is repaired,
removed, or reconstructed.

## 8. Readiness decision rules

- INCONCLUSIVE: requirement mapping empty (unsupported
  semantics), or no FAIL anywhere but some audit INCONCLUSIVE.
- NOT_READY: retrieval blocked by corruption, any binding/type
  contradiction, any missing required type, any provenance FAIL.
- READY: valid mapping, all required types present with
  binding-clean + provenance-PASS artifacts, zero failures.
- Unknown never becomes READY; NOT_READY requires an explicit
  contract-grounded failure. READY asserts only structural
  readiness — never vulnerability, safety, scope, or execution
  permission.

## 9. Security boundaries

AST-proven on the new module: no network (V), subprocess (W),
LLM/model/prompt (X), database (Y), verifier/executor/browser/
scheduler/queue/scope-policy/finding imports (Z, T, U),
no scope identifiers, no finding creation, no runtime
invocation calls, no `open()`/write/unlink/replace/`.put(`,
no generation/mutation/deletion attributes (AL–AN), no
authorization decision in the report (AO). Bytes never
executed (AF).

## 10. Adversarial test matrix (A–AP, 39 tests)

| ID | Coverage | Result |
|----|----------|--------|
| A | nuclei + xss + http plans with required artifacts → READY | ✅ |
| B | missing required artifact → NOT_READY (+ missing tuple) | ✅ |
| C | multiple same-type artifacts, all represented, id-ordered | ✅ |
| D–G | wrong plan/hypothesis/match/snapshot bindings → NOT_READY | ✅ |
| H | corrupted required artifact → NOT_READY, subject named | ✅ |
| I | corrupted unrelated artifact → explicit, READY withheld | ✅ |
| J | forged execution semantics → INCONCLUSIVE, empty requirements | ✅ |
| K | deterministic ordering of artifacts/types/failures | ✅ |
| L | repeated report equality | ✅ |
| M | empty store → NOT_READY, zero artifacts | ✅ |
| N | absent optional bindings never fabricated/mismatched | ✅ |
| O | artifact type mismatch → NOT_READY + missing required | ✅ |
| P | provenance FAIL surfaced (REJECTED-state tamper) | ✅ |
| Q | provenance INCONCLUSIVE → INCONCLUSIVE, deterministic | ✅ |
| R–AO | no verdict/execution/scope/finding vocabulary or fields | ✅ |
| S–AA | import/mutation/generation/deletion boundaries | ✅ |
| AB | exact plan-ID binding verified store-side per entry | ✅ |
| AC–AD | closed mapping only; hostile prose inert | ✅ |
| AE | directory-only mtime touch cannot change result | ✅ |
| AF | bytes never executed | ✅ |
| AG | snapshot-bound plans distinguishable, both READY | ✅ |
| AH | all required flavors + multi-type representation | ✅ |
| AI/AK | malformed plans/stores rejected (`TypeError`) | ✅ |
| AJ | malformed record → NOT_READY + integrity failures | ✅ |
| AP | READY carries no vulnerability/scope/execution signal | ✅ |

## 11. Exact test results

- `python3 -m unittest ai.test_test_plan_readiness` → **39 tests, OK**
- `ai.test_artifact_retrieval ai.test_artifact_store
  ai.test_artifact ai.test_hypothesis_testplan
  ai.test_test_plan_builder ai.test_hypothesis_engine
  ai.test_target_matcher ai.test_target_intelligence
  ai.test_pattern_store ai.test_pattern_projector
  ai.test_research_pattern` → **621 tests, OK**
- `ai.test_ingestion_schema ai.test_ingestion_grounding
  ai.test_knowledge_store ai.test_knowledge_ingestion` →
  **132 tests, OK**
- `ai.test_openrouter ai.test_xss_researcher
  ai.test_xss_llm_researcher ai.test_xss_verification
  ai.test_xss_oracle` → **265 tests, OK**
- `python3 -m compileall -q ai` → **OK**

## 12. Limitations

1. Requirement mapping covers only the category/execution
   literals the builder can emit today; a future builder triple
   needs a mapping entry, else plans report INCONCLUSIVE.
2. When store enumeration is blocked by corruption, per-plan
   attribution relies on the sweep; if the index itself is
   unreadable, failures name record hashes rather than plan
   bindings (explicit but coarse).
3. `available_*` counts only binding-clean, provenance-non-FAIL
   artifacts; present-but-broken artifacts appear in
   `artifacts` with failures rather than in `available_*` — by
   design, but consumers must read both.
4. No pagination or secondary indexes (O(n) over stored
   records per report); acceptable for audit-scale use.
5. Plan lifecycle `status` (PROPOSED/APPROVED/…) is
   intentionally ignored: readiness judges artifact structure,
   never workflow state or authority.

## 13. Explicit Git no-op confirmation

**No Git command was executed in this phase.** No `git status`,
`diff`, `add`, `commit`, `checkout`, `switch`, `restore`,
`reset`, `merge`, `branch`, `stash`, or any other Git operation
was run. No unrelated working-tree files were inspected,
staged, modified, or cleaned. Two new files were created; zero
existing files were modified.

## 14. Recommended next phase

A **read-only readiness aggregation/audit CLI or report
renderer** (human/machine-readable summaries over many plans,
sweep + readiness rollups) — still no generation, no
execution, no authorization. Executor integration (runtimes,
verifiers, schedulers, findings) remains a separate future
phase behind a new security review and explicit authorization
boundary, consuming only READY reports over sweep-clean
stores.

# R31.21 Research Intelligence Consistency Validator

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Validate that the complete R31.13-R31.20 evidence chain is internally
consistent:

    "Is the complete R31 research chain internally consistent?"

The validator only reports consistency. It never repairs, rewrites or
recomputes any upstream plan, never executes research, never inspects CVE
data, never calculates the Money Score and never modifies the R29 queue.

## 2. Files Changed

- `ai/schemas/research_consistency_validation.py` — **new** pydantic schema
  module (343 lines): `ResearchConsistencyValidationPlan`, closed
  validation-status/issue/checked-stage vocabularies, bounds and a sanitizer
  for its own snapshot (used by R31.22).
- `ai/knowledge/research_consistency_validator.py` — **new** pure module (309
  lines, `r31-21`): `validate_research_consistency()`.
- `backend/asset_cve_matching.py` — **modified additively**:
  `summary["research_consistency_validation_plan"]` and its `_rule_version`
  companion. No existing field changed.
- `tests/test_research_consistency_validator.py` — **new** focused suite (23
  tests, 440 lines).
- `agent-reports/stage-r31-21-research-consistency-validator.md` — this
  report.

## 3. Architecture Decisions

- **Authority reuse, no rule drift.** Cross-stage expectations are read from
  the real upstream tables: R31.17 `DECISION_TRANSITIONS`, R31.18
  `LIFECYCLE_OUTCOMES`, R31.19 `OUTCOME_FEEDBACK`, R31.20 `OUTCOME_SUMMARY`.
  The validator cannot silently diverge from the pipeline it checks.
- **Report-only.** Detected issues are recorded; no data is repaired.
- **Closed issue vocabulary.** 21 closed issue codes cover missing stages
  (8), invalid vocabulary values (9) and cross-stage mismatches (4).
- **Closed checked-stage list.** All eight mandatory stages
  (`R31_13_ACQUISITION` … `R31_20_SUMMARY`) are always listed in fixed order.
- **Status semantics.** `VALID` when no issues; `INVALID` when any issue is
  found; `UNKNOWN` when no plan at all is present (nothing can be validated).
  `valid` is `True` only for `VALID`.
- **Schema-validated output.** `extra="forbid"`, fixed `r31-21`, forced
  `research_only=True`, bounded/deduplicated issues and stages; invalid issue
  or stage codes raise, while the R31.22 snapshot sanitizer filters.

## 4. Checks

1. `R31.16 decision` → `R31.17 lifecycle` must match
   `DECISION_TRANSITIONS` (`ACCEPT_EVIDENCE`→`COMPLETED`, etc., with
   unrecognized/`UNKNOWN` decisions mapping to `UNKNOWN`).
2. `R31.17 lifecycle` → `R31.18 outcome` must match `LIFECYCLE_OUTCOMES`.
3. `R31.18 outcome` → `R31.19 feedback` must match `OUTCOME_FEEDBACK`.
4. No missing mandatory stage (`R31.13`-`R31.20`).
5. No invalid vocabulary values (acquisition method, prioritization items,
   confidence level/category, decision, lifecycle, outcome, feedback,
   research status).
6. `R31.18 outcome` → `R31.20 research_status` must match `OUTCOME_SUMMARY`
   (extra closure check; `INVALID_RESEARCH_STATUS` suppresses the mismatch
   code so issues stay precise).

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_consistency_validator -q
# combined regression and full suite as in R31.20
```

Results:

```
tests.test_research_consistency_validator           OK  (25 tests)
combined R31.10-R31.22 + R29/R30/R31 regression     Ran 1066 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)             Ran 2648 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile                                          OK
git diff --check                                    clean
```

Coverage: valid chain for every method plus deferred, all four mismatch codes
(decision/lifecycle, lifecycle/outcome, outcome/feedback, outcome/summary),
missing-stage reporting, all-missing `UNKNOWN`, partial-input `INVALID`,
invalid-vocabulary reporting, malformed non-dict inputs, determinism, no
input mutation, closed vocabulary + schema rejections, bounds, JSON,
research_only, no operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The validator checks structural/vocabulary consistency only. It does not
  judge evidence truth, target validity or exploitability, and it never
  repairs data.
- `UNKNOWN` is reserved for the no-input case; any present-but-missing stage
  produces `INVALID` with explicit `MISSING_*` issues.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.21
- Role: coding agent

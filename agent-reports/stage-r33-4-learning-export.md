# R33.4 Research Learning Export

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, database persistence, LLM call, embedding or
external network access is executed. No VM/deployment change.

## 1. Goal

Create the final deterministic R33 export over the pattern intelligence,
candidate ranking and efficiency plans:

    "What learning intelligence is ready for downstream research attention?"

The exporter packages existing plans only. It never executes research, never
persists anything, never uses or modifies the Money Score and never modifies
the R29 queue.

## 2. Files Changed

- `ai/schemas/research_learning_export.py` — **new** pydantic schema module
  (190 lines): `ResearchLearningExportPlan`, closed recommendation and
  limitation vocabularies, bounded raising validators and sanitizers for the
  embedded ranking/patterns/efficiency snapshots.
- `ai/knowledge/research_learning_export.py` — **new** pure module (171
  lines, `r33-4`): `export_research_learning()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R33 diff):
  `summary["research_learning_export_plan"]` and its `_rule_version`
  companion.
- `tests/test_research_learning_export.py` — **new** focused suite (18 tests,
  295 lines).
- `agent-reports/stage-r33-4-learning-export.md` — this report.

## 3. Architecture Decisions

- **Validation-gated readiness.** `ready` is `True` only when all three R33
  plans are present and carry valid closed vocabularies. Missing/malformed
  inputs are never silently upgraded.
- **Closed recommendations** (fixed order, first-match):
  `PRIORITIZE_HISTORICAL_SUCCESS` (any positive candidate score),
  `REDUCE_RECURRING_BLOCKERS`, `CLOSE_EVIDENCE_GAPS`,
  `INCREASE_SUCCESSFUL_RESEARCH`, `COLLECT_MORE_HISTORY` (absent or
  `NO_HISTORY` ranking), else `NO_ACTION`.
- **Closed limitations** (fixed order): `NO_HISTORY`,
  `LOW_PATTERN_CONFIDENCE`, `UNKNOWN_EFFICIENCY`,
  `NO_HISTORICAL_SUCCESS`.
- **Bounded, sanitized snapshots.** The embedded plans are projected through
  the R33.1/R33.2/R33.3 sanitizers with fixed key sets.
- **Read-only and no persistence.** Inputs are never mutated; the export is an
  in-memory dict attached to the backend candidate summary.

## 4. Export Shape

```json
{
  "rule_version": "r33-4",
  "ready": true,
  "ranking": { "...bounded R33.2 snapshot..." },
  "patterns": { "...bounded R33.1 snapshot..." },
  "efficiency": { "...bounded R33.3 snapshot..." },
  "recommendations": ["PRIORITIZE_HISTORICAL_SUCCESS"],
  "limitations": ["LOW_PATTERN_CONFIDENCE"],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_learning_export -q
./venv/bin/python -m unittest tests.test_research_pattern_intelligence \
    tests.test_historical_candidate_ranking tests.test_research_efficiency \
    tests.test_research_learning_export <R31/R32 + R29/R30/R31 regression> -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile <new modules> backend/asset_cve_matching.py
git diff --check
```

Results:

```
tests.test_research_learning_export               OK  (18 tests)
tests.test_research_pattern_intelligence          OK  (23 tests)
tests.test_historical_candidate_ranking           OK  (20 tests)
tests.test_research_efficiency                    OK  (19 tests)
combined R31+R32+R33 + R29/R30 regression        Ran 1227 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2809 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2729-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, ready-when-all-valid, not-ready for any
missing/malformed plan, every recommendation mapping, every limitation
mapping, embedded-snapshot aliasing, no input mutation, JSON serialization,
closed vocabulary + schema rejections, forced rule version/research_only, no
operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `ready` means "valid learning plans are present and packaged", not that the
  candidate is vulnerable; a valid empty-history export is also `ready` and is
  flagged through limitations.
- Recommendations are advisory research-attention hints; they never enqueue
  work, alter R29 or change the Money Score.
- The backend exports the current candidate's single-record history; callers
  with stored snapshots can drive multi-record ranking/pattern/efficiency
  plans through the same pure planners.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R33.4
- Role: coding agent

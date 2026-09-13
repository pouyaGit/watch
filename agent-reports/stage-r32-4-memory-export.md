# R32.4 Research Memory Export

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change. No persistence layer and no database migration.

## 1. Goal

Create the final deterministic export object over the R32.2 research history
and the R32.3 structural pattern detection:

    "What reusable historical intelligence is available for this layer?"

The exporter packages existing plans only. It never executes research, never
persists anything, never infers a vulnerability, never modifies the R29 queue
or the Money Score and never recomputes R31 logic.

## 2. Files Changed

- `ai/schemas/research_memory_export.py` — **new** pydantic schema module (151
  lines): `ResearchMemoryExportPlan`, closed limitation codes, bounded
  validators and sanitizers for the embedded history/pattern snapshots.
- `ai/knowledge/research_memory_exporter.py` — **new** pure module (117 lines,
  `r32-4`): `export_research_memory()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R32 diff):
  `summary["research_memory_export_plan"]` and its `_rule_version` companion.
- `tests/test_research_memory_export.py` — **new** focused suite (19 tests,
  226 lines).
- `agent-reports/stage-r32-4-memory-export.md` — this report.

## 3. Architecture Decisions

- **Deterministic readiness.** `ready` is `True` only when the history plan
  has at least one record and the pattern plan carries a closed
  `dominant_pattern`. Missing/malformed inputs yield `ready=False` and are
  never silently upgraded.
- **Closed limitation vocabulary.** `NO_HISTORY`, `SINGLE_RECORD_HISTORY`,
  `PATTERN_LOW_CONFIDENCE`, `RECURRING_BLOCKERS_PRESENT`, emitted in a fixed
  order and bounded/deduplicated.
- **Bounded, sanitized snapshots.** The embedded history and pattern plans are
  projected through the R32.2/R32.3 sanitizers with fixed key sets.
- **Read-only.** Inputs are never mutated; embedded snapshots do not alias
  caller data.
- **No persistence.** The export is an in-memory dict attached to the backend
  candidate summary; nothing is written, published or migrated.

## 4. Export Shape

```json
{
  "rule_version": "r32-4",
  "ready": true,
  "history": { "...bounded R32.2 snapshot..." },
  "patterns": { "...bounded R32.3 snapshot..." },
  "limitations": ["SINGLE_RECORD_HISTORY", "PATTERN_LOW_CONFIDENCE"],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_memory_export -q
./venv/bin/python -m unittest tests.test_research_memory_snapshot \
    tests.test_research_history_aggregator tests.test_research_pattern_detector \
    tests.test_research_memory_export <R31.10-R31.22 + R29/R30/R31 regression> -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile <new modules> backend/asset_cve_matching.py
git diff --check
```

Results:

```
tests.test_research_memory_export                OK  (19 tests)
tests.test_research_memory_snapshot              OK  (23 tests)
tests.test_research_history_aggregator           OK  (20 tests)
tests.test_research_pattern_detector             OK  (19 tests)
combined R31+R32 + R29/R30 regression            Ran 1147 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2729 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2648-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, ready/not-ready rules, every limitation code,
missing/malformed inputs, no input mutation, embedded-snapshot aliasing, JSON
serialization, closed limitation vocabulary, schema rejections, forced rule
version/research_only, bound/dedup behavior, no operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `ready` means "a usable in-memory memory export exists", not that research
  succeeded or that a candidate is vulnerable.
- The backend currently feeds one snapshot per candidate; multi-record
  history/pattern exports are available to callers with stored snapshots.
- No storage or retention policy is introduced by this stage.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R32.4
- Role: coding agent

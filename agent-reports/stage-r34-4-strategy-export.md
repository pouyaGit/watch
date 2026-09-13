# R34.4 Research Strategy Export

Local WSL implementation. Strategy-planning only: no HTTP requests, crawling,
scanning, Nuclei, fuzzing, exploit validation, browser automation, Mongo
operations, database persistence, LLM calls, embeddings or external network
access. No VM/deployment change. No R29/Money/CVE-scoring changes.

## 1. Goal

Create the final deterministic R34 downstream object over the strategy, path
and budget plans:

    "What strategy intelligence is ready for the next research step?"

The export packages existing plans only. It never executes research, never
persists anything and never modifies previous planner semantics.

## 2. Files Changed

- `ai/schemas/research_strategy_export.py` — **new** pydantic schema module
  (160 lines): `ResearchStrategyExportPlan`, closed limitation vocabulary,
  bounded validators and sanitizers for the embedded strategy/path/budget
  snapshots.
- `ai/knowledge/research_strategy_export.py` — **new** pure module (150
  lines, `r34-4`): `export_research_strategy()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R34 diff):
  `summary["research_strategy_export_plan"]` and its `_rule_version`
  companion.
- `tests/test_research_strategy_export.py` — **new** focused suite (18 tests,
  264 lines).
- `agent-reports/stage-r34-4-strategy-export.md` — this report.

## 3. Architecture Decisions

- **Validation-gated readiness.** `ready` is `True` only when the strategy,
  path and budget plans are all present and carry valid closed vocabularies;
  missing/malformed inputs are never silently upgraded.
- **Closed limitations** in fixed order: `UNKNOWN_STRATEGY` (unknown/missing
  strategy type), `LOW_CONFIDENCE` (low/unknown/missing confidence),
  `DEFERRED_STRATEGY` (explicit DEFERRED), `REPEATED_BLOCKERS` (PAUSE
  budget), `UNKNOWN_BUDGET` (unknown/missing budget state).
- **Bounded, sanitized snapshots.** Embedded plans are projected through the
  R34.1/R34.2/R34.3 sanitizers with fixed key sets; embedded data never
  aliases inputs.
- **Read-only and no persistence.** The export is an in-memory dict attached
  to the backend candidate summary; nothing is written, published or
  migrated.

## 4. Export Shape

```json
{
  "rule_version": "r34-4",
  "ready": true,
  "strategy": { "...bounded R34.1 snapshot..." },
  "path": { "...bounded R34.2 snapshot..." },
  "budget": { "...bounded R34.3 snapshot..." },
  "limitations": [],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_strategy_export -q
./venv/bin/python -m unittest tests.test_research_strategy_generator \
    tests.test_research_path_selector tests.test_research_budget_planner \
    tests.test_research_strategy_export <R31/R32/R33 + R29/R30 regression> -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile <new modules> backend/asset_cve_matching.py
git diff --check
```

Results:

```
tests.test_research_strategy_export               OK  (18 tests)
tests.test_research_strategy_generator            OK  (28 tests)
tests.test_research_path_selector                 OK  (15 tests)
tests.test_research_budget_planner                OK  (20 tests)
combined R31+R32+R33+R34 + R29/R30 regression    Ran 1308 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2890 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2809-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: ready-when-all-valid, not-ready for any missing/malformed plan,
every limitation mapping and ordering, embedded-snapshot aliasing, no input
mutation, deterministic output, JSON serialization, closed vocabulary +
schema rejections, forced rule version/research_only, no operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `ready` means "valid strategy plans are present and packaged", not that the
  candidate is vulnerable or that any step may be executed. `CONTINUE`
  remains an advisory budget label.
- The backend exports the current candidate's single-record strategy chain;
  multi-record history/learning inputs are supported by the same pure
  planners for callers with stored snapshots.
- No persistence, queue wiring, notification or execution authority is
  introduced by this stage.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R34.4
- Role: coding agent

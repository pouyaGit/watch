# R35.4 Orchestration Export

Local WSL implementation. Orchestration-planning only: no HTTP requests,
crawling, scanning, Nuclei, fuzzing, exploit validation, browser automation,
Mongo operations, database persistence, LLM calls or external network access.
No autonomous execution, task dispatch, worker queue, scheduler or agent
runtime is created. No VM/deployment change, no R29/Money/CVE-scoring
changes.

## 1. Goal

Create the final deterministic R35 downstream object over the role plan,
workflow graph and coordination plan:

    "What conceptual orchestration intelligence is ready?"

The exporter packages existing plans only. It never executes agents, never
persists anything and never modifies previous planner semantics.

## 2. Files Changed

- `ai/schemas/research_orchestration_export.py` — **new** pydantic schema
  module (162 lines): `ResearchOrchestrationExportPlan`, closed limitation
  vocabulary, bounded validators and sanitizers for the embedded
  role/workflow/coordination snapshots.
- `ai/knowledge/research_orchestration_export.py` — **new** pure module (147
  lines, `r35-4`): `export_research_orchestration()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R35 diff):
  `summary["research_orchestration_export_plan"]` and its `_rule_version`
  companion.
- `tests/test_research_orchestration_export.py` — **new** focused suite (18
  tests, 283 lines).
- `agent-reports/stage-r35-4-orchestration-export.md` — this report.

## 3. Architecture Decisions

- **Validation-gated readiness.** `ready` is `True` only when the role plan
  (roles + primary + reason + confidence), the workflow graph (nodes, edges,
  entry/terminal) and the coordination plan (mode + role sequence) are all
  present and valid. Missing/malformed inputs are never silently upgraded.
- **Closed limitations** in fixed order: `UNKNOWN_STRATEGY`,
  `LOW_CONFIDENCE`, `DEFERRED_STRATEGY`, `UNKNOWN_COORDINATION`,
  `EMPTY_WORKFLOW`.
- **Bounded, sanitized snapshots.** Embedded plans are projected through the
  R35.1/R35.2/R35.3 sanitizers with fixed key sets; embedded data never
  aliases inputs.
- **No runtime artifacts.** The export is an in-memory dict attached to the
  backend candidate summary; there is no queue, scheduler, dispatch or
  persistence.

## 4. Export Shape

```json
{
  "rule_version": "r35-4",
  "ready": true,
  "roles": { "...bounded R35.1 snapshot..." },
  "workflow": { "...bounded R35.2 snapshot..." },
  "coordination": { "...bounded R35.3 snapshot..." },
  "limitations": [],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_orchestration_export -q
./venv/bin/python -m unittest tests.test_agent_role_planner \
    tests.test_research_workflow_graph \
    tests.test_agent_coordination_planner \
    tests.test_research_orchestration_export \
    <R31/R32/R33/R34 + R29/R30 regression> -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile <new modules> backend/asset_cve_matching.py
git diff --check
```

Results:

```
tests.test_research_orchestration_export          OK  (18 tests)
tests.test_agent_role_planner                     OK  (21 tests)
tests.test_research_workflow_graph                OK  (18 tests)
tests.test_agent_coordination_planner             OK  (19 tests)
combined R31+R32+R33+R34+R35 + R29/R30          Ran 1384 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)         Ran 2966 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2890-test baseline; no new failure
py_compile / git diff --check                   OK / clean
```

Coverage: ready-when-all-valid, not-ready for any missing/malformed plan,
every limitation mapping and ordering, embedded-snapshot aliasing, no input
mutation, deterministic output, JSON serialization, closed vocabulary +
schema rejections, forced rule version/research_only, no operational
execution content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `ready` means "valid orchestration plans are present and packaged", not
  that agents exist or may execute. A valid deferred chain is also `ready`
  and is flagged through limitations.
- This stage deliberately creates no autonomous execution, task dispatch,
  worker queue, scheduler, agent runtime, persistence or Mongo writes.
- The backend exports the current candidate's single strategy chain;
  multi-candidate orchestration derives from the same pure planners.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R35.4
- Role: coding agent

# R34.3 Research Budget Planner

Local WSL implementation. Strategy-planning only: no HTTP requests, crawling,
scanning, Nuclei, fuzzing, exploit validation, browser automation, Mongo
operations, database persistence, LLM calls, embeddings or external network
access. No VM/deployment change. No R29/Money/CVE-scoring changes. The budget
state is never an execution authorization.

## 1. Goal

Determine whether research should continue, pause, or stop:

    "How much further research budget should this candidate receive?"

The planner consumes the R34.1 strategy, R34.2 path, R33.4 learning export
and R32.4 memory export read-only. It never executes research, never acquires
evidence, never contacts a target and never modifies previous planner
semantics.

## 2. Files Changed

- `ai/schemas/research_budget.py` — **new** pydantic schema module (198
  lines): `ResearchBudgetPlan`, closed budget-state/reason/next-step
  vocabularies, bounded validators and sanitizer.
- `ai/knowledge/research_budget_planner.py` — **new** pure module (169 lines,
  `r34-3`): `plan_research_budget()` and the closed `BUDGET_NEXT_STEP` table.
- `backend/asset_cve_matching.py` — **modified additively** (shared R34 diff):
  `summary["research_budget_plan"]` and its `_rule_version` companion.
- `tests/test_research_budget_planner.py` — **new** focused suite (20 tests,
  317 lines).
- `agent-reports/stage-r34-3-budget-planner.md` — this report.

## 3. Architecture Decisions

- **Deterministic precedence** (first match):
  1. `DEFERRED` strategy or `STOP` primary path → `STOP` /
     `DEFERRED_STRATEGY` / `NONE`;
  2. recurring blockers present in memory history → `PAUSE` /
     `REPEATED_BLOCKERS` / `HUMAN_REVIEW`;
  3. HIGH confidence with successful feedback (positive ranking or HIGH
     efficiency) → `CONTINUE` / `HIGH_CONFIDENCE_SUCCESS` / `MORE_EVIDENCE`;
  4. MEDIUM confidence → `LIMITED` / `MEDIUM_CONFIDENCE` / `MORE_ANALYSIS`;
  5. LOW confidence → `LIMITED` / `LOW_CONFIDENCE` / `MORE_ANALYSIS`;
  6. otherwise → `UNKNOWN` / `UNKNOWN_CONFIDENCE` / `UNKNOWN`.
- **Downgrade-first ordering.** Deferred and repeated blockers take precedence
  over high confidence, so a positive signal can never silently override a
  terminal/degrading state.
- **Closed vocabularies.** `budget_state` (5), `reason` (6),
  `allowed_next_step` (5); every state maps to exactly one next step via
  `BUDGET_NEXT_STEP`.
- **Read-only and bounded.** Malformed inputs yield `UNKNOWN` and are never
  silently upgraded.

## 4. Plan Shape

```json
{
  "rule_version": "r34-3",
  "budget_state": "CONTINUE",
  "reason": "HIGH_CONFIDENCE_SUCCESS",
  "allowed_next_step": "MORE_EVIDENCE",
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_budget_planner -q
# combined and full-suite runs shared with R34.1/R34.2/R34.4
```

Results:

```
tests.test_research_budget_planner                OK  (20 tests)
combined R31+R32+R33+R34 + R29/R30 regression    Ran 1308 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2890 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: every budget state, high-confidence-without-success fallback,
deferred/blockers precedence over continue, STOP from path alone, malformed
inputs, closed state→step table, deterministic output, no mutation, JSON
serialization, schema rejections, forced rule version/research_only, no
operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The budget state is an advisory planning label and never an execution
  authorization; `CONTINUE` does not permit any target interaction by itself.
- No numeric budget, time box, cost or payout semantics are introduced; no
  Money Score interaction exists.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R34.3
- Role: coding agent

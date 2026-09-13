# R34.1 Research Strategy Generator

Local WSL implementation. Strategy-planning only: no HTTP requests, crawling,
scanning, Nuclei, fuzzing, exploit validation, browser automation, Mongo
operations, database persistence, LLM calls, embeddings or external network
access. No VM/deployment change. No R29/Money/CVE-scoring changes.

## 1. Goal

Generate a deterministic high-level research strategy from historical
learning:

    "What research strategy should be preferred next?"

The generator consumes the R33.4 learning export and the R32.4 memory export
read-only. It is a historical mapping only: no prediction, probability, ML,
embeddings or LLM. It never executes research and never modifies previous
planner semantics.

## 2. Files Changed

- `ai/schemas/research_strategy.py` — **new** pydantic schema module (289
  lines): `ResearchStrategyPlan`, closed strategy/reason/basis vocabularies,
  imported confidence/blocker vocabularies, bounded validators and sanitizer.
- `ai/knowledge/research_strategy_generator.py` — **new** pure module (285
  lines, `r34-1`): `generate_research_strategy()` and the closed
  `PATTERN_STRATEGY` mapping.
- `backend/asset_cve_matching.py` — **modified additively** (shared R34 diff,
  +53/-0 total): import plus `summary["research_strategy_plan"]` and its
  `_rule_version` companion.
- `tests/test_research_strategy_generator.py` — **new** focused suite (28
  tests, 530 lines) including hermetic backend integration for R34.1-R34.4.
- `agent-reports/stage-r34-1-strategy-generator.md` — this report.

## 3. Architecture Decisions

- **Historical mapping only.** Strategy selection is a first-match precedence
  over closed vocabularies:
  1. no history → `UNKNOWN` / `INSUFFICIENT_HISTORY`;
  2. `IDENTITY_LIMITED` → `IDENTITY_FIRST`;
  3. `TECHNOLOGY_LIMITED` → `TECHNOLOGY_FIRST`;
  4. `SCOPE_LIMITED` → `SCOPE_FIRST`;
  5. `VERSION_LIMITED` → `VERSION_FIRST`;
  6. `HUMAN_RESEARCH` → `HUMAN_REVIEW_FIRST`;
  7. deferred-dominant history (`deferred >= successful` and
     `deferred >= waiting`, `deferred > 0`) → `DEFERRED`;
  8. `NO_PATTERN` with successful feedback (positive ranking or HIGH
     efficiency) → `EVIDENCE_FIRST`;
  9. otherwise → `UNKNOWN` / `UNMAPPED_PATTERN`.
- **Confidence semantics.** Pattern-mapped strategies carry the R33.1 pattern
  confidence; `DEFERRED` is MEDIUM with >=2 deferred records else LOW;
  `EVIDENCE_FIRST` uses pattern confidence when HIGH/MEDIUM else the
  efficiency state; `UNKNOWN` is UNKNOWN.
- **Closed vocabularies.** `strategy_type` (8 values), `strategy_reason` (10),
  `historical_basis` (10); confidence and blockers reuse R31.15 sets.
- **Read-only, bounded, sanitized.** Inputs are never mutated; malformed input
  yields `MALFORMED_INPUT` and is never silently upgraded.

## 4. Plan Shape

```json
{
  "rule_version": "r34-1",
  "strategy_type": "VERSION_FIRST",
  "strategy_reason": "VERSION_LIMITATION_DOMINANT",
  "historical_basis": "VERSION_LIMITATION",
  "confidence_level": "HIGH",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_strategy_generator -q
# combined and full-suite runs shared with R34.2-R34.4 (see R34.4 report)
```

Results:

```
tests.test_research_strategy_generator            OK  (28 tests)
combined R31+R32+R33+R34 + R29/R30 regression    Ran 1308 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2890 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2809-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: every strategy branch (identity/technology/scope/version/human/
deferred single+multi/evidence/unknown/unmapped/no-pattern/no-history),
deterministic output, blockers flow-through, malformed inputs, no mutation,
JSON serialization, closed vocabulary + schema rejections, forced rule
version/research_only, no operational content, and hermetic backend tests for
all four R34 plans.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Strategies are advisory planning labels. `EVIDENCE_FIRST` is a preference,
  never a claim that evidence exists or that a target is vulnerable.
- The backend maps the current candidate's single-record history; callers
  with stored snapshots can drive multi-record strategies through the same
  pure planners.
- No strategy is ever executed and no execution authorization is represented.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R34.1
- Role: coding agent

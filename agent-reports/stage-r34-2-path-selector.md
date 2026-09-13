# R34.2 Research Path Selector

Local WSL implementation. Strategy-planning only: no HTTP requests, crawling,
scanning, Nuclei, fuzzing, exploit validation, browser automation, Mongo
operations, database persistence, LLM calls, embeddings or external network
access. No VM/deployment change. No R29/Money/CVE-scoring changes.

## 1. Goal

Convert the R34.1 research strategy into an ordered research path:

    "In what order should the preferred strategy be approached?"

Every path step is a planning label. The selector never executes research,
never acquires evidence, never contacts a target and never modifies previous
planner semantics.

## 2. Files Changed

- `ai/schemas/research_path.py` — **new** pydantic schema module (234 lines):
  `ResearchPathPlan`, closed path-step/path-reason vocabularies, imported
  confidence vocabulary, bounded validators and sanitizer.
- `ai/knowledge/research_path_selector.py` — **new** pure module (138 lines,
  `r34-2`): `select_research_path()` and the closed `STRATEGY_PATH` mapping.
- `backend/asset_cve_matching.py` — **modified additively** (shared R34 diff):
  `summary["research_path_plan"]` and its `_rule_version` companion.
- `tests/test_research_path_selector.py` — **new** focused suite (15 tests,
  200 lines).
- `agent-reports/stage-r34-2-path-selector.md` — this report.

## 3. Architecture Decisions

- **Deterministic closed mapping** (first match, single table):

  | strategy | selected path | reason |
  |---|---|---|
  | `EVIDENCE_FIRST` | `COLLECT_EVIDENCE`, `REVIEW_HISTORY` | `EVIDENCE_STRATEGY` |
  | `IDENTITY_FIRST` | `IDENTIFY_ASSET`, `COLLECT_EVIDENCE` | `IDENTITY_STRATEGY` |
  | `TECHNOLOGY_FIRST` | `VERIFY_TECHNOLOGY`, `COLLECT_EVIDENCE` | `TECHNOLOGY_STRATEGY` |
  | `VERSION_FIRST` | `VERIFY_VERSION`, `COLLECT_EVIDENCE` | `VERSION_STRATEGY` |
  | `SCOPE_FIRST` | `VERIFY_SCOPE`, `COLLECT_EVIDENCE` | `SCOPE_STRATEGY` |
  | `HUMAN_REVIEW_FIRST` | `HUMAN_REVIEW` | `HUMAN_REVIEW_STRATEGY` |
  | `DEFERRED` | `STOP` | `DEFERRED_STRATEGY` |
  | `UNKNOWN` / malformed | `REVIEW_HISTORY` | `UNKNOWN_STRATEGY` |

- **Closed step vocabulary** (8): `IDENTIFY_ASSET`, `VERIFY_SCOPE`,
  `VERIFY_TECHNOLOGY`, `VERIFY_VERSION`, `COLLECT_EVIDENCE`,
  `REVIEW_HISTORY`, `HUMAN_REVIEW`, `STOP`. Steps are planning labels only;
  no operational action exists.
- **`primary_path` is always the first selected step**; confidence passes
  through from the strategy (invalid → `UNKNOWN`).
- **Read-only and bounded.** Malformed strategies yield the conservative
  `UNKNOWN_STRATEGY` path and are never silently upgraded.

## 4. Plan Shape

```json
{
  "rule_version": "r34-2",
  "selected_path": ["COLLECT_EVIDENCE", "REVIEW_HISTORY"],
  "primary_path": "COLLECT_EVIDENCE",
  "path_reason": "EVIDENCE_STRATEGY",
  "confidence_level": "HIGH",
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_path_selector -q
# combined and full-suite runs shared with R34.1/R34.3/R34.4
```

Results:

```
tests.test_research_path_selector                 OK  (15 tests)
combined R31+R32+R33+R34 + R29/R30 regression    Ran 1308 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2890 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: every strategy → path branch, `DEFERRED` STOP-only, confidence
passthrough/default, malformed and unrecognized strategies, deterministic
output, no mutation, JSON serialization, closed steps/order, schema
rejections, forced rule version/research_only, no operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `HUMAN_REVIEW_FIRST` and `UNKNOWN` path mappings are repository-convention
  additions beyond the explicitly specified mappings; both remain closed and
  deterministic.
- The path never schedules, enqueues or executes anything; it is an ordered
  advisory list only.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R34.2
- Role: coding agent

# R32.2 Research History Aggregator

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change. No persistence layer and no database migration.

## 1. Goal

Aggregate multiple R32.1 research memory snapshots into a deterministic
history plan:

    "What does the accumulated research history look like?"

The aggregator counts existing snapshots only. It never modifies history,
never infers a vulnerability, never recomputes R31 logic and never touches the
R29 queue or the Money Score.

## 2. Files Changed

- `ai/schemas/research_history.py` — **new** pydantic schema module (241
  lines): `ResearchHistoryPlan`, closed imported blocker/improvement/pattern
  vocabularies, bounds, raising validators for direct construction and a
  filtering sanitizer for embedded snapshots.
- `ai/knowledge/research_history_aggregator.py` — **new** pure module (178
  lines, `r32-2`): `count_patterns()`, `aggregate_research_history()` and the
  shared `PATTERN_BY_AREA`-based counting core.
- `backend/asset_cve_matching.py` — **modified additively** (shared R32 diff):
  `summary["research_history_plan"]` and its `_rule_version` companion.
- `tests/test_research_history_aggregator.py` — **new** focused suite (20
  tests, 265 lines).
- `agent-reports/stage-r32-2-history-aggregator.md` — this report.

## 3. Architecture Decisions

- **Aggregate-only.** Inputs are counted; nothing is repaired or rewritten.
  Non-dict and empty entries are skipped deterministically; malformed fields
  degrade to closed fallbacks instead of crashing.
- **Bounded records.** At most `MAX_RECORDS = 256` snapshots are aggregated,
  preserving input order.
- **Closed counting rules.**
  - `total_records` = bounded valid snapshot count.
  - `successful_count` / `deferred_count` / `waiting_count` classify by the
    snapshot `outcome` (`COMPLETED`, `DEFERRED`, `WAITING_FOR_EVIDENCE`).
  - `recurring_blockers` / `recurring_improvement_areas` require at least
    `MIN_RECURRENCE = 2` occurrences (improvement area `NONE` excluded as a
    non-signal), sorted by count descending then code ascending, bounded to 8.
  - `research_patterns` is the full closed pattern distribution
    (`{"pattern", "count"}` entries, bounded to 8) built by the shared
    `count_patterns()` core that R32.3 also uses.
- **Deterministic output.** Fixed sort order; no randomness, timestamps or
  external state.
- **Schema validation.** Direct construction rejects invalid codes and
  negative counts; embedded snapshots are filtered/sanitized.

## 4. Plan Shape

```json
{
  "rule_version": "r32-2",
  "total_records": 5,
  "successful_count": 2,
  "deferred_count": 1,
  "waiting_count": 1,
  "recurring_blockers": ["VERSION_EVIDENCE_MISSING"],
  "recurring_improvement_areas": ["VERSION"],
  "research_patterns": [
    {"pattern": "VERSION_LIMITED", "count": 2},
    {"pattern": "PATH_LIMITED", "count": 1}
  ],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_history_aggregator -q
# combined and full-suite runs shared with R32.1/R32.3/R32.4
```

Results:

```
tests.test_research_history_aggregator           OK  (20 tests)
combined R31+R32 + R29/R30 regression            Ran 1147 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2729 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, empty history (all falsy/malformed shapes),
multi-record counts, recurring blockers/areas, sorted pattern distribution,
`count_patterns()` helper, single-dict input, malformed entries/fields,
record bound, no input mutation, output aliasing, JSON serialization,
schema rejections and bounds, forced rule version/research_only, no
operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Recurrence is a simple count threshold, not a statistical test; the history
  plan is descriptive only.
- History is per-call and stateless: the backend aggregates the single current
  snapshot; callers with stored exports can aggregate arbitrary lists.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R32.2
- Role: coding agent

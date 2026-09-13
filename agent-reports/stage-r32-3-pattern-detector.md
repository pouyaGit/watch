# R32.3 Research Pattern Detector

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change. No persistence layer and no database migration.

## 1. Goal

Detect repeated structural patterns across R32.1 research memory snapshots:

    "Which research limitation pattern keeps repeating across history?"

Deterministic counting only: no ML, no embeddings, no LLM, no probability
semantics. The detector never modifies history and never infers a
vulnerability.

## 2. Files Changed

- `ai/schemas/research_pattern_plan.py` — **new** pydantic schema module (282
  lines): `ResearchPatternPlan`, closed pattern codes, the closed
  `PATTERN_BY_AREA` relation, confidence vocabulary and bounded evidence
  entries.
- `ai/knowledge/research_pattern_detector.py` — **new** pure module (101
  lines, `r32-3`): `confidence_for()` and `detect_research_patterns()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R32 diff):
  `summary["research_pattern_plan"]` and its `_rule_version` companion.
- `tests/test_research_pattern_detector.py` — **new** focused suite (19 tests,
  235 lines).
- `agent-reports/stage-r32-3-pattern-detector.md` — this report.

**Naming note:** the schema is named `research_pattern_plan.py` because
`ai/schemas/research_pattern.py` is an existing, actively used project module
(Phase 2A research-pattern contracts); the path collision was detected and the
original file was restored byte-identical (its 106 tests in
`ai/test_research_pattern.py` and `ai/test_pattern_store.py` pass).

## 3. Architecture Decisions

- **Reuse, not duplication.** The detector consumes the R32.2
  `count_patterns()` core, so history aggregation and pattern detection can
  never disagree about counts.
- **Closed pattern vocabulary.** `IDENTITY_LIMITED`, `VERSION_LIMITED`,
  `SCOPE_LIMITED`, `PATH_LIMITED`, `PARAMETER_LIMITED`, `BEHAVIOR_LIMITED`,
  `TECHNOLOGY_LIMITED`, `HUMAN_RESEARCH`, `PROCESS_LIMITED`, `UNKNOWN`,
  `NO_PATTERN`, derived from the R31.19 improvement-area vocabulary through
  the closed `PATTERN_BY_AREA` relation.
- **Deterministic dominant pattern.** Highest count wins; ties break
  alphabetically by pattern code. Empty/no-signal history yields
  `NO_PATTERN`.
- **Frequency classification, not probability.** Confidence is a closed label
  of the observed frequency: `>=3` HIGH, `2` MEDIUM, `1` LOW, `0` UNKNOWN.
- **Bounded evidence.** The full pattern distribution is retained as
  `{"pattern", "count"}` entries (max 8), sorted by count then code.
- **Read-only.** Inputs are never mutated; malformed entries are skipped.

## 4. Plan Shape

```json
{
  "rule_version": "r32-3",
  "dominant_pattern": "VERSION_LIMITED",
  "frequency": 3,
  "confidence": "HIGH",
  "evidence": [
    {"pattern": "VERSION_LIMITED", "count": 3},
    {"pattern": "PATH_LIMITED", "count": 1}
  ],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_pattern_detector -q
./venv/bin/python -m unittest ai.test_research_pattern ai.test_pattern_store -q
# combined and full-suite runs shared with R32.1/R32.2/R32.4
```

Results:

```
tests.test_research_pattern_detector             OK  (19 tests)
ai.test_research_pattern + ai.test_pattern_store OK  (106 tests, restored
                                                     original schema intact)
combined R31+R32 + R29/R30 regression            Ran 1147 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2729 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, empty history `NO_PATTERN`/UNKNOWN, LOW /
MEDIUM / HIGH confidence thresholds, alphabetical tie-break, sorted evidence
distribution, `NONE` area produces no pattern, malformed entries/areas
ignored, `confidence_for()` helper, no input mutation, JSON serialization,
closed pattern relation, schema rejections (pattern/frequency/confidence/
extra fields), forced rule version/research_only, no operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Detection is limited to the closed improvement-area → pattern relation; it
  is structural counting, not causal analysis.
- Confidence is a frequency label, never a probability of vulnerability.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R32.3
- Role: coding agent

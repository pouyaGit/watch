# R33.1 Research Pattern Intelligence

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, database persistence, LLM call, embedding or
external network access is executed. No VM/deployment change.

## 1. Goal

Convert historical patterns from the R32.4 research memory export into
deterministic research signals:

    "Which historical pattern is the strongest signal for future attention?"

The planner consumes the R32.4 export's embedded R32.3 pattern plan verbatim.
It never executes research, never recomputes R32/R31 logic, never uses
statistics, ML, embeddings or an LLM and never touches the Money Score or R29
queue.

## 2. Files Changed

- `ai/schemas/research_pattern_intelligence.py` — **new** pydantic schema
  module (231 lines): `ResearchPatternIntelligencePlan`, closed pattern
  vocabulary reuse, bounded raising validators and a filtering sanitizer.
- `ai/knowledge/research_pattern_intelligence.py` — **new** pure module (167
  lines, `r33-1`): `pattern_confidence()` and
  `plan_research_pattern_intelligence()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R33 diff,
  +55/-0 total): import plus
  `summary["research_pattern_intelligence_plan"]` and its `_rule_version`
  companion.
- `tests/test_research_pattern_intelligence.py` — **new** focused suite (23
  tests, 457 lines) including hermetic backend integration for R33.1-R33.4.
- `agent-reports/stage-r33-1-pattern-intelligence.md` — this report.

## 3. Architecture Decisions

- **Frequency classification only.** Confidence thresholds are exactly the
  requested ones: `>=5` HIGH, `2-4` MEDIUM, `1` LOW, `0` UNKNOWN. No
  statistical model or probability semantics.
- **Consume-only from R32.4.** Pattern counts are recovered from the embedded
  R32.3 `evidence` distribution; a `dominant_pattern`/`frequency` fallback is
  used when evidence is absent. A direct R32.3 `pattern_plan` override is
  accepted for callers that already hold it.
- **Deterministic ordering.** Patterns sort by frequency descending then code
  ascending; the strongest signal is the first entry with an alphabetical
  tie-break.
- **Closed vocabularies.** Pattern codes come from R32.3
  (`PATTERN_CODES`); confidence reuses the R31.15 closed levels.
- **Bounded, sanitized, read-only.** Max 8 patterns; malformed evidence is
  skipped, never repaired; inputs are never mutated.

## 4. Plan Shape

```json
{
  "rule_version": "r33-1",
  "dominant_patterns": ["PATH_LIMITED", "VERSION_LIMITED"],
  "pattern_scores": [
    {"pattern": "PATH_LIMITED", "frequency": 5, "confidence": "HIGH"},
    {"pattern": "VERSION_LIMITED", "frequency": 2, "confidence": "MEDIUM"}
  ],
  "strongest_signal": "PATH_LIMITED",
  "confidence": "HIGH",
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_pattern_intelligence -q
# combined and full-suite runs shared with R33.2-R33.4 (see R33.4 report)
```

Results:

```
tests.test_research_pattern_intelligence          OK  (23 tests)
combined R31+R32+R33 + R29/R30 regression        Ran 1227 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2809 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2729-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, empty history, single/medium/high frequency
thresholds, multiple-record ordering, dominant fallback, `NO_PATTERN`
exclusion, direct pattern-plan override, malformed evidence skipping,
`pattern_confidence()` helper, no mutation, JSON serialization, closed
vocabulary + schema rejections, forced rule version/research_only, no
operational content, and hermetic backend tests for all four R33 plans.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- Detection remains limited to the closed improvement-area → pattern relation
  defined in R32.3; R33.1 adds frequency classification, not new pattern
  discovery.
- Confidence is a frequency label, never a probability of vulnerability.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R33.1
- Role: coding agent

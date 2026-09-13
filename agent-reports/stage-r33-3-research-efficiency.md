# R33.3 Research Efficiency Intelligence

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, database persistence, LLM call, embedding or
external network access is executed. No VM/deployment change.

## 1. Goal

Measure research process efficiency from historical counts:

    "How efficiently is research progressing across recorded history?"

The planner consumes the R32.2 history plan (or the embedded history section
of the R32.4 export) and emits deterministic ratios and a closed efficiency
state. It is based solely on historical counts: no prediction, no
probability, no ML, no embeddings.

## 2. Files Changed

- `ai/schemas/research_efficiency.py` — **new** pydantic schema module (200
  lines): `ResearchEfficiencyPlan`, closed efficiency-state and
  improvement-signal vocabularies, bounded ratio coercion and sanitizer.
- `ai/knowledge/research_efficiency.py` — **new** pure module (149 lines,
  `r33-3`): `evaluate_research_efficiency()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R33 diff):
  `summary["research_efficiency_plan"]` and its `_rule_version` companion.
- `tests/test_research_efficiency.py` — **new** focused suite (19 tests, 219
  lines).
- `agent-reports/stage-r33-3-research-efficiency.md` — this report.

## 3. Architecture Decisions

- **Count-only ratios.** `successful_ratio = successful/total`,
  `evidence_gap_ratio = waiting/total`,
  `recurring_blocker_ratio = recurring_blockers/total`; all bounded to
  `[0, 1]` and rounded to 4 decimals. Zero history → all ratios 0.
- **Closed state classification.**
  - `UNKNOWN` when there is no history.
  - `HIGH` when `successful_ratio >= 0.5`, there are no recurring blockers and
    `evidence_gap_ratio < 0.5`.
  - `LOW` when `successful_ratio < 0.2` or `evidence_gap_ratio >= 0.5`.
  - `MEDIUM` otherwise.
- **Improvement signal.** `INSUFFICIENT_HISTORY` (no history),
  `REDUCE_RECURRING_BLOCKERS` (blocker density > 0), `CLOSE_EVIDENCE_GAPS`
  (gap ratio >= 0.5), `INCREASE_SUCCESSFUL_RESEARCH` (success ratio < 0.5),
  else `NONE` — first match wins, fixed order.
- **Read-only and bounded.** Inputs are never mutated; malformed counts
  degrade to zero; embedded snapshot sanitizer clamps ratios.
- **No prediction.** The plan describes recorded history only.

## 4. Plan Shape

```json
{
  "rule_version": "r33-3",
  "efficiency_state": "MEDIUM",
  "successful_ratio": 0.25,
  "evidence_gap_ratio": 0.0,
  "recurring_blocker_ratio": 0.0,
  "improvement_signal": "INCREASE_SUCCESSFUL_RESEARCH",
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_efficiency -q
# combined and full-suite runs shared with R33.1/R33.2/R33.4
```

Results:

```
tests.test_research_efficiency                    OK  (19 tests)
combined R31+R32+R33 + R29/R30 regression        Ran 1227 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2809 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, empty history, HIGH/MEDIUM/LOW states,
evidence-gap-driven LOW, recurring-blocker signal and HIGH suppression,
bounded/rounded ratios, R32.4 memory-export fallback, malformed count
degradation, no mutation, JSON serialization, schema ratio clamping,
closed-vocabulary rejections, forced rule version/research_only, no
operational content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The ratios are descriptive of recorded history only; they are not
  predictions and never feed the Money Score or R29.
- Efficiency thresholds are fixed constants; there is no calibration loop.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R33.3
- Role: coding agent

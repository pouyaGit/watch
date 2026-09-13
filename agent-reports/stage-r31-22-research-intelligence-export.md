# R31.22 Research Intelligence Export

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Create the final deterministic export object over the R31.20 research
intelligence summary and the R31.21 consistency validation:

    "Is the finalized R31 research intelligence ready for downstream
     consumers, and what does it contain?"

The exporter packages existing plans only. It never executes research, never
recomputes any previous stage, never inspects CVE data, never calculates the
Money Score and never modifies the R29 queue.

## 2. Files Changed

- `ai/schemas/research_intelligence_export.py` — **new** pydantic schema
  module (197 lines): `ResearchIntelligenceExportPlan`, closed export-status
  and generated-section vocabularies, bounds and sanitizers for the embedded
  summary/validation snapshots.
- `ai/knowledge/research_intelligence_exporter.py` — **new** pure module (127
  lines, `r31-22`): `export_research_intelligence()`.
- `backend/asset_cve_matching.py` — **modified additively**:
  `summary["research_intelligence_export_plan"]` and its `_rule_version`
  companion. No existing field changed.
- `tests/test_research_intelligence_export.py` — **new** focused suite (26
  tests, 333 lines).
- `agent-reports/stage-r31-22-research-intelligence-export.md` — this report.

## 3. Architecture Decisions

- **Validation-gated readiness.** `READY` only when the R31.21
  `validation_status` is `VALID`; `INVALID` yields `NOT_READY`;
  `UNKNOWN`/missing yields `UNKNOWN`. `ready` is `True` only for `READY`.
- **Deterministic sections.** `generated_sections` lists the included
  sections in fixed order (`RESEARCH_INTELLIGENCE_SUMMARY`,
  `CONSISTENCY_VALIDATION`) based on presence of the two inputs; the closed
  vocabulary is enforced and duplicates/unknown codes are filtered.
- **Schema-validated, bounded, sanitized.** `extra="forbid"`, fixed
  `r31-22`, forced `research_only=True`; the embedded summary and validation
  snapshots reuse the R31.20/R31.21 sanitizers with fixed key sets.
- **Consume-only.** The exporter reads the two plans verbatim and never
  recomputes them.

## 4. Output Shape

```json
{
  "rule_version": "r31-22",
  "ready": true,
  "status": "READY",
  "summary": { "...bounded R31.20 snapshot..." },
  "validation": { "...bounded R31.21 snapshot..." },
  "generated_sections": [
    "RESEARCH_INTELLIGENCE_SUMMARY",
    "CONSISTENCY_VALIDATION"
  ],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_intelligence_export -q
# combined regression and full suite as in R31.20
```

Results:

```
tests.test_research_intelligence_export             OK  (22 tests)
combined R31.10-R31.22 + R29/R30/R31 regression     Ran 1066 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)             Ran 2648 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile                                          OK
git diff --check                                    clean
```

Coverage: READY for all valid chains (including the deferred-but-consistent
chain), INVALID→`NOT_READY`, UNKNOWN/missing→`UNKNOWN`, section listing for
summary-only/validation-only/both/none, lowercase status normalization,
malformed inputs, determinism, key-order independence, no input mutation,
snapshot aliasing, closed vocabulary + schema rejections, section filtering
and bounds, JSON serialization, research_only, no operational attack content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `READY` means "the chain is internally consistent and packaged", not "the
  candidate is vulnerable" or "research succeeded" — a consistently deferred
  candidate also exports `READY`.
- The export is a pure in-memory dict attached to the candidate summary; it
  is not persisted, published, notified or wired into the R29 queue or any
  downstream consumer by this stage.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.22
- Role: coding agent

# R31.20 Research Intelligence Summary Planner

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change.

## 1. Goal

Aggregate the read-only R31.13-R31.19 evidence pipeline plans into a single
deterministic research intelligence summary for one Asset<->CVE candidate:

    "What is the final research intelligence status for this candidate?"

The planner aggregates existing plans only. It never executes research, never
recomputes any previous stage, never inspects CVE data, never calculates the
Money Score and never modifies the R29 queue or prior planner semantics.

## 2. Files Changed

- `ai/schemas/research_intelligence_summary.py` — **new** pydantic schema
  module (377 lines): `ResearchIntelligenceSummaryPlan`, closed
  research-status/summary-category vocabularies, imported evidence-status/
  final-state/confidence/feedback/improvement/blocker vocabularies, bounds
  and sanitizers for the embedded R31.18/R31.17 snapshots and its own
  snapshot.
- `ai/knowledge/research_intelligence_summary_planner.py` — **new** pure
  module (262 lines, `r31-20`): `OUTCOME_SUMMARY` table and
  `plan_research_intelligence_summary()`.
- `backend/asset_cve_matching.py` — **modified additively**: import plus
  `summary["research_intelligence_summary_plan"]` and its
  `_rule_version` companion (shared backend diff with R31.21/R31.22, +57/-0
  total). No existing field renamed, removed or changed.
- `tests/test_research_intelligence_summary_planner.py` — **new** focused
  suite (27 tests, 787 lines) including the hermetic backend integration
  tests for all three final stages.
- `agent-reports/stage-r31-20-research-intelligence-summary.md` — this report.

## 3. Architecture Decisions

- **Consume-only aggregation.** The R31.18 outcome drives
  `research_status`/`summary_category`; the remaining fields are consumed
  verbatim from R31.15 (`evidence_status`), R31.17 (`final_state`,
  `confidence_level`), R31.19 (`feedback_signal`, `improvement_area`) with
  closed-vocabulary fallbacks (`UNKNOWN`/`NONE`). Nothing is recomputed.
- **Vocabulary ownership.** Only `research_status` and `summary_category` are
  new closed vocabularies. `evidence_status` reuses the R31.15 evidence
  completeness set, `final_state` reuses the R31.17 lifecycle set, and
  `confidence_level`/`feedback_signal`/`improvement_area`/`blockers` reuse the
  R31.15/R31.19 sets.
- **Schema-validated, bounded, sanitized.** The schema rejects unknown fields
  (`extra="forbid"`), fixes `rule_version` to `r31-20`, forces
  `research_only=True`, bounds lists/strings and sanitizes all embedded
  snapshots (reusing the R31.17/R31.18 sanitizers).
- **Deterministic and conservative.** Unrecognized/missing outcomes yield
  `UNKNOWN`/`INVALID`; repeated output is byte-identical.

## 4. Deterministic Mapping

| R31.18 outcome | research_status | summary_category |
|---|---|---|
| `COMPLETED` | `COMPLETE` | `SUCCESSFUL_RESEARCH` |
| `IN_PROGRESS` | `ACTIVE` | `ONGOING_RESEARCH` |
| `WAITING_FOR_EVIDENCE` | `WAITING` | `EVIDENCE_REQUIRED` |
| `DEFERRED` | `DEFERRED` | `RESEARCH_PAUSED` |
| `UNKNOWN` / unrecognized / missing | `UNKNOWN` | `INVALID` |

Observed end-to-end values: completed → `COMPLETE`/evidence `COMPLETE`;
in-progress → `ACTIVE`/`PARTIAL`; waiting → `WAITING`/`MINIMAL`;
deferred → `DEFERRED`/`NONE`; malformed → `UNKNOWN`/`NONE`.

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_intelligence_summary_planner -q
./venv/bin/python -m unittest tests.test_research_intelligence_summary_planner \
    tests.test_research_consistency_validator tests.test_research_intelligence_export \
    <R31.13-R31.19 + R29/R30/R31 regression modules> -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile <new modules> backend/asset_cve_matching.py
git diff --check
```

Results:

```
tests.test_research_intelligence_summary_planner   OK  (27 tests)
combined R31.10-R31.22 + R29/R30/R31 regression    Ran 1066 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)            Ran 2648 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2574-test baseline; no new failure
py_compile                                         OK
git diff --check                                   clean
```

Coverage: deterministic output, all five outcome paths (real engine chain and
forged), malformed/unrecognized/lowercase outcomes, evidence/final-state/
confidence fallbacks, closed-vocabulary output and schema rejections, fixed
rule version, JSON serialization, no input mutation, snapshot aliasing,
research_only, no operational attack content, plus hermetic backend tests
(`COMPLETE`/`SUCCESSFUL_RESEARCH` immediate fixture, deferred blocked fixture,
additive fields/rule versions, Money Score canary).

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- `evidence_status` reuses the R31.15 completeness set (no `UNKNOWN` member);
  malformed confidence input therefore reports `NONE` rather than `UNKNOWN`.
- The summary aggregates one candidate; it does not rank candidates, persist
  history or feed the R29 queue.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.20
- Role: coding agent

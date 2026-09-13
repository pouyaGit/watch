# R33.2 Historical Candidate Ranking

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, database persistence, LLM call, embedding or
external network access is executed. No VM/deployment change.

## 1. Goal

Rank research candidates using historical memory signals:

    "Which candidate deserves higher research attention based on history?"

The planner groups R32.1-style memory records by candidate identity and emits
a deterministic score with closed historical signals. It never executes
research, never recomputes R32/R31 logic, never uses or modifies the Money
Score and never modifies the R29 queue.

## 2. Files Changed

- `ai/schemas/historical_candidate_ranking.py` — **new** pydantic schema
  module (269 lines): `HistoricalCandidateRankingPlan`, closed signal and
  ranking-reason vocabularies, bounded raising validators and a filtering
  sanitizer.
- `ai/knowledge/historical_candidate_ranking.py` — **new** pure module (268
  lines, `r33-2`): `rank_historical_candidates()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R33 diff):
  `summary["historical_candidate_ranking_plan"]` and its `_rule_version`
  companion.
- `tests/test_historical_candidate_ranking.py` — **new** focused suite (20
  tests, 297 lines).
- `agent-reports/stage-r33-2-candidate-ranking.md` — this report.

## 3. Architecture Decisions

- **Deterministic factor scoring only.** The score is a bounded sum of
  documented deltas; no probability, ML, embeddings or LLM.
  - Positive: `HISTORICAL_SUCCESS` +4 (any COMPLETED record),
    `REPEATED_SUCCESS` +2 (>=2 COMPLETED), `TECHNOLOGY_SUCCESS` +1 (latest
    improvement area is TECHNOLOGY with a success), `EVIDENCE_AVAILABILITY`
    +1 (any IN_PROGRESS/WAITING record).
  - Negative: `REPEATED_DEFER` -3 (>=2 DEFERRED), `REPEATED_MISSING_EVIDENCE`
    -2 (>=2 WAITING_FOR_EVIDENCE), `UNRESOLVED_BLOCKERS` -1 per recurring
    blocker (max -3).
  - Score clamped to `[0, 10]`.
- **Candidate grouping.** Records group by the caller-supplied
  `candidate_identity` (missing → `UNSPECIFIED`); records are bounded
  (`MAX_RECORDS = 256`, `MAX_CANDIDATES = 64`).
- **Stable ranking order.** Sort by score descending, successful count
  descending, then identity ascending; input order does not affect output.
- **Ranking reason.** `NO_HISTORY` (no records), `SINGLE_CANDIDATE`, or
  `HISTORICAL_SCORE`.
- **Read-only.** Inputs are never mutated; malformed records are skipped.

## 4. Plan Shape

```json
{
  "rule_version": "r33-2",
  "candidate_scores": [
    {"candidate_identity": "rc-a", "score": 6, "records": 2,
     "signals": ["HISTORICAL_SUCCESS", "REPEATED_SUCCESS"]}
  ],
  "ranking_reason": "SINGLE_CANDIDATE",
  "historical_signals": ["HISTORICAL_SUCCESS", "REPEATED_SUCCESS"],
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_historical_candidate_ranking -q
# combined and full-suite runs shared with R33.1/R33.3/R33.4
```

Results:

```
tests.test_historical_candidate_ranking           OK  (20 tests)
combined R31+R32+R33 + R29/R30 regression        Ran 1227 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2809 tests
    37 failures + 3 errors — failure set byte-identical to baseline
py_compile / git diff --check                    OK / clean
```

Coverage: deterministic output, empty history, single/multiple candidate
reasons, ranking order stability under input reversal, every positive and
negative signal, score clamping, grouping/record counts, missing identity,
malformed record skipping, no mutation, JSON serialization, closed vocabulary
+ schema rejections, forced rule version/research_only, no operational
content.

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The backend currently ranks the single current candidate snapshot; callers
  holding multiple snapshots get full historical ranking with no extra work.
- The score is an internal ordering signal only; it is not the Money Score,
  not a vulnerability probability and never feeds R29.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R33.2
- Role: coding agent

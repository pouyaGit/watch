# R32.1 Research Memory Snapshot

Local WSL implementation. Plan-only stage: no evidence acquisition, HTTP
request, crawl, scan, Nuclei run, fuzz, browser automation, exploit
validation, Mongo operation, LLM call or external network access is executed.
No VM/deployment change. No persistence layer and no database migration.

## 1. Goal

Represent one immutable historical research record derived from an R31.22
research intelligence export:

    "What was the research state at this point in history?"

The snapshot builder consumes the R31.22 export verbatim. It never recomputes
R31 logic, never infers a vulnerability, never modifies the R29 queue or the
Money Score and never reads a clock.

## 2. Files Changed

- `ai/schemas/research_memory_snapshot.py` — **new** pydantic schema module
  (283 lines): frozen `ResearchMemorySnapshot` model, closed imported
  vocabularies, bounded sanitizers for the source-export snapshot and the
  snapshot itself.
- `ai/knowledge/research_memory_snapshot.py` — **new** pure module (151
  lines, `r32-1`): `STATUS_TO_OUTCOME` decode and
  `create_research_memory_snapshot()`.
- `backend/asset_cve_matching.py` — **modified additively** (shared R32 diff,
  +65/-0 total): import plus `summary["research_memory_snapshot"]` and its
  `_rule_version` companion, built with a new privacy-preserving
  `_candidate_identity()` helper (`rc-<sha256[:16]>`).
- `tests/test_research_memory_snapshot.py` — **new** focused suite (23 tests,
  529 lines) including hermetic backend integration for R32.1-R32.4.
- `agent-reports/stage-r32-1-memory-snapshot.md` — this report.

## 3. Architecture Decisions

- **Deterministic, clock-free timestamps.** `timestamp_reference` is an
  explicit caller-supplied reference; absent input yields the fixed
  `UNSPECIFIED` label. No `time`/`datetime` call exists.
- **Privacy-preserving candidate identity.** The backend hashes the internal
  CVE id with the existing asset identity into `rc-<sha256[:16]>`, so raw
  targets never enter memory records. The planner itself accepts any
  caller-supplied identity.
- **Immutable model.** The pydantic model is `frozen=True` with
  `extra="forbid"`; the planner returns a fresh dict projection.
- **Closed decode, not recomputation.** `STATUS_TO_OUTCOME` is the inverse of
  the R31.20 `OUTCOME_SUMMARY` table (reused by import), so the outcome is a
  1:1 decode of the already-aggregated `research_status`.
- **Conservative defaults.** Missing/malformed exports yield
  `UNKNOWN`/`UNSPECIFIED` values; a bounded sanitized `source_export` snapshot
  is retained for traceability.
- **Plan-only.** No acquisition, no execution, no persistence.

## 4. Record Shape

```json
{
  "rule_version": "r32-1",
  "candidate_identity": "rc-<sha256[:16]>",
  "research_status": "WAITING",
  "outcome": "WAITING_FOR_EVIDENCE",
  "confidence_level": "LOW",
  "feedback_signal": "EVIDENCE_GAP_SIGNAL",
  "improvement_area": "VERSION",
  "blockers": ["VERSION_EVIDENCE_MISSING"],
  "timestamp_reference": "UNSPECIFIED",
  "source_export": { "...bounded R31.22 snapshot..." },
  "research_only": true
}
```

## 5. Tests Executed

```bash
./venv/bin/python -m unittest tests.test_research_memory_snapshot -q
# combined and full-suite runs shared with R32.2-R32.4 (see R32.4 report)
```

Results:

```
tests.test_research_memory_snapshot              OK  (23 tests)
combined R31+R32 + R29/R30 regression            Ran 1147 tests
    3 failures — pre-existing R29 money-score corpus drift (53 vs 50)
complete project suite (discover tests)          Ran 2729 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change 2648-test baseline; no new failure
py_compile / git diff --check                    OK / clean
```

Coverage: completed/in-progress/deferred exports, missing/malformed exports,
status→outcome table closure, deterministic output, no input mutation,
snapshot aliasing, privacy redaction, frozen schema (assignment rejected),
closed-vocabulary rejections, forced rule version/research_only, JSON
serialization, no operational content, and hermetic backend tests for all
four R32 plans (rule versions, privacy-preserving identity, immediate/blocked
fixtures, Money Score canary).

## 6. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests.
- The backend wires one snapshot per candidate per projection run; multi-record
  history is available to callers that hold multiple exports. There is no
  persistence layer by design.
- `timestamp_reference` is a caller-supplied label, not a real clock value.
- Advisory only; never executed.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R32.1
- Role: coding agent

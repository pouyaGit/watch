# AEC-1 EPIC6 — Autonomous Research Execution Bridge v1

**Status:** READY TO PUSH (pending operator approval)
**Branch:** `agent/daily-development`
**New tests:** 453 (hard criterion: ≥350) — all GREEN
**Full AEC regression:** 1,421/1,421 OK
**Production:** untouched (`73d754a`, baseline recorded)

## Purpose

EPIC6 completes the AEC-1 research loop: it turns authorization-approved
research candidates into executed, evidence-bearing, replayable research runs —
while keeping every live-network capability behind the existing Authorization
Gate and the verification chain frozen. The epic is deliberately **offline**:
it mints `AUTHORIZED_OBSERVATION_REQUEST` data-only artifacts inside the
runtime; nothing in the new packages opens a socket, issues HTTP, or claims a
production finding.

## Architecture

```
fixture/watch records
        │ aec/research/sources.normalize_record   (ORIGIN_MODES → SOURCE_MODES)
        ▼
coordinator pipeline (EPIC5) → ResearchRun (cases, plans, review)
        │ aec/runtime/loop.run_execution
        ▼
ResearchJob (13 states, fail-closed transition table)
        ▼
specialists.queue   →  aec/specialists (5 roles, closed verdict vocabulary)
        ▼
authorization gate (EPIC5, unchanged): GRANTED ⇔ proceed  |  MISSING ⇒
        WAITING_AUTHORIZATION  DENIED ⇒ BLOCKED  EXPIRED ⇒ EXPIRED
        ▼
ResearchExecutor.submit_plan → AUTHORIZED_OBSERVATION_REQUEST (obsreq-…19)
        ▼
evidence_bridge.ingest → EvidenceArtifactDraft (provenance + missing_fields)
        ▼
review boundary (EPIC5) → REVIEW_REQUIRED / blocked_reasons / failures
        ▼
ExecutionRun.to_dict → replay.kernel.replay (byte-identical) via captured context
```

## Components (all new unless noted)

- `aec/research/sources.py` — candidate normalization; provenance synthesis
  (`source_id`, `source_mode`); closed `ORIGIN_MODES`/`SOURCE_MODES`
  vocabulary (`REAL_WATCH_DATA` vs `OFFLINE_FIXTURE`).
- `aec/execution/` — `ResearchExecutor` (Part 4): verifies the gate decision
  and an explicit authorization state, then mints a data-only
  `AUTHORIZED_OBSERVATION_REQUEST`; refusal codes and retryable classes are
  closed vocabularies (`REFUSAL_CODES`, `RETRYABLE`).
- `aec/evidence_bridge/` — `ingest()`: turns an observation result into an
  `EvidenceArtifactDraft` with provenance and `missing_fields`; redaction via
  the existing `scrub_text`.
- `aec/specialists/registry.py` — 5 deterministic profiles (*nuclei-general*,
  *xss-general*, *authz-general*, *idor-general*, *technology-researcher*);
  `analysis.py` produces only `NO_SIGNAL` / `INSUFFICIENT_EVIDENCE` /
  `REQUIRES_OBSERVATION` / `POTENTIAL` / `REVIEW_REQUIRED` — **nothing may
  upgrade to CONFIRMED**.
- `aec/specialists/queue.py` — deterministic queue ordering
  `(attempts, band_priority, case_id)`; refusals stored as raw codes; queued
  excludes refused and duplicate_of.
- `aec/runtime/jobs.py` — 13-state `ResearchJob` with a fail-closed
  transition table: DISCOVERED → QUEUED → ASSIGNED → WAITING_AUTHORIZATION →
  READY_FOR_OBSERVATION → OBSERVATION_RUNNING → EVIDENCE_PENDING →
  ANALYSIS_PENDING → REVIEW_REQUIRED → COMPLETED, plus BLOCKED / FAILED /
  EXPIRED. Every transition records prev/next/reason/actor/tick; invalid
  moves raise `TransitionRefusal` (no silent state jumps).
- `aec/runtime/run.py` — `ExecutionRun` (frozen): jobs, cases, review records,
  blocked reasons, evidence, context snapshot; machine + human summaries.
- `aec/runtime/loop.py` — `run_execution(records, origin, authz, …)`:
  normalize → coordinator research run → jobs → authorization boundary →
  evidence ingestion → review mapping; counts (`blocked_count`, failures,
  etc.) drive the summary.
- `aec/runtime/recovery.py` — closed `RETRYABLE_KINDS` (TIMEOUT,
  INGESTION_ERROR, EXECUTION_REFUSAL) driving bounded requeue.
- `aec/replay/` — `identity.py`: content hash over the full deterministic
  input set (64-char identity); `kernel.py`: `serialize_run` /
  `validate` / `replay` reruns from the run's captured context, producing a
  **byte-identical** document.

## Authorization boundary (unchanged, enforced)

The gate is the only admission check. The loop consults the authorization
map: **MISSING → WAITING_AUTHORIZATION** (never default-open), **DENIED →
BLOCKED**, **EXPIRED → EXPIRED**, **GRANTED(+expiry) → proceed**. Missing
capability also blocks. The executor asserts the gate decision again before
minting a request. AST invariants prove the six new packages import no
`socket/ssl/http/urllib/requests/subprocess/ai/backend` module and contain
no verdict-vocabulary literals (guard module exempt as the enforcer).

## Tests (453 new, all GREEN)

| Module | Tests |
|---|---|
| test_aec_sources | 33 |
| test_aec_research_sources | 42 |
| test_aec_jobs | 37 |
| test_aec_runtime_jobs | 27 |
| test_aec_execution | 31 |
| test_aec_executor | 36 |
| test_aec_specialists | 35 |
| test_aec_specialist_queue | 19 |
| test_aec_evidence_bridge | 30 |
| test_aec_research_guard | 13 |
| test_aec_runtime_loop | 32 |
| test_aec_replay | 14 |
| test_aec_failure_recovery | 21 |
| test_aec_research_loop | 17 |
| test_aec_router_execution | 17 |
| test_aec_invariants | 12 |
| test_aec_execution_supplement | 30 |
| **Total** | **453** |

Verification run:
`unittest discover -s tests -p "test_aec_*.py"` → **1,421 tests OK**
(968 pre-EPIC6 + 453 new). Guards: `git diff --check` clean;
`scripts/check-aec-readonly.sh` → READ-ONLY VERIFIED; 7 frozen files
byte-identical to production. Delivery `check.sh` gated after commit.

## Operational notes for the operator

- **Nothing here enables live traffic.** Offline by design: requests are
  data-only artifacts; no sockets, no HTTP clients, no DNS, no target contact.
- **No production findings are fabricated.** Verdict vocabulary is closed and
  nothing reaches CONFIRMED offline.
- **REVIEW_REQUIRED is reachable** for jobs that complete evidence ingestion;
  BLOCKED/WAITING_AUTHORIZATION/EXPIRED pin the fail-closed posture per authz.
- Replay determinism is pinned: `serialize_run` output is byte-identical
  across runs of the same captured context.

## Reproduce

```bash
cd /opt/watch/.worktrees/watch-agent
PYTHONDONTWRITEBYTECODE=1 /opt/watch/venv/bin/python3 -m unittest \
  tests.test_aec_sources tests.test_aec_research_sources tests.test_aec_jobs \
  tests.test_aec_runtime_jobs tests.test_aec_execution tests.test_aec_executor \
  tests.test_aec_specialists tests.test_aec_specialist_queue \
  tests.test_aec_evidence_bridge tests.test_aec_research_guard \
  tests.test_aec_runtime_loop tests.test_aec_replay \
  tests.test_aec_failure_recovery tests.test_aec_research_loop \
  tests.test_aec_router_execution tests.test_aec_invariants \
  tests.test_aec_execution_supplement
bash scripts/check-aec-readonly.sh
bash scripts/watch-agent/delivery/check.sh
```
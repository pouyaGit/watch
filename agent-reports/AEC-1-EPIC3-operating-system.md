# AEC-1 EPIC 3 — Autonomous Research Operating System (offline)

## Architecture

```
CaseRef ──► orchestrator/intake (NEW) ──► mark_selected (SELECTED)
    ──► attach_plan (PLANNED) ──► record_authorized (AUTHORIZED_PLAN)
    ──► route_evidence (WAITING/PARTIAL/READY) ──► submit_review (REVIEW_REQUIRED)
                    │                       │
                    ▼                       ▼
            queue/priority          memory/store ──► patterns
      (rubric scores, snapshots,          │
       bounded retries)                   ▼
                              routers/aec (GET cases/queue/status)
```

New: `aec/orchestrator/` (models, lifecycle), `aec/queue/` (models,
priority), `aec/memory/` (models, store), `backend/routers/aec.py`.
Supporting change: S1 import guard scans `aec/` recursively.

## Data flow

Records flow one hop at a time with identity binding (plan/gap case ids
must match; gate decisions must ALLOW and name the attached plan). Queue
scores `risk + state − cost` with pinned weights and content-hash
snapshots. Memory scrubs every detail through the T2 scrubber at write
time. Router handlers project fixed field sets over explicitly supplied
data — the module is inert until mounted.

## State machines

- Lifecycle: NEW → SELECTED → PLANNED → AUTHORIZED_PLAN →
  WAITING_EVIDENCE → EVIDENCE_PARTIAL → EVIDENCE_READY → REVIEW_REQUIRED.
  EVIDENCE_PARTIAL extends the brief's list: the evidence layer reports
  three gap states and the record must hold the middle one. Order follows
  the mission flow (planning before authorization).
- Evidence lifecycle unchanged (EPIC 2); the orchestrator routes its
  states forward-only, never backward.

## Design decisions

- **Mounting deferred.** The router ships wired but `api.py` is
  untouched (pre-existing worktree dirt there is the operator's dashboard
  commit, not mine): exposing endpoints changes the serving surface and
  belongs to an explicit operator decision. One-line mount documented in
  the module docstring.
- **Layer direction downward only.** Lower layers never import
  orchestrator/queue/memory (test-enforced); queue/memory attach to
  records, never the reverse.
- **Denial-suite layering.** Router tests run outside the socket-denial
  suite: importing the backend package touches sockets at import, so the
  denial suite covers `aec/` only. One integration test initially crossed
  that boundary and failed under denial — replaced with a contract pin
  (record carries exactly the allowlisted keys) plus a router-side render
  test that runs normally.
- **Quality stays numeric.** No grades, bands, or severity-adjacent
  words near assessment JSON (test-enforced); memory secrets are
  scrubbed, never stored.

## Future execution boundary

Track B (`live_deps.py`, `observation_lane.py`) remains uncreated. When
it lands, it consumes ALLOW decisions + READY states + queue heads; this
epic changes nothing about that gate — READY here still means
draft-coverage only.

## Verification

159 new tests (46 orchestrator, 43 queue, 31 memory, 18 router, 14
integration, plus guard extensions), RED first (51→158 errors, packages
absent), GREEN after implementation with corrections: one code bug
(stray `del`), test-side fixes (local STATES shadow, scrubber pattern
shapes needing full header/40+ chars, fragment-assembled fixtures,
import paths, denial boundary). Full AEC: 464/464. `git diff --check`
clean, read-only VERIFIED, frozen files identical, diff guard PASS
post-commit.

## Delivery

Commit `feat(aec): add autonomous research operating system`; auto-push;
promotion request; await APPROVE. No main merge without it.

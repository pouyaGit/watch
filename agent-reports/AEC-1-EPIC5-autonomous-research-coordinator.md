# AEC-1 EPIC 5 — Autonomous Security Research Coordinator v1 (offline)

## Architecture

```
fixtures.CANDIDATES (21 committed records)
        │
        ▼
coordinator/pipeline.run_research
  adapt (surface) → refusal? record failure, continue
  recall (memory/connect) → researched? skip PRIOR_RESEARCH
  prioritize (intelligence) + assign (assignment)
  staff (coordinator/specialists, 5 roles)
  case (CaseRef + EvidenceGap) → intake → select (orchestrator)
  draft (case_compiler) → refusal? INVALID_DRAFT/MISSING_GAP + review
  plan (observation_plan) → refusal? INVALID_PLAN + review
  attach → gate (authorization_gate)
      REFUSE → GATE_REFUSAL + review AUTHORIZATION_REFUSED
      ALLOW → authorize → route initial gap (WAITING_EVIDENCE)
              → review EVIDENCE_INCOMPLETE
  queue snapshot over all selected cases
  ResearchRun (frozen, content-hash run_id)
        │
        ├── review/queue → ReviewItem per terminal case
        ├── reporting/report → ResearchReport (6 sections)
        └── backend/routers/aec → /research-runs /research-queue
                                   /review /research-summary
```

New: `aec/coordinator/` (models, pipeline, specialists, fixtures),
`aec/review/` (models, queue), `aec/reporting/` (models, report).
Extended: `backend/routers/aec.py` (+4 builders, +4 routes,
+technology-researcher role). No existing component modified.

## Complete lifecycle

SELECTED → PLANNED → AUTHORIZED_PLAN → WAITING_EVIDENCE per case, each
hop recording WHY in `state_reasons` (selection order, plan id + step
count, gate outcome, evidence outstanding). Cases that fail compilation
stay SELECTED with the reason in failures + review — never forced
forward. REVIEW_REQUIRED is unreachable offline by design (it needs
EVIDENCE_READY, which needs artifacts, which need live observation);
the review queue is the offline review surface.

## Failure model

Ten closed kinds; per-candidate isolation (one failure never stops the
run); skips (duplicate, prior research) recorded separately from
failures. Defense in depth: compiler gap codes map to MISSING_GAP,
unexpected errors map by stage (MEMORY/QUEUE), serialization validated.
Fault-injection tests cover PLAN/GATE/MEMORY/QUEUE paths with mocks.

## Replay model

run_id = `run-` + sha256(canonical input)[:12]; all ordering
deterministic (sorted memories, ranked queue, case-id-ordered review);
stable compact JSON everywhere. Same snapshot → byte-identical bytes.

## Review boundary

Review reasons/actions closed; items carry full offline context;
recommended action derived deterministically. Items are triage records
— the codebase bans conclusion vocabulary (CONFIRMED/VULNERABLE/
EXPLOITABLE/FINDING/VERDICT/…) in all three new packages by scan.

## Simulation result (21 candidates)

18 cases (17 ALLOW → WAITING_EVIDENCE, 1 POST stays SELECTED),
1 duplicate skip, 3 failures (INVALID_DRAFT/UNSUPPORTED_CATEGORY/
MALFORMED), 17 plans, 18 review items, 4 specialists exercised
(technology/input/authorization/server; generalist covered in unit
tests), queue total 18. Replay byte-identical.

## Verification

302 new tests (86 coordinator, 58 review, 43 reporting, 63 replay,
52 router), RED first (12 errors, packages absent), GREEN after
implementation with corrections: two impl bugs (snapshot variable
collision, duplicate state annotation), test-side pins (authorizations
shape, POST-case expectations, hex-digest invariant, route counts).
Full AEC: 968/968. `git diff --check` clean, read-only VERIFIED,
frozen files identical.

## Delivery

Commit `feat(aec): add autonomous research coordinator`; auto-push;
promotion request; await APPROVE. No main merge without it.

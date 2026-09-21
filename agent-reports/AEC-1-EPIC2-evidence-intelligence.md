# AEC-1 EPIC 2 — Evidence Intelligence Layer (offline)

## Architecture

```
T5 ObservationPlanDraft ──► evidence/builder ──► EvidenceArtifactDraft(s)
                                                            │
                              ┌─────────────────────────────┼──────────────┐
                              ▼                             ▼              ▼
                     evidence/quality              evidence/state_machine
                   (completeness 0..1)          (WAITING → PARTIAL → READY)
                              │                             │
                              └─────────────┬───────────────┘
                                            ▼
                              evidence/serialization (canonical JSON)
```

New package `aec/evidence/`: `models.py` (frozen drafts, assessments,
gap states), `builder.py` (plan steps → drafts, kinds mirror purposes),
`quality.py` (completeness/consistency/reproducibility/provenance +
mean overall), `state_machine.py` (`advance` from union coverage +
explicit `transition` validator), `serialization.py` (canonical dumps +
bundle). One supporting change: the S1 import guard now scans `aec/`
recursively (`rglob`), so the new subpackage is covered by the same AST
prohibitions as top-level modules.

## Data flow

Plan steps → one draft each (`plan-id:sNN:kind`, refs = step ids,
collected = plan-known dimension names, missing = targeted record type)
→ per-draft numeric assessment → union coverage advances the case gap
state → canonical bundle bytes. Every stage is a pure function of its
input; inputs are never mutated; all outputs frozen.

## State machine

`WAITING_EVIDENCE` (no coverage) → `EVIDENCE_PARTIAL` (record opened,
values outstanding) → `EVIDENCE_READY` (union coverage 1.0). `advance`
never regresses and only moves toward computed coverage; `transition`
allows staying or +1 step and refuses skips, backward moves, and unknown
names. History records each move. READY is unreachable from builder
drafts alone — observed values arrive only in Track B.

## Design decisions

- **Drafts describe shapes, never values.** `collected_fields` names
  known dimensions; nothing observed exists at this layer.
- **Quality is numeric and target-blind.** No grades, no bands, no words
  like high/medium/low anywhere near assessment JSON (test-enforced);
  overall is the mean, never a judgment.
- **Round-trip inputs are first-class.** Builder and gate accept plan
  objects or their JSON dicts — plans cross process boundaries as data.
- **Shape integrity is a gate rule.** Undeclared keys refuse the plan
  (`EXECUTION_FIELD_PRESENT`); the import guard's `rglob` fix closes the
  subpackage loophole the same class of mistake would exploit.

## Limitations

No collection, no transport, no authority: READY states computed here
describe draft coverage only. Live observation (`live_deps.py`,
`observation_lane.py`) remains uncreated by design; grant-liveness and
budget-remaining checks belong to Track B.

## Verification

New suite 52/52 (RED first: 51 errors, package absent). Corrections
en route: one code bug (stray `del`), four test-expectation fixes where
the rule was right (fresh drafts are PARTIAL with 0<c<1; `t` known not
missing; valid plans are not refusals). Full AEC: 305/305 green.
`git diff --check` clean, read-only VERIFIED, frozen files identical,
diff guard PASS post-commit.

## Delivery

Commit `feat(aec): add evidence intelligence layer`; auto-push;
promotion request; await APPROVE. No main merge without it.

# AEC-1 T5 — Observation Plan Compiler (S6)

## Files created

- `aec/observation_plan.py`: deterministic planner — T4
  `AuthorizationRequestDraft` → frozen `ObservationPlanDraft` (BASELINE +
  up-to-2 COMPARISON + CONTEXT_CAPTURE, ≤ 4 steps).
- `tests/test_aec_observation_plan.py` (23 tests).
- `agent-reports/AEC-1-T5-report.md` (this file).

## Files modified

- `tests/test_aec_no_network.py`: new suite runs under socket denial.

## Design decisions

- **Input is the T4 draft type**, not raw cases: gap, method, and identity
  checks already settled upstream; this layer only plans.
- **Variables, not values.** Each step carries `fixed_variables`
  (`parameter` + `method` held at case values) and at most one
  `single_variable_change` naming the *dimension* (`parameter`) with role
  `ALTERNATE`. No concrete alternate value exists anywhere in the module —
  inventing one would be payload generation, which is refused by design.
- **Pairs share the baseline.** Every COMPARISON's fixed set is identical
  to BASELINE's; the change names exactly one held variable (invariant
  test-enforced).
- **Artifact types are carried, never invented**: BASELINE/COMPARISON
  target the sorted outstanding gap items; CONTEXT_CAPTURE targets the
  constant `context`.
- **Budget cost = step count**, same policy as the draft's reference.
- **Determinism gate**: gap items must be non-empty strings; anything else
  (mixed types, mappings-as-strings) is refused as
  `NON_DETERMINISTIC_INPUT` rather than sorted optimistically.
- Closed refusals: `INVALID_REQUEST`, `MISSING_HOST`, `MISSING_ENDPOINT`,
  `MISSING_GAP`, `UNSUPPORTED_METHOD` (GET/HEAD only, same constant as
  T4), `NON_DETERMINISTIC_INPUT`.

## Constraints respected

Stdlib + `aec.case_compiler`/`aec.models` only; no `ai.*`, no authorizer,
no schema modification, no verification contact; no sockets/DNS/subprocess
(AST-proven + denial-suite green); no filesystem writes (AST-proven);
frozen in/out; no verdict or payload vocabulary anywhere (AST-proven);
`live_deps.py` / `observation_lane.py` still absent; frozen files
byte-identical to production.

## Tests

RED: 22 errors (module absent). One design correction en route: the change
first named the parameter *value*; the invariant test (change must name a
held variable) forced it to the *dimension* — rule right, code fixed.
Final: new suite 23/23; full AEC set 228/228; `git diff --check` clean;
read-only checker VERIFIED. Delivery `check.sh` pre-commit BLOCKs are the
documented pre-commit artifacts (uncommitted range, no report yet,
production moved by operator merges) — read, not fixed.

## Delivery

Commit `feat(aec): add observation plan compiler`; auto-push agent branch;
promotion request artifact; Telegram approval ask. No main merge without
APPROVE.

**READY TO PUSH.** Waiting for operator.

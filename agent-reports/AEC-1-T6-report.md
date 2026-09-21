# AEC-1 T6 — Observation Authorization Gate (S9, offline scope)

## Gate purpose

Decide whether a T5 observation plan is *structurally eligible* for a
later controlled process. The gate grants nothing, records no authority,
and draws no conclusions about the target. Live checks the plan names
for later steps (grant present/live, budget remaining) belong to Track B,
not this module.

## Validation rules (fixed order, refusal stops the run)

`PLAN_PRESENT → EXECUTION_FIELDS → CASE_REF → TARGET → ENDPOINT →
METHOD → STEP_LIMIT → BUDGET`, all recorded in `checked_rules`.

- Presence/shape: plan object or plain-data round-trip (else
  `MISSING_PLAN`); empty step list is a missing plan.
- Shape integrity: any undeclared key at plan/step/budget level refuses
  with `EXECUTION_FIELD_PRESENT` — smuggled channels (`headers`, `body`,
  …) cannot pass even inside an otherwise valid plan.
- Content: non-empty case id, per-step host/endpoint, GET/HEAD-only
  methods (same constant as T4/T5).
- Count before content: `STEP_LIMIT` precedes `BUDGET` deliberately — with
  cost tracking length, an over-long plan would otherwise always trip the
  budget rule first and leave `STEP_LIMIT_EXCEEDED` unreachable.
- Budget validity: integer costs in 1..MAX_STEPS, non-empty policy,
  identical across steps, equal to the step count.

ALLOW carries reason `ELIGIBLE`, the full rule list, the plan id, and a
`timestamp` that is a content hash (`plan-hash:<hex>`), never a clock.

## Refusal reasons (closed)

`MISSING_PLAN`, `MISSING_CASE`, `MISSING_TARGET`, `MISSING_ENDPOINT`,
`UNSUPPORTED_METHOD`, `INVALID_BUDGET`, `STEP_LIMIT_EXCEEDED`,
`EXECUTION_FIELD_PRESENT`. No free-form strings.

## Constraints respected

Stdlib + `aec.case_compiler`/`aec.observation_plan` types only; no
`ai.*`, no authorizer, no schema/verification contact; no sockets,
subprocess, dynamic evaluation, or filesystem writes (AST-proven +
denial-suite green); frozen in/out; no conclusion vocabulary anywhere
(AST-proven); `live_deps.py` / `observation_lane.py` still absent; frozen
files byte-identical to production.

## Tests

RED: 24 errors (module absent). One ordering correction en route: the
over-long plan first tripped `INVALID_BUDGET` (cost≠length), hiding
`STEP_LIMIT_EXCEEDED` — rule right in spirit, order fixed so every code
is reachable. Final: new suite 25/25; full AEC set 253/253;
`git diff --check` clean; read-only checker VERIFIED. Delivery `check.sh`
pre-commit BLOCKs are the documented artifacts (uncommitted range,
production advanced by the sanctioned T5 promotion).

## Delivery

Commit `feat(aec): add observation authorization gate`; auto-push agent
branch; promotion request artifact; Telegram approval ask. No main merge
without APPROVE.

**READY TO PUSH.** Waiting for operator.

"""Observation plan compiler (AEC-1 T5, offline preparation half).

Converts a T4 :class:`AuthorizationRequestDraft` into a deterministic
:class:`ObservationPlanDraft`: the minimum ordered evidence-acquisition
plan that can reduce the stated gap.

A plan describes *which* single variable varies per observation pair and
*what* each step targets. It never supplies request bodies, concrete
alternate values, execution instructions, or judgments about the target.
No sockets. No HTTP. No DNS. No subprocess. No filesystem writes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aec.case_compiler import (
    ALLOWED_METHODS,
    AuthorizationRequestDraft,
    BudgetReference,
)

PLAN_VERSION = "aec-observation-plan/v1"

#: Hard ceiling on steps per plan (plan §S6: no more than 4 requests).
MAX_STEPS = 4

#: Comparisons after the shared baseline (baseline + comparisons + one
#: context capture always fits within MAX_STEPS).
MAX_COMPARISONS = 2

#: The only change role a comparison step may name. It marks *which*
#: variable the authorized executor may vary, never the value to use.
CHANGE_ROLE_ALTERNATE = "ALTERNATE"

#: Closed purpose vocabulary, in plan order.
PURPOSES = ("BASELINE", "COMPARISON", "CONTEXT_CAPTURE")

#: The observed dimension a comparison step may vary: the case parameter.
#: Named as a dimension, never bound to a concrete alternate value here.
VARIED_VARIABLE = "parameter"

#: Closed refusal vocabulary. No free-form refusal reasons.
REFUSAL_CODES = frozenset({
    "INVALID_REQUEST",
    "MISSING_HOST",
    "MISSING_ENDPOINT",
    "MISSING_GAP",
    "UNSUPPORTED_METHOD",
    "NON_DETERMINISTIC_INPUT",
})


@dataclass(frozen=True)
class ObservationStep:
    """One ordered observation: purpose, held variables, at most one change."""

    step_id: str
    purpose: str
    target_host: str
    endpoint: str
    method: str
    fixed_variables: tuple[tuple[str, str], ...]
    single_variable_change: tuple[str, str] | None
    expected_artifact_type: str
    budget_reference: BudgetReference

    def to_dict(self) -> dict[str, Any]:
        change = self.single_variable_change
        return {
            "step_id": self.step_id,
            "purpose": self.purpose,
            "target_host": self.target_host,
            "endpoint": self.endpoint,
            "method": self.method,
            "fixed_variables": [list(pair) for pair in self.fixed_variables],
            "single_variable_change": list(change) if change is not None else None,
            "expected_artifact_type": self.expected_artifact_type,
            "budget_reference": self.budget_reference.to_dict(),
        }


@dataclass(frozen=True)
class ObservationPlanDraft:
    """Deterministic observation plan. Descriptive paperwork, not orders."""

    plan_id: str
    case_id: str
    steps: tuple[ObservationStep, ...]
    plan_version: str = PLAN_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "case_id": self.case_id,
            "plan_version": self.plan_version,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True)
class PlanOutcome:
    """Result of planning: either a draft plan or a closed-vocabulary refusal."""

    ok: bool
    plan: ObservationPlanDraft | None
    refusal_code: str | None
    refusal_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "refusal_code": self.refusal_code,
            "refusal_detail": self.refusal_detail,
        }


def _refuse(code: str, detail: str) -> PlanOutcome:
    assert code in REFUSAL_CODES, f"refusal code outside closed vocabulary: {code!r}"
    return PlanOutcome(ok=False, plan=None, refusal_code=code, refusal_detail=detail)


def _outstanding_items(gap: Mapping[str, Any]) -> tuple[str, ...]:
    """Sorted outstanding evidence items. Raises TypeError when not orderable."""
    raw: list[Any] = []
    for key in ("missing", "artifacts_missing"):
        items = gap.get(key, ())
        if isinstance(items, str) or not isinstance(items, (list, tuple)):
            raise TypeError(f"gap field {key!r} is not a sequence of names")
        raw.extend(items)
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise TypeError(f"gap item {item!r} is not a usable name")
    return tuple(sorted(set(raw)))


def compile_observation_plan(source: object) -> PlanOutcome:
    """Compile an authorization request draft into an observation plan draft.

    Pure and deterministic: equal drafts always yield equal plans, and the
    input draft is never mutated.
    """
    if not isinstance(source, AuthorizationRequestDraft):
        return _refuse(
            "INVALID_REQUEST",
            f"expected AuthorizationRequestDraft, got {type(source).__name__}",
        )
    draft = source
    if not draft.host.strip():
        return _refuse("MISSING_HOST", f"draft {draft.case_id!r} names no target host")
    if not draft.endpoint.strip():
        return _refuse("MISSING_ENDPOINT", f"draft {draft.case_id!r} names no endpoint")
    method = draft.method.strip().upper()
    if method not in ALLOWED_METHODS:
        return _refuse(
            "UNSUPPORTED_METHOD",
            f"draft {draft.case_id!r} uses method {draft.method!r}; "
            f"plans describe {', '.join(ALLOWED_METHODS)} only",
        )
    gap = draft.evidence_gap
    if not isinstance(gap, Mapping):
        return _refuse("MISSING_GAP", f"draft {draft.case_id!r} carries no evidence gap")
    try:
        outstanding = _outstanding_items(gap)
    except TypeError as exc:
        return _refuse("NON_DETERMINISTIC_INPUT", str(exc))
    if not outstanding:
        return _refuse(
            "MISSING_GAP", f"draft {draft.case_id!r} states no outstanding evidence"
        )

    variable = VARIED_VARIABLE
    fixed = (("parameter", draft.parameter), ("method", method))
    plan_id = f"plan-{draft.case_id}"
    comparison_items = outstanding[1 : 1 + MAX_COMPARISONS]
    step_count = 1 + len(comparison_items) + 1
    assert step_count <= MAX_STEPS, "plan exceeds the step ceiling"
    budget = BudgetReference(
        policy=draft.budget_ref.policy,
        requested_cost=step_count,
        case_id=draft.case_id,
        host=draft.host,
    )

    def make_step(
        index: int,
        purpose: str,
        artifact: str,
        change: tuple[str, str] | None,
    ) -> ObservationStep:
        return ObservationStep(
            step_id=f"{plan_id}-s{index:02d}",
            purpose=purpose,
            target_host=draft.host,
            endpoint=draft.endpoint,
            method=method,
            fixed_variables=fixed,
            single_variable_change=change,
            expected_artifact_type=artifact,
            budget_reference=budget,
        )

    steps: list[ObservationStep] = [
        make_step(1, "BASELINE", outstanding[0], None)
    ]
    for position, item in enumerate(comparison_items, start=2):
        steps.append(
            make_step(position, "COMPARISON", item, (variable, CHANGE_ROLE_ALTERNATE))
        )
    steps.append(make_step(len(steps) + 1, "CONTEXT_CAPTURE", "context", None))
    plan = ObservationPlanDraft(plan_id=plan_id, case_id=draft.case_id, steps=tuple(steps))
    return PlanOutcome(ok=True, plan=plan, refusal_code=None)


def serialize_plan(plan: ObservationPlanDraft) -> str:
    """Stable serialization: identical plans always produce identical bytes."""
    return json.dumps(plan.to_dict(), sort_keys=True)


__all__ = [
    "ALLOWED_METHODS",
    "CHANGE_ROLE_ALTERNATE",
    "VARIED_VARIABLE",
    "MAX_COMPARISONS",
    "MAX_STEPS",
    "PLAN_VERSION",
    "PURPOSES",
    "REFUSAL_CODES",
    "ObservationPlanDraft",
    "ObservationStep",
    "PlanOutcome",
    "compile_observation_plan",
    "serialize_plan",
]

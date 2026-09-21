"""Observation authorization gate (AEC-1 T6, offline preparation half).

Decides whether a T5 :class:`ObservationPlanDraft` is structurally
eligible for a later controlled process. The gate grants nothing, records
no authority, draws no conclusions about the target, and reaches nowhere:
no sockets, no subprocess, no dynamic evaluation, no filesystem writes.

It accepts a plan object or its plain-data round-trip (plans cross process
boundaries as JSON) and returns a frozen :class:`AuthorizationGateDecision`
with decision ``ALLOW``/``REFUSE``, a closed-vocabulary reason, the rules
evaluated, the plan id, and a deterministic content-hash stamp (no clock).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aec.case_compiler import ALLOWED_METHODS
from aec.observation_plan import MAX_STEPS, ObservationPlanDraft

#: The single allow reason. Refusals use REFUSAL_CODES.
ALLOW_REASON = "ELIGIBLE"

#: Closed refusal vocabulary. No free-form refusal strings.
REFUSAL_CODES = frozenset({
    "MISSING_PLAN",
    "MISSING_CASE",
    "MISSING_TARGET",
    "MISSING_ENDPOINT",
    "UNSUPPORTED_METHOD",
    "INVALID_BUDGET",
    "STEP_LIMIT_EXCEEDED",
    "EXECUTION_FIELD_PRESENT",
})

#: Rules evaluated in this fixed order; a refusal stops at the failing rule.
#: STEP_LIMIT precedes BUDGET deliberately: with cost tracking length, a
#: longer-than-allowed plan would otherwise always trip the budget rule
#: first and STEP_LIMIT_EXCEEDED would be unreachable.
RULES = (
    "PLAN_PRESENT",
    "EXECUTION_FIELDS",
    "CASE_REF",
    "TARGET",
    "ENDPOINT",
    "METHOD",
    "STEP_LIMIT",
    "BUDGET",
)

#: Permitted keys at each level of a plan document. Anything else is an
#: undeclared channel and refuses the plan.
ALLOWED_PLAN_KEYS = frozenset({"plan_id", "case_id", "plan_version", "steps"})
ALLOWED_STEP_KEYS = frozenset({
    "step_id",
    "purpose",
    "target_host",
    "endpoint",
    "method",
    "fixed_variables",
    "single_variable_change",
    "expected_artifact_type",
    "budget_reference",
})
ALLOWED_BUDGET_KEYS = frozenset({"policy", "requested_cost", "case_id", "host"})


@dataclass(frozen=True)
class AuthorizationGateDecision:
    """Eligibility outcome. A statement about plan shape, never permission."""

    decision: str  # "ALLOW" or "REFUSE"
    reason_code: str
    checked_rules: tuple[str, ...]
    plan_id: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "checked_rules": list(self.checked_rules),
            "plan_id": self.plan_id,
            "timestamp": self.timestamp,
        }


def serialize_decision(decision: AuthorizationGateDecision) -> str:
    """Stable serialization: identical decisions yield identical bytes."""
    return json.dumps(decision.to_dict(), sort_keys=True)


def _stamp(document: Mapping[str, Any] | None) -> str:
    """Deterministic content-hash stamp. No clock is consulted."""
    try:
        canonical = json.dumps(dict(document or {}), sort_keys=True).encode()
    except (TypeError, ValueError):
        return "logical:unshaped-input"
    if not (document or {}):
        return "logical:no-plan"
    return "plan-hash:" + hashlib.sha256(canonical).hexdigest()[:16]


def _text(value: object) -> str:
    return str(value or "").strip()


def _undeclared_keys(document: Mapping[str, Any]) -> bool:
    """True when any mapping in the document carries undeclared keys."""
    if not isinstance(document, Mapping):
        return True
    if set(document) - ALLOWED_PLAN_KEYS:
        return True
    steps = document.get("steps")
    if not isinstance(steps, (list, tuple)):
        return False
    for step in steps:
        if not isinstance(step, Mapping):
            return True
        if set(step) - ALLOWED_STEP_KEYS:
            return True
        budget = step.get("budget_reference")
        if isinstance(budget, Mapping) and set(budget) - ALLOWED_BUDGET_KEYS:
            return True
    return False


def check_authorization_eligibility(source: object) -> AuthorizationGateDecision:
    """Judge a plan's structural eligibility. Pure and deterministic."""
    checked: list[str] = []

    def refuse(code: str, plan_id: str, document: Mapping[str, Any] | None) -> AuthorizationGateDecision:
        assert code in REFUSAL_CODES, f"outside closed vocabulary: {code!r}"
        return AuthorizationGateDecision(
            decision="REFUSE",
            reason_code=code,
            checked_rules=tuple(checked),
            plan_id=plan_id,
            timestamp=_stamp(document),
        )

    checked.append("PLAN_PRESENT")
    document: Mapping[str, Any] | None
    if isinstance(source, ObservationPlanDraft):
        document = source.to_dict()
    elif isinstance(source, Mapping):
        document = source
    else:
        document = None
    if document is None:
        return refuse("MISSING_PLAN", "", None)
    steps = document.get("steps")
    if not isinstance(steps, (list, tuple)) or not steps:
        return refuse("MISSING_PLAN", _text(document.get("plan_id")), document)

    checked.append("EXECUTION_FIELDS")
    if _undeclared_keys(document):
        return refuse(
            "EXECUTION_FIELD_PRESENT", _text(document.get("plan_id")), document
        )

    checked.append("CASE_REF")
    if not _text(document.get("case_id")):
        return refuse("MISSING_CASE", _text(document.get("plan_id")), document)

    checked.append("TARGET")
    if any(not isinstance(s, Mapping) or not _text(s.get("target_host")) for s in steps):
        return refuse("MISSING_TARGET", _text(document.get("plan_id")), document)

    checked.append("ENDPOINT")
    if any(not isinstance(s, Mapping) or not _text(s.get("endpoint")) for s in steps):
        return refuse("MISSING_ENDPOINT", _text(document.get("plan_id")), document)

    checked.append("METHOD")
    if any(
        not isinstance(s, Mapping) or _text(s.get("method")).upper() not in ALLOWED_METHODS
        for s in steps
    ):
        return refuse("UNSUPPORTED_METHOD", _text(document.get("plan_id")), document)

    checked.append("STEP_LIMIT")
    if len(steps) > MAX_STEPS:
        return refuse("STEP_LIMIT_EXCEEDED", _text(document.get("plan_id")), document)

    checked.append("BUDGET")
    costs: list[Any] = []
    budget_ok = True
    for step in steps:
        budget = step.get("budget_reference") if isinstance(step, Mapping) else None
        if not isinstance(budget, Mapping):
            budget_ok = False
            break
        cost = budget.get("requested_cost")
        if (
            not isinstance(cost, int)
            or isinstance(cost, bool)
            or cost <= 0
            or cost > MAX_STEPS
            or not _text(budget.get("policy"))
        ):
            budget_ok = False
            break
        costs.append(cost)
    if not budget_ok or len(set(costs)) != 1 or costs[0] != len(steps):
        return refuse("INVALID_BUDGET", _text(document.get("plan_id")), document)

    resolved_plan_id = _text(document.get("plan_id")) or f"plan-{_text(document.get('case_id'))}"
    return AuthorizationGateDecision(
        decision="ALLOW",
        reason_code=ALLOW_REASON,
        checked_rules=tuple(checked),
        plan_id=resolved_plan_id,
        timestamp=_stamp(document),
    )


__all__ = [
    "ALLOWED_METHODS",
    "ALLOWED_BUDGET_KEYS",
    "ALLOWED_PLAN_KEYS",
    "ALLOWED_STEP_KEYS",
    "ALLOW_REASON",
    "REFUSAL_CODES",
    "RULES",
    "AuthorizationGateDecision",
    "check_authorization_eligibility",
    "serialize_decision",
]

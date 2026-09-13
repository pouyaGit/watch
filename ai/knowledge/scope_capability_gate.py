"""Stage R36.3 deterministic scope and capability gate (pure engine).

Produces the bounded capability/scope authorization snapshot:

    "WHAT (capability) is authorized for WHOM (role), WHERE (scope), WHY
     (strategy context) and under what CONSTRAINTS?"

Hard boundaries encoded here:

- Planning/authorization only: capabilities are conceptual research labels.
  No operational execution capability exists and nothing is executed.
- Conservative scope: a missing, malformed or non-component scope resolves to
  ``UNKNOWN``; it can never become unrestricted scope.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.agent_role_plan import AGENT_ROLES
from ai.schemas.execution_authorization_plan import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
)
from ai.schemas.scope_capability_gate import (
    CAPABILITY_UNKNOWN,
    CERTAINTY_HIGH,
    CERTAINTY_MEDIUM,
    CERTAINTY_UNKNOWN,
    GATE_CONSTRAINT_BLOCKED,
    GATE_CONSTRAINT_COMPONENT_SCOPED,
    GATE_CONSTRAINT_HUMAN_APPROVAL,
    GATE_CONSTRAINT_RESEARCH_ONLY,
    GATE_CONSTRAINT_UNKNOWN,
    RESEARCH_CAPABILITIES,
    SCOPE_AUTHORIZED_RESEARCH,
    SCOPE_CAPABILITY_GATE_RULE_VERSION,
    SCOPE_COMPONENT,
    SCOPE_PROGRAM,
    SCOPE_UNKNOWN,
    SCOPE_VALUES,
    ScopeCapabilityGatePlan,
    scope_capability_gate_plan_projection,
)

SCOPE_CAPABILITY_GATE_PLANNER_RULE_VERSION = "r36-3"
RULE_VERSION = SCOPE_CAPABILITY_GATE_PLANNER_RULE_VERSION

# support scope input -> (gate scope, certainty)
SCOPE_RESOLUTION: dict[str, tuple] = {
    SCOPE_COMPONENT: (SCOPE_COMPONENT, CERTAINTY_HIGH),
    SCOPE_AUTHORIZED_RESEARCH: (SCOPE_AUTHORIZED_RESEARCH, CERTAINTY_MEDIUM),
    SCOPE_PROGRAM: (SCOPE_PROGRAM, CERTAINTY_MEDIUM),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _constraints_for(decision: str, scope: str) -> list[str]:
    if decision == DECISION_BLOCK:
        return [GATE_CONSTRAINT_BLOCKED]
    if decision == DECISION_REQUIRE_HUMAN_APPROVAL:
        return [GATE_CONSTRAINT_HUMAN_APPROVAL]
    if decision == DECISION_ALLOW_WITH_LIMITS:
        out = [GATE_CONSTRAINT_RESEARCH_ONLY]
        if scope == SCOPE_COMPONENT:
            out.append(GATE_CONSTRAINT_COMPONENT_SCOPED)
        return out
    if decision == DECISION_ALLOW:
        out = []
        if scope == SCOPE_COMPONENT:
            out.append(GATE_CONSTRAINT_COMPONENT_SCOPED)
        return out
    return [GATE_CONSTRAINT_UNKNOWN]


def plan_scope_capability_gate(
    authorization_plan: object = None,
    role_plan: object = None,
    support_scope: object = None,
) -> dict:
    """Build the deterministic capability/scope snapshot (read-only).

    ``capability``/``agent_role`` come from the R35.1 role plan's primary role
    (unknown when absent/invalid). ``scope`` comes only from an explicit,
    recognized ``support_scope``; anything else resolves to ``UNKNOWN`` and
    is never treated as unrestricted. ``authorized`` is true only for an
    ALLOW/ALLOW_WITH_LIMITS decision with a known capability and known scope.
    """

    authorization = _block(authorization_plan)
    roles = _block(role_plan)

    cap = _upper(roles.get("primary_role"))
    if cap not in RESEARCH_CAPABILITIES or cap not in AGENT_ROLES:
        cap = CAPABILITY_UNKNOWN
    role = _upper(roles.get("primary_role"))
    if role not in AGENT_ROLES:
        role = CAPABILITY_UNKNOWN

    resolved_scope, certainty = SCOPE_RESOLUTION.get(
        _upper(support_scope), (SCOPE_UNKNOWN, CERTAINTY_UNKNOWN)
    )

    decision = _upper(authorization.get("decision"))
    authorized = (
        decision in (DECISION_ALLOW, DECISION_ALLOW_WITH_LIMITS)
        and cap != CAPABILITY_UNKNOWN
        and resolved_scope != SCOPE_UNKNOWN
    )

    source_strategy = _text(
        _block(authorization.get("source_strategy")).get("strategy_type")
    )

    plan = ScopeCapabilityGatePlan(
        rule_version=SCOPE_CAPABILITY_GATE_RULE_VERSION,
        capability=cap,
        agent_role=role,
        scope=resolved_scope,
        scope_certainty=certainty,
        authorized=authorized,
        source_strategy=source_strategy,
        constraints=_constraints_for(decision, resolved_scope),
        research_only=True,
    )
    return scope_capability_gate_plan_projection(plan)


__all__ = [
    "SCOPE_CAPABILITY_GATE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "SCOPE_RESOLUTION",
    "plan_scope_capability_gate",
]

"""Stage R37.1 deterministic decision provenance tracker (pure engine).

Tracks WHY an authorization decision exists:

    "Which upstream sources and signals produced this decision?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  created. Nothing is executed.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no wall-clock time, no
  randomness, no environment or filesystem state.
- No persistence and no database IDs: ``decision_id`` is a deterministic
  content token (SHA-256 over bounded closed inputs) recomputed identically
  on every run.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib

from ai.schemas.agent_role_plan import AGENT_ROLES
from ai.schemas.decision_provenance import (
    DECISION_ID_PREFIX,
    DECISION_PROVENANCE_RULE_VERSION,
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
    SIGNAL_APPROVAL,
    SIGNAL_AUTHORIZATION,
    SIGNAL_BOUNDARY,
    SIGNAL_ORCHESTRATION,
    SIGNAL_POLICY,
    SIGNAL_RISK,
    SIGNAL_STRATEGY,
    DecisionProvenancePlan,
    decision_provenance_plan_projection,
)
from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    DECISION_UNKNOWN,
)
from ai.schemas.execution_boundary_plan import BOUNDARY_STATES
from ai.schemas.execution_policy import EXECUTION_POLICIES
from ai.schemas.execution_risk import RISK_LEVELS
from ai.schemas.human_approval_gate import APPROVAL_STATES
from ai.schemas.research_strategy import STRATEGY_TYPES

DECISION_PROVENANCE_TRACKER_RULE_VERSION = "r37-1"
RULE_VERSION = DECISION_PROVENANCE_TRACKER_RULE_VERSION

# Fixed signal evaluation order.
SIGNAL_ORDER: tuple[str, ...] = (
    SIGNAL_STRATEGY,
    SIGNAL_ORCHESTRATION,
    SIGNAL_AUTHORIZATION,
    SIGNAL_POLICY,
    SIGNAL_RISK,
    SIGNAL_APPROVAL,
    SIGNAL_BOUNDARY,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def strategy_source_valid(strategy_export: object) -> bool:
    export = _block(strategy_export)
    strategy = _block(export.get("strategy"))
    strategy_type = _upper(
        strategy.get("strategy_type") or export.get("strategy_type")
    )
    return strategy_type in STRATEGY_TYPES


def orchestration_source_valid(orchestration_export: object) -> bool:
    export = _block(orchestration_export)
    roles = _block(export.get("roles"))
    primary_role = _upper(
        roles.get("primary_role") or export.get("primary_role")
    )
    workflow = _block(export.get("workflow"))
    nodes = workflow.get("nodes")
    return (
        primary_role in AGENT_ROLES
        and isinstance(nodes, (list, tuple))
        and bool(list(nodes))
    )


def authorization_source_valid(authorization_plan: object) -> bool:
    decision = _upper(_block(authorization_plan).get("decision"))
    return (
        decision in AUTHORIZATION_DECISIONS
        and decision != DECISION_UNKNOWN
    )


def _closed(value: object, allowed: tuple) -> bool:
    return _upper(value) in allowed


def compute_decision_id(
    strategy_export: object = None,
    orchestration_export: object = None,
    authorization_plan: object = None,
    policy_plan: object = None,
    risk_plan: object = None,
    approval_plan: object = None,
    boundary_plan: object = None,
) -> str:
    """Deterministic content id over bounded closed inputs (no clock)."""

    strategy = _block(_block(strategy_export).get("strategy"))
    roles = _block(_block(orchestration_export).get("roles"))
    basis = "\n".join(
        [
            DECISION_PROVENANCE_RULE_VERSION,
            _upper(
                strategy.get("strategy_type")
                or _block(strategy_export).get("strategy_type")
            ),
            _upper(
                roles.get("primary_role")
                or _block(orchestration_export).get("primary_role")
            ),
            _upper(_block(authorization_plan).get("decision")),
            _upper(_block(policy_plan).get("policy")),
            _upper(_block(risk_plan).get("risk_level")),
            _upper(_block(approval_plan).get("approval_state")),
            _upper(_block(boundary_plan).get("boundary_state")),
        ]
    )
    return DECISION_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def track_decision_provenance(
    strategy_export: object = None,
    orchestration_export: object = None,
    authorization_plan: object = None,
    policy_plan: object = None,
    risk_plan: object = None,
    approval_plan: object = None,
    boundary_plan: object = None,
) -> dict:
    """Record deterministic provenance for one decision (read-only).

    ``COMPLETE`` requires valid strategy, orchestration and authorization
    sources; ``PARTIAL`` requires at least one of the three; ``UNKNOWN``
    means all critical provenance is missing. Auxiliary signals (policy, risk,
    approval, boundary) are recorded only when valid.
    """

    strategy_valid = strategy_source_valid(strategy_export)
    orchestration_valid = orchestration_source_valid(orchestration_export)
    authorization_valid = authorization_source_valid(authorization_plan)

    validity = {
        SIGNAL_STRATEGY: strategy_valid,
        SIGNAL_ORCHESTRATION: orchestration_valid,
        SIGNAL_AUTHORIZATION: authorization_valid,
        SIGNAL_POLICY: _closed(
            _block(policy_plan).get("policy"), EXECUTION_POLICIES
        ),
        SIGNAL_RISK: _closed(
            _block(risk_plan).get("risk_level"), RISK_LEVELS
        ),
        SIGNAL_APPROVAL: _closed(
            _block(approval_plan).get("approval_state"), APPROVAL_STATES
        ),
        SIGNAL_BOUNDARY: _closed(
            _block(boundary_plan).get("boundary_state"), BOUNDARY_STATES
        ),
    }

    critical = (
        strategy_valid,
        orchestration_valid,
        authorization_valid,
    )
    if all(critical):
        state = PROVENANCE_COMPLETE
    elif any(critical):
        state = PROVENANCE_PARTIAL
    else:
        state = PROVENANCE_UNKNOWN

    plan = DecisionProvenancePlan(
        rule_version=DECISION_PROVENANCE_RULE_VERSION,
        decision_id=compute_decision_id(
            strategy_export, orchestration_export, authorization_plan,
            policy_plan, risk_plan, approval_plan, boundary_plan,
        ),
        source_strategy=_block(strategy_export),
        source_orchestration=_block(orchestration_export),
        source_authorization=_block(authorization_plan),
        contributing_signals=[
            signal for signal in SIGNAL_ORDER if validity[signal]
        ],
        provenance_state=state,
        research_only=True,
    )
    return decision_provenance_plan_projection(plan)


__all__ = [
    "DECISION_PROVENANCE_TRACKER_RULE_VERSION",
    "RULE_VERSION",
    "SIGNAL_ORDER",
    "strategy_source_valid",
    "orchestration_source_valid",
    "authorization_source_valid",
    "compute_decision_id",
    "track_decision_provenance",
]

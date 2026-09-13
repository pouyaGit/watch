"""Stage R37.3 deterministic research audit event builder (pure engine).

Creates the immutable conceptual audit record for one governance event:

    "What governance event occurred, from which source, and is the record
     internally valid?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  created. Nothing is stored.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no wall-clock time, no
  randomness, no environment or filesystem state. No runtime timestamps.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.decision_provenance import (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
    SIGNAL_AUTHORIZATION,
    SIGNAL_ORCHESTRATION,
    SIGNAL_STRATEGY,
)
from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
)
from ai.schemas.research_audit_event import (
    AUDIT_INVALID,
    AUDIT_UNKNOWN,
    AUDIT_VALID,
    EVENT_APPROVAL_REQUIRED,
    EVENT_AUTHORIZATION_DECIDED,
    EVENT_BLOCK_APPLIED,
    EVENT_STRATEGY_CREATED,
    EVENT_UNKNOWN,
    EVENT_WORKFLOW_CREATED,
    RESEARCH_AUDIT_EVENT_RULE_VERSION,
    SOURCE_AUTHORIZATION,
    SOURCE_ORCHESTRATION,
    SOURCE_STRATEGY,
    SOURCE_UNKNOWN,
    SUMMARY_APPROVAL,
    SUMMARY_AUTHORIZATION,
    SUMMARY_BLOCK,
    SUMMARY_STRATEGY,
    SUMMARY_UNKNOWN,
    SUMMARY_WORKFLOW,
    ResearchAuditEventPlan,
    research_audit_event_plan_projection,
)

RESEARCH_AUDIT_EVENT_BUILDER_RULE_VERSION = "r37-3"
RULE_VERSION = RESEARCH_AUDIT_EVENT_BUILDER_RULE_VERSION

# event type -> (source, summary)
EVENT_METADATA: dict[str, tuple] = {
    EVENT_STRATEGY_CREATED: (SOURCE_STRATEGY, SUMMARY_STRATEGY),
    EVENT_WORKFLOW_CREATED: (SOURCE_ORCHESTRATION, SUMMARY_WORKFLOW),
    EVENT_AUTHORIZATION_DECIDED: (
        SOURCE_AUTHORIZATION, SUMMARY_AUTHORIZATION,
    ),
    EVENT_APPROVAL_REQUIRED: (SOURCE_AUTHORIZATION, SUMMARY_APPROVAL),
    EVENT_BLOCK_APPLIED: (SOURCE_AUTHORIZATION, SUMMARY_BLOCK),
    EVENT_UNKNOWN: (SOURCE_UNKNOWN, SUMMARY_UNKNOWN),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def build_research_audit_event(
    provenance_plan: object = None,
    authorization_plan: object = None,
    policy_plan: object = None,
) -> dict:
    """Build the deterministic audit event for one decision (read-only).

    Event precedence: known authorization decisions (BLOCK / human approval /
    decided) first, then workflow, then strategy, else UNKNOWN. Audit state:
    UNKNOWN when no governance input exists, INVALID when critical provenance
    is unknown or the event cannot be classified, VALID otherwise.
    """

    provenance = _block(provenance_plan)
    authorization = _block(authorization_plan)
    policy = _block(policy_plan)

    decision = _upper(authorization.get("decision"))
    if decision not in AUTHORIZATION_DECISIONS:
        decision = _upper(
            _block(provenance.get("source_authorization")).get("decision")
        )
    if decision not in AUTHORIZATION_DECISIONS:
        decision = DECISION_UNKNOWN

    provenance_state = _upper(provenance.get("provenance_state"))
    signals = provenance.get("contributing_signals")
    signals = signals if isinstance(signals, (list, tuple)) else ()

    if not provenance and not authorization and not policy:
        event_type = EVENT_UNKNOWN
    elif decision == DECISION_BLOCK:
        event_type = EVENT_BLOCK_APPLIED
    elif decision == DECISION_REQUIRE_HUMAN_APPROVAL:
        event_type = EVENT_APPROVAL_REQUIRED
    elif decision in (DECISION_ALLOW, DECISION_ALLOW_WITH_LIMITS):
        event_type = EVENT_AUTHORIZATION_DECIDED
    elif SIGNAL_ORCHESTRATION in signals:
        event_type = EVENT_WORKFLOW_CREATED
    elif SIGNAL_STRATEGY in signals:
        event_type = EVENT_STRATEGY_CREATED
    else:
        event_type = EVENT_UNKNOWN

    if not provenance and not authorization and not policy:
        audit_state = AUDIT_UNKNOWN
    elif (
        provenance_state == PROVENANCE_UNKNOWN
        or event_type == EVENT_UNKNOWN
        or not provenance
    ):
        audit_state = AUDIT_INVALID
    elif provenance_state in (PROVENANCE_COMPLETE, PROVENANCE_PARTIAL):
        audit_state = AUDIT_VALID
    else:
        audit_state = AUDIT_INVALID

    source, summary = EVENT_METADATA[event_type]

    strategy_type = _text(
        _block(provenance.get("source_strategy")).get("strategy_type")
    )

    plan = ResearchAuditEventPlan(
        rule_version=RESEARCH_AUDIT_EVENT_RULE_VERSION,
        event_type=event_type,
        event_source=source,
        event_summary=summary,
        related_strategy=strategy_type,
        related_authorization=decision,
        audit_state=audit_state,
        research_only=True,
    )
    return research_audit_event_plan_projection(plan)


__all__ = [
    "RESEARCH_AUDIT_EVENT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "EVENT_METADATA",
    "build_research_audit_event",
]

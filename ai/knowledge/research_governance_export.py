"""Stage R37.5 deterministic research governance exporter (pure engine).

Packages the R37 governance layer into the final bounded, JSON-serializable
export:

    "Is the governance/audit record complete and internally valid?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  created. Nothing is executed.
- ``ready`` is true only when provenance, rule trace, audit event and
  explanation are all present and valid; UNKNOWN critical states prevent
  readiness.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.decision_provenance import (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    sanitize_decision_provenance_plan,
)
from ai.schemas.governance_rule_trace import (
    TRACE_COMPLETE,
    TRACE_PARTIAL,
    sanitize_governance_rule_trace_plan,
)
from ai.schemas.research_audit_event import (
    AUDIT_INVALID,
    AUDIT_VALID,
    sanitize_research_audit_event_plan,
)
from ai.schemas.research_explanation import (
    EXPLANATION_COMPLETE,
    EXPLANATION_PARTIAL,
    sanitize_research_explanation_plan,
)
from ai.schemas.research_governance_export import (
    LIMITATION_INVALID_AUDIT_EVENT,
    LIMITATION_MISSING_SOURCES,
    LIMITATION_UNKNOWN_AUDIT_EVENT,
    LIMITATION_UNKNOWN_EXPLANATION,
    LIMITATION_UNKNOWN_PROVENANCE,
    LIMITATION_UNKNOWN_RULE_TRACE,
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
    ResearchGovernanceExportPlan,
    research_governance_export_plan_projection,
)

RESEARCH_GOVERNANCE_EXPORTER_RULE_VERSION = "r37-5"
RULE_VERSION = RESEARCH_GOVERNANCE_EXPORTER_RULE_VERSION


def export_research_governance(
    provenance_plan: object = None,
    rule_trace_plan: object = None,
    audit_event_plan: object = None,
    explanation_plan: object = None,
) -> dict:
    """Package the R37 governance plans into a deterministic export.

    ``ready`` requires valid (non-UNKNOWN) provenance, rule trace and
    explanation plus a VALID audit event. Limitations are emitted in a fixed
    order.
    """

    provenance = sanitize_decision_provenance_plan(provenance_plan)
    rule_trace = sanitize_governance_rule_trace_plan(rule_trace_plan)
    audit_event = sanitize_research_audit_event_plan(audit_event_plan)
    explanation = sanitize_research_explanation_plan(explanation_plan)

    provenance_valid = provenance.get("provenance_state") in (
        PROVENANCE_COMPLETE, PROVENANCE_PARTIAL,
    )
    trace_valid = rule_trace.get("trace_state") in (
        TRACE_COMPLETE, TRACE_PARTIAL,
    )
    audit_valid = audit_event.get("audit_state") == AUDIT_VALID
    explanation_valid = explanation.get("explanation_state") in (
        EXPLANATION_COMPLETE, EXPLANATION_PARTIAL,
    )
    ready = provenance_valid and trace_valid and audit_valid and (
        explanation_valid
    )

    limitations: list[str] = []
    if not provenance_valid:
        limitations.append(LIMITATION_UNKNOWN_PROVENANCE)
    if not trace_valid:
        limitations.append(LIMITATION_UNKNOWN_RULE_TRACE)
    if audit_event.get("audit_state") == AUDIT_INVALID:
        limitations.append(LIMITATION_INVALID_AUDIT_EVENT)
    elif audit_event.get("audit_state") != AUDIT_VALID:
        limitations.append(LIMITATION_UNKNOWN_AUDIT_EVENT)
    if not explanation_valid:
        limitations.append(LIMITATION_UNKNOWN_EXPLANATION)
    if provenance.get("provenance_state") == PROVENANCE_PARTIAL:
        limitations.append(LIMITATION_MISSING_SOURCES)

    plan = ResearchGovernanceExportPlan(
        rule_version=RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
        ready=ready,
        provenance=provenance,
        rule_trace=rule_trace,
        audit_event=audit_event,
        explanation=explanation,
        limitations=limitations,
        research_only=True,
    )
    return research_governance_export_plan_projection(plan)


__all__ = [
    "RESEARCH_GOVERNANCE_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_governance",
]

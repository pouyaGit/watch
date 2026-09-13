"""Stage R39.5 deterministic XSS agent result exporter (pure engine).

Packages the XSS research pipeline into the standard, R38-compatible result:

    "What did the XSS research agent conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Research intelligence only: no payload storage, no exploit output, no
  execution logs, no HTTP request, no browser/JavaScript execution, no DOM
  crawling, no fuzzing, no exploitation, no auth bypass, no subprocess, no
  shell, no external API, no LLM call, no persistence, no worker or
  scheduler. Nothing is executed.
- R38 integration: the exporter consumes the R38 read-only input contract and
  projects the result onto a valid ``SecurityAgentResultPlan``.
- R37 integration: the result carries a bounded governance reference built
  from the R37 governance export; unreferenced governance is never treated as
  valid.
- Pure and offline: no I/O, no network, no LLM, no browser, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.security_agent_result_validator import (
    validate_security_agent_result,
)
from ai.knowledge.xss_agent_identity import (
    plan_xss_agent_identity,
)
from ai.knowledge.xss_context_analyzer import analyze_xss_context
from ai.knowledge.xss_evidence_planner import plan_xss_evidence
from ai.knowledge.xss_hypothesis_planner import plan_xss_hypotheses
from ai.schemas.evidence_confidence import CONFIDENCE_UNKNOWN
from ai.schemas.research_governance_export import (
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
)
from ai.schemas.security_agent_result import (
    EVIDENCE_PARTIAL,
    EVIDENCE_SUFFICIENT,
    EVIDENCE_UNKNOWN,
    FINDINGS_HYPOTHESES,
    FINDINGS_NONE,
)
from ai.schemas.xss_agent_identity import (
    XSS_CATEGORY,
    sanitize_xss_agent_identity_plan,
)
from ai.schemas.xss_agent_result import (
    GOVERNANCE_REFERENCED,
    GOVERNANCE_UNKNOWN,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_RESULT_UNKNOWN,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_UNKNOWN,
    XSS_AGENT_RESULT_RULE_VERSION,
    XSSAgentResultPlan,
    sanitize_governance_reference,
    sanitize_xss_agent_result_plan,
    xss_agent_result_plan_projection,
)
from ai.schemas.xss_evidence_plan import (
    STATE_COMPLETE,
    STATE_PARTIAL,
)

XSS_AGENT_RESULT_EXPORTER_RULE_VERSION = "r39-5"
RULE_VERSION = XSS_AGENT_RESULT_EXPORTER_RULE_VERSION

_INPUT_KEYS: tuple[str, ...] = (
    "agent_identity",
    "research_context",
    "memory_context",
    "strategy_context",
    "orchestration_context",
    "authorization_context",
    "governance_context",
)

_EVIDENCE_TO_R38: dict[str, str] = {
    STATE_COMPLETE: EVIDENCE_SUFFICIENT,
    STATE_PARTIAL: EVIDENCE_PARTIAL,
}


def _field(value: object, key: str) -> object:
    return value.get(key) if isinstance(value, dict) else None


def _bounded_r38_input(value: object) -> dict:
    """Validate a caller-provided R38 input plan (read-only)."""

    if not isinstance(value, dict):
        return {}
    return validate_security_agent_input(
        **{key: value.get(key) for key in _INPUT_KEYS}
    )


def _resolve_agent_name(
    agent_identity: object,
    bounded_input: dict,
) -> str:
    """Resolve the agent name from an explicit or R38-supplied identity."""

    source = agent_identity if isinstance(agent_identity, dict) else None
    if source is None:
        candidate = bounded_input.get("agent_identity") or {}
        if (
            candidate.get("category") == XSS_CATEGORY
            and candidate.get("agent_id")
        ):
            source = candidate
    sanitized = sanitize_xss_agent_identity_plan(source)
    return plan_xss_agent_identity(
        maturity=sanitized["maturity"] or None,
        version=sanitized["version"] or None,
        supported_contexts=sanitized["supported_contexts"] or None,
        agent_name=sanitized["agent_name"] or None,
    )["agent_name"]


def build_governance_reference(governance_plan: object = None) -> dict:
    """Build a bounded R37 governance reference (read-only).

    A reference is ``REFERENCED`` only when the plan carries the R37
    governance export rule version; missing, malformed or foreign plans
    degrade to ``UNKNOWN`` with ``ready=False``.
    """

    if (
        not isinstance(governance_plan, dict)
        or governance_plan.get("rule_version")
        != RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION
        or not all(
            isinstance(governance_plan.get(key), dict)
            for key in (
                "provenance",
                "rule_trace",
                "audit_event",
                "explanation",
            )
        )
    ):
        return sanitize_governance_reference(None)
    return sanitize_governance_reference(
        {
            "rule_version": governance_plan.get("rule_version"),
            "ready": governance_plan.get("ready"),
            "provenance_state": _field(
                governance_plan.get("provenance"), "provenance_state"
            ),
            "trace_state": _field(
                governance_plan.get("rule_trace"), "trace_state"
            ),
            "audit_state": _field(
                governance_plan.get("audit_event"), "audit_state"
            ),
            "explanation_state": _field(
                governance_plan.get("explanation"), "explanation_state"
            ),
            "reference_state": GOVERNANCE_REFERENCED,
        }
    )


def _derive_status(context_confidence: str, evidence_state: str) -> str:
    if evidence_state == STATE_COMPLETE:
        return STATUS_COMPLETED
    if evidence_state == STATE_PARTIAL:
        return STATUS_ANALYZING
    if context_confidence != CONFIDENCE_UNKNOWN:
        return STATUS_ANALYZING
    return STATUS_CREATED


def export_xss_agent_result(
    agent_identity: object = None,
    security_agent_input: object = None,
    input_location: object = None,
    output_context: object = None,
    reflection_state: object = None,
    encoding_state: object = None,
    framework_context: object = None,
    governance_plan: object = None,
) -> dict:
    """Run the deterministic XSS research pipeline into a result (read-only).

    The pipeline analyzes bounded context, plans hypotheses and evidence, and
    records the R37 governance reference. Status is conservative: only a
    complete evidence plan is ``COMPLETED``; a partial plan or partially
    known context is ``ANALYZING``; a fully unknown context is ``CREATED``.
    Nothing is executed and no vulnerability is ever claimed.
    """

    bounded_input = _bounded_r38_input(security_agent_input)
    agent_name = _resolve_agent_name(agent_identity, bounded_input)

    context = analyze_xss_context(
        input_location=input_location,
        output_context=output_context,
        reflection_state=reflection_state,
        encoding_state=encoding_state,
        framework_context=framework_context,
    )
    hypotheses = plan_xss_hypotheses(context)
    evidence = plan_xss_evidence(context, hypotheses)
    governance_reference = build_governance_reference(governance_plan)

    status = _derive_status(
        context["context_confidence"], evidence["evidence_state"]
    )

    limitations = [
        LIMITATION_NO_EXECUTION_PERFORMED,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_HYPOTHESIS_ONLY,
    ]
    if context["context_confidence"] == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)
    if governance_reference["reference_state"] != GOVERNANCE_REFERENCED:
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if status == STATUS_UNKNOWN:
        limitations.append(LIMITATION_RESULT_UNKNOWN)

    plan = XSSAgentResultPlan(
        rule_version=XSS_AGENT_RESULT_RULE_VERSION,
        agent_name=agent_name,
        status=status,
        context_analysis=context,
        hypotheses=hypotheses,
        evidence_plan=evidence,
        confidence=evidence["confidence"],
        limitations=limitations,
        governance_reference=governance_reference,
        research_only=True,
    )
    return xss_agent_result_plan_projection(plan)


def xss_agent_result_to_r38(result_plan: object = None) -> dict:
    """Project the XSS result onto a valid R38 result plan.

    The R38 result vocabulary is a subset of the R39 semantics: hypotheses
    map to ``HYPOTHESES_RECORDED`` and the evidence state maps to the R38
    evidence summary. The R38 validator then applies its conservative
    status rules (for example, ``CREATED``/``ANALYZING`` suppress findings).
    """

    result = sanitize_xss_agent_result_plan(
        result_plan
        if isinstance(result_plan, dict)
        else export_xss_agent_result()
    )
    findings_summary = (
        FINDINGS_HYPOTHESES if result["hypotheses"] else FINDINGS_NONE
    )
    evidence_summary = _EVIDENCE_TO_R38.get(
        result["evidence_plan"]["evidence_state"], EVIDENCE_UNKNOWN
    )
    return validate_security_agent_result(
        agent_name=result["agent_name"],
        status=result["status"],
        confidence=result["confidence"],
        findings_summary=findings_summary,
        evidence_summary=evidence_summary,
        limitations=[LIMITATION_NO_EXECUTION_PERFORMED],
    )


__all__ = [
    "XSS_AGENT_RESULT_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "build_governance_reference",
    "export_xss_agent_result",
    "xss_agent_result_to_r38",
]

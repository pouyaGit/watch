"""Stage R41.5 deterministic SQLi agent result exporter (pure engine).

Packages the SQLi research pipeline into the standard, R38-compatible
result:

    "What did the SQLi research agent conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Research intelligence only: no SQL execution, no database connection, no
  SQL payload storage or generation, no HTTP/network request, no fuzzing,
  no parameter brute forcing, no sqlmap, no browser, no socket, no
  subprocess, no shell, no external API, no LLM call, no persistence, no
  worker or scheduler. Nothing is executed.
- R38 integration: context enters through the R38 read-only input contract
  and the result projects onto a valid ``SecurityAgentResultPlan``.
- R37 integration: the result carries a bounded governance reference built
  from the R37 governance export; incomplete governance is never treated as
  valid.
- Provenance: the result records which R31-R37 input layers were supplied.
- Pure and offline: no I/O, no SQL, no network, no LLM, no target
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
from ai.knowledge.sqli_agent_identity import (
    plan_sqli_agent_identity,
)
from ai.knowledge.sqli_context_analyzer import analyze_sqli_context
from ai.knowledge.sqli_evidence_planner import plan_sqli_evidence
from ai.knowledge.sqli_hypothesis_planner import plan_sqli_hypotheses
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
from ai.schemas.sqli_agent_identity import (
    SQLI_CATEGORY,
    sanitize_sqli_agent_identity_plan,
)
from ai.schemas.sqli_agent_result import (
    GOVERNANCE_REFERENCED,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SQL_EXECUTION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_RESULT_UNKNOWN,
    PROVENANCE_AUTHORIZATION,
    PROVENANCE_COMPLETE,
    PROVENANCE_GOVERNANCE,
    PROVENANCE_LAYERS,
    PROVENANCE_MEMORY,
    PROVENANCE_ORCHESTRATION,
    PROVENANCE_PARTIAL,
    PROVENANCE_REASONING,
    PROVENANCE_STRATEGY,
    PROVENANCE_UNKNOWN,
    SQLI_AGENT_RESULT_RULE_VERSION,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_UNKNOWN,
    SQLIAgentResultPlan,
    sanitize_governance_reference,
    sanitize_provenance,
    sanitize_sqli_agent_result_plan,
    sqli_agent_result_plan_projection,
)
from ai.schemas.sqli_evidence_plan import (
    STATE_COMPLETE,
    STATE_PARTIAL,
)

SQLI_AGENT_RESULT_EXPORTER_RULE_VERSION = "r41-5"
RULE_VERSION = SQLI_AGENT_RESULT_EXPORTER_RULE_VERSION

_INPUT_KEYS: tuple[str, ...] = (
    "agent_identity",
    "research_context",
    "memory_context",
    "strategy_context",
    "orchestration_context",
    "authorization_context",
    "governance_context",
)

_LAYER_CONTEXT_KEYS: tuple[tuple[str, str], ...] = (
    (PROVENANCE_REASONING, "research_context"),
    (PROVENANCE_MEMORY, "memory_context"),
    (PROVENANCE_STRATEGY, "strategy_context"),
    (PROVENANCE_ORCHESTRATION, "orchestration_context"),
    (PROVENANCE_AUTHORIZATION, "authorization_context"),
    (PROVENANCE_GOVERNANCE, "governance_context"),
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


def _resolve_identity(
    agent_identity: object,
    bounded_input: dict,
) -> dict:
    """Resolve the SQLi identity from an explicit or R38-supplied plan."""

    source = agent_identity if isinstance(agent_identity, dict) else None
    if source is None:
        candidate = bounded_input.get("agent_identity") or {}
        if (
            candidate.get("category") == SQLI_CATEGORY
            and candidate.get("agent_id")
        ):
            source = candidate
    sanitized = sanitize_sqli_agent_identity_plan(source)
    return plan_sqli_agent_identity(
        maturity=sanitized["maturity"] or None,
        version=sanitized["version"] or None,
        supported_contexts=sanitized["supported_contexts"] or None,
        supported_capabilities=(
            sanitized["supported_capabilities"] or None
        ),
        lifecycle_state=sanitized["lifecycle_state"] or None,
        agent_name=sanitized["agent_name"] or None,
    )


def build_governance_reference(governance_plan: object = None) -> dict:
    """Build a bounded R37 governance reference (read-only).

    A reference is ``REFERENCED`` only when the plan carries the R37
    governance export rule version and all four component records; missing,
    malformed, foreign or component-less plans degrade to ``UNKNOWN`` with
    ``ready=False``.
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


def build_provenance(
    bounded_input: object = None,
    governance_reference: object = None,
) -> dict:
    """Build the bounded R31-R37 provenance reference (read-only).

    Source layers are recorded only when the corresponding R38 input context
    block was actually supplied (non-empty); the governance layer is also
    recorded when a real R37 governance reference was attached. No layer is
    ever invented.
    """

    layers: list[str] = []
    if isinstance(bounded_input, dict):
        for layer, key in _LAYER_CONTEXT_KEYS:
            block = bounded_input.get(key)
            if isinstance(block, dict) and block and layer not in layers:
                layers.append(layer)
    reference = (
        governance_reference
        if isinstance(governance_reference, dict)
        else {}
    )
    if (
        reference.get("reference_state") == GOVERNANCE_REFERENCED
        and "GOVERNANCE" not in layers
    ):
        layers.append("GOVERNANCE")
    if len(layers) >= len(PROVENANCE_LAYERS):
        state = PROVENANCE_COMPLETE
    elif layers:
        state = PROVENANCE_PARTIAL
    else:
        state = PROVENANCE_UNKNOWN
    return sanitize_provenance(
        {
            "rule_version": SQLI_AGENT_RESULT_RULE_VERSION,
            "source_layers": layers,
            "provenance_state": state,
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


def export_sqli_agent_result(
    agent_identity: object = None,
    security_agent_input: object = None,
    input_location: object = None,
    parameter_type: object = None,
    data_flow: object = None,
    query_context: object = None,
    database_context: object = None,
    input_handling: object = None,
    type_handling: object = None,
    error_behavior: object = None,
    behavioral_signal: object = None,
    governance_plan: object = None,
) -> dict:
    """Run the deterministic SQLi research pipeline into a result.

    The pipeline analyzes bounded context, plans hypotheses and evidence, and
    records the R37 governance reference and R31-R37 provenance. Status is
    conservative: only a complete evidence plan is ``COMPLETED``; a partial
    plan or partially known context is ``ANALYZING``; a fully unknown context
    is ``CREATED``. Nothing is executed and SQLi is never claimed.
    """

    bounded_input = _bounded_r38_input(security_agent_input)
    identity = _resolve_identity(agent_identity, bounded_input)

    context = analyze_sqli_context(
        input_location=input_location,
        parameter_type=parameter_type,
        data_flow=data_flow,
        query_context=query_context,
        database_context=database_context,
        input_handling=input_handling,
        type_handling=type_handling,
        error_behavior=error_behavior,
        behavioral_signal=behavioral_signal,
    )
    hypotheses = plan_sqli_hypotheses(context)
    evidence = plan_sqli_evidence(context, hypotheses)
    governance_reference = build_governance_reference(governance_plan)
    provenance = build_provenance(bounded_input, governance_reference)

    status = _derive_status(
        context["context_confidence"], evidence["evidence_state"]
    )

    limitations = [
        LIMITATION_NO_EXECUTION_PERFORMED,
        LIMITATION_NO_SQL_EXECUTION,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if context["context_confidence"] == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)
    if governance_reference["reference_state"] != GOVERNANCE_REFERENCED:
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if status == STATUS_UNKNOWN:
        limitations.append(LIMITATION_RESULT_UNKNOWN)

    plan = SQLIAgentResultPlan(
        rule_version=SQLI_AGENT_RESULT_RULE_VERSION,
        agent_name=identity["agent_name"],
        agent_identity=identity,
        status=status,
        context_analysis=context,
        hypotheses=hypotheses,
        evidence_plan=evidence,
        confidence=evidence["confidence"],
        limitations=limitations,
        governance_reference=governance_reference,
        provenance=provenance,
        research_only=True,
    )
    return sqli_agent_result_plan_projection(plan)


def sqli_agent_result_to_r38(result_plan: object = None) -> dict:
    """Project the SQLi result onto a valid R38 result plan.

    Hypotheses map to ``HYPOTHESES_RECORDED`` and the evidence state maps to
    the R38 evidence summary. The R38 validator then applies its conservative
    status rules (for example, ``CREATED``/``ANALYZING`` suppress findings).
    """

    result = sanitize_sqli_agent_result_plan(
        result_plan
        if isinstance(result_plan, dict)
        else export_sqli_agent_result()
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
    "SQLI_AGENT_RESULT_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "build_governance_reference",
    "build_provenance",
    "export_sqli_agent_result",
    "sqli_agent_result_to_r38",
]

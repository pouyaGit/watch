"""Stage R50.5 deterministic CVE research agent result exporter.

Packages the CVE research pipeline into the standard, R38-compatible
result:

    "What did the CVE research specialist conclude, and within which
     bounded limitations?"

Hard boundaries encoded here:

- Research intelligence only: no NVD/vendor API call, no web request, no
  reference retrieval, no exploit retrieval, no network access, no
  socket, no DNS, no database, no scanner, no vulnerability reproduction,
  no payload storage or generation, no secret extraction, no execution,
  no subprocess, no external API, no LLM call, no persistence, no worker
  or scheduler.
- R38 integration: context enters through the R38 read-only input
  contract and the result projects onto a valid ``SecurityAgentResultPlan``.
- R37 integration: the result carries a bounded governance reference built
  from the R37 governance export; incomplete governance is never treated
  as valid or as CVE research readiness.
- Provenance: the result records which R31-R37 input layers were supplied.
- Observed evidence is preserved exactly as supplied; vulnerability
  confirmation, exploitation or secret material is never fabricated.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.cve_research_agent_identity import (
    plan_cve_research_agent_identity,
)
from ai.knowledge.cve_research_context_analyzer import (
    analyze_cve_research_context,
)
from ai.knowledge.cve_research_evidence_planner import (
    plan_cve_research_evidence,
)
from ai.knowledge.cve_research_hypothesis_planner import (
    plan_cve_research_hypotheses,
)
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.security_agent_result_validator import (
    validate_security_agent_result,
)
from ai.schemas.cve_research_agent_identity import (
    CVE_RESEARCH_CATEGORY,
    sanitize_cve_research_agent_identity_plan,
)
from ai.schemas.cve_research_agent_result import (
    CVE_RESEARCH_AGENT_RESULT_RULE_VERSION,
    GOVERNANCE_REFERENCED,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_CVE_LOOKUP,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_RETRIEVAL,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_REFERENCE_RETRIEVAL,
    LIMITATION_NO_SCANNER_EXECUTION,
    LIMITATION_NO_SECRET_EXTRACTION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_VULNERABILITY_REPRODUCTION,
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
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_UNKNOWN,
    CVEResearchAgentResultPlan,
    cve_research_agent_result_plan_projection,
    sanitize_cve_research_agent_result_plan,
    sanitize_governance_reference,
    sanitize_provenance,
)
from ai.schemas.cve_research_evidence_plan import (
    STATE_COMPLETE,
    STATE_PARTIAL,
)
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

CVE_RESEARCH_AGENT_RESULT_EXPORTER_RULE_VERSION = "r50-5"
RULE_VERSION = CVE_RESEARCH_AGENT_RESULT_EXPORTER_RULE_VERSION

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
    """Resolve the CVE research identity from an explicit or R38 plan."""

    source = agent_identity if isinstance(agent_identity, dict) else None
    if source is None:
        candidate = bounded_input.get("agent_identity") or {}
        if (
            candidate.get("category") == CVE_RESEARCH_CATEGORY
            and candidate.get("agent_id")
        ):
            source = candidate
    sanitized = sanitize_cve_research_agent_identity_plan(source)
    return plan_cve_research_agent_identity(
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
    ``ready=False``. Unknown governance is never treated as CVE research
    readiness.
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

    Source layers are recorded only when the corresponding R38 input
    context block was actually supplied (non-empty); the governance layer
    is also recorded when a real R37 governance reference was attached. No
    layer is ever invented.
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
            "rule_version": CVE_RESEARCH_AGENT_RESULT_RULE_VERSION,
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


def export_cve_research_agent_result(
    agent_identity: object = None,
    security_agent_input: object = None,
    governance_plan: object = None,
    cve_metadata: object = None,
    vulnerability_description: object = None,
    affected_product: object = None,
    affected_versions: object = None,
    fixed_version: object = None,
    vendor_advisory: object = None,
    cwe_metadata: object = None,
    cvss_metadata: object = None,
    references: object = None,
    patch_information: object = None,
    observed_component: object = None,
    observed_version: object = None,
    technology_mapping: object = None,
    version_match: object = None,
    component_match: object = None,
    advisory_match: object = None,
    cwe_match: object = None,
    cvss_severity: object = None,
    attack_vector: object = None,
    prerequisites: object = None,
    exploit_maturity: object = None,
    fixed_version_state: object = None,
    patch_state: object = None,
    reference_corroboration: object = None,
    applicability_evidence: object = None,
    historical_context: object = None,
    target_exposure: object = None,
) -> dict:
    """Run the deterministic CVE research pipeline into a result.

    The pipeline analyzes bounded context, plans hypotheses and evidence,
    and records the R37 governance reference and R31-R37 provenance.
    Status is conservative: only a complete evidence plan is
    ``COMPLETED``; a partial plan or partially known context is
    ``ANALYZING``; a fully unknown context is ``CREATED``. Nothing is
    executed, fetched or confirmed.
    """

    bounded_input = _bounded_r38_input(security_agent_input)
    identity = _resolve_identity(agent_identity, bounded_input)

    supplied = {
        "cve_metadata": cve_metadata,
        "vulnerability_description": vulnerability_description,
        "affected_product": affected_product,
        "affected_versions": affected_versions,
        "fixed_version": fixed_version,
        "vendor_advisory": vendor_advisory,
        "cwe_metadata": cwe_metadata,
        "cvss_metadata": cvss_metadata,
        "references": references,
        "patch_information": patch_information,
        "observed_component": observed_component,
        "observed_version": observed_version,
        "technology_mapping": technology_mapping,
        "version_match": version_match,
        "component_match": component_match,
        "advisory_match": advisory_match,
        "cwe_match": cwe_match,
        "cvss_severity": cvss_severity,
        "attack_vector": attack_vector,
        "prerequisites": prerequisites,
        "exploit_maturity": exploit_maturity,
        "fixed_version_state": fixed_version_state,
        "patch_state": patch_state,
        "reference_corroboration": reference_corroboration,
        "applicability_evidence": applicability_evidence,
        "historical_context": historical_context,
        "target_exposure": target_exposure,
    }
    context = analyze_cve_research_context(**supplied)
    hypotheses = plan_cve_research_hypotheses(context)
    evidence = plan_cve_research_evidence(context, hypotheses)
    governance_reference = build_governance_reference(governance_plan)
    provenance = build_provenance(bounded_input, governance_reference)

    status = _derive_status(
        context["context_confidence"], evidence["evidence_state"]
    )

    limitations = [
        LIMITATION_NO_EXECUTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_CVE_LOOKUP,
        LIMITATION_NO_REFERENCE_RETRIEVAL,
        LIMITATION_NO_EXPLOIT_RETRIEVAL,
        LIMITATION_NO_VULNERABILITY_REPRODUCTION,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_SCANNER_EXECUTION,
        LIMITATION_NO_SECRET_EXTRACTION,
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

    plan = CVEResearchAgentResultPlan(
        rule_version=CVE_RESEARCH_AGENT_RESULT_RULE_VERSION,
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
    return cve_research_agent_result_plan_projection(plan)


def cve_research_agent_result_to_r38(
    result_plan: object = None,
) -> dict:
    """Project the CVE research result onto a valid R38 result plan.

    Hypotheses map to ``HYPOTHESES_RECORDED`` and the evidence state maps
    to the R38 evidence summary. The R38 validator then applies its
    conservative status rules (for example, ``CREATED``/``ANALYZING``
    suppress findings).
    """

    result = sanitize_cve_research_agent_result_plan(
        result_plan
        if isinstance(result_plan, dict)
        else export_cve_research_agent_result()
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
    "CVE_RESEARCH_AGENT_RESULT_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "build_governance_reference",
    "build_provenance",
    "export_cve_research_agent_result",
    "cve_research_agent_result_to_r38",
]

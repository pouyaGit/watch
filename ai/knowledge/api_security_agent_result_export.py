"""Stage R49.5 deterministic API security agent result exporter.

Packages the API security research pipeline into the standard,
R38-compatible result:

    "What did the API security research agent conclude, and within which
     bounded limitations?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no API call, no
  endpoint probing, no network connection, no socket, no DNS, no browser,
  no database, no scanner, no payload storage or generation, no secret
  extraction, no credential testing, no bypass, no execution, no
  subprocess, no external API, no LLM call, no persistence, no worker or
  scheduler.
- R38 integration: context enters through the R38 read-only input
  contract and the result projects onto a valid ``SecurityAgentResultPlan``.
- R37 integration: the result carries a bounded governance reference built
  from the R37 governance export; incomplete governance is never treated
  as valid or as API security readiness.
- Provenance: the result records which R31-R37 input layers were supplied.
- Observed evidence is preserved exactly as supplied; weakness,
  exploitation or secret material is never fabricated.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.api_security_agent_identity import (
    plan_api_security_agent_identity,
)
from ai.knowledge.api_security_context_analyzer import (
    analyze_api_security_context,
)
from ai.knowledge.api_security_evidence_planner import (
    plan_api_security_evidence,
)
from ai.knowledge.api_security_hypothesis_planner import (
    plan_api_security_hypotheses,
)
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.security_agent_result_validator import (
    validate_security_agent_result,
)
from ai.schemas.api_security_agent_identity import (
    API_SECURITY_CATEGORY,
    sanitize_api_security_agent_identity_plan,
)
from ai.schemas.api_security_agent_result import (
    API_SECURITY_AGENT_RESULT_RULE_VERSION,
    GOVERNANCE_REFERENCED,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_API_CALLS,
    LIMITATION_NO_BYPASS_ATTEMPT,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_ENDPOINT_PROBING,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SCANNER_EXECUTION,
    LIMITATION_NO_SECRET_EXTRACTION,
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
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_UNKNOWN,
    APISecurityAgentResultPlan,
    api_security_agent_result_plan_projection,
    sanitize_api_security_agent_result_plan,
    sanitize_governance_reference,
    sanitize_provenance,
)
from ai.schemas.api_security_evidence_plan import (
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

API_SECURITY_AGENT_RESULT_EXPORTER_RULE_VERSION = "r49-5"
RULE_VERSION = API_SECURITY_AGENT_RESULT_EXPORTER_RULE_VERSION

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

_CONTEXT_FIELD_NAMES: tuple[str, ...] = (
    "api_type",
    "api_versioning",
    "content_type",
    "authentication_mechanism",
    "resource_exposure",
    "sensitive_field_exposure",
    "error_detail",
    "debug_information",
    "graphql_introspection",
    "object_authorization_context",
    "endpoint_metadata",
    "request_schema",
    "response_schema",
    "pagination_context",
    "batch_context",
    "file_upload_context",
    "file_download_context",
    "nested_resource_context",
    "graphql_batching",
    "webhook_context",
    "api_authentication",
    "endpoint_authorization",
    "function_role_authorization",
    "tenant_isolation",
    "schema_validation",
    "parameter_validation",
    "unknown_field_handling",
    "content_type_validation",
    "http_method_restrictions",
    "method_override_control",
    "rate_limit_control",
    "request_size_limit",
    "pagination_limit",
    "query_complexity_limit",
    "batch_limit",
    "upload_limit",
    "download_control",
    "error_detail_control",
    "debug_mode_control",
    "sensitive_field_control",
    "cors_origin_policy",
    "cors_credentials_policy",
    "graphql_field_authorization",
    "graphql_mutation_authorization",
    "graphql_depth_limit",
    "graphql_complexity_limit",
    "graphql_introspection_control",
    "api_key_rotation",
    "api_key_revocation",
    "webhook_signature_validation",
    "webhook_replay_protection",
    "webhook_source_validation",
)


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
    """Resolve the API security identity from an explicit or R38 plan."""

    source = agent_identity if isinstance(agent_identity, dict) else None
    if source is None:
        candidate = bounded_input.get("agent_identity") or {}
        if (
            candidate.get("category") == API_SECURITY_CATEGORY
            and candidate.get("agent_id")
        ):
            source = candidate
    sanitized = sanitize_api_security_agent_identity_plan(source)
    return plan_api_security_agent_identity(
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
    ``ready=False``. Unknown governance is never treated as API security
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
            "rule_version": API_SECURITY_AGENT_RESULT_RULE_VERSION,
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


def export_api_security_agent_result(
    agent_identity: object = None,
    security_agent_input: object = None,
    governance_plan: object = None,
    api_type: object = None,
    api_versioning: object = None,
    content_type: object = None,
    authentication_mechanism: object = None,
    resource_exposure: object = None,
    sensitive_field_exposure: object = None,
    error_detail: object = None,
    debug_information: object = None,
    graphql_introspection: object = None,
    object_authorization_context: object = None,
    endpoint_metadata: object = None,
    request_schema: object = None,
    response_schema: object = None,
    pagination_context: object = None,
    batch_context: object = None,
    file_upload_context: object = None,
    file_download_context: object = None,
    nested_resource_context: object = None,
    graphql_batching: object = None,
    webhook_context: object = None,
    api_authentication: object = None,
    endpoint_authorization: object = None,
    function_role_authorization: object = None,
    tenant_isolation: object = None,
    schema_validation: object = None,
    parameter_validation: object = None,
    unknown_field_handling: object = None,
    content_type_validation: object = None,
    http_method_restrictions: object = None,
    method_override_control: object = None,
    rate_limit_control: object = None,
    request_size_limit: object = None,
    pagination_limit: object = None,
    query_complexity_limit: object = None,
    batch_limit: object = None,
    upload_limit: object = None,
    download_control: object = None,
    error_detail_control: object = None,
    debug_mode_control: object = None,
    sensitive_field_control: object = None,
    cors_origin_policy: object = None,
    cors_credentials_policy: object = None,
    graphql_field_authorization: object = None,
    graphql_mutation_authorization: object = None,
    graphql_depth_limit: object = None,
    graphql_complexity_limit: object = None,
    graphql_introspection_control: object = None,
    api_key_rotation: object = None,
    api_key_revocation: object = None,
    webhook_signature_validation: object = None,
    webhook_replay_protection: object = None,
    webhook_source_validation: object = None,
) -> dict:
    """Run the deterministic API security pipeline into a result.

    The pipeline analyzes bounded context, plans hypotheses and evidence,
    and records the R37 governance reference and R31-R37 provenance.
    Status is conservative: only a complete evidence plan is
    ``COMPLETED``; a partial plan or partially known context is
    ``ANALYZING``; a fully unknown context is ``CREATED``. Nothing is
    executed and no vulnerability is claimed.
    """

    bounded_input = _bounded_r38_input(security_agent_input)
    identity = _resolve_identity(agent_identity, bounded_input)

    supplied = {
        "api_type": api_type,
        "api_versioning": api_versioning,
        "content_type": content_type,
        "authentication_mechanism": authentication_mechanism,
        "resource_exposure": resource_exposure,
        "sensitive_field_exposure": sensitive_field_exposure,
        "error_detail": error_detail,
        "debug_information": debug_information,
        "graphql_introspection": graphql_introspection,
        "object_authorization_context": object_authorization_context,
        "endpoint_metadata": endpoint_metadata,
        "request_schema": request_schema,
        "response_schema": response_schema,
        "pagination_context": pagination_context,
        "batch_context": batch_context,
        "file_upload_context": file_upload_context,
        "file_download_context": file_download_context,
        "nested_resource_context": nested_resource_context,
        "graphql_batching": graphql_batching,
        "webhook_context": webhook_context,
        "api_authentication": api_authentication,
        "endpoint_authorization": endpoint_authorization,
        "function_role_authorization": function_role_authorization,
        "tenant_isolation": tenant_isolation,
        "schema_validation": schema_validation,
        "parameter_validation": parameter_validation,
        "unknown_field_handling": unknown_field_handling,
        "content_type_validation": content_type_validation,
        "http_method_restrictions": http_method_restrictions,
        "method_override_control": method_override_control,
        "rate_limit_control": rate_limit_control,
        "request_size_limit": request_size_limit,
        "pagination_limit": pagination_limit,
        "query_complexity_limit": query_complexity_limit,
        "batch_limit": batch_limit,
        "upload_limit": upload_limit,
        "download_control": download_control,
        "error_detail_control": error_detail_control,
        "debug_mode_control": debug_mode_control,
        "sensitive_field_control": sensitive_field_control,
        "cors_origin_policy": cors_origin_policy,
        "cors_credentials_policy": cors_credentials_policy,
        "graphql_field_authorization": graphql_field_authorization,
        "graphql_mutation_authorization": graphql_mutation_authorization,
        "graphql_depth_limit": graphql_depth_limit,
        "graphql_complexity_limit": graphql_complexity_limit,
        "graphql_introspection_control": graphql_introspection_control,
        "api_key_rotation": api_key_rotation,
        "api_key_revocation": api_key_revocation,
        "webhook_signature_validation": webhook_signature_validation,
        "webhook_replay_protection": webhook_replay_protection,
        "webhook_source_validation": webhook_source_validation,
    }
    context = analyze_api_security_context(**supplied)
    hypotheses = plan_api_security_hypotheses(context)
    evidence = plan_api_security_evidence(context, hypotheses)
    governance_reference = build_governance_reference(governance_plan)
    provenance = build_provenance(bounded_input, governance_reference)

    status = _derive_status(
        context["context_confidence"], evidence["evidence_state"]
    )

    limitations = [
        LIMITATION_NO_EXECUTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_API_CALLS,
        LIMITATION_NO_ENDPOINT_PROBING,
        LIMITATION_NO_SCANNER_EXECUTION,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_CREDENTIAL_TESTING,
        LIMITATION_NO_BYPASS_ATTEMPT,
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

    plan = APISecurityAgentResultPlan(
        rule_version=API_SECURITY_AGENT_RESULT_RULE_VERSION,
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
    return api_security_agent_result_plan_projection(plan)


def api_security_agent_result_to_r38(
    result_plan: object = None,
) -> dict:
    """Project the API security result onto a valid R38 result plan.

    Hypotheses map to ``HYPOTHESES_RECORDED`` and the evidence state maps
    to the R38 evidence summary. The R38 validator then applies its
    conservative status rules (for example, ``CREATED``/``ANALYZING``
    suppress findings).
    """

    result = sanitize_api_security_agent_result_plan(
        result_plan
        if isinstance(result_plan, dict)
        else export_api_security_agent_result()
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
    "API_SECURITY_AGENT_RESULT_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "build_governance_reference",
    "build_provenance",
    "export_api_security_agent_result",
    "api_security_agent_result_to_r38",
]

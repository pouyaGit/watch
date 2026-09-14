"""Stage R47.5 deterministic JWT/authentication agent result exporter.

Packages the JWT/authentication research pipeline into the standard,
R38-compatible result:

    "What did the JWT/authentication research agent conclude, and within
     which bounded limitations?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no DNS resolution, no
  socket, no browser, no database, no scanner, no token decoding or
  manipulation, no token forgery, no signature bypass, no authentication
  bypass, no brute force, no credential testing, no payload storage or
  generation, no secret extraction, no execution, no subprocess, no
  external API, no LLM call, no persistence, no worker or scheduler.
- R38 integration: context enters through the R38 read-only input contract
  and the result projects onto a valid ``SecurityAgentResultPlan``.
- R37 integration: the result carries a bounded governance reference built
  from the R37 governance export; incomplete governance is never treated as
  valid or as authentication readiness.
- Provenance: the result records which R31-R37 input layers were supplied.
- Observed evidence is preserved exactly as supplied; weakness,
  exploitation or secret material is never fabricated.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.jwt_authentication_agent_identity import (
    plan_jwt_authentication_agent_identity,
)
from ai.knowledge.jwt_authentication_context_analyzer import (
    analyze_jwt_authentication_context,
)
from ai.knowledge.jwt_authentication_evidence_planner import (
    plan_jwt_authentication_evidence,
)
from ai.knowledge.jwt_authentication_hypothesis_planner import (
    plan_jwt_authentication_hypotheses,
)
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.security_agent_result_validator import (
    validate_security_agent_result,
)
from ai.schemas.evidence_confidence import CONFIDENCE_UNKNOWN
from ai.schemas.jwt_authentication_agent_identity import (
    JWT_AUTHENTICATION_CATEGORY,
    sanitize_jwt_authentication_agent_identity_plan,
)
from ai.schemas.jwt_authentication_agent_result import (
    GOVERNANCE_REFERENCED,
    JWT_AUTHENTICATION_AGENT_RESULT_RULE_VERSION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_AUTHENTICATION_BYPASS,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SECRET_EXTRACTION,
    LIMITATION_NO_SIGNATURE_BYPASS,
    LIMITATION_NO_TOKEN_MANIPULATION,
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
    JWTAuthenticationAgentResultPlan,
    jwt_authentication_agent_result_plan_projection,
    sanitize_governance_reference,
    sanitize_jwt_authentication_agent_result_plan,
    sanitize_provenance,
)
from ai.schemas.jwt_authentication_evidence_plan import (
    STATE_COMPLETE,
    STATE_PARTIAL,
)
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

JWT_AUTHENTICATION_AGENT_RESULT_EXPORTER_RULE_VERSION = "r47-5"
RULE_VERSION = JWT_AUTHENTICATION_AGENT_RESULT_EXPORTER_RULE_VERSION

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
    """Resolve the JWT/authentication identity from an explicit or R38 plan."""

    source = agent_identity if isinstance(agent_identity, dict) else None
    if source is None:
        candidate = bounded_input.get("agent_identity") or {}
        if (
            candidate.get("category") == JWT_AUTHENTICATION_CATEGORY
            and candidate.get("agent_id")
        ):
            source = candidate
    sanitized = sanitize_jwt_authentication_agent_identity_plan(source)
    return plan_jwt_authentication_agent_identity(
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
    ``ready=False``. Unknown governance is never treated as authentication
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
            "rule_version": JWT_AUTHENTICATION_AGENT_RESULT_RULE_VERSION,
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


def export_jwt_authentication_agent_result(
    agent_identity: object = None,
    security_agent_input: object = None,
    authentication_mechanism: object = None,
    token_mechanism: object = None,
    token_format: object = None,
    signing_algorithm: object = None,
    signing_method: object = None,
    signature_verification: object = None,
    algorithm_validation: object = None,
    issuer_validation: object = None,
    audience_validation: object = None,
    expiration_validation: object = None,
    not_before_validation: object = None,
    claim_validation: object = None,
    key_management: object = None,
    key_rotation: object = None,
    token_lifetime: object = None,
    refresh_token: object = None,
    refresh_control: object = None,
    revocation_control: object = None,
    session_lifecycle: object = None,
    token_storage: object = None,
    cookie_attributes: object = None,
    token_exposure: object = None,
    authorization_boundary: object = None,
    authentication_flow: object = None,
    authentication_control: object = None,
    governance_plan: object = None,
) -> dict:
    """Run the deterministic JWT/authentication pipeline into a result.

    The pipeline analyzes bounded context, plans hypotheses and evidence, and
    records the R37 governance reference and R31-R37 provenance. Status is
    conservative: only a complete evidence plan is ``COMPLETED``; a partial
    plan or partially known context is ``ANALYZING``; a fully unknown context
    is ``CREATED``. Nothing is executed and no vulnerability is claimed.
    """

    bounded_input = _bounded_r38_input(security_agent_input)
    identity = _resolve_identity(agent_identity, bounded_input)

    context = analyze_jwt_authentication_context(
        authentication_mechanism=authentication_mechanism,
        token_mechanism=token_mechanism,
        token_format=token_format,
        signing_algorithm=signing_algorithm,
        signing_method=signing_method,
        signature_verification=signature_verification,
        algorithm_validation=algorithm_validation,
        issuer_validation=issuer_validation,
        audience_validation=audience_validation,
        expiration_validation=expiration_validation,
        not_before_validation=not_before_validation,
        claim_validation=claim_validation,
        key_management=key_management,
        key_rotation=key_rotation,
        token_lifetime=token_lifetime,
        refresh_token=refresh_token,
        refresh_control=refresh_control,
        revocation_control=revocation_control,
        session_lifecycle=session_lifecycle,
        token_storage=token_storage,
        cookie_attributes=cookie_attributes,
        token_exposure=token_exposure,
        authorization_boundary=authorization_boundary,
        authentication_flow=authentication_flow,
        authentication_control=authentication_control,
    )
    hypotheses = plan_jwt_authentication_hypotheses(context)
    evidence = plan_jwt_authentication_evidence(context, hypotheses)
    governance_reference = build_governance_reference(governance_plan)
    provenance = build_provenance(bounded_input, governance_reference)

    status = _derive_status(
        context["context_confidence"], evidence["evidence_state"]
    )

    limitations = [
        LIMITATION_NO_EXECUTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_TOKEN_MANIPULATION,
        LIMITATION_NO_SIGNATURE_BYPASS,
        LIMITATION_NO_AUTHENTICATION_BYPASS,
        LIMITATION_NO_CREDENTIAL_TESTING,
        LIMITATION_NO_PAYLOAD_GENERATION,
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

    plan = JWTAuthenticationAgentResultPlan(
        rule_version=JWT_AUTHENTICATION_AGENT_RESULT_RULE_VERSION,
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
    return jwt_authentication_agent_result_plan_projection(plan)


def jwt_authentication_agent_result_to_r38(
    result_plan: object = None,
) -> dict:
    """Project the JWT/authentication result onto a valid R38 result plan.

    Hypotheses map to ``HYPOTHESES_RECORDED`` and the evidence state maps to
    the R38 evidence summary. The R38 validator then applies its conservative
    status rules (for example, ``CREATED``/``ANALYZING`` suppress findings).
    """

    result = sanitize_jwt_authentication_agent_result_plan(
        result_plan
        if isinstance(result_plan, dict)
        else export_jwt_authentication_agent_result()
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
    "JWT_AUTHENTICATION_AGENT_RESULT_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "build_governance_reference",
    "build_provenance",
    "export_jwt_authentication_agent_result",
    "jwt_authentication_agent_result_to_r38",
]

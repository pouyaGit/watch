"""Stage R46.2 deterministic IDOR/BOLA context analyzer (pure engine).

Classifies object-level-authorization-relevant research context from bounded
observations:

    "Is there object-reference context, and what authorization evidence
     surrounds it?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP request, no DNS resolution, no socket,
  no database, no scanner, no browser, no object access, no authorization
  bypass, no payload, no subprocess, no LLM. Nothing is performed.
- An identifier, an object lookup, a route or a numeric parameter is NOT
  evidence of IDOR/BOLA. The analyzer distinguishes:
  object identifier exposure, authorization control evidence,
  ownership/tenant/role boundary evidence, observed authorization behavior
  and missing evidence.
- Confidence means "how complete/relevant is the supplied object-level
  authorization context?". It does NOT mean "probability that IDOR/BOLA
  exists". No vulnerability is confirmed.
- Confidence is capped at MEDIUM unless server-side authorization evidence is
  present together with object-reference and boundary context; a missing
  authorization signal can never produce HIGH confidence.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.idor_bola_context_analysis import (
    AUTH_CONTROL_ABSENT,
    AUTH_CONTROL_UNKNOWN,
    AUTH_LOCATION_SERVER_SIDE,
    AUTH_LOCATION_UNKNOWN,
    AUTHORIZATION_BEHAVIORS,
    AUTHORIZATION_CONTROL_PRESENT_STATES,
    AUTHORIZATION_CONTROLS,
    AUTHORIZATION_LOCATIONS,
    BEHAVIOR_UNKNOWN,
    BOUNDARY_NOT_RECORDED_STATES,
    BOUNDARY_RECORDED_STATES,
    CROSS_CONTEXT_BEHAVIORS,
    IDENTIFIER_TYPES,
    IDENT_UNKNOWN,
    IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION,
    IDORBOLAContextAnalysisPlan,
    LOOKUP_UNKNOWN,
    OBJREF_NONE_OBSERVED,
    OBJREF_UNKNOWN,
    OBJECT_LOOKUP_PATTERNS,
    OBJECT_REFERENCE_LOCATIONS,
    OWNERSHIP_STATES,
    OWNER_UNKNOWN,
    RESOURCE_TYPES,
    RESOURCE_UNKNOWN,
    ROLE_BOUNDARY_STATES,
    ROLE_UNKNOWN,
    ROUTE_CONTEXTS,
    ROUTE_UNKNOWN,
    TENANT_BOUNDARY_STATES,
    TENANT_UNKNOWN,
    idor_bola_context_analysis_plan_projection,
    sanitize_idor_bola_context_analysis_plan,
)

IDOR_BOLA_CONTEXT_ANALYZER_RULE_VERSION = "r46-2"
RULE_VERSION = IDOR_BOLA_CONTEXT_ANALYZER_RULE_VERSION

KNOWN_FIELDS: tuple[str, ...] = (
    "object_reference",
    "resource_type",
    "identifier_type",
    "ownership_relationship",
    "tenant_boundary",
    "role_boundary",
    "authorization_control",
    "authorization_location",
    "object_lookup",
    "authorization_behavior",
    "route_context",
)

UNKNOWN_VALUES: tuple[str, ...] = (
    OBJREF_UNKNOWN,
    RESOURCE_UNKNOWN,
    IDENT_UNKNOWN,
    OWNER_UNKNOWN,
    TENANT_UNKNOWN,
    ROLE_UNKNOWN,
    AUTH_CONTROL_UNKNOWN,
    LOOKUP_UNKNOWN,
    BEHAVIOR_UNKNOWN,
    ROUTE_UNKNOWN,
)

NON_REFERENCE_VALUES: tuple[str, ...] = (
    OBJREF_NONE_OBSERVED,
    OBJREF_UNKNOWN,
)

BOUNDARY_FACT_STATES: tuple[str, ...] = (
    BOUNDARY_RECORDED_STATES + BOUNDARY_NOT_RECORDED_STATES
)

_CONFIDENCE_ORDER: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _base_confidence(known_count: int) -> str:
    if known_count >= 9:
        return CONFIDENCE_HIGH
    if known_count >= 5:
        return CONFIDENCE_MEDIUM
    if known_count >= 1:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def _cap(confidence: str, ceiling: str) -> str:
    if _CONFIDENCE_ORDER[confidence] <= _CONFIDENCE_ORDER[ceiling]:
        return confidence
    return ceiling


def _confidence_for(
    object_reference: str,
    authorization_control: str,
    authorization_location: str,
    boundary_fact_count: int,
    known_count: int,
) -> str:
    if object_reference in NON_REFERENCE_VALUES:
        return CONFIDENCE_UNKNOWN
    confidence = _base_confidence(known_count)
    if authorization_control in AUTHORIZATION_CONTROL_PRESENT_STATES:
        if (
            authorization_location == AUTH_LOCATION_SERVER_SIDE
            and boundary_fact_count >= 1
        ):
            return confidence
        return _cap(confidence, CONFIDENCE_MEDIUM)
    return _cap(confidence, CONFIDENCE_MEDIUM)


def analyze_idor_bola_context(
    object_reference: object = None,
    resource_type: object = None,
    identifier_type: object = None,
    ownership_relationship: object = None,
    tenant_boundary: object = None,
    role_boundary: object = None,
    authorization_control: object = None,
    authorization_location: object = None,
    object_lookup: object = None,
    authorization_behavior: object = None,
    route_context: object = None,
) -> dict:
    """Build the deterministic descriptive IDOR/BOLA context analysis.

    Confidence is a pure function of supplied facts with a hard safety cap:
    unless server-side authorization evidence is present together with
    object-reference and boundary context, confidence can never exceed
    MEDIUM. An identifier alone, a numeric parameter alone or a resource
    lookup alone can never produce HIGH confidence.
    """

    resolved_reference = _closed(
        object_reference, OBJECT_REFERENCE_LOCATIONS, OBJREF_UNKNOWN
    )
    resolved_resource = _closed(
        resource_type, RESOURCE_TYPES, RESOURCE_UNKNOWN
    )
    resolved_identifier = _closed(
        identifier_type, IDENTIFIER_TYPES, IDENT_UNKNOWN
    )
    resolved_ownership = _closed(
        ownership_relationship, OWNERSHIP_STATES, OWNER_UNKNOWN
    )
    resolved_tenant = _closed(
        tenant_boundary, TENANT_BOUNDARY_STATES, TENANT_UNKNOWN
    )
    resolved_role = _closed(
        role_boundary, ROLE_BOUNDARY_STATES, ROLE_UNKNOWN
    )
    resolved_control = _closed(
        authorization_control, AUTHORIZATION_CONTROLS, AUTH_CONTROL_UNKNOWN
    )
    resolved_location = _closed(
        authorization_location,
        AUTHORIZATION_LOCATIONS,
        AUTH_LOCATION_UNKNOWN,
    )
    resolved_lookup = _closed(
        object_lookup, OBJECT_LOOKUP_PATTERNS, LOOKUP_UNKNOWN
    )
    resolved_behavior = _closed(
        authorization_behavior,
        AUTHORIZATION_BEHAVIORS,
        BEHAVIOR_UNKNOWN,
    )
    resolved_route = _closed(
        route_context, ROUTE_CONTEXTS, ROUTE_UNKNOWN
    )

    values = (
        resolved_reference,
        resolved_resource,
        resolved_identifier,
        resolved_ownership,
        resolved_tenant,
        resolved_role,
        resolved_control,
        resolved_location,
        resolved_lookup,
        resolved_behavior,
        resolved_route,
    )
    known_count = sum(1 for value in values if value not in UNKNOWN_VALUES)
    boundary_fact_count = sum(
        1
        for value in (
            resolved_ownership,
            resolved_tenant,
            resolved_role,
        )
        if value in BOUNDARY_FACT_STATES
    )
    confidence = _confidence_for(
        resolved_reference,
        resolved_control,
        resolved_location,
        boundary_fact_count,
        known_count,
    )

    plan = IDORBOLAContextAnalysisPlan(
        rule_version=IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION,
        object_reference=resolved_reference,
        resource_type=resolved_resource,
        identifier_type=resolved_identifier,
        ownership_relationship=resolved_ownership,
        tenant_boundary=resolved_tenant,
        role_boundary=resolved_role,
        authorization_control=resolved_control,
        authorization_location=resolved_location,
        object_lookup=resolved_lookup,
        authorization_behavior=resolved_behavior,
        route_context=resolved_route,
        context_confidence=confidence,
        research_only=True,
    )
    return idor_bola_context_analysis_plan_projection(plan)


def idor_bola_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so partial
    context dicts supplied directly to downstream planners receive the
    correct, safety-capped confidence.
    """

    plan = sanitize_idor_bola_context_analysis_plan(value)
    known_count = sum(
        1 for key in KNOWN_FIELDS if plan[key] not in UNKNOWN_VALUES
    )
    boundary_fact_count = sum(
        1
        for key in (
            "ownership_relationship",
            "tenant_boundary",
            "role_boundary",
        )
        if plan[key] in BOUNDARY_FACT_STATES
    )
    return _confidence_for(
        plan["object_reference"],
        plan["authorization_control"],
        plan["authorization_location"],
        boundary_fact_count,
        known_count,
    )


def idor_bola_object_reference_present(value: object) -> bool:
    """True when a known object reference location was supplied."""

    plan = sanitize_idor_bola_context_analysis_plan(value)
    return plan["object_reference"] not in NON_REFERENCE_VALUES


def idor_bola_authorization_control_present(value: object) -> bool:
    """True only when a positive authorization control was supplied."""

    plan = sanitize_idor_bola_context_analysis_plan(value)
    return (
        plan["authorization_control"]
        in AUTHORIZATION_CONTROL_PRESENT_STATES
    )


def idor_bola_authorization_control_absent(value: object) -> bool:
    """True only when authorization control was explicitly absent."""

    plan = sanitize_idor_bola_context_analysis_plan(value)
    return plan["authorization_control"] == AUTH_CONTROL_ABSENT


def idor_bola_authorization_control_unknown(value: object) -> bool:
    """True when neither presence nor explicit absence was supplied."""

    plan = sanitize_idor_bola_context_analysis_plan(value)
    control = plan["authorization_control"]
    return (
        control != AUTH_CONTROL_ABSENT
        and control not in AUTHORIZATION_CONTROL_PRESENT_STATES
    )


def idor_bola_boundary_context_count(value: object) -> int:
    """Count supplied ownership/tenant/role boundary facts."""

    plan = sanitize_idor_bola_context_analysis_plan(value)
    return sum(
        1
        for key in (
            "ownership_relationship",
            "tenant_boundary",
            "role_boundary",
        )
        if plan[key] in BOUNDARY_FACT_STATES
    )


def idor_bola_cross_context_behavior_observed(value: object) -> bool:
    """True only when cross-user/cross-tenant access was explicitly supplied.

    This never fabricates behavior: it is true solely when the supplied
    context already contains an explicit cross-context observation.
    """

    plan = sanitize_idor_bola_context_analysis_plan(value)
    return plan["authorization_behavior"] in CROSS_CONTEXT_BEHAVIORS


__all__ = [
    "IDOR_BOLA_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "KNOWN_FIELDS",
    "UNKNOWN_VALUES",
    "NON_REFERENCE_VALUES",
    "BOUNDARY_FACT_STATES",
    "analyze_idor_bola_context",
    "idor_bola_context_confidence_of",
    "idor_bola_object_reference_present",
    "idor_bola_authorization_control_present",
    "idor_bola_authorization_control_absent",
    "idor_bola_authorization_control_unknown",
    "idor_bola_boundary_context_count",
    "idor_bola_cross_context_behavior_observed",
]

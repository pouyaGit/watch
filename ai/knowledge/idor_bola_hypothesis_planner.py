"""Stage R46.3 deterministic IDOR/BOLA hypothesis planner (pure engine).

Creates deterministic research hypotheses from supplied object-level
authorization context:

    "Which IDOR/BOLA review hypothesis follows from the supplied context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no authorization-bypass claim, no payload, no executable request, no
  attack sequence, no object access, no network/database execution.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, signals, confidence,
  priority and limitations are pure functions of the bounded context.
- An identifier, an object lookup or a resource route is never claimed as a
  broken authorization. Explicit authorization controls reduce hypothesis
  priority but never erase the hypothesis: the control is preserved and
  reported as authorization evidence.
- Priority is research usefulness only (never severity, exploitability,
  CVSS or vulnerability probability).
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.idor_bola_context_analyzer import (
    idor_bola_context_confidence_of,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.idor_bola_context_analysis import (
    AUTH_CONTROL_ABSENT,
    AUTH_CONTROL_MIDDLEWARE,
    AUTH_CONTROL_OWNERSHIP_CHECK,
    AUTH_CONTROL_POLICY_ENFORCEMENT,
    AUTH_CONTROL_ROLE_AUTHORIZATION,
    AUTH_CONTROL_SERVER_SIDE,
    AUTH_CONTROL_TENANT_AUTHORIZATION,
    AUTH_LOCATION_CLIENT_SIDE,
    AUTH_LOCATION_SERVER_SIDE,
    AUTHORIZATION_CONTROL_PRESENT_STATES,
    BEHAVIOR_ACCESS_DENIED_OBSERVED,
    BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED,
    BEHAVIOR_CROSS_USER_ACCESS_OBSERVED,
    BEHAVIOR_NO_BEHAVIOR_OBSERVED,
    BEHAVIOR_OWN_OBJECT_ONLY_OBSERVED,
    CROSS_CONTEXT_BEHAVIORS,
    IDENT_COMPOSITE,
    IDENT_OPAQUE,
    IDENT_SEQUENTIAL_INTEGER,
    IDENT_UUID,
    LOOKUP_BY_IDENTIFIER,
    LOOKUP_BY_OWNED_SCOPE,
    LOOKUP_BY_TENANT_SCOPE,
    OBJREF_BODY_FIELD,
    OBJREF_COOKIE_VALUE,
    OBJREF_HEADER_VALUE,
    OBJREF_PATH_PARAMETER,
    OBJREF_QUERY_PARAMETER,
    OWNER_NOT_RECORDED,
    OWNER_RECORDED,
    RESOURCE_NONE_OBSERVED,
    RESOURCE_UNKNOWN,
    ROLE_NOT_RECORDED,
    ROLE_RECORDED,
    ROLE_SENSITIVE_ROUTES,
    ROUTE_ADMIN,
    ROUTE_COLLECTION,
    ROUTE_INTERNAL,
    ROUTE_RESOURCE,
    SCOPED_LOOKUP_PATTERNS,
    TENANT_NOT_RECORDED,
    TENANT_RECORDED,
    sanitize_idor_bola_context_analysis_plan,
)
from ai.schemas.idor_bola_hypothesis import (
    HYPOTHESIS_TYPES,
    IDOR_BOLA_HYPOTHESIS_RULE_VERSION,
    IDOR_BOLA_SIGNALS,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_AUTHORIZATION_BYPASS_CLAIM,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_ACCESS_DENIED_OBSERVED,
    SIGNAL_AUTHORIZATION_CLIENT_SIDE_ONLY,
    SIGNAL_AUTHORIZATION_CONTROL_ABSENT,
    SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
    SIGNAL_AUTHORIZATION_MIDDLEWARE_PRESENT,
    SIGNAL_AUTHORIZATION_SERVER_SIDE,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_CROSS_TENANT_ACCESS_OBSERVED,
    SIGNAL_CROSS_USER_ACCESS_OBSERVED,
    SIGNAL_IDENTIFIER_COMPOSITE,
    SIGNAL_IDENTIFIER_OPAQUE,
    SIGNAL_IDENTIFIER_SEQUENTIAL,
    SIGNAL_IDENTIFIER_UUID,
    SIGNAL_LOOKUP_BY_IDENTIFIER,
    SIGNAL_LOOKUP_BY_OWNED_SCOPE,
    SIGNAL_LOOKUP_BY_TENANT_SCOPE,
    SIGNAL_NO_BEHAVIOR_OBSERVED,
    SIGNAL_OBJECT_REFERENCE_BODY,
    SIGNAL_OBJECT_REFERENCE_COOKIE,
    SIGNAL_OBJECT_REFERENCE_HEADER,
    SIGNAL_OBJECT_REFERENCE_PATH,
    SIGNAL_OBJECT_REFERENCE_QUERY,
    SIGNAL_OWNER_NOT_RECORDED,
    SIGNAL_OWNER_RECORDED,
    SIGNAL_OWNERSHIP_CHECK_PRESENT,
    SIGNAL_OWN_OBJECT_ONLY_OBSERVED,
    SIGNAL_POLICY_ENFORCEMENT_PRESENT,
    SIGNAL_RESOURCE_TYPE_PRESENT,
    SIGNAL_ROLE_AUTHORIZATION_PRESENT,
    SIGNAL_ROLE_NOT_RECORDED,
    SIGNAL_ROLE_RECORDED,
    SIGNAL_ROUTE_ADMIN,
    SIGNAL_ROUTE_COLLECTION,
    SIGNAL_ROUTE_INTERNAL,
    SIGNAL_ROUTE_RESOURCE,
    SIGNAL_SERVER_SIDE_AUTHORIZATION_PRESENT,
    SIGNAL_TENANT_AUTHORIZATION_PRESENT,
    SIGNAL_TENANT_NOT_RECORDED,
    SIGNAL_TENANT_RECORDED,
    TYPE_AUTHORIZATION_CONTROL_PRESENT,
    TYPE_DIRECT_OBJECT_REFERENCE,
    TYPE_MISSING_AUTHORIZATION_CONTEXT,
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
    TYPE_OWNERSHIP_BOUNDARY_GAP,
    TYPE_ROLE_BOUNDARY_GAP,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_UNKNOWN,
    IDORBOLAHypothesisPlan,
    idor_bola_hypothesis_plan_projection,
)

IDOR_BOLA_HYPOTHESIS_PLANNER_RULE_VERSION = "r46-3"
RULE_VERSION = IDOR_BOLA_HYPOTHESIS_PLANNER_RULE_VERSION

_REFERENCE_SIGNALS: dict[str, str] = {
    OBJREF_PATH_PARAMETER: SIGNAL_OBJECT_REFERENCE_PATH,
    OBJREF_QUERY_PARAMETER: SIGNAL_OBJECT_REFERENCE_QUERY,
    OBJREF_BODY_FIELD: SIGNAL_OBJECT_REFERENCE_BODY,
    OBJREF_HEADER_VALUE: SIGNAL_OBJECT_REFERENCE_HEADER,
    OBJREF_COOKIE_VALUE: SIGNAL_OBJECT_REFERENCE_COOKIE,
}

_IDENTIFIER_SIGNALS: dict[str, str] = {
    IDENT_OPAQUE: SIGNAL_IDENTIFIER_OPAQUE,
    IDENT_SEQUENTIAL_INTEGER: SIGNAL_IDENTIFIER_SEQUENTIAL,
    IDENT_UUID: SIGNAL_IDENTIFIER_UUID,
    IDENT_COMPOSITE: SIGNAL_IDENTIFIER_COMPOSITE,
}

_LOOKUP_SIGNALS: dict[str, str] = {
    LOOKUP_BY_IDENTIFIER: SIGNAL_LOOKUP_BY_IDENTIFIER,
    LOOKUP_BY_OWNED_SCOPE: SIGNAL_LOOKUP_BY_OWNED_SCOPE,
    LOOKUP_BY_TENANT_SCOPE: SIGNAL_LOOKUP_BY_TENANT_SCOPE,
}

_CONTROL_SIGNALS: dict[str, str] = {
    AUTH_CONTROL_POLICY_ENFORCEMENT: SIGNAL_POLICY_ENFORCEMENT_PRESENT,
    AUTH_CONTROL_OWNERSHIP_CHECK: SIGNAL_OWNERSHIP_CHECK_PRESENT,
    AUTH_CONTROL_TENANT_AUTHORIZATION: (
        SIGNAL_TENANT_AUTHORIZATION_PRESENT
    ),
    AUTH_CONTROL_ROLE_AUTHORIZATION: SIGNAL_ROLE_AUTHORIZATION_PRESENT,
    AUTH_CONTROL_MIDDLEWARE: SIGNAL_AUTHORIZATION_MIDDLEWARE_PRESENT,
    AUTH_CONTROL_SERVER_SIDE: SIGNAL_SERVER_SIDE_AUTHORIZATION_PRESENT,
}

_LOCATION_SIGNALS: dict[str, str] = {
    AUTH_LOCATION_SERVER_SIDE: SIGNAL_AUTHORIZATION_SERVER_SIDE,
    AUTH_LOCATION_CLIENT_SIDE: SIGNAL_AUTHORIZATION_CLIENT_SIDE_ONLY,
}

_BEHAVIOR_SIGNALS: dict[str, str] = {
    BEHAVIOR_CROSS_USER_ACCESS_OBSERVED: SIGNAL_CROSS_USER_ACCESS_OBSERVED,
    BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED: (
        SIGNAL_CROSS_TENANT_ACCESS_OBSERVED
    ),
    BEHAVIOR_OWN_OBJECT_ONLY_OBSERVED: SIGNAL_OWN_OBJECT_ONLY_OBSERVED,
    BEHAVIOR_ACCESS_DENIED_OBSERVED: SIGNAL_ACCESS_DENIED_OBSERVED,
    BEHAVIOR_NO_BEHAVIOR_OBSERVED: SIGNAL_NO_BEHAVIOR_OBSERVED,
}

_ROUTE_SIGNALS: dict[str, str] = {
    ROUTE_RESOURCE: SIGNAL_ROUTE_RESOURCE,
    ROUTE_COLLECTION: SIGNAL_ROUTE_COLLECTION,
    ROUTE_ADMIN: SIGNAL_ROUTE_ADMIN,
    ROUTE_INTERNAL: SIGNAL_ROUTE_INTERNAL,
}

_OWNERSHIP_SIGNALS: dict[str, str] = {
    OWNER_RECORDED: SIGNAL_OWNER_RECORDED,
    OWNER_NOT_RECORDED: SIGNAL_OWNER_NOT_RECORDED,
}

_TENANT_SIGNALS: dict[str, str] = {
    TENANT_RECORDED: SIGNAL_TENANT_RECORDED,
    TENANT_NOT_RECORDED: SIGNAL_TENANT_NOT_RECORDED,
}

_ROLE_SIGNALS: dict[str, str] = {
    ROLE_RECORDED: SIGNAL_ROLE_RECORDED,
    ROLE_NOT_RECORDED: SIGNAL_ROLE_NOT_RECORDED,
}

_PRIORITY_ORDER: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}

NON_REFERENCE_VALUES: tuple[str, ...] = ("NONE_OBSERVED", "UNKNOWN")


def _signal(mapping: dict, value: object) -> str:
    return mapping.get(str(value), "")


def _major(confidence: str) -> str:
    return {
        CONFIDENCE_HIGH: CONFIDENCE_HIGH,
        CONFIDENCE_MEDIUM: CONFIDENCE_MEDIUM,
        CONFIDENCE_LOW: CONFIDENCE_LOW,
    }.get(confidence, CONFIDENCE_UNKNOWN)


def _minor(confidence: str) -> str:
    return {
        CONFIDENCE_HIGH: CONFIDENCE_MEDIUM,
        CONFIDENCE_MEDIUM: CONFIDENCE_LOW,
        CONFIDENCE_LOW: CONFIDENCE_LOW,
    }.get(confidence, CONFIDENCE_UNKNOWN)


def _at_least(priority: str, floor: str) -> str:
    if _PRIORITY_ORDER[priority] >= _PRIORITY_ORDER[floor]:
        return priority
    return floor


def _gap_priority(
    context_confidence: str,
    control_matches: bool,
    authorization_control: str,
    cross_context_observed: bool,
) -> str:
    auth_present = (
        authorization_control in AUTHORIZATION_CONTROL_PRESENT_STATES
    )
    if control_matches or auth_present:
        priority = CONFIDENCE_LOW
    elif authorization_control == AUTH_CONTROL_ABSENT:
        priority = _major(context_confidence)
    else:
        priority = _minor(context_confidence)
    if cross_context_observed and not control_matches:
        priority = _at_least(priority, CONFIDENCE_MEDIUM)
    return priority


def _hypothesis(
    hypothesis_type: str,
    confidence: str,
    signals: object,
) -> dict:
    bounded_signals: list[str] = []
    for signal in signals or ():
        if (
            signal
            and signal in IDOR_BOLA_SIGNALS
            and signal not in bounded_signals
        ):
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_NO_AUTHORIZATION_BYPASS_CLAIM,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if confidence == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = IDORBOLAHypothesisPlan(
        rule_version=IDOR_BOLA_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        supporting_signals=bounded_signals,
        confidence=confidence,
        priority=confidence,
        limitations=limitations,
        research_only=True,
    )
    return idor_bola_hypothesis_plan_projection(plan)


def plan_idor_bola_hypotheses(context_analysis: object = None) -> list[dict]:
    """Build the deterministic IDOR/BOLA research hypotheses (read-only).

    The mapping is conservative and never claims broken authorization:

    - a supplied object reference with a direct identifier lookup yields an
      object-level authorization gap review;
    - supplied ownership, tenant or role boundary facts yield their boundary
      reviews;
    - an object reference with unknown authorization state yields a direct
      object reference review;
    - no authorization or boundary evidence at all yields a missing
      authorization context review;
    - an explicit authorization control yields the control-present review and
      reduces (never erases) gap review priority;
    - nothing usable degrades to ``UNKNOWN``.
    """

    context = sanitize_idor_bola_context_analysis_plan(context_analysis)
    object_reference = context["object_reference"]
    resource_type = context["resource_type"]
    identifier_type = context["identifier_type"]
    ownership = context["ownership_relationship"]
    tenant = context["tenant_boundary"]
    role = context["role_boundary"]
    authorization_control = context["authorization_control"]
    authorization_location = context["authorization_location"]
    object_lookup = context["object_lookup"]
    behavior = context["authorization_behavior"]
    route_context = context["route_context"]
    context_confidence = idor_bola_context_confidence_of(context)

    reference_present = object_reference not in NON_REFERENCE_VALUES
    auth_present = (
        authorization_control in AUTHORIZATION_CONTROL_PRESENT_STATES
    )
    auth_absent = authorization_control == AUTH_CONTROL_ABSENT
    auth_unknown = not auth_present and not auth_absent
    owner_known = ownership in (OWNER_RECORDED, OWNER_NOT_RECORDED)
    tenant_known = tenant in (TENANT_RECORDED, TENANT_NOT_RECORDED)
    role_known = role in (ROLE_RECORDED, ROLE_NOT_RECORDED)
    direct_lookup = object_lookup == LOOKUP_BY_IDENTIFIER
    scoped_lookup = object_lookup in SCOPED_LOOKUP_PATTERNS
    role_sensitive_route = route_context in ROLE_SENSITIVE_ROUTES
    cross_context_observed = behavior in CROSS_CONTEXT_BEHAVIORS

    reference_signal = _signal(_REFERENCE_SIGNALS, object_reference)
    identifier_signal = _signal(_IDENTIFIER_SIGNALS, identifier_type)
    resource_signal = (
        SIGNAL_RESOURCE_TYPE_PRESENT
        if resource_type not in (RESOURCE_NONE_OBSERVED, RESOURCE_UNKNOWN)
        else ""
    )
    lookup_signal = _signal(_LOOKUP_SIGNALS, object_lookup)
    control_signal = _signal(_CONTROL_SIGNALS, authorization_control)
    location_signal = _signal(_LOCATION_SIGNALS, authorization_location)
    behavior_signal = _signal(_BEHAVIOR_SIGNALS, behavior)
    route_signal = _signal(_ROUTE_SIGNALS, route_context)
    ownership_signal = _signal(_OWNERSHIP_SIGNALS, ownership)
    tenant_signal = _signal(_TENANT_SIGNALS, tenant)
    role_signal = _signal(_ROLE_SIGNALS, role)

    found: dict[str, tuple] = {}

    def add(hypothesis_type: str, confidence: str, signals: object) -> None:
        if hypothesis_type not in found:
            found[hypothesis_type] = (confidence, signals)

    if reference_present:
        if direct_lookup:
            add(
                TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
                _gap_priority(
                    context_confidence,
                    auth_present,
                    authorization_control,
                    cross_context_observed,
                ),
                (
                    reference_signal,
                    resource_signal,
                    identifier_signal,
                    lookup_signal,
                    control_signal,
                    behavior_signal,
                ),
            )
        if owner_known:
            add(
                TYPE_OWNERSHIP_BOUNDARY_GAP,
                _gap_priority(
                    context_confidence,
                    authorization_control
                    == AUTH_CONTROL_OWNERSHIP_CHECK,
                    authorization_control,
                    cross_context_observed,
                ),
                (
                    ownership_signal,
                    reference_signal,
                    resource_signal,
                    lookup_signal,
                    control_signal,
                    behavior_signal,
                ),
            )
        if tenant_known and (direct_lookup or scoped_lookup):
            add(
                TYPE_TENANT_ISOLATION_GAP,
                _gap_priority(
                    context_confidence,
                    authorization_control
                    == AUTH_CONTROL_TENANT_AUTHORIZATION,
                    authorization_control,
                    cross_context_observed,
                ),
                (
                    tenant_signal,
                    reference_signal,
                    resource_signal,
                    lookup_signal,
                    control_signal,
                    behavior_signal,
                ),
            )
        if role_known and role_sensitive_route:
            add(
                TYPE_ROLE_BOUNDARY_GAP,
                _gap_priority(
                    context_confidence,
                    authorization_control
                    == AUTH_CONTROL_ROLE_AUTHORIZATION,
                    authorization_control,
                    cross_context_observed,
                ),
                (
                    role_signal,
                    reference_signal,
                    resource_signal,
                    route_signal,
                    control_signal,
                    behavior_signal,
                ),
            )
        if auth_unknown:
            add(
                TYPE_DIRECT_OBJECT_REFERENCE,
                _minor(context_confidence),
                (
                    reference_signal,
                    resource_signal,
                    identifier_signal,
                    lookup_signal,
                    SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
                ),
            )
        if not auth_present and not (owner_known or tenant_known or role_known):
            add(
                TYPE_MISSING_AUTHORIZATION_CONTEXT,
                _major(context_confidence)
                if auth_absent
                else _minor(context_confidence),
                (
                    reference_signal,
                    resource_signal,
                    lookup_signal,
                    SIGNAL_AUTHORIZATION_CONTROL_ABSENT
                    if auth_absent
                    else SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
                ),
            )
    if auth_present:
        add(
            TYPE_AUTHORIZATION_CONTROL_PRESENT,
            CONFIDENCE_LOW,
            (
                control_signal,
                location_signal,
                reference_signal,
                resource_signal,
                lookup_signal,
                behavior_signal,
            ),
        )

    if not found:
        return [
            _hypothesis(
                TYPE_UNKNOWN,
                CONFIDENCE_UNKNOWN,
                (SIGNAL_CONTEXT_UNKNOWN,),
            )
        ]

    hypotheses: list[dict] = []
    for hypothesis_type in HYPOTHESIS_TYPES:
        if hypothesis_type == TYPE_UNKNOWN:
            continue
        if hypothesis_type in found:
            confidence, signals = found[hypothesis_type]
            hypotheses.append(
                _hypothesis(hypothesis_type, confidence, signals)
            )
    return hypotheses


__all__ = [
    "IDOR_BOLA_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_idor_bola_hypotheses",
]

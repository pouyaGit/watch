"""Stage R49.4 deterministic API security evidence planner.

Defines which research evidence would be required to evaluate the API
security hypotheses:

    "Which bounded API security evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no API
  call, no endpoint probing, no network connection, no socket, no DNS, no
  browser, no database, no scanner, no payload, no credential testing, no
  bypass, no execution, no secret extraction, no persistence. Nothing is
  queried, called, probed or executed.
- Evidence items describe what would be relevant; they never instruct an
  attack and never generate attack content.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning
  state and confidence are pure functions of the bounded context and
  hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.api_security_context_analyzer import (
    api_security_context_confidence_of,
)
from ai.knowledge.api_security_hypothesis_planner import (
    plan_api_security_hypotheses,
)
from ai.schemas.api_security_context_analysis import (
    sanitize_api_security_context_analysis_plan,
)
from ai.schemas.api_security_evidence_plan import (
    API_SECURITY_EVIDENCE_PLAN_RULE_VERSION,
    EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
    API_SECURITY_EVIDENCE_ITEMS,
    EVIDENCE_API_AUTHENTICATION_ENFORCEMENT,
    EVIDENCE_API_KEY_REVOCATION_POLICY,
    EVIDENCE_API_KEY_ROTATION_POLICY,
    EVIDENCE_API_KEY_SCOPE_POLICY,
    EVIDENCE_API_SECURITY_CONFIGURATION,
    EVIDENCE_API_VERSIONING_POLICY,
    EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    EVIDENCE_BATCH_LIMIT_POLICY,
    EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY,
    EVIDENCE_CORS_CREDENTIAL_POLICY,
    EVIDENCE_CORS_ORIGIN_POLICY,
    EVIDENCE_DEBUG_CONFIGURATION,
    EVIDENCE_DOWNLOAD_CONTROL_POLICY,
    EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    EVIDENCE_ERROR_HANDLING_CONFIGURATION,
    EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_INTROSPECTION_POLICY,
    EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY,
    EVIDENCE_HTTP_METHOD_CONFIGURATION,
    EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
    EVIDENCE_METHOD_OVERRIDE_CONFIGURATION,
    EVIDENCE_PAGINATION_LIMIT_POLICY,
    EVIDENCE_QUERY_COMPLEXITY_POLICY,
    EVIDENCE_RATE_LIMIT_POLICY,
    EVIDENCE_REQUEST_SCHEMA_DEFINITION,
    EVIDENCE_REQUEST_SIZE_LIMIT_POLICY,
    EVIDENCE_RESPONSE_FIELD_POLICY,
    EVIDENCE_SENSITIVE_FIELD_POLICY,
    EVIDENCE_TENANT_ISOLATION_POLICY,
    EVIDENCE_UNKNOWN,
    EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY,
    EVIDENCE_UPLOAD_LIMIT_POLICY,
    EVIDENCE_WEBHOOK_REPLAY_PROTECTION,
    EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION,
    EVIDENCE_WEBHOOK_SOURCE_VALIDATION,
    EVIDENCE_WRITABLE_FIELD_POLICY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_API_CALLS,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_ENDPOINT_PROBING,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SCANNER_EXECUTION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    APISecurityEvidencePlan,
    api_security_evidence_plan_projection,
)
from ai.schemas.api_security_hypothesis import (
    TYPE_API_AUTHENTICATION_GAP,
    TYPE_API_AUTHORIZATION_GAP,
    TYPE_API_KEY_CONTROL_GAP,
    TYPE_API_SECURITY_CONTROL_PRESENT,
    TYPE_API_VERSIONING_RISK,
    TYPE_BATCH_OPERATION_CONTROL_GAP,
    TYPE_CONTENT_TYPE_CONTROL_GAP,
    TYPE_CORS_CONTROL_GAP,
    TYPE_DEBUG_INFORMATION_EXPOSURE,
    TYPE_ERROR_INFORMATION_DISCLOSURE,
    TYPE_FILE_DOWNLOAD_CONTROL_GAP,
    TYPE_FILE_UPLOAD_CONTROL_GAP,
    TYPE_FUNCTION_LEVEL_AUTHORIZATION_GAP,
    TYPE_GRAPHQL_AUTHORIZATION_GAP,
    TYPE_GRAPHQL_INTROSPECTION_RISK,
    TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP,
    TYPE_HTTP_METHOD_CONTROL_GAP,
    TYPE_INPUT_VALIDATION_GAP,
    TYPE_MASS_ASSIGNMENT_RISK,
    TYPE_METHOD_OVERRIDE_RISK,
    TYPE_MISSING_API_CONTEXT,
    TYPE_PAGINATION_CONTROL_GAP,
    TYPE_QUERY_COMPLEXITY_CONTROL_GAP,
    TYPE_RATE_LIMIT_CONTROL_GAP,
    TYPE_RESOURCE_EXPOSURE_RISK,
    TYPE_RESOURCE_LIMIT_CONTROL_GAP,
    TYPE_SCHEMA_VALIDATION_GAP,
    TYPE_SENSITIVE_FIELD_EXPOSURE_RISK,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_UNKNOWN,
    TYPE_WEBHOOK_REPLAY_CONTROL_GAP,
    TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP,
    sanitize_api_security_hypothesis_plan,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)

API_SECURITY_EVIDENCE_PLANNER_RULE_VERSION = "r49-4"
RULE_VERSION = API_SECURITY_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_API_AUTHENTICATION_GAP: (
        EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
        EVIDENCE_API_AUTHENTICATION_ENFORCEMENT,
        EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    ),
    TYPE_API_AUTHORIZATION_GAP: (
        EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
        EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    ),
    TYPE_FUNCTION_LEVEL_AUTHORIZATION_GAP: (
        EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY,
        EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    ),
    TYPE_TENANT_ISOLATION_GAP: (
        EVIDENCE_TENANT_ISOLATION_POLICY,
        EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    ),
    TYPE_INPUT_VALIDATION_GAP: (
        EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
        EVIDENCE_REQUEST_SCHEMA_DEFINITION,
    ),
    TYPE_SCHEMA_VALIDATION_GAP: (
        EVIDENCE_REQUEST_SCHEMA_DEFINITION,
        EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
    ),
    TYPE_MASS_ASSIGNMENT_RISK: (
        EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY,
        EVIDENCE_WRITABLE_FIELD_POLICY,
        EVIDENCE_SENSITIVE_FIELD_POLICY,
    ),
    TYPE_HTTP_METHOD_CONTROL_GAP: (
        EVIDENCE_HTTP_METHOD_CONFIGURATION,
        EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    ),
    TYPE_METHOD_OVERRIDE_RISK: (
        EVIDENCE_METHOD_OVERRIDE_CONFIGURATION,
        EVIDENCE_HTTP_METHOD_CONFIGURATION,
    ),
    TYPE_API_VERSIONING_RISK: (
        EVIDENCE_API_VERSIONING_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_RESOURCE_EXPOSURE_RISK: (
        EVIDENCE_RESPONSE_FIELD_POLICY,
        EVIDENCE_SENSITIVE_FIELD_POLICY,
    ),
    TYPE_SENSITIVE_FIELD_EXPOSURE_RISK: (
        EVIDENCE_SENSITIVE_FIELD_POLICY,
        EVIDENCE_RESPONSE_FIELD_POLICY,
    ),
    TYPE_ERROR_INFORMATION_DISCLOSURE: (
        EVIDENCE_ERROR_HANDLING_CONFIGURATION,
        EVIDENCE_DEBUG_CONFIGURATION,
    ),
    TYPE_DEBUG_INFORMATION_EXPOSURE: (
        EVIDENCE_DEBUG_CONFIGURATION,
        EVIDENCE_ERROR_HANDLING_CONFIGURATION,
    ),
    TYPE_RATE_LIMIT_CONTROL_GAP: (
        EVIDENCE_RATE_LIMIT_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_RESOURCE_LIMIT_CONTROL_GAP: (
        EVIDENCE_REQUEST_SIZE_LIMIT_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_PAGINATION_CONTROL_GAP: (
        EVIDENCE_PAGINATION_LIMIT_POLICY,
        EVIDENCE_REQUEST_SIZE_LIMIT_POLICY,
    ),
    TYPE_QUERY_COMPLEXITY_CONTROL_GAP: (
        EVIDENCE_QUERY_COMPLEXITY_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_BATCH_OPERATION_CONTROL_GAP: (
        EVIDENCE_BATCH_LIMIT_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_FILE_UPLOAD_CONTROL_GAP: (
        EVIDENCE_UPLOAD_LIMIT_POLICY,
        EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY,
    ),
    TYPE_FILE_DOWNLOAD_CONTROL_GAP: (
        EVIDENCE_DOWNLOAD_CONTROL_POLICY,
        EVIDENCE_RESPONSE_FIELD_POLICY,
    ),
    TYPE_CORS_CONTROL_GAP: (
        EVIDENCE_CORS_ORIGIN_POLICY,
        EVIDENCE_CORS_CREDENTIAL_POLICY,
    ),
    TYPE_GRAPHQL_INTROSPECTION_RISK: (
        EVIDENCE_GRAPHQL_INTROSPECTION_POLICY,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_GRAPHQL_AUTHORIZATION_GAP: (
        EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY,
        EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY,
    ),
    TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP: (
        EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY,
        EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY,
    ),
    TYPE_API_KEY_CONTROL_GAP: (
        EVIDENCE_API_KEY_ROTATION_POLICY,
        EVIDENCE_API_KEY_REVOCATION_POLICY,
        EVIDENCE_API_KEY_SCOPE_POLICY,
    ),
    TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP: (
        EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION,
        EVIDENCE_WEBHOOK_SOURCE_VALIDATION,
    ),
    TYPE_WEBHOOK_REPLAY_CONTROL_GAP: (
        EVIDENCE_WEBHOOK_REPLAY_PROTECTION,
        EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION,
    ),
    TYPE_CONTENT_TYPE_CONTROL_GAP: (
        EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY,
        EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
    ),
    TYPE_API_SECURITY_CONTROL_PRESENT: (
        EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
        EVIDENCE_API_SECURITY_CONFIGURATION,
    ),
    TYPE_MISSING_API_CONTEXT: (
        EVIDENCE_API_SECURITY_CONFIGURATION,
        EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
        EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    ),
    TYPE_UNKNOWN: (EVIDENCE_UNKNOWN,),
}


def _hypotheses(value: object) -> list[dict]:
    if isinstance(value, dict):
        raw = [value]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raw = []
    return [
        sanitize_api_security_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_api_security_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis
    evidence mappings. The planning state is ``UNKNOWN`` when nothing can
    be planned and ``COMPLETE`` only when the supplied context is HIGH
    confidence, no ``UNKNOWN`` hypothesis remains, and at least one
    substantive (non missing-context) hypothesis is present. A context
    that only degrades to ``MISSING_API_CONTEXT`` can never be
    ``COMPLETE``. Otherwise the state is ``PARTIAL``. No evidence is
    collected and no API, endpoint or network activity occurs.
    """

    context = sanitize_api_security_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_api_security_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    substantive_plans = [
        plan
        for plan in plans
        if plan["hypothesis_type"]
        not in (TYPE_UNKNOWN, TYPE_MISSING_API_CONTEXT)
    ]
    context_confidence = api_security_context_confidence_of(context)
    if not plans or items == [EVIDENCE_UNKNOWN]:
        state = STATE_UNKNOWN
    elif (
        context_confidence == CONFIDENCE_HIGH
        and substantive_plans
        and all(
            plan["hypothesis_type"] != TYPE_UNKNOWN for plan in plans
        )
    ):
        state = STATE_COMPLETE
    else:
        state = STATE_PARTIAL

    if state == STATE_UNKNOWN:
        confidence = CONFIDENCE_UNKNOWN
    elif state == STATE_COMPLETE:
        confidence = CONFIDENCE_HIGH
    else:
        confidence = (
            CONFIDENCE_UNKNOWN
            if context_confidence == CONFIDENCE_UNKNOWN
            else CONFIDENCE_LOW
        )

    limitations = [
        LIMITATION_NO_COLLECTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_API_CALLS,
        LIMITATION_NO_ENDPOINT_PROBING,
        LIMITATION_NO_SCANNER_EXECUTION,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_CREDENTIAL_TESTING,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = APISecurityEvidencePlan(
        rule_version=API_SECURITY_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return api_security_evidence_plan_projection(plan)


__all__ = [
    "API_SECURITY_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_api_security_evidence",
]

"""Stage R49.2 deterministic API security context analyzer.

Classifies API-security-relevant research context from bounded
observations:

    "Which API type, surface, authentication, authorization, validation,
     behavior, resource-control, CORS, GraphQL, API-key and webhook
     signals were supplied, and how complete is that context?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no API call, no
  endpoint probing, no network connection, no socket, no DNS, no browser,
  no database, no scanner, no payload, no credential testing, no bypass,
  no subprocess, no LLM. Nothing is performed.
- Technology presence is never vulnerability: API types, endpoint
  metadata, schemas, pagination, CORS metadata, API keys and webhooks are
  context only.
- Confidence means "how complete/relevant is the supplied API context?".
  It does NOT mean "probability that a vulnerability exists". No
  vulnerability is confirmed.
- Confidence is HIGH only with explicit structured evidence of an observed
  API security-control weakness inside an API context; technology metadata
  alone can never produce HIGH, and isolated exposure metadata without an
  API context is context only. MEDIUM requires explicit observed control
  evidence; otherwise LOW.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``/
  ``NOT_PROVIDED``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.api_security_context_analysis import (
    API_TYPE_GRAPHQL,
    API_TYPE_UNKNOWN,
    API_TYPE_WEBHOOK,
    API_VERSIONING_DEPRECATED_VERSION_OBSERVED,
    API_VERSIONING_NONE_OBSERVED,
    API_VERSIONING_UNKNOWN,
    API_VERSIONING_UNVERSIONED_OBSERVED,
    API_VERSIONING_VERSIONED_OBSERVED,
    AUTH_MECH_API_KEY,
    AUTH_MECH_NONE_OBSERVED,
    AUTH_MECH_UNKNOWN,
    CONTENT_TYPE_FORM_OBSERVED,
    CONTENT_TYPE_JSON_OBSERVED,
    CONTENT_TYPE_MULTIPART_OBSERVED,
    CONTENT_TYPE_NONE_OBSERVED,
    CONTENT_TYPE_UNKNOWN,
    CONTENT_TYPE_XML_OBSERVED,
    CONTEXT_OBSERVATIONS,
    CONTEXT_UNKNOWN,
    DEBUG_INFORMATION_NONE_OBSERVED,
    DEBUG_INFORMATION_OBSERVED,
    DEBUG_INFORMATION_UNKNOWN,
    ENUM_OBSERVATION_FIELDS,
    ERROR_DETAIL_DETAILED_OBSERVED,
    ERROR_DETAIL_GENERIC_OBSERVED,
    ERROR_DETAIL_NONE_OBSERVED,
    ERROR_DETAIL_STACK_TRACE_OBSERVED,
    ERROR_DETAIL_UNKNOWN,
    ERROR_DISCLOSURE_STATES,
    GRAPHQL_INTROSPECTION_DISABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_ENABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_NONE_OBSERVED,
    GRAPHQL_INTROSPECTION_UNKNOWN,
    KNOWN_API_TYPES,
    KNOWN_AUTHENTICATION_MECHANISMS,
    KNOWN_CONTENT_TYPES,
    NONE_OBSERVED,
    OBSERVED,
    OBSERVED_SENSITIVE_FIELD_STATES,
    PRESENCE_OBSERVATION_FIELDS,
    RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED,
    RESOURCE_EXPOSURE_NONE_OBSERVED,
    RESOURCE_EXPOSURE_UNKNOWN,
    SENSITIVE_FIELD_EXPOSURE_STATES,
    SENSITIVE_FIELD_NONE_OBSERVED,
    SENSITIVE_FIELD_UNKNOWN,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_CONTROL_PRESENT_STATES,
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_FIELDS,
    VALIDATION_MISSING_STATES,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_STATES,
    VALIDATION_UNKNOWN,
    APISecurityContextAnalysisPlan,
    API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION,
    api_security_context_analysis_plan_projection,
    sanitize_api_security_context_analysis_plan,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)

API_SECURITY_CONTEXT_ANALYZER_RULE_VERSION = "r49-2"
RULE_VERSION = API_SECURITY_CONTEXT_ANALYZER_RULE_VERSION

UNKNOWN_VALUES: tuple[str, ...] = (
    API_TYPE_UNKNOWN,
    API_VERSIONING_UNKNOWN,
    API_VERSIONING_NONE_OBSERVED,
    CONTENT_TYPE_UNKNOWN,
    CONTENT_TYPE_NONE_OBSERVED,
    AUTH_MECH_UNKNOWN,
    AUTH_MECH_NONE_OBSERVED,
    RESOURCE_EXPOSURE_UNKNOWN,
    RESOURCE_EXPOSURE_NONE_OBSERVED,
    SENSITIVE_FIELD_UNKNOWN,
    SENSITIVE_FIELD_NONE_OBSERVED,
    ERROR_DETAIL_UNKNOWN,
    ERROR_DETAIL_NONE_OBSERVED,
    DEBUG_INFORMATION_UNKNOWN,
    DEBUG_INFORMATION_NONE_OBSERVED,
    GRAPHQL_INTROSPECTION_UNKNOWN,
    GRAPHQL_INTROSPECTION_NONE_OBSERVED,
    CONTEXT_UNKNOWN,
    NONE_OBSERVED,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_UNKNOWN,
)

# Values that indicate a supplied semantic observation for the purpose of
# counting known context facts (visible for clarity and tests).
KNOWN_VERSIONING_STATES: tuple[str, ...] = (
    API_VERSIONING_VERSIONED_OBSERVED,
    API_VERSIONING_UNVERSIONED_OBSERVED,
    API_VERSIONING_DEPRECATED_VERSION_OBSERVED,
)

KNOWN_CONTENT_TYPE_STATES: tuple[str, ...] = (
    CONTENT_TYPE_JSON_OBSERVED,
    CONTENT_TYPE_FORM_OBSERVED,
    CONTENT_TYPE_XML_OBSERVED,
    CONTENT_TYPE_MULTIPART_OBSERVED,
)

KNOWN_ERROR_DETAIL_STATES: tuple[str, ...] = (
    ERROR_DETAIL_GENERIC_OBSERVED,
    ERROR_DETAIL_DETAILED_OBSERVED,
    ERROR_DETAIL_STACK_TRACE_OBSERVED,
)

KNOWN_INTROSPECTION_STATES: tuple[str, ...] = (
    GRAPHQL_INTROSPECTION_ENABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_DISABLED_OBSERVED,
)

COUNTED_STRING_FIELDS: tuple[str, ...] = (
    "api_type",
    "api_versioning",
    "content_type",
    "authentication_mechanism",
    "resource_exposure",
    "sensitive_field_exposure",
    "error_detail",
    "debug_information",
    "graphql_introspection",
) + PRESENCE_OBSERVATION_FIELDS + VALIDATION_FIELDS


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def api_security_context_present(value: object) -> bool:
    """True when supplied facts describe an API context."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return _api_context_observed(plan)


def _api_context_observed(plan: dict) -> bool:
    """True when the sanitized plan describes an API protocol context.

    A control weakness can only be observed in relation to an API context.
    Isolated exposure metadata without any API protocol context is context
    only and can never be promoted to HIGH confidence.
    """

    if plan["api_type"] in KNOWN_API_TYPES:
        return True
    if plan["content_type"] in KNOWN_CONTENT_TYPES:
        return True
    if plan["authentication_mechanism"] in KNOWN_AUTHENTICATION_MECHANISMS:
        return True
    if plan["api_versioning"] in KNOWN_VERSIONING_STATES:
        return True
    for name in PRESENCE_OBSERVATION_FIELDS:
        if plan[name] == OBSERVED:
            return True
    if plan["graphql_introspection"] in KNOWN_INTROSPECTION_STATES:
        return True
    return False


def _weakness_observed(plan: dict) -> bool:
    if not _api_context_observed(plan):
        return False
    if any(
        plan[name] in VALIDATION_CONTROL_ABSENT_STATES
        for name in VALIDATION_FIELDS
    ):
        return True
    if plan["resource_exposure"] == (
        RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED
    ):
        return True
    if plan["sensitive_field_exposure"] in OBSERVED_SENSITIVE_FIELD_STATES:
        return True
    if plan["error_detail"] in ERROR_DISCLOSURE_STATES:
        return True
    if plan["debug_information"] == DEBUG_INFORMATION_OBSERVED:
        return True
    return False


def _control_observed(plan: dict) -> bool:
    if not _api_context_observed(plan):
        return False
    return any(
        plan[name] in VALIDATION_CONTROL_PRESENT_STATES
        for name in VALIDATION_FIELDS
    )


def _known_count(plan: dict) -> int:
    count = 0
    for name in COUNTED_STRING_FIELDS:
        if plan[name] not in UNKNOWN_VALUES:
            count += 1
    return count


def analyze_api_security_context(
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
    """Build the deterministic descriptive API security analysis.

    Confidence is a pure function of supplied facts: HIGH only when
    explicit structured evidence of an observed API security-control
    weakness is present inside an API context; MEDIUM when explicit
    observed control evidence is present; LOW when only technology/context
    metadata is present (including isolated exposure metadata without an
    API context); UNKNOWN when nothing usable was supplied. No
    vulnerability is confirmed and no API request is performed.
    """

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

    resolved: dict = {}
    for name, allowed, fallback in ENUM_OBSERVATION_FIELDS:
        resolved[name] = _closed(supplied.get(name), allowed, fallback)
    for name in PRESENCE_OBSERVATION_FIELDS:
        resolved[name] = _closed(
            supplied.get(name), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        )
    for name in VALIDATION_FIELDS:
        resolved[name] = _closed(
            supplied.get(name), VALIDATION_STATES, VALIDATION_NOT_PROVIDED
        )

    known_count = _known_count(resolved)
    if known_count == 0:
        confidence = CONFIDENCE_UNKNOWN
    elif _weakness_observed(resolved):
        confidence = CONFIDENCE_HIGH
    elif _control_observed(resolved):
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW

    plan = APISecurityContextAnalysisPlan(
        rule_version=API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION,
        context_confidence=confidence,
        research_only=True,
        **resolved,
    )
    return api_security_context_analysis_plan_projection(plan)


def api_security_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so
    partial context dicts supplied directly to downstream planners receive
    the correct, safety-capped confidence.
    """

    plan = sanitize_api_security_context_analysis_plan(value)
    known_count = _known_count(plan)
    if known_count == 0:
        return CONFIDENCE_UNKNOWN
    if _weakness_observed(plan):
        return CONFIDENCE_HIGH
    if _control_observed(plan):
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def graphql_context_present(value: object) -> bool:
    """True when GraphQL-specific context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    if plan["api_type"] == API_TYPE_GRAPHQL:
        return True
    for name in (
        "graphql_field_authorization",
        "graphql_mutation_authorization",
        "graphql_depth_limit",
        "graphql_complexity_limit",
        "graphql_introspection_control",
    ):
        if plan[name] not in VALIDATION_MISSING_STATES:
            return True
    if plan["graphql_batching"] == OBSERVED:
        return True
    if plan["graphql_introspection"] in KNOWN_INTROSPECTION_STATES:
        return True
    return False


def webhook_context_present(value: object) -> bool:
    """True when webhook-specific context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    if plan["api_type"] == API_TYPE_WEBHOOK:
        return True
    if plan["webhook_context"] == OBSERVED:
        return True
    for name in (
        "webhook_signature_validation",
        "webhook_replay_protection",
        "webhook_source_validation",
    ):
        if plan[name] not in VALIDATION_MISSING_STATES:
            return True
    return False


def api_key_context_present(value: object) -> bool:
    """True when API-key-specific context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    if plan["authentication_mechanism"] == AUTH_MECH_API_KEY:
        return True
    for name in ("api_key_rotation", "api_key_revocation"):
        if plan[name] not in VALIDATION_MISSING_STATES:
            return True
    return False


def file_upload_context_present(value: object) -> bool:
    """True when file-upload context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return (
        plan["file_upload_context"] == OBSERVED
        or plan["upload_limit"] not in VALIDATION_MISSING_STATES
    )


def file_download_context_present(value: object) -> bool:
    """True when file-download context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return (
        plan["file_download_context"] == OBSERVED
        or plan["download_control"] not in VALIDATION_MISSING_STATES
    )


def batch_context_present(value: object) -> bool:
    """True when batch-operation context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return (
        plan["batch_context"] == OBSERVED
        or plan["batch_limit"] not in VALIDATION_MISSING_STATES
    )


def pagination_context_present(value: object) -> bool:
    """True when pagination context was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return (
        plan["pagination_context"] == OBSERVED
        or plan["pagination_limit"] not in VALIDATION_MISSING_STATES
    )


def validation_state_of(value: object, field: object) -> str:
    """Return the bounded validation state of a validation field."""

    plan = sanitize_api_security_context_analysis_plan(value)
    key = _text(field)
    if key not in VALIDATION_FIELDS:
        return VALIDATION_UNKNOWN
    return plan[key]


def weakness_observed(value: object) -> bool:
    """True only when explicit structured weakness evidence was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return _weakness_observed(plan)


def control_observed(value: object) -> bool:
    """True only when explicit structured control evidence was supplied."""

    plan = sanitize_api_security_context_analysis_plan(value)
    return _control_observed(plan)


__all__ = [
    "API_SECURITY_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "UNKNOWN_VALUES",
    "KNOWN_VERSIONING_STATES",
    "KNOWN_CONTENT_TYPE_STATES",
    "KNOWN_ERROR_DETAIL_STATES",
    "KNOWN_INTROSPECTION_STATES",
    "COUNTED_STRING_FIELDS",
    "api_security_context_present",
    "analyze_api_security_context",
    "api_security_context_confidence_of",
    "graphql_context_present",
    "webhook_context_present",
    "api_key_context_present",
    "file_upload_context_present",
    "file_download_context_present",
    "batch_context_present",
    "pagination_context_present",
    "validation_state_of",
    "weakness_observed",
    "control_observed",
]

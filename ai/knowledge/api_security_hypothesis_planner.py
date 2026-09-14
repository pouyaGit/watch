"""Stage R49.3 deterministic API security hypothesis planner.

Creates deterministic research hypotheses from supplied API security
context:

    "Which API-level security-review hypothesis follows from the supplied
     context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability
  confirmation, no API attack instructions, no fuzzing, no payload, no
  authentication/authorization bypass, no IDOR/BOLA/SQLi/XSS/SSRF
  exploitation, no token manipulation, no credential testing, no attack
  sequence, no network/database execution.
- Pure and offline: no I/O, no network, no API call, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, state, signals,
  confidence, priority, rationale and limitations are pure functions of
  the bounded context.
- Technology presence is never weakness: API types, endpoint metadata,
  schemas, pagination, CORS metadata, API keys and webhooks alone never
  produce a gap hypothesis.
- Boundary with R46/R47/R48: object-level authorization, JWT validation
  and OAuth protocol hypotheses are not created here.
- Priority is research usefulness only (never severity, exploitability,
  CVSS or vulnerability probability).
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.api_security_context_analyzer import (
    UNKNOWN_VALUES,
    api_key_context_present,
    api_security_context_present,
    batch_context_present,
    file_download_context_present,
    file_upload_context_present,
    graphql_context_present,
    pagination_context_present,
    webhook_context_present,
)
from ai.schemas.api_security_context_analysis import (
    API_TYPE_GRAPHQL,
    API_VERSIONING_DEPRECATED_VERSION_OBSERVED,
    API_VERSIONING_VERSIONED_OBSERVED,
    AUTH_MECH_API_KEY,
    AUTH_MECH_BASIC,
    AUTH_MECH_BEARER_TOKEN,
    AUTH_MECH_COOKIE_SESSION,
    AUTH_MECH_JWT_BEARER,
    AUTH_MECH_MUTUAL_TLS,
    AUTH_MECH_OAUTH2,
    CONTENT_TYPE_FORM_OBSERVED,
    CONTENT_TYPE_JSON_OBSERVED,
    CONTENT_TYPE_MULTIPART_OBSERVED,
    CONTENT_TYPE_XML_OBSERVED,
    DEBUG_INFORMATION_OBSERVED,
    ERROR_DETAIL_DETAILED_OBSERVED,
    ERROR_DETAIL_STACK_TRACE_OBSERVED,
    ERROR_DISCLOSURE_STATES,
    GRAPHQL_INTROSPECTION_DISABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_ENABLED_OBSERVED,
    NONE_OBSERVED,
    OBSERVED,
    OBSERVED_SENSITIVE_FIELD_STATES,
    RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_CONTROL_PRESENT_STATES,
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_FIELDS,
    VALIDATION_MISSING_STATES,
    sanitize_api_security_context_analysis_plan,
)
from ai.schemas.api_security_hypothesis import (
    API_SECURITY_HYPOTHESIS_RULE_VERSION,
    API_SECURITY_SIGNALS,
    HYPOTHESIS_TYPES,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_API_ATTACK_CLAIM,
    LIMITATION_NO_AUTH_BYPASS_CLAIM,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_IDOR_EXPLOIT_CLAIM,
    LIMITATION_NO_INJECTION_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_API_DEPRECATED_VERSION,
    SIGNAL_API_TYPE_GRAPHQL,
    SIGNAL_API_TYPE_JSON_API,
    SIGNAL_API_TYPE_REST,
    SIGNAL_API_TYPE_RPC,
    SIGNAL_API_TYPE_WEBHOOK,
    SIGNAL_API_TYPE_XML_API,
    SIGNAL_API_UNVERSIONED,
    SIGNAL_API_VERSIONED,
    SIGNAL_AUTH_MECHANISM_API_KEY,
    SIGNAL_AUTH_MECHANISM_BASIC,
    SIGNAL_AUTH_MECHANISM_BEARER_TOKEN,
    SIGNAL_AUTH_MECHANISM_COOKIE_SESSION,
    SIGNAL_AUTH_MECHANISM_JWT_BEARER,
    SIGNAL_AUTH_MECHANISM_MUTUAL_TLS,
    SIGNAL_AUTH_MECHANISM_OAUTH2,
    SIGNAL_BATCH_CONTEXT_OBSERVED,
    SIGNAL_CONTENT_TYPE_FORM,
    SIGNAL_CONTENT_TYPE_JSON,
    SIGNAL_CONTENT_TYPE_MULTIPART,
    SIGNAL_CONTENT_TYPE_XML,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_DEBUG_INFORMATION_OBSERVED,
    SIGNAL_ENDPOINT_METADATA_OBSERVED,
    SIGNAL_ERROR_DETAILED_OBSERVED,
    SIGNAL_ERROR_GENERIC_OBSERVED,
    SIGNAL_ERROR_STACK_TRACE_OBSERVED,
    SIGNAL_EXCESSIVE_DATA_OBSERVED,
    SIGNAL_FILE_DOWNLOAD_OBSERVED,
    SIGNAL_FILE_UPLOAD_OBSERVED,
    SIGNAL_GRAPHQL_BATCHING_OBSERVED,
    SIGNAL_INTERNAL_IDENTIFIERS_OBSERVED,
    SIGNAL_INTROSPECTION_DISABLED_OBSERVED,
    SIGNAL_INTROSPECTION_ENABLED_OBSERVED,
    SIGNAL_MISSING_API_CONTEXT,
    SIGNAL_NESTED_RESOURCES_OBSERVED,
    SIGNAL_OBJECT_AUTHORIZATION_CONTEXT_OBSERVED,
    SIGNAL_PAGINATION_CONTEXT_OBSERVED,
    SIGNAL_REQUEST_SCHEMA_OBSERVED,
    SIGNAL_RESPONSE_SCHEMA_OBSERVED,
    SIGNAL_SENSITIVE_FIELDS_OBSERVED,
    SIGNAL_WEBHOOK_CONTEXT_OBSERVED,
    STATE_CONTROL_PRESENT_OBSERVED,
    STATE_NEEDS_EVIDENCE,
    STATE_UNKNOWN,
    STATE_WEAKNESS_OBSERVED,
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
    APISecurityHypothesisPlan,
    api_security_hypothesis_plan_projection,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)

API_SECURITY_HYPOTHESIS_PLANNER_RULE_VERSION = "r49-3"
RULE_VERSION = API_SECURITY_HYPOTHESIS_PLANNER_RULE_VERSION


def _validation_signal_names(control: str) -> tuple[str, str, str]:
    """Deterministic signal names for a bounded validation control."""

    base = control.upper()
    return (
        f"{base}_ENFORCED_OBSERVED",
        f"{base}_ABSENT_OBSERVED",
        f"{base}_NOT_PROVIDED",
    )


VALIDATION_SIGNALS: dict[str, tuple[str, str, str]] = {
    field: _validation_signal_names(field) for field in VALIDATION_FIELDS
}

VALIDATION_SIGNALS_LOOKUP: frozenset[str] = frozenset(API_SECURITY_SIGNALS)

API_TYPE_SIGNALS: dict[str, str] = {
    "REST": SIGNAL_API_TYPE_REST,
    "GRAPHQL": SIGNAL_API_TYPE_GRAPHQL,
    "RPC": SIGNAL_API_TYPE_RPC,
    "JSON_API": SIGNAL_API_TYPE_JSON_API,
    "XML_API": SIGNAL_API_TYPE_XML_API,
    "WEBHOOK": SIGNAL_API_TYPE_WEBHOOK,
}

AUTH_MECHANISM_SIGNALS: dict[str, str] = {
    AUTH_MECH_BEARER_TOKEN: SIGNAL_AUTH_MECHANISM_BEARER_TOKEN,
    AUTH_MECH_JWT_BEARER: SIGNAL_AUTH_MECHANISM_JWT_BEARER,
    AUTH_MECH_COOKIE_SESSION: SIGNAL_AUTH_MECHANISM_COOKIE_SESSION,
    AUTH_MECH_OAUTH2: SIGNAL_AUTH_MECHANISM_OAUTH2,
    AUTH_MECH_API_KEY: SIGNAL_AUTH_MECHANISM_API_KEY,
    AUTH_MECH_BASIC: SIGNAL_AUTH_MECHANISM_BASIC,
    AUTH_MECH_MUTUAL_TLS: SIGNAL_AUTH_MECHANISM_MUTUAL_TLS,
}

RATIONALE_TEXTS: dict[str, str] = {
    TYPE_API_AUTHENTICATION_GAP: (
        "API authentication-control evidence is absent or not provided; "
        "this is a research hypothesis only and no credential, token or "
        "key was tested."
    ),
    TYPE_API_AUTHORIZATION_GAP: (
        "Endpoint-level API authorization evidence is absent or not "
        "provided; object-level authorization remains the R46 specialist "
        "responsibility."
    ),
    TYPE_FUNCTION_LEVEL_AUTHORIZATION_GAP: (
        "Function/role authorization evidence is absent or not provided; "
        "no role escalation was attempted."
    ),
    TYPE_TENANT_ISOLATION_GAP: (
        "Tenant-isolation evidence is absent or not provided; no "
        "cross-tenant access was attempted."
    ),
    TYPE_INPUT_VALIDATION_GAP: (
        "Parameter/input validation evidence is absent or not provided; "
        "no malicious input was generated and no fuzzing was performed."
    ),
    TYPE_SCHEMA_VALIDATION_GAP: (
        "Request-schema validation evidence is absent or not provided; "
        "schema presence alone is context only."
    ),
    TYPE_MASS_ASSIGNMENT_RISK: (
        "Supplied field-handling context indicates unknown or unexpected "
        "fields are accepted; no mutation request was sent."
    ),
    TYPE_HTTP_METHOD_CONTROL_GAP: (
        "HTTP method restriction evidence is absent or not provided; no "
        "method was exercised against any endpoint."
    ),
    TYPE_METHOD_OVERRIDE_RISK: (
        "Method override metadata is a research risk signal only; no "
        "override was attempted."
    ),
    TYPE_API_VERSIONING_RISK: (
        "Deprecated API version metadata is a research risk signal only; "
        "no deprecated endpoint was requested."
    ),
    TYPE_RESOURCE_EXPOSURE_RISK: (
        "Supplied response context indicates excessive data exposure; no "
        "response payload was collected."
    ),
    TYPE_SENSITIVE_FIELD_EXPOSURE_RISK: (
        "Supplied context indicates sensitive fields or internal "
        "identifiers are exposed; no data was extracted."
    ),
    TYPE_ERROR_INFORMATION_DISCLOSURE: (
        "Supplied error context indicates detailed error or stack-trace "
        "disclosure; no error was triggered."
    ),
    TYPE_DEBUG_INFORMATION_EXPOSURE: (
        "Supplied context indicates debug information exposure; no debug "
        "endpoint was probed."
    ),
    TYPE_RATE_LIMIT_CONTROL_GAP: (
        "Rate-limit control evidence is absent or not provided; no stress "
        "or flooding request was sent."
    ),
    TYPE_RESOURCE_LIMIT_CONTROL_GAP: (
        "Request-size limit evidence is absent or not provided; no large "
        "request was sent."
    ),
    TYPE_PAGINATION_CONTROL_GAP: (
        "Pagination limit evidence is absent or not provided; no large "
        "page was requested."
    ),
    TYPE_QUERY_COMPLEXITY_CONTROL_GAP: (
        "Query complexity limit evidence is absent or not provided; no "
        "complex query was sent."
    ),
    TYPE_BATCH_OPERATION_CONTROL_GAP: (
        "Batch-operation limit evidence is absent or not provided; no "
        "batch request was sent."
    ),
    TYPE_FILE_UPLOAD_CONTROL_GAP: (
        "File-upload limit evidence is absent or not provided; no upload "
        "was performed."
    ),
    TYPE_FILE_DOWNLOAD_CONTROL_GAP: (
        "File-download control evidence is absent or not provided; no "
        "download was performed."
    ),
    TYPE_CORS_CONTROL_GAP: (
        "CORS policy evidence is absent or not provided; no CORS request "
        "was performed."
    ),
    TYPE_GRAPHQL_INTROSPECTION_RISK: (
        "GraphQL introspection context is a research risk signal only; no "
        "introspection query was sent."
    ),
    TYPE_GRAPHQL_AUTHORIZATION_GAP: (
        "GraphQL field/mutation authorization evidence is absent or not "
        "provided; no query was sent."
    ),
    TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP: (
        "GraphQL depth/complexity limit evidence is absent or not "
        "provided; no complex query was sent."
    ),
    TYPE_API_KEY_CONTROL_GAP: (
        "API key rotation/revocation/scope evidence is absent or not "
        "provided; no key was used or tested."
    ),
    TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP: (
        "Webhook signature validation evidence is absent or not provided; "
        "no webhook request was sent."
    ),
    TYPE_WEBHOOK_REPLAY_CONTROL_GAP: (
        "Webhook replay protection evidence is absent or not provided; no "
        "webhook was replayed."
    ),
    TYPE_CONTENT_TYPE_CONTROL_GAP: (
        "Content-type validation evidence is absent or not provided; no "
        "alternate content type was submitted."
    ),
    TYPE_API_SECURITY_CONTROL_PRESENT: (
        "Supplied context explicitly contains API security control "
        "evidence; research priority is reduced."
    ),
    TYPE_MISSING_API_CONTEXT: (
        "No usable API control context was supplied; additional "
        "structured context is required."
    ),
    TYPE_UNKNOWN: (
        "Insufficient structured API context for a research hypothesis."
    ),
}


def _hypothesis(
    hypothesis_type: str,
    priority: str,
    hypothesis_state: str,
    signals: object,
) -> dict:
    bounded_signals: list[str] = []
    for signal in signals or ():
        if (
            signal
            and signal in VALIDATION_SIGNALS_LOOKUP
            and signal not in bounded_signals
        ):
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_NO_API_ATTACK_CLAIM,
        LIMITATION_NO_AUTH_BYPASS_CLAIM,
        LIMITATION_NO_IDOR_EXPLOIT_CLAIM,
        LIMITATION_NO_INJECTION_EXPLOIT_CLAIM,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if priority == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = APISecurityHypothesisPlan(
        rule_version=API_SECURITY_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        hypothesis_state=hypothesis_state,
        supporting_signals=bounded_signals,
        confidence=priority,
        priority=priority,
        rationale=RATIONALE_TEXTS.get(hypothesis_type, ""),
        limitations=limitations,
        research_only=True,
    )
    return api_security_hypothesis_plan_projection(plan)


def plan_api_security_hypotheses(
    context_analysis: object = None,
) -> list[dict]:
    """Build the deterministic API security hypotheses (read-only).

    The mapping is conservative and never claims a vulnerability:

    - explicit observed absence of an API validation/control produces the
      matching gap hypothesis with ``WEAKNESS_OBSERVED``;
    - not-provided validation information produces the matching gap
      hypothesis with ``NEEDS_EVIDENCE`` at low priority;
    - explicit observed control evidence produces
      ``API_SECURITY_CONTROL_PRESENT`` and never a gap for that control;
    - technology presence alone (API type, endpoint metadata, schemas,
      pagination, CORS metadata, API keys, webhooks) produces no gap
      hypothesis;
    - nothing usable degrades to ``UNKNOWN``.
    """

    context = sanitize_api_security_context_analysis_plan(context_analysis)
    has_api = api_security_context_present(context)
    has_graphql = graphql_context_present(context)
    has_webhook = webhook_context_present(context)
    has_api_key = api_key_context_present(context)
    has_upload = file_upload_context_present(context)
    has_download = file_download_context_present(context)
    has_batch = batch_context_present(context)
    has_pagination = pagination_context_present(context)
    is_graphql = context["api_type"] == API_TYPE_GRAPHQL

    known_count = sum(
        1 for key in context if key not in ("rule_version", "research_only",
                                            "context_confidence")
        and context[key] not in UNKNOWN_VALUES
    )

    api_type_signal = API_TYPE_SIGNALS.get(context["api_type"], "")
    mechanism_signal = AUTH_MECHANISM_SIGNALS.get(
        context["authentication_mechanism"], ""
    )
    versioning_signal = (
        SIGNAL_API_VERSIONED
        if context["api_versioning"] == API_VERSIONING_VERSIONED_OBSERVED
        else SIGNAL_API_DEPRECATED_VERSION
        if context["api_versioning"]
        == API_VERSIONING_DEPRECATED_VERSION_OBSERVED
        else SIGNAL_API_UNVERSIONED
        if context["api_versioning"] not in UNKNOWN_VALUES
        else ""
    )
    content_type_signal = {
        CONTENT_TYPE_JSON_OBSERVED: SIGNAL_CONTENT_TYPE_JSON,
        CONTENT_TYPE_FORM_OBSERVED: SIGNAL_CONTENT_TYPE_FORM,
        CONTENT_TYPE_XML_OBSERVED: SIGNAL_CONTENT_TYPE_XML,
        CONTENT_TYPE_MULTIPART_OBSERVED: SIGNAL_CONTENT_TYPE_MULTIPART,
    }.get(context["content_type"], "")
    surface_signals: list[str] = []
    for name, signal in (
        ("object_authorization_context",
         SIGNAL_OBJECT_AUTHORIZATION_CONTEXT_OBSERVED),
        ("endpoint_metadata", SIGNAL_ENDPOINT_METADATA_OBSERVED),
        ("request_schema", SIGNAL_REQUEST_SCHEMA_OBSERVED),
        ("response_schema", SIGNAL_RESPONSE_SCHEMA_OBSERVED),
        ("pagination_context", SIGNAL_PAGINATION_CONTEXT_OBSERVED),
        ("batch_context", SIGNAL_BATCH_CONTEXT_OBSERVED),
        ("file_upload_context", SIGNAL_FILE_UPLOAD_OBSERVED),
        ("file_download_context", SIGNAL_FILE_DOWNLOAD_OBSERVED),
        ("nested_resource_context", SIGNAL_NESTED_RESOURCES_OBSERVED),
        ("graphql_batching", SIGNAL_GRAPHQL_BATCHING_OBSERVED),
        ("webhook_context", SIGNAL_WEBHOOK_CONTEXT_OBSERVED),
    ):
        if context[name] == OBSERVED:
            surface_signals.append(signal)
    exposure_signal = (
        SIGNAL_EXCESSIVE_DATA_OBSERVED
        if context["resource_exposure"]
        == RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED
        else ""
    )
    sensitive_signal = (
        SIGNAL_SENSITIVE_FIELDS_OBSERVED
        if context["sensitive_field_exposure"]
        == "SENSITIVE_FIELDS_OBSERVED"
        else SIGNAL_INTERNAL_IDENTIFIERS_OBSERVED
        if context["sensitive_field_exposure"]
        == "INTERNAL_IDENTIFIERS_OBSERVED"
        else ""
    )
    error_signal = {
        "GENERIC_MESSAGE_OBSERVED": SIGNAL_ERROR_GENERIC_OBSERVED,
        "DETAILED_ERROR_OBSERVED": SIGNAL_ERROR_DETAILED_OBSERVED,
        "STACK_TRACE_OBSERVED": SIGNAL_ERROR_STACK_TRACE_OBSERVED,
    }.get(context["error_detail"], "")
    debug_signal = (
        SIGNAL_DEBUG_INFORMATION_OBSERVED
        if context["debug_information"] == DEBUG_INFORMATION_OBSERVED
        else ""
    )
    introspection_signal = {
        "INTROSPECTION_ENABLED_OBSERVED": (
            SIGNAL_INTROSPECTION_ENABLED_OBSERVED
        ),
        "INTROSPECTION_DISABLED_OBSERVED": (
            SIGNAL_INTROSPECTION_DISABLED_OBSERVED
        ),
    }.get(context["graphql_introspection"], "")

    base_signals = (
        api_type_signal,
        content_type_signal,
        mechanism_signal,
    )

    found: dict[str, tuple] = {}

    def add(
        hypothesis_type: str,
        priority: str,
        hypothesis_state: str,
        signals: object,
    ) -> None:
        if hypothesis_type not in found:
            found[hypothesis_type] = (
                priority,
                hypothesis_state,
                tuple(s for s in signals or () if s),
            )

    def validation_gap(
        hypothesis_type: str,
        field: str,
        state: str,
        strong_priority: str,
        required: bool,
        extra: object = (),
    ) -> None:
        if not required or state == VALIDATION_ENFORCED_OBSERVED:
            return
        enforced, absent, not_provided = VALIDATION_SIGNALS[field]
        signals = tuple(s for s in extra or () if s)
        if state in VALIDATION_CONTROL_ABSENT_STATES:
            add(
                hypothesis_type,
                strong_priority,
                STATE_WEAKNESS_OBSERVED,
                (absent,) + signals,
            )
        else:
            add(
                hypothesis_type,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (not_provided,) + signals,
            )

    if has_api:
        validation_gap(
            TYPE_API_AUTHENTICATION_GAP,
            "api_authentication",
            context["api_authentication"],
            CONFIDENCE_HIGH,
            True,
            base_signals,
        )
        validation_gap(
            TYPE_API_AUTHORIZATION_GAP,
            "endpoint_authorization",
            context["endpoint_authorization"],
            CONFIDENCE_HIGH,
            True,
            base_signals + tuple(surface_signals),
        )
        validation_gap(
            TYPE_FUNCTION_LEVEL_AUTHORIZATION_GAP,
            "function_role_authorization",
            context["function_role_authorization"],
            CONFIDENCE_HIGH,
            True,
            base_signals + (mechanism_signal,),
        )
        validation_gap(
            TYPE_TENANT_ISOLATION_GAP,
            "tenant_isolation",
            context["tenant_isolation"],
            CONFIDENCE_HIGH,
            True,
            base_signals + tuple(surface_signals),
        )
        validation_gap(
            TYPE_INPUT_VALIDATION_GAP,
            "parameter_validation",
            context["parameter_validation"],
            CONFIDENCE_HIGH,
            True,
            base_signals + (SIGNAL_REQUEST_SCHEMA_OBSERVED,)
            if context["request_schema"] == OBSERVED
            else base_signals,
        )
        validation_gap(
            TYPE_SCHEMA_VALIDATION_GAP,
            "schema_validation",
            context["schema_validation"],
            CONFIDENCE_HIGH,
            True,
            base_signals + (SIGNAL_REQUEST_SCHEMA_OBSERVED,)
            if context["request_schema"] == OBSERVED
            else base_signals,
        )
        unknown_field_state = context["unknown_field_handling"]
        if unknown_field_state in VALIDATION_CONTROL_ABSENT_STATES:
            add(
                TYPE_MASS_ASSIGNMENT_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    VALIDATION_SIGNALS["unknown_field_handling"][1],
                    VALIDATION_SIGNALS["sensitive_field_control"][1]
                    if context["sensitive_field_control"]
                    in VALIDATION_CONTROL_ABSENT_STATES
                    else "",
                    SIGNAL_REQUEST_SCHEMA_OBSERVED
                    if context["request_schema"] == OBSERVED
                    else "",
                ),
            )
        elif unknown_field_state in VALIDATION_MISSING_STATES:
            add(
                TYPE_MASS_ASSIGNMENT_RISK,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    VALIDATION_SIGNALS["unknown_field_handling"][2],
                    SIGNAL_REQUEST_SCHEMA_OBSERVED
                    if context["request_schema"] == OBSERVED
                    else "",
                ),
            )
        validation_gap(
            TYPE_HTTP_METHOD_CONTROL_GAP,
            "http_method_restrictions",
            context["http_method_restrictions"],
            CONFIDENCE_HIGH,
            True,
            base_signals + (SIGNAL_ENDPOINT_METADATA_OBSERVED,)
            if context["endpoint_metadata"] == OBSERVED
            else base_signals,
        )
        validation_gap(
            TYPE_METHOD_OVERRIDE_RISK,
            "method_override_control",
            context["method_override_control"],
            CONFIDENCE_MEDIUM,
            True,
            base_signals,
        )
        if context["api_versioning"] == (
            API_VERSIONING_DEPRECATED_VERSION_OBSERVED
        ):
            add(
                TYPE_API_VERSIONING_RISK,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (SIGNAL_API_DEPRECATED_VERSION, api_type_signal),
            )
        if context["resource_exposure"] == (
            RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED
        ):
            add(
                TYPE_RESOURCE_EXPOSURE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (exposure_signal, SIGNAL_RESPONSE_SCHEMA_OBSERVED)
                if context["response_schema"] == OBSERVED
                else (exposure_signal,),
            )
        if context["sensitive_field_exposure"] in (
            OBSERVED_SENSITIVE_FIELD_STATES
        ):
            add(
                TYPE_SENSITIVE_FIELD_EXPOSURE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (sensitive_signal,) + base_signals,
            )
        elif context["sensitive_field_control"] in (
            VALIDATION_CONTROL_ABSENT_STATES
        ):
            add(
                TYPE_SENSITIVE_FIELD_EXPOSURE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    VALIDATION_SIGNALS["sensitive_field_control"][1],
                ) + base_signals,
            )
        elif context["sensitive_field_control"] in VALIDATION_MISSING_STATES:
            add(
                TYPE_SENSITIVE_FIELD_EXPOSURE_RISK,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    VALIDATION_SIGNALS["sensitive_field_control"][2],
                ) + base_signals,
            )
        if context["error_detail"] in ERROR_DISCLOSURE_STATES:
            add(
                TYPE_ERROR_INFORMATION_DISCLOSURE,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (error_signal,) + base_signals,
            )
        elif context["error_detail"] in (
            "GENERIC_MESSAGE_OBSERVED",
            "NONE_OBSERVED",
        ):
            pass
        elif context["error_detail_control"] in (
            VALIDATION_CONTROL_ABSENT_STATES
        ):
            add(
                TYPE_ERROR_INFORMATION_DISCLOSURE,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    VALIDATION_SIGNALS["error_detail_control"][1],
                ) + base_signals,
            )
        elif context["error_detail_control"] in VALIDATION_MISSING_STATES:
            add(
                TYPE_ERROR_INFORMATION_DISCLOSURE,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    VALIDATION_SIGNALS["error_detail_control"][2],
                ) + base_signals,
            )
        if context["debug_information"] == DEBUG_INFORMATION_OBSERVED:
            add(
                TYPE_DEBUG_INFORMATION_EXPOSURE,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (debug_signal,) + base_signals,
            )
        elif context["debug_information"] == "NONE_OBSERVED":
            pass
        elif context["debug_mode_control"] in (
            VALIDATION_CONTROL_ABSENT_STATES
        ):
            add(
                TYPE_DEBUG_INFORMATION_EXPOSURE,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    VALIDATION_SIGNALS["debug_mode_control"][1],
                ) + base_signals,
            )
        elif context["debug_mode_control"] in VALIDATION_MISSING_STATES:
            add(
                TYPE_DEBUG_INFORMATION_EXPOSURE,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    VALIDATION_SIGNALS["debug_mode_control"][2],
                ) + base_signals,
            )
        validation_gap(
            TYPE_RATE_LIMIT_CONTROL_GAP,
            "rate_limit_control",
            context["rate_limit_control"],
            CONFIDENCE_HIGH,
            True,
            base_signals,
        )
        validation_gap(
            TYPE_RESOURCE_LIMIT_CONTROL_GAP,
            "request_size_limit",
            context["request_size_limit"],
            CONFIDENCE_HIGH,
            True,
            base_signals,
        )
        validation_gap(
            TYPE_PAGINATION_CONTROL_GAP,
            "pagination_limit",
            context["pagination_limit"],
            CONFIDENCE_HIGH,
            has_pagination or has_api,
            base_signals + (SIGNAL_PAGINATION_CONTEXT_OBSERVED,)
            if context["pagination_context"] == OBSERVED
            else base_signals,
        )
        if not is_graphql:
            validation_gap(
                TYPE_QUERY_COMPLEXITY_CONTROL_GAP,
                "query_complexity_limit",
                context["query_complexity_limit"],
                CONFIDENCE_HIGH,
                True,
                base_signals,
            )
        validation_gap(
            TYPE_BATCH_OPERATION_CONTROL_GAP,
            "batch_limit",
            context["batch_limit"],
            CONFIDENCE_HIGH,
            has_batch,
            base_signals + (SIGNAL_BATCH_CONTEXT_OBSERVED,)
            if context["batch_context"] == OBSERVED
            else base_signals,
        )
        validation_gap(
            TYPE_FILE_UPLOAD_CONTROL_GAP,
            "upload_limit",
            context["upload_limit"],
            CONFIDENCE_HIGH,
            has_upload,
            base_signals + (SIGNAL_FILE_UPLOAD_OBSERVED,)
            if context["file_upload_context"] == OBSERVED
            else base_signals,
        )
        validation_gap(
            TYPE_FILE_DOWNLOAD_CONTROL_GAP,
            "download_control",
            context["download_control"],
            CONFIDENCE_HIGH,
            has_download,
            base_signals + (SIGNAL_FILE_DOWNLOAD_OBSERVED,)
            if context["file_download_context"] == OBSERVED
            else base_signals,
        )
        validation_gap(
            TYPE_CORS_CONTROL_GAP,
            "cors_origin_policy",
            context["cors_origin_policy"],
            CONFIDENCE_HIGH,
            True,
            base_signals
            + (
                VALIDATION_SIGNALS["cors_credentials_policy"][1]
                if context["cors_credentials_policy"]
                in VALIDATION_CONTROL_ABSENT_STATES
                else "",
            ),
        )
        validation_gap(
            TYPE_CONTENT_TYPE_CONTROL_GAP,
            "content_type_validation",
            context["content_type_validation"],
            CONFIDENCE_MEDIUM,
            True,
            base_signals + (content_type_signal,),
        )
        if has_api_key:
            validation_gap(
                TYPE_API_KEY_CONTROL_GAP,
                "api_key_rotation",
                context["api_key_rotation"],
                CONFIDENCE_MEDIUM,
                True,
                base_signals + (SIGNAL_AUTH_MECHANISM_API_KEY,),
            )
            validation_gap(
                TYPE_API_KEY_CONTROL_GAP,
                "api_key_revocation",
                context["api_key_revocation"],
                CONFIDENCE_MEDIUM,
                True,
                base_signals + (SIGNAL_AUTH_MECHANISM_API_KEY,),
            )
        if has_webhook:
            validation_gap(
                TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP,
                "webhook_signature_validation",
                context["webhook_signature_validation"],
                CONFIDENCE_HIGH,
                True,
                base_signals
                + (SIGNAL_WEBHOOK_CONTEXT_OBSERVED,)
                if context["webhook_context"] == OBSERVED
                else base_signals,
            )
            validation_gap(
                TYPE_WEBHOOK_REPLAY_CONTROL_GAP,
                "webhook_replay_protection",
                context["webhook_replay_protection"],
                CONFIDENCE_HIGH,
                True,
                base_signals,
            )

    if has_graphql:
        if context["graphql_introspection"] == (
            GRAPHQL_INTROSPECTION_ENABLED_OBSERVED
        ):
            add(
                TYPE_GRAPHQL_INTROSPECTION_RISK,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (introspection_signal,) + base_signals,
            )
        elif context["graphql_introspection"] == (
            GRAPHQL_INTROSPECTION_DISABLED_OBSERVED
        ):
            pass
        elif context["graphql_introspection_control"] in (
            VALIDATION_CONTROL_ABSENT_STATES
        ):
            add(
                TYPE_GRAPHQL_INTROSPECTION_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    VALIDATION_SIGNALS[
                        "graphql_introspection_control"
                    ][1],
                ) + base_signals,
            )
        elif context["graphql_introspection_control"] in (
            VALIDATION_MISSING_STATES
        ):
            add(
                TYPE_GRAPHQL_INTROSPECTION_RISK,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    VALIDATION_SIGNALS[
                        "graphql_introspection_control"
                    ][2],
                    introspection_signal,
                ),
            )
        validation_gap(
            TYPE_GRAPHQL_AUTHORIZATION_GAP,
            "graphql_field_authorization",
            context["graphql_field_authorization"],
            CONFIDENCE_HIGH,
            True,
            base_signals
            + (
                VALIDATION_SIGNALS["graphql_mutation_authorization"][1]
                if context["graphql_mutation_authorization"]
                in VALIDATION_CONTROL_ABSENT_STATES
                else "",
            ),
        )
        validation_gap(
            TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP,
            "graphql_complexity_limit",
            context["graphql_complexity_limit"],
            CONFIDENCE_HIGH,
            True,
            base_signals
            + (
                VALIDATION_SIGNALS["graphql_depth_limit"][1]
                if context["graphql_depth_limit"]
                in VALIDATION_CONTROL_ABSENT_STATES
                else "",
            ),
        )

    enforced_control_signals = []
    for field in VALIDATION_FIELDS:
        if context[field] == VALIDATION_ENFORCED_OBSERVED:
            enforced_control_signals.append(VALIDATION_SIGNALS[field][0])
    if enforced_control_signals:
        add(
            TYPE_API_SECURITY_CONTROL_PRESENT,
            CONFIDENCE_LOW,
            STATE_CONTROL_PRESENT_OBSERVED,
            tuple(enforced_control_signals),
        )

    if not found:
        if known_count == 0:
            return [
                _hypothesis(
                    TYPE_UNKNOWN,
                    CONFIDENCE_UNKNOWN,
                    STATE_UNKNOWN,
                    (SIGNAL_CONTEXT_UNKNOWN,),
                )
            ]
        return [
            _hypothesis(
                TYPE_MISSING_API_CONTEXT,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_MISSING_API_CONTEXT,
                    api_type_signal,
                    mechanism_signal,
                ),
            )
        ]

    hypotheses: list[dict] = []
    for hypothesis_type in HYPOTHESIS_TYPES:
        if hypothesis_type == TYPE_UNKNOWN:
            continue
        if hypothesis_type in found:
            priority, hypothesis_state, signals = found[hypothesis_type]
            hypotheses.append(
                _hypothesis(
                    hypothesis_type,
                    priority,
                    hypothesis_state,
                    signals,
                )
            )
    return hypotheses


__all__ = [
    "API_SECURITY_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_SIGNALS",
    "VALIDATION_SIGNALS_LOOKUP",
    "API_TYPE_SIGNALS",
    "AUTH_MECHANISM_SIGNALS",
    "RATIONALE_TEXTS",
    "plan_api_security_hypotheses",
]

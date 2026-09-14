"""API security context analysis schema (Stage R49.2).

An :class:`APISecurityContextAnalysisPlan` is the deterministic,
descriptive analysis of supplied API security context. It answers the
research question:

    "Which API type, surface, authentication, authorization, validation,
     behavior, resource-control, CORS, GraphQL, API-key and webhook
     signals were supplied?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no API call, no
  endpoint probing, no network connection, no socket, no DNS, no browser,
  no database, no scanner, no payload, no credential testing, no bypass,
  no execution, no persistence. Nothing is performed.
- Technology presence is never vulnerability: REST/GraphQL/RPC APIs,
  endpoint metadata, schemas, pagination, CORS metadata, API keys and
  webhooks are context only.
- Closed vocabularies: every field is a closed set; unknown values remain
  ``UNKNOWN`` and are never promoted.
- Validation states explicitly distinguish observed-enforced evidence,
  observed-absent evidence, not-provided context and unknown context.
- Context confidence reuses the shared evidence-confidence vocabulary and
  means "how complete is the supplied API context?", never "is the target
  vulnerable?".
- Bounded, privacy-safe (no URLs, endpoints, keys or payloads are
  stored), JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION = "r49-2"
RULE_VERSION = API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# API type / versioning / content type
# ---------------------------------------------------------------------------

API_TYPE_NONE_OBSERVED = "NONE_OBSERVED"
API_TYPE_REST = "REST"
API_TYPE_GRAPHQL = "GRAPHQL"
API_TYPE_RPC = "RPC"
API_TYPE_JSON_API = "JSON_API"
API_TYPE_XML_API = "XML_API"
API_TYPE_WEBHOOK = "WEBHOOK"
API_TYPE_UNKNOWN = "UNKNOWN"

API_TYPES: tuple[str, ...] = (
    API_TYPE_NONE_OBSERVED,
    API_TYPE_REST,
    API_TYPE_GRAPHQL,
    API_TYPE_RPC,
    API_TYPE_JSON_API,
    API_TYPE_XML_API,
    API_TYPE_WEBHOOK,
    API_TYPE_UNKNOWN,
)

KNOWN_API_TYPES: tuple[str, ...] = (
    API_TYPE_REST,
    API_TYPE_GRAPHQL,
    API_TYPE_RPC,
    API_TYPE_JSON_API,
    API_TYPE_XML_API,
    API_TYPE_WEBHOOK,
)

API_VERSIONING_VERSIONED_OBSERVED = "VERSIONED_OBSERVED"
API_VERSIONING_UNVERSIONED_OBSERVED = "UNVERSIONED_OBSERVED"
API_VERSIONING_DEPRECATED_VERSION_OBSERVED = "DEPRECATED_VERSION_OBSERVED"
API_VERSIONING_NONE_OBSERVED = "NONE_OBSERVED"
API_VERSIONING_UNKNOWN = "UNKNOWN"

API_VERSIONING_STATES: tuple[str, ...] = (
    API_VERSIONING_VERSIONED_OBSERVED,
    API_VERSIONING_UNVERSIONED_OBSERVED,
    API_VERSIONING_DEPRECATED_VERSION_OBSERVED,
    API_VERSIONING_NONE_OBSERVED,
    API_VERSIONING_UNKNOWN,
)

CONTENT_TYPE_JSON_OBSERVED = "JSON_OBSERVED"
CONTENT_TYPE_FORM_OBSERVED = "FORM_OBSERVED"
CONTENT_TYPE_XML_OBSERVED = "XML_OBSERVED"
CONTENT_TYPE_MULTIPART_OBSERVED = "MULTIPART_OBSERVED"
CONTENT_TYPE_NONE_OBSERVED = "NONE_OBSERVED"
CONTENT_TYPE_UNKNOWN = "UNKNOWN"

CONTENT_TYPE_STATES: tuple[str, ...] = (
    CONTENT_TYPE_JSON_OBSERVED,
    CONTENT_TYPE_FORM_OBSERVED,
    CONTENT_TYPE_XML_OBSERVED,
    CONTENT_TYPE_MULTIPART_OBSERVED,
    CONTENT_TYPE_NONE_OBSERVED,
    CONTENT_TYPE_UNKNOWN,
)

KNOWN_CONTENT_TYPES: tuple[str, ...] = (
    CONTENT_TYPE_JSON_OBSERVED,
    CONTENT_TYPE_FORM_OBSERVED,
    CONTENT_TYPE_XML_OBSERVED,
    CONTENT_TYPE_MULTIPART_OBSERVED,
)

# ---------------------------------------------------------------------------
# Authentication mechanism / generic observations
# ---------------------------------------------------------------------------

AUTH_MECH_BEARER_TOKEN = "BEARER_TOKEN"
AUTH_MECH_JWT_BEARER = "JWT_BEARER"
AUTH_MECH_COOKIE_SESSION = "COOKIE_SESSION"
AUTH_MECH_OAUTH2 = "OAUTH2"
AUTH_MECH_API_KEY = "API_KEY"
AUTH_MECH_BASIC = "BASIC"
AUTH_MECH_MUTUAL_TLS = "MUTUAL_TLS"
AUTH_MECH_NONE_OBSERVED = "NONE_OBSERVED"
AUTH_MECH_UNKNOWN = "UNKNOWN"

AUTHENTICATION_MECHANISMS: tuple[str, ...] = (
    AUTH_MECH_NONE_OBSERVED,
    AUTH_MECH_BEARER_TOKEN,
    AUTH_MECH_JWT_BEARER,
    AUTH_MECH_COOKIE_SESSION,
    AUTH_MECH_OAUTH2,
    AUTH_MECH_API_KEY,
    AUTH_MECH_BASIC,
    AUTH_MECH_MUTUAL_TLS,
    AUTH_MECH_UNKNOWN,
)

KNOWN_AUTHENTICATION_MECHANISMS: tuple[str, ...] = (
    AUTH_MECH_BEARER_TOKEN,
    AUTH_MECH_JWT_BEARER,
    AUTH_MECH_COOKIE_SESSION,
    AUTH_MECH_OAUTH2,
    AUTH_MECH_API_KEY,
    AUTH_MECH_BASIC,
    AUTH_MECH_MUTUAL_TLS,
)

OBSERVED = "OBSERVED"
NONE_OBSERVED = "NONE_OBSERVED"
CONTEXT_UNKNOWN = "UNKNOWN"

CONTEXT_OBSERVATIONS: tuple[str, ...] = (
    NONE_OBSERVED,
    OBSERVED,
    CONTEXT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Resource / sensitive-field / error / debug / GraphQL observations
# ---------------------------------------------------------------------------

RESOURCE_EXPOSURE_NONE_OBSERVED = "NONE_OBSERVED"
RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED = "EXCESSIVE_DATA_OBSERVED"
RESOURCE_EXPOSURE_UNKNOWN = "UNKNOWN"

RESOURCE_EXPOSURE_STATES: tuple[str, ...] = (
    RESOURCE_EXPOSURE_NONE_OBSERVED,
    RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED,
    RESOURCE_EXPOSURE_UNKNOWN,
)

SENSITIVE_FIELD_NONE_OBSERVED = "NONE_OBSERVED"
SENSITIVE_FIELD_SENSITIVE_FIELDS_OBSERVED = "SENSITIVE_FIELDS_OBSERVED"
SENSITIVE_FIELD_INTERNAL_IDENTIFIERS_OBSERVED = (
    "INTERNAL_IDENTIFIERS_OBSERVED"
)
SENSITIVE_FIELD_UNKNOWN = "UNKNOWN"

SENSITIVE_FIELD_EXPOSURE_STATES: tuple[str, ...] = (
    SENSITIVE_FIELD_NONE_OBSERVED,
    SENSITIVE_FIELD_SENSITIVE_FIELDS_OBSERVED,
    SENSITIVE_FIELD_INTERNAL_IDENTIFIERS_OBSERVED,
    SENSITIVE_FIELD_UNKNOWN,
)

OBSERVED_SENSITIVE_FIELD_STATES: tuple[str, ...] = (
    SENSITIVE_FIELD_SENSITIVE_FIELDS_OBSERVED,
    SENSITIVE_FIELD_INTERNAL_IDENTIFIERS_OBSERVED,
)

ERROR_DETAIL_NONE_OBSERVED = "NONE_OBSERVED"
ERROR_DETAIL_GENERIC_OBSERVED = "GENERIC_MESSAGE_OBSERVED"
ERROR_DETAIL_DETAILED_OBSERVED = "DETAILED_ERROR_OBSERVED"
ERROR_DETAIL_STACK_TRACE_OBSERVED = "STACK_TRACE_OBSERVED"
ERROR_DETAIL_UNKNOWN = "UNKNOWN"

ERROR_DETAIL_STATES: tuple[str, ...] = (
    ERROR_DETAIL_NONE_OBSERVED,
    ERROR_DETAIL_GENERIC_OBSERVED,
    ERROR_DETAIL_DETAILED_OBSERVED,
    ERROR_DETAIL_STACK_TRACE_OBSERVED,
    ERROR_DETAIL_UNKNOWN,
)

ERROR_DISCLOSURE_STATES: tuple[str, ...] = (
    ERROR_DETAIL_DETAILED_OBSERVED,
    ERROR_DETAIL_STACK_TRACE_OBSERVED,
)

DEBUG_INFORMATION_NONE_OBSERVED = "NONE_OBSERVED"
DEBUG_INFORMATION_OBSERVED = "OBSERVED"
DEBUG_INFORMATION_UNKNOWN = "UNKNOWN"

DEBUG_INFORMATION_STATES: tuple[str, ...] = (
    DEBUG_INFORMATION_NONE_OBSERVED,
    DEBUG_INFORMATION_OBSERVED,
    DEBUG_INFORMATION_UNKNOWN,
)

GRAPHQL_INTROSPECTION_NONE_OBSERVED = "NONE_OBSERVED"
GRAPHQL_INTROSPECTION_ENABLED_OBSERVED = "INTROSPECTION_ENABLED_OBSERVED"
GRAPHQL_INTROSPECTION_DISABLED_OBSERVED = "INTROSPECTION_DISABLED_OBSERVED"
GRAPHQL_INTROSPECTION_UNKNOWN = "UNKNOWN"

GRAPHQL_INTROSPECTION_STATES: tuple[str, ...] = (
    GRAPHQL_INTROSPECTION_NONE_OBSERVED,
    GRAPHQL_INTROSPECTION_ENABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_DISABLED_OBSERVED,
    GRAPHQL_INTROSPECTION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Validation states (shared, explicit)
# ---------------------------------------------------------------------------

VALIDATION_ENFORCED_OBSERVED = "ENFORCED_OBSERVED"
VALIDATION_ABSENT_OBSERVED = "ABSENT_OBSERVED"
VALIDATION_NOT_PROVIDED = "NOT_PROVIDED"
VALIDATION_UNKNOWN = "UNKNOWN"

VALIDATION_STATES: tuple[str, ...] = (
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_UNKNOWN,
)

VALIDATION_CONTROL_PRESENT_STATES: tuple[str, ...] = (
    VALIDATION_ENFORCED_OBSERVED,
)

VALIDATION_CONTROL_ABSENT_STATES: tuple[str, ...] = (
    VALIDATION_ABSENT_OBSERVED,
)

VALIDATION_MISSING_STATES: tuple[str, ...] = (
    VALIDATION_NOT_PROVIDED,
    VALIDATION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Field groups
# ---------------------------------------------------------------------------

# (field name, allowed values, fallback)
ENUM_OBSERVATION_FIELDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("api_type", API_TYPES, API_TYPE_UNKNOWN),
    ("api_versioning", API_VERSIONING_STATES, API_VERSIONING_UNKNOWN),
    ("content_type", CONTENT_TYPE_STATES, CONTENT_TYPE_UNKNOWN),
    (
        "authentication_mechanism",
        AUTHENTICATION_MECHANISMS,
        AUTH_MECH_UNKNOWN,
    ),
    (
        "resource_exposure",
        RESOURCE_EXPOSURE_STATES,
        RESOURCE_EXPOSURE_UNKNOWN,
    ),
    (
        "sensitive_field_exposure",
        SENSITIVE_FIELD_EXPOSURE_STATES,
        SENSITIVE_FIELD_UNKNOWN,
    ),
    ("error_detail", ERROR_DETAIL_STATES, ERROR_DETAIL_UNKNOWN),
    (
        "debug_information",
        DEBUG_INFORMATION_STATES,
        DEBUG_INFORMATION_UNKNOWN,
    ),
    (
        "graphql_introspection",
        GRAPHQL_INTROSPECTION_STATES,
        GRAPHQL_INTROSPECTION_UNKNOWN,
    ),
)

PRESENCE_OBSERVATION_FIELDS: tuple[str, ...] = (
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
)

VALIDATION_FIELDS: tuple[str, ...] = (
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

CONTEXT_ANALYSIS_FIELDS: tuple[str, ...] = (
    ("rule_version",)
    + tuple(name for name, _allowed, _fallback in ENUM_OBSERVATION_FIELDS)
    + PRESENCE_OBSERVATION_FIELDS
    + VALIDATION_FIELDS
    + ("context_confidence", "research_only")
)

MAX_VALUE_LEN = 160
MAX_RATIONALE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _default_context_analysis() -> dict:
    out: dict = {"rule_version": ""}
    for name, _allowed, fallback in ENUM_OBSERVATION_FIELDS:
        out[name] = fallback
    for name in PRESENCE_OBSERVATION_FIELDS:
        out[name] = CONTEXT_UNKNOWN
    for name in VALIDATION_FIELDS:
        out[name] = VALIDATION_NOT_PROVIDED
    out["context_confidence"] = "UNKNOWN"
    out["research_only"] = True
    return out


def sanitize_api_security_context_analysis_plan(value: object) -> dict:
    """Project an R49.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_context_analysis()
    out: dict = {"rule_version": _safe_text(value.get("rule_version"))}
    for name, allowed, fallback in ENUM_OBSERVATION_FIELDS:
        out[name] = _closed(value.get(name), allowed, fallback)
    for name in PRESENCE_OBSERVATION_FIELDS:
        out[name] = _closed(
            value.get(name), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        )
    for name in VALIDATION_FIELDS:
        out[name] = _closed(
            value.get(name), VALIDATION_STATES, VALIDATION_NOT_PROVIDED
        )
    out["context_confidence"] = _closed(
        value.get("context_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
    )
    out["research_only"] = True
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class APISecurityContextAnalysisPlan(BaseModel):
    """Deterministic descriptive API security context analysis (R49.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION
    api_type: str = API_TYPE_UNKNOWN
    api_versioning: str = API_VERSIONING_UNKNOWN
    content_type: str = CONTENT_TYPE_UNKNOWN
    authentication_mechanism: str = AUTH_MECH_UNKNOWN
    resource_exposure: str = RESOURCE_EXPOSURE_UNKNOWN
    sensitive_field_exposure: str = SENSITIVE_FIELD_UNKNOWN
    error_detail: str = ERROR_DETAIL_UNKNOWN
    debug_information: str = DEBUG_INFORMATION_UNKNOWN
    graphql_introspection: str = GRAPHQL_INTROSPECTION_UNKNOWN
    object_authorization_context: str = CONTEXT_UNKNOWN
    endpoint_metadata: str = CONTEXT_UNKNOWN
    request_schema: str = CONTEXT_UNKNOWN
    response_schema: str = CONTEXT_UNKNOWN
    pagination_context: str = CONTEXT_UNKNOWN
    batch_context: str = CONTEXT_UNKNOWN
    file_upload_context: str = CONTEXT_UNKNOWN
    file_download_context: str = CONTEXT_UNKNOWN
    nested_resource_context: str = CONTEXT_UNKNOWN
    graphql_batching: str = CONTEXT_UNKNOWN
    webhook_context: str = CONTEXT_UNKNOWN
    api_authentication: str = VALIDATION_NOT_PROVIDED
    endpoint_authorization: str = VALIDATION_NOT_PROVIDED
    function_role_authorization: str = VALIDATION_NOT_PROVIDED
    tenant_isolation: str = VALIDATION_NOT_PROVIDED
    schema_validation: str = VALIDATION_NOT_PROVIDED
    parameter_validation: str = VALIDATION_NOT_PROVIDED
    unknown_field_handling: str = VALIDATION_NOT_PROVIDED
    content_type_validation: str = VALIDATION_NOT_PROVIDED
    http_method_restrictions: str = VALIDATION_NOT_PROVIDED
    method_override_control: str = VALIDATION_NOT_PROVIDED
    rate_limit_control: str = VALIDATION_NOT_PROVIDED
    request_size_limit: str = VALIDATION_NOT_PROVIDED
    pagination_limit: str = VALIDATION_NOT_PROVIDED
    query_complexity_limit: str = VALIDATION_NOT_PROVIDED
    batch_limit: str = VALIDATION_NOT_PROVIDED
    upload_limit: str = VALIDATION_NOT_PROVIDED
    download_control: str = VALIDATION_NOT_PROVIDED
    error_detail_control: str = VALIDATION_NOT_PROVIDED
    debug_mode_control: str = VALIDATION_NOT_PROVIDED
    sensitive_field_control: str = VALIDATION_NOT_PROVIDED
    cors_origin_policy: str = VALIDATION_NOT_PROVIDED
    cors_credentials_policy: str = VALIDATION_NOT_PROVIDED
    graphql_field_authorization: str = VALIDATION_NOT_PROVIDED
    graphql_mutation_authorization: str = VALIDATION_NOT_PROVIDED
    graphql_depth_limit: str = VALIDATION_NOT_PROVIDED
    graphql_complexity_limit: str = VALIDATION_NOT_PROVIDED
    graphql_introspection_control: str = VALIDATION_NOT_PROVIDED
    api_key_rotation: str = VALIDATION_NOT_PROVIDED
    api_key_revocation: str = VALIDATION_NOT_PROVIDED
    webhook_signature_validation: str = VALIDATION_NOT_PROVIDED
    webhook_replay_protection: str = VALIDATION_NOT_PROVIDED
    webhook_source_validation: str = VALIDATION_NOT_PROVIDED
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("api_type")
    @classmethod
    def _valid_api_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in API_TYPES:
            raise ValueError(f"invalid api_type: {value!r}")
        return text

    @field_validator("api_versioning")
    @classmethod
    def _valid_versioning(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in API_VERSIONING_STATES:
            raise ValueError(f"invalid api_versioning: {value!r}")
        return text

    @field_validator("content_type")
    @classmethod
    def _valid_content_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTENT_TYPE_STATES:
            raise ValueError(f"invalid content_type: {value!r}")
        return text

    @field_validator("authentication_mechanism")
    @classmethod
    def _valid_mechanism(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHENTICATION_MECHANISMS:
            raise ValueError(f"invalid authentication_mechanism: {value!r}")
        return text

    @field_validator("resource_exposure")
    @classmethod
    def _valid_resource_exposure(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESOURCE_EXPOSURE_STATES:
            raise ValueError(f"invalid resource_exposure: {value!r}")
        return text

    @field_validator("sensitive_field_exposure")
    @classmethod
    def _valid_sensitive_fields(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SENSITIVE_FIELD_EXPOSURE_STATES:
            raise ValueError(f"invalid sensitive_field_exposure: {value!r}")
        return text

    @field_validator("error_detail")
    @classmethod
    def _valid_error_detail(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ERROR_DETAIL_STATES:
            raise ValueError(f"invalid error_detail: {value!r}")
        return text

    @field_validator("debug_information")
    @classmethod
    def _valid_debug(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DEBUG_INFORMATION_STATES:
            raise ValueError(f"invalid debug_information: {value!r}")
        return text

    @field_validator("graphql_introspection")
    @classmethod
    def _valid_introspection(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in GRAPHQL_INTROSPECTION_STATES:
            raise ValueError(f"invalid graphql_introspection: {value!r}")
        return text

    @field_validator(*PRESENCE_OBSERVATION_FIELDS)
    @classmethod
    def _valid_observation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTEXT_OBSERVATIONS:
            raise ValueError(f"invalid context observation: {value!r}")
        return text

    @field_validator(*VALIDATION_FIELDS)
    @classmethod
    def _valid_validation_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in VALIDATION_STATES:
            raise ValueError(f"invalid validation state: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("api security context analyses are research-only")
        return True


def api_security_context_analysis_plan_projection(
    value: APISecurityContextAnalysisPlan,
) -> dict:
    """Serialize an R49.2 context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "API_SECURITY_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "API_TYPE_NONE_OBSERVED",
    "API_TYPE_REST",
    "API_TYPE_GRAPHQL",
    "API_TYPE_RPC",
    "API_TYPE_JSON_API",
    "API_TYPE_XML_API",
    "API_TYPE_WEBHOOK",
    "API_TYPE_UNKNOWN",
    "API_TYPES",
    "KNOWN_API_TYPES",
    "API_VERSIONING_VERSIONED_OBSERVED",
    "API_VERSIONING_UNVERSIONED_OBSERVED",
    "API_VERSIONING_DEPRECATED_VERSION_OBSERVED",
    "API_VERSIONING_NONE_OBSERVED",
    "API_VERSIONING_UNKNOWN",
    "API_VERSIONING_STATES",
    "CONTENT_TYPE_JSON_OBSERVED",
    "CONTENT_TYPE_FORM_OBSERVED",
    "CONTENT_TYPE_XML_OBSERVED",
    "CONTENT_TYPE_MULTIPART_OBSERVED",
    "CONTENT_TYPE_NONE_OBSERVED",
    "CONTENT_TYPE_UNKNOWN",
    "CONTENT_TYPE_STATES",
    "KNOWN_CONTENT_TYPES",
    "AUTH_MECH_BEARER_TOKEN",
    "AUTH_MECH_JWT_BEARER",
    "AUTH_MECH_COOKIE_SESSION",
    "AUTH_MECH_OAUTH2",
    "AUTH_MECH_API_KEY",
    "AUTH_MECH_BASIC",
    "AUTH_MECH_MUTUAL_TLS",
    "AUTH_MECH_NONE_OBSERVED",
    "AUTH_MECH_UNKNOWN",
    "AUTHENTICATION_MECHANISMS",
    "KNOWN_AUTHENTICATION_MECHANISMS",
    "OBSERVED",
    "NONE_OBSERVED",
    "CONTEXT_UNKNOWN",
    "CONTEXT_OBSERVATIONS",
    "RESOURCE_EXPOSURE_NONE_OBSERVED",
    "RESOURCE_EXPOSURE_EXCESSIVE_DATA_OBSERVED",
    "RESOURCE_EXPOSURE_UNKNOWN",
    "RESOURCE_EXPOSURE_STATES",
    "SENSITIVE_FIELD_NONE_OBSERVED",
    "SENSITIVE_FIELD_SENSITIVE_FIELDS_OBSERVED",
    "SENSITIVE_FIELD_INTERNAL_IDENTIFIERS_OBSERVED",
    "SENSITIVE_FIELD_UNKNOWN",
    "SENSITIVE_FIELD_EXPOSURE_STATES",
    "OBSERVED_SENSITIVE_FIELD_STATES",
    "ERROR_DETAIL_NONE_OBSERVED",
    "ERROR_DETAIL_GENERIC_OBSERVED",
    "ERROR_DETAIL_DETAILED_OBSERVED",
    "ERROR_DETAIL_STACK_TRACE_OBSERVED",
    "ERROR_DETAIL_UNKNOWN",
    "ERROR_DETAIL_STATES",
    "ERROR_DISCLOSURE_STATES",
    "DEBUG_INFORMATION_NONE_OBSERVED",
    "DEBUG_INFORMATION_OBSERVED",
    "DEBUG_INFORMATION_UNKNOWN",
    "DEBUG_INFORMATION_STATES",
    "GRAPHQL_INTROSPECTION_NONE_OBSERVED",
    "GRAPHQL_INTROSPECTION_ENABLED_OBSERVED",
    "GRAPHQL_INTROSPECTION_DISABLED_OBSERVED",
    "GRAPHQL_INTROSPECTION_UNKNOWN",
    "GRAPHQL_INTROSPECTION_STATES",
    "VALIDATION_ENFORCED_OBSERVED",
    "VALIDATION_ABSENT_OBSERVED",
    "VALIDATION_NOT_PROVIDED",
    "VALIDATION_UNKNOWN",
    "VALIDATION_STATES",
    "VALIDATION_CONTROL_PRESENT_STATES",
    "VALIDATION_CONTROL_ABSENT_STATES",
    "VALIDATION_MISSING_STATES",
    "ENUM_OBSERVATION_FIELDS",
    "PRESENCE_OBSERVATION_FIELDS",
    "VALIDATION_FIELDS",
    "CONTEXT_ANALYSIS_FIELDS",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_api_security_context_analysis_plan",
    "APISecurityContextAnalysisPlan",
    "api_security_context_analysis_plan_projection",
]

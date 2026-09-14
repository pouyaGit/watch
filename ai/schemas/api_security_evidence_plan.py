"""API security evidence plan schema (Stage R49.4).

An :class:`APISecurityEvidencePlan` defines which research evidence would
be required to evaluate the API security hypotheses. It answers the
research question:

    "Which bounded API security evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no API
  call, no endpoint probing, no network connection, no socket, no DNS, no
  browser, no database, no scanner, no payload, no credential testing, no
  bypass, no execution, no secret extraction, no persistence. Nothing is
  queried, called, probed or executed.
- Evidence items describe what would be relevant; they are never
  collected here and never instruct an attack.
- Closed vocabularies: evidence items, evidence state and limitations are
  closed sets; confidence reuses the shared evidence-confidence
  vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

API_SECURITY_EVIDENCE_PLAN_RULE_VERSION = "r49-4"
RULE_VERSION = API_SECURITY_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed evidence vocabulary
# ---------------------------------------------------------------------------

EVIDENCE_API_AUTHENTICATION_CONFIGURATION = (
    "API_AUTHENTICATION_CONFIGURATION"
)
EVIDENCE_API_AUTHENTICATION_ENFORCEMENT = "API_AUTHENTICATION_ENFORCEMENT"
EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY = "ENDPOINT_AUTHORIZATION_POLICY"
EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR = (
    "AUTHORIZATION_ENFORCEMENT_BEHAVIOR"
)
EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY = (
    "FUNCTION_ROLE_AUTHORIZATION_POLICY"
)
EVIDENCE_TENANT_ISOLATION_POLICY = "TENANT_ISOLATION_POLICY"
EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION = (
    "INPUT_VALIDATION_IMPLEMENTATION"
)
EVIDENCE_REQUEST_SCHEMA_DEFINITION = "REQUEST_SCHEMA_DEFINITION"
EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY = "UNKNOWN_FIELD_HANDLING_POLICY"
EVIDENCE_WRITABLE_FIELD_POLICY = "WRITABLE_FIELD_POLICY"
EVIDENCE_HTTP_METHOD_CONFIGURATION = "HTTP_METHOD_CONFIGURATION"
EVIDENCE_METHOD_OVERRIDE_CONFIGURATION = "METHOD_OVERRIDE_CONFIGURATION"
EVIDENCE_API_VERSIONING_POLICY = "API_VERSIONING_POLICY"
EVIDENCE_RESPONSE_FIELD_POLICY = "RESPONSE_FIELD_POLICY"
EVIDENCE_SENSITIVE_FIELD_POLICY = "SENSITIVE_FIELD_POLICY"
EVIDENCE_ERROR_HANDLING_CONFIGURATION = "ERROR_HANDLING_CONFIGURATION"
EVIDENCE_DEBUG_CONFIGURATION = "DEBUG_CONFIGURATION"
EVIDENCE_RATE_LIMIT_POLICY = "RATE_LIMIT_POLICY"
EVIDENCE_REQUEST_SIZE_LIMIT_POLICY = "REQUEST_SIZE_LIMIT_POLICY"
EVIDENCE_PAGINATION_LIMIT_POLICY = "PAGINATION_LIMIT_POLICY"
EVIDENCE_QUERY_COMPLEXITY_POLICY = "QUERY_COMPLEXITY_POLICY"
EVIDENCE_BATCH_LIMIT_POLICY = "BATCH_LIMIT_POLICY"
EVIDENCE_UPLOAD_LIMIT_POLICY = "UPLOAD_LIMIT_POLICY"
EVIDENCE_DOWNLOAD_CONTROL_POLICY = "DOWNLOAD_CONTROL_POLICY"
EVIDENCE_CORS_ORIGIN_POLICY = "CORS_ORIGIN_POLICY"
EVIDENCE_CORS_CREDENTIAL_POLICY = "CORS_CREDENTIAL_POLICY"
EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY = (
    "GRAPHQL_FIELD_AUTHORIZATION_POLICY"
)
EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY = (
    "GRAPHQL_MUTATION_AUTHORIZATION_POLICY"
)
EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY = "GRAPHQL_DEPTH_LIMIT_POLICY"
EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY = (
    "GRAPHQL_COMPLEXITY_LIMIT_POLICY"
)
EVIDENCE_GRAPHQL_INTROSPECTION_POLICY = "GRAPHQL_INTROSPECTION_POLICY"
EVIDENCE_API_KEY_ROTATION_POLICY = "API_KEY_ROTATION_POLICY"
EVIDENCE_API_KEY_REVOCATION_POLICY = "API_KEY_REVOCATION_POLICY"
EVIDENCE_API_KEY_SCOPE_POLICY = "API_KEY_SCOPE_POLICY"
EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION = "WEBHOOK_SIGNATURE_VALIDATION"
EVIDENCE_WEBHOOK_REPLAY_PROTECTION = "WEBHOOK_REPLAY_PROTECTION"
EVIDENCE_WEBHOOK_SOURCE_VALIDATION = "WEBHOOK_SOURCE_VALIDATION"
EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY = "CONTENT_TYPE_VALIDATION_POLICY"
EVIDENCE_API_SECURITY_CONFIGURATION = "API_SECURITY_CONFIGURATION"
EVIDENCE_UNKNOWN = "UNKNOWN"

API_SECURITY_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
    EVIDENCE_API_AUTHENTICATION_ENFORCEMENT,
    EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY,
    EVIDENCE_TENANT_ISOLATION_POLICY,
    EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
    EVIDENCE_REQUEST_SCHEMA_DEFINITION,
    EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY,
    EVIDENCE_WRITABLE_FIELD_POLICY,
    EVIDENCE_HTTP_METHOD_CONFIGURATION,
    EVIDENCE_METHOD_OVERRIDE_CONFIGURATION,
    EVIDENCE_API_VERSIONING_POLICY,
    EVIDENCE_RESPONSE_FIELD_POLICY,
    EVIDENCE_SENSITIVE_FIELD_POLICY,
    EVIDENCE_ERROR_HANDLING_CONFIGURATION,
    EVIDENCE_DEBUG_CONFIGURATION,
    EVIDENCE_RATE_LIMIT_POLICY,
    EVIDENCE_REQUEST_SIZE_LIMIT_POLICY,
    EVIDENCE_PAGINATION_LIMIT_POLICY,
    EVIDENCE_QUERY_COMPLEXITY_POLICY,
    EVIDENCE_BATCH_LIMIT_POLICY,
    EVIDENCE_UPLOAD_LIMIT_POLICY,
    EVIDENCE_DOWNLOAD_CONTROL_POLICY,
    EVIDENCE_CORS_ORIGIN_POLICY,
    EVIDENCE_CORS_CREDENTIAL_POLICY,
    EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_INTROSPECTION_POLICY,
    EVIDENCE_API_KEY_ROTATION_POLICY,
    EVIDENCE_API_KEY_REVOCATION_POLICY,
    EVIDENCE_API_KEY_SCOPE_POLICY,
    EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION,
    EVIDENCE_WEBHOOK_REPLAY_PROTECTION,
    EVIDENCE_WEBHOOK_SOURCE_VALIDATION,
    EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY,
    EVIDENCE_API_SECURITY_CONFIGURATION,
    EVIDENCE_UNKNOWN,
)

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_API_CALLS = "NO_API_CALLS"
LIMITATION_NO_ENDPOINT_PROBING = "NO_ENDPOINT_PROBING"
LIMITATION_NO_SCANNER_EXECUTION = "NO_SCANNER_EXECUTION"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_CREDENTIAL_TESTING = "NO_CREDENTIAL_TESTING"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

API_SECURITY_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_API_CALLS,
    LIMITATION_NO_ENDPOINT_PROBING,
    LIMITATION_NO_SCANNER_EXECUTION,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 40
MAX_LIMITATIONS = 9
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_api_security_evidence_plan(value: object) -> dict:
    """Project an R49.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_items": [],
            "evidence_state": STATE_UNKNOWN,
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    evidence_state = _safe_text(value.get("evidence_state")).strip().upper()
    if evidence_state not in EVIDENCE_STATES:
        evidence_state = STATE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": [
            item
            for item in (
                _safe_text(entry)
                for entry in value.get("evidence_items") or ()
            )
            if item in API_SECURITY_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in API_SECURITY_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class APISecurityEvidencePlan(BaseModel):
    """Deterministic research-only API security evidence plan (R49.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = API_SECURITY_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return API_SECURITY_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(
            value, API_SECURITY_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS
        )

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STATES:
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, API_SECURITY_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("api security evidence plans are research-only")
        return True


def api_security_evidence_plan_projection(
    value: APISecurityEvidencePlan,
) -> dict:
    """Serialize an R49.4 evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "API_SECURITY_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_API_AUTHENTICATION_CONFIGURATION",
    "EVIDENCE_API_AUTHENTICATION_ENFORCEMENT",
    "EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY",
    "EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR",
    "EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY",
    "EVIDENCE_TENANT_ISOLATION_POLICY",
    "EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION",
    "EVIDENCE_REQUEST_SCHEMA_DEFINITION",
    "EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY",
    "EVIDENCE_WRITABLE_FIELD_POLICY",
    "EVIDENCE_HTTP_METHOD_CONFIGURATION",
    "EVIDENCE_METHOD_OVERRIDE_CONFIGURATION",
    "EVIDENCE_API_VERSIONING_POLICY",
    "EVIDENCE_RESPONSE_FIELD_POLICY",
    "EVIDENCE_SENSITIVE_FIELD_POLICY",
    "EVIDENCE_ERROR_HANDLING_CONFIGURATION",
    "EVIDENCE_DEBUG_CONFIGURATION",
    "EVIDENCE_RATE_LIMIT_POLICY",
    "EVIDENCE_REQUEST_SIZE_LIMIT_POLICY",
    "EVIDENCE_PAGINATION_LIMIT_POLICY",
    "EVIDENCE_QUERY_COMPLEXITY_POLICY",
    "EVIDENCE_BATCH_LIMIT_POLICY",
    "EVIDENCE_UPLOAD_LIMIT_POLICY",
    "EVIDENCE_DOWNLOAD_CONTROL_POLICY",
    "EVIDENCE_CORS_ORIGIN_POLICY",
    "EVIDENCE_CORS_CREDENTIAL_POLICY",
    "EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY",
    "EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY",
    "EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY",
    "EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY",
    "EVIDENCE_GRAPHQL_INTROSPECTION_POLICY",
    "EVIDENCE_API_KEY_ROTATION_POLICY",
    "EVIDENCE_API_KEY_REVOCATION_POLICY",
    "EVIDENCE_API_KEY_SCOPE_POLICY",
    "EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION",
    "EVIDENCE_WEBHOOK_REPLAY_PROTECTION",
    "EVIDENCE_WEBHOOK_SOURCE_VALIDATION",
    "EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY",
    "EVIDENCE_API_SECURITY_CONFIGURATION",
    "EVIDENCE_UNKNOWN",
    "API_SECURITY_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_API_CALLS",
    "LIMITATION_NO_ENDPOINT_PROBING",
    "LIMITATION_NO_SCANNER_EXECUTION",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_CREDENTIAL_TESTING",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "API_SECURITY_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_api_security_evidence_plan",
    "APISecurityEvidencePlan",
    "api_security_evidence_plan_projection",
]

"""OAuth context analysis schema (Stage R48.2).

A :class:`OAuthContextAnalysisPlan` is the deterministic, descriptive
analysis of supplied OAuth protocol context. It answers the research
question:

    "Which OAuth version, flow, actor, request, control, client
     configuration and security-context signals were supplied?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no OAuth
  authorization/token/callback request, no redirect following, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or exchange, no state/nonce/PKCE manipulation, no payload, no
  execution, no persistence. Nothing is performed.
- Technology presence is never vulnerability: OAuth, flows, redirect_uri,
  state, nonce, PKCE, scopes, client ids, authorization codes and refresh
  tokens are context only.
- Closed vocabularies: every field is a closed set; unknown values remain
  ``UNKNOWN`` and are never promoted.
- Validation states explicitly distinguish observed-enforced evidence,
  observed-absent evidence, not-provided context and unknown context.
- Context confidence reuses the shared evidence-confidence vocabulary and
  means "how complete is the supplied OAuth context?", never "is the
  target vulnerable?".
- Bounded, privacy-safe (no URLs, secrets or tokens are stored), JSON
  serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

OAUTH_CONTEXT_ANALYSIS_RULE_VERSION = "r48-2"
RULE_VERSION = OAUTH_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# OAuth version
# ---------------------------------------------------------------------------

OAUTH_VERSION_OAUTH2 = "OAUTH2"
OAUTH_VERSION_OAUTH2_1 = "OAUTH2_1"
OAUTH_VERSION_NONE_OBSERVED = "NONE_OBSERVED"
OAUTH_VERSION_UNKNOWN = "UNKNOWN"

OAUTH_VERSIONS: tuple[str, ...] = (
    OAUTH_VERSION_NONE_OBSERVED,
    OAUTH_VERSION_OAUTH2,
    OAUTH_VERSION_OAUTH2_1,
    OAUTH_VERSION_UNKNOWN,
)

KNOWN_OAUTH_VERSIONS: tuple[str, ...] = (
    OAUTH_VERSION_OAUTH2,
    OAUTH_VERSION_OAUTH2_1,
)

# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

FLOW_AUTHORIZATION_CODE = "AUTHORIZATION_CODE"
FLOW_AUTHORIZATION_CODE_PKCE = "AUTHORIZATION_CODE_PKCE"
FLOW_IMPLICIT = "IMPLICIT"
FLOW_CLIENT_CREDENTIALS = "CLIENT_CREDENTIALS"
FLOW_DEVICE_AUTHORIZATION = "DEVICE_AUTHORIZATION"
FLOW_REFRESH_TOKEN = "REFRESH_TOKEN"
FLOW_HYBRID = "HYBRID"
FLOW_NONE_OBSERVED = "NONE_OBSERVED"
FLOW_UNKNOWN = "UNKNOWN"

OAUTH_FLOWS: tuple[str, ...] = (
    FLOW_NONE_OBSERVED,
    FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_IMPLICIT,
    FLOW_CLIENT_CREDENTIALS,
    FLOW_DEVICE_AUTHORIZATION,
    FLOW_REFRESH_TOKEN,
    FLOW_HYBRID,
    FLOW_UNKNOWN,
)

KNOWN_OAUTH_FLOWS: tuple[str, ...] = (
    FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_IMPLICIT,
    FLOW_CLIENT_CREDENTIALS,
    FLOW_DEVICE_AUTHORIZATION,
    FLOW_REFRESH_TOKEN,
    FLOW_HYBRID,
)

INTERACTIVE_OAUTH_FLOWS: tuple[str, ...] = (
    FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_IMPLICIT,
    FLOW_HYBRID,
)

# ---------------------------------------------------------------------------
# Client type / actors / endpoint + parameter observations
# ---------------------------------------------------------------------------

CLIENT_TYPE_PUBLIC = "PUBLIC_CLIENT"
CLIENT_TYPE_CONFIDENTIAL = "CONFIDENTIAL_CLIENT"
CLIENT_TYPE_NONE_OBSERVED = "NONE_OBSERVED"
CLIENT_TYPE_UNKNOWN = "UNKNOWN"

CLIENT_TYPES: tuple[str, ...] = (
    CLIENT_TYPE_NONE_OBSERVED,
    CLIENT_TYPE_PUBLIC,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_UNKNOWN,
)

KNOWN_CLIENT_TYPES: tuple[str, ...] = (
    CLIENT_TYPE_PUBLIC,
    CLIENT_TYPE_CONFIDENTIAL,
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
# response_type / grant_type
# ---------------------------------------------------------------------------

RESPONSE_TYPE_CODE = "CODE"
RESPONSE_TYPE_TOKEN = "TOKEN"
RESPONSE_TYPE_ID_TOKEN = "ID_TOKEN"
RESPONSE_TYPE_CODE_ID_TOKEN = "CODE_ID_TOKEN"
RESPONSE_TYPE_NONE_OBSERVED = "NONE_OBSERVED"
RESPONSE_TYPE_UNKNOWN = "UNKNOWN"

RESPONSE_TYPES: tuple[str, ...] = (
    RESPONSE_TYPE_NONE_OBSERVED,
    RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_TOKEN,
    RESPONSE_TYPE_ID_TOKEN,
    RESPONSE_TYPE_CODE_ID_TOKEN,
    RESPONSE_TYPE_UNKNOWN,
)

GRANT_AUTHORIZATION_CODE = "AUTHORIZATION_CODE"
GRANT_CLIENT_CREDENTIALS = "CLIENT_CREDENTIALS"
GRANT_REFRESH_TOKEN = "REFRESH_TOKEN"
GRANT_DEVICE_CODE = "DEVICE_CODE"
GRANT_IMPLICIT = "IMPLICIT"
GRANT_NONE_OBSERVED = "NONE_OBSERVED"
GRANT_UNKNOWN = "UNKNOWN"

GRANT_TYPES: tuple[str, ...] = (
    GRANT_NONE_OBSERVED,
    GRANT_AUTHORIZATION_CODE,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_REFRESH_TOKEN,
    GRANT_DEVICE_CODE,
    GRANT_IMPLICIT,
    GRANT_UNKNOWN,
)

KNOWN_GRANT_TYPES: tuple[str, ...] = (
    GRANT_AUTHORIZATION_CODE,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_REFRESH_TOKEN,
    GRANT_DEVICE_CODE,
    GRANT_IMPLICIT,
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
# Authorization code lifetime / registration / auth method
# ---------------------------------------------------------------------------

CODE_LIFETIME_SHORT_OBSERVED = "SHORT_OBSERVED"
CODE_LIFETIME_LONG_OBSERVED = "LONG_OBSERVED"
CODE_LIFETIME_UNBOUNDED_OBSERVED = "UNBOUNDED_OBSERVED"
CODE_LIFETIME_NONE_OBSERVED = "NONE_OBSERVED"
CODE_LIFETIME_UNKNOWN = "UNKNOWN"

AUTHORIZATION_CODE_LIFETIME_STATES: tuple[str, ...] = (
    CODE_LIFETIME_SHORT_OBSERVED,
    CODE_LIFETIME_LONG_OBSERVED,
    CODE_LIFETIME_UNBOUNDED_OBSERVED,
    CODE_LIFETIME_NONE_OBSERVED,
    CODE_LIFETIME_UNKNOWN,
)

CODE_LIFETIME_RISK_STATES: tuple[str, ...] = (
    CODE_LIFETIME_LONG_OBSERVED,
    CODE_LIFETIME_UNBOUNDED_OBSERVED,
)

REDIRECT_REGISTRATION_EXACT = "EXACT_REGISTERED"
REDIRECT_REGISTRATION_WILDCARD = "WILDCARD_REGISTERED"
REDIRECT_REGISTRATION_NONE_OBSERVED = "NONE_OBSERVED"
REDIRECT_REGISTRATION_UNKNOWN = "UNKNOWN"

REDIRECT_URI_REGISTRATION_STATES: tuple[str, ...] = (
    REDIRECT_REGISTRATION_EXACT,
    REDIRECT_REGISTRATION_WILDCARD,
    REDIRECT_REGISTRATION_NONE_OBSERVED,
    REDIRECT_REGISTRATION_UNKNOWN,
)

TOKEN_AUTH_CLIENT_SECRET_BASIC = "CLIENT_SECRET_BASIC"
TOKEN_AUTH_CLIENT_SECRET_POST = "CLIENT_SECRET_POST"
TOKEN_AUTH_PRIVATE_KEY_JWT = "PRIVATE_KEY_JWT"
TOKEN_AUTH_TLS_CLIENT_AUTH = "TLS_CLIENT_AUTH"
TOKEN_AUTH_NONE_OBSERVED = "NONE_OBSERVED"
TOKEN_AUTH_UNKNOWN = "UNKNOWN"

TOKEN_ENDPOINT_AUTH_METHODS: tuple[str, ...] = (
    TOKEN_AUTH_CLIENT_SECRET_BASIC,
    TOKEN_AUTH_CLIENT_SECRET_POST,
    TOKEN_AUTH_PRIVATE_KEY_JWT,
    TOKEN_AUTH_TLS_CLIENT_AUTH,
    TOKEN_AUTH_NONE_OBSERVED,
    TOKEN_AUTH_UNKNOWN,
)

CLIENT_SECRET_REQUIRED_OBSERVED = "REQUIRED_OBSERVED"
CLIENT_SECRET_NOT_REQUIRED_OBSERVED = "NOT_REQUIRED_OBSERVED"
CLIENT_SECRET_NONE_OBSERVED = "NONE_OBSERVED"
CLIENT_SECRET_UNKNOWN = "UNKNOWN"

CLIENT_SECRET_USAGE_STATES: tuple[str, ...] = (
    CLIENT_SECRET_REQUIRED_OBSERVED,
    CLIENT_SECRET_NOT_REQUIRED_OBSERVED,
    CLIENT_SECRET_NONE_OBSERVED,
    CLIENT_SECRET_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Token exposure / authorization boundary / session integration
# ---------------------------------------------------------------------------

EXPOSURE_NONE_OBSERVED = "NONE_OBSERVED"
EXPOSURE_URL_OBSERVED = "URL_EXPOSURE_OBSERVED"
EXPOSURE_BROWSER_STORAGE_OBSERVED = "BROWSER_STORAGE_EXPOSURE_OBSERVED"
EXPOSURE_RESPONSE_BODY_OBSERVED = "RESPONSE_BODY_EXPOSURE_OBSERVED"
EXPOSURE_LOG_OBSERVED = "LOG_EXPOSURE_OBSERVED"
EXPOSURE_REFERRER_OBSERVED = "REFERRER_EXPOSURE_OBSERVED"
EXPOSURE_CLIENT_STORAGE_OBSERVED = "CLIENT_STORAGE_EXPOSURE_OBSERVED"
EXPOSURE_UNKNOWN = "UNKNOWN"

TOKEN_EXPOSURE_STATES: tuple[str, ...] = (
    EXPOSURE_NONE_OBSERVED,
    EXPOSURE_URL_OBSERVED,
    EXPOSURE_BROWSER_STORAGE_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_REFERRER_OBSERVED,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
    EXPOSURE_UNKNOWN,
)

OBSERVED_EXPOSURE_STATES: tuple[str, ...] = (
    EXPOSURE_URL_OBSERVED,
    EXPOSURE_BROWSER_STORAGE_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_REFERRER_OBSERVED,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
)

BOUNDARY_SERVER_SIDE_OBSERVED = "SERVER_SIDE_ENFORCED_OBSERVED"
BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED = "CLIENT_SIDE_ONLY_OBSERVED"
BOUNDARY_MIXED_OBSERVED = "MIXED_OBSERVED"
BOUNDARY_NONE_OBSERVED = "NONE_OBSERVED"
BOUNDARY_UNKNOWN = "UNKNOWN"

AUTHORIZATION_BOUNDARY_STATES: tuple[str, ...] = (
    BOUNDARY_SERVER_SIDE_OBSERVED,
    BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED,
    BOUNDARY_MIXED_OBSERVED,
    BOUNDARY_NONE_OBSERVED,
    BOUNDARY_UNKNOWN,
)

SESSION_SERVER_SIDE_OBSERVED = "SERVER_SIDE_SESSION_OBSERVED"
SESSION_CLIENT_SIDE_OBSERVED = "CLIENT_SIDE_SESSION_OBSERVED"
SESSION_STATELESS_TOKEN_OBSERVED = "STATELESS_TOKEN_OBSERVED"
SESSION_NONE_OBSERVED = "NONE_OBSERVED"
SESSION_UNKNOWN = "UNKNOWN"

SESSION_INTEGRATION_STATES: tuple[str, ...] = (
    SESSION_SERVER_SIDE_OBSERVED,
    SESSION_CLIENT_SIDE_OBSERVED,
    SESSION_STATELESS_TOKEN_OBSERVED,
    SESSION_NONE_OBSERVED,
    SESSION_UNKNOWN,
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


def sanitize_oauth_context_analysis_plan(value: object) -> dict:
    """Project an R48.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "oauth_version": OAUTH_VERSION_UNKNOWN,
            "flow": FLOW_UNKNOWN,
            "client_type": CLIENT_TYPE_UNKNOWN,
            "authorization_server_context": CONTEXT_UNKNOWN,
            "resource_server_context": CONTEXT_UNKNOWN,
            "authorization_endpoint": CONTEXT_UNKNOWN,
            "token_endpoint": CONTEXT_UNKNOWN,
            "redirect_uri": CONTEXT_UNKNOWN,
            "client_id": CONTEXT_UNKNOWN,
            "response_type": RESPONSE_TYPE_UNKNOWN,
            "grant_type": GRANT_UNKNOWN,
            "scope_context": CONTEXT_UNKNOWN,
            "state_parameter": CONTEXT_UNKNOWN,
            "nonce_parameter": CONTEXT_UNKNOWN,
            "pkce_challenge": CONTEXT_UNKNOWN,
            "redirect_uri_validation": VALIDATION_NOT_PROVIDED,
            "exact_redirect_matching": VALIDATION_NOT_PROVIDED,
            "redirect_uri_registration": REDIRECT_REGISTRATION_UNKNOWN,
            "state_validation": VALIDATION_NOT_PROVIDED,
            "state_binding": VALIDATION_NOT_PROVIDED,
            "nonce_validation": VALIDATION_NOT_PROVIDED,
            "pkce_enforcement": VALIDATION_NOT_PROVIDED,
            "pkce_verifier_validation": VALIDATION_NOT_PROVIDED,
            "authorization_code_binding": VALIDATION_NOT_PROVIDED,
            "authorization_code_lifetime": CODE_LIFETIME_UNKNOWN,
            "code_reuse_control": VALIDATION_NOT_PROVIDED,
            "client_authentication": VALIDATION_NOT_PROVIDED,
            "token_endpoint_auth_method": TOKEN_AUTH_UNKNOWN,
            "client_secret_usage": CLIENT_SECRET_UNKNOWN,
            "scope_validation": VALIDATION_NOT_PROVIDED,
            "resource_audience_validation": VALIDATION_NOT_PROVIDED,
            "issuer_validation": VALIDATION_NOT_PROVIDED,
            "token_validation": VALIDATION_NOT_PROVIDED,
            "refresh_token_present": CONTEXT_UNKNOWN,
            "refresh_token_rotation": VALIDATION_NOT_PROVIDED,
            "refresh_token_revocation": VALIDATION_NOT_PROVIDED,
            "consent_control": VALIDATION_NOT_PROVIDED,
            "csrf_protection": VALIDATION_NOT_PROVIDED,
            "login_csrf_protection": VALIDATION_NOT_PROVIDED,
            "redirect_handling": VALIDATION_NOT_PROVIDED,
            "authorization_boundary": BOUNDARY_UNKNOWN,
            "session_integration": SESSION_UNKNOWN,
            "token_exposure": EXPOSURE_UNKNOWN,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "oauth_version": _closed(
            value.get("oauth_version"), OAUTH_VERSIONS, OAUTH_VERSION_UNKNOWN
        ),
        "flow": _closed(value.get("flow"), OAUTH_FLOWS, FLOW_UNKNOWN),
        "client_type": _closed(
            value.get("client_type"), CLIENT_TYPES, CLIENT_TYPE_UNKNOWN
        ),
        "authorization_server_context": _closed(
            value.get("authorization_server_context"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "resource_server_context": _closed(
            value.get("resource_server_context"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "authorization_endpoint": _closed(
            value.get("authorization_endpoint"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "token_endpoint": _closed(
            value.get("token_endpoint"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "redirect_uri": _closed(
            value.get("redirect_uri"), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        ),
        "client_id": _closed(
            value.get("client_id"), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        ),
        "response_type": _closed(
            value.get("response_type"), RESPONSE_TYPES, RESPONSE_TYPE_UNKNOWN
        ),
        "grant_type": _closed(
            value.get("grant_type"), GRANT_TYPES, GRANT_UNKNOWN
        ),
        "scope_context": _closed(
            value.get("scope_context"), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        ),
        "state_parameter": _closed(
            value.get("state_parameter"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "nonce_parameter": _closed(
            value.get("nonce_parameter"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "pkce_challenge": _closed(
            value.get("pkce_challenge"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "redirect_uri_validation": _closed(
            value.get("redirect_uri_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "exact_redirect_matching": _closed(
            value.get("exact_redirect_matching"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "redirect_uri_registration": _closed(
            value.get("redirect_uri_registration"),
            REDIRECT_URI_REGISTRATION_STATES,
            REDIRECT_REGISTRATION_UNKNOWN,
        ),
        "state_validation": _closed(
            value.get("state_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "state_binding": _closed(
            value.get("state_binding"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "nonce_validation": _closed(
            value.get("nonce_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "pkce_enforcement": _closed(
            value.get("pkce_enforcement"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "pkce_verifier_validation": _closed(
            value.get("pkce_verifier_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "authorization_code_binding": _closed(
            value.get("authorization_code_binding"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "authorization_code_lifetime": _closed(
            value.get("authorization_code_lifetime"),
            AUTHORIZATION_CODE_LIFETIME_STATES,
            CODE_LIFETIME_UNKNOWN,
        ),
        "code_reuse_control": _closed(
            value.get("code_reuse_control"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "client_authentication": _closed(
            value.get("client_authentication"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "token_endpoint_auth_method": _closed(
            value.get("token_endpoint_auth_method"),
            TOKEN_ENDPOINT_AUTH_METHODS,
            TOKEN_AUTH_UNKNOWN,
        ),
        "client_secret_usage": _closed(
            value.get("client_secret_usage"),
            CLIENT_SECRET_USAGE_STATES,
            CLIENT_SECRET_UNKNOWN,
        ),
        "scope_validation": _closed(
            value.get("scope_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "resource_audience_validation": _closed(
            value.get("resource_audience_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "issuer_validation": _closed(
            value.get("issuer_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "token_validation": _closed(
            value.get("token_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "refresh_token_present": _closed(
            value.get("refresh_token_present"),
            CONTEXT_OBSERVATIONS,
            CONTEXT_UNKNOWN,
        ),
        "refresh_token_rotation": _closed(
            value.get("refresh_token_rotation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "refresh_token_revocation": _closed(
            value.get("refresh_token_revocation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "consent_control": _closed(
            value.get("consent_control"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "csrf_protection": _closed(
            value.get("csrf_protection"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "login_csrf_protection": _closed(
            value.get("login_csrf_protection"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "redirect_handling": _closed(
            value.get("redirect_handling"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "authorization_boundary": _closed(
            value.get("authorization_boundary"),
            AUTHORIZATION_BOUNDARY_STATES,
            BOUNDARY_UNKNOWN,
        ),
        "session_integration": _closed(
            value.get("session_integration"),
            SESSION_INTEGRATION_STATES,
            SESSION_UNKNOWN,
        ),
        "token_exposure": _closed(
            value.get("token_exposure"),
            TOKEN_EXPOSURE_STATES,
            EXPOSURE_UNKNOWN,
        ),
        "context_confidence": _closed(
            value.get("context_confidence"),
            CONFIDENCE_LEVELS,
            "UNKNOWN",
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class OAuthContextAnalysisPlan(BaseModel):
    """Deterministic descriptive OAuth context analysis (R48.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = OAUTH_CONTEXT_ANALYSIS_RULE_VERSION
    oauth_version: str = OAUTH_VERSION_UNKNOWN
    flow: str = FLOW_UNKNOWN
    client_type: str = CLIENT_TYPE_UNKNOWN
    authorization_server_context: str = CONTEXT_UNKNOWN
    resource_server_context: str = CONTEXT_UNKNOWN
    authorization_endpoint: str = CONTEXT_UNKNOWN
    token_endpoint: str = CONTEXT_UNKNOWN
    redirect_uri: str = CONTEXT_UNKNOWN
    client_id: str = CONTEXT_UNKNOWN
    response_type: str = RESPONSE_TYPE_UNKNOWN
    grant_type: str = GRANT_UNKNOWN
    scope_context: str = CONTEXT_UNKNOWN
    state_parameter: str = CONTEXT_UNKNOWN
    nonce_parameter: str = CONTEXT_UNKNOWN
    pkce_challenge: str = CONTEXT_UNKNOWN
    redirect_uri_validation: str = VALIDATION_NOT_PROVIDED
    exact_redirect_matching: str = VALIDATION_NOT_PROVIDED
    redirect_uri_registration: str = REDIRECT_REGISTRATION_UNKNOWN
    state_validation: str = VALIDATION_NOT_PROVIDED
    state_binding: str = VALIDATION_NOT_PROVIDED
    nonce_validation: str = VALIDATION_NOT_PROVIDED
    pkce_enforcement: str = VALIDATION_NOT_PROVIDED
    pkce_verifier_validation: str = VALIDATION_NOT_PROVIDED
    authorization_code_binding: str = VALIDATION_NOT_PROVIDED
    authorization_code_lifetime: str = CODE_LIFETIME_UNKNOWN
    code_reuse_control: str = VALIDATION_NOT_PROVIDED
    client_authentication: str = VALIDATION_NOT_PROVIDED
    token_endpoint_auth_method: str = TOKEN_AUTH_UNKNOWN
    client_secret_usage: str = CLIENT_SECRET_UNKNOWN
    scope_validation: str = VALIDATION_NOT_PROVIDED
    resource_audience_validation: str = VALIDATION_NOT_PROVIDED
    issuer_validation: str = VALIDATION_NOT_PROVIDED
    token_validation: str = VALIDATION_NOT_PROVIDED
    refresh_token_present: str = CONTEXT_UNKNOWN
    refresh_token_rotation: str = VALIDATION_NOT_PROVIDED
    refresh_token_revocation: str = VALIDATION_NOT_PROVIDED
    consent_control: str = VALIDATION_NOT_PROVIDED
    csrf_protection: str = VALIDATION_NOT_PROVIDED
    login_csrf_protection: str = VALIDATION_NOT_PROVIDED
    redirect_handling: str = VALIDATION_NOT_PROVIDED
    authorization_boundary: str = BOUNDARY_UNKNOWN
    session_integration: str = SESSION_UNKNOWN
    token_exposure: str = EXPOSURE_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return OAUTH_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("oauth_version")
    @classmethod
    def _valid_version(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OAUTH_VERSIONS:
            raise ValueError(f"invalid oauth_version: {value!r}")
        return text

    @field_validator("flow")
    @classmethod
    def _valid_flow(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OAUTH_FLOWS:
            raise ValueError(f"invalid flow: {value!r}")
        return text

    @field_validator("client_type")
    @classmethod
    def _valid_client_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLIENT_TYPES:
            raise ValueError(f"invalid client_type: {value!r}")
        return text

    @field_validator(
        "authorization_server_context",
        "resource_server_context",
        "authorization_endpoint",
        "token_endpoint",
        "redirect_uri",
        "client_id",
        "scope_context",
        "state_parameter",
        "nonce_parameter",
        "pkce_challenge",
        "refresh_token_present",
    )
    @classmethod
    def _valid_observation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTEXT_OBSERVATIONS:
            raise ValueError(f"invalid context observation: {value!r}")
        return text

    @field_validator("response_type")
    @classmethod
    def _valid_response_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESPONSE_TYPES:
            raise ValueError(f"invalid response_type: {value!r}")
        return text

    @field_validator("grant_type")
    @classmethod
    def _valid_grant_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in GRANT_TYPES:
            raise ValueError(f"invalid grant_type: {value!r}")
        return text

    @field_validator(
        "redirect_uri_validation",
        "exact_redirect_matching",
        "state_validation",
        "state_binding",
        "nonce_validation",
        "pkce_enforcement",
        "pkce_verifier_validation",
        "authorization_code_binding",
        "code_reuse_control",
        "client_authentication",
        "scope_validation",
        "resource_audience_validation",
        "issuer_validation",
        "token_validation",
        "refresh_token_rotation",
        "refresh_token_revocation",
        "consent_control",
        "csrf_protection",
        "login_csrf_protection",
        "redirect_handling",
    )
    @classmethod
    def _valid_validation_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in VALIDATION_STATES:
            raise ValueError(f"invalid validation state: {value!r}")
        return text

    @field_validator("redirect_uri_registration")
    @classmethod
    def _valid_registration(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REDIRECT_URI_REGISTRATION_STATES:
            raise ValueError(f"invalid redirect_uri_registration: {value!r}")
        return text

    @field_validator("authorization_code_lifetime")
    @classmethod
    def _valid_code_lifetime(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_CODE_LIFETIME_STATES:
            raise ValueError(f"invalid authorization_code_lifetime: {value!r}")
        return text

    @field_validator("token_endpoint_auth_method")
    @classmethod
    def _valid_token_auth_method(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_ENDPOINT_AUTH_METHODS:
            raise ValueError(f"invalid token_endpoint_auth_method: {value!r}")
        return text

    @field_validator("client_secret_usage")
    @classmethod
    def _valid_client_secret(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLIENT_SECRET_USAGE_STATES:
            raise ValueError(f"invalid client_secret_usage: {value!r}")
        return text

    @field_validator("authorization_boundary")
    @classmethod
    def _valid_boundary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_BOUNDARY_STATES:
            raise ValueError(f"invalid authorization_boundary: {value!r}")
        return text

    @field_validator("session_integration")
    @classmethod
    def _valid_session(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SESSION_INTEGRATION_STATES:
            raise ValueError(f"invalid session_integration: {value!r}")
        return text

    @field_validator("token_exposure")
    @classmethod
    def _valid_exposure(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_EXPOSURE_STATES:
            raise ValueError(f"invalid token_exposure: {value!r}")
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
            raise ValueError("oauth context analyses are research-only")
        return True


def oauth_context_analysis_plan_projection(
    value: OAuthContextAnalysisPlan,
) -> dict:
    """Serialize an R48.2 context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "OAUTH_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "OAUTH_VERSION_OAUTH2",
    "OAUTH_VERSION_OAUTH2_1",
    "OAUTH_VERSION_NONE_OBSERVED",
    "OAUTH_VERSION_UNKNOWN",
    "OAUTH_VERSIONS",
    "KNOWN_OAUTH_VERSIONS",
    "FLOW_AUTHORIZATION_CODE",
    "FLOW_AUTHORIZATION_CODE_PKCE",
    "FLOW_IMPLICIT",
    "FLOW_CLIENT_CREDENTIALS",
    "FLOW_DEVICE_AUTHORIZATION",
    "FLOW_REFRESH_TOKEN",
    "FLOW_HYBRID",
    "FLOW_NONE_OBSERVED",
    "FLOW_UNKNOWN",
    "OAUTH_FLOWS",
    "KNOWN_OAUTH_FLOWS",
    "INTERACTIVE_OAUTH_FLOWS",
    "CLIENT_TYPE_PUBLIC",
    "CLIENT_TYPE_CONFIDENTIAL",
    "CLIENT_TYPE_NONE_OBSERVED",
    "CLIENT_TYPE_UNKNOWN",
    "CLIENT_TYPES",
    "KNOWN_CLIENT_TYPES",
    "OBSERVED",
    "NONE_OBSERVED",
    "CONTEXT_UNKNOWN",
    "CONTEXT_OBSERVATIONS",
    "RESPONSE_TYPE_CODE",
    "RESPONSE_TYPE_TOKEN",
    "RESPONSE_TYPE_ID_TOKEN",
    "RESPONSE_TYPE_CODE_ID_TOKEN",
    "RESPONSE_TYPE_NONE_OBSERVED",
    "RESPONSE_TYPE_UNKNOWN",
    "RESPONSE_TYPES",
    "GRANT_AUTHORIZATION_CODE",
    "GRANT_CLIENT_CREDENTIALS",
    "GRANT_REFRESH_TOKEN",
    "GRANT_DEVICE_CODE",
    "GRANT_IMPLICIT",
    "GRANT_NONE_OBSERVED",
    "GRANT_UNKNOWN",
    "GRANT_TYPES",
    "KNOWN_GRANT_TYPES",
    "VALIDATION_ENFORCED_OBSERVED",
    "VALIDATION_ABSENT_OBSERVED",
    "VALIDATION_NOT_PROVIDED",
    "VALIDATION_UNKNOWN",
    "VALIDATION_STATES",
    "VALIDATION_CONTROL_PRESENT_STATES",
    "VALIDATION_CONTROL_ABSENT_STATES",
    "VALIDATION_MISSING_STATES",
    "CODE_LIFETIME_SHORT_OBSERVED",
    "CODE_LIFETIME_LONG_OBSERVED",
    "CODE_LIFETIME_UNBOUNDED_OBSERVED",
    "CODE_LIFETIME_NONE_OBSERVED",
    "CODE_LIFETIME_UNKNOWN",
    "AUTHORIZATION_CODE_LIFETIME_STATES",
    "CODE_LIFETIME_RISK_STATES",
    "REDIRECT_REGISTRATION_EXACT",
    "REDIRECT_REGISTRATION_WILDCARD",
    "REDIRECT_REGISTRATION_NONE_OBSERVED",
    "REDIRECT_REGISTRATION_UNKNOWN",
    "REDIRECT_URI_REGISTRATION_STATES",
    "TOKEN_AUTH_CLIENT_SECRET_BASIC",
    "TOKEN_AUTH_CLIENT_SECRET_POST",
    "TOKEN_AUTH_PRIVATE_KEY_JWT",
    "TOKEN_AUTH_TLS_CLIENT_AUTH",
    "TOKEN_AUTH_NONE_OBSERVED",
    "TOKEN_AUTH_UNKNOWN",
    "TOKEN_ENDPOINT_AUTH_METHODS",
    "CLIENT_SECRET_REQUIRED_OBSERVED",
    "CLIENT_SECRET_NOT_REQUIRED_OBSERVED",
    "CLIENT_SECRET_NONE_OBSERVED",
    "CLIENT_SECRET_UNKNOWN",
    "CLIENT_SECRET_USAGE_STATES",
    "EXPOSURE_NONE_OBSERVED",
    "EXPOSURE_URL_OBSERVED",
    "EXPOSURE_BROWSER_STORAGE_OBSERVED",
    "EXPOSURE_RESPONSE_BODY_OBSERVED",
    "EXPOSURE_LOG_OBSERVED",
    "EXPOSURE_REFERRER_OBSERVED",
    "EXPOSURE_CLIENT_STORAGE_OBSERVED",
    "EXPOSURE_UNKNOWN",
    "TOKEN_EXPOSURE_STATES",
    "OBSERVED_EXPOSURE_STATES",
    "BOUNDARY_SERVER_SIDE_OBSERVED",
    "BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED",
    "BOUNDARY_MIXED_OBSERVED",
    "BOUNDARY_NONE_OBSERVED",
    "BOUNDARY_UNKNOWN",
    "AUTHORIZATION_BOUNDARY_STATES",
    "SESSION_SERVER_SIDE_OBSERVED",
    "SESSION_CLIENT_SIDE_OBSERVED",
    "SESSION_STATELESS_TOKEN_OBSERVED",
    "SESSION_NONE_OBSERVED",
    "SESSION_UNKNOWN",
    "SESSION_INTEGRATION_STATES",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_oauth_context_analysis_plan",
    "OAuthContextAnalysisPlan",
    "oauth_context_analysis_plan_projection",
]

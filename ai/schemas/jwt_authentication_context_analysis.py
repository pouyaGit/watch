"""JWT/authentication context analysis schema (Stage R47.2).

A :class:`JWTAuthenticationContextAnalysisPlan` is the deterministic,
descriptive analysis of supplied authentication/JWT context. It answers the
research question:

    "Which authentication, token, validation, storage, session and
     authorization-boundary signals were supplied?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no DNS resolution, no
  socket, no browser, no database, no scanner, no token decoding or
  manipulation, no token forgery, no signature bypass, no authentication
  bypass, no brute force, no credential testing, no payload, no execution,
  no persistence.
- Technology presence is never vulnerability: JWT, bearer tokens, cookies,
  algorithm metadata or claim metadata are context only.
- Closed vocabularies: every field is a closed set; unknown values remain
  ``UNKNOWN`` and are never promoted.
- Validation states explicitly distinguish observed-enforced evidence,
  observed-absent evidence, not-provided context and unknown context.
- Context confidence reuses the shared evidence-confidence vocabulary and
  means "how complete is the supplied authentication context?", never "is
  the target vulnerable?".
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION = "r47-2"
RULE_VERSION = JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Authentication mechanism
# ---------------------------------------------------------------------------

AUTH_MECH_NONE_OBSERVED = "NONE_OBSERVED"
AUTH_MECH_BEARER_TOKEN = "BEARER_TOKEN"
AUTH_MECH_JWT_BEARER = "JWT_BEARER"
AUTH_MECH_COOKIE_SESSION = "COOKIE_SESSION"
AUTH_MECH_OAUTH2 = "OAUTH2"
AUTH_MECH_API_KEY = "API_KEY"
AUTH_MECH_BASIC = "BASIC"
AUTH_MECH_MUTUAL_TLS = "MUTUAL_TLS"
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

# ---------------------------------------------------------------------------
# Token mechanism / format
# ---------------------------------------------------------------------------

TOKEN_MECH_NONE_OBSERVED = "NONE_OBSERVED"
TOKEN_MECH_JWT = "JWT"
TOKEN_MECH_OPAQUE_ACCESS = "OPAQUE_ACCESS_TOKEN"
TOKEN_MECH_REFRESH = "REFRESH_TOKEN"
TOKEN_MECH_SESSION_COOKIE = "SESSION_COOKIE"
TOKEN_MECH_UNKNOWN = "UNKNOWN"

TOKEN_MECHANISMS: tuple[str, ...] = (
    TOKEN_MECH_NONE_OBSERVED,
    TOKEN_MECH_JWT,
    TOKEN_MECH_OPAQUE_ACCESS,
    TOKEN_MECH_REFRESH,
    TOKEN_MECH_SESSION_COOKIE,
    TOKEN_MECH_UNKNOWN,
)

JWT_TOKEN_MECHANISMS: tuple[str, ...] = (TOKEN_MECH_JWT,)

TOKEN_FORMAT_NONE_OBSERVED = "NONE_OBSERVED"
TOKEN_FORMAT_COMPACT_JWS = "COMPACT_JWS"
TOKEN_FORMAT_COMPACT_JWE = "COMPACT_JWE"
TOKEN_FORMAT_UNKNOWN = "UNKNOWN"

TOKEN_FORMATS: tuple[str, ...] = (
    TOKEN_FORMAT_NONE_OBSERVED,
    TOKEN_FORMAT_COMPACT_JWS,
    TOKEN_FORMAT_COMPACT_JWE,
    TOKEN_FORMAT_UNKNOWN,
)

JWT_TOKEN_FORMATS: tuple[str, ...] = (
    TOKEN_FORMAT_COMPACT_JWS,
    TOKEN_FORMAT_COMPACT_JWE,
)

# ---------------------------------------------------------------------------
# Signing algorithm / method metadata
# ---------------------------------------------------------------------------

ALG_NONE_OBSERVED = "NONE_OBSERVED"
ALG_HS256 = "HS256"
ALG_HS384 = "HS384"
ALG_HS512 = "HS512"
ALG_RS256 = "RS256"
ALG_RS384 = "RS384"
ALG_RS512 = "RS512"
ALG_ES256 = "ES256"
ALG_ES384 = "ES384"
ALG_ES512 = "ES512"
ALG_PS256 = "PS256"
ALG_PS384 = "PS384"
ALG_PS512 = "PS512"
ALG_NONE = "NONE"
ALG_UNKNOWN = "UNKNOWN"

SIGNING_ALGORITHMS: tuple[str, ...] = (
    ALG_NONE_OBSERVED,
    ALG_HS256,
    ALG_HS384,
    ALG_HS512,
    ALG_RS256,
    ALG_RS384,
    ALG_RS512,
    ALG_ES256,
    ALG_ES384,
    ALG_ES512,
    ALG_PS256,
    ALG_PS384,
    ALG_PS512,
    ALG_NONE,
    ALG_UNKNOWN,
)

HMAC_ALGORITHMS: tuple[str, ...] = (ALG_HS256, ALG_HS384, ALG_HS512)
ASYMMETRIC_ALGORITHMS: tuple[str, ...] = (
    ALG_RS256,
    ALG_RS384,
    ALG_RS512,
    ALG_ES256,
    ALG_ES384,
    ALG_ES512,
    ALG_PS256,
    ALG_PS384,
    ALG_PS512,
)

SIGNING_NONE_OBSERVED = "NONE_OBSERVED"
SIGNING_SYMMETRIC = "SYMMETRIC"
SIGNING_ASYMMETRIC = "ASYMMETRIC"
SIGNING_UNKNOWN = "UNKNOWN"

SIGNING_METHODS: tuple[str, ...] = (
    SIGNING_NONE_OBSERVED,
    SIGNING_SYMMETRIC,
    SIGNING_ASYMMETRIC,
    SIGNING_UNKNOWN,
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
# Key management / rotation
# ---------------------------------------------------------------------------

KEY_MANAGEMENT_MANAGED_OBSERVED = "MANAGED_OBSERVED"
KEY_MANAGEMENT_STATIC_KEY_OBSERVED = "STATIC_KEY_OBSERVED"
KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED = "EMBEDDED_KEY_OBSERVED"
KEY_MANAGEMENT_ABSENT_OBSERVED = "KEY_MANAGEMENT_ABSENT_OBSERVED"
KEY_MANAGEMENT_NONE_OBSERVED = "NONE_OBSERVED"
KEY_MANAGEMENT_UNKNOWN = "UNKNOWN"

KEY_MANAGEMENT_STATES: tuple[str, ...] = (
    KEY_MANAGEMENT_MANAGED_OBSERVED,
    KEY_MANAGEMENT_STATIC_KEY_OBSERVED,
    KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED,
    KEY_MANAGEMENT_ABSENT_OBSERVED,
    KEY_MANAGEMENT_NONE_OBSERVED,
    KEY_MANAGEMENT_UNKNOWN,
)

KEY_ROTATION_CONFIGURED_OBSERVED = "ROTATION_CONFIGURED_OBSERVED"
KEY_ROTATION_NO_ROTATION_OBSERVED = "NO_ROTATION_OBSERVED"
KEY_ROTATION_NONE_OBSERVED = "NONE_OBSERVED"
KEY_ROTATION_UNKNOWN = "UNKNOWN"

KEY_ROTATION_STATES: tuple[str, ...] = (
    KEY_ROTATION_CONFIGURED_OBSERVED,
    KEY_ROTATION_NO_ROTATION_OBSERVED,
    KEY_ROTATION_NONE_OBSERVED,
    KEY_ROTATION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Token lifetime / refresh
# ---------------------------------------------------------------------------

LIFETIME_SHORT_OBSERVED = "SHORT_OBSERVED"
LIFETIME_LONG_OBSERVED = "LONG_OBSERVED"
LIFETIME_UNBOUNDED_OBSERVED = "UNBOUNDED_OBSERVED"
LIFETIME_NONE_OBSERVED = "NONE_OBSERVED"
LIFETIME_UNKNOWN = "UNKNOWN"

TOKEN_LIFETIME_STATES: tuple[str, ...] = (
    LIFETIME_SHORT_OBSERVED,
    LIFETIME_LONG_OBSERVED,
    LIFETIME_UNBOUNDED_OBSERVED,
    LIFETIME_NONE_OBSERVED,
    LIFETIME_UNKNOWN,
)

REFRESH_PRESENT = "PRESENT"
REFRESH_ABSENT_OBSERVED = "ABSENT_OBSERVED"
REFRESH_NONE_OBSERVED = "NONE_OBSERVED"
REFRESH_UNKNOWN = "UNKNOWN"

REFRESH_TOKEN_STATES: tuple[str, ...] = (
    REFRESH_PRESENT,
    REFRESH_ABSENT_OBSERVED,
    REFRESH_NONE_OBSERVED,
    REFRESH_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

SESSION_SERVER_SIDE_OBSERVED = "SERVER_SIDE_SESSION_OBSERVED"
SESSION_CLIENT_SIDE_OBSERVED = "CLIENT_SIDE_SESSION_OBSERVED"
SESSION_STATELESS_TOKEN_OBSERVED = "STATELESS_TOKEN_OBSERVED"
SESSION_NONE_OBSERVED = "NONE_OBSERVED"
SESSION_UNKNOWN = "UNKNOWN"

SESSION_LIFECYCLE_STATES: tuple[str, ...] = (
    SESSION_SERVER_SIDE_OBSERVED,
    SESSION_CLIENT_SIDE_OBSERVED,
    SESSION_STATELESS_TOKEN_OBSERVED,
    SESSION_NONE_OBSERVED,
    SESSION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Token storage / cookie attributes / exposure
# ---------------------------------------------------------------------------

STORAGE_SERVER_SIDE_OBSERVED = "SERVER_SIDE_OBSERVED"
STORAGE_MEMORY_ONLY_OBSERVED = "MEMORY_ONLY_OBSERVED"
STORAGE_COOKIE_OBSERVED = "COOKIE_OBSERVED"
STORAGE_LOCAL_STORAGE_OBSERVED = "LOCAL_STORAGE_OBSERVED"
STORAGE_SESSION_STORAGE_OBSERVED = "SESSION_STORAGE_OBSERVED"
STORAGE_NONE_OBSERVED = "NONE_OBSERVED"
STORAGE_UNKNOWN = "UNKNOWN"

TOKEN_STORAGE_STATES: tuple[str, ...] = (
    STORAGE_SERVER_SIDE_OBSERVED,
    STORAGE_MEMORY_ONLY_OBSERVED,
    STORAGE_COOKIE_OBSERVED,
    STORAGE_LOCAL_STORAGE_OBSERVED,
    STORAGE_SESSION_STORAGE_OBSERVED,
    STORAGE_NONE_OBSERVED,
    STORAGE_UNKNOWN,
)

CLIENT_STORAGE_STATES: tuple[str, ...] = (
    STORAGE_LOCAL_STORAGE_OBSERVED,
    STORAGE_SESSION_STORAGE_OBSERVED,
)

COOKIE_ATTR_SECURE = "SECURE"
COOKIE_ATTR_HTTP_ONLY = "HTTP_ONLY"
COOKIE_ATTR_SAME_SITE_STRICT = "SAME_SITE_STRICT"
COOKIE_ATTR_SAME_SITE_LAX = "SAME_SITE_LAX"
COOKIE_ATTR_SAME_SITE_NONE = "SAME_SITE_NONE"

COOKIE_ATTRIBUTES: tuple[str, ...] = (
    COOKIE_ATTR_SECURE,
    COOKIE_ATTR_HTTP_ONLY,
    COOKIE_ATTR_SAME_SITE_STRICT,
    COOKIE_ATTR_SAME_SITE_LAX,
    COOKIE_ATTR_SAME_SITE_NONE,
)

SECURE_COOKIE_ATTRIBUTES: tuple[str, ...] = (
    COOKIE_ATTR_SECURE,
    COOKIE_ATTR_HTTP_ONLY,
)

SAME_SITE_SOFT_ATTRIBUTES: tuple[str, ...] = (COOKIE_ATTR_SAME_SITE_NONE,)

EXPOSURE_NONE_OBSERVED = "NONE_OBSERVED"
EXPOSURE_URL_OBSERVED = "URL_EXPOSURE_OBSERVED"
EXPOSURE_LOG_OBSERVED = "LOG_EXPOSURE_OBSERVED"
EXPOSURE_RESPONSE_BODY_OBSERVED = "RESPONSE_BODY_EXPOSURE_OBSERVED"
EXPOSURE_CLIENT_STORAGE_OBSERVED = "CLIENT_STORAGE_EXPOSURE_OBSERVED"
EXPOSURE_UNKNOWN = "UNKNOWN"

TOKEN_EXPOSURE_STATES: tuple[str, ...] = (
    EXPOSURE_NONE_OBSERVED,
    EXPOSURE_URL_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
    EXPOSURE_UNKNOWN,
)

OBSERVED_EXPOSURE_STATES: tuple[str, ...] = (
    EXPOSURE_URL_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
)

# ---------------------------------------------------------------------------
# Authorization boundary / authentication flow
# ---------------------------------------------------------------------------

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

FLOW_LOGIN_OBSERVED = "LOGIN_FLOW_OBSERVED"
FLOW_TOKEN_OBSERVED = "TOKEN_FLOW_OBSERVED"
FLOW_SESSION_OBSERVED = "SESSION_FLOW_OBSERVED"
FLOW_REFRESH_OBSERVED = "REFRESH_FLOW_OBSERVED"
FLOW_NONE_OBSERVED = "NONE_OBSERVED"
FLOW_UNKNOWN = "UNKNOWN"

AUTHENTICATION_FLOW_STATES: tuple[str, ...] = (
    FLOW_LOGIN_OBSERVED,
    FLOW_TOKEN_OBSERVED,
    FLOW_SESSION_OBSERVED,
    FLOW_REFRESH_OBSERVED,
    FLOW_NONE_OBSERVED,
    FLOW_UNKNOWN,
)

MAX_COOKIE_ATTRIBUTES = 5
MAX_VALUE_LEN = 160
MAX_RATIONALE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_jwt_authentication_context_analysis_plan(
    value: object,
) -> dict:
    """Project an R47.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "authentication_mechanism": AUTH_MECH_UNKNOWN,
            "token_mechanism": TOKEN_MECH_UNKNOWN,
            "token_format": TOKEN_FORMAT_UNKNOWN,
            "signing_algorithm": ALG_UNKNOWN,
            "signing_method": SIGNING_UNKNOWN,
            "signature_verification": VALIDATION_NOT_PROVIDED,
            "algorithm_validation": VALIDATION_NOT_PROVIDED,
            "issuer_validation": VALIDATION_NOT_PROVIDED,
            "audience_validation": VALIDATION_NOT_PROVIDED,
            "expiration_validation": VALIDATION_NOT_PROVIDED,
            "not_before_validation": VALIDATION_NOT_PROVIDED,
            "claim_validation": VALIDATION_NOT_PROVIDED,
            "key_management": KEY_MANAGEMENT_UNKNOWN,
            "key_rotation": KEY_ROTATION_UNKNOWN,
            "token_lifetime": LIFETIME_UNKNOWN,
            "refresh_token": REFRESH_UNKNOWN,
            "refresh_control": VALIDATION_NOT_PROVIDED,
            "revocation_control": VALIDATION_NOT_PROVIDED,
            "session_lifecycle": SESSION_UNKNOWN,
            "token_storage": STORAGE_UNKNOWN,
            "cookie_attributes": [],
            "token_exposure": EXPOSURE_UNKNOWN,
            "authorization_boundary": BOUNDARY_UNKNOWN,
            "authentication_flow": FLOW_UNKNOWN,
            "authentication_control": VALIDATION_NOT_PROVIDED,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "authentication_mechanism": _closed(
            value.get("authentication_mechanism"),
            AUTHENTICATION_MECHANISMS,
            AUTH_MECH_UNKNOWN,
        ),
        "token_mechanism": _closed(
            value.get("token_mechanism"),
            TOKEN_MECHANISMS,
            TOKEN_MECH_UNKNOWN,
        ),
        "token_format": _closed(
            value.get("token_format"), TOKEN_FORMATS, TOKEN_FORMAT_UNKNOWN
        ),
        "signing_algorithm": _closed(
            value.get("signing_algorithm"),
            SIGNING_ALGORITHMS,
            ALG_UNKNOWN,
        ),
        "signing_method": _closed(
            value.get("signing_method"),
            SIGNING_METHODS,
            SIGNING_UNKNOWN,
        ),
        "signature_verification": _closed(
            value.get("signature_verification"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "algorithm_validation": _closed(
            value.get("algorithm_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "issuer_validation": _closed(
            value.get("issuer_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "audience_validation": _closed(
            value.get("audience_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "expiration_validation": _closed(
            value.get("expiration_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "not_before_validation": _closed(
            value.get("not_before_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "claim_validation": _closed(
            value.get("claim_validation"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "key_management": _closed(
            value.get("key_management"),
            KEY_MANAGEMENT_STATES,
            KEY_MANAGEMENT_UNKNOWN,
        ),
        "key_rotation": _closed(
            value.get("key_rotation"),
            KEY_ROTATION_STATES,
            KEY_ROTATION_UNKNOWN,
        ),
        "token_lifetime": _closed(
            value.get("token_lifetime"),
            TOKEN_LIFETIME_STATES,
            LIFETIME_UNKNOWN,
        ),
        "refresh_token": _closed(
            value.get("refresh_token"), REFRESH_TOKEN_STATES, REFRESH_UNKNOWN
        ),
        "refresh_control": _closed(
            value.get("refresh_control"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "revocation_control": _closed(
            value.get("revocation_control"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
        ),
        "session_lifecycle": _closed(
            value.get("session_lifecycle"),
            SESSION_LIFECYCLE_STATES,
            SESSION_UNKNOWN,
        ),
        "token_storage": _closed(
            value.get("token_storage"),
            TOKEN_STORAGE_STATES,
            STORAGE_UNKNOWN,
        ),
        "cookie_attributes": _bounded_codes(
            value.get("cookie_attributes"),
            COOKIE_ATTRIBUTES,
            MAX_COOKIE_ATTRIBUTES,
        ),
        "token_exposure": _closed(
            value.get("token_exposure"),
            TOKEN_EXPOSURE_STATES,
            EXPOSURE_UNKNOWN,
        ),
        "authorization_boundary": _closed(
            value.get("authorization_boundary"),
            AUTHORIZATION_BOUNDARY_STATES,
            BOUNDARY_UNKNOWN,
        ),
        "authentication_flow": _closed(
            value.get("authentication_flow"),
            AUTHENTICATION_FLOW_STATES,
            FLOW_UNKNOWN,
        ),
        "authentication_control": _closed(
            value.get("authentication_control"),
            VALIDATION_STATES,
            VALIDATION_NOT_PROVIDED,
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


class JWTAuthenticationContextAnalysisPlan(BaseModel):
    """Deterministic descriptive JWT/authentication context analysis (R47.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION
    authentication_mechanism: str = AUTH_MECH_UNKNOWN
    token_mechanism: str = TOKEN_MECH_UNKNOWN
    token_format: str = TOKEN_FORMAT_UNKNOWN
    signing_algorithm: str = ALG_UNKNOWN
    signing_method: str = SIGNING_UNKNOWN
    signature_verification: str = VALIDATION_NOT_PROVIDED
    algorithm_validation: str = VALIDATION_NOT_PROVIDED
    issuer_validation: str = VALIDATION_NOT_PROVIDED
    audience_validation: str = VALIDATION_NOT_PROVIDED
    expiration_validation: str = VALIDATION_NOT_PROVIDED
    not_before_validation: str = VALIDATION_NOT_PROVIDED
    claim_validation: str = VALIDATION_NOT_PROVIDED
    key_management: str = KEY_MANAGEMENT_UNKNOWN
    key_rotation: str = KEY_ROTATION_UNKNOWN
    token_lifetime: str = LIFETIME_UNKNOWN
    refresh_token: str = REFRESH_UNKNOWN
    refresh_control: str = VALIDATION_NOT_PROVIDED
    revocation_control: str = VALIDATION_NOT_PROVIDED
    session_lifecycle: str = SESSION_UNKNOWN
    token_storage: str = STORAGE_UNKNOWN
    cookie_attributes: list[str] = Field(default_factory=list)
    token_exposure: str = EXPOSURE_UNKNOWN
    authorization_boundary: str = BOUNDARY_UNKNOWN
    authentication_flow: str = FLOW_UNKNOWN
    authentication_control: str = VALIDATION_NOT_PROVIDED
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("authentication_mechanism")
    @classmethod
    def _valid_mechanism(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHENTICATION_MECHANISMS:
            raise ValueError(f"invalid authentication_mechanism: {value!r}")
        return text

    @field_validator("token_mechanism")
    @classmethod
    def _valid_token_mechanism(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_MECHANISMS:
            raise ValueError(f"invalid token_mechanism: {value!r}")
        return text

    @field_validator("token_format")
    @classmethod
    def _valid_format(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_FORMATS:
            raise ValueError(f"invalid token_format: {value!r}")
        return text

    @field_validator("signing_algorithm")
    @classmethod
    def _valid_algorithm(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SIGNING_ALGORITHMS:
            raise ValueError(f"invalid signing_algorithm: {value!r}")
        return text

    @field_validator("signing_method")
    @classmethod
    def _valid_method(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SIGNING_METHODS:
            raise ValueError(f"invalid signing_method: {value!r}")
        return text

    @field_validator(
        "signature_verification",
        "algorithm_validation",
        "issuer_validation",
        "audience_validation",
        "expiration_validation",
        "not_before_validation",
        "claim_validation",
        "refresh_control",
        "revocation_control",
        "authentication_control",
    )
    @classmethod
    def _valid_validation_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in VALIDATION_STATES:
            raise ValueError(f"invalid validation state: {value!r}")
        return text

    @field_validator("key_management")
    @classmethod
    def _valid_key_management(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in KEY_MANAGEMENT_STATES:
            raise ValueError(f"invalid key_management: {value!r}")
        return text

    @field_validator("key_rotation")
    @classmethod
    def _valid_key_rotation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in KEY_ROTATION_STATES:
            raise ValueError(f"invalid key_rotation: {value!r}")
        return text

    @field_validator("token_lifetime")
    @classmethod
    def _valid_lifetime(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_LIFETIME_STATES:
            raise ValueError(f"invalid token_lifetime: {value!r}")
        return text

    @field_validator("refresh_token")
    @classmethod
    def _valid_refresh(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REFRESH_TOKEN_STATES:
            raise ValueError(f"invalid refresh_token: {value!r}")
        return text

    @field_validator("session_lifecycle")
    @classmethod
    def _valid_session(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SESSION_LIFECYCLE_STATES:
            raise ValueError(f"invalid session_lifecycle: {value!r}")
        return text

    @field_validator("token_storage")
    @classmethod
    def _valid_storage(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_STORAGE_STATES:
            raise ValueError(f"invalid token_storage: {value!r}")
        return text

    @field_validator("cookie_attributes")
    @classmethod
    def _valid_cookie_attributes(cls, value: list) -> list[str]:
        return _bounded_codes(
            value, COOKIE_ATTRIBUTES, MAX_COOKIE_ATTRIBUTES
        )

    @field_validator("token_exposure")
    @classmethod
    def _valid_exposure(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TOKEN_EXPOSURE_STATES:
            raise ValueError(f"invalid token_exposure: {value!r}")
        return text

    @field_validator("authorization_boundary")
    @classmethod
    def _valid_boundary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_BOUNDARY_STATES:
            raise ValueError(f"invalid authorization_boundary: {value!r}")
        return text

    @field_validator("authentication_flow")
    @classmethod
    def _valid_flow(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHENTICATION_FLOW_STATES:
            raise ValueError(f"invalid authentication_flow: {value!r}")
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
            raise ValueError(
                "jwt/authentication context analyses are research-only"
            )
        return True


def jwt_authentication_context_analysis_plan_projection(
    value: JWTAuthenticationContextAnalysisPlan,
) -> dict:
    """Serialize an R47.2 context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "AUTH_MECH_NONE_OBSERVED",
    "AUTH_MECH_BEARER_TOKEN",
    "AUTH_MECH_JWT_BEARER",
    "AUTH_MECH_COOKIE_SESSION",
    "AUTH_MECH_OAUTH2",
    "AUTH_MECH_API_KEY",
    "AUTH_MECH_BASIC",
    "AUTH_MECH_MUTUAL_TLS",
    "AUTH_MECH_UNKNOWN",
    "AUTHENTICATION_MECHANISMS",
    "KNOWN_AUTHENTICATION_MECHANISMS",
    "TOKEN_MECH_NONE_OBSERVED",
    "TOKEN_MECH_JWT",
    "TOKEN_MECH_OPAQUE_ACCESS",
    "TOKEN_MECH_REFRESH",
    "TOKEN_MECH_SESSION_COOKIE",
    "TOKEN_MECH_UNKNOWN",
    "TOKEN_MECHANISMS",
    "JWT_TOKEN_MECHANISMS",
    "TOKEN_FORMAT_NONE_OBSERVED",
    "TOKEN_FORMAT_COMPACT_JWS",
    "TOKEN_FORMAT_COMPACT_JWE",
    "TOKEN_FORMAT_UNKNOWN",
    "TOKEN_FORMATS",
    "JWT_TOKEN_FORMATS",
    "ALG_NONE_OBSERVED",
    "ALG_HS256",
    "ALG_HS384",
    "ALG_HS512",
    "ALG_RS256",
    "ALG_RS384",
    "ALG_RS512",
    "ALG_ES256",
    "ALG_ES384",
    "ALG_ES512",
    "ALG_PS256",
    "ALG_PS384",
    "ALG_PS512",
    "ALG_NONE",
    "ALG_UNKNOWN",
    "SIGNING_ALGORITHMS",
    "HMAC_ALGORITHMS",
    "ASYMMETRIC_ALGORITHMS",
    "SIGNING_NONE_OBSERVED",
    "SIGNING_SYMMETRIC",
    "SIGNING_ASYMMETRIC",
    "SIGNING_UNKNOWN",
    "SIGNING_METHODS",
    "VALIDATION_ENFORCED_OBSERVED",
    "VALIDATION_ABSENT_OBSERVED",
    "VALIDATION_NOT_PROVIDED",
    "VALIDATION_UNKNOWN",
    "VALIDATION_STATES",
    "VALIDATION_CONTROL_PRESENT_STATES",
    "VALIDATION_CONTROL_ABSENT_STATES",
    "VALIDATION_MISSING_STATES",
    "KEY_MANAGEMENT_MANAGED_OBSERVED",
    "KEY_MANAGEMENT_STATIC_KEY_OBSERVED",
    "KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED",
    "KEY_MANAGEMENT_ABSENT_OBSERVED",
    "KEY_MANAGEMENT_NONE_OBSERVED",
    "KEY_MANAGEMENT_UNKNOWN",
    "KEY_MANAGEMENT_STATES",
    "KEY_ROTATION_CONFIGURED_OBSERVED",
    "KEY_ROTATION_NO_ROTATION_OBSERVED",
    "KEY_ROTATION_NONE_OBSERVED",
    "KEY_ROTATION_UNKNOWN",
    "KEY_ROTATION_STATES",
    "LIFETIME_SHORT_OBSERVED",
    "LIFETIME_LONG_OBSERVED",
    "LIFETIME_UNBOUNDED_OBSERVED",
    "LIFETIME_NONE_OBSERVED",
    "LIFETIME_UNKNOWN",
    "TOKEN_LIFETIME_STATES",
    "REFRESH_PRESENT",
    "REFRESH_ABSENT_OBSERVED",
    "REFRESH_NONE_OBSERVED",
    "REFRESH_UNKNOWN",
    "REFRESH_TOKEN_STATES",
    "SESSION_SERVER_SIDE_OBSERVED",
    "SESSION_CLIENT_SIDE_OBSERVED",
    "SESSION_STATELESS_TOKEN_OBSERVED",
    "SESSION_NONE_OBSERVED",
    "SESSION_UNKNOWN",
    "SESSION_LIFECYCLE_STATES",
    "STORAGE_SERVER_SIDE_OBSERVED",
    "STORAGE_MEMORY_ONLY_OBSERVED",
    "STORAGE_COOKIE_OBSERVED",
    "STORAGE_LOCAL_STORAGE_OBSERVED",
    "STORAGE_SESSION_STORAGE_OBSERVED",
    "STORAGE_NONE_OBSERVED",
    "STORAGE_UNKNOWN",
    "TOKEN_STORAGE_STATES",
    "CLIENT_STORAGE_STATES",
    "COOKIE_ATTR_SECURE",
    "COOKIE_ATTR_HTTP_ONLY",
    "COOKIE_ATTR_SAME_SITE_STRICT",
    "COOKIE_ATTR_SAME_SITE_LAX",
    "COOKIE_ATTR_SAME_SITE_NONE",
    "COOKIE_ATTRIBUTES",
    "SECURE_COOKIE_ATTRIBUTES",
    "SAME_SITE_SOFT_ATTRIBUTES",
    "EXPOSURE_NONE_OBSERVED",
    "EXPOSURE_URL_OBSERVED",
    "EXPOSURE_LOG_OBSERVED",
    "EXPOSURE_RESPONSE_BODY_OBSERVED",
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
    "FLOW_LOGIN_OBSERVED",
    "FLOW_TOKEN_OBSERVED",
    "FLOW_SESSION_OBSERVED",
    "FLOW_REFRESH_OBSERVED",
    "FLOW_NONE_OBSERVED",
    "FLOW_UNKNOWN",
    "AUTHENTICATION_FLOW_STATES",
    "MAX_COOKIE_ATTRIBUTES",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_jwt_authentication_context_analysis_plan",
    "JWTAuthenticationContextAnalysisPlan",
    "jwt_authentication_context_analysis_plan_projection",
]

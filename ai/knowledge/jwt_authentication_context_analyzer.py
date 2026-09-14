"""Stage R47.2 deterministic JWT/authentication context analyzer.

Classifies authentication/JWT-relevant research context from bounded
observations:

    "Which authentication, token, validation and control signals were
     supplied, and how complete is that context?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no DNS resolution, no
  socket, no browser, no database, no scanner, no token decoding or
  manipulation, no token forgery, no signature bypass, no authentication
  bypass, no brute force, no credential testing, no payload, no subprocess,
  no LLM. Nothing is performed.
- Technology presence is never vulnerability: JWT, bearer tokens, cookies,
  algorithm metadata and claim metadata are context only.
- Confidence means "how complete/relevant is the supplied authentication
  context?". It does NOT mean "probability that a vulnerability exists".
  No vulnerability is confirmed.
- Confidence is HIGH only with explicit structured evidence of an observed
  validation/control weakness inside an authentication context; technology
  metadata alone can never produce HIGH, and isolated lifetime, storage,
  exposure, key or authorization-boundary metadata without an authentication
  context is context only. MEDIUM requires explicit observed control
  evidence; otherwise LOW.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``/``NOT_PROVIDED``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.jwt_authentication_context_analysis import (
    ALG_NONE_OBSERVED,
    ALG_UNKNOWN,
    AUTH_MECH_NONE_OBSERVED,
    AUTH_MECH_UNKNOWN,
    AUTHORIZATION_BOUNDARY_STATES,
    AUTHENTICATION_FLOW_STATES,
    AUTHENTICATION_MECHANISMS,
    BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED,
    BOUNDARY_NONE_OBSERVED,
    BOUNDARY_SERVER_SIDE_OBSERVED,
    BOUNDARY_UNKNOWN,
    CLIENT_STORAGE_STATES,
    COOKIE_ATTR_HTTP_ONLY,
    COOKIE_ATTR_SECURE,
    COOKIE_ATTRIBUTES,
    EXPOSURE_NONE_OBSERVED,
    EXPOSURE_UNKNOWN,
    FLOW_NONE_OBSERVED,
    FLOW_UNKNOWN,
    JWT_TOKEN_FORMATS,
    JWT_TOKEN_MECHANISMS,
    KEY_MANAGEMENT_ABSENT_OBSERVED,
    KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED,
    KEY_MANAGEMENT_MANAGED_OBSERVED,
    KEY_MANAGEMENT_NONE_OBSERVED,
    KEY_MANAGEMENT_STATIC_KEY_OBSERVED,
    KEY_MANAGEMENT_STATES,
    KEY_MANAGEMENT_UNKNOWN,
    KEY_ROTATION_CONFIGURED_OBSERVED,
    KEY_ROTATION_NONE_OBSERVED,
    KEY_ROTATION_NO_ROTATION_OBSERVED,
    KEY_ROTATION_STATES,
    KEY_ROTATION_UNKNOWN,
    LIFETIME_LONG_OBSERVED,
    LIFETIME_NONE_OBSERVED,
    LIFETIME_UNBOUNDED_OBSERVED,
    LIFETIME_UNKNOWN,
    OBSERVED_EXPOSURE_STATES,
    REFRESH_NONE_OBSERVED,
    REFRESH_PRESENT,
    REFRESH_TOKEN_STATES,
    REFRESH_UNKNOWN,
    SESSION_CLIENT_SIDE_OBSERVED,
    SESSION_LIFECYCLE_STATES,
    SESSION_NONE_OBSERVED,
    SESSION_SERVER_SIDE_OBSERVED,
    SESSION_STATELESS_TOKEN_OBSERVED,
    SESSION_UNKNOWN,
    SIGNING_ALGORITHMS,
    SIGNING_METHODS,
    SIGNING_NONE_OBSERVED,
    SIGNING_UNKNOWN,
    STORAGE_COOKIE_OBSERVED,
    STORAGE_MEMORY_ONLY_OBSERVED,
    STORAGE_NONE_OBSERVED,
    STORAGE_SERVER_SIDE_OBSERVED,
    STORAGE_UNKNOWN,
    TOKEN_FORMAT_NONE_OBSERVED,
    TOKEN_FORMAT_UNKNOWN,
    TOKEN_FORMATS,
    TOKEN_LIFETIME_STATES,
    TOKEN_MECHANISMS,
    TOKEN_MECH_NONE_OBSERVED,
    TOKEN_MECH_UNKNOWN,
    TOKEN_STORAGE_STATES,
    TOKEN_EXPOSURE_STATES,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_CONTROL_PRESENT_STATES,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_STATES,
    VALIDATION_UNKNOWN,
    JWTAuthenticationContextAnalysisPlan,
    JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION,
    jwt_authentication_context_analysis_plan_projection,
    sanitize_jwt_authentication_context_analysis_plan,
)

JWT_AUTHENTICATION_CONTEXT_ANALYZER_RULE_VERSION = "r47-2"
RULE_VERSION = JWT_AUTHENTICATION_CONTEXT_ANALYZER_RULE_VERSION

VALIDATION_FIELDS: tuple[str, ...] = (
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

JWT_VALIDATION_FIELDS: tuple[str, ...] = (
    "signature_verification",
    "algorithm_validation",
    "issuer_validation",
    "audience_validation",
    "expiration_validation",
    "not_before_validation",
    "claim_validation",
)

KNOWN_FIELDS: tuple[str, ...] = (
    "authentication_mechanism",
    "token_mechanism",
    "token_format",
    "signing_algorithm",
    "signing_method",
) + VALIDATION_FIELDS + (
    "key_management",
    "key_rotation",
    "token_lifetime",
    "refresh_token",
    "session_lifecycle",
    "token_storage",
    "token_exposure",
    "authorization_boundary",
    "authentication_flow",
)

UNKNOWN_VALUES: tuple[str, ...] = (
    AUTH_MECH_UNKNOWN,
    AUTH_MECH_NONE_OBSERVED,
    TOKEN_MECH_UNKNOWN,
    TOKEN_MECH_NONE_OBSERVED,
    TOKEN_FORMAT_UNKNOWN,
    TOKEN_FORMAT_NONE_OBSERVED,
    ALG_UNKNOWN,
    ALG_NONE_OBSERVED,
    SIGNING_UNKNOWN,
    SIGNING_NONE_OBSERVED,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_UNKNOWN,
    KEY_MANAGEMENT_UNKNOWN,
    KEY_MANAGEMENT_NONE_OBSERVED,
    KEY_ROTATION_UNKNOWN,
    KEY_ROTATION_NONE_OBSERVED,
    LIFETIME_UNKNOWN,
    LIFETIME_NONE_OBSERVED,
    REFRESH_UNKNOWN,
    REFRESH_NONE_OBSERVED,
    SESSION_UNKNOWN,
    SESSION_NONE_OBSERVED,
    STORAGE_UNKNOWN,
    STORAGE_NONE_OBSERVED,
    EXPOSURE_UNKNOWN,
    EXPOSURE_NONE_OBSERVED,
    BOUNDARY_UNKNOWN,
    BOUNDARY_NONE_OBSERVED,
    FLOW_UNKNOWN,
    FLOW_NONE_OBSERVED,
)

KNOWN_SIGNING_ALGORITHMS: tuple[str, ...] = tuple(
    value for value in SIGNING_ALGORITHMS if value != ALG_UNKNOWN
)

KNOWN_SIGNING_METHODS: tuple[str, ...] = tuple(
    value for value in SIGNING_METHODS if value != SIGNING_UNKNOWN
)

KEY_MANAGEMENT_WEAK_STATES: tuple[str, ...] = (
    KEY_MANAGEMENT_STATIC_KEY_OBSERVED,
    KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED,
    KEY_MANAGEMENT_ABSENT_OBSERVED,
)

KEY_MANAGEMENT_CONTROL_STATES: tuple[str, ...] = (
    KEY_MANAGEMENT_MANAGED_OBSERVED,
)

LIFETIME_RISK_STATES: tuple[str, ...] = (
    LIFETIME_LONG_OBSERVED,
    LIFETIME_UNBOUNDED_OBSERVED,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _authentication_context_observed(
    mechanism: str,
    token_mechanism: str,
    token_format: str,
    algorithm: str,
    signing_method: str,
    authentication_control: str,
    authentication_flow: str,
    session_lifecycle: str,
) -> bool:
    """True when supplied facts describe an authentication context.

    A validation/control weakness can only be observed in relation to an
    authentication context. Isolated lifetime, storage, exposure, key or
    authorization-boundary metadata without any authentication mechanism is
    context only and can never be promoted to HIGH confidence.
    """

    return (
        mechanism not in (AUTH_MECH_UNKNOWN, AUTH_MECH_NONE_OBSERVED)
        or token_mechanism
        not in (TOKEN_MECH_UNKNOWN, TOKEN_MECH_NONE_OBSERVED)
        or token_format in JWT_TOKEN_FORMATS
        or algorithm not in (ALG_UNKNOWN, ALG_NONE_OBSERVED)
        or signing_method not in (SIGNING_UNKNOWN, SIGNING_NONE_OBSERVED)
        or authentication_control
        not in (VALIDATION_NOT_PROVIDED, VALIDATION_UNKNOWN)
        or authentication_flow not in (FLOW_UNKNOWN, FLOW_NONE_OBSERVED)
        or session_lifecycle not in (SESSION_UNKNOWN, SESSION_NONE_OBSERVED)
    )


def analyze_jwt_authentication_context(
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
) -> dict:
    """Build the deterministic descriptive JWT/authentication analysis.

    Confidence is a pure function of supplied facts: HIGH only when explicit
    structured evidence of an observed validation/control weakness is present
    inside an authentication context; MEDIUM when explicit observed control
    evidence is present; LOW when only technology/context metadata is present
    (including isolated risk metadata without an authentication context);
    UNKNOWN when nothing usable was supplied. No vulnerability is confirmed.
    """

    resolved_mechanism = _closed(
        authentication_mechanism,
        AUTHENTICATION_MECHANISMS,
        AUTH_MECH_UNKNOWN,
    )
    resolved_token_mechanism = _closed(
        token_mechanism, TOKEN_MECHANISMS, TOKEN_MECH_UNKNOWN
    )
    resolved_token_format = _closed(
        token_format, TOKEN_FORMATS, TOKEN_FORMAT_UNKNOWN
    )
    resolved_algorithm = _closed(
        signing_algorithm, SIGNING_ALGORITHMS, ALG_UNKNOWN
    )
    resolved_signing_method = _closed(
        signing_method, SIGNING_METHODS, SIGNING_UNKNOWN
    )
    resolved_signature = _closed(
        signature_verification, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_algorithm_validation = _closed(
        algorithm_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_issuer = _closed(
        issuer_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_audience = _closed(
        audience_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_expiration = _closed(
        expiration_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_not_before = _closed(
        not_before_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_claim = _closed(
        claim_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_key_management = _closed(
        key_management, KEY_MANAGEMENT_STATES, KEY_MANAGEMENT_UNKNOWN
    )
    resolved_key_rotation = _closed(
        key_rotation, KEY_ROTATION_STATES, KEY_ROTATION_UNKNOWN
    )
    resolved_lifetime = _closed(
        token_lifetime, TOKEN_LIFETIME_STATES, LIFETIME_UNKNOWN
    )
    resolved_refresh = _closed(
        refresh_token, REFRESH_TOKEN_STATES, REFRESH_UNKNOWN
    )
    resolved_refresh_control = _closed(
        refresh_control, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_revocation = _closed(
        revocation_control, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_session = _closed(
        session_lifecycle, SESSION_LIFECYCLE_STATES, SESSION_UNKNOWN
    )
    resolved_storage = _closed(
        token_storage, TOKEN_STORAGE_STATES, STORAGE_UNKNOWN
    )
    resolved_cookie_attributes: list[str] = []
    for item in cookie_attributes or ():
        text = _text(item).upper()
        if text in COOKIE_ATTRIBUTES and text not in resolved_cookie_attributes:
            resolved_cookie_attributes.append(text)
    resolved_exposure = _closed(
        token_exposure, TOKEN_EXPOSURE_STATES, EXPOSURE_UNKNOWN
    )
    resolved_boundary = _closed(
        authorization_boundary,
        AUTHORIZATION_BOUNDARY_STATES,
        BOUNDARY_UNKNOWN,
    )
    resolved_flow = _closed(
        authentication_flow, AUTHENTICATION_FLOW_STATES, FLOW_UNKNOWN
    )
    resolved_auth_control = _closed(
        authentication_control, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )

    validation_values = {
        "signature_verification": resolved_signature,
        "algorithm_validation": resolved_algorithm_validation,
        "issuer_validation": resolved_issuer,
        "audience_validation": resolved_audience,
        "expiration_validation": resolved_expiration,
        "not_before_validation": resolved_not_before,
        "claim_validation": resolved_claim,
        "refresh_control": resolved_refresh_control,
        "revocation_control": resolved_revocation,
        "authentication_control": resolved_auth_control,
    }

    scalars = (
        resolved_mechanism,
        resolved_token_mechanism,
        resolved_token_format,
        resolved_algorithm,
        resolved_signing_method,
        resolved_signature,
        resolved_algorithm_validation,
        resolved_issuer,
        resolved_audience,
        resolved_expiration,
        resolved_not_before,
        resolved_claim,
        resolved_key_management,
        resolved_key_rotation,
        resolved_lifetime,
        resolved_refresh,
        resolved_refresh_control,
        resolved_revocation,
        resolved_session,
        resolved_storage,
        resolved_exposure,
        resolved_boundary,
        resolved_flow,
        resolved_auth_control,
    )
    known_count = sum(
        1 for value in scalars if value not in UNKNOWN_VALUES
    )
    if resolved_cookie_attributes:
        known_count += 1

    cookie_security_incomplete = (
        resolved_storage == STORAGE_COOKIE_OBSERVED
        and bool(resolved_cookie_attributes)
        and (
            COOKIE_ATTR_SECURE not in resolved_cookie_attributes
            or COOKIE_ATTR_HTTP_ONLY not in resolved_cookie_attributes
        )
    )

    weakness_observed = _authentication_context_observed(
        resolved_mechanism,
        resolved_token_mechanism,
        resolved_token_format,
        resolved_algorithm,
        resolved_signing_method,
        resolved_auth_control,
        resolved_flow,
        resolved_session,
    ) and (
        any(
            value in VALIDATION_CONTROL_ABSENT_STATES
            for value in validation_values.values()
        )
        or resolved_key_management in KEY_MANAGEMENT_WEAK_STATES
        or resolved_key_rotation == KEY_ROTATION_NO_ROTATION_OBSERVED
        or resolved_lifetime in LIFETIME_RISK_STATES
        or resolved_storage in CLIENT_STORAGE_STATES
        or resolved_exposure in OBSERVED_EXPOSURE_STATES
        or resolved_session == SESSION_CLIENT_SIDE_OBSERVED
        or (
            resolved_session == SESSION_STATELESS_TOKEN_OBSERVED
            and resolved_revocation in VALIDATION_CONTROL_ABSENT_STATES
        )
        or resolved_boundary == BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED
        or (
            resolved_refresh == REFRESH_PRESENT
            and resolved_refresh_control in VALIDATION_CONTROL_ABSENT_STATES
        )
        or cookie_security_incomplete
    )

    control_observed = _authentication_context_observed(
        resolved_mechanism,
        resolved_token_mechanism,
        resolved_token_format,
        resolved_algorithm,
        resolved_signing_method,
        resolved_auth_control,
        resolved_flow,
        resolved_session,
    ) and (
        any(
            value in VALIDATION_CONTROL_PRESENT_STATES
            for value in validation_values.values()
        )
        or resolved_key_management in KEY_MANAGEMENT_CONTROL_STATES
        or resolved_key_rotation == KEY_ROTATION_CONFIGURED_OBSERVED
        or resolved_storage
        in (STORAGE_SERVER_SIDE_OBSERVED, STORAGE_MEMORY_ONLY_OBSERVED)
        or resolved_session == SESSION_SERVER_SIDE_OBSERVED
        or resolved_boundary == BOUNDARY_SERVER_SIDE_OBSERVED
        or (
            resolved_storage == STORAGE_COOKIE_OBSERVED
            and COOKIE_ATTR_SECURE in resolved_cookie_attributes
            and COOKIE_ATTR_HTTP_ONLY in resolved_cookie_attributes
        )
    )

    if known_count == 0:
        confidence = CONFIDENCE_UNKNOWN
    elif weakness_observed:
        confidence = CONFIDENCE_HIGH
    elif control_observed:
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW

    plan = JWTAuthenticationContextAnalysisPlan(
        rule_version=JWT_AUTHENTICATION_CONTEXT_ANALYSIS_RULE_VERSION,
        authentication_mechanism=resolved_mechanism,
        token_mechanism=resolved_token_mechanism,
        token_format=resolved_token_format,
        signing_algorithm=resolved_algorithm,
        signing_method=resolved_signing_method,
        signature_verification=resolved_signature,
        algorithm_validation=resolved_algorithm_validation,
        issuer_validation=resolved_issuer,
        audience_validation=resolved_audience,
        expiration_validation=resolved_expiration,
        not_before_validation=resolved_not_before,
        claim_validation=resolved_claim,
        key_management=resolved_key_management,
        key_rotation=resolved_key_rotation,
        token_lifetime=resolved_lifetime,
        refresh_token=resolved_refresh,
        refresh_control=resolved_refresh_control,
        revocation_control=resolved_revocation,
        session_lifecycle=resolved_session,
        token_storage=resolved_storage,
        cookie_attributes=resolved_cookie_attributes,
        token_exposure=resolved_exposure,
        authorization_boundary=resolved_boundary,
        authentication_flow=resolved_flow,
        authentication_control=resolved_auth_control,
        context_confidence=confidence,
        research_only=True,
    )
    return jwt_authentication_context_analysis_plan_projection(plan)


def jwt_authentication_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so partial
    context dicts supplied directly to downstream planners receive the
    correct, safety-capped confidence.
    """

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    values = [
        plan[key] for key in KNOWN_FIELDS
    ]
    known_count = sum(
        1 for value in values if value not in UNKNOWN_VALUES
    )
    if plan["cookie_attributes"]:
        known_count += 1

    validation_values = {
        key: plan[key] for key in VALIDATION_FIELDS
    }
    has_authentication_context = _authentication_context_observed(
        plan["authentication_mechanism"],
        plan["token_mechanism"],
        plan["token_format"],
        plan["signing_algorithm"],
        plan["signing_method"],
        plan["authentication_control"],
        plan["authentication_flow"],
        plan["session_lifecycle"],
    )
    weakness_observed = has_authentication_context and (
        any(
            value in VALIDATION_CONTROL_ABSENT_STATES
            for value in validation_values.values()
        )
        or plan["key_management"] in KEY_MANAGEMENT_WEAK_STATES
        or plan["key_rotation"] == KEY_ROTATION_NO_ROTATION_OBSERVED
        or plan["token_lifetime"] in LIFETIME_RISK_STATES
        or plan["token_storage"] in CLIENT_STORAGE_STATES
        or plan["token_exposure"] in OBSERVED_EXPOSURE_STATES
        or plan["session_lifecycle"] == SESSION_CLIENT_SIDE_OBSERVED
        or (
            plan["session_lifecycle"] == SESSION_STATELESS_TOKEN_OBSERVED
            and plan["revocation_control"]
            in VALIDATION_CONTROL_ABSENT_STATES
        )
        or plan["authorization_boundary"]
        == BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED
        or (
            plan["refresh_token"] == REFRESH_PRESENT
            and plan["refresh_control"]
            in VALIDATION_CONTROL_ABSENT_STATES
        )
        or (
            plan["token_storage"] == STORAGE_COOKIE_OBSERVED
            and bool(plan["cookie_attributes"])
            and (
                COOKIE_ATTR_SECURE not in plan["cookie_attributes"]
                or COOKIE_ATTR_HTTP_ONLY not in plan["cookie_attributes"]
            )
        )
    )
    control_observed = has_authentication_context and (
        any(
            value in VALIDATION_CONTROL_PRESENT_STATES
            for value in validation_values.values()
        )
        or plan["key_management"] in KEY_MANAGEMENT_CONTROL_STATES
        or plan["key_rotation"] == KEY_ROTATION_CONFIGURED_OBSERVED
        or plan["token_storage"]
        in (STORAGE_SERVER_SIDE_OBSERVED, STORAGE_MEMORY_ONLY_OBSERVED)
        or plan["session_lifecycle"] == SESSION_SERVER_SIDE_OBSERVED
        or plan["authorization_boundary"] == BOUNDARY_SERVER_SIDE_OBSERVED
        or (
            plan["token_storage"] == STORAGE_COOKIE_OBSERVED
            and COOKIE_ATTR_SECURE in plan["cookie_attributes"]
            and COOKIE_ATTR_HTTP_ONLY in plan["cookie_attributes"]
        )
    )

    if known_count == 0:
        return CONFIDENCE_UNKNOWN
    if weakness_observed:
        return CONFIDENCE_HIGH
    if control_observed:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def jwt_present(value: object) -> bool:
    """True when supplied context indicates JWT usage (context only)."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    return (
        plan["token_mechanism"] in JWT_TOKEN_MECHANISMS
        or plan["token_format"] in JWT_TOKEN_FORMATS
        or plan["signing_algorithm"] in KNOWN_SIGNING_ALGORITHMS
        or plan["signing_method"] in KNOWN_SIGNING_METHODS
    )


def token_present(value: object) -> bool:
    """True when supplied context indicates token-based authentication."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    return (
        jwt_present(plan)
        or plan["token_mechanism"] not in UNKNOWN_VALUES
        or plan["authentication_mechanism"]
        in (
            "BEARER_TOKEN",
            "JWT_BEARER",
            "OAUTH2",
            "API_KEY",
        )
    )


def authentication_context_present(value: object) -> bool:
    """True when any usable authentication context was supplied."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    if (
        plan["authentication_mechanism"] not in UNKNOWN_VALUES
        or plan["token_mechanism"] not in UNKNOWN_VALUES
    ):
        return True
    return jwt_authentication_context_confidence_of(plan) != (
        CONFIDENCE_UNKNOWN
    )


def validation_state_of(value: object, field: object) -> str:
    """Return the bounded validation state of a validation field."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    key = _text(field)
    if key not in VALIDATION_FIELDS:
        return VALIDATION_UNKNOWN
    return plan[key]


def weakness_observed(value: object) -> bool:
    """True only when explicit structured weakness evidence was supplied."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    if jwt_authentication_context_confidence_of(plan) == CONFIDENCE_HIGH:
        return True
    return False


def control_observed(value: object) -> bool:
    """True only when explicit structured control evidence was supplied."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    confidence = jwt_authentication_context_confidence_of(plan)
    return confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)


def cookie_security_incomplete(value: object) -> bool:
    """True when cookie storage was supplied without Secure/HttpOnly."""

    plan = sanitize_jwt_authentication_context_analysis_plan(value)
    return (
        plan["token_storage"] == STORAGE_COOKIE_OBSERVED
        and bool(plan["cookie_attributes"])
        and (
            COOKIE_ATTR_SECURE not in plan["cookie_attributes"]
            or COOKIE_ATTR_HTTP_ONLY not in plan["cookie_attributes"]
        )
    )


__all__ = [
    "JWT_AUTHENTICATION_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_FIELDS",
    "JWT_VALIDATION_FIELDS",
    "KNOWN_FIELDS",
    "UNKNOWN_VALUES",
    "KNOWN_SIGNING_ALGORITHMS",
    "KNOWN_SIGNING_METHODS",
    "KEY_MANAGEMENT_WEAK_STATES",
    "KEY_MANAGEMENT_CONTROL_STATES",
    "LIFETIME_RISK_STATES",
    "analyze_jwt_authentication_context",
    "jwt_authentication_context_confidence_of",
    "jwt_present",
    "token_present",
    "authentication_context_present",
    "validation_state_of",
    "weakness_observed",
    "control_observed",
    "cookie_security_incomplete",
]

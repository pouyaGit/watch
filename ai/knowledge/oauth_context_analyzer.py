"""Stage R48.2 deterministic OAuth context analyzer.

Classifies OAuth-relevant research context from bounded observations:

    "Which OAuth version, flow, actor, request, control, client and
     security-context signals were supplied, and how complete is that
     context?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no OAuth
  authorization/token/callback request, no redirect following, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or exchange, no state/nonce/PKCE manipulation, no payload, no
  subprocess, no LLM. Nothing is performed.
- Technology presence is never vulnerability: OAuth, flows, redirect_uri,
  state, nonce, PKCE, scopes, client ids, authorization codes and refresh
  tokens are context only.
- Confidence means "how complete/relevant is the supplied OAuth context?".
  It does NOT mean "probability that a vulnerability exists". No
  vulnerability is confirmed.
- Confidence is HIGH only with explicit structured evidence of an observed
  validation/control weakness inside an OAuth context; technology metadata
  alone can never produce HIGH, and isolated exposure/session/boundary
  metadata without an OAuth context is context only. MEDIUM requires
  explicit observed control evidence; otherwise LOW.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``/
  ``NOT_PROVIDED``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.oauth_context_analysis import (
    AUTHORIZATION_BOUNDARY_STATES,
    AUTHORIZATION_CODE_LIFETIME_STATES,
    BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED,
    BOUNDARY_NONE_OBSERVED,
    BOUNDARY_SERVER_SIDE_OBSERVED,
    BOUNDARY_UNKNOWN,
    CLIENT_SECRET_NONE_OBSERVED,
    CLIENT_SECRET_REQUIRED_OBSERVED,
    CLIENT_SECRET_UNKNOWN,
    CLIENT_SECRET_USAGE_STATES,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_NONE_OBSERVED,
    CLIENT_TYPE_PUBLIC,
    CLIENT_TYPE_UNKNOWN,
    CLIENT_TYPES,
    CODE_LIFETIME_NONE_OBSERVED,
    CODE_LIFETIME_RISK_STATES,
    CODE_LIFETIME_UNKNOWN,
    CONTEXT_OBSERVATIONS,
    CONTEXT_UNKNOWN,
    EXPOSURE_NONE_OBSERVED,
    EXPOSURE_UNKNOWN,
    FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_CLIENT_CREDENTIALS,
    FLOW_DEVICE_AUTHORIZATION,
    FLOW_HYBRID,
    FLOW_IMPLICIT,
    FLOW_NONE_OBSERVED,
    FLOW_REFRESH_TOKEN,
    FLOW_UNKNOWN,
    GRANT_AUTHORIZATION_CODE,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_DEVICE_CODE,
    GRANT_IMPLICIT,
    GRANT_NONE_OBSERVED,
    GRANT_REFRESH_TOKEN,
    GRANT_TYPES,
    GRANT_UNKNOWN,
    INTERACTIVE_OAUTH_FLOWS,
    KNOWN_CLIENT_TYPES,
    KNOWN_GRANT_TYPES,
    KNOWN_OAUTH_FLOWS,
    KNOWN_OAUTH_VERSIONS,
    NONE_OBSERVED,
    OBSERVED,
    OBSERVED_EXPOSURE_STATES,
    OAUTH_FLOWS,
    OAUTH_VERSION_NONE_OBSERVED,
    OAUTH_VERSION_UNKNOWN,
    OAUTH_VERSIONS,
    REDIRECT_REGISTRATION_EXACT,
    REDIRECT_REGISTRATION_NONE_OBSERVED,
    REDIRECT_REGISTRATION_UNKNOWN,
    REDIRECT_REGISTRATION_WILDCARD,
    REDIRECT_URI_REGISTRATION_STATES,
    RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_CODE_ID_TOKEN,
    RESPONSE_TYPE_ID_TOKEN,
    RESPONSE_TYPE_NONE_OBSERVED,
    RESPONSE_TYPE_TOKEN,
    RESPONSE_TYPE_UNKNOWN,
    RESPONSE_TYPES,
    SESSION_CLIENT_SIDE_OBSERVED,
    SESSION_INTEGRATION_STATES,
    SESSION_NONE_OBSERVED,
    SESSION_SERVER_SIDE_OBSERVED,
    SESSION_STATELESS_TOKEN_OBSERVED,
    SESSION_UNKNOWN,
    TOKEN_AUTH_NONE_OBSERVED,
    TOKEN_AUTH_UNKNOWN,
    TOKEN_ENDPOINT_AUTH_METHODS,
    TOKEN_EXPOSURE_STATES,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_CONTROL_PRESENT_STATES,
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_MISSING_STATES,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_STATES,
    VALIDATION_UNKNOWN,
    OAuthContextAnalysisPlan,
    OAUTH_CONTEXT_ANALYSIS_RULE_VERSION,
    oauth_context_analysis_plan_projection,
    sanitize_oauth_context_analysis_plan,
)

OAUTH_CONTEXT_ANALYZER_RULE_VERSION = "r48-2"
RULE_VERSION = OAUTH_CONTEXT_ANALYZER_RULE_VERSION

VALIDATION_FIELDS: tuple[str, ...] = (
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

FLOW_CONTROL_FIELDS: tuple[str, ...] = (
    "redirect_uri_validation",
    "exact_redirect_matching",
    "state_validation",
    "state_binding",
    "nonce_validation",
    "pkce_enforcement",
    "pkce_verifier_validation",
    "authorization_code_binding",
    "code_reuse_control",
    "csrf_protection",
    "login_csrf_protection",
    "redirect_handling",
)

KNOWN_FIELDS: tuple[str, ...] = (
    "oauth_version",
    "flow",
    "client_type",
    "authorization_server_context",
    "resource_server_context",
    "authorization_endpoint",
    "token_endpoint",
    "redirect_uri",
    "client_id",
    "response_type",
    "grant_type",
    "scope_context",
    "state_parameter",
    "nonce_parameter",
    "pkce_challenge",
) + VALIDATION_FIELDS + (
    "redirect_uri_registration",
    "authorization_code_lifetime",
    "token_endpoint_auth_method",
    "client_secret_usage",
    "refresh_token_present",
    "authorization_boundary",
    "session_integration",
    "token_exposure",
)

UNKNOWN_VALUES: tuple[str, ...] = (
    OAUTH_VERSION_UNKNOWN,
    OAUTH_VERSION_NONE_OBSERVED,
    FLOW_UNKNOWN,
    FLOW_NONE_OBSERVED,
    CLIENT_TYPE_UNKNOWN,
    CLIENT_TYPE_NONE_OBSERVED,
    CONTEXT_UNKNOWN,
    NONE_OBSERVED,
    RESPONSE_TYPE_UNKNOWN,
    RESPONSE_TYPE_NONE_OBSERVED,
    GRANT_UNKNOWN,
    GRANT_NONE_OBSERVED,
    VALIDATION_NOT_PROVIDED,
    VALIDATION_UNKNOWN,
    REDIRECT_REGISTRATION_UNKNOWN,
    REDIRECT_REGISTRATION_NONE_OBSERVED,
    CODE_LIFETIME_UNKNOWN,
    CODE_LIFETIME_NONE_OBSERVED,
    TOKEN_AUTH_UNKNOWN,
    TOKEN_AUTH_NONE_OBSERVED,
    CLIENT_SECRET_UNKNOWN,
    CLIENT_SECRET_NONE_OBSERVED,
    EXPOSURE_UNKNOWN,
    EXPOSURE_NONE_OBSERVED,
    BOUNDARY_UNKNOWN,
    BOUNDARY_NONE_OBSERVED,
    SESSION_UNKNOWN,
    SESSION_NONE_OBSERVED,
)

KNOWN_RESPONSE_TYPES: tuple[str, ...] = (
    RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_TOKEN,
    RESPONSE_TYPE_ID_TOKEN,
    RESPONSE_TYPE_CODE_ID_TOKEN,
)

KNOWN_TOKEN_AUTH_METHODS: tuple[str, ...] = tuple(
    value
    for value in TOKEN_ENDPOINT_AUTH_METHODS
    if value not in (TOKEN_AUTH_NONE_OBSERVED, TOKEN_AUTH_UNKNOWN)
)

CLIENT_SECRET_PRESENT_STATES: tuple[str, ...] = (
    CLIENT_SECRET_REQUIRED_OBSERVED,
)

WEAK_CLIENT_SECRET_STATES: tuple[str, ...] = (
    CLIENT_SECRET_REQUIRED_OBSERVED,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _oauth_context_observed(
    oauth_version: str,
    flow: str,
    client_type: str,
    authorization_server_context: str,
    resource_server_context: str,
    authorization_endpoint: str,
    token_endpoint: str,
    redirect_uri: str,
    client_id: str,
    response_type: str,
    grant_type: str,
    scope_context: str,
    state_parameter: str,
    nonce_parameter: str,
    pkce_challenge: str,
    redirect_uri_registration: str,
    token_endpoint_auth_method: str,
    client_secret_usage: str,
    refresh_token_present: str,
) -> bool:
    """True when supplied facts describe an OAuth protocol context.

    A validation/control weakness can only be observed in relation to an
    OAuth context. Isolated session, boundary or exposure metadata without
    any OAuth protocol context is context only and can never be promoted
    to HIGH confidence.
    """

    return (
        oauth_version in KNOWN_OAUTH_VERSIONS
        or flow in KNOWN_OAUTH_FLOWS
        or client_type in KNOWN_CLIENT_TYPES
        or authorization_server_context == OBSERVED
        or resource_server_context == OBSERVED
        or authorization_endpoint == OBSERVED
        or token_endpoint == OBSERVED
        or redirect_uri == OBSERVED
        or client_id == OBSERVED
        or response_type in KNOWN_RESPONSE_TYPES
        or grant_type in KNOWN_GRANT_TYPES
        or scope_context == OBSERVED
        or state_parameter == OBSERVED
        or nonce_parameter == OBSERVED
        or pkce_challenge == OBSERVED
        or redirect_uri_registration
        in (REDIRECT_REGISTRATION_EXACT, REDIRECT_REGISTRATION_WILDCARD)
        or token_endpoint_auth_method in KNOWN_TOKEN_AUTH_METHODS
        or client_secret_usage in CLIENT_SECRET_USAGE_STATES[:2]
        or refresh_token_present == OBSERVED
    )


def analyze_oauth_context(
    oauth_version: object = None,
    flow: object = None,
    client_type: object = None,
    authorization_server_context: object = None,
    resource_server_context: object = None,
    authorization_endpoint: object = None,
    token_endpoint: object = None,
    redirect_uri: object = None,
    client_id: object = None,
    response_type: object = None,
    grant_type: object = None,
    scope_context: object = None,
    state_parameter: object = None,
    nonce_parameter: object = None,
    pkce_challenge: object = None,
    redirect_uri_validation: object = None,
    exact_redirect_matching: object = None,
    redirect_uri_registration: object = None,
    state_validation: object = None,
    state_binding: object = None,
    nonce_validation: object = None,
    pkce_enforcement: object = None,
    pkce_verifier_validation: object = None,
    authorization_code_binding: object = None,
    authorization_code_lifetime: object = None,
    code_reuse_control: object = None,
    client_authentication: object = None,
    token_endpoint_auth_method: object = None,
    client_secret_usage: object = None,
    scope_validation: object = None,
    resource_audience_validation: object = None,
    issuer_validation: object = None,
    token_validation: object = None,
    refresh_token_present: object = None,
    refresh_token_rotation: object = None,
    refresh_token_revocation: object = None,
    consent_control: object = None,
    csrf_protection: object = None,
    login_csrf_protection: object = None,
    redirect_handling: object = None,
    authorization_boundary: object = None,
    session_integration: object = None,
    token_exposure: object = None,
) -> dict:
    """Build the deterministic descriptive OAuth analysis.

    Confidence is a pure function of supplied facts: HIGH only when
    explicit structured evidence of an observed validation/control
    weakness is present inside an OAuth context; MEDIUM when explicit
    observed control evidence is present; LOW when only technology/context
    metadata is present (including isolated risk metadata without an OAuth
    context); UNKNOWN when nothing usable was supplied. No vulnerability
    is confirmed.
    """

    resolved_version = _closed(
        oauth_version, OAUTH_VERSIONS, OAUTH_VERSION_UNKNOWN
    )
    resolved_flow = _closed(flow, OAUTH_FLOWS, FLOW_UNKNOWN)
    resolved_client_type = _closed(
        client_type, CLIENT_TYPES, CLIENT_TYPE_UNKNOWN
    )
    resolved_authz_server = _closed(
        authorization_server_context,
        CONTEXT_OBSERVATIONS,
        CONTEXT_UNKNOWN,
    )
    resolved_resource_server = _closed(
        resource_server_context,
        CONTEXT_OBSERVATIONS,
        CONTEXT_UNKNOWN,
    )
    resolved_authz_endpoint = _closed(
        authorization_endpoint, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_token_endpoint = _closed(
        token_endpoint, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_redirect_uri = _closed(
        redirect_uri, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_client_id = _closed(
        client_id, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_response_type = _closed(
        response_type, RESPONSE_TYPES, RESPONSE_TYPE_UNKNOWN
    )
    resolved_grant_type = _closed(grant_type, GRANT_TYPES, GRANT_UNKNOWN)
    resolved_scope = _closed(
        scope_context, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_state_param = _closed(
        state_parameter, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_nonce_param = _closed(
        nonce_parameter, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_pkce_challenge = _closed(
        pkce_challenge, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_redirect_validation = _closed(
        redirect_uri_validation,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_exact_matching = _closed(
        exact_redirect_matching,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_registration = _closed(
        redirect_uri_registration,
        REDIRECT_URI_REGISTRATION_STATES,
        REDIRECT_REGISTRATION_UNKNOWN,
    )
    resolved_state_validation = _closed(
        state_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_state_binding = _closed(
        state_binding, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_nonce_validation = _closed(
        nonce_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_pkce_enforcement = _closed(
        pkce_enforcement, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_pkce_verifier = _closed(
        pkce_verifier_validation,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_code_binding = _closed(
        authorization_code_binding,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_code_lifetime = _closed(
        authorization_code_lifetime,
        AUTHORIZATION_CODE_LIFETIME_STATES,
        CODE_LIFETIME_UNKNOWN,
    )
    resolved_code_reuse = _closed(
        code_reuse_control, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_client_auth = _closed(
        client_authentication, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_token_auth_method = _closed(
        token_endpoint_auth_method,
        TOKEN_ENDPOINT_AUTH_METHODS,
        TOKEN_AUTH_UNKNOWN,
    )
    resolved_client_secret = _closed(
        client_secret_usage,
        CLIENT_SECRET_USAGE_STATES,
        CLIENT_SECRET_UNKNOWN,
    )
    resolved_scope_validation = _closed(
        scope_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_resource_audience = _closed(
        resource_audience_validation,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_issuer_validation = _closed(
        issuer_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_token_validation = _closed(
        token_validation, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_refresh_present = _closed(
        refresh_token_present, CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
    )
    resolved_refresh_rotation = _closed(
        refresh_token_rotation,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_refresh_revocation = _closed(
        refresh_token_revocation,
        VALIDATION_STATES,
        VALIDATION_NOT_PROVIDED,
    )
    resolved_consent = _closed(
        consent_control, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_csrf = _closed(
        csrf_protection, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_login_csrf = _closed(
        login_csrf_protection, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_redirect_handling = _closed(
        redirect_handling, VALIDATION_STATES, VALIDATION_NOT_PROVIDED
    )
    resolved_boundary = _closed(
        authorization_boundary,
        AUTHORIZATION_BOUNDARY_STATES,
        BOUNDARY_UNKNOWN,
    )
    resolved_session = _closed(
        session_integration,
        SESSION_INTEGRATION_STATES,
        SESSION_UNKNOWN,
    )
    resolved_exposure = _closed(
        token_exposure, TOKEN_EXPOSURE_STATES, EXPOSURE_UNKNOWN
    )

    validation_values = {
        "redirect_uri_validation": resolved_redirect_validation,
        "exact_redirect_matching": resolved_exact_matching,
        "state_validation": resolved_state_validation,
        "state_binding": resolved_state_binding,
        "nonce_validation": resolved_nonce_validation,
        "pkce_enforcement": resolved_pkce_enforcement,
        "pkce_verifier_validation": resolved_pkce_verifier,
        "authorization_code_binding": resolved_code_binding,
        "code_reuse_control": resolved_code_reuse,
        "client_authentication": resolved_client_auth,
        "scope_validation": resolved_scope_validation,
        "resource_audience_validation": resolved_resource_audience,
        "issuer_validation": resolved_issuer_validation,
        "token_validation": resolved_token_validation,
        "refresh_token_rotation": resolved_refresh_rotation,
        "refresh_token_revocation": resolved_refresh_revocation,
        "consent_control": resolved_consent,
        "csrf_protection": resolved_csrf,
        "login_csrf_protection": resolved_login_csrf,
        "redirect_handling": resolved_redirect_handling,
    }

    scalars = (
        resolved_version,
        resolved_flow,
        resolved_client_type,
        resolved_authz_server,
        resolved_resource_server,
        resolved_authz_endpoint,
        resolved_token_endpoint,
        resolved_redirect_uri,
        resolved_client_id,
        resolved_response_type,
        resolved_grant_type,
        resolved_scope,
        resolved_state_param,
        resolved_nonce_param,
        resolved_pkce_challenge,
        resolved_redirect_validation,
        resolved_exact_matching,
        resolved_registration,
        resolved_state_validation,
        resolved_state_binding,
        resolved_nonce_validation,
        resolved_pkce_enforcement,
        resolved_pkce_verifier,
        resolved_code_binding,
        resolved_code_lifetime,
        resolved_code_reuse,
        resolved_client_auth,
        resolved_token_auth_method,
        resolved_client_secret,
        resolved_scope_validation,
        resolved_resource_audience,
        resolved_issuer_validation,
        resolved_token_validation,
        resolved_refresh_present,
        resolved_refresh_rotation,
        resolved_refresh_revocation,
        resolved_consent,
        resolved_csrf,
        resolved_login_csrf,
        resolved_redirect_handling,
        resolved_boundary,
        resolved_session,
        resolved_exposure,
    )
    known_count = sum(
        1 for value in scalars if value not in UNKNOWN_VALUES
    )

    has_oauth_context = _oauth_context_observed(
        resolved_version,
        resolved_flow,
        resolved_client_type,
        resolved_authz_server,
        resolved_resource_server,
        resolved_authz_endpoint,
        resolved_token_endpoint,
        resolved_redirect_uri,
        resolved_client_id,
        resolved_response_type,
        resolved_grant_type,
        resolved_scope,
        resolved_state_param,
        resolved_nonce_param,
        resolved_pkce_challenge,
        resolved_registration,
        resolved_token_auth_method,
        resolved_client_secret,
        resolved_refresh_present,
    )

    weakness_observed = has_oauth_context and (
        any(
            value in VALIDATION_CONTROL_ABSENT_STATES
            for value in validation_values.values()
        )
        or resolved_registration == REDIRECT_REGISTRATION_WILDCARD
        or resolved_code_lifetime in CODE_LIFETIME_RISK_STATES
        or resolved_exposure in OBSERVED_EXPOSURE_STATES
        or resolved_boundary == BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED
        or resolved_session
        in (
            SESSION_CLIENT_SIDE_OBSERVED,
            SESSION_STATELESS_TOKEN_OBSERVED,
        )
    )

    control_observed = has_oauth_context and (
        any(
            value in VALIDATION_CONTROL_PRESENT_STATES
            for value in validation_values.values()
        )
        or resolved_registration == REDIRECT_REGISTRATION_EXACT
        or resolved_client_secret in CLIENT_SECRET_PRESENT_STATES
        or resolved_boundary == BOUNDARY_SERVER_SIDE_OBSERVED
        or resolved_session == SESSION_SERVER_SIDE_OBSERVED
    )

    if known_count == 0:
        confidence = CONFIDENCE_UNKNOWN
    elif weakness_observed:
        confidence = CONFIDENCE_HIGH
    elif control_observed:
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW

    plan = OAuthContextAnalysisPlan(
        rule_version=OAUTH_CONTEXT_ANALYSIS_RULE_VERSION,
        oauth_version=resolved_version,
        flow=resolved_flow,
        client_type=resolved_client_type,
        authorization_server_context=resolved_authz_server,
        resource_server_context=resolved_resource_server,
        authorization_endpoint=resolved_authz_endpoint,
        token_endpoint=resolved_token_endpoint,
        redirect_uri=resolved_redirect_uri,
        client_id=resolved_client_id,
        response_type=resolved_response_type,
        grant_type=resolved_grant_type,
        scope_context=resolved_scope,
        state_parameter=resolved_state_param,
        nonce_parameter=resolved_nonce_param,
        pkce_challenge=resolved_pkce_challenge,
        redirect_uri_validation=resolved_redirect_validation,
        exact_redirect_matching=resolved_exact_matching,
        redirect_uri_registration=resolved_registration,
        state_validation=resolved_state_validation,
        state_binding=resolved_state_binding,
        nonce_validation=resolved_nonce_validation,
        pkce_enforcement=resolved_pkce_enforcement,
        pkce_verifier_validation=resolved_pkce_verifier,
        authorization_code_binding=resolved_code_binding,
        authorization_code_lifetime=resolved_code_lifetime,
        code_reuse_control=resolved_code_reuse,
        client_authentication=resolved_client_auth,
        token_endpoint_auth_method=resolved_token_auth_method,
        client_secret_usage=resolved_client_secret,
        scope_validation=resolved_scope_validation,
        resource_audience_validation=resolved_resource_audience,
        issuer_validation=resolved_issuer_validation,
        token_validation=resolved_token_validation,
        refresh_token_present=resolved_refresh_present,
        refresh_token_rotation=resolved_refresh_rotation,
        refresh_token_revocation=resolved_refresh_revocation,
        consent_control=resolved_consent,
        csrf_protection=resolved_csrf,
        login_csrf_protection=resolved_login_csrf,
        redirect_handling=resolved_redirect_handling,
        authorization_boundary=resolved_boundary,
        session_integration=resolved_session,
        token_exposure=resolved_exposure,
        context_confidence=confidence,
        research_only=True,
    )
    return oauth_context_analysis_plan_projection(plan)


def oauth_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so
    partial context dicts supplied directly to downstream planners receive
    the correct, safety-capped confidence.
    """

    plan = sanitize_oauth_context_analysis_plan(value)
    values = [plan[key] for key in KNOWN_FIELDS]
    known_count = sum(
        1 for value in values if value not in UNKNOWN_VALUES
    )

    validation_values = {
        key: plan[key] for key in VALIDATION_FIELDS
    }
    has_oauth_context = _oauth_context_observed(
        plan["oauth_version"],
        plan["flow"],
        plan["client_type"],
        plan["authorization_server_context"],
        plan["resource_server_context"],
        plan["authorization_endpoint"],
        plan["token_endpoint"],
        plan["redirect_uri"],
        plan["client_id"],
        plan["response_type"],
        plan["grant_type"],
        plan["scope_context"],
        plan["state_parameter"],
        plan["nonce_parameter"],
        plan["pkce_challenge"],
        plan["redirect_uri_registration"],
        plan["token_endpoint_auth_method"],
        plan["client_secret_usage"],
        plan["refresh_token_present"],
    )
    weakness_observed = has_oauth_context and (
        any(
            value in VALIDATION_CONTROL_ABSENT_STATES
            for value in validation_values.values()
        )
        or plan["redirect_uri_registration"]
        == REDIRECT_REGISTRATION_WILDCARD
        or plan["authorization_code_lifetime"] in CODE_LIFETIME_RISK_STATES
        or plan["token_exposure"] in OBSERVED_EXPOSURE_STATES
        or plan["authorization_boundary"]
        == BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED
        or plan["session_integration"]
        in (
            SESSION_CLIENT_SIDE_OBSERVED,
            SESSION_STATELESS_TOKEN_OBSERVED,
        )
    )
    control_observed = has_oauth_context and (
        any(
            value in VALIDATION_CONTROL_PRESENT_STATES
            for value in validation_values.values()
        )
        or plan["redirect_uri_registration"] == REDIRECT_REGISTRATION_EXACT
        or plan["client_secret_usage"] in CLIENT_SECRET_PRESENT_STATES
        or plan["authorization_boundary"] == BOUNDARY_SERVER_SIDE_OBSERVED
        or plan["session_integration"] == SESSION_SERVER_SIDE_OBSERVED
    )

    if known_count == 0:
        return CONFIDENCE_UNKNOWN
    if weakness_observed:
        return CONFIDENCE_HIGH
    if control_observed:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def oauth_context_present(value: object) -> bool:
    """True when supplied context indicates an OAuth protocol context."""

    plan = sanitize_oauth_context_analysis_plan(value)
    return _oauth_context_observed(
        plan["oauth_version"],
        plan["flow"],
        plan["client_type"],
        plan["authorization_server_context"],
        plan["resource_server_context"],
        plan["authorization_endpoint"],
        plan["token_endpoint"],
        plan["redirect_uri"],
        plan["client_id"],
        plan["response_type"],
        plan["grant_type"],
        plan["scope_context"],
        plan["state_parameter"],
        plan["nonce_parameter"],
        plan["pkce_challenge"],
        plan["redirect_uri_registration"],
        plan["token_endpoint_auth_method"],
        plan["client_secret_usage"],
        plan["refresh_token_present"],
    )


def interactive_flow_present(value: object) -> bool:
    """True when an interactive authorization flow was supplied."""

    plan = sanitize_oauth_context_analysis_plan(value)
    return plan["flow"] in INTERACTIVE_OAUTH_FLOWS


def token_flow_present(value: object) -> bool:
    """True when a token-issuing/using OAuth flow was supplied."""

    plan = sanitize_oauth_context_analysis_plan(value)
    return (
        plan["flow"]
        in (
            FLOW_AUTHORIZATION_CODE,
            FLOW_AUTHORIZATION_CODE_PKCE,
            FLOW_CLIENT_CREDENTIALS,
            FLOW_DEVICE_AUTHORIZATION,
            FLOW_REFRESH_TOKEN,
            FLOW_HYBRID,
        )
        or plan["token_endpoint"] == OBSERVED
        or plan["grant_type"]
        in (
            GRANT_AUTHORIZATION_CODE,
            GRANT_CLIENT_CREDENTIALS,
            GRANT_REFRESH_TOKEN,
            GRANT_DEVICE_CODE,
            GRANT_IMPLICIT,
        )
    )


def authorization_code_flow_present(value: object) -> bool:
    """True when an authorization-code based flow was supplied."""

    plan = sanitize_oauth_context_analysis_plan(value)
    return (
        plan["flow"]
        in (FLOW_AUTHORIZATION_CODE, FLOW_AUTHORIZATION_CODE_PKCE)
        or plan["grant_type"] == GRANT_AUTHORIZATION_CODE
        or plan["response_type"]
        in (RESPONSE_TYPE_CODE, RESPONSE_TYPE_CODE_ID_TOKEN)
    )


def pkce_context_present(value: object) -> bool:
    """True when PKCE is relevant to the supplied OAuth context."""

    plan = sanitize_oauth_context_analysis_plan(value)
    return (
        plan["flow"] == FLOW_AUTHORIZATION_CODE_PKCE
        or plan["client_type"] == CLIENT_TYPE_PUBLIC
        or plan["pkce_challenge"] == OBSERVED
    )


def validation_state_of(value: object, field: object) -> str:
    """Return the bounded validation state of a validation field."""

    plan = sanitize_oauth_context_analysis_plan(value)
    key = _text(field)
    if key not in VALIDATION_FIELDS:
        return VALIDATION_UNKNOWN
    return plan[key]


def weakness_observed(value: object) -> bool:
    """True only when explicit structured weakness evidence was supplied."""

    plan = sanitize_oauth_context_analysis_plan(value)
    if oauth_context_confidence_of(plan) == CONFIDENCE_HIGH:
        return True
    return False


def control_observed(value: object) -> bool:
    """True only when explicit structured control evidence was supplied."""

    plan = sanitize_oauth_context_analysis_plan(value)
    confidence = oauth_context_confidence_of(plan)
    return confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)


__all__ = [
    "OAUTH_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_FIELDS",
    "FLOW_CONTROL_FIELDS",
    "KNOWN_FIELDS",
    "UNKNOWN_VALUES",
    "KNOWN_RESPONSE_TYPES",
    "KNOWN_TOKEN_AUTH_METHODS",
    "CLIENT_SECRET_PRESENT_STATES",
    "WEAK_CLIENT_SECRET_STATES",
    "analyze_oauth_context",
    "oauth_context_confidence_of",
    "oauth_context_present",
    "interactive_flow_present",
    "token_flow_present",
    "authorization_code_flow_present",
    "pkce_context_present",
    "validation_state_of",
    "weakness_observed",
    "control_observed",
]

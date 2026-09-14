"""Stage R48.3 deterministic OAuth hypothesis planner.

Creates deterministic research hypotheses from supplied OAuth context:

    "Which OAuth protocol/authorization-flow review hypothesis follows
     from the supplied context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability
  confirmation, no OAuth bypass, no redirect_uri exploitation, no CSRF
  exploitation, no token exchange, no token replay, no credential
  testing, no payload, no executable request, no attack sequence, no
  network/database execution.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, state, signals,
  confidence, priority, rationale and limitations are pure functions of
  the bounded context.
- Technology presence is never weakness: OAuth, flows, redirect_uri,
  state, nonce, PKCE, scopes, client ids, authorization codes and refresh
  tokens alone never produce a gap hypothesis.
- Present controls are distinguished from possible gaps; missing
  information produces ``NEEDS_EVIDENCE`` research items, never
  vulnerability claims.
- Priority is research usefulness only (never severity, exploitability,
  CVSS or vulnerability probability).
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.oauth_context_analyzer import (
    CLIENT_SECRET_PRESENT_STATES,
    KNOWN_FIELDS,
    UNKNOWN_VALUES,
    authorization_code_flow_present,
    interactive_flow_present,
    oauth_context_present,
    pkce_context_present,
    token_flow_present,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.oauth_context_analysis import (
    BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED,
    BOUNDARY_MIXED_OBSERVED,
    BOUNDARY_SERVER_SIDE_OBSERVED,
    CLIENT_SECRET_NOT_REQUIRED_OBSERVED,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_PUBLIC,
    CODE_LIFETIME_LONG_OBSERVED,
    CODE_LIFETIME_UNBOUNDED_OBSERVED,
    EXPOSURE_BROWSER_STORAGE_OBSERVED,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_REFERRER_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_URL_OBSERVED,
    FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_CLIENT_CREDENTIALS,
    FLOW_DEVICE_AUTHORIZATION,
    FLOW_HYBRID,
    FLOW_IMPLICIT,
    FLOW_REFRESH_TOKEN,
    GRANT_AUTHORIZATION_CODE,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_DEVICE_CODE,
    GRANT_IMPLICIT,
    GRANT_REFRESH_TOKEN,
    OBSERVED,
    OBSERVED_EXPOSURE_STATES,
    OAUTH_VERSION_OAUTH2,
    OAUTH_VERSION_OAUTH2_1,
    REDIRECT_REGISTRATION_EXACT,
    REDIRECT_REGISTRATION_WILDCARD,
    RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_CODE_ID_TOKEN,
    RESPONSE_TYPE_ID_TOKEN,
    RESPONSE_TYPE_TOKEN,
    SESSION_SERVER_SIDE_OBSERVED,
    TOKEN_AUTH_CLIENT_SECRET_BASIC,
    TOKEN_AUTH_CLIENT_SECRET_POST,
    TOKEN_AUTH_NONE_OBSERVED,
    TOKEN_AUTH_PRIVATE_KEY_JWT,
    TOKEN_AUTH_TLS_CLIENT_AUTH,
    TOKEN_AUTH_UNKNOWN,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_MISSING_STATES,
    sanitize_oauth_context_analysis_plan,
)
from ai.schemas.oauth_hypothesis import (
    HYPOTHESIS_TYPES,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_CSRF_EXPLOIT_CLAIM,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_OAUTH_BYPASS_CLAIM,
    LIMITATION_NO_REDIRECT_URI_EXPLOIT_CLAIM,
    LIMITATION_NO_TOKEN_EXCHANGE_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    OAUTH_HYPOTHESIS_RULE_VERSION,
    OAUTH_SIGNALS,
    SIGNAL_AUTHORIZATION_BOUNDARY_CLIENT_SIDE,
    SIGNAL_AUTHORIZATION_BOUNDARY_SERVER_SIDE,
    SIGNAL_AUTHORIZATION_CODE_BINDING_ABSENT,
    SIGNAL_AUTHORIZATION_CODE_BINDING_ENFORCED,
    SIGNAL_AUTHORIZATION_CODE_BINDING_NOT_PROVIDED,
    SIGNAL_AUTHORIZATION_ENDPOINT_OBSERVED,
    SIGNAL_AUTHORIZATION_SERVER_OBSERVED,
    SIGNAL_CLIENT_AUTHENTICATION_ABSENT,
    SIGNAL_CLIENT_AUTHENTICATION_ENFORCED,
    SIGNAL_CLIENT_AUTHENTICATION_NOT_PROVIDED,
    SIGNAL_CLIENT_ID_OBSERVED,
    SIGNAL_CLIENT_SECRET_NOT_REQUIRED,
    SIGNAL_CLIENT_SECRET_REQUIRED,
    SIGNAL_CLIENT_TYPE_CONFIDENTIAL,
    SIGNAL_CLIENT_TYPE_PUBLIC,
    SIGNAL_CODE_LIFETIME_LONG,
    SIGNAL_CODE_LIFETIME_SHORT,
    SIGNAL_CODE_LIFETIME_UNBOUNDED,
    SIGNAL_CODE_REUSE_CONTROL_ABSENT,
    SIGNAL_CODE_REUSE_CONTROL_ENFORCED,
    SIGNAL_CODE_REUSE_CONTROL_NOT_PROVIDED,
    SIGNAL_CONSENT_CONTROL_ABSENT,
    SIGNAL_CONSENT_CONTROL_ENFORCED,
    SIGNAL_CONSENT_CONTROL_NOT_PROVIDED,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_CSRF_PROTECTION_ABSENT,
    SIGNAL_CSRF_PROTECTION_ENFORCED,
    SIGNAL_CSRF_PROTECTION_NOT_PROVIDED,
    SIGNAL_EXACT_REDIRECT_MATCHING_ABSENT,
    SIGNAL_EXACT_REDIRECT_MATCHING_ENFORCED,
    SIGNAL_EXACT_REDIRECT_MATCHING_NOT_PROVIDED,
    SIGNAL_FLOW_AUTHORIZATION_CODE,
    SIGNAL_FLOW_AUTHORIZATION_CODE_PKCE,
    SIGNAL_FLOW_CLIENT_CREDENTIALS,
    SIGNAL_FLOW_DEVICE_AUTHORIZATION,
    SIGNAL_FLOW_HYBRID,
    SIGNAL_FLOW_IMPLICIT,
    SIGNAL_FLOW_REFRESH_TOKEN,
    SIGNAL_GRANT_TYPE_AUTHORIZATION_CODE,
    SIGNAL_GRANT_TYPE_CLIENT_CREDENTIALS,
    SIGNAL_GRANT_TYPE_REFRESH_TOKEN,
    SIGNAL_ISSUER_VALIDATION_ABSENT,
    SIGNAL_ISSUER_VALIDATION_ENFORCED,
    SIGNAL_ISSUER_VALIDATION_NOT_PROVIDED,
    SIGNAL_LOGIN_CSRF_PROTECTION_ABSENT,
    SIGNAL_LOGIN_CSRF_PROTECTION_ENFORCED,
    SIGNAL_LOGIN_CSRF_PROTECTION_NOT_PROVIDED,
    SIGNAL_MISSING_OAUTH_CONTEXT,
    SIGNAL_NONCE_PARAM_OBSERVED,
    SIGNAL_NONCE_VALIDATION_ABSENT,
    SIGNAL_NONCE_VALIDATION_ENFORCED,
    SIGNAL_NONCE_VALIDATION_NOT_PROVIDED,
    SIGNAL_OAUTH2_1_OBSERVED,
    SIGNAL_OAUTH2_OBSERVED,
    SIGNAL_PKCE_CHALLENGE_OBSERVED,
    SIGNAL_PKCE_ENFORCEMENT_ABSENT,
    SIGNAL_PKCE_ENFORCEMENT_ENFORCED,
    SIGNAL_PKCE_ENFORCEMENT_NOT_PROVIDED,
    SIGNAL_PKCE_VERIFIER_VALIDATION_ABSENT,
    SIGNAL_PKCE_VERIFIER_VALIDATION_ENFORCED,
    SIGNAL_PKCE_VERIFIER_VALIDATION_NOT_PROVIDED,
    SIGNAL_REDIRECT_HANDLING_ABSENT,
    SIGNAL_REDIRECT_HANDLING_ENFORCED,
    SIGNAL_REDIRECT_HANDLING_NOT_PROVIDED,
    SIGNAL_REDIRECT_REGISTRATION_EXACT,
    SIGNAL_REDIRECT_REGISTRATION_WILDCARD,
    SIGNAL_REDIRECT_URI_PARAM_OBSERVED,
    SIGNAL_REDIRECT_URI_VALIDATION_ABSENT,
    SIGNAL_REDIRECT_URI_VALIDATION_ENFORCED,
    SIGNAL_REDIRECT_URI_VALIDATION_NOT_PROVIDED,
    SIGNAL_REFRESH_TOKEN_OBSERVED,
    SIGNAL_REFRESH_TOKEN_REVOCATION_ABSENT,
    SIGNAL_REFRESH_TOKEN_REVOCATION_ENFORCED,
    SIGNAL_REFRESH_TOKEN_REVOCATION_NOT_PROVIDED,
    SIGNAL_REFRESH_TOKEN_ROTATION_ABSENT,
    SIGNAL_REFRESH_TOKEN_ROTATION_ENFORCED,
    SIGNAL_REFRESH_TOKEN_ROTATION_NOT_PROVIDED,
    SIGNAL_RESOURCE_AUDIENCE_VALIDATION_ABSENT,
    SIGNAL_RESOURCE_AUDIENCE_VALIDATION_ENFORCED,
    SIGNAL_RESOURCE_AUDIENCE_VALIDATION_NOT_PROVIDED,
    SIGNAL_RESOURCE_SERVER_OBSERVED,
    SIGNAL_RESPONSE_TYPE_CODE,
    SIGNAL_RESPONSE_TYPE_ID_TOKEN,
    SIGNAL_RESPONSE_TYPE_TOKEN,
    SIGNAL_SCOPE_OBSERVED,
    SIGNAL_SCOPE_VALIDATION_ABSENT,
    SIGNAL_SCOPE_VALIDATION_ENFORCED,
    SIGNAL_SCOPE_VALIDATION_NOT_PROVIDED,
    SIGNAL_SESSION_SERVER_SIDE,
    SIGNAL_STATE_BINDING_ABSENT,
    SIGNAL_STATE_BINDING_ENFORCED,
    SIGNAL_STATE_BINDING_NOT_PROVIDED,
    SIGNAL_STATE_PARAM_OBSERVED,
    SIGNAL_STATE_VALIDATION_ABSENT,
    SIGNAL_STATE_VALIDATION_ENFORCED,
    SIGNAL_STATE_VALIDATION_NOT_PROVIDED,
    SIGNAL_TOKEN_AUTH_CLIENT_SECRET_BASIC,
    SIGNAL_TOKEN_AUTH_CLIENT_SECRET_POST,
    SIGNAL_TOKEN_AUTH_NONE_OBSERVED,
    SIGNAL_TOKEN_AUTH_PRIVATE_KEY_JWT,
    SIGNAL_TOKEN_AUTH_TLS_CLIENT_AUTH,
    SIGNAL_TOKEN_ENDPOINT_OBSERVED,
    SIGNAL_TOKEN_EXPOSURE_BROWSER_STORAGE,
    SIGNAL_TOKEN_EXPOSURE_CLIENT_STORAGE,
    SIGNAL_TOKEN_EXPOSURE_LOG,
    SIGNAL_TOKEN_EXPOSURE_REFERRER,
    SIGNAL_TOKEN_EXPOSURE_RESPONSE_BODY,
    SIGNAL_TOKEN_EXPOSURE_URL,
    SIGNAL_TOKEN_VALIDATION_ABSENT,
    SIGNAL_TOKEN_VALIDATION_ENFORCED,
    SIGNAL_TOKEN_VALIDATION_NOT_PROVIDED,
    STATE_CONTROL_PRESENT_OBSERVED,
    STATE_NEEDS_EVIDENCE,
    STATE_UNKNOWN,
    STATE_WEAKNESS_OBSERVED,
    TYPE_AUTHENTICATION_CONTROL_PRESENT,
    TYPE_AUTHORIZATION_CODE_LIFETIME_RISK,
    TYPE_AUTHORIZATION_CODE_REUSE_GAP,
    TYPE_AUTHORIZATION_CODE_VALIDATION_GAP,
    TYPE_AUTHORIZATION_FLOW_GAP,
    TYPE_CLIENT_AUTHENTICATION_GAP,
    TYPE_CLIENT_CONFIGURATION_GAP,
    TYPE_CONSENT_CONTROL_GAP,
    TYPE_CSRF_PROTECTION_GAP,
    TYPE_IMPLICIT_FLOW_RISK,
    TYPE_ISSUER_VALIDATION_GAP,
    TYPE_LOGIN_CSRF_GAP,
    TYPE_MISSING_OAUTH_CONTEXT,
    TYPE_NONCE_VALIDATION_GAP,
    TYPE_PKCE_ENFORCEMENT_GAP,
    TYPE_PKCE_VERIFIER_VALIDATION_GAP,
    TYPE_REDIRECT_HANDLING_RISK,
    TYPE_REDIRECT_URI_VALIDATION_GAP,
    TYPE_REFRESH_TOKEN_REVOCATION_GAP,
    TYPE_REFRESH_TOKEN_ROTATION_GAP,
    TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP,
    TYPE_SCOPE_VALIDATION_GAP,
    TYPE_STATE_VALIDATION_GAP,
    TYPE_TOKEN_EXPOSURE_RISK,
    TYPE_TOKEN_VALIDATION_GAP,
    TYPE_UNKNOWN,
    OAuthHypothesisPlan,
    oauth_hypothesis_plan_projection,
)

OAUTH_HYPOTHESIS_PLANNER_RULE_VERSION = "r48-3"
RULE_VERSION = OAUTH_HYPOTHESIS_PLANNER_RULE_VERSION

# Bounded membership set used to keep supporting signals within the closed
# R48.3 signal vocabulary.
VALIDATION_SIGNALS_LOOKUP: frozenset[str] = frozenset(OAUTH_SIGNALS)

VERSION_SIGNALS: dict[str, str] = {
    OAUTH_VERSION_OAUTH2: SIGNAL_OAUTH2_OBSERVED,
    OAUTH_VERSION_OAUTH2_1: SIGNAL_OAUTH2_1_OBSERVED,
}

FLOW_SIGNALS: dict[str, str] = {
    FLOW_AUTHORIZATION_CODE: SIGNAL_FLOW_AUTHORIZATION_CODE,
    FLOW_AUTHORIZATION_CODE_PKCE: SIGNAL_FLOW_AUTHORIZATION_CODE_PKCE,
    FLOW_IMPLICIT: SIGNAL_FLOW_IMPLICIT,
    FLOW_CLIENT_CREDENTIALS: SIGNAL_FLOW_CLIENT_CREDENTIALS,
    FLOW_DEVICE_AUTHORIZATION: SIGNAL_FLOW_DEVICE_AUTHORIZATION,
    FLOW_REFRESH_TOKEN: SIGNAL_FLOW_REFRESH_TOKEN,
    FLOW_HYBRID: SIGNAL_FLOW_HYBRID,
}

CLIENT_TYPE_SIGNALS: dict[str, str] = {
    CLIENT_TYPE_PUBLIC: SIGNAL_CLIENT_TYPE_PUBLIC,
    CLIENT_TYPE_CONFIDENTIAL: SIGNAL_CLIENT_TYPE_CONFIDENTIAL,
}

VALIDATION_SIGNALS: dict[str, tuple[str, str, str]] = {
    "redirect_uri_validation": (
        SIGNAL_REDIRECT_URI_VALIDATION_ENFORCED,
        SIGNAL_REDIRECT_URI_VALIDATION_ABSENT,
        SIGNAL_REDIRECT_URI_VALIDATION_NOT_PROVIDED,
    ),
    "exact_redirect_matching": (
        SIGNAL_EXACT_REDIRECT_MATCHING_ENFORCED,
        SIGNAL_EXACT_REDIRECT_MATCHING_ABSENT,
        SIGNAL_EXACT_REDIRECT_MATCHING_NOT_PROVIDED,
    ),
    "state_validation": (
        SIGNAL_STATE_VALIDATION_ENFORCED,
        SIGNAL_STATE_VALIDATION_ABSENT,
        SIGNAL_STATE_VALIDATION_NOT_PROVIDED,
    ),
    "state_binding": (
        SIGNAL_STATE_BINDING_ENFORCED,
        SIGNAL_STATE_BINDING_ABSENT,
        SIGNAL_STATE_BINDING_NOT_PROVIDED,
    ),
    "nonce_validation": (
        SIGNAL_NONCE_VALIDATION_ENFORCED,
        SIGNAL_NONCE_VALIDATION_ABSENT,
        SIGNAL_NONCE_VALIDATION_NOT_PROVIDED,
    ),
    "pkce_enforcement": (
        SIGNAL_PKCE_ENFORCEMENT_ENFORCED,
        SIGNAL_PKCE_ENFORCEMENT_ABSENT,
        SIGNAL_PKCE_ENFORCEMENT_NOT_PROVIDED,
    ),
    "pkce_verifier_validation": (
        SIGNAL_PKCE_VERIFIER_VALIDATION_ENFORCED,
        SIGNAL_PKCE_VERIFIER_VALIDATION_ABSENT,
        SIGNAL_PKCE_VERIFIER_VALIDATION_NOT_PROVIDED,
    ),
    "authorization_code_binding": (
        SIGNAL_AUTHORIZATION_CODE_BINDING_ENFORCED,
        SIGNAL_AUTHORIZATION_CODE_BINDING_ABSENT,
        SIGNAL_AUTHORIZATION_CODE_BINDING_NOT_PROVIDED,
    ),
    "code_reuse_control": (
        SIGNAL_CODE_REUSE_CONTROL_ENFORCED,
        SIGNAL_CODE_REUSE_CONTROL_ABSENT,
        SIGNAL_CODE_REUSE_CONTROL_NOT_PROVIDED,
    ),
    "client_authentication": (
        SIGNAL_CLIENT_AUTHENTICATION_ENFORCED,
        SIGNAL_CLIENT_AUTHENTICATION_ABSENT,
        SIGNAL_CLIENT_AUTHENTICATION_NOT_PROVIDED,
    ),
    "scope_validation": (
        SIGNAL_SCOPE_VALIDATION_ENFORCED,
        SIGNAL_SCOPE_VALIDATION_ABSENT,
        SIGNAL_SCOPE_VALIDATION_NOT_PROVIDED,
    ),
    "resource_audience_validation": (
        SIGNAL_RESOURCE_AUDIENCE_VALIDATION_ENFORCED,
        SIGNAL_RESOURCE_AUDIENCE_VALIDATION_ABSENT,
        SIGNAL_RESOURCE_AUDIENCE_VALIDATION_NOT_PROVIDED,
    ),
    "issuer_validation": (
        SIGNAL_ISSUER_VALIDATION_ENFORCED,
        SIGNAL_ISSUER_VALIDATION_ABSENT,
        SIGNAL_ISSUER_VALIDATION_NOT_PROVIDED,
    ),
    "token_validation": (
        SIGNAL_TOKEN_VALIDATION_ENFORCED,
        SIGNAL_TOKEN_VALIDATION_ABSENT,
        SIGNAL_TOKEN_VALIDATION_NOT_PROVIDED,
    ),
    "refresh_token_rotation": (
        SIGNAL_REFRESH_TOKEN_ROTATION_ENFORCED,
        SIGNAL_REFRESH_TOKEN_ROTATION_ABSENT,
        SIGNAL_REFRESH_TOKEN_ROTATION_NOT_PROVIDED,
    ),
    "refresh_token_revocation": (
        SIGNAL_REFRESH_TOKEN_REVOCATION_ENFORCED,
        SIGNAL_REFRESH_TOKEN_REVOCATION_ABSENT,
        SIGNAL_REFRESH_TOKEN_REVOCATION_NOT_PROVIDED,
    ),
    "consent_control": (
        SIGNAL_CONSENT_CONTROL_ENFORCED,
        SIGNAL_CONSENT_CONTROL_ABSENT,
        SIGNAL_CONSENT_CONTROL_NOT_PROVIDED,
    ),
    "csrf_protection": (
        SIGNAL_CSRF_PROTECTION_ENFORCED,
        SIGNAL_CSRF_PROTECTION_ABSENT,
        SIGNAL_CSRF_PROTECTION_NOT_PROVIDED,
    ),
    "login_csrf_protection": (
        SIGNAL_LOGIN_CSRF_PROTECTION_ENFORCED,
        SIGNAL_LOGIN_CSRF_PROTECTION_ABSENT,
        SIGNAL_LOGIN_CSRF_PROTECTION_NOT_PROVIDED,
    ),
    "redirect_handling": (
        SIGNAL_REDIRECT_HANDLING_ENFORCED,
        SIGNAL_REDIRECT_HANDLING_ABSENT,
        SIGNAL_REDIRECT_HANDLING_NOT_PROVIDED,
    ),
}

TOKEN_AUTH_METHOD_SIGNALS: dict[str, str] = {
    TOKEN_AUTH_CLIENT_SECRET_BASIC: SIGNAL_TOKEN_AUTH_CLIENT_SECRET_BASIC,
    TOKEN_AUTH_CLIENT_SECRET_POST: SIGNAL_TOKEN_AUTH_CLIENT_SECRET_POST,
    TOKEN_AUTH_PRIVATE_KEY_JWT: SIGNAL_TOKEN_AUTH_PRIVATE_KEY_JWT,
    TOKEN_AUTH_TLS_CLIENT_AUTH: SIGNAL_TOKEN_AUTH_TLS_CLIENT_AUTH,
    TOKEN_AUTH_NONE_OBSERVED: SIGNAL_TOKEN_AUTH_NONE_OBSERVED,
}

GRANT_SIGNALS: dict[str, str] = {
    GRANT_AUTHORIZATION_CODE: SIGNAL_GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_REFRESH_TOKEN: SIGNAL_GRANT_TYPE_REFRESH_TOKEN,
    GRANT_CLIENT_CREDENTIALS: SIGNAL_GRANT_TYPE_CLIENT_CREDENTIALS,
}

RESPONSE_SIGNALS: dict[str, str] = {
    RESPONSE_TYPE_CODE: SIGNAL_RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_TOKEN: SIGNAL_RESPONSE_TYPE_TOKEN,
    RESPONSE_TYPE_ID_TOKEN: SIGNAL_RESPONSE_TYPE_ID_TOKEN,
}

EXPOSURE_SIGNALS: dict[str, str] = {
    EXPOSURE_URL_OBSERVED: SIGNAL_TOKEN_EXPOSURE_URL,
    EXPOSURE_BROWSER_STORAGE_OBSERVED: (
        SIGNAL_TOKEN_EXPOSURE_BROWSER_STORAGE
    ),
    EXPOSURE_RESPONSE_BODY_OBSERVED: SIGNAL_TOKEN_EXPOSURE_RESPONSE_BODY,
    EXPOSURE_LOG_OBSERVED: SIGNAL_TOKEN_EXPOSURE_LOG,
    EXPOSURE_REFERRER_OBSERVED: SIGNAL_TOKEN_EXPOSURE_REFERRER,
    EXPOSURE_CLIENT_STORAGE_OBSERVED: SIGNAL_TOKEN_EXPOSURE_CLIENT_STORAGE,
}

RATIONALE_TEXTS: dict[str, str] = {
    TYPE_REDIRECT_URI_VALIDATION_GAP: (
        "Redirect URI validation evidence is absent or not provided; this "
        "is a research hypothesis only, and no redirect payload was "
        "generated and no redirect chaining was attempted."
    ),
    TYPE_STATE_VALIDATION_GAP: (
        "State parameter validation evidence is absent or not provided; "
        "parameter presence alone is not a control."
    ),
    TYPE_NONCE_VALIDATION_GAP: (
        "Nonce validation evidence is absent or not provided where the "
        "supplied flow makes nonce relevant."
    ),
    TYPE_PKCE_ENFORCEMENT_GAP: (
        "PKCE enforcement evidence is absent or not provided where PKCE is "
        "relevant; PKCE presence alone is not enforcement."
    ),
    TYPE_PKCE_VERIFIER_VALIDATION_GAP: (
        "PKCE verifier validation evidence is absent or not provided; no "
        "verifier was generated, replayed or tested."
    ),
    TYPE_AUTHORIZATION_CODE_VALIDATION_GAP: (
        "Authorization-code binding evidence is absent or not provided; no "
        "code was exchanged or replayed."
    ),
    TYPE_AUTHORIZATION_CODE_REUSE_GAP: (
        "Authorization-code one-time-use/replay control evidence is absent "
        "or not provided; no replay was attempted."
    ),
    TYPE_AUTHORIZATION_CODE_LIFETIME_RISK: (
        "Supplied authorization-code lifetime metadata indicates a long or "
        "unbounded code lifetime; lifetime policy evidence is required."
    ),
    TYPE_CLIENT_AUTHENTICATION_GAP: (
        "Client authentication evidence is absent or not provided where "
        "client authentication is expected; no secret was tested."
    ),
    TYPE_CLIENT_CONFIGURATION_GAP: (
        "Supplied client registration/configuration metadata indicates a "
        "configuration risk; registration evidence is required."
    ),
    TYPE_SCOPE_VALIDATION_GAP: (
        "Scope validation evidence is absent or not provided; scope name "
        "presence alone is not a vulnerability and no escalation was "
        "attempted."
    ),
    TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP: (
        "Resource/audience validation evidence is absent or not provided; "
        "resource indicators are context only."
    ),
    TYPE_ISSUER_VALIDATION_GAP: (
        "Issuer validation evidence is absent or not provided; this is a "
        "research hypothesis only."
    ),
    TYPE_TOKEN_VALIDATION_GAP: (
        "OAuth token validation evidence is absent or not provided; token "
        "content was not decoded or tested."
    ),
    TYPE_REFRESH_TOKEN_ROTATION_GAP: (
        "Refresh-token rotation evidence is absent or not provided; no "
        "refresh token was exchanged or replayed."
    ),
    TYPE_REFRESH_TOKEN_REVOCATION_GAP: (
        "Refresh-token revocation evidence is absent or not provided; no "
        "revocation request was sent."
    ),
    TYPE_CONSENT_CONTROL_GAP: (
        "Consent control evidence is absent or not provided; consent "
        "behavior was not exercised."
    ),
    TYPE_CSRF_PROTECTION_GAP: (
        "CSRF protection evidence is absent or not provided for the "
        "supplied interactive flow; no CSRF payload was generated and no "
        "CSRF was performed."
    ),
    TYPE_LOGIN_CSRF_GAP: (
        "Login CSRF protection evidence is absent or not provided for the "
        "supplied interactive flow; no login request was replayed."
    ),
    TYPE_REDIRECT_HANDLING_RISK: (
        "Redirect handling evidence is absent or not provided; no redirect "
        "was followed or chained."
    ),
    TYPE_IMPLICIT_FLOW_RISK: (
        "Implicit flow metadata is a research risk signal only; no "
        "exploitation was performed and no token was extracted."
    ),
    TYPE_TOKEN_EXPOSURE_RISK: (
        "Supplied exposure context indicates token material in a "
        "client-visible location; no token was extracted or decoded."
    ),
    TYPE_AUTHORIZATION_FLOW_GAP: (
        "Supplied authorization-boundary context indicates a client-side "
        "or unspecified boundary; no authorization bypass was attempted."
    ),
    TYPE_AUTHENTICATION_CONTROL_PRESENT: (
        "Supplied context explicitly contains OAuth control evidence; "
        "research priority is reduced."
    ),
    TYPE_MISSING_OAUTH_CONTEXT: (
        "No usable OAuth control context was supplied; additional "
        "structured context is required."
    ),
    TYPE_UNKNOWN: (
        "Insufficient structured OAuth context for a research hypothesis."
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
        LIMITATION_NO_OAUTH_BYPASS_CLAIM,
        LIMITATION_NO_REDIRECT_URI_EXPLOIT_CLAIM,
        LIMITATION_NO_TOKEN_EXCHANGE_CLAIM,
        LIMITATION_NO_CSRF_EXPLOIT_CLAIM,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if priority == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = OAuthHypothesisPlan(
        rule_version=OAUTH_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        hypothesis_state=hypothesis_state,
        supporting_signals=bounded_signals,
        confidence=priority,
        priority=priority,
        rationale=RATIONALE_TEXTS.get(hypothesis_type, ""),
        limitations=limitations,
        research_only=True,
    )
    return oauth_hypothesis_plan_projection(plan)


def plan_oauth_hypotheses(context_analysis: object = None) -> list[dict]:
    """Build the deterministic OAuth hypotheses (read-only).

    The mapping is conservative and never claims a vulnerability:

    - explicit observed absence of a validation/control produces the
      matching gap hypothesis with ``WEAKNESS_OBSERVED``;
    - not-provided validation information produces the matching gap
      hypothesis with ``NEEDS_EVIDENCE`` at low priority;
    - explicit observed control evidence produces
      ``AUTHENTICATION_CONTROL_PRESENT`` and never a gap for that control;
    - technology presence alone (OAuth version, flow, redirect_uri, state,
      nonce, PKCE, scope, client id, authorization code or refresh token
      metadata) produces no gap hypothesis;
    - nothing usable degrades to ``UNKNOWN``.
    """

    context = sanitize_oauth_context_analysis_plan(context_analysis)
    has_oauth = oauth_context_present(context)
    has_interactive = interactive_flow_present(context)
    has_code_flow = authorization_code_flow_present(context)
    has_pkce_context = pkce_context_present(context)
    has_token_flow = token_flow_present(context)
    has_refresh = context["refresh_token_present"] == OBSERVED
    is_public = context["client_type"] == CLIENT_TYPE_PUBLIC
    is_confidential = context["client_type"] == CLIENT_TYPE_CONFIDENTIAL
    is_implicit = context["flow"] == FLOW_IMPLICIT
    redirect_relevant = (
        context["redirect_uri"] == OBSERVED
        or context["redirect_uri_validation"]
        not in VALIDATION_MISSING_STATES
        or context["redirect_uri_registration"]
        in (REDIRECT_REGISTRATION_EXACT, REDIRECT_REGISTRATION_WILDCARD)
        or has_interactive
    )
    state_relevant = has_interactive or context["state_parameter"] == OBSERVED
    nonce_relevant = (
        context["nonce_parameter"] == OBSERVED
        or context["flow"] in (FLOW_IMPLICIT, FLOW_HYBRID)
    )
    pkce_in_use = (
        context["pkce_enforcement"] not in VALIDATION_MISSING_STATES
        or context["pkce_challenge"] == OBSERVED
        or context["flow"] == FLOW_AUTHORIZATION_CODE_PKCE
    )
    scope_relevant = (
        context["scope_context"] == OBSERVED
        or context["scope_validation"] not in VALIDATION_MISSING_STATES
        or has_token_flow
    )
    resource_relevant = (
        context["resource_server_context"] == OBSERVED
        or context["resource_audience_validation"]
        not in VALIDATION_MISSING_STATES
        or has_token_flow
    )
    issuer_relevant = (
        context["authorization_server_context"] == OBSERVED
        or context["issuer_validation"] not in VALIDATION_MISSING_STATES
        or has_token_flow
    )
    token_validation_relevant = (
        has_token_flow
        or context["token_endpoint"] == OBSERVED
        or context["token_validation"] not in VALIDATION_MISSING_STATES
    )
    csrf_relevant = has_interactive or context["state_parameter"] == OBSERVED
    consent_relevant = has_interactive

    known_count = sum(
        1
        for key in KNOWN_FIELDS
        if context[key] not in UNKNOWN_VALUES
    )

    version_signal = VERSION_SIGNALS.get(context["oauth_version"], "")
    flow_signal = FLOW_SIGNALS.get(context["flow"], "")
    client_type_signal = CLIENT_TYPE_SIGNALS.get(
        context["client_type"], ""
    )
    base_signals = (version_signal, flow_signal, client_type_signal)

    server_signals = (
        SIGNAL_AUTHORIZATION_SERVER_OBSERVED
        if context["authorization_server_context"] == OBSERVED
        else "",
        SIGNAL_RESOURCE_SERVER_OBSERVED
        if context["resource_server_context"] == OBSERVED
        else "",
    )
    endpoint_signals = (
        SIGNAL_AUTHORIZATION_ENDPOINT_OBSERVED
        if context["authorization_endpoint"] == OBSERVED
        else "",
        SIGNAL_TOKEN_ENDPOINT_OBSERVED
        if context["token_endpoint"] == OBSERVED
        else "",
    )
    parameter_signals = (
        SIGNAL_REDIRECT_URI_PARAM_OBSERVED
        if context["redirect_uri"] == OBSERVED
        else "",
        SIGNAL_CLIENT_ID_OBSERVED
        if context["client_id"] == OBSERVED
        else "",
        SIGNAL_SCOPE_OBSERVED
        if context["scope_context"] == OBSERVED
        else "",
        SIGNAL_STATE_PARAM_OBSERVED
        if context["state_parameter"] == OBSERVED
        else "",
        SIGNAL_NONCE_PARAM_OBSERVED
        if context["nonce_parameter"] == OBSERVED
        else "",
        SIGNAL_PKCE_CHALLENGE_OBSERVED
        if context["pkce_challenge"] == OBSERVED
        else "",
    )
    response_signal = RESPONSE_SIGNALS.get(
        context["response_type"], ""
    )
    grant_signal = GRANT_SIGNALS.get(context["grant_type"], "")
    token_auth_signal = TOKEN_AUTH_METHOD_SIGNALS.get(
        context["token_endpoint_auth_method"], ""
    )
    exposure_signal = EXPOSURE_SIGNALS.get(context["token_exposure"], "")
    registration_signal = (
        SIGNAL_REDIRECT_REGISTRATION_EXACT
        if context["redirect_uri_registration"]
        == REDIRECT_REGISTRATION_EXACT
        else SIGNAL_REDIRECT_REGISTRATION_WILDCARD
        if context["redirect_uri_registration"]
        == REDIRECT_REGISTRATION_WILDCARD
        else ""
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

    if has_oauth:
        validation_gap(
            TYPE_REDIRECT_URI_VALIDATION_GAP,
            "redirect_uri_validation",
            context["redirect_uri_validation"],
            CONFIDENCE_HIGH,
            redirect_relevant,
            base_signals
            + parameter_signals
            + (registration_signal,)
            + (
                VALIDATION_SIGNALS["exact_redirect_matching"][1]
                if context["exact_redirect_matching"]
                == VALIDATION_ABSENT_OBSERVED
                else "",
            ),
        )
        validation_gap(
            TYPE_STATE_VALIDATION_GAP,
            "state_validation",
            context["state_validation"],
            CONFIDENCE_HIGH,
            state_relevant,
            base_signals
            + parameter_signals
            + (
                VALIDATION_SIGNALS["state_binding"][1]
                if context["state_binding"] == VALIDATION_ABSENT_OBSERVED
                else "",
            ),
        )
        validation_gap(
            TYPE_NONCE_VALIDATION_GAP,
            "nonce_validation",
            context["nonce_validation"],
            CONFIDENCE_HIGH,
            nonce_relevant,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_PKCE_ENFORCEMENT_GAP,
            "pkce_enforcement",
            context["pkce_enforcement"],
            CONFIDENCE_HIGH,
            has_pkce_context,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_PKCE_VERIFIER_VALIDATION_GAP,
            "pkce_verifier_validation",
            context["pkce_verifier_validation"],
            CONFIDENCE_HIGH,
            has_pkce_context and pkce_in_use,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_SCOPE_VALIDATION_GAP,
            "scope_validation",
            context["scope_validation"],
            CONFIDENCE_HIGH,
            scope_relevant,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP,
            "resource_audience_validation",
            context["resource_audience_validation"],
            CONFIDENCE_HIGH,
            resource_relevant,
            base_signals + server_signals,
        )
        validation_gap(
            TYPE_ISSUER_VALIDATION_GAP,
            "issuer_validation",
            context["issuer_validation"],
            CONFIDENCE_HIGH,
            issuer_relevant,
            base_signals + server_signals,
        )
        validation_gap(
            TYPE_TOKEN_VALIDATION_GAP,
            "token_validation",
            context["token_validation"],
            CONFIDENCE_HIGH,
            token_validation_relevant,
            base_signals + endpoint_signals + server_signals,
        )
        validation_gap(
            TYPE_CONSENT_CONTROL_GAP,
            "consent_control",
            context["consent_control"],
            CONFIDENCE_MEDIUM,
            consent_relevant,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_CSRF_PROTECTION_GAP,
            "csrf_protection",
            context["csrf_protection"],
            CONFIDENCE_HIGH,
            csrf_relevant,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_LOGIN_CSRF_GAP,
            "login_csrf_protection",
            context["login_csrf_protection"],
            CONFIDENCE_HIGH,
            csrf_relevant,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_REDIRECT_HANDLING_RISK,
            "redirect_handling",
            context["redirect_handling"],
            CONFIDENCE_HIGH,
            redirect_relevant,
            base_signals
            + parameter_signals
            + (registration_signal,),
        )
        if context["authorization_boundary"] == (
            BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED
        ):
            add(
                TYPE_AUTHORIZATION_FLOW_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (SIGNAL_AUTHORIZATION_BOUNDARY_CLIENT_SIDE,)
                + base_signals,
            )
        elif context["authorization_boundary"] == BOUNDARY_MIXED_OBSERVED:
            add(
                TYPE_AUTHORIZATION_FLOW_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                base_signals + server_signals,
            )

    if has_code_flow:
        validation_gap(
            TYPE_AUTHORIZATION_CODE_VALIDATION_GAP,
            "authorization_code_binding",
            context["authorization_code_binding"],
            CONFIDENCE_HIGH,
            True,
            base_signals + parameter_signals,
        )
        validation_gap(
            TYPE_AUTHORIZATION_CODE_REUSE_GAP,
            "code_reuse_control",
            context["code_reuse_control"],
            CONFIDENCE_HIGH,
            True,
            base_signals + parameter_signals,
        )
        if context["authorization_code_lifetime"] == (
            CODE_LIFETIME_LONG_OBSERVED
        ):
            add(
                TYPE_AUTHORIZATION_CODE_LIFETIME_RISK,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (SIGNAL_CODE_LIFETIME_LONG,) + base_signals,
            )
        elif context["authorization_code_lifetime"] == (
            CODE_LIFETIME_UNBOUNDED_OBSERVED
        ):
            add(
                TYPE_AUTHORIZATION_CODE_LIFETIME_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (SIGNAL_CODE_LIFETIME_UNBOUNDED,) + base_signals,
            )

    client_auth_state = context["client_authentication"]
    client_auth_required = is_confidential or (
        context["token_endpoint_auth_method"]
        not in (TOKEN_AUTH_NONE_OBSERVED, TOKEN_AUTH_UNKNOWN)
    )
    if (
        is_confidential
        and context["token_endpoint_auth_method"] == TOKEN_AUTH_NONE_OBSERVED
        and client_auth_state in VALIDATION_MISSING_STATES
    ):
        client_auth_state = VALIDATION_ABSENT_OBSERVED
    if has_oauth and client_auth_required:
        validation_gap(
            TYPE_CLIENT_AUTHENTICATION_GAP,
            "client_authentication",
            client_auth_state,
            CONFIDENCE_HIGH,
            True,
            base_signals + endpoint_signals
            + (token_auth_signal,)
            + (
                SIGNAL_CLIENT_SECRET_NOT_REQUIRED
                if context["client_secret_usage"]
                == CLIENT_SECRET_NOT_REQUIRED_OBSERVED
                else SIGNAL_CLIENT_SECRET_REQUIRED
                if context["client_secret_usage"]
                in CLIENT_SECRET_PRESENT_STATES
                else "",
            ),
        )

    if has_oauth and context["redirect_uri_registration"] == (
        REDIRECT_REGISTRATION_WILDCARD
    ):
        add(
            TYPE_CLIENT_CONFIGURATION_GAP,
            CONFIDENCE_MEDIUM,
            STATE_WEAKNESS_OBSERVED,
            (SIGNAL_REDIRECT_REGISTRATION_WILDCARD,) + base_signals,
        )
    elif (
        has_oauth
        and is_confidential
        and context["client_secret_usage"]
        == CLIENT_SECRET_NOT_REQUIRED_OBSERVED
    ):
        add(
            TYPE_CLIENT_CONFIGURATION_GAP,
            CONFIDENCE_MEDIUM,
            STATE_WEAKNESS_OBSERVED,
            (SIGNAL_CLIENT_SECRET_NOT_REQUIRED,)
            + base_signals
            + (client_type_signal,),
        )

    if has_refresh:
        validation_gap(
            TYPE_REFRESH_TOKEN_ROTATION_GAP,
            "refresh_token_rotation",
            context["refresh_token_rotation"],
            CONFIDENCE_HIGH,
            True,
            (SIGNAL_REFRESH_TOKEN_OBSERVED,)
            + base_signals
            + parameter_signals,
        )
        validation_gap(
            TYPE_REFRESH_TOKEN_REVOCATION_GAP,
            "refresh_token_revocation",
            context["refresh_token_revocation"],
            CONFIDENCE_HIGH,
            True,
            (SIGNAL_REFRESH_TOKEN_OBSERVED,)
            + base_signals
            + parameter_signals,
        )

    if is_implicit:
        add(
            TYPE_IMPLICIT_FLOW_RISK,
            CONFIDENCE_LOW,
            STATE_WEAKNESS_OBSERVED,
            (SIGNAL_FLOW_IMPLICIT,)
            + (SIGNAL_RESPONSE_TYPE_TOKEN,)
            + base_signals,
        )

    if has_oauth and context["token_exposure"] in OBSERVED_EXPOSURE_STATES:
        add(
            TYPE_TOKEN_EXPOSURE_RISK,
            CONFIDENCE_MEDIUM,
            STATE_WEAKNESS_OBSERVED,
            (exposure_signal,) + base_signals,
        )

    enforced_control_signals = []
    for field, (enforced, _absent, _not_provided) in (
        VALIDATION_SIGNALS.items()
    ):
        if context[field] == VALIDATION_ENFORCED_OBSERVED:
            enforced_control_signals.append(enforced)
    if context["redirect_uri_registration"] == REDIRECT_REGISTRATION_EXACT:
        enforced_control_signals.append(SIGNAL_REDIRECT_REGISTRATION_EXACT)
    if context["client_secret_usage"] in CLIENT_SECRET_PRESENT_STATES:
        enforced_control_signals.append(SIGNAL_CLIENT_SECRET_REQUIRED)
    if context["authorization_boundary"] == BOUNDARY_SERVER_SIDE_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_AUTHORIZATION_BOUNDARY_SERVER_SIDE
        )
    if context["session_integration"] == SESSION_SERVER_SIDE_OBSERVED:
        enforced_control_signals.append(SIGNAL_SESSION_SERVER_SIDE)
    if enforced_control_signals:
        add(
            TYPE_AUTHENTICATION_CONTROL_PRESENT,
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
                TYPE_MISSING_OAUTH_CONTEXT,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_MISSING_OAUTH_CONTEXT,
                    flow_signal,
                    client_type_signal,
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
    "OAUTH_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "VERSION_SIGNALS",
    "FLOW_SIGNALS",
    "CLIENT_TYPE_SIGNALS",
    "VALIDATION_SIGNALS",
    "TOKEN_AUTH_METHOD_SIGNALS",
    "GRANT_SIGNALS",
    "RESPONSE_SIGNALS",
    "EXPOSURE_SIGNALS",
    "RATIONALE_TEXTS",
    "VALIDATION_SIGNALS_LOOKUP",
    "plan_oauth_hypotheses",
]

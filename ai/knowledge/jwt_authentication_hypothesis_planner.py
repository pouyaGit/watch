"""Stage R47.3 deterministic JWT/authentication hypothesis planner.

Creates deterministic research hypotheses from supplied authentication/JWT
context:

    "Which authentication/JWT review hypothesis follows from the supplied
     context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no signature bypass, no authentication bypass, no token forgery, no
  credential testing, no payload, no executable request, no attack sequence,
  no network/database execution.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, state, signals, confidence,
  priority, rationale and limitations are pure functions of the bounded
  context.
- Technology presence is never weakness: JWT, bearer tokens, cookies and
  algorithm metadata alone never produce a gap hypothesis.
- Present controls are distinguished from possible gaps; missing information
  produces ``NEEDS_EVIDENCE`` research items, never vulnerability claims.
- Priority is research usefulness only (never severity, exploitability,
  CVSS or vulnerability probability).
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.jwt_authentication_context_analyzer import (
    KNOWN_FIELDS,
    UNKNOWN_VALUES,
    jwt_present,
    token_present,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.jwt_authentication_context_analysis import (
    ALG_NONE,
    AUTH_MECH_BASIC,
    AUTH_MECH_BEARER_TOKEN,
    AUTH_MECH_COOKIE_SESSION,
    AUTH_MECH_JWT_BEARER,
    AUTH_MECH_MUTUAL_TLS,
    AUTH_MECH_OAUTH2,
    AUTH_MECH_API_KEY,
    BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED,
    BOUNDARY_SERVER_SIDE_OBSERVED,
    CLIENT_STORAGE_STATES,
    COOKIE_ATTR_HTTP_ONLY,
    COOKIE_ATTR_SECURE,
    EXPOSURE_CLIENT_STORAGE_OBSERVED,
    EXPOSURE_LOG_OBSERVED,
    EXPOSURE_RESPONSE_BODY_OBSERVED,
    EXPOSURE_URL_OBSERVED,
    FLOW_LOGIN_OBSERVED,
    FLOW_REFRESH_OBSERVED,
    FLOW_SESSION_OBSERVED,
    FLOW_TOKEN_OBSERVED,
    KEY_MANAGEMENT_ABSENT_OBSERVED,
    KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED,
    KEY_MANAGEMENT_MANAGED_OBSERVED,
    KEY_MANAGEMENT_STATIC_KEY_OBSERVED,
    KEY_ROTATION_CONFIGURED_OBSERVED,
    KEY_ROTATION_NO_ROTATION_OBSERVED,
    LIFETIME_LONG_OBSERVED,
    LIFETIME_SHORT_OBSERVED,
    LIFETIME_UNBOUNDED_OBSERVED,
    OBSERVED_EXPOSURE_STATES,
    REFRESH_PRESENT,
    SESSION_CLIENT_SIDE_OBSERVED,
    SESSION_SERVER_SIDE_OBSERVED,
    SESSION_STATELESS_TOKEN_OBSERVED,
    SIGNING_ASYMMETRIC,
    SIGNING_SYMMETRIC,
    STORAGE_COOKIE_OBSERVED,
    STORAGE_LOCAL_STORAGE_OBSERVED,
    STORAGE_MEMORY_ONLY_OBSERVED,
    STORAGE_SERVER_SIDE_OBSERVED,
    STORAGE_SESSION_STORAGE_OBSERVED,
    TOKEN_FORMAT_COMPACT_JWE,
    TOKEN_FORMAT_COMPACT_JWS,
    TOKEN_MECH_JWT,
    TOKEN_MECH_OPAQUE_ACCESS,
    TOKEN_MECH_REFRESH,
    TOKEN_MECH_SESSION_COOKIE,
    VALIDATION_ABSENT_OBSERVED,
    VALIDATION_CONTROL_ABSENT_STATES,
    VALIDATION_ENFORCED_OBSERVED,
    VALIDATION_MISSING_STATES,
    sanitize_jwt_authentication_context_analysis_plan,
)
from ai.schemas.jwt_authentication_hypothesis import (
    HYPOTHESIS_TYPES,
    JWT_AUTHENTICATION_HYPOTHESIS_RULE_VERSION,
    JWT_AUTHENTICATION_SIGNALS,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_AUTHENTICATION_BYPASS_CLAIM,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_SIGNATURE_BYPASS_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_ALGORITHM_VALIDATION_ABSENT,
    SIGNAL_ALGORITHM_VALIDATION_ENFORCED,
    SIGNAL_ALGORITHM_VALIDATION_NOT_PROVIDED,
    SIGNAL_AUDIENCE_VALIDATION_ABSENT,
    SIGNAL_AUDIENCE_VALIDATION_ENFORCED,
    SIGNAL_AUDIENCE_VALIDATION_NOT_PROVIDED,
    SIGNAL_AUTHENTICATION_CONTROL_ABSENT,
    SIGNAL_AUTHENTICATION_CONTROL_ENFORCED,
    SIGNAL_AUTHENTICATION_CONTROL_NOT_PROVIDED,
    SIGNAL_AUTHENTICATION_FLOW_OBSERVED,
    SIGNAL_AUTHORIZATION_BOUNDARY_CLIENT_SIDE,
    SIGNAL_AUTHORIZATION_BOUNDARY_SERVER_SIDE,
    SIGNAL_CLAIM_VALIDATION_ABSENT,
    SIGNAL_CLAIM_VALIDATION_ENFORCED,
    SIGNAL_CLAIM_VALIDATION_NOT_PROVIDED,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_COOKIE_HTTP_ONLY_PRESENT,
    SIGNAL_COOKIE_SAME_SITE_PRESENT,
    SIGNAL_COOKIE_SECURE_PRESENT,
    SIGNAL_COOKIE_SECURITY_ATTRIBUTES_MISSING,
    SIGNAL_EXPIRATION_VALIDATION_ABSENT,
    SIGNAL_EXPIRATION_VALIDATION_ENFORCED,
    SIGNAL_EXPIRATION_VALIDATION_NOT_PROVIDED,
    SIGNAL_ISSUER_VALIDATION_ABSENT,
    SIGNAL_ISSUER_VALIDATION_ENFORCED,
    SIGNAL_ISSUER_VALIDATION_NOT_PROVIDED,
    SIGNAL_JWT_FORMAT_COMPACT_JWE,
    SIGNAL_JWT_FORMAT_COMPACT_JWS,
    SIGNAL_KEY_MANAGEMENT_ABSENT,
    SIGNAL_KEY_MANAGEMENT_EMBEDDED,
    SIGNAL_KEY_MANAGEMENT_MANAGED,
    SIGNAL_KEY_MANAGEMENT_STATIC,
    SIGNAL_KEY_ROTATION_ABSENT,
    SIGNAL_KEY_ROTATION_CONFIGURED,
    SIGNAL_MISSING_AUTHENTICATION_CONTEXT,
    SIGNAL_NOT_BEFORE_VALIDATION_ABSENT,
    SIGNAL_NOT_BEFORE_VALIDATION_ENFORCED,
    SIGNAL_NOT_BEFORE_VALIDATION_NOT_PROVIDED,
    SIGNAL_REFRESH_CONTROL_ABSENT,
    SIGNAL_REFRESH_CONTROL_ENFORCED,
    SIGNAL_REFRESH_CONTROL_NOT_PROVIDED,
    SIGNAL_REFRESH_TOKEN_PRESENT,
    SIGNAL_REVOCATION_CONTROL_ABSENT,
    SIGNAL_REVOCATION_CONTROL_ENFORCED,
    SIGNAL_REVOCATION_CONTROL_NOT_PROVIDED,
    SIGNAL_SESSION_CLIENT_SIDE,
    SIGNAL_SESSION_SERVER_SIDE,
    SIGNAL_SESSION_STATELESS_TOKEN,
    SIGNAL_SIGNATURE_VERIFICATION_ABSENT,
    SIGNAL_SIGNATURE_VERIFICATION_ENFORCED,
    SIGNAL_SIGNATURE_VERIFICATION_NOT_PROVIDED,
    SIGNAL_SIGNING_ALGORITHM_METADATA_PRESENT,
    SIGNAL_SIGNING_ALGORITHM_NONE_OBSERVED,
    SIGNAL_SIGNING_METHOD_ASYMMETRIC,
    SIGNAL_SIGNING_METHOD_SYMMETRIC,
    SIGNAL_STORAGE_COOKIE,
    SIGNAL_STORAGE_LOCAL,
    SIGNAL_STORAGE_MEMORY_ONLY,
    SIGNAL_STORAGE_SERVER_SIDE,
    SIGNAL_STORAGE_SESSION,
    SIGNAL_TOKEN_EXPOSURE_CLIENT_STORAGE,
    SIGNAL_TOKEN_EXPOSURE_LOG,
    SIGNAL_TOKEN_EXPOSURE_RESPONSE_BODY,
    SIGNAL_TOKEN_EXPOSURE_URL,
    SIGNAL_TOKEN_LIFETIME_LONG,
    SIGNAL_TOKEN_LIFETIME_SHORT,
    SIGNAL_TOKEN_LIFETIME_UNBOUNDED,
    SIGNAL_TOKEN_MECHANISM_JWT,
    SIGNAL_TOKEN_MECHANISM_OPAQUE_ACCESS,
    SIGNAL_TOKEN_MECHANISM_REFRESH,
    SIGNAL_TOKEN_MECHANISM_SESSION_COOKIE,
    STATE_CONTROL_PRESENT_OBSERVED,
    STATE_NEEDS_EVIDENCE,
    STATE_UNKNOWN,
    STATE_WEAKNESS_OBSERVED,
    TYPE_ALGORITHM_VALIDATION_GAP,
    TYPE_AUDIENCE_VALIDATION_GAP,
    TYPE_AUTHENTICATION_CONTROL_PRESENT,
    TYPE_AUTHENTICATION_FLOW_GAP,
    TYPE_CLAIM_VALIDATION_GAP,
    TYPE_EXPIRATION_VALIDATION_GAP,
    TYPE_ISSUER_VALIDATION_GAP,
    TYPE_JWT_VALIDATION_GAP,
    TYPE_KEY_MANAGEMENT_GAP,
    TYPE_MISSING_AUTHENTICATION_CONTEXT,
    TYPE_NOT_BEFORE_VALIDATION_GAP,
    TYPE_REFRESH_TOKEN_CONTROL_GAP,
    TYPE_SESSION_MANAGEMENT_GAP,
    TYPE_SIGNATURE_VERIFICATION_GAP,
    TYPE_TOKEN_LIFETIME_RISK,
    TYPE_TOKEN_REVOCATION_GAP,
    TYPE_TOKEN_STORAGE_RISK,
    TYPE_UNKNOWN,
    JWTAuthenticationHypothesisPlan,
    jwt_authentication_hypothesis_plan_projection,
)

JWT_AUTHENTICATION_HYPOTHESIS_PLANNER_RULE_VERSION = "r47-3"
RULE_VERSION = JWT_AUTHENTICATION_HYPOTHESIS_PLANNER_RULE_VERSION

AUTH_MECHANISM_SIGNALS: dict[str, str] = {
    AUTH_MECH_BEARER_TOKEN: "AUTH_MECHANISM_BEARER_TOKEN",
    AUTH_MECH_JWT_BEARER: "AUTH_MECHANISM_JWT_BEARER",
    AUTH_MECH_COOKIE_SESSION: "AUTH_MECHANISM_COOKIE_SESSION",
    AUTH_MECH_OAUTH2: "AUTH_MECHANISM_OAUTH2",
    AUTH_MECH_API_KEY: "AUTH_MECHANISM_API_KEY",
    AUTH_MECH_BASIC: "AUTH_MECHANISM_BASIC",
    AUTH_MECH_MUTUAL_TLS: "AUTH_MECHANISM_MUTUAL_TLS",
}

RATIONALE_TEXTS: dict[str, str] = {
    TYPE_JWT_VALIDATION_GAP: (
        "Supplied context does not describe several JWT validation controls; "
        "treated as research evidence needed, not as a vulnerability."
    ),
    TYPE_SIGNATURE_VERIFICATION_GAP: (
        "Signature verification evidence is absent or not provided; this is "
        "a research hypothesis only, and no signature bypass was attempted."
    ),
    TYPE_ALGORITHM_VALIDATION_GAP: (
        "Algorithm acceptance evidence is absent or not provided; algorithm "
        "metadata alone is not a vulnerability."
    ),
    TYPE_CLAIM_VALIDATION_GAP: (
        "Claim validation evidence is absent or not provided; token claim "
        "presence alone is not a vulnerability."
    ),
    TYPE_ISSUER_VALIDATION_GAP: (
        "Issuer validation evidence is absent or not provided; this is a "
        "research hypothesis only."
    ),
    TYPE_AUDIENCE_VALIDATION_GAP: (
        "Audience validation evidence is absent or not provided; this is a "
        "research hypothesis only."
    ),
    TYPE_EXPIRATION_VALIDATION_GAP: (
        "Expiration validation evidence is absent or not provided; this is "
        "a research hypothesis only."
    ),
    TYPE_NOT_BEFORE_VALIDATION_GAP: (
        "Not-before validation evidence is absent or not provided; this is "
        "a research hypothesis only."
    ),
    TYPE_KEY_MANAGEMENT_GAP: (
        "Key management evidence is static, embedded, absent or rotation is "
        "not observed; key handling should be reviewed with structured "
        "evidence."
    ),
    TYPE_TOKEN_LIFETIME_RISK: (
        "Supplied lifetime metadata indicates long or unbounded tokens; "
        "lifetime policy evidence is required to evaluate this."
    ),
    TYPE_TOKEN_STORAGE_RISK: (
        "Supplied storage or exposure context indicates client-side storage "
        "or token exposure; storage policy evidence is required."
    ),
    TYPE_TOKEN_REVOCATION_GAP: (
        "Revocation control evidence is absent or not provided; session and "
        "revocation policy evidence is required."
    ),
    TYPE_REFRESH_TOKEN_CONTROL_GAP: (
        "Refresh tokens are present while refresh control evidence is absent "
        "or not provided; control configuration evidence is required."
    ),
    TYPE_SESSION_MANAGEMENT_GAP: (
        "Session lifecycle context indicates client-side or stateless "
        "sessions; session management evidence is required."
    ),
    TYPE_AUTHENTICATION_FLOW_GAP: (
        "Authentication control evidence is absent or not provided; flow "
        "configuration evidence is required."
    ),
    TYPE_AUTHENTICATION_CONTROL_PRESENT: (
        "Supplied context explicitly contains authentication/validation "
        "control evidence; research priority is reduced."
    ),
    TYPE_MISSING_AUTHENTICATION_CONTEXT: (
        "No usable authentication control context was supplied; additional "
        "structured context is required."
    ),
    TYPE_UNKNOWN: (
        "Insufficient structured authentication context for a research "
        "hypothesis."
    ),
}

_PRIORITY_ORDER: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}


def _at_least(priority: str, floor: str) -> str:
    if _PRIORITY_ORDER[priority] >= _PRIORITY_ORDER[floor]:
        return priority
    return floor


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
            and signal in JWT_AUTHENTICATION_SIGNALS
            and signal not in bounded_signals
        ):
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_NO_SIGNATURE_BYPASS_CLAIM,
        LIMITATION_NO_AUTHENTICATION_BYPASS_CLAIM,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if priority == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = JWTAuthenticationHypothesisPlan(
        rule_version=JWT_AUTHENTICATION_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        hypothesis_state=hypothesis_state,
        supporting_signals=bounded_signals,
        confidence=priority,
        priority=priority,
        rationale=RATIONALE_TEXTS.get(hypothesis_type, ""),
        limitations=limitations,
        research_only=True,
    )
    return jwt_authentication_hypothesis_plan_projection(plan)


def _validation_signals(
    state: str,
    enforced: str,
    absent: str,
    not_provided: str,
    extra: object = (),
) -> tuple:
    signals: list[str] = []
    if state == VALIDATION_ENFORCED_OBSERVED:
        signals.append(enforced)
    elif state == VALIDATION_ABSENT_OBSERVED:
        signals.append(absent)
    else:
        signals.append(not_provided)
    for signal in extra or ():
        if signal:
            signals.append(signal)
    return tuple(signals)


def plan_jwt_authentication_hypotheses(
    context_analysis: object = None,
) -> list[dict]:
    """Build the deterministic JWT/authentication hypotheses (read-only).

    The mapping is conservative and never claims a vulnerability:

    - explicit observed absence of a validation/control produces the
      matching gap hypothesis with ``WEAKNESS_OBSERVED``;
    - not-provided validation information produces the matching gap
      hypothesis with ``NEEDS_EVIDENCE`` at low priority;
    - explicit observed control evidence produces
      ``AUTHENTICATION_CONTROL_PRESENT`` and never a gap for that control;
    - technology presence alone (JWT, bearer token, cookies, algorithm or
      claim metadata) produces no gap hypothesis;
    - nothing usable degrades to ``UNKNOWN``.
    """

    context = sanitize_jwt_authentication_context_analysis_plan(
        context_analysis
    )
    has_jwt = jwt_present(context)
    has_token = token_present(context)
    has_auth_context = (
        context["authentication_mechanism"] not in UNKNOWN_VALUES
        or context["token_mechanism"] not in UNKNOWN_VALUES
        or has_jwt
        or context["authentication_control"] not in VALIDATION_MISSING_STATES
        or context["session_lifecycle"]
        in (
            SESSION_SERVER_SIDE_OBSERVED,
            SESSION_CLIENT_SIDE_OBSERVED,
            SESSION_STATELESS_TOKEN_OBSERVED,
        )
        or context["authentication_flow"]
        in (
            FLOW_LOGIN_OBSERVED,
            FLOW_TOKEN_OBSERVED,
            FLOW_SESSION_OBSERVED,
            FLOW_REFRESH_OBSERVED,
        )
    )
    known_count = sum(
        1
        for key in KNOWN_FIELDS
        if context[key] not in UNKNOWN_VALUES
    )
    if context["cookie_attributes"]:
        known_count += 1

    signature = context["signature_verification"]
    algorithm_validation = context["algorithm_validation"]
    issuer = context["issuer_validation"]
    audience = context["audience_validation"]
    expiration = context["expiration_validation"]
    not_before = context["not_before_validation"]
    claim = context["claim_validation"]
    refresh_control = context["refresh_control"]
    revocation = context["revocation_control"]
    authentication_control = context["authentication_control"]

    jwt_format_signal = (
        SIGNAL_JWT_FORMAT_COMPACT_JWS
        if context["token_format"] == TOKEN_FORMAT_COMPACT_JWS
        else SIGNAL_JWT_FORMAT_COMPACT_JWE
        if context["token_format"] == TOKEN_FORMAT_COMPACT_JWE
        else ""
    )
    token_mechanism_signal = {
        TOKEN_MECH_JWT: SIGNAL_TOKEN_MECHANISM_JWT,
        TOKEN_MECH_OPAQUE_ACCESS: SIGNAL_TOKEN_MECHANISM_OPAQUE_ACCESS,
        TOKEN_MECH_REFRESH: SIGNAL_TOKEN_MECHANISM_REFRESH,
        TOKEN_MECH_SESSION_COOKIE: SIGNAL_TOKEN_MECHANISM_SESSION_COOKIE,
    }.get(context["token_mechanism"], "")
    mechanism_signal = AUTH_MECHANISM_SIGNALS.get(
        context["authentication_mechanism"], ""
    )
    algorithm_signal = (
        SIGNAL_SIGNING_ALGORITHM_NONE_OBSERVED
        if context["signing_algorithm"] == ALG_NONE
        else SIGNAL_SIGNING_ALGORITHM_METADATA_PRESENT
        if context["signing_algorithm"]
        not in ("NONE_OBSERVED", "UNKNOWN")
        else ""
    )
    signing_method_signal = {
        SIGNING_SYMMETRIC: SIGNAL_SIGNING_METHOD_SYMMETRIC,
        SIGNING_ASYMMETRIC: SIGNAL_SIGNING_METHOD_ASYMMETRIC,
    }.get(context["signing_method"], "")
    key_management_signal = {
        KEY_MANAGEMENT_MANAGED_OBSERVED: SIGNAL_KEY_MANAGEMENT_MANAGED,
        KEY_MANAGEMENT_STATIC_KEY_OBSERVED: SIGNAL_KEY_MANAGEMENT_STATIC,
        KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED:
            SIGNAL_KEY_MANAGEMENT_EMBEDDED,
        KEY_MANAGEMENT_ABSENT_OBSERVED: SIGNAL_KEY_MANAGEMENT_ABSENT,
    }.get(context["key_management"], "")
    key_rotation_signal = {
        KEY_ROTATION_CONFIGURED_OBSERVED: SIGNAL_KEY_ROTATION_CONFIGURED,
        KEY_ROTATION_NO_ROTATION_OBSERVED: SIGNAL_KEY_ROTATION_ABSENT,
    }.get(context["key_rotation"], "")
    lifetime_signal = {
        LIFETIME_SHORT_OBSERVED: SIGNAL_TOKEN_LIFETIME_SHORT,
        LIFETIME_LONG_OBSERVED: SIGNAL_TOKEN_LIFETIME_LONG,
        LIFETIME_UNBOUNDED_OBSERVED: SIGNAL_TOKEN_LIFETIME_UNBOUNDED,
    }.get(context["token_lifetime"], "")
    storage_signal = {
        STORAGE_SERVER_SIDE_OBSERVED: SIGNAL_STORAGE_SERVER_SIDE,
        STORAGE_MEMORY_ONLY_OBSERVED: SIGNAL_STORAGE_MEMORY_ONLY,
        STORAGE_COOKIE_OBSERVED: SIGNAL_STORAGE_COOKIE,
        STORAGE_LOCAL_STORAGE_OBSERVED: SIGNAL_STORAGE_LOCAL,
        STORAGE_SESSION_STORAGE_OBSERVED: SIGNAL_STORAGE_SESSION,
    }.get(context["token_storage"], "")
    cookie_signals: list[str] = []
    if COOKIE_ATTR_SECURE in context["cookie_attributes"]:
        cookie_signals.append(SIGNAL_COOKIE_SECURE_PRESENT)
    if COOKIE_ATTR_HTTP_ONLY in context["cookie_attributes"]:
        cookie_signals.append(SIGNAL_COOKIE_HTTP_ONLY_PRESENT)
    if any(
        value.startswith("SAME_SITE")
        for value in context["cookie_attributes"]
    ):
        cookie_signals.append(SIGNAL_COOKIE_SAME_SITE_PRESENT)
    if (
        context["token_storage"] == STORAGE_COOKIE_OBSERVED
        and bool(context["cookie_attributes"])
        and (
            COOKIE_ATTR_SECURE not in context["cookie_attributes"]
            or COOKIE_ATTR_HTTP_ONLY not in context["cookie_attributes"]
        )
    ):
        cookie_signals.append(SIGNAL_COOKIE_SECURITY_ATTRIBUTES_MISSING)
    exposure_signal = {
        EXPOSURE_URL_OBSERVED: SIGNAL_TOKEN_EXPOSURE_URL,
        EXPOSURE_LOG_OBSERVED: SIGNAL_TOKEN_EXPOSURE_LOG,
        EXPOSURE_RESPONSE_BODY_OBSERVED:
            SIGNAL_TOKEN_EXPOSURE_RESPONSE_BODY,
        EXPOSURE_CLIENT_STORAGE_OBSERVED:
            SIGNAL_TOKEN_EXPOSURE_CLIENT_STORAGE,
    }.get(context["token_exposure"], "")
    boundary_signal = {
        BOUNDARY_SERVER_SIDE_OBSERVED:
            SIGNAL_AUTHORIZATION_BOUNDARY_SERVER_SIDE,
        BOUNDARY_CLIENT_SIDE_ONLY_OBSERVED:
            SIGNAL_AUTHORIZATION_BOUNDARY_CLIENT_SIDE,
    }.get(context["authorization_boundary"], "")
    session_signal = {
        SESSION_SERVER_SIDE_OBSERVED: SIGNAL_SESSION_SERVER_SIDE,
        SESSION_CLIENT_SIDE_OBSERVED: SIGNAL_SESSION_CLIENT_SIDE,
        SESSION_STATELESS_TOKEN_OBSERVED:
            SIGNAL_SESSION_STATELESS_TOKEN,
    }.get(context["session_lifecycle"], "")
    flow_signal = (
        SIGNAL_AUTHENTICATION_FLOW_OBSERVED
        if context["authentication_flow"]
        in (
            FLOW_LOGIN_OBSERVED,
            FLOW_TOKEN_OBSERVED,
            FLOW_SESSION_OBSERVED,
            FLOW_REFRESH_OBSERVED,
        )
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
        state: str,
        strong_priority: str,
        enforced_signal: str,
        absent_signal: str,
        not_provided_signal: str,
        extra: object = (),
    ) -> None:
        if state == VALIDATION_ENFORCED_OBSERVED:
            return
        if state in VALIDATION_CONTROL_ABSENT_STATES:
            add(
                hypothesis_type,
                strong_priority,
                STATE_WEAKNESS_OBSERVED,
                _validation_signals(
                    state,
                    enforced_signal,
                    absent_signal,
                    not_provided_signal,
                    extra,
                ),
            )
        else:
            add(
                hypothesis_type,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                _validation_signals(
                    state,
                    enforced_signal,
                    absent_signal,
                    not_provided_signal,
                    extra,
                ),
            )

    base_jwt_signals = (
        token_mechanism_signal,
        jwt_format_signal,
        mechanism_signal,
    )

    if has_jwt:
        validation_gap(
            TYPE_SIGNATURE_VERIFICATION_GAP,
            signature,
            CONFIDENCE_HIGH,
            SIGNAL_SIGNATURE_VERIFICATION_ENFORCED,
            SIGNAL_SIGNATURE_VERIFICATION_ABSENT,
            SIGNAL_SIGNATURE_VERIFICATION_NOT_PROVIDED,
            (algorithm_signal, signing_method_signal),
        )
        validation_gap(
            TYPE_ALGORITHM_VALIDATION_GAP,
            algorithm_validation,
            CONFIDENCE_HIGH,
            SIGNAL_ALGORITHM_VALIDATION_ENFORCED,
            SIGNAL_ALGORITHM_VALIDATION_ABSENT,
            SIGNAL_ALGORITHM_VALIDATION_NOT_PROVIDED,
            (algorithm_signal, signing_method_signal),
        )
        validation_gap(
            TYPE_ISSUER_VALIDATION_GAP,
            issuer,
            CONFIDENCE_HIGH,
            SIGNAL_ISSUER_VALIDATION_ENFORCED,
            SIGNAL_ISSUER_VALIDATION_ABSENT,
            SIGNAL_ISSUER_VALIDATION_NOT_PROVIDED,
            base_jwt_signals,
        )
        validation_gap(
            TYPE_AUDIENCE_VALIDATION_GAP,
            audience,
            CONFIDENCE_HIGH,
            SIGNAL_AUDIENCE_VALIDATION_ENFORCED,
            SIGNAL_AUDIENCE_VALIDATION_ABSENT,
            SIGNAL_AUDIENCE_VALIDATION_NOT_PROVIDED,
            base_jwt_signals,
        )
        validation_gap(
            TYPE_NOT_BEFORE_VALIDATION_GAP,
            not_before,
            CONFIDENCE_MEDIUM,
            SIGNAL_NOT_BEFORE_VALIDATION_ENFORCED,
            SIGNAL_NOT_BEFORE_VALIDATION_ABSENT,
            SIGNAL_NOT_BEFORE_VALIDATION_NOT_PROVIDED,
            base_jwt_signals,
        )
        validation_gap(
            TYPE_CLAIM_VALIDATION_GAP,
            claim,
            CONFIDENCE_MEDIUM,
            SIGNAL_CLAIM_VALIDATION_ENFORCED,
            SIGNAL_CLAIM_VALIDATION_ABSENT,
            SIGNAL_CLAIM_VALIDATION_NOT_PROVIDED,
            base_jwt_signals,
        )

        missing_jwt_validation = [
            state
            for state in (
                signature,
                algorithm_validation,
                issuer,
                audience,
                expiration,
                not_before,
                claim,
            )
            if state in VALIDATION_MISSING_STATES
        ]
        absent_jwt_validation = [
            state
            for state in (
                signature,
                algorithm_validation,
                issuer,
                audience,
                expiration,
                not_before,
                claim,
            )
            if state in VALIDATION_CONTROL_ABSENT_STATES
        ]
        if len(missing_jwt_validation) >= 2 and not absent_jwt_validation:
            add(
                TYPE_JWT_VALIDATION_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                base_jwt_signals
                + (SIGNAL_MISSING_AUTHENTICATION_CONTEXT,),
            )

        if context["key_management"] in (
            KEY_MANAGEMENT_STATIC_KEY_OBSERVED,
            KEY_MANAGEMENT_EMBEDDED_KEY_OBSERVED,
        ):
            add(
                TYPE_KEY_MANAGEMENT_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    key_management_signal,
                    key_rotation_signal,
                    algorithm_signal,
                ),
            )
        elif context["key_management"] == KEY_MANAGEMENT_ABSENT_OBSERVED:
            add(
                TYPE_KEY_MANAGEMENT_GAP,
                CONFIDENCE_HIGH,
                STATE_WEAKNESS_OBSERVED,
                (
                    key_management_signal,
                    key_rotation_signal,
                    algorithm_signal,
                ),
            )
        elif (
            context["key_rotation"] == KEY_ROTATION_NO_ROTATION_OBSERVED
            and context["key_management"] != KEY_MANAGEMENT_MANAGED_OBSERVED
        ):
            add(
                TYPE_KEY_MANAGEMENT_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    key_rotation_signal,
                    key_management_signal,
                    algorithm_signal,
                ),
            )

    if has_token:
        validation_gap(
            TYPE_EXPIRATION_VALIDATION_GAP,
            expiration,
            CONFIDENCE_HIGH,
            SIGNAL_EXPIRATION_VALIDATION_ENFORCED,
            SIGNAL_EXPIRATION_VALIDATION_ABSENT,
            SIGNAL_EXPIRATION_VALIDATION_NOT_PROVIDED,
            base_jwt_signals + (SIGNAL_TOKEN_LIFETIME_SHORT,),
        )
        validation_gap(
            TYPE_TOKEN_REVOCATION_GAP,
            revocation,
            CONFIDENCE_HIGH,
            SIGNAL_REVOCATION_CONTROL_ENFORCED,
            SIGNAL_REVOCATION_CONTROL_ABSENT,
            SIGNAL_REVOCATION_CONTROL_NOT_PROVIDED,
            base_jwt_signals + (session_signal,),
        )

        if context["token_lifetime"] == LIFETIME_LONG_OBSERVED:
            add(
                TYPE_TOKEN_LIFETIME_RISK,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (lifetime_signal, token_mechanism_signal),
            )
        elif context["token_lifetime"] == LIFETIME_UNBOUNDED_OBSERVED:
            add(
                TYPE_TOKEN_LIFETIME_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (lifetime_signal, token_mechanism_signal),
            )

    if has_token or has_auth_context:
        if context["token_storage"] in CLIENT_STORAGE_STATES:
            add(
                TYPE_TOKEN_STORAGE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (storage_signal, *cookie_signals, exposure_signal),
            )
        elif (
            context["token_storage"] == STORAGE_COOKIE_OBSERVED
            and SIGNAL_COOKIE_SECURITY_ATTRIBUTES_MISSING
            in cookie_signals
        ):
            add(
                TYPE_TOKEN_STORAGE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (storage_signal, *cookie_signals),
            )
        elif context["token_exposure"] in OBSERVED_EXPOSURE_STATES:
            add(
                TYPE_TOKEN_STORAGE_RISK,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (exposure_signal, storage_signal, *cookie_signals),
            )

    if context["refresh_token"] == REFRESH_PRESENT:
        validation_gap(
            TYPE_REFRESH_TOKEN_CONTROL_GAP,
            refresh_control,
            CONFIDENCE_HIGH,
            SIGNAL_REFRESH_CONTROL_ENFORCED,
            SIGNAL_REFRESH_CONTROL_ABSENT,
            SIGNAL_REFRESH_CONTROL_NOT_PROVIDED,
            (SIGNAL_REFRESH_TOKEN_PRESENT, token_mechanism_signal),
        )

    if has_auth_context:
        if context["session_lifecycle"] == SESSION_CLIENT_SIDE_OBSERVED:
            add(
                TYPE_SESSION_MANAGEMENT_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (
                    session_signal,
                    storage_signal,
                    SIGNAL_REVOCATION_CONTROL_ABSENT
                    if revocation in VALIDATION_CONTROL_ABSENT_STATES
                    else SIGNAL_REVOCATION_CONTROL_NOT_PROVIDED,
                ),
            )
        elif (
            context["session_lifecycle"]
            == SESSION_STATELESS_TOKEN_OBSERVED
        ):
            priority = (
                CONFIDENCE_HIGH
                if revocation in VALIDATION_CONTROL_ABSENT_STATES
                else CONFIDENCE_LOW
            )
            add(
                TYPE_SESSION_MANAGEMENT_GAP,
                priority,
                STATE_WEAKNESS_OBSERVED
                if priority == CONFIDENCE_HIGH
                else STATE_NEEDS_EVIDENCE,
                (
                    session_signal,
                    SIGNAL_REVOCATION_CONTROL_ABSENT
                    if revocation in VALIDATION_CONTROL_ABSENT_STATES
                    else SIGNAL_REVOCATION_CONTROL_NOT_PROVIDED,
                    storage_signal,
                ),
            )

        if authentication_control in VALIDATION_CONTROL_ABSENT_STATES:
            add(
                TYPE_AUTHENTICATION_FLOW_GAP,
                CONFIDENCE_HIGH,
                STATE_WEAKNESS_OBSERVED,
                (
                    SIGNAL_AUTHENTICATION_CONTROL_ABSENT,
                    flow_signal,
                    mechanism_signal,
                ),
            )
        elif authentication_control in VALIDATION_MISSING_STATES:
            add(
                TYPE_AUTHENTICATION_FLOW_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_AUTHENTICATION_CONTROL_NOT_PROVIDED,
                    flow_signal,
                    mechanism_signal,
                ),
            )

    enforced_control_signals = []
    if signature == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_SIGNATURE_VERIFICATION_ENFORCED
        )
    if algorithm_validation == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_ALGORITHM_VALIDATION_ENFORCED
        )
    if issuer == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(SIGNAL_ISSUER_VALIDATION_ENFORCED)
    if audience == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_AUDIENCE_VALIDATION_ENFORCED
        )
    if expiration == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_EXPIRATION_VALIDATION_ENFORCED
        )
    if claim == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(SIGNAL_CLAIM_VALIDATION_ENFORCED)
    if revocation == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_REVOCATION_CONTROL_ENFORCED
        )
    if refresh_control == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(SIGNAL_REFRESH_CONTROL_ENFORCED)
    if authentication_control == VALIDATION_ENFORCED_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_AUTHENTICATION_CONTROL_ENFORCED
        )
    if context["key_management"] == KEY_MANAGEMENT_MANAGED_OBSERVED:
        enforced_control_signals.append(SIGNAL_KEY_MANAGEMENT_MANAGED)
    if context["key_rotation"] == KEY_ROTATION_CONFIGURED_OBSERVED:
        enforced_control_signals.append(SIGNAL_KEY_ROTATION_CONFIGURED)
    if context["authorization_boundary"] == BOUNDARY_SERVER_SIDE_OBSERVED:
        enforced_control_signals.append(
            SIGNAL_AUTHORIZATION_BOUNDARY_SERVER_SIDE
        )
    if context["session_lifecycle"] == SESSION_SERVER_SIDE_OBSERVED:
        enforced_control_signals.append(SIGNAL_SESSION_SERVER_SIDE)
    if context["token_storage"] in (
        STORAGE_SERVER_SIDE_OBSERVED,
        STORAGE_MEMORY_ONLY_OBSERVED,
    ):
        enforced_control_signals.append(SIGNAL_STORAGE_SERVER_SIDE)
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
                TYPE_MISSING_AUTHENTICATION_CONTEXT,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_MISSING_AUTHENTICATION_CONTEXT,
                    mechanism_signal,
                    token_mechanism_signal,
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
    "JWT_AUTHENTICATION_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "AUTH_MECHANISM_SIGNALS",
    "RATIONALE_TEXTS",
    "plan_jwt_authentication_hypotheses",
]

"""Stage R48.4 deterministic OAuth evidence planner.

Defines which research evidence would be required to evaluate the OAuth
hypotheses:

    "Which bounded OAuth evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no OAuth
  authorization/token/callback request, no redirect following, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or exchange, no state/nonce/PKCE manipulation, no credential
  testing, no payload, no execution, no secret extraction, no
  persistence. Nothing is queried, sent, exchanged or executed.
- Evidence items describe what would be relevant; they never instruct an
  attack and never generate bypass content.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning
  state and confidence are pure functions of the bounded context and
  hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.oauth_context_analyzer import (
    oauth_context_confidence_of,
)
from ai.knowledge.oauth_hypothesis_planner import plan_oauth_hypotheses
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.oauth_context_analysis import (
    sanitize_oauth_context_analysis_plan,
)
from ai.schemas.oauth_evidence_plan import (
    EVIDENCE_AUDIENCE_VALIDATION_POLICY,
    EVIDENCE_AUTHORIZATION_CODE_BINDING,
    EVIDENCE_AUTHORIZATION_CODE_LIFETIME,
    EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE,
    EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS,
    EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
    EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
    EVIDENCE_CLIENT_AUTHENTICATION_METHOD,
    EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
    EVIDENCE_CLIENT_TYPE,
    EVIDENCE_CONSENT_CONFIGURATION,
    EVIDENCE_CSRF_REQUEST_BINDING,
    EVIDENCE_GRANTED_SCOPES,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_LOGIN_CSRF_SESSION_BINDING,
    EVIDENCE_NONCE_VALIDATION_BEHAVIOR,
    EVIDENCE_PKCE_CHALLENGE_METHOD,
    EVIDENCE_PKCE_ENFORCEMENT_POLICY,
    EVIDENCE_PKCE_VERIFIER_VALIDATION,
    EVIDENCE_REDIRECT_HANDLING_CONFIGURATION,
    EVIDENCE_REDIRECT_URI_MATCHING_POLICY,
    EVIDENCE_REDIRECT_URI_REGISTRATION,
    EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR,
    EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION,
    EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY,
    EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY,
    EVIDENCE_REQUESTED_SCOPES,
    EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION,
    EVIDENCE_SCOPE_VALIDATION_POLICY,
    EVIDENCE_STATE_GENERATION,
    EVIDENCE_STATE_SESSION_BINDING,
    EVIDENCE_STATE_VALIDATION_BEHAVIOR,
    EVIDENCE_TOKEN_EXPOSURE_CONTEXT,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
    EVIDENCE_UNKNOWN,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_OAUTH_FLOW_EXECUTION,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_REDIRECT_FOLLOWING,
    LIMITATION_NO_TOKEN_EXCHANGE,
    OAUTH_EVIDENCE_PLAN_RULE_VERSION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    OAuthEvidencePlan,
    oauth_evidence_plan_projection,
)
from ai.schemas.oauth_hypothesis import (
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
    sanitize_oauth_hypothesis_plan,
)

OAUTH_EVIDENCE_PLANNER_RULE_VERSION = "r48-4"
RULE_VERSION = OAUTH_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_REDIRECT_URI_VALIDATION_GAP: (
        EVIDENCE_REDIRECT_URI_REGISTRATION,
        EVIDENCE_REDIRECT_URI_MATCHING_POLICY,
        EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR,
    ),
    TYPE_STATE_VALIDATION_GAP: (
        EVIDENCE_STATE_GENERATION,
        EVIDENCE_STATE_SESSION_BINDING,
        EVIDENCE_STATE_VALIDATION_BEHAVIOR,
    ),
    TYPE_NONCE_VALIDATION_GAP: (
        EVIDENCE_NONCE_VALIDATION_BEHAVIOR,
        EVIDENCE_STATE_SESSION_BINDING,
    ),
    TYPE_PKCE_ENFORCEMENT_GAP: (
        EVIDENCE_PKCE_ENFORCEMENT_POLICY,
        EVIDENCE_PKCE_CHALLENGE_METHOD,
    ),
    TYPE_PKCE_VERIFIER_VALIDATION_GAP: (
        EVIDENCE_PKCE_VERIFIER_VALIDATION,
        EVIDENCE_PKCE_CHALLENGE_METHOD,
    ),
    TYPE_AUTHORIZATION_CODE_VALIDATION_GAP: (
        EVIDENCE_AUTHORIZATION_CODE_BINDING,
        EVIDENCE_AUTHORIZATION_CODE_LIFETIME,
        EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE,
    ),
    TYPE_AUTHORIZATION_CODE_REUSE_GAP: (
        EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE,
        EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS,
    ),
    TYPE_AUTHORIZATION_CODE_LIFETIME_RISK: (
        EVIDENCE_AUTHORIZATION_CODE_LIFETIME,
        EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS,
    ),
    TYPE_CLIENT_AUTHENTICATION_GAP: (
        EVIDENCE_CLIENT_TYPE,
        EVIDENCE_CLIENT_AUTHENTICATION_METHOD,
        EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
    ),
    TYPE_CLIENT_CONFIGURATION_GAP: (
        EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
        EVIDENCE_REDIRECT_URI_REGISTRATION,
        EVIDENCE_CLIENT_TYPE,
    ),
    TYPE_SCOPE_VALIDATION_GAP: (
        EVIDENCE_REQUESTED_SCOPES,
        EVIDENCE_GRANTED_SCOPES,
        EVIDENCE_SCOPE_VALIDATION_POLICY,
    ),
    TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP: (
        EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION,
        EVIDENCE_AUDIENCE_VALIDATION_POLICY,
        EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
    ),
    TYPE_ISSUER_VALIDATION_GAP: (
        EVIDENCE_ISSUER_CONFIGURATION,
        EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
        EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
    ),
    TYPE_TOKEN_VALIDATION_GAP: (
        EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
        EVIDENCE_ISSUER_CONFIGURATION,
        EVIDENCE_AUDIENCE_VALIDATION_POLICY,
    ),
    TYPE_REFRESH_TOKEN_ROTATION_GAP: (
        EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY,
        EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION,
    ),
    TYPE_REFRESH_TOKEN_REVOCATION_GAP: (
        EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY,
        EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY,
    ),
    TYPE_CONSENT_CONTROL_GAP: (
        EVIDENCE_CONSENT_CONFIGURATION,
        EVIDENCE_REQUESTED_SCOPES,
    ),
    TYPE_CSRF_PROTECTION_GAP: (
        EVIDENCE_CSRF_REQUEST_BINDING,
        EVIDENCE_STATE_VALIDATION_BEHAVIOR,
        EVIDENCE_STATE_SESSION_BINDING,
    ),
    TYPE_LOGIN_CSRF_GAP: (
        EVIDENCE_LOGIN_CSRF_SESSION_BINDING,
        EVIDENCE_STATE_SESSION_BINDING,
        EVIDENCE_CSRF_REQUEST_BINDING,
    ),
    TYPE_REDIRECT_HANDLING_RISK: (
        EVIDENCE_REDIRECT_HANDLING_CONFIGURATION,
        EVIDENCE_REDIRECT_URI_MATCHING_POLICY,
        EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR,
    ),
    TYPE_IMPLICIT_FLOW_RISK: (
        EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
        EVIDENCE_TOKEN_STORAGE_MECHANISM,
        EVIDENCE_TOKEN_EXPOSURE_CONTEXT,
    ),
    TYPE_TOKEN_EXPOSURE_RISK: (
        EVIDENCE_TOKEN_STORAGE_MECHANISM,
        EVIDENCE_TOKEN_EXPOSURE_CONTEXT,
    ),
    TYPE_AUTHORIZATION_FLOW_GAP: (
        EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
        EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
        EVIDENCE_CLIENT_TYPE,
    ),
    TYPE_AUTHENTICATION_CONTROL_PRESENT: (
        EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
        EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
        EVIDENCE_STATE_VALIDATION_BEHAVIOR,
    ),
    TYPE_MISSING_OAUTH_CONTEXT: (
        EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
        EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
        EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
    ),
    TYPE_UNKNOWN: (EVIDENCE_UNKNOWN,),
}


def _hypotheses(value: object) -> list[dict]:
    if isinstance(value, dict):
        raw = [value]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raw = []
    return [
        sanitize_oauth_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_oauth_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis
    evidence mappings. The planning state is ``UNKNOWN`` when nothing can
    be planned and ``COMPLETE`` only when the supplied context is HIGH
    confidence, no ``UNKNOWN`` hypothesis remains, and at least one
    substantive (non missing-context) hypothesis is present. A context that
    only degrades to ``MISSING_OAUTH_CONTEXT`` can never be ``COMPLETE``.
    Otherwise the state is ``PARTIAL``. No evidence is collected and no
    network, OAuth flow, redirect or token activity occurs.
    """

    context = sanitize_oauth_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_oauth_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    substantive_plans = [
        plan
        for plan in plans
        if plan["hypothesis_type"]
        not in (TYPE_UNKNOWN, TYPE_MISSING_OAUTH_CONTEXT)
    ]
    context_confidence = oauth_context_confidence_of(context)
    if not plans or items == [EVIDENCE_UNKNOWN]:
        state = STATE_UNKNOWN
    elif (
        context_confidence == CONFIDENCE_HIGH
        and substantive_plans
        and all(
            plan["hypothesis_type"] != TYPE_UNKNOWN for plan in plans
        )
    ):
        state = STATE_COMPLETE
    else:
        state = STATE_PARTIAL

    if state == STATE_UNKNOWN:
        confidence = CONFIDENCE_UNKNOWN
    elif state == STATE_COMPLETE:
        confidence = CONFIDENCE_HIGH
    else:
        confidence = (
            CONFIDENCE_UNKNOWN
            if context_confidence == CONFIDENCE_UNKNOWN
            else CONFIDENCE_LOW
        )

    limitations = [
        LIMITATION_NO_COLLECTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_OAUTH_FLOW_EXECUTION,
        LIMITATION_NO_TOKEN_EXCHANGE,
        LIMITATION_NO_REDIRECT_FOLLOWING,
        LIMITATION_NO_CREDENTIAL_TESTING,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = OAuthEvidencePlan(
        rule_version=OAUTH_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return oauth_evidence_plan_projection(plan)


__all__ = [
    "OAUTH_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_oauth_evidence",
]

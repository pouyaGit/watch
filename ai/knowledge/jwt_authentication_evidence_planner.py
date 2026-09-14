"""Stage R47.4 deterministic JWT/authentication evidence planner.

Defines which research evidence would be required to evaluate the
JWT/authentication hypotheses:

    "Which bounded authentication/validation evidence categories would this
     research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or manipulation, no token forgery, no signature bypass, no
  authentication bypass, no brute force, no credential testing, no payload,
  no execution, no secret extraction, no persistence. Nothing is queried,
  sent, forged, bypassed or executed.
- Evidence items describe what would be relevant; they never instruct an
  attack and never generate bypass content.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning state
  and confidence are pure functions of the bounded context and hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.jwt_authentication_context_analyzer import (
    jwt_authentication_context_confidence_of,
)
from ai.knowledge.jwt_authentication_hypothesis_planner import (
    plan_jwt_authentication_hypotheses,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.jwt_authentication_context_analysis import (
    sanitize_jwt_authentication_context_analysis_plan,
)
from ai.schemas.jwt_authentication_evidence_plan import (
    EVIDENCE_ALGORITHM_ACCEPTANCE_RULES,
    EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR,
    EVIDENCE_AUDIENCE_CONFIGURATION,
    EVIDENCE_AUDIENCE_VALIDATION_RULES,
    EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
    EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION,
    EVIDENCE_CLAIM_VALIDATION_RULES,
    EVIDENCE_COOKIE_SECURITY_ATTRIBUTES,
    EVIDENCE_EXPIRATION_POLICY,
    EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_ISSUER_VALIDATION_RULES,
    EVIDENCE_KEY_MANAGEMENT_CONFIGURATION,
    EVIDENCE_KEY_ROTATION_POLICY,
    EVIDENCE_NOT_BEFORE_POLICY,
    EVIDENCE_NOT_BEFORE_VALIDATION_BEHAVIOR,
    EVIDENCE_REFRESH_CONTROL_CONFIGURATION,
    EVIDENCE_REVOCATION_CONFIGURATION,
    EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION,
    EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR,
    EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
    EVIDENCE_TOKEN_LIFETIME_POLICY,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_UNKNOWN,
    EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_AUTHENTICATION_BYPASS,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SIGNATURE_BYPASS,
    LIMITATION_NO_TOKEN_MANIPULATION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    JWTAuthenticationEvidencePlan,
    jwt_authentication_evidence_plan_projection,
)
from ai.schemas.jwt_authentication_hypothesis import (
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
    sanitize_jwt_authentication_hypothesis_plan,
)

JWT_AUTHENTICATION_EVIDENCE_PLANNER_RULE_VERSION = "r47-4"
RULE_VERSION = JWT_AUTHENTICATION_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_SIGNATURE_VERIFICATION_GAP: (
        EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
        EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_ALGORITHM_VALIDATION_GAP: (
        EVIDENCE_ALGORITHM_ACCEPTANCE_RULES,
        EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_ISSUER_VALIDATION_GAP: (
        EVIDENCE_ISSUER_CONFIGURATION,
        EVIDENCE_ISSUER_VALIDATION_RULES,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_AUDIENCE_VALIDATION_GAP: (
        EVIDENCE_AUDIENCE_CONFIGURATION,
        EVIDENCE_AUDIENCE_VALIDATION_RULES,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_EXPIRATION_VALIDATION_GAP: (
        EVIDENCE_EXPIRATION_POLICY,
        EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR,
        EVIDENCE_TOKEN_LIFETIME_POLICY,
    ),
    TYPE_NOT_BEFORE_VALIDATION_GAP: (
        EVIDENCE_NOT_BEFORE_POLICY,
        EVIDENCE_NOT_BEFORE_VALIDATION_BEHAVIOR,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_CLAIM_VALIDATION_GAP: (
        EVIDENCE_CLAIM_VALIDATION_RULES,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_JWT_VALIDATION_GAP: (
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
        EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
        EVIDENCE_ISSUER_CONFIGURATION,
        EVIDENCE_AUDIENCE_CONFIGURATION,
        EVIDENCE_EXPIRATION_POLICY,
    ),
    TYPE_KEY_MANAGEMENT_GAP: (
        EVIDENCE_KEY_MANAGEMENT_CONFIGURATION,
        EVIDENCE_KEY_ROTATION_POLICY,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_TOKEN_LIFETIME_RISK: (
        EVIDENCE_TOKEN_LIFETIME_POLICY,
        EVIDENCE_EXPIRATION_POLICY,
    ),
    TYPE_TOKEN_STORAGE_RISK: (
        EVIDENCE_TOKEN_STORAGE_MECHANISM,
        EVIDENCE_COOKIE_SECURITY_ATTRIBUTES,
    ),
    TYPE_TOKEN_REVOCATION_GAP: (
        EVIDENCE_REVOCATION_CONFIGURATION,
        EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION,
    ),
    TYPE_REFRESH_TOKEN_CONTROL_GAP: (
        EVIDENCE_REFRESH_CONTROL_CONFIGURATION,
        EVIDENCE_REVOCATION_CONFIGURATION,
    ),
    TYPE_SESSION_MANAGEMENT_GAP: (
        EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION,
        EVIDENCE_TOKEN_STORAGE_MECHANISM,
        EVIDENCE_REVOCATION_CONFIGURATION,
    ),
    TYPE_AUTHENTICATION_FLOW_GAP: (
        EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION,
        EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
    ),
    TYPE_AUTHENTICATION_CONTROL_PRESENT: (
        EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
        EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    ),
    TYPE_MISSING_AUTHENTICATION_CONTEXT: (
        EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION,
        EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
        EVIDENCE_TOKEN_STORAGE_MECHANISM,
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
        sanitize_jwt_authentication_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_jwt_authentication_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis evidence
    mappings. The planning state is ``UNKNOWN`` when nothing can be planned
    and ``COMPLETE`` only when the supplied context is HIGH confidence, no
    ``UNKNOWN`` hypothesis remains, and at least one substantive (non
    missing-context) hypothesis is present. A context that only degrades to
    ``MISSING_AUTHENTICATION_CONTEXT`` can never be ``COMPLETE`` where a
    weakness signal was observed without an authentication context. Otherwise
    the state is ``PARTIAL``. No evidence is collected and no network, token
    or target activity occurs.
    """

    context = sanitize_jwt_authentication_context_analysis_plan(
        context_analysis
    )
    if hypotheses is None:
        plans = _hypotheses(plan_jwt_authentication_hypotheses(context))
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
        not in (TYPE_UNKNOWN, TYPE_MISSING_AUTHENTICATION_CONTEXT)
    ]
    context_confidence = jwt_authentication_context_confidence_of(context)
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
        LIMITATION_NO_TOKEN_MANIPULATION,
        LIMITATION_NO_SIGNATURE_BYPASS,
        LIMITATION_NO_AUTHENTICATION_BYPASS,
        LIMITATION_NO_CREDENTIAL_TESTING,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = JWTAuthenticationEvidencePlan(
        rule_version=JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return jwt_authentication_evidence_plan_projection(plan)


__all__ = [
    "JWT_AUTHENTICATION_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_jwt_authentication_evidence",
]

"""Stage R40.4 deterministic SSRF evidence planner (pure engine).

Defines which research evidence would be required to evaluate the SSRF
hypotheses:

    "Which bounded evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/network request, no DNS
  resolution, no localhost/private-IP connection, no port scan, no URL
  probing, no payload execution, no metadata access, no persistence.
  Nothing is fetched, resolved, sent or executed.
- Pure and offline: no I/O, no network, no DNS, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning
  state and confidence are pure functions of the bounded context and
  hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.ssrf_context_analyzer import (
    ssrf_context_confidence_of,
)
from ai.knowledge.ssrf_hypothesis_planner import plan_ssrf_hypotheses
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.ssrf_context_analysis import (
    sanitize_ssrf_context_analysis_plan,
)
from ai.schemas.ssrf_evidence_plan import (
    EVIDENCE_APPLICATION_BEHAVIOR,
    EVIDENCE_CLOUD_BOUNDARY_CONTEXT,
    EVIDENCE_DESTINATION_RESTRICTION,
    EVIDENCE_DNS_RESOLUTION_BEHAVIOR,
    EVIDENCE_HOST_VALIDATION,
    EVIDENCE_IP_RANGE_VALIDATION,
    EVIDENCE_PROTOCOL_RESTRICTION,
    EVIDENCE_REDIRECT_POLICY,
    EVIDENCE_SERVER_FETCH_BEHAVIOR,
    EVIDENCE_UNKNOWN,
    EVIDENCE_URL_PARSING_CONTEXT,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_DNS_RESOLUTION,
    LIMITATION_NO_NETWORK_REQUESTS,
    SSRF_EVIDENCE_PLAN_RULE_VERSION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    SSRFEvidencePlan,
    ssrf_evidence_plan_projection,
)
from ai.schemas.ssrf_hypothesis import (
    TYPE_CLOUD_METADATA_BOUNDARY_REVIEW,
    TYPE_DNS_REBINDING_REVIEW,
    TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW,
    TYPE_IP_VALIDATION_REVIEW,
    TYPE_PROTOCOL_HANDLING_REVIEW,
    TYPE_REDIRECT_HANDLING_REVIEW,
    TYPE_SERVER_SIDE_FETCH_ANALYSIS,
    TYPE_UNKNOWN,
    TYPE_URL_VALIDATION_REVIEW,
    TYPE_WEBHOOK_FETCH_REVIEW,
    sanitize_ssrf_hypothesis_plan,
)

SSRF_EVIDENCE_PLANNER_RULE_VERSION = "r40-4"
RULE_VERSION = SSRF_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_SERVER_SIDE_FETCH_ANALYSIS: (
        EVIDENCE_SERVER_FETCH_BEHAVIOR,
        EVIDENCE_APPLICATION_BEHAVIOR,
    ),
    TYPE_URL_VALIDATION_REVIEW: (
        EVIDENCE_URL_PARSING_CONTEXT,
        EVIDENCE_HOST_VALIDATION,
    ),
    TYPE_IP_VALIDATION_REVIEW: (
        EVIDENCE_IP_RANGE_VALIDATION,
    ),
    TYPE_REDIRECT_HANDLING_REVIEW: (
        EVIDENCE_REDIRECT_POLICY,
    ),
    TYPE_PROTOCOL_HANDLING_REVIEW: (
        EVIDENCE_PROTOCOL_RESTRICTION,
    ),
    TYPE_DNS_REBINDING_REVIEW: (
        EVIDENCE_DNS_RESOLUTION_BEHAVIOR,
        EVIDENCE_HOST_VALIDATION,
    ),
    TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW: (
        EVIDENCE_IP_RANGE_VALIDATION,
        EVIDENCE_DESTINATION_RESTRICTION,
    ),
    TYPE_CLOUD_METADATA_BOUNDARY_REVIEW: (
        EVIDENCE_CLOUD_BOUNDARY_CONTEXT,
        EVIDENCE_DESTINATION_RESTRICTION,
    ),
    TYPE_WEBHOOK_FETCH_REVIEW: (
        EVIDENCE_APPLICATION_BEHAVIOR,
        EVIDENCE_URL_PARSING_CONTEXT,
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
        sanitize_ssrf_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_ssrf_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis evidence
    mappings. The planning state is ``UNKNOWN`` when nothing can be planned,
    ``COMPLETE`` only when the observed context is HIGH confidence and every
    hypothesis is at least MEDIUM and not ``UNKNOWN``, and ``PARTIAL``
    otherwise. No evidence is collected and no network/DNS activity occurs.
    """

    context = sanitize_ssrf_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_ssrf_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    context_confidence = ssrf_context_confidence_of(context)
    if not plans or items == [EVIDENCE_UNKNOWN]:
        state = STATE_UNKNOWN
    elif (
        context_confidence == CONFIDENCE_HIGH
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
        LIMITATION_NO_DNS_RESOLUTION,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = SSRFEvidencePlan(
        rule_version=SSRF_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return ssrf_evidence_plan_projection(plan)


__all__ = [
    "SSRF_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_ssrf_evidence",
]

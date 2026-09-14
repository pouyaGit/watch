"""Stage R46.4 deterministic IDOR/BOLA evidence planner (pure engine).

Defines which research evidence would be required to evaluate the IDOR/BOLA
hypotheses:

    "Which bounded authorization evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP request, no DNS resolution,
  no socket, no database, no scanner, no browser, no object access, no
  authorization bypass, no payload, no execution, no persistence. Nothing is
  queried, sent, bypassed or executed.
- Evidence items describe what would be relevant; they never instruct an
  attack and never generate bypass content.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning state
  and confidence are pure functions of the bounded context and hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.idor_bola_context_analyzer import (
    idor_bola_context_confidence_of,
)
from ai.knowledge.idor_bola_hypothesis_planner import (
    plan_idor_bola_hypotheses,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.idor_bola_context_analysis import (
    sanitize_idor_bola_context_analysis_plan,
)
from ai.schemas.idor_bola_evidence_plan import (
    EVIDENCE_ACCESS_CONTROL_POLICY,
    EVIDENCE_AUTHORIZATION_CONTROL,
    EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
    EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
    EVIDENCE_OBJECT_LOOKUP_CONTEXT,
    EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
    EVIDENCE_OWNERSHIP_RELATIONSHIP,
    EVIDENCE_ROLE_DEFINITION,
    EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
    EVIDENCE_SERVER_SIDE_AUTHORIZATION,
    EVIDENCE_TENANT_BOUNDARY,
    EVIDENCE_UNKNOWN,
    IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_AUTHORIZATION_BYPASS,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    IDORBOLAEvidencePlan,
    idor_bola_evidence_plan_projection,
)
from ai.schemas.idor_bola_hypothesis import (
    TYPE_AUTHORIZATION_CONTROL_PRESENT,
    TYPE_DIRECT_OBJECT_REFERENCE,
    TYPE_MISSING_AUTHORIZATION_CONTEXT,
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
    TYPE_OWNERSHIP_BOUNDARY_GAP,
    TYPE_ROLE_BOUNDARY_GAP,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_UNKNOWN,
    sanitize_idor_bola_hypothesis_plan,
)

IDOR_BOLA_EVIDENCE_PLANNER_RULE_VERSION = "r46-4"
RULE_VERSION = IDOR_BOLA_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP: (
        EVIDENCE_AUTHORIZATION_CONTROL,
        EVIDENCE_OWNERSHIP_RELATIONSHIP,
        EVIDENCE_OBJECT_LOOKUP_CONTEXT,
        EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
    ),
    TYPE_OWNERSHIP_BOUNDARY_GAP: (
        EVIDENCE_OWNERSHIP_RELATIONSHIP,
        EVIDENCE_AUTHORIZATION_CONTROL,
        EVIDENCE_SERVER_SIDE_AUTHORIZATION,
        EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
    ),
    TYPE_TENANT_ISOLATION_GAP: (
        EVIDENCE_TENANT_BOUNDARY,
        EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
        EVIDENCE_SERVER_SIDE_AUTHORIZATION,
        EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
    ),
    TYPE_ROLE_BOUNDARY_GAP: (
        EVIDENCE_ROLE_DEFINITION,
        EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
        EVIDENCE_SERVER_SIDE_AUTHORIZATION,
        EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
    ),
    TYPE_DIRECT_OBJECT_REFERENCE: (
        EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
        EVIDENCE_AUTHORIZATION_CONTROL,
        EVIDENCE_OBJECT_LOOKUP_CONTEXT,
    ),
    TYPE_MISSING_AUTHORIZATION_CONTEXT: (
        EVIDENCE_AUTHORIZATION_CONTROL,
        EVIDENCE_ACCESS_CONTROL_POLICY,
        EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
    ),
    TYPE_AUTHORIZATION_CONTROL_PRESENT: (
        EVIDENCE_AUTHORIZATION_CONTROL,
        EVIDENCE_ACCESS_CONTROL_POLICY,
        EVIDENCE_OWNERSHIP_RELATIONSHIP,
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
        sanitize_idor_bola_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_idor_bola_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis evidence
    mappings. The planning state is ``UNKNOWN`` when nothing can be planned,
    ``COMPLETE`` only when the supplied context is HIGH confidence and no
    ``UNKNOWN`` hypothesis remains, and ``PARTIAL`` otherwise. No evidence is
    collected and no network, database or target activity occurs.
    """

    context = sanitize_idor_bola_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_idor_bola_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    context_confidence = idor_bola_context_confidence_of(context)
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
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_AUTHORIZATION_BYPASS,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = IDORBOLAEvidencePlan(
        rule_version=IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return idor_bola_evidence_plan_projection(plan)


__all__ = [
    "IDOR_BOLA_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_idor_bola_evidence",
]

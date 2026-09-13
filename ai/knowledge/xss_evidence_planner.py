"""Stage R39.4 deterministic XSS evidence planner (pure engine).

Defines which research evidence would be required to evaluate the XSS
hypotheses:

    "Which bounded evidence items would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP request, no payload, no
  execution, no browser/JavaScript, no fuzzing, no exploitation, no
  persistence. Nothing is fetched, sent or executed.
- Pure and offline: no I/O, no network, no LLM, no browser, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence items, planning state and
  confidence are pure functions of the bounded context and hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.xss_context_analyzer import context_confidence_of
from ai.knowledge.xss_hypothesis_planner import plan_xss_hypotheses
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.xss_context_analysis import (
    sanitize_xss_context_analysis_plan,
)
from ai.schemas.xss_evidence_plan import (
    EVIDENCE_APPLICATION_BEHAVIOR,
    EVIDENCE_OUTPUT_ENCODING_CONTEXT,
    EVIDENCE_REFLECTION_CONTEXT,
    EVIDENCE_SINK_CONTEXT,
    EVIDENCE_SOURCE_CONTEXT,
    EVIDENCE_UNKNOWN,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    XSS_EVIDENCE_PLAN_RULE_VERSION,
    XSSEvidencePlan,
    xss_evidence_plan_projection,
)
from ai.schemas.xss_hypothesis import (
    TYPE_CONTEXT_REVIEW,
    TYPE_DOM_FLOW_ANALYSIS,
    TYPE_REFLECTION_ANALYSIS,
    TYPE_STORAGE_FLOW_ANALYSIS,
    TYPE_UNKNOWN,
    sanitize_xss_hypothesis_plan,
)

XSS_EVIDENCE_PLANNER_RULE_VERSION = "r39-4"
RULE_VERSION = XSS_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence items (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_REFLECTION_ANALYSIS: (
        EVIDENCE_REFLECTION_CONTEXT,
        EVIDENCE_OUTPUT_ENCODING_CONTEXT,
    ),
    TYPE_DOM_FLOW_ANALYSIS: (
        EVIDENCE_SOURCE_CONTEXT,
        EVIDENCE_SINK_CONTEXT,
    ),
    TYPE_STORAGE_FLOW_ANALYSIS: (
        EVIDENCE_APPLICATION_BEHAVIOR,
        EVIDENCE_REFLECTION_CONTEXT,
    ),
    TYPE_CONTEXT_REVIEW: (
        EVIDENCE_OUTPUT_ENCODING_CONTEXT,
        EVIDENCE_SINK_CONTEXT,
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
        sanitize_xss_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_xss_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required items are the ordered union of the per-hypothesis evidence
    mappings. The planning state is ``UNKNOWN`` when nothing can be
    planned, ``COMPLETE`` when the context is high-confidence and every
    hypothesis is at least medium-confidence, and ``PARTIAL`` otherwise.
    No evidence is collected.
    """

    context = sanitize_xss_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_xss_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    if not plans or items == [EVIDENCE_UNKNOWN]:
        state = STATE_UNKNOWN
    elif (
        context_confidence_of(context) == CONFIDENCE_HIGH
        and all(
            plan["confidence"] in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)
            and plan["hypothesis_type"] != TYPE_UNKNOWN
            for plan in plans
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
            if context_confidence_of(context) == CONFIDENCE_UNKNOWN
            else CONFIDENCE_LOW
        )

    limitations = [
        LIMITATION_NO_COLLECTION_PERFORMED,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = XSSEvidencePlan(
        rule_version=XSS_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return xss_evidence_plan_projection(plan)


__all__ = [
    "XSS_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_xss_evidence",
]

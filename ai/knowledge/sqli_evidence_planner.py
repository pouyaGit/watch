"""Stage R41.4 deterministic SQLi evidence planner (pure engine).

Defines which research evidence would be required to evaluate the SQLi
hypotheses:

    "Which bounded evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no SQL execution, no database
  connection, no HTTP/network request, no payload, no fuzzing, no parameter
  brute forcing, no sqlmap, no persistence. Nothing is queried, sent or
  executed.
- Pure and offline: no I/O, no SQL, no network, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning
  state and confidence are pure functions of the bounded context and
  hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.sqli_context_analyzer import (
    sqli_context_confidence_of,
)
from ai.knowledge.sqli_hypothesis_planner import plan_sqli_hypotheses
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.sqli_context_analysis import (
    sanitize_sqli_context_analysis_plan,
)
from ai.schemas.sqli_evidence_plan import (
    EVIDENCE_APPLICATION_BEHAVIOR,
    EVIDENCE_BOOLEAN_BEHAVIOR,
    EVIDENCE_DATABASE_CONTEXT,
    EVIDENCE_ERROR_BEHAVIOR,
    EVIDENCE_IDENTIFIER_CONTEXT,
    EVIDENCE_INPUT_VALIDATION,
    EVIDENCE_ORM_QUERY_CONTEXT,
    EVIDENCE_ORDER_BY_CONTEXT,
    EVIDENCE_PARAMETERIZATION,
    EVIDENCE_QUERY_CONSTRUCTION,
    EVIDENCE_RAW_QUERY_CONTEXT,
    EVIDENCE_STORED_PROCEDURE_CONTEXT,
    EVIDENCE_TIMING_BEHAVIOR,
    EVIDENCE_TYPE_HANDLING,
    EVIDENCE_UNKNOWN,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SQL_EXECUTION,
    SQLI_EVIDENCE_PLAN_RULE_VERSION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    SQLIEvidencePlan,
    sqli_evidence_plan_projection,
)
from ai.schemas.sqli_hypothesis import (
    TYPE_BOOLEAN_DIFFERENTIAL_REVIEW,
    TYPE_DATABASE_SPECIFIC_REVIEW,
    TYPE_ERROR_SIGNAL_REVIEW,
    TYPE_IDENTIFIER_HANDLING_REVIEW,
    TYPE_INPUT_HANDLING_REVIEW,
    TYPE_ORM_QUERY_REVIEW,
    TYPE_ORDER_BY_INJECTION_REVIEW,
    TYPE_PARAMETERIZATION_REVIEW,
    TYPE_QUERY_CONSTRUCTION_REVIEW,
    TYPE_RAW_QUERY_REVIEW,
    TYPE_STORED_PROCEDURE_REVIEW,
    TYPE_TIMING_SIGNAL_REVIEW,
    TYPE_TYPE_HANDLING_REVIEW,
    TYPE_UNKNOWN,
    sanitize_sqli_hypothesis_plan,
)

SQLI_EVIDENCE_PLANNER_RULE_VERSION = "r41-4"
RULE_VERSION = SQLI_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_QUERY_CONSTRUCTION_REVIEW: (
        EVIDENCE_QUERY_CONSTRUCTION,
        EVIDENCE_APPLICATION_BEHAVIOR,
    ),
    TYPE_PARAMETERIZATION_REVIEW: (
        EVIDENCE_PARAMETERIZATION,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_INPUT_HANDLING_REVIEW: (
        EVIDENCE_INPUT_VALIDATION,
        EVIDENCE_PARAMETERIZATION,
    ),
    TYPE_TYPE_HANDLING_REVIEW: (
        EVIDENCE_TYPE_HANDLING,
    ),
    TYPE_ORM_QUERY_REVIEW: (
        EVIDENCE_ORM_QUERY_CONTEXT,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_RAW_QUERY_REVIEW: (
        EVIDENCE_RAW_QUERY_CONTEXT,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_ERROR_SIGNAL_REVIEW: (
        EVIDENCE_ERROR_BEHAVIOR,
        EVIDENCE_APPLICATION_BEHAVIOR,
    ),
    TYPE_BOOLEAN_DIFFERENTIAL_REVIEW: (
        EVIDENCE_BOOLEAN_BEHAVIOR,
        EVIDENCE_APPLICATION_BEHAVIOR,
    ),
    TYPE_TIMING_SIGNAL_REVIEW: (
        EVIDENCE_TIMING_BEHAVIOR,
        EVIDENCE_APPLICATION_BEHAVIOR,
    ),
    TYPE_ORDER_BY_INJECTION_REVIEW: (
        EVIDENCE_ORDER_BY_CONTEXT,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_IDENTIFIER_HANDLING_REVIEW: (
        EVIDENCE_IDENTIFIER_CONTEXT,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_STORED_PROCEDURE_REVIEW: (
        EVIDENCE_STORED_PROCEDURE_CONTEXT,
        EVIDENCE_QUERY_CONSTRUCTION,
    ),
    TYPE_DATABASE_SPECIFIC_REVIEW: (
        EVIDENCE_DATABASE_CONTEXT,
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
        sanitize_sqli_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_sqli_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis evidence
    mappings. The planning state is ``UNKNOWN`` when nothing can be planned,
    ``COMPLETE`` only when the observed context is HIGH confidence and no
    ``UNKNOWN`` hypothesis remains, and ``PARTIAL`` otherwise. No evidence
    is collected and no SQL or network activity occurs.
    """

    context = sanitize_sqli_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_sqli_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    context_confidence = sqli_context_confidence_of(context)
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
        LIMITATION_NO_SQL_EXECUTION,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = SQLIEvidencePlan(
        rule_version=SQLI_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return sqli_evidence_plan_projection(plan)


__all__ = [
    "SQLI_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_sqli_evidence",
]

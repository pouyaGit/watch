"""Stage R41.2 deterministic SQLi context analyzer (pure engine).

Classifies SQL-injection-relevant research context from bounded observations:

    "Is there SQLi-relevant input, and was unsafe query construction
     evidence observed?"

Hard boundaries encoded here:

- Research intelligence only: no SQL execution, no database connection, no
  HTTP/network request, no payload, no fuzzing, no parameter brute forcing,
  no browser, no socket, no subprocess, no sqlmap. Nothing is performed.
- A parameter, a search box, a database or an ORM is NOT evidence of SQLi.
  The analyzer distinguishes SQLi-relevant input from observed unsafe query
  construction evidence, and confidence is capped unless construction
  evidence is present.
- Confidence means "how complete/relevant is the supplied SQLi research
  context?". It does NOT mean "probability that SQLi exists". No
  vulnerability is confirmed.
- Pure and offline: no I/O, no SQL, no network, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.sqli_context_analysis import (
    BEHAVIORAL_SIGNALS,
    DATABASE_CONTEXTS,
    DATA_FLOWS,
    DB_UNKNOWN,
    ERROR_BEHAVIORS,
    ERROR_UNKNOWN,
    FLOW_RAW_QUERY,
    FLOW_UNKNOWN,
    HANDLING_CONCATENATED,
    HANDLING_PARAMETERIZED,
    HANDLING_RAW,
    HANDLING_UNKNOWN,
    INPUT_HANDLING_STATES,
    INPUT_LOCATIONS,
    INPUT_UNKNOWN,
    PARAM_UNKNOWN,
    PARAMETER_TYPES,
    QCTX_UNKNOWN,
    QUERY_CONTEXTS,
    SIGNAL_UNKNOWN,
    SQLI_CONTEXT_ANALYSIS_RULE_VERSION,
    SQLIContextAnalysisPlan,
    TYPE_HANDLING_STATES,
    TYPE_UNKNOWN,
    sanitize_sqli_context_analysis_plan,
    sqli_context_analysis_plan_projection,
)

SQLI_CONTEXT_ANALYZER_RULE_VERSION = "r41-2"
RULE_VERSION = SQLI_CONTEXT_ANALYZER_RULE_VERSION

KNOWN_FIELDS: tuple[str, ...] = (
    "input_location",
    "parameter_type",
    "data_flow",
    "query_context",
    "database_context",
    "input_handling",
    "type_handling",
    "error_behavior",
    "behavioral_signal",
)

UNKNOWN_VALUES: tuple[str, ...] = (
    INPUT_UNKNOWN,
    PARAM_UNKNOWN,
    FLOW_UNKNOWN,
    QCTX_UNKNOWN,
    DB_UNKNOWN,
    HANDLING_UNKNOWN,
    TYPE_UNKNOWN,
    ERROR_UNKNOWN,
    SIGNAL_UNKNOWN,
)

STRONG_CONSTRUCTION_HANDLING: tuple[str, ...] = (
    HANDLING_CONCATENATED,
    HANDLING_RAW,
)

_CONFIDENCE_ORDER: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _base_confidence(known_count: int) -> str:
    if known_count >= 8:
        return CONFIDENCE_HIGH
    if known_count >= 5:
        return CONFIDENCE_MEDIUM
    if known_count >= 2:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def _cap(confidence: str, ceiling: str) -> str:
    if _CONFIDENCE_ORDER[confidence] <= _CONFIDENCE_ORDER[ceiling]:
        return confidence
    return ceiling


def _strong_construction(handling: str, flow: str) -> bool:
    return (
        handling in STRONG_CONSTRUCTION_HANDLING
        or flow == FLOW_RAW_QUERY
    )


def _confidence_for(handling: str, flow: str, known_count: int) -> str:
    confidence = _base_confidence(known_count)
    if not _strong_construction(handling, flow):
        confidence = _cap(confidence, CONFIDENCE_MEDIUM)
    return confidence


def analyze_sqli_context(
    input_location: object = None,
    parameter_type: object = None,
    data_flow: object = None,
    query_context: object = None,
    database_context: object = None,
    input_handling: object = None,
    type_handling: object = None,
    error_behavior: object = None,
    behavioral_signal: object = None,
) -> dict:
    """Build the deterministic descriptive SQLi context analysis.

    Confidence is a pure function of supplied facts with a hard safety cap:
    unless unsafe query construction evidence (``CONCATENATED``/``RAW``
    handling or ``RAW_QUERY`` flow) was observed, confidence can never exceed
    MEDIUM. A parameter alone, a database type alone, or an ORM alone can
    never produce HIGH confidence.
    """

    resolved_input = _closed(input_location, INPUT_LOCATIONS, INPUT_UNKNOWN)
    resolved_parameter = _closed(
        parameter_type, PARAMETER_TYPES, PARAM_UNKNOWN
    )
    resolved_flow = _closed(data_flow, DATA_FLOWS, FLOW_UNKNOWN)
    resolved_query = _closed(query_context, QUERY_CONTEXTS, QCTX_UNKNOWN)
    resolved_database = _closed(
        database_context, DATABASE_CONTEXTS, DB_UNKNOWN
    )
    resolved_handling = _closed(
        input_handling, INPUT_HANDLING_STATES, HANDLING_UNKNOWN
    )
    resolved_type = _closed(
        type_handling, TYPE_HANDLING_STATES, TYPE_UNKNOWN
    )
    resolved_error = _closed(
        error_behavior, ERROR_BEHAVIORS, ERROR_UNKNOWN
    )
    resolved_signal = _closed(
        behavioral_signal, BEHAVIORAL_SIGNALS, SIGNAL_UNKNOWN
    )

    values = (
        resolved_input,
        resolved_parameter,
        resolved_flow,
        resolved_query,
        resolved_database,
        resolved_handling,
        resolved_type,
        resolved_error,
        resolved_signal,
    )
    known_count = sum(1 for value in values if value not in UNKNOWN_VALUES)
    confidence = _confidence_for(
        resolved_handling, resolved_flow, known_count
    )

    plan = SQLIContextAnalysisPlan(
        rule_version=SQLI_CONTEXT_ANALYSIS_RULE_VERSION,
        input_location=resolved_input,
        parameter_type=resolved_parameter,
        data_flow=resolved_flow,
        query_context=resolved_query,
        database_context=resolved_database,
        input_handling=resolved_handling,
        type_handling=resolved_type,
        error_behavior=resolved_error,
        behavioral_signal=resolved_signal,
        context_confidence=confidence,
        research_only=True,
    )
    return sqli_context_analysis_plan_projection(plan)


def sqli_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so partial
    context dicts supplied directly to downstream planners receive the
    correct, safety-capped confidence.
    """

    plan = sanitize_sqli_context_analysis_plan(value)
    known_count = sum(
        1 for key in KNOWN_FIELDS if plan[key] not in UNKNOWN_VALUES
    )
    return _confidence_for(
        plan["input_handling"], plan["data_flow"], known_count
    )


def strong_construction_observed(value: object) -> bool:
    """True only when unsafe query construction evidence was observed.

    This is deliberately stronger than "a parameter exists": it requires
    ``CONCATENATED``/``RAW`` input handling or a ``RAW_QUERY`` data flow.
    """

    plan = sanitize_sqli_context_analysis_plan(value)
    return _strong_construction(
        plan["input_handling"], plan["data_flow"]
    )


def parameterization_observed(value: object) -> bool:
    """True only when parameterized input handling was observed."""

    plan = sanitize_sqli_context_analysis_plan(value)
    return plan["input_handling"] == HANDLING_PARAMETERIZED


def sqli_input_possible(value: object) -> bool:
    """True when there is SQLi-relevant input context.

    This is deliberately weaker than :func:`strong_construction_observed`:
    an input location or parameter type indicates a candidate input, not
    unsafe query construction.
    """

    plan = sanitize_sqli_context_analysis_plan(value)
    return (
        plan["input_location"] != INPUT_UNKNOWN
        or plan["parameter_type"] != PARAM_UNKNOWN
    )


__all__ = [
    "SQLI_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "KNOWN_FIELDS",
    "UNKNOWN_VALUES",
    "STRONG_CONSTRUCTION_HANDLING",
    "analyze_sqli_context",
    "sqli_context_confidence_of",
    "strong_construction_observed",
    "parameterization_observed",
    "sqli_input_possible",
]

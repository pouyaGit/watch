"""Stage R41.3 deterministic SQLi hypothesis planner (pure engine).

Creates deterministic research hypotheses from observed SQLi context:

    "Which SQLi review hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no SQL payload, no executable injection string, no database command, no
  exploitation instruction, no SQL/database/network execution.
- Pure and offline: no I/O, no SQL, no network, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, signals, confidence,
  priority and limitations are pure functions of the bounded context.
- Unsafe construction is never claimed from a parameter, database or ORM
  alone; hypotheses remain research-only review items.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.sqli_context_analyzer import (
    sqli_context_confidence_of,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.sqli_context_analysis import (
    DB_UNKNOWN,
    FLOW_ORM,
    FLOW_RAW_QUERY,
    FLOW_STORED_PROCEDURE,
    HANDLING_CONCATENATED,
    HANDLING_ESCAPED,
    HANDLING_PARAMETERIZED,
    HANDLING_RAW,
    HANDLING_SANITIZED,
    INPUT_BODY,
    INPUT_COOKIE,
    INPUT_HEADER,
    INPUT_PATH,
    INPUT_QUERY,
    PARAM_BOOLEAN,
    PARAM_FILTER,
    PARAM_IDENTIFIER,
    PARAM_INTEGER,
    PARAM_SEARCH,
    PARAM_SORT,
    PARAM_STRING,
    QCTX_ORDER_BY,
    SIGNAL_BOOLEAN_RELEVANT,
    SIGNAL_DIFFERENTIAL,
    SIGNAL_NONE_OBSERVED,
    SIGNAL_TIMING_RELEVANT,
    TYPE_NONE_OBSERVED,
    TYPE_WEAK,
    sanitize_sqli_context_analysis_plan,
)
from ai.schemas.sqli_hypothesis import (
    HYPOTHESIS_TYPES,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_BEHAVIOR_BOOLEAN_RELEVANT,
    SIGNAL_BEHAVIOR_DIFFERENTIAL,
    SIGNAL_BEHAVIOR_NONE_OBSERVED,
    SIGNAL_BEHAVIOR_TIMING_RELEVANT,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_DB_MSSQL,
    SIGNAL_DB_MYSQL,
    SIGNAL_DB_ORACLE,
    SIGNAL_DB_POSTGRESQL,
    SIGNAL_DB_SQLITE,
    SIGNAL_ERROR_APPLICATION_ONLY,
    SIGNAL_ERROR_DATABASE_OBSERVED,
    SIGNAL_ERROR_NONE_OBSERVED,
    SIGNAL_FLOW_DIRECT_QUERY,
    SIGNAL_FLOW_ORM,
    SIGNAL_FLOW_QUERY_BUILDER,
    SIGNAL_FLOW_RAW_QUERY,
    SIGNAL_FLOW_STORED_PROCEDURE,
    SIGNAL_HANDLING_CONCATENATED,
    SIGNAL_HANDLING_ESCAPED,
    SIGNAL_HANDLING_PARAMETERIZED,
    SIGNAL_HANDLING_RAW,
    SIGNAL_HANDLING_SANITIZED,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_PATH,
    SIGNAL_INPUT_QUERY,
    SIGNAL_PARAM_BOOLEAN,
    SIGNAL_PARAM_FILTER,
    SIGNAL_PARAM_IDENTIFIER,
    SIGNAL_PARAM_INTEGER,
    SIGNAL_PARAM_SEARCH,
    SIGNAL_PARAM_SORT,
    SIGNAL_PARAM_STRING,
    SIGNAL_QUERY_DELETE,
    SIGNAL_QUERY_INSERT,
    SIGNAL_QUERY_LIMIT,
    SIGNAL_QUERY_OFFSET,
    SIGNAL_QUERY_ORDER_BY,
    SIGNAL_QUERY_SELECT,
    SIGNAL_QUERY_UPDATE,
    SIGNAL_QUERY_WHERE,
    SIGNAL_TYPE_CAST,
    SIGNAL_TYPE_NONE_OBSERVED,
    SIGNAL_TYPE_STRONG,
    SIGNAL_TYPE_WEAK,
    SQLI_HYPOTHESIS_RULE_VERSION,
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
    SQLIHypothesisPlan,
    sqli_hypothesis_plan_projection,
)

SQLI_HYPOTHESIS_PLANNER_RULE_VERSION = "r41-3"
RULE_VERSION = SQLI_HYPOTHESIS_PLANNER_RULE_VERSION

_INPUT_SIGNALS: dict[str, str] = {
    INPUT_QUERY: SIGNAL_INPUT_QUERY,
    INPUT_BODY: SIGNAL_INPUT_BODY,
    INPUT_HEADER: SIGNAL_INPUT_HEADER,
    INPUT_COOKIE: SIGNAL_INPUT_COOKIE,
    INPUT_PATH: SIGNAL_INPUT_PATH,
}

_PARAM_SIGNALS: dict[str, str] = {
    PARAM_STRING: SIGNAL_PARAM_STRING,
    PARAM_INTEGER: SIGNAL_PARAM_INTEGER,
    PARAM_BOOLEAN: SIGNAL_PARAM_BOOLEAN,
    PARAM_SORT: SIGNAL_PARAM_SORT,
    PARAM_FILTER: SIGNAL_PARAM_FILTER,
    PARAM_SEARCH: SIGNAL_PARAM_SEARCH,
    PARAM_IDENTIFIER: SIGNAL_PARAM_IDENTIFIER,
}

_FLOW_SIGNALS: dict[str, str] = {
    "DIRECT_QUERY": SIGNAL_FLOW_DIRECT_QUERY,
    "QUERY_BUILDER": SIGNAL_FLOW_QUERY_BUILDER,
    FLOW_ORM: SIGNAL_FLOW_ORM,
    FLOW_STORED_PROCEDURE: SIGNAL_FLOW_STORED_PROCEDURE,
    FLOW_RAW_QUERY: SIGNAL_FLOW_RAW_QUERY,
}

_QUERY_SIGNALS: dict[str, str] = {
    "WHERE": SIGNAL_QUERY_WHERE,
    QCTX_ORDER_BY: SIGNAL_QUERY_ORDER_BY,
    "LIMIT": SIGNAL_QUERY_LIMIT,
    "OFFSET": SIGNAL_QUERY_OFFSET,
    "SELECT": SIGNAL_QUERY_SELECT,
    "INSERT": SIGNAL_QUERY_INSERT,
    "UPDATE": SIGNAL_QUERY_UPDATE,
    "DELETE": SIGNAL_QUERY_DELETE,
}

_DB_SIGNALS: dict[str, str] = {
    "MYSQL": SIGNAL_DB_MYSQL,
    "POSTGRESQL": SIGNAL_DB_POSTGRESQL,
    "MSSQL": SIGNAL_DB_MSSQL,
    "SQLITE": SIGNAL_DB_SQLITE,
    "ORACLE": SIGNAL_DB_ORACLE,
}

_HANDLING_SIGNALS: dict[str, str] = {
    HANDLING_PARAMETERIZED: SIGNAL_HANDLING_PARAMETERIZED,
    HANDLING_SANITIZED: SIGNAL_HANDLING_SANITIZED,
    HANDLING_ESCAPED: SIGNAL_HANDLING_ESCAPED,
    HANDLING_CONCATENATED: SIGNAL_HANDLING_CONCATENATED,
    HANDLING_RAW: SIGNAL_HANDLING_RAW,
}

_TYPE_SIGNALS: dict[str, str] = {
    "STRONG": SIGNAL_TYPE_STRONG,
    TYPE_WEAK: SIGNAL_TYPE_WEAK,
    "CAST": SIGNAL_TYPE_CAST,
    TYPE_NONE_OBSERVED: SIGNAL_TYPE_NONE_OBSERVED,
}

_ERROR_SIGNALS: dict[str, str] = {
    "DATABASE_ERROR_OBSERVED": SIGNAL_ERROR_DATABASE_OBSERVED,
    "APPLICATION_ERROR_ONLY": SIGNAL_ERROR_APPLICATION_ONLY,
    "NO_ERROR_OBSERVED": SIGNAL_ERROR_NONE_OBSERVED,
}

_BEHAVIOR_SIGNALS: dict[str, str] = {
    SIGNAL_DIFFERENTIAL: SIGNAL_BEHAVIOR_DIFFERENTIAL,
    SIGNAL_TIMING_RELEVANT: SIGNAL_BEHAVIOR_TIMING_RELEVANT,
    SIGNAL_BOOLEAN_RELEVANT: SIGNAL_BEHAVIOR_BOOLEAN_RELEVANT,
    SIGNAL_NONE_OBSERVED: SIGNAL_BEHAVIOR_NONE_OBSERVED,
}

_CONSTRUCTION_HANDLING: tuple[str, ...] = (
    HANDLING_CONCATENATED,
    HANDLING_RAW,
)

_WEAK_TYPE_HANDLING: tuple[str, ...] = (
    TYPE_WEAK,
    TYPE_NONE_OBSERVED,
)


def _signal(mapping: dict, value: object) -> str:
    return mapping.get(str(value), "")


def _hypothesis(
    hypothesis_type: str,
    confidence: str,
    signals: object,
) -> dict:
    bounded_signals: list[str] = []
    for signal in signals or ():
        if signal and signal not in bounded_signals:
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if confidence == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = SQLIHypothesisPlan(
        rule_version=SQLI_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        supporting_signals=bounded_signals,
        confidence=confidence,
        priority=confidence,
        limitations=limitations,
        research_only=True,
    )
    return sqli_hypothesis_plan_projection(plan)


def _major(confidence: str) -> str:
    return {
        CONFIDENCE_HIGH: CONFIDENCE_HIGH,
        CONFIDENCE_MEDIUM: CONFIDENCE_MEDIUM,
        CONFIDENCE_LOW: CONFIDENCE_LOW,
    }.get(confidence, CONFIDENCE_UNKNOWN)


def _minor(confidence: str) -> str:
    return {
        CONFIDENCE_HIGH: CONFIDENCE_MEDIUM,
        CONFIDENCE_MEDIUM: CONFIDENCE_LOW,
        CONFIDENCE_LOW: CONFIDENCE_LOW,
    }.get(confidence, CONFIDENCE_UNKNOWN)


def plan_sqli_hypotheses(context_analysis: object = None) -> list[dict]:
    """Build the deterministic SQLi research hypotheses (read-only).

    The mapping is conservative and never claims SQLi:

    - RAW/CONCATENATED handling yields construction and parameterization
      reviews; SANITIZED/ESCAPED handling yields an input-handling review;
    - RAW_QUERY flow yields a raw-query review; ORM and stored procedures
      yield their own bounded reviews;
    - ORDER_BY contexts and IDENTIFIER parameters yield targeted reviews;
    - weak/missing type handling, known database types, observed database
      errors, and boolean/differential/timing signals each add their review;
    - nothing usable degrades to a low parameterization review or to
      ``UNKNOWN``.
    """

    context = sanitize_sqli_context_analysis_plan(context_analysis)
    input_location = context["input_location"]
    parameter_type = context["parameter_type"]
    data_flow = context["data_flow"]
    query_context = context["query_context"]
    database_context = context["database_context"]
    input_handling = context["input_handling"]
    type_handling = context["type_handling"]
    error_behavior = context["error_behavior"]
    behavioral_signal = context["behavioral_signal"]
    context_confidence = sqli_context_confidence_of(context)

    input_signal = _signal(_INPUT_SIGNALS, input_location)
    param_signal = _signal(_PARAM_SIGNALS, parameter_type)
    flow_signal = _signal(_FLOW_SIGNALS, data_flow)
    query_signal = _signal(_QUERY_SIGNALS, query_context)
    database_signal = _signal(_DB_SIGNALS, database_context)
    handling_signal = _signal(_HANDLING_SIGNALS, input_handling)
    type_signal = _signal(_TYPE_SIGNALS, type_handling)
    error_signal = _signal(_ERROR_SIGNALS, error_behavior)
    behavior_signal = _signal(_BEHAVIOR_SIGNALS, behavioral_signal)

    found: dict[str, tuple] = {}

    def add(hypothesis_type: str, confidence: str, signals: object) -> None:
        if hypothesis_type not in found:
            found[hypothesis_type] = (confidence, signals)

    if input_handling in _CONSTRUCTION_HANDLING:
        add(
            TYPE_QUERY_CONSTRUCTION_REVIEW,
            _major(context_confidence),
            (handling_signal, flow_signal, input_signal, param_signal),
        )
        add(
            TYPE_PARAMETERIZATION_REVIEW,
            _major(context_confidence),
            (handling_signal, flow_signal, input_signal),
        )
    elif input_handling in (HANDLING_SANITIZED, HANDLING_ESCAPED):
        add(
            TYPE_INPUT_HANDLING_REVIEW,
            _minor(context_confidence),
            (handling_signal, input_signal, param_signal),
        )
        add(
            TYPE_PARAMETERIZATION_REVIEW,
            _minor(context_confidence),
            (handling_signal, input_signal),
        )
    elif input_handling == HANDLING_PARAMETERIZED:
        add(
            TYPE_PARAMETERIZATION_REVIEW,
            CONFIDENCE_LOW,
            (handling_signal, flow_signal, input_signal),
        )

    if data_flow == FLOW_RAW_QUERY:
        add(
            TYPE_RAW_QUERY_REVIEW,
            _major(context_confidence),
            (flow_signal, handling_signal, input_signal),
        )
    elif data_flow == FLOW_ORM:
        add(
            TYPE_ORM_QUERY_REVIEW,
            _minor(context_confidence),
            (flow_signal, query_signal, param_signal),
        )
    elif data_flow == FLOW_STORED_PROCEDURE:
        add(
            TYPE_STORED_PROCEDURE_REVIEW,
            _minor(context_confidence),
            (flow_signal, query_signal, database_signal),
        )

    if query_context == QCTX_ORDER_BY:
        add(
            TYPE_ORDER_BY_INJECTION_REVIEW,
            _major(context_confidence),
            (query_signal, param_signal, handling_signal),
        )

    if parameter_type == PARAM_IDENTIFIER:
        add(
            TYPE_IDENTIFIER_HANDLING_REVIEW,
            _major(context_confidence),
            (param_signal, query_signal, handling_signal),
        )

    if type_handling in _WEAK_TYPE_HANDLING:
        add(
            TYPE_TYPE_HANDLING_REVIEW,
            _minor(context_confidence),
            (type_signal, param_signal),
        )

    if database_context != DB_UNKNOWN:
        add(
            TYPE_DATABASE_SPECIFIC_REVIEW,
            _minor(context_confidence),
            (database_signal, flow_signal, handling_signal),
        )

    if error_signal == SIGNAL_ERROR_DATABASE_OBSERVED:
        add(
            TYPE_ERROR_SIGNAL_REVIEW,
            _major(context_confidence),
            (error_signal, input_signal),
        )

    if behavioral_signal in (SIGNAL_DIFFERENTIAL, SIGNAL_BOOLEAN_RELEVANT):
        add(
            TYPE_BOOLEAN_DIFFERENTIAL_REVIEW,
            _major(context_confidence),
            (behavior_signal, param_signal, query_signal),
        )
    elif behavioral_signal == SIGNAL_TIMING_RELEVANT:
        add(
            TYPE_TIMING_SIGNAL_REVIEW,
            _major(context_confidence),
            (behavior_signal, input_signal),
        )

    if not found:
        if context_confidence == CONFIDENCE_UNKNOWN:
            return [
                _hypothesis(
                    TYPE_UNKNOWN,
                    CONFIDENCE_UNKNOWN,
                    (SIGNAL_CONTEXT_UNKNOWN,),
                )
            ]
        add(
            TYPE_PARAMETERIZATION_REVIEW,
            CONFIDENCE_LOW,
            (input_signal, param_signal, flow_signal),
        )

    hypotheses: list[dict] = []
    for hypothesis_type in HYPOTHESIS_TYPES:
        if hypothesis_type == TYPE_UNKNOWN:
            continue
        if hypothesis_type in found:
            confidence, signals = found[hypothesis_type]
            hypotheses.append(
                _hypothesis(hypothesis_type, confidence, signals)
            )
    return hypotheses


__all__ = [
    "SQLI_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_sqli_hypotheses",
]

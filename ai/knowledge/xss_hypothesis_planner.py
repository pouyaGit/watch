"""Stage R39.3 deterministic XSS hypothesis planner (pure engine).

Creates deterministic research hypotheses from an observed XSS context:

    "Which XSS research hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no payload, no execution, no browser/JavaScript, no fuzzing, no attack
  automation.
- Pure and offline: no I/O, no network, no LLM, no browser, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, signals, confidence,
  priority and limitations are pure functions of the bounded context.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.xss_context_analyzer import context_confidence_of
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.xss_context_analysis import (
    ENCODING_ENCODED,
    ENCODING_NONE_OBSERVED,
    ENCODING_PARTIAL,
    FRAMEWORK_NONE_OBSERVED,
    FRAMEWORK_UNKNOWN,
    INPUT_BODY,
    INPUT_COOKIE,
    INPUT_HEADER,
    INPUT_QUERY,
    OUTPUT_ATTRIBUTE,
    OUTPUT_DOM,
    OUTPUT_HTML,
    OUTPUT_JAVASCRIPT,
    REFLECTION_NOT_OBSERVED,
    REFLECTION_REFLECTED,
    REFLECTION_UNKNOWN,
    sanitize_xss_context_analysis_plan,
)
from ai.schemas.xss_hypothesis import (
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_ENCODING_ENCODED,
    SIGNAL_ENCODING_NONE,
    SIGNAL_ENCODING_PARTIAL,
    SIGNAL_FRAMEWORK_PRESENT,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_QUERY,
    SIGNAL_OUTPUT_ATTRIBUTE,
    SIGNAL_OUTPUT_DOM,
    SIGNAL_OUTPUT_HTML,
    SIGNAL_OUTPUT_JAVASCRIPT,
    SIGNAL_REFLECTION_NOT_OBSERVED,
    SIGNAL_REFLECTION_OBSERVED,
    SIGNAL_REFLECTION_UNKNOWN,
    TYPE_CONTEXT_REVIEW,
    TYPE_DOM_FLOW_ANALYSIS,
    TYPE_REFLECTION_ANALYSIS,
    TYPE_STORAGE_FLOW_ANALYSIS,
    TYPE_UNKNOWN,
    XSS_HYPOTHESIS_RULE_VERSION,
    XSSHypothesisPlan,
    xss_hypothesis_plan_projection,
)

XSS_HYPOTHESIS_PLANNER_RULE_VERSION = "r39-3"
RULE_VERSION = XSS_HYPOTHESIS_PLANNER_RULE_VERSION

_REFLECTION_SIGNALS: dict[str, str] = {
    REFLECTION_REFLECTED: SIGNAL_REFLECTION_OBSERVED,
    REFLECTION_NOT_OBSERVED: SIGNAL_REFLECTION_NOT_OBSERVED,
    REFLECTION_UNKNOWN: SIGNAL_REFLECTION_UNKNOWN,
}

_ENCODING_SIGNALS: dict[str, str] = {
    ENCODING_NONE_OBSERVED: SIGNAL_ENCODING_NONE,
    ENCODING_PARTIAL: SIGNAL_ENCODING_PARTIAL,
    ENCODING_ENCODED: SIGNAL_ENCODING_ENCODED,
}

_OUTPUT_SIGNALS: dict[str, str] = {
    OUTPUT_HTML: SIGNAL_OUTPUT_HTML,
    OUTPUT_ATTRIBUTE: SIGNAL_OUTPUT_ATTRIBUTE,
    OUTPUT_JAVASCRIPT: SIGNAL_OUTPUT_JAVASCRIPT,
    OUTPUT_DOM: SIGNAL_OUTPUT_DOM,
}

_INPUT_SIGNALS: dict[str, str] = {
    INPUT_QUERY: SIGNAL_INPUT_QUERY,
    INPUT_BODY: SIGNAL_INPUT_BODY,
    INPUT_HEADER: SIGNAL_INPUT_HEADER,
    INPUT_COOKIE: SIGNAL_INPUT_COOKIE,
}


def _signal(mapping: dict, value: object) -> str:
    return mapping.get(str(value), "")


def _framework_signal(framework_context: str) -> str:
    if framework_context in (FRAMEWORK_NONE_OBSERVED, FRAMEWORK_UNKNOWN):
        return ""
    return SIGNAL_FRAMEWORK_PRESENT


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

    plan = XSSHypothesisPlan(
        rule_version=XSS_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        supporting_signals=bounded_signals,
        confidence=confidence,
        priority=confidence,
        limitations=limitations,
        research_only=True,
    )
    return xss_hypothesis_plan_projection(plan)


def plan_xss_hypotheses(context_analysis: object = None) -> list[dict]:
    """Build the deterministic research hypotheses (read-only).

    The mapping is conservative and never claims a vulnerability:

    - reflected observation → ``REFLECTION_ANALYSIS`` whose confidence
      depends only on the observed encoding state;
    - no reflection observed from a body/cookie input → low-confidence
      ``STORAGE_FLOW_ANALYSIS``;
    - a DOM output context adds a ``DOM_FLOW_ANALYSIS`` hypothesis;
    - everything else degrades to ``CONTEXT_REVIEW`` or ``UNKNOWN``.
    """

    context = sanitize_xss_context_analysis_plan(context_analysis)
    reflection = context["reflection_state"]
    encoding = context["encoding_state"]
    output = context["output_context"]
    input_location = context["input_location"]
    framework_context = context["framework_context"]
    context_confidence = context_confidence_of(context)

    reflection_signal = _signal(_REFLECTION_SIGNALS, reflection)
    encoding_signal = _signal(_ENCODING_SIGNALS, encoding)
    output_signal = _signal(_OUTPUT_SIGNALS, output)
    input_signal = _signal(_INPUT_SIGNALS, input_location)
    framework_signal = _framework_signal(framework_context)

    hypotheses: list[dict] = []

    if reflection == REFLECTION_REFLECTED:
        if encoding == ENCODING_NONE_OBSERVED:
            confidence = CONFIDENCE_HIGH
        elif encoding == ENCODING_PARTIAL:
            confidence = CONFIDENCE_MEDIUM
        else:
            confidence = CONFIDENCE_LOW
        hypotheses.append(
            _hypothesis(
                TYPE_REFLECTION_ANALYSIS,
                confidence,
                (reflection_signal, encoding_signal, output_signal,
                 input_signal, framework_signal),
            )
        )
    elif reflection == REFLECTION_NOT_OBSERVED:
        if input_location in (INPUT_BODY, INPUT_COOKIE):
            hypotheses.append(
                _hypothesis(
                    TYPE_STORAGE_FLOW_ANALYSIS,
                    CONFIDENCE_LOW,
                    (reflection_signal, input_signal, output_signal),
                )
            )
        else:
            hypotheses.append(
                _hypothesis(
                    TYPE_CONTEXT_REVIEW,
                    CONFIDENCE_LOW,
                    (reflection_signal, encoding_signal, output_signal),
                )
            )
    elif output == OUTPUT_DOM:
        confidence = (
            CONFIDENCE_LOW
            if context_confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)
            else CONFIDENCE_UNKNOWN
        )
        hypotheses.append(
            _hypothesis(
                TYPE_DOM_FLOW_ANALYSIS,
                confidence,
                (output_signal, framework_signal, input_signal),
            )
        )
    elif context_confidence == CONFIDENCE_UNKNOWN:
        hypotheses.append(
            _hypothesis(
                TYPE_UNKNOWN,
                CONFIDENCE_UNKNOWN,
                (SIGNAL_CONTEXT_UNKNOWN,),
            )
        )
    else:
        hypotheses.append(
            _hypothesis(
                TYPE_CONTEXT_REVIEW,
                CONFIDENCE_LOW,
                (output_signal, encoding_signal, framework_signal),
            )
        )

    existing = {item["hypothesis_type"] for item in hypotheses}
    if output == OUTPUT_DOM and TYPE_DOM_FLOW_ANALYSIS not in existing:
        confidence = (
            CONFIDENCE_MEDIUM
            if context_confidence == CONFIDENCE_HIGH
            else CONFIDENCE_LOW
        )
        hypotheses.append(
            _hypothesis(
                TYPE_DOM_FLOW_ANALYSIS,
                confidence,
                (SIGNAL_OUTPUT_DOM, framework_signal),
            )
        )

    return hypotheses


__all__ = [
    "XSS_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_xss_hypotheses",
]

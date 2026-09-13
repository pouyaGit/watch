"""Stage R39.2 deterministic XSS context analyzer (pure engine).

Analyzes possible XSS-relevant context from bounded observations:

    "What input location, output context, reflection and encoding state were
     observed?"

Hard boundaries encoded here:

- Research intelligence only: no payload generation, no HTTP request, no
  execution, no browser/JavaScript, no DOM crawling, no fuzzing, no
  exploitation, no persistence.
- Pure and offline: no I/O, no network, no LLM, no browser, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``; nothing is
  inferred or promoted.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.xss_context_analysis import (
    ENCODING_STATES,
    ENCODING_UNKNOWN,
    FRAMEWORK_CONTEXTS,
    FRAMEWORK_UNKNOWN,
    INPUT_LOCATIONS,
    INPUT_UNKNOWN,
    OUTPUT_CONTEXTS,
    OUTPUT_UNKNOWN,
    REFLECTION_STATES,
    REFLECTION_UNKNOWN,
    XSS_CONTEXT_ANALYSIS_RULE_VERSION,
    XSSContextAnalysisPlan,
    sanitize_xss_context_analysis_plan,
    xss_context_analysis_plan_projection,
)

XSS_CONTEXT_ANALYZER_RULE_VERSION = "r39-2"
RULE_VERSION = XSS_CONTEXT_ANALYZER_RULE_VERSION

UNKNOWN_VALUES: tuple[str, ...] = (
    INPUT_UNKNOWN,
    OUTPUT_UNKNOWN,
    REFLECTION_UNKNOWN,
    ENCODING_UNKNOWN,
    FRAMEWORK_UNKNOWN,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _confidence_for(known_count: int) -> str:
    if known_count >= 5:
        return CONFIDENCE_HIGH
    if known_count >= 3:
        return CONFIDENCE_MEDIUM
    if known_count >= 1:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def analyze_xss_context(
    input_location: object = None,
    output_context: object = None,
    reflection_state: object = None,
    encoding_state: object = None,
    framework_context: object = None,
) -> dict:
    """Build the deterministic descriptive context analysis (read-only).

    Each observation is bounded to its closed vocabulary; malformed or
    missing values remain ``UNKNOWN`` and never promote confidence. Context
    confidence is a pure function of how many of the five observations are
    known (5 → HIGH, 3-4 → MEDIUM, 1-2 → LOW, 0 → UNKNOWN).
    """

    resolved_input = _closed(input_location, INPUT_LOCATIONS, INPUT_UNKNOWN)
    resolved_output = _closed(
        output_context, OUTPUT_CONTEXTS, OUTPUT_UNKNOWN
    )
    resolved_reflection = _closed(
        reflection_state, REFLECTION_STATES, REFLECTION_UNKNOWN
    )
    resolved_encoding = _closed(
        encoding_state, ENCODING_STATES, ENCODING_UNKNOWN
    )
    resolved_framework = _closed(
        framework_context, FRAMEWORK_CONTEXTS, FRAMEWORK_UNKNOWN
    )

    known_count = sum(
        1
        for value in (
            resolved_input,
            resolved_output,
            resolved_reflection,
            resolved_encoding,
            resolved_framework,
        )
        if value not in UNKNOWN_VALUES
    )

    plan = XSSContextAnalysisPlan(
        rule_version=XSS_CONTEXT_ANALYSIS_RULE_VERSION,
        input_location=resolved_input,
        output_context=resolved_output,
        reflection_state=resolved_reflection,
        encoding_state=resolved_encoding,
        framework_context=resolved_framework,
        context_confidence=_confidence_for(known_count),
        research_only=True,
    )
    return xss_context_analysis_plan_projection(plan)


def context_confidence_of(value: object) -> str:
    """Derive the deterministic confidence from known context facts.

    The stored ``context_confidence`` is ignored and recomputed from the
    bounded observations, so partial context dicts (for example supplied
    directly to the hypothesis planner) still receive the correct
    confidence.
    """

    plan = sanitize_xss_context_analysis_plan(value)
    known_count = sum(
        1
        for key in (
            "input_location",
            "output_context",
            "reflection_state",
            "encoding_state",
            "framework_context",
        )
        if plan[key] not in UNKNOWN_VALUES
    )
    return _confidence_for(known_count)


def context_is_known(value: object) -> bool:
    """True when the sanitized analysis carries at least one known fact."""

    return context_confidence_of(value) != CONFIDENCE_UNKNOWN


__all__ = [
    "XSS_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "UNKNOWN_VALUES",
    "analyze_xss_context",
    "context_confidence_of",
    "context_is_known",
]

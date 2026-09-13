"""XSS context analysis schema (Stage R39.2).

An :class:`XSSContextAnalysisPlan` is the deterministic, descriptive analysis
of possible XSS-relevant context. It answers the research question:

    "What input location, output context, reflection and encoding state were
     observed?"

Hard boundaries encoded here:

- Research intelligence only: no payload generation, no HTTP request, no
  execution, no browser/JavaScript, no DOM crawling, no fuzzing, no
  exploitation, no persistence.
- Closed vocabularies: input location, output context, reflection state,
  encoding state and framework context are closed sets; unknown values remain
  ``UNKNOWN`` and are never promoted.
- Context confidence reuses the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

XSS_CONTEXT_ANALYSIS_RULE_VERSION = "r39-2"
RULE_VERSION = XSS_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

INPUT_QUERY = "QUERY"
INPUT_BODY = "BODY"
INPUT_HEADER = "HEADER"
INPUT_COOKIE = "COOKIE"
INPUT_UNKNOWN = "UNKNOWN"

INPUT_LOCATIONS: tuple[str, ...] = (
    INPUT_QUERY,
    INPUT_BODY,
    INPUT_HEADER,
    INPUT_COOKIE,
    INPUT_UNKNOWN,
)

OUTPUT_HTML = "HTML"
OUTPUT_ATTRIBUTE = "ATTRIBUTE"
OUTPUT_JAVASCRIPT = "JAVASCRIPT"
OUTPUT_DOM = "DOM"
OUTPUT_UNKNOWN = "UNKNOWN"

OUTPUT_CONTEXTS: tuple[str, ...] = (
    OUTPUT_HTML,
    OUTPUT_ATTRIBUTE,
    OUTPUT_JAVASCRIPT,
    OUTPUT_DOM,
    OUTPUT_UNKNOWN,
)

REFLECTION_REFLECTED = "REFLECTED"
REFLECTION_NOT_OBSERVED = "NOT_OBSERVED"
REFLECTION_UNKNOWN = "UNKNOWN"

REFLECTION_STATES: tuple[str, ...] = (
    REFLECTION_REFLECTED,
    REFLECTION_NOT_OBSERVED,
    REFLECTION_UNKNOWN,
)

ENCODING_ENCODED = "ENCODED"
ENCODING_PARTIAL = "PARTIAL"
ENCODING_NONE_OBSERVED = "NONE_OBSERVED"
ENCODING_UNKNOWN = "UNKNOWN"

ENCODING_STATES: tuple[str, ...] = (
    ENCODING_ENCODED,
    ENCODING_PARTIAL,
    ENCODING_NONE_OBSERVED,
    ENCODING_UNKNOWN,
)

FRAMEWORK_NONE_OBSERVED = "NONE_OBSERVED"
FRAMEWORK_GENERIC = "GENERIC"
FRAMEWORK_REACT = "REACT"
FRAMEWORK_VUE = "VUE"
FRAMEWORK_ANGULAR = "ANGULAR"
FRAMEWORK_JQUERY = "JQUERY"
FRAMEWORK_UNKNOWN = "UNKNOWN"

FRAMEWORK_CONTEXTS: tuple[str, ...] = (
    FRAMEWORK_NONE_OBSERVED,
    FRAMEWORK_GENERIC,
    FRAMEWORK_REACT,
    FRAMEWORK_VUE,
    FRAMEWORK_ANGULAR,
    FRAMEWORK_JQUERY,
    FRAMEWORK_UNKNOWN,
)

MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_xss_context_analysis_plan(value: object) -> dict:
    """Project an R39.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "input_location": INPUT_UNKNOWN,
            "output_context": OUTPUT_UNKNOWN,
            "reflection_state": REFLECTION_UNKNOWN,
            "encoding_state": ENCODING_UNKNOWN,
            "framework_context": FRAMEWORK_UNKNOWN,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "input_location": _closed(
            value.get("input_location"), INPUT_LOCATIONS, INPUT_UNKNOWN
        ),
        "output_context": _closed(
            value.get("output_context"), OUTPUT_CONTEXTS, OUTPUT_UNKNOWN
        ),
        "reflection_state": _closed(
            value.get("reflection_state"),
            REFLECTION_STATES,
            REFLECTION_UNKNOWN,
        ),
        "encoding_state": _closed(
            value.get("encoding_state"), ENCODING_STATES, ENCODING_UNKNOWN
        ),
        "framework_context": _closed(
            value.get("framework_context"),
            FRAMEWORK_CONTEXTS,
            FRAMEWORK_UNKNOWN,
        ),
        "context_confidence": _closed(
            value.get("context_confidence"),
            CONFIDENCE_LEVELS,
            "UNKNOWN",
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class XSSContextAnalysisPlan(BaseModel):
    """Deterministic descriptive XSS context analysis (R39.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = XSS_CONTEXT_ANALYSIS_RULE_VERSION
    input_location: str = INPUT_UNKNOWN
    output_context: str = OUTPUT_UNKNOWN
    reflection_state: str = REFLECTION_UNKNOWN
    encoding_state: str = ENCODING_UNKNOWN
    framework_context: str = FRAMEWORK_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return XSS_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("input_location")
    @classmethod
    def _valid_input(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in INPUT_LOCATIONS:
            raise ValueError(f"invalid input_location: {value!r}")
        return text

    @field_validator("output_context")
    @classmethod
    def _valid_output(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OUTPUT_CONTEXTS:
            raise ValueError(f"invalid output_context: {value!r}")
        return text

    @field_validator("reflection_state")
    @classmethod
    def _valid_reflection(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REFLECTION_STATES:
            raise ValueError(f"invalid reflection_state: {value!r}")
        return text

    @field_validator("encoding_state")
    @classmethod
    def _valid_encoding(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ENCODING_STATES:
            raise ValueError(f"invalid encoding_state: {value!r}")
        return text

    @field_validator("framework_context")
    @classmethod
    def _valid_framework(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FRAMEWORK_CONTEXTS:
            raise ValueError(f"invalid framework_context: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("xss context analyses are research-only")
        return True


def xss_context_analysis_plan_projection(
    value: XSSContextAnalysisPlan,
) -> dict:
    """Serialize an XSS context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "XSS_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "INPUT_QUERY",
    "INPUT_BODY",
    "INPUT_HEADER",
    "INPUT_COOKIE",
    "INPUT_UNKNOWN",
    "INPUT_LOCATIONS",
    "OUTPUT_HTML",
    "OUTPUT_ATTRIBUTE",
    "OUTPUT_JAVASCRIPT",
    "OUTPUT_DOM",
    "OUTPUT_UNKNOWN",
    "OUTPUT_CONTEXTS",
    "REFLECTION_REFLECTED",
    "REFLECTION_NOT_OBSERVED",
    "REFLECTION_UNKNOWN",
    "REFLECTION_STATES",
    "ENCODING_ENCODED",
    "ENCODING_PARTIAL",
    "ENCODING_NONE_OBSERVED",
    "ENCODING_UNKNOWN",
    "ENCODING_STATES",
    "FRAMEWORK_NONE_OBSERVED",
    "FRAMEWORK_GENERIC",
    "FRAMEWORK_REACT",
    "FRAMEWORK_VUE",
    "FRAMEWORK_ANGULAR",
    "FRAMEWORK_JQUERY",
    "FRAMEWORK_UNKNOWN",
    "FRAMEWORK_CONTEXTS",
    "MAX_VALUE_LEN",
    "sanitize_xss_context_analysis_plan",
    "XSSContextAnalysisPlan",
    "xss_context_analysis_plan_projection",
]

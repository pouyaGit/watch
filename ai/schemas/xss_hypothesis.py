"""XSS hypothesis schema (Stage R39.3).

An :class:`XSSHypothesisPlan` is a deterministic research hypothesis about
possible XSS-relevant behavior. It answers the research question:

    "Which XSS research hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no payload, no execution, no browser/JavaScript, no fuzzing, no attack
  automation.
- Closed vocabularies: hypothesis type, supporting signals, confidence,
  priority and limitations are closed sets.
- Confidence and priority reuse the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

XSS_HYPOTHESIS_RULE_VERSION = "r39-3"
RULE_VERSION = XSS_HYPOTHESIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

TYPE_REFLECTION_ANALYSIS = "REFLECTION_ANALYSIS"
TYPE_DOM_FLOW_ANALYSIS = "DOM_FLOW_ANALYSIS"
TYPE_STORAGE_FLOW_ANALYSIS = "STORAGE_FLOW_ANALYSIS"
TYPE_CONTEXT_REVIEW = "CONTEXT_REVIEW"
TYPE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_REFLECTION_ANALYSIS,
    TYPE_DOM_FLOW_ANALYSIS,
    TYPE_STORAGE_FLOW_ANALYSIS,
    TYPE_CONTEXT_REVIEW,
    TYPE_UNKNOWN,
)

SIGNAL_REFLECTION_OBSERVED = "REFLECTION_OBSERVED"
SIGNAL_REFLECTION_NOT_OBSERVED = "REFLECTION_NOT_OBSERVED"
SIGNAL_REFLECTION_UNKNOWN = "REFLECTION_UNKNOWN"
SIGNAL_ENCODING_NONE = "ENCODING_NONE_OBSERVED"
SIGNAL_ENCODING_PARTIAL = "ENCODING_PARTIAL"
SIGNAL_ENCODING_ENCODED = "ENCODING_ENCODED"
SIGNAL_OUTPUT_HTML = "OUTPUT_HTML"
SIGNAL_OUTPUT_ATTRIBUTE = "OUTPUT_ATTRIBUTE"
SIGNAL_OUTPUT_JAVASCRIPT = "OUTPUT_JAVASCRIPT"
SIGNAL_OUTPUT_DOM = "OUTPUT_DOM"
SIGNAL_INPUT_QUERY = "INPUT_QUERY"
SIGNAL_INPUT_BODY = "INPUT_BODY"
SIGNAL_INPUT_HEADER = "INPUT_HEADER"
SIGNAL_INPUT_COOKIE = "INPUT_COOKIE"
SIGNAL_FRAMEWORK_PRESENT = "FRAMEWORK_PRESENT"
SIGNAL_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

XSS_SIGNALS: tuple[str, ...] = (
    SIGNAL_REFLECTION_OBSERVED,
    SIGNAL_REFLECTION_NOT_OBSERVED,
    SIGNAL_REFLECTION_UNKNOWN,
    SIGNAL_ENCODING_NONE,
    SIGNAL_ENCODING_PARTIAL,
    SIGNAL_ENCODING_ENCODED,
    SIGNAL_OUTPUT_HTML,
    SIGNAL_OUTPUT_ATTRIBUTE,
    SIGNAL_OUTPUT_JAVASCRIPT,
    SIGNAL_OUTPUT_DOM,
    SIGNAL_INPUT_QUERY,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_FRAMEWORK_PRESENT,
    SIGNAL_CONTEXT_UNKNOWN,
)

LIMITATION_NO_EXPLOIT_CLAIM = "NO_EXPLOIT_CLAIM"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

XSS_HYPOTHESIS_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_SIGNALS = 8
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_xss_hypothesis_plan(value: object) -> dict:
    """Project an R39.3 hypothesis onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "hypothesis_type": TYPE_UNKNOWN,
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if hypothesis_type not in HYPOTHESIS_TYPES:
        hypothesis_type = TYPE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "hypothesis_type": hypothesis_type,
        "supporting_signals": [
            signal
            for signal in (
                _safe_text(item) for item in value.get("supporting_signals")
                or ()
            )
            if signal in XSS_SIGNALS
        ][:MAX_SIGNALS],
        "confidence": confidence,
        "priority": priority,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in XSS_HYPOTHESIS_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class XSSHypothesisPlan(BaseModel):
    """Deterministic research-only XSS hypothesis (R39.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = XSS_HYPOTHESIS_RULE_VERSION
    hypothesis_type: str
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return XSS_HYPOTHESIS_RULE_VERSION

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(value, XSS_SIGNALS, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, XSS_HYPOTHESIS_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("xss hypotheses are research-only")
        return True


def xss_hypothesis_plan_projection(value: XSSHypothesisPlan) -> dict:
    """Serialize an XSS hypothesis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "XSS_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "TYPE_REFLECTION_ANALYSIS",
    "TYPE_DOM_FLOW_ANALYSIS",
    "TYPE_STORAGE_FLOW_ANALYSIS",
    "TYPE_CONTEXT_REVIEW",
    "TYPE_UNKNOWN",
    "HYPOTHESIS_TYPES",
    "SIGNAL_REFLECTION_OBSERVED",
    "SIGNAL_REFLECTION_NOT_OBSERVED",
    "SIGNAL_REFLECTION_UNKNOWN",
    "SIGNAL_ENCODING_NONE",
    "SIGNAL_ENCODING_PARTIAL",
    "SIGNAL_ENCODING_ENCODED",
    "SIGNAL_OUTPUT_HTML",
    "SIGNAL_OUTPUT_ATTRIBUTE",
    "SIGNAL_OUTPUT_JAVASCRIPT",
    "SIGNAL_OUTPUT_DOM",
    "SIGNAL_INPUT_QUERY",
    "SIGNAL_INPUT_BODY",
    "SIGNAL_INPUT_HEADER",
    "SIGNAL_INPUT_COOKIE",
    "SIGNAL_FRAMEWORK_PRESENT",
    "SIGNAL_CONTEXT_UNKNOWN",
    "XSS_SIGNALS",
    "LIMITATION_NO_EXPLOIT_CLAIM",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "XSS_HYPOTHESIS_LIMITATIONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_xss_hypothesis_plan",
    "XSSHypothesisPlan",
    "xss_hypothesis_plan_projection",
]

"""Finding context schema (Stage R53.2).

A :class:`FindingContextPlan` is the bounded, descriptive research context of
a finding candidate: title, summary, technical description, affected
structured context and endpoint/component information when the structured
input actually carries it. It answers:

    "What structured research context does this finding candidate describe?"

Hard boundaries encoded here:

- Description only: the context is assembled exclusively from structured
  upstream values. No application-specific detail, no business impact and no
  target interaction are invented.
- Observed facts only: affected context facts come from known (non-UNKNOWN)
  structured context values. Missing context stays explicitly unavailable.
- Endpoint/component metadata is ``PRESENT`` only when the structured input
  carries it; otherwise it is ``UNAVAILABLE``.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

FINDING_CONTEXT_RULE_VERSION = "r53-2"
RULE_VERSION = FINDING_CONTEXT_RULE_VERSION

ENDPOINT_PRESENT = "PRESENT"
ENDPOINT_UNAVAILABLE = "UNAVAILABLE"
ENDPOINT_UNKNOWN = "UNKNOWN"

ENDPOINT_AVAILABILITIES: tuple[str, ...] = (
    ENDPOINT_PRESENT,
    ENDPOINT_UNAVAILABLE,
    ENDPOINT_UNKNOWN,
)

MAX_CONTEXT_FACTS = 12
MAX_TITLE_LEN = 200
MAX_SUMMARY_LEN = 600
MAX_DESCRIPTION_LEN = 1200
MAX_VALUE_LEN = 160

_CONTEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,60}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_context_fact(value: object) -> dict:
    """Project one structured context fact onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {"key": "", "value": ""}
    key = _safe_text(value.get("key"), 80)
    if not _CONTEXT_KEY_RE.match(key):
        key = ""
    return {
        "key": key,
        "value": _safe_text(value.get("value")),
    }


def sanitize_context_facts(value: object) -> list[dict]:
    """Project a bounded list of context facts (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_context_fact(item)
        if projected["key"] and projected not in out:
            out.append(projected)
        if len(out) >= MAX_CONTEXT_FACTS:
            break
    return out


def sanitize_endpoint_component(value: object) -> dict:
    """Project endpoint/component metadata onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "availability": ENDPOINT_UNAVAILABLE,
            "component_name": "",
            "component_version": "",
            "endpoint_reference": "",
        }
    return {
        "availability": _closed(
            value.get("availability"),
            ENDPOINT_AVAILABILITIES,
            ENDPOINT_UNAVAILABLE,
        ),
        "component_name": _safe_text(value.get("component_name")),
        "component_version": _safe_text(value.get("component_version")),
        "endpoint_reference": _safe_text(value.get("endpoint_reference")),
    }


def sanitize_finding_context(value: object) -> dict:
    """Project a finding context onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "title": "",
            "summary": "",
            "technical_description": "",
            "affected_context": [],
            "endpoint_component": sanitize_endpoint_component(None),
            "context_fact_count": 0,
            "research_only": True,
        }
    facts = sanitize_context_facts(value.get("affected_context"))
    count = value.get("context_fact_count")
    if isinstance(count, bool) or not isinstance(count, int):
        count = len(facts)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "title": _safe_text(value.get("title"), MAX_TITLE_LEN),
        "summary": _safe_text(value.get("summary"), MAX_SUMMARY_LEN),
        "technical_description": _safe_text(
            value.get("technical_description"), MAX_DESCRIPTION_LEN
        ),
        "affected_context": facts,
        "endpoint_component": sanitize_endpoint_component(
            value.get("endpoint_component")
        ),
        "context_fact_count": max(0, min(MAX_CONTEXT_FACTS, count)),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ContextFactPlan(BaseModel):
    """One observed structured context fact (R53.2)."""

    model_config = ConfigDict(extra="forbid")

    key: str
    value: str = ""

    @field_validator("key")
    @classmethod
    def _valid_key(cls, value: object) -> str:
        text = _safe_text(value, 80)
        if not _CONTEXT_KEY_RE.match(text):
            raise ValueError(f"invalid context fact key: {value!r}")
        return text

    @field_validator("value")
    @classmethod
    def _bounded_value(cls, value: object) -> str:
        return _safe_text(value)


class EndpointComponentPlan(BaseModel):
    """Bounded endpoint/component metadata (R53.2)."""

    model_config = ConfigDict(extra="forbid")

    availability: str = ENDPOINT_UNAVAILABLE
    component_name: str = ""
    component_version: str = ""
    endpoint_reference: str = ""

    @field_validator("availability")
    @classmethod
    def _valid_availability(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ENDPOINT_AVAILABILITIES:
            raise ValueError(f"invalid endpoint availability: {value!r}")
        return text

    @field_validator("component_name", "component_version",
                     "endpoint_reference")
    @classmethod
    def _bounded_value(cls, value: object) -> str:
        return _safe_text(value)


class FindingContextPlan(BaseModel):
    """Descriptive research context of a finding candidate (R53.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_CONTEXT_RULE_VERSION
    title: str = ""
    summary: str = ""
    technical_description: str = ""
    affected_context: list[dict] = Field(default_factory=list)
    endpoint_component: dict = Field(
        default_factory=lambda: sanitize_endpoint_component(None)
    )
    context_fact_count: int = 0
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_CONTEXT_RULE_VERSION

    @field_validator("title")
    @classmethod
    def _bounded_title(cls, value: object) -> str:
        return _safe_text(value, MAX_TITLE_LEN)

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> str:
        return _safe_text(value, MAX_SUMMARY_LEN)

    @field_validator("technical_description")
    @classmethod
    def _bounded_description(cls, value: object) -> str:
        return _safe_text(value, MAX_DESCRIPTION_LEN)

    @field_validator("affected_context")
    @classmethod
    def _bounded_facts(cls, value: object) -> list[dict]:
        facts = sanitize_context_facts(value)
        return [
            ContextFactPlan(**fact).model_dump(mode="json") for fact in facts
        ]

    @field_validator("endpoint_component")
    @classmethod
    def _bounded_endpoint(cls, value: object) -> dict:
        return EndpointComponentPlan(
            **sanitize_endpoint_component(value)
        ).model_dump(mode="json")

    @field_validator("context_fact_count")
    @classmethod
    def _bounded_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(0, min(MAX_CONTEXT_FACTS, value))

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding contexts are research-only")
        return True


def finding_context_plan_projection(value: FindingContextPlan) -> dict:
    """Serialize a finding context to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_CONTEXT_RULE_VERSION",
    "RULE_VERSION",
    "ENDPOINT_AVAILABILITIES",
    "ENDPOINT_PRESENT",
    "ENDPOINT_UNAVAILABLE",
    "ENDPOINT_UNKNOWN",
    "MAX_CONTEXT_FACTS",
    "MAX_TITLE_LEN",
    "MAX_SUMMARY_LEN",
    "MAX_DESCRIPTION_LEN",
    "MAX_VALUE_LEN",
    "sanitize_context_fact",
    "sanitize_context_facts",
    "sanitize_endpoint_component",
    "sanitize_finding_context",
    "ContextFactPlan",
    "EndpointComponentPlan",
    "FindingContextPlan",
    "finding_context_plan_projection",
]

"""LLM provider contract schema (Stage R45.3).

Deterministic request/response contracts for the advisory provider
abstraction. They answer:

    "What may be sent to an advisory provider, and what may come back?"

Hard boundaries encoded here:

- Provider contract only: version 1 defines the interface and the mock
  provider response shape. There is no API key, no network client, no SDK
  import and no HTTP transport anywhere in this module.
- The provider kind vocabulary is closed. Only ``MOCK`` is supported in
  version 1; future kinds are declared but not implemented.
- Responses carry bounded text only; forbidden output categories are
  rejected by the R45.6 validator, not sanitized here.
- ``deterministic`` and ``research_only`` are always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.llm_advisory_input import (
    ADVISORY_INPUT_LIMITATIONS,
    GOVERNANCE_UNKNOWN,
    LLM_ADVISORY_SOURCE_LAYERS,
    SAFETY_UNKNOWN,
    sanitize_advisory_collaboration_summary,
    sanitize_advisory_evaluation_summary,
    sanitize_advisory_learning_signals,
    sanitize_advisory_research_context,
)
from ai.schemas.llm_advisory_policy import (
    ADVISORY_MODES,
    MAX_ADVISORY_TEXT_LEN,
    MAX_INSIGHTS,
    MAX_RECOMMENDATIONS,
)

LLM_PROVIDER_RULE_VERSION = "r45-3"
RULE_VERSION = LLM_PROVIDER_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed provider vocabularies
# ---------------------------------------------------------------------------

PROVIDER_KIND_MOCK = "MOCK"

SUPPORTED_PROVIDER_KINDS: tuple[str, ...] = (PROVIDER_KIND_MOCK,)

PROVIDER_KIND_OPENAI = "OPENAI"
PROVIDER_KIND_OPENROUTER = "OPENROUTER"
PROVIDER_KIND_OLLAMA = "OLLAMA"
PROVIDER_KIND_LOCAL = "LOCAL"

FUTURE_PROVIDER_KINDS: tuple[str, ...] = (
    PROVIDER_KIND_OPENAI,
    PROVIDER_KIND_OPENROUTER,
    PROVIDER_KIND_OLLAMA,
    PROVIDER_KIND_LOCAL,
)

PROVIDER_KINDS: tuple[str, ...] = (
    SUPPORTED_PROVIDER_KINDS + FUTURE_PROVIDER_KINDS
)

SOURCE_REF_LAYER_R42 = "R42"
SOURCE_REF_LAYER_R43 = "R43"
SOURCE_REF_LAYER_R44 = "R44"
SOURCE_REF_LAYER_R45 = "R45"

SOURCE_REF_LAYERS: tuple[str, ...] = (
    SOURCE_REF_LAYER_R42,
    SOURCE_REF_LAYER_R43,
    SOURCE_REF_LAYER_R44,
    SOURCE_REF_LAYER_R45,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_CREDENTIALS_USED = "NO_CREDENTIALS_USED"
LIMITATION_DETERMINISTIC_MOCK = "DETERMINISTIC_MOCK_RESPONSE"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

PROVIDER_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_CREDENTIALS_USED,
    LIMITATION_DETERMINISTIC_MOCK,
    LIMITATION_ADVISORY_ONLY,
)

# Requests preserve the advisory input limitations in addition to the
# provider-specific mock limitations.
PROVIDER_REQUEST_LIMITATIONS: tuple[str, ...] = tuple(
    dict.fromkeys(ADVISORY_INPUT_LIMITATIONS + PROVIDER_LIMITATIONS)
)

MAX_SOURCE_REFS = 8
MAX_LIST = 16
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_RULE_VERSION_RE = re.compile(r"^r[0-9]{2,3}-[0-9]{1,2}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_advisory_source_refs(value: object) -> list[dict]:
    """Project source references onto a bounded deterministic shape."""

    if isinstance(value, dict):
        raw_items = [value]
    elif isinstance(value, (list, tuple)):
        raw_items = list(value)
    else:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        layer = _safe_text(item.get("layer")).strip().upper()
        reference = _safe_text(item.get("reference")).strip().lower()
        if layer not in SOURCE_REF_LAYERS:
            continue
        if reference and not _RULE_VERSION_RE.match(reference):
            continue
        key = (layer, reference)
        if key in seen:
            continue
        seen.add(key)
        out.append({"layer": layer, "reference": reference})
        if len(out) >= MAX_SOURCE_REFS:
            break
    return out


def _sanitize_coded_items(value: object, code_field: str, limit: int) -> list[dict]:
    if isinstance(value, dict):
        raw_items = [value]
    elif isinstance(value, (list, tuple)):
        raw_items = list(value)
    else:
        return []
    out: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        code = _safe_text(item.get(code_field)).strip().upper()
        if not code or not _TOKEN_RE.match(code):
            continue
        text = _safe_text(item.get("text"), MAX_ADVISORY_TEXT_LEN)
        out.append(
            {
                code_field: code,
                "text": text,
                "source_refs": sanitize_advisory_source_refs(
                    item.get("source_refs")
                ),
                "research_only": True,
            }
        )
        if len(out) >= limit:
            break
    return out


def sanitize_advisory_insights(value: object) -> list[dict]:
    """Project provider insights onto a bounded deterministic shape."""

    return _sanitize_coded_items(value, "insight_code", MAX_INSIGHTS)


def sanitize_advisory_recommendations(value: object) -> list[dict]:
    """Project provider recommendations onto a bounded deterministic shape."""

    return _sanitize_coded_items(
        value, "recommendation_code", MAX_RECOMMENDATIONS
    )


def sanitize_provider_request_sections(value: object) -> dict:
    """Project the request sections onto the bounded advisory input view."""

    if not isinstance(value, dict):
        return {
            "research_context": sanitize_advisory_research_context(None),
            "evaluation_summary": sanitize_advisory_evaluation_summary(None),
            "collaboration_summary": (
                sanitize_advisory_collaboration_summary(None)
            ),
            "learning_signals": [],
            "governance_state": GOVERNANCE_UNKNOWN,
            "safety_state": SAFETY_UNKNOWN,
        }
    return {
        "research_context": sanitize_advisory_research_context(
            value.get("research_context")
        ),
        "evaluation_summary": sanitize_advisory_evaluation_summary(
            value.get("evaluation_summary")
        ),
        "collaboration_summary": sanitize_advisory_collaboration_summary(
            value.get("collaboration_summary")
        ),
        "learning_signals": sanitize_advisory_learning_signals(
            value.get("learning_signals")
        ),
        "governance_state": _closed(
            value.get("governance_state"),
            (
                "CONSISTENT_REFERENCED",
                "MIXED",
                GOVERNANCE_UNKNOWN,
            ),
            GOVERNANCE_UNKNOWN,
        ),
        "safety_state": _closed(
            value.get("safety_state"),
            ("PASS", "DEGRADED", "FAILED", SAFETY_UNKNOWN),
            SAFETY_UNKNOWN,
        ),
    }


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class LLMProviderRequestPlan(BaseModel):
    """Deterministic advisory provider request (R45.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_PROVIDER_RULE_VERSION
    advisory_id: str = ""
    advisory_mode: str = "SUMMARY"
    provider_kind: str = PROVIDER_KIND_MOCK
    source_layer: str = "UNKNOWN"
    instruction: str = ""
    sections: dict = Field(default_factory=dict)
    source_refs: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_PROVIDER_RULE_VERSION

    @field_validator("advisory_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("advisory_mode")
    @classmethod
    def _valid_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_MODES:
            raise ValueError(f"invalid advisory_mode: {value!r}")
        return text

    @field_validator("provider_kind")
    @classmethod
    def _valid_provider_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SUPPORTED_PROVIDER_KINDS:
            raise ValueError(f"unsupported provider_kind: {value!r}")
        return text

    @field_validator("source_layer")
    @classmethod
    def _valid_source_layer(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LLM_ADVISORY_SOURCE_LAYERS:
            raise ValueError(f"invalid source_layer: {value!r}")
        return text

    @field_validator("instruction")
    @classmethod
    def _bounded_instruction(cls, value: object) -> str:
        return _safe_text(value, MAX_ADVISORY_TEXT_LEN)

    @field_validator("sections")
    @classmethod
    def _bounded_sections(cls, value: object) -> dict:
        return sanitize_provider_request_sections(value)

    @field_validator("source_refs")
    @classmethod
    def _bounded_refs(cls, value: list) -> list[dict]:
        return sanitize_advisory_source_refs(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: list) -> list[str]:
        return _bounded_codes(value, PROVIDER_REQUEST_LIMITATIONS, MAX_LIST)

    @field_validator("research_only", "deterministic")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("provider requests are deterministic and "
                             "research-only")
        return True


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class LLMProviderResponsePlan(BaseModel):
    """Deterministic advisory provider response contract (R45.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_PROVIDER_RULE_VERSION
    provider_kind: str = PROVIDER_KIND_MOCK
    advisory_id: str = ""
    advisory_mode: str = "SUMMARY"
    summary: str = ""
    insights: list[dict] = Field(default_factory=list)
    recommendations: list[dict] = Field(default_factory=list)
    source_refs: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_PROVIDER_RULE_VERSION

    @field_validator("provider_kind")
    @classmethod
    def _valid_provider_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SUPPORTED_PROVIDER_KINDS:
            raise ValueError(f"unsupported provider_kind: {value!r}")
        return text

    @field_validator("advisory_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("advisory_mode")
    @classmethod
    def _valid_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_MODES:
            raise ValueError(f"invalid advisory_mode: {value!r}")
        return text

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> str:
        return _safe_text(value, MAX_ADVISORY_TEXT_LEN)

    @field_validator("insights")
    @classmethod
    def _bounded_insights(cls, value: list) -> list[dict]:
        return sanitize_advisory_insights(value)

    @field_validator("recommendations")
    @classmethod
    def _bounded_recommendations(cls, value: list) -> list[dict]:
        return sanitize_advisory_recommendations(value)

    @field_validator("source_refs")
    @classmethod
    def _bounded_refs(cls, value: list) -> list[dict]:
        return sanitize_advisory_source_refs(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: list) -> list[str]:
        return _bounded_codes(value, PROVIDER_LIMITATIONS, MAX_LIST)

    @field_validator("research_only", "deterministic")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("provider responses are deterministic and "
                             "research-only")
        return True


def llm_provider_request_plan_projection(
    value: LLMProviderRequestPlan,
) -> dict:
    """Serialize a provider request to a deterministic dict."""

    return value.model_dump(mode="json")


def llm_provider_response_plan_projection(
    value: LLMProviderResponsePlan,
) -> dict:
    """Serialize a provider response to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_PROVIDER_RULE_VERSION",
    "RULE_VERSION",
    "PROVIDER_KIND_MOCK",
    "SUPPORTED_PROVIDER_KINDS",
    "PROVIDER_KINDS",
    "FUTURE_PROVIDER_KINDS",
    "PROVIDER_KIND_OPENAI",
    "PROVIDER_KIND_OPENROUTER",
    "PROVIDER_KIND_OLLAMA",
    "PROVIDER_KIND_LOCAL",
    "SOURCE_REF_LAYERS",
    "SOURCE_REF_LAYER_R42",
    "SOURCE_REF_LAYER_R43",
    "SOURCE_REF_LAYER_R44",
    "SOURCE_REF_LAYER_R45",
    "PROVIDER_LIMITATIONS",
    "PROVIDER_REQUEST_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_CREDENTIALS_USED",
    "LIMITATION_DETERMINISTIC_MOCK",
    "LIMITATION_ADVISORY_ONLY",
    "MAX_SOURCE_REFS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "sanitize_advisory_source_refs",
    "sanitize_advisory_insights",
    "sanitize_advisory_recommendations",
    "sanitize_provider_request_sections",
    "LLMProviderRequestPlan",
    "LLMProviderResponsePlan",
    "llm_provider_request_plan_projection",
    "llm_provider_response_plan_projection",
]

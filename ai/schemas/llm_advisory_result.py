"""LLM advisory result schema (Stage R45.5).

An :class:`LLMAdvisoryResultPlan` is the deterministic, research-only result
of the advisory layer. It answers:

    "What human-readable advisory explanation was produced?"

Hard boundaries encoded here:

- Advisory only: the result explains structured layer outputs. It never
  confirms a vulnerability, never contains execution instructions, never
  generates payloads and never plans an attack. Rejected provider output is
  not included at all.
- Attribution is preserved: source references, provenance and governance
  visibility from the deterministic layers remain attached to the result.
- The deterministic layers stay authoritative: R42 evaluation, R43
  collaboration and R44 learning signals are consumed, never recomputed.
- ``deterministic`` and ``research_only`` are always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.llm_advisory_input import (
    ADVISORY_GOVERNANCE_STATES,
    ADVISORY_INPUT_LIMITATIONS,
    ADVISORY_SAFETY_STATES,
    GOVERNANCE_UNKNOWN,
    SAFETY_UNKNOWN,
)
from ai.schemas.llm_advisory_policy import (
    ADVISORY_MODES,
    MAX_ADVISORY_TEXT_LEN,
)
from ai.schemas.llm_provider import (
    PROVIDER_LIMITATIONS,
    sanitize_advisory_insights,
    sanitize_advisory_recommendations,
    sanitize_advisory_source_refs,
)

LLM_ADVISORY_RESULT_RULE_VERSION = "r45-5"
RULE_VERSION = LLM_ADVISORY_RESULT_RULE_VERSION

VALIDATION_PASS = "PASS"
VALIDATION_REJECTED = "REJECTED"

VALIDATION_STATES: tuple[str, ...] = (VALIDATION_PASS, VALIDATION_REJECTED)

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_UNKNOWN = "UNKNOWN"

ADVISORY_PROVENANCE_STATES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_DETERMINISTIC_MOCK = "DETERMINISTIC_MOCK_RESPONSE"

ADVISORY_RESULT_LIMITATIONS: tuple[str, ...] = tuple(
    dict.fromkeys(
        ADVISORY_INPUT_LIMITATIONS
        + PROVIDER_LIMITATIONS
        + (
            LIMITATION_NO_EXECUTION_PERFORMED,
            LIMITATION_NO_NETWORK_REQUESTS,
            LIMITATION_NO_VULNERABILITY_CONFIRMATION,
            LIMITATION_NO_EXPLOIT_GENERATION,
            LIMITATION_ADVISORY_ONLY,
        )
    )
)

VIOLATION_CODE_RE = re.compile(r"^[A-Z0-9_]{1,80}$")

MAX_DIAGNOSTICS = 16
MAX_SOURCE_REFS = 8
MAX_LIST = 16
MAX_VALUE_LEN = 160

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


def sanitize_advisory_provenance(value: object) -> dict:
    """Project advisory provenance onto a bounded shape."""

    if not isinstance(value, dict):
        return {
            "source_layers": [],
            "provenance_state": PROVENANCE_UNKNOWN,
            "research_only": True,
        }
    layers: list[str] = []
    for item in value.get("source_layers") or ():
        text = _safe_text(item).strip().upper()
        if text in ("R42", "R43", "R44") and text not in layers:
            layers.append(text)
    return {
        "source_layers": layers,
        "provenance_state": _closed(
            value.get("provenance_state"),
            ADVISORY_PROVENANCE_STATES,
            PROVENANCE_UNKNOWN,
        ),
        "research_only": True,
    }


def sanitize_advisory_governance(value: object) -> dict:
    """Project advisory governance visibility onto a bounded shape."""

    if not isinstance(value, dict):
        return {
            "governance_state": GOVERNANCE_UNKNOWN,
            "reference_present": False,
            "research_only": True,
        }
    return {
        "governance_state": _closed(
            value.get("governance_state"),
            ADVISORY_GOVERNANCE_STATES,
            GOVERNANCE_UNKNOWN,
        ),
        "reference_present": bool(
            value.get("reference_present", False)
        ) is True,
        "research_only": True,
    }


def sanitize_advisory_validation_diagnostics(value: object) -> list[dict]:
    """Project validator diagnostics onto a bounded deterministic shape."""

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
        code = _safe_text(item.get("violation_code")).strip().upper()
        if not code or not VIOLATION_CODE_RE.match(code):
            continue
        out.append(
            {
                "rule_version": _safe_text(
                    item.get("rule_version")
                ) or LLM_ADVISORY_RESULT_RULE_VERSION,
                "violation_code": code,
                "category": _safe_text(
                    item.get("category")
                ).strip().upper(),
                "severity": _safe_text(
                    item.get("severity")
                ).strip().upper(),
                "field": _safe_text(item.get("field")),
            }
        )
        if len(out) >= MAX_DIAGNOSTICS:
            break
    return out


def sanitize_llm_advisory_result(value: object) -> dict:
    """Project an advisory result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    validation_state = _closed(
        value.get("validation_state"), VALIDATION_STATES, VALIDATION_REJECTED
    )
    result = {
        "rule_version": _safe_text(value.get("rule_version")),
        "advisory_rule_version": _safe_text(
            value.get("advisory_rule_version")
        ),
        "advisory_id": _safe_text(value.get("advisory_id")),
        "advisory_mode": _closed(
            value.get("advisory_mode"), ADVISORY_MODES, "SUMMARY"
        ),
        "summary": _safe_text(
            value.get("summary"), MAX_ADVISORY_TEXT_LEN
        ),
        "insights": sanitize_advisory_insights(value.get("insights")),
        "recommendations": sanitize_advisory_recommendations(
            value.get("recommendations")
        ),
        "source_refs": sanitize_advisory_source_refs(
            value.get("source_refs")
        ),
        "provenance": sanitize_advisory_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_advisory_governance(
            value.get("governance")
        ),
        "validation_state": validation_state,
        "validation_diagnostics": (
            sanitize_advisory_validation_diagnostics(
                value.get("validation_diagnostics")
            )
        ),
        "safety_state": _closed(
            value.get("safety_state"),
            ADVISORY_SAFETY_STATES,
            SAFETY_UNKNOWN,
        ),
        "limitations": _bounded_codes(
            value.get("limitations"), ADVISORY_RESULT_LIMITATIONS, MAX_LIST
        ),
        "research_only": bool(value.get("research_only", True)) is True,
        "deterministic": bool(value.get("deterministic", True)) is True,
    }
    if validation_state == VALIDATION_REJECTED:
        result["summary"] = ""
        result["insights"] = []
        result["recommendations"] = []
    return result


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LLMAdvisoryResultPlan(BaseModel):
    """Deterministic advisory result (R45.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_ADVISORY_RESULT_RULE_VERSION
    advisory_rule_version: str = LLM_ADVISORY_RESULT_RULE_VERSION
    advisory_id: str = ""
    advisory_mode: str = "SUMMARY"
    summary: str = ""
    insights: list[dict] = Field(default_factory=list)
    recommendations: list[dict] = Field(default_factory=list)
    source_refs: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    validation_state: str = VALIDATION_PASS
    validation_diagnostics: list[dict] = Field(default_factory=list)
    safety_state: str = SAFETY_UNKNOWN
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version", "advisory_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_ADVISORY_RESULT_RULE_VERSION

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

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_advisory_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_advisory_governance(value)

    @field_validator("validation_state")
    @classmethod
    def _valid_validation_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in VALIDATION_STATES:
            raise ValueError(f"invalid validation_state: {value!r}")
        return text

    @field_validator("validation_diagnostics")
    @classmethod
    def _bounded_diagnostics(cls, value: list) -> list[dict]:
        return sanitize_advisory_validation_diagnostics(value)

    @field_validator("safety_state")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_SAFETY_STATES:
            raise ValueError(f"invalid safety_state: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: list) -> list[str]:
        return _bounded_codes(value, ADVISORY_RESULT_LIMITATIONS, MAX_LIST)

    @field_validator("research_only", "deterministic")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("advisory results are deterministic and "
                             "research-only")
        return True


def llm_advisory_result_plan_projection(
    value: LLMAdvisoryResultPlan,
) -> dict:
    """Serialize an advisory result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_ADVISORY_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_PASS",
    "VALIDATION_REJECTED",
    "VALIDATION_STATES",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "ADVISORY_PROVENANCE_STATES",
    "ADVISORY_RESULT_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_DETERMINISTIC_MOCK",
    "VIOLATION_CODE_RE",
    "MAX_DIAGNOSTICS",
    "MAX_SOURCE_REFS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "sanitize_advisory_provenance",
    "sanitize_advisory_governance",
    "sanitize_advisory_validation_diagnostics",
    "sanitize_llm_advisory_result",
    "LLMAdvisoryResultPlan",
    "llm_advisory_result_plan_projection",
]

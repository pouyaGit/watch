"""LLM advisory policy schema (Stage R45.2).

An :class:`LLMAdvisoryPolicyPlan` is the deterministic, research-only policy
that constrains what the advisory layer may explain. It answers:

    "Which advisory modes are allowed, and which are forbidden?"

Hard boundaries encoded here:

- Advisory only: the policy describes explanation modes. It never grants
  execution, scanning, exploitation or confirmation authority.
- The allowed and forbidden mode vocabularies are closed and fixed; they are
  not runtime configurable.
- No execution, no network, no database, no browser, no provider call, no
  payloads.
- ``deterministic`` and ``research_only`` are always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

LLM_ADVISORY_POLICY_RULE_VERSION = "r45-2"
RULE_VERSION = LLM_ADVISORY_POLICY_RULE_VERSION

# ---------------------------------------------------------------------------
# Allowed advisory modes (closed)
# ---------------------------------------------------------------------------

MODE_SUMMARY = "SUMMARY"
MODE_EXPLANATION = "EXPLANATION"
MODE_RESEARCH_PRIORITY = "RESEARCH_PRIORITY"
MODE_CONFLICT_EXPLANATION = "CONFLICT_EXPLANATION"
MODE_LEARNING_SUMMARY = "LEARNING_SUMMARY"

ADVISORY_MODES: tuple[str, ...] = (
    MODE_SUMMARY,
    MODE_EXPLANATION,
    MODE_RESEARCH_PRIORITY,
    MODE_CONFLICT_EXPLANATION,
    MODE_LEARNING_SUMMARY,
)

DEFAULT_ADVISORY_MODE = MODE_SUMMARY

# ---------------------------------------------------------------------------
# Forbidden advisory modes (closed)
# ---------------------------------------------------------------------------

MODE_EXPLOITATION = "EXPLOITATION"
MODE_EXECUTION = "EXECUTION"
MODE_PAYLOAD_GENERATION = "PAYLOAD_GENERATION"
MODE_VULNERABILITY_CONFIRMATION = "VULNERABILITY_CONFIRMATION"
MODE_ATTACK_PLANNING = "ATTACK_PLANNING"

FORBIDDEN_ADVISORY_MODES: tuple[str, ...] = (
    MODE_EXPLOITATION,
    MODE_EXECUTION,
    MODE_PAYLOAD_GENERATION,
    MODE_VULNERABILITY_CONFIRMATION,
    MODE_ATTACK_PLANNING,
)

ADVISORY_MODE_ORDER: dict[str, int] = {
    mode: index for index, mode in enumerate(ADVISORY_MODES)
}

# ---------------------------------------------------------------------------
# Policy limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

ADVISORY_POLICY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_ADVISORY_ONLY,
)

MAX_INSIGHTS = 8
MAX_RECOMMENDATIONS = 8
MAX_ADVISORY_TEXT_LEN = 400
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def sanitize_llm_advisory_policy(value: object) -> dict:
    """Project an advisory policy onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "allowed_modes": list(ADVISORY_MODES),
        "forbidden_modes": list(FORBIDDEN_ADVISORY_MODES),
        "default_mode": DEFAULT_ADVISORY_MODE,
        "max_insights": MAX_INSIGHTS,
        "max_recommendations": MAX_RECOMMENDATIONS,
        "limitations": list(ADVISORY_POLICY_LIMITATIONS),
        "deterministic": True,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LLMAdvisoryPolicyPlan(BaseModel):
    """Deterministic advisory policy (R45.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_ADVISORY_POLICY_RULE_VERSION
    allowed_modes: list[str] = Field(default_factory=lambda: list(ADVISORY_MODES))
    forbidden_modes: list[str] = Field(
        default_factory=lambda: list(FORBIDDEN_ADVISORY_MODES)
    )
    default_mode: str = DEFAULT_ADVISORY_MODE
    max_insights: int = MAX_INSIGHTS
    max_recommendations: int = MAX_RECOMMENDATIONS
    limitations: list[str] = Field(
        default_factory=lambda: list(ADVISORY_POLICY_LIMITATIONS)
    )
    deterministic: bool = True
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_ADVISORY_POLICY_RULE_VERSION

    @field_validator("allowed_modes")
    @classmethod
    def _fixed_allowed(cls, value: object) -> list[str]:
        return list(ADVISORY_MODES)

    @field_validator("forbidden_modes")
    @classmethod
    def _fixed_forbidden(cls, value: object) -> list[str]:
        return list(FORBIDDEN_ADVISORY_MODES)

    @field_validator("default_mode")
    @classmethod
    def _fixed_default(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text != DEFAULT_ADVISORY_MODE:
            raise ValueError(f"invalid default_mode: {value!r}")
        return text

    @field_validator("max_insights")
    @classmethod
    def _fixed_max_insights(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_insights: {value!r}")
        if value != MAX_INSIGHTS:
            raise ValueError(f"max_insights is fixed: {value!r}")
        return value

    @field_validator("max_recommendations")
    @classmethod
    def _fixed_max_recommendations(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid max_recommendations: {value!r}")
        if value != MAX_RECOMMENDATIONS:
            raise ValueError(f"max_recommendations is fixed: {value!r}")
        return value

    @field_validator("limitations")
    @classmethod
    def _fixed_limitations(cls, value: object) -> list[str]:
        return list(ADVISORY_POLICY_LIMITATIONS)

    @field_validator("deterministic", "research_only")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("advisory policy is deterministic and research-only")
        return True


def llm_advisory_policy_plan_projection(value: LLMAdvisoryPolicyPlan) -> dict:
    """Serialize an advisory policy to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_ADVISORY_POLICY_RULE_VERSION",
    "RULE_VERSION",
    "ADVISORY_MODES",
    "MODE_SUMMARY",
    "MODE_EXPLANATION",
    "MODE_RESEARCH_PRIORITY",
    "MODE_CONFLICT_EXPLANATION",
    "MODE_LEARNING_SUMMARY",
    "DEFAULT_ADVISORY_MODE",
    "ADVISORY_MODE_ORDER",
    "FORBIDDEN_ADVISORY_MODES",
    "MODE_EXPLOITATION",
    "MODE_EXECUTION",
    "MODE_PAYLOAD_GENERATION",
    "MODE_VULNERABILITY_CONFIRMATION",
    "MODE_ATTACK_PLANNING",
    "ADVISORY_POLICY_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_ADVISORY_ONLY",
    "MAX_INSIGHTS",
    "MAX_RECOMMENDATIONS",
    "MAX_ADVISORY_TEXT_LEN",
    "MAX_VALUE_LEN",
    "sanitize_llm_advisory_policy",
    "LLMAdvisoryPolicyPlan",
    "llm_advisory_policy_plan_projection",
]

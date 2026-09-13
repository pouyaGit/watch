"""Execution risk schema (Stage R36.4).

An :class:`ExecutionRiskPlan` is the deterministic, bounded execution-safety
risk classification for one research candidate:

    "How risky would the authorized (or blocked) plan be?"

Hard boundaries encoded here:

- Planning only: risk is a closed classification label. No execution runtime,
  worker queue, scheduler, dispatch, subprocess, shell command, browser,
  network, Mongo persistence or LLM call is represented or created.
- Risk is NOT permission: authorization (R36.2) is authoritative and is never
  weakened or overridden by a low risk result. ``authorization_authoritative``
  is forced ``True``.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXECUTION_RISK_RULE_VERSION = "r36-4"
RULE_VERSION = EXECUTION_RISK_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"
RISK_UNKNOWN = "UNKNOWN"

RISK_LEVELS: tuple[str, ...] = (
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
    RISK_UNKNOWN,
)

REASON_ACTIVE_AUTHORIZED = "ACTIVE_AUTHORIZED"
REASON_LIMITED_AUTHORIZATION = "LIMITED_AUTHORIZATION"
REASON_HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
REASON_AUTHORIZATION_BLOCK = "AUTHORIZATION_BLOCK"
REASON_UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"

RISK_REASONS: tuple[str, ...] = (
    REASON_ACTIVE_AUTHORIZED,
    REASON_LIMITED_AUTHORIZATION,
    REASON_HUMAN_APPROVAL_REQUIRED,
    REASON_AUTHORIZATION_BLOCK,
    REASON_UNKNOWN_CONTEXT,
)

FACTOR_ACTIVE_AUTHORIZED = "ACTIVE_AUTHORIZED"
FACTOR_LIMITED_AUTHORIZATION = "LIMITED_AUTHORIZATION"
FACTOR_HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
FACTOR_AUTHORIZATION_BLOCK = "AUTHORIZATION_BLOCK"
FACTOR_MISSING_SCOPE = "MISSING_SCOPE"
FACTOR_INVALID_WORKFLOW = "INVALID_WORKFLOW"
FACTOR_LOW_CONFIDENCE = "LOW_CONFIDENCE"
FACTOR_APPROVAL_REJECTED = "APPROVAL_REJECTED"
FACTOR_APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
FACTOR_UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"

RISK_FACTORS: tuple[str, ...] = (
    FACTOR_ACTIVE_AUTHORIZED,
    FACTOR_LIMITED_AUTHORIZATION,
    FACTOR_HUMAN_APPROVAL_REQUIRED,
    FACTOR_AUTHORIZATION_BLOCK,
    FACTOR_MISSING_SCOPE,
    FACTOR_INVALID_WORKFLOW,
    FACTOR_LOW_CONFIDENCE,
    FACTOR_APPROVAL_REJECTED,
    FACTOR_APPROVAL_EXPIRED,
    FACTOR_UNKNOWN_CONTEXT,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_FACTORS = 8
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


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


def sanitize_execution_risk_plan(value: object) -> dict:
    """Project an R36.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "risk_level": "",
            "risk_reason": "",
            "risk_factors": [],
            "authorization_authoritative": True,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "risk_level": _safe_text(value.get("risk_level")),
        "risk_reason": _safe_text(value.get("risk_reason")),
        "risk_factors": _bounded_codes(
            value.get("risk_factors"), RISK_FACTORS, MAX_FACTORS
        ),
        "authorization_authoritative": True,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionRiskPlan(BaseModel):
    """Deterministic execution risk classification (R36.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_RISK_RULE_VERSION
    risk_level: str
    risk_reason: str
    risk_factors: list[str] = Field(default_factory=list)
    authorization_authoritative: bool = True
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_RISK_RULE_VERSION

    @field_validator("risk_level")
    @classmethod
    def _valid_level(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RISK_LEVELS:
            raise ValueError(f"invalid risk_level: {value!r}")
        return text

    @field_validator("risk_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RISK_REASONS:
            raise ValueError(f"invalid risk_reason: {value!r}")
        return text

    @field_validator("risk_factors")
    @classmethod
    def _valid_factors(cls, value: list) -> list[str]:
        return _require_codes(value, RISK_FACTORS, MAX_FACTORS)

    @field_validator("authorization_authoritative")
    @classmethod
    def _authoritative(cls, value: object) -> bool:
        if not value:
            raise ValueError("authorization is always authoritative")
        return True

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution risk plans are research-only")
        return True


def execution_risk_plan_projection(value: ExecutionRiskPlan) -> dict:
    """Serialize an execution risk plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_RISK_RULE_VERSION",
    "RULE_VERSION",
    "RISK_LEVELS",
    "RISK_REASONS",
    "RISK_FACTORS",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "RISK_UNKNOWN",
    "REASON_ACTIVE_AUTHORIZED",
    "REASON_LIMITED_AUTHORIZATION",
    "REASON_HUMAN_APPROVAL_REQUIRED",
    "REASON_AUTHORIZATION_BLOCK",
    "REASON_UNKNOWN_CONTEXT",
    "FACTOR_ACTIVE_AUTHORIZED",
    "FACTOR_LIMITED_AUTHORIZATION",
    "FACTOR_HUMAN_APPROVAL_REQUIRED",
    "FACTOR_AUTHORIZATION_BLOCK",
    "FACTOR_MISSING_SCOPE",
    "FACTOR_INVALID_WORKFLOW",
    "FACTOR_LOW_CONFIDENCE",
    "FACTOR_APPROVAL_REJECTED",
    "FACTOR_APPROVAL_EXPIRED",
    "FACTOR_UNKNOWN_CONTEXT",
    "MAX_FACTORS",
    "MAX_VALUE_LEN",
    "ExecutionRiskPlan",
    "sanitize_execution_risk_plan",
    "execution_risk_plan_projection",
]

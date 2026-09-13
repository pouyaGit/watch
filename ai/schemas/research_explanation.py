"""Research explanation schema (Stage R37.4).

A :class:`ResearchExplanationPlan` is a deterministic human-readable
explanation of an authorization decision. It answers the audit question:

    "Why was this decision made, in bounded governance terms?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  represented or created.
- No hallucinated reasons: every reason/limitation is a closed code derived
  only from the strategy/orchestration/authorization/provenance/rule-trace
  inputs; no free-form text and no LLM participates.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

RESEARCH_EXPLANATION_RULE_VERSION = "r37-4"
RULE_VERSION = RESEARCH_EXPLANATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SUMMARY_AUTHORIZED = "EXPLANATION_AUTHORIZED"
SUMMARY_LIMITED = "EXPLANATION_LIMITED"
SUMMARY_HUMAN_APPROVAL = "EXPLANATION_HUMAN_APPROVAL"
SUMMARY_BLOCKED = "EXPLANATION_BLOCKED"
SUMMARY_UNKNOWN = "EXPLANATION_UNKNOWN"

EXPLANATION_SUMMARIES: tuple[str, ...] = (
    SUMMARY_AUTHORIZED,
    SUMMARY_LIMITED,
    SUMMARY_HUMAN_APPROVAL,
    SUMMARY_BLOCKED,
    SUMMARY_UNKNOWN,
)

REASON_POLICY_RESEARCH_ONLY = "POLICY_RESEARCH_ONLY"
REASON_POLICY_PASSIVE_ONLY = "POLICY_PASSIVE_ONLY"
REASON_POLICY_ACTIVE_ALLOWED = "POLICY_ACTIVE_ALLOWED"
REASON_POLICY_BLOCKED = "POLICY_BLOCKED"
REASON_POLICY_HUMAN_APPROVAL = "POLICY_HUMAN_APPROVAL_REQUIRED"
REASON_CONTEXT_INCOMPLETE = "CONTEXT_INCOMPLETE"
REASON_SCOPE_UNKNOWN = "SCOPE_UNKNOWN"
REASON_BOUNDARY_BLOCKED = "BOUNDARY_BLOCKED"
REASON_APPROVAL_PENDING = "APPROVAL_PENDING"
REASON_RISK_ELEVATED = "RISK_ELEVATED"

EXPLANATION_REASONS: tuple[str, ...] = (
    REASON_POLICY_RESEARCH_ONLY,
    REASON_POLICY_PASSIVE_ONLY,
    REASON_POLICY_ACTIVE_ALLOWED,
    REASON_POLICY_BLOCKED,
    REASON_POLICY_HUMAN_APPROVAL,
    REASON_CONTEXT_INCOMPLETE,
    REASON_SCOPE_UNKNOWN,
    REASON_BOUNDARY_BLOCKED,
    REASON_APPROVAL_PENDING,
    REASON_RISK_ELEVATED,
)

LIMITATION_SOURCE_CONTEXT_MISSING = "SOURCE_CONTEXT_MISSING"
LIMITATION_PARTIAL_PROVENANCE = "PARTIAL_PROVENANCE"
LIMITATION_SCOPE_UNKNOWN = "SCOPE_UNKNOWN"
LIMITATION_UNKNOWN_EXPLANATION = "UNKNOWN_EXPLANATION"

EXPLANATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_SOURCE_CONTEXT_MISSING,
    LIMITATION_PARTIAL_PROVENANCE,
    LIMITATION_SCOPE_UNKNOWN,
    LIMITATION_UNKNOWN_EXPLANATION,
)

EXPLANATION_COMPLETE = "COMPLETE"
EXPLANATION_PARTIAL = "PARTIAL"
EXPLANATION_UNKNOWN = "UNKNOWN"

EXPLANATION_STATES: tuple[str, ...] = (
    EXPLANATION_COMPLETE,
    EXPLANATION_PARTIAL,
    EXPLANATION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_REASONS = 8
MAX_LIMITATIONS = 6
MAX_VALUE_LEN = 160

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


def sanitize_research_explanation_plan(value: object) -> dict:
    """Project an R37.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "summary": "",
            "reasons": [],
            "limitations": [],
            "confidence": "",
            "explanation_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "summary": _safe_text(value.get("summary")),
        "reasons": _bounded_codes(
            value.get("reasons"), EXPLANATION_REASONS, MAX_REASONS
        ),
        "limitations": _bounded_codes(
            value.get("limitations"), EXPLANATION_LIMITATIONS,
            MAX_LIMITATIONS,
        ),
        "confidence": _safe_text(value.get("confidence")),
        "explanation_state": _safe_text(value.get("explanation_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchExplanationPlan(BaseModel):
    """Deterministic governance explanation (R37.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_EXPLANATION_RULE_VERSION
    summary: str
    reasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence: str
    explanation_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_EXPLANATION_RULE_VERSION

    @field_validator("summary")
    @classmethod
    def _valid_summary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXPLANATION_SUMMARIES:
            raise ValueError(f"invalid summary: {value!r}")
        return text

    @field_validator("reasons")
    @classmethod
    def _valid_reasons(cls, value: list) -> list[str]:
        return _require_codes(value, EXPLANATION_REASONS, MAX_REASONS)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, EXPLANATION_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("explanation_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXPLANATION_STATES:
            raise ValueError(f"invalid explanation_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research explanations are research-only")
        return True


def research_explanation_plan_projection(
    value: ResearchExplanationPlan,
) -> dict:
    """Serialize a research explanation to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_EXPLANATION_RULE_VERSION",
    "RULE_VERSION",
    "EXPLANATION_SUMMARIES",
    "EXPLANATION_REASONS",
    "EXPLANATION_LIMITATIONS",
    "EXPLANATION_STATES",
    "SUMMARY_AUTHORIZED",
    "SUMMARY_LIMITED",
    "SUMMARY_HUMAN_APPROVAL",
    "SUMMARY_BLOCKED",
    "SUMMARY_UNKNOWN",
    "REASON_POLICY_RESEARCH_ONLY",
    "REASON_POLICY_PASSIVE_ONLY",
    "REASON_POLICY_ACTIVE_ALLOWED",
    "REASON_POLICY_BLOCKED",
    "REASON_POLICY_HUMAN_APPROVAL",
    "REASON_CONTEXT_INCOMPLETE",
    "REASON_SCOPE_UNKNOWN",
    "REASON_BOUNDARY_BLOCKED",
    "REASON_APPROVAL_PENDING",
    "REASON_RISK_ELEVATED",
    "LIMITATION_SOURCE_CONTEXT_MISSING",
    "LIMITATION_PARTIAL_PROVENANCE",
    "LIMITATION_SCOPE_UNKNOWN",
    "LIMITATION_UNKNOWN_EXPLANATION",
    "EXPLANATION_COMPLETE",
    "EXPLANATION_PARTIAL",
    "EXPLANATION_UNKNOWN",
    "MAX_REASONS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchExplanationPlan",
    "sanitize_research_explanation_plan",
    "research_explanation_plan_projection",
]

"""Research governance export schema (Stage R37.5).

A :class:`ResearchGovernanceExportPlan` is the final deterministic, read-only
export of the R37 governance layer. It answers the governance question:

    "Is the governance/audit record complete and internally valid?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  represented or created.
- ``ready`` is true only when provenance, rule trace, audit event and
  explanation are all present and valid; UNKNOWN critical states prevent
  readiness.
- Bounded, privacy-safe, JSON serializable: embedded plans are projected onto
  fixed closed key sets and sanitized.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.decision_provenance import sanitize_decision_provenance_plan
from ai.schemas.governance_rule_trace import (
    sanitize_governance_rule_trace_plan,
)
from ai.schemas.research_audit_event import (
    sanitize_research_audit_event_plan,
)
from ai.schemas.research_explanation import sanitize_research_explanation_plan

RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION = "r37-5"
RULE_VERSION = RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_UNKNOWN_PROVENANCE = "UNKNOWN_PROVENANCE"
LIMITATION_UNKNOWN_RULE_TRACE = "UNKNOWN_RULE_TRACE"
LIMITATION_INVALID_AUDIT_EVENT = "INVALID_AUDIT_EVENT"
LIMITATION_UNKNOWN_AUDIT_EVENT = "UNKNOWN_AUDIT_EVENT"
LIMITATION_UNKNOWN_EXPLANATION = "UNKNOWN_EXPLANATION"
LIMITATION_MISSING_SOURCES = "MISSING_SOURCES"

GOVERNANCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_UNKNOWN_PROVENANCE,
    LIMITATION_UNKNOWN_RULE_TRACE,
    LIMITATION_INVALID_AUDIT_EVENT,
    LIMITATION_UNKNOWN_AUDIT_EVENT,
    LIMITATION_UNKNOWN_EXPLANATION,
    LIMITATION_MISSING_SOURCES,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_LIMITATIONS = 8
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


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchGovernanceExportPlan(BaseModel):
    """Final deterministic R37 governance export object (R37.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION
    ready: bool
    provenance: dict = Field(default_factory=dict)
    rule_trace: dict = Field(default_factory=dict)
    audit_event: dict = Field(default_factory=dict)
    explanation: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_decision_provenance_plan(value)

    @field_validator("rule_trace")
    @classmethod
    def _bounded_trace(cls, value: object) -> dict:
        return sanitize_governance_rule_trace_plan(value)

    @field_validator("audit_event")
    @classmethod
    def _bounded_audit(cls, value: object) -> dict:
        return sanitize_research_audit_event_plan(value)

    @field_validator("explanation")
    @classmethod
    def _bounded_explanation(cls, value: object) -> dict:
        return sanitize_research_explanation_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(value, GOVERNANCE_LIMITATIONS, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research governance exports are research-only")
        return True


def research_governance_export_plan_projection(
    value: ResearchGovernanceExportPlan,
) -> dict:
    """Serialize a governance export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "GOVERNANCE_LIMITATIONS",
    "LIMITATION_UNKNOWN_PROVENANCE",
    "LIMITATION_UNKNOWN_RULE_TRACE",
    "LIMITATION_INVALID_AUDIT_EVENT",
    "LIMITATION_UNKNOWN_AUDIT_EVENT",
    "LIMITATION_UNKNOWN_EXPLANATION",
    "LIMITATION_MISSING_SOURCES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchGovernanceExportPlan",
    "research_governance_export_plan_projection",
]

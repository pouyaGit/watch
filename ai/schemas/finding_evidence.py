"""Finding evidence linkage schema (Stage R53.4).

A :class:`FindingEvidencePlan` links a finding candidate to the structured
evidence artifacts produced upstream. It answers:

    "Which structured evidence does this finding rest on, and how complete is
     it?"

Hard boundaries encoded here:

- Linkage only: R53 collects no evidence. Everything is a bounded reference
  to an upstream structured contract (specialist evidence plan, R43 merged
  evidence) or an observed structured context fact.
- Explicit separation: observed structured facts, planned evidence
  requirements and missing evidence are represented by different fields so
  a requirement can never be mistaken for a collected observation.
- Assumptions are never manufactured: ``assumptions_recorded`` is forced
  ``False``.
- No promotion: completeness mirrors the upstream closed state and never
  upgrades it.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.collaboration_evidence import (
    sanitize_collaboration_evidence_item,
)
from ai.schemas.finding_context import sanitize_context_facts

FINDING_EVIDENCE_RULE_VERSION = "r53-4"
RULE_VERSION = FINDING_EVIDENCE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_PARTIAL = "PARTIAL"
COMPLETENESS_MISSING = "MISSING"
COMPLETENESS_UNKNOWN = "UNKNOWN"

EVIDENCE_COMPLETENESS_LEVELS: tuple[str, ...] = (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_MISSING,
    COMPLETENESS_UNKNOWN,
)

ORIGIN_SPECIALIST_PLAN = "SPECIALIST_PLAN"
ORIGIN_COLLABORATION_MERGED = "COLLABORATION_MERGED"
ORIGIN_NONE = "NONE"
ORIGIN_UNKNOWN = "UNKNOWN"

EVIDENCE_ORIGINS: tuple[str, ...] = (
    ORIGIN_SPECIALIST_PLAN,
    ORIGIN_COLLABORATION_MERGED,
    ORIGIN_NONE,
    ORIGIN_UNKNOWN,
)

MAX_PLANNED_REQUIREMENTS = 32
MAX_MERGED_REQUIREMENTS = 16
MAX_EVIDENCE_REFERENCES = 16
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_tokens(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text or not _TOKEN_RE.match(text) or text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_finding_evidence(value: object) -> dict:
    """Project an evidence linkage onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_state": "UNKNOWN",
            "evidence_completeness": COMPLETENESS_MISSING,
            "evidence_origin": ORIGIN_NONE,
            "observed_context": [],
            "planned_requirements": [],
            "merged_requirements": [],
            "evidence_references": [],
            "evidence_missing": True,
            "assumptions_recorded": False,
            "research_only": True,
        }
    planned = _bounded_tokens(
        value.get("planned_requirements"), MAX_PLANNED_REQUIREMENTS
    )
    merged: list[dict] = []
    for item in value.get("merged_requirements") or ():
        if isinstance(item, dict):
            projected = sanitize_collaboration_evidence_item(item)
            if projected["evidence_category"]:
                merged.append(projected)
        if len(merged) >= MAX_MERGED_REQUIREMENTS:
            break
    references: list[str] = []
    for item in value.get("evidence_references") or ():
        text = _safe_text(item, 120)
        if text and text not in references:
            references.append(text)
        if len(references) >= MAX_EVIDENCE_REFERENCES:
            break
    completeness = value.get("evidence_completeness")
    if completeness not in EVIDENCE_COMPLETENESS_LEVELS:
        completeness = None
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_state": _safe_text(value.get("evidence_state")).upper(),
        "evidence_completeness": completeness
        or derive_evidence_completeness(
            value.get("evidence_state"), planned, merged
        ),
        "evidence_origin": (
            value.get("evidence_origin")
            if value.get("evidence_origin") in EVIDENCE_ORIGINS
            else derive_evidence_origin(planned, merged)
        ),
        "observed_context": sanitize_context_facts(
            value.get("observed_context")
        ),
        "planned_requirements": planned,
        "merged_requirements": merged,
        "evidence_references": references,
        "evidence_missing": bool(planned or merged) is False,
        "assumptions_recorded": False,
        "research_only": True,
    }


def derive_evidence_origin(planned: list, merged: list) -> str:
    """Derive the evidence origin from what was actually supplied."""

    if planned and merged:
        return ORIGIN_COLLABORATION_MERGED
    if planned:
        return ORIGIN_SPECIALIST_PLAN
    if merged:
        return ORIGIN_COLLABORATION_MERGED
    return ORIGIN_NONE


def derive_evidence_completeness(
    evidence_state: object,
    planned: list,
    merged: list,
) -> str:
    """Derive evidence completeness conservatively from closed states.

    A complete evidence *plan* is not collected evidence: completeness is
    reported at plan granularity and never upgraded beyond the upstream
    closed state.
    """

    state = _safe_text(evidence_state).strip().upper() or "UNKNOWN"
    has_items = bool(planned or merged)
    if not has_items and state == "UNKNOWN":
        return COMPLETENESS_MISSING
    if state == "COMPLETE" and has_items:
        return COMPLETENESS_COMPLETE
    if state == "PARTIAL" and has_items:
        return COMPLETENESS_PARTIAL
    if state == "PARTIAL" and not has_items:
        return COMPLETENESS_PARTIAL
    if state == "COMPLETE" and not has_items:
        return COMPLETENESS_UNKNOWN
    return COMPLETENESS_UNKNOWN


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class FindingEvidencePlan(BaseModel):
    """Structured evidence linkage of a finding candidate (R53.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_EVIDENCE_RULE_VERSION
    evidence_state: str = "UNKNOWN"
    evidence_completeness: str = COMPLETENESS_MISSING
    evidence_origin: str = ORIGIN_NONE
    observed_context: list[dict] = Field(default_factory=list)
    planned_requirements: list[str] = Field(default_factory=list)
    merged_requirements: list[dict] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    evidence_missing: bool = True
    assumptions_recorded: bool = False
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_EVIDENCE_RULE_VERSION

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ("COMPLETE", "PARTIAL", "UNKNOWN"):
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("evidence_completeness")
    @classmethod
    def _valid_completeness(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_COMPLETENESS_LEVELS:
            raise ValueError(f"invalid evidence_completeness: {value!r}")
        return text

    @field_validator("evidence_origin")
    @classmethod
    def _valid_origin(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_ORIGINS:
            raise ValueError(f"invalid evidence_origin: {value!r}")
        return text

    @field_validator("observed_context")
    @classmethod
    def _bounded_observed(cls, value: object) -> list[dict]:
        return sanitize_context_facts(value)

    @field_validator("planned_requirements")
    @classmethod
    def _bounded_planned(cls, value: object) -> list[str]:
        return _bounded_tokens(value, MAX_PLANNED_REQUIREMENTS)

    @field_validator("merged_requirements")
    @classmethod
    def _bounded_merged(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                projected = sanitize_collaboration_evidence_item(item)
                if projected["evidence_category"]:
                    out.append(projected)
            if len(out) >= MAX_MERGED_REQUIREMENTS:
                break
        return out

    @field_validator("evidence_references")
    @classmethod
    def _bounded_references(cls, value: object) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item, 120)
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_EVIDENCE_REFERENCES:
                break
        return out

    @field_validator("evidence_missing")
    @classmethod
    def _missing_is_bool(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError("evidence_missing must be a boolean")
        return value

    @field_validator("assumptions_recorded")
    @classmethod
    def _no_assumptions(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("R53 never records assumptions as evidence")
        return False

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding evidence is research-only")
        return True


def finding_evidence_plan_projection(value: FindingEvidencePlan) -> dict:
    """Serialize an evidence linkage to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_EVIDENCE_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_COMPLETENESS_LEVELS",
    "EVIDENCE_ORIGINS",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPLETENESS_MISSING",
    "COMPLETENESS_UNKNOWN",
    "ORIGIN_SPECIALIST_PLAN",
    "ORIGIN_COLLABORATION_MERGED",
    "ORIGIN_NONE",
    "ORIGIN_UNKNOWN",
    "MAX_PLANNED_REQUIREMENTS",
    "MAX_MERGED_REQUIREMENTS",
    "MAX_EVIDENCE_REFERENCES",
    "MAX_VALUE_LEN",
    "sanitize_finding_evidence",
    "derive_evidence_origin",
    "derive_evidence_completeness",
    "FindingEvidencePlan",
    "finding_evidence_plan_projection",
]

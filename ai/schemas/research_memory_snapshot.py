"""Research memory snapshot schema (Stage R32.1).

A :class:`ResearchMemorySnapshot` is one immutable, deterministic historical
record derived from an R31.22 research intelligence export. It answers the
owner's personal-research question:

    "What was the research state at this point in history?"

Hard boundaries encoded here:

- Immutable behavior: the pydantic model is ``frozen=True`` and unknown fields
  are rejected; consumers receive a fresh dict projection.
- Deterministic: no clock is ever read. ``timestamp_reference`` is an explicit
  caller-supplied reference (default ``UNSPECIFIED``), never system time.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: research status, outcome, confidence, feedback,
  improvement area and blocker codes are closed sets owned by the R31 stages.
- Bounded, privacy-safe: the embedded source export is projected onto fixed,
  closed keys and sanitized.

No I/O, no network, no LLM, no Mongo, no persistence, no execution of any kind
is represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
)
from ai.schemas.evidence_feedback_calibration import (
    FEEDBACK_TYPES,
    IMPROVEMENT_AREAS,
)
from ai.schemas.evidence_research_outcome import OUTCOMES
from ai.schemas.research_consistency_validation import (
    sanitize_consistency_validation_plan,
)
from ai.schemas.research_intelligence_export import (
    EXPORT_STATUSES,
    GENERATED_SECTIONS,
)
from ai.schemas.research_intelligence_summary import (
    RESEARCH_STATUSES,
    sanitize_research_summary_plan,
)

RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION = "r32-1"
RULE_VERSION = RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION

CANDIDATE_UNSPECIFIED = "UNSPECIFIED"
TIMESTAMP_UNSPECIFIED = "UNSPECIFIED"

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_SECTIONS = 2
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:MAX_VALUE_LEN]


def _closed_token(value: object, allowed: tuple) -> str:
    text = _safe_text(value).strip().upper()
    if text in allowed:
        return text
    return ""


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_source_export(value: object) -> dict:
    """Project an R31.22 export onto a fixed, bounded, sanitized key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "ready": False,
            "status": "",
            "generated_sections": [],
            "summary": {},
            "validation": {},
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "ready": bool(value.get("ready")),
        "status": _closed_token(value.get("status"), EXPORT_STATUSES),
        "generated_sections": _bounded_codes(
            value.get("generated_sections"), GENERATED_SECTIONS,
            MAX_SECTIONS,
        ),
        "summary": sanitize_research_summary_plan(value.get("summary")),
        "validation": sanitize_consistency_validation_plan(
            value.get("validation")
        ),
        "research_only": True,
    }


def sanitize_research_memory_snapshot(value: object) -> dict:
    """Project an R32.1 snapshot onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "candidate_identity": _safe_text(
            value.get("candidate_identity")
        ) or CANDIDATE_UNSPECIFIED,
        "research_status": _closed_token(
            value.get("research_status"), RESEARCH_STATUSES
        ) or "UNKNOWN",
        "outcome": _closed_token(
            value.get("outcome"), OUTCOMES
        ) or "UNKNOWN",
        "confidence_level": _closed_token(
            value.get("confidence_level"), CONFIDENCE_LEVELS
        ) or "UNKNOWN",
        "feedback_signal": _closed_token(
            value.get("feedback_signal"), FEEDBACK_TYPES
        ) or "UNKNOWN",
        "improvement_area": _closed_token(
            value.get("improvement_area"), IMPROVEMENT_AREAS
        ) or "UNKNOWN",
        "blockers": _bounded_codes(
            value.get("blockers"), CONFIDENCE_BLOCKERS, MAX_BLOCKERS
        ),
        "timestamp_reference": _safe_text(
            value.get("timestamp_reference")
        ) or TIMESTAMP_UNSPECIFIED,
        "source_export": sanitize_source_export(value.get("source_export")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchMemorySnapshot(BaseModel):
    """One immutable historical research record (R32.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_version: str = RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION
    candidate_identity: str = CANDIDATE_UNSPECIFIED
    research_status: str = "UNKNOWN"
    outcome: str = "UNKNOWN"
    confidence_level: str = "UNKNOWN"
    feedback_signal: str = "UNKNOWN"
    improvement_area: str = "UNKNOWN"
    blockers: list[str] = Field(default_factory=list)
    timestamp_reference: str = TIMESTAMP_UNSPECIFIED
    source_export: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION

    @field_validator("candidate_identity", "timestamp_reference")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("research_status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESEARCH_STATUSES:
            raise ValueError(f"invalid research_status: {value!r}")
        return text

    @field_validator("outcome")
    @classmethod
    def _valid_outcome(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OUTCOMES:
            raise ValueError(f"invalid outcome: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("feedback_signal")
    @classmethod
    def _valid_feedback(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FEEDBACK_TYPES:
            raise ValueError(f"invalid feedback_signal: {value!r}")
        return text

    @field_validator("improvement_area")
    @classmethod
    def _valid_area(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IMPROVEMENT_AREAS:
            raise ValueError(f"invalid improvement_area: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        return _bounded_codes(value, CONFIDENCE_BLOCKERS, MAX_BLOCKERS)

    @field_validator("source_export")
    @classmethod
    def _bounded_export(cls, value: object) -> dict:
        return sanitize_source_export(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research memory snapshots are research-only")
        return True


def research_memory_snapshot_projection(
    value: ResearchMemorySnapshot,
) -> dict:
    """Serialize an immutable research memory snapshot to a dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION",
    "RULE_VERSION",
    "CANDIDATE_UNSPECIFIED",
    "TIMESTAMP_UNSPECIFIED",
    "MAX_BLOCKERS",
    "MAX_VALUE_LEN",
    "ResearchMemorySnapshot",
    "sanitize_source_export",
    "sanitize_research_memory_snapshot",
    "research_memory_snapshot_projection",
]

"""Research history schema (Stage R32.2).

A :class:`ResearchHistoryPlan` is a deterministic, read-only aggregation over
immutable R32.1 research memory snapshots. It answers the owner's
personal-research question:

    "What does the accumulated research history look like?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Aggregate-only: existing snapshots are counted; history is never modified
  and no vulnerability is ever inferred.
- Closed vocabularies: blocker, improvement-area and structural-pattern codes
  are closed sets owned by R31.15/R31.19/R32.3.
- Bounded, privacy-safe: only closed codes and bounded counts are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_BLOCKERS
from ai.schemas.evidence_feedback_calibration import IMPROVEMENT_AREAS
from ai.schemas.research_pattern_plan import (
    PATTERN_CODES,
    bounded_pattern_entries,
)

RESEARCH_HISTORY_RULE_VERSION = "r32-2"
RULE_VERSION = RESEARCH_HISTORY_RULE_VERSION

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_RECORDS = 256
MAX_RECURRING = 8
MAX_PATTERNS = 8
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


def _coerce_count(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


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


def _require_patterns(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed pattern entry: {item!r}")
        text = _safe_text(item.get("pattern"))
        if text not in PATTERN_CODES:
            raise ValueError(f"invalid pattern code: {text!r}")
        try:
            count = int(item.get("count"))
        except (TypeError, ValueError):
            raise ValueError(f"malformed pattern count: {item!r}")
        if count < 0:
            raise ValueError(f"negative pattern count: {item!r}")
        entry = {"pattern": text, "count": count}
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def sanitize_research_history_plan(value: object) -> dict:
    """Project an R32.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "total_records": 0,
            "successful_count": 0,
            "deferred_count": 0,
            "waiting_count": 0,
            "recurring_blockers": [],
            "recurring_improvement_areas": [],
            "research_patterns": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "total_records": _coerce_count(value.get("total_records")),
        "successful_count": _coerce_count(value.get("successful_count")),
        "deferred_count": _coerce_count(value.get("deferred_count")),
        "waiting_count": _coerce_count(value.get("waiting_count")),
        "recurring_blockers": _bounded_codes(
            value.get("recurring_blockers"), CONFIDENCE_BLOCKERS,
            MAX_RECURRING,
        ),
        "recurring_improvement_areas": _bounded_codes(
            value.get("recurring_improvement_areas"), IMPROVEMENT_AREAS,
            MAX_RECURRING,
        ),
        "research_patterns": bounded_pattern_entries(
            value.get("research_patterns"), MAX_PATTERNS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchHistoryPlan(BaseModel):
    """Deterministic aggregate over research memory snapshots."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_HISTORY_RULE_VERSION
    total_records: int = 0
    successful_count: int = 0
    deferred_count: int = 0
    waiting_count: int = 0
    recurring_blockers: list[str] = Field(default_factory=list)
    recurring_improvement_areas: list[str] = Field(default_factory=list)
    research_patterns: list[dict] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_HISTORY_RULE_VERSION

    @field_validator(
        "total_records", "successful_count", "deferred_count",
        "waiting_count",
    )
    @classmethod
    def _valid_count(cls, value: object) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"malformed count: {value!r}")
        if number < 0:
            raise ValueError(f"negative count: {value!r}")
        return number

    @field_validator("recurring_blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        return _require_codes(value, CONFIDENCE_BLOCKERS, MAX_RECURRING)

    @field_validator("recurring_improvement_areas")
    @classmethod
    def _valid_areas(cls, value: list) -> list[str]:
        return _require_codes(value, IMPROVEMENT_AREAS, MAX_RECURRING)

    @field_validator("research_patterns")
    @classmethod
    def _valid_patterns(cls, value: list) -> list[dict]:
        return _require_patterns(value, MAX_PATTERNS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research history plans are research-only")
        return True


def research_history_plan_projection(value: ResearchHistoryPlan) -> dict:
    """Serialize a research history plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_HISTORY_RULE_VERSION",
    "RULE_VERSION",
    "MAX_RECORDS",
    "MAX_RECURRING",
    "MAX_PATTERNS",
    "MAX_VALUE_LEN",
    "ResearchHistoryPlan",
    "sanitize_research_history_plan",
    "research_history_plan_projection",
]

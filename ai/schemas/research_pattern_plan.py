"""Research pattern schema (Stage R32.3).

A :class:`ResearchPatternPlan` is a deterministic, read-only structural
pattern detection over immutable R32.1 research memory snapshots. It answers
the owner's personal-research question:

    "Which research limitation pattern keeps repeating across history?"

Hard boundaries encoded here:

- Deterministic counting only: no ML, no embeddings, no LLM, no probability
  semantics. ``confidence`` is a bounded frequency classification.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: pattern codes and confidence levels are closed sets.
- Bounded, privacy-safe: only closed codes and bounded counts are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.evidence_feedback_calibration import (
    AREA_HTTP_BEHAVIOR,
    AREA_HUMAN_RESEARCH,
    AREA_IDENTITY,
    AREA_NONE,
    AREA_PARAMETER,
    AREA_PATH,
    AREA_PROCESS,
    AREA_SCOPE,
    AREA_TECHNOLOGY,
    AREA_UNKNOWN,
    AREA_VERSION,
    IMPROVEMENT_AREAS,
)

RESEARCH_PATTERN_RULE_VERSION = "r32-3"
RULE_VERSION = RESEARCH_PATTERN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

PATTERN_IDENTITY_LIMITED = "IDENTITY_LIMITED"
PATTERN_VERSION_LIMITED = "VERSION_LIMITED"
PATTERN_SCOPE_LIMITED = "SCOPE_LIMITED"
PATTERN_PATH_LIMITED = "PATH_LIMITED"
PATTERN_PARAMETER_LIMITED = "PARAMETER_LIMITED"
PATTERN_BEHAVIOR_LIMITED = "BEHAVIOR_LIMITED"
PATTERN_TECHNOLOGY_LIMITED = "TECHNOLOGY_LIMITED"
PATTERN_HUMAN_RESEARCH = "HUMAN_RESEARCH"
PATTERN_PROCESS_LIMITED = "PROCESS_LIMITED"
PATTERN_UNKNOWN = "UNKNOWN"
PATTERN_NONE = "NO_PATTERN"

PATTERN_CODES: tuple[str, ...] = (
    PATTERN_IDENTITY_LIMITED,
    PATTERN_VERSION_LIMITED,
    PATTERN_SCOPE_LIMITED,
    PATTERN_PATH_LIMITED,
    PATTERN_PARAMETER_LIMITED,
    PATTERN_BEHAVIOR_LIMITED,
    PATTERN_TECHNOLOGY_LIMITED,
    PATTERN_HUMAN_RESEARCH,
    PATTERN_PROCESS_LIMITED,
    PATTERN_UNKNOWN,
    PATTERN_NONE,
)

# Confidence reuses the R31.15 closed level set (HIGH / MEDIUM / LOW /
# UNKNOWN) and is a frequency classification, never a probability.
PATTERN_CONFIDENCES: tuple[str, ...] = CONFIDENCE_LEVELS

# Research improvement area -> structural pattern (closed relation).
PATTERN_BY_AREA: dict[str, str] = {
    AREA_IDENTITY: PATTERN_IDENTITY_LIMITED,
    AREA_VERSION: PATTERN_VERSION_LIMITED,
    AREA_SCOPE: PATTERN_SCOPE_LIMITED,
    AREA_PATH: PATTERN_PATH_LIMITED,
    AREA_PARAMETER: PATTERN_PARAMETER_LIMITED,
    AREA_HTTP_BEHAVIOR: PATTERN_BEHAVIOR_LIMITED,
    AREA_TECHNOLOGY: PATTERN_TECHNOLOGY_LIMITED,
    AREA_HUMAN_RESEARCH: PATTERN_HUMAN_RESEARCH,
    AREA_PROCESS: PATTERN_PROCESS_LIMITED,
    AREA_UNKNOWN: PATTERN_UNKNOWN,
}

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_EVIDENCE = 8
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


def bounded_pattern_entries(
    value: object, limit: int = MAX_EVIDENCE
) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        pattern = _closed_token(item.get("pattern"), PATTERN_CODES)
        if not pattern:
            continue
        try:
            count = int(item.get("count"))
        except (TypeError, ValueError):
            continue
        if count < 0:
            continue
        entry = {"pattern": pattern, "count": count}
        if entry not in out:
            out.append(entry)
        if len(out) >= max(1, int(limit)):
            break
    return out


def sanitize_research_pattern_plan(value: object) -> dict:
    """Project an R32.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "dominant_pattern": "",
            "frequency": 0,
            "confidence": "",
            "evidence": [],
            "research_only": True,
        }
    try:
        frequency = int(value.get("frequency"))
    except (TypeError, ValueError):
        frequency = 0
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "dominant_pattern": _closed_token(
            value.get("dominant_pattern"), PATTERN_CODES
        ),
        "frequency": max(0, frequency),
        "confidence": _closed_token(
            value.get("confidence"), PATTERN_CONFIDENCES
        ),
        "evidence": bounded_pattern_entries(value.get("evidence")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchPatternPlan(BaseModel):
    """Deterministic structural pattern detection over memory history."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_PATTERN_RULE_VERSION
    dominant_pattern: str
    frequency: int
    confidence: str
    evidence: list[dict] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_PATTERN_RULE_VERSION

    @field_validator("dominant_pattern")
    @classmethod
    def _valid_pattern(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATTERN_CODES:
            raise ValueError(f"invalid dominant_pattern: {value!r}")
        return text

    @field_validator("frequency")
    @classmethod
    def _valid_frequency(cls, value: object) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"malformed frequency: {value!r}")
        if number < 0:
            raise ValueError(f"negative frequency: {value!r}")
        return number

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATTERN_CONFIDENCES:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("evidence")
    @classmethod
    def _valid_evidence(cls, value: list) -> list[dict]:
        return bounded_pattern_entries(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research pattern plans are research-only")
        return True


def research_pattern_plan_projection(
    value: ResearchPatternPlan,
) -> dict:
    """Serialize a research pattern plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_PATTERN_RULE_VERSION",
    "RULE_VERSION",
    "PATTERN_CODES",
    "PATTERN_CONFIDENCES",
    "PATTERN_BY_AREA",
    "PATTERN_IDENTITY_LIMITED",
    "PATTERN_VERSION_LIMITED",
    "PATTERN_SCOPE_LIMITED",
    "PATTERN_PATH_LIMITED",
    "PATTERN_PARAMETER_LIMITED",
    "PATTERN_BEHAVIOR_LIMITED",
    "PATTERN_TECHNOLOGY_LIMITED",
    "PATTERN_HUMAN_RESEARCH",
    "PATTERN_PROCESS_LIMITED",
    "PATTERN_UNKNOWN",
    "PATTERN_NONE",
    "MAX_EVIDENCE",
    "MAX_VALUE_LEN",
    "IMPROVEMENT_AREAS",
    "AREA_NONE",
    "ResearchPatternPlan",
    "bounded_pattern_entries",
    "sanitize_research_pattern_plan",
    "research_pattern_plan_projection",
]

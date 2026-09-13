"""Research path schema (Stage R34.2).

A :class:`ResearchPathPlan` converts a research strategy into an ordered,
deterministic research path. It answers the owner's personal-research
question:

    "In what order should the preferred strategy be approached?"

Hard boundaries encoded here:

- Plan-only: the path names planning steps only; nothing is acquired,
  executed, scanned, crawled, fuzzed or contacted. No operational action is
  represented and ``research_only`` is forced ``True``.
- Closed vocabularies: path steps and path reasons are closed sets; the
  confidence level reuses the R31.15 set.
- Bounded, privacy-safe: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

RESEARCH_PATH_RULE_VERSION = "r34-2"
RULE_VERSION = RESEARCH_PATH_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STEP_IDENTIFY_ASSET = "IDENTIFY_ASSET"
STEP_VERIFY_SCOPE = "VERIFY_SCOPE"
STEP_VERIFY_TECHNOLOGY = "VERIFY_TECHNOLOGY"
STEP_VERIFY_VERSION = "VERIFY_VERSION"
STEP_COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
STEP_REVIEW_HISTORY = "REVIEW_HISTORY"
STEP_HUMAN_REVIEW = "HUMAN_REVIEW"
STEP_STOP = "STOP"

PATH_STEPS: tuple[str, ...] = (
    STEP_IDENTIFY_ASSET,
    STEP_VERIFY_SCOPE,
    STEP_VERIFY_TECHNOLOGY,
    STEP_VERIFY_VERSION,
    STEP_COLLECT_EVIDENCE,
    STEP_REVIEW_HISTORY,
    STEP_HUMAN_REVIEW,
    STEP_STOP,
)

REASON_EVIDENCE = "EVIDENCE_STRATEGY"
REASON_IDENTITY = "IDENTITY_STRATEGY"
REASON_TECHNOLOGY = "TECHNOLOGY_STRATEGY"
REASON_VERSION = "VERSION_STRATEGY"
REASON_SCOPE = "SCOPE_STRATEGY"
REASON_HUMAN = "HUMAN_REVIEW_STRATEGY"
REASON_DEFERRED = "DEFERRED_STRATEGY"
REASON_UNKNOWN = "UNKNOWN_STRATEGY"

PATH_REASONS: tuple[str, ...] = (
    REASON_EVIDENCE,
    REASON_IDENTITY,
    REASON_TECHNOLOGY,
    REASON_VERSION,
    REASON_SCOPE,
    REASON_HUMAN,
    REASON_DEFERRED,
    REASON_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_PATH_STEPS = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_steps(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in PATH_STEPS:
            raise ValueError(f"invalid path step: {text!r}")
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_steps(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in PATH_STEPS:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_research_path_plan(value: object) -> dict:
    """Project an R34.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "selected_path": [],
            "primary_path": "",
            "path_reason": "",
            "confidence_level": "",
            "research_only": True,
        }
    primary = _safe_text(value.get("primary_path"))
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "selected_path": _bounded_steps(
            value.get("selected_path"), MAX_PATH_STEPS
        ),
        "primary_path": primary if primary in PATH_STEPS else "",
        "path_reason": _safe_text(value.get("path_reason")),
        "confidence_level": _safe_text(value.get("confidence_level")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchPathPlan(BaseModel):
    """Deterministic ordered research path (R34.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_PATH_RULE_VERSION
    selected_path: list[str] = Field(default_factory=list)
    primary_path: str
    path_reason: str
    confidence_level: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_PATH_RULE_VERSION

    @field_validator("selected_path")
    @classmethod
    def _valid_steps(cls, value: list) -> list[str]:
        return _require_steps(value, MAX_PATH_STEPS)

    @field_validator("primary_path")
    @classmethod
    def _valid_primary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATH_STEPS:
            raise ValueError(f"invalid primary_path: {value!r}")
        return text

    @field_validator("path_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATH_REASONS:
            raise ValueError(f"invalid path_reason: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research path plans are research-only")
        return True


def research_path_plan_projection(value: ResearchPathPlan) -> dict:
    """Serialize a research path plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_PATH_RULE_VERSION",
    "RULE_VERSION",
    "PATH_STEPS",
    "PATH_REASONS",
    "STEP_IDENTIFY_ASSET",
    "STEP_VERIFY_SCOPE",
    "STEP_VERIFY_TECHNOLOGY",
    "STEP_VERIFY_VERSION",
    "STEP_COLLECT_EVIDENCE",
    "STEP_REVIEW_HISTORY",
    "STEP_HUMAN_REVIEW",
    "STEP_STOP",
    "REASON_EVIDENCE",
    "REASON_IDENTITY",
    "REASON_TECHNOLOGY",
    "REASON_VERSION",
    "REASON_SCOPE",
    "REASON_HUMAN",
    "REASON_DEFERRED",
    "REASON_UNKNOWN",
    "MAX_PATH_STEPS",
    "MAX_VALUE_LEN",
    "ResearchPathPlan",
    "sanitize_research_path_plan",
    "research_path_plan_projection",
]

"""Evidence confidence schema (Stage R31.15).

An :class:`EvidenceConfidencePlan` is a deterministic, read-only confidence
assessment over one R31.13 Evidence Acquisition Plan and one R31.14 Evidence
Prioritization Plan. It answers the owner's personal-research question:

    "How confident are we that the current evidence is sufficient, what
     evidence dimension limits confidence, and what prevents higher
     confidence?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: confidence level, confidence category, evidence
  completeness, limiting factor, priority alignment and blocker codes are
  closed deterministic sets. The R31.13/R31.14 target/method vocabularies
  remain owned by those stages and are never redefined here.
- Bounded, privacy-safe: strings and lists are bounded; both embedded source
  plans are projected onto fixed, closed key sets and sanitized.
- No probability / exploitability / severity / CVSS / payout fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ai.schemas.evidence_prioritization import (
    EvidencePriorityItem,
    sanitize_source_plan,
)

EVIDENCE_CONFIDENCE_RULE_VERSION = "r31-15"
RULE_VERSION = EVIDENCE_CONFIDENCE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_UNKNOWN = "UNKNOWN"

CONFIDENCE_LEVELS: tuple[str, ...] = (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)

CATEGORY_SUFFICIENT_EVIDENCE = "SUFFICIENT_EVIDENCE"
CATEGORY_IDENTITY_LIMITED = "IDENTITY_LIMITED"
CATEGORY_VERSION_LIMITED = "VERSION_LIMITED"
CATEGORY_SCOPE_LIMITED = "SCOPE_LIMITED"
CATEGORY_PATH_LIMITED = "PATH_LIMITED"
CATEGORY_PARAMETER_LIMITED = "PARAMETER_LIMITED"
CATEGORY_BEHAVIOR_LIMITED = "BEHAVIOR_LIMITED"
CATEGORY_TECHNOLOGY_LIMITED = "TECHNOLOGY_LIMITED"
CATEGORY_RESEARCH_INCOMPLETE = "RESEARCH_INCOMPLETE"

CONFIDENCE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_SUFFICIENT_EVIDENCE,
    CATEGORY_IDENTITY_LIMITED,
    CATEGORY_VERSION_LIMITED,
    CATEGORY_SCOPE_LIMITED,
    CATEGORY_PATH_LIMITED,
    CATEGORY_PARAMETER_LIMITED,
    CATEGORY_BEHAVIOR_LIMITED,
    CATEGORY_TECHNOLOGY_LIMITED,
    CATEGORY_RESEARCH_INCOMPLETE,
)

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_PARTIAL = "PARTIAL"
COMPLETENESS_MINIMAL = "MINIMAL"
COMPLETENESS_NONE = "NONE"

EVIDENCE_COMPLETENESS_LEVELS: tuple[str, ...] = (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_MINIMAL,
    COMPLETENESS_NONE,
)

LIMITING_NONE = "NONE"
LIMITING_COMPONENT_IDENTITY = "COMPONENT_IDENTITY"
LIMITING_VERSION = "VERSION"
LIMITING_SCOPE = "SCOPE"
LIMITING_PATH = "PATH"
LIMITING_PARAMETER = "PARAMETER"
LIMITING_HTTP_BEHAVIOR = "HTTP_BEHAVIOR"
LIMITING_TECHNOLOGY = "TECHNOLOGY"
LIMITING_HUMAN_RESEARCH = "HUMAN_RESEARCH"
LIMITING_UPSTREAM_PLAN = "UPSTREAM_PLAN"

LIMITING_FACTORS: tuple[str, ...] = (
    LIMITING_NONE,
    LIMITING_COMPONENT_IDENTITY,
    LIMITING_VERSION,
    LIMITING_SCOPE,
    LIMITING_PATH,
    LIMITING_PARAMETER,
    LIMITING_HTTP_BEHAVIOR,
    LIMITING_TECHNOLOGY,
    LIMITING_HUMAN_RESEARCH,
    LIMITING_UPSTREAM_PLAN,
)

ALIGNMENT_ALIGNED = "ALIGNED"
ALIGNMENT_MISALIGNED = "MISALIGNED"
ALIGNMENT_NOT_APPLICABLE = "NOT_APPLICABLE"

PRIORITY_ALIGNMENTS: tuple[str, ...] = (
    ALIGNMENT_ALIGNED,
    ALIGNMENT_MISALIGNED,
    ALIGNMENT_NOT_APPLICABLE,
)

BLOCKER_IDENTITY_EVIDENCE_MISSING = "IDENTITY_EVIDENCE_MISSING"
BLOCKER_VERSION_EVIDENCE_MISSING = "VERSION_EVIDENCE_MISSING"
BLOCKER_SCOPE_EVIDENCE_MISSING = "SCOPE_EVIDENCE_MISSING"
BLOCKER_PATH_EVIDENCE_MISSING = "PATH_EVIDENCE_MISSING"
BLOCKER_PARAMETER_EVIDENCE_MISSING = "PARAMETER_EVIDENCE_MISSING"
BLOCKER_HTTP_BEHAVIOR_EVIDENCE_MISSING = "HTTP_BEHAVIOR_EVIDENCE_MISSING"
BLOCKER_TECHNOLOGY_EVIDENCE_MISSING = "TECHNOLOGY_EVIDENCE_MISSING"
BLOCKER_HUMAN_RESEARCH_REQUIRED = "HUMAN_RESEARCH_REQUIRED"
BLOCKER_NO_ACQUISITION_PLANNED = "NO_ACQUISITION_PLANNED"
BLOCKER_MALFORMED_ACQUISITION_PLAN = "MALFORMED_ACQUISITION_PLAN"
BLOCKER_UNKNOWN_ACQUISITION_METHOD = "UNKNOWN_ACQUISITION_METHOD"
BLOCKER_MISSING_PRIORITIZATION_ITEM = "MISSING_PRIORITIZATION_ITEM"
BLOCKER_PRIORITY_MISALIGNMENT = "PRIORITY_MISALIGNMENT"

CONFIDENCE_BLOCKERS: tuple[str, ...] = (
    BLOCKER_IDENTITY_EVIDENCE_MISSING,
    BLOCKER_VERSION_EVIDENCE_MISSING,
    BLOCKER_SCOPE_EVIDENCE_MISSING,
    BLOCKER_PATH_EVIDENCE_MISSING,
    BLOCKER_PARAMETER_EVIDENCE_MISSING,
    BLOCKER_HTTP_BEHAVIOR_EVIDENCE_MISSING,
    BLOCKER_TECHNOLOGY_EVIDENCE_MISSING,
    BLOCKER_HUMAN_RESEARCH_REQUIRED,
    BLOCKER_NO_ACQUISITION_PLANNED,
    BLOCKER_MALFORMED_ACQUISITION_PLAN,
    BLOCKER_UNKNOWN_ACQUISITION_METHOD,
    BLOCKER_MISSING_PRIORITIZATION_ITEM,
    BLOCKER_PRIORITY_MISALIGNMENT,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.14 plan snapshot.
SOURCE_PRIORITIZATION_KEYS: tuple[str, ...] = (
    "rule_version",
    "items",
    "research_only",
)

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
    """Bound and redact credential-like text before it enters evidence."""

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


def _closed_token(value: object) -> str:
    text = _safe_text(value).strip().upper()
    if not text:
        return ""
    if not _TOKEN_RE.match(text):
        raise ValueError(f"malformed closed token: {value!r}")
    return text


def _bounded_blockers(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_BLOCKERS:
            break
    return out


def sanitize_source_prioritization_plan(value: object) -> dict:
    """Project an R31.14 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {"rule_version": "", "items": [], "research_only": True}
    items: list[dict] = []
    raw_items = value.get("items")
    if isinstance(raw_items, (list, tuple)):
        for entry in raw_items:
            if not isinstance(entry, dict):
                continue
            try:
                item = EvidencePriorityItem(**entry)
            except (ValidationError, TypeError):
                continue
            items.append(item.model_dump(mode="json"))
            if len(items) >= MAX_ITEMS:
                break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "items": items,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class EvidenceConfidencePlan(BaseModel):
    """Deterministic confidence assessment over R31.13/R31.14 plans."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_CONFIDENCE_RULE_VERSION
    confidence_level: str
    confidence_category: str
    limiting_factor: str
    evidence_completeness: str
    priority_alignment: str
    blockers: list[str] = Field(default_factory=list)
    source_acquisition_plan: dict = Field(default_factory=dict)
    source_prioritization_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_CONFIDENCE_RULE_VERSION

    @field_validator("confidence_level")
    @classmethod
    def _valid_level(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("confidence_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in CONFIDENCE_CATEGORIES:
            raise ValueError(f"invalid confidence_category: {value!r}")
        return text

    @field_validator("limiting_factor")
    @classmethod
    def _valid_limiting(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in LIMITING_FACTORS:
            raise ValueError(f"invalid limiting_factor: {value!r}")
        return text

    @field_validator("evidence_completeness")
    @classmethod
    def _valid_completeness(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in EVIDENCE_COMPLETENESS_LEVELS:
            raise ValueError(f"invalid evidence_completeness: {value!r}")
        return text

    @field_validator("priority_alignment")
    @classmethod
    def _valid_alignment(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in PRIORITY_ALIGNMENTS:
            raise ValueError(f"invalid priority_alignment: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        codes = _bounded_blockers(value)
        for code in codes:
            if code not in CONFIDENCE_BLOCKERS:
                raise ValueError(f"invalid blocker code: {code!r}")
        return codes

    @field_validator("source_acquisition_plan")
    @classmethod
    def _bounded_acquisition(cls, value: object) -> dict:
        return sanitize_source_plan(value)

    @field_validator("source_prioritization_plan")
    @classmethod
    def _bounded_prioritization(cls, value: object) -> dict:
        return sanitize_source_prioritization_plan(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "evidence confidence plans are research-only"
            )
        return True


def confidence_plan_projection(value: EvidenceConfidencePlan) -> dict:
    """Serialize a confidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_CONFIDENCE_RULE_VERSION",
    "RULE_VERSION",
    "CONFIDENCE_LEVELS",
    "CONFIDENCE_CATEGORIES",
    "EVIDENCE_COMPLETENESS_LEVELS",
    "LIMITING_FACTORS",
    "PRIORITY_ALIGNMENTS",
    "CONFIDENCE_BLOCKERS",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_LOW",
    "CONFIDENCE_UNKNOWN",
    "CATEGORY_SUFFICIENT_EVIDENCE",
    "CATEGORY_IDENTITY_LIMITED",
    "CATEGORY_VERSION_LIMITED",
    "CATEGORY_SCOPE_LIMITED",
    "CATEGORY_PATH_LIMITED",
    "CATEGORY_PARAMETER_LIMITED",
    "CATEGORY_BEHAVIOR_LIMITED",
    "CATEGORY_TECHNOLOGY_LIMITED",
    "CATEGORY_RESEARCH_INCOMPLETE",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPLETENESS_MINIMAL",
    "COMPLETENESS_NONE",
    "LIMITING_NONE",
    "LIMITING_COMPONENT_IDENTITY",
    "LIMITING_VERSION",
    "LIMITING_SCOPE",
    "LIMITING_PATH",
    "LIMITING_PARAMETER",
    "LIMITING_HTTP_BEHAVIOR",
    "LIMITING_TECHNOLOGY",
    "LIMITING_HUMAN_RESEARCH",
    "LIMITING_UPSTREAM_PLAN",
    "ALIGNMENT_ALIGNED",
    "ALIGNMENT_MISALIGNED",
    "ALIGNMENT_NOT_APPLICABLE",
    "BLOCKER_IDENTITY_EVIDENCE_MISSING",
    "BLOCKER_VERSION_EVIDENCE_MISSING",
    "BLOCKER_SCOPE_EVIDENCE_MISSING",
    "BLOCKER_PATH_EVIDENCE_MISSING",
    "BLOCKER_PARAMETER_EVIDENCE_MISSING",
    "BLOCKER_HTTP_BEHAVIOR_EVIDENCE_MISSING",
    "BLOCKER_TECHNOLOGY_EVIDENCE_MISSING",
    "BLOCKER_HUMAN_RESEARCH_REQUIRED",
    "BLOCKER_NO_ACQUISITION_PLANNED",
    "BLOCKER_MALFORMED_ACQUISITION_PLAN",
    "BLOCKER_UNKNOWN_ACQUISITION_METHOD",
    "BLOCKER_MISSING_PRIORITIZATION_ITEM",
    "BLOCKER_PRIORITY_MISALIGNMENT",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "SOURCE_PRIORITIZATION_KEYS",
    "EvidenceConfidencePlan",
    "sanitize_source_prioritization_plan",
    "confidence_plan_projection",
]

"""Evidence prioritization schema (Stage R31.14).

An :class:`EvidencePrioritizationPlan` is a deterministic, read-only roadmap
projection over one R31.13 Evidence Acquisition Plan. It answers the owner's
personal-research question:

    "Of the evidence I still need for this candidate, which piece should I
     prioritize, why, how dependent is it on earlier evidence, and how
     important is completing it?"

Hard boundaries encoded here:

- Plan-only: nothing is executed, acquired, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: priority reason, uncertainty category, dependency
  level and completion importance are closed deterministic sets. The
  ``evidence_target`` / ``acquisition_method`` vocabularies remain owned by
  R31.13 (``ai/knowledge/evidence_acquisition_planner.py``); this schema only
  bounds their shape so the two vocabularies cannot silently drift here.
- Bounded, privacy-safe: strings and lists are bounded; the embedded
  ``source_acquisition_plan`` is projected onto a fixed, closed key set and
  sanitized.
- No probability / exploitability / severity / CVSS / payout fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

EVIDENCE_PRIORITIZATION_RULE_VERSION = "r31-14"
RULE_VERSION = EVIDENCE_PRIORITIZATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies (R31.14-specific fields)
# ---------------------------------------------------------------------------

PRIORITY_EXISTING_EVIDENCE = "PRIORITY_EXISTING_EVIDENCE"
PRIORITY_IDENTITY = "PRIORITY_IDENTITY"
PRIORITY_VERSION = "PRIORITY_VERSION"
PRIORITY_SCOPE = "PRIORITY_SCOPE"
PRIORITY_PATH = "PRIORITY_PATH"
PRIORITY_PARAMETER = "PRIORITY_PARAMETER"
PRIORITY_HTTP_BEHAVIOR = "PRIORITY_HTTP_BEHAVIOR"
PRIORITY_TECHNOLOGY = "PRIORITY_TECHNOLOGY"
PRIORITY_MANUAL_RESEARCH = "PRIORITY_MANUAL_RESEARCH"

PRIORITY_REASONS: tuple[str, ...] = (
    PRIORITY_EXISTING_EVIDENCE,
    PRIORITY_IDENTITY,
    PRIORITY_VERSION,
    PRIORITY_SCOPE,
    PRIORITY_PATH,
    PRIORITY_PARAMETER,
    PRIORITY_HTTP_BEHAVIOR,
    PRIORITY_TECHNOLOGY,
    PRIORITY_MANUAL_RESEARCH,
)

UNCERTAINTY_EXISTING_EVIDENCE = "EXISTING_EVIDENCE_UNCERTAINTY"
UNCERTAINTY_IDENTITY = "IDENTITY_UNCERTAINTY"
UNCERTAINTY_VERSION = "VERSION_UNCERTAINTY"
UNCERTAINTY_SCOPE = "SCOPE_UNCERTAINTY"
UNCERTAINTY_PATH = "PATH_UNCERTAINTY"
UNCERTAINTY_PARAMETER = "PARAMETER_UNCERTAINTY"
UNCERTAINTY_HTTP_BEHAVIOR = "HTTP_BEHAVIOR_UNCERTAINTY"
UNCERTAINTY_TECHNOLOGY = "TECHNOLOGY_UNCERTAINTY"
UNCERTAINTY_HUMAN_JUDGEMENT = "HUMAN_JUDGEMENT_UNCERTAINTY"

UNCERTAINTY_CATEGORIES: tuple[str, ...] = (
    UNCERTAINTY_EXISTING_EVIDENCE,
    UNCERTAINTY_IDENTITY,
    UNCERTAINTY_VERSION,
    UNCERTAINTY_SCOPE,
    UNCERTAINTY_PATH,
    UNCERTAINTY_PARAMETER,
    UNCERTAINTY_HTTP_BEHAVIOR,
    UNCERTAINTY_TECHNOLOGY,
    UNCERTAINTY_HUMAN_JUDGEMENT,
)

# Dependency ladder: 0 = independent of earlier evidence layers,
# 1 = one upstream layer, 2 = two upstream layers, 3 = behavioral evidence
# that requires the path/parameter context to be interpretable.
DEPENDENCY_INDEPENDENT = 0
DEPENDENCY_UPSTREAM = 1
DEPENDENCY_DERIVED = 2
DEPENDENCY_BEHAVIORAL = 3

DEPENDENCY_LEVELS: tuple[int, ...] = (
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UPSTREAM,
    DEPENDENCY_DERIVED,
    DEPENDENCY_BEHAVIORAL,
)

IMPORTANCE_CRITICAL = "CRITICAL"
IMPORTANCE_HIGH = "HIGH"
IMPORTANCE_MEDIUM = "MEDIUM"
IMPORTANCE_LOW = "LOW"

COMPLETION_IMPORTANCE_LEVELS: tuple[str, ...] = (
    IMPORTANCE_CRITICAL,
    IMPORTANCE_HIGH,
    IMPORTANCE_MEDIUM,
    IMPORTANCE_LOW,
)

MIN_PRIORITY_RANK = 1
MAX_PRIORITY_RANK = 8

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_ITEMS = 8
MAX_REASON_CODES = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.13 plan snapshot.
SOURCE_PLAN_KEYS: tuple[str, ...] = (
    "rule_version",
    "acquisition_method",
    "acquisition_rank",
    "evidence_target",
    "evidence_gap",
    "completion_condition",
    "reason_codes",
    "source_action",
    "source_actionability",
    "source_priority",
    "source_hunt_score",
    "confidence",
    "estimated_effort",
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


def _bounded_strings(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _closed_token(value: object) -> str:
    text = _safe_text(value).strip().upper()
    if not text:
        return ""
    if not _TOKEN_RE.match(text):
        raise ValueError(f"malformed closed token: {value!r}")
    return text


def sanitize_source_plan(value: object) -> dict:
    """Project an R31.13 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "acquisition_method": "",
            "acquisition_rank": -1,
            "evidence_target": "",
            "evidence_gap": "",
            "completion_condition": "",
            "reason_codes": [],
            "source_action": "",
            "source_actionability": "",
            "source_priority": "",
            "source_hunt_score": 0,
            "confidence": "",
            "estimated_effort": "",
        }
    out: dict = {}
    for key in SOURCE_PLAN_KEYS:
        if key not in value:
            continue
        raw = value.get(key)
        if key == "acquisition_rank" or key == "source_hunt_score":
            try:
                out[key] = int(raw)
            except (TypeError, ValueError):
                out[key] = -1 if key == "acquisition_rank" else 0
        elif key == "reason_codes":
            out[key] = _bounded_strings(raw, MAX_REASON_CODES)
        else:
            out[key] = _safe_text(raw)
    return out


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EvidencePriorityItem(BaseModel):
    """One prioritized evidence item derived from the R31.13 plan."""

    model_config = ConfigDict(extra="forbid")

    evidence_target: str
    acquisition_method: str
    priority_rank: int
    priority_reason: str
    uncertainty_category: str
    dependency_level: int
    completion_importance: str

    @field_validator("evidence_target", "acquisition_method")
    @classmethod
    def _valid_target(cls, value: object) -> str:
        return _closed_token(value)

    @field_validator("priority_rank")
    @classmethod
    def _valid_rank(cls, value: object) -> int:
        try:
            rank = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"malformed priority_rank: {value!r}")
        if not MIN_PRIORITY_RANK <= rank <= MAX_PRIORITY_RANK:
            raise ValueError(f"priority_rank out of range: {value!r}")
        return rank

    @field_validator("priority_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in PRIORITY_REASONS:
            raise ValueError(f"invalid priority_reason: {value!r}")
        return text

    @field_validator("uncertainty_category")
    @classmethod
    def _valid_uncertainty(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in UNCERTAINTY_CATEGORIES:
            raise ValueError(f"invalid uncertainty_category: {value!r}")
        return text

    @field_validator("dependency_level")
    @classmethod
    def _valid_dependency(cls, value: object) -> int:
        try:
            level = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"malformed dependency_level: {value!r}")
        if level not in DEPENDENCY_LEVELS:
            raise ValueError(f"invalid dependency_level: {value!r}")
        return level

    @field_validator("completion_importance")
    @classmethod
    def _valid_importance(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in COMPLETION_IMPORTANCE_LEVELS:
            raise ValueError(f"invalid completion_importance: {value!r}")
        return text


class EvidencePrioritizationPlan(BaseModel):
    """Deterministic prioritized evidence roadmap over one R31.13 plan."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_PRIORITIZATION_RULE_VERSION
    items: list[EvidencePriorityItem] = Field(default_factory=list)
    source_acquisition_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_PRIORITIZATION_RULE_VERSION

    @field_validator("items")
    @classmethod
    def _bounded_items(cls, value: list) -> list:
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"malformed items: {value!r}")
        return list(value)[:MAX_ITEMS]

    @field_validator("source_acquisition_plan")
    @classmethod
    def _bounded_source_plan(cls, value: object) -> dict:
        return sanitize_source_plan(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "evidence prioritization plans are research-only"
            )
        return True


def priority_item_projection(value: EvidencePriorityItem) -> dict:
    """Serialize one prioritized evidence item to a deterministic dict."""

    return value.model_dump(mode="json")


def prioritization_plan_projection(value: EvidencePrioritizationPlan) -> dict:
    """Serialize a prioritization plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_PRIORITIZATION_RULE_VERSION",
    "RULE_VERSION",
    "PRIORITY_REASONS",
    "UNCERTAINTY_CATEGORIES",
    "DEPENDENCY_LEVELS",
    "COMPLETION_IMPORTANCE_LEVELS",
    "PRIORITY_EXISTING_EVIDENCE",
    "PRIORITY_IDENTITY",
    "PRIORITY_VERSION",
    "PRIORITY_SCOPE",
    "PRIORITY_PATH",
    "PRIORITY_PARAMETER",
    "PRIORITY_HTTP_BEHAVIOR",
    "PRIORITY_TECHNOLOGY",
    "PRIORITY_MANUAL_RESEARCH",
    "UNCERTAINTY_EXISTING_EVIDENCE",
    "UNCERTAINTY_IDENTITY",
    "UNCERTAINTY_VERSION",
    "UNCERTAINTY_SCOPE",
    "UNCERTAINTY_PATH",
    "UNCERTAINTY_PARAMETER",
    "UNCERTAINTY_HTTP_BEHAVIOR",
    "UNCERTAINTY_TECHNOLOGY",
    "UNCERTAINTY_HUMAN_JUDGEMENT",
    "DEPENDENCY_INDEPENDENT",
    "DEPENDENCY_UPSTREAM",
    "DEPENDENCY_DERIVED",
    "DEPENDENCY_BEHAVIORAL",
    "IMPORTANCE_CRITICAL",
    "IMPORTANCE_HIGH",
    "IMPORTANCE_MEDIUM",
    "IMPORTANCE_LOW",
    "MIN_PRIORITY_RANK",
    "MAX_PRIORITY_RANK",
    "MAX_ITEMS",
    "MAX_REASON_CODES",
    "MAX_VALUE_LEN",
    "SOURCE_PLAN_KEYS",
    "EvidencePriorityItem",
    "EvidencePrioritizationPlan",
    "sanitize_source_plan",
    "priority_item_projection",
    "prioritization_plan_projection",
]

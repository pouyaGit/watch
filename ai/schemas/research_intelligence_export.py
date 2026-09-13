"""Research intelligence export schema (Stage R31.22).

A :class:`ResearchIntelligenceExportPlan` is the final deterministic,
read-only export object over the R31.20 research intelligence summary and the
R31.21 consistency validation. It answers the owner's personal-research
question:

    "Is the finalized R31 research intelligence ready for downstream
     consumers, and what does it contain?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: export status and generated-section codes are closed
  deterministic sets; summary/validation vocabularies remain owned by
  R31.20/R31.21 and are imported, never redefined.
- Bounded, privacy-safe: strings and lists are bounded; the embedded summary
  and validation plans are projected onto fixed, closed key sets and
  sanitized.
- No probability / exploitability / severity / CVSS / payout fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.research_consistency_validation import (
    sanitize_consistency_validation_plan,
)
from ai.schemas.research_intelligence_summary import (
    sanitize_research_summary_plan,
)

RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION = "r31-22"
RULE_VERSION = RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

EXPORT_READY = "READY"
EXPORT_NOT_READY = "NOT_READY"
EXPORT_UNKNOWN = "UNKNOWN"

EXPORT_STATUSES: tuple[str, ...] = (
    EXPORT_READY,
    EXPORT_NOT_READY,
    EXPORT_UNKNOWN,
)

SECTION_SUMMARY = "RESEARCH_INTELLIGENCE_SUMMARY"
SECTION_VALIDATION = "CONSISTENCY_VALIDATION"

GENERATED_SECTIONS: tuple[str, ...] = (
    SECTION_SUMMARY,
    SECTION_VALIDATION,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

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


def _bounded_sections(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in GENERATED_SECTIONS and text not in out:
            out.append(text)
        if len(out) >= MAX_SECTIONS:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchIntelligenceExportPlan(BaseModel):
    """Final deterministic R31 research intelligence export object."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION
    ready: bool
    status: str
    summary: dict = Field(default_factory=dict)
    validation: dict = Field(default_factory=dict)
    generated_sections: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in EXPORT_STATUSES:
            raise ValueError(f"invalid status: {value!r}")
        return text

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_research_summary_plan(value)

    @field_validator("validation")
    @classmethod
    def _bounded_validation(cls, value: object) -> dict:
        return sanitize_consistency_validation_plan(value)

    @field_validator("generated_sections")
    @classmethod
    def _valid_sections(cls, value: list) -> list[str]:
        return _bounded_sections(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research intelligence exports are research-only"
            )
        return True


def research_export_plan_projection(
    value: ResearchIntelligenceExportPlan,
) -> dict:
    """Serialize a research intelligence export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "EXPORT_STATUSES",
    "GENERATED_SECTIONS",
    "EXPORT_READY",
    "EXPORT_NOT_READY",
    "EXPORT_UNKNOWN",
    "SECTION_SUMMARY",
    "SECTION_VALIDATION",
    "MAX_SECTIONS",
    "MAX_VALUE_LEN",
    "ResearchIntelligenceExportPlan",
    "research_export_plan_projection",
]

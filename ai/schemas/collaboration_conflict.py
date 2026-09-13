"""Collaboration conflict schema (Stage R43.4).

Explicit, deterministic representation of conflicts between collaborating
specialist research results. It answers:

    "Which structured research claims diverge, and how can the divergence
     be characterized?"

Hard boundaries encoded here:

- Collaboration only: conflicts are computed from structured data. Both
  sides are always preserved; nothing is deleted or silently normalized.
- Conflict types and resolution states are closed vocabularies.
- No execution, no network, no database, no browser, no LLM, no payloads.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

COLLABORATION_CONFLICT_RULE_VERSION = "r43-5"
RULE_VERSION = COLLABORATION_CONFLICT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CONFLICT_CONFIDENCE = "CONFIDENCE_CONFLICT"
CONFLICT_CONTEXT = "CONTEXT_CONFLICT"
CONFLICT_HYPOTHESIS = "HYPOTHESIS_CONFLICT"
CONFLICT_EVIDENCE_STATE = "EVIDENCE_STATE_CONFLICT"
CONFLICT_GOVERNANCE = "GOVERNANCE_CONFLICT"
CONFLICT_PROVENANCE = "PROVENANCE_CONFLICT"
CONFLICT_SAFETY = "SAFETY_CONFLICT"
CONFLICT_UNKNOWN = "UNKNOWN"

CONFLICT_TYPES: tuple[str, ...] = (
    CONFLICT_CONFIDENCE,
    CONFLICT_CONTEXT,
    CONFLICT_HYPOTHESIS,
    CONFLICT_EVIDENCE_STATE,
    CONFLICT_GOVERNANCE,
    CONFLICT_PROVENANCE,
    CONFLICT_SAFETY,
    CONFLICT_UNKNOWN,
)

RESOLUTION_CONSISTENT = "CONSISTENT"
RESOLUTION_RECONCILABLE = "RECONCILABLE"
RESOLUTION_UNRESOLVED = "UNRESOLVED"
RESOLUTION_UNKNOWN = "UNKNOWN"

RESOLUTION_STATES: tuple[str, ...] = (
    RESOLUTION_CONSISTENT,
    RESOLUTION_RECONCILABLE,
    RESOLUTION_UNRESOLVED,
    RESOLUTION_UNKNOWN,
)

CONFLICT_ID_PREFIX = "cf-"
CONFLICT_ID_RE = re.compile(r"^cf-[0-9a-f]{16}$")

MAX_SUBJECTS = 12
MAX_FIELDS = 12
MAX_REFERENCES = 12
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\[\]\.]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_strings(value: object, limit: int, pattern=None) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, 120)
        if not text or text in out:
            continue
        if pattern is not None and not pattern.match(text):
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_collaboration_conflict(value: object) -> dict:
    """Project a conflict record onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "conflict_id": "",
            "conflict_type": CONFLICT_UNKNOWN,
            "subjects": [],
            "conflicting_fields": [],
            "resolution_state": RESOLUTION_UNKNOWN,
            "message": "",
            "evidence_references": [],
        }
    conflict_type = _safe_text(
        value.get("conflict_type")
    ).strip().upper()
    if conflict_type not in CONFLICT_TYPES:
        conflict_type = CONFLICT_UNKNOWN
    resolution = _safe_text(
        value.get("resolution_state")
    ).strip().upper()
    if resolution not in RESOLUTION_STATES:
        resolution = RESOLUTION_UNKNOWN
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "conflict_id": _safe_text(value.get("conflict_id")),
        "conflict_type": conflict_type,
        "subjects": _bounded_strings(value.get("subjects"), MAX_SUBJECTS),
        "conflicting_fields": _bounded_strings(
            value.get("conflicting_fields"), MAX_FIELDS
        ),
        "resolution_state": resolution,
        "message": _safe_text(value.get("message"), 240),
        "evidence_references": _bounded_strings(
            value.get("evidence_references"), MAX_REFERENCES,
            _TOKEN_RE,
        ),
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CollaborationConflictRecordPlan(BaseModel):
    """Deterministic collaboration conflict record (R43.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COLLABORATION_CONFLICT_RULE_VERSION
    conflict_id: str = ""
    conflict_type: str = CONFLICT_UNKNOWN
    subjects: list[str] = Field(default_factory=list)
    conflicting_fields: list[str] = Field(default_factory=list)
    resolution_state: str = RESOLUTION_UNKNOWN
    message: str = ""
    evidence_references: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COLLABORATION_CONFLICT_RULE_VERSION

    @field_validator("conflict_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("conflict_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFLICT_TYPES:
            raise ValueError(f"invalid conflict_type: {value!r}")
        return text

    @field_validator("subjects")
    @classmethod
    def _valid_subjects(cls, value: list) -> list[str]:
        return _bounded_strings(value, MAX_SUBJECTS)

    @field_validator("conflicting_fields")
    @classmethod
    def _valid_fields(cls, value: list) -> list[str]:
        return _bounded_strings(value, MAX_FIELDS)

    @field_validator("resolution_state")
    @classmethod
    def _valid_resolution(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESOLUTION_STATES:
            raise ValueError(f"invalid resolution_state: {value!r}")
        return text

    @field_validator("message")
    @classmethod
    def _bounded_message(cls, value: object) -> str:
        return _safe_text(value, 240)

    @field_validator("evidence_references")
    @classmethod
    def _valid_references(cls, value: list) -> list[str]:
        return _bounded_strings(value, MAX_REFERENCES, _TOKEN_RE)


def collaboration_conflict_record_plan_projection(
    value: CollaborationConflictRecordPlan,
) -> dict:
    """Serialize a conflict record to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "COLLABORATION_CONFLICT_RULE_VERSION",
    "RULE_VERSION",
    "CONFLICT_TYPES",
    "CONFLICT_CONFIDENCE",
    "CONFLICT_CONTEXT",
    "CONFLICT_HYPOTHESIS",
    "CONFLICT_EVIDENCE_STATE",
    "CONFLICT_GOVERNANCE",
    "CONFLICT_PROVENANCE",
    "CONFLICT_SAFETY",
    "CONFLICT_UNKNOWN",
    "RESOLUTION_STATES",
    "RESOLUTION_CONSISTENT",
    "RESOLUTION_RECONCILABLE",
    "RESOLUTION_UNRESOLVED",
    "RESOLUTION_UNKNOWN",
    "CONFLICT_ID_PREFIX",
    "CONFLICT_ID_RE",
    "MAX_SUBJECTS",
    "MAX_FIELDS",
    "MAX_REFERENCES",
    "MAX_VALUE_LEN",
    "sanitize_collaboration_conflict",
    "CollaborationConflictRecordPlan",
    "collaboration_conflict_record_plan_projection",
]

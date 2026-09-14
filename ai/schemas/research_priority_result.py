"""Research prioritization result schema (Stage R55.2).

Defines the deterministic R55 research-prioritization result that groups the
bounded research-priority plans derived from R53 finding intelligence
(optionally enriched with R54 correlation intelligence and R44 learning
context). It answers:

    "In which order should these research findings be investigated, and why?"

Hard boundaries encoded here:

- Research ordering only: the result ranks research artifacts. It never
  confirms a vulnerability, never merges, rewrites or deletes findings and
  never executes anything. Every original finding, evidence reference,
  provenance reference, governance reference and limitation remains
  addressable through its stable finding id.
- Priority is not confidence: the result and every plan force
  ``confidence_effect = NONE``; upstream finding confidence is preserved
  untouched (R55 is read-only over its inputs).
- Safety first: unsafe inputs are never dropped; they are preserved in
  ``deferred_findings`` with an explicit deferral reason and limitation.
- Closed vocabularies: statuses, skip reasons, error categories and
  governance summary states are closed sets.
- Deterministic: content-derived ids only; canonical ordering; no timestamps,
  UUIDs, pids or randomness.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)
from ai.schemas.research_priority import (
    MAX_LIST,
    MAX_LIMITATIONS,
    MAX_PRIORITY_SCORE,
    MAX_VALUE_LEN,
    PRIORITY_BANDS,
    PRIORITY_LIMITATIONS,
    ResearchPriorityPlan,
    sanitize_research_priority,
)

RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION = "r55-2"
RULE_VERSION = RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NO_FINDINGS = "NO_FINDINGS"
STATUS_FAILED = "FAILED"

PRIORITIZATION_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
)

SKIP_MALFORMED_FINDING = "MALFORMED_FINDING"
SKIP_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
SKIP_DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
SKIP_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

FINDING_SKIP_REASONS: tuple[str, ...] = (
    SKIP_MALFORMED_FINDING,
    SKIP_UNSUPPORTED_CATEGORY,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_FINDING = "MALFORMED_FINDING"
ERROR_DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
ERROR_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_CORRELATION_MISMATCH = "CORRELATION_MISMATCH"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

PRIORITIZATION_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_FINDING,
    ERROR_DUPLICATE_IDENTITY,
    ERROR_UNSUPPORTED_CATEGORY,
    ERROR_SAFETY_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_CORRELATION_MISMATCH,
    ERROR_UNKNOWN,
)

PRIORITIZATION_ID_PREFIX = "pri-"
PRIORITIZATION_ID_RE = re.compile(r"^pri-[0-9a-f]{16}$")

GOVERNANCE_SUMMARY_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

MAX_FINDINGS = 8
MAX_SKIPPED = 16
MAX_ERRORS = 16
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_ids(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(r"^fnd-[0-9a-f]{16}$", text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_count(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in PRIORITY_LIMITATIONS:
            found.add(text)
    return [code for code in PRIORITY_LIMITATIONS if code in found][
        :MAX_LIMITATIONS
    ]


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_priority_skip(value: object) -> dict:
    """Project one skipped finding onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not re.match(r"^fnd-[0-9a-f]{16}$", finding_id):
        finding_id = ""
    return {
        "finding_id": finding_id,
        "category": _safe_text(value.get("category")).strip().upper(),
        "agent_id": _safe_text(value.get("agent_id")),
        "reason": _closed(
            value.get("reason"), FINDING_SKIP_REASONS, SKIP_MALFORMED_FINDING
        ),
    }


def sanitize_priority_error(value: object) -> dict:
    """Project one prioritization error onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in PRIORITIZATION_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "finding_id": _safe_text(value.get("finding_id")),
        "category": _safe_text(value.get("category")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_priority_band_counts(value: object) -> dict:
    """Project the per-band counts onto the closed band vocabulary."""

    counts = value if isinstance(value, dict) else {}
    return {
        band: _bounded_count(counts.get(band), 0, MAX_FINDINGS)
        for band in PRIORITY_BANDS
    }


def sanitize_prioritization_summary(value: object) -> dict:
    """Project the aggregated prioritization summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "finding_count": 0,
            "ranked_count": 0,
            "deferred_count": 0,
            "skipped_count": 0,
            "band_counts": sanitize_priority_band_counts(None),
            "conflict_finding_count": 0,
            "duplicate_finding_count": 0,
            "related_finding_count": 0,
            "evidence_complete_count": 0,
            "evidence_partial_count": 0,
            "evidence_missing_count": 0,
            "severity_assessed_count": 0,
            "impact_observed_count": 0,
            "learning_available_count": 0,
            "highest_score": 0,
            "lowest_score": 0,
            "research_only": True,
        }
    return {
        "finding_count": _bounded_count(
            value.get("finding_count"), 0, MAX_FINDINGS
        ),
        "ranked_count": _bounded_count(
            value.get("ranked_count"), 0, MAX_FINDINGS
        ),
        "deferred_count": _bounded_count(
            value.get("deferred_count"), 0, MAX_FINDINGS
        ),
        "skipped_count": _bounded_count(
            value.get("skipped_count"), 0, MAX_SKIPPED
        ),
        "band_counts": sanitize_priority_band_counts(
            value.get("band_counts")
        ),
        "conflict_finding_count": _bounded_count(
            value.get("conflict_finding_count"), 0, MAX_FINDINGS
        ),
        "duplicate_finding_count": _bounded_count(
            value.get("duplicate_finding_count"), 0, MAX_FINDINGS
        ),
        "related_finding_count": _bounded_count(
            value.get("related_finding_count"), 0, MAX_FINDINGS
        ),
        "evidence_complete_count": _bounded_count(
            value.get("evidence_complete_count"), 0, MAX_FINDINGS
        ),
        "evidence_partial_count": _bounded_count(
            value.get("evidence_partial_count"), 0, MAX_FINDINGS
        ),
        "evidence_missing_count": _bounded_count(
            value.get("evidence_missing_count"), 0, MAX_FINDINGS
        ),
        "severity_assessed_count": _bounded_count(
            value.get("severity_assessed_count"), 0, MAX_FINDINGS
        ),
        "impact_observed_count": _bounded_count(
            value.get("impact_observed_count"), 0, MAX_FINDINGS
        ),
        "learning_available_count": _bounded_count(
            value.get("learning_available_count"), 0, MAX_FINDINGS
        ),
        "highest_score": _bounded_count(
            value.get("highest_score"), 0, MAX_PRIORITY_SCORE
        ),
        "lowest_score": _bounded_count(
            value.get("lowest_score"), 0, MAX_PRIORITY_SCORE
        ),
        "research_only": True,
    }


def sanitize_prioritization_provenance(value: object) -> dict:
    """Project container-level prioritization provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "priority_rule_version": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "source_kinds": [],
            "orchestration_ids": [],
            "source_categories": [],
            "source_agent_ids": [],
            "deterministic": True,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "source_kinds": _bounded_strings(value.get("source_kinds"), MAX_LIST),
        "orchestration_ids": _bounded_strings(
            value.get("orchestration_ids"), MAX_LIST
        ),
        "source_categories": _bounded_strings(
            value.get("source_categories"), MAX_LIST
        ),
        "source_agent_ids": _bounded_strings(
            value.get("source_agent_ids"), MAX_LIST
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_prioritization_governance(value: object) -> dict:
    """Project the aggregated governance summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "governance_state": GOVERNANCE_UNKNOWN,
            "referenced_finding_ids": [],
            "unknown_finding_ids": [],
            "ready_finding_ids": [],
            "not_ready_finding_ids": [],
            "research_only": True,
        }
    return {
        "governance_state": _closed(
            value.get("governance_state"),
            GOVERNANCE_SUMMARY_STATES,
            GOVERNANCE_UNKNOWN,
        ),
        "referenced_finding_ids": _bounded_ids(
            value.get("referenced_finding_ids"), MAX_FINDINGS
        ),
        "unknown_finding_ids": _bounded_ids(
            value.get("unknown_finding_ids"), MAX_FINDINGS
        ),
        "ready_finding_ids": _bounded_ids(
            value.get("ready_finding_ids"), MAX_FINDINGS
        ),
        "not_ready_finding_ids": _bounded_ids(
            value.get("not_ready_finding_ids"), MAX_FINDINGS
        ),
        "research_only": True,
    }


def _bounded_plans(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        try:
            projected = ResearchPriorityPlan(
                **sanitize_research_priority(item)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            continue
        out.append(projected)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchPrioritizationResultPlan(BaseModel):
    """Deterministic R55 research-prioritization result (R55.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
    prioritization_rule_version: str = (
        RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
    )
    priority_rule_version: str = ""
    finding_rule_version: str = ""
    correlation_rule_version: str = ""
    prioritization_id: str = ""
    status: str = STATUS_NO_FINDINGS
    ranked_findings: list[dict] = Field(default_factory=list)
    deferred_findings: list[dict] = Field(default_factory=list)
    skipped_findings: list[dict] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    confidence_effect: str = "NONE"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version", "prioritization_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION

    @field_validator(
        "priority_rule_version",
        "finding_rule_version",
        "correlation_rule_version",
    )
    @classmethod
    def _bounded_rule(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("prioritization_id")
    @classmethod
    def _valid_prioritization_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not PRIORITIZATION_ID_RE.match(text):
            raise ValueError(f"malformed prioritization_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITIZATION_STATUSES:
            raise ValueError(f"invalid prioritization status: {value!r}")
        return text

    @field_validator("ranked_findings", "deferred_findings")
    @classmethod
    def _bounded_plans(cls, value: object) -> list[dict]:
        return _bounded_plans(value, MAX_FINDINGS)

    @field_validator("skipped_findings")
    @classmethod
    def _bounded_skipped(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_priority_skip(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SKIPPED:
                break
        return out

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_priority_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_prioritization_summary(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_prioritization_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_prioritization_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("priority never changes finding confidence")
        return "NONE"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("prioritization results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("prioritization results are deterministic")
        return True


def sanitize_research_prioritization_result(value: object) -> dict:
    """Project an R55 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "prioritization_rule_version": "",
            "priority_rule_version": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "prioritization_id": "",
            "status": STATUS_NO_FINDINGS,
            "ranked_findings": [],
            "deferred_findings": [],
            "skipped_findings": [],
            "errors": [],
            "summary": sanitize_prioritization_summary(None),
            "provenance": sanitize_prioritization_provenance(None),
            "governance": sanitize_prioritization_governance(None),
            "limitations": [],
            "confidence_effect": "NONE",
            "research_only": True,
            "deterministic": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "prioritization_rule_version": _safe_text(
            value.get("prioritization_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "status": _closed(
            value.get("status"),
            PRIORITIZATION_STATUSES,
            STATUS_NO_FINDINGS,
        ),
        "ranked_findings": _bounded_plans(
            value.get("ranked_findings"), MAX_FINDINGS
        ),
        "deferred_findings": _bounded_plans(
            value.get("deferred_findings"), MAX_FINDINGS
        ),
        "skipped_findings": [
            projected
            for projected in (
                sanitize_priority_skip(item)
                for item in value.get("skipped_findings") or ()
            )
            if projected
        ][:MAX_SKIPPED],
        "errors": [
            projected
            for projected in (
                sanitize_priority_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "summary": sanitize_prioritization_summary(value.get("summary")),
        "provenance": sanitize_prioritization_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_prioritization_governance(
            value.get("governance")
        ),
        "limitations": _ordered_limitations(value.get("limitations")),
        "confidence_effect": "NONE",
        "research_only": True,
        "deterministic": True,
    }


def research_prioritization_result_plan_projection(
    value: ResearchPrioritizationResultPlan,
) -> dict:
    """Serialize an R55 result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "PRIORITIZATION_STATUSES",
    "PRIORITIZATION_ERROR_CATEGORIES",
    "FINDING_SKIP_REASONS",
    "GOVERNANCE_SUMMARY_STATES",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_NO_FINDINGS",
    "STATUS_FAILED",
    "SKIP_MALFORMED_FINDING",
    "SKIP_UNSUPPORTED_CATEGORY",
    "SKIP_DUPLICATE_IDENTITY",
    "SKIP_LIMIT_EXCEEDED",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_FINDING",
    "ERROR_DUPLICATE_IDENTITY",
    "ERROR_UNSUPPORTED_CATEGORY",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_CORRELATION_MISMATCH",
    "ERROR_UNKNOWN",
    "PRIORITIZATION_ID_PREFIX",
    "PRIORITIZATION_ID_RE",
    "MAX_FINDINGS",
    "MAX_SKIPPED",
    "MAX_ERRORS",
    "MAX_MESSAGE_LEN",
    "sanitize_priority_skip",
    "sanitize_priority_error",
    "sanitize_priority_band_counts",
    "sanitize_prioritization_summary",
    "sanitize_prioritization_provenance",
    "sanitize_prioritization_governance",
    "sanitize_research_prioritization_result",
    "ResearchPrioritizationResultPlan",
    "research_prioritization_result_plan_projection",
]

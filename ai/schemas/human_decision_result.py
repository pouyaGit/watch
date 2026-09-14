"""Human review result schema (Stage R56.3).

Defines the deterministic R56 human-review result that groups the bounded
human reviews and decisions derived from one R55 prioritization result. It
answers:

    "Which findings were reviewed, what did the human decide, and what
     remains explicitly unconfirmed and unauthorized?"

Hard boundaries encoded here:

- Decision recording only: the result never executes anything, never sends
  notifications, never collects evidence, never confirms a vulnerability and
  never authorizes execution, exploitation or payloads.
- Explicit authority: ``decision_authority`` is forced ``HUMAN``,
  ``ai_role`` is forced ``ADVISORY``, and ``execution_authorized`` /
  ``vulnerability_confirmed`` are forced ``False`` with
  ``confirmation_state = NOT_CONFIRMED``.
- Immutable upstream: the R55 recommendation is carried as read-only
  reference; ``confidence_effect`` is forced ``NONE`` and nothing rewrites
  the upstream priority, correlation or finding artifacts.
- Fail closed: rejected decisions (automated authority, execution or
  vulnerability authorization, malformed evidence, invalid transitions) are
  preserved in ``invalid_decisions`` with structured reasons and are never
  applied or repaired.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.human_decision import (
    AI_ROLE_ADVISORY,
    DECISION_AUTHORITY_HUMAN,
    DECISION_SOURCE_HUMAN,
    HUMAN_DECISION_TYPES,
)
from ai.schemas.human_review import (
    HumanReviewPlan,
    MAX_REVIEWS,
    sanitize_human_review_batch,
    sanitize_human_review_plan,
)
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)
from ai.schemas.research_priority import MAX_LIST

HUMAN_REVIEW_RESULT_RULE_VERSION = "r56-3"
RULE_VERSION = HUMAN_REVIEW_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_PENDING = "PENDING"
STATUS_NO_FINDINGS = "NO_FINDINGS"
STATUS_FAILED = "FAILED"

HUMAN_REVIEW_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_PENDING,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
)

SKIP_MALFORMED_PRIORITY = "MALFORMED_PRIORITY"
SKIP_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
SKIP_DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
SKIP_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

HUMAN_REVIEW_SKIP_REASONS: tuple[str, ...] = (
    SKIP_MALFORMED_PRIORITY,
    SKIP_UNSUPPORTED_CATEGORY,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_PRIORITY = "MALFORMED_PRIORITY"
ERROR_DECISION_REJECTED = "DECISION_REJECTED"
ERROR_INVALID_TRANSITION = "INVALID_TRANSITION"
ERROR_NOT_FOUND = "NOT_FOUND"
ERROR_DUPLICATE_DECISION = "DUPLICATE_DECISION"
ERROR_CORRELATION_MISMATCH = "CORRELATION_MISMATCH"
ERROR_INVALID_REVIEW_ORDER = "INVALID_REVIEW_ORDER"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

HUMAN_REVIEW_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_PRIORITY,
    ERROR_DECISION_REJECTED,
    ERROR_INVALID_TRANSITION,
    ERROR_NOT_FOUND,
    ERROR_DUPLICATE_DECISION,
    ERROR_CORRELATION_MISMATCH,
    ERROR_INVALID_REVIEW_ORDER,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

REJECTION_AUTOMATED_AUTHORITY = "AUTOMATED_AUTHORITY_REJECTED"
REJECTION_EXECUTION_AUTHORIZATION = "EXECUTION_AUTHORIZATION_REJECTED"
REJECTION_VULNERABILITY_CONFIRMATION = (
    "VULNERABILITY_CONFIRMATION_REJECTED"
)
REJECTION_EXPLOIT_AUTHORIZATION = "EXPLOIT_AUTHORIZATION_REJECTED"
REJECTION_UNKNOWN_DECISION = "UNKNOWN_DECISION_TYPE"
REJECTION_MISSING_FINDING_ID = "MISSING_FINDING_ID"
REJECTION_MISSING_SOURCE_PRIORITY = "MISSING_SOURCE_PRIORITY"
REJECTION_MALFORMED_EVIDENCE_REFERENCE = (
    "MALFORMED_EVIDENCE_REFERENCE"
)
REJECTION_INVALID_PROVENANCE = "INVALID_PROVENANCE"
REJECTION_INVALID_GOVERNANCE = "INVALID_GOVERNANCE"
REJECTION_INVALID_TRANSITION = "INVALID_TRANSITION"
REJECTION_MALFORMED_DECISION = "MALFORMED_DECISION"
REJECTION_DUPLICATE_DECISION = "DUPLICATE_DECISION"
REJECTION_FINDING_NOT_FOUND = "FINDING_NOT_FOUND"
REJECTION_UNKNOWN = "UNKNOWN_REJECTION"

DECISION_REJECTION_REASONS: tuple[str, ...] = (
    REJECTION_AUTOMATED_AUTHORITY,
    REJECTION_EXECUTION_AUTHORIZATION,
    REJECTION_VULNERABILITY_CONFIRMATION,
    REJECTION_EXPLOIT_AUTHORIZATION,
    REJECTION_UNKNOWN_DECISION,
    REJECTION_MISSING_FINDING_ID,
    REJECTION_MISSING_SOURCE_PRIORITY,
    REJECTION_MALFORMED_EVIDENCE_REFERENCE,
    REJECTION_INVALID_PROVENANCE,
    REJECTION_INVALID_GOVERNANCE,
    REJECTION_INVALID_TRANSITION,
    REJECTION_MALFORMED_DECISION,
    REJECTION_DUPLICATE_DECISION,
    REJECTION_FINDING_NOT_FOUND,
    REJECTION_UNKNOWN,
)

REVIEW_RESULT_ID_PREFIX = "hrr-"
REVIEW_RESULT_ID_RE = re.compile(r"^hrr-[0-9a-f]{16}$")

GOVERNANCE_SUMMARY_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

MAX_SKIPPED = 16
MAX_ERRORS = 16
MAX_INVALID = 16
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = 160) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_ids(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(r"^fnd-[0-9a-f]{16}$", text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_human_review_skip(value: object) -> dict:
    """Project one skipped priority entry onto fixed keys."""

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
            value.get("reason"),
            HUMAN_REVIEW_SKIP_REASONS,
            SKIP_MALFORMED_PRIORITY,
        ),
    }


def sanitize_human_review_error(value: object) -> dict:
    """Project one review error onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in HUMAN_REVIEW_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "finding_id": _safe_text(value.get("finding_id")),
        "category": _safe_text(value.get("category")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_invalid_decision(value: object) -> dict:
    """Project one rejected decision attempt onto fixed keys (never applied)."""

    if not isinstance(value, dict):
        return {}
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not re.match(r"^fnd-[0-9a-f]{16}$", finding_id):
        finding_id = ""
    decision_type = _safe_text(value.get("decision_type")).strip().upper()
    if decision_type not in HUMAN_DECISION_TYPES:
        decision_type = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_id": finding_id,
        "decision_type": decision_type,
        "decision_state": "INVALID",
        "rejection_reason": _closed(
            value.get("rejection_reason"),
            DECISION_REJECTION_REASONS,
            REJECTION_UNKNOWN,
        ),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
        "research_only": True,
        "deterministic": True,
    }


def sanitize_decision_type_counts(value: object) -> dict:
    """Project the per-decision-type counts onto the closed vocabulary."""

    counts = value if isinstance(value, dict) else {}
    return {
        decision_type: _bounded_int(
            counts.get(decision_type), 0, MAX_REVIEWS
        )
        for decision_type in HUMAN_DECISION_TYPES
    }


def sanitize_human_review_summary(value: object) -> dict:
    """Project the aggregated review summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "finding_count": 0,
            "review_count": 0,
            "decided_count": 0,
            "pending_count": 0,
            "expired_count": 0,
            "invalid_count": 0,
            "skipped_count": 0,
            "decision_type_counts": sanitize_decision_type_counts(None),
            "conflict_review_count": 0,
            "duplicate_review_count": 0,
            "evidence_request_count": 0,
            "escalation_count": 0,
            "research_only": True,
        }
    return {
        "finding_count": _bounded_int(
            value.get("finding_count"), 0, MAX_REVIEWS
        ),
        "review_count": _bounded_int(
            value.get("review_count"), 0, MAX_REVIEWS
        ),
        "decided_count": _bounded_int(
            value.get("decided_count"), 0, MAX_REVIEWS
        ),
        "pending_count": _bounded_int(
            value.get("pending_count"), 0, MAX_REVIEWS
        ),
        "expired_count": _bounded_int(
            value.get("expired_count"), 0, MAX_REVIEWS
        ),
        "invalid_count": _bounded_int(
            value.get("invalid_count"), 0, MAX_INVALID
        ),
        "skipped_count": _bounded_int(
            value.get("skipped_count"), 0, MAX_SKIPPED
        ),
        "decision_type_counts": sanitize_decision_type_counts(
            value.get("decision_type_counts")
        ),
        "conflict_review_count": _bounded_int(
            value.get("conflict_review_count"), 0, MAX_REVIEWS
        ),
        "duplicate_review_count": _bounded_int(
            value.get("duplicate_review_count"), 0, MAX_REVIEWS
        ),
        "evidence_request_count": _bounded_int(
            value.get("evidence_request_count"), 0, MAX_REVIEWS
        ),
        "escalation_count": _bounded_int(
            value.get("escalation_count"), 0, MAX_REVIEWS
        ),
        "research_only": True,
    }


def sanitize_human_review_provenance(value: object) -> dict:
    """Project container-level provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "review_rule_version": "",
            "decision_rule_version": "",
            "priority_rule_version": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "prioritization_id": "",
            "correlation_id": "",
            "source_kinds": [],
            "orchestration_ids": [],
            "source_categories": [],
            "source_agent_ids": [],
            "decision_source": DECISION_SOURCE_HUMAN,
            "deterministic": True,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "review_rule_version": _safe_text(
            value.get("review_rule_version")
        ),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
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
        "correlation_id": _safe_text(value.get("correlation_id")),
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
        "decision_source": DECISION_SOURCE_HUMAN,
        "deterministic": True,
        "research_only": True,
    }


def sanitize_human_review_governance(value: object) -> dict:
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
            value.get("referenced_finding_ids"), MAX_REVIEWS
        ),
        "unknown_finding_ids": _bounded_ids(
            value.get("unknown_finding_ids"), MAX_REVIEWS
        ),
        "ready_finding_ids": _bounded_ids(
            value.get("ready_finding_ids"), MAX_REVIEWS
        ),
        "not_ready_finding_ids": _bounded_ids(
            value.get("not_ready_finding_ids"), MAX_REVIEWS
        ),
        "research_only": True,
    }


def _bounded_reviews(value: object) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        try:
            projected = HumanReviewPlan(
                **sanitize_human_review_plan(item)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            continue
        out.append(projected)
        if len(out) >= MAX_REVIEWS:
            break
    return out


def sanitize_human_review_result(value: object) -> dict:
    """Project an R56 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_result()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "review_rule_version": _safe_text(
            value.get("review_rule_version")
        ),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
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
        "review_result_id": _safe_text(value.get("review_result_id")),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "status": _closed(
            value.get("status"),
            HUMAN_REVIEW_STATUSES,
            STATUS_NO_FINDINGS,
        ),
        "reviews": _bounded_reviews(value.get("reviews")),
        "invalid_decisions": [
            projected
            for projected in (
                sanitize_invalid_decision(item)
                for item in value.get("invalid_decisions") or ()
            )
            if projected
        ][:MAX_INVALID],
        "skipped_findings": [
            projected
            for projected in (
                sanitize_human_review_skip(item)
                for item in value.get("skipped_findings") or ()
            )
            if projected
        ][:MAX_SKIPPED],
        "errors": [
            projected
            for projected in (
                sanitize_human_review_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "batch": sanitize_human_review_batch(value.get("batch")),
        "summary": sanitize_human_review_summary(value.get("summary")),
        "provenance": sanitize_human_review_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_human_review_governance(
            value.get("governance")
        ),
        "limitations": _ordered_limitations(value.get("limitations")),
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "confidence_effect": "NONE",
        "research_only": True,
        "deterministic": True,
    }


def _ordered_limitations(codes: object) -> list[str]:
    from ai.schemas.human_decision import HUMAN_DECISION_LIMITATIONS

    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in HUMAN_DECISION_LIMITATIONS:
            found.add(text)
    return [code for code in HUMAN_DECISION_LIMITATIONS if code in found][
        :MAX_LIST
    ]


def _default_result() -> dict:
    return {
        "rule_version": "",
        "review_rule_version": "",
        "decision_rule_version": "",
        "priority_rule_version": "",
        "finding_rule_version": "",
        "correlation_rule_version": "",
        "review_result_id": "",
        "prioritization_id": "",
        "status": STATUS_NO_FINDINGS,
        "reviews": [],
        "invalid_decisions": [],
        "skipped_findings": [],
        "errors": [],
        "batch": {},
        "summary": sanitize_human_review_summary(None),
        "provenance": sanitize_human_review_provenance(None),
        "governance": sanitize_human_review_governance(None),
        "limitations": [],
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "confidence_effect": "NONE",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class HumanReviewResultPlan(BaseModel):
    """Deterministic R56 human-review result (R56.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_REVIEW_RESULT_RULE_VERSION
    review_rule_version: str = "r56-2"
    decision_rule_version: str = "r56-1"
    priority_rule_version: str = ""
    finding_rule_version: str = ""
    correlation_rule_version: str = ""
    review_result_id: str = ""
    prioritization_id: str = ""
    status: str = STATUS_NO_FINDINGS
    reviews: list[dict] = Field(default_factory=list)
    invalid_decisions: list[dict] = Field(default_factory=list)
    skipped_findings: list[dict] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    batch: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    decision_authority: str = DECISION_AUTHORITY_HUMAN
    ai_role: str = AI_ROLE_ADVISORY
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    confidence_effect: str = "NONE"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_REVIEW_RESULT_RULE_VERSION

    @field_validator(
        "review_rule_version",
        "decision_rule_version",
        "priority_rule_version",
        "finding_rule_version",
        "correlation_rule_version",
    )
    @classmethod
    def _bounded_rule(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("review_result_id")
    @classmethod
    def _valid_result_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not REVIEW_RESULT_ID_RE.match(text):
            raise ValueError(f"malformed review_result_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HUMAN_REVIEW_STATUSES:
            raise ValueError(f"invalid status: {value!r}")
        return text

    @field_validator("reviews")
    @classmethod
    def _bounded_reviews_field(cls, value: object) -> list[dict]:
        return _bounded_reviews(value)

    @field_validator("invalid_decisions")
    @classmethod
    def _bounded_invalid(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_invalid_decision(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_INVALID:
                break
        return out

    @field_validator("skipped_findings")
    @classmethod
    def _bounded_skipped(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_human_review_skip(item)
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
            projected = sanitize_human_review_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("batch")
    @classmethod
    def _bounded_batch(cls, value: object) -> dict:
        return sanitize_human_review_batch(value)

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_human_review_summary(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_human_review_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_human_review_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("decision_authority")
    @classmethod
    def _human_authority(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != DECISION_AUTHORITY_HUMAN:
            raise ValueError("decision authority must be HUMAN")
        return DECISION_AUTHORITY_HUMAN

    @field_validator("ai_role")
    @classmethod
    def _advisory_ai(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != AI_ROLE_ADVISORY:
            raise ValueError("the AI role is advisory only")
        return AI_ROLE_ADVISORY

    @field_validator("execution_authorized", "vulnerability_confirmed")
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "review results never authorize execution or confirmation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("review results never confirm a vulnerability")
        return "NOT_CONFIRMED"

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("human review never changes finding confidence")
        return "NONE"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("human review results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("human review results are deterministic")
        return True


def human_review_result_plan_projection(
    value: HumanReviewResultPlan,
) -> dict:
    """Serialize an R56 result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "HUMAN_REVIEW_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "HUMAN_REVIEW_STATUSES",
    "HUMAN_REVIEW_SKIP_REASONS",
    "HUMAN_REVIEW_ERROR_CATEGORIES",
    "DECISION_REJECTION_REASONS",
    "GOVERNANCE_SUMMARY_STATES",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_PENDING",
    "STATUS_NO_FINDINGS",
    "STATUS_FAILED",
    "SKIP_MALFORMED_PRIORITY",
    "SKIP_UNSUPPORTED_CATEGORY",
    "SKIP_DUPLICATE_IDENTITY",
    "SKIP_LIMIT_EXCEEDED",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_PRIORITY",
    "ERROR_DECISION_REJECTED",
    "ERROR_INVALID_TRANSITION",
    "ERROR_NOT_FOUND",
    "ERROR_DUPLICATE_DECISION",
    "ERROR_CORRELATION_MISMATCH",
    "ERROR_INVALID_REVIEW_ORDER",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "REJECTION_AUTOMATED_AUTHORITY",
    "REJECTION_EXECUTION_AUTHORIZATION",
    "REJECTION_VULNERABILITY_CONFIRMATION",
    "REJECTION_EXPLOIT_AUTHORIZATION",
    "REJECTION_UNKNOWN_DECISION",
    "REJECTION_MISSING_FINDING_ID",
    "REJECTION_MISSING_SOURCE_PRIORITY",
    "REJECTION_MALFORMED_EVIDENCE_REFERENCE",
    "REJECTION_INVALID_PROVENANCE",
    "REJECTION_INVALID_GOVERNANCE",
    "REJECTION_INVALID_TRANSITION",
    "REJECTION_MALFORMED_DECISION",
    "REJECTION_DUPLICATE_DECISION",
    "REJECTION_FINDING_NOT_FOUND",
    "REJECTION_UNKNOWN",
    "REVIEW_RESULT_ID_PREFIX",
    "REVIEW_RESULT_ID_RE",
    "MAX_REVIEWS",
    "MAX_SKIPPED",
    "MAX_ERRORS",
    "MAX_INVALID",
    "MAX_MESSAGE_LEN",
    "sanitize_human_review_skip",
    "sanitize_human_review_error",
    "sanitize_invalid_decision",
    "sanitize_decision_type_counts",
    "sanitize_human_review_summary",
    "sanitize_human_review_provenance",
    "sanitize_human_review_governance",
    "sanitize_human_review_result",
    "HumanReviewResultPlan",
    "human_review_result_plan_projection",
]

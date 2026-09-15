"""Copilot result schema (Stage R60.4).

Defines the bounded, deterministic top-level result of the Watch Bug Bounty
Copilot. It answers:

    "Which advisory briefing was produced, from which bounded context, with
     what status and what explicit safety boundary?"

Hard boundaries encoded here:

- Advisory only: the result wraps a briefing; it never confirms a
  vulnerability, never authorizes exploitation and never executes anything.
  ``execution_performed`` and ``external_executor_present`` are forced
  ``False`` and ``confirmation_state`` is forced ``NOT_CONFIRMED``.
- Safe failure: malformed, contradictory or unavailable upstream context
  produces a structured error, an advisory-safe status and an explicit
  human-review flag rather than optimistic authorization.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no subprocess, no execution of any kind
is represented here.
"""

from __future__ import annotations

import re

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ai.schemas.copilot_brief import (
    BRIEF_BASE_LIMITATIONS,
    COPILOT_BRIEF_LIMITATIONS,
    CopilotBriefPlan,
    sanitize_copilot_brief,
)
from ai.schemas.copilot_opportunity import (
    MAX_VALUE_LEN,
    sanitize_copilot_provenance,
)

COPILOT_RESULT_RULE_VERSION = "r60-4"
RULE_VERSION = COPILOT_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Result status vocabulary (closed; no executed state exists)
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NO_CONTEXT = "NO_CONTEXT"
STATUS_FAILED = "FAILED"

COPILOT_RESULT_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NO_CONTEXT,
    STATUS_FAILED,
)

# ---------------------------------------------------------------------------
# Error vocabulary (closed)
# ---------------------------------------------------------------------------

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_INPUT = "MALFORMED_INPUT"
ERROR_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_CONFLICTING_CONTEXT = "CONFLICTING_CONTEXT"
ERROR_WORKFLOW_CONTEXT_UNAVAILABLE = "WORKFLOW_CONTEXT_UNAVAILABLE"
ERROR_UPSTREAM_WORKFLOW_BLOCKED = "UPSTREAM_WORKFLOW_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

COPILOT_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    ERROR_CONFLICTING_CONTEXT,
    ERROR_WORKFLOW_CONTEXT_UNAVAILABLE,
    ERROR_UPSTREAM_WORKFLOW_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

#: Result limitation vocabulary (shared with the brief; no duplicates).
COPILOT_RESULT_LIMITATIONS: tuple[str, ...] = COPILOT_BRIEF_LIMITATIONS

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

RESULT_ID_PREFIX = "bbr-"
RESULT_ID_RE = re.compile(r"^bbr-[0-9a-f]{16}$")

MAX_ERRORS = 16
MAX_LIMITATIONS = 16
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in COPILOT_RESULT_LIMITATIONS:
            found.add(text)
    return [
        code for code in COPILOT_RESULT_LIMITATIONS if code in found
    ][:MAX_LIMITATIONS]


def sanitize_copilot_error(value: object) -> dict:
    """Project one copilot error onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in COPILOT_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "input_kind": _safe_text(value.get("input_kind")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_copilot_summary(value: object) -> dict:
    """Project the deterministic copilot summary onto fixed keys."""

    if not isinstance(value, dict):
        return _default_summary()
    return {
        "opportunity_count": _bounded_int(
            value.get("opportunity_count"), 0, 4096
        ),
        "high_priority_count": _bounded_int(
            value.get("high_priority_count"), 0, 4096
        ),
        "recommended_action_count": _bounded_int(
            value.get("recommended_action_count"), 0, 4096
        ),
        "human_review_required": bool(
            value.get("human_review_required")
        )
        is True,
        "confidence": _safe_text(value.get("confidence")).upper()
        or "UNKNOWN",
        "workflow_state": _safe_text(
            value.get("workflow_state")
        ).upper(),
        "safety_status": _safe_text(
            value.get("safety_status")
        ).upper()
        or "RESEARCH_ONLY",
        "error_count": _bounded_int(value.get("error_count"), 0, MAX_ERRORS),
    }


def _default_summary() -> dict:
    return {
        "opportunity_count": 0,
        "high_priority_count": 0,
        "recommended_action_count": 0,
        "human_review_required": True,
        "confidence": "UNKNOWN",
        "workflow_state": "",
        "safety_status": "RESEARCH_ONLY",
        "error_count": 0,
    }


def sanitize_copilot_result(value: object) -> dict:
    """Project an R60 copilot result onto its fixed key set."""

    if not isinstance(value, dict) or not value:
        return _default_result()
    try:
        brief = CopilotBriefPlan(
            **sanitize_copilot_brief(value.get("brief"))
        ).model_dump(mode="json")
    except (TypeError, ValueError):
        brief = sanitize_copilot_brief(value.get("brief"))
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "result_id": _safe_text(value.get("result_id")),
        "status": _safe_text(value.get("status")).strip().upper()
        if _safe_text(value.get("status")).strip().upper()
        in COPILOT_RESULT_STATUSES
        else STATUS_FAILED,
        "brief": brief,
        "summary": sanitize_copilot_summary(value.get("summary")),
        "errors": [
            projected
            for projected in (
                sanitize_copilot_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "provenance": sanitize_copilot_provenance(value.get("provenance")),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations")),
        "advisory": True,
        "human_authority_preserved": True,
        "execution_performed": False,
        "external_executor_present": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _default_result() -> dict:
    return {
        "rule_version": "",
        "result_id": "",
        "status": STATUS_FAILED,
        "brief": sanitize_copilot_brief(None),
        "summary": _default_summary(),
        "errors": [],
        "provenance": sanitize_copilot_provenance(None),
        "governance": {},
        "limitations": list(BRIEF_BASE_LIMITATIONS),
        "advisory": True,
        "human_authority_preserved": True,
        "execution_performed": False,
        "external_executor_present": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CopilotResultPlan(BaseModel):
    """Deterministic R60 bug bounty copilot result (R60.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COPILOT_RESULT_RULE_VERSION
    result_id: str
    status: str = STATUS_NO_CONTEXT
    brief: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    advisory: bool = True
    human_authority_preserved: bool = True
    execution_performed: bool = False
    external_executor_present: bool = False
    vulnerability_confirmed: bool = False
    exploit_authorized: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COPILOT_RESULT_RULE_VERSION

    @field_validator("result_id")
    @classmethod
    def _valid_result_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not RESULT_ID_RE.match(text):
            raise ValueError(f"malformed result_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in COPILOT_RESULT_STATUSES:
            raise ValueError(f"invalid copilot status: {value!r}")
        return text

    @field_validator("brief")
    @classmethod
    def _bounded_brief(cls, value: object) -> dict:
        try:
            return CopilotBriefPlan(
                **sanitize_copilot_brief(value)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            return sanitize_copilot_brief(value)

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_copilot_summary(value)

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_copilot_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_copilot_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("advisory", "human_authority_preserved", "research_only")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "copilot results are advisory and preserve human authority"
            )
        return True

    @field_validator("execution_performed", "external_executor_present")
    @classmethod
    def _never_executed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("the copilot never executes anything")
        return False

    @field_validator("vulnerability_confirmed", "exploit_authorized")
    @classmethod
    def _never_confirmed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "the copilot never confirms or authorizes exploitation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed_state(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("copilot results never confirm")
        return "NOT_CONFIRMED"

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("copilot results are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_status(self) -> "CopilotResultPlan":
        if self.status == STATUS_FAILED and not self.errors:
            raise ValueError("failed copilot results require structured errors")
        if self.status == STATUS_COMPLETED and not self.brief:
            raise ValueError("completed copilot results require a brief")
        return self


def copilot_result_plan_projection(value: CopilotResultPlan) -> dict:
    """Serialize an R60 copilot result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "COPILOT_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_NO_CONTEXT",
    "STATUS_FAILED",
    "COPILOT_RESULT_STATUSES",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_INPUT",
    "ERROR_RULE_VERSION_MISMATCH",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_CONFLICTING_CONTEXT",
    "ERROR_WORKFLOW_CONTEXT_UNAVAILABLE",
    "ERROR_UPSTREAM_WORKFLOW_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "COPILOT_ERROR_CATEGORIES",
    "COPILOT_RESULT_LIMITATIONS",
    "RESULT_ID_PREFIX",
    "RESULT_ID_RE",
    "MAX_ERRORS",
    "MAX_LIMITATIONS",
    "MAX_MESSAGE_LEN",
    "sanitize_copilot_error",
    "sanitize_copilot_summary",
    "sanitize_copilot_result",
    "CopilotResultPlan",
    "copilot_result_plan_projection",
]

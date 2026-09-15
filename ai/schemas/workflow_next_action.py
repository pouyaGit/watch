"""Workflow next-action schema (Stage R59.3).

Defines the bounded, deterministic next-step recommendation of the R59
end-to-end security research workflow. It answers:

    "Given the current structured workflow state, what is the advisory next
     step, and why?"

Hard boundaries encoded here:

- Advisory only: a recommendation never means "execute this action now".
  ``advisory`` and ``human_authority_required`` are forced ``True`` and
  ``auto_execute`` is forced ``False``. The caller (or a human) decides
  whether and how to proceed.
- No execution capability: the recommendation vocabulary contains only
  research-workflow steps (analysis, evaluation, collaboration, feedback,
  findings, correlation, prioritization, human review, learning, execution
  control review, block or complete). It never names an exploit, payload,
  scan, browser, command or network action.
- Closed vocabularies: action codes, stage targets and reasons are closed
  sets.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no subprocess, no execution of any kind
is represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.workflow_stage import WORKFLOW_STAGE_ORDER

WORKFLOW_NEXT_ACTION_RULE_VERSION = "r59-3"
RULE_VERSION = WORKFLOW_NEXT_ACTION_RULE_VERSION

# ---------------------------------------------------------------------------
# Action vocabulary (closed; advisory research-workflow steps only)
# ---------------------------------------------------------------------------

ACTION_RUN_RESEARCH_ANALYSIS = "RUN_RESEARCH_ANALYSIS"
ACTION_RUN_EVALUATION = "RUN_EVALUATION"
ACTION_RUN_COLLABORATION = "RUN_COLLABORATION"
ACTION_RUN_FEEDBACK_ANALYSIS = "RUN_FEEDBACK_ANALYSIS"
ACTION_BUILD_FINDINGS = "BUILD_FINDINGS"
ACTION_CORRELATE_FINDINGS = "CORRELATE_FINDINGS"
ACTION_PRIORITIZE_RESEARCH = "PRIORITIZE_RESEARCH"
ACTION_REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"
ACTION_WAIT_FOR_HUMAN_DECISION = "WAIT_FOR_HUMAN_DECISION"
ACTION_UPDATE_LEARNING = "UPDATE_LEARNING"
ACTION_REVIEW_EXECUTION_CONTROL = "REVIEW_EXECUTION_CONTROL"
ACTION_BLOCK_WORKFLOW = "BLOCK_WORKFLOW"
ACTION_COMPLETE_WORKFLOW = "COMPLETE_WORKFLOW"

WORKFLOW_NEXT_ACTIONS: tuple[str, ...] = (
    ACTION_RUN_RESEARCH_ANALYSIS,
    ACTION_RUN_EVALUATION,
    ACTION_RUN_COLLABORATION,
    ACTION_RUN_FEEDBACK_ANALYSIS,
    ACTION_BUILD_FINDINGS,
    ACTION_CORRELATE_FINDINGS,
    ACTION_PRIORITIZE_RESEARCH,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_WAIT_FOR_HUMAN_DECISION,
    ACTION_UPDATE_LEARNING,
    ACTION_REVIEW_EXECUTION_CONTROL,
    ACTION_BLOCK_WORKFLOW,
    ACTION_COMPLETE_WORKFLOW,
)

#: Action code -> the workflow stage the recommendation concerns.
ACTION_STAGE: dict[str, str] = {
    ACTION_RUN_RESEARCH_ANALYSIS: "SPECIALIST_RESEARCH",
    ACTION_RUN_EVALUATION: "EVALUATION",
    ACTION_RUN_COLLABORATION: "COLLABORATION",
    ACTION_RUN_FEEDBACK_ANALYSIS: "FEEDBACK",
    ACTION_BUILD_FINDINGS: "FINDING",
    ACTION_CORRELATE_FINDINGS: "CORRELATION",
    ACTION_PRIORITIZE_RESEARCH: "PRIORITIZATION",
    ACTION_REQUEST_HUMAN_REVIEW: "HUMAN_REVIEW",
    ACTION_WAIT_FOR_HUMAN_DECISION: "HUMAN_REVIEW",
    ACTION_UPDATE_LEARNING: "LEARNING",
    ACTION_REVIEW_EXECUTION_CONTROL: "EXECUTION_CONTROL",
    ACTION_BLOCK_WORKFLOW: "",
    ACTION_COMPLETE_WORKFLOW: "",
}

#: Actions that indicate the workflow cannot proceed toward execution.
BLOCKING_ACTIONS: tuple[str, ...] = (
    ACTION_BLOCK_WORKFLOW,
    ACTION_WAIT_FOR_HUMAN_DECISION,
)

# ---------------------------------------------------------------------------
# Action reason vocabulary (closed)
# ---------------------------------------------------------------------------

REASON_RESEARCH_INPUT_READY = "RESEARCH_INPUT_READY"
REASON_SPECIALIST_RESULTS_PRESENT = "SPECIALIST_RESULTS_PRESENT"
REASON_EVALUATION_MISSING = "EVALUATION_MISSING"
REASON_COLLABORATION_MISSING = "COLLABORATION_MISSING"
REASON_FEEDBACK_MISSING = "FEEDBACK_MISSING"
REASON_FINDINGS_MISSING = "FINDINGS_MISSING"
REASON_CORRELATION_MISSING = "CORRELATION_MISSING"
REASON_PRIORITIZATION_MISSING = "PRIORITIZATION_MISSING"
REASON_HUMAN_DECISION_MISSING = "HUMAN_DECISION_MISSING"
REASON_HUMAN_DECISION_PENDING = "HUMAN_DECISION_PENDING"
REASON_HUMAN_DECISION_APPROVED = "HUMAN_DECISION_APPROVED"
REASON_HUMAN_REQUESTED_MORE_EVIDENCE = "HUMAN_REQUESTED_MORE_EVIDENCE"
REASON_HUMAN_DEFERRED = "HUMAN_DEFERRED"
REASON_HUMAN_REJECTED = "HUMAN_REJECTED"
REASON_HUMAN_ESCALATED = "HUMAN_ESCALATED"
REASON_HUMAN_NEEDS_REVIEW = "HUMAN_NEEDS_REVIEW"
REASON_LEARNING_MISSING = "LEARNING_MISSING"
REASON_LEARNING_UPDATED = "LEARNING_UPDATED"
REASON_LEARNING_BLOCKING_RECOMMENDATION = "LEARNING_BLOCKING_RECOMMENDATION"
REASON_EXECUTION_REVIEW_MISSING = "EXECUTION_REVIEW_MISSING"
REASON_EXECUTION_AUTHORIZED = "EXECUTION_AUTHORIZED"
REASON_EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
REASON_EXECUTION_READY = "EXECUTION_READY_FOR_EXTERNAL_EXECUTOR"
REASON_NO_FINDINGS_PRODUCED = "NO_FINDINGS_PRODUCED"
REASON_SAFETY_BLOCKED = "SAFETY_BLOCKED"
REASON_WORKFLOW_INVALID = "WORKFLOW_INVALID"
REASON_WORKFLOW_COMPLETE = "WORKFLOW_COMPLETE"
REASON_WORKFLOW_CONFLICT = "WORKFLOW_CONFLICT"
REASON_STAGE_ORDER_INVALID = "STAGE_ORDER_INVALID"
REASON_OPTION_DISABLED = "OPTION_DISABLED"
REASON_UNKNOWN = "UNKNOWN_REASON"

WORKFLOW_NEXT_ACTION_REASONS: tuple[str, ...] = (
    REASON_RESEARCH_INPUT_READY,
    REASON_SPECIALIST_RESULTS_PRESENT,
    REASON_EVALUATION_MISSING,
    REASON_COLLABORATION_MISSING,
    REASON_FEEDBACK_MISSING,
    REASON_FINDINGS_MISSING,
    REASON_CORRELATION_MISSING,
    REASON_PRIORITIZATION_MISSING,
    REASON_HUMAN_DECISION_MISSING,
    REASON_HUMAN_DECISION_PENDING,
    REASON_HUMAN_DECISION_APPROVED,
    REASON_HUMAN_REQUESTED_MORE_EVIDENCE,
    REASON_HUMAN_DEFERRED,
    REASON_HUMAN_REJECTED,
    REASON_HUMAN_ESCALATED,
    REASON_HUMAN_NEEDS_REVIEW,
    REASON_LEARNING_MISSING,
    REASON_LEARNING_UPDATED,
    REASON_LEARNING_BLOCKING_RECOMMENDATION,
    REASON_EXECUTION_REVIEW_MISSING,
    REASON_EXECUTION_AUTHORIZED,
    REASON_EXECUTION_BLOCKED,
    REASON_EXECUTION_READY,
    REASON_NO_FINDINGS_PRODUCED,
    REASON_SAFETY_BLOCKED,
    REASON_WORKFLOW_INVALID,
    REASON_WORKFLOW_COMPLETE,
    REASON_WORKFLOW_CONFLICT,
    REASON_STAGE_ORDER_INVALID,
    REASON_OPTION_DISABLED,
    REASON_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Action limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_NOT_AN_EXECUTION_INSTRUCTION = "NOT_AN_EXECUTION_INSTRUCTION"
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"

WORKFLOW_NEXT_ACTION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

ACTION_ID_PREFIX = "wna-"
ACTION_ID_RE = re.compile(r"^wna-[0-9a-f]{16}$")

MAX_LIMITATIONS = 12
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in WORKFLOW_NEXT_ACTION_LIMITATIONS:
            found.add(text)
    return [
        code for code in WORKFLOW_NEXT_ACTION_LIMITATIONS if code in found
    ][:MAX_LIMITATIONS]


def sanitize_next_action_provenance(value: object) -> dict:
    """Project next-action provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "workflow_id": "",
            "next_action_rule_version": WORKFLOW_NEXT_ACTION_RULE_VERSION,
            "workflow_state": "",
            "deterministic": True,
            "research_only": True,
        }
    return {
        "workflow_id": _safe_text(value.get("workflow_id")),
        "next_action_rule_version": WORKFLOW_NEXT_ACTION_RULE_VERSION,
        "workflow_state": _safe_text(value.get("workflow_state")).upper(),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_workflow_next_action(value: object) -> dict:
    """Project a workflow next-action recommendation onto fixed keys."""

    if not isinstance(value, dict):
        return _default_next_action()
    action_code = _safe_text(value.get("action_code")).strip().upper()
    if action_code not in WORKFLOW_NEXT_ACTIONS:
        action_code = ACTION_BLOCK_WORKFLOW
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "action_id": _safe_text(value.get("action_id")),
        "action_code": action_code,
        "stage_type": _safe_text(value.get("stage_type")).strip().upper()
        if _safe_text(value.get("stage_type")).strip().upper()
        in WORKFLOW_STAGE_ORDER
        else "",
        "reason": _safe_text(value.get("reason")).strip().upper()
        if _safe_text(value.get("reason")).strip().upper()
        in WORKFLOW_NEXT_ACTION_REASONS
        else REASON_UNKNOWN,
        "execution_blocked": bool(value.get("execution_blocked")) is True,
        "human_authority_required": True,
        "advisory": True,
        "auto_execute": False,
        "provenance": sanitize_next_action_provenance(
            value.get("provenance")
        ),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _default_next_action() -> dict:
    return {
        "rule_version": "",
        "action_id": "",
        "action_code": ACTION_BLOCK_WORKFLOW,
        "stage_type": "",
        "reason": REASON_WORKFLOW_INVALID,
        "execution_blocked": True,
        "human_authority_required": True,
        "advisory": True,
        "auto_execute": False,
        "provenance": sanitize_next_action_provenance(None),
        "limitations": list(WORKFLOW_NEXT_ACTION_LIMITATIONS),
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class WorkflowNextActionPlan(BaseModel):
    """Deterministic advisory R59 next-action recommendation (R59.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = WORKFLOW_NEXT_ACTION_RULE_VERSION
    action_id: str
    action_code: str
    stage_type: str = ""
    reason: str = REASON_UNKNOWN
    execution_blocked: bool = False
    human_authority_required: bool = True
    advisory: bool = True
    auto_execute: bool = False
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return WORKFLOW_NEXT_ACTION_RULE_VERSION

    @field_validator("action_id")
    @classmethod
    def _valid_action_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not ACTION_ID_RE.match(text):
            raise ValueError(f"malformed action_id: {value!r}")
        return text

    @field_validator("action_code")
    @classmethod
    def _valid_action_code(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_NEXT_ACTIONS:
            raise ValueError(f"invalid action_code: {value!r}")
        return text

    @field_validator("stage_type")
    @classmethod
    def _valid_stage_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_STAGE_ORDER:
            raise ValueError(f"invalid action stage_type: {value!r}")
        return text

    @field_validator("reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_NEXT_ACTION_REASONS:
            raise ValueError(f"invalid action reason: {value!r}")
        return text

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_next_action_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("human_authority_required", "advisory", "research_only")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "next actions are advisory and require human authority"
            )
        return True

    @field_validator("auto_execute")
    @classmethod
    def _never_auto_executes(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("next actions never auto-execute")
        return False

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("next actions are deterministic")
        return True


def workflow_next_action_plan_projection(
    value: WorkflowNextActionPlan,
) -> dict:
    """Serialize a next-action recommendation to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "WORKFLOW_NEXT_ACTION_RULE_VERSION",
    "RULE_VERSION",
    "ACTION_RUN_RESEARCH_ANALYSIS",
    "ACTION_RUN_EVALUATION",
    "ACTION_RUN_COLLABORATION",
    "ACTION_RUN_FEEDBACK_ANALYSIS",
    "ACTION_BUILD_FINDINGS",
    "ACTION_CORRELATE_FINDINGS",
    "ACTION_PRIORITIZE_RESEARCH",
    "ACTION_REQUEST_HUMAN_REVIEW",
    "ACTION_WAIT_FOR_HUMAN_DECISION",
    "ACTION_UPDATE_LEARNING",
    "ACTION_REVIEW_EXECUTION_CONTROL",
    "ACTION_BLOCK_WORKFLOW",
    "ACTION_COMPLETE_WORKFLOW",
    "WORKFLOW_NEXT_ACTIONS",
    "ACTION_STAGE",
    "BLOCKING_ACTIONS",
    "REASON_RESEARCH_INPUT_READY",
    "REASON_SPECIALIST_RESULTS_PRESENT",
    "REASON_EVALUATION_MISSING",
    "REASON_COLLABORATION_MISSING",
    "REASON_FEEDBACK_MISSING",
    "REASON_FINDINGS_MISSING",
    "REASON_CORRELATION_MISSING",
    "REASON_PRIORITIZATION_MISSING",
    "REASON_HUMAN_DECISION_MISSING",
    "REASON_HUMAN_DECISION_PENDING",
    "REASON_HUMAN_DECISION_APPROVED",
    "REASON_HUMAN_REQUESTED_MORE_EVIDENCE",
    "REASON_HUMAN_DEFERRED",
    "REASON_HUMAN_REJECTED",
    "REASON_HUMAN_ESCALATED",
    "REASON_HUMAN_NEEDS_REVIEW",
    "REASON_LEARNING_MISSING",
    "REASON_LEARNING_UPDATED",
    "REASON_LEARNING_BLOCKING_RECOMMENDATION",
    "REASON_EXECUTION_REVIEW_MISSING",
    "REASON_EXECUTION_AUTHORIZED",
    "REASON_EXECUTION_BLOCKED",
    "REASON_EXECUTION_READY",
    "REASON_NO_FINDINGS_PRODUCED",
    "REASON_SAFETY_BLOCKED",
    "REASON_WORKFLOW_INVALID",
    "REASON_WORKFLOW_COMPLETE",
    "REASON_WORKFLOW_CONFLICT",
    "REASON_STAGE_ORDER_INVALID",
    "REASON_OPTION_DISABLED",
    "REASON_UNKNOWN",
    "WORKFLOW_NEXT_ACTION_REASONS",
    "WORKFLOW_NEXT_ACTION_LIMITATIONS",
    "ACTION_ID_PREFIX",
    "ACTION_ID_RE",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_next_action_provenance",
    "sanitize_workflow_next_action",
    "WorkflowNextActionPlan",
    "workflow_next_action_plan_projection",
]

"""Security research workflow result schema (Stage R59.4).

Defines the bounded, deterministic result of the R59 end-to-end security
research workflow. It answers:

    "What is the current structured state of the security research
     workflow, what should happen next, and what is the safest valid
     boundary the workflow can reach?"

Hard boundaries encoded here:

- Workflow states are research states: no state implies vulnerability
  confirmation and no state implies execution occurred. ``EXECUTED`` does
  not exist in this vocabulary.
- ``execution_performed``, ``external_executor_present``,
  ``vulnerability_confirmed`` and ``exploit_authorized`` are forced
  ``False`` and ``confirmation_state`` is forced ``NOT_CONFIRMED``.
- The result is advisory: ``advisory`` and ``human_authority_preserved`` are
  forced ``True``; the next action never auto-executes.
- Read-only references: upstream artifacts are represented by bounded
  references; the result never mutates or embeds raw upstream artifacts.
- Closed vocabularies; bounded, privacy-safe, JSON serializable; no
  timestamps, UUIDs, pids or randomness.

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

from ai.schemas.workflow_next_action import (
    WORKFLOW_NEXT_ACTION_REASONS,
    WorkflowNextActionPlan,
    sanitize_workflow_next_action,
)
from ai.schemas.workflow_stage import (
    WORKFLOW_STAGE_ORDER,
    WorkflowStagePlan,
    sanitize_workflow_stage,
)

SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION = "r59-4"
RULE_VERSION = SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Workflow state vocabulary (closed; no EXECUTED/CONFIRMED state exists)
# ---------------------------------------------------------------------------

STATE_INITIALIZED = "INITIALIZED"
STATE_RESEARCH_READY = "RESEARCH_READY"
STATE_SPECIALISTS_EVALUATED = "SPECIALISTS_EVALUATED"
STATE_COLLABORATED = "COLLABORATED"
STATE_FEEDBACK_ANALYZED = "FEEDBACK_ANALYZED"
STATE_FINDINGS_BUILT = "FINDINGS_BUILT"
STATE_FINDINGS_CORRELATED = "FINDINGS_CORRELATED"
STATE_PRIORITIZED = "PRIORITIZED"
STATE_AWAITING_HUMAN_DECISION = "AWAITING_HUMAN_DECISION"
STATE_HUMAN_DECIDED = "HUMAN_DECIDED"
STATE_LEARNING_UPDATED = "LEARNING_UPDATED"
STATE_EXECUTION_REVIEWED = "EXECUTION_REVIEWED"
STATE_BLOCKED = "BLOCKED"
STATE_COMPLETED = "COMPLETED"
STATE_INVALID = "INVALID"

WORKFLOW_STATES: tuple[str, ...] = (
    STATE_INITIALIZED,
    STATE_RESEARCH_READY,
    STATE_SPECIALISTS_EVALUATED,
    STATE_COLLABORATED,
    STATE_FEEDBACK_ANALYZED,
    STATE_FINDINGS_BUILT,
    STATE_FINDINGS_CORRELATED,
    STATE_PRIORITIZED,
    STATE_AWAITING_HUMAN_DECISION,
    STATE_HUMAN_DECIDED,
    STATE_LEARNING_UPDATED,
    STATE_EXECUTION_REVIEWED,
    STATE_BLOCKED,
    STATE_COMPLETED,
    STATE_INVALID,
)

#: States that may never be reported by R59 (defense in depth).
FORBIDDEN_STATES: tuple[str, ...] = (
    "EXECUTED",
    "EXECUTION_PERFORMED",
    "CONFIRMED",
    "VULNERABILITY_CONFIRMED",
    "EXPLOITED",
)

# ---------------------------------------------------------------------------
# Safety status vocabulary (closed)
# ---------------------------------------------------------------------------

SAFETY_STATUS_RESEARCH_ONLY = "RESEARCH_ONLY"
SAFETY_STATUS_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
SAFETY_STATUS_EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
SAFETY_STATUS_SAFETY_BLOCKED = "SAFETY_BLOCKED"
SAFETY_STATUS_CONTROLLED_AUTHORIZATION = "CONTROLLED_AUTHORIZATION"
SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR = "READY_FOR_EXTERNAL_EXECUTOR"
SAFETY_STATUS_INVALID = "INVALID"

WORKFLOW_SAFETY_STATUSES: tuple[str, ...] = (
    SAFETY_STATUS_RESEARCH_ONLY,
    SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
    SAFETY_STATUS_EXECUTION_BLOCKED,
    SAFETY_STATUS_SAFETY_BLOCKED,
    SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
    SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    SAFETY_STATUS_INVALID,
)

# ---------------------------------------------------------------------------
# Human decision summary vocabulary (closed)
# ---------------------------------------------------------------------------

HUMAN_STATUS_NOT_REQUESTED = "NOT_REQUESTED"
HUMAN_STATUS_PENDING = "PENDING"
HUMAN_STATUS_DECIDED = "DECIDED"
HUMAN_STATUS_BLOCKED = "BLOCKED"
HUMAN_STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
HUMAN_STATUS_CONFLICT = "CONFLICT"

HUMAN_DECISION_SUMMARY_STATUSES: tuple[str, ...] = (
    HUMAN_STATUS_NOT_REQUESTED,
    HUMAN_STATUS_PENDING,
    HUMAN_STATUS_DECIDED,
    HUMAN_STATUS_BLOCKED,
    HUMAN_STATUS_REVIEW_REQUIRED,
    HUMAN_STATUS_CONFLICT,
)

# ---------------------------------------------------------------------------
# Error vocabulary (closed)
# ---------------------------------------------------------------------------

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MISSING_REQUIRED_STAGE = "MISSING_REQUIRED_STAGE"
ERROR_STAGE_ORDER_INVALID = "STAGE_ORDER_INVALID"
ERROR_UPSTREAM_RESULT_INVALID = "UPSTREAM_RESULT_INVALID"
ERROR_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
ERROR_HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"
ERROR_EXECUTION_CONTROL_BLOCKED = "EXECUTION_CONTROL_BLOCKED"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_LEARNING_REVIEW_REQUIRED = "LEARNING_REVIEW_REQUIRED"
ERROR_WORKFLOW_CONFLICT = "WORKFLOW_CONFLICT"
ERROR_UNSUPPORTED_TRANSITION = "UNSUPPORTED_TRANSITION"
ERROR_MALFORMED_INPUT = "MALFORMED_INPUT"

WORKFLOW_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MISSING_REQUIRED_STAGE,
    ERROR_STAGE_ORDER_INVALID,
    ERROR_UPSTREAM_RESULT_INVALID,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_HUMAN_DECISION_REQUIRED,
    ERROR_EXECUTION_CONTROL_BLOCKED,
    ERROR_SAFETY_BLOCKED,
    ERROR_LEARNING_REVIEW_REQUIRED,
    ERROR_WORKFLOW_CONFLICT,
    ERROR_UNSUPPORTED_TRANSITION,
    ERROR_MALFORMED_INPUT,
)

# ---------------------------------------------------------------------------
# Result limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION = "AUTHORIZATION_IS_NOT_EXECUTION"
LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE = (
    "WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE"
)
LIMITATION_PARTIAL_WORKFLOW_SUPPORTED = "PARTIAL_WORKFLOW_SUPPORTED"
LIMITATION_UPSTREAM_REFERENCES_BOUNDED = "UPSTREAM_REFERENCES_BOUNDED"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_NO_LLM_INVOLVEMENT = "NO_LLM_INVOLVEMENT"
LIMITATION_LEARNING_NOT_AUTHORIZATION = "LEARNING_NOT_AUTHORIZATION"
LIMITATION_EXECUTION_GATE_ONLY = "EXECUTION_GATE_ONLY"
LIMITATION_SAFETY_BLOCKED = "SAFETY_BLOCKED"
LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL = (
    "HUMAN_DECISION_NOT_TRUTH_LABEL"
)
LIMITATION_PRIORITY_NOT_AUTHORIZATION = "PRIORITY_NOT_AUTHORIZATION"
LIMITATION_FINDING_NOT_CONFIRMATION = "FINDING_NOT_CONFIRMATION"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"

WORKFLOW_RESULT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION,
    LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE,
    LIMITATION_PARTIAL_WORKFLOW_SUPPORTED,
    LIMITATION_UPSTREAM_REFERENCES_BOUNDED,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_LEARNING_NOT_AUTHORIZATION,
    LIMITATION_EXECUTION_GATE_ONLY,
    LIMITATION_SAFETY_BLOCKED,
    LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL,
    LIMITATION_PRIORITY_NOT_AUTHORIZATION,
    LIMITATION_FINDING_NOT_CONFIRMATION,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
)

#: Base limitations carried by every result.
RESULT_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION,
    LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE,
    LIMITATION_PARTIAL_WORKFLOW_SUPPORTED,
    LIMITATION_UPSTREAM_REFERENCES_BOUNDED,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_LEARNING_NOT_AUTHORIZATION,
    LIMITATION_EXECUTION_GATE_ONLY,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

RESULT_ID_PREFIX = "wrr-"
RESULT_ID_RE = re.compile(r"^wrr-[0-9a-f]{16}$")

MAX_STAGES = len(WORKFLOW_STAGE_ORDER)
MAX_LIMITATIONS = 32
MAX_ERRORS = 16
MAX_LIST = 24
MAX_VALUE_LEN = 160
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_stage_types(value: object) -> list[str]:
    found = set()
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in WORKFLOW_STAGE_ORDER:
            found.add(text)
    return [stage for stage in WORKFLOW_STAGE_ORDER if stage in found]


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, WORKFLOW_RESULT_LIMITATIONS, MAX_LIMITATIONS
    )


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

REFERENCE_KINDS: tuple[str, ...] = (
    "SPECIALIST_RESULTS",
    "EVALUATION",
    "COLLABORATION",
    "FEEDBACK",
    "FINDING",
    "CORRELATION",
    "PRIORITIZATION",
    "HUMAN_DECISION",
    "LEARNING",
    "EXECUTION_CONTROL",
)


def sanitize_workflow_reference(value: object) -> dict:
    """Project one bounded upstream reference onto fixed keys."""

    if not isinstance(value, dict) or not value:
        return {
            "present": False,
            "reference_kind": "",
            "reference_id": "",
            "rule_version": "",
            "status": "",
            "item_count": 0,
            "research_only": True,
        }
    kind = _safe_text(value.get("reference_kind")).upper()
    if kind not in REFERENCE_KINDS:
        kind = ""
    return {
        "present": bool(value.get("present")) is True,
        "reference_kind": kind,
        "reference_id": _safe_text(value.get("reference_id")),
        "rule_version": _safe_text(value.get("rule_version")),
        "status": _safe_text(value.get("status")).upper(),
        "item_count": _bounded_int(value.get("item_count"), 0, 4096),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def sanitize_workflow_result_summary(value: object) -> dict:
    """Project the bounded workflow summary onto fixed keys."""

    if not isinstance(value, dict):
        return _default_summary()
    return {
        "stage_count": _bounded_int(value.get("stage_count"), 0, MAX_STAGES),
        "completed_stage_count": _bounded_int(
            value.get("completed_stage_count"), 0, MAX_STAGES
        ),
        "pending_stage_count": _bounded_int(
            value.get("pending_stage_count"), 0, MAX_STAGES
        ),
        "blocked_stage_count": _bounded_int(
            value.get("blocked_stage_count"), 0, MAX_STAGES
        ),
        "specialists_considered": _bounded_int(
            value.get("specialists_considered"), 0, 4096
        ),
        "specialists_completed": _bounded_int(
            value.get("specialists_completed"), 0, 4096
        ),
        "evaluation_count": _bounded_int(
            value.get("evaluation_count"), 0, 4096
        ),
        "finding_count": _bounded_int(value.get("finding_count"), 0, 4096),
        "correlated_finding_count": _bounded_int(
            value.get("correlated_finding_count"), 0, 4096
        ),
        "priority_band": _safe_text(value.get("priority_band")).upper(),
        "human_decision_status": _closed(
            value.get("human_decision_status"),
            HUMAN_DECISION_SUMMARY_STATUSES,
            HUMAN_STATUS_NOT_REQUESTED,
        ),
        "human_decision_type": _safe_text(
            value.get("human_decision_type")
        ).upper(),
        "learning_pattern_count": _bounded_int(
            value.get("learning_pattern_count"), 0, 4096
        ),
        "recommendation_count": _bounded_int(
            value.get("recommendation_count"), 0, 4096
        ),
        "execution_control_status": _safe_text(
            value.get("execution_control_status")
        ).upper(),
        "safety_status": _closed(
            value.get("safety_status"),
            WORKFLOW_SAFETY_STATUSES,
            SAFETY_STATUS_RESEARCH_ONLY,
        ),
        "workflow_state": _closed(
            value.get("workflow_state"), WORKFLOW_STATES, STATE_INITIALIZED
        ),
        "next_action": _safe_text(value.get("next_action")).upper(),
        "research_only": True,
    }


def _default_summary() -> dict:
    return {
        "stage_count": 0,
        "completed_stage_count": 0,
        "pending_stage_count": 0,
        "blocked_stage_count": 0,
        "specialists_considered": 0,
        "specialists_completed": 0,
        "evaluation_count": 0,
        "finding_count": 0,
        "correlated_finding_count": 0,
        "priority_band": "",
        "human_decision_status": HUMAN_STATUS_NOT_REQUESTED,
        "human_decision_type": "",
        "learning_pattern_count": 0,
        "recommendation_count": 0,
        "execution_control_status": "",
        "safety_status": SAFETY_STATUS_RESEARCH_ONLY,
        "workflow_state": STATE_INITIALIZED,
        "next_action": "",
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Provenance / errors / stages / next action projections
# ---------------------------------------------------------------------------


def sanitize_workflow_result_provenance(value: object) -> dict:
    """Project result provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION,
            "workflow_id": "",
            "request_rule_version": "",
            "stage_ids": [],
            "orchestration_id": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decision_rule_version": "",
            "learning_rule_version": "",
            "execution_control_rule_version": "",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    return {
        "rule_version": SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION,
        "workflow_id": _safe_text(value.get("workflow_id")),
        "request_rule_version": _safe_text(
            value.get("request_rule_version")
        ),
        "stage_ids": _bounded_strings(value.get("stage_ids"), MAX_STAGES, 40),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "learning_rule_version": _safe_text(
            value.get("learning_rule_version")
        ),
        "execution_control_rule_version": _safe_text(
            value.get("execution_control_rule_version")
        ),
        "source_stages": _bounded_strings(
            value.get("source_stages"), MAX_LIST, 60
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_workflow_error(value: object) -> dict:
    """Project one workflow error onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in WORKFLOW_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "stage_type": _safe_text(value.get("stage_type")).strip().upper()
        if _safe_text(value.get("stage_type")).strip().upper()
        in WORKFLOW_STAGE_ORDER
        else "",
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def _bounded_stages(value: object) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        try:
            projected = WorkflowStagePlan(**sanitize_workflow_stage(item))
        except (TypeError, ValueError):
            continue
        out.append(projected.model_dump(mode="json"))
        if len(out) >= MAX_STAGES:
            break
    return out


def sanitize_next_action_field(value: object) -> dict:
    """Project the embedded next-action recommendation."""

    if not isinstance(value, dict) or not value:
        return {}
    try:
        return WorkflowNextActionPlan(
            **sanitize_workflow_next_action(value)
        ).model_dump(mode="json")
    except (TypeError, ValueError):
        return {}


def sanitize_security_research_workflow_result(value: object) -> dict:
    """Project an R59 workflow result onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_result()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "result_id": _safe_text(value.get("result_id")),
        "workflow_id": _safe_text(value.get("workflow_id")),
        "workflow_state": _closed(
            value.get("workflow_state"),
            WORKFLOW_STATES,
            STATE_INVALID,
        ),
        "current_stage": _closed(
            value.get("current_stage"), WORKFLOW_STAGE_ORDER, ""
        ),
        "completed_stages": _ordered_stage_types(
            value.get("completed_stages")
        ),
        "pending_stages": _ordered_stage_types(value.get("pending_stages")),
        "blocked_stages": _ordered_stage_types(value.get("blocked_stages")),
        "stages": _bounded_stages(value.get("stages")),
        "next_action": sanitize_next_action_field(value.get("next_action")),
        "next_action_reason": _closed(
            value.get("next_action_reason"),
            WORKFLOW_NEXT_ACTION_REASONS,
            "UNKNOWN_REASON",
        ),
        "specialist_results_reference": sanitize_workflow_reference(
            value.get("specialist_results_reference")
        ),
        "evaluation_reference": sanitize_workflow_reference(
            value.get("evaluation_reference")
        ),
        "collaboration_reference": sanitize_workflow_reference(
            value.get("collaboration_reference")
        ),
        "feedback_reference": sanitize_workflow_reference(
            value.get("feedback_reference")
        ),
        "finding_reference": sanitize_workflow_reference(
            value.get("finding_reference")
        ),
        "correlation_reference": sanitize_workflow_reference(
            value.get("correlation_reference")
        ),
        "priority_reference": sanitize_workflow_reference(
            value.get("priority_reference")
        ),
        "human_decision_reference": sanitize_workflow_reference(
            value.get("human_decision_reference")
        ),
        "learning_reference": sanitize_workflow_reference(
            value.get("learning_reference")
        ),
        "execution_control_reference": sanitize_workflow_reference(
            value.get("execution_control_reference")
        ),
        "safety_status": _closed(
            value.get("safety_status"),
            WORKFLOW_SAFETY_STATUSES,
            SAFETY_STATUS_INVALID,
        ),
        "summary": sanitize_workflow_result_summary(value.get("summary")),
        "errors": [
            projected
            for projected in (
                sanitize_workflow_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "provenance": sanitize_workflow_result_provenance(
            value.get("provenance")
        ),
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
        "workflow_id": "",
        "workflow_state": STATE_INVALID,
        "current_stage": "",
        "completed_stages": [],
        "pending_stages": [],
        "blocked_stages": [],
        "stages": [],
        "next_action": {},
        "next_action_reason": "UNKNOWN_REASON",
        "specialist_results_reference": sanitize_workflow_reference(None),
        "evaluation_reference": sanitize_workflow_reference(None),
        "collaboration_reference": sanitize_workflow_reference(None),
        "feedback_reference": sanitize_workflow_reference(None),
        "finding_reference": sanitize_workflow_reference(None),
        "correlation_reference": sanitize_workflow_reference(None),
        "priority_reference": sanitize_workflow_reference(None),
        "human_decision_reference": sanitize_workflow_reference(None),
        "learning_reference": sanitize_workflow_reference(None),
        "execution_control_reference": sanitize_workflow_reference(None),
        "safety_status": SAFETY_STATUS_INVALID,
        "summary": _default_summary(),
        "errors": [],
        "governance": {},
        "provenance": sanitize_workflow_result_provenance(None),
        "limitations": list(RESULT_BASE_LIMITATIONS),
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


class SecurityResearchWorkflowResultPlan(BaseModel):
    """Deterministic R59 security research workflow result (R59.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION
    result_id: str
    workflow_id: str = ""
    workflow_state: str = STATE_INITIALIZED
    current_stage: str = ""
    completed_stages: list[str] = Field(default_factory=list)
    pending_stages: list[str] = Field(default_factory=list)
    blocked_stages: list[str] = Field(default_factory=list)
    stages: list[dict] = Field(default_factory=list)
    next_action: dict = Field(default_factory=dict)
    next_action_reason: str = "UNKNOWN_REASON"
    specialist_results_reference: dict = Field(default_factory=dict)
    evaluation_reference: dict = Field(default_factory=dict)
    collaboration_reference: dict = Field(default_factory=dict)
    feedback_reference: dict = Field(default_factory=dict)
    finding_reference: dict = Field(default_factory=dict)
    correlation_reference: dict = Field(default_factory=dict)
    priority_reference: dict = Field(default_factory=dict)
    human_decision_reference: dict = Field(default_factory=dict)
    learning_reference: dict = Field(default_factory=dict)
    execution_control_reference: dict = Field(default_factory=dict)
    safety_status: str = SAFETY_STATUS_RESEARCH_ONLY
    summary: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)
    governance: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
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
        return SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION

    @field_validator("result_id")
    @classmethod
    def _valid_result_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not RESULT_ID_RE.match(text):
            raise ValueError(f"malformed result_id: {value!r}")
        return text

    @field_validator("workflow_id")
    @classmethod
    def _bounded_workflow_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("workflow_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_STATES:
            raise ValueError(f"invalid workflow_state: {value!r}")
        return text

    @field_validator("current_stage")
    @classmethod
    def _valid_current_stage(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_STAGE_ORDER:
            raise ValueError(f"invalid current_stage: {value!r}")
        return text

    @field_validator("completed_stages", "pending_stages", "blocked_stages")
    @classmethod
    def _bounded_stage_types(cls, value: object) -> list[str]:
        return _ordered_stage_types(value)

    @field_validator("stages")
    @classmethod
    def _bounded_stage_list(cls, value: object) -> list[dict]:
        return _bounded_stages(value)

    @field_validator("next_action")
    @classmethod
    def _bounded_next_action(cls, value: object) -> dict:
        return sanitize_next_action_field(value)

    @field_validator("next_action_reason")
    @classmethod
    def _valid_action_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_NEXT_ACTION_REASONS:
            raise ValueError(f"invalid next_action_reason: {value!r}")
        return text

    @field_validator(
        "specialist_results_reference",
        "evaluation_reference",
        "collaboration_reference",
        "feedback_reference",
        "finding_reference",
        "correlation_reference",
        "priority_reference",
        "human_decision_reference",
        "learning_reference",
        "execution_control_reference",
    )
    @classmethod
    def _bounded_reference(cls, value: object) -> dict:
        return sanitize_workflow_reference(value)

    @field_validator("safety_status")
    @classmethod
    def _valid_safety_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_SAFETY_STATUSES:
            raise ValueError(f"invalid safety_status: {value!r}")
        return text

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_workflow_result_summary(value)

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_workflow_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_workflow_result_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("advisory", "human_authority_preserved", "research_only")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "workflow results are advisory and preserve human authority"
            )
        return True

    @field_validator("execution_performed", "external_executor_present")
    @classmethod
    def _never_executed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("the workflow never executes anything")
        return False

    @field_validator("vulnerability_confirmed", "exploit_authorized")
    @classmethod
    def _never_confirmed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "the workflow never confirms or authorizes exploitation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed_state(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("workflow results never confirm")
        return "NOT_CONFIRMED"

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("workflow results are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_state(self) -> "SecurityResearchWorkflowResultPlan":
        for forbidden in FORBIDDEN_STATES:
            if self.workflow_state == forbidden:
                raise ValueError(
                    "workflow states never imply execution or confirmation"
                )
        if self.workflow_state == STATE_BLOCKED:
            if not self.blocked_stages and not self.errors:
                raise ValueError(
                    "blocked workflows require a blocked stage or a reason"
                )
        if self.workflow_state == STATE_INVALID and not self.errors:
            raise ValueError("invalid workflows require structured errors")
        return self


def security_research_workflow_result_plan_projection(
    value: SecurityResearchWorkflowResultPlan,
) -> dict:
    """Serialize an R59 workflow result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_RESEARCH_WORKFLOW_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "STATE_INITIALIZED",
    "STATE_RESEARCH_READY",
    "STATE_SPECIALISTS_EVALUATED",
    "STATE_COLLABORATED",
    "STATE_FEEDBACK_ANALYZED",
    "STATE_FINDINGS_BUILT",
    "STATE_FINDINGS_CORRELATED",
    "STATE_PRIORITIZED",
    "STATE_AWAITING_HUMAN_DECISION",
    "STATE_HUMAN_DECIDED",
    "STATE_LEARNING_UPDATED",
    "STATE_EXECUTION_REVIEWED",
    "STATE_BLOCKED",
    "STATE_COMPLETED",
    "STATE_INVALID",
    "WORKFLOW_STATES",
    "FORBIDDEN_STATES",
    "SAFETY_STATUS_RESEARCH_ONLY",
    "SAFETY_STATUS_HUMAN_REVIEW_REQUIRED",
    "SAFETY_STATUS_EXECUTION_BLOCKED",
    "SAFETY_STATUS_SAFETY_BLOCKED",
    "SAFETY_STATUS_CONTROLLED_AUTHORIZATION",
    "SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR",
    "SAFETY_STATUS_INVALID",
    "WORKFLOW_SAFETY_STATUSES",
    "HUMAN_STATUS_NOT_REQUESTED",
    "HUMAN_STATUS_PENDING",
    "HUMAN_STATUS_DECIDED",
    "HUMAN_STATUS_BLOCKED",
    "HUMAN_STATUS_REVIEW_REQUIRED",
    "HUMAN_STATUS_CONFLICT",
    "HUMAN_DECISION_SUMMARY_STATUSES",
    "ERROR_INVALID_INPUT",
    "ERROR_MISSING_REQUIRED_STAGE",
    "ERROR_STAGE_ORDER_INVALID",
    "ERROR_UPSTREAM_RESULT_INVALID",
    "ERROR_RULE_VERSION_MISMATCH",
    "ERROR_HUMAN_DECISION_REQUIRED",
    "ERROR_EXECUTION_CONTROL_BLOCKED",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_LEARNING_REVIEW_REQUIRED",
    "ERROR_WORKFLOW_CONFLICT",
    "ERROR_UNSUPPORTED_TRANSITION",
    "ERROR_MALFORMED_INPUT",
    "WORKFLOW_ERROR_CATEGORIES",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_HUMAN_AUTHORITY_REQUIRED",
    "LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION",
    "LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE",
    "LIMITATION_PARTIAL_WORKFLOW_SUPPORTED",
    "LIMITATION_UPSTREAM_REFERENCES_BOUNDED",
    "LIMITATION_NO_WALL_CLOCK_METADATA",
    "LIMITATION_NO_LLM_INVOLVEMENT",
    "LIMITATION_LEARNING_NOT_AUTHORIZATION",
    "LIMITATION_EXECUTION_GATE_ONLY",
    "LIMITATION_SAFETY_BLOCKED",
    "LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL",
    "LIMITATION_PRIORITY_NOT_AUTHORIZATION",
    "LIMITATION_FINDING_NOT_CONFIRMATION",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "WORKFLOW_RESULT_LIMITATIONS",
    "RESULT_BASE_LIMITATIONS",
    "RESULT_ID_PREFIX",
    "RESULT_ID_RE",
    "MAX_STAGES",
    "MAX_LIMITATIONS",
    "MAX_ERRORS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "MAX_MESSAGE_LEN",
    "REFERENCE_KINDS",
    "sanitize_workflow_reference",
    "sanitize_workflow_result_summary",
    "sanitize_workflow_result_provenance",
    "sanitize_workflow_error",
    "sanitize_next_action_field",
    "sanitize_security_research_workflow_result",
    "SecurityResearchWorkflowResultPlan",
    "security_research_workflow_result_plan_projection",
]

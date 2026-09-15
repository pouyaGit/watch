"""Workflow stage schema (Stage R59.2).

Defines one bounded, deterministic stage of the R59 end-to-end security
research workflow. It answers:

    "Which stage of the research intelligence pipeline is represented, what
     structured input/output reference does it carry, and why is it in this
     state?"

Hard boundaries encoded here:

- Workflow metadata only: a stage records which upstream artifact exists and
  its bounded reference. It never executes anything, never confirms a
  vulnerability and never authorizes exploitation.
- No invented metadata: only deterministic metadata already supplied by
  upstream artifacts is projected (counts and closed status codes). No
  timestamps, durations, UUIDs, pids or randomness are generated.
- Closed vocabularies: stage types have a fixed order; stage statuses and
  reasons are closed sets.
- Bounded, privacy-safe, JSON serializable.

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

from ai.schemas.execution_control_result import SAFETY_RESULTS
from ai.schemas.human_decision import (
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_INVALID,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_TYPES,
)
from ai.schemas.research_priority import PRIORITY_BANDS

WORKFLOW_STAGE_RULE_VERSION = "r59-2"
RULE_VERSION = WORKFLOW_STAGE_RULE_VERSION

# ---------------------------------------------------------------------------
# Stage type vocabulary (closed; fixed order)
# ---------------------------------------------------------------------------

STAGE_SPECIALIST_RESEARCH = "SPECIALIST_RESEARCH"
STAGE_EVALUATION = "EVALUATION"
STAGE_COLLABORATION = "COLLABORATION"
STAGE_FEEDBACK = "FEEDBACK"
STAGE_FINDING = "FINDING"
STAGE_CORRELATION = "CORRELATION"
STAGE_PRIORITIZATION = "PRIORITIZATION"
STAGE_HUMAN_REVIEW = "HUMAN_REVIEW"
STAGE_LEARNING = "LEARNING"
STAGE_EXECUTION_CONTROL = "EXECUTION_CONTROL"

WORKFLOW_STAGE_ORDER: tuple[str, ...] = (
    STAGE_SPECIALIST_RESEARCH,
    STAGE_EVALUATION,
    STAGE_COLLABORATION,
    STAGE_FEEDBACK,
    STAGE_FINDING,
    STAGE_CORRELATION,
    STAGE_PRIORITIZATION,
    STAGE_HUMAN_REVIEW,
    STAGE_LEARNING,
    STAGE_EXECUTION_CONTROL,
)

# ---------------------------------------------------------------------------
# Stage status vocabulary (closed)
# ---------------------------------------------------------------------------

STAGE_STATUS_NOT_STARTED = "NOT_STARTED"
STAGE_STATUS_READY = "READY"
STAGE_STATUS_COMPLETED = "COMPLETED"
STAGE_STATUS_BLOCKED = "BLOCKED"
STAGE_STATUS_SKIPPED = "SKIPPED"
STAGE_STATUS_INVALID = "INVALID"

WORKFLOW_STAGE_STATUSES: tuple[str, ...] = (
    STAGE_STATUS_NOT_STARTED,
    STAGE_STATUS_READY,
    STAGE_STATUS_COMPLETED,
    STAGE_STATUS_BLOCKED,
    STAGE_STATUS_SKIPPED,
    STAGE_STATUS_INVALID,
)

# ---------------------------------------------------------------------------
# Stage reason vocabulary (closed)
# ---------------------------------------------------------------------------

REASON_RESEARCH_INPUT_PRESENT = "RESEARCH_INPUT_PRESENT"
REASON_SPECIALIST_RESULTS_PRESENT = "SPECIALIST_RESULTS_PRESENT"
REASON_EVALUATIONS_PRESENT = "EVALUATIONS_PRESENT"
REASON_COLLABORATION_PRESENT = "COLLABORATION_PRESENT"
REASON_FEEDBACK_PRESENT = "FEEDBACK_PRESENT"
REASON_FINDINGS_PRESENT = "FINDINGS_PRESENT"
REASON_NO_FINDINGS_PRODUCED = "NO_FINDINGS_PRODUCED"
REASON_CORRELATION_PRESENT = "CORRELATION_PRESENT"
REASON_PRIORITIZATION_PRESENT = "PRIORITIZATION_PRESENT"
REASON_HUMAN_REVIEW_PENDING = "HUMAN_REVIEW_PENDING"
REASON_HUMAN_DECIDED = "HUMAN_DECIDED"
REASON_HUMAN_DECISION_BLOCKS = "HUMAN_DECISION_BLOCKS"
REASON_HUMAN_ESCALATION_REQUIRED = "HUMAN_ESCALATION_REQUIRED"
REASON_LEARNING_PRESENT = "LEARNING_PRESENT"
REASON_LEARNING_REVIEW_REQUIRED = "LEARNING_REVIEW_REQUIRED"
REASON_EXECUTION_ALLOWED = "EXECUTION_ALLOWED"
REASON_EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
REASON_EXECUTION_READY = "EXECUTION_READY_FOR_EXTERNAL_EXECUTOR"
REASON_RECOMMENDED_NEXT_STAGE = "RECOMMENDED_NEXT_STAGE"
REASON_STAGE_COMPLETED_EXTERNALLY = "STAGE_COMPLETED_EXTERNALLY"
REASON_NOT_PROVIDED = "NOT_PROVIDED"
REASON_SKIPPED_BY_OPTION = "SKIPPED_BY_OPTION"
REASON_UPSTREAM_RESULT_INVALID = "UPSTREAM_RESULT_INVALID"
REASON_UNKNOWN = "UNKNOWN_REASON"

WORKFLOW_STAGE_REASONS: tuple[str, ...] = (
    REASON_RESEARCH_INPUT_PRESENT,
    REASON_SPECIALIST_RESULTS_PRESENT,
    REASON_EVALUATIONS_PRESENT,
    REASON_COLLABORATION_PRESENT,
    REASON_FEEDBACK_PRESENT,
    REASON_FINDINGS_PRESENT,
    REASON_NO_FINDINGS_PRODUCED,
    REASON_CORRELATION_PRESENT,
    REASON_PRIORITIZATION_PRESENT,
    REASON_HUMAN_REVIEW_PENDING,
    REASON_HUMAN_DECIDED,
    REASON_HUMAN_DECISION_BLOCKS,
    REASON_HUMAN_ESCALATION_REQUIRED,
    REASON_LEARNING_PRESENT,
    REASON_LEARNING_REVIEW_REQUIRED,
    REASON_EXECUTION_ALLOWED,
    REASON_EXECUTION_BLOCKED,
    REASON_EXECUTION_READY,
    REASON_RECOMMENDED_NEXT_STAGE,
    REASON_STAGE_COMPLETED_EXTERNALLY,
    REASON_NOT_PROVIDED,
    REASON_SKIPPED_BY_OPTION,
    REASON_UPSTREAM_RESULT_INVALID,
    REASON_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Stage limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_METADATA_FROM_UPSTREAM = "METADATA_FROM_UPSTREAM_ONLY"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_STAGE_REFERENCE_BOUNDED = "STAGE_REFERENCE_BOUNDED"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
LIMITATION_BLOCKED_PENDING_HUMAN = "BLOCKED_PENDING_HUMAN_REVIEW"
LIMITATION_STAGE_SKIPPED_BY_OPTION = "STAGE_SKIPPED_BY_OPTION"

WORKFLOW_STAGE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_METADATA_FROM_UPSTREAM,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_STAGE_REFERENCE_BOUNDED,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_BLOCKED_PENDING_HUMAN,
    LIMITATION_STAGE_SKIPPED_BY_OPTION,
)

#: Base limitations carried by every stage.
STAGE_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_METADATA_FROM_UPSTREAM,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_STAGE_REFERENCE_BOUNDED,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

STAGE_ID_PREFIX = "wfs-"
STAGE_ID_RE = re.compile(r"^wfs-[0-9a-f]{16}$")

MAX_LIMITATIONS = 16
MAX_METADATA = 24
MAX_REFERENCE_FIELDS = 8
MAX_VALUE_LEN = 160

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


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(codes, WORKFLOW_STAGE_LIMITATIONS, MAX_LIMITATIONS)


# ---------------------------------------------------------------------------
# Deterministic metadata (closed keys; upstream-supplied values only)
# ---------------------------------------------------------------------------

_METADATA_INT_KEYS: tuple[str, ...] = (
    "specialist_count",
    "evaluation_count",
    "participant_count",
    "conflict_count",
    "classification_count",
    "finding_count",
    "relationship_count",
    "cluster_count",
    "ranked_count",
    "deferred_count",
    "decided_count",
    "pending_count",
    "pattern_count",
    "recommendation_count",
    "blocking_recommendation_count",
    "review_count",
)

_METADATA_BOOL_KEYS: tuple[str, ...] = (
    "research_input_present",
    "decision_present",
    "decision_conflict",
    "decision_blocks",
    "review_required",
    "review_present",
    "execution_ready",
    "unsafe_claim",
    "contradiction",
)

_METADATA_CODE_KEYS: dict[str, tuple] = {
    "evaluation_safety_state": ("PASS", "DEGRADED", "FAILED", "UNKNOWN"),
    "decision_type": HUMAN_DECISION_TYPES,
    "decision_state": (
        DECISION_STATE_PENDING,
        DECISION_STATE_DECIDED,
        DECISION_STATE_EXPIRED,
        DECISION_STATE_INVALID,
    ),
    "priority_band": PRIORITY_BANDS,
    "safety_result": SAFETY_RESULTS,
    "finding_status": ("COMPLETED", "PARTIAL", "NO_FINDINGS", "FAILED"),
    "correlation_status": (
        "COMPLETED",
        "PARTIAL",
        "NO_RELATIONSHIPS",
        "FAILED",
    ),
    "prioritization_status": (
        "COMPLETED",
        "PARTIAL",
        "NO_FINDINGS",
        "FAILED",
    ),
}

_METADATA_BOUNDED_KEYS: tuple[str, ...] = (
    "control_outcome",
    "authorization_status",
    "execution_status",
    "learning_status",
)

#: The complete closed metadata key set.
WORKFLOW_STAGE_METADATA_KEYS: tuple[str, ...] = (
    _METADATA_INT_KEYS
    + _METADATA_BOOL_KEYS
    + tuple(_METADATA_CODE_KEYS)
    + _METADATA_BOUNDED_KEYS
)


def sanitize_stage_reference(value: object) -> dict:
    """Project a bounded stage input/output reference onto fixed keys."""

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
    return {
        "present": bool(value.get("present")) is True,
        "reference_kind": _safe_text(value.get("reference_kind")).upper(),
        "reference_id": _safe_text(value.get("reference_id")),
        "rule_version": _safe_text(value.get("rule_version")),
        "status": _safe_text(value.get("status")).upper(),
        "item_count": _bounded_int(value.get("item_count"), 0, 4096),
        "research_only": True,
    }


def sanitize_stage_metadata(value: object) -> dict:
    """Project upstream-supplied deterministic metadata onto closed keys.

    Only known keys are retained; ints are bounded, codes are validated and
    unknown values are dropped. No timestamp or clock-derived field exists.
    """

    if not isinstance(value, dict) or not value:
        return {}
    out: dict = {}
    for key in _METADATA_INT_KEYS:
        if key in value:
            out[key] = _bounded_int(value.get(key), 0, 4096)
    for key in _METADATA_BOOL_KEYS:
        if key in value:
            out[key] = bool(value.get(key)) is True
    for key, allowed in _METADATA_CODE_KEYS.items():
        if key in value:
            out[key] = _closed(value.get(key), allowed, "")
    for key in _METADATA_BOUNDED_KEYS:
        if key in value:
            out[key] = _safe_text(value.get(key)).upper()
    return out


def sanitize_stage_provenance(value: object) -> dict:
    """Project stage provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "workflow_id": "",
            "stage_rule_version": WORKFLOW_STAGE_RULE_VERSION,
            "upstream_rule_version": "",
            "upstream_reference_id": "",
            "deterministic": True,
            "research_only": True,
        }
    return {
        "workflow_id": _safe_text(value.get("workflow_id")),
        "stage_rule_version": WORKFLOW_STAGE_RULE_VERSION,
        "upstream_rule_version": _safe_text(
            value.get("upstream_rule_version")
        ),
        "upstream_reference_id": _safe_text(
            value.get("upstream_reference_id")
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_workflow_stage(value: object) -> dict:
    """Project one R59 workflow stage onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_stage()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "stage_id": _safe_text(value.get("stage_id")),
        "stage_type": _closed(
            value.get("stage_type"), WORKFLOW_STAGE_ORDER, ""
        ),
        "stage_status": _closed(
            value.get("stage_status"),
            WORKFLOW_STAGE_STATUSES,
            STAGE_STATUS_INVALID,
        ),
        "input_reference": sanitize_stage_reference(
            value.get("input_reference")
        ),
        "output_reference": sanitize_stage_reference(
            value.get("output_reference")
        ),
        "reason": _closed(
            value.get("reason"), WORKFLOW_STAGE_REASONS, REASON_UNKNOWN
        ),
        "deterministic_metadata": sanitize_stage_metadata(
            value.get("deterministic_metadata")
        ),
        "provenance": sanitize_stage_provenance(value.get("provenance")),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
        "execution_performed": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
    }


def _default_stage() -> dict:
    return {
        "rule_version": "",
        "stage_id": "",
        "stage_type": "",
        "stage_status": STAGE_STATUS_INVALID,
        "input_reference": sanitize_stage_reference(None),
        "output_reference": sanitize_stage_reference(None),
        "reason": REASON_NOT_PROVIDED,
        "deterministic_metadata": {},
        "provenance": sanitize_stage_provenance(None),
        "governance": {},
        "limitations": list(STAGE_BASE_LIMITATIONS),
        "research_only": True,
        "deterministic": True,
        "execution_performed": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class WorkflowStagePlan(BaseModel):
    """Deterministic R59 workflow stage (R59.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = WORKFLOW_STAGE_RULE_VERSION
    stage_id: str
    stage_type: str
    stage_status: str = STAGE_STATUS_NOT_STARTED
    input_reference: dict = Field(default_factory=dict)
    output_reference: dict = Field(default_factory=dict)
    reason: str = REASON_NOT_PROVIDED
    deterministic_metadata: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True
    execution_performed: bool = False
    vulnerability_confirmed: bool = False
    exploit_authorized: bool = False

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return WORKFLOW_STAGE_RULE_VERSION

    @field_validator("stage_id")
    @classmethod
    def _valid_stage_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not STAGE_ID_RE.match(text):
            raise ValueError(f"malformed stage_id: {value!r}")
        return text

    @field_validator("stage_type")
    @classmethod
    def _valid_stage_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_STAGE_ORDER:
            raise ValueError(f"invalid stage_type: {value!r}")
        return text

    @field_validator("stage_status")
    @classmethod
    def _valid_stage_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_STAGE_STATUSES:
            raise ValueError(f"invalid stage_status: {value!r}")
        return text

    @field_validator("input_reference", "output_reference")
    @classmethod
    def _bounded_reference(cls, value: object) -> dict:
        return sanitize_stage_reference(value)

    @field_validator("reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_STAGE_REASONS:
            raise ValueError(f"invalid stage reason: {value!r}")
        return text

    @field_validator("deterministic_metadata")
    @classmethod
    def _bounded_metadata(cls, value: object) -> dict:
        return sanitize_stage_metadata(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_stage_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("execution_performed")
    @classmethod
    def _never_executed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("workflow stages never execute")
        return False

    @field_validator("vulnerability_confirmed", "exploit_authorized")
    @classmethod
    def _never_confirmed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "workflow stages never confirm or authorize exploitation"
            )
        return False

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("workflow stages are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("workflow stages are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_status(self) -> "WorkflowStagePlan":
        if self.stage_status == STAGE_STATUS_SKIPPED and self.reason not in (
            REASON_SKIPPED_BY_OPTION,
            REASON_UNKNOWN,
        ):
            raise ValueError("skipped stages require a skip reason")
        if self.stage_status == STAGE_STATUS_INVALID and self.reason != (
            REASON_UPSTREAM_RESULT_INVALID
        ):
            raise ValueError("invalid stages require an invalid-stage reason")
        return self


def workflow_stage_plan_projection(value: WorkflowStagePlan) -> dict:
    """Serialize one R59 workflow stage to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "WORKFLOW_STAGE_RULE_VERSION",
    "RULE_VERSION",
    "STAGE_SPECIALIST_RESEARCH",
    "STAGE_EVALUATION",
    "STAGE_COLLABORATION",
    "STAGE_FEEDBACK",
    "STAGE_FINDING",
    "STAGE_CORRELATION",
    "STAGE_PRIORITIZATION",
    "STAGE_HUMAN_REVIEW",
    "STAGE_LEARNING",
    "STAGE_EXECUTION_CONTROL",
    "WORKFLOW_STAGE_ORDER",
    "STAGE_STATUS_NOT_STARTED",
    "STAGE_STATUS_READY",
    "STAGE_STATUS_COMPLETED",
    "STAGE_STATUS_BLOCKED",
    "STAGE_STATUS_SKIPPED",
    "STAGE_STATUS_INVALID",
    "WORKFLOW_STAGE_STATUSES",
    "REASON_RESEARCH_INPUT_PRESENT",
    "REASON_SPECIALIST_RESULTS_PRESENT",
    "REASON_EVALUATIONS_PRESENT",
    "REASON_COLLABORATION_PRESENT",
    "REASON_FEEDBACK_PRESENT",
    "REASON_FINDINGS_PRESENT",
    "REASON_NO_FINDINGS_PRODUCED",
    "REASON_CORRELATION_PRESENT",
    "REASON_PRIORITIZATION_PRESENT",
    "REASON_HUMAN_REVIEW_PENDING",
    "REASON_HUMAN_DECIDED",
    "REASON_HUMAN_DECISION_BLOCKS",
    "REASON_HUMAN_ESCALATION_REQUIRED",
    "REASON_LEARNING_PRESENT",
    "REASON_LEARNING_REVIEW_REQUIRED",
    "REASON_EXECUTION_ALLOWED",
    "REASON_EXECUTION_BLOCKED",
    "REASON_EXECUTION_READY",
    "REASON_RECOMMENDED_NEXT_STAGE",
    "REASON_STAGE_COMPLETED_EXTERNALLY",
    "REASON_NOT_PROVIDED",
    "REASON_SKIPPED_BY_OPTION",
    "REASON_UPSTREAM_RESULT_INVALID",
    "REASON_UNKNOWN",
    "WORKFLOW_STAGE_REASONS",
    "WORKFLOW_STAGE_LIMITATIONS",
    "STAGE_BASE_LIMITATIONS",
    "WORKFLOW_STAGE_METADATA_KEYS",
    "STAGE_ID_PREFIX",
    "STAGE_ID_RE",
    "MAX_LIMITATIONS",
    "MAX_METADATA",
    "MAX_VALUE_LEN",
    "sanitize_stage_reference",
    "sanitize_stage_metadata",
    "sanitize_stage_provenance",
    "sanitize_workflow_stage",
    "WorkflowStagePlan",
    "workflow_stage_plan_projection",
]

"""Controlled execution plan schema (Stage R58.3).

Defines the bounded, deterministic, *declarative* R58 controlled execution
plan. It answers:

    "If a future external executor were authorized, what would it be
     allowed to consider, in what order, under which preconditions, safety
     checks and stop conditions?"

Hard boundaries encoded here:

- Declarative only: the plan describes steps; it never executes them. Every
  step is forced ``execution_mode = DECLARATIVE_ONLY`` with
  ``performs_network_io = False`` and ``executes_commands = False``.
- No executor exists: ``execution_performed`` and
  ``external_executor_present`` are forced ``False`` and
  ``external_executor_state`` is forced ``ABSENT``. There is no ``EXECUTED``
  plan status in this architecture.
- Authorization-bound: a plan can only reach ``AUTHORIZED`` or
  ``READY_FOR_EXTERNAL_EXECUTOR`` through a valid R58.2 authorization whose
  action, target, scope and finding match the request exactly.
- No payloads: the plan vocabulary contains no exploit, attack, payload,
  command, scanner or browser step. Active testing, if ever needed, must be
  a separate future controlled capability.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs, pids or
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

from ai.schemas.controlled_execution_authorization import (
    AUTHORIZATION_STATUS_AUTHORIZED,
    EXECUTION_AUTHORIZATION_STATUSES,
)
from ai.schemas.execution_control_result import (
    EXECUTION_CONTROL_LIMITATIONS,
    MAX_LIMITATIONS,
)
from ai.schemas.execution_request import (
    ACTION_UNSPECIFIED,
    EXECUTION_ACTION_VALUES,
    SCOPE_KINDS,
    SCOPE_KIND_UNSPECIFIED,
    normalize_execution_scope,
    normalize_target_reference,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import sanitize_finding_governance

CONTROLLED_EXECUTION_PLAN_RULE_VERSION = "r58-3"
RULE_VERSION = CONTROLLED_EXECUTION_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Plan status vocabulary (closed; no EXECUTED state exists)
# ---------------------------------------------------------------------------

PLAN_STATUS_NOT_REQUESTED = "NOT_REQUESTED"
PLAN_STATUS_REQUESTED = "REQUESTED"
PLAN_STATUS_BLOCKED = "BLOCKED"
PLAN_STATUS_AUTHORIZED = "AUTHORIZED"
PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR = "READY_FOR_EXTERNAL_EXECUTOR"
PLAN_STATUS_EXPIRED = "EXPIRED"
PLAN_STATUS_INVALID = "INVALID"

CONTROLLED_EXECUTION_PLAN_STATUSES: tuple[str, ...] = (
    PLAN_STATUS_NOT_REQUESTED,
    PLAN_STATUS_REQUESTED,
    PLAN_STATUS_BLOCKED,
    PLAN_STATUS_AUTHORIZED,
    PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    PLAN_STATUS_EXPIRED,
    PLAN_STATUS_INVALID,
)

# ---------------------------------------------------------------------------
# Declarative step vocabulary (closed; safe research/control steps only)
# ---------------------------------------------------------------------------

STEP_LOAD_RECORDED_EVIDENCE = "LOAD_RECORDED_EVIDENCE"
STEP_REVIEW_STORED_RESPONSE = "REVIEW_STORED_RESPONSE"
STEP_CONFIRM_SCOPE_METADATA = "CONFIRM_SCOPE_METADATA"
STEP_RECONFIRM_CONTEXT_SUMMARY = "RECONFIRM_CONTEXT_SUMMARY"
STEP_PREPARE_RESEARCH_NOTE = "PREPARE_RESEARCH_NOTE"
STEP_REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"
STEP_VERIFY_HUMAN_AUTHORIZATION = "VERIFY_HUMAN_AUTHORIZATION"
STEP_ASSERT_SAFETY_CONSTRAINTS = "ASSERT_SAFETY_CONSTRAINTS"

EXECUTION_STEP_CODES: tuple[str, ...] = (
    STEP_LOAD_RECORDED_EVIDENCE,
    STEP_REVIEW_STORED_RESPONSE,
    STEP_CONFIRM_SCOPE_METADATA,
    STEP_RECONFIRM_CONTEXT_SUMMARY,
    STEP_PREPARE_RESEARCH_NOTE,
    STEP_REQUEST_HUMAN_REVIEW,
    STEP_VERIFY_HUMAN_AUTHORIZATION,
    STEP_ASSERT_SAFETY_CONSTRAINTS,
)

EXECUTION_MODE_DECLARATIVE = "DECLARATIVE_ONLY"
EXECUTION_MODES: tuple[str, ...] = (EXECUTION_MODE_DECLARATIVE,)

STEP_DESCRIPTIONS: dict[str, str] = {
    STEP_LOAD_RECORDED_EVIDENCE: (
        "Locate already-recorded research evidence for the finding; "
        "no collection is performed by R58."
    ),
    STEP_REVIEW_STORED_RESPONSE: (
        "Review an already-stored response artifact; R58 performs no "
        "I/O and sends no requests."
    ),
    STEP_CONFIRM_SCOPE_METADATA: (
        "Re-confirm the recorded scope metadata associated with the "
        "authorized scope; no scope expansion is permitted."
    ),
    STEP_RECONFIRM_CONTEXT_SUMMARY: (
        "Re-read the recorded context summary for the finding; no "
        "context is gathered from any target."
    ),
    STEP_PREPARE_RESEARCH_NOTE: (
        "Prepare a bounded research note describing the next research "
        "step; the note is not an executable instruction."
    ),
    STEP_REQUEST_HUMAN_REVIEW: (
        "Record a request for human review; no notification is sent by "
        "R58."
    ),
    STEP_VERIFY_HUMAN_AUTHORIZATION: (
        "Verify the explicit human authorization mirrors this action, "
        "target, scope and finding exactly."
    ),
    STEP_ASSERT_SAFETY_CONSTRAINTS: (
        "Assert the closed safety constraints (no network, no command, "
        "no payload, no exploit, no autonomy) remain in force."
    ),
}

# ---------------------------------------------------------------------------
# Precondition vocabulary (closed)
# ---------------------------------------------------------------------------

PRECONDITION_HUMAN_AUTHORIZATION = "HUMAN_AUTHORIZATION_VALID"
PRECONDITION_REQUEST_ELIGIBLE = "REQUEST_ELIGIBLE"
PRECONDITION_TARGET_MATCH = "TARGET_EXACT_MATCH"
PRECONDITION_SCOPE_MATCH = "SCOPE_EXACT_MATCH"
PRECONDITION_ACTION_MATCH = "ACTION_EXACT_MATCH"
PRECONDITION_SAFETY_PASS = "SAFETY_GATE_PASS"
PRECONDITION_EXTERNAL_EXECUTOR_ABSENT = "EXTERNAL_EXECUTOR_ABSENT"

EXECUTION_PLAN_PRECONDITIONS: tuple[str, ...] = (
    PRECONDITION_HUMAN_AUTHORIZATION,
    PRECONDITION_REQUEST_ELIGIBLE,
    PRECONDITION_ACTION_MATCH,
    PRECONDITION_TARGET_MATCH,
    PRECONDITION_SCOPE_MATCH,
    PRECONDITION_SAFETY_PASS,
    PRECONDITION_EXTERNAL_EXECUTOR_ABSENT,
)

# ---------------------------------------------------------------------------
# Safety check vocabulary (closed)
# ---------------------------------------------------------------------------

SAFETY_CHECK_NO_NETWORK_IO = "NO_NETWORK_IO"
SAFETY_CHECK_NO_COMMAND_EXECUTION = "NO_COMMAND_EXECUTION"
SAFETY_CHECK_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
SAFETY_CHECK_NO_EXPLOIT_AUTHORIZATION = "NO_EXPLOIT_AUTHORIZATION"
SAFETY_CHECK_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
SAFETY_CHECK_HUMAN_AUTHORITY_EXPLICIT = "HUMAN_AUTHORITY_EXPLICIT"
SAFETY_CHECK_SCOPE_EXACT = "SCOPE_EXACT_MATCH"
SAFETY_CHECK_TARGET_EXACT = "TARGET_EXACT_MATCH"
SAFETY_CHECK_NO_AUTONOMY = "NO_AUTONOMOUS_AUTHORIZATION"
SAFETY_CHECK_EXTERNAL_EXECUTOR_ABSENT = "EXTERNAL_EXECUTOR_ABSENT"

EXECUTION_SAFETY_CHECKS: tuple[str, ...] = (
    SAFETY_CHECK_NO_NETWORK_IO,
    SAFETY_CHECK_NO_COMMAND_EXECUTION,
    SAFETY_CHECK_NO_PAYLOAD_GENERATION,
    SAFETY_CHECK_NO_EXPLOIT_AUTHORIZATION,
    SAFETY_CHECK_NO_VULNERABILITY_CONFIRMATION,
    SAFETY_CHECK_HUMAN_AUTHORITY_EXPLICIT,
    SAFETY_CHECK_SCOPE_EXACT,
    SAFETY_CHECK_TARGET_EXACT,
    SAFETY_CHECK_NO_AUTONOMY,
    SAFETY_CHECK_EXTERNAL_EXECUTOR_ABSENT,
)

# ---------------------------------------------------------------------------
# Stop condition vocabulary (closed)
# ---------------------------------------------------------------------------

STOP_AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
STOP_SCOPE_CHANGED = "SCOPE_CHANGED"
STOP_TARGET_CHANGED = "TARGET_CHANGED"
STOP_ACTION_CHANGED = "ACTION_CHANGED"
STOP_FINDING_CHANGED = "FINDING_CHANGED"
STOP_SAFETY_BLOCK = "SAFETY_BLOCK"
STOP_HUMAN_ESCALATION = "HUMAN_ESCALATION"
STOP_VALIDITY_EXPIRED = "VALIDITY_EXPIRED"
STOP_UNEXPECTED_STATE = "UNEXPECTED_STATE"

EXECUTION_STOP_CONDITIONS: tuple[str, ...] = (
    STOP_AUTHORIZATION_REVOKED,
    STOP_SCOPE_CHANGED,
    STOP_TARGET_CHANGED,
    STOP_ACTION_CHANGED,
    STOP_FINDING_CHANGED,
    STOP_SAFETY_BLOCK,
    STOP_HUMAN_ESCALATION,
    STOP_VALIDITY_EXPIRED,
    STOP_UNEXPECTED_STATE,
)

# ---------------------------------------------------------------------------
# Rollback / abort vocabulary (closed)
# ---------------------------------------------------------------------------

ROLLBACK_REASON_NO_EXECUTION = "NO_EXECUTION_PERFORMED"
ROLLBACK_REASON_DECLARATIVE_ONLY = "DECLARATIVE_PLAN_ONLY"

ROLLBACK_REASONS: tuple[str, ...] = (
    ROLLBACK_REASON_NO_EXECUTION,
    ROLLBACK_REASON_DECLARATIVE_ONLY,
)

# ---------------------------------------------------------------------------
# External executor vocabulary (closed; none exists in R58)
# ---------------------------------------------------------------------------

EXTERNAL_EXECUTOR_ABSENT = "ABSENT"
EXTERNAL_EXECUTOR_STATES: tuple[str, ...] = (EXTERNAL_EXECUTOR_ABSENT,)

# ---------------------------------------------------------------------------
# Limitations (closed; shared gate vocabulary)
# ---------------------------------------------------------------------------

CONTROLLED_EXECUTION_PLAN_LIMITATIONS: tuple[str, ...] = (
    EXECUTION_CONTROL_LIMITATIONS
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

PLAN_ID_PREFIX = "exp-"
PLAN_ID_RE = re.compile(r"^exp-[0-9a-f]{16}$")

MAX_STEPS = len(EXECUTION_STEP_CODES) + 2
MAX_VALUE_LEN = 160
MAX_DESCRIPTION_LEN = 240

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
    return _ordered_codes(
        codes, CONTROLLED_EXECUTION_PLAN_LIMITATIONS, MAX_LIMITATIONS
    )


def sanitize_execution_step(value: object) -> dict:
    """Project one declarative plan step onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    step_code = _safe_text(value.get("step_code")).strip().upper()
    if step_code not in EXECUTION_STEP_CODES:
        return {}
    return {
        "step_index": _bounded_int(value.get("step_index"), 0, MAX_STEPS),
        "step_code": step_code,
        "execution_mode": EXECUTION_MODE_DECLARATIVE,
        "declarative": True,
        "requires_external_executor": False,
        "performs_network_io": False,
        "executes_commands": False,
        "description": _safe_text(
            value.get("description")
            or STEP_DESCRIPTIONS.get(step_code, ""),
            MAX_DESCRIPTION_LEN,
        ),
        "research_only": True,
    }


def sanitize_execution_steps(value: object) -> list[dict]:
    """Project the bounded ordered step list (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_execution_step(item)
        if projected and projected not in out:
            out.append(projected)
        if len(out) >= MAX_STEPS:
            break
    return out


def sanitize_target_scope(value: object) -> dict:
    """Project the exact execution target/scope reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "target_reference": "",
            "action_scope": "",
            "scope_kind": SCOPE_KIND_UNSPECIFIED,
            "wildcard": False,
            "expands_scope": False,
            "research_only": True,
        }
    return {
        "target_reference": normalize_target_reference(
            value.get("target_reference")
        ),
        "action_scope": normalize_execution_scope(value.get("action_scope")),
        "scope_kind": _closed(
            value.get("scope_kind"), SCOPE_KINDS, SCOPE_KIND_UNSPECIFIED
        ),
        "wildcard": bool(value.get("wildcard")) is True,
        "expands_scope": False,
        "research_only": True,
    }


def sanitize_authorization_reference(value: object) -> dict:
    """Project the bound authorization reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "authorization_id": "",
            "authorization_status": "",
            "decision_reference": "",
            "validity_state": "",
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True,
        "authorization_id": _safe_text(value.get("authorization_id")),
        "authorization_status": _closed(
            value.get("authorization_status"),
            EXECUTION_AUTHORIZATION_STATUSES + ("",),
            "",
        ),
        "decision_reference": _safe_text(value.get("decision_reference")),
        "validity_state": _safe_text(
            value.get("validity_state")
        ).strip().upper(),
        "research_only": True,
    }


def sanitize_rollback_metadata(value: object) -> dict:
    """Project abort/rollback metadata onto fixed keys.

    R58 executes nothing, so there is nothing to roll back; abort is always
    represented as supported declaratively.
    """

    if not isinstance(value, dict):
        return {
            "abort_supported": True,
            "rollback_supported": False,
            "rollback_reason": ROLLBACK_REASON_NO_EXECUTION,
            "reversible": False,
            "research_only": True,
        }
    return {
        "abort_supported": True,
        "rollback_supported": False,
        "rollback_reason": _closed(
            value.get("rollback_reason"),
            ROLLBACK_REASONS,
            ROLLBACK_REASON_NO_EXECUTION,
        ),
        "reversible": False,
        "research_only": True,
    }


def sanitize_plan_provenance(value: object) -> dict:
    """Project plan provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "request_rule_version": "",
            "authorization_rule_version": "",
            "finding_rule_version": "",
            "decision_rule_version": "",
            "learning_rule_version": "",
            "request_id": "",
            "authorization_id": "",
            "finding_id": "",
            "decision_id": "",
            "deterministic": True,
            "research_only": True,
        }
    return {
        "request_rule_version": _safe_text(
            value.get("request_rule_version")
        ),
        "authorization_rule_version": _safe_text(
            value.get("authorization_rule_version")
        ),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "learning_rule_version": _safe_text(
            value.get("learning_rule_version")
        ),
        "request_id": _safe_text(value.get("request_id")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "finding_id": _safe_text(value.get("finding_id")),
        "decision_id": _safe_text(value.get("decision_id")),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_controlled_execution_plan(value: object) -> dict:
    """Project an R58 controlled execution plan onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_plan()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "plan_id": _safe_text(value.get("plan_id")),
        "request_id": _safe_text(value.get("request_id")),
        "finding_id": finding_id,
        "action_type": _closed(
            value.get("action_type"),
            EXECUTION_ACTION_VALUES,
            ACTION_UNSPECIFIED,
        ),
        "action_scope": normalize_execution_scope(value.get("action_scope")),
        "target_reference": normalize_target_reference(
            value.get("target_reference")
        ),
        "ordered_steps": sanitize_execution_steps(
            value.get("ordered_steps")
        ),
        "target_scope": sanitize_target_scope(value.get("target_scope")),
        "preconditions": _ordered_codes(
            value.get("preconditions"),
            EXECUTION_PLAN_PRECONDITIONS,
            len(EXECUTION_PLAN_PRECONDITIONS),
        ),
        "authorization_reference": sanitize_authorization_reference(
            value.get("authorization_reference")
        ),
        "safety_checks": _ordered_codes(
            value.get("safety_checks"),
            EXECUTION_SAFETY_CHECKS,
            len(EXECUTION_SAFETY_CHECKS),
        ),
        "stop_conditions": _ordered_codes(
            value.get("stop_conditions"),
            EXECUTION_STOP_CONDITIONS,
            len(EXECUTION_STOP_CONDITIONS),
        ),
        "rollback": sanitize_rollback_metadata(value.get("rollback")),
        "provenance": sanitize_plan_provenance(value.get("provenance")),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "execution_status": _closed(
            value.get("execution_status"),
            CONTROLLED_EXECUTION_PLAN_STATUSES,
            PLAN_STATUS_INVALID,
        ),
        "execution_performed": False,
        "external_executor_present": False,
        "external_executor_state": EXTERNAL_EXECUTOR_ABSENT,
        "plan_declarative": True,
        "research_only": True,
        "deterministic": True,
    }


def _default_plan() -> dict:
    return {
        "rule_version": "",
        "plan_id": "",
        "request_id": "",
        "finding_id": "",
        "action_type": ACTION_UNSPECIFIED,
        "action_scope": "",
        "target_reference": "",
        "ordered_steps": [],
        "target_scope": sanitize_target_scope(None),
        "preconditions": [],
        "authorization_reference": sanitize_authorization_reference(None),
        "safety_checks": [],
        "stop_conditions": [],
        "rollback": sanitize_rollback_metadata(None),
        "provenance": sanitize_plan_provenance(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "execution_status": PLAN_STATUS_NOT_REQUESTED,
        "execution_performed": False,
        "external_executor_present": False,
        "external_executor_state": EXTERNAL_EXECUTOR_ABSENT,
        "plan_declarative": True,
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ControlledExecutionPlan(BaseModel):
    """Deterministic declarative R58 controlled execution plan (R58.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CONTROLLED_EXECUTION_PLAN_RULE_VERSION
    plan_id: str
    request_id: str = ""
    finding_id: str = ""
    action_type: str = ACTION_UNSPECIFIED
    action_scope: str = ""
    target_reference: str = ""
    ordered_steps: list[dict] = Field(default_factory=list)
    target_scope: dict = Field(default_factory=dict)
    preconditions: list[str] = Field(default_factory=list)
    authorization_reference: dict = Field(default_factory=dict)
    safety_checks: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    rollback: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    execution_status: str = PLAN_STATUS_NOT_REQUESTED
    execution_performed: bool = False
    external_executor_present: bool = False
    external_executor_state: str = EXTERNAL_EXECUTOR_ABSENT
    plan_declarative: bool = True
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CONTROLLED_EXECUTION_PLAN_RULE_VERSION

    @field_validator("plan_id")
    @classmethod
    def _valid_plan_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not PLAN_ID_RE.match(text):
            raise ValueError(f"malformed plan_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("action_type")
    @classmethod
    def _valid_action(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_ACTION_VALUES:
            raise ValueError(f"invalid action_type: {value!r}")
        return text

    @field_validator("ordered_steps")
    @classmethod
    def _bounded_steps(cls, value: object) -> list[dict]:
        return sanitize_execution_steps(value)

    @field_validator("target_scope")
    @classmethod
    def _bounded_target_scope(cls, value: object) -> dict:
        return sanitize_target_scope(value)

    @field_validator("preconditions")
    @classmethod
    def _bounded_preconditions(cls, value: object) -> list[str]:
        return _ordered_codes(
            value,
            EXECUTION_PLAN_PRECONDITIONS,
            len(EXECUTION_PLAN_PRECONDITIONS),
        )

    @field_validator("authorization_reference")
    @classmethod
    def _bounded_authorization_reference(cls, value: object) -> dict:
        return sanitize_authorization_reference(value)

    @field_validator("safety_checks")
    @classmethod
    def _bounded_safety_checks(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, EXECUTION_SAFETY_CHECKS, len(EXECUTION_SAFETY_CHECKS)
        )

    @field_validator("stop_conditions")
    @classmethod
    def _bounded_stop_conditions(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, EXECUTION_STOP_CONDITIONS, len(EXECUTION_STOP_CONDITIONS)
        )

    @field_validator("rollback")
    @classmethod
    def _bounded_rollback(cls, value: object) -> dict:
        return sanitize_rollback_metadata(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_plan_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("execution_status")
    @classmethod
    def _valid_execution_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTROLLED_EXECUTION_PLAN_STATUSES:
            raise ValueError(f"invalid execution_status: {value!r}")
        return text

    @field_validator("execution_performed")
    @classmethod
    def _never_executed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("controlled execution plans never execute")
        return False

    @field_validator("external_executor_present")
    @classmethod
    def _no_external_executor(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("no external executor exists in R58")
        return False

    @field_validator("external_executor_state")
    @classmethod
    def _external_executor_absent(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXTERNAL_EXECUTOR_STATES:
            raise ValueError("the external executor state must be ABSENT")
        return EXTERNAL_EXECUTOR_ABSENT

    @field_validator("plan_declarative")
    @classmethod
    def _declarative_only(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("controlled execution plans are declarative")
        return True

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("controlled execution plans are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("controlled execution plans are deterministic")
        return True

    @model_validator(mode="after")
    def _ready_requires_authorization(self) -> "ControlledExecutionPlan":
        if self.execution_status == PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR:
            reference = self.authorization_reference
            if not reference.get("authorization_id"):
                raise ValueError(
                    "ready plans require a bound authorization"
                )
            if (
                reference.get("authorization_status")
                != AUTHORIZATION_STATUS_AUTHORIZED
            ):
                raise ValueError(
                    "ready plans require an authorized authorization"
                )
        return self


def controlled_execution_plan_projection(
    value: ControlledExecutionPlan,
) -> dict:
    """Serialize an R58 plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CONTROLLED_EXECUTION_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "PLAN_STATUS_NOT_REQUESTED",
    "PLAN_STATUS_REQUESTED",
    "PLAN_STATUS_BLOCKED",
    "PLAN_STATUS_AUTHORIZED",
    "PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR",
    "PLAN_STATUS_EXPIRED",
    "PLAN_STATUS_INVALID",
    "CONTROLLED_EXECUTION_PLAN_STATUSES",
    "STEP_LOAD_RECORDED_EVIDENCE",
    "STEP_REVIEW_STORED_RESPONSE",
    "STEP_CONFIRM_SCOPE_METADATA",
    "STEP_RECONFIRM_CONTEXT_SUMMARY",
    "STEP_PREPARE_RESEARCH_NOTE",
    "STEP_REQUEST_HUMAN_REVIEW",
    "STEP_VERIFY_HUMAN_AUTHORIZATION",
    "STEP_ASSERT_SAFETY_CONSTRAINTS",
    "EXECUTION_STEP_CODES",
    "EXECUTION_MODE_DECLARATIVE",
    "EXECUTION_MODES",
    "STEP_DESCRIPTIONS",
    "PRECONDITION_HUMAN_AUTHORIZATION",
    "PRECONDITION_REQUEST_ELIGIBLE",
    "PRECONDITION_TARGET_MATCH",
    "PRECONDITION_SCOPE_MATCH",
    "PRECONDITION_ACTION_MATCH",
    "PRECONDITION_SAFETY_PASS",
    "PRECONDITION_EXTERNAL_EXECUTOR_ABSENT",
    "EXECUTION_PLAN_PRECONDITIONS",
    "SAFETY_CHECK_NO_NETWORK_IO",
    "SAFETY_CHECK_NO_COMMAND_EXECUTION",
    "SAFETY_CHECK_NO_PAYLOAD_GENERATION",
    "SAFETY_CHECK_NO_EXPLOIT_AUTHORIZATION",
    "SAFETY_CHECK_NO_VULNERABILITY_CONFIRMATION",
    "SAFETY_CHECK_HUMAN_AUTHORITY_EXPLICIT",
    "SAFETY_CHECK_SCOPE_EXACT",
    "SAFETY_CHECK_TARGET_EXACT",
    "SAFETY_CHECK_NO_AUTONOMY",
    "SAFETY_CHECK_EXTERNAL_EXECUTOR_ABSENT",
    "EXECUTION_SAFETY_CHECKS",
    "STOP_AUTHORIZATION_REVOKED",
    "STOP_SCOPE_CHANGED",
    "STOP_TARGET_CHANGED",
    "STOP_ACTION_CHANGED",
    "STOP_FINDING_CHANGED",
    "STOP_SAFETY_BLOCK",
    "STOP_HUMAN_ESCALATION",
    "STOP_VALIDITY_EXPIRED",
    "STOP_UNEXPECTED_STATE",
    "EXECUTION_STOP_CONDITIONS",
    "ROLLBACK_REASON_NO_EXECUTION",
    "ROLLBACK_REASON_DECLARATIVE_ONLY",
    "ROLLBACK_REASONS",
    "EXTERNAL_EXECUTOR_ABSENT",
    "EXTERNAL_EXECUTOR_STATES",
    "CONTROLLED_EXECUTION_PLAN_LIMITATIONS",
    "PLAN_ID_PREFIX",
    "PLAN_ID_RE",
    "MAX_STEPS",
    "MAX_VALUE_LEN",
    "MAX_DESCRIPTION_LEN",
    "sanitize_execution_step",
    "sanitize_execution_steps",
    "sanitize_target_scope",
    "sanitize_authorization_reference",
    "sanitize_rollback_metadata",
    "sanitize_plan_provenance",
    "sanitize_controlled_execution_plan",
    "ControlledExecutionPlan",
    "controlled_execution_plan_projection",
]

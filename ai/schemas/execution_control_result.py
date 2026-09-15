"""Execution control result schema (Stage R58.4).

Defines the deterministic R58 controlled-execution result produced by the
execution-control gate. It answers:

    "Is a proposed action structurally eligible to enter a controlled
     execution workflow, under explicit human authorization and safety
     constraints?"

Hard boundaries encoded here:

- Gate only, never executor: the result records an authorization/safety
  *decision*. ``execution_performed`` and ``external_executor_present`` are
  forced ``False`` and no ``EXECUTED`` state exists in this architecture.
- Human authority only: ``execution_authorized`` may be ``True`` only when an
  explicit human authorization matched the request exactly. AI-originated,
  autonomous or bypassed authorization is rejected and recorded as a
  structured block reason.
- Fail closed: missing, ambiguous, mis-matched or expired authorization is
  denied; unsafe execution claims are denied with closed reason codes and are
  never downgraded into safe requests.
- Priority, findings, correlation and learning are context only: they can
  never authorize execution, and ``vulnerability_confirmed`` /
  ``exploit_authorized`` are forced ``False`` with
  ``confirmation_state = NOT_CONFIRMED``.
- Auditability: request, finding, decision, authorization, action, target,
  scope, safety result and allow/block reasons are preserved.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs, pids,
  randomness or wall-clock behavior.

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

from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.research_audit_event import AUDIT_STATES, AUDIT_UNKNOWN

EXECUTION_CONTROL_RESULT_RULE_VERSION = "r58-4"
RULE_VERSION = EXECUTION_CONTROL_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Safety result vocabulary (closed)
# ---------------------------------------------------------------------------

SAFETY_PASS = "PASS"
SAFETY_BLOCKED = "BLOCKED"
SAFETY_INVALID = "INVALID"
SAFETY_UNKNOWN = "UNKNOWN"

SAFETY_RESULTS: tuple[str, ...] = (
    SAFETY_PASS,
    SAFETY_BLOCKED,
    SAFETY_INVALID,
    SAFETY_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Control status / outcome vocabulary (closed; no EXECUTED state exists)
# ---------------------------------------------------------------------------

CONTROL_STATUS_COMPLETED = "COMPLETED"
CONTROL_STATUS_BLOCKED = "BLOCKED"
CONTROL_STATUS_NOT_REQUESTED = "NOT_REQUESTED"
CONTROL_STATUS_INVALID = "INVALID"
CONTROL_STATUS_FAILED = "FAILED"

EXECUTION_CONTROL_STATUSES: tuple[str, ...] = (
    CONTROL_STATUS_COMPLETED,
    CONTROL_STATUS_BLOCKED,
    CONTROL_STATUS_NOT_REQUESTED,
    CONTROL_STATUS_INVALID,
    CONTROL_STATUS_FAILED,
)

CONTROL_OUTCOME_ALLOW = "ALLOW"
CONTROL_OUTCOME_DENY = "DENY"
CONTROL_OUTCOME_NOT_REQUESTED = "NOT_REQUESTED"
CONTROL_OUTCOME_INVALID = "INVALID"

CONTROL_OUTCOMES: tuple[str, ...] = (
    CONTROL_OUTCOME_ALLOW,
    CONTROL_OUTCOME_DENY,
    CONTROL_OUTCOME_NOT_REQUESTED,
    CONTROL_OUTCOME_INVALID,
)

# ---------------------------------------------------------------------------
# Safety gate rejection reasons (closed)
# ---------------------------------------------------------------------------

SAFETY_REASON_EXPLOIT_AUTHORIZATION = "EXPLOIT_AUTHORIZATION_REJECTED"
SAFETY_REASON_VULNERABILITY_CONFIRMATION = (
    "VULNERABILITY_CONFIRMATION_REJECTED"
)
SAFETY_REASON_PAYLOAD_GENERATION = "PAYLOAD_GENERATION_REJECTED"
SAFETY_REASON_ATTACK_PLANNING = "ATTACK_PLANNING_REJECTED"
SAFETY_REASON_COMMAND_EXECUTION = "COMMAND_EXECUTION_REJECTED"
SAFETY_REASON_CODE_EXECUTION = "ARBITRARY_CODE_EXECUTION_REJECTED"
SAFETY_REASON_NETWORK_EXECUTION = "NETWORK_EXECUTION_REJECTED"
SAFETY_REASON_SCANNER_EXECUTION = "SCANNER_EXECUTION_REJECTED"
SAFETY_REASON_BROWSER_AUTOMATION = "BROWSER_AUTOMATION_REJECTED"
SAFETY_REASON_SUBPROCESS_EXECUTION = "SUBPROCESS_EXECUTION_REJECTED"
SAFETY_REASON_AUTONOMOUS_AUTHORIZATION = "AUTONOMOUS_AUTHORIZATION_REJECTED"
SAFETY_REASON_POLICY_BYPASS = "POLICY_BYPASS_REJECTED"
SAFETY_REASON_HUMAN_APPROVAL_BYPASS = "HUMAN_APPROVAL_BYPASS_REJECTED"
SAFETY_REASON_UNSAFE_ACTION = "UNSAFE_ACTION_REJECTED"
SAFETY_REASON_UNSAFE_INPUT = "UNSAFE_INPUT_MARKER_REJECTED"
SAFETY_REASON_MALFORMED_INPUT = "MALFORMED_INPUT_REJECTED"
SAFETY_REASON_AMBIGUOUS_INPUT = "AMBIGUOUS_INPUT_REJECTED"

SAFETY_REJECTION_REASONS: tuple[str, ...] = (
    SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    SAFETY_REASON_VULNERABILITY_CONFIRMATION,
    SAFETY_REASON_PAYLOAD_GENERATION,
    SAFETY_REASON_ATTACK_PLANNING,
    SAFETY_REASON_COMMAND_EXECUTION,
    SAFETY_REASON_CODE_EXECUTION,
    SAFETY_REASON_NETWORK_EXECUTION,
    SAFETY_REASON_SCANNER_EXECUTION,
    SAFETY_REASON_BROWSER_AUTOMATION,
    SAFETY_REASON_SUBPROCESS_EXECUTION,
    SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    SAFETY_REASON_POLICY_BYPASS,
    SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    SAFETY_REASON_UNSAFE_ACTION,
    SAFETY_REASON_UNSAFE_INPUT,
    SAFETY_REASON_MALFORMED_INPUT,
    SAFETY_REASON_AMBIGUOUS_INPUT,
)

# ---------------------------------------------------------------------------
# Authorization rejection reasons (closed; shared gate vocabulary)
# ---------------------------------------------------------------------------

REASON_AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
REASON_HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"
REASON_HUMAN_DECISION_PENDING = "HUMAN_DECISION_PENDING"
REASON_AI_AUTHORIZATION_REJECTED = "AI_AUTHORIZATION_REJECTED"
REASON_AUTHORIZATION_AMBIGUOUS = "AUTHORIZATION_AMBIGUOUS"
REASON_ACTION_MISMATCH = "ACTION_MISMATCH"
REASON_TARGET_MISMATCH = "TARGET_MISMATCH"
REASON_SCOPE_MISMATCH = "SCOPE_MISMATCH"
REASON_FINDING_MISMATCH = "FINDING_MISMATCH"
REASON_DECISION_MISMATCH = "DECISION_MISMATCH"
REASON_DECISION_DOES_NOT_AUTHORIZE = "DECISION_DOES_NOT_AUTHORIZE"
REASON_ESCALATION_REVIEW_REQUIRED = "ESCALATION_REVIEW_REQUIRED"
REASON_AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
REASON_AUTHORIZATION_INVALID = "AUTHORIZATION_INVALID"
REASON_EXECUTION_NOT_REQUESTED = "EXECUTION_NOT_REQUESTED"
REASON_REQUEST_INVALID = "REQUEST_INVALID"
REASON_UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION_NOT_ALLOWED"
REASON_WILDCARD_SCOPE = "WILDCARD_SCOPE_NOT_ALLOWED"
REASON_R57_RECOMMENDATION_REVIEW = "R57_RECOMMENDATION_REQUIRES_REVIEW"
REASON_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
REASON_INVALID_INPUT = "INVALID_INPUT"
REASON_MALFORMED_INPUT = "MALFORMED_INPUT"
REASON_UNKNOWN = "UNKNOWN_REASON"

EXECUTION_AUTHORIZATION_REJECTION_REASONS: tuple[str, ...] = (
    REASON_AUTHORIZATION_MISSING,
    REASON_HUMAN_DECISION_REQUIRED,
    REASON_HUMAN_DECISION_PENDING,
    REASON_AI_AUTHORIZATION_REJECTED,
    REASON_AUTHORIZATION_AMBIGUOUS,
    REASON_ACTION_MISMATCH,
    REASON_TARGET_MISMATCH,
    REASON_SCOPE_MISMATCH,
    REASON_FINDING_MISMATCH,
    REASON_DECISION_MISMATCH,
    REASON_DECISION_DOES_NOT_AUTHORIZE,
    REASON_ESCALATION_REVIEW_REQUIRED,
    REASON_AUTHORIZATION_EXPIRED,
    REASON_AUTHORIZATION_INVALID,
    REASON_EXECUTION_NOT_REQUESTED,
    REASON_REQUEST_INVALID,
    REASON_UNSUPPORTED_ACTION,
    REASON_WILDCARD_SCOPE,
    REASON_R57_RECOMMENDATION_REVIEW,
    REASON_RULE_VERSION_MISMATCH,
    REASON_INVALID_INPUT,
    REASON_MALFORMED_INPUT,
    REASON_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Allow reasons (closed)
# ---------------------------------------------------------------------------

ALLOW_REASON_HUMAN_AUTHORITY = "HUMAN_AUTHORITY_EXPLICIT"
ALLOW_REASON_DECISION_APPROVES_RESEARCH = "DECISION_APPROVE_RESEARCH"
ALLOW_REASON_ACTION_MATCH = "ACTION_MATCH"
ALLOW_REASON_TARGET_MATCH = "TARGET_MATCH"
ALLOW_REASON_SCOPE_MATCH = "SCOPE_MATCH"
ALLOW_REASON_FINDING_MATCH = "FINDING_MATCH"
ALLOW_REASON_DECISION_MATCH = "DECISION_MATCH"
ALLOW_REASON_VALIDITY_VALID = "VALIDITY_VALID"
ALLOW_REASON_SAFETY_GATE_PASS = "SAFETY_GATE_PASS"

EXECUTION_ALLOW_REASONS: tuple[str, ...] = (
    ALLOW_REASON_HUMAN_AUTHORITY,
    ALLOW_REASON_DECISION_APPROVES_RESEARCH,
    ALLOW_REASON_ACTION_MATCH,
    ALLOW_REASON_TARGET_MATCH,
    ALLOW_REASON_SCOPE_MATCH,
    ALLOW_REASON_FINDING_MATCH,
    ALLOW_REASON_DECISION_MATCH,
    ALLOW_REASON_VALIDITY_VALID,
    ALLOW_REASON_SAFETY_GATE_PASS,
)

#: Every closed reason that may appear in ``block_reasons`` / ``allow_reasons``.
EXECUTION_OUTCOME_REASONS: tuple[str, ...] = (
    EXECUTION_ALLOW_REASONS + EXECUTION_AUTHORIZATION_REJECTION_REASONS
    + SAFETY_REJECTION_REASONS
)

# ---------------------------------------------------------------------------
# Error vocabulary (closed)
# ---------------------------------------------------------------------------

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_INPUT = "MALFORMED_INPUT"
ERROR_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_AUTHORIZATION_BLOCKED = "AUTHORIZATION_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

EXECUTION_CONTROL_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    ERROR_AUTHORIZATION_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_GATE_ONLY_NOT_EXECUTOR = "CONTROL_GATE_ONLY_NOT_EXECUTOR"
LIMITATION_DECLARATIVE_ONLY = "DECLARATIVE_ONLY"
LIMITATION_EXTERNAL_EXECUTOR_ABSENT = "EXTERNAL_EXECUTOR_ABSENT"
LIMITATION_FUTURE_EXECUTION_LAYER_REQUIRED = (
    "FUTURE_EXECUTION_LAYER_REQUIRED"
)
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION = (
    "AUTHORIZATION_IS_NOT_EXECUTION"
)
LIMITATION_HUMAN_APPROVAL_IS_NOT_EXECUTION = (
    "HUMAN_APPROVAL_IS_NOT_EXECUTION"
)
LIMITATION_PRIORITY_NOT_AUTHORIZATION = "PRIORITY_NOT_AUTHORIZATION"
LIMITATION_FINDING_NOT_CONFIRMATION = "FINDING_NOT_CONFIRMATION"
LIMITATION_CORRELATION_NOT_AUTHORIZATION = "CORRELATION_NOT_AUTHORIZATION"
LIMITATION_LEARNING_NOT_AUTHORIZATION = "LEARNING_NOT_AUTHORIZATION"
LIMITATION_DECISION_DOES_NOT_AUTHORIZE_ACTION = (
    "DECISION_DOES_NOT_AUTHORIZE_ACTION"
)
LIMITATION_SCOPE_NOT_EXPANDABLE = "SCOPE_NOT_EXPANDABLE"
LIMITATION_ACTION_NOT_TRANSFERABLE = "ACTION_NOT_TRANSFERABLE"
LIMITATION_TARGET_NOT_TRANSFERABLE = "TARGET_NOT_TRANSFERABLE"
LIMITATION_VALIDITY_EXPLICIT_ONLY = "VALIDITY_EXPLICIT_ONLY"
LIMITATION_SAFETY_BLOCKED = "SAFETY_BLOCKED"
LIMITATION_AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
LIMITATION_PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED = (
    "PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED"
)
LIMITATION_ATTACK_PLANNING_NOT_AUTHORIZED = (
    "ATTACK_PLANNING_NOT_AUTHORIZED"
)
LIMITATION_AUTONOMOUS_EXECUTION_NOT_AUTHORIZED = (
    "AUTONOMOUS_EXECUTION_NOT_AUTHORIZED"
)
LIMITATION_NO_LLM_INVOLVEMENT = "NO_LLM_INVOLVEMENT"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
LIMITATION_AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
LIMITATION_PLAN_NOT_READY = "PLAN_NOT_READY_FOR_EXTERNAL_EXECUTOR"

EXECUTION_CONTROL_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_GATE_ONLY_NOT_EXECUTOR,
    LIMITATION_DECLARATIVE_ONLY,
    LIMITATION_EXTERNAL_EXECUTOR_ABSENT,
    LIMITATION_FUTURE_EXECUTION_LAYER_REQUIRED,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION,
    LIMITATION_HUMAN_APPROVAL_IS_NOT_EXECUTION,
    LIMITATION_PRIORITY_NOT_AUTHORIZATION,
    LIMITATION_FINDING_NOT_CONFIRMATION,
    LIMITATION_CORRELATION_NOT_AUTHORIZATION,
    LIMITATION_LEARNING_NOT_AUTHORIZATION,
    LIMITATION_DECISION_DOES_NOT_AUTHORIZE_ACTION,
    LIMITATION_SCOPE_NOT_EXPANDABLE,
    LIMITATION_ACTION_NOT_TRANSFERABLE,
    LIMITATION_TARGET_NOT_TRANSFERABLE,
    LIMITATION_VALIDITY_EXPLICIT_ONLY,
    LIMITATION_SAFETY_BLOCKED,
    LIMITATION_AUTHORIZATION_MISSING,
    LIMITATION_PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED,
    LIMITATION_ATTACK_PLANNING_NOT_AUTHORIZED,
    LIMITATION_AUTONOMOUS_EXECUTION_NOT_AUTHORIZED,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_AUTHORIZATION_EXPIRED,
    LIMITATION_PLAN_NOT_READY,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

CONTROL_ID_PREFIX = "exc-"
CONTROL_ID_RE = re.compile(r"^exc-[0-9a-f]{16}$")
AUDIT_ID_PREFIX = "exd-"
AUDIT_ID_RE = re.compile(r"^exd-[0-9a-f]{16}$")

MAX_REASONS = 32
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


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, EXECUTION_OUTCOME_REASONS, MAX_REASONS)


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, EXECUTION_CONTROL_LIMITATIONS, MAX_LIMITATIONS
    )


def sanitize_execution_error(value: object) -> dict:
    """Project one control error onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in EXECUTION_CONTROL_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "input_kind": _safe_text(value.get("input_kind")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_execution_control_summary(value: object) -> dict:
    """Project the bounded control summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "request_count": 0,
            "block_reason_count": 0,
            "safety_reason_count": 0,
            "authorization_reason_count": 0,
            "step_count": 0,
            "research_only": True,
        }
    return {
        "request_count": _bounded_int(value.get("request_count"), 0, 1),
        "block_reason_count": _bounded_int(
            value.get("block_reason_count"), 0, MAX_REASONS
        ),
        "safety_reason_count": _bounded_int(
            value.get("safety_reason_count"), 0, MAX_REASONS
        ),
        "authorization_reason_count": _bounded_int(
            value.get("authorization_reason_count"), 0, MAX_REASONS
        ),
        "step_count": _bounded_int(value.get("step_count"), 0, MAX_LIST),
        "research_only": True,
    }


def sanitize_execution_control_provenance(value: object) -> dict:
    """Project container-level control provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "request_rule_version": "",
            "authorization_rule_version": "",
            "plan_rule_version": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decision_rule_version": "",
            "learning_rule_version": "",
            "request_id": "",
            "authorization_id": "",
            "plan_id": "",
            "finding_id": "",
            "decision_id": "",
            "prioritization_id": "",
            "correlation_id": "",
            "orchestration_id": "",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "request_rule_version": _safe_text(
            value.get("request_rule_version")
        ),
        "authorization_rule_version": _safe_text(
            value.get("authorization_rule_version")
        ),
        "plan_rule_version": _safe_text(value.get("plan_rule_version")),
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
        "request_id": _safe_text(value.get("request_id")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "plan_id": _safe_text(value.get("plan_id")),
        "finding_id": _safe_text(value.get("finding_id")),
        "decision_id": _safe_text(value.get("decision_id")),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "source_stages": _bounded_strings(
            value.get("source_stages"), MAX_LIST, 80
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_execution_audit(value: object) -> dict:
    """Project the deterministic execution-control audit onto fixed keys.

    The audit preserves who authorized what, for which finding, action,
    target and scope, with the safety result and the reason(s) for
    allow/block. It never contains secrets, credentials, tokens or raw
    network data.
    """

    if not isinstance(value, dict):
        return _default_audit()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "audit_id": _safe_text(value.get("audit_id")),
        "request_id": _safe_text(value.get("request_id")),
        "decision_id": _safe_text(value.get("decision_id")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "plan_id": _safe_text(value.get("plan_id")),
        "finding_id": finding_id,
        "action_type": _safe_text(value.get("action_type")).strip().upper(),
        "action_scope": _safe_text(value.get("action_scope"), 240),
        "target_reference": _safe_text(
            value.get("target_reference"), 240
        ),
        "safety_result": _closed(
            value.get("safety_result"), SAFETY_RESULTS, SAFETY_UNKNOWN
        ),
        "control_outcome": _closed(
            value.get("control_outcome"), CONTROL_OUTCOMES, CONTROL_OUTCOME_INVALID
        ),
        "outcome_reasons": _ordered_reasons(value.get("outcome_reasons")),
        "authorization_status": _safe_text(
            value.get("authorization_status")
        ).strip().upper(),
        "execution_status": _safe_text(
            value.get("execution_status")
        ).strip().upper(),
        "provenance": sanitize_execution_control_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_finding_governance(value.get("governance")),
        "audit_state": _closed(
            value.get("audit_state"), AUDIT_STATES, AUDIT_UNKNOWN
        ),
        "research_only": True,
        "deterministic": True,
    }


def _default_audit() -> dict:
    return {
        "rule_version": "",
        "audit_id": "",
        "request_id": "",
        "decision_id": "",
        "authorization_id": "",
        "plan_id": "",
        "finding_id": "",
        "action_type": "",
        "action_scope": "",
        "target_reference": "",
        "safety_result": SAFETY_UNKNOWN,
        "control_outcome": CONTROL_OUTCOME_INVALID,
        "outcome_reasons": [],
        "authorization_status": "",
        "execution_status": "",
        "provenance": sanitize_execution_control_provenance(None),
        "governance": sanitize_finding_governance(None),
        "audit_state": AUDIT_UNKNOWN,
        "research_only": True,
        "deterministic": True,
    }


def sanitize_execution_control_result(value: object) -> dict:
    """Project an R58 execution-control result onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_result()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "control_id": _safe_text(value.get("control_id")),
        "request_id": _safe_text(value.get("request_id")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "plan_id": _safe_text(value.get("plan_id")),
        "finding_id": finding_id,
        "decision_id": _safe_text(value.get("decision_id")),
        "action_type": _safe_text(value.get("action_type")).strip().upper(),
        "action_scope": _safe_text(value.get("action_scope"), 240),
        "target_reference": _safe_text(
            value.get("target_reference"), 240
        ),
        "status": _closed(
            value.get("status"),
            EXECUTION_CONTROL_STATUSES,
            CONTROL_STATUS_INVALID,
        ),
        "control_outcome": _closed(
            value.get("control_outcome"),
            CONTROL_OUTCOMES,
            CONTROL_OUTCOME_INVALID,
        ),
        "safety_result": _closed(
            value.get("safety_result"), SAFETY_RESULTS, SAFETY_UNKNOWN
        ),
        "safety_reasons": _ordered_codes(
            value.get("safety_reasons"),
            SAFETY_REJECTION_REASONS,
            MAX_REASONS,
        ),
        "authorization_status": _safe_text(
            value.get("authorization_status")
        ).strip().upper(),
        "execution_status": _safe_text(
            value.get("execution_status")
        ).strip().upper(),
        "block_reasons": _ordered_reasons(value.get("block_reasons")),
        "allow_reasons": _ordered_reasons(value.get("allow_reasons")),
        "request": value.get("request")
        if isinstance(value.get("request"), dict)
        else {},
        "authorization": value.get("authorization")
        if isinstance(value.get("authorization"), dict)
        else {},
        "plan": value.get("plan")
        if isinstance(value.get("plan"), dict)
        else {},
        "audit": sanitize_execution_audit(value.get("audit")),
        "summary": sanitize_execution_control_summary(value.get("summary")),
        "errors": [
            projected
            for projected in (
                sanitize_execution_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "provenance": sanitize_execution_control_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "execution_authorized": bool(
            value.get("execution_authorized")
        )
        is True,
        "execution_performed": False,
        "external_executor_present": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _default_result() -> dict:
    return {
        "rule_version": "",
        "control_id": "",
        "request_id": "",
        "authorization_id": "",
        "plan_id": "",
        "finding_id": "",
        "decision_id": "",
        "action_type": "",
        "action_scope": "",
        "target_reference": "",
        "status": CONTROL_STATUS_NOT_REQUESTED,
        "control_outcome": CONTROL_OUTCOME_NOT_REQUESTED,
        "safety_result": SAFETY_UNKNOWN,
        "safety_reasons": [],
        "authorization_status": "",
        "execution_status": "",
        "block_reasons": [],
        "allow_reasons": [],
        "request": {},
        "authorization": {},
        "plan": {},
        "audit": sanitize_execution_audit(None),
        "summary": sanitize_execution_control_summary(None),
        "errors": [],
        "provenance": sanitize_execution_control_provenance(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "execution_authorized": False,
        "execution_performed": False,
        "external_executor_present": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionControlResultPlan(BaseModel):
    """Deterministic R58 execution-control result (R58.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_CONTROL_RESULT_RULE_VERSION
    control_id: str
    request_id: str = ""
    authorization_id: str = ""
    plan_id: str = ""
    finding_id: str = ""
    decision_id: str = ""
    action_type: str = ""
    action_scope: str = ""
    target_reference: str = ""
    status: str = CONTROL_STATUS_NOT_REQUESTED
    control_outcome: str = CONTROL_OUTCOME_NOT_REQUESTED
    safety_result: str = SAFETY_UNKNOWN
    safety_reasons: list[str] = Field(default_factory=list)
    authorization_status: str = ""
    execution_status: str = ""
    block_reasons: list[str] = Field(default_factory=list)
    allow_reasons: list[str] = Field(default_factory=list)
    request: dict = Field(default_factory=dict)
    authorization: dict = Field(default_factory=dict)
    plan: dict = Field(default_factory=dict)
    audit: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    execution_authorized: bool = False
    execution_performed: bool = False
    external_executor_present: bool = False
    exploit_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_CONTROL_RESULT_RULE_VERSION

    @field_validator("control_id")
    @classmethod
    def _valid_control_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not CONTROL_ID_RE.match(text):
            raise ValueError(f"malformed control_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_CONTROL_STATUSES:
            raise ValueError(f"invalid control status: {value!r}")
        return text

    @field_validator("control_outcome")
    @classmethod
    def _valid_outcome(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTROL_OUTCOMES:
            raise ValueError(f"invalid control outcome: {value!r}")
        return text

    @field_validator("safety_result")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SAFETY_RESULTS:
            raise ValueError(f"invalid safety_result: {value!r}")
        return text

    @field_validator("safety_reasons")
    @classmethod
    def _bounded_safety_reasons(cls, value: object) -> list[str]:
        return _ordered_codes(value, SAFETY_REJECTION_REASONS, MAX_REASONS)

    @field_validator("block_reasons", "allow_reasons")
    @classmethod
    def _bounded_reasons(cls, value: object) -> list[str]:
        return _ordered_reasons(value)

    @field_validator("audit")
    @classmethod
    def _bounded_audit(cls, value: object) -> dict:
        return sanitize_execution_audit(value)

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_execution_control_summary(value)

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_execution_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_execution_control_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("execution_performed")
    @classmethod
    def _never_executed(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("the control gate never performs execution")
        return False

    @field_validator("external_executor_present")
    @classmethod
    def _no_external_executor(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("no external executor exists in R58")
        return False

    @field_validator("exploit_authorized", "vulnerability_confirmed")
    @classmethod
    def _never_confirmed_or_exploited(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "controlled execution never confirms or exploits"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("controlled execution never confirms")
        return "NOT_CONFIRMED"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution control results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("execution control results are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_outcome(self) -> "ExecutionControlResultPlan":
        if self.status == CONTROL_STATUS_COMPLETED:
            if self.control_outcome != CONTROL_OUTCOME_ALLOW:
                raise ValueError("completed control requires ALLOW")
            if self.execution_authorized is not True:
                raise ValueError("completed control requires authorization")
            if self.safety_result != SAFETY_PASS:
                raise ValueError("completed control requires a safety pass")
            if self.block_reasons:
                raise ValueError("completed control cannot carry block reasons")
            if not self.allow_reasons:
                raise ValueError("completed control requires allow reasons")
        elif self.control_outcome == CONTROL_OUTCOME_ALLOW:
            raise ValueError("ALLOW requires a completed status")
        if self.control_outcome in (
            CONTROL_OUTCOME_DENY,
            CONTROL_OUTCOME_NOT_REQUESTED,
            CONTROL_OUTCOME_INVALID,
        ):
            if self.execution_authorized is not False:
                raise ValueError(
                    "non-allowed control never authorizes execution"
                )
        if self.status == CONTROL_STATUS_BLOCKED and not self.block_reasons:
            raise ValueError("blocked control requires block reasons")
        return self


def execution_control_result_plan_projection(
    value: ExecutionControlResultPlan,
) -> dict:
    """Serialize an R58 control result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_CONTROL_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "SAFETY_PASS",
    "SAFETY_BLOCKED",
    "SAFETY_INVALID",
    "SAFETY_UNKNOWN",
    "SAFETY_RESULTS",
    "CONTROL_STATUS_COMPLETED",
    "CONTROL_STATUS_BLOCKED",
    "CONTROL_STATUS_NOT_REQUESTED",
    "CONTROL_STATUS_INVALID",
    "CONTROL_STATUS_FAILED",
    "EXECUTION_CONTROL_STATUSES",
    "CONTROL_OUTCOME_ALLOW",
    "CONTROL_OUTCOME_DENY",
    "CONTROL_OUTCOME_NOT_REQUESTED",
    "CONTROL_OUTCOME_INVALID",
    "CONTROL_OUTCOMES",
    "SAFETY_REASON_EXPLOIT_AUTHORIZATION",
    "SAFETY_REASON_VULNERABILITY_CONFIRMATION",
    "SAFETY_REASON_PAYLOAD_GENERATION",
    "SAFETY_REASON_ATTACK_PLANNING",
    "SAFETY_REASON_COMMAND_EXECUTION",
    "SAFETY_REASON_CODE_EXECUTION",
    "SAFETY_REASON_NETWORK_EXECUTION",
    "SAFETY_REASON_SCANNER_EXECUTION",
    "SAFETY_REASON_BROWSER_AUTOMATION",
    "SAFETY_REASON_SUBPROCESS_EXECUTION",
    "SAFETY_REASON_AUTONOMOUS_AUTHORIZATION",
    "SAFETY_REASON_POLICY_BYPASS",
    "SAFETY_REASON_HUMAN_APPROVAL_BYPASS",
    "SAFETY_REASON_UNSAFE_ACTION",
    "SAFETY_REASON_UNSAFE_INPUT",
    "SAFETY_REASON_MALFORMED_INPUT",
    "SAFETY_REASON_AMBIGUOUS_INPUT",
    "SAFETY_REJECTION_REASONS",
    "REASON_AUTHORIZATION_MISSING",
    "REASON_HUMAN_DECISION_REQUIRED",
    "REASON_HUMAN_DECISION_PENDING",
    "REASON_AI_AUTHORIZATION_REJECTED",
    "REASON_AUTHORIZATION_AMBIGUOUS",
    "REASON_ACTION_MISMATCH",
    "REASON_TARGET_MISMATCH",
    "REASON_SCOPE_MISMATCH",
    "REASON_FINDING_MISMATCH",
    "REASON_DECISION_MISMATCH",
    "REASON_DECISION_DOES_NOT_AUTHORIZE",
    "REASON_ESCALATION_REVIEW_REQUIRED",
    "REASON_AUTHORIZATION_EXPIRED",
    "REASON_AUTHORIZATION_INVALID",
    "REASON_EXECUTION_NOT_REQUESTED",
    "REASON_REQUEST_INVALID",
    "REASON_UNSUPPORTED_ACTION",
    "REASON_WILDCARD_SCOPE",
    "REASON_R57_RECOMMENDATION_REVIEW",
    "REASON_RULE_VERSION_MISMATCH",
    "REASON_INVALID_INPUT",
    "REASON_MALFORMED_INPUT",
    "REASON_UNKNOWN",
    "EXECUTION_AUTHORIZATION_REJECTION_REASONS",
    "ALLOW_REASON_HUMAN_AUTHORITY",
    "ALLOW_REASON_DECISION_APPROVES_RESEARCH",
    "ALLOW_REASON_ACTION_MATCH",
    "ALLOW_REASON_TARGET_MATCH",
    "ALLOW_REASON_SCOPE_MATCH",
    "ALLOW_REASON_FINDING_MATCH",
    "ALLOW_REASON_DECISION_MATCH",
    "ALLOW_REASON_VALIDITY_VALID",
    "ALLOW_REASON_SAFETY_GATE_PASS",
    "EXECUTION_ALLOW_REASONS",
    "EXECUTION_OUTCOME_REASONS",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_INPUT",
    "ERROR_RULE_VERSION_MISMATCH",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_AUTHORIZATION_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "EXECUTION_CONTROL_ERROR_CATEGORIES",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_GATE_ONLY_NOT_EXECUTOR",
    "LIMITATION_DECLARATIVE_ONLY",
    "LIMITATION_EXTERNAL_EXECUTOR_ABSENT",
    "LIMITATION_FUTURE_EXECUTION_LAYER_REQUIRED",
    "LIMITATION_HUMAN_AUTHORITY_REQUIRED",
    "LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION",
    "LIMITATION_HUMAN_APPROVAL_IS_NOT_EXECUTION",
    "LIMITATION_PRIORITY_NOT_AUTHORIZATION",
    "LIMITATION_FINDING_NOT_CONFIRMATION",
    "LIMITATION_CORRELATION_NOT_AUTHORIZATION",
    "LIMITATION_LEARNING_NOT_AUTHORIZATION",
    "LIMITATION_DECISION_DOES_NOT_AUTHORIZE_ACTION",
    "LIMITATION_SCOPE_NOT_EXPANDABLE",
    "LIMITATION_ACTION_NOT_TRANSFERABLE",
    "LIMITATION_TARGET_NOT_TRANSFERABLE",
    "LIMITATION_VALIDITY_EXPLICIT_ONLY",
    "LIMITATION_SAFETY_BLOCKED",
    "LIMITATION_AUTHORIZATION_MISSING",
    "LIMITATION_PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED",
    "LIMITATION_ATTACK_PLANNING_NOT_AUTHORIZED",
    "LIMITATION_AUTONOMOUS_EXECUTION_NOT_AUTHORIZED",
    "LIMITATION_NO_LLM_INVOLVEMENT",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "LIMITATION_AUTHORIZATION_EXPIRED",
    "LIMITATION_PLAN_NOT_READY",
    "EXECUTION_CONTROL_LIMITATIONS",
    "CONTROL_ID_PREFIX",
    "CONTROL_ID_RE",
    "AUDIT_ID_PREFIX",
    "AUDIT_ID_RE",
    "MAX_REASONS",
    "MAX_LIMITATIONS",
    "MAX_ERRORS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "MAX_MESSAGE_LEN",
    "sanitize_execution_error",
    "sanitize_execution_control_summary",
    "sanitize_execution_control_provenance",
    "sanitize_execution_audit",
    "sanitize_execution_control_result",
    "ExecutionControlResultPlan",
    "execution_control_result_plan_projection",
]

"""Execution request schema (Stage R58.1).

Defines the bounded, deterministic R58 controlled-execution request: the
structured proposal that a research action should be considered for a future
controlled execution workflow. It answers:

    "What exact research action is being proposed, for which finding, on
     which target and scope, and under which recorded human decision?"

Hard boundaries encoded here:

- Proposal only: a request is never authority and never execution.
  ``execution_authorized``, ``vulnerability_confirmed`` and
  ``exploit_authorized`` are forced ``False`` with
  ``confirmation_state = NOT_CONFIRMED``. Nothing is sent, scanned, launched
  or modified.
- Closed action vocabulary: only safe research/control actions exist. An
  unsupported action is represented as ``UNSPECIFIED`` with a structured
  rejection code and is never silently mapped to another action.
- AI may recommend: ``requested_by`` may be ``AI_ADVISORY``, but a request is
  only ever *eligible*; authorization requires explicit human authority in
  the R58.2 authorization contract.
- Scope is exact: the action scope and target reference are preserved as
  bounded text; wildcard expansion is rejected by the safety gate, never
  silently broadened.
- Human decisions are referenced, never reinterpreted: the R56 decision is
  carried as a bounded reference for audit only.
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
    sanitize_authorization_context,
)
from ai.schemas.execution_control_result import (
    EXECUTION_CONTROL_LIMITATIONS,
    MAX_LIMITATIONS,
    MAX_REASONS,
    SAFETY_REJECTION_REASONS,
    SAFETY_RESULTS,
    SAFETY_UNKNOWN,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.human_decision import (
    sanitize_correlation_reference,
    sanitize_finding_reference,
    sanitize_human_governance,
    sanitize_priority_reference,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

EXECUTION_REQUEST_RULE_VERSION = "r58-1"
RULE_VERSION = EXECUTION_REQUEST_RULE_VERSION

# ---------------------------------------------------------------------------
# Action vocabulary (closed; safe research/control actions only)
# ---------------------------------------------------------------------------

ACTION_COLLECT_EXISTING_EVIDENCE = "COLLECT_EXISTING_EVIDENCE"
ACTION_REVIEW_EXISTING_RESPONSE = "REVIEW_EXISTING_RESPONSE"
ACTION_RECHECK_SCOPE = "RECHECK_SCOPE"
ACTION_REASSESS_CONTEXT = "REASSESS_CONTEXT"
ACTION_PREPARE_RESEARCH_STEP = "PREPARE_RESEARCH_STEP"
ACTION_REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"

EXECUTION_ACTIONS: tuple[str, ...] = (
    ACTION_COLLECT_EXISTING_EVIDENCE,
    ACTION_REVIEW_EXISTING_RESPONSE,
    ACTION_RECHECK_SCOPE,
    ACTION_REASSESS_CONTEXT,
    ACTION_PREPARE_RESEARCH_STEP,
    ACTION_REQUEST_HUMAN_REVIEW,
)

#: Explicit "no action selected" value: never a valid executable action.
ACTION_UNSPECIFIED = "UNSPECIFIED"

EXECUTION_ACTION_VALUES: tuple[str, ...] = EXECUTION_ACTIONS + (
    ACTION_UNSPECIFIED,
)

# ---------------------------------------------------------------------------
# Request state vocabulary (closed)
# ---------------------------------------------------------------------------

REQUEST_STATE_NOT_REQUESTED = "NOT_REQUESTED"
REQUEST_STATE_REQUESTED = "REQUESTED"
REQUEST_STATE_BLOCKED = "BLOCKED"
REQUEST_STATE_INVALID = "INVALID"

EXECUTION_REQUEST_STATES: tuple[str, ...] = (
    REQUEST_STATE_NOT_REQUESTED,
    REQUEST_STATE_REQUESTED,
    REQUEST_STATE_BLOCKED,
    REQUEST_STATE_INVALID,
)

# ---------------------------------------------------------------------------
# Requester vocabulary (closed; AI may recommend, only humans authorize)
# ---------------------------------------------------------------------------

REQUESTER_HUMAN = "HUMAN"
REQUESTER_AI_ADVISORY = "AI_ADVISORY"
REQUESTER_UNSPECIFIED = "UNSPECIFIED"

EXECUTION_REQUESTERS: tuple[str, ...] = (
    REQUESTER_HUMAN,
    REQUESTER_AI_ADVISORY,
    REQUESTER_UNSPECIFIED,
)

# ---------------------------------------------------------------------------
# Scope kind vocabulary (closed)
# ---------------------------------------------------------------------------

SCOPE_KIND_TARGET_REFERENCE = "TARGET_REFERENCE"
SCOPE_KIND_PATH = "PATH"
SCOPE_KIND_FINDING = "FINDING"
SCOPE_KIND_RESEARCH_STEP = "RESEARCH_STEP"
SCOPE_KIND_UNSPECIFIED = "UNSPECIFIED"

SCOPE_KINDS: tuple[str, ...] = (
    SCOPE_KIND_TARGET_REFERENCE,
    SCOPE_KIND_PATH,
    SCOPE_KIND_FINDING,
    SCOPE_KIND_RESEARCH_STEP,
    SCOPE_KIND_UNSPECIFIED,
)

# ---------------------------------------------------------------------------
# Request rejection vocabulary (closed)
# ---------------------------------------------------------------------------

REJECTION_FINDING_ID_REQUIRED = "FINDING_ID_REQUIRED"
REJECTION_ACTION_NOT_SUPPORTED = "ACTION_NOT_SUPPORTED"
REJECTION_SCOPE_REQUIRED = "SCOPE_REQUIRED"
REJECTION_TARGET_REQUIRED = "TARGET_REQUIRED"
REJECTION_REQUESTER_REQUIRED = "REQUESTER_REQUIRED"
REJECTION_PURPOSE_REQUIRED = "PURPOSE_REQUIRED"
REJECTION_MALFORMED_REQUEST = "MALFORMED_REQUEST"
REJECTION_UNSAFE_REQUEST = "UNSAFE_REQUEST"
REJECTION_WILDCARD_SCOPE = "WILDCARD_SCOPE_NOT_ALLOWED"
REJECTION_WILDCARD_TARGET = "WILDCARD_TARGET_NOT_ALLOWED"
REJECTION_UNKNOWN = "UNKNOWN_REJECTION"

EXECUTION_REQUEST_REJECTION_CODES: tuple[str, ...] = (
    REJECTION_FINDING_ID_REQUIRED,
    REJECTION_ACTION_NOT_SUPPORTED,
    REJECTION_SCOPE_REQUIRED,
    REJECTION_TARGET_REQUIRED,
    REJECTION_REQUESTER_REQUIRED,
    REJECTION_PURPOSE_REQUIRED,
    REJECTION_MALFORMED_REQUEST,
    REJECTION_UNSAFE_REQUEST,
    REJECTION_WILDCARD_SCOPE,
    REJECTION_WILDCARD_TARGET,
    REJECTION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Decision reference vocabulary (read-only mirror of R56)
# ---------------------------------------------------------------------------

EXECUTION_DECISION_TYPES: tuple[str, ...] = (
    "APPROVE_RESEARCH",
    "REQUEST_MORE_EVIDENCE",
    "DEFER",
    "REJECT",
    "ESCALATE",
    "NEEDS_REVIEW",
)

EXECUTION_DECISION_STATES: tuple[str, ...] = (
    "DECIDED",
    "PENDING_HUMAN_REVIEW",
    "EXPIRED",
    "INVALID",
)

# ---------------------------------------------------------------------------
# Limitations (closed; shared gate vocabulary)
# ---------------------------------------------------------------------------

EXECUTION_REQUEST_LIMITATIONS: tuple[str, ...] = (
    EXECUTION_CONTROL_LIMITATIONS
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

REQUEST_ID_PREFIX = "exr-"
REQUEST_ID_RE = re.compile(r"^exr-[0-9a-f]{16}$")

MAX_VALUE_LEN = 160
MAX_PURPOSE_LEN = 240
MAX_SCOPE_LEN = 240
MAX_TARGET_LEN = 160

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


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_request_rejections(codes: object) -> list[str]:
    return _ordered_codes(
        codes, EXECUTION_REQUEST_REJECTION_CODES, MAX_REASONS
    )


def _ordered_safety_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, SAFETY_REJECTION_REASONS, MAX_REASONS)


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, EXECUTION_REQUEST_LIMITATIONS, MAX_LIMITATIONS
    )


def normalize_execution_scope(value: object) -> str:
    """Deterministic bounded normalization of an action scope."""

    return _safe_text(value, MAX_SCOPE_LEN).strip()


def normalize_target_reference(value: object) -> str:
    """Deterministic bounded normalization of a target reference."""

    return _safe_text(value, MAX_TARGET_LEN).strip()


def sanitize_decision_reference(value: object) -> dict:
    """Project the referenced R56 human decision onto fixed keys."""

    if not isinstance(value, dict) or not value:
        return {
            "present": False,
            "decision_id": "",
            "decision_type": "",
            "decision_state": "",
            "finding_id": "",
            "human_authority": False,
            "decision_source": "",
            "decision_authority": "",
            "decision_rule_version": "",
            "research_only": True,
        }
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "present": True,
        "decision_id": _safe_text(value.get("decision_id")),
        "decision_type": _closed(
            value.get("decision_type"),
            EXECUTION_DECISION_TYPES,
            "",
        ),
        "decision_state": _closed(
            value.get("decision_state"),
            EXECUTION_DECISION_STATES,
            "",
        ),
        "finding_id": finding_id,
        "human_authority": bool(value.get("human_authority")) is True,
        "decision_source": _safe_text(
            value.get("decision_source")
        ).strip().upper(),
        "decision_authority": _safe_text(
            value.get("decision_authority")
        ).strip().upper(),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "research_only": True,
    }


def sanitize_safety_context(value: object) -> dict:
    """Project the request safety context onto fixed keys.

    Every execution-capable flag is forced ``False``: a request can never
    carry permission to execute, scan, browse, resolve or spawn anything.
    """

    if not isinstance(value, dict) or not value:
        return _default_safety_context()
    return {
        "safety_state": _closed(
            value.get("safety_state"), SAFETY_RESULTS, SAFETY_UNKNOWN
        ),
        "safety_reasons": _ordered_safety_reasons(
            value.get("safety_reasons")
        ),
        "network_io": False,
        "command_execution": False,
        "payload_generation": False,
        "exploit_execution": False,
        "browser_automation": False,
        "subprocess_execution": False,
        "scanner_execution": False,
        "arbitrary_code_execution": False,
        "autonomous_authorization": False,
        "policy_bypass": False,
        "human_approval_bypass": False,
        "research_only": True,
    }


def _default_safety_context() -> dict:
    return {
        "safety_state": SAFETY_UNKNOWN,
        "safety_reasons": [],
        "network_io": False,
        "command_execution": False,
        "payload_generation": False,
        "exploit_execution": False,
        "browser_automation": False,
        "subprocess_execution": False,
        "scanner_execution": False,
        "arbitrary_code_execution": False,
        "autonomous_authorization": False,
        "policy_bypass": False,
        "human_approval_bypass": False,
        "research_only": True,
    }


def sanitize_request_provenance(value: object) -> dict:
    """Project request provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decision_rule_version": "",
            "learning_rule_version": "",
            "prioritization_id": "",
            "correlation_id": "",
            "orchestration_id": "",
            "decision_id": "",
            "agent_id": "",
            "category": "",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    return {
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
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "decision_id": _safe_text(value.get("decision_id")),
        "agent_id": _safe_text(value.get("agent_id")),
        "category": category,
        "source_stages": _bounded_strings(
            value.get("source_stages"), 24, 80
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_execution_request(value: object) -> dict:
    """Project an R58 execution request onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_request()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "request_id": _safe_text(value.get("request_id")),
        "finding_id": finding_id,
        "action_type": _closed(
            value.get("action_type"),
            EXECUTION_ACTION_VALUES,
            ACTION_UNSPECIFIED,
        ),
        "requested_action_type": _safe_text(
            value.get("requested_action_type")
        ).strip().upper(),
        "action_scope": normalize_execution_scope(value.get("action_scope")),
        "scope_kind": _closed(
            value.get("scope_kind"), SCOPE_KINDS, SCOPE_KIND_UNSPECIFIED
        ),
        "target_reference": normalize_target_reference(
            value.get("target_reference")
        ),
        "purpose": _safe_text(value.get("purpose"), MAX_PURPOSE_LEN),
        "requested_by": _closed(
            value.get("requested_by"),
            EXECUTION_REQUESTERS,
            REQUESTER_UNSPECIFIED,
        ),
        "request_state": _closed(
            value.get("request_state"),
            EXECUTION_REQUEST_STATES,
            REQUEST_STATE_INVALID,
        ),
        "request_rejection_codes": _ordered_request_rejections(
            value.get("request_rejection_codes")
        ),
        "human_decision_reference": sanitize_decision_reference(
            value.get("human_decision_reference")
        ),
        "authorization_context": sanitize_authorization_context(
            value.get("authorization_context")
        ),
        "priority_reference": sanitize_priority_reference(
            value.get("priority_reference")
        ),
        "correlation_reference": sanitize_correlation_reference(
            value.get("correlation_reference")
        ),
        "finding_reference": sanitize_finding_reference(
            value.get("finding_reference")
        ),
        "safety_context": sanitize_safety_context(
            value.get("safety_context")
        ),
        "provenance": sanitize_request_provenance(value.get("provenance")),
        "governance": sanitize_human_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "execution_requested": bool(
            value.get("execution_requested")
        )
        is True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _default_request() -> dict:
    return {
        "rule_version": "",
        "request_id": "",
        "finding_id": "",
        "action_type": ACTION_UNSPECIFIED,
        "requested_action_type": "",
        "action_scope": "",
        "scope_kind": SCOPE_KIND_UNSPECIFIED,
        "target_reference": "",
        "purpose": "",
        "requested_by": REQUESTER_UNSPECIFIED,
        "request_state": REQUEST_STATE_INVALID,
        "request_rejection_codes": [],
        "human_decision_reference": sanitize_decision_reference(None),
        "authorization_context": sanitize_authorization_context(None),
        "priority_reference": sanitize_priority_reference(None),
        "correlation_reference": sanitize_correlation_reference(None),
        "finding_reference": sanitize_finding_reference(None),
        "safety_context": _default_safety_context(),
        "provenance": sanitize_request_provenance(None),
        "governance": sanitize_human_governance(None),
        "limitations": [],
        "execution_requested": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionRequestPlan(BaseModel):
    """Deterministic R58 controlled-execution request (R58.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_REQUEST_RULE_VERSION
    request_id: str
    finding_id: str = ""
    action_type: str = ACTION_UNSPECIFIED
    requested_action_type: str = ""
    action_scope: str = ""
    scope_kind: str = SCOPE_KIND_UNSPECIFIED
    target_reference: str = ""
    purpose: str = ""
    requested_by: str = REQUESTER_UNSPECIFIED
    request_state: str = REQUEST_STATE_INVALID
    request_rejection_codes: list[str] = Field(default_factory=list)
    human_decision_reference: dict = Field(default_factory=dict)
    authorization_context: dict = Field(default_factory=dict)
    priority_reference: dict = Field(default_factory=dict)
    correlation_reference: dict = Field(default_factory=dict)
    finding_reference: dict = Field(default_factory=dict)
    safety_context: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    execution_requested: bool = False
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    exploit_authorized: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_REQUEST_RULE_VERSION

    @field_validator("request_id")
    @classmethod
    def _valid_request_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not REQUEST_ID_RE.match(text):
            raise ValueError(f"malformed request_id: {value!r}")
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

    @field_validator("scope_kind")
    @classmethod
    def _valid_scope_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SCOPE_KINDS:
            raise ValueError(f"invalid scope_kind: {value!r}")
        return text

    @field_validator("requested_by")
    @classmethod
    def _valid_requester(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_REQUESTERS:
            raise ValueError(f"invalid requested_by: {value!r}")
        return text

    @field_validator("request_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_REQUEST_STATES:
            raise ValueError(f"invalid request_state: {value!r}")
        return text

    @field_validator("request_rejection_codes")
    @classmethod
    def _bounded_rejections(cls, value: object) -> list[str]:
        return _ordered_request_rejections(value)

    @field_validator("human_decision_reference")
    @classmethod
    def _bounded_decision_reference(cls, value: object) -> dict:
        return sanitize_decision_reference(value)

    @field_validator("authorization_context")
    @classmethod
    def _bounded_authorization_context(cls, value: object) -> dict:
        return sanitize_authorization_context(value)

    @field_validator("priority_reference")
    @classmethod
    def _bounded_priority(cls, value: object) -> dict:
        return sanitize_priority_reference(value)

    @field_validator("correlation_reference")
    @classmethod
    def _bounded_correlation(cls, value: object) -> dict:
        return sanitize_correlation_reference(value)

    @field_validator("finding_reference")
    @classmethod
    def _bounded_finding(cls, value: object) -> dict:
        return sanitize_finding_reference(value)

    @field_validator("safety_context")
    @classmethod
    def _bounded_safety(cls, value: object) -> dict:
        return sanitize_safety_context(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_request_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_human_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator(
        "execution_authorized",
        "vulnerability_confirmed",
        "exploit_authorized",
    )
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "execution requests never authorize, confirm or exploit"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("execution requests never confirm")
        return "NOT_CONFIRMED"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution requests are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("execution requests are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_state(self) -> "ExecutionRequestPlan":
        if self.request_state == REQUEST_STATE_REQUESTED:
            if self.execution_requested is not True:
                raise ValueError("requested state requires execution_requested")
            if self.action_type not in EXECUTION_ACTIONS:
                raise ValueError(
                    "requested state requires a supported action"
                )
            if not self.action_scope:
                raise ValueError("requested state requires an action scope")
            if not self.target_reference:
                raise ValueError("requested state requires a target")
            if not self.purpose:
                raise ValueError("requested state requires a purpose")
            if self.requested_by == REQUESTER_UNSPECIFIED:
                raise ValueError("requested state requires an explicit requester")
            if self.request_rejection_codes:
                raise ValueError(
                    "requested state cannot carry rejection codes"
                )
            if self.finding_id == "":
                raise ValueError("requested state requires a finding id")
        elif self.request_state == REQUEST_STATE_NOT_REQUESTED:
            if self.execution_requested is not False:
                raise ValueError(
                    "not-requested state cannot request execution"
                )
        elif not self.request_rejection_codes:
            raise ValueError(
                "blocked/invalid requests require structured reasons"
            )
        return self


def execution_request_plan_projection(value: ExecutionRequestPlan) -> dict:
    """Serialize an R58 execution request to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_REQUEST_RULE_VERSION",
    "RULE_VERSION",
    "EXECUTION_ACTIONS",
    "EXECUTION_ACTION_VALUES",
    "ACTION_COLLECT_EXISTING_EVIDENCE",
    "ACTION_REVIEW_EXISTING_RESPONSE",
    "ACTION_RECHECK_SCOPE",
    "ACTION_REASSESS_CONTEXT",
    "ACTION_PREPARE_RESEARCH_STEP",
    "ACTION_REQUEST_HUMAN_REVIEW",
    "ACTION_UNSPECIFIED",
    "REQUEST_STATE_NOT_REQUESTED",
    "REQUEST_STATE_REQUESTED",
    "REQUEST_STATE_BLOCKED",
    "REQUEST_STATE_INVALID",
    "EXECUTION_REQUEST_STATES",
    "REQUESTER_HUMAN",
    "REQUESTER_AI_ADVISORY",
    "REQUESTER_UNSPECIFIED",
    "EXECUTION_REQUESTERS",
    "SCOPE_KIND_TARGET_REFERENCE",
    "SCOPE_KIND_PATH",
    "SCOPE_KIND_FINDING",
    "SCOPE_KIND_RESEARCH_STEP",
    "SCOPE_KIND_UNSPECIFIED",
    "SCOPE_KINDS",
    "REJECTION_FINDING_ID_REQUIRED",
    "REJECTION_ACTION_NOT_SUPPORTED",
    "REJECTION_SCOPE_REQUIRED",
    "REJECTION_TARGET_REQUIRED",
    "REJECTION_REQUESTER_REQUIRED",
    "REJECTION_PURPOSE_REQUIRED",
    "REJECTION_MALFORMED_REQUEST",
    "REJECTION_UNSAFE_REQUEST",
    "REJECTION_WILDCARD_SCOPE",
    "REJECTION_WILDCARD_TARGET",
    "REJECTION_UNKNOWN",
    "EXECUTION_REQUEST_REJECTION_CODES",
    "EXECUTION_DECISION_TYPES",
    "EXECUTION_DECISION_STATES",
    "EXECUTION_REQUEST_LIMITATIONS",
    "REQUEST_ID_PREFIX",
    "REQUEST_ID_RE",
    "MAX_VALUE_LEN",
    "MAX_PURPOSE_LEN",
    "MAX_SCOPE_LEN",
    "MAX_TARGET_LEN",
    "normalize_execution_scope",
    "normalize_target_reference",
    "sanitize_decision_reference",
    "sanitize_safety_context",
    "sanitize_request_provenance",
    "sanitize_execution_request",
    "ExecutionRequestPlan",
    "execution_request_plan_projection",
]

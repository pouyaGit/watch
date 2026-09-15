"""Controlled execution authorization schema (Stage R58.2).

Defines the bounded, deterministic R58 execution authorization produced by the
controlled-execution gate. It answers:

    "Did an explicit human authority authorize exactly this action, on
     exactly this target, within exactly this scope, for exactly this
     finding and decision?"

Hard boundaries encoded here:

- Human authority only: ``authorization_status = AUTHORIZED`` requires an
  explicit ``HUMAN`` source and ``HUMAN`` authority. AI-originated, autonomous
  or bypassed authorization is represented as ``BLOCKED`` with a closed
  rejection code and can never become authority.
- Authorization is not execution: an authorized record permits a future
  external executor to consider the action; it never executes, schedules,
  sends or confirms anything. ``exploit_authorized`` and
  ``vulnerability_confirmed`` are forced ``False`` with
  ``confirmation_state = NOT_CONFIRMED``.
- Exact matching, no expansion: approval for one action, target, scope,
  finding or decision never transfers to another; wildcard scopes are
  rejected.
- Deterministic validity: validity is explicit structured metadata only.
  No wall clock is consulted and omitted validity defaults to currently
  valid with no expiry behavior.
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

from ai.schemas.execution_control_result import (
    EXECUTION_ALLOW_REASONS,
    EXECUTION_AUTHORIZATION_REJECTION_REASONS,
    EXECUTION_CONTROL_LIMITATIONS,
    MAX_LIMITATIONS,
    MAX_REASONS,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import sanitize_finding_governance

CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION = "r58-2"
RULE_VERSION = CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION


def _safe_text(value: object, limit: int = 160) -> str:
    text = re.sub(
        r"[\x00-\x1f\x7f]+", " ", str(value if value is not None else "")
    )
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]

# ---------------------------------------------------------------------------
# Authorization status vocabulary (closed)
# ---------------------------------------------------------------------------

AUTHORIZATION_STATUS_NOT_REQUESTED = "NOT_REQUESTED"
AUTHORIZATION_STATUS_REQUESTED = "REQUESTED"
AUTHORIZATION_STATUS_BLOCKED = "BLOCKED"
AUTHORIZATION_STATUS_AUTHORIZED = "AUTHORIZED"
AUTHORIZATION_STATUS_EXPIRED = "EXPIRED"
AUTHORIZATION_STATUS_INVALID = "INVALID"

EXECUTION_AUTHORIZATION_STATUSES: tuple[str, ...] = (
    AUTHORIZATION_STATUS_NOT_REQUESTED,
    AUTHORIZATION_STATUS_REQUESTED,
    AUTHORIZATION_STATUS_BLOCKED,
    AUTHORIZATION_STATUS_AUTHORIZED,
    AUTHORIZATION_STATUS_EXPIRED,
    AUTHORIZATION_STATUS_INVALID,
)

# ---------------------------------------------------------------------------
# Authority vocabulary (closed; only HUMAN can authorize)
# ---------------------------------------------------------------------------

AUTHORIZATION_SOURCE_HUMAN = "HUMAN"
AUTHORIZATION_SOURCE_AI = "AI"
AUTHORIZATION_SOURCE_SYSTEM = "SYSTEM"
AUTHORIZATION_SOURCE_UNSPECIFIED = "UNSPECIFIED"

EXECUTION_AUTHORIZATION_SOURCES: tuple[str, ...] = (
    AUTHORIZATION_SOURCE_HUMAN,
    AUTHORIZATION_SOURCE_AI,
    AUTHORIZATION_SOURCE_SYSTEM,
    AUTHORIZATION_SOURCE_UNSPECIFIED,
)

AUTHORIZATION_AUTHORITY_HUMAN = "HUMAN"
AUTHORIZATION_AUTHORITY_AI = "AI"
AUTHORIZATION_AUTHORITY_SYSTEM = "SYSTEM"
AUTHORIZATION_AUTHORITY_UNSPECIFIED = "UNSPECIFIED"

EXECUTION_AUTHORIZATION_AUTHORITIES: tuple[str, ...] = (
    AUTHORIZATION_AUTHORITY_HUMAN,
    AUTHORIZATION_AUTHORITY_AI,
    AUTHORIZATION_AUTHORITY_SYSTEM,
    AUTHORIZATION_AUTHORITY_UNSPECIFIED,
)

# ---------------------------------------------------------------------------
# Validity vocabulary (closed; explicit structured metadata only)
# ---------------------------------------------------------------------------

VALIDITY_VALID = "VALID"
VALIDITY_EXPIRED = "EXPIRED"
VALIDITY_INVALID = "INVALID"
VALIDITY_UNSPECIFIED = "UNSPECIFIED"

AUTHORIZATION_VALIDITY_STATES: tuple[str, ...] = (
    VALIDITY_VALID,
    VALIDITY_EXPIRED,
    VALIDITY_INVALID,
    VALIDITY_UNSPECIFIED,
)

VALIDITY_BASIS_EXPLICIT = "EXPLICIT_METADATA"
VALIDITY_BASIS_DEFAULT = "DEFAULT_VALID_NO_EXPIRY"
VALIDITY_BASIS_UNSPECIFIED = "UNSPECIFIED"

AUTHORIZATION_VALIDITY_BASES: tuple[str, ...] = (
    VALIDITY_BASIS_EXPLICIT,
    VALIDITY_BASIS_DEFAULT,
    VALIDITY_BASIS_UNSPECIFIED,
)

# ---------------------------------------------------------------------------
# Approval constraint vocabulary (closed)
# ---------------------------------------------------------------------------

CONSTRAINT_RESEARCH_ONLY_ACTION = "RESEARCH_ONLY_ACTION"
CONSTRAINT_NO_NETWORK_EXECUTION = "NO_NETWORK_EXECUTION"
CONSTRAINT_NO_COMMAND_EXECUTION = "NO_COMMAND_EXECUTION"
CONSTRAINT_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
CONSTRAINT_SINGLE_ACTION = "SINGLE_ACTION"
CONSTRAINT_SINGLE_TARGET = "SINGLE_TARGET"
CONSTRAINT_SINGLE_SCOPE = "SINGLE_SCOPE"
CONSTRAINT_NO_SCOPE_EXPANSION = "NO_SCOPE_EXPANSION"
CONSTRAINT_NO_TARGET_EXPANSION = "NO_TARGET_EXPANSION"
CONSTRAINT_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
CONSTRAINT_FUTURE_EXECUTOR_REQUIRED = "FUTURE_EXECUTOR_REQUIRED"
CONSTRAINT_NO_AUTONOMOUS_AUTHORIZATION = "NO_AUTONOMOUS_AUTHORIZATION"

APPROVAL_CONSTRAINTS: tuple[str, ...] = (
    CONSTRAINT_RESEARCH_ONLY_ACTION,
    CONSTRAINT_NO_NETWORK_EXECUTION,
    CONSTRAINT_NO_COMMAND_EXECUTION,
    CONSTRAINT_NO_PAYLOAD_GENERATION,
    CONSTRAINT_SINGLE_ACTION,
    CONSTRAINT_SINGLE_TARGET,
    CONSTRAINT_SINGLE_SCOPE,
    CONSTRAINT_NO_SCOPE_EXPANSION,
    CONSTRAINT_NO_TARGET_EXPANSION,
    CONSTRAINT_HUMAN_REVIEW_REQUIRED,
    CONSTRAINT_FUTURE_EXECUTOR_REQUIRED,
    CONSTRAINT_NO_AUTONOMOUS_AUTHORIZATION,
)

#: Constraints the gate always attaches to every authorization record.
REQUIRED_APPROVAL_CONSTRAINTS: tuple[str, ...] = APPROVAL_CONSTRAINTS

# ---------------------------------------------------------------------------
# Decision vocabulary (read-only mirror of R56)
# ---------------------------------------------------------------------------

DECISION_TYPE_APPROVE_RESEARCH = "APPROVE_RESEARCH"
DECISION_TYPE_REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
DECISION_TYPE_DEFER = "DEFER"
DECISION_TYPE_REJECT = "REJECT"
DECISION_TYPE_ESCALATE = "ESCALATE"
DECISION_TYPE_NEEDS_REVIEW = "NEEDS_REVIEW"

EXECUTION_DECISION_TYPES: tuple[str, ...] = (
    DECISION_TYPE_APPROVE_RESEARCH,
    DECISION_TYPE_REQUEST_MORE_EVIDENCE,
    DECISION_TYPE_DEFER,
    DECISION_TYPE_REJECT,
    DECISION_TYPE_ESCALATE,
    DECISION_TYPE_NEEDS_REVIEW,
)

DECISION_STATE_DECIDED = "DECIDED"
DECISION_STATE_PENDING = "PENDING_HUMAN_REVIEW"
DECISION_STATE_EXPIRED = "EXPIRED"
DECISION_STATE_INVALID = "INVALID"

EXECUTION_DECISION_STATES: tuple[str, ...] = (
    DECISION_STATE_DECIDED,
    DECISION_STATE_PENDING,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_INVALID,
)

# ---------------------------------------------------------------------------
# Limitations (closed; shared gate vocabulary)
# ---------------------------------------------------------------------------

EXECUTION_AUTHORIZATION_LIMITATIONS: tuple[str, ...] = (
    EXECUTION_CONTROL_LIMITATIONS
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

AUTHORIZATION_ID_PREFIX = "exa-"
AUTHORIZATION_ID_RE = re.compile(r"^exa-[0-9a-f]{16}$")

MAX_APPROVAL_CONSTRAINTS = len(APPROVAL_CONSTRAINTS)
MAX_VALUE_LEN = 160
MAX_SCOPE_LEN = 240


def _ordered_authorization_reasons(codes: object) -> list[str]:
    return _ordered_codes(
        codes,
        EXECUTION_AUTHORIZATION_REJECTION_REASONS,
        MAX_REASONS,
    )


def _ordered_allow_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, EXECUTION_ALLOW_REASONS, MAX_REASONS)


def _ordered_constraints(codes: object) -> list[str]:
    return _ordered_codes(codes, APPROVAL_CONSTRAINTS, MAX_APPROVAL_CONSTRAINTS)


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, EXECUTION_AUTHORIZATION_LIMITATIONS, MAX_LIMITATIONS
    )


def normalize_authorization_text(value: object, limit: int = MAX_SCOPE_LEN) -> str:
    """Deterministic bounded text normalization for targets and scopes."""

    return _safe_text(value, limit).strip()


def sanitize_authorization_validity(value: object) -> dict:
    """Project explicit, deterministic validity metadata onto fixed keys.

    No wall clock is consulted: validity is either explicitly structured by
    the caller or defaults to ``VALID`` with no expiry behavior.
    """

    if not isinstance(value, dict) or not value:
        return {
            "validity_state": VALIDITY_VALID,
            "validity_basis": VALIDITY_BASIS_DEFAULT,
            "expires": False,
            "research_only": True,
        }
    raw_state = _safe_text(value.get("validity_state")).strip().upper()
    if raw_state in AUTHORIZATION_VALIDITY_STATES:
        state = raw_state
        basis = (
            VALIDITY_BASIS_UNSPECIFIED
            if state == VALIDITY_UNSPECIFIED
            else VALIDITY_BASIS_EXPLICIT
        )
    else:
        state = VALIDITY_VALID
        basis = VALIDITY_BASIS_DEFAULT
    return {
        "validity_state": state,
        "validity_basis": basis,
        "expires": state == VALIDITY_EXPIRED,
        "research_only": True,
    }


def sanitize_authorization_context(value: object) -> dict:
    """Project the supplied explicit human authorization context.

    The context preserves the *claimed* source and authority verbatim (bounded
    and uppercased) so that AI-originated or autonomous claims remain visible
    as evidence; it never coerces them into human authority.
    """

    if not isinstance(value, dict) or not value:
        return {
            "present": False,
            "authorization_source": "",
            "authorization_authority": "",
            "decision_reference": "",
            "approved_action": "",
            "approved_scope": "",
            "approved_target": "",
            "approval_constraints": [],
            "validity": sanitize_authorization_validity(None),
            "research_only": True,
        }
    return {
        "present": True,
        "authorization_source": _safe_text(
            value.get("authorization_source")
        ).strip().upper(),
        "authorization_authority": _safe_text(
            value.get("authorization_authority")
        ).strip().upper(),
        "decision_reference": _safe_text(value.get("decision_reference")),
        "approved_action": _safe_text(
            value.get("approved_action")
        ).strip().upper(),
        "approved_scope": normalize_authorization_text(
            value.get("approved_scope")
        ),
        "approved_target": normalize_authorization_text(
            value.get("approved_target")
        ),
        "approval_constraints": _ordered_constraints(
            value.get("approval_constraints")
        ),
        "validity": sanitize_authorization_validity(value.get("validity")),
        "research_only": True,
    }


def sanitize_execution_authorization(value: object) -> dict:
    """Project an R58 execution authorization onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_authorization()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "request_id": _safe_text(value.get("request_id")),
        "finding_id": finding_id,
        "authorization_status": _closed(
            value.get("authorization_status"),
            EXECUTION_AUTHORIZATION_STATUSES,
            AUTHORIZATION_STATUS_INVALID,
        ),
        "authorization_source": _closed(
            value.get("authorization_source"),
            EXECUTION_AUTHORIZATION_SOURCES,
            AUTHORIZATION_SOURCE_UNSPECIFIED,
        ),
        "authorization_authority": _closed(
            value.get("authorization_authority"),
            EXECUTION_AUTHORIZATION_AUTHORITIES,
            AUTHORIZATION_AUTHORITY_UNSPECIFIED,
        ),
        "human_authority": bool(value.get("human_authority")) is True,
        "decision_reference": _safe_text(value.get("decision_reference")),
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
        "approved_action": _safe_text(
            value.get("approved_action")
        ).strip().upper(),
        "approved_scope": normalize_authorization_text(
            value.get("approved_scope")
        ),
        "approved_target": normalize_authorization_text(
            value.get("approved_target")
        ),
        "approval_constraints": _ordered_constraints(
            value.get("approval_constraints")
        ),
        "allow_reasons": _ordered_allow_reasons(value.get("allow_reasons")),
        "rejection_codes": _ordered_authorization_reasons(
            value.get("rejection_codes")
        ),
        "validity": sanitize_authorization_validity(value.get("validity")),
        "authorization_context": sanitize_authorization_context(
            value.get("authorization_context")
        ),
        "execution_authorized": bool(
            value.get("execution_authorized")
        )
        is True,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "provenance": sanitize_authorization_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _default_authorization() -> dict:
    return {
        "rule_version": "",
        "authorization_id": "",
        "request_id": "",
        "finding_id": "",
        "authorization_status": AUTHORIZATION_STATUS_NOT_REQUESTED,
        "authorization_source": AUTHORIZATION_SOURCE_UNSPECIFIED,
        "authorization_authority": AUTHORIZATION_AUTHORITY_UNSPECIFIED,
        "human_authority": False,
        "decision_reference": "",
        "decision_type": "",
        "decision_state": "",
        "approved_action": "",
        "approved_scope": "",
        "approved_target": "",
        "approval_constraints": [],
        "allow_reasons": [],
        "rejection_codes": [],
        "validity": sanitize_authorization_validity(None),
        "authorization_context": sanitize_authorization_context(None),
        "execution_authorized": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "provenance": sanitize_authorization_provenance(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


def sanitize_authorization_provenance(value: object) -> dict:
    """Project authorization provenance onto fixed bounded keys."""

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
            "deterministic": True,
            "research_only": True,
        }
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
        "deterministic": True,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ControlledExecutionAuthorizationPlan(BaseModel):
    """Deterministic R58 controlled-execution authorization (R58.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION
    authorization_id: str
    request_id: str = ""
    finding_id: str = ""
    authorization_status: str = AUTHORIZATION_STATUS_NOT_REQUESTED
    authorization_source: str = AUTHORIZATION_SOURCE_UNSPECIFIED
    authorization_authority: str = AUTHORIZATION_AUTHORITY_UNSPECIFIED
    human_authority: bool = False
    decision_reference: str = ""
    decision_type: str = ""
    decision_state: str = ""
    approved_action: str = ""
    approved_scope: str = ""
    approved_target: str = ""
    approval_constraints: list[str] = Field(default_factory=list)
    allow_reasons: list[str] = Field(default_factory=list)
    rejection_codes: list[str] = Field(default_factory=list)
    validity: dict = Field(default_factory=dict)
    authorization_context: dict = Field(default_factory=dict)
    execution_authorized: bool = False
    exploit_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION

    @field_validator("authorization_id")
    @classmethod
    def _valid_authorization_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not AUTHORIZATION_ID_RE.match(text):
            raise ValueError(f"malformed authorization_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("authorization_status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_AUTHORIZATION_STATUSES:
            raise ValueError(f"invalid authorization_status: {value!r}")
        return text

    @field_validator("authorization_source")
    @classmethod
    def _valid_source(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_AUTHORIZATION_SOURCES:
            raise ValueError(f"invalid authorization_source: {value!r}")
        return text

    @field_validator("authorization_authority")
    @classmethod
    def _valid_authority(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_AUTHORIZATION_AUTHORITIES:
            raise ValueError(f"invalid authorization_authority: {value!r}")
        return text

    @field_validator("decision_type")
    @classmethod
    def _valid_decision_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in EXECUTION_DECISION_TYPES:
            raise ValueError(f"invalid decision_type: {value!r}")
        return text

    @field_validator("decision_state")
    @classmethod
    def _valid_decision_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in EXECUTION_DECISION_STATES:
            raise ValueError(f"invalid decision_state: {value!r}")
        return text

    @field_validator("approval_constraints")
    @classmethod
    def _bounded_constraints(cls, value: object) -> list[str]:
        return _ordered_constraints(value)

    @field_validator("allow_reasons")
    @classmethod
    def _bounded_allow_reasons(cls, value: object) -> list[str]:
        return _ordered_allow_reasons(value)

    @field_validator("rejection_codes")
    @classmethod
    def _bounded_rejection_codes(cls, value: object) -> list[str]:
        return _ordered_authorization_reasons(value)

    @field_validator("validity")
    @classmethod
    def _bounded_validity(cls, value: object) -> dict:
        return sanitize_authorization_validity(value)

    @field_validator("authorization_context")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_authorization_context(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_authorization_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("exploit_authorized", "vulnerability_confirmed")
    @classmethod
    def _never_exploited(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "controlled execution authorization never exploits or "
                "confirms"
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
            raise ValueError("execution authorizations are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("execution authorizations are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_authority(self) -> "ControlledExecutionAuthorizationPlan":
        if self.authorization_status == AUTHORIZATION_STATUS_AUTHORIZED:
            if self.authorization_source != AUTHORIZATION_SOURCE_HUMAN:
                raise ValueError("authorized execution requires a human source")
            if (
                self.authorization_authority
                != AUTHORIZATION_AUTHORITY_HUMAN
            ):
                raise ValueError(
                    "authorized execution requires human authority"
                )
            if self.human_authority is not True:
                raise ValueError(
                    "authorized execution requires explicit human authority"
                )
            if self.execution_authorized is not True:
                raise ValueError(
                    "authorized status requires execution_authorized"
                )
            if self.rejection_codes:
                raise ValueError(
                    "authorized execution cannot carry rejection codes"
                )
        elif self.execution_authorized is not False:
            raise ValueError(
                "only an authorized record may authorize execution"
            )
        return self


def controlled_execution_authorization_plan_projection(
    value: ControlledExecutionAuthorizationPlan,
) -> dict:
    """Serialize an R58 authorization to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION",
    "RULE_VERSION",
    "AUTHORIZATION_STATUS_NOT_REQUESTED",
    "AUTHORIZATION_STATUS_REQUESTED",
    "AUTHORIZATION_STATUS_BLOCKED",
    "AUTHORIZATION_STATUS_AUTHORIZED",
    "AUTHORIZATION_STATUS_EXPIRED",
    "AUTHORIZATION_STATUS_INVALID",
    "EXECUTION_AUTHORIZATION_STATUSES",
    "AUTHORIZATION_SOURCE_HUMAN",
    "AUTHORIZATION_SOURCE_AI",
    "AUTHORIZATION_SOURCE_SYSTEM",
    "AUTHORIZATION_SOURCE_UNSPECIFIED",
    "EXECUTION_AUTHORIZATION_SOURCES",
    "AUTHORIZATION_AUTHORITY_HUMAN",
    "AUTHORIZATION_AUTHORITY_AI",
    "AUTHORIZATION_AUTHORITY_SYSTEM",
    "AUTHORIZATION_AUTHORITY_UNSPECIFIED",
    "EXECUTION_AUTHORIZATION_AUTHORITIES",
    "VALIDITY_VALID",
    "VALIDITY_EXPIRED",
    "VALIDITY_INVALID",
    "VALIDITY_UNSPECIFIED",
    "AUTHORIZATION_VALIDITY_STATES",
    "VALIDITY_BASIS_EXPLICIT",
    "VALIDITY_BASIS_DEFAULT",
    "VALIDITY_BASIS_UNSPECIFIED",
    "AUTHORIZATION_VALIDITY_BASES",
    "CONSTRAINT_RESEARCH_ONLY_ACTION",
    "CONSTRAINT_NO_NETWORK_EXECUTION",
    "CONSTRAINT_NO_COMMAND_EXECUTION",
    "CONSTRAINT_NO_PAYLOAD_GENERATION",
    "CONSTRAINT_SINGLE_ACTION",
    "CONSTRAINT_SINGLE_TARGET",
    "CONSTRAINT_SINGLE_SCOPE",
    "CONSTRAINT_NO_SCOPE_EXPANSION",
    "CONSTRAINT_NO_TARGET_EXPANSION",
    "CONSTRAINT_HUMAN_REVIEW_REQUIRED",
    "CONSTRAINT_FUTURE_EXECUTOR_REQUIRED",
    "CONSTRAINT_NO_AUTONOMOUS_AUTHORIZATION",
    "APPROVAL_CONSTRAINTS",
    "REQUIRED_APPROVAL_CONSTRAINTS",
    "DECISION_TYPE_APPROVE_RESEARCH",
    "DECISION_TYPE_REQUEST_MORE_EVIDENCE",
    "DECISION_TYPE_DEFER",
    "DECISION_TYPE_REJECT",
    "DECISION_TYPE_ESCALATE",
    "DECISION_TYPE_NEEDS_REVIEW",
    "EXECUTION_DECISION_TYPES",
    "DECISION_STATE_DECIDED",
    "DECISION_STATE_PENDING",
    "DECISION_STATE_EXPIRED",
    "DECISION_STATE_INVALID",
    "EXECUTION_DECISION_STATES",
    "EXECUTION_AUTHORIZATION_LIMITATIONS",
    "AUTHORIZATION_ID_PREFIX",
    "AUTHORIZATION_ID_RE",
    "MAX_APPROVAL_CONSTRAINTS",
    "MAX_VALUE_LEN",
    "MAX_SCOPE_LEN",
    "normalize_authorization_text",
    "sanitize_authorization_validity",
    "sanitize_authorization_context",
    "sanitize_authorization_provenance",
    "sanitize_execution_authorization",
    "ControlledExecutionAuthorizationPlan",
    "controlled_execution_authorization_plan_projection",
]

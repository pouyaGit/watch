"""Security research workflow request schema (Stage R59.1).

Defines the bounded, deterministic request of the R59 end-to-end security
research workflow. It answers:

    "Which existing structured research artifacts and options describe this
     workflow run?"

Hard boundaries encoded here:

- Workflow metadata only: the request references existing artifacts; it never
  contains commands, payloads, targets-to-attack, credentials or execution
  instructions. ``execution_authorized``, ``vulnerability_confirmed`` and
  ``exploit_authorized`` are forced ``False``.
- Reference-based: research/specialist/finding/human/execution contexts carry
  bounded identifiers and closed codes, never raw target data.
- Partial workflows are first-class: every context is optional, so the
  workflow can honestly represent partial state.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no subprocess, no execution of any kind
is represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.execution_control_result import (
    CONTROL_OUTCOMES,
    SAFETY_RESULTS,
)
from ai.schemas.human_decision import HUMAN_DECISION_TYPES

SECURITY_RESEARCH_WORKFLOW_RULE_VERSION = "r59-1"
RULE_VERSION = SECURITY_RESEARCH_WORKFLOW_RULE_VERSION

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

WORKFLOW_ID_PREFIX = "wfr-"
WORKFLOW_ID_RE = re.compile(r"^wfr-[0-9a-f]{16}$")

MAX_VALUE_LEN = 160
MAX_LIST = 24
MAX_LIMITATIONS = 16
MAX_DEPTH = 4
MAX_MAPPING_KEYS = 32

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


def _bounded_ids(value: object, limit: int, pattern: str) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(pattern, text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_value(value: object, depth: int = 0) -> object:
    """Deep-bound arbitrary caller input (no I/O, no execution semantics)."""

    if depth > MAX_DEPTH:
        return ""
    if isinstance(value, dict):
        out: dict = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_MAPPING_KEYS:
                break
            text_key = _safe_text(key, 80)
            if text_key:
                out[text_key] = _bounded_value(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [
            _bounded_value(item, depth + 1) for item in list(value)[:MAX_LIST]
        ]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return max(-10**9, min(10**9, value))
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return _safe_text(value, 240)
    return ""


def sanitize_bounded_mapping(value: object) -> dict:
    """Project arbitrary caller input onto a bounded mapping."""

    if not isinstance(value, dict) or not value:
        return {}
    projected = _bounded_value(value)
    return projected if isinstance(projected, dict) else {}


# ---------------------------------------------------------------------------
# Workflow option vocabulary (closed)
# ---------------------------------------------------------------------------

OPTION_ENABLE_LEARNING = "enable_learning"
OPTION_ENABLE_EXECUTION_REVIEW = "enable_execution_review"
OPTION_REQUIRE_HUMAN_DECISION = "require_human_decision"
OPTION_STAGE_ORDER_FIXED = "stage_order_fixed"

WORKFLOW_OPTION_KEYS: tuple[str, ...] = (
    OPTION_ENABLE_LEARNING,
    OPTION_ENABLE_EXECUTION_REVIEW,
    OPTION_REQUIRE_HUMAN_DECISION,
    OPTION_STAGE_ORDER_FIXED,
)

#: Options that cannot be disabled (human boundary and fixed stage order).
FORCED_TRUE_OPTIONS: tuple[str, ...] = (
    OPTION_REQUIRE_HUMAN_DECISION,
    OPTION_STAGE_ORDER_FIXED,
)

CONFIGURABLE_OPTIONS: tuple[str, ...] = (
    OPTION_ENABLE_LEARNING,
    OPTION_ENABLE_EXECUTION_REVIEW,
)


def sanitize_workflow_options(value: object) -> dict:
    """Project the bounded workflow options onto closed boolean keys."""

    source = value if isinstance(value, dict) else {}
    out: dict = {}
    for key in CONFIGURABLE_OPTIONS:
        raw = source.get(key)
        out[key] = True if raw is None else raw is True
    for key in FORCED_TRUE_OPTIONS:
        out[key] = True
    return out


# ---------------------------------------------------------------------------
# Context projections (reference-based)
# ---------------------------------------------------------------------------


def sanitize_specialist_context(value: object) -> dict:
    """Project specialist-stage references onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "specialist_count": 0,
            "selected_specialists": [],
            "specialist_ids": [],
            "orchestration_id": "",
            "orchestration_rule_version": "",
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True
        or bool(value.get("specialist_count"))
        or bool(value.get("orchestration_id")),
        "specialist_count": _bounded_int(
            value.get("specialist_count"), 0, MAX_LIST
        ),
        "selected_specialists": _bounded_strings(
            value.get("selected_specialists"), MAX_LIST, 40
        ),
        "specialist_ids": _bounded_strings(
            value.get("specialist_ids"), MAX_LIST, 80
        ),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "orchestration_rule_version": _safe_text(
            value.get("orchestration_rule_version")
        ),
        "research_only": True,
    }


def sanitize_finding_context(value: object) -> dict:
    """Project finding-stage references onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "finding_count": 0,
            "finding_ids": [],
            "finding_status": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True
        or bool(value.get("finding_count")),
        "finding_count": _bounded_int(
            value.get("finding_count"), 0, MAX_LIST
        ),
        "finding_ids": _bounded_ids(
            value.get("finding_ids"), MAX_LIST, r"^fnd-[0-9a-f]{16}$"
        ),
        "finding_status": _safe_text(value.get("finding_status")).upper(),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "research_only": True,
    }


def sanitize_human_context(value: object) -> dict:
    """Project human-boundary references onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "review_result_id": "",
            "decision_ids": [],
            "decision_types": [],
            "decision_state": "",
            "human_authority": False,
            "execution_authorized": False,
            "vulnerability_confirmed": False,
            "decision_rule_version": "",
            "research_only": True,
        }
    types = []
    for item in value.get("decision_types") or ():
        text = _safe_text(item).strip().upper()
        if text in HUMAN_DECISION_TYPES and text not in types:
            types.append(text)
    return {
        "present": bool(value.get("present")) is True
        or bool(value.get("review_result_id")),
        "review_result_id": _safe_text(value.get("review_result_id")),
        "decision_ids": _bounded_ids(
            value.get("decision_ids"), MAX_LIST, r"^hdc-[0-9a-f]{16}$"
        ),
        "decision_types": types[:MAX_LIST],
        "decision_state": _safe_text(value.get("decision_state")).upper(),
        "human_authority": bool(value.get("human_authority")) is True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "research_only": True,
    }


def sanitize_execution_context(value: object) -> dict:
    """Project execution-control references onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "control_id": "",
            "request_id": "",
            "authorization_id": "",
            "control_outcome": "",
            "authorization_status": "",
            "execution_status": "",
            "safety_result": "",
            "request_rule_version": "",
            "authorization_rule_version": "",
            "control_rule_version": "",
            "execution_authorized": False,
            "execution_performed": False,
            "vulnerability_confirmed": False,
            "exploit_authorized": False,
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True
        or bool(value.get("control_id")),
        "control_id": _safe_text(value.get("control_id")),
        "request_id": _safe_text(value.get("request_id")),
        "authorization_id": _safe_text(value.get("authorization_id")),
        "control_outcome": _closed(
            value.get("control_outcome"), CONTROL_OUTCOMES, ""
        ),
        "authorization_status": _safe_text(
            value.get("authorization_status")
        ).upper(),
        "execution_status": _safe_text(
            value.get("execution_status")
        ).upper(),
        "safety_result": _closed(
            value.get("safety_result"), SAFETY_RESULTS, ""
        ),
        "request_rule_version": _safe_text(
            value.get("request_rule_version")
        ),
        "authorization_rule_version": _safe_text(
            value.get("authorization_rule_version")
        ),
        "control_rule_version": _safe_text(
            value.get("control_rule_version")
        ),
        "execution_authorized": False,
        "execution_performed": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_PARTIAL_WORKFLOW_SUPPORTED = "PARTIAL_WORKFLOW_SUPPORTED"
LIMITATION_UPSTREAM_REFERENCES_BOUNDED = "UPSTREAM_REFERENCES_BOUNDED"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_NO_LLM_INVOLVEMENT = "NO_LLM_INVOLVEMENT"

WORKFLOW_REQUEST_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_PARTIAL_WORKFLOW_SUPPORTED,
    LIMITATION_UPSTREAM_REFERENCES_BOUNDED,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_NO_LLM_INVOLVEMENT,
)


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in WORKFLOW_REQUEST_LIMITATIONS:
            found.add(text)
    return [
        code for code in WORKFLOW_REQUEST_LIMITATIONS if code in found
    ][:MAX_LIMITATIONS]


def sanitize_workflow_request_provenance(value: object) -> dict:
    """Project request provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "request_rule_version": SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
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
        "request_rule_version": SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
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


def sanitize_workflow_request(value: object) -> dict:
    """Project an R59 workflow request onto its fixed key set."""

    if not isinstance(value, dict):
        return _default_request()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "workflow_id": _safe_text(value.get("workflow_id")),
        "workflow_input": sanitize_bounded_mapping(value.get("workflow_input")),
        "research_context": sanitize_bounded_mapping(
            value.get("research_context")
        ),
        "specialist_context": sanitize_specialist_context(
            value.get("specialist_context")
        ),
        "finding_context": sanitize_finding_context(
            value.get("finding_context")
        ),
        "human_context": sanitize_human_context(value.get("human_context")),
        "execution_context": sanitize_execution_context(
            value.get("execution_context")
        ),
        "workflow_options": sanitize_workflow_options(
            value.get("workflow_options")
        ),
        "provenance": sanitize_workflow_request_provenance(
            value.get("provenance")
        ),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations")),
        "execution_requested": False,
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
        "workflow_id": "",
        "workflow_input": {},
        "research_context": {},
        "specialist_context": sanitize_specialist_context(None),
        "finding_context": sanitize_finding_context(None),
        "human_context": sanitize_human_context(None),
        "execution_context": sanitize_execution_context(None),
        "workflow_options": sanitize_workflow_options(None),
        "provenance": sanitize_workflow_request_provenance(None),
        "governance": {},
        "limitations": list(WORKFLOW_REQUEST_LIMITATIONS),
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


class SecurityResearchWorkflowRequestPlan(BaseModel):
    """Deterministic R59 security research workflow request (R59.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_RESEARCH_WORKFLOW_RULE_VERSION
    workflow_id: str
    workflow_input: dict = Field(default_factory=dict)
    research_context: dict = Field(default_factory=dict)
    specialist_context: dict = Field(default_factory=dict)
    finding_context: dict = Field(default_factory=dict)
    human_context: dict = Field(default_factory=dict)
    execution_context: dict = Field(default_factory=dict)
    workflow_options: dict = Field(default_factory=dict)
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
        return SECURITY_RESEARCH_WORKFLOW_RULE_VERSION

    @field_validator("workflow_id")
    @classmethod
    def _valid_workflow_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not WORKFLOW_ID_RE.match(text):
            raise ValueError(f"malformed workflow_id: {value!r}")
        return text

    @field_validator("specialist_context")
    @classmethod
    def _bounded_specialist(cls, value: object) -> dict:
        return sanitize_specialist_context(value)

    @field_validator("finding_context")
    @classmethod
    def _bounded_finding(cls, value: object) -> dict:
        return sanitize_finding_context(value)

    @field_validator("human_context")
    @classmethod
    def _bounded_human(cls, value: object) -> dict:
        return sanitize_human_context(value)

    @field_validator("execution_context")
    @classmethod
    def _bounded_execution(cls, value: object) -> dict:
        return sanitize_execution_context(value)

    @field_validator("workflow_options")
    @classmethod
    def _bounded_options(cls, value: object) -> dict:
        return sanitize_workflow_options(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_workflow_request_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator(
        "execution_requested",
        "execution_authorized",
        "vulnerability_confirmed",
        "exploit_authorized",
    )
    @classmethod
    def _never_requests_execution(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "workflow requests never request, authorize, confirm or "
                "exploit"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("workflow requests never confirm")
        return "NOT_CONFIRMED"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("workflow requests are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("workflow requests are deterministic")
        return True


def security_research_workflow_request_projection(
    value: SecurityResearchWorkflowRequestPlan,
) -> dict:
    """Serialize an R59 workflow request to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_RESEARCH_WORKFLOW_RULE_VERSION",
    "RULE_VERSION",
    "WORKFLOW_ID_PREFIX",
    "WORKFLOW_ID_RE",
    "MAX_VALUE_LEN",
    "MAX_LIST",
    "MAX_LIMITATIONS",
    "MAX_DEPTH",
    "MAX_MAPPING_KEYS",
    "OPTION_ENABLE_LEARNING",
    "OPTION_ENABLE_EXECUTION_REVIEW",
    "OPTION_REQUIRE_HUMAN_DECISION",
    "OPTION_STAGE_ORDER_FIXED",
    "WORKFLOW_OPTION_KEYS",
    "FORCED_TRUE_OPTIONS",
    "CONFIGURABLE_OPTIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_HUMAN_AUTHORITY_REQUIRED",
    "LIMITATION_PARTIAL_WORKFLOW_SUPPORTED",
    "LIMITATION_UPSTREAM_REFERENCES_BOUNDED",
    "LIMITATION_NO_WALL_CLOCK_METADATA",
    "LIMITATION_NO_LLM_INVOLVEMENT",
    "WORKFLOW_REQUEST_LIMITATIONS",
    "sanitize_bounded_mapping",
    "sanitize_workflow_options",
    "sanitize_specialist_context",
    "sanitize_finding_context",
    "sanitize_human_context",
    "sanitize_execution_context",
    "sanitize_workflow_request_provenance",
    "sanitize_workflow_request",
    "SecurityResearchWorkflowRequestPlan",
    "security_research_workflow_request_projection",
]

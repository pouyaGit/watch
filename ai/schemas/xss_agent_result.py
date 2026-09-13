"""XSS agent result schema (Stage R39.5).

An :class:`XSSAgentResultPlan` is the standard, R38-compatible descriptive
output of the XSS specialist research agent. It answers the research question:

    "What did the XSS research agent conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Research intelligence only: no payload storage, no exploit output, no
  execution logs, no HTTP, no browser/JavaScript, no fuzzing, no
  exploitation, no persistence, no worker or scheduler.
- R38 compatible: status and confidence reuse the R38 result vocabularies,
  and the plan projects onto a valid ``SecurityAgentResultPlan``.
- R37 integrated: ``governance_reference`` is a bounded reference to the R37
  governance export (provenance/rule-trace/audit/explanation states).
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.decision_provenance import PROVENANCE_STATES
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.governance_rule_trace import TRACE_STATES
from ai.schemas.research_audit_event import AUDIT_STATES
from ai.schemas.research_explanation import EXPLANATION_STATES
from ai.schemas.research_governance_export import (
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
)
from ai.schemas.security_agent_result import (
    AGENT_RESULT_STATUSES,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_FAILED,
    STATUS_UNKNOWN,
)
from ai.schemas.xss_context_analysis import (
    sanitize_xss_context_analysis_plan,
)
from ai.schemas.xss_evidence_plan import sanitize_xss_evidence_plan
from ai.schemas.xss_hypothesis import sanitize_xss_hypothesis_plan

XSS_AGENT_RESULT_RULE_VERSION = "r39-5"
RULE_VERSION = XSS_AGENT_RESULT_RULE_VERSION

XSS_AGENT_STATUSES: tuple[str, ...] = AGENT_RESULT_STATUSES

# ---------------------------------------------------------------------------
# Governance reference (R37 integration)
# ---------------------------------------------------------------------------

GOVERNANCE_REFERENCED = "REFERENCED"
GOVERNANCE_UNKNOWN = "UNKNOWN"

GOVERNANCE_REFERENCE_STATES: tuple[str, ...] = (
    GOVERNANCE_REFERENCED,
    GOVERNANCE_UNKNOWN,
)

GOVERNANCE_REFERENCE_KEYS: tuple[str, ...] = (
    "rule_version",
    "ready",
    "provenance_state",
    "trace_state",
    "audit_state",
    "explanation_state",
    "reference_state",
)

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_RESULT_UNKNOWN = "RESULT_UNKNOWN"

XSS_AGENT_RESULT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_RESULT_UNKNOWN,
)

MAX_HYPOTHESES = 2
MAX_LIMITATIONS = 7
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_governance_reference(value: object) -> dict:
    """Project an R37 governance reference onto fixed bounded keys.

    A reference is ``REFERENCED`` only when it carries the R37 export rule
    version; anything else (missing, malformed, foreign version) degrades to
    ``UNKNOWN`` with ``ready=False`` and is never treated as valid
    governance.
    """

    unknown = {
        "rule_version": "",
        "ready": False,
        "provenance_state": "UNKNOWN",
        "trace_state": "UNKNOWN",
        "audit_state": "UNKNOWN",
        "explanation_state": "UNKNOWN",
        "reference_state": GOVERNANCE_UNKNOWN,
    }
    if not isinstance(value, dict):
        return unknown
    rule_version = _safe_text(value.get("rule_version"))
    if rule_version != RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION:
        return unknown
    reference_state = _closed(
        value.get("reference_state"),
        GOVERNANCE_REFERENCE_STATES,
        GOVERNANCE_UNKNOWN,
    )
    if reference_state != GOVERNANCE_REFERENCED:
        return unknown
    return {
        "rule_version": rule_version,
        "ready": bool(value.get("ready")) is True,
        "provenance_state": _closed(
            value.get("provenance_state"), PROVENANCE_STATES, "UNKNOWN"
        ),
        "trace_state": _closed(
            value.get("trace_state"), TRACE_STATES, "UNKNOWN"
        ),
        "audit_state": _closed(
            value.get("audit_state"), AUDIT_STATES, "UNKNOWN"
        ),
        "explanation_state": _closed(
            value.get("explanation_state"), EXPLANATION_STATES, "UNKNOWN"
        ),
        "reference_state": GOVERNANCE_REFERENCED,
    }


def _bounded_hypotheses(value: object) -> list[dict]:
    out: list[dict] = []
    raw = value if isinstance(value, (list, tuple)) else []
    for item in raw:
        if isinstance(item, dict):
            out.append(sanitize_xss_hypothesis_plan(item))
        if len(out) >= MAX_HYPOTHESES:
            break
    return out


def sanitize_xss_agent_result_plan(value: object) -> dict:
    """Project an R39.5 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_name": "",
            "status": "UNKNOWN",
            "context_analysis": sanitize_xss_context_analysis_plan(None),
            "hypotheses": [],
            "evidence_plan": sanitize_xss_evidence_plan(None),
            "confidence": "UNKNOWN",
            "limitations": [],
            "governance_reference": sanitize_governance_reference(None),
            "research_only": True,
        }
    status = _safe_text(value.get("status")).strip().upper()
    if status not in XSS_AGENT_STATUSES:
        status = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    hypotheses: list[dict] = []
    raw_hypotheses = value.get("hypotheses")
    if isinstance(raw_hypotheses, (list, tuple)):
        hypotheses = _bounded_hypotheses(raw_hypotheses)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_name": _safe_text(value.get("agent_name")),
        "status": status,
        "context_analysis": sanitize_xss_context_analysis_plan(
            value.get("context_analysis")
        ),
        "hypotheses": hypotheses,
        "evidence_plan": sanitize_xss_evidence_plan(
            value.get("evidence_plan")
        ),
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in XSS_AGENT_RESULT_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "governance_reference": sanitize_governance_reference(
            value.get("governance_reference")
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class XSSAgentResultPlan(BaseModel):
    """Deterministic R38-compatible XSS research agent result (R39.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = XSS_AGENT_RESULT_RULE_VERSION
    agent_name: str = ""
    status: str = "UNKNOWN"
    context_analysis: dict = Field(default_factory=dict)
    hypotheses: list[dict] = Field(default_factory=list)
    evidence_plan: dict = Field(default_factory=dict)
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    governance_reference: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return XSS_AGENT_RESULT_RULE_VERSION

    @field_validator("agent_name")
    @classmethod
    def _bounded_name(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in XSS_AGENT_STATUSES:
            raise ValueError(f"invalid status: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("context_analysis")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_xss_context_analysis_plan(value)

    @field_validator("hypotheses")
    @classmethod
    def _bounded_hypotheses_field(cls, value: list) -> list[dict]:
        return _bounded_hypotheses(value)

    @field_validator("evidence_plan")
    @classmethod
    def _bounded_evidence(cls, value: object) -> dict:
        return sanitize_xss_evidence_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, XSS_AGENT_RESULT_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("governance_reference")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_governance_reference(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("xss agent results are research-only")
        return True


def xss_agent_result_plan_projection(value: XSSAgentResultPlan) -> dict:
    """Serialize an XSS agent result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "XSS_AGENT_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "XSS_AGENT_STATUSES",
    "STATUS_CREATED",
    "STATUS_ANALYZING",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_UNKNOWN",
    "GOVERNANCE_REFERENCED",
    "GOVERNANCE_UNKNOWN",
    "GOVERNANCE_REFERENCE_STATES",
    "GOVERNANCE_REFERENCE_KEYS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_RESULT_UNKNOWN",
    "XSS_AGENT_RESULT_LIMITATIONS",
    "MAX_HYPOTHESES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_governance_reference",
    "sanitize_xss_agent_result_plan",
    "XSSAgentResultPlan",
    "xss_agent_result_plan_projection",
]

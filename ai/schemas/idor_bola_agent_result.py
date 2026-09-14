"""IDOR/BOLA agent result schema (Stage R46.5).

An :class:`IDORBOLAAgentResultPlan` is the standard, R38-compatible
descriptive output of the IDOR/BOLA specialist research agent. It answers the
research question:

    "What did the IDOR/BOLA research agent conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP request, no DNS resolution, no socket,
  no database, no scanner, no browser, no object access, no authorization
  bypass, no payload storage or generation, no execution logs, no
  persistence, no worker or scheduler.
- R38 compatible: status/confidence reuse the R38 result vocabularies and
  the result projects onto a valid ``SecurityAgentResultPlan``.
- R37 integrated: ``governance_reference`` is a bounded reference to the R37
  governance export; unknown governance is never treated as authorization
  readiness.
- Provenance: ``provenance`` records which R31-R37 input layers were supplied
  through the R38 read-only input contract; no layer is ever invented.
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
from ai.schemas.idor_bola_agent_identity import (
    sanitize_idor_bola_agent_identity_plan,
)
from ai.schemas.idor_bola_context_analysis import (
    sanitize_idor_bola_context_analysis_plan,
)
from ai.schemas.idor_bola_evidence_plan import (
    sanitize_idor_bola_evidence_plan,
)
from ai.schemas.idor_bola_hypothesis import sanitize_idor_bola_hypothesis_plan
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

IDOR_BOLA_AGENT_RESULT_RULE_VERSION = "r46-5"
RULE_VERSION = IDOR_BOLA_AGENT_RESULT_RULE_VERSION

IDOR_BOLA_AGENT_STATUSES: tuple[str, ...] = AGENT_RESULT_STATUSES

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
# Provenance reference (R31-R37 input layers)
# ---------------------------------------------------------------------------

PROVENANCE_REASONING = "REASONING"
PROVENANCE_MEMORY = "MEMORY"
PROVENANCE_STRATEGY = "STRATEGY"
PROVENANCE_ORCHESTRATION = "ORCHESTRATION"
PROVENANCE_AUTHORIZATION = "AUTHORIZATION"
PROVENANCE_GOVERNANCE = "GOVERNANCE"

PROVENANCE_LAYERS: tuple[str, ...] = (
    PROVENANCE_REASONING,
    PROVENANCE_MEMORY,
    PROVENANCE_STRATEGY,
    PROVENANCE_ORCHESTRATION,
    PROVENANCE_AUTHORIZATION,
    PROVENANCE_GOVERNANCE,
)

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_UNKNOWN = "UNKNOWN"

PROVENANCE_STATES_OUT: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)

PROVENANCE_REFERENCE_KEYS: tuple[str, ...] = (
    "rule_version",
    "source_layers",
    "provenance_state",
    "research_only",
)

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_AUTHORIZATION_BYPASS = "NO_AUTHORIZATION_BYPASS"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_TARGET_MODIFICATION = "NO_TARGET_MODIFICATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_RESULT_UNKNOWN = "RESULT_UNKNOWN"

IDOR_BOLA_AGENT_RESULT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_AUTHORIZATION_BYPASS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_TARGET_MODIFICATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_RESULT_UNKNOWN,
)

MAX_HYPOTHESES = 8
MAX_LIMITATIONS = 11
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
    version, the ``REFERENCED`` state and all four component records;
    anything else (missing, malformed, foreign version, component-less)
    degrades to ``UNKNOWN`` with ``ready=False`` and is never treated as
    valid governance or authorization readiness.
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
    if not all(
        key in value
        for key in (
            "provenance_state",
            "trace_state",
            "audit_state",
            "explanation_state",
        )
    ):
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


def sanitize_provenance(value: object) -> dict:
    """Project an R31-R37 provenance reference onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "source_layers": [],
            "provenance_state": PROVENANCE_UNKNOWN,
            "research_only": True,
        }
    source_layers: list[str] = []
    for item in value.get("source_layers") or ():
        text = _safe_text(item)
        if text in PROVENANCE_LAYERS and text not in source_layers:
            source_layers.append(text)
    provenance_state = _closed(
        value.get("provenance_state"),
        PROVENANCE_STATES_OUT,
        PROVENANCE_UNKNOWN,
    )
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "source_layers": source_layers,
        "provenance_state": provenance_state,
        "research_only": True,
    }


def _bounded_identity(value: object) -> dict:
    return sanitize_idor_bola_agent_identity_plan(value)


def _bounded_hypotheses(value: object) -> list[dict]:
    out: list[dict] = []
    raw = value if isinstance(value, (list, tuple)) else []
    for item in raw:
        if isinstance(item, dict):
            out.append(sanitize_idor_bola_hypothesis_plan(item))
        if len(out) >= MAX_HYPOTHESES:
            break
    return out


def sanitize_idor_bola_agent_result_plan(value: object) -> dict:
    """Project an R46.5 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_name": "",
            "agent_identity": {},
            "status": "UNKNOWN",
            "context_analysis": (
                sanitize_idor_bola_context_analysis_plan(None)
            ),
            "hypotheses": [],
            "evidence_plan": sanitize_idor_bola_evidence_plan(None),
            "confidence": "UNKNOWN",
            "limitations": [],
            "governance_reference": sanitize_governance_reference(None),
            "provenance": sanitize_provenance(None),
            "research_only": True,
        }
    status = _safe_text(value.get("status")).strip().upper()
    if status not in IDOR_BOLA_AGENT_STATUSES:
        status = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_name": _safe_text(value.get("agent_name")),
        "agent_identity": _bounded_identity(value.get("agent_identity")),
        "status": status,
        "context_analysis": sanitize_idor_bola_context_analysis_plan(
            value.get("context_analysis")
        ),
        "hypotheses": _bounded_hypotheses(value.get("hypotheses")),
        "evidence_plan": sanitize_idor_bola_evidence_plan(
            value.get("evidence_plan")
        ),
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in IDOR_BOLA_AGENT_RESULT_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "governance_reference": sanitize_governance_reference(
            value.get("governance_reference")
        ),
        "provenance": sanitize_provenance(value.get("provenance")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class IDORBOLAAgentResultPlan(BaseModel):
    """Deterministic R38-compatible IDOR/BOLA research agent result (R46.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = IDOR_BOLA_AGENT_RESULT_RULE_VERSION
    agent_name: str = ""
    agent_identity: dict = Field(default_factory=dict)
    status: str = "UNKNOWN"
    context_analysis: dict = Field(default_factory=dict)
    hypotheses: list[dict] = Field(default_factory=list)
    evidence_plan: dict = Field(default_factory=dict)
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    governance_reference: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return IDOR_BOLA_AGENT_RESULT_RULE_VERSION

    @field_validator("agent_name")
    @classmethod
    def _bounded_name(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IDOR_BOLA_AGENT_STATUSES:
            raise ValueError(f"invalid status: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("agent_identity")
    @classmethod
    def _bounded_identity_field(cls, value: object) -> dict:
        return _bounded_identity(value)

    @field_validator("context_analysis")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_idor_bola_context_analysis_plan(value)

    @field_validator("hypotheses")
    @classmethod
    def _bounded_hypotheses_field(cls, value: list) -> list[dict]:
        return _bounded_hypotheses(value)

    @field_validator("evidence_plan")
    @classmethod
    def _bounded_evidence(cls, value: object) -> dict:
        return sanitize_idor_bola_evidence_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, IDOR_BOLA_AGENT_RESULT_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("governance_reference")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_governance_reference(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_provenance(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("idor/bola agent results are research-only")
        return True


def idor_bola_agent_result_plan_projection(
    value: IDORBOLAAgentResultPlan,
) -> dict:
    """Serialize an IDOR/BOLA agent result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "IDOR_BOLA_AGENT_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "IDOR_BOLA_AGENT_STATUSES",
    "STATUS_CREATED",
    "STATUS_ANALYZING",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_UNKNOWN",
    "GOVERNANCE_REFERENCED",
    "GOVERNANCE_UNKNOWN",
    "GOVERNANCE_REFERENCE_STATES",
    "GOVERNANCE_REFERENCE_KEYS",
    "PROVENANCE_REASONING",
    "PROVENANCE_MEMORY",
    "PROVENANCE_STRATEGY",
    "PROVENANCE_ORCHESTRATION",
    "PROVENANCE_AUTHORIZATION",
    "PROVENANCE_GOVERNANCE",
    "PROVENANCE_LAYERS",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "PROVENANCE_STATES_OUT",
    "PROVENANCE_REFERENCE_KEYS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_AUTHORIZATION_BYPASS",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_TARGET_MODIFICATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_RESULT_UNKNOWN",
    "IDOR_BOLA_AGENT_RESULT_LIMITATIONS",
    "MAX_HYPOTHESES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_governance_reference",
    "sanitize_provenance",
    "sanitize_idor_bola_agent_result_plan",
    "IDORBOLAAgentResultPlan",
    "idor_bola_agent_result_plan_projection",
]

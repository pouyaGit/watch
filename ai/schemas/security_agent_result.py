"""Security agent result schema (Stage R38.5).

A :class:`SecurityAgentResultPlan` defines the standard descriptive output
format for future security specialist agents. It answers the framework
question:

    "What did this agent conceptually conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Framework/model only: results are descriptive research summaries. There
  are no exploit outputs, no payload storage, no execution logs, no tool or
  runtime activity.
- Closed vocabularies: status, confidence, findings summary, evidence
  summary and limitation codes are closed sets.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SECURITY_AGENT_RESULT_RULE_VERSION = "r38-5"
RULE_VERSION = SECURITY_AGENT_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_CREATED = "CREATED"
STATUS_ANALYZING = "ANALYZING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_UNKNOWN = "UNKNOWN"

AGENT_RESULT_STATUSES: tuple[str, ...] = (
    STATUS_CREATED,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_UNKNOWN,
)

FINDINGS_NONE = "NO_FINDINGS"
FINDINGS_OBSERVATIONS = "OBSERVATIONS_RECORDED"
FINDINGS_HYPOTHESES = "HYPOTHESES_RECORDED"
FINDINGS_UNKNOWN = "UNKNOWN"

FINDINGS_SUMMARIES: tuple[str, ...] = (
    FINDINGS_NONE,
    FINDINGS_OBSERVATIONS,
    FINDINGS_HYPOTHESES,
    FINDINGS_UNKNOWN,
)

EVIDENCE_NONE = "EVIDENCE_NONE"
EVIDENCE_PARTIAL = "EVIDENCE_PARTIAL"
EVIDENCE_SUFFICIENT = "EVIDENCE_SUFFICIENT"
EVIDENCE_UNKNOWN = "UNKNOWN"

EVIDENCE_SUMMARIES: tuple[str, ...] = (
    EVIDENCE_NONE,
    EVIDENCE_PARTIAL,
    EVIDENCE_SUFFICIENT,
    EVIDENCE_UNKNOWN,
)

LIMITATION_RESULT_UNKNOWN = "RESULT_UNKNOWN"
LIMITATION_CONFIDENCE_DOWNGRADED = "CONFIDENCE_DOWNGRADED"
LIMITATION_FINDINGS_SUPPRESSED = "FINDINGS_SUPPRESSED"
LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"

RESULT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_RESULT_UNKNOWN,
    LIMITATION_CONFIDENCE_DOWNGRADED,
    LIMITATION_FINDINGS_SUPPRESSED,
    LIMITATION_NO_EXECUTION_PERFORMED,
)

MAX_LIMITATIONS = 4
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


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


def sanitize_security_agent_result_plan(value: object) -> dict:
    """Project an R38.5 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_name": "",
            "status": "",
            "confidence": "",
            "findings_summary": "",
            "evidence_summary": "",
            "limitations": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_name": _safe_text(value.get("agent_name")),
        "status": _safe_text(value.get("status")),
        "confidence": _safe_text(value.get("confidence")),
        "findings_summary": _safe_text(value.get("findings_summary")),
        "evidence_summary": _safe_text(value.get("evidence_summary")),
        "limitations": _bounded_codes(
            value.get("limitations"), RESULT_LIMITATIONS, MAX_LIMITATIONS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentResultPlan(BaseModel):
    """Descriptive-only agent result contract (R38.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_RESULT_RULE_VERSION
    agent_name: str
    status: str
    confidence: str
    findings_summary: str
    evidence_summary: str
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_RESULT_RULE_VERSION

    @field_validator("agent_name")
    @classmethod
    def _bounded_name(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_RESULT_STATUSES:
            raise ValueError(f"invalid status: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("findings_summary")
    @classmethod
    def _valid_findings(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FINDINGS_SUMMARIES:
            raise ValueError(f"invalid findings_summary: {value!r}")
        return text

    @field_validator("evidence_summary")
    @classmethod
    def _valid_evidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_SUMMARIES:
            raise ValueError(f"invalid evidence_summary: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, RESULT_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("security agent results are research-only")
        return True


def security_agent_result_plan_projection(
    value: SecurityAgentResultPlan,
) -> dict:
    """Serialize an agent result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "AGENT_RESULT_STATUSES",
    "FINDINGS_SUMMARIES",
    "EVIDENCE_SUMMARIES",
    "RESULT_LIMITATIONS",
    "STATUS_CREATED",
    "STATUS_ANALYZING",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_UNKNOWN",
    "FINDINGS_NONE",
    "FINDINGS_OBSERVATIONS",
    "FINDINGS_HYPOTHESES",
    "FINDINGS_UNKNOWN",
    "EVIDENCE_NONE",
    "EVIDENCE_PARTIAL",
    "EVIDENCE_SUFFICIENT",
    "EVIDENCE_UNKNOWN",
    "LIMITATION_RESULT_UNKNOWN",
    "LIMITATION_CONFIDENCE_DOWNGRADED",
    "LIMITATION_FINDINGS_SUPPRESSED",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "SecurityAgentResultPlan",
    "sanitize_security_agent_result_plan",
    "security_agent_result_plan_projection",
]

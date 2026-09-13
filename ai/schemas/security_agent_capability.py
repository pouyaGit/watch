"""Security agent capability schema (Stage R38.2).

A :class:`SecurityAgentCapabilityPlan` defines WHAT a future security
specialist agent conceptually may do. It answers the framework question:

    "Which analysis-only capabilities may this agent use, and which
     execution capabilities are explicitly prohibited?"

Hard boundaries encoded here:

- Framework/model only: no agent runtime, execution, scanning, tooling, LLM
  call, plugin loading, dynamic import or persistence is represented or
  created.
- Execution is impossible by construction: only analysis/planning capability
  labels exist and every plan must explicitly list all prohibited execution
  capabilities. Allowed and prohibited vocabularies are disjoint.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_identity import AGENT_CATEGORIES

SECURITY_AGENT_CAPABILITY_RULE_VERSION = "r38-2"
RULE_VERSION = SECURITY_AGENT_CAPABILITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CAP_ANALYZE_CONTEXT = "ANALYZE_CONTEXT"
CAP_ANALYZE_PATTERN = "ANALYZE_PATTERN"
CAP_CREATE_HYPOTHESIS = "CREATE_HYPOTHESIS"
CAP_REQUEST_EVIDENCE = "REQUEST_EVIDENCE"
CAP_GENERATE_EXPLANATION = "GENERATE_EXPLANATION"
CAP_RANK_FINDINGS = "RANK_FINDINGS"

ALLOWED_CAPABILITIES: tuple[str, ...] = (
    CAP_ANALYZE_CONTEXT,
    CAP_ANALYZE_PATTERN,
    CAP_CREATE_HYPOTHESIS,
    CAP_REQUEST_EVIDENCE,
    CAP_GENERATE_EXPLANATION,
    CAP_RANK_FINDINGS,
)

PROHIBITED_EXECUTE_EXPLOIT = "EXECUTE_EXPLOIT"
PROHIBITED_RUN_PAYLOAD = "RUN_PAYLOAD"
PROHIBITED_BYPASS_AUTH = "BYPASS_AUTH"
PROHIBITED_MODIFY_TARGET = "MODIFY_TARGET"
PROHIBITED_AUTOMATE_ATTACK = "AUTOMATE_ATTACK"

PROHIBITED_CAPABILITIES: tuple[str, ...] = (
    PROHIBITED_EXECUTE_EXPLOIT,
    PROHIBITED_RUN_PAYLOAD,
    PROHIBITED_BYPASS_AUTH,
    PROHIBITED_MODIFY_TARGET,
    PROHIBITED_AUTOMATE_ATTACK,
)

CAPABILITY_VALID = "VALID"
CAPABILITY_PARTIAL = "PARTIAL"
CAPABILITY_UNKNOWN = "UNKNOWN"

CAPABILITY_STATES: tuple[str, ...] = (
    CAPABILITY_VALID,
    CAPABILITY_PARTIAL,
    CAPABILITY_UNKNOWN,
)

MAX_CAPABILITIES = 6
MAX_PROHIBITED = 5
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
            raise ValueError(f"invalid capability: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_security_agent_capability_plan(value: object) -> dict:
    """Project an R38.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_category": "",
            "allowed_capabilities": [],
            "prohibited_capabilities": [],
            "capability_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_category": _safe_text(value.get("agent_category")),
        "allowed_capabilities": _bounded_codes(
            value.get("allowed_capabilities"), ALLOWED_CAPABILITIES,
            MAX_CAPABILITIES,
        ),
        "prohibited_capabilities": _bounded_codes(
            value.get("prohibited_capabilities"), PROHIBITED_CAPABILITIES,
            MAX_PROHIBITED,
        ),
        "capability_state": _safe_text(value.get("capability_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentCapabilityPlan(BaseModel):
    """Deterministic security agent capability contract (R38.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_CAPABILITY_RULE_VERSION
    agent_category: str
    allowed_capabilities: list[str] = Field(default_factory=list)
    prohibited_capabilities: list[str] = Field(default_factory=list)
    capability_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_CAPABILITY_RULE_VERSION

    @field_validator("agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid agent_category: {value!r}")
        return text

    @field_validator("allowed_capabilities")
    @classmethod
    def _valid_allowed(cls, value: list) -> list[str]:
        return _require_codes(value, ALLOWED_CAPABILITIES, MAX_CAPABILITIES)

    @field_validator("prohibited_capabilities")
    @classmethod
    def _valid_prohibited(cls, value: list) -> list[str]:
        return _require_codes(
            value, PROHIBITED_CAPABILITIES, MAX_PROHIBITED
        )

    @field_validator("capability_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CAPABILITY_STATES:
            raise ValueError(f"invalid capability_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "security agent capabilities are research-only"
            )
        return True

    def model_post_init(self, __context: object) -> None:
        overlap = set(self.allowed_capabilities) & set(
            self.prohibited_capabilities
        )
        if overlap:
            raise ValueError(
                f"allowed and prohibited capabilities overlap: {overlap!r}"
            )


def security_agent_capability_plan_projection(
    value: SecurityAgentCapabilityPlan,
) -> dict:
    """Serialize a capability contract to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_CAPABILITY_RULE_VERSION",
    "RULE_VERSION",
    "ALLOWED_CAPABILITIES",
    "PROHIBITED_CAPABILITIES",
    "CAPABILITY_STATES",
    "CAP_ANALYZE_CONTEXT",
    "CAP_ANALYZE_PATTERN",
    "CAP_CREATE_HYPOTHESIS",
    "CAP_REQUEST_EVIDENCE",
    "CAP_GENERATE_EXPLANATION",
    "CAP_RANK_FINDINGS",
    "PROHIBITED_EXECUTE_EXPLOIT",
    "PROHIBITED_RUN_PAYLOAD",
    "PROHIBITED_BYPASS_AUTH",
    "PROHIBITED_MODIFY_TARGET",
    "PROHIBITED_AUTOMATE_ATTACK",
    "CAPABILITY_VALID",
    "CAPABILITY_PARTIAL",
    "CAPABILITY_UNKNOWN",
    "MAX_CAPABILITIES",
    "MAX_PROHIBITED",
    "MAX_VALUE_LEN",
    "SecurityAgentCapabilityPlan",
    "sanitize_security_agent_capability_plan",
    "security_agent_capability_plan_projection",
]

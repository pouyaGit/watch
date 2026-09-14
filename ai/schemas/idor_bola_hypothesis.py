"""IDOR/BOLA hypothesis schema (Stage R46.3).

An :class:`IDORBOLAHypothesisPlan` is a deterministic research hypothesis
about possible object-level authorization behavior. It answers the research
question:

    "Which IDOR/BOLA research hypothesis follows from the supplied context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no authorization-bypass claim, no payload, no attack sequence, no request,
  no browser, no database, no scanning, no execution.
- IDOR and BOLA are related authorization research concepts; a hypothesis is
  never a finding.
- Closed vocabularies: hypothesis type, supporting signals, confidence,
  priority and limitations are closed sets.
- Confidence and priority reuse the shared evidence-confidence vocabulary.
  Priority means "how useful is further research of this authorization
  hypothesis?"; it is NOT severity, exploitability, CVSS or vulnerability
  probability.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

IDOR_BOLA_HYPOTHESIS_RULE_VERSION = "r46-3"
RULE_VERSION = IDOR_BOLA_HYPOTHESIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed hypothesis vocabulary
# ---------------------------------------------------------------------------

TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP = "OBJECT_LEVEL_AUTHORIZATION_GAP"
TYPE_OWNERSHIP_BOUNDARY_GAP = "OWNERSHIP_BOUNDARY_GAP"
TYPE_TENANT_ISOLATION_GAP = "TENANT_ISOLATION_GAP"
TYPE_ROLE_BOUNDARY_GAP = "ROLE_BOUNDARY_GAP"
TYPE_DIRECT_OBJECT_REFERENCE = "DIRECT_OBJECT_REFERENCE"
TYPE_MISSING_AUTHORIZATION_CONTEXT = "MISSING_AUTHORIZATION_CONTEXT"
TYPE_AUTHORIZATION_CONTROL_PRESENT = "AUTHORIZATION_CONTROL_PRESENT"
TYPE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
    TYPE_OWNERSHIP_BOUNDARY_GAP,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_ROLE_BOUNDARY_GAP,
    TYPE_DIRECT_OBJECT_REFERENCE,
    TYPE_MISSING_AUTHORIZATION_CONTEXT,
    TYPE_AUTHORIZATION_CONTROL_PRESENT,
    TYPE_UNKNOWN,
)

GAP_HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
    TYPE_OWNERSHIP_BOUNDARY_GAP,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_ROLE_BOUNDARY_GAP,
)

# ---------------------------------------------------------------------------
# Closed supporting-signal vocabulary
# ---------------------------------------------------------------------------

SIGNAL_OBJECT_REFERENCE_PATH = "OBJECT_REFERENCE_PATH"
SIGNAL_OBJECT_REFERENCE_QUERY = "OBJECT_REFERENCE_QUERY"
SIGNAL_OBJECT_REFERENCE_BODY = "OBJECT_REFERENCE_BODY"
SIGNAL_OBJECT_REFERENCE_HEADER = "OBJECT_REFERENCE_HEADER"
SIGNAL_OBJECT_REFERENCE_COOKIE = "OBJECT_REFERENCE_COOKIE"
SIGNAL_RESOURCE_TYPE_PRESENT = "RESOURCE_TYPE_PRESENT"
SIGNAL_IDENTIFIER_OPAQUE = "IDENTIFIER_OPAQUE"
SIGNAL_IDENTIFIER_SEQUENTIAL = "IDENTIFIER_SEQUENTIAL_INTEGER"
SIGNAL_IDENTIFIER_UUID = "IDENTIFIER_UUID"
SIGNAL_IDENTIFIER_COMPOSITE = "IDENTIFIER_COMPOSITE"
SIGNAL_OWNER_RECORDED = "OWNER_RECORDED"
SIGNAL_OWNER_NOT_RECORDED = "OWNER_NOT_RECORDED"
SIGNAL_TENANT_RECORDED = "TENANT_RECORDED"
SIGNAL_TENANT_NOT_RECORDED = "TENANT_NOT_RECORDED"
SIGNAL_ROLE_RECORDED = "ROLE_RECORDED"
SIGNAL_ROLE_NOT_RECORDED = "ROLE_NOT_RECORDED"
SIGNAL_LOOKUP_BY_IDENTIFIER = "LOOKUP_BY_IDENTIFIER"
SIGNAL_LOOKUP_BY_OWNED_SCOPE = "LOOKUP_BY_OWNED_SCOPE"
SIGNAL_LOOKUP_BY_TENANT_SCOPE = "LOOKUP_BY_TENANT_SCOPE"
SIGNAL_AUTHORIZATION_CONTROL_ABSENT = "AUTHORIZATION_CONTROL_ABSENT"
SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN = "AUTHORIZATION_CONTROL_UNKNOWN"
SIGNAL_POLICY_ENFORCEMENT_PRESENT = "POLICY_ENFORCEMENT_PRESENT"
SIGNAL_OWNERSHIP_CHECK_PRESENT = "OWNERSHIP_CHECK_PRESENT"
SIGNAL_TENANT_AUTHORIZATION_PRESENT = "TENANT_AUTHORIZATION_PRESENT"
SIGNAL_ROLE_AUTHORIZATION_PRESENT = "ROLE_AUTHORIZATION_PRESENT"
SIGNAL_AUTHORIZATION_MIDDLEWARE_PRESENT = "AUTHORIZATION_MIDDLEWARE_PRESENT"
SIGNAL_SERVER_SIDE_AUTHORIZATION_PRESENT = (
    "SERVER_SIDE_AUTHORIZATION_PRESENT"
)
SIGNAL_AUTHORIZATION_SERVER_SIDE = "AUTHORIZATION_SERVER_SIDE"
SIGNAL_AUTHORIZATION_CLIENT_SIDE_ONLY = "AUTHORIZATION_CLIENT_SIDE_ONLY"
SIGNAL_CROSS_USER_ACCESS_OBSERVED = "CROSS_USER_ACCESS_OBSERVED"
SIGNAL_CROSS_TENANT_ACCESS_OBSERVED = "CROSS_TENANT_ACCESS_OBSERVED"
SIGNAL_OWN_OBJECT_ONLY_OBSERVED = "OWN_OBJECT_ONLY_OBSERVED"
SIGNAL_ACCESS_DENIED_OBSERVED = "ACCESS_DENIED_OBSERVED"
SIGNAL_NO_BEHAVIOR_OBSERVED = "NO_BEHAVIOR_OBSERVED"
SIGNAL_ROUTE_RESOURCE = "ROUTE_RESOURCE"
SIGNAL_ROUTE_COLLECTION = "ROUTE_COLLECTION"
SIGNAL_ROUTE_ADMIN = "ROUTE_ADMIN"
SIGNAL_ROUTE_INTERNAL = "ROUTE_INTERNAL"
SIGNAL_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

IDOR_BOLA_SIGNALS: tuple[str, ...] = (
    SIGNAL_OBJECT_REFERENCE_PATH,
    SIGNAL_OBJECT_REFERENCE_QUERY,
    SIGNAL_OBJECT_REFERENCE_BODY,
    SIGNAL_OBJECT_REFERENCE_HEADER,
    SIGNAL_OBJECT_REFERENCE_COOKIE,
    SIGNAL_RESOURCE_TYPE_PRESENT,
    SIGNAL_IDENTIFIER_OPAQUE,
    SIGNAL_IDENTIFIER_SEQUENTIAL,
    SIGNAL_IDENTIFIER_UUID,
    SIGNAL_IDENTIFIER_COMPOSITE,
    SIGNAL_OWNER_RECORDED,
    SIGNAL_OWNER_NOT_RECORDED,
    SIGNAL_TENANT_RECORDED,
    SIGNAL_TENANT_NOT_RECORDED,
    SIGNAL_ROLE_RECORDED,
    SIGNAL_ROLE_NOT_RECORDED,
    SIGNAL_LOOKUP_BY_IDENTIFIER,
    SIGNAL_LOOKUP_BY_OWNED_SCOPE,
    SIGNAL_LOOKUP_BY_TENANT_SCOPE,
    SIGNAL_AUTHORIZATION_CONTROL_ABSENT,
    SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
    SIGNAL_POLICY_ENFORCEMENT_PRESENT,
    SIGNAL_OWNERSHIP_CHECK_PRESENT,
    SIGNAL_TENANT_AUTHORIZATION_PRESENT,
    SIGNAL_ROLE_AUTHORIZATION_PRESENT,
    SIGNAL_AUTHORIZATION_MIDDLEWARE_PRESENT,
    SIGNAL_SERVER_SIDE_AUTHORIZATION_PRESENT,
    SIGNAL_AUTHORIZATION_SERVER_SIDE,
    SIGNAL_AUTHORIZATION_CLIENT_SIDE_ONLY,
    SIGNAL_CROSS_USER_ACCESS_OBSERVED,
    SIGNAL_CROSS_TENANT_ACCESS_OBSERVED,
    SIGNAL_OWN_OBJECT_ONLY_OBSERVED,
    SIGNAL_ACCESS_DENIED_OBSERVED,
    SIGNAL_NO_BEHAVIOR_OBSERVED,
    SIGNAL_ROUTE_RESOURCE,
    SIGNAL_ROUTE_COLLECTION,
    SIGNAL_ROUTE_ADMIN,
    SIGNAL_ROUTE_INTERNAL,
    SIGNAL_CONTEXT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_EXPLOIT_CLAIM = "NO_EXPLOIT_CLAIM"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_AUTHORIZATION_BYPASS_CLAIM = "NO_AUTHORIZATION_BYPASS_CLAIM"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

IDOR_BOLA_HYPOTHESIS_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_AUTHORIZATION_BYPASS_CLAIM,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_SIGNALS = 12
MAX_LIMITATIONS = 6
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


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


def sanitize_idor_bola_hypothesis_plan(value: object) -> dict:
    """Project an R46.3 hypothesis onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "hypothesis_type": TYPE_UNKNOWN,
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if hypothesis_type not in HYPOTHESIS_TYPES:
        hypothesis_type = TYPE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "hypothesis_type": hypothesis_type,
        "supporting_signals": [
            signal
            for signal in (
                _safe_text(item)
                for item in value.get("supporting_signals") or ()
            )
            if signal in IDOR_BOLA_SIGNALS
        ][:MAX_SIGNALS],
        "confidence": confidence,
        "priority": priority,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in IDOR_BOLA_HYPOTHESIS_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class IDORBOLAHypothesisPlan(BaseModel):
    """Deterministic research-only IDOR/BOLA hypothesis (R46.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = IDOR_BOLA_HYPOTHESIS_RULE_VERSION
    hypothesis_type: str
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return IDOR_BOLA_HYPOTHESIS_RULE_VERSION

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(value, IDOR_BOLA_SIGNALS, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, IDOR_BOLA_HYPOTHESIS_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("idor/bola hypotheses are research-only")
        return True


def idor_bola_hypothesis_plan_projection(
    value: IDORBOLAHypothesisPlan,
) -> dict:
    """Serialize an IDOR/BOLA hypothesis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "IDOR_BOLA_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP",
    "TYPE_OWNERSHIP_BOUNDARY_GAP",
    "TYPE_TENANT_ISOLATION_GAP",
    "TYPE_ROLE_BOUNDARY_GAP",
    "TYPE_DIRECT_OBJECT_REFERENCE",
    "TYPE_MISSING_AUTHORIZATION_CONTEXT",
    "TYPE_AUTHORIZATION_CONTROL_PRESENT",
    "TYPE_UNKNOWN",
    "HYPOTHESIS_TYPES",
    "GAP_HYPOTHESIS_TYPES",
    "SIGNAL_OBJECT_REFERENCE_PATH",
    "SIGNAL_OBJECT_REFERENCE_QUERY",
    "SIGNAL_OBJECT_REFERENCE_BODY",
    "SIGNAL_OBJECT_REFERENCE_HEADER",
    "SIGNAL_OBJECT_REFERENCE_COOKIE",
    "SIGNAL_RESOURCE_TYPE_PRESENT",
    "SIGNAL_IDENTIFIER_OPAQUE",
    "SIGNAL_IDENTIFIER_SEQUENTIAL",
    "SIGNAL_IDENTIFIER_UUID",
    "SIGNAL_IDENTIFIER_COMPOSITE",
    "SIGNAL_OWNER_RECORDED",
    "SIGNAL_OWNER_NOT_RECORDED",
    "SIGNAL_TENANT_RECORDED",
    "SIGNAL_TENANT_NOT_RECORDED",
    "SIGNAL_ROLE_RECORDED",
    "SIGNAL_ROLE_NOT_RECORDED",
    "SIGNAL_LOOKUP_BY_IDENTIFIER",
    "SIGNAL_LOOKUP_BY_OWNED_SCOPE",
    "SIGNAL_LOOKUP_BY_TENANT_SCOPE",
    "SIGNAL_AUTHORIZATION_CONTROL_ABSENT",
    "SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN",
    "SIGNAL_POLICY_ENFORCEMENT_PRESENT",
    "SIGNAL_OWNERSHIP_CHECK_PRESENT",
    "SIGNAL_TENANT_AUTHORIZATION_PRESENT",
    "SIGNAL_ROLE_AUTHORIZATION_PRESENT",
    "SIGNAL_AUTHORIZATION_MIDDLEWARE_PRESENT",
    "SIGNAL_SERVER_SIDE_AUTHORIZATION_PRESENT",
    "SIGNAL_AUTHORIZATION_SERVER_SIDE",
    "SIGNAL_AUTHORIZATION_CLIENT_SIDE_ONLY",
    "SIGNAL_CROSS_USER_ACCESS_OBSERVED",
    "SIGNAL_CROSS_TENANT_ACCESS_OBSERVED",
    "SIGNAL_OWN_OBJECT_ONLY_OBSERVED",
    "SIGNAL_ACCESS_DENIED_OBSERVED",
    "SIGNAL_NO_BEHAVIOR_OBSERVED",
    "SIGNAL_ROUTE_RESOURCE",
    "SIGNAL_ROUTE_COLLECTION",
    "SIGNAL_ROUTE_ADMIN",
    "SIGNAL_ROUTE_INTERNAL",
    "SIGNAL_CONTEXT_UNKNOWN",
    "IDOR_BOLA_SIGNALS",
    "LIMITATION_NO_EXPLOIT_CLAIM",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_AUTHORIZATION_BYPASS_CLAIM",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "IDOR_BOLA_HYPOTHESIS_LIMITATIONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_idor_bola_hypothesis_plan",
    "IDORBOLAHypothesisPlan",
    "idor_bola_hypothesis_plan_projection",
]

"""CVE research evidence plan schema (Stage R50.4).

A :class:`CVEResearchEvidencePlan` defines which research evidence would
be required to evaluate the CVE research hypotheses. It answers the
research question:

    "Which bounded CVE research evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no NVD/vendor API call, no web
  request, no reference retrieval, no exploit retrieval, no network
  access, no socket, no DNS, no database, no scanner, no vulnerability
  reproduction, no payload, no execution, no secret extraction, no
  persistence. Nothing is fetched, queried or executed.
- Evidence items describe what would be relevant; they are never
  collected here and never instruct an attack or a lookup.
- Closed vocabularies: evidence items, evidence state and limitations are
  closed sets; confidence reuses the shared evidence-confidence
  vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION = "r50-4"
RULE_VERSION = CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed evidence vocabulary
# ---------------------------------------------------------------------------

EVIDENCE_CVE_IDENTITY_REFERENCE = "CVE_IDENTITY_REFERENCE"
EVIDENCE_VULNERABILITY_DESCRIPTION = "VULNERABILITY_DESCRIPTION"
EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION = "AFFECTED_PRODUCT_IDENTIFICATION"
EVIDENCE_AFFECTED_VERSION_CONSTRAINTS = "AFFECTED_VERSION_CONSTRAINTS"
EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION = (
    "OBSERVED_COMPONENT_IDENTIFICATION"
)
EVIDENCE_OBSERVED_VERSION_IDENTIFICATION = (
    "OBSERVED_VERSION_IDENTIFICATION"
)
EVIDENCE_VERSION_CONSTRAINT_COMPARISON = "VERSION_CONSTRAINT_COMPARISON"
EVIDENCE_COMPONENT_MATCH_EVIDENCE = "COMPONENT_MATCH_EVIDENCE"
EVIDENCE_VENDOR_ADVISORY = "VENDOR_ADVISORY_EVIDENCE"
EVIDENCE_CWE_REFERENCE = "CWE_REFERENCE"
EVIDENCE_CVSS_METADATA = "CVSS_METADATA"
EVIDENCE_ATTACK_VECTOR_CONTEXT = "ATTACK_VECTOR_CONTEXT"
EVIDENCE_PREREQUISITE_CONTEXT = "PREREQUISITE_CONTEXT"
EVIDENCE_EXPLOIT_MATURITY_SOURCE = "EXPLOIT_MATURITY_SOURCE"
EVIDENCE_REFERENCE_CORROBORATION = "REFERENCE_CORROBORATION"
EVIDENCE_REFERENCE_PROVENANCE = "REFERENCE_PROVENANCE"
EVIDENCE_FIXED_VERSION_INFORMATION = "FIXED_VERSION_INFORMATION"
EVIDENCE_PATCH_AVAILABILITY = "PATCH_AVAILABILITY"
EVIDENCE_PATCH_APPLICATION_STATE = "PATCH_APPLICATION_STATE"
EVIDENCE_TECHNOLOGY_MAPPING = "TECHNOLOGY_MAPPING"
EVIDENCE_TARGET_EXPOSURE_CONTEXT = "TARGET_EXPOSURE_CONTEXT"
EVIDENCE_APPLICABILITY_EVIDENCE = "APPLICABILITY_EVIDENCE"
EVIDENCE_HISTORICAL_PATTERN_CONTEXT = "HISTORICAL_PATTERN_CONTEXT"
EVIDENCE_CVE_RESEARCH_CONTEXT = "CVE_RESEARCH_CONTEXT"
EVIDENCE_UNKNOWN = "UNKNOWN"

CVE_RESEARCH_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_CVE_IDENTITY_REFERENCE,
    EVIDENCE_VULNERABILITY_DESCRIPTION,
    EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION,
    EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
    EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION,
    EVIDENCE_OBSERVED_VERSION_IDENTIFICATION,
    EVIDENCE_VERSION_CONSTRAINT_COMPARISON,
    EVIDENCE_COMPONENT_MATCH_EVIDENCE,
    EVIDENCE_VENDOR_ADVISORY,
    EVIDENCE_CWE_REFERENCE,
    EVIDENCE_CVSS_METADATA,
    EVIDENCE_ATTACK_VECTOR_CONTEXT,
    EVIDENCE_PREREQUISITE_CONTEXT,
    EVIDENCE_EXPLOIT_MATURITY_SOURCE,
    EVIDENCE_REFERENCE_CORROBORATION,
    EVIDENCE_REFERENCE_PROVENANCE,
    EVIDENCE_FIXED_VERSION_INFORMATION,
    EVIDENCE_PATCH_AVAILABILITY,
    EVIDENCE_PATCH_APPLICATION_STATE,
    EVIDENCE_TECHNOLOGY_MAPPING,
    EVIDENCE_TARGET_EXPOSURE_CONTEXT,
    EVIDENCE_APPLICABILITY_EVIDENCE,
    EVIDENCE_HISTORICAL_PATTERN_CONTEXT,
    EVIDENCE_CVE_RESEARCH_CONTEXT,
    EVIDENCE_UNKNOWN,
)

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_CVE_LOOKUP = "NO_CVE_LOOKUP"
LIMITATION_NO_REFERENCE_RETRIEVAL = "NO_REFERENCE_RETRIEVAL"
LIMITATION_NO_EXPLOIT_RETRIEVAL = "NO_EXPLOIT_RETRIEVAL"
LIMITATION_NO_VULNERABILITY_REPRODUCTION = "NO_VULNERABILITY_REPRODUCTION"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

CVE_RESEARCH_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_CVE_LOOKUP,
    LIMITATION_NO_REFERENCE_RETRIEVAL,
    LIMITATION_NO_EXPLOIT_RETRIEVAL,
    LIMITATION_NO_VULNERABILITY_REPRODUCTION,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 25
MAX_LIMITATIONS = 9
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


def sanitize_cve_research_evidence_plan(value: object) -> dict:
    """Project an R50.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_items": [],
            "evidence_state": STATE_UNKNOWN,
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    evidence_state = _safe_text(value.get("evidence_state")).strip().upper()
    if evidence_state not in EVIDENCE_STATES:
        evidence_state = STATE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": [
            item
            for item in (
                _safe_text(entry)
                for entry in value.get("evidence_items") or ()
            )
            if item in CVE_RESEARCH_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in CVE_RESEARCH_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CVEResearchEvidencePlan(BaseModel):
    """Deterministic research-only CVE research evidence plan (R50.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(
            value, CVE_RESEARCH_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS
        )

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STATES:
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, CVE_RESEARCH_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("cve research evidence plans are research-only")
        return True


def cve_research_evidence_plan_projection(
    value: CVEResearchEvidencePlan,
) -> dict:
    """Serialize an R50.4 evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_CVE_IDENTITY_REFERENCE",
    "EVIDENCE_VULNERABILITY_DESCRIPTION",
    "EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION",
    "EVIDENCE_AFFECTED_VERSION_CONSTRAINTS",
    "EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION",
    "EVIDENCE_OBSERVED_VERSION_IDENTIFICATION",
    "EVIDENCE_VERSION_CONSTRAINT_COMPARISON",
    "EVIDENCE_COMPONENT_MATCH_EVIDENCE",
    "EVIDENCE_VENDOR_ADVISORY",
    "EVIDENCE_CWE_REFERENCE",
    "EVIDENCE_CVSS_METADATA",
    "EVIDENCE_ATTACK_VECTOR_CONTEXT",
    "EVIDENCE_PREREQUISITE_CONTEXT",
    "EVIDENCE_EXPLOIT_MATURITY_SOURCE",
    "EVIDENCE_REFERENCE_CORROBORATION",
    "EVIDENCE_REFERENCE_PROVENANCE",
    "EVIDENCE_FIXED_VERSION_INFORMATION",
    "EVIDENCE_PATCH_AVAILABILITY",
    "EVIDENCE_PATCH_APPLICATION_STATE",
    "EVIDENCE_TECHNOLOGY_MAPPING",
    "EVIDENCE_TARGET_EXPOSURE_CONTEXT",
    "EVIDENCE_APPLICABILITY_EVIDENCE",
    "EVIDENCE_HISTORICAL_PATTERN_CONTEXT",
    "EVIDENCE_CVE_RESEARCH_CONTEXT",
    "EVIDENCE_UNKNOWN",
    "CVE_RESEARCH_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_CVE_LOOKUP",
    "LIMITATION_NO_REFERENCE_RETRIEVAL",
    "LIMITATION_NO_EXPLOIT_RETRIEVAL",
    "LIMITATION_NO_VULNERABILITY_REPRODUCTION",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "CVE_RESEARCH_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_cve_research_evidence_plan",
    "CVEResearchEvidencePlan",
    "cve_research_evidence_plan_projection",
]

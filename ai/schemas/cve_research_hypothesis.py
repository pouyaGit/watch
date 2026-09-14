"""CVE research hypothesis schema (Stage R50.3).

A :class:`CVEResearchHypothesisPlan` is a deterministic research
hypothesis about possible CVE applicability/severity/evidence context. It
answers the research question:

    "Which CVE research hypothesis follows from the supplied context?"

Hard boundaries encoded here:

- Research hypothesis only: no vulnerability confirmation, no exploit
  claim, no exploit retrieval, no vulnerability reproduction, no payload,
  no attack sequence, no CVE lookup, no network request, no execution.
- CVE metadata presence is never a hypothesis of confirmed
  vulnerability: a CVE identifier, product name, version string, CVSS
  score, CWE, advisory or exploit-maturity label is context only.
- Closed vocabularies: hypothesis type, hypothesis state, supporting
  signals, confidence, priority, rationale and limitations are
  closed/bounded.
- Confidence and priority reuse the shared evidence-confidence
  vocabulary. Priority means "how useful is further CVE research of this
  hypothesis?"; it is NOT severity, exploitability, CVSS or vulnerability
  probability.
- ``hypothesis_state`` distinguishes an observed signal, an observed
  remediation/evidence control, a need for evidence, an observed
  non-match and unknown context.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

CVE_RESEARCH_HYPOTHESIS_RULE_VERSION = "r50-3"
RULE_VERSION = CVE_RESEARCH_HYPOTHESIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed hypothesis vocabulary
# ---------------------------------------------------------------------------

TYPE_AFFECTED_VERSION_MATCH = "AFFECTED_VERSION_MATCH"
TYPE_VENDOR_ADVISORY_MATCH = "VENDOR_ADVISORY_MATCH"
TYPE_CWE_MATCH = "CWE_MATCH"
TYPE_CVSS_RISK_SIGNAL = "CVSS_RISK_SIGNAL"
TYPE_EXPLOIT_MATURITY_SIGNAL = "EXPLOIT_MATURITY_SIGNAL"
TYPE_FIXED_VERSION_GAP = "FIXED_VERSION_GAP"
TYPE_COMPONENT_MATCH = "COMPONENT_MATCH"
TYPE_VERSION_CONSTRAINT_GAP = "VERSION_CONSTRAINT_GAP"
TYPE_VULNERABILITY_DESCRIPTION_MATCH = "VULNERABILITY_DESCRIPTION_MATCH"
TYPE_REFERENCE_CORROBORATION_GAP = "REFERENCE_CORROBORATION_GAP"
TYPE_PATCH_AVAILABILITY_GAP = "PATCH_AVAILABILITY_GAP"
TYPE_EXPOSURE_RELEVANCE = "EXPOSURE_RELEVANCE"
TYPE_CVE_CONTEXT_PRESENT = "CVE_CONTEXT_PRESENT"
TYPE_MISSING_CVE_CONTEXT = "MISSING_CVE_CONTEXT"
TYPE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_AFFECTED_VERSION_MATCH,
    TYPE_VENDOR_ADVISORY_MATCH,
    TYPE_CWE_MATCH,
    TYPE_CVSS_RISK_SIGNAL,
    TYPE_EXPLOIT_MATURITY_SIGNAL,
    TYPE_FIXED_VERSION_GAP,
    TYPE_COMPONENT_MATCH,
    TYPE_VERSION_CONSTRAINT_GAP,
    TYPE_VULNERABILITY_DESCRIPTION_MATCH,
    TYPE_REFERENCE_CORROBORATION_GAP,
    TYPE_PATCH_AVAILABILITY_GAP,
    TYPE_EXPOSURE_RELEVANCE,
    TYPE_CVE_CONTEXT_PRESENT,
    TYPE_MISSING_CVE_CONTEXT,
    TYPE_UNKNOWN,
)

MATCH_HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_AFFECTED_VERSION_MATCH,
    TYPE_VENDOR_ADVISORY_MATCH,
    TYPE_CWE_MATCH,
    TYPE_COMPONENT_MATCH,
    TYPE_VULNERABILITY_DESCRIPTION_MATCH,
    TYPE_EXPOSURE_RELEVANCE,
)

RISK_HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_CVSS_RISK_SIGNAL,
    TYPE_EXPLOIT_MATURITY_SIGNAL,
)

GAP_HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_FIXED_VERSION_GAP,
    TYPE_VERSION_CONSTRAINT_GAP,
    TYPE_REFERENCE_CORROBORATION_GAP,
    TYPE_PATCH_AVAILABILITY_GAP,
)

# ---------------------------------------------------------------------------
# Closed hypothesis states
# ---------------------------------------------------------------------------

STATE_WEAKNESS_OBSERVED = "WEAKNESS_OBSERVED"
STATE_CONTROL_PRESENT_OBSERVED = "CONTROL_PRESENT_OBSERVED"
STATE_NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
STATE_NOT_OBSERVED = "NOT_OBSERVED"
STATE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_STATES: tuple[str, ...] = (
    STATE_WEAKNESS_OBSERVED,
    STATE_CONTROL_PRESENT_OBSERVED,
    STATE_NEEDS_EVIDENCE,
    STATE_NOT_OBSERVED,
    STATE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed supporting-signal vocabulary
# ---------------------------------------------------------------------------

SIGNAL_CVE_METADATA_OBSERVED = "CVE_METADATA_OBSERVED"
SIGNAL_VULNERABILITY_DESCRIPTION_OBSERVED = (
    "VULNERABILITY_DESCRIPTION_OBSERVED"
)
SIGNAL_AFFECTED_PRODUCT_OBSERVED = "AFFECTED_PRODUCT_OBSERVED"
SIGNAL_AFFECTED_VERSIONS_OBSERVED = "AFFECTED_VERSIONS_OBSERVED"
SIGNAL_FIXED_VERSION_OBSERVED = "FIXED_VERSION_OBSERVED"
SIGNAL_VENDOR_ADVISORY_OBSERVED = "VENDOR_ADVISORY_OBSERVED"
SIGNAL_CWE_METADATA_OBSERVED = "CWE_METADATA_OBSERVED"
SIGNAL_CVSS_METADATA_OBSERVED = "CVSS_METADATA_OBSERVED"
SIGNAL_REFERENCES_OBSERVED = "REFERENCES_OBSERVED"
SIGNAL_PATCH_INFORMATION_OBSERVED = "PATCH_INFORMATION_OBSERVED"
SIGNAL_OBSERVED_COMPONENT_OBSERVED = "OBSERVED_COMPONENT_OBSERVED"
SIGNAL_OBSERVED_VERSION_OBSERVED = "OBSERVED_VERSION_OBSERVED"
SIGNAL_TECHNOLOGY_MAPPING_OBSERVED = "TECHNOLOGY_MAPPING_OBSERVED"

SIGNAL_VERSION_MATCH_OBSERVED = "VERSION_MATCH_OBSERVED"
SIGNAL_VERSION_NO_MATCH_OBSERVED = "VERSION_NO_MATCH_OBSERVED"
SIGNAL_VERSION_PARTIAL_MATCH_OBSERVED = "VERSION_PARTIAL_MATCH_OBSERVED"
SIGNAL_COMPONENT_MATCH_OBSERVED = "COMPONENT_MATCH_OBSERVED"
SIGNAL_COMPONENT_NO_MATCH_OBSERVED = "COMPONENT_NO_MATCH_OBSERVED"
SIGNAL_COMPONENT_PARTIAL_MATCH_OBSERVED = (
    "COMPONENT_PARTIAL_MATCH_OBSERVED"
)
SIGNAL_ADVISORY_MATCH_OBSERVED = "ADVISORY_MATCH_OBSERVED"
SIGNAL_ADVISORY_NO_MATCH_OBSERVED = "ADVISORY_NO_MATCH_OBSERVED"
SIGNAL_CWE_MATCH_OBSERVED = "CWE_MATCH_OBSERVED"
SIGNAL_CWE_NO_MATCH_OBSERVED = "CWE_NO_MATCH_OBSERVED"

SIGNAL_CVSS_CRITICAL_OBSERVED = "CVSS_CRITICAL_OBSERVED"
SIGNAL_CVSS_HIGH_OBSERVED = "CVSS_HIGH_OBSERVED"
SIGNAL_CVSS_MEDIUM_OBSERVED = "CVSS_MEDIUM_OBSERVED"
SIGNAL_CVSS_LOW_OBSERVED = "CVSS_LOW_OBSERVED"
SIGNAL_CVSS_NONE_OBSERVED = "CVSS_NONE_OBSERVED"

SIGNAL_ATTACK_VECTOR_NETWORK = "ATTACK_VECTOR_NETWORK_OBSERVED"
SIGNAL_ATTACK_VECTOR_ADJACENT = "ATTACK_VECTOR_ADJACENT_OBSERVED"
SIGNAL_ATTACK_VECTOR_LOCAL = "ATTACK_VECTOR_LOCAL_OBSERVED"
SIGNAL_ATTACK_VECTOR_PHYSICAL = "ATTACK_VECTOR_PHYSICAL_OBSERVED"
SIGNAL_PREREQUISITES_NONE_OBSERVED = "PREREQUISITES_NONE_OBSERVED"
SIGNAL_PREREQUISITES_AUTHENTICATION_REQUIRED = (
    "PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED"
)
SIGNAL_PREREQUISITES_USER_INTERACTION_REQUIRED = (
    "PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED"
)
SIGNAL_PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED = (
    "PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED"
)

SIGNAL_EXPLOIT_MATURITY_NONE_OBSERVED = "EXPLOIT_MATURITY_NONE_OBSERVED"
SIGNAL_EXPLOIT_MATURITY_POC_OBSERVED = (
    "EXPLOIT_MATURITY_PROOF_OF_CONCEPT_OBSERVED"
)
SIGNAL_EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED = (
    "EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED"
)
SIGNAL_EXPLOIT_MATURITY_WEAPONIZED_OBSERVED = (
    "EXPLOIT_MATURITY_WEAPONIZED_OBSERVED"
)

SIGNAL_FIXED_VERSION_AVAILABLE_OBSERVED = (
    "FIXED_VERSION_AVAILABLE_OBSERVED"
)
SIGNAL_FIXED_VERSION_NOT_AVAILABLE_OBSERVED = (
    "FIXED_VERSION_NOT_AVAILABLE_OBSERVED"
)
SIGNAL_FIX_APPLIED_OBSERVED = "FIX_APPLIED_OBSERVED"
SIGNAL_PATCH_AVAILABLE_OBSERVED = "PATCH_AVAILABLE_OBSERVED"
SIGNAL_PATCH_NOT_AVAILABLE_OBSERVED = "PATCH_NOT_AVAILABLE_OBSERVED"
SIGNAL_PATCH_APPLIED_OBSERVED = "PATCH_APPLIED_OBSERVED"

SIGNAL_REFERENCE_CORROBORATED_OBSERVED = "REFERENCE_CORROBORATED_OBSERVED"
SIGNAL_REFERENCE_SINGLE_SOURCE_OBSERVED = (
    "REFERENCE_SINGLE_SOURCE_OBSERVED"
)
SIGNAL_REFERENCE_NONE_OBSERVED = "REFERENCE_NONE_OBSERVED"
SIGNAL_APPLICABILITY_CONFIRMED_OBSERVED = (
    "APPLICABILITY_CONFIRMED_OBSERVED"
)
SIGNAL_APPLICABILITY_MATCH_OBSERVED = "APPLICABILITY_MATCH_OBSERVED"
SIGNAL_APPLICABILITY_NONE_OBSERVED = "APPLICABILITY_NONE_OBSERVED"

SIGNAL_HISTORICAL_RECURRING_OBSERVED = "HISTORICAL_RECURRING_OBSERVED"
SIGNAL_HISTORICAL_ISOLATED_OBSERVED = "HISTORICAL_ISOLATED_OBSERVED"

SIGNAL_EXPOSURE_EXPOSED_OBSERVED = "EXPOSURE_EXPOSED_OBSERVED"
SIGNAL_EXPOSURE_NOT_EXPOSED_OBSERVED = "EXPOSURE_NOT_EXPOSED_OBSERVED"

SIGNAL_MISSING_CVE_CONTEXT = "MISSING_CVE_CONTEXT"
SIGNAL_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

CVE_RESEARCH_SIGNALS: tuple[str, ...] = (
    SIGNAL_CVE_METADATA_OBSERVED,
    SIGNAL_VULNERABILITY_DESCRIPTION_OBSERVED,
    SIGNAL_AFFECTED_PRODUCT_OBSERVED,
    SIGNAL_AFFECTED_VERSIONS_OBSERVED,
    SIGNAL_FIXED_VERSION_OBSERVED,
    SIGNAL_VENDOR_ADVISORY_OBSERVED,
    SIGNAL_CWE_METADATA_OBSERVED,
    SIGNAL_CVSS_METADATA_OBSERVED,
    SIGNAL_REFERENCES_OBSERVED,
    SIGNAL_PATCH_INFORMATION_OBSERVED,
    SIGNAL_OBSERVED_COMPONENT_OBSERVED,
    SIGNAL_OBSERVED_VERSION_OBSERVED,
    SIGNAL_TECHNOLOGY_MAPPING_OBSERVED,
    SIGNAL_VERSION_MATCH_OBSERVED,
    SIGNAL_VERSION_NO_MATCH_OBSERVED,
    SIGNAL_VERSION_PARTIAL_MATCH_OBSERVED,
    SIGNAL_COMPONENT_MATCH_OBSERVED,
    SIGNAL_COMPONENT_NO_MATCH_OBSERVED,
    SIGNAL_COMPONENT_PARTIAL_MATCH_OBSERVED,
    SIGNAL_ADVISORY_MATCH_OBSERVED,
    SIGNAL_ADVISORY_NO_MATCH_OBSERVED,
    SIGNAL_CWE_MATCH_OBSERVED,
    SIGNAL_CWE_NO_MATCH_OBSERVED,
    SIGNAL_CVSS_CRITICAL_OBSERVED,
    SIGNAL_CVSS_HIGH_OBSERVED,
    SIGNAL_CVSS_MEDIUM_OBSERVED,
    SIGNAL_CVSS_LOW_OBSERVED,
    SIGNAL_CVSS_NONE_OBSERVED,
    SIGNAL_ATTACK_VECTOR_NETWORK,
    SIGNAL_ATTACK_VECTOR_ADJACENT,
    SIGNAL_ATTACK_VECTOR_LOCAL,
    SIGNAL_ATTACK_VECTOR_PHYSICAL,
    SIGNAL_PREREQUISITES_NONE_OBSERVED,
    SIGNAL_PREREQUISITES_AUTHENTICATION_REQUIRED,
    SIGNAL_PREREQUISITES_USER_INTERACTION_REQUIRED,
    SIGNAL_PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED,
    SIGNAL_EXPLOIT_MATURITY_NONE_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_POC_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_WEAPONIZED_OBSERVED,
    SIGNAL_FIXED_VERSION_AVAILABLE_OBSERVED,
    SIGNAL_FIXED_VERSION_NOT_AVAILABLE_OBSERVED,
    SIGNAL_FIX_APPLIED_OBSERVED,
    SIGNAL_PATCH_AVAILABLE_OBSERVED,
    SIGNAL_PATCH_NOT_AVAILABLE_OBSERVED,
    SIGNAL_PATCH_APPLIED_OBSERVED,
    SIGNAL_REFERENCE_CORROBORATED_OBSERVED,
    SIGNAL_REFERENCE_SINGLE_SOURCE_OBSERVED,
    SIGNAL_REFERENCE_NONE_OBSERVED,
    SIGNAL_APPLICABILITY_CONFIRMED_OBSERVED,
    SIGNAL_APPLICABILITY_MATCH_OBSERVED,
    SIGNAL_APPLICABILITY_NONE_OBSERVED,
    SIGNAL_HISTORICAL_RECURRING_OBSERVED,
    SIGNAL_HISTORICAL_ISOLATED_OBSERVED,
    SIGNAL_EXPOSURE_EXPOSED_OBSERVED,
    SIGNAL_EXPOSURE_NOT_EXPOSED_OBSERVED,
    SIGNAL_MISSING_CVE_CONTEXT,
    SIGNAL_CONTEXT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_EXPLOIT_CLAIM = "NO_EXPLOIT_CLAIM"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_CVE_LOOKUP_CLAIM = "NO_CVE_LOOKUP_CLAIM"
LIMITATION_NO_EXPLOIT_RETRIEVAL_CLAIM = "NO_EXPLOIT_RETRIEVAL_CLAIM"
LIMITATION_NO_REPRODUCTION_CLAIM = "NO_REPRODUCTION_CLAIM"
LIMITATION_NO_PAYLOAD_GENERATION_CLAIM = "NO_PAYLOAD_GENERATION_CLAIM"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

CVE_RESEARCH_HYPOTHESIS_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_CVE_LOOKUP_CLAIM,
    LIMITATION_NO_EXPLOIT_RETRIEVAL_CLAIM,
    LIMITATION_NO_REPRODUCTION_CLAIM,
    LIMITATION_NO_PAYLOAD_GENERATION_CLAIM,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_SIGNALS = 12
MAX_LIMITATIONS = 9
MAX_VALUE_LEN = 160
MAX_RATIONALE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


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


def sanitize_cve_research_hypothesis_plan(value: object) -> dict:
    """Project an R50.3 hypothesis onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "hypothesis_type": TYPE_UNKNOWN,
            "hypothesis_state": STATE_UNKNOWN,
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "rationale": "",
            "limitations": [],
            "research_only": True,
        }
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if hypothesis_type not in HYPOTHESIS_TYPES:
        hypothesis_type = TYPE_UNKNOWN
    hypothesis_state = _safe_text(
        value.get("hypothesis_state")
    ).strip().upper()
    if hypothesis_state not in HYPOTHESIS_STATES:
        hypothesis_state = STATE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "hypothesis_type": hypothesis_type,
        "hypothesis_state": hypothesis_state,
        "supporting_signals": [
            signal
            for signal in (
                _safe_text(item)
                for item in value.get("supporting_signals") or ()
            )
            if signal in CVE_RESEARCH_SIGNALS
        ][:MAX_SIGNALS],
        "confidence": confidence,
        "priority": priority,
        "rationale": _safe_text(value.get("rationale"), MAX_RATIONALE_LEN),
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in CVE_RESEARCH_HYPOTHESIS_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CVEResearchHypothesisPlan(BaseModel):
    """Deterministic research-only CVE research hypothesis (R50.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CVE_RESEARCH_HYPOTHESIS_RULE_VERSION
    hypothesis_type: str
    hypothesis_state: str = STATE_UNKNOWN
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    rationale: str = ""
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CVE_RESEARCH_HYPOTHESIS_RULE_VERSION

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("hypothesis_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_STATES:
            raise ValueError(f"invalid hypothesis_state: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(value, CVE_RESEARCH_SIGNALS, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("rationale")
    @classmethod
    def _bounded_rationale(cls, value: object) -> str:
        return _safe_text(value, MAX_RATIONALE_LEN)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, CVE_RESEARCH_HYPOTHESIS_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("cve research hypotheses are research-only")
        return True


def cve_research_hypothesis_plan_projection(
    value: CVEResearchHypothesisPlan,
) -> dict:
    """Serialize an R50.3 hypothesis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CVE_RESEARCH_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "TYPE_AFFECTED_VERSION_MATCH",
    "TYPE_VENDOR_ADVISORY_MATCH",
    "TYPE_CWE_MATCH",
    "TYPE_CVSS_RISK_SIGNAL",
    "TYPE_EXPLOIT_MATURITY_SIGNAL",
    "TYPE_FIXED_VERSION_GAP",
    "TYPE_COMPONENT_MATCH",
    "TYPE_VERSION_CONSTRAINT_GAP",
    "TYPE_VULNERABILITY_DESCRIPTION_MATCH",
    "TYPE_REFERENCE_CORROBORATION_GAP",
    "TYPE_PATCH_AVAILABILITY_GAP",
    "TYPE_EXPOSURE_RELEVANCE",
    "TYPE_CVE_CONTEXT_PRESENT",
    "TYPE_MISSING_CVE_CONTEXT",
    "TYPE_UNKNOWN",
    "HYPOTHESIS_TYPES",
    "MATCH_HYPOTHESIS_TYPES",
    "RISK_HYPOTHESIS_TYPES",
    "GAP_HYPOTHESIS_TYPES",
    "STATE_WEAKNESS_OBSERVED",
    "STATE_CONTROL_PRESENT_OBSERVED",
    "STATE_NEEDS_EVIDENCE",
    "STATE_NOT_OBSERVED",
    "STATE_UNKNOWN",
    "HYPOTHESIS_STATES",
    "CVE_RESEARCH_SIGNALS",
    "LIMITATION_NO_EXPLOIT_CLAIM",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_CVE_LOOKUP_CLAIM",
    "LIMITATION_NO_EXPLOIT_RETRIEVAL_CLAIM",
    "LIMITATION_NO_REPRODUCTION_CLAIM",
    "LIMITATION_NO_PAYLOAD_GENERATION_CLAIM",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "CVE_RESEARCH_HYPOTHESIS_LIMITATIONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_cve_research_hypothesis_plan",
    "CVEResearchHypothesisPlan",
    "cve_research_hypothesis_plan_projection",
]

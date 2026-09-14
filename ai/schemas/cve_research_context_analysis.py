"""CVE research context analysis schema (Stage R50.2).

A :class:`CVEResearchContextAnalysisPlan` is the deterministic,
descriptive analysis of supplied CVE research context. It answers the
research question:

    "Which CVE identity, description, affected-product/version, advisory,
     CWE, CVSS, exploit-maturity, reference, patch and exposure signals
     were supplied?"

Hard boundaries encoded here:

- Research intelligence only: no NVD/vendor API call, no web request, no
  exploit retrieval, no network access, no socket, no DNS, no database,
  no scanner, no vulnerability reproduction, no payload, no subprocess,
  no execution, no persistence. Nothing is fetched or performed.
- CVE metadata presence is never vulnerability: a CVE identifier,
  description, product name, version string, advisory, CWE, CVSS score,
  exploit-maturity label or reference is context only.
- Closed vocabularies: every field is a closed set; unknown values remain
  ``UNKNOWN`` and are never promoted.
- Match/applicability states distinguish observed match, observed
  non-match, partial match, not-provided context and unknown context.
- Context confidence reuses the shared evidence-confidence vocabulary and
  means "how strong is the supplied CVE research context?", never "is the
  target vulnerable?".
- Bounded, privacy-safe (no URLs, references, versions or scores are
  stored as raw values), JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION = "r50-2"
RULE_VERSION = CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Generic presence observations
# ---------------------------------------------------------------------------

OBSERVED = "OBSERVED"
NONE_OBSERVED = "NONE_OBSERVED"
CONTEXT_UNKNOWN = "UNKNOWN"

CONTEXT_OBSERVATIONS: tuple[str, ...] = (
    NONE_OBSERVED,
    OBSERVED,
    CONTEXT_UNKNOWN,
)

PRESENCE_OBSERVATION_FIELDS: tuple[str, ...] = (
    "cve_metadata",
    "vulnerability_description",
    "affected_product",
    "affected_versions",
    "fixed_version",
    "vendor_advisory",
    "cwe_metadata",
    "cvss_metadata",
    "references",
    "patch_information",
    "observed_component",
    "observed_version",
    "technology_mapping",
)

# ---------------------------------------------------------------------------
# Match / applicability states
# ---------------------------------------------------------------------------

MATCH_OBSERVED = "MATCH_OBSERVED"
NO_MATCH_OBSERVED = "NO_MATCH_OBSERVED"
PARTIAL_MATCH_OBSERVED = "PARTIAL_MATCH_OBSERVED"
MATCH_UNKNOWN = "UNKNOWN"

MATCH_STATES: tuple[str, ...] = (
    MATCH_OBSERVED,
    NO_MATCH_OBSERVED,
    PARTIAL_MATCH_OBSERVED,
    MATCH_UNKNOWN,
)

MATCH_FIELD_NAMES: tuple[str, ...] = (
    "version_match",
    "component_match",
    "advisory_match",
    "cwe_match",
)

OBSERVED_MATCH_STATES: tuple[str, ...] = (
    MATCH_OBSERVED,
    PARTIAL_MATCH_OBSERVED,
)

# ---------------------------------------------------------------------------
# CVSS severity / attack vector / prerequisites
# ---------------------------------------------------------------------------

CVSS_CRITICAL_OBSERVED = "CRITICAL_OBSERVED"
CVSS_HIGH_OBSERVED = "HIGH_OBSERVED"
CVSS_MEDIUM_OBSERVED = "MEDIUM_OBSERVED"
CVSS_LOW_OBSERVED = "LOW_OBSERVED"
CVSS_NONE_OBSERVED = "NONE_OBSERVED"
CVSS_UNKNOWN = "UNKNOWN"

CVSS_SEVERITIES: tuple[str, ...] = (
    CVSS_CRITICAL_OBSERVED,
    CVSS_HIGH_OBSERVED,
    CVSS_MEDIUM_OBSERVED,
    CVSS_LOW_OBSERVED,
    CVSS_NONE_OBSERVED,
    CVSS_UNKNOWN,
)

CVSS_RISK_STATES: tuple[str, ...] = (
    CVSS_CRITICAL_OBSERVED,
    CVSS_HIGH_OBSERVED,
)

CVSS_BENIGN_STATES: tuple[str, ...] = (
    CVSS_LOW_OBSERVED,
    CVSS_NONE_OBSERVED,
)

ATTACK_VECTOR_NETWORK_OBSERVED = "NETWORK_OBSERVED"
ATTACK_VECTOR_ADJACENT_OBSERVED = "ADJACENT_OBSERVED"
ATTACK_VECTOR_LOCAL_OBSERVED = "LOCAL_OBSERVED"
ATTACK_VECTOR_PHYSICAL_OBSERVED = "PHYSICAL_OBSERVED"
ATTACK_VECTOR_UNKNOWN = "UNKNOWN"

ATTACK_VECTORS: tuple[str, ...] = (
    ATTACK_VECTOR_NETWORK_OBSERVED,
    ATTACK_VECTOR_ADJACENT_OBSERVED,
    ATTACK_VECTOR_LOCAL_OBSERVED,
    ATTACK_VECTOR_PHYSICAL_OBSERVED,
    ATTACK_VECTOR_UNKNOWN,
)

PREREQUISITES_NONE_OBSERVED = "NONE_OBSERVED"
PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED = (
    "AUTHENTICATION_REQUIRED_OBSERVED"
)
PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED = (
    "USER_INTERACTION_REQUIRED_OBSERVED"
)
PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED = (
    "PRIVILEGED_ACCESS_REQUIRED_OBSERVED"
)
PREREQUISITES_UNKNOWN = "UNKNOWN"

PREREQUISITE_STATES: tuple[str, ...] = (
    PREREQUISITES_NONE_OBSERVED,
    PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED,
    PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED,
    PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED,
    PREREQUISITES_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Exploit maturity
# ---------------------------------------------------------------------------

EXPLOIT_MATURITY_NONE_OBSERVED = "NONE_OBSERVED"
EXPLOIT_MATURITY_POC_OBSERVED = "PROOF_OF_CONCEPT_OBSERVED"
EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED = "FUNCTIONAL_OBSERVED"
EXPLOIT_MATURITY_WEAPONIZED_OBSERVED = "WEAPONIZED_OBSERVED"
EXPLOIT_MATURITY_UNKNOWN = "UNKNOWN"

EXPLOIT_MATURITY_STATES: tuple[str, ...] = (
    EXPLOIT_MATURITY_NONE_OBSERVED,
    EXPLOIT_MATURITY_POC_OBSERVED,
    EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED,
    EXPLOIT_MATURITY_WEAPONIZED_OBSERVED,
    EXPLOIT_MATURITY_UNKNOWN,
)

ELEVATED_EXPLOIT_MATURITY_STATES: tuple[str, ...] = (
    EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED,
    EXPLOIT_MATURITY_WEAPONIZED_OBSERVED,
)

# ---------------------------------------------------------------------------
# Fixed version / patch states
# ---------------------------------------------------------------------------

FIXED_VERSION_AVAILABLE_OBSERVED = "FIXED_VERSION_AVAILABLE_OBSERVED"
FIXED_VERSION_NOT_AVAILABLE_OBSERVED = "FIXED_VERSION_NOT_AVAILABLE_OBSERVED"
FIXED_VERSION_APPLIED_OBSERVED = "FIX_APPLIED_OBSERVED"
FIXED_VERSION_UNKNOWN = "UNKNOWN"

FIXED_VERSION_STATES: tuple[str, ...] = (
    FIXED_VERSION_AVAILABLE_OBSERVED,
    FIXED_VERSION_NOT_AVAILABLE_OBSERVED,
    FIXED_VERSION_APPLIED_OBSERVED,
    FIXED_VERSION_UNKNOWN,
)

REMEDIATION_OBSERVED_STATES: tuple[str, ...] = (
    FIXED_VERSION_AVAILABLE_OBSERVED,
    FIXED_VERSION_APPLIED_OBSERVED,
)

PATCH_AVAILABLE_OBSERVED = "PATCH_AVAILABLE_OBSERVED"
PATCH_NOT_AVAILABLE_OBSERVED = "PATCH_NOT_AVAILABLE_OBSERVED"
PATCH_APPLIED_OBSERVED = "PATCH_APPLIED_OBSERVED"
PATCH_UNKNOWN = "UNKNOWN"

PATCH_STATES: tuple[str, ...] = (
    PATCH_AVAILABLE_OBSERVED,
    PATCH_NOT_AVAILABLE_OBSERVED,
    PATCH_APPLIED_OBSERVED,
    PATCH_UNKNOWN,
)

PATCH_PRESENT_STATES: tuple[str, ...] = (
    PATCH_AVAILABLE_OBSERVED,
    PATCH_APPLIED_OBSERVED,
)

# ---------------------------------------------------------------------------
# Reference corroboration / applicability evidence / history / exposure
# ---------------------------------------------------------------------------

REFERENCE_CORROBORATED_OBSERVED = "CORROBORATED_OBSERVED"
REFERENCE_SINGLE_SOURCE_OBSERVED = "SINGLE_SOURCE_OBSERVED"
REFERENCE_NONE_OBSERVED = "NONE_OBSERVED"
REFERENCE_UNKNOWN = "UNKNOWN"

CORROBORATION_STATES: tuple[str, ...] = (
    REFERENCE_CORROBORATED_OBSERVED,
    REFERENCE_SINGLE_SOURCE_OBSERVED,
    REFERENCE_NONE_OBSERVED,
    REFERENCE_UNKNOWN,
)

APPLICABILITY_CONFIRMED_OBSERVED = "CONFIRMED_OBSERVED"
APPLICABILITY_MATCH_OBSERVED = "MATCH_OBSERVED"
APPLICABILITY_NONE_OBSERVED = "NONE_OBSERVED"
APPLICABILITY_UNKNOWN = "UNKNOWN"

APPLICABILITY_STATES: tuple[str, ...] = (
    APPLICABILITY_CONFIRMED_OBSERVED,
    APPLICABILITY_MATCH_OBSERVED,
    APPLICABILITY_NONE_OBSERVED,
    APPLICABILITY_UNKNOWN,
)

APPLICABILITY_EVIDENCE_STATES: tuple[str, ...] = (
    APPLICABILITY_CONFIRMED_OBSERVED,
    APPLICABILITY_MATCH_OBSERVED,
)

HISTORICAL_RECURRING_OBSERVED = "RECURRING_PATTERN_OBSERVED"
HISTORICAL_ISOLATED_OBSERVED = "ISOLATED_OBSERVED"
HISTORICAL_UNKNOWN = "UNKNOWN"

HISTORICAL_STATES: tuple[str, ...] = (
    HISTORICAL_RECURRING_OBSERVED,
    HISTORICAL_ISOLATED_OBSERVED,
    HISTORICAL_UNKNOWN,
)

EXPOSURE_EXPOSED_OBSERVED = "EXPOSED_OBSERVED"
EXPOSURE_NOT_EXPOSED_OBSERVED = "NOT_EXPOSED_OBSERVED"
EXPOSURE_UNKNOWN = "UNKNOWN"

EXPOSURE_STATES: tuple[str, ...] = (
    EXPOSURE_EXPOSED_OBSERVED,
    EXPOSURE_NOT_EXPOSED_OBSERVED,
    EXPOSURE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Field groups
# ---------------------------------------------------------------------------

# (field name, allowed values, fallback)
ENUM_OBSERVATION_FIELDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("version_match", MATCH_STATES, MATCH_UNKNOWN),
    ("component_match", MATCH_STATES, MATCH_UNKNOWN),
    ("advisory_match", MATCH_STATES, MATCH_UNKNOWN),
    ("cwe_match", MATCH_STATES, MATCH_UNKNOWN),
    ("cvss_severity", CVSS_SEVERITIES, CVSS_UNKNOWN),
    ("attack_vector", ATTACK_VECTORS, ATTACK_VECTOR_UNKNOWN),
    ("prerequisites", PREREQUISITE_STATES, PREREQUISITES_UNKNOWN),
    ("exploit_maturity", EXPLOIT_MATURITY_STATES, EXPLOIT_MATURITY_UNKNOWN),
    ("fixed_version_state", FIXED_VERSION_STATES, FIXED_VERSION_UNKNOWN),
    ("patch_state", PATCH_STATES, PATCH_UNKNOWN),
    (
        "reference_corroboration",
        CORROBORATION_STATES,
        REFERENCE_UNKNOWN,
    ),
    (
        "applicability_evidence",
        APPLICABILITY_STATES,
        APPLICABILITY_UNKNOWN,
    ),
    ("historical_context", HISTORICAL_STATES, HISTORICAL_UNKNOWN),
    ("target_exposure", EXPOSURE_STATES, EXPOSURE_UNKNOWN),
)

CONTEXT_ANALYSIS_FIELDS: tuple[str, ...] = (
    ("rule_version",)
    + PRESENCE_OBSERVATION_FIELDS
    + tuple(name for name, _allowed, _fallback in ENUM_OBSERVATION_FIELDS)
    + ("context_confidence", "research_only")
)

MAX_VALUE_LEN = 160
MAX_RATIONALE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _default_context_analysis() -> dict:
    out: dict = {"rule_version": ""}
    for name in PRESENCE_OBSERVATION_FIELDS:
        out[name] = CONTEXT_UNKNOWN
    for name, _allowed, fallback in ENUM_OBSERVATION_FIELDS:
        out[name] = fallback
    out["context_confidence"] = "UNKNOWN"
    out["research_only"] = True
    return out


def sanitize_cve_research_context_analysis_plan(value: object) -> dict:
    """Project an R50.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_context_analysis()
    out: dict = {"rule_version": _safe_text(value.get("rule_version"))}
    for name in PRESENCE_OBSERVATION_FIELDS:
        out[name] = _closed(
            value.get(name), CONTEXT_OBSERVATIONS, CONTEXT_UNKNOWN
        )
    for name, allowed, fallback in ENUM_OBSERVATION_FIELDS:
        out[name] = _closed(value.get(name), allowed, fallback)
    out["context_confidence"] = _closed(
        value.get("context_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
    )
    out["research_only"] = True
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CVEResearchContextAnalysisPlan(BaseModel):
    """Deterministic descriptive CVE research context analysis (R50.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION
    cve_metadata: str = CONTEXT_UNKNOWN
    vulnerability_description: str = CONTEXT_UNKNOWN
    affected_product: str = CONTEXT_UNKNOWN
    affected_versions: str = CONTEXT_UNKNOWN
    fixed_version: str = CONTEXT_UNKNOWN
    vendor_advisory: str = CONTEXT_UNKNOWN
    cwe_metadata: str = CONTEXT_UNKNOWN
    cvss_metadata: str = CONTEXT_UNKNOWN
    references: str = CONTEXT_UNKNOWN
    patch_information: str = CONTEXT_UNKNOWN
    observed_component: str = CONTEXT_UNKNOWN
    observed_version: str = CONTEXT_UNKNOWN
    technology_mapping: str = CONTEXT_UNKNOWN
    version_match: str = MATCH_UNKNOWN
    component_match: str = MATCH_UNKNOWN
    advisory_match: str = MATCH_UNKNOWN
    cwe_match: str = MATCH_UNKNOWN
    cvss_severity: str = CVSS_UNKNOWN
    attack_vector: str = ATTACK_VECTOR_UNKNOWN
    prerequisites: str = PREREQUISITES_UNKNOWN
    exploit_maturity: str = EXPLOIT_MATURITY_UNKNOWN
    fixed_version_state: str = FIXED_VERSION_UNKNOWN
    patch_state: str = PATCH_UNKNOWN
    reference_corroboration: str = REFERENCE_UNKNOWN
    applicability_evidence: str = APPLICABILITY_UNKNOWN
    historical_context: str = HISTORICAL_UNKNOWN
    target_exposure: str = EXPOSURE_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator(*PRESENCE_OBSERVATION_FIELDS)
    @classmethod
    def _valid_observation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTEXT_OBSERVATIONS:
            raise ValueError(f"invalid context observation: {value!r}")
        return text

    @field_validator(*MATCH_FIELD_NAMES)
    @classmethod
    def _valid_match(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in MATCH_STATES:
            raise ValueError(f"invalid match state: {value!r}")
        return text

    @field_validator("cvss_severity")
    @classmethod
    def _valid_cvss(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CVSS_SEVERITIES:
            raise ValueError(f"invalid cvss_severity: {value!r}")
        return text

    @field_validator("attack_vector")
    @classmethod
    def _valid_attack_vector(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ATTACK_VECTORS:
            raise ValueError(f"invalid attack_vector: {value!r}")
        return text

    @field_validator("prerequisites")
    @classmethod
    def _valid_prerequisites(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PREREQUISITE_STATES:
            raise ValueError(f"invalid prerequisites: {value!r}")
        return text

    @field_validator("exploit_maturity")
    @classmethod
    def _valid_maturity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXPLOIT_MATURITY_STATES:
            raise ValueError(f"invalid exploit_maturity: {value!r}")
        return text

    @field_validator("fixed_version_state")
    @classmethod
    def _valid_fixed(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FIXED_VERSION_STATES:
            raise ValueError(f"invalid fixed_version_state: {value!r}")
        return text

    @field_validator("patch_state")
    @classmethod
    def _valid_patch(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATCH_STATES:
            raise ValueError(f"invalid patch_state: {value!r}")
        return text

    @field_validator("reference_corroboration")
    @classmethod
    def _valid_corroboration(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CORROBORATION_STATES:
            raise ValueError(f"invalid reference_corroboration: {value!r}")
        return text

    @field_validator("applicability_evidence")
    @classmethod
    def _valid_applicability(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in APPLICABILITY_STATES:
            raise ValueError(f"invalid applicability_evidence: {value!r}")
        return text

    @field_validator("historical_context")
    @classmethod
    def _valid_historical(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HISTORICAL_STATES:
            raise ValueError(f"invalid historical_context: {value!r}")
        return text

    @field_validator("target_exposure")
    @classmethod
    def _valid_exposure(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXPOSURE_STATES:
            raise ValueError(f"invalid target_exposure: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("cve research context analyses are research-only")
        return True


def cve_research_context_analysis_plan_projection(
    value: CVEResearchContextAnalysisPlan,
) -> dict:
    """Serialize an R50.2 context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "OBSERVED",
    "NONE_OBSERVED",
    "CONTEXT_UNKNOWN",
    "CONTEXT_OBSERVATIONS",
    "PRESENCE_OBSERVATION_FIELDS",
    "MATCH_OBSERVED",
    "NO_MATCH_OBSERVED",
    "PARTIAL_MATCH_OBSERVED",
    "MATCH_UNKNOWN",
    "MATCH_STATES",
    "MATCH_FIELD_NAMES",
    "OBSERVED_MATCH_STATES",
    "CVSS_CRITICAL_OBSERVED",
    "CVSS_HIGH_OBSERVED",
    "CVSS_MEDIUM_OBSERVED",
    "CVSS_LOW_OBSERVED",
    "CVSS_NONE_OBSERVED",
    "CVSS_UNKNOWN",
    "CVSS_SEVERITIES",
    "CVSS_RISK_STATES",
    "CVSS_BENIGN_STATES",
    "ATTACK_VECTOR_NETWORK_OBSERVED",
    "ATTACK_VECTOR_ADJACENT_OBSERVED",
    "ATTACK_VECTOR_LOCAL_OBSERVED",
    "ATTACK_VECTOR_PHYSICAL_OBSERVED",
    "ATTACK_VECTOR_UNKNOWN",
    "ATTACK_VECTORS",
    "PREREQUISITES_NONE_OBSERVED",
    "PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED",
    "PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED",
    "PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED",
    "PREREQUISITES_UNKNOWN",
    "PREREQUISITE_STATES",
    "EXPLOIT_MATURITY_NONE_OBSERVED",
    "EXPLOIT_MATURITY_POC_OBSERVED",
    "EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED",
    "EXPLOIT_MATURITY_WEAPONIZED_OBSERVED",
    "EXPLOIT_MATURITY_UNKNOWN",
    "EXPLOIT_MATURITY_STATES",
    "ELEVATED_EXPLOIT_MATURITY_STATES",
    "FIXED_VERSION_AVAILABLE_OBSERVED",
    "FIXED_VERSION_NOT_AVAILABLE_OBSERVED",
    "FIXED_VERSION_APPLIED_OBSERVED",
    "FIXED_VERSION_UNKNOWN",
    "FIXED_VERSION_STATES",
    "REMEDIATION_OBSERVED_STATES",
    "PATCH_AVAILABLE_OBSERVED",
    "PATCH_NOT_AVAILABLE_OBSERVED",
    "PATCH_APPLIED_OBSERVED",
    "PATCH_UNKNOWN",
    "PATCH_STATES",
    "PATCH_PRESENT_STATES",
    "REFERENCE_CORROBORATED_OBSERVED",
    "REFERENCE_SINGLE_SOURCE_OBSERVED",
    "REFERENCE_NONE_OBSERVED",
    "REFERENCE_UNKNOWN",
    "CORROBORATION_STATES",
    "APPLICABILITY_CONFIRMED_OBSERVED",
    "APPLICABILITY_MATCH_OBSERVED",
    "APPLICABILITY_NONE_OBSERVED",
    "APPLICABILITY_UNKNOWN",
    "APPLICABILITY_STATES",
    "APPLICABILITY_EVIDENCE_STATES",
    "HISTORICAL_RECURRING_OBSERVED",
    "HISTORICAL_ISOLATED_OBSERVED",
    "HISTORICAL_UNKNOWN",
    "HISTORICAL_STATES",
    "EXPOSURE_EXPOSED_OBSERVED",
    "EXPOSURE_NOT_EXPOSED_OBSERVED",
    "EXPOSURE_UNKNOWN",
    "EXPOSURE_STATES",
    "ENUM_OBSERVATION_FIELDS",
    "CONTEXT_ANALYSIS_FIELDS",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_cve_research_context_analysis_plan",
    "CVEResearchContextAnalysisPlan",
    "cve_research_context_analysis_plan_projection",
]

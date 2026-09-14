"""Stage R50.2 deterministic CVE research context analyzer.

Classifies CVE-research-relevant context from bounded observations:

    "Which CVE identity, description, product/version, advisory, CWE,
     CVSS, exploit-maturity, reference, patch and exposure signals were
     supplied, and how strong is that research context?"

Hard boundaries encoded here:

- Research intelligence only: no NVD/vendor API call, no web request, no
  reference retrieval, no exploit retrieval, no network access, no
  socket, no DNS, no database, no scanner, no vulnerability reproduction,
  no payload, no subprocess, no LLM. Nothing is fetched or performed.
- CVE metadata presence is never vulnerability: an identifier,
  description, product name, version string, advisory, CWE, CVSS score,
  exploit-maturity label or reference is context only.
- Confidence means "how strong/relevant is the supplied CVE research
  context?". It does NOT mean "probability that the target is
  vulnerable". No vulnerability is confirmed.
- Confidence is HIGH only when the caller supplies explicit structured
  applicability evidence (``CONFIRMED_OBSERVED``) from an external system;
  version/component/CVSS/exploit metadata alone can never produce HIGH.
  MEDIUM requires explicit match/remediation/corroboration evidence;
  otherwise LOW.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.cve_research_context_analysis import (
    APPLICABILITY_CONFIRMED_OBSERVED,
    APPLICABILITY_MATCH_OBSERVED,
    APPLICABILITY_UNKNOWN,
    CONTEXT_OBSERVATIONS,
    ENUM_OBSERVATION_FIELDS,
    MATCH_OBSERVED,
    MATCH_UNKNOWN,
    OBSERVED,
    PRESENCE_OBSERVATION_FIELDS,
    REFERENCE_CORROBORATED_OBSERVED,
    REMEDIATION_OBSERVED_STATES,
    CVEResearchContextAnalysisPlan,
    CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION,
    cve_research_context_analysis_plan_projection,
    sanitize_cve_research_context_analysis_plan,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)

CVE_RESEARCH_CONTEXT_ANALYZER_RULE_VERSION = "r50-2"
RULE_VERSION = CVE_RESEARCH_CONTEXT_ANALYZER_RULE_VERSION


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _known_count(plan: dict) -> int:
    """Count supplied, usable CVE research facts.

    Presence observations count only when explicitly ``OBSERVED``;
    enumerated state fields count any non-``UNKNOWN`` value.
    """

    count = 0
    for name in PRESENCE_OBSERVATION_FIELDS:
        if plan[name] == OBSERVED:
            count += 1
    for name, _allowed, fallback in ENUM_OBSERVATION_FIELDS:
        if plan[name] != fallback:
            count += 1
    return count


def _cve_context_observed(plan: dict) -> bool:
    return _known_count(plan) > 0


def _weakness_observed(plan: dict) -> bool:
    """HIGH context requires explicit structured applicability evidence."""

    if not _cve_context_observed(plan):
        return False
    return plan["applicability_evidence"] == APPLICABILITY_CONFIRMED_OBSERVED


def _control_observed(plan: dict) -> bool:
    """MEDIUM context: explicit match, remediation or corroboration
    evidence (still short of applicability confirmation)."""

    if not _cve_context_observed(plan):
        return False
    if plan["applicability_evidence"] == APPLICABILITY_MATCH_OBSERVED:
        return True
    if plan["version_match"] == MATCH_OBSERVED:
        return True
    if plan["fixed_version_state"] in REMEDIATION_OBSERVED_STATES:
        return True
    if plan["patch_state"] == "PATCH_APPLIED_OBSERVED":
        return True
    if plan["reference_corroboration"] == REFERENCE_CORROBORATED_OBSERVED:
        return True
    return False


def analyze_cve_research_context(
    cve_metadata: object = None,
    vulnerability_description: object = None,
    affected_product: object = None,
    affected_versions: object = None,
    fixed_version: object = None,
    vendor_advisory: object = None,
    cwe_metadata: object = None,
    cvss_metadata: object = None,
    references: object = None,
    patch_information: object = None,
    observed_component: object = None,
    observed_version: object = None,
    technology_mapping: object = None,
    version_match: object = None,
    component_match: object = None,
    advisory_match: object = None,
    cwe_match: object = None,
    cvss_severity: object = None,
    attack_vector: object = None,
    prerequisites: object = None,
    exploit_maturity: object = None,
    fixed_version_state: object = None,
    patch_state: object = None,
    reference_corroboration: object = None,
    applicability_evidence: object = None,
    historical_context: object = None,
    target_exposure: object = None,
) -> dict:
    """Build the deterministic descriptive CVE research analysis.

    Confidence is a pure function of supplied facts: HIGH only with
    explicit structured applicability evidence (``CONFIRMED_OBSERVED``);
    MEDIUM with explicit match/remediation/corroboration evidence; LOW
    with metadata only; UNKNOWN when nothing usable was supplied. No
    vulnerability is confirmed and nothing is fetched.
    """

    supplied = {
        "cve_metadata": cve_metadata,
        "vulnerability_description": vulnerability_description,
        "affected_product": affected_product,
        "affected_versions": affected_versions,
        "fixed_version": fixed_version,
        "vendor_advisory": vendor_advisory,
        "cwe_metadata": cwe_metadata,
        "cvss_metadata": cvss_metadata,
        "references": references,
        "patch_information": patch_information,
        "observed_component": observed_component,
        "observed_version": observed_version,
        "technology_mapping": technology_mapping,
        "version_match": version_match,
        "component_match": component_match,
        "advisory_match": advisory_match,
        "cwe_match": cwe_match,
        "cvss_severity": cvss_severity,
        "attack_vector": attack_vector,
        "prerequisites": prerequisites,
        "exploit_maturity": exploit_maturity,
        "fixed_version_state": fixed_version_state,
        "patch_state": patch_state,
        "reference_corroboration": reference_corroboration,
        "applicability_evidence": applicability_evidence,
        "historical_context": historical_context,
        "target_exposure": target_exposure,
    }

    resolved: dict = {}
    for name in PRESENCE_OBSERVATION_FIELDS:
        resolved[name] = _closed(
            supplied.get(name), CONTEXT_OBSERVATIONS, "UNKNOWN"
        )
    for name, allowed, fallback in ENUM_OBSERVATION_FIELDS:
        resolved[name] = _closed(supplied.get(name), allowed, fallback)

    known_count = _known_count(resolved)
    if known_count == 0:
        confidence = CONFIDENCE_UNKNOWN
    elif _weakness_observed(resolved):
        confidence = CONFIDENCE_HIGH
    elif _control_observed(resolved):
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW

    plan = CVEResearchContextAnalysisPlan(
        rule_version=CVE_RESEARCH_CONTEXT_ANALYSIS_RULE_VERSION,
        context_confidence=confidence,
        research_only=True,
        **resolved,
    )
    return cve_research_context_analysis_plan_projection(plan)


def cve_research_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so
    partial context dicts supplied directly to downstream planners receive
    the correct, safety-capped confidence.
    """

    plan = sanitize_cve_research_context_analysis_plan(value)
    known_count = _known_count(plan)
    if known_count == 0:
        return CONFIDENCE_UNKNOWN
    if _weakness_observed(plan):
        return CONFIDENCE_HIGH
    if _control_observed(plan):
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def cve_research_context_present(value: object) -> bool:
    """True when any usable CVE research context was supplied."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return _cve_context_observed(plan)


def cve_research_context_fact_count(value: object) -> int:
    """Count supplied, usable CVE research facts (pure helper)."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return _known_count(plan)


def applicability_confirmed(value: object) -> bool:
    """True only with explicit structured confirmation evidence."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return plan["applicability_evidence"] == APPLICABILITY_CONFIRMED_OBSERVED


def version_match_observed(value: object) -> bool:
    """True when an affected-version constraint match was observed."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return plan["version_match"] == MATCH_OBSERVED


def remediation_present(value: object) -> bool:
    """True when a fix or applied patch was observed."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return (
        plan["fixed_version_state"] in REMEDIATION_OBSERVED_STATES
        or plan["patch_state"] == "PATCH_APPLIED_OBSERVED"
    )


def match_state_of(value: object, field: object) -> str:
    """Return the bounded match state of a match field."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    key = _text(field)
    if key not in (
        "version_match",
        "component_match",
        "advisory_match",
        "cwe_match",
    ):
        return MATCH_UNKNOWN
    return plan[key]


def weakness_observed(value: object) -> bool:
    """True only when explicit structured applicability evidence exists."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return _weakness_observed(plan)


def control_observed(value: object) -> bool:
    """True only when explicit match/remediation/corroboration evidence
    was supplied."""

    plan = sanitize_cve_research_context_analysis_plan(value)
    return _control_observed(plan)


__all__ = [
    "CVE_RESEARCH_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "cve_research_context_present",
    "cve_research_context_fact_count",
    "analyze_cve_research_context",
    "cve_research_context_confidence_of",
    "applicability_confirmed",
    "version_match_observed",
    "remediation_present",
    "match_state_of",
    "weakness_observed",
    "control_observed",
]

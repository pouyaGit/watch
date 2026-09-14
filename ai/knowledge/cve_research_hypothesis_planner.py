"""Stage R50.3 deterministic CVE research hypothesis planner.

Creates deterministic research hypotheses from supplied CVE context:

    "Which CVE applicability/severity/evidence hypothesis follows from
     the supplied context?"

Hard boundaries encoded here:

- Research hypothesis only: no vulnerability confirmation, no exploit
  claim, no exploit retrieval, no vulnerability reproduction, no payload,
  no attack sequence, no CVE lookup, no network request, no execution.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, state, signals,
  confidence, priority, rationale and limitations are pure functions of
  the bounded context.
- CVE metadata presence is never weakness: a CVE identifier, product
  name, version string, CVSS score, CWE, advisory or exploit-maturity
  label alone never produces a weakness hypothesis.
- Priority is research usefulness only (never severity, exploitability,
  CVSS or vulnerability probability).
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.cve_research_context_analyzer import (
    applicability_confirmed,
    cve_research_context_fact_count,
    cve_research_context_present,
    remediation_present,
    version_match_observed,
)
from ai.schemas.cve_research_context_analysis import (
    APPLICABILITY_CONFIRMED_OBSERVED,
    APPLICABILITY_MATCH_OBSERVED,
    ATTACK_VECTOR_ADJACENT_OBSERVED,
    ATTACK_VECTOR_LOCAL_OBSERVED,
    ATTACK_VECTOR_NETWORK_OBSERVED,
    ATTACK_VECTOR_PHYSICAL_OBSERVED,
    CVSS_BENIGN_STATES,
    CVSS_CRITICAL_OBSERVED,
    CVSS_HIGH_OBSERVED,
    CVSS_MEDIUM_OBSERVED,
    CVSS_RISK_STATES,
    ELEVATED_EXPLOIT_MATURITY_STATES,
    EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED,
    EXPLOIT_MATURITY_NONE_OBSERVED,
    EXPLOIT_MATURITY_POC_OBSERVED,
    EXPLOIT_MATURITY_WEAPONIZED_OBSERVED,
    EXPOSURE_EXPOSED_OBSERVED,
    EXPOSURE_NOT_EXPOSED_OBSERVED,
    FIXED_VERSION_APPLIED_OBSERVED,
    FIXED_VERSION_AVAILABLE_OBSERVED,
    FIXED_VERSION_NOT_AVAILABLE_OBSERVED,
    HISTORICAL_ISOLATED_OBSERVED,
    HISTORICAL_RECURRING_OBSERVED,
    MATCH_OBSERVED,
    NO_MATCH_OBSERVED,
    OBSERVED,
    PARTIAL_MATCH_OBSERVED,
    PATCH_APPLIED_OBSERVED,
    PATCH_AVAILABLE_OBSERVED,
    PATCH_NOT_AVAILABLE_OBSERVED,
    PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED,
    PREREQUISITES_NONE_OBSERVED,
    PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED,
    PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED,
    REFERENCE_CORROBORATED_OBSERVED,
    REFERENCE_NONE_OBSERVED,
    REFERENCE_SINGLE_SOURCE_OBSERVED,
    sanitize_cve_research_context_analysis_plan,
)
from ai.schemas.cve_research_hypothesis import (
    CVE_RESEARCH_HYPOTHESIS_RULE_VERSION,
    CVE_RESEARCH_SIGNALS,
    HYPOTHESIS_TYPES,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_CVE_LOOKUP_CLAIM,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_EXPLOIT_RETRIEVAL_CLAIM,
    LIMITATION_NO_PAYLOAD_GENERATION_CLAIM,
    LIMITATION_NO_REPRODUCTION_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_ADVISORY_MATCH_OBSERVED,
    SIGNAL_ADVISORY_NO_MATCH_OBSERVED,
    SIGNAL_AFFECTED_PRODUCT_OBSERVED,
    SIGNAL_AFFECTED_VERSIONS_OBSERVED,
    SIGNAL_APPLICABILITY_CONFIRMED_OBSERVED,
    SIGNAL_APPLICABILITY_MATCH_OBSERVED,
    SIGNAL_APPLICABILITY_NONE_OBSERVED,
    SIGNAL_ATTACK_VECTOR_ADJACENT,
    SIGNAL_ATTACK_VECTOR_LOCAL,
    SIGNAL_ATTACK_VECTOR_NETWORK,
    SIGNAL_ATTACK_VECTOR_PHYSICAL,
    SIGNAL_COMPONENT_MATCH_OBSERVED,
    SIGNAL_COMPONENT_NO_MATCH_OBSERVED,
    SIGNAL_COMPONENT_PARTIAL_MATCH_OBSERVED,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_CVSS_CRITICAL_OBSERVED,
    SIGNAL_CVSS_HIGH_OBSERVED,
    SIGNAL_CVSS_LOW_OBSERVED,
    SIGNAL_CVSS_MEDIUM_OBSERVED,
    SIGNAL_CVSS_METADATA_OBSERVED,
    SIGNAL_CVSS_NONE_OBSERVED,
    SIGNAL_CWE_MATCH_OBSERVED,
    SIGNAL_CWE_METADATA_OBSERVED,
    SIGNAL_CWE_NO_MATCH_OBSERVED,
    SIGNAL_CVE_METADATA_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_NONE_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_POC_OBSERVED,
    SIGNAL_EXPLOIT_MATURITY_WEAPONIZED_OBSERVED,
    SIGNAL_EXPOSURE_EXPOSED_OBSERVED,
    SIGNAL_EXPOSURE_NOT_EXPOSED_OBSERVED,
    SIGNAL_FIXED_VERSION_AVAILABLE_OBSERVED,
    SIGNAL_FIXED_VERSION_NOT_AVAILABLE_OBSERVED,
    SIGNAL_FIXED_VERSION_OBSERVED,
    SIGNAL_FIX_APPLIED_OBSERVED,
    SIGNAL_HISTORICAL_ISOLATED_OBSERVED,
    SIGNAL_HISTORICAL_RECURRING_OBSERVED,
    SIGNAL_MISSING_CVE_CONTEXT,
    SIGNAL_OBSERVED_COMPONENT_OBSERVED,
    SIGNAL_OBSERVED_VERSION_OBSERVED,
    SIGNAL_PATCH_APPLIED_OBSERVED,
    SIGNAL_PATCH_AVAILABLE_OBSERVED,
    SIGNAL_PATCH_INFORMATION_OBSERVED,
    SIGNAL_PATCH_NOT_AVAILABLE_OBSERVED,
    SIGNAL_PREREQUISITES_AUTHENTICATION_REQUIRED,
    SIGNAL_PREREQUISITES_NONE_OBSERVED,
    SIGNAL_PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED,
    SIGNAL_PREREQUISITES_USER_INTERACTION_REQUIRED,
    SIGNAL_REFERENCE_CORROBORATED_OBSERVED,
    SIGNAL_REFERENCE_NONE_OBSERVED,
    SIGNAL_REFERENCE_SINGLE_SOURCE_OBSERVED,
    SIGNAL_REFERENCES_OBSERVED,
    SIGNAL_TECHNOLOGY_MAPPING_OBSERVED,
    SIGNAL_VENDOR_ADVISORY_OBSERVED,
    SIGNAL_VERSION_MATCH_OBSERVED,
    SIGNAL_VERSION_NO_MATCH_OBSERVED,
    SIGNAL_VERSION_PARTIAL_MATCH_OBSERVED,
    SIGNAL_VULNERABILITY_DESCRIPTION_OBSERVED,
    STATE_CONTROL_PRESENT_OBSERVED,
    STATE_NEEDS_EVIDENCE,
    STATE_NOT_OBSERVED,
    STATE_UNKNOWN,
    STATE_WEAKNESS_OBSERVED,
    TYPE_AFFECTED_VERSION_MATCH,
    TYPE_COMPONENT_MATCH,
    TYPE_CVE_CONTEXT_PRESENT,
    TYPE_CVSS_RISK_SIGNAL,
    TYPE_EXPLOIT_MATURITY_SIGNAL,
    TYPE_EXPOSURE_RELEVANCE,
    TYPE_FIXED_VERSION_GAP,
    TYPE_MISSING_CVE_CONTEXT,
    TYPE_PATCH_AVAILABILITY_GAP,
    TYPE_REFERENCE_CORROBORATION_GAP,
    TYPE_UNKNOWN,
    TYPE_VENDOR_ADVISORY_MATCH,
    TYPE_VERSION_CONSTRAINT_GAP,
    TYPE_VULNERABILITY_DESCRIPTION_MATCH,
    TYPE_CWE_MATCH,
    CVEResearchHypothesisPlan,
    cve_research_hypothesis_plan_projection,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)

CVE_RESEARCH_HYPOTHESIS_PLANNER_RULE_VERSION = "r50-3"
RULE_VERSION = CVE_RESEARCH_HYPOTHESIS_PLANNER_RULE_VERSION

VALIDATION_SIGNALS_LOOKUP: frozenset[str] = frozenset(CVE_RESEARCH_SIGNALS)

PRESENCE_SIGNALS: dict[str, str] = {
    "cve_metadata": SIGNAL_CVE_METADATA_OBSERVED,
    "vulnerability_description": SIGNAL_VULNERABILITY_DESCRIPTION_OBSERVED,
    "affected_product": SIGNAL_AFFECTED_PRODUCT_OBSERVED,
    "affected_versions": SIGNAL_AFFECTED_VERSIONS_OBSERVED,
    "fixed_version": SIGNAL_FIXED_VERSION_OBSERVED,
    "vendor_advisory": SIGNAL_VENDOR_ADVISORY_OBSERVED,
    "cwe_metadata": SIGNAL_CWE_METADATA_OBSERVED,
    "cvss_metadata": SIGNAL_CVSS_METADATA_OBSERVED,
    "references": SIGNAL_REFERENCES_OBSERVED,
    "patch_information": SIGNAL_PATCH_INFORMATION_OBSERVED,
    "observed_component": SIGNAL_OBSERVED_COMPONENT_OBSERVED,
    "observed_version": SIGNAL_OBSERVED_VERSION_OBSERVED,
    "technology_mapping": SIGNAL_TECHNOLOGY_MAPPING_OBSERVED,
}

MATCH_SIGNALS: dict[str, dict[str, str]] = {
    "version_match": {
        MATCH_OBSERVED: SIGNAL_VERSION_MATCH_OBSERVED,
        NO_MATCH_OBSERVED: SIGNAL_VERSION_NO_MATCH_OBSERVED,
        PARTIAL_MATCH_OBSERVED: SIGNAL_VERSION_PARTIAL_MATCH_OBSERVED,
    },
    "component_match": {
        MATCH_OBSERVED: SIGNAL_COMPONENT_MATCH_OBSERVED,
        NO_MATCH_OBSERVED: SIGNAL_COMPONENT_NO_MATCH_OBSERVED,
        PARTIAL_MATCH_OBSERVED: SIGNAL_COMPONENT_PARTIAL_MATCH_OBSERVED,
    },
    "advisory_match": {
        MATCH_OBSERVED: SIGNAL_ADVISORY_MATCH_OBSERVED,
        NO_MATCH_OBSERVED: SIGNAL_ADVISORY_NO_MATCH_OBSERVED,
    },
    "cwe_match": {
        MATCH_OBSERVED: SIGNAL_CWE_MATCH_OBSERVED,
        NO_MATCH_OBSERVED: SIGNAL_CWE_NO_MATCH_OBSERVED,
    },
}

CVSS_SIGNALS: dict[str, str] = {
    CVSS_CRITICAL_OBSERVED: SIGNAL_CVSS_CRITICAL_OBSERVED,
    CVSS_HIGH_OBSERVED: SIGNAL_CVSS_HIGH_OBSERVED,
    CVSS_MEDIUM_OBSERVED: SIGNAL_CVSS_MEDIUM_OBSERVED,
    "LOW_OBSERVED": SIGNAL_CVSS_LOW_OBSERVED,
    "NONE_OBSERVED": SIGNAL_CVSS_NONE_OBSERVED,
}

ATTACK_VECTOR_SIGNALS: dict[str, str] = {
    ATTACK_VECTOR_NETWORK_OBSERVED: SIGNAL_ATTACK_VECTOR_NETWORK,
    ATTACK_VECTOR_ADJACENT_OBSERVED: SIGNAL_ATTACK_VECTOR_ADJACENT,
    ATTACK_VECTOR_LOCAL_OBSERVED: SIGNAL_ATTACK_VECTOR_LOCAL,
    ATTACK_VECTOR_PHYSICAL_OBSERVED: SIGNAL_ATTACK_VECTOR_PHYSICAL,
}

PREREQUISITE_SIGNALS: dict[str, str] = {
    PREREQUISITES_NONE_OBSERVED: SIGNAL_PREREQUISITES_NONE_OBSERVED,
    PREREQUISITES_AUTHENTICATION_REQUIRED_OBSERVED: (
        SIGNAL_PREREQUISITES_AUTHENTICATION_REQUIRED
    ),
    PREREQUISITES_USER_INTERACTION_REQUIRED_OBSERVED: (
        SIGNAL_PREREQUISITES_USER_INTERACTION_REQUIRED
    ),
    PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED_OBSERVED: (
        SIGNAL_PREREQUISITES_PRIVILEGED_ACCESS_REQUIRED
    ),
}

EXPLOIT_MATURITY_SIGNALS: dict[str, str] = {
    EXPLOIT_MATURITY_NONE_OBSERVED: SIGNAL_EXPLOIT_MATURITY_NONE_OBSERVED,
    EXPLOIT_MATURITY_POC_OBSERVED: SIGNAL_EXPLOIT_MATURITY_POC_OBSERVED,
    EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED: (
        SIGNAL_EXPLOIT_MATURITY_FUNCTIONAL_OBSERVED
    ),
    EXPLOIT_MATURITY_WEAPONIZED_OBSERVED: (
        SIGNAL_EXPLOIT_MATURITY_WEAPONIZED_OBSERVED
    ),
}

FIXED_VERSION_SIGNALS: dict[str, str] = {
    FIXED_VERSION_AVAILABLE_OBSERVED: SIGNAL_FIXED_VERSION_AVAILABLE_OBSERVED,
    FIXED_VERSION_NOT_AVAILABLE_OBSERVED: (
        SIGNAL_FIXED_VERSION_NOT_AVAILABLE_OBSERVED
    ),
    FIXED_VERSION_APPLIED_OBSERVED: SIGNAL_FIX_APPLIED_OBSERVED,
}

PATCH_SIGNALS: dict[str, str] = {
    PATCH_AVAILABLE_OBSERVED: SIGNAL_PATCH_AVAILABLE_OBSERVED,
    PATCH_NOT_AVAILABLE_OBSERVED: SIGNAL_PATCH_NOT_AVAILABLE_OBSERVED,
    PATCH_APPLIED_OBSERVED: SIGNAL_PATCH_APPLIED_OBSERVED,
}

CORROBORATION_SIGNALS: dict[str, str] = {
    REFERENCE_CORROBORATED_OBSERVED: SIGNAL_REFERENCE_CORROBORATED_OBSERVED,
    REFERENCE_SINGLE_SOURCE_OBSERVED: SIGNAL_REFERENCE_SINGLE_SOURCE_OBSERVED,
    REFERENCE_NONE_OBSERVED: SIGNAL_REFERENCE_NONE_OBSERVED,
}

APPLICABILITY_SIGNALS: dict[str, str] = {
    APPLICABILITY_CONFIRMED_OBSERVED: (
        SIGNAL_APPLICABILITY_CONFIRMED_OBSERVED
    ),
    APPLICABILITY_MATCH_OBSERVED: SIGNAL_APPLICABILITY_MATCH_OBSERVED,
    "NONE_OBSERVED": SIGNAL_APPLICABILITY_NONE_OBSERVED,
}

HISTORICAL_SIGNALS: dict[str, str] = {
    HISTORICAL_RECURRING_OBSERVED: SIGNAL_HISTORICAL_RECURRING_OBSERVED,
    HISTORICAL_ISOLATED_OBSERVED: SIGNAL_HISTORICAL_ISOLATED_OBSERVED,
}

EXPOSURE_SIGNALS: dict[str, str] = {
    EXPOSURE_EXPOSED_OBSERVED: SIGNAL_EXPOSURE_EXPOSED_OBSERVED,
    EXPOSURE_NOT_EXPOSED_OBSERVED: SIGNAL_EXPOSURE_NOT_EXPOSED_OBSERVED,
}

RATIONALE_TEXTS: dict[str, str] = {
    TYPE_AFFECTED_VERSION_MATCH: (
        "Supplied context indicates an observed affected-version constraint "
        "comparison; this is applicability research context only and no "
        "vulnerability is confirmed."
    ),
    TYPE_VENDOR_ADVISORY_MATCH: (
        "Supplied context indicates a vendor advisory match; advisory "
        "presence alone does not confirm target vulnerability."
    ),
    TYPE_CWE_MATCH: (
        "Supplied context indicates a CWE metadata match; weakness-class "
        "metadata alone is not a vulnerability."
    ),
    TYPE_CVSS_RISK_SIGNAL: (
        "Supplied CVSS severity metadata is a risk signal only; severity is "
        "never vulnerability confirmation."
    ),
    TYPE_EXPLOIT_MATURITY_SIGNAL: (
        "Supplied exploit-maturity metadata is a research signal only; no "
        "exploit was retrieved, generated or executed."
    ),
    TYPE_FIXED_VERSION_GAP: (
        "Supplied context indicates no fixed version or an unapplied fix; "
        "this is remediation research context only."
    ),
    TYPE_COMPONENT_MATCH: (
        "Supplied context indicates a component/technology match; product "
        "name or technology matching alone is not vulnerability."
    ),
    TYPE_VERSION_CONSTRAINT_GAP: (
        "Version constraint information is absent or incomplete for the "
        "observed version; additional structured context is required."
    ),
    TYPE_VULNERABILITY_DESCRIPTION_MATCH: (
        "Supplied vulnerability description context matches; description "
        "text alone is not confirmation."
    ),
    TYPE_REFERENCE_CORROBORATION_GAP: (
        "Reference corroboration is absent or single-source; no reference "
        "was retrieved."
    ),
    TYPE_PATCH_AVAILABILITY_GAP: (
        "Patch availability/application evidence is absent or indicates no "
        "available patch; no package or patch was downloaded."
    ),
    TYPE_EXPOSURE_RELEVANCE: (
        "Supplied target exposure context is a relevance signal only; no "
        "target was probed."
    ),
    TYPE_CVE_CONTEXT_PRESENT: (
        "Supplied context explicitly contains match/remediation/corroboration "
        "evidence; research priority is reduced."
    ),
    TYPE_MISSING_CVE_CONTEXT: (
        "No usable CVE context was supplied; additional structured context "
        "is required."
    ),
    TYPE_UNKNOWN: (
        "Insufficient structured CVE context for a research hypothesis."
    ),
}


def _hypothesis(
    hypothesis_type: str,
    priority: str,
    hypothesis_state: str,
    signals: object,
) -> dict:
    bounded_signals: list[str] = []
    for signal in signals or ():
        if (
            signal
            and signal in VALIDATION_SIGNALS_LOOKUP
            and signal not in bounded_signals
        ):
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_NO_CVE_LOOKUP_CLAIM,
        LIMITATION_NO_EXPLOIT_RETRIEVAL_CLAIM,
        LIMITATION_NO_REPRODUCTION_CLAIM,
        LIMITATION_NO_PAYLOAD_GENERATION_CLAIM,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if priority == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = CVEResearchHypothesisPlan(
        rule_version=CVE_RESEARCH_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        hypothesis_state=hypothesis_state,
        supporting_signals=bounded_signals,
        confidence=priority,
        priority=priority,
        rationale=RATIONALE_TEXTS.get(hypothesis_type, ""),
        limitations=limitations,
        research_only=True,
    )
    return cve_research_hypothesis_plan_projection(plan)


def plan_cve_research_hypotheses(
    context_analysis: object = None,
) -> list[dict]:
    """Build the deterministic CVE research hypotheses (read-only).

    The mapping is conservative and never claims a vulnerability:

    - explicit structured applicability evidence drives the strongest
      research priority (still never a confirmation claim);
    - observed version/component/advisory/CWE matches are context signals;
    - CVSS severity and exploit maturity are risk signals only;
    - missing or not-provided information produces ``NEEDS_EVIDENCE``;
    - nothing usable degrades to ``UNKNOWN``.
    """

    context = sanitize_cve_research_context_analysis_plan(context_analysis)
    has_context = cve_research_context_present(context)
    confirmed = applicability_confirmed(context)
    version_match = version_match_observed(context)
    remediation = remediation_present(context)
    known_count = cve_research_context_fact_count(context)

    presence_signals: list[str] = []
    for name, signal in PRESENCE_SIGNALS.items():
        if context[name] == OBSERVED:
            presence_signals.append(signal)

    version_match_signal = MATCH_SIGNALS["version_match"].get(
        context["version_match"], ""
    )
    component_match_signal = MATCH_SIGNALS["component_match"].get(
        context["component_match"], ""
    )
    advisory_match_signal = MATCH_SIGNALS["advisory_match"].get(
        context["advisory_match"], ""
    )
    cwe_match_signal = MATCH_SIGNALS["cwe_match"].get(
        context["cwe_match"], ""
    )
    cvss_signal = CVSS_SIGNALS.get(context["cvss_severity"], "")
    attack_vector_signal = ATTACK_VECTOR_SIGNALS.get(
        context["attack_vector"], ""
    )
    prerequisite_signal = PREREQUISITE_SIGNALS.get(
        context["prerequisites"], ""
    )
    maturity_signal = EXPLOIT_MATURITY_SIGNALS.get(
        context["exploit_maturity"], ""
    )
    fixed_signal = FIXED_VERSION_SIGNALS.get(
        context["fixed_version_state"], ""
    )
    patch_signal = PATCH_SIGNALS.get(context["patch_state"], "")
    corroboration_signal = CORROBORATION_SIGNALS.get(
        context["reference_corroboration"], ""
    )
    applicability_signal = APPLICABILITY_SIGNALS.get(
        context["applicability_evidence"], ""
    )
    historical_signal = HISTORICAL_SIGNALS.get(
        context["historical_context"], ""
    )
    exposure_signal = EXPOSURE_SIGNALS.get(context["target_exposure"], "")

    base_signals = tuple(presence_signals)

    found: dict[str, tuple] = {}

    def add(
        hypothesis_type: str,
        priority: str,
        hypothesis_state: str,
        signals: object,
    ) -> None:
        if hypothesis_type not in found:
            found[hypothesis_type] = (
                priority,
                hypothesis_state,
                tuple(s for s in signals or () if s),
            )

    if has_context:
        # AFFECTED_VERSION_MATCH
        state = context["version_match"]
        if state == MATCH_OBSERVED:
            priority = CONFIDENCE_HIGH if confirmed else CONFIDENCE_MEDIUM
            add(
                TYPE_AFFECTED_VERSION_MATCH,
                priority,
                STATE_WEAKNESS_OBSERVED,
                (version_match_signal, applicability_signal)
                + base_signals,
            )
        elif state == PARTIAL_MATCH_OBSERVED:
            add(
                TYPE_AFFECTED_VERSION_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (version_match_signal, applicability_signal)
                + base_signals,
            )
        elif state == NO_MATCH_OBSERVED:
            add(
                TYPE_AFFECTED_VERSION_MATCH,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (version_match_signal,) + base_signals,
            )
        elif (
            context["observed_version"] == OBSERVED
            and context["affected_versions"] == OBSERVED
        ):
            add(
                TYPE_AFFECTED_VERSION_MATCH,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_OBSERVED_VERSION_OBSERVED,
                    SIGNAL_AFFECTED_VERSIONS_OBSERVED,
                )
                + base_signals,
            )

        # COMPONENT_MATCH
        state = context["component_match"]
        if state == MATCH_OBSERVED:
            add(
                TYPE_COMPONENT_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (component_match_signal,) + base_signals,
            )
        elif state == PARTIAL_MATCH_OBSERVED:
            add(
                TYPE_COMPONENT_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (component_match_signal,) + base_signals,
            )
        elif state == NO_MATCH_OBSERVED:
            add(
                TYPE_COMPONENT_MATCH,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (component_match_signal,) + base_signals,
            )
        elif (
            context["observed_component"] == OBSERVED
            and context["affected_product"] == OBSERVED
        ):
            add(
                TYPE_COMPONENT_MATCH,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_OBSERVED_COMPONENT_OBSERVED,
                    SIGNAL_AFFECTED_PRODUCT_OBSERVED,
                )
                + base_signals,
            )

        # VENDOR_ADVISORY_MATCH
        state = context["advisory_match"]
        if state == MATCH_OBSERVED:
            add(
                TYPE_VENDOR_ADVISORY_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (advisory_match_signal, SIGNAL_VENDOR_ADVISORY_OBSERVED)
                + base_signals,
            )
        elif state == NO_MATCH_OBSERVED:
            add(
                TYPE_VENDOR_ADVISORY_MATCH,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (advisory_match_signal,),
            )
        elif context["vendor_advisory"] == OBSERVED:
            add(
                TYPE_VENDOR_ADVISORY_MATCH,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_VENDOR_ADVISORY_OBSERVED,) + base_signals,
            )

        # CWE_MATCH
        state = context["cwe_match"]
        if state == MATCH_OBSERVED:
            add(
                TYPE_CWE_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (cwe_match_signal, SIGNAL_CWE_METADATA_OBSERVED)
                + base_signals,
            )
        elif state == NO_MATCH_OBSERVED:
            add(
                TYPE_CWE_MATCH,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (cwe_match_signal,),
            )
        elif context["cwe_metadata"] == OBSERVED:
            add(
                TYPE_CWE_MATCH,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_CWE_METADATA_OBSERVED,) + base_signals,
            )

        # CVSS_RISK_SIGNAL
        severity = context["cvss_severity"]
        cvss_extra = (
            (attack_vector_signal, prerequisite_signal, historical_signal)
        )
        if severity in CVSS_RISK_STATES:
            add(
                TYPE_CVSS_RISK_SIGNAL,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (cvss_signal,) + cvss_extra + base_signals,
            )
        elif severity == CVSS_MEDIUM_OBSERVED:
            add(
                TYPE_CVSS_RISK_SIGNAL,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (cvss_signal,) + cvss_extra + base_signals,
            )
        elif severity in CVSS_BENIGN_STATES:
            add(
                TYPE_CVSS_RISK_SIGNAL,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (cvss_signal,),
            )
        elif context["cvss_metadata"] == OBSERVED:
            add(
                TYPE_CVSS_RISK_SIGNAL,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_CVSS_METADATA_OBSERVED,) + base_signals,
            )

        # EXPLOIT_MATURITY_SIGNAL
        maturity = context["exploit_maturity"]
        if maturity in ELEVATED_EXPLOIT_MATURITY_STATES:
            add(
                TYPE_EXPLOIT_MATURITY_SIGNAL,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (maturity_signal, cvss_signal, prerequisite_signal)
                + base_signals,
            )
        elif maturity == EXPLOIT_MATURITY_POC_OBSERVED:
            add(
                TYPE_EXPLOIT_MATURITY_SIGNAL,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (maturity_signal, cvss_signal) + base_signals,
            )
        elif maturity == EXPLOIT_MATURITY_NONE_OBSERVED:
            add(
                TYPE_EXPLOIT_MATURITY_SIGNAL,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (maturity_signal,),
            )
        elif context["cve_metadata"] == OBSERVED:
            add(
                TYPE_EXPLOIT_MATURITY_SIGNAL,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_CVE_METADATA_OBSERVED,) + base_signals,
            )

        # FIXED_VERSION_GAP
        fixed = context["fixed_version_state"]
        if fixed == FIXED_VERSION_NOT_AVAILABLE_OBSERVED:
            add(
                TYPE_FIXED_VERSION_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (fixed_signal, patch_signal, prerequisite_signal)
                + base_signals,
            )
        elif fixed in (
            FIXED_VERSION_AVAILABLE_OBSERVED,
            FIXED_VERSION_APPLIED_OBSERVED,
        ):
            add(
                TYPE_FIXED_VERSION_GAP,
                CONFIDENCE_LOW,
                STATE_CONTROL_PRESENT_OBSERVED,
                (fixed_signal, SIGNAL_FIXED_VERSION_OBSERVED),
            )
        elif context["affected_versions"] == OBSERVED:
            add(
                TYPE_FIXED_VERSION_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_AFFECTED_VERSIONS_OBSERVED,) + base_signals,
            )

        # VERSION_CONSTRAINT_GAP
        if (
            context["observed_version"] == OBSERVED
            and context["affected_versions"] != OBSERVED
        ):
            add(
                TYPE_VERSION_CONSTRAINT_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_OBSERVED_VERSION_OBSERVED,
                    version_match_signal,
                ),
            )
        elif (
            context["affected_versions"] == OBSERVED
            and context["observed_version"] != OBSERVED
        ):
            add(
                TYPE_VERSION_CONSTRAINT_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (
                    SIGNAL_AFFECTED_VERSIONS_OBSERVED,
                    version_match_signal,
                ),
            )

        # VULNERABILITY_DESCRIPTION_MATCH
        if context["vulnerability_description"] == OBSERVED:
            add(
                TYPE_VULNERABILITY_DESCRIPTION_MATCH,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (SIGNAL_VULNERABILITY_DESCRIPTION_OBSERVED,)
                + base_signals,
            )
        elif context["cve_metadata"] == OBSERVED:
            add(
                TYPE_VULNERABILITY_DESCRIPTION_MATCH,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_CVE_METADATA_OBSERVED,),
            )

        # REFERENCE_CORROBORATION_GAP
        corroboration = context["reference_corroboration"]
        if corroboration == REFERENCE_CORROBORATED_OBSERVED:
            add(
                TYPE_REFERENCE_CORROBORATION_GAP,
                CONFIDENCE_LOW,
                STATE_CONTROL_PRESENT_OBSERVED,
                (corroboration_signal, SIGNAL_REFERENCES_OBSERVED),
            )
        elif corroboration == REFERENCE_SINGLE_SOURCE_OBSERVED:
            add(
                TYPE_REFERENCE_CORROBORATION_GAP,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (corroboration_signal, SIGNAL_REFERENCES_OBSERVED)
                + base_signals,
            )
        elif corroboration == REFERENCE_NONE_OBSERVED:
            add(
                TYPE_REFERENCE_CORROBORATION_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (corroboration_signal,) + base_signals,
            )
        elif context["references"] == OBSERVED:
            add(
                TYPE_REFERENCE_CORROBORATION_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_REFERENCES_OBSERVED,) + base_signals,
            )

        # PATCH_AVAILABILITY_GAP
        patch = context["patch_state"]
        if patch == PATCH_NOT_AVAILABLE_OBSERVED:
            add(
                TYPE_PATCH_AVAILABILITY_GAP,
                CONFIDENCE_MEDIUM,
                STATE_WEAKNESS_OBSERVED,
                (patch_signal, fixed_signal) + base_signals,
            )
        elif patch in (PATCH_AVAILABLE_OBSERVED, PATCH_APPLIED_OBSERVED):
            add(
                TYPE_PATCH_AVAILABILITY_GAP,
                CONFIDENCE_LOW,
                STATE_CONTROL_PRESENT_OBSERVED,
                (patch_signal, SIGNAL_PATCH_INFORMATION_OBSERVED),
            )
        elif context["patch_information"] == OBSERVED:
            add(
                TYPE_PATCH_AVAILABILITY_GAP,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_PATCH_INFORMATION_OBSERVED,) + base_signals,
            )

        # EXPOSURE_RELEVANCE
        exposure = context["target_exposure"]
        if exposure == EXPOSURE_EXPOSED_OBSERVED:
            add(
                TYPE_EXPOSURE_RELEVANCE,
                CONFIDENCE_LOW,
                STATE_WEAKNESS_OBSERVED,
                (exposure_signal, cvss_signal, attack_vector_signal)
                + base_signals,
            )
        elif exposure == EXPOSURE_NOT_EXPOSED_OBSERVED:
            add(
                TYPE_EXPOSURE_RELEVANCE,
                CONFIDENCE_LOW,
                STATE_NOT_OBSERVED,
                (exposure_signal,),
            )
        elif context["cve_metadata"] == OBSERVED:
            add(
                TYPE_EXPOSURE_RELEVANCE,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                base_signals,
            )

        # CVE_CONTEXT_PRESENT
        positive_signals = []
        if confirmed or context["applicability_evidence"] == (
            APPLICABILITY_MATCH_OBSERVED
        ):
            positive_signals.append(applicability_signal)
        if version_match:
            positive_signals.append(version_match_signal)
        if context["advisory_match"] == MATCH_OBSERVED:
            positive_signals.append(advisory_match_signal)
        if context["reference_corroboration"] == (
            REFERENCE_CORROBORATED_OBSERVED
        ):
            positive_signals.append(corroboration_signal)
        if remediation:
            positive_signals.append(fixed_signal)
            positive_signals.append(patch_signal)
        if positive_signals:
            add(
                TYPE_CVE_CONTEXT_PRESENT,
                CONFIDENCE_LOW,
                STATE_CONTROL_PRESENT_OBSERVED,
                tuple(positive_signals),
            )

    if not found:
        if known_count == 0:
            return [
                _hypothesis(
                    TYPE_UNKNOWN,
                    CONFIDENCE_UNKNOWN,
                    STATE_UNKNOWN,
                    (SIGNAL_CONTEXT_UNKNOWN,),
                )
            ]
        return [
            _hypothesis(
                TYPE_MISSING_CVE_CONTEXT,
                CONFIDENCE_LOW,
                STATE_NEEDS_EVIDENCE,
                (SIGNAL_MISSING_CVE_CONTEXT,) + base_signals,
            )
        ]

    hypotheses: list[dict] = []
    for hypothesis_type in HYPOTHESIS_TYPES:
        if hypothesis_type == TYPE_UNKNOWN:
            continue
        if hypothesis_type in found:
            priority, hypothesis_state, signals = found[hypothesis_type]
            hypotheses.append(
                _hypothesis(
                    hypothesis_type,
                    priority,
                    hypothesis_state,
                    signals,
                )
            )
    return hypotheses


__all__ = [
    "CVE_RESEARCH_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_SIGNALS_LOOKUP",
    "PRESENCE_SIGNALS",
    "MATCH_SIGNALS",
    "CVSS_SIGNALS",
    "ATTACK_VECTOR_SIGNALS",
    "PREREQUISITE_SIGNALS",
    "EXPLOIT_MATURITY_SIGNALS",
    "FIXED_VERSION_SIGNALS",
    "PATCH_SIGNALS",
    "CORROBORATION_SIGNALS",
    "APPLICABILITY_SIGNALS",
    "HISTORICAL_SIGNALS",
    "EXPOSURE_SIGNALS",
    "RATIONALE_TEXTS",
    "plan_cve_research_hypotheses",
]

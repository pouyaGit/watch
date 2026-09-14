"""Stage R50.4 deterministic CVE research evidence planner.

Defines which research evidence would be required to evaluate the CVE
research hypotheses:

    "Which bounded CVE research evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no NVD/vendor API call, no web
  request, no reference retrieval, no exploit retrieval, no network
  access, no socket, no DNS, no database, no scanner, no vulnerability
  reproduction, no payload, no execution, no secret extraction, no
  persistence. Nothing is fetched, queried or executed.
- Evidence items describe what would be relevant; they never instruct a
  lookup or an attack.
- Pure and offline: no I/O, no network, no LLM, no target interaction, no
  Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: required evidence categories, planning
  state and confidence are pure functions of the bounded context and
  hypotheses.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.cve_research_context_analyzer import (
    cve_research_context_confidence_of,
)
from ai.knowledge.cve_research_hypothesis_planner import (
    plan_cve_research_hypotheses,
)
from ai.schemas.cve_research_context_analysis import (
    sanitize_cve_research_context_analysis_plan,
)
from ai.schemas.cve_research_evidence_plan import (
    CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION,
    EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION,
    EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
    EVIDENCE_APPLICABILITY_EVIDENCE,
    EVIDENCE_ATTACK_VECTOR_CONTEXT,
    EVIDENCE_COMPONENT_MATCH_EVIDENCE,
    EVIDENCE_CVE_IDENTITY_REFERENCE,
    EVIDENCE_CVE_RESEARCH_CONTEXT,
    EVIDENCE_CVSS_METADATA,
    EVIDENCE_CWE_REFERENCE,
    EVIDENCE_EXPLOIT_MATURITY_SOURCE,
    EVIDENCE_FIXED_VERSION_INFORMATION,
    EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION,
    EVIDENCE_OBSERVED_VERSION_IDENTIFICATION,
    EVIDENCE_PATCH_APPLICATION_STATE,
    EVIDENCE_PATCH_AVAILABILITY,
    EVIDENCE_PREREQUISITE_CONTEXT,
    EVIDENCE_REFERENCE_CORROBORATION,
    EVIDENCE_REFERENCE_PROVENANCE,
    EVIDENCE_TARGET_EXPOSURE_CONTEXT,
    EVIDENCE_TECHNOLOGY_MAPPING,
    EVIDENCE_UNKNOWN,
    EVIDENCE_VENDOR_ADVISORY,
    EVIDENCE_VERSION_CONSTRAINT_COMPARISON,
    EVIDENCE_VULNERABILITY_DESCRIPTION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_CVE_LOOKUP,
    LIMITATION_NO_EXPLOIT_RETRIEVAL,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_REFERENCE_RETRIEVAL,
    LIMITATION_NO_VULNERABILITY_REPRODUCTION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    CVEResearchEvidencePlan,
    cve_research_evidence_plan_projection,
)
from ai.schemas.cve_research_hypothesis import (
    TYPE_AFFECTED_VERSION_MATCH,
    TYPE_COMPONENT_MATCH,
    TYPE_CVE_CONTEXT_PRESENT,
    TYPE_CVSS_RISK_SIGNAL,
    TYPE_CWE_MATCH,
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
    sanitize_cve_research_hypothesis_plan,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)

CVE_RESEARCH_EVIDENCE_PLANNER_RULE_VERSION = "r50-4"
RULE_VERSION = CVE_RESEARCH_EVIDENCE_PLANNER_RULE_VERSION

# hypothesis type -> required evidence categories (fixed order)
HYPOTHESIS_EVIDENCE: dict[str, tuple] = {
    TYPE_AFFECTED_VERSION_MATCH: (
        EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
        EVIDENCE_OBSERVED_VERSION_IDENTIFICATION,
        EVIDENCE_VERSION_CONSTRAINT_COMPARISON,
        EVIDENCE_APPLICABILITY_EVIDENCE,
    ),
    TYPE_COMPONENT_MATCH: (
        EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION,
        EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION,
        EVIDENCE_COMPONENT_MATCH_EVIDENCE,
        EVIDENCE_TECHNOLOGY_MAPPING,
    ),
    TYPE_VENDOR_ADVISORY_MATCH: (
        EVIDENCE_VENDOR_ADVISORY,
        EVIDENCE_REFERENCE_PROVENANCE,
    ),
    TYPE_CWE_MATCH: (
        EVIDENCE_CWE_REFERENCE,
        EVIDENCE_CVE_IDENTITY_REFERENCE,
    ),
    TYPE_CVSS_RISK_SIGNAL: (
        EVIDENCE_CVSS_METADATA,
        EVIDENCE_ATTACK_VECTOR_CONTEXT,
        EVIDENCE_PREREQUISITE_CONTEXT,
    ),
    TYPE_EXPLOIT_MATURITY_SIGNAL: (
        EVIDENCE_EXPLOIT_MATURITY_SOURCE,
        EVIDENCE_REFERENCE_CORROBORATION,
    ),
    TYPE_FIXED_VERSION_GAP: (
        EVIDENCE_FIXED_VERSION_INFORMATION,
        EVIDENCE_PATCH_APPLICATION_STATE,
    ),
    TYPE_VERSION_CONSTRAINT_GAP: (
        EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
        EVIDENCE_OBSERVED_VERSION_IDENTIFICATION,
    ),
    TYPE_VULNERABILITY_DESCRIPTION_MATCH: (
        EVIDENCE_VULNERABILITY_DESCRIPTION,
        EVIDENCE_CVE_IDENTITY_REFERENCE,
    ),
    TYPE_REFERENCE_CORROBORATION_GAP: (
        EVIDENCE_REFERENCE_CORROBORATION,
        EVIDENCE_REFERENCE_PROVENANCE,
    ),
    TYPE_PATCH_AVAILABILITY_GAP: (
        EVIDENCE_PATCH_AVAILABILITY,
        EVIDENCE_PATCH_APPLICATION_STATE,
    ),
    TYPE_EXPOSURE_RELEVANCE: (
        EVIDENCE_TARGET_EXPOSURE_CONTEXT,
        EVIDENCE_TECHNOLOGY_MAPPING,
    ),
    TYPE_CVE_CONTEXT_PRESENT: (
        EVIDENCE_CVE_RESEARCH_CONTEXT,
        EVIDENCE_APPLICABILITY_EVIDENCE,
    ),
    TYPE_MISSING_CVE_CONTEXT: (
        EVIDENCE_CVE_IDENTITY_REFERENCE,
        EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION,
        EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
    ),
    TYPE_UNKNOWN: (EVIDENCE_UNKNOWN,),
}


def _hypotheses(value: object) -> list[dict]:
    if isinstance(value, dict):
        raw = [value]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raw = []
    return [
        sanitize_cve_research_hypothesis_plan(item)
        for item in raw
        if isinstance(item, dict)
    ]


def plan_cve_research_evidence(
    context_analysis: object = None,
    hypotheses: object = None,
) -> dict:
    """Build the deterministic evidence plan (read-only).

    Required categories are the ordered union of the per-hypothesis
    evidence mappings. The planning state is ``UNKNOWN`` when nothing can
    be planned and ``COMPLETE`` only when the supplied context is HIGH
    confidence, no ``UNKNOWN`` hypothesis remains, and at least one
    substantive (non missing-context) hypothesis is present. A context
    that only degrades to ``MISSING_CVE_CONTEXT`` can never be
    ``COMPLETE``. Otherwise the state is ``PARTIAL``. No evidence is
    collected and no lookup, network or reproduction activity occurs.
    """

    context = sanitize_cve_research_context_analysis_plan(context_analysis)
    if hypotheses is None:
        plans = _hypotheses(plan_cve_research_hypotheses(context))
    else:
        plans = _hypotheses(hypotheses)

    items: list[str] = []
    for plan in plans:
        for item in HYPOTHESIS_EVIDENCE.get(
            plan["hypothesis_type"], (EVIDENCE_UNKNOWN,)
        ):
            if item not in items:
                items.append(item)

    substantive_plans = [
        plan
        for plan in plans
        if plan["hypothesis_type"]
        not in (TYPE_UNKNOWN, TYPE_MISSING_CVE_CONTEXT)
    ]
    context_confidence = cve_research_context_confidence_of(context)
    if not plans or items == [EVIDENCE_UNKNOWN]:
        state = STATE_UNKNOWN
    elif (
        context_confidence == CONFIDENCE_HIGH
        and substantive_plans
        and all(
            plan["hypothesis_type"] != TYPE_UNKNOWN for plan in plans
        )
    ):
        state = STATE_COMPLETE
    else:
        state = STATE_PARTIAL

    if state == STATE_UNKNOWN:
        confidence = CONFIDENCE_UNKNOWN
    elif state == STATE_COMPLETE:
        confidence = CONFIDENCE_HIGH
    else:
        confidence = (
            CONFIDENCE_UNKNOWN
            if context_confidence == CONFIDENCE_UNKNOWN
            else CONFIDENCE_LOW
        )

    limitations = [
        LIMITATION_NO_COLLECTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_CVE_LOOKUP,
        LIMITATION_NO_REFERENCE_RETRIEVAL,
        LIMITATION_NO_EXPLOIT_RETRIEVAL,
        LIMITATION_NO_VULNERABILITY_REPRODUCTION,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == STATE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = CVEResearchEvidencePlan(
        rule_version=CVE_RESEARCH_EVIDENCE_PLAN_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return cve_research_evidence_plan_projection(plan)


__all__ = [
    "CVE_RESEARCH_EVIDENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HYPOTHESIS_EVIDENCE",
    "plan_cve_research_evidence",
]

"""Stage R53.2 deterministic finding reasoning (pure engine).

Builds the identity, descriptive context, endpoint/component metadata,
impact description and remediation context of a finding candidate:

    "What structured description follows from the supplied research result?"

Hard boundaries encoded here:

- Description only: every value is assembled from structured upstream data.
  No application-specific detail, business impact or target interaction is
  invented, and no vulnerability is confirmed.
- Fixed mappings: category labels and potential-impact statements are closed
  deterministic maps; they describe the research category, never a specific
  application.
- Deterministic identity: the finding id is a content token derived from the
  originating structured result, so the same result always yields the same
  finding id.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.schemas.finding_assessment import (
    IMPACT_POTENTIAL,
    IMPACT_UNKNOWN,
    REMEDIATION_AVAILABLE,
    REMEDIATION_RESEARCH_QUALITY,
    REMEDIATION_UNAVAILABLE,
    SEVERITY_SOURCE_CVSS_CONTEXT,
    SEVERITY_SOURCE_NOT_ASSESSED,
    STATE_INSUFFICIENT_EVIDENCE,
)
from ai.schemas.finding_assessment import (
    FINDING_ASSESSMENT_RULE_VERSION,
)
from ai.schemas.finding_context import (
    ENDPOINT_PRESENT,
    ENDPOINT_UNAVAILABLE,
    FINDING_CONTEXT_RULE_VERSION,
)
from ai.schemas.finding_identity import (
    FINDING_ID_PREFIX,
    FINDING_IDENTITY_RULE_VERSION,
)
from ai.schemas.cve_research_context_analysis import (
    CVSS_SEVERITIES,
    CVSS_UNKNOWN,
)
from ai.schemas.security_agent_identity import (
    CATEGORY_CVE_RESEARCH,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_SQLI,
    CATEGORY_SSRF,
    CATEGORY_XSS,
)

FINDING_REASONING_RULE_VERSION = "r53-2"
RULE_VERSION = FINDING_REASONING_RULE_VERSION

#: Fixed descriptive labels for the canonical R38 categories.
CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_XSS: "Cross-Site Scripting (XSS)",
    CATEGORY_SSRF: "Server-Side Request Forgery (SSRF)",
    CATEGORY_SQLI: "SQL Injection (SQLi)",
    CATEGORY_IDOR: "Insecure Direct Object Reference / BOLA (IDOR/BOLA)",
    CATEGORY_JWT: "JWT / Authentication Token Security",
    CATEGORY_OAUTH: "OAuth Authorization Flow Security",
    CATEGORY_RECON: "API Security",
    CATEGORY_CVE_RESEARCH: "CVE / Vulnerability Research",
}

#: Fixed potential-impact statements. They describe the research category and
#: explicitly record that nothing was executed and no impact was observed.
CATEGORY_IMPACT_TEXT: dict[str, str] = {
    CATEGORY_XSS: (
        "Potential impact is limited to the observed client-side output "
        "context. No request, browser execution or payload delivery was "
        "performed and no impact is confirmed."
    ),
    CATEGORY_SSRF: (
        "Potential impact is limited to the observed server-side fetch "
        "context. No request, DNS resolution or internal access was "
        "performed and no impact is confirmed."
    ),
    CATEGORY_SQLI: (
        "Potential impact is limited to the observed query and parameter "
        "context. No query was executed and no impact is confirmed."
    ),
    CATEGORY_IDOR: (
        "Potential impact is limited to the observed object-authorization "
        "context. No object access was attempted and no impact is confirmed."
    ),
    CATEGORY_JWT: (
        "Potential impact is limited to the observed token-authentication "
        "context. No token was manipulated and no impact is confirmed."
    ),
    CATEGORY_OAUTH: (
        "Potential impact is limited to the observed authorization-flow "
        "context. No flow was exercised and no impact is confirmed."
    ),
    CATEGORY_RECON: (
        "Potential impact is limited to the observed API and authorization "
        "context. No endpoint was contacted and no impact is confirmed."
    ),
    CATEGORY_CVE_RESEARCH: (
        "Potential impact is limited to the observed component, version and "
        "vulnerability-research context. Applicability is not confirmed and "
        "no impact is confirmed."
    ),
}

#: Structured context keys that carry endpoint/component metadata. Values are
#: carried through as observed structured facts, never interpreted as
#: verified inventory.
COMPONENT_NAME_KEYS: tuple[str, ...] = (
    "observed_component",
    "api_type",
    "technology_mapping",
)
COMPONENT_VERSION_KEYS: tuple[str, ...] = (
    "observed_version",
    "affected_versions",
    "api_versioning",
)
ENDPOINT_REFERENCE_KEYS: tuple[str, ...] = (
    "endpoint_metadata",
    "route_context",
    "authorization_endpoint",
    "token_endpoint",
)

MAX_FACTS = 12
MAX_TECHNICAL_ITEMS = 8


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def category_label(category: object) -> str:
    """Fixed descriptive label for a canonical category."""

    return CATEGORY_LABELS.get(_upper(category), "")


def descriptive_label(category: object) -> str:
    """Fixed finding-candidate label for a canonical category."""

    label = CATEGORY_LABELS.get(_upper(category))
    if not label:
        return ""
    return f"{label} research finding candidate"


def known_context_facts(
    context_analysis: object,
    limit: int = MAX_FACTS,
) -> list[dict]:
    """Extract known (non-empty, non-UNKNOWN) structured context facts.

    Keys are the specialist's own context keys; values are carried through
    unchanged and bounded. Nothing is inferred.
    """

    if not isinstance(context_analysis, dict):
        return []
    facts: list[dict] = []
    for key in sorted(context_analysis.keys(), key=lambda item: str(item)):
        if len(facts) >= limit:
            break
        name = _text(key)
        if not name or name in ("rule_version", "research_only"):
            continue
        raw = context_analysis.get(key)
        if isinstance(raw, bool):
            facts.append({"key": name, "value": str(raw)})
            continue
        if isinstance(raw, (int, float)):
            facts.append({"key": name, "value": str(raw)})
            continue
        if isinstance(raw, str):
            text = _text(raw)
            if text and text.upper() != "UNKNOWN":
                facts.append({"key": name, "value": text})
            continue
        if isinstance(raw, (list, tuple)):
            items = [str(item) for item in raw if _text(item)]
            if items:
                facts.append({"key": name, "value": ", ".join(items)[:160]})
            continue
    return facts


def _first_context_value(
    context_analysis: object, keys: tuple[str, ...]
) -> str:
    if not isinstance(context_analysis, dict):
        return ""
    for key in keys:
        raw = context_analysis.get(key)
        if isinstance(raw, str):
            text = _text(raw)
            if text and text.upper() != "UNKNOWN":
                return text
    return ""


def extract_endpoint_component(
    context_analysis: object,
) -> dict:
    """Extract endpoint/component metadata from structured context.

    ``availability`` is ``PRESENT`` only when at least one structured
    endpoint/component value is known; otherwise it is ``UNAVAILABLE``.
    """

    component_name = _first_context_value(
        context_analysis, COMPONENT_NAME_KEYS
    )
    component_version = _first_context_value(
        context_analysis, COMPONENT_VERSION_KEYS
    )
    endpoint_reference = _first_context_value(
        context_analysis, ENDPOINT_REFERENCE_KEYS
    )
    present = bool(
        component_name or component_version or endpoint_reference
    )
    return {
        "availability": ENDPOINT_PRESENT if present else ENDPOINT_UNAVAILABLE,
        "component_name": component_name,
        "component_version": component_version,
        "endpoint_reference": endpoint_reference,
    }


def compute_finding_id(
    category: object,
    agent_id: object,
    result_rule_version: object,
    hypothesis_types: object,
    evidence_items: object,
    context_rule_version: object,
) -> str:
    """Deterministic content id for a finding candidate.

    The basis contains only structured, deterministic values: the canonical
    category, the originating agent id, the originating result rule version,
    the ordered hypothesis types, the ordered evidence requirements and the
    context rule version. No clock, no randomness, no orchestration id (so
    the same specialist result always produces the same finding id).
    """

    basis = json.dumps(
        {
            "rule_version": FINDING_IDENTITY_RULE_VERSION,
            "category": _upper(category),
            "agent_id": _text(agent_id),
            "result_rule_version": _text(result_rule_version),
            "hypothesis_types": [
                _upper(item) for item in hypothesis_types or ()
            ],
            "evidence_items": [
                _upper(item) for item in evidence_items or ()
            ],
            "context_rule_version": _text(context_rule_version),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return FINDING_ID_PREFIX + digest[:16]


def build_finding_identity(
    category: object,
    specialist_name: object = "",
    agent_id: object = "",
    result_rule_version: object = "",
    hypothesis_types: object = None,
    evidence_items: object = None,
    context_rule_version: object = "",
) -> dict:
    """Build the deterministic finding identity (read-only)."""

    resolved_category = _upper(category)
    return {
        "rule_version": FINDING_IDENTITY_RULE_VERSION,
        "finding_id": compute_finding_id(
            resolved_category,
            agent_id,
            result_rule_version,
            hypothesis_types,
            evidence_items,
            context_rule_version,
        ),
        "category": resolved_category,
        "specialist_name": _text(specialist_name),
        "agent_id": _text(agent_id),
        "category_label": category_label(resolved_category),
        "descriptive_label": descriptive_label(resolved_category),
        "research_only": True,
    }


def build_finding_context(
    category: object,
    specialist_name: object,
    context_analysis: object,
    hypotheses: object,
    evidence: object,
) -> dict:
    """Build the descriptive research context (read-only).

    The technical description is a deterministic composition of the actual
    structured hypothesis types, evidence requirements and observed context
    facts; nothing is invented.
    """

    facts = known_context_facts(context_analysis)
    hypothesis_types: list[str] = []
    for hypothesis in hypotheses or ():
        if not isinstance(hypothesis, dict):
            continue
        hypothesis_type = _upper(hypothesis.get("hypothesis_type"))
        if hypothesis_type and hypothesis_type != "UNKNOWN" and (
            hypothesis_type not in hypothesis_types
        ):
            hypothesis_types.append(hypothesis_type)
        if len(hypothesis_types) >= MAX_TECHNICAL_ITEMS:
            break
    evidence_items: list[str] = []
    if isinstance(evidence, dict):
        for item in evidence.get("planned_requirements") or ():
            text = _upper(item)
            if text and text not in evidence_items:
                evidence_items.append(text)
            if len(evidence_items) >= MAX_TECHNICAL_ITEMS:
                break

    label = category_label(category)
    resolved_specialist = _text(specialist_name) or "specialist"
    title = f"{label} research finding candidate"
    summary = (
        f"{resolved_specialist} produced {len(hypothesis_types)} "
        f"structured hypothesis type(s) for {label}; "
        f"{len(evidence_items)} evidence requirement(s) and "
        f"{len(facts)} observed context fact(s) are linked. "
        "No execution was performed and no vulnerability is confirmed."
    )
    description_parts = [
        f"Research category: {label}.",
        "Hypothesis types: "
        + (", ".join(hypothesis_types) if hypothesis_types else "UNKNOWN")
        + ".",
        "Evidence requirements: "
        + (", ".join(evidence_items) if evidence_items else "NONE_PLANNED")
        + ".",
        "Observed context facts: "
        + (
            "; ".join(
                f"{fact['key']}={fact['value']}" for fact in facts
            )
            if facts
            else "NONE"
        )
        + ".",
        "This is a research finding candidate derived from structured "
        "specialist output; it is not a confirmed vulnerability.",
    ]
    return {
        "rule_version": FINDING_CONTEXT_RULE_VERSION,
        "title": title,
        "summary": summary,
        "technical_description": " ".join(description_parts),
        "affected_context": facts,
        "endpoint_component": extract_endpoint_component(context_analysis),
        "context_fact_count": len(facts),
        "research_only": True,
    }


def build_impact(
    category: object,
    has_hypotheses: bool,
    confidence: object,
) -> dict:
    """Build the potential-impact reasoning (read-only).

    ``OBSERVED`` impact is never produced by R53: without an explicit
    structured observed-impact contract the impact stays ``POTENTIAL`` (when
    hypotheses exist) or ``UNKNOWN``.
    """

    if not has_hypotheses:
        return {
            "impact_state": IMPACT_UNKNOWN,
            "impact_confidence": "UNKNOWN",
            "impact_description": "",
        }
    impact_state = IMPACT_POTENTIAL
    impact_confidence = _cap_impact_confidence(confidence)
    return {
        "impact_state": impact_state,
        "impact_confidence": impact_confidence,
        "impact_description": CATEGORY_IMPACT_TEXT.get(
            _upper(category), ""
        ),
    }


def _cap_impact_confidence(confidence: object) -> str:
    """Impact confidence never exceeds the finding confidence and MEDIUM."""

    text = _upper(confidence)
    if text == "HIGH":
        return "MEDIUM"
    if text in ("MEDIUM", "LOW"):
        return text
    return "UNKNOWN"


def build_severity(
    category: object,
    context_analysis: object,
) -> dict:
    """Mirror observed CVSS severity metadata, or stay NOT_ASSESSED.

    R53 never computes severity. Only an explicitly observed CVSS severity
    value in the CVE research context is mirrored; everything else stays
    ``UNKNOWN``.
    """

    if _upper(category) != CATEGORY_CVE_RESEARCH:
        return {
            "severity": CVSS_UNKNOWN,
            "severity_source": SEVERITY_SOURCE_NOT_ASSESSED,
        }
    raw = (
        context_analysis.get("cvss_severity")
        if isinstance(context_analysis, dict)
        else None
    )
    value = _upper(raw)
    if value in CVSS_SEVERITIES and value != CVSS_UNKNOWN:
        return {
            "severity": value,
            "severity_source": SEVERITY_SOURCE_CVSS_CONTEXT,
        }
    return {
        "severity": CVSS_UNKNOWN,
        "severity_source": SEVERITY_SOURCE_NOT_ASSESSED,
    }


def build_remediation(evaluation: object) -> dict:
    """Mirror upstream structured remediation hints, or stay UNAVAILABLE.

    Only R42 diagnostic remediation hints are used; no application-specific
    fix is ever invented.
    """

    items: list[dict] = []
    if isinstance(evaluation, dict):
        for diagnostic in evaluation.get("diagnostics") or ():
            if not isinstance(diagnostic, dict):
                continue
            hint = _text(diagnostic.get("remediation_hint"))
            code = _upper(diagnostic.get("diagnostic_code"))
            if not hint:
                continue
            item = {
                "remediation_type": REMEDIATION_RESEARCH_QUALITY,
                "guidance": hint,
                "source": code,
            }
            if item not in items:
                items.append(item)
            if len(items) >= 8:
                break
    return {
        "remediation_state": (
            REMEDIATION_AVAILABLE if items else REMEDIATION_UNAVAILABLE
        ),
        "remediation_items": items,
    }


def build_assessment(
    category: object,
    state: object,
    confidence: object,
    confidence_reasons: object,
    context_analysis: object,
    evaluation: object,
    has_hypotheses: bool,
) -> dict:
    """Assemble the bounded assessment block from derived reasoning."""

    impact = build_impact(category, has_hypotheses, confidence)
    severity = build_severity(category, context_analysis)
    remediation = build_remediation(evaluation)
    return {
        "rule_version": FINDING_ASSESSMENT_RULE_VERSION,
        "state": _upper(state) or STATE_INSUFFICIENT_EVIDENCE,
        "confidence": _upper(confidence) or "UNKNOWN",
        "confidence_reasons": list(confidence_reasons or ()),
        **impact,
        **severity,
        **remediation,
        "business_impact_asserted": False,
    }


__all__ = [
    "FINDING_REASONING_RULE_VERSION",
    "RULE_VERSION",
    "CATEGORY_LABELS",
    "CATEGORY_IMPACT_TEXT",
    "COMPONENT_NAME_KEYS",
    "COMPONENT_VERSION_KEYS",
    "ENDPOINT_REFERENCE_KEYS",
    "category_label",
    "descriptive_label",
    "known_context_facts",
    "extract_endpoint_component",
    "compute_finding_id",
    "build_finding_identity",
    "build_finding_context",
    "build_impact",
    "build_severity",
    "build_remediation",
    "build_assessment",
]

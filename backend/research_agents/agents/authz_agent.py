"""backend/research_agents/agents/authz_agent.py — AuthZ research agent (v1).

Produces an investigation plan for access-control candidates
(``AUTHZ_CANDIDATE`` / ``AUTHORIZATION_CANDIDATE``). It identifies privileged
endpoints and identity/ownership parameters and lists the authorization
evidence a researcher must collect before any conclusion.

It does **not** replay another user's session, does not enumerate accounts and
never confirms a broken access-control vulnerability.
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    bump_confidence,
    confidence_for,
    is_api_endpoint,
    is_identifier,
    is_privileged_endpoint,
    is_stateful,
    present_evidence_types,
    report_section,
)
from backend.research_agents.models import CandidateRef

KEY = "authz"
NAME = "AuthZ Research Agent"
CATEGORY = "authz"
DESCRIPTION = (
    "Plans broken access-control investigation and authorization evidence."
)

STRATEGY = (
    "identify the privileged endpoint and the identity/ownership parameter",
    "record baseline response metadata for the current principal",
    "compare responses across authorization contexts (observation only)",
    "classify authorization behavior and the ownership model",
    "request explicit multi-identity authorization before any comparison",
)

CONFIDENCE_MODEL = (
    "candidate-derived: declared confidence, else priority score "
    "(>=80 HIGH, >=55 MEDIUM, else LOW); raised one level only when all "
    "planned evidence artifacts are collected"
)

REPORT_SECTIONS = (
    "target", "endpoint", "evidence", "confidence", "missing proof",
    "researcher notes",
)

EVIDENCE_TYPES = (
    "authorization comparison",
    "role/ownership context",
    "access-control matrix",
    "response difference",
)

_SIGNALS = (
    "privileged endpoint",
    "identity/ownership parameter",
    "authorization boundary unknown",
)
_BLOCKERS = (
    "authorization boundary unknown",
    "multi-identity context unavailable",
    "ownership model unknown",
)


def analyze(candidate: CandidateRef) -> dict:
    """Return the AuthZ investigation plan for one candidate (pure)."""

    signals: list[str] = []
    if is_privileged_endpoint(candidate.endpoint):
        signals.append("privileged endpoint")
    if is_identifier(candidate.parameter):
        signals.append("identity/ownership parameter")
    if candidate.parameter:
        signals.append(f"candidate parameter: {candidate.parameter}")
    if is_api_endpoint(candidate.endpoint):
        signals.append("API endpoint")
    if not signals:
        signals = list(_SIGNALS)
    if is_stateful(candidate.method):
        signals.append(f"state-changing method ({candidate.method})")
    if candidate.technology:
        signals.append("technology context: " + ", ".join(candidate.technology))

    return {
        "agent": NAME,
        "confidence": confidence_for(candidate),
        "signals": _dedupe(signals),
        "strategy": list(STRATEGY),
        "evidence_required": list(EVIDENCE_TYPES),
        "blockers": list(_BLOCKERS),
        "findings": [],
    }


#: Human evidence requirement -> the artifact type that satisfies it.
EVIDENCE_MAP: dict[str, str] = {
    "authorization comparison": "HTTP_METADATA",
    "role/ownership context": "TECHNOLOGY_CONTEXT",
    "access-control matrix": "PARAMETER_BEHAVIOR",
    "response difference": "RESPONSE_COMPARISON",
}


def analyze_evidence(candidate, artifacts) -> dict:
    """Consume collected evidence and update the AuthZ investigation state."""

    ref = CandidateRef.from_any(candidate)
    base = confidence_for(ref)
    present = present_evidence_types(artifacts)
    missing = [
        requirement for requirement, artifact_type in EVIDENCE_MAP.items()
        if artifact_type not in present
    ]
    if not missing:
        confidence = bump_confidence(base, 1)
        next_action = (
            "evidence complete for this plan; review it and prepare a report "
            "candidate for a human researcher"
        )
    else:
        confidence = base
        next_action = "collect missing evidence: " + ", ".join(missing)
    return {
        "agent": NAME,
        "confidence": confidence,
        "base_confidence": base,
        "missing_evidence": missing,
        "evidence_present": sorted(present),
        "next_action": next_action,
        "observed": sorted(present),
        "blockers": list(_BLOCKERS),
    }


def report(candidate, analysis) -> dict:
    """The AuthZ agent's section of a Security Research Report."""

    ref = CandidateRef.from_any(candidate)
    analysis = analysis if isinstance(analysis, dict) else {}
    return report_section(
        agent=NAME,
        target=ref.program or ref.subdomain or ref.url or ref.endpoint,
        endpoint=ref.endpoint,
        parameter=ref.parameter,
        confidence=str(analysis.get("confidence") or confidence_for(ref)),
        strategy=STRATEGY,
        evidence_present=analysis.get("evidence_present") or (),
        missing_evidence=analysis.get("missing_evidence") or (),
        next_action=str(analysis.get("next_action") or ""),
        signals=analysis.get("observed") or (),
        blockers=analysis.get("blockers") or _BLOCKERS,
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = " ".join(str(value or "").split())
        if text and text not in out:
            out.append(text)
    return out


__all__ = [
    "KEY",
    "NAME",
    "CATEGORY",
    "DESCRIPTION",
    "STRATEGY",
    "CONFIDENCE_MODEL",
    "REPORT_SECTIONS",
    "EVIDENCE_TYPES",
    "EVIDENCE_MAP",
    "analyze",
    "analyze_evidence",
    "report",
]

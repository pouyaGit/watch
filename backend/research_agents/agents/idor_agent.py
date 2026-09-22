"""backend/research_agents/agents/idor_agent.py — IDOR research agent (v1).

Produces an investigation plan for an ``IDOR_CANDIDATE``: the signals that make
it interesting, the evidence a researcher must collect, and the blockers that
currently prevent any conclusion. It does **not** make requests, compare live
responses or confirm an authorization boundary.
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    bump_confidence,
    confidence_for,
    is_api_endpoint,
    is_identifier,
    is_stateful,
    present_evidence_types,
    report_section,
)
from backend.research_agents.models import CandidateRef

KEY = "idor"
NAME = "IDOR Research Agent"
CATEGORY = "idor"
DESCRIPTION = "Plans object-reference investigation and authorization evidence."

STRATEGY = (
    "identify the object-reference parameter and endpoint shape",
    "capture the baseline response metadata for the referenced object",
    "compare responses for two distinct object references",
    "capture the ownership/technology context (observation only)",
    "request an explicit multi-identity authorization before any replay",
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
    "object ownership context",
    "response difference",
)

_SIGNALS = (
    "numeric identifier",
    "object reference parameter",
    "API endpoint",
)
_BLOCKERS = (
    "authorization boundary unknown",
    "object ownership context unknown",
)


def analyze(candidate: CandidateRef) -> dict:
    """Return the IDOR investigation plan for one candidate (pure)."""

    signals: list[str] = []
    if is_identifier(candidate.parameter):
        signals.append("numeric identifier")
    if candidate.parameter:
        signals.append("object reference parameter")
        signals.append(f"candidate parameter: {candidate.parameter}")
    if is_api_endpoint(candidate.endpoint):
        signals.append("API endpoint")
    if not signals:
        signals = list(_SIGNALS)
    if is_stateful(candidate.method):
        signals.append(f"state-changing method ({candidate.method})")
    if candidate.technology:
        signals.append(
            "technology context: " + ", ".join(candidate.technology)
        )

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
    "object ownership context": "TECHNOLOGY_CONTEXT",
    "response difference": "RESPONSE_COMPARISON",
}


def analyze_evidence(candidate, artifacts) -> dict:
    """Consume collected evidence and update the IDOR investigation state.

    Returns the confidence update, the missing evidence and the next action.
    It never confirms an authorization boundary or a vulnerability.
    """

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


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = " ".join(str(value or "").split())
        if text and text not in out:
            out.append(text)
    return out


def report(candidate, analysis) -> dict:
    """The IDOR agent's section of a Security Research Report (Phase 6)."""

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

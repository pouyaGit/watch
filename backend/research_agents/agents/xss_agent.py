"""backend/research_agents/agents/xss_agent.py — XSS research agent (v1).

Produces an investigation plan for an ``XSS_CANDIDATE``: the signals that make
it interesting, the evidence a researcher must collect, and the blockers that
currently prevent any conclusion. It does **not** send payloads, render pages
or confirm reflection.
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    bump_confidence,
    confidence_for,
    is_stateful,
    present_evidence_types,
    report_section,
)
from backend.research_agents.models import CandidateRef

KEY = "xss"
NAME = "XSS Research Agent"
CATEGORY = "xss"
DESCRIPTION = "Plans cross-site scripting investigation and reflection evidence."

STRATEGY = (
    "identify the reflected parameter and its delivery location",
    "capture the baseline response metadata for the candidate parameter",
    "compare encoded and raw parameter responses for encoding context",
    "capture the server/client execution context (observation only)",
    "confirm reflection and execution in an isolated, authorized context",
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
    "reflection confirmation",
    "encoding context",
    "execution context",
)

_SIGNALS = (
    "reflected parameter",
    "input location unknown",
    "javascript context unknown",
)
_BLOCKERS = (
    "reflection not confirmed",
    "encoding context unknown",
    "execution context unknown",
)


def analyze(candidate: CandidateRef) -> dict:
    """Return the XSS investigation plan for one candidate (pure)."""

    signals = list(_SIGNALS)
    if candidate.parameter:
        signals.append(f"candidate parameter: {candidate.parameter}")
    if is_stateful(candidate.method):
        signals.append(f"state-changing method ({candidate.method})")
    if candidate.location == "body":
        signals.append("parameter delivered in request body")
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
    "reflection confirmation": "HTTP_METADATA",
    "encoding context": "RESPONSE_COMPARISON",
    "execution context": "TECHNOLOGY_CONTEXT",
}


def analyze_evidence(candidate, artifacts) -> dict:
    """Consume collected evidence and update the XSS investigation state.

    Returns the confidence update, the missing evidence and the next action.
    It never confirms reflection or a vulnerability.
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
    """The XSS agent's section of a Security Research Report (Phase 6)."""

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

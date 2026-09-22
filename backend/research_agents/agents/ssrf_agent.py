"""backend/research_agents/agents/ssrf_agent.py — SSRF research agent (v1).

Produces an investigation plan for an ``SSRF_CANDIDATE``. It identifies the
remote-resource parameter, the response behavior a researcher must observe, and
the blockers that prevent any conclusion.

It does **not** make the remote request, does not follow redirects and never
confirms server-side request forgery. The research strategy explicitly marks
live egress as requiring a separate authorization boundary.
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    bump_confidence,
    confidence_for,
    is_api_endpoint,
    is_stateful,
    is_url_parameter,
    present_evidence_types,
    report_section,
)
from backend.research_agents.models import CandidateRef

KEY = "ssrf"
NAME = "SSRF Research Agent"
CATEGORY = "ssrf"
DESCRIPTION = (
    "Plans server-side request forgery investigation and remote-resource "
    "response evidence."
)

STRATEGY = (
    "identify the remote-resource parameter and its delivery location",
    "record baseline response metadata without fetching any external resource",
    "classify parameter-response behavior against the baseline",
    "capture the server/client technology and egress context (observation only)",
    "request an explicit egress authorization boundary before any remote fetch",
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
    "baseline response",
    "remote-resource response behavior",
    "network context",
    "response difference",
)

_SIGNALS = (
    "remote-resource parameter",
    "server-side fetch hypothesis",
    "egress context unknown",
)
_BLOCKERS = (
    "egress context unknown",
    "remote fetch not authorized",
    "network boundary unknown",
)


def analyze(candidate: CandidateRef) -> dict:
    """Return the SSRF investigation plan for one candidate (pure)."""

    signals: list[str] = []
    if is_url_parameter(candidate.parameter):
        signals.append("URL-like parameter name")
    if candidate.parameter:
        signals.append("remote-resource parameter")
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
    "baseline response": "HTTP_METADATA",
    "remote-resource response behavior": "PARAMETER_BEHAVIOR",
    "network context": "TECHNOLOGY_CONTEXT",
    "response difference": "RESPONSE_COMPARISON",
}


def analyze_evidence(candidate, artifacts) -> dict:
    """Consume collected evidence and update the SSRF investigation state."""

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
    """The SSRF agent's section of a Security Research Report (Phase 6)."""

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

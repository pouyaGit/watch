"""backend/research_agents/agents/upload_agent.py — file upload research agent.

Produces an investigation plan for a ``FILE_UPLOAD_CANDIDATE``. It records the
upload-response behavior and content-type handling a researcher must observe
and the blockers that prevent any conclusion.

It does **not** upload a file, does not send a payload and never confirms an
arbitrary file upload vulnerability. Live uploads are explicitly out of scope
and require a separate authorization boundary.
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    bump_confidence,
    confidence_for,
    is_file_parameter,
    is_stateful,
    present_evidence_types,
    report_section,
)
from backend.research_agents.models import CandidateRef

KEY = "file_upload"
NAME = "File Upload Research Agent"
CATEGORY = "file_upload"
DESCRIPTION = (
    "Plans file-upload investigation and content-type/response evidence."
)

STRATEGY = (
    "identify the file-handling parameter and endpoint",
    "record baseline response metadata without uploading anything",
    "classify how the endpoint responds to file-type parameter variation",
    "capture the storage/structure technology context (observation only)",
    "request an explicit upload authorization boundary before any upload",
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
    "upload response metadata",
    "content-type handling",
    "storage location context",
    "response difference",
)

_SIGNALS = (
    "file-handling parameter",
    "file upload hypothesis",
    "content-type enforcement unknown",
)
_BLOCKERS = (
    "content-type enforcement unknown",
    "upload not authorized",
    "storage location unknown",
)


def analyze(candidate: CandidateRef) -> dict:
    """Return the file-upload investigation plan for one candidate (pure)."""

    signals: list[str] = []
    if is_file_parameter(candidate.parameter):
        signals.append("file-like parameter name")
    if candidate.parameter:
        signals.append("file-handling parameter")
        signals.append(f"candidate parameter: {candidate.parameter}")
    if is_stateful(candidate.method):
        signals.append(f"state-changing method ({candidate.method})")
    if not signals:
        signals = list(_SIGNALS)
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
    "upload response metadata": "HTTP_METADATA",
    "content-type handling": "PARAMETER_BEHAVIOR",
    "storage location context": "TECHNOLOGY_CONTEXT",
    "response difference": "RESPONSE_COMPARISON",
}


def analyze_evidence(candidate, artifacts) -> dict:
    """Consume collected evidence and update the upload investigation state."""

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
    """The file-upload agent's section of a Security Research Report."""

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

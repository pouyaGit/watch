"""backend/research_agents/agents/common.py — shared agent helpers."""

from __future__ import annotations

import re

from backend.research_agents.models import CandidateRef

_IDENTIFIER_RE = re.compile(r"(^|_)(id|uid)$")
_API_RE = re.compile(r"(^|/)(api|v\d+|rest|graphql)(/|$)", re.IGNORECASE)
_STATEFUL_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FILE_RE = re.compile(
    r"(file|upload|attachment|image|avatar|photo|media|document|content|blob)",
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r"(url|uri|link|target|dest|destination|redirect|callback|webhook|"
    r"fetch|proxy|endpoint|host|image_url|next|return|continue)",
    re.IGNORECASE,
)
_PRIVILEGED_RE = re.compile(
    r"(admin|internal|private|manage|management|staff|root|superuser|"
    r"billing|account|user|role|permission|tenant|org|owner)",
    re.IGNORECASE,
)


def confidence_for(candidate: CandidateRef) -> str:
    """Derive an explainable confidence from the candidate (never invented)."""

    declared = str(getattr(candidate, "confidence", "") or "").upper()
    if declared in ("LOW", "MEDIUM", "HIGH"):
        return declared
    try:
        score = int(getattr(candidate, "priority_score", 0) or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        return "HIGH"
    if score >= 55:
        return "MEDIUM"
    return "LOW"


def is_identifier(parameter: object) -> bool:
    text = str(parameter or "").strip().lower()
    return bool(text and (_IDENTIFIER_RE.search(text) or text in {"id", "uid"}))


def is_api_endpoint(endpoint: object) -> bool:
    return bool(_API_RE.search(str(endpoint or "")))


def is_stateful(method: object) -> bool:
    return str(method or "").upper() in _STATEFUL_METHODS


def is_file_parameter(parameter: object) -> bool:
    text = str(parameter or "").strip()
    return bool(text and _FILE_RE.search(text))


def is_url_parameter(parameter: object) -> bool:
    text = str(parameter or "").strip()
    return bool(text and _URL_RE.search(text))


def is_privileged_endpoint(endpoint: object) -> bool:
    return bool(_PRIVILEGED_RE.search(str(endpoint or "")))


_CONFIDENCE_LEVELS = ("LOW", "MEDIUM", "HIGH")


def bump_confidence(level: object, steps: int = 1) -> str:
    """Raise a confidence level by ``steps`` (capped at HIGH)."""

    text = str(level or "LOW").upper()
    index = _CONFIDENCE_LEVELS.index(text) if text in _CONFIDENCE_LEVELS else 0
    return _CONFIDENCE_LEVELS[min(index + max(steps, 0),
                                  len(_CONFIDENCE_LEVELS) - 1)]


def _artifact_value(artifact: object, name: str) -> str:
    if isinstance(artifact, dict):
        value = artifact.get(name)
    else:
        value = getattr(artifact, name, None)
    return str(value or "").strip()


def evidence_type(artifact: object) -> str:
    return _artifact_value(artifact, "type").upper()


def evidence_status(artifact: object) -> str:
    return _artifact_value(artifact, "status").upper() or "COLLECTED"


def present_evidence_types(artifacts) -> set[str]:
    """Types of collected/analyzed artifacts (missing/failed excluded)."""

    out: set[str] = set()
    for artifact in artifacts or ():
        if evidence_status(artifact) in ("MISSING", "FAILED", "PLANNED"):
            continue
        evidence_type_value = evidence_type(artifact)
        if evidence_type_value:
            out.add(evidence_type_value)
    return out


def report_section(
    *,
    agent: str,
    target: object,
    endpoint: object,
    parameter: object,
    confidence: str,
    strategy=(),
    evidence_present=(),
    missing_evidence=(),
    next_action: str = "",
    signals=(),
    blockers=(),
) -> dict:
    """The agent's contribution to a Security Research Report (Phase 6).

    Uses the mission's report vocabulary: target, endpoint, evidence,
    confidence, missing proof and researcher notes. It never states a
    vulnerability.
    """

    return {
        "agent": str(agent or ""),
        "target": str(target or ""),
        "endpoint": str(endpoint or ""),
        "parameter": str(parameter or ""),
        "confidence": str(confidence or ""),
        "research_strategy": [str(item) for item in strategy],
        "evidence": [str(item) for item in evidence_present],
        "missing_proof": [str(item) for item in missing_evidence],
        "next_action": str(next_action or ""),
        "researcher_notes": {
            "signals": [str(item) for item in signals],
            "blockers": [str(item) for item in blockers],
            "model_generated": False,
            "verdict": "report_candidate_only",
        },
    }


__all__ = [
    "confidence_for",
    "is_identifier",
    "is_api_endpoint",
    "is_stateful",
    "is_file_parameter",
    "is_url_parameter",
    "is_privileged_endpoint",
    "bump_confidence",
    "evidence_type",
    "evidence_status",
    "present_evidence_types",
    "report_section",
]

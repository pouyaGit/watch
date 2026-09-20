"""backend/attack_surface — Attack Surface Intelligence Platform (v1).

Turns the attack surface Watch already collects (domains, subdomains, HTTP
assets, URLs, endpoints, parameters, technologies) into prioritized,
explainable security research candidates that specialist agents can consume.

The package is deliberately split so each concern is independently testable:

- ``models``     -- normalized records, candidate vocabulary, lifecycle.
- ``repository`` -- read-only access to the existing recon records.
- ``classifier`` -- deterministic, LLM-free candidate classification rules.
- ``scorer``     -- deterministic, explainable candidate scoring.
- ``service``    -- orchestration: candidates, queue lifecycle and payloads.

Read-only by design: no writes, no network, no LLM, no target interaction, no
Nuclei/browser/PoC. Candidates are *research hypotheses*, never confirmed
vulnerabilities.
"""

from __future__ import annotations

from backend.attack_surface.models import (
    CANDIDATE_CATEGORIES,
    CANDIDATE_STATUSES,
    CONFIDENCE_LEVELS,
    RULE_VERSION,
    AttackSurfaceCandidate,
    AttackSurfaceRecord,
    AttackSurfaceSnapshot,
    CandidateCategory,
    CandidateStatus,
    Confidence,
    candidate_id_for,
)
from backend.attack_surface.service import (
    CandidateQueue,
    attack_surface_payload,
    build_candidates,
    build_discovery,
    build_priority_queue,
    summarize_candidates,
)

__all__ = [
    "CANDIDATE_CATEGORIES",
    "CANDIDATE_STATUSES",
    "CONFIDENCE_LEVELS",
    "RULE_VERSION",
    "AttackSurfaceCandidate",
    "AttackSurfaceRecord",
    "AttackSurfaceSnapshot",
    "CandidateCategory",
    "CandidateStatus",
    "Confidence",
    "candidate_id_for",
    "CandidateQueue",
    "attack_surface_payload",
    "build_candidates",
    "build_discovery",
    "build_priority_queue",
    "summarize_candidates",
]

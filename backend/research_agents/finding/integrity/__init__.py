"""EPIC11 claim / evidence integrity layer.

Enforces, in deterministic application code:

    observation != candidate != verification != confirmed vulnerability

- ``taxonomy``   — closed evidence vocabulary + stages; normalizes raw
  evidence rows and collapses duplicate events.
- ``contracts``  — per-class claim specs and the evidence required before
  a class may be called *confirmed*.
- ``claims``     — claim evaluation (SUPPORTED / UNSUPPORTED /
  CONTRADICTED / NOT_TESTED) with explicit reasons.
- ``gate``       — the authoritative Evidence Gate: only a supported
  confirmation claim yields VERIFIED; otherwise VERIFICATION_PENDING or
  BLOCKED.
- ``report``     — evidence-first report contract, report validation gate
  and contradiction detection.
- ``projection`` — re-assessment of already-persisted records without
  rewriting history.

Nothing in this package accepts model output as input.
"""

from __future__ import annotations

from backend.research_agents.finding.integrity import claims, contracts
from backend.research_agents.finding.integrity import gate as integrity_gate
from backend.research_agents.finding.integrity import projection
from backend.research_agents.finding.integrity import report as integrity_report
from backend.research_agents.finding.integrity import taxonomy

INTEGRITY_RULE_VERSION = "epic11-integrity-1"

__all__ = [
    "INTEGRITY_RULE_VERSION", "claims", "contracts", "integrity_gate",
    "integrity_report", "projection", "taxonomy",
]

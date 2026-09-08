"""Controlled live validation lane (Phase 5K-live).

First controlled bridge from research-only to real target-side
validation. Narrowly scoped to CVE-2026-1557 with explicit gates,
reusing the existing 5B-5J authority chain.

Default remains research-only/dry-run. Live execution requires:
1. Explicit enablement (WATCH_AI_LIVE_VALIDATION env gate, default false)
2. Explicit caller-supplied target

The lane never creates authoritative findings, never alerts, never
touches 5J, and never commits to git.
"""

from ai.live_validation.lane import ControlledLiveValidationLane
from ai.live_validation.schemas import (
    GateResult,
    LiveValidationEvidence,
    LiveValidationMode,
    LiveValidationResult,
    LiveValidationStatus,
    VerificationFacts,
)

__all__ = [
    "ControlledLiveValidationLane",
    "GateResult",
    "LiveValidationEvidence",
    "LiveValidationMode",
    "LiveValidationResult",
    "LiveValidationStatus",
    "VerificationFacts",
]

"""Case orchestrator package (EPIC 3 Part 1).

Coordinates the existing offline components into one case lifecycle:
intake → selection → planning → authorization → evidence → review.
Each hop is a pure function returning a new record or a closed-vocabulary
refusal; every hop appends one audit event. No network, no writes, and no
conclusions about any target.
"""

__all__: list[str] = []

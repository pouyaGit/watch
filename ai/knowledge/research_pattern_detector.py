"""Stage R32.3 deterministic research pattern detector (pure engine).

Detects repeated structural patterns across read-only R32.1 research memory
snapshots:

    "Which research limitation pattern keeps repeating across history?"

Deterministic counting only: no ML, no embeddings, no LLM, no probability.
This module never executes research, never acquires evidence, never contacts a
target and never touches Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic: reuse of the R32.2 ``count_patterns`` counting core, a fixed
  dominant-pattern tie-break (code ascending) and a closed
  frequency->confidence classification. Byte-identical repeated output.
- Read-only: inputs are never mutated.
- Privacy: only closed pattern codes and bounded counts are retained.
"""

from __future__ import annotations

from ai.knowledge.research_history_aggregator import count_patterns
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_pattern_plan import (
    MAX_EVIDENCE,
    PATTERN_NONE,
    RESEARCH_PATTERN_RULE_VERSION,
    ResearchPatternPlan,
    research_pattern_plan_projection,
)

RESEARCH_PATTERN_DETECTOR_RULE_VERSION = "r32-3"
RULE_VERSION = RESEARCH_PATTERN_DETECTOR_RULE_VERSION

HIGH_FREQUENCY = 3
MEDIUM_FREQUENCY = 2
LOW_FREQUENCY = 1


def confidence_for(frequency: int) -> str:
    """Closed frequency -> confidence classification (never a probability)."""

    if frequency >= HIGH_FREQUENCY:
        return CONFIDENCE_HIGH
    if frequency == MEDIUM_FREQUENCY:
        return CONFIDENCE_MEDIUM
    if frequency == LOW_FREQUENCY:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def detect_research_patterns(snapshots: object = None) -> dict:
    """Detect the dominant structural pattern across memory snapshots.

    The dominant pattern is the highest-count pattern with an alphabetical
    tie-break. Confidence is a closed classification of the observed
    frequency (>=3 HIGH, 2 MEDIUM, 1 LOW, none UNKNOWN). The full distribution
    is retained as bounded ``evidence`` entries.
    """

    counts = count_patterns(snapshots)
    if not counts:
        dominant = PATTERN_NONE
        frequency = 0
    else:
        dominant, frequency = counts[0]

    evidence = [
        {"pattern": pattern, "count": count}
        for pattern, count in counts
    ][:MAX_EVIDENCE]

    plan = ResearchPatternPlan(
        rule_version=RESEARCH_PATTERN_RULE_VERSION,
        dominant_pattern=dominant,
        frequency=frequency,
        confidence=confidence_for(frequency),
        evidence=evidence,
        research_only=True,
    )
    return research_pattern_plan_projection(plan)


__all__ = [
    "RESEARCH_PATTERN_DETECTOR_RULE_VERSION",
    "RULE_VERSION",
    "HIGH_FREQUENCY",
    "MEDIUM_FREQUENCY",
    "LOW_FREQUENCY",
    "confidence_for",
    "detect_research_patterns",
]

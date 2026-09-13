"""Stage R33.1 deterministic research pattern intelligence (pure engine).

Consumes the read-only R32.4 research memory export (whose ``patterns`` section
is the R32.3 structural pattern plan) and converts historical patterns into
deterministic research signals:

    "Which historical pattern is the strongest signal for future attention?"

This is an **intelligence signal only**. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo. No statistical model, ML, embeddings or probability is used.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic frequency classification only (>=5 HIGH, 2-4 MEDIUM, 1 LOW,
  0 UNKNOWN) with a stable count/pattern sort order.
- Consume-only and read-only: inputs are never mutated; malformed evidence is
  skipped, never repaired.
- Privacy: only closed pattern codes and bounded counts are retained.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_pattern_intelligence import (
    MAX_PATTERNS,
    RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION,
    ResearchPatternIntelligencePlan,
    research_pattern_intelligence_plan_projection,
)
from ai.schemas.research_pattern_plan import (
    PATTERN_CODES,
    PATTERN_NONE,
)

RESEARCH_PATTERN_INTELLIGENCE_PLANNER_RULE_VERSION = "r33-1"
RULE_VERSION = RESEARCH_PATTERN_INTELLIGENCE_PLANNER_RULE_VERSION

HIGH_FREQUENCY = 5
MEDIUM_MIN_FREQUENCY = 2
LOW_FREQUENCY = 1


def pattern_confidence(frequency: int) -> str:
    """Closed R33 frequency -> confidence classification (no statistics)."""

    if frequency >= HIGH_FREQUENCY:
        return CONFIDENCE_HIGH
    if frequency >= MEDIUM_MIN_FREQUENCY:
        return CONFIDENCE_MEDIUM
    if frequency == LOW_FREQUENCY:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _counts_from_patterns(patterns: dict) -> list[tuple[str, int]]:
    """Recover closed pattern counts from the R32.3 plan (read-only)."""

    counts: dict[str, int] = {}
    evidence = patterns.get("evidence")
    if isinstance(evidence, (list, tuple)):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            pattern = _upper(item.get("pattern"))
            if pattern not in PATTERN_CODES or pattern == PATTERN_NONE:
                continue
            try:
                count = max(0, int(item.get("count")))
            except (TypeError, ValueError):
                continue
            if count:
                counts[pattern] = counts.get(pattern, 0) + count
    if not counts:
        dominant = _upper(patterns.get("dominant_pattern"))
        try:
            frequency = max(0, int(patterns.get("frequency")))
        except (TypeError, ValueError):
            frequency = 0
        if dominant in PATTERN_CODES and dominant != PATTERN_NONE:
            if frequency:
                counts[dominant] = frequency
    return sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )[:MAX_PATTERNS]


def plan_research_pattern_intelligence(
    memory_export: object = None,
    *,
    pattern_plan: object = None,
) -> dict:
    """Convert R32 memory patterns into a deterministic intelligence plan.

    ``memory_export`` is the R32.4 export dict (its embedded ``patterns``
    section is consumed). ``pattern_plan`` is an optional direct R32.3 pattern
    plan override for callers that already hold it. Missing or malformed input
    yields ``NO_PATTERN`` / ``UNKNOWN`` and is never silently upgraded.
    """

    export = _block(memory_export)
    patterns = _block(pattern_plan) or _block(export.get("patterns"))

    counts = _counts_from_patterns(patterns)
    if not counts:
        plan = ResearchPatternIntelligencePlan(
            rule_version=RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION,
            dominant_patterns=[],
            pattern_scores=[],
            strongest_signal=PATTERN_NONE,
            confidence=CONFIDENCE_UNKNOWN,
            research_only=True,
        )
        return research_pattern_intelligence_plan_projection(plan)

    dominant_patterns = [pattern for pattern, _ in counts]
    pattern_scores = [
        {
            "pattern": pattern,
            "frequency": count,
            "confidence": pattern_confidence(count),
        }
        for pattern, count in counts
    ]
    strongest, frequency = counts[0]

    plan = ResearchPatternIntelligencePlan(
        rule_version=RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION,
        dominant_patterns=dominant_patterns,
        pattern_scores=pattern_scores,
        strongest_signal=strongest,
        confidence=pattern_confidence(frequency),
        research_only=True,
    )
    return research_pattern_intelligence_plan_projection(plan)


__all__ = [
    "RESEARCH_PATTERN_INTELLIGENCE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HIGH_FREQUENCY",
    "MEDIUM_MIN_FREQUENCY",
    "LOW_FREQUENCY",
    "MAX_PATTERNS",
    "pattern_confidence",
    "plan_research_pattern_intelligence",
]

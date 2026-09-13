"""Stage R44.4 deterministic learning memory export (pure engine).

Aggregates feedback events into structured learning patterns:

    "Which recurring structured research patterns did previous outcomes
     reveal?"

Hard boundaries encoded here:

- Learning only: patterns are advisory records. There are no automatic rule
  changes, no automatic agent tuning and no execution.
- Deterministic aggregation: pattern ids, counts, confidence and ordering
  are pure functions of the bounded events.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib

from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.schemas.research_feedback_classification import (
    CLASSIFICATION_UNKNOWN,
    sanitize_research_feedback_classification,
)
from ai.schemas.research_feedback_event import (
    sanitize_research_feedback_event,
)
from ai.schemas.research_learning_memory import (
    MEMORY_LIMITATIONS,
    PATTERN_ID_PREFIX,
    PATTERN_LIMITATIONS,
    RESEARCH_LEARNING_MEMORY_RULE_VERSION,
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
    LearningPatternPlan,
    ResearchLearningMemoryPlan,
    learning_pattern_plan_projection,
    research_learning_memory_plan_projection,
)

RESEARCH_LEARNING_MEMORY_EXPORTER_RULE_VERSION = "r44-4"
RULE_VERSION = RESEARCH_LEARNING_MEMORY_EXPORTER_RULE_VERSION


def _pattern_id(category: str, pattern_type: str) -> str:
    basis = "|".join(
        [RESEARCH_LEARNING_MEMORY_RULE_VERSION, category, pattern_type]
    )
    return PATTERN_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def _pattern_confidence(
    count: int,
    confidences: list[str],
) -> str:
    if count >= 3 and "HIGH" in confidences:
        return "HIGH"
    if count >= 2 or "HIGH" in confidences:
        return "MEDIUM"
    return "LOW"


def export_research_learning_memory(
    events: object = None,
    classifications: object = None,
) -> dict:
    """Aggregate feedback events into deterministic learning patterns.

    Patterns group by (source category, classification); occurrence counts,
    supporting event ids and confidence are deterministic. No automatic rule
    change or agent tuning occurs.
    """

    if isinstance(events, dict):
        raw_events = [events]
    elif isinstance(events, (list, tuple)):
        raw_events = list(events)
    else:
        raw_events = []

    bounded_events = [
        sanitize_research_feedback_event(event) for event in raw_events
    ]

    if classifications is None:
        bounded_classifications = classify_research_feedback_events(
            bounded_events
        )
    elif isinstance(classifications, dict):
        bounded_classifications = [
            sanitize_research_feedback_classification(classifications)
        ]
    elif isinstance(classifications, (list, tuple)):
        bounded_classifications = [
            sanitize_research_feedback_classification(item)
            for item in classifications
        ]
    else:
        bounded_classifications = []

    while len(bounded_classifications) < len(bounded_events):
        index = len(bounded_classifications)
        event = bounded_events[index]
        classified = classify_research_feedback_events([event])
        bounded_classifications.append(
            classified[0] if classified else None
        )

    grouped: dict[tuple, dict] = {}
    for index, event in enumerate(bounded_events):
        classification = bounded_classifications[index]
        if not isinstance(classification, dict):
            continue
        category = event.get("source_category") or "UNKNOWN"
        pattern_type = (
            classification.get("classification")
            or CLASSIFICATION_UNKNOWN
        )
        key = (category, pattern_type)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "confidence_values": [],
                "supporting_events": [],
            }
            grouped[key] = entry
        confidence = classification.get("confidence") or "UNKNOWN"
        entry["confidence_values"].append(confidence)
        feedback_id = event.get("feedback_id") or ""
        if feedback_id and feedback_id not in entry["supporting_events"]:
            entry["supporting_events"].append(feedback_id)

    patterns: list[dict] = []
    for (category, pattern_type), entry in grouped.items():
        count = len(entry["confidence_values"])
        confidence = (
            "UNKNOWN"
            if pattern_type == CLASSIFICATION_UNKNOWN
            else _pattern_confidence(count, entry["confidence_values"])
        )
        plan = LearningPatternPlan(
            rule_version=RESEARCH_LEARNING_MEMORY_RULE_VERSION,
            pattern_id=_pattern_id(category, pattern_type),
            source_category=category,
            pattern_type=pattern_type,
            occurrence_count=count,
            confidence=confidence,
            supporting_events=entry["supporting_events"],
            limitations=list(PATTERN_LIMITATIONS),
            research_only=True,
        )
        patterns.append(learning_pattern_plan_projection(plan))

    if not patterns:
        state = STATE_UNKNOWN
    elif all(
        pattern["pattern_type"] != CLASSIFICATION_UNKNOWN
        for pattern in patterns
    ):
        state = STATE_COMPLETE
    else:
        state = STATE_PARTIAL

    memory = ResearchLearningMemoryPlan(
        rule_version=RESEARCH_LEARNING_MEMORY_RULE_VERSION,
        patterns=patterns,
        memory_state=state,
        limitations=list(MEMORY_LIMITATIONS),
        research_only=True,
    )
    result = research_learning_memory_plan_projection(memory)
    result["rule_version"] = RESEARCH_LEARNING_MEMORY_RULE_VERSION
    return result


__all__ = [
    "RESEARCH_LEARNING_MEMORY_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_learning_memory",
]

"""Stage R44.5 deterministic learning recommendation generator (pure engine).

Turns learning signals into advisory recommendations:

    "Which advisory recommendation follows from previous research outcomes?"

Hard boundaries encoded here:

- Learning only: recommendations are advisory. They never modify agents,
  rules, source code, security policies or runtime behavior, and they never
  modify R34 strategy or R35 orchestration.
- Deterministic mapping: recommendation type, text, id and ordering are
  pure functions of the bounded signals.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib

from ai.knowledge.learning_signal_extractor import (
    extract_learning_signals,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.schemas.learning_recommendation import (
    LEARNING_RECOMMENDATION_LIMITATIONS,
    LEARNING_RECOMMENDATION_RULE_VERSION,
    RECOMMENDATION_ID_PREFIX,
    RECOMMENDATION_ORDER,
    REC_CALIBRATE_CONFIDENCE,
    REC_DEDUPLICATE_HYPOTHESES,
    REC_IMPROVE_CONTEXT_CAPTURE,
    REC_PRESERVE_PROVENANCE,
    REC_PRESERVE_SUCCESSFUL_PATTERN,
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_STRENGTHEN_HYPOTHESES,
    REC_UNKNOWN,
    LearningRecommendationPlan,
    learning_recommendation_plan_projection,
)
from ai.schemas.learning_signal import (
    SIGNAL_AVOID_DUPLICATION,
    SIGNAL_IMPROVE_CONTEXT_COLLECTION,
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY,
    SIGNAL_IMPROVE_SAFETY_BOUNDARY,
    SIGNAL_PRESERVE_SUCCESS_PATTERN,
    SIGNAL_REDUCE_CONFIDENCE,
    SIGNAL_REQUIRE_MORE_EVIDENCE,
    SIGNAL_REVIEW_GOVERNANCE,
    SIGNAL_REVIEW_PROVENANCE,
    SIGNAL_UNKNOWN,
    sanitize_learning_signal,
)

LEARNING_RECOMMENDATION_GENERATOR_RULE_VERSION = "r44-5"
RULE_VERSION = LEARNING_RECOMMENDATION_GENERATOR_RULE_VERSION

SIGNAL_TO_RECOMMENDATION: dict[str, str] = {
    SIGNAL_REQUIRE_MORE_EVIDENCE: REC_PRIORITIZE_EVIDENCE_PLANNING,
    SIGNAL_REDUCE_CONFIDENCE: REC_CALIBRATE_CONFIDENCE,
    SIGNAL_IMPROVE_CONTEXT_COLLECTION: REC_IMPROVE_CONTEXT_CAPTURE,
    SIGNAL_PRESERVE_SUCCESS_PATTERN: REC_PRESERVE_SUCCESSFUL_PATTERN,
    SIGNAL_AVOID_DUPLICATION: REC_DEDUPLICATE_HYPOTHESES,
    SIGNAL_REVIEW_GOVERNANCE: REC_REVIEW_GOVERNANCE_REFERENCES,
    SIGNAL_REVIEW_PROVENANCE: REC_PRESERVE_PROVENANCE,
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY: REC_STRENGTHEN_HYPOTHESES,
    SIGNAL_IMPROVE_SAFETY_BOUNDARY: REC_RESTORE_SAFETY_BOUNDARY,
    SIGNAL_UNKNOWN: REC_UNKNOWN,
}

RECOMMENDATION_TEXT: dict[str, str] = {
    REC_PRIORITIZE_EVIDENCE_PLANNING: (
        "Prioritize evidence planning before high-confidence classification"
    ),
    REC_CALIBRATE_CONFIDENCE: (
        "Calibrate confidence against available context and evidence"
    ),
    REC_IMPROVE_CONTEXT_CAPTURE: (
        "Capture more structured context before analysis"
    ),
    REC_PRESERVE_SUCCESSFUL_PATTERN: (
        "Preserve and reuse the successful research pattern"
    ),
    REC_DEDUPLICATE_HYPOTHESES: (
        "Review duplicated hypotheses before collaboration ranking"
    ),
    REC_REVIEW_GOVERNANCE_REFERENCES: (
        "Review governance references for completeness"
    ),
    REC_PRESERVE_PROVENANCE: (
        "Preserve provenance layers across research results"
    ),
    REC_STRENGTHEN_HYPOTHESES: (
        "Strengthen hypothesis signals and internal consistency"
    ),
    REC_RESTORE_SAFETY_BOUNDARY: (
        "Restore the research-only safety boundary"
    ),
    REC_UNKNOWN: (
        "Insufficient structured data for a recommendation"
    ),
}


def _recommendation_id(
    recommendation_type: str,
    related_agent: str,
    related_category: str,
    source_classification: str,
) -> str:
    basis = "|".join(
        [
            LEARNING_RECOMMENDATION_RULE_VERSION,
            recommendation_type,
            related_agent,
            related_category,
            source_classification,
        ]
    )
    return RECOMMENDATION_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def generate_learning_recommendations(
    events: object = None,
    classifications: object = None,
    signals: object = None,
) -> list[dict]:
    """Generate advisory recommendations from learning signals (read-only).

    When signals are omitted they are extracted from the supplied
    classifications; when classifications are omitted they are computed from
    the supplied events. Recommendations are deduplicated and ordered
    deterministically, and never modify agents, rules or strategy.
    """

    if signals is None:
        if classifications is None:
            if isinstance(events, dict):
                raw_events = [events]
            elif isinstance(events, (list, tuple)):
                raw_events = list(events)
            else:
                raw_events = []
            classifications = classify_research_feedback_events(
                raw_events
            )
        signals = extract_learning_signals(classifications)

    if isinstance(signals, dict):
        raw_signals = [signals]
    elif isinstance(signals, (list, tuple)):
        raw_signals = list(signals)
    else:
        raw_signals = []

    recommendations: list[dict] = []
    seen: set[tuple] = set()
    for item in raw_signals:
        if not isinstance(item, dict):
            continue
        bounded = sanitize_learning_signal(item)
        signal_type = bounded["signal_type"]
        recommendation_type = SIGNAL_TO_RECOMMENDATION.get(
            signal_type, REC_UNKNOWN
        )
        related_agent = bounded["source_agent"]
        related_category = bounded["subject"]
        source_classification = bounded["source_classification"]
        key = (
            recommendation_type,
            related_agent,
            related_category,
            source_classification,
        )
        if key in seen:
            continue
        seen.add(key)
        plan = LearningRecommendationPlan(
            rule_version=LEARNING_RECOMMENDATION_RULE_VERSION,
            recommendation_id=_recommendation_id(*key),
            recommendation_type=recommendation_type,
            related_agent=related_agent,
            related_category=related_category,
            source_classification=source_classification,
            supporting_signals=bounded["supporting_signals"],
            recommendation=RECOMMENDATION_TEXT.get(
                recommendation_type, ""
            ),
            confidence=bounded["confidence"],
            limitations=list(LEARNING_RECOMMENDATION_LIMITATIONS),
        )
        recommendations.append(
            learning_recommendation_plan_projection(plan)
        )

    recommendations.sort(
        key=lambda entry: (
            RECOMMENDATION_ORDER.get(
                entry["recommendation_type"], 99
            ),
            entry["related_category"],
            entry["related_agent"],
            entry["source_classification"],
        )
    )
    return recommendations


__all__ = [
    "LEARNING_RECOMMENDATION_GENERATOR_RULE_VERSION",
    "RULE_VERSION",
    "SIGNAL_TO_RECOMMENDATION",
    "RECOMMENDATION_TEXT",
    "generate_learning_recommendations",
]

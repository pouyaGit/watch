"""Stage R44.3 deterministic learning signal extractor (pure engine).

Extracts advisory learning signals from feedback classifications:

    "What should future research consider?"

Hard boundaries encoded here:

- Learning only: signals are recommendations, not actions. They never modify
  agents, rules, source code, security policies or runtime behavior, and
  they never execute anything.
- Deterministic mapping: signal type, recommendation text and limitations
  are pure functions of the classification.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.learning_signal import (
    LEARNING_SIGNAL_LIMITATIONS,
    LEARNING_SIGNAL_RULE_VERSION,
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
    LearningSignalPlan,
    learning_signal_plan_projection,
)
from ai.schemas.research_feedback_classification import (
    CLASSIFICATION_CONFIDENCE_CALIBRATION,
    CLASSIFICATION_CONFLICT_PATTERN,
    CLASSIFICATION_DUPLICATION_PATTERN,
    CLASSIFICATION_EVIDENCE_GAP,
    CLASSIFICATION_GOVERNANCE_ISSUE,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS,
    CLASSIFICATION_PROVENANCE_ISSUE,
    CLASSIFICATION_QUALITY_IMPROVEMENT,
    CLASSIFICATION_SAFETY_ISSUE,
    CLASSIFICATION_SUCCESS_PATTERN,
    CLASSIFICATION_UNKNOWN,
    sanitize_research_feedback_classification,
)

LEARNING_SIGNAL_EXTRACTOR_RULE_VERSION = "r44-3"
RULE_VERSION = LEARNING_SIGNAL_EXTRACTOR_RULE_VERSION

CLASSIFICATION_TO_SIGNAL: dict[str, str] = {
    CLASSIFICATION_SAFETY_ISSUE: SIGNAL_IMPROVE_SAFETY_BOUNDARY,
    CLASSIFICATION_GOVERNANCE_ISSUE: SIGNAL_REVIEW_GOVERNANCE,
    CLASSIFICATION_PROVENANCE_ISSUE: SIGNAL_REVIEW_PROVENANCE,
    CLASSIFICATION_CONFLICT_PATTERN: SIGNAL_IMPROVE_HYPOTHESIS_QUALITY,
    CLASSIFICATION_DUPLICATION_PATTERN: SIGNAL_AVOID_DUPLICATION,
    CLASSIFICATION_CONFIDENCE_CALIBRATION: SIGNAL_REDUCE_CONFIDENCE,
    CLASSIFICATION_EVIDENCE_GAP: SIGNAL_REQUIRE_MORE_EVIDENCE,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS: SIGNAL_IMPROVE_HYPOTHESIS_QUALITY,
    CLASSIFICATION_QUALITY_IMPROVEMENT: SIGNAL_IMPROVE_CONTEXT_COLLECTION,
    CLASSIFICATION_SUCCESS_PATTERN: SIGNAL_PRESERVE_SUCCESS_PATTERN,
    CLASSIFICATION_UNKNOWN: SIGNAL_UNKNOWN,
}

SIGNAL_RECOMMENDATIONS: dict[str, str] = {
    SIGNAL_REQUIRE_MORE_EVIDENCE: (
        "Require stronger evidence before concluding research"
    ),
    SIGNAL_REDUCE_CONFIDENCE: (
        "Reduce confidence until context and evidence support it"
    ),
    SIGNAL_IMPROVE_CONTEXT_COLLECTION: (
        "Collect more structured context before analysis"
    ),
    SIGNAL_PRESERVE_SUCCESS_PATTERN: (
        "Preserve the successful research pattern"
    ),
    SIGNAL_AVOID_DUPLICATION: (
        "Deduplicate equivalent hypotheses before ranking"
    ),
    SIGNAL_REVIEW_GOVERNANCE: (
        "Review governance references for completeness"
    ),
    SIGNAL_REVIEW_PROVENANCE: (
        "Record and preserve research provenance layers"
    ),
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY: (
        "Strengthen hypothesis signals and internal consistency"
    ),
    SIGNAL_IMPROVE_SAFETY_BOUNDARY: (
        "Restore the research-only safety boundary"
    ),
    SIGNAL_UNKNOWN: (
        "Insufficient structured data for a learning signal"
    ),
}


def extract_learning_signals(classifications: object = None) -> list[dict]:
    """Extract one advisory learning signal per classification (read-only).

    Signals preserve subject, source agent, source classification and
    supporting signals; they never modify agents, rules or runtime behavior.
    """

    if isinstance(classifications, dict):
        raw_items = [classifications]
    elif isinstance(classifications, (list, tuple)):
        raw_items = list(classifications)
    else:
        raw_items = []

    signals: list[dict] = []
    for item in raw_items:
        bounded = sanitize_research_feedback_classification(item)
        classification = bounded["classification"]
        signal_type = CLASSIFICATION_TO_SIGNAL.get(
            classification, SIGNAL_UNKNOWN
        )
        plan = LearningSignalPlan(
            rule_version=LEARNING_SIGNAL_RULE_VERSION,
            signal_type=signal_type,
            subject=bounded["subject"],
            source_agent=bounded["source_agent"],
            source_classification=classification,
            recommendation=SIGNAL_RECOMMENDATIONS.get(signal_type, ""),
            supporting_signals=bounded["supporting_signals"],
            confidence=bounded["confidence"],
            limitations=list(LEARNING_SIGNAL_LIMITATIONS),
            research_only=True,
        )
        signals.append(learning_signal_plan_projection(plan))
    return signals


__all__ = [
    "LEARNING_SIGNAL_EXTRACTOR_RULE_VERSION",
    "RULE_VERSION",
    "CLASSIFICATION_TO_SIGNAL",
    "SIGNAL_RECOMMENDATIONS",
    "extract_learning_signals",
]

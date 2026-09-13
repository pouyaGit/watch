"""Stage R33.4 deterministic research learning exporter (pure engine).

Creates the final read-only export over the R33.1 pattern intelligence, R33.2
candidate ranking and R33.3 efficiency plans:

    "What learning intelligence is ready for downstream research attention?"

This is an **export signal only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches Mongo.
It never uses or modifies the Money Score and never modifies the R29 queue.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic readiness rule and fixed recommendation/limitation order.
  Byte-identical repeated output.
- Conservative: ``ready`` requires all three R33 plans to be present and
  valid; missing or malformed inputs are never silently upgraded.
- Read-only and privacy-safe: inputs are never mutated; embedded plans are
  bounded, sanitized snapshots.
"""

from __future__ import annotations

from ai.schemas.historical_candidate_ranking import (
    RANKING_REASONS,
    REASON_NO_HISTORY,
    sanitize_historical_candidate_ranking_plan,
)
from ai.schemas.research_efficiency import (
    EFFICIENCY_STATES,
    IMPROVEMENT_SIGNALS,
    SIGNAL_CLOSE_EVIDENCE_GAPS,
    SIGNAL_INCREASE_SUCCESSFUL_RESEARCH,
    SIGNAL_REDUCE_RECURRING_BLOCKERS,
    sanitize_research_efficiency_plan,
)
from ai.schemas.research_learning_export import (
    LIMITATION_LOW_PATTERN_CONFIDENCE,
    LIMITATION_NO_HISTORICAL_SUCCESS,
    LIMITATION_NO_HISTORY,
    LIMITATION_UNKNOWN_EFFICIENCY,
    RECOMMEND_CLOSE_GAPS,
    RECOMMEND_COLLECT_HISTORY,
    RECOMMEND_INCREASE_SUCCESS,
    RECOMMEND_NO_ACTION,
    RECOMMEND_PRIORITIZE,
    RECOMMEND_REDUCE_BLOCKERS,
    RESEARCH_LEARNING_EXPORT_RULE_VERSION,
    ResearchLearningExportPlan,
    research_learning_export_plan_projection,
)
from ai.schemas.research_pattern_intelligence import (
    sanitize_research_pattern_intelligence_plan,
)
from ai.schemas.research_pattern_plan import PATTERN_CODES

RESEARCH_LEARNING_EXPORTER_RULE_VERSION = "r33-4"
RULE_VERSION = RESEARCH_LEARNING_EXPORTER_RULE_VERSION


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _positive_score(ranking: dict) -> bool:
    scores = ranking.get("candidate_scores")
    if not isinstance(scores, (list, tuple)):
        return False
    for entry in scores:
        if not isinstance(entry, dict):
            continue
        try:
            if int(entry.get("score")) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def export_research_learning(
    pattern_plan: object = None,
    ranking_plan: object = None,
    efficiency_plan: object = None,
) -> dict:
    """Package the three R33 plans into a deterministic learning export.

    ``ready`` is ``True`` only when the pattern intelligence, ranking and
    efficiency plans are all present and carry valid closed vocabularies.
    Recommendations and limitations are emitted in a fixed order.
    """

    patterns = sanitize_research_pattern_intelligence_plan(pattern_plan)
    ranking = sanitize_historical_candidate_ranking_plan(ranking_plan)
    efficiency = sanitize_research_efficiency_plan(efficiency_plan)

    patterns_valid = (
        patterns.get("strongest_signal") in PATTERN_CODES
        and patterns.get("confidence")
        in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
        and isinstance(pattern_plan, dict)
        and bool(pattern_plan)
    )
    ranking_valid = (
        ranking.get("ranking_reason") in RANKING_REASONS
        and isinstance(ranking_plan, dict)
        and bool(ranking_plan)
    )
    efficiency_valid = (
        efficiency.get("efficiency_state") in EFFICIENCY_STATES
        and efficiency.get("improvement_signal") in IMPROVEMENT_SIGNALS
        and isinstance(efficiency_plan, dict)
        and bool(efficiency_plan)
    )
    ready = patterns_valid and ranking_valid and efficiency_valid

    ranking_missing = (
        ranking.get("ranking_reason") not in RANKING_REASONS
        or ranking.get("ranking_reason") == REASON_NO_HISTORY
    )

    recommendations: list[str] = []
    if _positive_score(ranking):
        recommendations.append(RECOMMEND_PRIORITIZE)
    improvement = efficiency.get("improvement_signal")
    if improvement == SIGNAL_REDUCE_RECURRING_BLOCKERS:
        recommendations.append(RECOMMEND_REDUCE_BLOCKERS)
    elif improvement == SIGNAL_CLOSE_EVIDENCE_GAPS:
        recommendations.append(RECOMMEND_CLOSE_GAPS)
    elif improvement == SIGNAL_INCREASE_SUCCESSFUL_RESEARCH:
        recommendations.append(RECOMMEND_INCREASE_SUCCESS)
    if ranking_missing:
        recommendations.append(RECOMMEND_COLLECT_HISTORY)
    if not recommendations:
        recommendations.append(RECOMMEND_NO_ACTION)

    limitations: list[str] = []
    if ranking_missing:
        limitations.append(LIMITATION_NO_HISTORY)
    if patterns.get("confidence") not in ("HIGH", "MEDIUM"):
        limitations.append(LIMITATION_LOW_PATTERN_CONFIDENCE)
    if efficiency.get("efficiency_state") not in (
        "HIGH", "MEDIUM", "LOW",
    ):
        limitations.append(LIMITATION_UNKNOWN_EFFICIENCY)
    if (
        ranking.get("candidate_scores")
        and not _positive_score(ranking)
    ):
        limitations.append(LIMITATION_NO_HISTORICAL_SUCCESS)

    plan = ResearchLearningExportPlan(
        rule_version=RESEARCH_LEARNING_EXPORT_RULE_VERSION,
        ready=ready,
        ranking=ranking,
        patterns=patterns,
        efficiency=efficiency,
        recommendations=recommendations,
        limitations=limitations,
        research_only=True,
    )
    return research_learning_export_plan_projection(plan)


__all__ = [
    "RESEARCH_LEARNING_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_learning",
]

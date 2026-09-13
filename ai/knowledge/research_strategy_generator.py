"""Stage R34.1 deterministic research strategy generator (pure engine).

Consumes the read-only R33.4 research learning export and the R32.4 research
memory export and selects a deterministic high-level research strategy:

    "What research strategy should be preferred next?"

This is a **strategy signal only**. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo. It is a historical mapping only: no prediction, no
probability, no ML, no embeddings. It never uses or modifies the Money Score
and never modifies the R29 queue.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic precedence over closed vocabularies, byte-identical repeated
  output. No randomness, timestamps or external state.
- Read-only: inputs are never mutated; malformed values fall back to closed
  defaults and are never silently upgraded.
- Privacy: only closed codes and bounded lists are retained.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_pattern_plan import (
    PATTERN_HUMAN_RESEARCH,
    PATTERN_IDENTITY_LIMITED,
    PATTERN_NONE,
    PATTERN_SCOPE_LIMITED,
    PATTERN_TECHNOLOGY_LIMITED,
    PATTERN_VERSION_LIMITED,
)
from ai.schemas.research_strategy import (
    BASIS_DEFERRED,
    BASIS_EVIDENCE_SUCCESS,
    BASIS_HUMAN,
    BASIS_IDENTITY,
    BASIS_MALFORMED,
    BASIS_NO_HISTORY,
    BASIS_SCOPE,
    BASIS_TECHNOLOGY,
    BASIS_UNKNOWN_PATTERN,
    BASIS_VERSION,
    MAX_BLOCKERS,
    REASON_DEFERRED,
    REASON_HUMAN,
    REASON_IDENTITY,
    REASON_MALFORMED,
    REASON_NO_HISTORY,
    REASON_SCOPE,
    REASON_SUCCESS_EVIDENCE,
    REASON_TECHNOLOGY,
    REASON_UNMAPPED,
    REASON_VERSION,
    RESEARCH_STRATEGY_RULE_VERSION,
    STRATEGY_DEFERRED,
    STRATEGY_EVIDENCE_FIRST,
    STRATEGY_HUMAN_REVIEW_FIRST,
    STRATEGY_IDENTITY_FIRST,
    STRATEGY_SCOPE_FIRST,
    STRATEGY_TECHNOLOGY_FIRST,
    STRATEGY_UNKNOWN,
    STRATEGY_VERSION_FIRST,
    ResearchStrategyPlan,
    research_strategy_plan_projection,
)

RESEARCH_STRATEGY_GENERATOR_RULE_VERSION = "r34-1"
RULE_VERSION = RESEARCH_STRATEGY_GENERATOR_RULE_VERSION

CONFIDENCE_HIGH_MIN_DEFERRED = 2

# improvement-area pattern -> (strategy, reason, basis)
PATTERN_STRATEGY: dict[str, tuple] = {
    PATTERN_IDENTITY_LIMITED: (
        STRATEGY_IDENTITY_FIRST, REASON_IDENTITY, BASIS_IDENTITY,
    ),
    PATTERN_TECHNOLOGY_LIMITED: (
        STRATEGY_TECHNOLOGY_FIRST, REASON_TECHNOLOGY, BASIS_TECHNOLOGY,
    ),
    PATTERN_SCOPE_LIMITED: (
        STRATEGY_SCOPE_FIRST, REASON_SCOPE, BASIS_SCOPE,
    ),
    PATTERN_VERSION_LIMITED: (
        STRATEGY_VERSION_FIRST, REASON_VERSION, BASIS_VERSION,
    ),
    PATTERN_HUMAN_RESEARCH: (
        STRATEGY_HUMAN_REVIEW_FIRST, REASON_HUMAN, BASIS_HUMAN,
    ),
}

EFFICIENCY_CONFIDENCE: dict[str, str] = {
    CONFIDENCE_HIGH: CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM: CONFIDENCE_MEDIUM,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _i(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _closed(value: object, allowed: tuple) -> str:
    text = _upper(value)
    return text if text in allowed else ""


def _blockers(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        code = _upper(item)
        if code in CONFIDENCE_BLOCKERS and code not in out:
            out.append(code)
        if len(out) >= MAX_BLOCKERS:
            break
    return out


def _positive_ranking(ranking: dict) -> bool:
    scores = ranking.get("candidate_scores")
    if not isinstance(scores, (list, tuple)):
        return False
    for entry in scores:
        if isinstance(entry, dict):
            if _i(entry.get("score")) > 0:
                return True
    return False


def generate_research_strategy(
    learning_export: object = None,
    memory_export: object = None,
) -> dict:
    """Select a deterministic strategy from R33 learning + R32 memory.

    ``learning_export`` is the R33.4 export and ``memory_export`` the R32.4
    export. Missing/malformed learning input yields
    ``UNKNOWN``/``MALFORMED_INPUT``; an empty history yields
    ``UNKNOWN``/``INSUFFICIENT_HISTORY``. Strategy precedence is documented
    and deterministic; nothing is predicted.
    """

    learning = _block(learning_export)
    memory = _block(memory_export)
    patterns = _block(learning.get("patterns"))
    ranking = _block(learning.get("ranking"))
    efficiency = _block(learning.get("efficiency"))
    history = _block(memory.get("history"))

    blockers = _blockers(history.get("recurring_blockers"))

    if not learning:
        plan = ResearchStrategyPlan(
            rule_version=RESEARCH_STRATEGY_RULE_VERSION,
            strategy_type=STRATEGY_UNKNOWN,
            strategy_reason=REASON_MALFORMED,
            historical_basis=BASIS_MALFORMED,
            confidence_level=CONFIDENCE_UNKNOWN,
            blockers=blockers,
            research_only=True,
        )
        return research_strategy_plan_projection(plan)

    total_records = _i(history.get("total_records"))
    successful = _i(history.get("successful_count"))
    deferred = _i(history.get("deferred_count"))
    waiting = _i(history.get("waiting_count"))

    strongest = _upper(patterns.get("strongest_signal"))
    pattern_confidence = _closed(
        patterns.get("confidence"), CONFIDENCE_LEVELS
    ) or CONFIDENCE_UNKNOWN
    efficiency_state = _upper(efficiency.get("efficiency_state"))

    if total_records == 0 and not ranking.get("candidate_scores"):
        plan = ResearchStrategyPlan(
            rule_version=RESEARCH_STRATEGY_RULE_VERSION,
            strategy_type=STRATEGY_UNKNOWN,
            strategy_reason=REASON_NO_HISTORY,
            historical_basis=BASIS_NO_HISTORY,
            confidence_level=CONFIDENCE_UNKNOWN,
            blockers=blockers,
            research_only=True,
        )
        return research_strategy_plan_projection(plan)

    row = PATTERN_STRATEGY.get(strongest)
    if row is not None:
        plan = ResearchStrategyPlan(
            rule_version=RESEARCH_STRATEGY_RULE_VERSION,
            strategy_type=row[0],
            strategy_reason=row[1],
            historical_basis=row[2],
            confidence_level=pattern_confidence,
            blockers=blockers,
            research_only=True,
        )
        return research_strategy_plan_projection(plan)

    deferred_dominant = (
        deferred > 0
        and deferred >= successful
        and deferred >= waiting
    )
    if deferred_dominant:
        plan = ResearchStrategyPlan(
            rule_version=RESEARCH_STRATEGY_RULE_VERSION,
            strategy_type=STRATEGY_DEFERRED,
            strategy_reason=REASON_DEFERRED,
            historical_basis=BASIS_DEFERRED,
            confidence_level=(
                CONFIDENCE_MEDIUM
                if deferred >= CONFIDENCE_HIGH_MIN_DEFERRED
                else CONFIDENCE_LOW
            ),
            blockers=blockers,
            research_only=True,
        )
        return research_strategy_plan_projection(plan)

    if strongest == PATTERN_NONE and (
        _positive_ranking(ranking) or efficiency_state == CONFIDENCE_HIGH
    ):
        if pattern_confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM):
            confidence = pattern_confidence
        else:
            confidence = EFFICIENCY_CONFIDENCE.get(
                efficiency_state, CONFIDENCE_LOW
            )
        plan = ResearchStrategyPlan(
            rule_version=RESEARCH_STRATEGY_RULE_VERSION,
            strategy_type=STRATEGY_EVIDENCE_FIRST,
            strategy_reason=REASON_SUCCESS_EVIDENCE,
            historical_basis=BASIS_EVIDENCE_SUCCESS,
            confidence_level=confidence,
            blockers=blockers,
            research_only=True,
        )
        return research_strategy_plan_projection(plan)

    plan = ResearchStrategyPlan(
        rule_version=RESEARCH_STRATEGY_RULE_VERSION,
        strategy_type=STRATEGY_UNKNOWN,
        strategy_reason=REASON_UNMAPPED,
        historical_basis=BASIS_UNKNOWN_PATTERN,
        confidence_level=CONFIDENCE_UNKNOWN,
        blockers=blockers,
        research_only=True,
    )
    return research_strategy_plan_projection(plan)


__all__ = [
    "RESEARCH_STRATEGY_GENERATOR_RULE_VERSION",
    "RULE_VERSION",
    "PATTERN_STRATEGY",
    "EFFICIENCY_CONFIDENCE",
    "CONFIDENCE_HIGH_MIN_DEFERRED",
    "generate_research_strategy",
]

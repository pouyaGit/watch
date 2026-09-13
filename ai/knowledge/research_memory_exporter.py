"""Stage R32.4 deterministic research memory exporter (pure engine).

Creates the final read-only export object over the R32.2 research history and
the R32.3 structural pattern detection:

    "What reusable historical intelligence is available for this layer?"

This is an **export signal only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches
Mongo. It packages existing plans, never persists anything and never changes
previous planner behavior.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic: a fixed readiness rule and a fixed limitation order, with
  byte-identical repeated output. No randomness, timestamps or external
  state.
- Conservative: ``ready`` requires at least one history record and a valid
  R32.3 pattern plan; missing or malformed inputs are never silently
  upgraded.
- Read-only and privacy-safe: inputs are never mutated; the embedded history
  and pattern plans are bounded, sanitized snapshots.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_memory_export import (
    LIMITATION_NO_HISTORY,
    LIMITATION_PATTERN_LOW_CONFIDENCE,
    LIMITATION_RECURRING_BLOCKERS,
    LIMITATION_SINGLE_RECORD,
    RESEARCH_MEMORY_EXPORT_RULE_VERSION,
    ResearchMemoryExportPlan,
    research_memory_export_plan_projection,
)
from ai.schemas.research_pattern_plan import PATTERN_CODES

RESEARCH_MEMORY_EXPORTER_RULE_VERSION = "r32-4"
RULE_VERSION = RESEARCH_MEMORY_EXPORTER_RULE_VERSION


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def export_research_memory(
    history_plan: object = None,
    pattern_plan: object = None,
) -> dict:
    """Package the R32.2 history and R32.3 pattern plans into an export.

    ``ready`` is ``True`` only when at least one history record was aggregated
    and a valid pattern plan is present. ``limitations`` always lists the
    deterministic caveats (no history, single record, low-confidence pattern,
    recurring blockers) in a fixed order.
    """

    history = _block(history_plan)
    patterns = _block(pattern_plan)

    total_records = _coerce_int(history.get("total_records"))
    dominant = _upper(patterns.get("dominant_pattern"))
    confidence = _upper(patterns.get("confidence"))
    recurring_blockers = history.get("recurring_blockers") or ()

    limitations: list[str] = []
    if total_records == 0:
        limitations.append(LIMITATION_NO_HISTORY)
    elif total_records == 1:
        limitations.append(LIMITATION_SINGLE_RECORD)
    if not confidence or confidence in (CONFIDENCE_LOW, CONFIDENCE_UNKNOWN):
        limitations.append(LIMITATION_PATTERN_LOW_CONFIDENCE)
    if isinstance(recurring_blockers, (list, tuple)) and any(
        _text(code) for code in recurring_blockers
    ):
        limitations.append(LIMITATION_RECURRING_BLOCKERS)

    ready = total_records > 0 and dominant in PATTERN_CODES

    plan = ResearchMemoryExportPlan(
        rule_version=RESEARCH_MEMORY_EXPORT_RULE_VERSION,
        ready=ready,
        history=history,
        patterns=patterns,
        limitations=limitations,
        research_only=True,
    )
    return research_memory_export_plan_projection(plan)


__all__ = [
    "RESEARCH_MEMORY_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_memory",
]

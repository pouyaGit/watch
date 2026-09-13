"""Stage R32.1 deterministic research memory snapshot builder (pure engine).

Consumes one read-only R31.22 research intelligence export and projects one
immutable historical research record:

    "What was the research state at this point in history?"

This is a **memory record only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches
Mongo. It never recomputes R31 logic and never infers a vulnerability.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic: no clock is ever read. ``timestamp_reference`` is an
  explicit caller-supplied reference (``UNSPECIFIED`` when absent); the same
  export, identity and reference always produce byte-identical output.
- Consume-only: the R31.22 export is read verbatim. The status -> outcome
  decode reuses the R31.20 ``OUTCOME_SUMMARY`` table (inverted), so it is a
  closed 1:1 decode of an already-aggregated status, not a recomputation of
  evidence logic.
- Immutable and read-only: inputs are never mutated; the returned snapshot
  dict is a fresh bounded projection of a frozen pydantic model.
- Privacy: only closed codes, a caller-supplied identity/reference and a
  bounded sanitized export snapshot are retained; raw URLs, credentials,
  tokens and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.knowledge.research_intelligence_summary_planner import OUTCOME_SUMMARY
from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.evidence_feedback_calibration import (
    AREA_UNKNOWN,
    FEEDBACK_TYPES,
    FEEDBACK_UNKNOWN,
    IMPROVEMENT_AREAS,
)
from ai.schemas.evidence_research_outcome import OUTCOME_UNKNOWN
from ai.schemas.research_intelligence_summary import (
    RESEARCH_STATUSES,
    STATUS_UNKNOWN,
)
from ai.schemas.research_memory_snapshot import (
    CANDIDATE_UNSPECIFIED,
    RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION,
    TIMESTAMP_UNSPECIFIED,
    ResearchMemorySnapshot,
    research_memory_snapshot_projection,
)

RESEARCH_MEMORY_SNAPSHOT_BUILDER_RULE_VERSION = "r32-1"
RULE_VERSION = RESEARCH_MEMORY_SNAPSHOT_BUILDER_RULE_VERSION

# research_status -> outcome (inverse of the R31.20 outcome summary table).
STATUS_TO_OUTCOME: dict[str, str] = {
    row[0]: outcome for outcome, row in OUTCOME_SUMMARY.items()
}

MAX_BLOCKERS = 8


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


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


def create_research_memory_snapshot(
    export_plan: object = None,
    *,
    candidate_identity: object = None,
    timestamp_reference: object = None,
) -> dict:
    """Build one immutable memory snapshot from an R31.22 export (read-only).

    ``candidate_identity`` and ``timestamp_reference`` are explicit
    caller-supplied values; the clock is never read. Missing or malformed
    export fields yield the closed ``UNKNOWN``/``UNSPECIFIED`` defaults and
    are never silently upgraded.
    """

    export = _block(export_plan)
    summary = _block(export.get("summary"))

    status = _closed(
        summary.get("research_status"), RESEARCH_STATUSES
    ) or STATUS_UNKNOWN
    outcome = STATUS_TO_OUTCOME.get(status, OUTCOME_UNKNOWN)

    plan = ResearchMemorySnapshot(
        rule_version=RESEARCH_MEMORY_SNAPSHOT_RULE_VERSION,
        candidate_identity=(
            _text(candidate_identity) or CANDIDATE_UNSPECIFIED
        ),
        research_status=status,
        outcome=outcome,
        confidence_level=_closed(
            summary.get("confidence_level"), CONFIDENCE_LEVELS
        ) or CONFIDENCE_UNKNOWN,
        feedback_signal=_closed(
            summary.get("feedback_signal"), FEEDBACK_TYPES
        ) or FEEDBACK_UNKNOWN,
        improvement_area=_closed(
            summary.get("improvement_area"), IMPROVEMENT_AREAS
        ) or AREA_UNKNOWN,
        blockers=_blockers(summary.get("blockers")),
        timestamp_reference=(
            _text(timestamp_reference) or TIMESTAMP_UNSPECIFIED
        ),
        source_export=export,
        research_only=True,
    )
    return research_memory_snapshot_projection(plan)


__all__ = [
    "RESEARCH_MEMORY_SNAPSHOT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "STATUS_TO_OUTCOME",
    "MAX_BLOCKERS",
    "create_research_memory_snapshot",
]

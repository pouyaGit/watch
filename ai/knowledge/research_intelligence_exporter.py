"""Stage R31.22 deterministic research intelligence exporter (pure engine).

Creates the final read-only export object over the R31.20 research
intelligence summary and the R31.21 consistency validation:

    "Is the finalized R31 research intelligence ready for downstream
     consumers, and what does it contain?"

This is an **export signal only**. It never executes research, never acquires
evidence, never contacts a target, never scans, never runs Nuclei, never
crawls, never fuzzes, never exploits, never calls an LLM and never touches
Mongo. It packages existing plans and never changes previous planner
behavior.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the summary and validation plans are read verbatim. The
  exporter never recomputes them and never inspects CVE data, the Money
  Score or the R29 hunt queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-22``.
- Deterministic: a closed validation-status→readiness mapping, a fixed
  section order and byte-identical repeated output. No randomness, no
  timestamps, no hashes and no external state.
- Conservative: only a ``VALID`` R31.21 validation makes the export
  ``READY``; ``INVALID``/``UNKNOWN``/missing validation yields
  ``NOT_READY``/``UNKNOWN`` and is never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the two
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.schemas.research_consistency_validation import (
    VALIDATION_INVALID,
    VALIDATION_VALID,
)
from ai.schemas.research_intelligence_export import (
    EXPORT_NOT_READY,
    EXPORT_READY,
    EXPORT_UNKNOWN,
    MAX_SECTIONS,
    RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION,
    SECTION_SUMMARY,
    SECTION_VALIDATION,
    ResearchIntelligenceExportPlan,
    research_export_plan_projection,
)

RESEARCH_INTELLIGENCE_EXPORTER_RULE_VERSION = "r31-22"
RULE_VERSION = RESEARCH_INTELLIGENCE_EXPORTER_RULE_VERSION


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def export_research_intelligence(
    summary_plan: object = None,
    validation_plan: object = None,
) -> dict:
    """Package the R31.20 summary and R31.21 validation into an export.

    Both inputs are consumed read-only. The export is ``READY`` only when the
    R31.21 validation status is ``VALID``; an ``INVALID`` status yields
    ``NOT_READY`` and an ``UNKNOWN``/missing status yields ``UNKNOWN``.
    ``generated_sections`` lists the included summary/validation sections in a
    fixed order.
    """

    summary = _block(summary_plan)
    validation = _block(validation_plan)

    sections: list[str] = []
    if summary:
        sections.append(SECTION_SUMMARY)
    if validation:
        sections.append(SECTION_VALIDATION)

    validation_status = _upper(validation.get("validation_status"))
    if validation_status == VALIDATION_VALID:
        ready, status = True, EXPORT_READY
    elif validation_status == VALIDATION_INVALID:
        ready, status = False, EXPORT_NOT_READY
    else:
        ready, status = False, EXPORT_UNKNOWN

    plan = ResearchIntelligenceExportPlan(
        rule_version=RESEARCH_INTELLIGENCE_EXPORT_RULE_VERSION,
        ready=ready,
        status=status,
        summary=summary,
        validation=validation,
        generated_sections=sections[:MAX_SECTIONS],
        research_only=True,
    )
    return research_export_plan_projection(plan)


__all__ = [
    "RESEARCH_INTELLIGENCE_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "MAX_SECTIONS",
    "export_research_intelligence",
]

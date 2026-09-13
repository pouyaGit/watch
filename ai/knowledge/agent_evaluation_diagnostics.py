"""Stage R42.4 deterministic evaluation diagnostics builder (pure engine).

Turns raw rule-engine diagnostic references into ordered, structured,
deterministic diagnostics:

    "Which quality problems were found?"

Hard boundaries encoded here:

- Evaluation only: diagnostics are built from fixed deterministic templates.
  No LLM judgment, no execution, no network, no database, no payloads, no
  exploit instructions.
- Unknown diagnostic codes are dropped deterministically; diagnostic order
  is deterministic (dimension order, then code, then reference).
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.agent_evaluation_diagnostic import (
    AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION,
    DIAGNOSTIC_CATALOG,
    DIAGNOSTIC_CODES,
    AgentEvaluationDiagnosticPlan,
    agent_evaluation_diagnostic_plan_projection,
)
from ai.schemas.agent_evaluation_rule import EVALUATION_DIMENSIONS

AGENT_EVALUATION_DIAGNOSTICS_BUILDER_RULE_VERSION = "r42-4"
RULE_VERSION = AGENT_EVALUATION_DIAGNOSTICS_BUILDER_RULE_VERSION

MAX_DIAGNOSTICS = 32


def build_agent_evaluation_diagnostics(raw_diagnostics: object) -> list[dict]:
    """Build ordered, deduplicated diagnostics from raw references.

    Each raw item is a bounded ``{diagnostic_code, evidence_reference}``
    dict; unknown codes or malformed items are dropped. Ordering is by
    canonical dimension order, then diagnostic code, then evidence
    reference — always deterministic.
    """

    if not isinstance(raw_diagnostics, (list, tuple)):
        return []
    collected: dict[tuple, dict] = {}
    for item in raw_diagnostics:
        if not isinstance(item, dict):
            continue
        code = str(item.get("diagnostic_code") or "").strip().upper()
        if code not in DIAGNOSTIC_CODES:
            continue
        reference = str(item.get("evidence_reference") or "").strip()
        collected.setdefault((code, reference), item)
    diagnostics: list[dict] = []
    for (code, reference) in collected:
        dimension, severity, message, hint = DIAGNOSTIC_CATALOG[code]
        plan = AgentEvaluationDiagnosticPlan(
            rule_version=AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION,
            diagnostic_code=code,
            dimension=dimension,
            severity=severity,
            message=message,
            evidence_reference=reference,
            remediation_hint=hint,
        )
        diagnostics.append(
            agent_evaluation_diagnostic_plan_projection(plan)
        )
    diagnostics.sort(
        key=lambda entry: (
            EVALUATION_DIMENSIONS.index(entry["dimension"]),
            entry["diagnostic_code"],
            entry["evidence_reference"],
        )
    )
    return diagnostics[:MAX_DIAGNOSTICS]


def collect_evaluation_diagnostics(outcomes: object) -> list[dict]:
    """Flatten the diagnostics of dimension outcomes (read-only)."""

    raw: list[dict] = []
    if not isinstance(outcomes, (list, tuple)):
        return []
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            continue
        for item in outcome.get("diagnostics") or ():
            if isinstance(item, dict):
                raw.append(item)
    return build_agent_evaluation_diagnostics(raw)


__all__ = [
    "AGENT_EVALUATION_DIAGNOSTICS_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "MAX_DIAGNOSTICS",
    "build_agent_evaluation_diagnostics",
    "collect_evaluation_diagnostics",
]

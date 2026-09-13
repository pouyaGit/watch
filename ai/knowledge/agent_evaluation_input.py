"""Stage R42.1 deterministic agent evaluation input builder (pure engine).

Builds the bounded, read-only evaluation input from a structured security
agent result:

    "What structured result is being evaluated?"

Hard boundaries encoded here:

- Evaluation only: the builder reads structured data and performs no
  execution, no network, no database, no browser, no LLM call and no
  payload handling.
- Malformed values are projected deterministically and recorded in
  ``structural_flags``; malformed input never silently becomes valid.
- Generic: works for R38-compatible results and for R39/R40/R41 specialist
  results (and future specialists) without specialist-specific logic.
- ``research_only`` is preserved as supplied so the safety evaluator can
  detect and fail it.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import re

from ai.schemas.agent_evaluation_input import (
    AGENT_EVALUATION_INPUT_RULE_VERSION,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_INVALID_RULE_VERSION,
    FLAG_MALFORMED_EVIDENCE_PLAN,
    FLAG_MALFORMED_GOVERNANCE,
    FLAG_MALFORMED_HYPOTHESIS,
    FLAG_MALFORMED_LIMITATIONS,
    FLAG_MALFORMED_PROVENANCE,
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_NON_DETERMINISTIC_OUTPUT,
    FLAG_PROVENANCE_INVENTED_LAYER,
    FLAG_UNKNOWN_AGENT_CATEGORY,
    GENERIC_PROVENANCE_LAYERS,
    STRUCTURAL_FLAGS,
    AgentEvaluationInputPlan,
    agent_evaluation_input_plan_projection,
    sanitize_agent_evaluation_input,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES
from ai.schemas.security_agent_result import AGENT_RESULT_STATUSES

AGENT_EVALUATION_INPUT_BUILDER_RULE_VERSION = "r42-1"
RULE_VERSION = AGENT_EVALUATION_INPUT_BUILDER_RULE_VERSION

_RULE_VERSION_RE = re.compile(r"^r[0-9]{2,3}-[0-9]{1,2}$")

NONDETERMINISTIC_KEY_TOKENS: tuple[str, ...] = (
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "evaluated_at",
    "runtime_id",
    "nonce",
    "uuid",
    "random",
)

STATUS_FIELD = "status"
CONFIDENCE_FIELD = "confidence"
RULE_VERSION_FIELD = "rule_version"
AGENT_IDENTITY_FIELD = "agent_identity"


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _has_nondeterministic_keys(value: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            if any(token in name for token in NONDETERMINISTIC_KEY_TOKENS):
                return True
            if _has_nondeterministic_keys(child, depth + 1):
                return True
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:32]:
            if _has_nondeterministic_keys(item, depth + 1):
                return True
    return False


def _has_invented_layers(raw_provenance: object) -> bool:
    if not isinstance(raw_provenance, dict):
        return False
    for item in raw_provenance.get("source_layers") or ():
        text = _text(item).upper()
        if text and text not in GENERIC_PROVENANCE_LAYERS:
            return True
    return False


def _collect_flags(
    raw: object,
    agent_category: object = None,
    agent_id: object = None,
) -> list[str]:
    flags: list[str] = []
    if not isinstance(raw, dict):
        return [FLAG_MISSING_REQUIRED_FIELD]

    identity = raw.get(AGENT_IDENTITY_FIELD)
    identity = identity if isinstance(identity, dict) else {}

    category = (
        _text(agent_category)
        or _text(identity.get("category"))
        or _text(raw.get("agent_category"))
        or "UNKNOWN"
    ).upper()
    if category not in AGENT_CATEGORIES:
        flags.append(FLAG_INVALID_ENUM_VALUE)
        category = "UNKNOWN"
    if category == "UNKNOWN":
        flags.append(FLAG_UNKNOWN_AGENT_CATEGORY)

    resolved_agent_id = (
        _text(agent_id)
        or _text(identity.get("agent_id"))
        or _text(raw.get("agent_id"))
    )
    if not resolved_agent_id:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)

    result_rule = _text(raw.get(RULE_VERSION_FIELD))
    identity_rule = _text(identity.get(RULE_VERSION_FIELD))
    if not result_rule:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not _RULE_VERSION_RE.match(result_rule):
        flags.append(FLAG_INVALID_RULE_VERSION)
    if identity_rule and not _RULE_VERSION_RE.match(identity_rule):
        flags.append(FLAG_INVALID_RULE_VERSION)

    if STATUS_FIELD not in raw:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    else:
        status = _text(raw.get(STATUS_FIELD)).upper()
        if status not in AGENT_RESULT_STATUSES:
            flags.append(FLAG_INVALID_ENUM_VALUE)

    if CONFIDENCE_FIELD not in raw:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    else:
        confidence = _text(raw.get(CONFIDENCE_FIELD)).upper()
        if confidence not in CONFIDENCE_LEVELS:
            flags.append(FLAG_INVALID_ENUM_VALUE)

    if "context_analysis" not in raw:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)

    raw_hypotheses = raw.get("hypotheses")
    if raw_hypotheses is None:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not isinstance(raw_hypotheses, (list, tuple)):
        flags.append(FLAG_MALFORMED_HYPOTHESIS)
    else:
        for item in raw_hypotheses:
            if not isinstance(item, dict):
                flags.append(FLAG_MALFORMED_HYPOTHESIS)
                break
            if not _text(item.get("hypothesis_type")):
                flags.append(FLAG_MALFORMED_HYPOTHESIS)
                break
            confidence = _text(item.get("confidence")).upper()
            if confidence and confidence not in CONFIDENCE_LEVELS:
                flags.append(FLAG_INVALID_ENUM_VALUE)
                break

    raw_evidence = raw.get("evidence_plan")
    if raw_evidence is None:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not isinstance(raw_evidence, dict):
        flags.append(FLAG_MALFORMED_EVIDENCE_PLAN)

    raw_limitations = raw.get("limitations")
    if raw_limitations is None:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not isinstance(raw_limitations, (list, tuple)):
        flags.append(FLAG_MALFORMED_LIMITATIONS)

    raw_provenance = raw.get("provenance")
    if raw_provenance is None:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not isinstance(raw_provenance, dict):
        flags.append(FLAG_MALFORMED_PROVENANCE)
    elif _has_invented_layers(raw_provenance):
        flags.append(FLAG_PROVENANCE_INVENTED_LAYER)

    raw_governance = raw.get("governance_reference")
    if raw_governance is None:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
    elif not isinstance(raw_governance, dict):
        flags.append(FLAG_MALFORMED_GOVERNANCE)

    if _has_nondeterministic_keys(raw):
        flags.append(FLAG_NON_DETERMINISTIC_OUTPUT)

    return flags


def build_agent_evaluation_input(
    result_plan: object = None,
    agent_id: object = None,
    agent_category: object = None,
) -> dict:
    """Build the deterministic evaluation input (read-only).

    ``result_plan`` may be a plain R38-compatible result or an R39/R40/R41
    specialist result (or a future specialist result with the same generic
    shape). Malformed values are projected to bounded placeholders and
    recorded in ``structural_flags``; nothing is silently accepted.
    """

    raw = result_plan if isinstance(result_plan, dict) else {}
    identity = raw.get(AGENT_IDENTITY_FIELD)
    identity = identity if isinstance(identity, dict) else {}

    requested_category = (
        _text(agent_category)
        or _text(identity.get("category"))
        or _text(raw.get("agent_category"))
        or "UNKNOWN"
    ).upper()
    category = (
        requested_category
        if requested_category in AGENT_CATEGORIES
        else "UNKNOWN"
    )

    resolved_agent_id = (
        _text(agent_id)
        or _text(identity.get("agent_id"))
        or _text(raw.get("agent_id"))
    )

    result_rule = _text(raw.get(RULE_VERSION_FIELD))
    agent_rule = _text(identity.get(RULE_VERSION_FIELD)) or result_rule

    flags = _collect_flags(
        raw, agent_category=requested_category, agent_id=resolved_agent_id
    )

    values = sanitize_agent_evaluation_input(
        {
            "rule_version": AGENT_EVALUATION_INPUT_RULE_VERSION,
            "agent_id": resolved_agent_id,
            "agent_category": category,
            "agent_rule_version": agent_rule,
            "result_rule_version": result_rule,
            "result_status": raw.get(STATUS_FIELD),
            "result_confidence": raw.get(CONFIDENCE_FIELD),
            "context_analysis": raw.get("context_analysis"),
            "hypotheses": raw.get("hypotheses"),
            "evidence_plan": raw.get("evidence_plan"),
            "limitations": raw.get("limitations"),
            "provenance": raw.get("provenance"),
            "governance_reference": raw.get("governance_reference"),
            "research_only": raw.get("research_only", True),
            "structural_flags": flags,
        }
    )
    values["rule_version"] = AGENT_EVALUATION_INPUT_RULE_VERSION
    ordered_flags: list[str] = []
    for flag in STRUCTURAL_FLAGS:
        if flag in flags and flag not in ordered_flags:
            ordered_flags.append(flag)
    values["structural_flags"] = ordered_flags

    plan = AgentEvaluationInputPlan(**values)
    return agent_evaluation_input_plan_projection(plan)


def evaluation_context_fact_count(context_analysis: object) -> int:
    """Count known (non-UNKNOWN, non-empty) context facts.

    A pure generic proxy for how much structured context the agent received.
    It does not measure whether a vulnerability exists.
    """

    if not isinstance(context_analysis, dict):
        return 0
    count = 0
    for key, value in context_analysis.items():
        if key in ("rule_version", "research_only"):
            continue
        if isinstance(value, bool):
            count += 1
        elif isinstance(value, (int, float)):
            count += 1
        elif isinstance(value, str):
            text = value.strip().upper()
            if text and text != "UNKNOWN":
                count += 1
        elif isinstance(value, (list, tuple)):
            if value:
                count += 1
    return count


__all__ = [
    "AGENT_EVALUATION_INPUT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "NONDETERMINISTIC_KEY_TOKENS",
    "build_agent_evaluation_input",
    "evaluation_context_fact_count",
]

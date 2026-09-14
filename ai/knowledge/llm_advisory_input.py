"""Stage R45.1 deterministic LLM advisory input builder (pure engine).

Builds the bounded, read-only advisory input from already-produced
deterministic research artifacts:

    "What structured research intelligence should be explained?"

Hard boundaries encoded here:

- Advisory only: the builder reads structured data and performs no execution,
  no network, no database, no browser, no LLM provider call and no payload
  handling. The LLM is never contacted here; only a bounded request
  representation is prepared.
- Deterministic consumption: R42 evaluation results and R43 collaboration
  results are consumed through their own sanitizers; R44 learning signals
  through the R44 signal sanitizer. Nothing is recomputed.
- No runtime identity: ``advisory_id`` is a deterministic content token
  derived from the bounded input; no timestamps, UUIDs, randomness or
  runtime ids.
- Malformed values are projected deterministically and recorded in
  ``structural_flags``; malformed input never silently becomes valid.
- ``research_only`` is always true.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json
import re

from ai.schemas.agent_evaluation_result import (
    sanitize_agent_evaluation_result_plan,
)
from ai.schemas.llm_advisory_input import (
    ADVISORY_ID_PREFIX,
    ADVISORY_ID_RE,
    ADVISORY_GOVERNANCE_STATES,
    ADVISORY_INPUT_LIMITATIONS,
    ADVISORY_INPUT_STRUCTURAL_FLAGS,
    ADVISORY_SAFETY_STATES,
    FLAG_INVALID_ADVISORY_ID,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_INVALID_RULE_VERSION,
    FLAG_MALFORMED_COLLABORATION_SUMMARY,
    FLAG_MALFORMED_EVALUATION_SUMMARY,
    FLAG_MALFORMED_LEARNING_SIGNALS,
    FLAG_NON_DETERMINISTIC_INPUT,
    FLAG_UNKNOWN_SOURCE_LAYER,
    GOVERNANCE_UNKNOWN,
    LLM_ADVISORY_INPUT_RULE_VERSION,
    LLM_ADVISORY_SOURCE_LAYERS,
    SAFETY_UNKNOWN,
    SOURCE_LAYER_MULTI,
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R43,
    SOURCE_LAYER_R44,
    SOURCE_LAYER_UNKNOWN,
    LLMAdvisoryInputPlan,
    llm_advisory_input_plan_projection,
    sanitize_advisory_collaboration_summary,
    sanitize_advisory_evaluation_summary,
    sanitize_advisory_learning_signals,
    sanitize_advisory_research_context,
    sanitize_llm_advisory_input,
)
from ai.schemas.multi_agent_collaboration_result import (
    sanitize_multi_agent_collaboration_result,
)

LLM_ADVISORY_INPUT_BUILDER_RULE_VERSION = "r45-1"
RULE_VERSION = LLM_ADVISORY_INPUT_BUILDER_RULE_VERSION

_RULE_VERSION_RE = re.compile(r"^r[0-9]{2,3}-[0-9]{1,2}$")

NONDETERMINISTIC_KEY_TOKENS: tuple[str, ...] = (
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "generated_at",
    "runtime_id",
    "nonce",
    "uuid",
    "random",
)


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


def _valid_rule_version(value: object) -> bool:
    return bool(_RULE_VERSION_RE.match(str(value if value is not None else "")))


def _is_evaluation_artifact(value: object) -> bool:
    """Return True when the value looks like an R42 evaluation result."""

    if not isinstance(value, dict):
        return False
    rule_version = str(value.get("rule_version") or "")
    if rule_version.startswith("r42-"):
        return True
    return "evaluation_rule_version" in value and "overall_rating" in value


def _is_collaboration_artifact(value: object) -> bool:
    """Return True when the value looks like an R43 collaboration result."""

    if not isinstance(value, dict):
        return False
    rule_version = str(value.get("rule_version") or "")
    if rule_version.startswith("r43-"):
        return True
    return (
        "collaboration_rule_version" in value
        and "collaboration_id" in value
    )


def _ordered_flags(flags: list[str]) -> list[str]:
    return [
        flag
        for flag in ADVISORY_INPUT_STRUCTURAL_FLAGS
        if flag in flags
    ]


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def derive_llm_advisory_id(payload: object) -> str:
    """Derive the deterministic advisory id from bounded content."""

    digest = hashlib.sha256(
        _canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return ADVISORY_ID_PREFIX + digest[:16]


def _derive_source_layer(
    evaluation_summary: dict,
    collaboration_summary: dict,
    learning_signals: list[dict],
) -> str:
    layers: list[str] = []
    if evaluation_summary.get("present"):
        layers.append(SOURCE_LAYER_R42)
    if collaboration_summary.get("present"):
        layers.append(SOURCE_LAYER_R43)
    if learning_signals:
        layers.append(SOURCE_LAYER_R44)
    if not layers:
        return SOURCE_LAYER_UNKNOWN
    if len(layers) > 1:
        return SOURCE_LAYER_MULTI
    return layers[0]


def _derive_governance_state(collaboration_summary: dict) -> str:
    if not collaboration_summary.get("present"):
        return GOVERNANCE_UNKNOWN
    state = str(
        collaboration_summary.get("governance_state") or GOVERNANCE_UNKNOWN
    ).upper()
    return state if state in ADVISORY_GOVERNANCE_STATES else GOVERNANCE_UNKNOWN


def _derive_safety_state(
    evaluation_summary: dict, explicit: object
) -> str:
    if isinstance(explicit, str) and explicit.strip():
        text = explicit.strip().upper()
        return text if text in ADVISORY_SAFETY_STATES else SAFETY_UNKNOWN
    if evaluation_summary.get("present"):
        state = str(
            evaluation_summary.get("safety_state") or SAFETY_UNKNOWN
        ).upper()
        if state in ADVISORY_SAFETY_STATES:
            return state
    return SAFETY_UNKNOWN


def build_llm_advisory_input(
    evaluation_result: object = None,
    collaboration_result: object = None,
    learning_signals: object = None,
    research_context: object = None,
    governance_state: object = None,
    safety_state: object = None,
    source_layer: object = None,
    advisory_id: object = None,
    limitations: object = None,
) -> dict:
    """Build the deterministic advisory input (read-only).

    R42 evaluation results and R43 collaboration results are consumed
    through their own sanitizers; R44 learning signals through the R44
    sanitizer. Malformed values are projected to bounded placeholders and
    recorded in ``structural_flags``; nothing is silently accepted.
    """

    flags: list[str] = []

    evaluation_source = evaluation_result
    if evaluation_source is not None and (
        not isinstance(evaluation_source, dict)
        or not _is_evaluation_artifact(evaluation_source)
    ):
        flags.append(FLAG_MALFORMED_EVALUATION_SUMMARY)
        evaluation_source = None
    if isinstance(evaluation_source, dict):
        if not _valid_rule_version(evaluation_source.get("rule_version")):
            flags.append(FLAG_INVALID_RULE_VERSION)
        bounded_evaluation = sanitize_agent_evaluation_result_plan(
            evaluation_source
        )
    else:
        bounded_evaluation = sanitize_agent_evaluation_result_plan(None)
    evaluation_summary = sanitize_advisory_evaluation_summary(
        {
            **bounded_evaluation,
            "reference_rule_version": bounded_evaluation.get("rule_version"),
            "diagnostic_codes": [
                entry.get("diagnostic_code")
                for entry in bounded_evaluation.get("diagnostics") or ()
                if isinstance(entry, dict)
            ],
            "present": evaluation_source is not None,
        }
    )

    collaboration_source = collaboration_result
    if collaboration_source is not None and (
        not isinstance(collaboration_source, dict)
        or not _is_collaboration_artifact(collaboration_source)
    ):
        flags.append(FLAG_MALFORMED_COLLABORATION_SUMMARY)
        collaboration_source = None
    if isinstance(collaboration_source, dict):
        if not _valid_rule_version(collaboration_source.get("rule_version")):
            flags.append(FLAG_INVALID_RULE_VERSION)
        bounded_collaboration = sanitize_multi_agent_collaboration_result(
            collaboration_source
        )
    else:
        bounded_collaboration = sanitize_multi_agent_collaboration_result(
            None
        )
    collaboration_summary = sanitize_advisory_collaboration_summary(
        {
            **bounded_collaboration,
            "reference_rule_version": bounded_collaboration.get(
                "rule_version"
            ),
            "present": collaboration_source is not None,
        }
    )

    if learning_signals is not None:
        if isinstance(learning_signals, dict):
            signal_items: list = [learning_signals]
        elif isinstance(learning_signals, (list, tuple)):
            signal_items = list(learning_signals)
            if any(not isinstance(item, dict) for item in signal_items):
                flags.append(FLAG_MALFORMED_LEARNING_SIGNALS)
        else:
            flags.append(FLAG_MALFORMED_LEARNING_SIGNALS)
            signal_items = []
    else:
        signal_items = []
    bounded_signals = sanitize_advisory_learning_signals(signal_items)

    bounded_context = sanitize_advisory_research_context(research_context)

    explicit_layer = str(
        source_layer if source_layer is not None else ""
    ).strip().upper()
    if explicit_layer:
        if explicit_layer not in LLM_ADVISORY_SOURCE_LAYERS:
            flags.append(FLAG_UNKNOWN_SOURCE_LAYER)
            resolved_layer = _derive_source_layer(
                evaluation_summary, collaboration_summary, bounded_signals
            )
        else:
            resolved_layer = explicit_layer
    else:
        resolved_layer = _derive_source_layer(
            evaluation_summary, collaboration_summary, bounded_signals
        )

    if governance_state is not None and str(governance_state).strip():
        text = str(governance_state).strip().upper()
        if text not in ADVISORY_GOVERNANCE_STATES:
            flags.append(FLAG_INVALID_ENUM_VALUE)
            resolved_governance = _derive_governance_state(
                collaboration_summary
            )
        else:
            resolved_governance = text
    else:
        resolved_governance = _derive_governance_state(
            collaboration_summary
        )

    if safety_state is not None and str(safety_state).strip():
        text = str(safety_state).strip().upper()
        if text not in ADVISORY_SAFETY_STATES:
            flags.append(FLAG_INVALID_ENUM_VALUE)
    resolved_safety = _derive_safety_state(evaluation_summary, safety_state)

    supplied_id = str(
        advisory_id if advisory_id is not None else ""
    ).strip()
    if supplied_id and not ADVISORY_ID_RE.match(supplied_id):
        flags.append(FLAG_INVALID_ADVISORY_ID)
        supplied_id = ""

    if any(
        _has_nondeterministic_keys(item)
        for item in (
            evaluation_result,
            collaboration_result,
            signal_items,
            research_context,
        )
    ):
        flags.append(FLAG_NON_DETERMINISTIC_INPUT)

    bounded_limitations = [
        code
        for code in (limitations if limitations is not None
                     else ADVISORY_INPUT_LIMITATIONS)
        if isinstance(code, str)
        and code.strip().upper() in ADVISORY_INPUT_LIMITATIONS
    ]
    if not bounded_limitations:
        bounded_limitations = list(ADVISORY_INPUT_LIMITATIONS)

    content = {
        "source_layer": resolved_layer,
        "research_context": bounded_context,
        "evaluation_summary": evaluation_summary,
        "collaboration_summary": collaboration_summary,
        "learning_signals": bounded_signals,
        "governance_state": resolved_governance,
        "safety_state": resolved_safety,
    }
    resolved_id = supplied_id or derive_llm_advisory_id(content)

    values = sanitize_llm_advisory_input(
        {
            "rule_version": LLM_ADVISORY_INPUT_RULE_VERSION,
            "advisory_id": resolved_id,
            **content,
            "limitations": [
                code.strip().upper()
                for code in bounded_limitations
            ],
            "research_only": True,
            "structural_flags": _ordered_flags(flags),
        }
    )
    values["rule_version"] = LLM_ADVISORY_INPUT_RULE_VERSION
    values["advisory_id"] = resolved_id
    values["structural_flags"] = _ordered_flags(flags)

    plan = LLMAdvisoryInputPlan(**values)
    result = llm_advisory_input_plan_projection(plan)
    result["rule_version"] = LLM_ADVISORY_INPUT_RULE_VERSION
    return result


__all__ = [
    "LLM_ADVISORY_INPUT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "NONDETERMINISTIC_KEY_TOKENS",
    "build_llm_advisory_input",
    "derive_llm_advisory_id",
]

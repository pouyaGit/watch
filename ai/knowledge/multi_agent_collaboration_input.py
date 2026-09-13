"""Stage R43.1 deterministic collaboration input builder (pure engine).

Builds the bounded, read-only multi-agent collaboration input from
specialist results and optional R42 evaluation results:

    "Which specialist research artifacts are collaborating?"

Hard boundaries encoded here:

- Collaboration only: no agent execution, no subprocess, no network, no
  database, no browser, no LLM call, no payloads.
- Generic: R42's evaluation input projection normalizes every specialist
  result; no specialist-specific branches exist.
- Malformed results are preserved with structural flags and diagnostics;
  nothing is silently discarded or invented.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.agent_evaluation_input import (
    build_agent_evaluation_input,
)
from ai.knowledge.shared_research_context import (
    merge_shared_research_context,
)
from ai.schemas.agent_evaluation_result import (
    sanitize_agent_evaluation_result_plan,
)
from ai.schemas.multi_agent_collaboration_input import (
    COLLABORATION_ID_PREFIX,
    COLLABORATION_ID_RE,
    DIAGNOSTIC_DUPLICATE_AGENT_ID,
    DIAGNOSTIC_EVALUATION_AGENT_MISMATCH,
    DIAGNOSTIC_INVALID_EVALUATION_RESULT,
    DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT,
    DIAGNOSTIC_MISSING_AGENT_IDENTITY,
    DIAGNOSTIC_MISSING_PROVENANCE,
    DIAGNOSTIC_MISSING_SPECIALIST_RESULTS,
    DIAGNOSTIC_NON_DETERMINISTIC_INPUT,
    DIAGNOSTIC_UNKNOWN_AGENT_CATEGORY,
    MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    MultiAgentCollaborationInputPlan,
    multi_agent_collaboration_input_plan_projection,
    sanitize_collaboration_evaluation,
    sanitize_multi_agent_collaboration_input,
    sanitize_specialist_result,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

MULTI_AGENT_COLLABORATION_INPUT_BUILDER_RULE_VERSION = "r43-1"
RULE_VERSION = MULTI_AGENT_COLLABORATION_INPUT_BUILDER_RULE_VERSION

_MALFORMED_FLAG_MARKERS: tuple[str, ...] = (
    "MALFORMED_HYPOTHESIS",
    "MALFORMED_EVIDENCE_PLAN",
    "MALFORMED_PROVENANCE",
    "MALFORMED_GOVERNANCE",
    "MALFORMED_LIMITATIONS",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _diagnostic(
    code: str,
    severity: str,
    reference: str,
    message: str,
) -> dict:
    return {
        "diagnostic_code": code,
        "severity": severity,
        "agent_reference": reference,
        "message": message,
    }


def _participating_agent(projected: dict) -> dict:
    return {
        "agent_id": projected.get("agent_id") or "",
        "agent_category": projected.get("agent_category") or "UNKNOWN",
        "agent_rule_version": projected.get("agent_rule_version") or "",
        "result_rule_version": projected.get("result_rule_version") or "",
        "research_only": bool(projected.get("research_only", True)),
        "provenance": projected.get("provenance") or {},
    }


def _deterministic_collaboration_id(
    projected_results: list[dict],
    shared_context: dict,
) -> str:
    basis = "|".join(
        sorted(
            "{}#{}#{}".format(
                result.get("agent_id") or "",
                result.get("agent_category") or "UNKNOWN",
                result.get("result_rule_version") or "",
            )
            for result in projected_results
        )
    )
    context_digest = hashlib.sha256(
        json.dumps(shared_context, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    basis = f"{MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION}|{basis}|" \
            f"{context_digest}"
    return COLLABORATION_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def build_multi_agent_collaboration_input(
    result_plans: object = None,
    evaluation_results: object = None,
    shared_context: object = None,
    collaboration_id: object = None,
) -> dict:
    """Build the deterministic collaboration input (read-only).

    Every specialist result is normalized through the R42 evaluation input
    projection; malformed results are retained with structural flags and
    collaboration diagnostics so attribution is never lost.
    """

    raw_results = (
        list(result_plans)
        if isinstance(result_plans, (list, tuple))
        else []
    )
    diagnostics: list[dict] = []
    if not raw_results:
        diagnostics.append(
            _diagnostic(
                DIAGNOSTIC_MISSING_SPECIALIST_RESULTS,
                SEVERITY_HIGH,
                "specialist_results",
                "no specialist results were supplied",
            )
        )

    projected_results: list[dict] = []
    for index, raw in enumerate(raw_results):
        reference = f"specialist_results[{index}]"
        override_id = None
        override_category = None
        if isinstance(raw, dict) and isinstance(
            raw.get("specialist_result"), dict
        ):
            override_id = raw.get("agent_id")
            override_category = raw.get("agent_category")
            raw = raw["specialist_result"]
        if not isinstance(raw, dict):
            projected = sanitize_specialist_result(None)
            projected_results.append(projected)
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT,
                    SEVERITY_HIGH,
                    reference,
                    "specialist result is not a structured object",
                )
            )
            continue
        projected = build_agent_evaluation_input(
            raw,
            agent_id=override_id,
            agent_category=override_category,
        )
        raw_hypotheses = raw.get("hypotheses")
        if isinstance(raw_hypotheses, (list, tuple)):
            projected_hypotheses = projected.get("hypotheses") or []
            for hypothesis_index, hypothesis in enumerate(
                projected_hypotheses
            ):
                if hypothesis_index >= len(raw_hypotheses):
                    break
                original = raw_hypotheses[hypothesis_index]
                if not isinstance(original, dict):
                    continue
                subject = original.get("subject_reference")
                if subject:
                    hypothesis["subject_reference"] = str(subject)
        projected_results.append(projected)
        if not projected.get("agent_id"):
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_MISSING_AGENT_IDENTITY,
                    SEVERITY_MEDIUM,
                    reference,
                    "specialist result has no agent identity",
                )
            )
        if projected.get("agent_category") not in AGENT_CATEGORIES or (
            projected.get("agent_category") == "UNKNOWN"
        ):
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_UNKNOWN_AGENT_CATEGORY,
                    SEVERITY_MEDIUM,
                    reference,
                    "specialist result has no declared agent category",
                )
            )
        raw_provenance = raw.get("provenance")
        if not isinstance(raw_provenance, dict) or not raw_provenance:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_MISSING_PROVENANCE,
                    SEVERITY_LOW,
                    reference,
                    "specialist result has no provenance record",
                )
            )
        flags = projected.get("structural_flags") or ()
        if any(marker in flags for marker in _MALFORMED_FLAG_MARKERS):
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT,
                    SEVERITY_MEDIUM,
                    reference,
                    "specialist result contains malformed structures",
                )
            )
        if "NON_DETERMINISTIC_OUTPUT" in flags:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_NON_DETERMINISTIC_INPUT,
                    SEVERITY_LOW,
                    reference,
                    "specialist result contains non-deterministic markers",
                )
            )

    seen_ids: dict[str, int] = {}
    for result in projected_results:
        agent_id = result.get("agent_id") or ""
        if agent_id:
            seen_ids[agent_id] = seen_ids.get(agent_id, 0) + 1
    for agent_id, count in seen_ids.items():
        if count > 1:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_DUPLICATE_AGENT_ID,
                    SEVERITY_MEDIUM,
                    agent_id,
                    "multiple specialist results share an agent id",
                )
            )

    participants: list[dict] = []
    for result in projected_results:
        participant = _participating_agent(result)
        if participant not in participants:
            participants.append(participant)

    evaluations: list[dict] = []
    raw_evaluations = (
        list(evaluation_results)
        if isinstance(evaluation_results, (list, tuple))
        else []
    )
    known_agents = {
        (result.get("agent_id") or "", result.get("agent_category") or "")
        for result in projected_results
    }
    for index, raw in enumerate(raw_evaluations):
        reference = f"evaluation_results[{index}]"
        if not isinstance(raw, dict):
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_INVALID_EVALUATION_RESULT,
                    SEVERITY_MEDIUM,
                    reference,
                    "evaluation result is not a structured object",
                )
            )
            continue
        sanitized = sanitize_agent_evaluation_result_plan(raw)
        projected = sanitize_collaboration_evaluation(sanitized)
        if not projected.get("agent_id"):
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_INVALID_EVALUATION_RESULT,
                    SEVERITY_MEDIUM,
                    reference,
                    "evaluation result is missing required fields",
                )
            )
        evaluations.append(projected)
        match = (
            projected.get("agent_id") or "",
            projected.get("agent_category") or "",
        )
        if known_agents and match not in known_agents:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_EVALUATION_AGENT_MISMATCH,
                    SEVERITY_LOW,
                    reference,
                    "evaluation result does not match a participating "
                    "agent",
                )
            )

    merged_context = merge_shared_research_context(shared_context)

    provided_id = _text(collaboration_id)
    if provided_id and COLLABORATION_ID_RE.match(provided_id):
        resolved_id = provided_id
    else:
        resolved_id = _deterministic_collaboration_id(
            projected_results, merged_context
        )

    sanitized = sanitize_multi_agent_collaboration_input(
        {
            "rule_version": MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION,
            "collaboration_rule_version": (
                MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION
            ),
            "collaboration_id": resolved_id,
            "participating_agents": participants,
            "specialist_results": [
                dict(result) for result in projected_results
            ],
            "evaluation_results": evaluations,
            "shared_context": merged_context,
            "collaboration_diagnostics": diagnostics,
            "research_only": True,
        }
    )
    sanitized["rule_version"] = (
        MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION
    )
    sanitized["collaboration_rule_version"] = (
        MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION
    )

    plan = MultiAgentCollaborationInputPlan(**sanitized)
    return multi_agent_collaboration_input_plan_projection(plan)


__all__ = [
    "MULTI_AGENT_COLLABORATION_INPUT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "build_multi_agent_collaboration_input",
]

"""Stage R43.4 deterministic collaboration conflict analyzer (pure engine).

Detects and characterizes conflicts between collaborating specialist
research results:

    "Which structured research claims diverge, and how can the divergence
     be characterized?"

Hard boundaries encoded here:

- Collaboration only: conflicts are computed from structured data. Both
  sides are always preserved; nothing is deleted or silently normalized.
- No invention: a conflict exists only when the structured fields actually
  diverge; unknown/insufficient data yields UNKNOWN resolution.
- Safety surfacing: forbidden execution/confirmation claims in inputs are
  preserved with attribution and surfaced as SAFETY_CONFLICT; unsafe claims
  are never normalized into safe claims.
- Deterministic: records, ids and ordering are pure functions of the
  normalized structured data.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib

from ai.schemas.collaboration_conflict import (
    COLLABORATION_CONFLICT_RULE_VERSION,
    CONFLICT_CONFIDENCE,
    CONFLICT_CONTEXT,
    CONFLICT_EVIDENCE_STATE,
    CONFLICT_GOVERNANCE,
    CONFLICT_HYPOTHESIS,
    CONFLICT_ID_PREFIX,
    CONFLICT_PROVENANCE,
    CONFLICT_SAFETY,
    CONFLICT_TYPES,
    CollaborationConflictRecordPlan,
    collaboration_conflict_record_plan_projection,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.hypothesis_correlation import (
    CONFIDENCE_CONFLICT as GROUP_CONFIDENCE_CONFLICT,
    CORRELATION_CONFLICTING,
)
from ai.schemas.multi_agent_collaboration_input import (
    sanitize_multi_agent_collaboration_input,
)

COLLABORATION_CONFLICT_ANALYZER_RULE_VERSION = "r43-5"
RULE_VERSION = COLLABORATION_CONFLICT_ANALYZER_RULE_VERSION

CONFIDENCE_BANDS: dict[str, int] = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

EVIDENCE_BANDS: dict[str, int] = {
    "UNKNOWN": 0,
    "PARTIAL": 1,
    "COMPLETE": 2,
}

PROVENANCE_BANDS: dict[str, int] = {
    "UNKNOWN": 0,
    "PARTIAL": 1,
    "COMPLETE": 2,
}

EXECUTION_CLAIM_TOKENS: tuple[str, ...] = (
    "PAYLOAD_SENT",
    "PAYLOAD_EXECUTED",
    "COMMAND_EXECUTED",
    "ATTACK_PERFORMED",
    "SCAN_PERFORMED",
    "EXPLOITED",
    "EXECUTED",
)

CONFIRMATION_CLAIM_TOKENS: tuple[str, ...] = (
    "VULNERABILITY_CONFIRMED",
    "CONFIRMED_VULNERABILITY",
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
)

_CONFLICT_MESSAGES: dict[str, str] = {
    CONFLICT_SAFETY: "conflicting safety posture detected",
    CONFLICT_CONFIDENCE: "result confidence diverges between agents",
    CONFLICT_CONTEXT: "observed context diverges between agents",
    CONFLICT_HYPOTHESIS: "hypotheses indicate conflicting research "
                         "directions",
    CONFLICT_EVIDENCE_STATE: "evidence planning state diverges between "
                             "agents",
    CONFLICT_GOVERNANCE: "governance reference state diverges between "
                         "agents",
    CONFLICT_PROVENANCE: "provenance completeness diverges between agents",
}

_CONFLICT_ORDER: dict[str, int] = {
    conflict_type: index
    for index, conflict_type in enumerate(CONFLICT_TYPES)
}


def _agent_label(result: dict, index: int) -> str:
    agent_id = result.get("agent_id") or ""
    return agent_id or f"specialist_results[{index}]"


def _claim_text(result: dict) -> str:
    parts: list[str] = []
    for item in result.get("limitations") or ():
        parts.append(str(item))
    for hypothesis in result.get("hypotheses") or ():
        if not isinstance(hypothesis, dict):
            continue
        parts.append(str(hypothesis.get("hypothesis_type") or ""))
        parts.append(
            " ".join(
                str(signal)
                for signal in hypothesis.get("supporting_signals") or ()
            )
        )
        parts.append(
            " ".join(
                str(code)
                for code in hypothesis.get("limitations") or ()
            )
        )
    evidence = result.get("evidence_plan") or {}
    parts.append(
        " ".join(str(item) for item in evidence.get("limitations") or ())
    )
    return " ".join(parts).upper()


def _has_claim(result: dict, tokens: tuple) -> bool:
    text = _claim_text(result)
    return any(token in text for token in tokens)


def _known_context(result: dict) -> dict:
    context = result.get("context_analysis") or {}
    known: dict = {}
    for key, value in context.items():
        if key in ("rule_version", "research_only"):
            continue
        if isinstance(value, str) and value.strip().upper() == "UNKNOWN":
            continue
        if value in ("", None):
            continue
        known[key] = value
    return known


def _confidence_band(value: object) -> int:
    text = str(value or "UNKNOWN").strip().upper()
    if text not in CONFIDENCE_LEVELS and text not in CONFIDENCE_BANDS:
        return 0
    return CONFIDENCE_BANDS.get(text, 0)


def _context_fact_count(result: dict) -> int:
    return len(_known_context(result))


def _record(
    conflict_type: str,
    subjects: list[str],
    fields: list[str],
    resolution: str,
    references: list[str],
) -> dict:
    basis = "|".join(
        [
            COLLABORATION_CONFLICT_RULE_VERSION,
            conflict_type,
            " ".join(subjects),
            " ".join(fields),
        ]
    )
    conflict_id = CONFLICT_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]
    plan = CollaborationConflictRecordPlan(
        rule_version=COLLABORATION_CONFLICT_RULE_VERSION,
        conflict_id=conflict_id,
        conflict_type=conflict_type,
        subjects=subjects,
        conflicting_fields=fields,
        resolution_state=resolution,
        message=_CONFLICT_MESSAGES.get(conflict_type, ""),
        evidence_references=references,
    )
    return collaboration_conflict_record_plan_projection(plan)


def _safety_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    labels = [
        _agent_label(result, index)
        for index, result in enumerate(results)
    ]
    unsafe = [
        labels[index]
        for index, result in enumerate(results)
        if not result.get("research_only", True)
    ]
    if unsafe and len(unsafe) != len(results):
        records.append(
            _record(
                CONFLICT_SAFETY, unsafe, ["research_only"],
                "UNRESOLVED", ["research_only"],
            )
        )
    claimed = [
        labels[index]
        for index, result in enumerate(results)
        if _has_claim(result, EXECUTION_CLAIM_TOKENS)
        or _has_claim(result, CONFIRMATION_CLAIM_TOKENS)
    ]
    if claimed:
        records.append(
            _record(
                CONFLICT_SAFETY, claimed, ["limitations"],
                "UNRESOLVED", ["limitations"],
            )
        )
    return records


def _confidence_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            first_confidence = results[first].get("result_confidence")
            second_confidence = results[second].get("result_confidence")
            distance = abs(
                _confidence_band(first_confidence)
                - _confidence_band(second_confidence)
            )
            if distance < 2:
                continue
            first_facts = _context_fact_count(results[first])
            second_facts = _context_fact_count(results[second])
            if {first_facts >= 5, second_facts >= 5} == {True, False}:
                resolution = "RECONCILABLE"
            elif (
                first_confidence == "UNKNOWN"
                or second_confidence == "UNKNOWN"
                or (first_facts < 2 and second_facts < 2)
            ):
                resolution = "UNKNOWN"
            else:
                resolution = "UNRESOLVED"
            records.append(
                _record(
                    CONFLICT_CONFIDENCE,
                    [
                        _agent_label(results[first], first),
                        _agent_label(results[second], second),
                    ],
                    ["result_confidence"],
                    resolution,
                    [
                        f"specialist_results[{first}]",
                        f"specialist_results[{second}]",
                    ],
                )
            )
    return records


def _context_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            if (
                results[first].get("agent_category")
                != results[second].get("agent_category")
            ):
                continue
            first_context = _known_context(results[first])
            second_context = _known_context(results[second])
            conflicting = sorted(
                key
                for key in first_context
                if key in second_context
                and first_context[key] != second_context[key]
            )
            one_sided = sorted(
                key
                for key in set(first_context) ^ set(second_context)
            )
            if conflicting:
                resolution = "UNRESOLVED"
            elif len(one_sided) >= 3:
                resolution = "RECONCILABLE"
            else:
                continue
            fields = conflicting or one_sided
            records.append(
                _record(
                    CONFLICT_CONTEXT,
                    [
                        _agent_label(results[first], first),
                        _agent_label(results[second], second),
                    ],
                    fields,
                    resolution,
                    [
                        f"specialist_results[{first}].context_analysis",
                        f"specialist_results[{second}].context_analysis",
                    ],
                )
            )
    return records


def _hypothesis_conflicts(
    groups: object,
    results: list[dict],
) -> list[dict]:
    records: list[dict] = []
    if not isinstance(groups, (list, tuple)):
        return records
    for group in groups:
        if not isinstance(group, dict):
            continue
        summary = group.get("confidence_summary") or {}
        confidence_state = summary.get("confidence_state")
        correlation_type = group.get("correlation_type")
        if (
            correlation_type != CORRELATION_CONFLICTING
            and confidence_state != GROUP_CONFIDENCE_CONFLICT
        ):
            continue
        subjects = [
            str(item)
            for item in group.get("participating_agents") or ()
            if str(item)
        ]
        if not subjects:
            subjects = [str(group.get("correlation_id") or "")]
        if confidence_state == GROUP_CONFIDENCE_CONFLICT:
            resolution = "UNRESOLVED"
        elif confidence_state == "DIVERGENT":
            resolution = "RECONCILABLE"
        else:
            resolution = "UNKNOWN"
        fields = ["hypothesis_type", "supporting_signals", "confidence"]
        records.append(
            _record(
                CONFLICT_HYPOTHESIS,
                subjects,
                fields,
                resolution,
                [str(group.get("correlation_id") or "")],
            )
        )
    return records


def _evidence_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            first_state = (
                results[first].get("evidence_plan") or {}
            ).get("evidence_state")
            second_state = (
                results[second].get("evidence_plan") or {}
            ).get("evidence_state")
            distance = abs(
                EVIDENCE_BANDS.get(str(first_state).upper(), 0)
                - EVIDENCE_BANDS.get(str(second_state).upper(), 0)
            )
            if distance < 2:
                continue
            first_items = (
                results[first].get("evidence_plan") or {}
            ).get("evidence_items") or []
            second_items = (
                results[second].get("evidence_plan") or {}
            ).get("evidence_items") or []
            if first_items and second_items:
                resolution = "RECONCILABLE"
            elif not first_items and not second_items:
                resolution = "UNKNOWN"
            else:
                resolution = "UNRESOLVED"
            records.append(
                _record(
                    CONFLICT_EVIDENCE_STATE,
                    [
                        _agent_label(results[first], first),
                        _agent_label(results[second], second),
                    ],
                    ["evidence_state"],
                    resolution,
                    [
                        f"specialist_results[{first}].evidence_plan",
                        f"specialist_results[{second}].evidence_plan",
                    ],
                )
            )
    return records


def _governance_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            first_gov = results[first].get("governance_reference") or {}
            second_gov = results[second].get("governance_reference") or {}
            first_state = str(
                first_gov.get("reference_state") or "UNKNOWN"
            ).upper()
            second_state = str(
                second_gov.get("reference_state") or "UNKNOWN"
            ).upper()
            if first_state == second_state:
                continue
            referenced = (
                first_gov
                if first_state == "REFERENCED"
                else (second_gov if second_state == "REFERENCED" else None)
            )
            unknown_present = "UNKNOWN" in (first_state, second_state)
            if referenced is not None and unknown_present:
                resolution = (
                    "RECONCILABLE"
                    if str(referenced.get("rule_version") or "") == "r37-5"
                    else "UNRESOLVED"
                )
            elif referenced is not None:
                resolution = "UNRESOLVED"
            else:
                resolution = "UNKNOWN"
            records.append(
                _record(
                    CONFLICT_GOVERNANCE,
                    [
                        _agent_label(results[first], first),
                        _agent_label(results[second], second),
                    ],
                    ["reference_state"],
                    resolution,
                    [
                        f"specialist_results[{first}].governance_reference",
                        f"specialist_results[{second}].governance_reference",
                    ],
                )
            )
    return records


def _provenance_conflicts(results: list[dict]) -> list[dict]:
    records: list[dict] = []
    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            first_state = str(
                (results[first].get("provenance") or {}).get(
                    "provenance_state"
                )
                or "UNKNOWN"
            ).upper()
            second_state = str(
                (results[second].get("provenance") or {}).get(
                    "provenance_state"
                )
                or "UNKNOWN"
            ).upper()
            first_band = PROVENANCE_BANDS.get(first_state, 0)
            second_band = PROVENANCE_BANDS.get(second_state, 0)
            if abs(first_band - second_band) < 1:
                continue
            if {first_band >= 2, second_band >= 2} == {True, False}:
                resolution = "RECONCILABLE"
            elif first_band >= 1 and second_band >= 1:
                resolution = "RECONCILABLE"
            elif first_band == 0 or second_band == 0:
                resolution = "UNKNOWN"
            else:
                resolution = "UNRESOLVED"
            records.append(
                _record(
                    CONFLICT_PROVENANCE,
                    [
                        _agent_label(results[first], first),
                        _agent_label(results[second], second),
                    ],
                    ["provenance_state"],
                    resolution,
                    [
                        f"specialist_results[{first}].provenance",
                        f"specialist_results[{second}].provenance",
                    ],
                )
            )
    return records


def analyze_collaboration_conflicts(
    value: object = None,
    hypothesis_groups: object = None,
) -> list[dict]:
    """Detect deterministic collaboration conflicts (read-only).

    If ``hypothesis_groups`` is omitted, the correlator is run to derive
    them. Both sides of every conflict are preserved through subject labels
    and evidence references; nothing is deleted.
    """

    collaboration = sanitize_multi_agent_collaboration_input(value)
    results = [
        result
        for result in collaboration.get("specialist_results") or ()
        if isinstance(result, dict)
    ]

    groups = hypothesis_groups
    if groups is None:
        from ai.knowledge.hypothesis_correlator import (
            correlate_hypotheses,
        )

        groups = correlate_hypotheses(collaboration)

    records: list[dict] = []
    records.extend(_safety_conflicts(results))
    records.extend(_confidence_conflicts(results))
    records.extend(_context_conflicts(results))
    records.extend(_hypothesis_conflicts(groups, results))
    records.extend(_evidence_conflicts(results))
    records.extend(_governance_conflicts(results))
    records.extend(_provenance_conflicts(results))

    deduped: dict[tuple, dict] = {}
    for record in records:
        key = (
            record["conflict_type"],
            tuple(record["subjects"]),
            tuple(record["conflicting_fields"]),
        )
        deduped.setdefault(key, record)
    ordered = sorted(
        deduped.values(),
        key=lambda item: (
            _CONFLICT_ORDER.get(item["conflict_type"], 99),
            tuple(item["subjects"]),
            tuple(item["conflicting_fields"]),
        ),
    )
    return ordered


__all__ = [
    "COLLABORATION_CONFLICT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "EXECUTION_CLAIM_TOKENS",
    "CONFIRMATION_CLAIM_TOKENS",
    "analyze_collaboration_conflicts",
]

"""Stage R43.3 deterministic hypothesis correlator (pure engine).

Correlates hypotheses contributed by collaborating specialist agents:

    "How do these hypotheses relate: duplicate, related, independent or
     conflicting?"

Hard boundaries encoded here:

- Collaboration only: correlation uses structured attributes only
  (agent category, hypothesis type, supporting signals, normalized subject
  reference). No semantic/LLM similarity and no invented relations.
- Different vulnerability classes may be RELATED without being DUPLICATE.
- Duplicates are grouped, never deleted; every original hypothesis remains
  referenced with full attribution and a deterministic fingerprint.
- Deterministic: fingerprints and groups are pure functions of normalized
  structured data; no timestamps, randomness or runtime ids.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib

from ai.schemas.hypothesis_correlation import (
    CONFIDENCE_AGREE,
    CONFIDENCE_BANDS,
    CONFIDENCE_CONFLICT,
    CONFIDENCE_DIVERGENT,
    CONFIDENCE_UNKNOWN,
    CORRELATION_CONFLICTING,
    CORRELATION_DUPLICATE,
    CORRELATION_ID_PREFIX,
    CORRELATION_INDEPENDENT,
    CORRELATION_RELATED,
    CORRELATION_UNKNOWN,
    HYPOTHESIS_CORRELATION_RULE_VERSION,
    HypothesisGroupPlan,
    HypothesisReferencePlan,
    hypothesis_group_plan_projection,
    hypothesis_reference_plan_projection,
)
from ai.schemas.multi_agent_collaboration_input import (
    sanitize_multi_agent_collaboration_input,
)

HYPOTHESIS_CORRELATOR_RULE_VERSION = "r43-3"
RULE_VERSION = HYPOTHESIS_CORRELATOR_RULE_VERSION

FINGERPRINT_PREFIX = "fp-"
UNKNOWN_TYPE = "UNKNOWN"

_TYPE_PRECEDENCE: dict[str, int] = {
    CORRELATION_CONFLICTING: 4,
    CORRELATION_DUPLICATE: 3,
    CORRELATION_RELATED: 2,
    CORRELATION_INDEPENDENT: 1,
    CORRELATION_UNKNOWN: 0,
}


def _hypothesis_fingerprint(
    agent_category: str,
    hypothesis_type: str,
    signals: object,
    subject_reference: str,
) -> str:
    basis = "|".join(
        [
            agent_category or "UNKNOWN",
            hypothesis_type or UNKNOWN_TYPE,
            " ".join(sorted(str(item) for item in (signals or ()))),
            subject_reference or "",
        ]
    )
    return FINGERPRINT_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def hypothesis_fingerprint(
    agent_category: object = None,
    hypothesis_type: object = None,
    signals: object = None,
    subject_reference: object = None,
) -> str:
    """Public deterministic fingerprint over normalized structured data."""

    category = str(agent_category or "UNKNOWN").strip().upper()
    htype = str(hypothesis_type or UNKNOWN_TYPE).strip().upper()
    subject = str(subject_reference or "").strip()
    bounded_signals = []
    for item in signals or ():
        text = str(item or "").strip().upper()
        if text and text not in bounded_signals:
            bounded_signals.append(text)
    return _hypothesis_fingerprint(
        category, htype, bounded_signals, subject
    )


def _references(value: object) -> list[dict]:
    collaboration = sanitize_multi_agent_collaboration_input(value)
    references: list[dict] = []
    for result in collaboration.get("specialist_results") or ():
        agent_id = result.get("agent_id") or ""
        agent_category = result.get("agent_category") or "UNKNOWN"
        for index, hypothesis in enumerate(result.get("hypotheses") or ()):
            if not isinstance(hypothesis, dict):
                continue
            signals = [
                str(item).strip().upper()
                for item in hypothesis.get("supporting_signals") or ()
                if str(item).strip()
            ]
            subject = str(
                hypothesis.get("subject_reference") or ""
            ).strip()
            payload = {
                "rule_version": HYPOTHESIS_CORRELATION_RULE_VERSION,
                "agent_id": agent_id,
                "agent_category": agent_category,
                "agent_rule_version": result.get("agent_rule_version") or "",
                "result_rule_version": (
                    result.get("result_rule_version") or ""
                ),
                "hypothesis_index": index,
                "hypothesis_type": hypothesis.get("hypothesis_type")
                or UNKNOWN_TYPE,
                "supporting_signals": signals,
                "confidence": hypothesis.get("confidence") or "UNKNOWN",
                "priority": hypothesis.get("priority") or "UNKNOWN",
                "limitations": hypothesis.get("limitations") or [],
                "subject_reference": subject,
                "fingerprint": _hypothesis_fingerprint(
                    agent_category,
                    hypothesis.get("hypothesis_type") or UNKNOWN_TYPE,
                    signals,
                    subject,
                ),
            }
            references.append(payload)
    return [
        hypothesis_reference_plan_projection(
            HypothesisReferencePlan(**item)
        )
        for item in references
    ]


def _relation(first: dict, second: dict) -> str:
    first_signals = set(first["supporting_signals"])
    second_signals = set(second["supporting_signals"])
    same_category = (
        first["agent_category"] == second["agent_category"]
    )
    same_type = first["hypothesis_type"] == second["hypothesis_type"]
    same_subject = (
        first["subject_reference"] == second["subject_reference"]
    )

    if (
        first["hypothesis_type"] == UNKNOWN_TYPE
        or second["hypothesis_type"] == UNKNOWN_TYPE
    ):
        if (
            same_category
            and same_type
            and first_signals == second_signals
            and same_subject
        ):
            return CORRELATION_DUPLICATE
        return CORRELATION_UNKNOWN

    if same_category and same_type:
        if first_signals == second_signals:
            if same_subject:
                return CORRELATION_DUPLICATE
            return CORRELATION_RELATED
        if first_signals and second_signals:
            if first_signals < second_signals or (
                second_signals < first_signals
            ):
                return CORRELATION_RELATED
            if first_signals & second_signals:
                return CORRELATION_CONFLICTING
            return CORRELATION_INDEPENDENT
        return CORRELATION_INDEPENDENT

    if first_signals & second_signals:
        return CORRELATION_RELATED
    if same_type and same_subject:
        return CORRELATION_RELATED
    if same_type:
        return CORRELATION_RELATED
    if not first_signals and not second_signals:
        return CORRELATION_UNKNOWN
    return CORRELATION_INDEPENDENT


def _confidence_state(references: list[dict]) -> tuple[str, str, str]:
    confidences = [item["confidence"] for item in references]
    known = [
        value for value in confidences
        if value in CONFIDENCE_BANDS and value != "UNKNOWN"
    ]
    banded = [CONFIDENCE_BANDS.get(value, 0) for value in confidences]
    highest = max(confidences, key=lambda v: CONFIDENCE_BANDS.get(v, 0))
    lowest = min(confidences, key=lambda v: CONFIDENCE_BANDS.get(v, 0))
    if not known:
        return "UNKNOWN", "UNKNOWN", CONFIDENCE_UNKNOWN
    if len(known) != len(confidences):
        return highest, lowest, CONFIDENCE_DIVERGENT
    if max(banded) - min(banded) >= 2:
        return highest, lowest, CONFIDENCE_CONFLICT
    if max(banded) == min(banded):
        return highest, lowest, CONFIDENCE_AGREE
    return highest, lowest, CONFIDENCE_DIVERGENT


def _correlation_id(members: list[dict], correlation_type: str) -> str:
    basis = "|".join(
        sorted(
            "{}#{}#{}".format(
                item["agent_id"],
                item["hypothesis_index"],
                item["fingerprint"],
            )
            for item in members
        )
    )
    basis = f"{HYPOTHESIS_CORRELATION_RULE_VERSION}|" \
            f"{correlation_type}|{basis}"
    return CORRELATION_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def correlate_hypotheses(value: object = None) -> list[dict]:
    """Correlate contributed hypotheses into deterministic groups.

    Duplicate and related hypotheses are grouped (never deleted), conflicting
    hypotheses are grouped and flagged, independent hypotheses remain in
    single-member groups, and unclassifiable pairs remain UNKNOWN. The same
    input always produces the same groups.
    """

    references = _references(value)
    if not references:
        return []

    parent = list(range(len(references)))
    pair_relations: dict[tuple, str] = {}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        root_first = find(first)
        root_second = find(second)
        if root_first != root_second:
            parent[max(root_first, root_second)] = min(
                root_first, root_second
            )

    for first in range(len(references)):
        for second in range(first + 1, len(references)):
            relation = _relation(references[first], references[second])
            pair_relations[(first, second)] = relation
            if relation in (CORRELATION_DUPLICATE, CORRELATION_CONFLICTING):
                union(first, second)

    # RELATED pairs merge only while both sides are still singleton clusters;
    # this keeps duplicate/conflict groups precise and prevents one generic
    # signal from chaining unrelated specialists into one giant group.
    for first in range(len(references)):
        for second in range(first + 1, len(references)):
            if pair_relations[(first, second)] != CORRELATION_RELATED:
                continue
            first_root = find(first)
            second_root = find(second)
            if first_root == second_root:
                continue
            first_size = sum(
                1 for index in range(len(references))
                if find(index) == first_root
            )
            second_size = sum(
                1 for index in range(len(references))
                if find(index) == second_root
            )
            if first_size == 1 and second_size == 1:
                union(first, second)

    clusters: dict[int, list[int]] = {}
    for index in range(len(references)):
        clusters.setdefault(find(index), []).append(index)

    groups: list[dict] = []
    for root in sorted(clusters, key=lambda item: clusters[item][0]):
        member_indexes = clusters[root]
        members = [references[index] for index in member_indexes]
        if len(member_indexes) == 1:
            correlation_type = CORRELATION_INDEPENDENT
        else:
            relations = [
                pair_relations[(first, second)]
                for first in member_indexes
                for second in member_indexes
                if first < second
            ]
            correlation_type = max(
                relations, key=lambda item: _TYPE_PRECEDENCE.get(item, 0)
            )

        signal_lists = [item["supporting_signals"] for item in members]
        shared: list[str] = []
        if signal_lists:
            for signal in signal_lists[0]:
                if all(signal in signals for signals in signal_lists[1:]):
                    shared.append(signal)

        highest, lowest, confidence_state = _confidence_state(members)
        participating: list[str] = []
        for member in members:
            if member["agent_id"] and member["agent_id"] not in participating:
                participating.append(member["agent_id"])

        group = HypothesisGroupPlan(
            rule_version=HYPOTHESIS_CORRELATION_RULE_VERSION,
            correlation_id=_correlation_id(members, correlation_type),
            correlation_type=correlation_type,
            hypothesis_references=members,
            participating_agents=participating,
            shared_signals=shared,
            confidence_summary={
                "highest_confidence": highest,
                "lowest_confidence": lowest,
                "confidence_state": confidence_state,
            },
            member_count=len(members),
        )
        groups.append(hypothesis_group_plan_projection(group))
    return groups


__all__ = [
    "HYPOTHESIS_CORRELATOR_RULE_VERSION",
    "RULE_VERSION",
    "FINGERPRINT_PREFIX",
    "hypothesis_fingerprint",
    "correlate_hypotheses",
]

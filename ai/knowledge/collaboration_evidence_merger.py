"""Stage R43.4 deterministic collaboration evidence merger (pure engine).

Merges evidence requirements contributed by collaborating specialists:

    "Which evidence categories do the collaborating agents require?"

Hard boundaries encoded here:

- Evidence coordination only: requirements are merged and attributed; no
  evidence is collected. No network, no database, no browser, no payloads,
  no scanning.
- Equivalence-based deduplication: items merge only on the exact normalized
  evidence category; source agents and hypothesis attribution are preserved.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.collaboration_evidence import (
    COLLABORATION_EVIDENCE_RULE_VERSION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_DATABASE_ACCESS,
    LIMITATION_NO_NETWORK_REQUESTS,
    REQUIREMENT_REQUIRED,
    CollaborationEvidenceItemPlan,
    CollaborationEvidencePlan,
    collaboration_evidence_item_plan_projection,
    collaboration_evidence_plan_projection,
)
from ai.schemas.multi_agent_collaboration_input import (
    sanitize_multi_agent_collaboration_input,
)

COLLABORATION_EVIDENCE_MERGER_RULE_VERSION = "r43-4"
RULE_VERSION = COLLABORATION_EVIDENCE_MERGER_RULE_VERSION

_UNKNOWN_ITEM = "UNKNOWN"
_UNKNOWN_TYPE = "UNKNOWN"


def _hypothesis_references(result: dict) -> list[dict]:
    references: list[dict] = []
    for index, hypothesis in enumerate(result.get("hypotheses") or ()):
        if not isinstance(hypothesis, dict):
            continue
        hypothesis_type = str(
            hypothesis.get("hypothesis_type") or _UNKNOWN_TYPE
        ).strip().upper()
        if not hypothesis_type or hypothesis_type == _UNKNOWN_TYPE:
            continue
        references.append(
            {
                "agent_id": result.get("agent_id") or "",
                "hypothesis_index": index,
                "hypothesis_type": hypothesis_type,
            }
        )
    return references


def merge_collaboration_evidence(value: object = None) -> dict:
    """Merge evidence requirements into a deterministic attributed plan.

    Items merge only when their normalized evidence category is exactly
    equivalent. Referenced hypotheses come from the same source agent and
    are attributed; no item-level mapping is invented beyond the supplied
    structured data.
    """

    collaboration = sanitize_multi_agent_collaboration_input(value)
    merged: dict[str, dict] = {}
    source_total = 0
    source_complete = 0
    source_confidence: list[str] = []

    for result in collaboration.get("specialist_results") or ():
        evidence = result.get("evidence_plan") or {}
        items = [
            str(item).strip().upper()
            for item in evidence.get("evidence_items") or ()
            if str(item).strip()
        ]
        state = str(
            evidence.get("evidence_state") or "UNKNOWN"
        ).strip().upper()
        source_confidence.append(
            str(evidence.get("confidence") or "UNKNOWN").strip().upper()
        )
        source_total += 1
        if state == "COMPLETE":
            source_complete += 1
        agent_id = result.get("agent_id") or ""
        references = _hypothesis_references(result)
        for item in items:
            if item == _UNKNOWN_ITEM:
                continue
            entry = merged.get(item)
            if entry is None:
                entry = {
                    "rule_version": COLLABORATION_EVIDENCE_RULE_VERSION,
                    "evidence_category": item,
                    "requirement_state": (
                        REQUIREMENT_REQUIRED
                        if state in ("COMPLETE", "PARTIAL")
                        else "CONSIDERED"
                    ),
                    "source_agents": [],
                    "hypothesis_references": [],
                    "source_count": 0,
                }
                merged[item] = entry
            if agent_id and agent_id not in entry["source_agents"]:
                entry["source_agents"].append(agent_id)
            for reference in references:
                if reference not in entry["hypothesis_references"]:
                    entry["hypothesis_references"].append(reference)
            if state in ("COMPLETE", "PARTIAL"):
                entry["requirement_state"] = REQUIREMENT_REQUIRED
            entry["source_count"] = len(entry["source_agents"])

    items: list[dict] = []
    for entry in merged.values():
        items.append(
            collaboration_evidence_item_plan_projection(
                CollaborationEvidenceItemPlan(**entry)
            )
        )

    if not items:
        state = "UNKNOWN"
    elif source_total and source_complete == source_total:
        state = "COMPLETE"
    else:
        state = "PARTIAL"

    if state == "UNKNOWN":
        confidence = "UNKNOWN"
    elif state == "COMPLETE":
        confidence = (
            "HIGH" if "HIGH" in source_confidence else "MEDIUM"
        )
    else:
        confidence = (
            "UNKNOWN"
            if all(value == "UNKNOWN" for value in source_confidence)
            else "LOW"
        )

    limitations = [
        LIMITATION_NO_COLLECTION_PERFORMED,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_DATABASE_ACCESS,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if state == "UNKNOWN":
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = CollaborationEvidencePlan(
        rule_version=COLLABORATION_EVIDENCE_RULE_VERSION,
        evidence_items=items,
        evidence_state=state,
        confidence=confidence,
        limitations=limitations,
        research_only=True,
    )
    return collaboration_evidence_plan_projection(plan)


__all__ = [
    "COLLABORATION_EVIDENCE_MERGER_RULE_VERSION",
    "RULE_VERSION",
    "merge_collaboration_evidence",
]

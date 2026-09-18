"""Stage R99 — case-to-finding evidence packaging (pure projection).

Packages the already-authoritative research state of one R76 case into a
bounded, deterministic, human-reviewable evidence package:

- case identity / status / stopping reason (R76),
- per-hypothesis evidence binding with the R70 evidence state (direct vs
  structural/derived), supporting, contradicting and invalidated references
  from the R75 provenance records,
- decision/readiness (R72), missing evidence, acquisition state (R91),
  human-review state (R77), bounded limitations,
- the unchanged safety block and explicit non-claims.

The projection copies authoritative values; it never re-derives
classifications, never fabricates evidence, never persists anything and
never claims a confirmed vulnerability. Categories remain closed
(`evidence_state`, `effect`, `relation_to_previous`, `provenance_state`,
case statuses and readiness states are used as received).
"""

from __future__ import annotations

from typing import Mapping

from ai.knowledge.research_feedback_loop import (
    EFFECT_CONTRADICTS,
    EFFECT_INVALIDATES,
    EFFECT_PROVIDES,
)
from ai.knowledge.research_outcome_planner import SAFETY_BLOCK

RULE_VERSION = "r99-1"

PACKAGE_TYPE = "RESEARCH_EVIDENCE_PACKAGE"

MAX_HYPOTHESES = 8
MAX_EVIDENCE_PER_HYPOTHESIS = 6
MAX_PROVENANCE_RECORDS = 32
MAX_LIMITATIONS = 8
MAX_TEXT_CHARS = 320
MAX_REF_CHARS = 512

ERROR_MALFORMED_CASE = "MALFORMED_CASE"
ERROR_MALFORMED_ACTION_PLAN = "MALFORMED_ACTION_PLAN"
ERROR_MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"

EVIDENCE_PACKAGE_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_ACTION_PLAN,
    ERROR_MALFORMED_PROVENANCE,
)

#: Relation values that indicate contradicting / invalidating evidence
#: (R75 vocabulary, copied as received).
CONTRADICTING_RELATIONS: tuple[str, ...] = (
    "CONTRADICTS_EXISTING",
    "INVALIDATES_EXISTING",
)

NON_CLAIMS: tuple[str, ...] = (
    "not a confirmed vulnerability: confirmation_state is NOT_CONFIRMED",
    "no execution, exploitation, scanning or target validation was performed",
    "technology, version or CVE matches are structural evidence, not "
    "behavioral proof",
    "absence of evidence does not prove that a vulnerability does not exist",
    "exhausted sources or missing evidence are not a disproval",
    "human authority is required before any security conclusion",
)


class EvidencePackageError(ValueError):
    """Deterministic, secret-free R99 package failure (fail closed)."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        super().__init__(safe_message or code)
        self.code = code
        self.safe_message = safe_message


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _upper(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return _text(value, limit).upper()


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_list(value: object, limit: int, width: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, width)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _refs(value: object) -> list[str]:
    return _bounded_list(value, MAX_EVIDENCE_PER_HYPOTHESIS, MAX_REF_CHARS)


def _outcome_by_ref(action_plan: Mapping) -> dict[str, Mapping]:
    out: dict[str, Mapping] = {}
    for outcome in _mapping_items(action_plan.get("outcomes")):
        ref = _text(outcome.get("hypothesis_ref"), 16)
        if ref and ref not in out:
            out[ref] = outcome
    return out


def _provenance_records(provenance: Mapping) -> list[Mapping]:
    return _mapping_items(provenance.get("records"))[:MAX_PROVENANCE_RECORDS]


def _record_refs(record: Mapping) -> list[str]:
    refs = _refs(record.get("evidence_refs"))
    if not refs:
        refs = _refs([record.get("evidence_ref")])
    return refs


def _provenance_item(record: Mapping) -> dict:
    return {
        "provenance_ref": _text(record.get("provenance_id"), 16),
        "evidence_id": _text(record.get("evidence_id"), 16),
        "requirement_kind": _upper(record.get("requirement_kind"), 64),
        "effect": _upper(record.get("effect"), 32),
        "relation_to_previous": _upper(
            record.get("relation_to_previous"), 40
        ),
        "provenance_state": _upper(record.get("provenance_state"), 32),
        "conflict_state": _upper(record.get("conflict_state"), 32),
        "human_review_required": bool(record.get("human_review_required")),
        "evidence_refs": _record_refs(record),
    }


def _split_provenance(
    records: list[Mapping],
) -> tuple[list[dict], list[dict], list[dict]]:
    supporting: list[dict] = []
    contradicting: list[dict] = []
    invalidated: list[dict] = []
    for record in records:
        item = _provenance_item(record)
        effect = item["effect"]
        relation = item["relation_to_previous"]
        if effect == EFFECT_INVALIDATES or relation == "INVALIDATES_EXISTING":
            invalidated.append(item)
        elif effect == EFFECT_CONTRADICTS or relation in CONTRADICTING_RELATIONS:
            contradicting.append(item)
        elif effect == EFFECT_PROVIDES:
            supporting.append(item)
        # Anything else (unknown effect) is intentionally omitted rather than
        # guessed; the closed R75 vocabulary only emits the values above.
    return supporting, contradicting, invalidated


def _decision(block: Mapping) -> dict:
    readiness = _block(block.get("readiness"))
    evidence = _block(block.get("evidence"))
    return {
        "sufficiency_state": _upper(readiness.get("sufficiency_state"), 40),
        "decision_state": _upper(readiness.get("decision_state"), 40),
        "blocking_codes": _bounded_list(readiness.get("blocking_codes"), 8, 64),
        "decision_basis": _upper(
            _block(readiness.get("decision_basis")).get("code"), 64
        ),
        "available_count": int(evidence.get("available_count") or 0),
        "missing_count": int(evidence.get("missing_count") or 0),
        "decision_missing_count": int(
            evidence.get("decision_missing_count") or 0
        ),
        "available_requirement_kinds": _bounded_list(
            evidence.get("available_requirement_kinds"), 8, 64
        ),
        "missing_requirement_kinds": _bounded_list(
            evidence.get("missing_requirement_kinds"), 8, 64
        ),
    }


def _hypotheses(
    block: Mapping,
    action_plan: Mapping,
    records: list[Mapping],
) -> list[dict]:
    outcomes = _outcome_by_ref(action_plan)
    by_ref: dict[str, list[Mapping]] = {}
    for record in records:
        ref = _text(record.get("hypothesis_ref"), 16)
        if ref:
            by_ref.setdefault(ref, []).append(record)

    items: list[dict] = []
    for ref in _bounded_list(block.get("hypothesis_refs"), MAX_HYPOTHESES, 16):
        outcome = outcomes.get(ref, {})
        current = _block(outcome.get("current_evidence"))
        supporting, contradicting, invalidated = _split_provenance(
            by_ref.get(ref, [])
        )
        items.append(
            {
                "hypothesis_ref": ref,
                "title": _text(outcome.get("title")),
                "category": _upper(outcome.get("category"), 32),
                "priority": _upper(outcome.get("priority"), 16),
                "confidence": _upper(outcome.get("confidence"), 16),
                "evidence_state": _upper(outcome.get("evidence_state"), 32),
                "detail_state": (
                    "AVAILABLE" if outcome else "UNAVAILABLE"
                ),
                "selected_evidence_refs": _refs(
                    current.get("selected_evidence_refs")
                ),
                "missing_evidence": _bounded_list(
                    outcome.get("hypothesis_missing_evidence"), 8, 160
                ),
                "supporting": supporting[:MAX_EVIDENCE_PER_HYPOTHESIS],
                "contradicting": contradicting[:MAX_EVIDENCE_PER_HYPOTHESIS],
                "invalidated": invalidated[:MAX_EVIDENCE_PER_HYPOTHESIS],
            }
        )
    return items


def _provenance_summary(provenance: Mapping) -> dict | None:
    if not provenance:
        return None
    summary = _block(provenance.get("summary"))
    if not summary:
        return None
    return {
        "package_status": _upper(provenance.get("package_status"), 40),
        "record_count": int(summary.get("record_count") or 0),
        "complete_provenance": int(summary.get("complete_provenance") or 0),
        "partial_provenance": int(summary.get("partial_provenance") or 0),
        "missing_provenance": int(summary.get("missing_provenance") or 0),
        "invalid_provenance": int(summary.get("invalid_provenance") or 0),
        "conflict_count": int(summary.get("conflict_count") or 0),
        "human_review_required": bool(
            summary.get("human_review_required")
        ),
        "relation_bands": {
            _upper(key, 40): int(value or 0)
            for key, value in sorted(
                _block(summary.get("relation_bands")).items()
            )
        },
    }


def _conflicts(provenance: Mapping) -> list[dict]:
    out: list[dict] = []
    for conflict in _mapping_items(provenance.get("conflicts"))[:8]:
        requirement_kind = _upper(conflict.get("requirement_kind"), 64)
        existing = _refs(conflict.get("existing_evidence_refs"))
        new = _refs(conflict.get("new_evidence_refs"))
        if not requirement_kind and not existing and not new:
            continue
        out.append(
            {
                "requirement_kind": requirement_kind,
                "relation_to_previous": _upper(
                    conflict.get("relation_to_previous"), 40
                ),
                "existing_evidence_refs": existing,
                "new_evidence_refs": new,
            }
        )
    return out


def _acquisition(ledger: Mapping) -> dict | None:
    if not ledger:
        return None
    counts = _block(ledger.get("counts"))
    return {
        "next_action": _upper(ledger.get("next_action"), 40),
        "offline_sources_exhausted": bool(
            ledger.get("offline_sources_exhausted")
        ),
        "human_action_required": bool(ledger.get("human_action_required")),
        "counts": {
            _upper(key, 40): int(value or 0)
            for key, value in sorted(counts.items())
            if isinstance(value, (int, float))
        },
    }


def build_case_evidence_package(
    case: object,
    *,
    action_plan: object = None,
    evidence_provenance: object = None,
    limitations: object = None,
    acquisition_ledger: object = None,
    human_review: object = None,
    source_cve: object = "",
) -> dict:
    """One bounded, deterministic human-reviewable evidence package.

    Raises :class:`EvidencePackageError` (fail closed) on malformed case or
    stage inputs. Copies authoritative values only; never fabricates
    evidence and never claims confirmation.
    """

    block = _block(case)
    case_id = _text(block.get("case_id"), 96)
    if not case_id:
        raise EvidencePackageError(ERROR_MALFORMED_CASE, "case_id is required")
    status = _upper(block.get("status"), 40)
    if not status:
        raise EvidencePackageError(
            ERROR_MALFORMED_CASE, "case status is required"
        )

    if action_plan is not None and not isinstance(action_plan, Mapping):
        raise EvidencePackageError(
            ERROR_MALFORMED_ACTION_PLAN, "action plan is not an object"
        )
    plan = _block(action_plan)

    if evidence_provenance is not None and not isinstance(
        evidence_provenance, Mapping
    ):
        raise EvidencePackageError(
            ERROR_MALFORMED_PROVENANCE, "evidence provenance is not an object"
        )
    provenance = _block(evidence_provenance)
    records = _provenance_records(provenance)

    review = _block(human_review)
    return {
        "rule_version": RULE_VERSION,
        "package_type": PACKAGE_TYPE,
        "case": {
            "case_id": case_id,
            "program": _text(block.get("program"), 64),
            "category": _upper(block.get("category"), 32),
            "gap_id": _upper(block.get("gap_id"), 64),
            "case_version": _upper(block.get("case_version"), 16),
            "status": status,
            "stopping_reason": _upper(block.get("stopping_reason"), 64),
            "cve_id": _upper(source_cve, 32),
            "hypothesis_refs": _bounded_list(
                block.get("hypothesis_refs"), MAX_HYPOTHESES, 16
            ),
            "iteration_count": int(block.get("iteration_count") or 0),
        },
        "decision": _decision(block),
        "hypotheses": _hypotheses(block, plan, records),
        "evidence_provenance": _provenance_summary(provenance),
        "conflicts": _conflicts(provenance),
        "acquisition": _acquisition(_block(acquisition_ledger)),
        "human_review": (
            {
                "required": bool(
                    review.get("required")
                    or block.get("human_review_required")
                ),
                "reasons": _bounded_list(review.get("reasons"), 4, 64),
                "case_stopping_reason": _upper(
                    review.get("case_stopping_reason")
                    or block.get("stopping_reason"),
                    64,
                ),
            }
            if review or block.get("human_review_required") is not None
            else None
        ),
        "limitations": _bounded_list(limitations, MAX_LIMITATIONS, MAX_TEXT_CHARS),
        "safety": dict(SAFETY_BLOCK),
        "non_claims": list(NON_CLAIMS),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "PACKAGE_TYPE",
    "MAX_HYPOTHESES",
    "MAX_EVIDENCE_PER_HYPOTHESIS",
    "MAX_PROVENANCE_RECORDS",
    "ERROR_MALFORMED_CASE",
    "ERROR_MALFORMED_ACTION_PLAN",
    "ERROR_MALFORMED_PROVENANCE",
    "EVIDENCE_PACKAGE_ERROR_CODES",
    "NON_CLAIMS",
    "CONTRADICTING_RELATIONS",
    "EvidencePackageError",
    "build_case_evidence_package",
]

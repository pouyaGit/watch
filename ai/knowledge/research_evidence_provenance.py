"""Stage R75 deterministic evidence provenance and conflict analysis.

R75 answers, for evidence that R74 already accepted or rejected:

    "How should Watch understand the provenance and consistency of this
     evidence, without deciding whether a vulnerability exists?"

It adds a bounded provenance + consistency layer over the existing chain:

    R74 accepted evidence -> R75 provenance/conflict analysis
      -> R73 feedback (unchanged) -> R72 readiness (unchanged)

R75 is **not** a confidence scorer, not a vulnerability verdict, not a
readiness planner, not a feedback planner, not an acquisition planner and not
a hypothesis model. It composes the existing layers:

- R74 remains the evidence intake authority: R75 consumes its result (or calls
  its public ``normalize_evidence_package`` when handed a raw package) and
  never re-validates or re-accepts evidence on its own terms.
- R73 remains the feedback authority and R72 the readiness authority; R75
  never alters their output and never decides that a hypothesis is true or
  false.
- R68 remains the evidence identity contract; R75 reuses canonical
  ``kind:value`` references and introduces no new evidence namespace.
- R70/R71 state supplies the previous evidence context (available requirement
  refs, outcome observations) used for relationship analysis.

Hard boundaries encoded here:

- No automatic conflict resolution: incompatible explicit effects produce
  ``CONFLICTING`` + ``human_review_required = true``; the conflicting
  evidence is preserved on both sides, never resolved by recency, source
  preference or wording.
- No hidden inference: relationships are computed only from structured
  fields (hypothesis, requirement, canonical refs, explicit effect,
  explicit invalidation). Wording similarity is never used.
- Not persisted: rejected evidence bodies are never copied; provenance
  records for rejected items carry only the bounded rejection code.
- Pure and offline: no I/O, no network, no HTTP client, no socket, no
  subprocess, no shell, no LLM, no Mongo, no target interaction, no
  execution, no authorization semantics.
- Deterministic: stable ``PR1``... ids, canonical ordering, no timestamps, no
  randomness; repeated runs are byte-identical and inputs are never mutated.
- Additive: every result is a new dict with rule version ``r75-1``.
"""

from __future__ import annotations

from typing import Mapping

from ai.knowledge.research_evidence_intake import (
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_DUPLICATE_EVIDENCE,
    REJECTION_EXECUTION_INSTRUCTION,
    REJECTION_INVALID_EVIDENCE_REF,
    REJECTION_INVALID_SOURCE,
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_UNKNOWN_REQUIREMENT,
    REJECTION_UNSUPPORTED_EFFECT,
    RULE_VERSION as SOURCE_INTAKE_RULE_VERSION,
    STATUS_NOT_PROVIDED,
    normalize_evidence_package,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    RULE_VERSION as SOURCE_ACQUISITION_RULE_VERSION,
    STATUS_AVAILABLE,
)
from ai.knowledge.research_decision_readiness_planner import (
    RULE_VERSION as SOURCE_READINESS_RULE_VERSION,
)
from ai.knowledge.research_feedback_loop import (
    EFFECT_CONTRADICTS,
    EFFECT_INVALIDATES,
    EFFECT_PROVIDES,
    RULE_VERSION as SOURCE_FEEDBACK_RULE_VERSION,
)
from ai.knowledge.research_outcome_planner import (
    RULE_VERSION as SOURCE_ACTION_RULE_VERSION,
    SAFETY_BLOCK,
)

RULE_VERSION = "r75-1"

MAX_RECORDS = 32
MAX_REFS = 6
MAX_CONFLICTS = 16
MAX_TEXT_CHARS = 320
MAX_REF_CHARS = 512

# ---------------------------------------------------------------------------
# Closed provenance-state vocabulary
# ---------------------------------------------------------------------------

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_MISSING = "MISSING"
PROVENANCE_INVALID = "INVALID"

PROVENANCE_STATES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_MISSING,
    PROVENANCE_INVALID,
)

# ---------------------------------------------------------------------------
# Closed relationship vocabulary
# ---------------------------------------------------------------------------

RELATION_NEW = "NEW"
RELATION_DUPLICATE = "DUPLICATE"
RELATION_SUPPORTS_EXISTING = "SUPPORTS_EXISTING"
RELATION_CONTRADICTS_EXISTING = "CONTRADICTS_EXISTING"
RELATION_INVALIDATES_EXISTING = "INVALIDATES_EXISTING"
RELATION_CONFLICTING = "CONFLICTING"
#: Only used for records derived from rejected items, where no relationship
#: can be evaluated without inspecting the rejected body.
RELATION_NONE = "NONE"

RELATIONSHIPS: tuple[str, ...] = (
    RELATION_NEW,
    RELATION_DUPLICATE,
    RELATION_SUPPORTS_EXISTING,
    RELATION_CONTRADICTS_EXISTING,
    RELATION_INVALIDATES_EXISTING,
    RELATION_CONFLICTING,
    RELATION_NONE,
)

# ---------------------------------------------------------------------------
# Closed conflict vocabulary
# ---------------------------------------------------------------------------

CONFLICT_NONE = "NONE"
CONFLICT_PRESENT = "CONFLICTING"

CONFLICT_STATES: tuple[str, ...] = (CONFLICT_NONE, CONFLICT_PRESENT)

#: Rejection codes that mean required provenance association is absent; all
#: other rejection codes are malformed/rejected provenance.
MISSING_PROVENANCE_REJECTIONS: frozenset[str] = frozenset(
    {
        REJECTION_UNKNOWN_HYPOTHESIS,
        REJECTION_UNKNOWN_REQUIREMENT,
        REJECTION_UNKNOWN_INVALIDATED_REF,
    }
)

CONFLICT_RELATIONS: frozenset[str] = frozenset(
    {RELATION_CONFLICTING, RELATION_CONTRADICTS_EXISTING}
)

PACKAGE_REJECTION_INVALID = "PACKAGE_REJECTION"


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_refs(value: object, limit: int = MAX_REFS) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item)[:MAX_REF_CHARS]
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _item_refs(item: Mapping) -> list[str]:
    """Canonical observation refs of one R74 accepted item."""

    return _bounded_refs(
        [
            _block(entry).get("ref")
            for entry in _mapping_items(item.get("observations"))
        ]
    )


def _identity(item: Mapping) -> tuple[str, tuple]:
    """Stable evidence identity: canonical refs, else bounded signals."""

    refs = _item_refs(item)
    if refs:
        return "refs", tuple(sorted(refs))
    signals = tuple(
        sorted(
            (
                _upper(entry.get("signal")),
                _text(entry.get("detail"))[:MAX_TEXT_CHARS],
            )
            for entry in _mapping_items(item.get("derived_signals"))
        )
    )
    return "signals", signals


# ---------------------------------------------------------------------------
# Previous evidence context (read-only over R70/R71 and prior provenance)
# ---------------------------------------------------------------------------


def _internal_previous_evidence(
    action_plan: object, acquisition_plan: object
) -> dict[tuple[str, str], dict]:
    """(hypothesis_ref, requirement) -> available refs from the prior state."""

    refs_by_plan: dict[str, dict[str, list[str]]] = {}
    for plan in _mapping_items(_block(acquisition_plan).get("plans")):
        plan_ref = _text(plan.get("plan_id"))
        entries: dict[str, list[str]] = {}
        for entry in _mapping_items(plan.get("required_evidence")):
            kind = _upper(entry.get("requirement_kind"))
            if not kind:
                continue
            if _upper(entry.get("status")) != STATUS_AVAILABLE:
                continue
            refs = _bounded_refs(
                [
                    _block(evidence).get("ref")
                    for evidence in _mapping_items(entry.get("evidence"))
                ]
            )
            if refs:
                entries[kind] = refs
        if plan_ref:
            refs_by_plan[plan_ref] = entries

    previous: dict[tuple[str, str], dict] = {}
    for record in _mapping_items(_block(acquisition_plan).get("plans")):
        plan_ref = _text(record.get("plan_id"))
        entries = refs_by_plan.get(plan_ref, {})
        for hypothesis_ref in record.get("hypothesis_refs") or ():
            hypothesis = _text(hypothesis_ref)
            for kind, refs in entries.items():
                previous.setdefault(
                    (hypothesis, kind), {"available_refs": [], "outcomes": []}
                )["available_refs"].extend(refs)
    outcome_refs = _outcome_refs(action_plan)
    for key, value in previous.items():
        value["outcomes"] = outcome_refs.get(key[0], [])
    return previous


def _outcome_refs(action_plan: object) -> dict[str, list[str]]:
    by_hypothesis: dict[str, list[str]] = {}
    for action in _mapping_items(_block(action_plan).get("actions")):
        hypothesis_refs = [
            _text(ref) for ref in action.get("hypothesis_refs") or ()
        ]
        outcome_refs: list[str] = []
        for outcome in _mapping_items(_block(action_plan).get("outcomes")):
            if _text(outcome.get("hypothesis_ref")) not in hypothesis_refs:
                continue
            evidence = outcome.get("current_evidence")
            if not isinstance(evidence, Mapping):
                continue
            for entry in _mapping_items(evidence.get("observations")):
                ref = _text(entry.get("ref"))[:MAX_REF_CHARS]
                if ref and ref not in outcome_refs:
                    outcome_refs.append(ref)
        for hypothesis_ref in hypothesis_refs:
            if hypothesis_ref and outcome_refs:
                by_hypothesis[hypothesis_ref] = list(outcome_refs)
    return by_hypothesis


def _previous_provenance_index(previous_provenance: object) -> dict:
    records: list[Mapping] = []
    block = _block(previous_provenance)
    raw = block.get("records")
    if raw is not None:
        records = _mapping_items(raw)
    elif isinstance(previous_provenance, (list, tuple)):
        records = _mapping_items(previous_provenance)

    index: dict[tuple[str, str], list[dict]] = {}
    signatures: set[tuple] = set()
    for record in records:
        hypothesis = _text(record.get("hypothesis_ref"))
        requirement = _upper(record.get("requirement_kind"))
        effect = _upper(record.get("effect"))
        if not hypothesis or not requirement or not effect:
            continue
        refs = _bounded_refs(
            record.get("evidence_refs") or record.get("evidence_ref")
        )
        identity = (
            ("refs", tuple(sorted(refs))) if refs else ("signals", ())
        )
        signature = (hypothesis, requirement, effect) + identity
        entry = {
            "hypothesis_ref": hypothesis,
            "requirement_kind": requirement,
            "effect": effect,
            "refs": refs,
            "provenance_id": _text(record.get("provenance_id")),
        }
        if signature not in signatures:
            signatures.add(signature)
            index.setdefault((hypothesis, requirement), []).append(entry)
    return {"by_key": index, "signatures": signatures}


# ---------------------------------------------------------------------------
# Relationship + provenance evaluation
# ---------------------------------------------------------------------------


def _relation_for(
    item: Mapping,
    index: Mapping,
    internal: Mapping,
) -> tuple[str, bool, dict]:
    """Return (relation, human_review_required, conflict_basis)."""

    hypothesis = item["hypothesis_ref"]
    requirement = item["requirement_kind"]
    effect = item["effect"]
    refs = _item_refs(item)
    identity = _identity(item)
    key = (hypothesis, requirement)
    prior_entries = index["by_key"].get(key, [])
    prior_positive = [
        entry for entry in prior_entries if entry["effect"] == EFFECT_PROVIDES
    ]
    prior_contradicting = [
        entry
        for entry in prior_entries
        if entry["effect"] == EFFECT_CONTRADICTS
    ]
    internal_entry = internal.get(key) or {}
    internal_refs = list(internal_entry.get("available_refs") or [])
    internal_refs.extend(internal_entry.get("outcomes") or [])
    internal_available = bool(internal_refs)
    known_positive_refs = sorted(
        {
            ref
            for entry in prior_positive
            for ref in entry["refs"]
        }
        | set(internal_refs)
    )

    if effect == EFFECT_INVALIDATES:
        return RELATION_INVALIDATES_EXISTING, False, {}

    if effect == EFFECT_PROVIDES:
        signature = (hypothesis, requirement, effect) + identity
        if signature in index["signatures"]:
            return RELATION_DUPLICATE, False, {}
        if refs and sorted(refs) == sorted(internal_refs):
            return RELATION_DUPLICATE, False, {}
        if prior_contradicting:
            basis = {
                "hypothesis_ref": hypothesis,
                "requirement_kind": requirement,
                "existing_evidence_refs": sorted(
                    {
                        ref
                        for entry in prior_contradicting
                        for ref in entry["refs"]
                    }
                )[:MAX_REFS],
                "new_evidence_refs": refs,
                "note": (
                    "conflict preserved for human review; no automatic "
                    "resolution"
                ),
            }
            return RELATION_CONFLICTING, True, basis
        if known_positive_refs:
            return RELATION_SUPPORTS_EXISTING, False, {}
        return RELATION_NEW, False, {}

    if effect == EFFECT_CONTRADICTS:
        signature = (hypothesis, requirement, effect) + identity
        if signature in index["signatures"]:
            return RELATION_DUPLICATE, False, {}
        if prior_contradicting and not internal_available and not prior_positive:
            return RELATION_SUPPORTS_EXISTING, False, {}
        if known_positive_refs or internal_available:
            basis = {
                "hypothesis_ref": hypothesis,
                "requirement_kind": requirement,
                "existing_evidence_refs": known_positive_refs[:MAX_REFS],
                "new_evidence_refs": refs,
                "note": (
                    "conflict preserved for human review; no automatic "
                    "resolution"
                ),
            }
            return RELATION_CONTRADICTS_EXISTING, True, basis
        return RELATION_NEW, False, {}

    return RELATION_NONE, False, {}


def _provenance_state(item: Mapping) -> str:
    refs = _item_refs(item)
    invalidates = _bounded_refs(item.get("invalidates_refs"))
    if refs or invalidates:
        return PROVENANCE_COMPLETE
    return PROVENANCE_PARTIAL


def _accepted_record(
    item: Mapping,
    index: int,
    provenance_index: Mapping,
    internal: Mapping,
) -> dict:
    relation, review, basis = _relation_for(item, provenance_index, internal)
    conflict = (
        CONFLICT_PRESENT if relation in CONFLICT_RELATIONS else CONFLICT_NONE
    )
    refs = _item_refs(item)
    if not refs and _upper(item.get("effect")) == EFFECT_INVALIDATES:
        refs = _bounded_refs(item.get("invalidates_refs"))
    return {
        "provenance_id": "",
        "evidence_id": _text(item.get("intake_id")) or f"EI{index}",
        "evidence_ref": refs[0] if refs else "",
        "evidence_refs": refs,
        "hypothesis_ref": _text(item.get("hypothesis_ref")),
        "requirement_kind": _upper(item.get("requirement_kind")),
        "source": _upper(item.get("source")),
        "effect": _upper(item.get("effect")),
        "provenance_state": _provenance_state(item),
        "relation_to_previous": relation,
        "conflict_state": conflict,
        "conflict_basis": basis,
        "human_review_required": bool(review),
        "reason": relation,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _rejected_record(entry: Mapping, index: int) -> dict:
    code = _upper(entry.get("code")) or REJECTION_MALFORMED_EVIDENCE
    if code == REJECTION_DUPLICATE_EVIDENCE:
        state = PROVENANCE_INVALID
        relation = RELATION_DUPLICATE
    elif code in MISSING_PROVENANCE_REJECTIONS:
        state = PROVENANCE_MISSING
        relation = RELATION_NONE
    else:
        state = PROVENANCE_INVALID
        relation = RELATION_NONE
    return {
        "provenance_id": "",
        "evidence_id": f"X{index}",
        "evidence_ref": "",
        "evidence_refs": [],
        "hypothesis_ref": "",
        "requirement_kind": "",
        "source": "",
        "effect": "",
        "provenance_state": state,
        "relation_to_previous": relation,
        "conflict_state": CONFLICT_NONE,
        "conflict_basis": {},
        "human_review_required": False,
        "reason": code,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def analyze_evidence_provenance(
    intake_result: object = None,
    *,
    package: object = None,
    hypotheses: object = None,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    previous_provenance: object = None,
    limit: int = MAX_RECORDS,
) -> dict:
    """Build bounded provenance records for one R74 intake result.

    ``intake_result`` is the R74 result dict; when it is absent and a raw
    ``package`` is supplied, R74's public ``normalize_evidence_package`` is
    called first so R74 stays the intake authority. The result never mutates
    its inputs and never changes R72/R73 output.
    """

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if limit < 0:
        raise ValueError("limit must be >= 0")

    intake = _block(intake_result)
    if not intake and package is not None:
        intake = normalize_evidence_package(
            package,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
    accepted = _mapping_items(intake.get("accepted_items"))
    rejections = _mapping_items(intake.get("rejections"))
    package_rejections = _mapping_items(intake.get("package_rejections"))

    previous_index = _previous_provenance_index(previous_provenance)
    internal = _internal_previous_evidence(action_plan, acquisition_plan)

    working_index = {
        "by_key": {
            key: [dict(entry) for entry in entries]
            for key, entries in previous_index["by_key"].items()
        },
        "signatures": set(previous_index["signatures"]),
    }

    records: list[dict] = []
    for index, item in enumerate(accepted, start=1):
        records.append(_accepted_record(item, index, working_index, internal))
        hypothesis = _text(item.get("hypothesis_ref"))
        requirement = _upper(item.get("requirement_kind"))
        effect = _upper(item.get("effect"))
        refs = _item_refs(item)
        if hypothesis and requirement and effect:
            identity = (
                ("refs", tuple(sorted(refs))) if refs else ("signals", ())
            )
            working_index["signatures"].add(
                (hypothesis, requirement, effect) + identity
            )
            working_index["by_key"].setdefault(
                (hypothesis, requirement), []
            ).append(
                {
                    "hypothesis_ref": hypothesis,
                    "requirement_kind": requirement,
                    "effect": effect,
                    "refs": refs,
                    "provenance_id": "",
                }
            )
    for index, entry in enumerate(rejections, start=1):
        records.append(_rejected_record(entry, index))
    for index, entry in enumerate(package_rejections, start=1):
        record = _rejected_record(entry, index)
        record["evidence_id"] = f"XP{index}"
        record["reason"] = _upper(entry.get("code")) or PACKAGE_REJECTION_INVALID
        records.append(record)

    limited = [dict(record) for record in records[:limit]]
    for position, record in enumerate(limited, start=1):
        record["provenance_id"] = f"PR{position}"

    conflicts = [
        {
            "provenance_id": record["provenance_id"],
            "hypothesis_ref": record["hypothesis_ref"],
            "requirement_kind": record["requirement_kind"],
            "relation_to_previous": record["relation_to_previous"],
            "existing_evidence_refs": (
                record["conflict_basis"].get("existing_evidence_refs") or []
            ),
            "new_evidence_refs": (
                record["conflict_basis"].get("new_evidence_refs") or []
            ),
        }
        for record in limited
        if record["conflict_state"] == CONFLICT_PRESENT
    ][:MAX_CONFLICTS]

    state_bands = {state: 0 for state in PROVENANCE_STATES}
    relation_bands = {relation: 0 for relation in RELATIONSHIPS}
    for record in limited:
        state = _upper(record.get("provenance_state"))
        if state in state_bands:
            state_bands[state] += 1
        relation = _upper(record.get("relation_to_previous"))
        if relation in relation_bands:
            relation_bands[relation] += 1

    return {
        "rule_version": RULE_VERSION,
        "source_action_rule_version": SOURCE_ACTION_RULE_VERSION,
        "source_acquisition_rule_version": SOURCE_ACQUISITION_RULE_VERSION,
        "source_readiness_rule_version": SOURCE_READINESS_RULE_VERSION,
        "source_feedback_rule_version": SOURCE_FEEDBACK_RULE_VERSION,
        "source_intake_rule_version": (
            _text(intake.get("rule_version")) or SOURCE_INTAKE_RULE_VERSION
        ),
        "package_status": _upper(intake.get("package_status"))
        or STATUS_NOT_PROVIDED,
        "records": limited,
        "conflicts": conflicts,
        "summary": {
            "rule_version": RULE_VERSION,
            "record_count": len(limited),
            "complete_provenance": state_bands[PROVENANCE_COMPLETE],
            "partial_provenance": state_bands[PROVENANCE_PARTIAL],
            "missing_provenance": state_bands[PROVENANCE_MISSING],
            "invalid_provenance": state_bands[PROVENANCE_INVALID],
            "conflict_count": len(conflicts),
            "human_review_required": any(
                record["human_review_required"] for record in limited
            ),
            "state_bands": state_bands,
            "relation_bands": relation_bands,
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "SOURCE_ACTION_RULE_VERSION",
    "SOURCE_ACQUISITION_RULE_VERSION",
    "SOURCE_READINESS_RULE_VERSION",
    "SOURCE_FEEDBACK_RULE_VERSION",
    "SOURCE_INTAKE_RULE_VERSION",
    "MAX_RECORDS",
    "MAX_REFS",
    "MAX_CONFLICTS",
    "MAX_TEXT_CHARS",
    "MAX_REF_CHARS",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_MISSING",
    "PROVENANCE_INVALID",
    "PROVENANCE_STATES",
    "RELATION_NEW",
    "RELATION_DUPLICATE",
    "RELATION_SUPPORTS_EXISTING",
    "RELATION_CONTRADICTS_EXISTING",
    "RELATION_INVALIDATES_EXISTING",
    "RELATION_CONFLICTING",
    "RELATION_NONE",
    "RELATIONSHIPS",
    "CONFLICT_NONE",
    "CONFLICT_PRESENT",
    "CONFLICT_STATES",
    "CONFLICT_RELATIONS",
    "MISSING_PROVENANCE_REJECTIONS",
    "analyze_evidence_provenance",
]

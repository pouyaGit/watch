"""Stage R72 deterministic evidence sufficiency and decision readiness (pure engine).

Consumes the validated R70 outcome/action plan and the R71 evidence
acquisition plan and derives, for every R71 plan, one bounded readiness
record:

    evidence -> hypothesis -> R70 action -> R71 acquisition plan
             -> sufficiency + decision readiness

It answers the human-researcher question:

    "Do we currently have enough evidence to make a meaningful research
     decision about this hypothesis, and if not, exactly what evidence is
     still blocking the decision?"

This is a **decision-readiness signal only, and it is plan-only**. It never
confirms a vulnerability, never generates a finding, never scores
exploitability or severity, never authorizes anything, never executes, never
contacts a target, never scans, never calls an LLM and never touches Mongo.

Architecture / reuse decision (existing concepts inspected first):

- The R31.15 chain
  (``ai/knowledge/evidence_confidence_aggregator.py`` and
  ``ai/schemas/evidence_confidence.py``) measures a *confidence level* over one
  R31.13/R31.14 Asset<->CVE plan pair with its own method/target vocabularies.
  It cannot consume R70/R71 research-layer outputs, and re-deriving R31
  confidence here would be a competing framework.
- R72 therefore composes instead: it consumes the R71 requirement statuses
  (the research-layer equivalent of acquisition completeness), mirrors the
  R31.15 conventions (closed completeness/blocker vocabularies, bounded,
  sanitized, read-only projections, fail-closed unknown handling), and reuses
  the R70 safety block, category order, evidence states and the R70/R71 rule
  versions verbatim. It computes no confidence level and no probability:
  sufficiency is a deterministic gate over R71's ``AVAILABLE``/``MISSING``
  requirement split.
- R70 remains the source of truth for outcomes, gaps and actions; R71 remains
  the source of truth for acquisition plans, sources, steps and stopping
  conditions. R72 re-derives neither.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no persistence, no execution.
- Sufficiency is never inferred from priority, confidence, skill presence,
  parameter names, endpoint names, technology names or model wording. Only
  the presence/absence of the R71-required evidence decides it.
- Fail-closed: a missing, malformed or empty upstream plan yields
  ``INSUFFICIENT`` + ``REMAINS_UNRESOLVED`` (or an empty result), never a
  silent upgrade; unknown requirement kinds default to decision-critical.
- Closed vocabularies: sufficiency, decision, acquisition status, basis codes,
  instruction codes, requirement classes and safety flags are closed sets.
- Additive and read-only: inputs are never mutated; every result is a new dict
  with rule version ``r72-1``.
- Every record forces ``confirmation_state = NOT_CONFIRMED`` and carries the
  R71 stopping condition; ``SUFFICIENT_FOR_REVIEW`` means only that a human
  researcher has enough evidence for a meaningful review decision.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.research_outcome_planner import (
    EVIDENCE_STATES,
    RULE_VERSION as SOURCE_ACTION_RULE_VERSION,
    SAFETY_BLOCK,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    RULE_VERSION as SOURCE_ACQUISITION_RULE_VERSION,
    STATUS_AVAILABLE,
    STATUS_MISSING,
)

RULE_VERSION = "r72-1"

MAX_READINESS = 8
MAX_HYPOTHESES = 8
MAX_REQUIREMENTS = 6
MAX_BLOCKERS = 6
MAX_INSTRUCTION_TARGETS = 6
MAX_INSTRUCTION_SOURCES = 6
MAX_TEXT_CHARS = 320
MAX_TITLES = 8

# ---------------------------------------------------------------------------
# Closed requirement classes (structural support vs decision evidence)
# ---------------------------------------------------------------------------

CLASS_SUPPORT = "SUPPORT"
CLASS_DECISION = "DECISION"

REQUIREMENT_CLASSES: tuple[str, ...] = (CLASS_SUPPORT, CLASS_DECISION)

#: Structural/signal observations support a hypothesis but cannot decide it.
SUPPORT_REQUIREMENT_KINDS: frozenset[str] = frozenset(
    {
        "OBJECT_REFERENCE",
        "INPUT_SURFACE",
        "ENDPOINT_PURPOSE",
        "TECHNOLOGY_IDENTITY",
        "VERSION_IDENTITY",
        "SUPPORTING_OBSERVATION",
        "WATCH_SIGNAL",
    }
)

#: Behaviour/artifact evidence can move a research decision.
DECISION_REQUIREMENT_KINDS: frozenset[str] = frozenset(
    {
        "AUTHORIZATION_OUTCOME",
        "OWNERSHIP_BINDING",
        "FETCH_BEHAVIOR",
        "DESTINATION_CONTROL",
        "RESPONSE_CONTEXT",
        "ENCODING",
        "QUERY_RESPONSE",
        "REPRODUCIBILITY",
        "TOKEN_ARTIFACT",
        "VALIDATION_ARTIFACT",
        "FLOW_ARTIFACT",
        "REDIRECT_HANDLING",
        "COMPONENT_BINDING",
        "METHOD_AUTH",
        "RESPONSE_BEHAVIOR",
        "CORROBORATING_OBSERVATION",
    }
)

# ---------------------------------------------------------------------------
# Closed sufficiency / decision vocabularies
# ---------------------------------------------------------------------------

SUFFICIENCY_INSUFFICIENT = "INSUFFICIENT"
SUFFICIENCY_PARTIAL = "PARTIALLY_SUFFICIENT"
SUFFICIENCY_SUFFICIENT_FOR_REVIEW = "SUFFICIENT_FOR_REVIEW"

SUFFICIENCY_STATES: tuple[str, ...] = (
    SUFFICIENCY_INSUFFICIENT,
    SUFFICIENCY_PARTIAL,
    SUFFICIENCY_SUFFICIENT_FOR_REVIEW,
)

DECISION_NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
DECISION_READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
DECISION_REMAINS_UNRESOLVED = "REMAINS_UNRESOLVED"

DECISION_STATES: tuple[str, ...] = (
    DECISION_NEEDS_EVIDENCE,
    DECISION_READY_FOR_HUMAN_REVIEW,
    DECISION_REMAINS_UNRESOLVED,
)

ACQUISITION_PLANNED = "PLANNED"
ACQUISITION_NOT_REQUIRED = "NOT_REQUIRED"
ACQUISITION_UNAVAILABLE = "UNAVAILABLE"

ACQUISITION_STATUSES: tuple[str, ...] = (
    ACQUISITION_PLANNED,
    ACQUISITION_NOT_REQUIRED,
    ACQUISITION_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# Closed decision-basis codes
# ---------------------------------------------------------------------------

BASIS_NO_REQUIREMENTS = "NO_REQUIREMENTS"
BASIS_NO_DECISION_EVIDENCE = "NO_DECISION_EVIDENCE"
BASIS_PARTIAL_DECISION_EVIDENCE = "PARTIAL_DECISION_EVIDENCE"
BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE = "ALL_REQUIRED_EVIDENCE_AVAILABLE"

DECISION_BASIS_CODES: tuple[str, ...] = (
    BASIS_NO_REQUIREMENTS,
    BASIS_NO_DECISION_EVIDENCE,
    BASIS_PARTIAL_DECISION_EVIDENCE,
    BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE,
)

# ---------------------------------------------------------------------------
# Closed next-decision-step instruction codes
# ---------------------------------------------------------------------------

INSTRUCTION_ACQUIRE = "ACQUIRE_MISSING_DECISION_EVIDENCE"
INSTRUCTION_REVIEW = "HUMAN_REVIEW_SUFFICIENT_EVIDENCE"
INSTRUCTION_UNRESOLVED = "NO_ACTION_UPSTREAM_PLAN_INVALID"

INSTRUCTION_CODES: tuple[str, ...] = (
    INSTRUCTION_ACQUIRE,
    INSTRUCTION_REVIEW,
    INSTRUCTION_UNRESOLVED,
)

# ---------------------------------------------------------------------------
# Closed blocker codes (R71 requirement kinds + defensive upstream codes)
# ---------------------------------------------------------------------------

BLOCKER_NO_REQUIRED_EVIDENCE = "NO_REQUIRED_EVIDENCE"
BLOCKER_MALFORMED_ACQUISITION_PLAN = "MALFORMED_ACQUISITION_PLAN"

DEFAULT_STOP_CONDITION = (
    "No readiness decision can be made without a valid R71 acquisition plan; "
    "keep the hypothesis NOT_CONFIRMED and remain unresolved."
)

_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


class DecisionReadinessError(ValueError):
    """Deterministic, secret-free R72 readiness failure."""


def requirement_class_of(kind: object) -> str:
    """Closed requirement class; unknown kinds default to DECISION."""

    text = _upper(kind)
    if text in SUPPORT_REQUIREMENT_KINDS:
        return CLASS_SUPPORT
    return CLASS_DECISION


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _safe_text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Bound and redact credential-like text before it enters a record."""

    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:limit]


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _safe_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _coerce_count(value: object, default: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    if value < 0:
        return default
    return min(value, maximum)


def _outcomes_by_ref(action_plan: object) -> dict[str, Mapping]:
    outcomes: dict[str, Mapping] = {}
    for outcome in _mapping_items(_block(action_plan).get("outcomes")):
        ref = _safe_text(outcome.get("hypothesis_ref"), 16)
        if ref:
            outcomes[ref] = outcome
    return outcomes


def _actions_by_ref(action_plan: object) -> dict[str, Mapping]:
    actions: dict[str, Mapping] = {}
    for action in _mapping_items(_block(action_plan).get("actions")):
        ref = _safe_text(action.get("action_id"), 16)
        if ref:
            actions[ref] = action
    return actions


def _plans(acquisition_plan: object) -> list[Mapping]:
    block = _block(acquisition_plan)
    raw = block.get("plans")
    if raw is not None:
        return _mapping_items(raw)
    return _mapping_items(acquisition_plan)


def _evidence_state_for(
    hypothesis_refs: Sequence[str],
    actions_by_ref: Mapping[str, Mapping],
    outcomes: Mapping[str, Mapping],
    action_ref: str,
) -> tuple[str, list[str]]:
    """Strongest R70 evidence state among the correlated hypotheses."""

    states: list[str] = []
    action = actions_by_ref.get(action_ref)
    if isinstance(action, Mapping):
        states.extend(
            _bounded_strings(action.get("evidence_states"), MAX_HYPOTHESES, 32)
        )
    if not states:
        for ref in hypothesis_refs:
            outcome = outcomes.get(ref)
            if isinstance(outcome, Mapping):
                state = _upper(outcome.get("evidence_state"))
                if state and state not in states:
                    states.append(state)
    known = [state for state in states if state in EVIDENCE_STATES]
    if not known:
        return "NONE", []
    strongest = min(known, key=EVIDENCE_STATES.index)
    ordered = sorted(set(known), key=EVIDENCE_STATES.index)
    return strongest, ordered


def _requirements(plan: Mapping) -> list[dict]:
    out: list[dict] = []
    for entry in _mapping_items(plan.get("required_evidence")):
        kind = _upper(entry.get("requirement_kind"))
        if not kind:
            continue
        status = _upper(entry.get("status"))
        if status not in (STATUS_AVAILABLE, STATUS_MISSING):
            status = STATUS_MISSING
        out.append(
            {
                "requirement_kind": kind,
                "requirement_class": requirement_class_of(kind),
                "description": _safe_text(entry.get("description")),
                "status": status,
            }
        )
        if len(out) >= MAX_REQUIREMENTS:
            break
    return out


def _sufficiency_rule(
    requirements: Sequence[Mapping],
) -> tuple[str, str, str, str]:
    """Deterministic ladder -> (sufficiency, decision, acquisition, basis)."""

    if not requirements:
        return (
            SUFFICIENCY_INSUFFICIENT,
            DECISION_REMAINS_UNRESOLVED,
            ACQUISITION_UNAVAILABLE,
            BASIS_NO_REQUIREMENTS,
        )
    decision = [
        entry
        for entry in requirements
        if entry["requirement_class"] == CLASS_DECISION
    ]
    decision_missing = [
        entry for entry in decision if entry["status"] == STATUS_MISSING
    ]
    decision_available = [
        entry for entry in decision if entry["status"] == STATUS_AVAILABLE
    ]
    any_missing = any(
        entry["status"] == STATUS_MISSING for entry in requirements
    )
    if not decision_missing:
        return (
            SUFFICIENCY_SUFFICIENT_FOR_REVIEW,
            DECISION_READY_FOR_HUMAN_REVIEW,
            ACQUISITION_PLANNED if any_missing else ACQUISITION_NOT_REQUIRED,
            BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE,
        )
    if not decision_available:
        return (
            SUFFICIENCY_INSUFFICIENT,
            DECISION_NEEDS_EVIDENCE,
            ACQUISITION_PLANNED,
            BASIS_NO_DECISION_EVIDENCE,
        )
    return (
        SUFFICIENCY_PARTIAL,
        DECISION_NEEDS_EVIDENCE,
        ACQUISITION_PLANNED,
        BASIS_PARTIAL_DECISION_EVIDENCE,
    )


def _build_record(
    plan: Mapping,
    outcomes: Mapping[str, Mapping],
    actions_by_ref: Mapping[str, Mapping],
    position: int,
) -> dict:
    plan_ref = _safe_text(plan.get("plan_id"), 16) or f"P{position}"
    action_ref = _safe_text(plan.get("action_ref"), 16) or f"A{position}"
    hypothesis_refs = _bounded_strings(
        plan.get("hypothesis_refs"), MAX_HYPOTHESES, 16
    )
    hypothesis_count = _coerce_count(
        plan.get("hypothesis_count"),
        len(hypothesis_refs),
        MAX_HYPOTHESES,
    )
    category = _upper(plan.get("category"))
    gap_id = _upper(plan.get("gap_id"))
    action = actions_by_ref.get(action_ref)
    hypothesis_titles = (
        _bounded_strings(
            action.get("hypothesis_titles"), MAX_TITLES, 160
        )
        if isinstance(action, Mapping)
        else []
    )
    evidence_state, evidence_states = _evidence_state_for(
        hypothesis_refs, actions_by_ref, outcomes, action_ref
    )

    requirements = _requirements(plan)
    sufficiency, decision_state, acquisition_status, basis = _sufficiency_rule(
        requirements
    )
    available = [
        {
            "requirement_kind": entry["requirement_kind"],
            "requirement_class": entry["requirement_class"],
        }
        for entry in requirements
        if entry["status"] == STATUS_AVAILABLE
    ]
    missing = [
        entry for entry in requirements if entry["status"] == STATUS_MISSING
    ]
    blocking = [
        {
            "requirement_kind": entry["requirement_kind"],
            "requirement_class": entry["requirement_class"],
            "description": entry["description"],
        }
        for entry in missing
        if entry["requirement_class"] == CLASS_DECISION
    ][:MAX_BLOCKERS]
    non_blocking_missing = [
        entry["requirement_kind"]
        for entry in missing
        if entry["requirement_class"] == CLASS_SUPPORT
    ]

    if decision_state == DECISION_NEEDS_EVIDENCE:
        instruction = INSTRUCTION_ACQUIRE
        targets = [entry["requirement_kind"] for entry in blocking][
            :MAX_INSTRUCTION_TARGETS
        ]
        sources = _bounded_strings(
            plan.get("acquisition_sources"), MAX_INSTRUCTION_SOURCES, 64
        )
    elif decision_state == DECISION_READY_FOR_HUMAN_REVIEW:
        instruction = INSTRUCTION_REVIEW
        targets = []
        sources = []
    else:
        instruction = INSTRUCTION_UNRESOLVED
        targets = []
        sources = []

    blocking_codes = [entry["requirement_kind"] for entry in blocking]
    if not requirements:
        blocking_codes = [BLOCKER_NO_REQUIRED_EVIDENCE]

    decision_requirements = [
        entry
        for entry in requirements
        if entry["requirement_class"] == CLASS_DECISION
    ]
    decision_satisfied = [
        entry
        for entry in decision_requirements
        if entry["status"] == STATUS_AVAILABLE
    ]
    support_satisfied = [
        entry
        for entry in requirements
        if entry["requirement_class"] == CLASS_SUPPORT
        and entry["status"] == STATUS_AVAILABLE
    ]

    stop_condition = (
        _safe_text(plan.get("stopping_condition")) or DEFAULT_STOP_CONDITION
    )

    return {
        "readiness_id": "",
        "order": 0,
        "plan_ref": plan_ref,
        "action_ref": action_ref,
        "hypothesis_refs": hypothesis_refs,
        "hypothesis_titles": hypothesis_titles,
        "hypothesis_count": hypothesis_count,
        "category": category,
        "gap_id": gap_id,
        "evidence_gap": _safe_text(plan.get("evidence_gap")),
        "evidence_state": evidence_state,
        "evidence_states": evidence_states,
        "required_evidence": [
            {
                "requirement_kind": entry["requirement_kind"],
                "requirement_class": entry["requirement_class"],
                "status": entry["status"],
            }
            for entry in requirements
        ],
        "available_evidence": available,
        "missing_evidence": [
            {
                "requirement_kind": entry["requirement_kind"],
                "requirement_class": entry["requirement_class"],
                "description": entry["description"],
            }
            for entry in missing
        ],
        "acquisition_status": acquisition_status,
        "sufficiency_state": sufficiency,
        "decision_state": decision_state,
        "blocking_requirements": blocking,
        "blocking_codes": blocking_codes[:MAX_BLOCKERS],
        "non_blocking_missing_requirements": non_blocking_missing,
        "decision_basis": {
            "code": basis,
            "requirements_total": len(requirements),
            "decision_requirements": len(decision_requirements),
            "decision_satisfied": len(decision_satisfied),
            "support_satisfied": len(support_satisfied),
            "requirements_missing": len(missing),
        },
        "next_decision_step": {
            "instruction": instruction,
            "plan_ref": plan_ref,
            "action_ref": action_ref,
            "sources": sources,
            "targets": targets,
        },
        "stop_condition": stop_condition,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def build_readiness_records(
    action_plan: object = None, acquisition_plan: object = None
) -> list[dict]:
    """One bounded readiness record per R71 plan (input order).

    Both inputs are consumed read-only. A plan without required evidence fails
    closed to ``INSUFFICIENT`` + ``REMAINS_UNRESOLVED``; no readiness state is
    ever invented.
    """

    outcomes = _outcomes_by_ref(action_plan)
    actions_by_ref = _actions_by_ref(action_plan)
    return [
        _build_record(plan, outcomes, actions_by_ref, position)
        for position, plan in enumerate(_plans(acquisition_plan), start=1)
    ]


def summarize_readiness(records: object = None) -> dict:
    """Bounded readiness summary (counts, bands, top record)."""

    items = list(_mapping_items(records))
    sufficiency_bands = {
        SUFFICIENCY_INSUFFICIENT: 0,
        SUFFICIENCY_PARTIAL: 0,
        SUFFICIENCY_SUFFICIENT_FOR_REVIEW: 0,
    }
    decision_bands = {
        DECISION_NEEDS_EVIDENCE: 0,
        DECISION_READY_FOR_HUMAN_REVIEW: 0,
        DECISION_REMAINS_UNRESOLVED: 0,
    }
    for record in items:
        sufficiency = _upper(record.get("sufficiency_state"))
        if sufficiency in sufficiency_bands:
            sufficiency_bands[sufficiency] += 1
        decision = _upper(record.get("decision_state"))
        if decision in decision_bands:
            decision_bands[decision] += 1
    top = items[0] if items else {}
    return {
        "rule_version": RULE_VERSION,
        "record_count": len(items),
        "covered_plans": len(
            {
                _safe_text(record.get("plan_ref"), 16)
                for record in items
                if record.get("plan_ref")
            }
        ),
        "covered_actions": len(
            {
                _safe_text(record.get("action_ref"), 16)
                for record in items
                if record.get("action_ref")
            }
        ),
        "covered_hypotheses": sum(
            int(record.get("hypothesis_count") or 0) for record in items
        ),
        "sufficiency_bands": sufficiency_bands,
        "decision_bands": decision_bands,
        "top_readiness_id": _safe_text(top.get("readiness_id"), 16),
        "top_sufficiency_state": _upper(top.get("sufficiency_state")),
        "top_decision_state": _upper(top.get("decision_state")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def plan_decision_readiness(
    action_plan: object = None,
    acquisition_plan: object = None,
    *,
    limit: int = MAX_READINESS,
) -> dict:
    """Build, bound and summarize the R72 decision-readiness result."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise DecisionReadinessError("limit must be an integer")
    if limit < 0:
        raise DecisionReadinessError("limit must be >= 0")

    records = build_readiness_records(action_plan, acquisition_plan)
    limited = [dict(record) for record in records[:limit]]
    for position, record in enumerate(limited, start=1):
        record["readiness_id"] = f"R{position}"
        record["order"] = position
    return {
        "rule_version": RULE_VERSION,
        "source_action_rule_version": (
            _safe_text(_block(action_plan).get("rule_version"), 32)
            or SOURCE_ACTION_RULE_VERSION
        ),
        "source_acquisition_rule_version": (
            _safe_text(_block(acquisition_plan).get("rule_version"), 32)
            or SOURCE_ACQUISITION_RULE_VERSION
        ),
        "records": limited,
        "summary": summarize_readiness(limited),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "SOURCE_ACTION_RULE_VERSION",
    "SOURCE_ACQUISITION_RULE_VERSION",
    "MAX_READINESS",
    "MAX_HYPOTHESES",
    "MAX_REQUIREMENTS",
    "MAX_BLOCKERS",
    "MAX_INSTRUCTION_TARGETS",
    "MAX_INSTRUCTION_SOURCES",
    "MAX_TEXT_CHARS",
    "MAX_TITLES",
    "CLASS_SUPPORT",
    "CLASS_DECISION",
    "REQUIREMENT_CLASSES",
    "SUPPORT_REQUIREMENT_KINDS",
    "DECISION_REQUIREMENT_KINDS",
    "SUFFICIENCY_INSUFFICIENT",
    "SUFFICIENCY_PARTIAL",
    "SUFFICIENCY_SUFFICIENT_FOR_REVIEW",
    "SUFFICIENCY_STATES",
    "DECISION_NEEDS_EVIDENCE",
    "DECISION_READY_FOR_HUMAN_REVIEW",
    "DECISION_REMAINS_UNRESOLVED",
    "DECISION_STATES",
    "ACQUISITION_PLANNED",
    "ACQUISITION_NOT_REQUIRED",
    "ACQUISITION_UNAVAILABLE",
    "ACQUISITION_STATUSES",
    "BASIS_NO_REQUIREMENTS",
    "BASIS_NO_DECISION_EVIDENCE",
    "BASIS_PARTIAL_DECISION_EVIDENCE",
    "BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE",
    "DECISION_BASIS_CODES",
    "INSTRUCTION_ACQUIRE",
    "INSTRUCTION_REVIEW",
    "INSTRUCTION_UNRESOLVED",
    "INSTRUCTION_CODES",
    "BLOCKER_NO_REQUIRED_EVIDENCE",
    "BLOCKER_MALFORMED_ACQUISITION_PLAN",
    "DEFAULT_STOP_CONDITION",
    "DecisionReadinessError",
    "requirement_class_of",
    "build_readiness_records",
    "summarize_readiness",
    "plan_decision_readiness",
]

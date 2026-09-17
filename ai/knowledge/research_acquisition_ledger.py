"""Stage R91 deterministic case acquisition ledger (pure engine).

Answers, for every required evidence kind of a persisted research case:

    "What acquisition was already attempted, with which outcome, and what
     does that imply for the next controlled research step?"

The ledger is a **read-only projection** over the existing authorities:

    R71 acquisition plan / R72 readiness  -> planned requirement kinds
    R74 intake / R75 provenance           -> accepted evidence + conflicts
    R76 case workspace                    -> status / readiness / evidence
    R87 / R89 completion blocks           -> persisted attempt outcomes
    R91 evidence_acquisition block (R87/R89 write it on success)

Hard boundaries encoded here:

- Bookkeeping only: the ledger records and projects acquisition *attempts*.
  It never acquires evidence, never contacts a target, never executes
  anything and never changes a case state.
- No new acquisition source: the source vocabulary is the existing R74/R71
  vocabulary; the only deterministic source is the existing R87 completion
  path (``WATCH_DERIVED``) and the only human source is the existing R89
  boundary (``HUMAN_REVIEW``).
- Fail closed: a malformed case (no bounded ``case_id``) raises
  :class:`AcquisitionLedgerError`; malformed optional sub-blocks are ignored
  (they can never fabricate attempts or evidence).
- Deterministic: no wall-clock time, no randomness, no UUIDs; the same
  inputs always produce byte-identical output.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no scanner, no database, no persistence. Nothing here is a
  vulnerability verdict.
"""

from __future__ import annotations

from typing import Mapping

from ai.knowledge.research_decision_readiness_planner import (
    CLASS_DECISION,
    CLASS_SUPPORT,
    requirement_class_of,
)
from ai.knowledge.research_workbench import (
    ACTION_CONTINUE_RESEARCH,
    ACTION_HUMAN_REVIEW,
    ACTION_PROVIDE_EVIDENCE,
    ACTION_REVIEW_CONFLICT,
    ACTION_REVIEW_EVIDENCE,
    ACTION_STOP,
)

RULE_VERSION = "r91-1"

MAX_REQUIREMENTS = 24
MAX_ATTEMPTS = 32
MAX_REFS = 8
MAX_TEXT_CHARS = 240
MAX_REF_CHARS = 512
MAX_PORTFOLIO_CASES = 32
MAX_WHY = 6

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_SATISFIED = "SATISFIED"
STATUS_ATTEMPTED_NO_OBSERVATION = "ATTEMPTED_NO_OBSERVATION"
STATUS_ATTEMPTED_UNRESOLVED = "ATTEMPTED_UNRESOLVED"
STATUS_HUMAN_REQUIRED = "HUMAN_REQUIRED"
STATUS_NOT_ATTEMPTED = "NOT_ATTEMPTED"
STATUS_CONFLICT_REVIEW = "CONFLICT_REVIEW"

REQUIREMENT_STATUSES: tuple[str, ...] = (
    STATUS_SATISFIED,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_ATTEMPTED_UNRESOLVED,
    STATUS_HUMAN_REQUIRED,
    STATUS_NOT_ATTEMPTED,
    STATUS_CONFLICT_REVIEW,
)

SOURCE_WATCH_DERIVED = "WATCH_DERIVED"
SOURCE_HUMAN_REVIEW = "HUMAN_REVIEW"

DETERMINISTIC_SOURCES: tuple[str, ...] = (SOURCE_WATCH_DERIVED,)
HUMAN_SOURCES: tuple[str, ...] = (SOURCE_HUMAN_REVIEW,)

OUTCOME_ACCEPTED = "ACCEPTED"
OUTCOME_NO_MATCHING_OBSERVATION = "NO_MATCHING_OBSERVATION"
OUTCOME_NO_GENUINE_EVIDENCE = "NO_GENUINE_EVIDENCE"
OUTCOME_HUMAN_REVIEW_ONLY = "HUMAN_REVIEW_ONLY"

#: Outcomes that mean "an offline/deterministic attempt produced nothing".
OFFLINE_NO_OBSERVATION_OUTCOMES: tuple[str, ...] = (
    OUTCOME_NO_MATCHING_OBSERVATION,
    OUTCOME_NO_GENUINE_EVIDENCE,
)

#: Human-review-only requirement vocabulary (mirrors the R71 human-only
#: source targets and the R87/R89 ``HUMAN_ONLY_REQUIREMENTS`` rule).
HUMAN_ONLY_REQUIREMENTS: tuple[str, ...] = ("WATCH_SIGNAL",)

#: The R87 deterministic completion block is the only completion block that
#: implies a deterministic attempt; R89 blocks are human-driven.
DETERMINISTIC_COMPLETION_RULE_VERSION = "r87-1"

ACTION_RANK: dict[str, int] = {
    ACTION_PROVIDE_EVIDENCE: 0,
    ACTION_REVIEW_CONFLICT: 1,
    ACTION_HUMAN_REVIEW: 2,
    ACTION_CONTINUE_RESEARCH: 3,
    ACTION_REVIEW_EVIDENCE: 4,
    ACTION_STOP: 5,
}


class AcquisitionLedgerError(ValueError):
    """Deterministic, secret-free R91 ledger failure."""


# ---------------------------------------------------------------------------
# Bounded helpers (mirrors the previous stages' conventions)
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _upper(value: object) -> str:
    return _text(value).upper()


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _block(value: object) -> dict:
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


# ---------------------------------------------------------------------------
# Attempt normalization and merge (persisted on write; projected on read)
# ---------------------------------------------------------------------------


def normalize_attempt(entry: object) -> dict | None:
    """One bounded, deterministic attempt record, or None when malformed."""

    block = _block(entry)
    requirement_kind = _upper(block.get("requirement_kind"))
    source = _upper(block.get("source"))
    outcome = _upper(block.get("outcome"))
    if not requirement_kind or not source or not outcome:
        return None
    if len(requirement_kind) > 64 or len(source) > 32 or len(outcome) > 64:
        return None
    return {
        "requirement_kind": requirement_kind,
        "source": source,
        "outcome": outcome,
        "evidence_refs": _bounded_list(
            block.get("evidence_refs"), MAX_REFS, MAX_REF_CHARS
        ),
        "last_iteration": max(_int(block.get("last_iteration"), 0), 0),
        "rule_version": _text(block.get("rule_version"), 32),
        "count": max(_int(block.get("count"), 1), 1),
    }


def merge_acquisition_attempts(
    previous: object,
    incoming: object,
    *,
    limit: int = MAX_ATTEMPTS,
) -> list[dict]:
    """Latest attempt per (requirement_kind, source); deterministic order.

    Existing entries are preserved; a new entry for the same key replaces the
    previous outcome and evidence refs and accumulates its count. No
    timestamps are recorded.
    """

    merged: dict[tuple[str, str], dict] = {}
    for raw in _mapping_items(previous):
        item = normalize_attempt(raw)
        if item is not None:
            merged[(item["requirement_kind"], item["source"])] = item
    for raw in _mapping_items(incoming):
        item = normalize_attempt(raw)
        if item is None:
            continue
        key = (item["requirement_kind"], item["source"])
        existing = merged.get(key)
        if existing is not None:
            item["count"] = existing.get("count", 1) + 1
        merged[key] = item
    return sorted(
        merged.values(),
        key=lambda item: (item["requirement_kind"], item["source"]),
    )[: max(int(limit), 0)]


def acquisition_block(attempts: object) -> dict:
    """Bounded persisted ``evidence_acquisition`` artifact block."""

    entries = merge_acquisition_attempts((), attempts)
    return {
        "rule_version": RULE_VERSION,
        "attempts": entries,
        "summary": {
            "attempt_count": sum(
                max(_int(item.get("count"), 1), 1) for item in entries
            ),
            "requirement_count": len(
                {item["requirement_kind"] for item in entries}
            ),
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


# ---------------------------------------------------------------------------
# Ledger construction
# ---------------------------------------------------------------------------


def _requirement_universe(
    case: Mapping,
    acquisition_plan: object,
    readiness_plan: object,
) -> list[dict]:
    classes: dict[str, str] = {}
    kinds: list[str] = []

    def add(kind: object, klass: object = "") -> None:
        name = _upper(kind)
        if not name or len(name) > 64:
            return
        kinds.append(name)
        value = _upper(klass)
        if value in (CLASS_SUPPORT, CLASS_DECISION):
            classes[name] = value
        else:
            classes.setdefault(name, requirement_class_of(name))

    for record in _mapping_items(_block(readiness_plan).get("records")):
        for entry in _mapping_items(record.get("required_evidence")):
            add(entry.get("requirement_kind"), entry.get("requirement_class"))
    for plan in _mapping_items(_block(acquisition_plan).get("plans")):
        for entry in _mapping_items(plan.get("required_evidence")):
            add(entry.get("requirement_kind"))
    evidence = _block(case.get("evidence"))
    for kind in _bounded_list(
        evidence.get("available_requirement_kinds"), MAX_REQUIREMENTS, 64
    ) + _bounded_list(
        evidence.get("missing_requirement_kinds"), MAX_REQUIREMENTS, 64
    ):
        add(kind)

    out: list[dict] = []
    seen: set[str] = set()
    for kind in kinds:
        if kind in seen:
            continue
        seen.add(kind)
        out.append(
            {
                "requirement_kind": kind,
                "requirement_class": classes.get(kind)
                or requirement_class_of(kind),
            }
        )
    out.sort(
        key=lambda entry: (
            0 if entry["requirement_class"] == CLASS_DECISION else 1,
            entry["requirement_kind"],
        )
    )
    return out[:MAX_REQUIREMENTS]


def _recorded_attempts(block: object) -> list[dict]:
    entries: list[dict] = []
    for raw in _mapping_items(_block(block).get("attempts")):
        item = normalize_attempt(raw)
        if item is not None:
            entries.append(item)
    entries.sort(key=lambda item: (item["requirement_kind"], item["source"]))
    return entries[:MAX_ATTEMPTS]


def _reconstructed_attempt(
    kind: str, completion: object, iteration: int
) -> dict | None:
    """Reconstruct one deterministic attempt from a persisted R87 block.

    The R87 completion path evaluates every non-human requirement with the
    unchanged R30.1 projection and reports ``HUMAN_REVIEW_ONLY`` for the
    human-only vocabulary; its persisted block therefore implies, for the
    kinds it lists, that a deterministic attempt happened. Nothing is
    reconstructed from a human (R89) block.
    """

    block = _block(completion)
    rule_version = _text(block.get("rule_version"), 32)
    if rule_version != DETERMINISTIC_COMPLETION_RULE_VERSION:
        return None
    accepted = set(
        _bounded_list(block.get("requirement_kinds"), MAX_REQUIREMENTS, 64)
    )
    missing = set(
        _bounded_list(
            block.get("missing_requirement_kinds"), MAX_REQUIREMENTS, 64
        )
    )
    if kind in accepted:
        outcome = OUTCOME_ACCEPTED
    elif kind in missing:
        outcome = (
            OUTCOME_HUMAN_REVIEW_ONLY
            if kind in HUMAN_ONLY_REQUIREMENTS
            else OUTCOME_NO_MATCHING_OBSERVATION
        )
    else:
        return None
    return {
        "requirement_kind": kind,
        "source": SOURCE_WATCH_DERIVED,
        "outcome": outcome,
        "evidence_refs": [],
        "last_iteration": max(int(iteration), 0),
        "rule_version": rule_version,
        "count": 1,
        "record_source": "RECONSTRUCTED_R87",
    }


def _provenance_for(provenance: object, kind: str) -> dict:
    refs: list[str] = []
    conflict = False
    human_review = False
    for record in _mapping_items(_block(provenance).get("records")):
        if _upper(record.get("requirement_kind")) != kind:
            continue
        for ref in _bounded_list(
            record.get("evidence_refs"), MAX_REFS, MAX_REF_CHARS
        ):
            if ref not in refs:
                refs.append(ref)
        state = _upper(record.get("conflict_state"))
        if state and state not in ("NONE",):
            conflict = True
        if record.get("human_review_required") is True:
            human_review = True
        if len(refs) >= MAX_REFS:
            break
    return {
        "evidence_refs": refs[:MAX_REFS],
        "conflict": conflict,
        "human_review_required": human_review,
    }


def _status_for(
    kind: str,
    satisfied: bool,
    attempts: list[dict],
    provenance: dict,
) -> str:
    if satisfied:
        return STATUS_SATISFIED
    if provenance.get("conflict"):
        return STATUS_CONFLICT_REVIEW
    if kind in HUMAN_ONLY_REQUIREMENTS or any(
        item["outcome"] == OUTCOME_HUMAN_REVIEW_ONLY for item in attempts
    ):
        return STATUS_HUMAN_REQUIRED
    if any(
        item["source"] in DETERMINISTIC_SOURCES
        and item["outcome"] in OFFLINE_NO_OBSERVATION_OUTCOMES
        for item in attempts
    ):
        return STATUS_ATTEMPTED_NO_OBSERVATION
    if attempts:
        return STATUS_ATTEMPTED_UNRESOLVED
    return STATUS_NOT_ATTEMPTED


def _next_action(
    case: Mapping,
    counts: Mapping,
    human_review_required: bool,
) -> str:
    if _upper(case.get("status")) == "STOPPED":
        return ACTION_STOP
    if counts.get("conflict_review", 0) > 0:
        return ACTION_REVIEW_CONFLICT
    if human_review_required or _upper(
        _block(case.get("readiness")).get("decision_state")
    ) == "READY_FOR_HUMAN_REVIEW":
        return ACTION_HUMAN_REVIEW
    if counts.get("not_attempted", 0) > 0:
        return ACTION_CONTINUE_RESEARCH
    if (
        counts.get("human_required", 0) > 0
        or counts.get("attempted_no_observation", 0) > 0
        or counts.get("attempted_unresolved", 0) > 0
    ):
        return ACTION_PROVIDE_EVIDENCE
    if counts.get("missing", 0) == 0:
        return ACTION_REVIEW_EVIDENCE
    return ACTION_PROVIDE_EVIDENCE


def build_case_acquisition_ledger(
    case: object,
    *,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    evidence_provenance: object = None,
    evidence_completion: object = None,
    evidence_acquisition: object = None,
) -> dict:
    """Bounded acquisition ledger for one persisted R76 case."""

    block = _block(case)
    case_id = _text(block.get("case_id"), 96)
    if not case_id:
        raise AcquisitionLedgerError("MALFORMED_CASE")
    program = _text(block.get("program"), 64)
    evidence = _block(block.get("evidence"))
    readiness = _block(block.get("readiness"))
    available = set(
        _bounded_list(
            evidence.get("available_requirement_kinds"), MAX_REQUIREMENTS, 64
        )
    )
    iteration = _int(block.get("iteration_count"), 0)
    provenance_block = _block(evidence_provenance)
    human_review_required = bool(block.get("human_review_required"))
    recorded = _recorded_attempts(evidence_acquisition)
    recorded_keys = {
        (item["requirement_kind"], item["source"]) for item in recorded
    }

    requirements: list[dict] = []
    for entry in _requirement_universe(
        block, acquisition_plan, readiness_plan
    ):
        kind = entry["requirement_kind"]
        attempts = [
            item for item in recorded if item["requirement_kind"] == kind
        ]
        if not attempts:
            reconstructed = _reconstructed_attempt(
                kind, evidence_completion, iteration
            )
            if reconstructed is not None:
                attempts = [reconstructed]
        provenance = _provenance_for(provenance_block, kind)
        satisfied = kind in available
        status = _status_for(kind, satisfied, attempts, provenance)
        offline_exhausted = status == STATUS_ATTEMPTED_NO_OBSERVATION
        if satisfied:
            remaining: list[str] = []
        elif offline_exhausted or status == STATUS_HUMAN_REQUIRED:
            remaining = [SOURCE_HUMAN_REVIEW]
        else:
            remaining = [SOURCE_WATCH_DERIVED, SOURCE_HUMAN_REVIEW]
        requirements.append(
            {
                "requirement_kind": kind,
                "requirement_class": entry["requirement_class"],
                "status": status,
                "evidence_refs": provenance.get("evidence_refs") or [],
                "attempts": attempts[:MAX_ATTEMPTS],
                "remaining_sources": remaining,
                "offline_exhausted": offline_exhausted,
            }
        )

    counts = {
        "required": len(requirements),
        "satisfied": sum(
            1 for item in requirements if item["status"] == STATUS_SATISFIED
        ),
        "missing": sum(
            1 for item in requirements if item["status"] != STATUS_SATISFIED
        ),
        "decision_missing": sum(
            1
            for item in requirements
            if item["status"] != STATUS_SATISFIED
            and item["requirement_class"] == CLASS_DECISION
        ),
        "human_required": sum(
            1
            for item in requirements
            if item["status"] == STATUS_HUMAN_REQUIRED
        ),
        "attempted_no_observation": sum(
            1
            for item in requirements
            if item["status"] == STATUS_ATTEMPTED_NO_OBSERVATION
        ),
        "attempted_unresolved": sum(
            1
            for item in requirements
            if item["status"] == STATUS_ATTEMPTED_UNRESOLVED
        ),
        "not_attempted": sum(
            1
            for item in requirements
            if item["status"] == STATUS_NOT_ATTEMPTED
        ),
        "conflict_review": sum(
            1
            for item in requirements
            if item["status"] == STATUS_CONFLICT_REVIEW
        ),
    }
    missing_offline = [
        item
        for item in requirements
        if item["status"] != STATUS_SATISFIED
        and item["requirement_kind"] not in HUMAN_ONLY_REQUIREMENTS
        and item["status"] != STATUS_CONFLICT_REVIEW
    ]
    offline_sources_exhausted = bool(missing_offline) and all(
        item["status"] == STATUS_ATTEMPTED_NO_OBSERVATION
        for item in missing_offline
    )
    next_action = _next_action(block, counts, human_review_required)

    why: list[str] = []
    if counts["decision_missing"]:
        why.append(
            "decision-critical requirement(s) missing: "
            + ", ".join(
                item["requirement_kind"]
                for item in requirements
                if item["status"] != STATUS_SATISFIED
                and item["requirement_class"] == CLASS_DECISION
            )[:MAX_TEXT_CHARS]
        )
    if counts["human_required"]:
        why.append(
            "human-review-only requirement(s) never auto-attempted: "
            + ", ".join(
                item["requirement_kind"]
                for item in requirements
                if item["status"] == STATUS_HUMAN_REQUIRED
            )[:MAX_TEXT_CHARS]
        )
    if counts["attempted_no_observation"]:
        why.append(
            "deterministic acquisition attempted with no stored observation: "
            + ", ".join(
                item["requirement_kind"]
                for item in requirements
                if item["status"] == STATUS_ATTEMPTED_NO_OBSERVATION
            )[:MAX_TEXT_CHARS]
        )
    if counts["not_attempted"]:
        why.append(
            "no deterministic attempt recorded yet for: "
            + ", ".join(
                item["requirement_kind"]
                for item in requirements
                if item["status"] == STATUS_NOT_ATTEMPTED
            )[:MAX_TEXT_CHARS]
        )
    if offline_sources_exhausted:
        why.append(
            "offline deterministic sources exhausted for every missing "
            "non-human requirement; remaining source: HUMAN_REVIEW"
        )
    if counts["conflict_review"]:
        why.append("conflicting evidence preserved; human review required")

    return {
        "rule_version": RULE_VERSION,
        "case_id": case_id,
        "case_version": _upper(block.get("case_version")),
        "program": program,
        "case_status": _upper(block.get("status")),
        "sufficiency_state": _upper(readiness.get("sufficiency_state")),
        "decision_state": _upper(readiness.get("decision_state")),
        "iteration_count": iteration,
        "counts": counts,
        "offline_sources_exhausted": offline_sources_exhausted,
        "human_action_required": bool(
            human_review_required
            or counts["human_required"]
            or counts["conflict_review"]
            or offline_sources_exhausted
        ),
        "next_action": next_action,
        "why": why[:MAX_WHY],
        "requirements": requirements,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def build_acquisition_portfolio(ledgers: object) -> dict:
    """Deterministic attention ordering over case acquisition ledgers."""

    rows: list[dict] = []
    for raw in _mapping_items(ledgers):
        case_id = _text(raw.get("case_id"), 96)
        if not case_id:
            continue
        counts = _block(raw.get("counts"))
        rows.append(
            {
                "case_id": case_id,
                "program": _text(raw.get("program"), 64),
                "case_status": _upper(raw.get("case_status")),
                "sufficiency_state": _upper(raw.get("sufficiency_state")),
                "decision_state": _upper(raw.get("decision_state")),
                "next_action": _upper(raw.get("next_action")),
                "missing": _int(counts.get("missing"), 0),
                "decision_missing": _int(counts.get("decision_missing"), 0),
                "human_required": _int(counts.get("human_required"), 0),
                "offline_sources_exhausted": bool(
                    raw.get("offline_sources_exhausted")
                ),
                "human_action_required": bool(
                    raw.get("human_action_required")
                ),
                "iteration_count": _int(raw.get("iteration_count"), 0),
            }
        )

    rows.sort(
        key=lambda row: (
            ACTION_RANK.get(row["next_action"], len(ACTION_RANK)),
            -row["decision_missing"],
            -row["missing"],
            row["case_id"],
        )
    )
    rows = rows[:MAX_PORTFOLIO_CASES]

    by_action: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for row in rows:
        by_action[row["next_action"]] = by_action.get(row["next_action"], 0) + 1
        by_status[row["case_status"]] = by_status.get(row["case_status"], 0) + 1
    return {
        "rule_version": RULE_VERSION,
        "total": len(rows),
        "items": rows,
        "summary": {
            "by_action": {
                key: by_action[key] for key in sorted(by_action)
            },
            "by_status": {
                key: by_status[key] for key in sorted(by_status)
            },
            "human_action_required": sum(
                1 for row in rows if row["human_action_required"]
            ),
            "offline_sources_exhausted": sum(
                1 for row in rows if row["offline_sources_exhausted"]
            ),
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "MAX_REQUIREMENTS",
    "MAX_ATTEMPTS",
    "MAX_PORTFOLIO_CASES",
    "STATUS_SATISFIED",
    "STATUS_ATTEMPTED_NO_OBSERVATION",
    "STATUS_ATTEMPTED_UNRESOLVED",
    "STATUS_HUMAN_REQUIRED",
    "STATUS_NOT_ATTEMPTED",
    "STATUS_CONFLICT_REVIEW",
    "REQUIREMENT_STATUSES",
    "SOURCE_WATCH_DERIVED",
    "SOURCE_HUMAN_REVIEW",
    "DETERMINISTIC_SOURCES",
    "HUMAN_SOURCES",
    "OUTCOME_ACCEPTED",
    "OUTCOME_NO_MATCHING_OBSERVATION",
    "OUTCOME_NO_GENUINE_EVIDENCE",
    "OUTCOME_HUMAN_REVIEW_ONLY",
    "OFFLINE_NO_OBSERVATION_OUTCOMES",
    "HUMAN_ONLY_REQUIREMENTS",
    "AcquisitionLedgerError",
    "normalize_attempt",
    "merge_acquisition_attempts",
    "acquisition_block",
    "build_case_acquisition_ledger",
    "build_acquisition_portfolio",
]

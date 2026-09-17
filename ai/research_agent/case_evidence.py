"""Stage R87 — real evidence completion for persisted research cases.

R86 activated real cases from persisted research results, but every external
evidence package was ``NOT_PROVIDED``, so the production case stayed
``WAITING_FOR_EVIDENCE``. R80 built the safe external submission boundary and
R81 exposed it read-only/in-memory through the researcher API; neither
persists a completed case update.

R87 is the bounded completion step and nothing else. It is the smallest
deterministic link that:

    existing Watch observed data and deterministic match projections
      -> genuine case-bound evidence items (only what is actually supported)
      -> R80 safe submission boundary (authoritative)
      -> R74 intake / R75 provenance / R72 readiness / R73 feedback
      -> R76 case update / R77 workbench
      -> one atomic, bounded update of the existing case artifact

No authority is reimplemented and no stage output is re-derived:

- R80 ``submit_research_evidence`` is the only submission entry point; this
  module never calls R74 directly and never bypasses the boundary.
- The existing R30.1 asset/CVE matcher remains the authority for which
  observed technology/version/component values are attributable to one CVE in
  one program. This module only translates its explicit match rows into the
  existing R74 item vocabulary.
- R75 provenance, R72 readiness, R73 feedback, R76 case state and R77
  workbench are called exactly as the existing service path calls them.

Hard boundaries encoded here:

- Evidence is never fabricated and never derived from hypothesis titles,
  model text, CVE names or planner output. An item is built only when the
  deterministic matcher exposes an explicit stored observation for this
  program and this CVE. ``WATCH_SIGNAL`` is a human-review requirement and is
  never auto-submitted.
- Fail-closed identity: the artifact, case id, program, CVE binding and stage
  blocks are validated before anything is submitted; malformed or mismatched
  artifacts produce no submission and no write.
- Idempotent by construction: an item whose identity is already recorded in
  the case provenance is reported as replayed and never resubmitted; repeated
  execution is byte-stable and never creates duplicate evidence, cases,
  hypotheses or feedback.
- The case moves only through the existing deterministic readiness rules; no
  status is ever forced. Conflicts remain conflicts and force human review.
- Bounded and hygiene-safe: only canonical refs, bounded facts and existing
  stage blocks enter the artifact; no secrets, URLs, targets, Mongo ids or
  execution content are emitted. No target interaction, no network, no LLM
  and no execution is performed here. Mongo is only read through the existing
  matcher projection.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ai.knowledge.research_case_workspace import (
    summarize_research_cases,
    update_research_case,
)
from ai.knowledge.research_evidence_provenance import (
    CONFLICT_STATES,
    MAX_CONFLICTS,
    MAX_RECORDS,
    PROVENANCE_STATES,
    RELATIONSHIPS,
    analyze_evidence_provenance,
)
from ai.knowledge.research_evidence_submission import (
    SUBMISSION_VERSION,
    submit_research_evidence,
)
from ai.knowledge.research_feedback_loop import (
    EFFECT_PROVIDES,
    SOURCE_WATCH_DERIVED,
)
from ai.knowledge.research_outcome_planner import SAFETY_BLOCK
from ai.knowledge.research_workbench import build_research_workbench

RULE_VERSION = "r87-1"

DEFAULT_CASES_DIR = Path("ai_data/research/cases")

SUBMITTER_LABEL = "watch-r87-evidence-completion"

MAX_ITEMS = 8
MAX_TEXT_CHARS = 320
MAX_FACT_CHARS = 320
MAX_REF_CHARS = 512
MAX_HYPOTHESIS_REF_CHARS = 16
MAX_WORKBENCH_HISTORY = 8

REQUIREMENT_TECHNOLOGY_IDENTITY = "TECHNOLOGY_IDENTITY"
REQUIREMENT_VERSION_IDENTITY = "VERSION_IDENTITY"
REQUIREMENT_COMPONENT_BINDING = "COMPONENT_BINDING"
REQUIREMENT_ORDER: tuple[str, ...] = (
    REQUIREMENT_TECHNOLOGY_IDENTITY,
    REQUIREMENT_VERSION_IDENTITY,
    REQUIREMENT_COMPONENT_BINDING,
)
HUMAN_ONLY_REQUIREMENTS: tuple[str, ...] = ("WATCH_SIGNAL",)

MATCH_TYPE_TECHNOLOGY = "TECHNOLOGY"
MATCH_TYPE_VERSION = "VERSION"
MATCH_TYPE_COMPONENT = "COMPONENT"
MATCH_TYPE_PLUGIN = "PLUGIN"

# Closed completion-status vocabulary (workflow vocabulary only).
STATUS_COMPLETED = "COMPLETED"
STATUS_REPLAYED = "REPLAYED"
STATUS_NO_EVIDENCE = "NO_EVIDENCE"
STATUS_REJECTED = "REJECTED"
STATUS_ERROR = "ERROR"

COMPLETION_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_REPLAYED,
    STATUS_NO_EVIDENCE,
    STATUS_REJECTED,
    STATUS_ERROR,
)

REASON_MALFORMED_ARTIFACT = "MALFORMED_ARTIFACT"
REASON_CASE_ID_MISMATCH = "CASE_ID_MISMATCH"
REASON_PROGRAM_MISSING = "PROGRAM_MISSING"
REASON_CVE_MISSING = "CVE_MISSING"
REASON_STAGE_MISSING = "STAGE_MISSING"
REASON_NO_ITEMS = "NO_GENUINE_EVIDENCE"
REASON_ALL_REPLAYED = "ALL_EVIDENCE_ALREADY_RECORDED"
REASON_BOUNDARY_REJECTED = "BOUNDARY_REJECTED"
REASON_WRITE_FAILED = "WRITE_FAILED"

COMPLETION_REASONS: tuple[str, ...] = (
    REASON_MALFORMED_ARTIFACT,
    REASON_CASE_ID_MISMATCH,
    REASON_PROGRAM_MISSING,
    REASON_CVE_MISSING,
    REASON_STAGE_MISSING,
    REASON_NO_ITEMS,
    REASON_ALL_REPLAYED,
    REASON_BOUNDARY_REJECTED,
    REASON_WRITE_FAILED,
)

_CASE_ID_RE = re.compile(r"^case-[a-z0-9-]{1,72}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

LIMITATIONS: tuple[str, ...] = (
    "Evidence completion is research-only and advisory; it never confirms a "
    "vulnerability, never authorizes execution and never derives evidence "
    "from model output.",
    "Only explicit deterministic matcher rows over stored Watch observations "
    "can become evidence; WATCH_SIGNAL is human-review-only and is never "
    "auto-submitted.",
    "The case artifact keeps its identity and format; only existing stage "
    "blocks, the case workspace, the workbench and an accumulated provenance "
    "record are updated atomically through the existing R76 update path.",
    "No target interaction, network access, LLM call, execution or direct "
    "Mongo write is performed by this module.",
)

MatchLoader = Callable[[str], object]


class CaseEvidenceError(ValueError):
    """Deterministic, secret-free R87 completion failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Bounded helpers (mirrors the previous stages' conventions)
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _upper(value: object) -> str:
    return _text(value, MAX_TEXT_CHARS).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_refs(value: object, limit: int = MAX_ITEMS) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, MAX_REF_CHARS)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Deterministic evidence selection (R30.1 matcher rows -> R74 items)
# ---------------------------------------------------------------------------


def default_match_loader(cve_id: str) -> list[dict]:
    """Existing R30.1 matcher projection (read-only; ``[]`` when unavailable)."""

    try:
        from backend import asset_cve_matching

        result = asset_cve_matching.build_matches(cve=str(cve_id))
    except Exception:
        return []
    items = result.get("items") if isinstance(result, Mapping) else None
    return [dict(item) for item in _mapping_items(items)]


def _item(
    hypothesis_ref: str, requirement_kind: str, ref: str, fact: str
) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": requirement_kind,
        "effect": EFFECT_PROVIDES,
        "source": SOURCE_WATCH_DERIVED,
        "evidence_ref": ref,
        "observations": [{"ref": ref, "fact": fact}],
    }


def build_completion_items(
    case: object,
    cve_id: object,
    match_items: object,
) -> tuple[list[dict], dict]:
    """Genuine case-bound evidence items for one program/CVE context.

    Only explicit matcher rows for the case program and CVE produce items;
    everything else is reported as a bounded unavailable reason. The first
    case hypothesis ref is the deterministic binding (the requirement is
    plan-level and shared by all case hypotheses).
    """

    block = _block(case)
    program = _text(block.get("program"), 64)
    cve = _upper(cve_id)
    hypothesis_refs = _bounded_refs(
        block.get("hypothesis_refs"), limit=1
    )
    hypothesis_ref = _text(
        hypothesis_refs[0] if hypothesis_refs else "", MAX_HYPOTHESIS_REF_CHARS
    )
    unavailable: dict[str, str] = {
        kind: "NO_MATCHING_OBSERVATION" for kind in REQUIREMENT_ORDER
    }
    for kind in HUMAN_ONLY_REQUIREMENTS:
        unavailable[kind] = "HUMAN_REVIEW_ONLY"
    if not program or not cve or not hypothesis_ref:
        return [], unavailable

    items: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def emit(kind: str, ref: str, fact: str) -> None:
        safe_ref = _text(ref, MAX_REF_CHARS)
        safe_fact = _text(fact, MAX_FACT_CHARS)
        if not safe_ref or not safe_fact:
            return
        signature = (kind, safe_ref)
        if signature in seen:
            return
        seen.add(signature)
        items.append(_item(hypothesis_ref, kind, safe_ref, safe_fact))
        unavailable.pop(kind, None)

    for row in _mapping_items(match_items):
        if _text(row.get("program"), 64) != program:
            continue
        if _upper(row.get("cve_id")) != cve:
            continue
        for match in _mapping_items(row.get("all_matches")):
            match_type = _upper(match.get("match_type"))
            value = _text(match.get("matched_value"), 128)
            if not value:
                continue
            match_id = _text(match.get("match_id"), 64)
            confidence = _upper(match.get("confidence")) or "NONE"
            identity = (
                f"R30.1 match {match_id} confidence {confidence}"
                if match_id
                else f"R30.1 match confidence {confidence}"
            )
            if match_type == MATCH_TYPE_TECHNOLOGY:
                emit(
                    REQUIREMENT_TECHNOLOGY_IDENTITY,
                    f"technology:{value}",
                    f"observed technology {value} from stored program "
                    f"{program} inventory (Http.tech); {identity} for {cve}",
                )
            elif match_type == MATCH_TYPE_VERSION:
                emit(
                    REQUIREMENT_VERSION_IDENTITY,
                    f"version:{value}",
                    f"observed version {value} from stored program {program} "
                    f"technology inventory; {identity} for {cve}",
                )
            elif match_type in (MATCH_TYPE_COMPONENT, MATCH_TYPE_PLUGIN):
                if match_id:
                    emit(
                        REQUIREMENT_COMPONENT_BINDING,
                        f"record:{match_id}",
                        f"observed {match_type.lower()} {value} matched in "
                        f"program {program}; {identity} component binding "
                        f"for {cve}",
                    )

    items.sort(key=lambda item: (item["requirement_kind"], item["evidence_ref"]))
    return items[:MAX_ITEMS], unavailable


# ---------------------------------------------------------------------------
# Evidence identity and provenance accumulation (persistence composition)
# ---------------------------------------------------------------------------


def _record_signature(record: Mapping) -> tuple:
    refs = _bounded_refs(record.get("evidence_refs"), limit=MAX_ITEMS)
    if not refs:
        single = _text(record.get("evidence_ref"), MAX_REF_CHARS)
        refs = [single] if single else []
    return (
        _text(record.get("hypothesis_ref"), MAX_HYPOTHESIS_REF_CHARS),
        _upper(record.get("requirement_kind")),
        _upper(record.get("effect")),
        tuple(sorted(refs)),
    )


def _item_signature(item: Mapping) -> tuple:
    refs = [
        _text(entry.get("ref"), MAX_REF_CHARS)
        for entry in _mapping_items(item.get("observations"))
    ]
    refs = [ref for ref in refs if ref]
    return (
        _text(item.get("hypothesis_ref"), MAX_HYPOTHESIS_REF_CHARS),
        _upper(item.get("requirement_kind")),
        _upper(item.get("effect")),
        tuple(sorted(refs)),
    )


def _recorded_signatures(provenance: object) -> set[tuple]:
    signatures: set[tuple] = set()
    for record in _mapping_items(_block(provenance).get("records")):
        signature = _record_signature(record)
        if signature[0] and signature[1]:
            signatures.add(signature)
    return signatures


def _accumulated_provenance(previous: object, current: Mapping) -> dict:
    """Append one round's provenance records, preserving earlier rounds."""

    records = [
        dict(record)
        for record in _mapping_items(_block(previous).get("records"))
    ] + [dict(record) for record in _mapping_items(current.get("records"))]
    records = records[-MAX_RECORDS:]
    for position, record in enumerate(records, start=1):
        record["provenance_id"] = f"PR{position}"

    conflicts = [
        dict(conflict)
        for conflict in _mapping_items(_block(previous).get("conflicts"))
    ] + [dict(conflict) for conflict in _mapping_items(current.get("conflicts"))]
    conflicts = conflicts[-MAX_CONFLICTS:]

    state_bands = {state: 0 for state in PROVENANCE_STATES}
    relation_bands = {relation: 0 for relation in RELATIONSHIPS}
    for record in records:
        state = _upper(record.get("provenance_state"))
        if state in state_bands:
            state_bands[state] += 1
        relation = _upper(record.get("relation_to_previous"))
        if relation in relation_bands:
            relation_bands[relation] += 1

    provenance = {
        key: value
        for key, value in current.items()
        if key not in ("records", "conflicts", "summary")
    }
    provenance["records"] = records
    provenance["conflicts"] = conflicts
    provenance["summary"] = {
        "rule_version": _text(current.get("rule_version"), 32),
        "record_count": len(records),
        "complete_provenance": state_bands.get("COMPLETE", 0),
        "partial_provenance": state_bands.get("PARTIAL", 0),
        "missing_provenance": state_bands.get("MISSING", 0),
        "invalid_provenance": state_bands.get("INVALID", 0),
        "conflict_count": len(conflicts),
        "human_review_required": any(
            bool(record.get("human_review_required")) for record in records
        ),
        "state_bands": state_bands,
        "relation_bands": relation_bands,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }
    return provenance


# ---------------------------------------------------------------------------
# Artifact persistence (same atomic pattern as R86)
# ---------------------------------------------------------------------------


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, dest)


def load_case_artifact(case_path: object) -> dict:
    """Read one persisted R86/R87 case artifact (fail closed)."""

    path = Path(case_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CaseEvidenceError(
            REASON_MALFORMED_ARTIFACT, "case artifact is not readable"
        ) from None
    if not isinstance(payload, Mapping):
        raise CaseEvidenceError(
            REASON_MALFORMED_ARTIFACT, "case artifact is not an object"
        )
    return dict(payload)


def _extract_case(artifact: Mapping, expected_case_id: str) -> tuple[dict, dict]:
    workspace = _block(artifact.get("research_case_workspace"))
    cases = _mapping_items(workspace.get("cases"))
    if not cases:
        raise CaseEvidenceError(
            REASON_MALFORMED_ARTIFACT, "case workspace is missing"
        )
    case = dict(cases[0])
    case_id = _text(case.get("case_id"), 96)
    if not case_id or not _CASE_ID_RE.match(case_id):
        raise CaseEvidenceError(
            REASON_MALFORMED_ARTIFACT, "case identity is invalid"
        )
    if expected_case_id and case_id != expected_case_id:
        raise CaseEvidenceError(
            REASON_CASE_ID_MISMATCH,
            "case id does not match the requested case",
        )
    if not _text(case.get("program"), 64):
        raise CaseEvidenceError(REASON_PROGRAM_MISSING, "program is missing")
    return case, workspace


# ---------------------------------------------------------------------------
# Completion runner
# ---------------------------------------------------------------------------


def _outcome() -> dict:
    return {
        "rule_version": RULE_VERSION,
        "status": STATUS_ERROR,
        "reason": "",
        "detail": "",
        "case_id": "",
        "program": "",
        "cve_id": "",
        "case_path": "",
        "before_status": "",
        "after_status": "",
        "eligible_items": 0,
        "replayed_items": 0,
        "accepted_items": 0,
        "rejected_items": 0,
        "rejection_codes": [],
        "submitted_evidence": [],
        "unavailable_requirements": {},
        "available_requirement_kinds": [],
        "missing_requirement_kinds": [],
        "readiness": {},
        "feedback": {},
        "provenance": {},
        "written": False,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def complete_case_evidence(
    case_path: object,
    *,
    expected_case_id: str = "",
    match_loader: MatchLoader | None = None,
    write: bool = False,
) -> dict:
    """Run one real evidence-completion round for one persisted case.

    Builds only genuinely supported evidence items, submits them through the
    R80 boundary, re-evaluates through R74/R75/R72/R73, updates the case
    through R76/R77 and (only with ``write``) persists one atomic artifact
    update. Never forces a case status.
    """

    outcome = _outcome()
    path = Path(case_path)
    outcome["case_path"] = path.name
    try:
        artifact = load_case_artifact(path)
        case, workspace = _extract_case(artifact, expected_case_id)
    except CaseEvidenceError as exc:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = exc.code
        outcome["detail"] = exc.safe_message
        return outcome
    except Exception as exc:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    case_id = _text(case.get("case_id"), 96)
    program = _text(case.get("program"), 64)
    result = _block(artifact.get("result"))
    cve_id = _upper(result.get("cve_id"))
    outcome["case_id"] = case_id
    outcome["program"] = program
    outcome["cve_id"] = cve_id
    outcome["before_status"] = _upper(case.get("status"))
    if not cve_id:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = REASON_CVE_MISSING
        return outcome

    stages = {
        key: _block(artifact.get(key))
        for key in ("action_plan", "acquisition_plan", "readiness_plan")
    }
    if any(not stage for stage in stages.values()):
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = REASON_STAGE_MISSING
        return outcome
    action_plan = stages["action_plan"]
    acquisition_plan = stages["acquisition_plan"]
    readiness_plan = stages["readiness_plan"]
    iteration_plan = _block(artifact.get("iteration_plan"))
    hypotheses = _block(artifact.get("research")).get("hypotheses")
    previous_provenance = _block(artifact.get("evidence_provenance"))

    loader = match_loader or default_match_loader
    try:
        match_items = loader(cve_id)
    except Exception:
        match_items = []
    items, unavailable = build_completion_items(case, cve_id, match_items)
    outcome["unavailable_requirements"] = dict(sorted(unavailable.items()))
    if not items:
        outcome["status"] = STATUS_NO_EVIDENCE
        outcome["reason"] = REASON_NO_ITEMS
        return outcome

    recorded = _recorded_signatures(previous_provenance)
    replay = [item for item in items if _item_signature(item) in recorded]
    fresh = [item for item in items if _item_signature(item) not in recorded]
    outcome["eligible_items"] = len(items)
    outcome["replayed_items"] = len(replay)
    if not fresh:
        outcome["status"] = STATUS_REPLAYED
        outcome["reason"] = REASON_ALL_REPLAYED
        return outcome

    outcome["submitted_evidence"] = [
        {
            "hypothesis_ref": _text(item.get("hypothesis_ref"), 16),
            "requirement_kind": _text(item.get("requirement_kind"), 64),
            "evidence_ref": _text(item.get("evidence_ref"), MAX_REF_CHARS),
        }
        for item in fresh[:MAX_ITEMS]
    ]

    submission = {
        "submission_version": SUBMISSION_VERSION,
        "case_ref": case_id,
        "submitted_by": SUBMITTER_LABEL,
        "items": fresh[:MAX_ITEMS],
    }
    try:
        submitted = submit_research_evidence(
            submission,
            case=case,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
    except Exception as exc:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    intake = submitted.get("intake")
    if not isinstance(intake, Mapping):
        outcome["status"] = STATUS_REJECTED
        outcome["reason"] = REASON_BOUNDARY_REJECTED
        for entry in _mapping_items(submitted.get("rejections")):
            code = _text(entry.get("code"), 64)
            if code and code not in outcome["rejection_codes"]:
                outcome["rejection_codes"].append(code)
        return outcome

    accepted = _mapping_items(intake.get("accepted_items"))
    intake_rejections = _mapping_items(intake.get("rejections"))
    package_rejections = _mapping_items(intake.get("package_rejections"))
    outcome["accepted_items"] = len(accepted)
    outcome["rejected_items"] = len(intake_rejections) + len(
        package_rejections
    )
    for entry in intake_rejections + package_rejections:
        code = _text(entry.get("code"), 64)
        if code and code not in outcome["rejection_codes"]:
            outcome["rejection_codes"].append(code)
    if not accepted:
        outcome["status"] = STATUS_REJECTED
        outcome["reason"] = REASON_BOUNDARY_REJECTED
        return outcome

    try:
        provenance = analyze_evidence_provenance(
            intake,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            previous_provenance=previous_provenance,
        )
    except Exception as exc:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome
    accumulated = _accumulated_provenance(previous_provenance, provenance)

    reevaluation = _block(intake.get("reevaluation"))
    new_acquisition = _block(reevaluation.get("acquisition_after"))
    new_readiness = _block(reevaluation.get("readiness_after"))
    new_iteration = _block(reevaluation.get("feedback"))
    if not new_acquisition or not new_readiness or not new_iteration:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = REASON_STAGE_MISSING
        return outcome

    try:
        updated_case = update_research_case(
            case,
            action_plan,
            new_acquisition,
            new_readiness,
            new_iteration,
            evidence_intake=intake,
            evidence_provenance=accumulated,
        )
        workbench = build_research_workbench(
            updated_case,
            action_plan=action_plan,
            acquisition_plan=new_acquisition,
            evidence_provenance=accumulated,
            limit=MAX_WORKBENCH_HISTORY,
        )
    except Exception as exc:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = _text(type(exc).__name__, 64)
        return outcome

    outcome["after_status"] = _upper(updated_case.get("status"))
    evidence = _block(updated_case.get("evidence"))
    outcome["available_requirement_kinds"] = _bounded_refs(
        evidence.get("available_requirement_kinds")
    )
    outcome["missing_requirement_kinds"] = _bounded_refs(
        evidence.get("missing_requirement_kinds")
    )
    readiness = _block(updated_case.get("readiness"))
    outcome["readiness"] = {
        "sufficiency_state": _upper(readiness.get("sufficiency_state")),
        "decision_state": _upper(readiness.get("decision_state")),
        "blocking_codes": _bounded_refs(readiness.get("blocking_codes")),
    }
    feedback = _block(updated_case.get("feedback"))
    outcome["feedback"] = {
        "feedback_state": _upper(feedback.get("feedback_state")),
        "hypothesis_state": _upper(feedback.get("hypothesis_state")),
        "next_iteration": _upper(feedback.get("next_iteration")),
        "reason": _upper(feedback.get("reason")),
    }
    provenance_summary = _block(accumulated.get("summary"))
    outcome["provenance"] = {
        "package_status": _upper(provenance.get("package_status")),
        "record_count": int(provenance_summary.get("record_count") or 0),
        "conflict_count": int(provenance_summary.get("conflict_count") or 0),
        "human_review_required": bool(
            provenance_summary.get("human_review_required")
        ),
    }

    updated_artifact = dict(artifact)
    updated_artifact["acquisition_plan"] = new_acquisition
    updated_artifact["readiness_plan"] = new_readiness
    updated_artifact["iteration_plan"] = new_iteration
    updated_artifact["evidence_intake"] = intake
    updated_artifact["evidence_provenance"] = accumulated
    updated_workspace = dict(workspace)
    updated_workspace["cases"] = [updated_case]
    updated_workspace["summary"] = summarize_research_cases([updated_case])
    updated_artifact["research_case_workspace"] = updated_workspace
    updated_artifact["research_workbench"] = workbench
    updated_artifact["evidence_completion"] = {
        "rule_version": RULE_VERSION,
        "status": STATUS_COMPLETED,
        "accepted_items": len(accepted),
        "replayed_items": len(replay),
        "requirement_kinds": sorted(
            {
                _upper(item.get("requirement_kind"))
                for item in accepted
                if item.get("requirement_kind")
            }
        ),
        "missing_requirement_kinds": list(
            outcome["missing_requirement_kinds"]
        ),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }

    outcome["status"] = STATUS_COMPLETED
    if not write:
        return outcome
    try:
        _atomic_write_text(
            path,
            json.dumps(
                updated_artifact, ensure_ascii=False, indent=2, sort_keys=True
            ),
        )
    except OSError:
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = REASON_WRITE_FAILED
        return outcome
    outcome["written"] = True
    return outcome


__all__ = [
    "RULE_VERSION",
    "DEFAULT_CASES_DIR",
    "SUBMITTER_LABEL",
    "MAX_ITEMS",
    "REQUIREMENT_TECHNOLOGY_IDENTITY",
    "REQUIREMENT_VERSION_IDENTITY",
    "REQUIREMENT_COMPONENT_BINDING",
    "REQUIREMENT_ORDER",
    "HUMAN_ONLY_REQUIREMENTS",
    "STATUS_COMPLETED",
    "STATUS_REPLAYED",
    "STATUS_NO_EVIDENCE",
    "STATUS_REJECTED",
    "STATUS_ERROR",
    "COMPLETION_STATUSES",
    "REASON_MALFORMED_ARTIFACT",
    "REASON_CASE_ID_MISMATCH",
    "REASON_PROGRAM_MISSING",
    "REASON_CVE_MISSING",
    "REASON_STAGE_MISSING",
    "REASON_NO_ITEMS",
    "REASON_ALL_REPLAYED",
    "REASON_BOUNDARY_REJECTED",
    "REASON_WRITE_FAILED",
    "COMPLETION_REASONS",
    "CaseEvidenceError",
    "default_match_loader",
    "build_completion_items",
    "load_case_artifact",
    "complete_case_evidence",
]

"""backend/research_cases.py — Stage R81/R89 researcher research-case service.

Presentation/service glue for the researcher-facing contract:

    LIST CASES     -> bounded case summaries from persisted research artifacts
    GET CASE       -> R77 workbench (R77 remains the workbench authority)
                      + R91 acquisition ledger + R95 evidence request projection
    SUBMIT EVIDENCE-> R80 submission boundary -> R74 intake -> R75 provenance
                      -> R76 case update -> R77 workbench (in-memory preview)
    SUBMIT HUMAN   -> R89 controlled human evidence: the same R80 boundary and
                      authorities, persisted atomically through the existing
                      R89 case-update path (opt-in route; the R81 preview
                      route and its in-memory contract are unchanged)

Authority boundaries (unchanged):

- R77 is the workbench authority: this module only calls
  ``build_research_workbench`` and never re-implements its logic.
- R80 is the evidence submission authority: the API calls
  ``submit_research_evidence`` and never calls R74 directly.
- R74/R75/R76 remain intake/provenance/case-state authorities; this module
  composes them and duplicates none of their rules.

Read-only by construction: listing/detail only read persisted artifacts. The
R81 evidence submission is fully in-memory (no Mongo, no artifact writes, no
persistence layer). The R89 human-evidence route delegates to the existing
R89 module, which owns the single atomic case-artifact write; this module
contains no write primitives of its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ai.knowledge.research_acquisition_ledger import (
    AcquisitionLedgerError,
    build_acquisition_portfolio,
    build_case_acquisition_ledger,
)
from ai.knowledge.research_case_workspace import (
    summarize_research_case,
    update_research_case,
)
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_case_evidence_package import (
    EvidencePackageError,
    build_case_evidence_package,
)
from ai.knowledge.research_evidence_request import (
    EvidenceRequestError,
    build_case_evidence_request,
)
from ai.knowledge.research_evidence_submission import (
    ERROR_CASE_MISMATCH,
    ERROR_CASE_REF_REQUIRED,
    ERROR_CASE_STATE_UNAVAILABLE,
    ERROR_EXECUTION_CONTENT,
    ERROR_HYPOTHESIS_NOT_IN_CASE,
    ERROR_MALFORMED_ENVELOPE,
    ERROR_SENSITIVE_SUBMISSION,
    ERROR_SUBMISSION_TOO_LARGE,
    ERROR_SUBMITTER_NOT_ALLOWED,
    ERROR_UNKNOWN_CASE,
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
    ERROR_UNSUPPORTED_SUBMISSION_VERSION,
    submit_research_evidence,
)
from ai.knowledge.research_workbench import build_research_workbench

RULE_VERSION = "r81-1"
HUMAN_RULE_VERSION = "r89-1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = PROJECT_ROOT / "ai_data" / "research"

MAX_CASES = 32
MAX_HISTORY = 8
MAX_TEXT_CHARS = 320

STAGE_KEYS: tuple[str, ...] = (
    "action_plan",
    "acquisition_plan",
    "readiness_plan",
    "iteration_plan",
    "evidence_provenance",
)

#: Boundary rejection code -> HTTP status (bounded, documented).
BOUNDARY_HTTP_STATUS: dict[str, int] = {
    ERROR_MALFORMED_ENVELOPE: 400,
    ERROR_UNSUPPORTED_SUBMISSION_VERSION: 400,
    ERROR_CASE_REF_REQUIRED: 400,
    ERROR_UNKNOWN_CASE: 404,
    ERROR_CASE_MISMATCH: 409,
    ERROR_CASE_STATE_UNAVAILABLE: 422,
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE: 400,
    ERROR_HYPOTHESIS_NOT_IN_CASE: 400,
    ERROR_SUBMITTER_NOT_ALLOWED: 400,
    ERROR_SENSITIVE_SUBMISSION: 400,
    ERROR_EXECUTION_CONTENT: 400,
    ERROR_SUBMISSION_TOO_LARGE: 413,
}

#: R89 human-boundary rejection code -> HTTP status (bounded, documented).
HUMAN_EVIDENCE_HTTP_STATUS: dict[str, int] = {
    "MALFORMED_SUBMISSION": 400,
    "SUBMISSION_TOO_LARGE": 413,
    "NON_HUMAN_SOURCE": 400,
    "UNSUPPORTED_DETERMINISTIC_REF": 409,
}

BOUNDARY_MESSAGES: dict[str, str] = {
    ERROR_MALFORMED_ENVELOPE: "submission envelope is malformed",
    ERROR_UNSUPPORTED_SUBMISSION_VERSION: "unsupported submission version",
    ERROR_CASE_REF_REQUIRED: "case_ref is required",
    ERROR_UNKNOWN_CASE: "unknown case",
    ERROR_CASE_MISMATCH: "submission case_ref does not match the target case",
    ERROR_CASE_STATE_UNAVAILABLE: "case state is unavailable",
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE: (
        "requirement does not belong to this case"
    ),
    ERROR_HYPOTHESIS_NOT_IN_CASE: "hypothesis does not belong to this case",
    ERROR_SUBMITTER_NOT_ALLOWED: "submitter label is not allowed",
    ERROR_SENSITIVE_SUBMISSION: "submission contains sensitive evidence",
    ERROR_EXECUTION_CONTENT: "submission contains execution content",
    ERROR_SUBMISSION_TOO_LARGE: "submission exceeds the bounded size",
    "MALFORMED_SUBMISSION": "human submission envelope is malformed",
    "SUBMISSION_TOO_LARGE": "human submission exceeds the bounded size",
    "NON_HUMAN_SOURCE": (
        "human evidence must use the existing HUMAN_REVIEW source"
    ),
    "UNSUPPORTED_DETERMINISTIC_REF": (
        "claimed Watch-deterministic reference is not in the case projection"
    ),
    "INTERNAL_PROCESSING_FAILURE": "internal processing failure",
}


class CaseServiceError(Exception):
    """Bounded, secret-free service failure for the API layer."""

    def __init__(self, code: str, *, http_status: int = 400) -> None:
        self.code = str(code)
        self.http_status = int(http_status)
        self.message = BOUNDARY_MESSAGES.get(self.code, "request rejected")
        super().__init__(f"{self.code}: {self.message}")


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


# ---------------------------------------------------------------------------
# Artifact discovery (read-only; deterministic ordering)
# ---------------------------------------------------------------------------


def _artifact_paths() -> list[Path]:
    root = Path(ARTIFACT_ROOT)
    if not root.is_dir():
        return []
    return sorted(
        path
        for path in root.glob("*/*.json")
        if path.is_file()
    )


def _load_entry(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if not isinstance(payload, Mapping):
        return None
    workspace = _block(payload.get("research_case_workspace"))
    cases = _mapping_items(workspace.get("cases"))
    if not cases:
        return None
    for key in ("action_plan", "acquisition_plan", "readiness_plan"):
        if not isinstance(payload.get(key), Mapping):
            return None
    entry = {
        "artifact_path": str(path),
        "program": _text(payload.get("program")),
        "source": _text(payload.get("source")),
        "research_run_version": _text(payload.get("research_run_version")),
        "result_cve": _text(_block(payload.get("result")).get("cve_id")),
        "limitations": [
            _text(item)
            for item in (payload.get("limitations") or ())
            if _text(item)
        ][:8],
        "case": dict(cases[0]),
        "hypotheses": list(
            _block(payload.get("research")).get("hypotheses") or ()
        ),
        "stages": {
            "action_plan": dict(_block(payload.get("action_plan"))),
            "acquisition_plan": dict(
                _block(payload.get("acquisition_plan"))
            ),
            "readiness_plan": dict(_block(payload.get("readiness_plan"))),
            "iteration_plan": dict(_block(payload.get("iteration_plan"))),
            "evidence_provenance": dict(
                _block(payload.get("evidence_provenance"))
            ),
            "evidence_intake": dict(
                _block(payload.get("evidence_intake"))
            ),
            "evidence_completion": dict(
                _block(payload.get("evidence_completion"))
            ),
            "evidence_acquisition": dict(
                _block(payload.get("evidence_acquisition"))
            ),
        },
    }
    return entry


def case_entries() -> list[dict]:
    """All bounded case entries, deduped by case_id (first path wins)."""

    entries: list[dict] = []
    seen: set[str] = set()
    for path in _artifact_paths():
        loaded = _load_entry(path)
        if loaded is None:
            continue
        case_id = _text(loaded["case"].get("case_id"))
        if not case_id or case_id in seen:
            continue
        seen.add(case_id)
        entries.append(loaded)
        if len(entries) >= MAX_CASES:
            break
    return entries


def get_case_entry(case_id: object) -> dict | None:
    wanted = _text(case_id)
    if not wanted:
        return None
    for entry in case_entries():
        if _text(entry["case"].get("case_id")) == wanted:
            return entry
    return None


# ---------------------------------------------------------------------------
# Read-only views
# ---------------------------------------------------------------------------


def _case_summary(entry: Mapping) -> dict:
    case = _block(entry.get("case"))
    summary = summarize_research_case(case)
    evidence = _block(case.get("evidence"))
    return {
        "case_id": _text(case.get("case_id")),
        "program": _text(case.get("program")),
        "category": _text(case.get("category")),
        "gap_id": _text(case.get("gap_id")),
        "status": _text(summary.get("status")),
        "readiness": _text(summary.get("sufficiency_state")),
        "decision": _text(summary.get("decision_state")),
        "feedback": _text(summary.get("feedback_state")),
        "hypothesis_state": _text(summary.get("hypothesis_state")),
        "next_iteration": _text(summary.get("next_iteration")),
        "human_review_required": bool(
            summary.get("human_review_required")
        ),
        "evidence": {
            "available_count": int(summary.get("available_count") or 0),
            "missing_count": int(summary.get("missing_count") or 0),
            "decision_missing_count": int(
                summary.get("decision_missing_count") or 0
            ),
            "available_requirement_kinds": [
                _text(kind)
                for kind in evidence.get("available_requirement_kinds") or ()
            ],
        },
        "missing_evidence": {
            "decision_critical": [
                _text(kind)
                for kind in _block(case.get("readiness")).get(
                    "blocking_codes"
                )
                or ()
            ]
        },
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def list_cases() -> dict:
    """Bounded case list for the researcher dashboard."""

    entries = case_entries()
    return {
        "rule_version": RULE_VERSION,
        "total": len(entries),
        "items": [_case_summary(entry) for entry in entries],
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _case_acquisition_ledger(entry: Mapping) -> dict | None:
    """R91 acquisition ledger for one entry (None when unavailable)."""

    stages = _block(entry.get("stages"))
    try:
        return build_case_acquisition_ledger(
            entry.get("case"),
            acquisition_plan=stages.get("acquisition_plan"),
            readiness_plan=stages.get("readiness_plan"),
            evidence_provenance=stages.get("evidence_provenance"),
            evidence_completion=stages.get("evidence_completion"),
            evidence_acquisition=stages.get("evidence_acquisition"),
        )
    except AcquisitionLedgerError:
        return None


def acquisition_portfolio() -> dict:
    """R91 read-only acquisition ledger portfolio over persisted cases."""

    ledgers: list[dict] = []
    for entry in case_entries():
        ledger = _case_acquisition_ledger(entry)
        if ledger is not None:
            ledgers.append(ledger)
    return build_acquisition_portfolio(ledgers)


def _case_evidence_request(
    entry: Mapping, workbench: object = None, ledger: object = None
) -> dict | None:
    """R95 deterministic human evidence request for one entry.

    Read-only projection of the unchanged R95 engine over the same R91
    ledger and R77 workbench already exposed for the case. Returns ``None``
    when the request is unavailable (fail closed): the case detail remains
    readable and no request is fabricated.
    """

    if ledger is None:
        ledger = _case_acquisition_ledger(entry)
    if ledger is None:
        return None
    try:
        return build_case_evidence_request(
            entry.get("case"),
            ledger,
            workbench=workbench,
            source_cve=_text(entry.get("result_cve")),
        )
    except EvidenceRequestError:
        return None


def _case_evidence_package(
    entry: Mapping, workbench: Mapping, ledger: object = None
) -> dict | None:
    """R99 human-reviewable evidence package for one entry.

    Read-only projection of the persisted R76 case, R70 outcomes, R75
    provenance and R91 acquisition state. Returns ``None`` on any failure
    (fail closed); nothing is fabricated and no confirmation is implied.
    """

    stages = _block(entry.get("stages"))
    try:
        return build_case_evidence_package(
            entry.get("case"),
            action_plan=stages.get("action_plan"),
            evidence_provenance=stages.get("evidence_provenance"),
            limitations=entry.get("limitations"),
            acquisition_ledger=ledger,
            human_review=_block(workbench).get("human_review"),
            source_cve=entry.get("result_cve"),
        )
    except EvidencePackageError:
        return None


def get_case_workbench(case_id: object) -> dict | None:
    """R77 workbench for one case (R77 remains the workbench authority).

    The response also carries the R91 acquisition ledger projection, the R95
    deterministic evidence request and the R99 human-reviewable evidence
    package (all read-only; ``None`` when unavailable). No submission is
    triggered, no evidence is fabricated and no confirmation is implied.
    """

    entry = get_case_entry(case_id)
    if entry is None:
        return None
    stages = _block(entry.get("stages"))
    workbench = build_research_workbench(
        entry["case"],
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        evidence_provenance=stages.get("evidence_provenance"),
        limit=MAX_HISTORY,
    )
    ledger = _case_acquisition_ledger(entry)
    return {
        "rule_version": RULE_VERSION,
        "workbench_rule_version": _text(workbench.get("workbench_version")),
        "case_id": _text(entry["case"].get("case_id")),
        "program": _text(entry["program"]),
        "artifact_path": _text(entry.get("artifact_path")),
        "case_summary": _case_summary(entry),
        "workbench": workbench,
        "acquisition_ledger": ledger,
        "evidence_request": _case_evidence_request(entry, workbench, ledger),
        "evidence_package": _case_evidence_package(entry, workbench, ledger),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


# ---------------------------------------------------------------------------
# Evidence submission (R80 boundary + composed authorities)
# ---------------------------------------------------------------------------


def _submission_rejection_code(result: Mapping) -> str:
    for entry in _block(result).get("rejections") or ():
        if isinstance(entry, Mapping) and entry.get("code"):
            return _text(entry.get("code"))
    return ERROR_MALFORMED_ENVELOPE


def _bounded_submission_response(
    case_id: str, submitted: Mapping, provenance: Mapping
) -> dict:
    intake = _block(submitted.get("intake"))
    rejected_codes = [
        _text(entry.get("code"))
        for entry in intake.get("rejections") or ()
        if isinstance(entry, Mapping)
    ]
    accepted_items = _mapping_items(intake.get("accepted_items"))
    conflicts = _mapping_items(_block(provenance).get("conflicts"))
    records = _mapping_items(_block(provenance).get("records"))
    conflicting_kinds: list[str] = []
    for conflict in conflicts:
        kind = _text(conflict.get("requirement_kind"))
        if kind and kind not in conflicting_kinds:
            conflicting_kinds.append(kind)
    return {
        "rule_version": RULE_VERSION,
        "case_id": case_id,
        "submission_status": _text(submitted.get("status")),
        "accepted_external_evidence": int(
            intake.get("accepted_external_evidence") or 0
        ),
        "rejected_items": len(rejected_codes),
        "rejection_codes": rejected_codes,
        "accepted_requirement_kinds": [
            _text(item.get("requirement_kind"))
            for item in accepted_items
            if item.get("requirement_kind")
        ],
        "provenance": {
            "state": _text(_block(provenance).get("package_status")),
            "record_count": len(records),
            "conflict_count": len(conflicts),
            "conflicting_requirement_kinds": conflicting_kinds[:8],
            "human_review_required": any(
                bool(record.get("human_review_required"))
                for record in records
            )
            or bool(conflicts),
        },
        "safety": dict(_block(submitted.get("safety"))),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def submit_case_evidence(case_id: object, submission: object) -> dict:
    """Handle one evidence submission: R80 -> R74 -> R75 -> R76 -> R77."""

    wanted = _text(case_id)
    entry = get_case_entry(wanted)
    if entry is None:
        raise CaseServiceError(ERROR_UNKNOWN_CASE, http_status=404)

    body = dict(submission) if isinstance(submission, Mapping) else submission
    if not isinstance(body, Mapping):
        raise CaseServiceError(ERROR_MALFORMED_ENVELOPE, http_status=400)
    body_case_ref = _text(body.get("case_ref"))
    if not body_case_ref:
        raise CaseServiceError(ERROR_CASE_REF_REQUIRED, http_status=400)
    if body_case_ref != wanted:
        raise CaseServiceError(ERROR_CASE_MISMATCH, http_status=409)

    stages = _block(entry.get("stages"))
    case = entry["case"]
    submitted = submit_research_evidence(
        body,
        case=case,
        hypotheses=entry.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
    )
    if submitted.get("intake") is None:
        code = _submission_rejection_code(submitted)
        raise CaseServiceError(
            code, http_status=BOUNDARY_HTTP_STATUS.get(code, 400)
        )

    intake = submitted["intake"]
    provenance = analyze_evidence_provenance(
        intake,
        hypotheses=entry.get("hypotheses"),
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        readiness_plan=stages.get("readiness_plan"),
        previous_provenance=stages.get("evidence_provenance"),
    )
    updated_case = update_research_case(
        case,
        stages.get("action_plan"),
        stages.get("acquisition_plan"),
        stages.get("readiness_plan"),
        stages.get("iteration_plan"),
        evidence_intake=intake,
        evidence_provenance=provenance,
    )
    workbench = build_research_workbench(
        updated_case,
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        evidence_provenance=provenance,
        limit=MAX_HISTORY,
    )
    response = _bounded_submission_response(wanted, submitted, provenance)
    response["case_summary"] = summarize_research_case(updated_case)
    response["workbench"] = workbench
    return response


# ---------------------------------------------------------------------------
# Controlled human evidence submission (Stage R89; persisted)
# ---------------------------------------------------------------------------


def _bounded_human_response(
    case_id: str, outcome: Mapping, entry: Mapping
) -> dict:
    """Bounded public result of one persisted human submission."""

    provenance = _block(outcome.get("provenance"))
    accepted = _mapping_items(outcome.get("submitted_evidence"))
    codes: list[str] = []
    for code in outcome.get("rejection_codes") or ():
        text = _text(code)
        if text and text not in codes:
            codes.append(text)
    return {
        "rule_version": HUMAN_RULE_VERSION,
        "case_id": case_id,
        "submission_status": _text(outcome.get("status")),
        "accepted_external_evidence": int(
            outcome.get("accepted_items") or 0
        ),
        "replayed_items": int(outcome.get("replayed_items") or 0),
        "rejected_items": int(outcome.get("rejected_items") or 0),
        "rejection_codes": codes[:8],
        "accepted_requirement_kinds": [
            _text(item.get("requirement_kind"))
            for item in accepted
            if item.get("requirement_kind")
        ],
        "provenance": {
            "state": _text(provenance.get("package_status")),
            "record_count": int(provenance.get("record_count") or 0),
            "conflict_count": int(provenance.get("conflict_count") or 0),
            "human_review_required": bool(
                provenance.get("human_review_required")
            ),
        },
        "persistence": {
            "written": bool(outcome.get("written")),
            "artifact_path": _text(entry.get("artifact_path")),
        },
        "safety": {
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
            "execution_performed": False,
            "exploit_authorized": False,
            "human_authority_required": True,
            "vulnerability_confirmed": False,
        },
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def submit_human_case_evidence(case_id: object, submission: object) -> dict:
    """R89: persist one controlled human evidence submission for one case.

    The route is opt-in and additive: the R81 in-memory preview contract is
    unchanged. Every item must use the existing ``HUMAN_REVIEW`` source and
    may only claim Watch-deterministic references that the existing R30.1
    projection actually contains; the R89 module owns the single atomic
    case-artifact write.
    """

    wanted = _text(case_id)
    entry = get_case_entry(wanted)
    if entry is None:
        raise CaseServiceError(ERROR_UNKNOWN_CASE, http_status=404)

    body = dict(submission) if isinstance(submission, Mapping) else submission
    if not isinstance(body, Mapping):
        raise CaseServiceError(ERROR_MALFORMED_ENVELOPE, http_status=400)
    body_case_ref = _text(body.get("case_ref"))
    if not body_case_ref:
        raise CaseServiceError(ERROR_CASE_REF_REQUIRED, http_status=400)
    if body_case_ref != wanted:
        raise CaseServiceError(ERROR_CASE_MISMATCH, http_status=409)

    from ai.research_agent.case_evidence import (
        submit_human_case_evidence as _submit_human_evidence,
    )

    outcome = _submit_human_evidence(
        entry["artifact_path"],
        body,
        expected_case_id=wanted,
        write=True,
    )
    status = _text(outcome.get("status"))
    if status == "ERROR":
        raise CaseServiceError(
            "INTERNAL_PROCESSING_FAILURE", http_status=500
        )
    if status == "REJECTED":
        code = ""
        for candidate in outcome.get("rejection_codes") or ():
            text = _text(candidate)
            if text:
                code = text
                break
        code = code or _text(outcome.get("reason")) or ERROR_MALFORMED_ENVELOPE
        raise CaseServiceError(
            code,
            http_status=BOUNDARY_HTTP_STATUS.get(
                code, HUMAN_EVIDENCE_HTTP_STATUS.get(code, 400)
            ),
        )

    after = get_case_entry(wanted) or entry
    stages = _block(after.get("stages"))
    workbench = build_research_workbench(
        after["case"],
        action_plan=stages.get("action_plan"),
        acquisition_plan=stages.get("acquisition_plan"),
        evidence_provenance=stages.get("evidence_provenance"),
        limit=MAX_HISTORY,
    )
    response = _bounded_human_response(wanted, outcome, after)
    response["case_summary"] = _case_summary(after)
    response["workbench"] = workbench
    return response


__all__ = [
    "RULE_VERSION",
    "HUMAN_RULE_VERSION",
    "ARTIFACT_ROOT",
    "MAX_CASES",
    "MAX_HISTORY",
    "BOUNDARY_HTTP_STATUS",
    "HUMAN_EVIDENCE_HTTP_STATUS",
    "BOUNDARY_MESSAGES",
    "CaseServiceError",
    "case_entries",
    "get_case_entry",
    "list_cases",
    "get_case_workbench",
    "acquisition_portfolio",
    "submit_case_evidence",
    "submit_human_case_evidence",
]

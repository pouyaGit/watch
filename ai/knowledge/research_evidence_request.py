"""Stage R95 — deterministic case-bound human evidence request (pure engine).

Turns the R91 acquisition ledger's ``PROVIDE_EVIDENCE`` state into a bounded,
operator-facing request that is submittable through the existing R80/R89
human evidence boundary. The engine:

- consumes only existing authorities: the R76 case, the R91 acquisition
  ledger (requirement statuses, attempts, remaining sources, next action) and
  the optional persisted R77 workbench (missing-requirement descriptions,
  expected result, stopping condition);
- binds every requestable requirement to the only remaining authorized
  acquisition source (``HUMAN_REVIEW``) and states the permitted evidence
  contract, provenance requirements, safety boundary and completion
  condition;
- emits a submission-ready R80 envelope *template* whose items carry empty
  references and observations: the operator must fill in real human-reviewed
  facts. Nothing is fabricated, inferred or auto-submitted;
- is deterministic, idempotent, fail-closed and free of I/O, network, Mongo,
  LLM, subprocess, clock or randomness.

The request never authorizes execution, never confirms a vulnerability and
never bypasses the R80/R89 boundary or the R92/R93 case-aware scheduler.
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from ai.knowledge.research_acquisition_ledger import (
    ACTION_PROVIDE_EVIDENCE,
    SOURCE_HUMAN_REVIEW,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_ATTEMPTED_UNRESOLVED,
    STATUS_HUMAN_REQUIRED,
)
from ai.knowledge.research_workbench import WORKFLOW_ACTIONS

RULE_VERSION = "r95-1"

REQUEST_STATE_REQUIRED = "EVIDENCE_REQUESTED"
REQUEST_STATE_NONE = "NO_REQUEST"
REQUEST_STATES: tuple[str, ...] = (REQUEST_STATE_REQUIRED, REQUEST_STATE_NONE)

ACQUISITION_TYPE_HUMAN_REVIEW = "HUMAN_REVIEW"
ENVELOPE_VERSION = "r80-1"
REQUEST_ITEM_SOURCE = SOURCE_HUMAN_REVIEW
REQUEST_ITEM_EFFECT = "PROVIDES"

MAX_ITEMS = 8
MAX_TEXT_CHARS = 320
MAX_HYPOTHESES = 8
MAX_ATTEMPTS = 6

ERROR_MALFORMED_CASE = "MALFORMED_CASE"
ERROR_MALFORMED_LEDGER = "MALFORMED_LEDGER"
ERROR_CONTRADICTORY_CASE = "CONTRADICTORY_CASE"
ERROR_UNKNOWN_NEXT_ACTION = "UNKNOWN_NEXT_ACTION"

EVIDENCE_REQUEST_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_LEDGER,
    ERROR_CONTRADICTORY_CASE,
    ERROR_UNKNOWN_NEXT_ACTION,
)

#: Requirement statuses that represent a blocked deterministic path and can
#: legitimately be handed to the human boundary (R91 vocabulary).
REQUESTABLE_STATUSES: tuple[str, ...] = (
    STATUS_HUMAN_REQUIRED,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_ATTEMPTED_UNRESOLVED,
)

#: Closed provenance contract for a human submission (mirrors R80/R89, no
#: new authority is created here).
PROVENANCE_REQUIREMENTS: tuple[str, ...] = (
    "source must be HUMAN_REVIEW (the only remaining authorized source for "
    "these requirements)",
    "each item needs a bounded evidence_ref plus at least one observation "
    "with a ref and a bounded fact",
    "record:/technology:/version: refs must already exist in the unchanged "
    "R30.1 projection for this case; arbitrary deterministic identities are "
    "rejected",
    "no URLs, IP addresses, Mongo ids, credentials, tokens or user-info in "
    "refs or facts",
    "no executable instructions, payloads or payload-adjacent content",
    "repeated submissions replay by signature and never duplicate evidence",
)

SAFETY_BOUNDARY: tuple[str, ...] = (
    "research-planning only: no target interaction, scanning, crawling, "
    "exploitation, fuzzing or browser automation",
    "human-reviewed facts only; model output is never submitted as human "
    "evidence",
    "the request is advisory; acceptance and evidence validation remain with "
    "the existing R80/R74 boundary",
    "no vulnerability is confirmed by this request or by any later submission",
)

DEFAULT_COMPLETION_TEMPLATE = (
    "accepted {kind} evidence is written through the existing R80 -> R74 -> "
    "R75 -> R72 -> R73 -> R76 path, the case readiness is recomputed and the "
    "R91 acquisition ledger is regenerated; next_action changes only when the "
    "remaining requirements close"
)


class EvidenceRequestError(ValueError):
    """Deterministic, secret-free R95 request failure (fail closed)."""

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


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _attempts_brief(value: object) -> list[dict]:
    out: list[dict] = []
    for entry in _mapping_items(value)[:MAX_ATTEMPTS]:
        source = _upper(entry.get("source"), 32)
        outcome = _upper(entry.get("outcome"), 64)
        if not source or not outcome:
            continue
        out.append(
            {
                "source": source,
                "outcome": outcome,
                "last_iteration": max(_int(entry.get("last_iteration")), 0),
                "count": max(_int(entry.get("count"), 1), 1),
            }
        )
    out.sort(key=lambda item: (item["source"], item["outcome"]))
    return out


def _description_map(workbench: object) -> dict[str, str]:
    out: dict[str, str] = {}
    missing = _block(_block(workbench).get("what_is_missing"))
    for entry in _mapping_items(missing.get("requirement_details")):
        kind = _upper(entry.get("requirement_kind"), 64)
        description = _text(entry.get("description"))
        if kind and description:
            out.setdefault(kind, description)
    return out


def _expected_output(kind: str, description: str) -> str:
    if description:
        return _text(f"a human-reviewed observation providing {description}")
    return _text(f"a human-reviewed observation satisfying {kind}")


def _request_ref(case_id: str, kinds: list[str]) -> str:
    digest = hashlib.sha256(
        "|".join([RULE_VERSION, case_id, ",".join(sorted(kinds))]).encode(
            "utf-8"
        )
    ).hexdigest()
    return "r95-" + digest[:16]


def build_case_evidence_request(
    case: object,
    acquisition_ledger: object,
    *,
    workbench: object = None,
    source_cve: object = "",
    max_items: int = MAX_ITEMS,
) -> dict:
    """One deterministic, bounded human evidence request for one R76 case.

    Raises :class:`EvidenceRequestError` (fail closed) when the case identity,
    ledger identity, ledger next action or ledger requirement list is
    missing, malformed or contradictory. Returns ``request_state =
    NO_REQUEST`` when the ledger's next action is not ``PROVIDE_EVIDENCE``.
    """

    block = _block(case)
    case_id = _text(block.get("case_id"), 96)
    if not case_id:
        raise EvidenceRequestError(ERROR_MALFORMED_CASE, "case_id is required")
    case_status = _upper(block.get("status"), 40)
    if not case_status:
        raise EvidenceRequestError(ERROR_MALFORMED_CASE, "case status is required")

    ledger = _block(acquisition_ledger)
    if not ledger:
        raise EvidenceRequestError(
            ERROR_MALFORMED_LEDGER, "acquisition ledger is required"
        )
    ledger_case_id = _text(ledger.get("case_id"), 96)
    if not ledger_case_id:
        raise EvidenceRequestError(
            ERROR_MALFORMED_LEDGER, "ledger case_id is required"
        )
    if ledger_case_id != case_id:
        raise EvidenceRequestError(
            ERROR_CONTRADICTORY_CASE,
            "ledger case_id does not match the case",
        )
    next_action = _upper(ledger.get("next_action"), 40)
    if next_action not in WORKFLOW_ACTIONS:
        raise EvidenceRequestError(
            ERROR_UNKNOWN_NEXT_ACTION,
            "ledger next action is not in the R77 vocabulary",
        )

    raw_requirements = ledger.get("requirements")
    if raw_requirements is None:
        raw_requirements = []
    if not isinstance(raw_requirements, (list, tuple)):
        raise EvidenceRequestError(
            ERROR_MALFORMED_LEDGER, "ledger requirements are malformed"
        )
    requirements = [
        entry for entry in raw_requirements if isinstance(entry, Mapping)
    ]

    hypothesis_refs = _bounded_list(
        block.get("hypothesis_refs"), MAX_HYPOTHESES, 64
    )
    descriptions = _description_map(workbench)
    missing = _block(_block(workbench).get("what_is_missing"))
    expected_result = _text(missing.get("expected_result"))
    stopping_condition = _text(missing.get("stopping_condition"))

    cap = max(int(max_items), 0)
    items: list[dict] = []
    if next_action == ACTION_PROVIDE_EVIDENCE:
        for entry in requirements:
            if len(items) >= cap:
                break
            kind = _upper(entry.get("requirement_kind"), 64)
            status = _upper(entry.get("status"), 40)
            if not kind or status not in REQUESTABLE_STATUSES:
                continue
            remaining = _bounded_list(
                entry.get("remaining_sources"), 4, 32
            )
            if ACQUISITION_TYPE_HUMAN_REVIEW not in remaining:
                continue
            description = descriptions.get(kind, "")
            items.append(
                {
                    "requirement_kind": kind,
                    "requirement_class": _upper(
                        entry.get("requirement_class"), 32
                    ),
                    "status": status,
                    "offline_exhausted": bool(
                        entry.get("offline_exhausted")
                    ),
                    "remaining_sources": remaining,
                    "acquisition_type": ACQUISITION_TYPE_HUMAN_REVIEW,
                    "description": description,
                    "attempts": _attempts_brief(entry.get("attempts")),
                    "expected_output": _expected_output(kind, description),
                    "completion_condition": _text(
                        stopping_condition
                        or DEFAULT_COMPLETION_TEMPLATE.format(kind=kind)
                    ),
                    "hypothesis_refs": list(hypothesis_refs),
                    "submission_item": {
                        "hypothesis_ref": "",
                        "requirement_kind": kind,
                        "source": REQUEST_ITEM_SOURCE,
                        "effect": REQUEST_ITEM_EFFECT,
                        "evidence_ref": "",
                        "observations": [],
                    },
                }
            )

    envelope = None
    if items:
        envelope = {
            "submission_version": ENVELOPE_VERSION,
            "case_ref": case_id,
            "submitted_by": "",
            "items": [dict(item["submission_item"]) for item in items],
            "template": True,
            "evidence_included": False,
            "note": (
                "combined template only: fill in a real human-reviewed "
                "evidence_ref and at least one observation (ref + fact) for "
                "every item you submit, and delete the items you are not "
                "submitting; never submit fabricated or model-generated facts"
            ),
        }
        for item in items:
            item["submission_envelope"] = {
                "submission_version": ENVELOPE_VERSION,
                "case_ref": case_id,
                "submitted_by": "",
                "items": [dict(item["submission_item"])],
                "template": True,
                "evidence_included": False,
                "note": (
                    "single-requirement template: fill in a real "
                    "human-reviewed evidence_ref and at least one observation "
                    "(ref + fact); never submit fabricated or model-generated "
                    "facts"
                ),
            }

    kinds = [item["requirement_kind"] for item in items]
    return {
        "rule_version": RULE_VERSION,
        "request_ref": _request_ref(case_id, kinds),
        "request_state": (
            REQUEST_STATE_REQUIRED if items else REQUEST_STATE_NONE
        ),
        "case_id": case_id,
        "program": _text(block.get("program"), 64),
        "cve_id": _upper(source_cve, 32),
        "case_status": case_status,
        "next_action": next_action,
        "human_action_required": True,
        "offline_sources_exhausted": bool(
            ledger.get("offline_sources_exhausted")
        ),
        "hypothesis_refs": list(hypothesis_refs),
        "requirement_count": len(items),
        "requirements": items,
        "submission_envelope": envelope,
        "submission_boundary": {
            "boundary": "R80/R89 human evidence submission",
            "submission_version": ENVELOPE_VERSION,
            "cli": (
                "agent human-evidence --case <case_id> --file <envelope.json>"
            ),
        },
        "expected_result": expected_result,
        "stopping_condition": stopping_condition,
        "provenance_requirements": list(PROVENANCE_REQUIREMENTS),
        "safety_boundary": list(SAFETY_BOUNDARY),
        "reason": (
            ""
            if items
            else f"next action is {next_action}; no human evidence request is required"
        ),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
        "human_authority_required": True,
    }


__all__ = [
    "RULE_VERSION",
    "REQUEST_STATE_REQUIRED",
    "REQUEST_STATE_NONE",
    "REQUEST_STATES",
    "ACQUISITION_TYPE_HUMAN_REVIEW",
    "ENVELOPE_VERSION",
    "REQUEST_ITEM_SOURCE",
    "REQUEST_ITEM_EFFECT",
    "MAX_ITEMS",
    "REQUESTABLE_STATUSES",
    "PROVENANCE_REQUIREMENTS",
    "SAFETY_BOUNDARY",
    "ERROR_MALFORMED_CASE",
    "ERROR_MALFORMED_LEDGER",
    "ERROR_CONTRADICTORY_CASE",
    "ERROR_UNKNOWN_NEXT_ACTION",
    "EVIDENCE_REQUEST_ERROR_CODES",
    "EvidenceRequestError",
    "build_case_evidence_request",
]

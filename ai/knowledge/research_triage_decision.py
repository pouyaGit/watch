"""Stage R100 — case-bound human triage decision boundary (pure engine).

Records one explicit, attributable human triage decision on one R99
``RESEARCH_EVIDENCE_PACKAGE`` for one R76 research case:

- the decision vocabulary, rationale vocabulary, escalation targets and
  non-authorized codes are reused verbatim from the existing R56 human
  decision schema (no parallel vocabulary);
- the decision is bound to the case identity and to the exact evidence
  package that was reviewed (deterministic package fingerprint), so a stale
  decision can never silently apply to newer evidence;
- authority is forced to ``HUMAN`` / ``ADVISORY`` server-side and all
  execution/confirmation/exploit flags are forced ``False``; the R56
  ``authority_rejection`` guard is applied defensively;
- the record is deterministic (content-derived ``hdc-`` reference; no clock,
  randomness, LLM, network or environment dependence); timestamps are
  optional inputs supplied by the persistence layer, never read here.

This is an authority record, not a case state change: case status,
readiness, confirmation and acquisition state are untouched.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from ai.knowledge.human_decision_rules import authority_rejection
from ai.schemas.human_decision import (
    AI_ROLE_ADVISORY,
    DECISION_AUTHORITY_HUMAN,
    DECISION_ESCALATE,
    DECISION_SOURCE_HUMAN,
    ESCALATION_TARGET_UNKNOWN,
    ESCALATION_TARGETS,
    HUMAN_DECISION_LIMITATIONS,
    HUMAN_DECISION_TYPES,
    HUMAN_RATIONALE_CODES,
    NOT_AUTHORIZED_CODES,
    RATIONALE_NOT_PROVIDED,
    RATIONALE_STATE_NOT_PROVIDED,
    RATIONALE_STATE_PROVIDED,
)

RULE_VERSION = "r100-1"

PACKAGE_TYPE_REQUIRED = "RESEARCH_EVIDENCE_PACKAGE"
PACKAGE_FINGERPRINT_PREFIX = "r99p-"
DECISION_REF_PREFIX = "hdc-"

MAX_TEXT_CHARS = 320
MAX_BY_CHARS = 64
MAX_NOTE_CHARS = 512

DECISION_STATUS_NOT_DECIDED = "NOT_DECIDED"
DECISION_STATUS_CURRENT = "CURRENT"
DECISION_STATUS_STALE = "STALE"
DECISION_STATUS_INVALID = "INVALID"

DECISION_STALENESS_STATES: tuple[str, ...] = (
    DECISION_STATUS_NOT_DECIDED,
    DECISION_STATUS_CURRENT,
    DECISION_STATUS_STALE,
    DECISION_STATUS_INVALID,
)

ERROR_MALFORMED_CASE = "MALFORMED_CASE"
ERROR_MALFORMED_PACKAGE = "MALFORMED_PACKAGE"
ERROR_CONTRADICTORY_CASE = "CONTRADICTORY_CASE"
ERROR_UNKNOWN_DECISION = "UNKNOWN_DECISION"
ERROR_UNKNOWN_RATIONALE = "UNKNOWN_RATIONALE"
ERROR_MISSING_HUMAN_AUTHORITY = "MISSING_HUMAN_AUTHORITY"
ERROR_AUTOMATED_AUTHORITY = "AUTOMATED_AUTHORITY"
ERROR_UNKNOWN_ESCALATION_TARGET = "UNKNOWN_ESCALATION_TARGET"

CASE_TRIAGE_DECISION_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_PACKAGE,
    ERROR_CONTRADICTORY_CASE,
    ERROR_UNKNOWN_DECISION,
    ERROR_UNKNOWN_RATIONALE,
    ERROR_MISSING_HUMAN_AUTHORITY,
    ERROR_AUTOMATED_AUTHORITY,
    ERROR_UNKNOWN_ESCALATION_TARGET,
)

_SENSITIVE_RE = re.compile(
    r"(?i)(://|token|secret|password|api[_-]?key|bearer)"
)


class CaseTriageDecisionError(ValueError):
    """Deterministic, secret-free R100 decision failure (fail closed)."""

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


def _canonical(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def package_fingerprint(package: object) -> str:
    """Deterministic identity of one R99 evidence package (reviewed state)."""

    block = _block(package)
    if not block or not _text(block.get("case")):
        raise CaseTriageDecisionError(
            ERROR_MALFORMED_PACKAGE, "evidence package is required"
        )
    if _upper(block.get("package_type")) != PACKAGE_TYPE_REQUIRED:
        raise CaseTriageDecisionError(
            ERROR_MALFORMED_PACKAGE, "package type is not an evidence package"
        )
    digest = hashlib.sha256(_canonical(block).encode("utf-8")).hexdigest()
    return PACKAGE_FINGERPRINT_PREFIX + digest[:16]


def _decision_ref(payload: Mapping) -> str:
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    return DECISION_REF_PREFIX + digest[:16]


def _reviewed_state(package: Mapping) -> dict:
    package_case = _block(package.get("case"))
    decision = _block(package.get("decision"))
    hypotheses = package.get("hypotheses")
    if not isinstance(hypotheses, (list, tuple)):
        hypotheses = ()
    return {
        "reviewed_case_status": _upper(package_case.get("status"), 40),
        "reviewed_decision_state": _upper(decision.get("decision_state"), 40),
        "reviewed_sufficiency_state": _upper(
            decision.get("sufficiency_state"), 40
        ),
        "reviewed_missing_count": int(decision.get("missing_count") or 0),
        "reviewed_hypothesis_count": len(hypotheses),
    }


def build_case_triage_decision(
    case: object,
    package: object,
    *,
    decision: object,
    decided_by: object,
    rationale_code: object = "",
    rationale_note: object = "",
    escalation_target: object = "",
    decided_at: object = "",
) -> dict:
    """One explicit, case-bound, package-bound human triage decision.

    Raises :class:`CaseTriageDecisionError` (fail closed) for malformed or
    contradictory inputs, unknown vocabulary, missing human authority or any
    automated authority signal. No case state is modified.
    """

    case_block = _block(case)
    case_id = _text(case_block.get("case_id"), 96)
    if not case_id:
        raise CaseTriageDecisionError(ERROR_MALFORMED_CASE, "case_id is required")

    package_block = _block(package)
    fingerprint = package_fingerprint(package_block)
    package_case_id = _text(
        _block(package_block.get("case")).get("case_id"), 96
    )
    if not package_case_id or package_case_id != case_id:
        raise CaseTriageDecisionError(
            ERROR_CONTRADICTORY_CASE,
            "package case_id does not match the case",
        )

    decision_value = _upper(decision, 40)
    if decision_value not in HUMAN_DECISION_TYPES:
        raise CaseTriageDecisionError(
            ERROR_UNKNOWN_DECISION, "decision is not in the R56 vocabulary"
        )

    rationale_value = _upper(rationale_code, 64)
    if not rationale_value:
        rationale_value = RATIONALE_NOT_PROVIDED
        rationale_state = RATIONALE_STATE_NOT_PROVIDED
    elif rationale_value in HUMAN_RATIONALE_CODES:
        rationale_state = RATIONALE_STATE_PROVIDED
    else:
        raise CaseTriageDecisionError(
            ERROR_UNKNOWN_RATIONALE,
            "rationale is not in the R56 vocabulary",
        )

    operator = _text(decided_by, MAX_BY_CHARS)
    if not operator:
        raise CaseTriageDecisionError(
            ERROR_MISSING_HUMAN_AUTHORITY,
            "an explicit human authority label is required",
        )
    if _SENSITIVE_RE.search(operator):
        raise CaseTriageDecisionError(
            ERROR_MISSING_HUMAN_AUTHORITY,
            "human authority label must be a bounded non-sensitive label",
        )

    target = ""
    if decision_value == DECISION_ESCALATE:
        target = _upper(escalation_target, 64) or ESCALATION_TARGET_UNKNOWN
        if target not in ESCALATION_TARGETS:
            raise CaseTriageDecisionError(
                ERROR_UNKNOWN_ESCALATION_TARGET,
                "escalation target is not in the R56 vocabulary",
            )

    note = _text(rationale_note, MAX_NOTE_CHARS)
    identity = {
        "rule_version": RULE_VERSION,
        "case_id": case_id,
        "decision": decision_value,
        "rationale_code": rationale_value,
        "rationale_note": note,
        "decided_by": operator,
        "escalation_target": target,
        "reviewed_package_fingerprint": fingerprint,
    }
    record = {
        "rule_version": RULE_VERSION,
        "decision_ref": _decision_ref(identity),
        "case_id": case_id,
        "decision": decision_value,
        "rationale_code": rationale_value,
        "rationale_state": rationale_state,
        "rationale_note": note,
        "escalation_target": target,
        "decided_by": operator,
        "decided_at": _text(decided_at, 40),
        "decision_source": DECISION_SOURCE_HUMAN,
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "reviewed_package_fingerprint": fingerprint,
        **_reviewed_state(package_block),
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "not_authorized": list(NOT_AUTHORIZED_CODES),
        "human_authority_required": True,
        "limitations": list(HUMAN_DECISION_LIMITATIONS),
        "advisory": True,
        "research_only": True,
    }
    rejection = authority_rejection(record)
    if rejection:
        raise CaseTriageDecisionError(ERROR_AUTOMATED_AUTHORITY, rejection)
    return record


def decision_signature(record: object) -> tuple:
    """Replay identity: content-derived ref + reviewed fingerprint + authority."""

    block = _block(record)
    return (
        _text(block.get("decision_ref"), 32),
        _text(block.get("reviewed_package_fingerprint"), 32),
        _text(block.get("decided_by"), MAX_BY_CHARS),
        _upper(block.get("decision"), 40),
    )


def evaluate_case_triage_decision(
    record: object, package: object
) -> dict:
    """CURRENT/STALE/INVALID/NOT_DECIDED evaluation against a package."""

    block = _block(record)
    if not block:
        return {
            "status": DECISION_STATUS_NOT_DECIDED,
            "decision": "",
            "decision_ref": "",
            "reviewed_package_fingerprint": "",
            "current_package_fingerprint": "",
        }
    try:
        current = package_fingerprint(package)
    except CaseTriageDecisionError:
        current = ""
    decision_ref = _text(block.get("decision_ref"), 32)
    reviewed = _text(block.get("reviewed_package_fingerprint"), 32)
    if (
        not decision_ref
        or not reviewed
        or _upper(block.get("decision_source")) != DECISION_SOURCE_HUMAN
        or _upper(block.get("decision_authority")) != DECISION_AUTHORITY_HUMAN
        or _upper(block.get("decision")) not in HUMAN_DECISION_TYPES
    ):
        status = DECISION_STATUS_INVALID
    elif not current:
        # the current evidence package cannot be evaluated: fail closed
        status = DECISION_STATUS_INVALID
    elif reviewed == current:
        status = DECISION_STATUS_CURRENT
    else:
        status = DECISION_STATUS_STALE
    return {
        "status": status,
        "decision": _upper(block.get("decision"), 40),
        "decision_ref": decision_ref,
        "decided_by": _text(block.get("decided_by"), MAX_BY_CHARS),
        "decided_at": _text(block.get("decided_at"), 40),
        "rationale_code": _upper(block.get("rationale_code"), 64),
        "rationale_state": _upper(block.get("rationale_state"), 40),
        "rationale_note": _text(block.get("rationale_note"), MAX_NOTE_CHARS),
        "escalation_target": _upper(block.get("escalation_target"), 64),
        "reviewed_package_fingerprint": reviewed,
        "current_package_fingerprint": current,
        "reviewed_case_status": _upper(
            block.get("reviewed_case_status"), 40
        ),
        "reviewed_decision_state": _upper(
            block.get("reviewed_decision_state"), 40
        ),
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "PACKAGE_TYPE_REQUIRED",
    "PACKAGE_FINGERPRINT_PREFIX",
    "DECISION_REF_PREFIX",
    "DECISION_STATUS_NOT_DECIDED",
    "DECISION_STATUS_CURRENT",
    "DECISION_STATUS_STALE",
    "DECISION_STATUS_INVALID",
    "DECISION_STALENESS_STATES",
    "ERROR_MALFORMED_CASE",
    "ERROR_MALFORMED_PACKAGE",
    "ERROR_CONTRADICTORY_CASE",
    "ERROR_UNKNOWN_DECISION",
    "ERROR_UNKNOWN_RATIONALE",
    "ERROR_MISSING_HUMAN_AUTHORITY",
    "ERROR_AUTOMATED_AUTHORITY",
    "ERROR_UNKNOWN_ESCALATION_TARGET",
    "CASE_TRIAGE_DECISION_ERROR_CODES",
    "CaseTriageDecisionError",
    "package_fingerprint",
    "build_case_triage_decision",
    "decision_signature",
    "evaluate_case_triage_decision",
]

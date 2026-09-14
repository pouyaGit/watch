"""Stage R56.4 deterministic human-decision rules (pure engine).

Validates and builds the bounded human decision on one R55 priority plan:

    "What did the human decide should happen next, and why?"

Hard boundaries encoded here:

- Human authority only: a decision is a recorded research-workflow choice.
  Automated/AI authority, vulnerability confirmation, exploit authorization
  and execution authorization are rejected fail-closed and never applied.
- Recommendation preservation: the R55 recommendation is referenced
  read-only; nothing here mutates priority score, band or ranking.
- Rationale is data: closed rationale codes plus an optional bounded note
  sanitized as text; missing rationale becomes ``RATIONALE_NOT_PROVIDED``
  and is never invented.
- Records only: evidence requests and escalations are structured records;
  nothing is sent, collected, notified or executed.
- Deterministic: content-derived ids only; no timestamps, UUIDs, pids or
  randomness.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no database, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.schemas.human_decision import (
    AI_ROLE_ADVISORY,
    ALLOWED_TRANSITIONS,
    HUMAN_DECISION_LIMITATIONS,
    DECISION_AUTHORITY_HUMAN,
    DECISION_SOURCE_HUMAN,
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_PENDING,
    EVIDENCE_REQUEST_REASON_NOT_SPECIFIED,
    EVIDENCE_REQUEST_TYPES,
    EVIDENCE_REQUEST_UNKNOWN,
    ESCALATION_REASON_NOT_SPECIFIED,
    ESCALATION_TARGETS,
    ESCALATION_TARGET_UNKNOWN,
    HUMAN_DECISION_TYPES,
    LIMITATION_AI_ADVISORY_ONLY,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DECISION_HISTORY_PRESENT,
    LIMITATION_DECISION_RECORDED_ONLY,
    LIMITATION_DUPLICATE_PRESENT,
    LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY,
    LIMITATION_ESCALATION_RECORDED_ONLY,
    LIMITATION_EXECUTION_NOT_AUTHORIZED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM,
    LIMITATION_NOT_AUTHORIZED_LISTED,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_PENDING_HUMAN_DECISION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_RATIONALE_NOT_PROVIDED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_REVIEW_EXPIRED,
    LIMITATION_SAFETY_DEFERRED,
    OPTION_APPROVE_RESEARCH,
    OPTION_DEFER,
    OPTION_DISABLED_EXECUTION,
    OPTION_ESCALATE,
    OPTION_EXECUTION_PLACEHOLDER,
    OPTION_NEEDS_REVIEW,
    OPTION_REJECT,
    OPTION_REQUEST_MORE_EVIDENCE,
    RATIONALE_STATE_PROVIDED,
    TRANSITION_DECISION_SUPERSEDED,
    TRANSITION_INITIAL_DECISION,
    TRANSITION_REJECTED,
    TRANSITION_REVIEW_EXPIRED,
    sanitize_correlation_reference,
    sanitize_decision_options,
    sanitize_decision_rationale,
    sanitize_evidence_request,
    sanitize_escalation,
    sanitize_finding_reference,
    sanitize_human_audit,
    sanitize_human_decision,
    sanitize_priority_reference,
)
from ai.schemas.human_decision_result import (
    REJECTION_AUTOMATED_AUTHORITY,
    REJECTION_EXECUTION_AUTHORIZATION,
    REJECTION_EXPLOIT_AUTHORIZATION,
    REJECTION_INVALID_TRANSITION,
    REJECTION_MALFORMED_DECISION,
    REJECTION_MALFORMED_EVIDENCE_REFERENCE,
    REJECTION_UNKNOWN_DECISION,
    REJECTION_VULNERABILITY_CONFIRMATION,
)
from ai.schemas.human_review import (
    sanitize_human_review_plan,
    sanitize_review_transition,
)
from ai.schemas.research_audit_event import (
    AUDIT_UNKNOWN,
    AUDIT_VALID,
)
from ai.schemas.research_priority import (
    BAND_DEFERRED,
    CONFLICT_PRESENT,
)

HUMAN_DECISION_RULES_RULE_VERSION = "r56-4"
RULE_VERSION = HUMAN_DECISION_RULES_RULE_VERSION

MAX_HISTORY = 8
MAX_VALUE_LEN = 160
MAX_NOTE_LEN = 240

_AUTHORITY_KEYS = ("decision_source", "decision_authority", "ai_role")
_EXECUTION_KEYS = (
    "execution_authorized",
    "execute",
    "execution_allowed",
    "execution_authorization",
)
_CONFIRMATION_KEYS = (
    "vulnerability_confirmed",
    "confirmed",
    "is_vulnerable",
    "vulnerability_confirmation",
)
_EXPLOIT_KEYS = (
    "exploit_authorized",
    "exploit_authorization",
    "exploitation_authorized",
    "payload_authorized",
    "payload_authorization",
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_AI_ADVISORY_ONLY,
    LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM,
    LIMITATION_EXECUTION_NOT_AUTHORIZED,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_NOT_AUTHORIZED_LISTED,
    LIMITATION_DECISION_RECORDED_ONLY,
    LIMITATION_PRIORITY_PRESERVED,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _is_truthy(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().upper() in ("TRUE", "YES", "1")
    return False


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------


def decision_id(
    finding_id: str,
    prioritization_id: str,
    decision_type: str,
    rationale_codes: list[str],
    rationale_note: str,
    requested_evidence_type: str,
    escalation_target: str,
) -> str:
    """Deterministic content-derived decision id (no time, no random)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r56-1",
                "finding_id": finding_id,
                "prioritization_id": prioritization_id,
                "decision_type": decision_type,
                "rationale_codes": list(rationale_codes),
                "rationale_note": rationale_note,
                "requested_evidence_type": requested_evidence_type,
                "escalation_target": escalation_target,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "hdc-" + digest[:16]


def review_id(
    finding_id: str, prioritization_id: str, review_state: str
) -> str:
    """Deterministic content-derived review id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r56-2",
                "finding_id": finding_id,
                "prioritization_id": prioritization_id,
                "review_state": review_state,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "hrv-" + digest[:16]


def audit_id(finding_id: str, decision_type: str, audit_state: str) -> str:
    """Deterministic content-derived audit id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r56-2",
                "finding_id": finding_id,
                "decision_type": decision_type,
                "audit_state": audit_state,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "hda-" + digest[:16]


def batch_id(
    prioritization_id: str, review_order: list[str], review_ids: list[str]
) -> str:
    """Deterministic content-derived batch id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r56-2",
                "prioritization_id": prioritization_id,
                "review_order": list(review_order),
                "review_ids": list(review_ids),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "hrb-" + digest[:16]


def result_id(
    prioritization_id: str, review_ids: list[str], invalid_ids: list[str]
) -> str:
    """Deterministic content-derived review-result id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r56-3",
                "prioritization_id": prioritization_id,
                "review_ids": list(review_ids),
                "invalid": list(invalid_ids),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "hrr-" + digest[:16]


# ---------------------------------------------------------------------------
# References from the immutable R55 plan
# ---------------------------------------------------------------------------


def priority_reference(
    plan: dict, prioritization_id: str, priority_rule_version: str = ""
) -> dict:
    """Build the immutable R55 recommendation reference (read-only)."""

    return sanitize_priority_reference(
        {
            "prioritization_id": prioritization_id,
            "priority_rule_version": priority_rule_version,
            "priority_score": plan.get("priority_score"),
            "priority_band": plan.get("priority_band"),
            "ranking_position": plan.get("ranking_position"),
            "priority_reasons": plan.get("priority_reasons"),
        }
    )


def finding_reference(plan: dict) -> dict:
    """Build the upstream finding reference (read-only)."""

    provenance = plan.get("provenance") or {}
    return sanitize_finding_reference(
        {
            "source_kind": provenance.get("source_kind"),
            "finding_rule_version": provenance.get("finding_rule_version"),
            "category": plan.get("category"),
            "agent_id": plan.get("agent_id"),
            "orchestration_id": provenance.get("orchestration_id"),
            "state": plan.get("state"),
            "confidence": plan.get("confidence"),
            "evidence_completeness": plan.get("evidence_completeness"),
            "severity": plan.get("severity"),
            "severity_source": plan.get("severity_source"),
            "impact_state": plan.get("impact_state"),
        }
    )


def correlation_reference(
    plan: dict, correlation_result: object = None
) -> dict:
    """Build the correlation context reference (read-only)."""

    summary = plan.get("correlation_summary") or {}
    conflict_state = _upper(plan.get("conflict_state")) or "UNKNOWN"
    correlation_id = ""
    rule_version = _text(
        (plan.get("provenance") or {}).get("correlation_rule_version")
    )
    if isinstance(correlation_result, dict):
        correlation_id = _text(correlation_result.get("correlation_id"))
        rule_version = _text(
            correlation_result.get("rule_version")
        ) or rule_version
    return sanitize_correlation_reference(
        {
            "correlation_id": correlation_id,
            "correlation_rule_version": rule_version,
            "conflict_state": conflict_state,
            "conflict_sources": summary.get("conflict_sources"),
            "relationship_types": summary.get("relationship_types"),
            "duplicate_present": "DUPLICATE"
            in (summary.get("relationship_types") or ()),
        }
    )


def decision_options() -> list[dict]:
    """Explicit workflow options; execution is never enabled."""

    return sanitize_decision_options(
        [
            {
                "option": OPTION_APPROVE_RESEARCH,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_REQUEST_MORE_EVIDENCE,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_DEFER,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_REJECT,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_ESCALATE,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_NEEDS_REVIEW,
                "enabled": True,
                "disabled_reason": "",
            },
            {
                "option": OPTION_EXECUTION_PLACEHOLDER,
                "enabled": False,
                "disabled_reason": OPTION_DISABLED_EXECUTION,
            },
        ]
    )


# ---------------------------------------------------------------------------
# Fail-closed validation
# ---------------------------------------------------------------------------


def authority_rejection(request: object) -> str:
    """Closed rejection reason for authority/authorization violations."""

    if not isinstance(request, dict):
        return REJECTION_MALFORMED_DECISION
    for key in _AUTHORITY_KEYS:
        if key not in request:
            continue
        text = _upper(request.get(key))
        if not text:
            continue
        if key == "ai_role" and text == AI_ROLE_ADVISORY:
            continue
        if key == "decision_source" and text == DECISION_SOURCE_HUMAN:
            continue
        if key == "decision_authority" and text == DECISION_AUTHORITY_HUMAN:
            continue
        return REJECTION_AUTOMATED_AUTHORITY
    for key in _EXECUTION_KEYS:
        if _is_truthy(request.get(key)):
            return REJECTION_EXECUTION_AUTHORIZATION
    for key in _CONFIRMATION_KEYS:
        if _is_truthy(request.get(key)):
            return REJECTION_VULNERABILITY_CONFIRMATION
    confirmation = _upper(request.get("confirmation_state"))
    if confirmation and confirmation != "NOT_CONFIRMED":
        return REJECTION_VULNERABILITY_CONFIRMATION
    for key in _EXPLOIT_KEYS:
        if _is_truthy(request.get(key)):
            return REJECTION_EXPLOIT_AUTHORIZATION
    return ""


def normalize_evidence_request(
    raw: object,
    finding_id: str,
    plan: dict,
    rationale: dict,
) -> tuple[dict, str]:
    """Validate/synthesize a bounded evidence request record (no collection)."""

    if raw is None:
        return (
            sanitize_evidence_request(
                {
                    "requested_evidence_type": EVIDENCE_REQUEST_UNKNOWN,
                    "source_finding_id": finding_id,
                    "reason": EVIDENCE_REQUEST_REASON_NOT_SPECIFIED,
                    "priority": plan.get("confidence"),
                    "originating_reference": "",
                }
            ),
            "",
        )
    if not isinstance(raw, dict):
        return {}, REJECTION_MALFORMED_EVIDENCE_REFERENCE
    request_type = _upper(raw.get("requested_evidence_type"))
    if request_type and request_type not in EVIDENCE_REQUEST_TYPES:
        return {}, REJECTION_MALFORMED_EVIDENCE_REFERENCE
    source_finding_id = _text(raw.get("source_finding_id")) or finding_id
    if not source_finding_id.startswith("fnd-"):
        return {}, REJECTION_MALFORMED_EVIDENCE_REFERENCE
    reason = _text(raw.get("reason")) or (
        rationale.get("rationale_codes") or [""]
    )[0]
    return (
        sanitize_evidence_request(
            {
                "requested_evidence_type": request_type
                or EVIDENCE_REQUEST_UNKNOWN,
                "source_finding_id": source_finding_id,
                "reason": reason or EVIDENCE_REQUEST_REASON_NOT_SPECIFIED,
                "priority": raw.get("priority") or plan.get("confidence"),
                "originating_reference": raw.get("originating_reference"),
            }
        ),
        "",
    )


def normalize_escalation(
    raw: object,
    finding_id: str,
    plan: dict,
    rationale: dict,
) -> tuple[dict, str]:
    """Validate/synthesize a bounded escalation record (no notification)."""

    if raw is None:
        return (
            sanitize_escalation(
                {
                    "escalation_target": ESCALATION_TARGET_UNKNOWN,
                    "reason": (rationale.get("rationale_codes") or [""])[0]
                    or ESCALATION_REASON_NOT_SPECIFIED,
                    "finding_id": finding_id,
                    "priority_band": plan.get("priority_band"),
                    "evidence_context": _evidence_context(plan),
                    "provenance": _escalation_provenance(plan),
                }
            ),
            "",
        )
    if not isinstance(raw, dict):
        return {}, REJECTION_MALFORMED_DECISION
    target = _upper(raw.get("escalation_target"))
    if target and target not in ESCALATION_TARGETS:
        return {}, REJECTION_UNKNOWN_DECISION
    return (
        sanitize_escalation(
            {
                "escalation_target": target or ESCALATION_TARGET_UNKNOWN,
                "reason": raw.get("reason")
                or (rationale.get("rationale_codes") or [""])[0]
                or ESCALATION_REASON_NOT_SPECIFIED,
                "finding_id": _text(raw.get("finding_id")) or finding_id,
                "priority_band": raw.get("priority_band")
                or plan.get("priority_band"),
                "evidence_context": raw.get("evidence_context")
                or _evidence_context(plan),
                "provenance": raw.get("provenance")
                or _escalation_provenance(plan),
            }
        ),
        "",
    )


def _evidence_context(plan: dict) -> str:
    summary = plan.get("correlation_summary") or {}
    completeness = _upper(plan.get("evidence_completeness")) or "UNKNOWN"
    state = _upper(plan.get("state")) or "UNKNOWN"
    conflict = _upper(plan.get("conflict_state")) or "UNKNOWN"
    relationships = len(summary.get("relationship_types") or ())
    parts = [
        f"evidence_completeness={completeness}",
        f"state={state}",
        f"conflict_state={conflict}",
        f"relationship_types={relationships}",
    ]
    return ";".join(parts)[:240]


def _escalation_provenance(plan: dict) -> dict:
    provenance = plan.get("provenance") or {}
    return {
        "prioritization_id": "",
        "correlation_id": "",
        "finding_rule_version": provenance.get("finding_rule_version"),
        "priority_rule_version": provenance.get("priority_rule_version"),
        "orchestration_id": provenance.get("orchestration_id"),
    }


# ---------------------------------------------------------------------------
# Audit and limitations
# ---------------------------------------------------------------------------


def evidence_references(
    decision_type: str, evidence_request: dict, escalation: dict
) -> list[str]:
    """Bounded audit references (recorded, never acted upon)."""

    refs: list[str] = []
    if decision_type == "REQUEST_MORE_EVIDENCE":
        request_type = _text(evidence_request.get("requested_evidence_type"))
        if request_type:
            refs.append(f"requested:{request_type}")
        source = _text(evidence_request.get("source_finding_id"))
        if source:
            refs.append(f"source:{source}")
    if decision_type == "ESCALATE":
        target = _text(escalation.get("escalation_target"))
        if target:
            refs.append(f"escalation:{target}")
    return refs[:8]


def _audit_state(review_state: str) -> str:
    if review_state == DECISION_STATE_DECIDED:
        return AUDIT_VALID
    return AUDIT_UNKNOWN


def build_audit(
    *,
    finding_id: str,
    plan: dict,
    decision_type: str,
    review_state: str,
    rationale: dict,
    evidence_references_value: list[str],
    governance: dict,
) -> dict:
    """Deterministic audit representation for one reviewed finding."""

    summary = plan.get("correlation_summary") or {}
    audit_state = _audit_state(review_state)
    return sanitize_human_audit(
        {
            "rule_version": "r56-2",
            "audit_id": audit_id(
                finding_id, decision_type, audit_state
            ),
            "finding_id": finding_id,
            "automated_recommendation": {
                "priority_band": plan.get("priority_band"),
                "priority_score": plan.get("priority_score"),
                "priority_reasons": plan.get("priority_reasons"),
            },
            "human_decision_type": decision_type,
            "human_decision_state": review_state,
            "decision_rationale_state": rationale.get("rationale_state"),
            "decision_rationale_codes": rationale.get("rationale_codes"),
            "evidence_references": evidence_references_value,
            "governance_state": (
                _upper(governance.get("reference_state")) or "UNKNOWN"
            ),
            "audit_state": audit_state,
        }
    )


def review_limitations(
    plan: dict,
    *,
    review_state: str,
    rationale: dict,
    decision_type: str,
    governance: dict,
    correlation_available: bool,
    history_present: bool,
) -> list[str]:
    """Deterministic, ordered limitations of one review."""

    found = set(_BASE_LIMITATIONS)
    if rationale.get("rationale_state") != RATIONALE_STATE_PROVIDED:
        found.add(LIMITATION_RATIONALE_NOT_PROVIDED)
    if decision_type == "REQUEST_MORE_EVIDENCE":
        found.add(LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY)
    if decision_type == "ESCALATE":
        found.add(LIMITATION_ESCALATION_RECORDED_ONLY)
    if plan.get("conflict_state") == CONFLICT_PRESENT:
        found.add(LIMITATION_CONFLICT_PRESENT)
    if "DUPLICATE" in (
        (plan.get("correlation_summary") or {}).get("relationship_types")
        or ()
    ):
        found.add(LIMITATION_DUPLICATE_PRESENT)
    if _upper(governance.get("reference_state")) != "REFERENCED":
        found.add(LIMITATION_GOVERNANCE_UNKNOWN)
    provenance = plan.get("provenance") or {}
    if not provenance.get("orchestration_id"):
        found.add(LIMITATION_PROVENANCE_INCOMPLETE)
    if not correlation_available:
        found.add(LIMITATION_CORRELATION_UNAVAILABLE)
    if review_state == DECISION_STATE_PENDING:
        found.add(LIMITATION_PENDING_HUMAN_DECISION)
    if review_state == DECISION_STATE_EXPIRED:
        found.add(LIMITATION_REVIEW_EXPIRED)
    if history_present:
        found.add(LIMITATION_DECISION_HISTORY_PRESENT)
    if _upper(plan.get("priority_band")) == BAND_DEFERRED:
        found.add(LIMITATION_SAFETY_DEFERRED)
    return [code for code in HUMAN_DECISION_LIMITATIONS if code in found]


# ---------------------------------------------------------------------------
# Decision and review construction
# ---------------------------------------------------------------------------


def build_decision(
    request: dict,
    *,
    finding_id: str,
    plan: dict,
    priority_reference_value: dict,
    correlation_reference_value: dict,
    finding_reference_value: dict,
    provenance_value: dict,
    governance: dict,
) -> tuple[dict, str]:
    """Validate one human decision request and build the decision payload.

    Returns ``(decision, rejection_reason)``; an empty rejection reason means
    the decision was accepted. Rejected requests are never repaired.
    """

    rejection = authority_rejection(request)
    if rejection:
        return {}, rejection
    decision_type = _upper(request.get("decision_type"))
    if decision_type not in HUMAN_DECISION_TYPES:
        return {}, REJECTION_UNKNOWN_DECISION
    rationale = sanitize_decision_rationale(
        {
            "rationale_codes": request.get("rationale_codes"),
            "rationale_note": request.get("rationale_note"),
        }
    )
    evidence_request: dict = {}
    escalation: dict = {}
    if decision_type == "REQUEST_MORE_EVIDENCE":
        evidence_request, error = normalize_evidence_request(
            request.get("evidence_request"), finding_id, plan, rationale
        )
        if error:
            return {}, error
    else:
        evidence_request = sanitize_evidence_request(None)
    if decision_type == "ESCALATE":
        escalation, error = normalize_escalation(
            request.get("escalation"), finding_id, plan, rationale
        )
        if error:
            return {}, error
    else:
        escalation = sanitize_escalation(None)
    decision_version = decision_id(
        finding_id,
        _text(priority_reference_value.get("prioritization_id")),
        decision_type,
        rationale.get("rationale_codes") or [],
        rationale.get("rationale_note") or "",
        _text(evidence_request.get("requested_evidence_type")),
        _text(escalation.get("escalation_target")),
    )
    audit = build_audit(
        finding_id=finding_id,
        plan=plan,
        decision_type=decision_type,
        review_state=DECISION_STATE_DECIDED,
        rationale=rationale,
        evidence_references_value=evidence_references(
            decision_type, evidence_request, escalation
        ),
        governance=governance,
    )
    limitations = review_limitations(
        plan,
        review_state=DECISION_STATE_DECIDED,
        rationale=rationale,
        decision_type=decision_type,
        governance=governance,
        correlation_available=bool(
            correlation_reference_value.get("correlation_id")
        )
        or bool(correlation_reference_value.get("correlation_rule_version")),
        history_present=False,
    )
    payload = {
        "rule_version": "r56-1",
        "decision_id": decision_version,
        "finding_id": finding_id,
        "decision_type": decision_type,
        "decision_state": DECISION_STATE_DECIDED,
        "decision_source": DECISION_SOURCE_HUMAN,
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "human_authority": True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "priority_reference": priority_reference_value,
        "correlation_reference": correlation_reference_value,
        "finding_reference": finding_reference_value,
        "rationale": rationale,
        "evidence_request": evidence_request,
        "escalation": escalation,
        "decision_options": decision_options(),
        "audit": audit,
        "provenance": provenance_value,
        "governance": governance,
        "limitations": limitations,
        "research_only": True,
        "deterministic": True,
    }
    return sanitize_human_decision(payload), ""


def decision_summary(decision: dict) -> dict:
    """Bounded decision summary used in history and batch records."""

    return {
        "decision_id": decision.get("decision_id"),
        "decision_type": decision.get("decision_type"),
        "decision_state": decision.get("decision_state"),
        "rationale_state": (decision.get("rationale") or {}).get(
            "rationale_state"
        ),
        "rationale_codes": (decision.get("rationale") or {}).get(
            "rationale_codes"
        )
        or [],
        "transition_reason": decision.get("transition_reason"),
    }


def transition_for(
    previous_state: str, requested_state: str, *, has_previous: bool
) -> dict:
    """Deterministic closed transition (invalid transitions fail closed)."""

    allowed = requested_state in ALLOWED_TRANSITIONS.get(
        previous_state, ()
    )
    if not allowed:
        reason = TRANSITION_REJECTED
    elif previous_state == DECISION_STATE_PENDING:
        reason = (
            TRANSITION_REVIEW_EXPIRED
            if requested_state == DECISION_STATE_EXPIRED
            else TRANSITION_INITIAL_DECISION
        )
    else:
        reason = TRANSITION_DECISION_SUPERSEDED
    return {
        "from_state": previous_state,
        "to_state": requested_state,
        "allowed": allowed,
        "transition_reason": reason,
    }


def build_review(
    *,
    finding_id: str,
    plan: dict,
    prioritization_id: str,
    correlation_reference_value: dict,
    provenance_value: dict,
    governance: dict,
    request: object = None,
    previous_review: object = None,
) -> tuple[dict, str]:
    """Build one review payload plus its accepted decision (read-only).

    Returns ``(review, rejection_reason)``; a rejection leaves the review
    pending and never applies or repairs the rejected request.
    """

    priority_ref = priority_reference(plan, prioritization_id)
    finding_ref = finding_reference(plan)
    previous_state = DECISION_STATE_PENDING
    history: list[dict] = []
    previous_decision_summary: dict = {}
    previous_decision: dict = {}
    if isinstance(previous_review, dict) and previous_review:
        previous_state = (
            _upper(previous_review.get("review_state"))
            or DECISION_STATE_PENDING
        )
        history = list(previous_review.get("decision_history") or ())
        if isinstance(previous_review.get("decision"), dict) and (
            previous_review.get("decision")
        ):
            previous_decision = previous_review["decision"]
            previous_decision_summary = decision_summary(previous_decision)
            previous_decision_summary["transition_reason"] = _text(
                (previous_review.get("transition") or {}).get(
                    "transition_reason"
                )
            )
            if previous_decision_summary not in history:
                history = history + [previous_decision_summary]

    request_dict = request if isinstance(request, dict) else {}
    expired = (
        _upper(request_dict.get("decision_state"))
        == DECISION_STATE_EXPIRED
    )
    rejection = ""
    decision: dict = {}
    transition = sanitize_review_transition(None)
    if request is not None and not isinstance(request, dict):
        rejection = REJECTION_MALFORMED_DECISION
    elif expired:
        transition = transition_for(
            previous_state,
            DECISION_STATE_EXPIRED,
            has_previous=bool(previous_review),
        )
        if not transition["allowed"]:
            rejection = REJECTION_INVALID_TRANSITION
    elif previous_review and request is None:
        transition = sanitize_review_transition(None)
        rejection = REJECTION_MALFORMED_DECISION
    else:
        transition = transition_for(
            previous_state,
            DECISION_STATE_DECIDED,
            has_previous=bool(previous_review),
        )
        if not transition["allowed"]:
            rejection = REJECTION_INVALID_TRANSITION
        elif request is not None:
            decision, rejection = build_decision(
                request_dict,
                finding_id=finding_id,
                plan=plan,
                priority_reference_value=priority_ref,
                correlation_reference_value=correlation_reference_value,
                finding_reference_value=finding_ref,
                provenance_value=provenance_value,
                governance=governance,
            )
    review_state = DECISION_STATE_PENDING
    if decision:
        review_state = DECISION_STATE_DECIDED
        decision["transition_reason"] = transition["transition_reason"]
    elif expired and not rejection:
        review_state = DECISION_STATE_EXPIRED
    rationale = (decision.get("rationale") if decision else None) or (
        sanitize_decision_rationale(None)
    )
    decision_type = _text(decision.get("decision_type")) if decision else ""
    limitations = review_limitations(
        plan,
        review_state=review_state,
        rationale=rationale,
        decision_type=decision_type,
        governance=governance,
        correlation_available=bool(
            correlation_reference_value.get("correlation_id")
        )
        or bool(correlation_reference_value.get("correlation_rule_version")),
        history_present=bool(history),
    )
    audit = build_audit(
        finding_id=finding_id,
        plan=plan,
        decision_type=decision_type,
        review_state=review_state,
        rationale=rationale,
        evidence_references_value=(
            evidence_references(
                decision_type,
                decision.get("evidence_request") or {},
                decision.get("escalation") or {},
            )
            if decision
            else []
        ),
        governance=governance,
    )
    review = {
        "rule_version": "r56-2",
        "review_id": review_id(
            finding_id, prioritization_id, review_state
        ),
        "finding_id": finding_id,
        "finding_reference": finding_ref,
        "priority_reference": priority_ref,
        "correlation_reference": correlation_reference_value,
        "review_state": review_state,
        "review_order": _bounded_int(plan.get("ranking_position"), 0, 24),
        "decision_options": decision_options(),
        "decision": decision,
        "previous_decision": previous_decision_summary,
        "decision_history": history[:MAX_HISTORY],
        "transition": transition,
        "audit": audit,
        "priority_immutable": True,
        "recommendation_preserved": True,
        "human_authority": True,
        "ai_role": AI_ROLE_ADVISORY,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "governance": governance,
        "provenance": provenance_value,
        "limitations": limitations,
        "research_only": True,
        "deterministic": True,
    }
    return sanitize_human_review_plan(review), rejection


__all__ = [
    "HUMAN_DECISION_RULES_RULE_VERSION",
    "RULE_VERSION",
    "decision_id",
    "review_id",
    "audit_id",
    "batch_id",
    "result_id",
    "priority_reference",
    "finding_reference",
    "correlation_reference",
    "decision_options",
    "authority_rejection",
    "normalize_evidence_request",
    "normalize_escalation",
    "evidence_references",
    "build_audit",
    "review_limitations",
    "build_decision",
    "decision_summary",
    "transition_for",
    "build_review",
]

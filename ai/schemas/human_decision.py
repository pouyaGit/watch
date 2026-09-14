"""Human decision schema (Stage R56.1).

Defines the bounded, deterministic human decision on one structured research
finding. It answers:

    "What did the human decide should happen next with this research
     finding, and why?"

Hard boundaries encoded here:

- Human decision only: a decision is a recorded research-workflow choice.
  It is never vulnerability confirmation, exploit authorization, execution
  authorization, payload authorization or attack authorization.
- Explicit authority: ``decision_source`` and ``decision_authority`` are
  forced ``HUMAN`` and ``ai_role`` is forced ``ADVISORY``; automated/AI
  authority is rejected. ``execution_authorized``, ``vulnerability_confirmed``
  and ``exploit_authorized`` are forced ``False`` and
  ``confirmation_state`` is forced ``NOT_CONFIRMED``.
- No execution: the schema represents no command, payload, request, scanner,
  browser, database or LLM call. Nothing is executed, sent or collected.
- Rationale is data: rationale codes are a closed vocabulary, the optional
  human note is bounded and sanitized as text, and it is never interpreted
  as an executable instruction. Missing rationale is represented explicitly
  as ``RATIONALE_NOT_PROVIDED`` and never invented.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ai.schemas.cve_research_context_analysis import (
    CVSS_SEVERITIES,
    CVSS_UNKNOWN,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_assessment import (
    CONFIRMATION_NOT_CONFIRMED,
    FINDING_STATES,
    IMPACT_STATES,
    SEVERITY_SOURCE_NOT_ASSESSED,
    SEVERITY_SOURCES,
)
from ai.schemas.finding_evidence import EVIDENCE_COMPLETENESS_LEVELS
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.research_priority import (
    BAND_DEFERRED,
    CONFLICT_STATES,
    CONFLICT_UNKNOWN,
    PRIORITY_BANDS,
    SOURCE_KINDS,
)
from ai.schemas.research_audit_event import (
    AUDIT_STATES,
    AUDIT_UNKNOWN,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

HUMAN_DECISION_RULE_VERSION = "r56-1"
RULE_VERSION = HUMAN_DECISION_RULE_VERSION

# ---------------------------------------------------------------------------
# Decision vocabulary (closed)
# ---------------------------------------------------------------------------

DECISION_APPROVE_RESEARCH = "APPROVE_RESEARCH"
DECISION_REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
DECISION_DEFER = "DEFER"
DECISION_REJECT = "REJECT"
DECISION_ESCALATE = "ESCALATE"
DECISION_NEEDS_REVIEW = "NEEDS_REVIEW"

HUMAN_DECISION_TYPES: tuple[str, ...] = (
    DECISION_APPROVE_RESEARCH,
    DECISION_REQUEST_MORE_EVIDENCE,
    DECISION_DEFER,
    DECISION_REJECT,
    DECISION_ESCALATE,
    DECISION_NEEDS_REVIEW,
)

DECISION_STATE_PENDING = "PENDING_HUMAN_REVIEW"
DECISION_STATE_DECIDED = "DECIDED"
DECISION_STATE_EXPIRED = "EXPIRED"
DECISION_STATE_INVALID = "INVALID"

HUMAN_DECISION_STATES: tuple[str, ...] = (
    DECISION_STATE_PENDING,
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_INVALID,
)

# ---------------------------------------------------------------------------
# Authority vocabulary (closed; automated authority does not exist here)
# ---------------------------------------------------------------------------

DECISION_SOURCE_HUMAN = "HUMAN"
DECISION_SOURCES: tuple[str, ...] = (DECISION_SOURCE_HUMAN,)

DECISION_AUTHORITY_HUMAN = "HUMAN"
DECISION_AUTHORITIES: tuple[str, ...] = (DECISION_AUTHORITY_HUMAN,)

AI_ROLE_ADVISORY = "ADVISORY"
AI_ROLES: tuple[str, ...] = (AI_ROLE_ADVISORY,)

# ---------------------------------------------------------------------------
# Rationale vocabulary (closed)
# ---------------------------------------------------------------------------

RATIONALE_EVIDENCE_SUFFICIENT = "EVIDENCE_SUFFICIENT"
RATIONALE_EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING = "HYPOTHESIS_NEEDS_STRENGTHENING"
RATIONALE_CONFLICT_REQUIRES_RESOLUTION = "CONFLICT_REQUIRES_RESOLUTION"
RATIONALE_DUPLICATE_RESEARCH_OVERLAP = "DUPLICATE_RESEARCH_OVERLAP"
RATIONALE_FAILS_RESEARCH_SCOPE = "FAILS_RESEARCH_SCOPE"
RATIONALE_RESEARCH_VALUE_LOW = "RESEARCH_VALUE_LOW"
RATIONALE_ESCALATION_REQUIRED = "ESCALATION_REQUIRED"
RATIONALE_GOVERNANCE_REVIEW_REQUIRED = "GOVERNANCE_REVIEW_REQUIRED"
RATIONALE_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
RATIONALE_SEVERITY_CONTEXT_REQUIRED = "SEVERITY_CONTEXT_REQUIRED"
RATIONALE_PRIORITY_CONTEXT_ACKNOWLEDGED = "PRIORITY_CONTEXT_ACKNOWLEDGED"
RATIONALE_OTHER = "OTHER"
RATIONALE_NOT_PROVIDED = "RATIONALE_NOT_PROVIDED"

HUMAN_RATIONALE_CODES: tuple[str, ...] = (
    RATIONALE_EVIDENCE_SUFFICIENT,
    RATIONALE_EVIDENCE_INCOMPLETE,
    RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING,
    RATIONALE_CONFLICT_REQUIRES_RESOLUTION,
    RATIONALE_DUPLICATE_RESEARCH_OVERLAP,
    RATIONALE_FAILS_RESEARCH_SCOPE,
    RATIONALE_RESEARCH_VALUE_LOW,
    RATIONALE_ESCALATION_REQUIRED,
    RATIONALE_GOVERNANCE_REVIEW_REQUIRED,
    RATIONALE_PROVENANCE_INCOMPLETE,
    RATIONALE_SEVERITY_CONTEXT_REQUIRED,
    RATIONALE_PRIORITY_CONTEXT_ACKNOWLEDGED,
    RATIONALE_OTHER,
    RATIONALE_NOT_PROVIDED,
)

RATIONALE_STATE_PROVIDED = "PROVIDED"
RATIONALE_STATE_NOT_PROVIDED = "RATIONALE_NOT_PROVIDED"

RATIONALE_STATES: tuple[str, ...] = (
    RATIONALE_STATE_PROVIDED,
    RATIONALE_STATE_NOT_PROVIDED,
)

# ---------------------------------------------------------------------------
# Evidence request vocabulary (closed)
# ---------------------------------------------------------------------------

EVIDENCE_REQUEST_OBSERVATION = "EVIDENCE_OBSERVATION_CONFIRMATION"
EVIDENCE_REQUEST_CONTEXT = "EVIDENCE_CONTEXT_COMPLETION"
EVIDENCE_REQUEST_HYPOTHESIS = "EVIDENCE_HYPOTHESIS_STRENGTHENING"
EVIDENCE_REQUEST_CONFLICT = "EVIDENCE_CONFLICT_RESOLUTION"
EVIDENCE_REQUEST_PROVENANCE = "EVIDENCE_PROVENANCE_COMPLETION"
EVIDENCE_REQUEST_SEVERITY = "EVIDENCE_SEVERITY_CONTEXT"
EVIDENCE_REQUEST_IMPACT = "EVIDENCE_IMPACT_CONTEXT"
EVIDENCE_REQUEST_OTHER = "EVIDENCE_OTHER"
EVIDENCE_REQUEST_UNKNOWN = "EVIDENCE_UNKNOWN"

EVIDENCE_REQUEST_TYPES: tuple[str, ...] = (
    EVIDENCE_REQUEST_OBSERVATION,
    EVIDENCE_REQUEST_CONTEXT,
    EVIDENCE_REQUEST_HYPOTHESIS,
    EVIDENCE_REQUEST_CONFLICT,
    EVIDENCE_REQUEST_PROVENANCE,
    EVIDENCE_REQUEST_SEVERITY,
    EVIDENCE_REQUEST_IMPACT,
    EVIDENCE_REQUEST_OTHER,
    EVIDENCE_REQUEST_UNKNOWN,
)

EVIDENCE_REQUEST_REASON_NOT_SPECIFIED = "REASON_NOT_SPECIFIED"

# ---------------------------------------------------------------------------
# Escalation vocabulary (closed)
# ---------------------------------------------------------------------------

ESCALATION_TARGET_ANALYST = "HUMAN_ANALYST_REVIEW"
ESCALATION_TARGET_RESEARCH_LEAD = "RESEARCH_LEAD_REVIEW"
ESCALATION_TARGET_GOVERNANCE = "GOVERNANCE_REVIEW"
ESCALATION_TARGET_SECURITY_REVIEW = "SECURITY_REVIEW_BOARD"
ESCALATION_TARGET_UNKNOWN = "ESCALATION_UNKNOWN"

ESCALATION_TARGETS: tuple[str, ...] = (
    ESCALATION_TARGET_ANALYST,
    ESCALATION_TARGET_RESEARCH_LEAD,
    ESCALATION_TARGET_GOVERNANCE,
    ESCALATION_TARGET_SECURITY_REVIEW,
    ESCALATION_TARGET_UNKNOWN,
)

ESCALATION_REASON_CONFLICT = "CONFLICT_REQUIRES_REVIEW"
ESCALATION_REASON_EVIDENCE = "EVIDENCE_INSUFFICIENT"
ESCALATION_REASON_GOVERNANCE = "GOVERNANCE_REVIEW_REQUIRED"
ESCALATION_REASON_PROVENANCE = "PROVENANCE_INCOMPLETE"
ESCALATION_REASON_SEVERITY = "SEVERITY_CONTEXT_REQUIRED"
ESCALATION_REASON_SCOPE = "SCOPE_OR_AUTHORIZATION_REVIEW"
ESCALATION_REASON_NOT_SPECIFIED = "REASON_NOT_SPECIFIED"

ESCALATION_REASONS: tuple[str, ...] = (
    ESCALATION_REASON_CONFLICT,
    ESCALATION_REASON_EVIDENCE,
    ESCALATION_REASON_GOVERNANCE,
    ESCALATION_REASON_PROVENANCE,
    ESCALATION_REASON_SEVERITY,
    ESCALATION_REASON_SCOPE,
    ESCALATION_REASON_NOT_SPECIFIED,
)

# ---------------------------------------------------------------------------
# Explicitly-not-authorized vocabulary (closed)
# ---------------------------------------------------------------------------

NOT_AUTHORIZED_EXECUTION = "EXECUTION_NOT_AUTHORIZED"
NOT_AUTHORIZED_VULNERABILITY_CONFIRMATION = (
    "VULNERABILITY_CONFIRMATION_NOT_AUTHORIZED"
)
NOT_AUTHORIZED_EXPLOIT = "EXPLOIT_AUTHORIZATION_NOT_AUTHORIZED"
NOT_AUTHORIZED_PAYLOAD = "PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED"
NOT_AUTHORIZED_ATTACK_PLANNING = "ATTACK_PLANNING_NOT_AUTHORIZED"
NOT_AUTHORIZED_AUTOMATED_DECISION = "AUTOMATED_DECISION_NOT_AUTHORIZED"

NOT_AUTHORIZED_CODES: tuple[str, ...] = (
    NOT_AUTHORIZED_EXECUTION,
    NOT_AUTHORIZED_VULNERABILITY_CONFIRMATION,
    NOT_AUTHORIZED_EXPLOIT,
    NOT_AUTHORIZED_PAYLOAD,
    NOT_AUTHORIZED_ATTACK_PLANNING,
    NOT_AUTHORIZED_AUTOMATED_DECISION,
)

# ---------------------------------------------------------------------------
# Decision option vocabulary (closed)
# ---------------------------------------------------------------------------

OPTION_APPROVE_RESEARCH = "OPTION_APPROVE_RESEARCH"
OPTION_REQUEST_MORE_EVIDENCE = "OPTION_REQUEST_MORE_EVIDENCE"
OPTION_DEFER = "OPTION_DEFER"
OPTION_REJECT = "OPTION_REJECT"
OPTION_ESCALATE = "OPTION_ESCALATE"
OPTION_NEEDS_REVIEW = "OPTION_NEEDS_REVIEW"
OPTION_EXECUTION_PLACEHOLDER = "OPTION_EXECUTION_PLACEHOLDER"

DECISION_OPTION_CODES: tuple[str, ...] = (
    OPTION_APPROVE_RESEARCH,
    OPTION_REQUEST_MORE_EVIDENCE,
    OPTION_DEFER,
    OPTION_REJECT,
    OPTION_ESCALATE,
    OPTION_NEEDS_REVIEW,
    OPTION_EXECUTION_PLACEHOLDER,
)

OPTION_DISABLED_EXECUTION = "EXECUTION_NEVER_AUTHORIZED_RESEARCH_ONLY"

DECISION_TYPE_TO_OPTION: dict[str, str] = {
    DECISION_APPROVE_RESEARCH: OPTION_APPROVE_RESEARCH,
    DECISION_REQUEST_MORE_EVIDENCE: OPTION_REQUEST_MORE_EVIDENCE,
    DECISION_DEFER: OPTION_DEFER,
    DECISION_REJECT: OPTION_REJECT,
    DECISION_ESCALATE: OPTION_ESCALATE,
    DECISION_NEEDS_REVIEW: OPTION_NEEDS_REVIEW,
}

# ---------------------------------------------------------------------------
# Transition vocabulary (closed)
# ---------------------------------------------------------------------------

TRANSITION_INITIAL_DECISION = "INITIAL_DECISION"
TRANSITION_DECISION_SUPERSEDED = "DECISION_SUPERSEDED"
TRANSITION_REVIEW_EXPIRED = "REVIEW_EXPIRED"
TRANSITION_REJECTED = "TRANSITION_REJECTED"

TRANSITION_REASONS: tuple[str, ...] = (
    TRANSITION_INITIAL_DECISION,
    TRANSITION_DECISION_SUPERSEDED,
    TRANSITION_REVIEW_EXPIRED,
    TRANSITION_REJECTED,
)

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    DECISION_STATE_PENDING: (
        DECISION_STATE_DECIDED,
        DECISION_STATE_EXPIRED,
    ),
    DECISION_STATE_DECIDED: (DECISION_STATE_DECIDED,),
    DECISION_STATE_EXPIRED: (),
    DECISION_STATE_INVALID: (),
}

# ---------------------------------------------------------------------------
# Limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_AI_ADVISORY_ONLY = "AI_ADVISORY_ONLY"
LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM = (
    "HUMAN_DECISION_DOES_NOT_CONFIRM"
)
LIMITATION_EXECUTION_NOT_AUTHORIZED = "EXECUTION_NOT_AUTHORIZED"
LIMITATION_NOT_CONFIRMED = "NOT_CONFIRMED"
LIMITATION_DECISION_RECORDED_ONLY = "DECISION_RECORDED_ONLY"
LIMITATION_RATIONALE_NOT_PROVIDED = "RATIONALE_NOT_PROVIDED"
LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY = "EVIDENCE_REQUEST_RECORDED_ONLY"
LIMITATION_ESCALATION_RECORDED_ONLY = "ESCALATION_RECORDED_ONLY"
LIMITATION_CONFLICT_PRESENT = "CONFLICT_PRESENT"
LIMITATION_DUPLICATE_PRESENT = "DUPLICATE_PRESENT"
LIMITATION_PRIORITY_PRESERVED = "PRIORITY_PRESERVED"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
LIMITATION_CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"
LIMITATION_PENDING_HUMAN_DECISION = "PENDING_HUMAN_DECISION"
LIMITATION_DECISION_HISTORY_PRESENT = "DECISION_HISTORY_PRESENT"
LIMITATION_REVIEW_EXPIRED = "REVIEW_EXPIRED"
LIMITATION_SAFETY_DEFERRED = "SAFETY_DEFERRED"
LIMITATION_NOT_AUTHORIZED_LISTED = "NOT_AUTHORIZED_LISTED"

HUMAN_DECISION_LIMITATIONS: tuple[str, ...] = (
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
    LIMITATION_RATIONALE_NOT_PROVIDED,
    LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY,
    LIMITATION_ESCALATION_RECORDED_ONLY,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DUPLICATE_PRESENT,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_PENDING_HUMAN_DECISION,
    LIMITATION_DECISION_HISTORY_PRESENT,
    LIMITATION_REVIEW_EXPIRED,
    LIMITATION_SAFETY_DEFERRED,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

DECISION_ID_PREFIX = "hdc-"
DECISION_ID_RE = re.compile(r"^hdc-[0-9a-f]{16}$")

MAX_DECISION_TYPES = 16
MAX_RATIONALE_CODES = 8
MAX_RATIONALE_NOTE_LEN = 240
MAX_OPTIONS = 8
MAX_HISTORY = 8
MAX_LIST = 24
MAX_LIMITATIONS = 24
MAX_EVIDENCE_REFERENCES = 8
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, HUMAN_DECISION_LIMITATIONS, MAX_LIMITATIONS
    )


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_priority_reference(value: object) -> dict:
    """Project the immutable R55 recommendation reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "prioritization_id": "",
            "priority_rule_version": "",
            "priority_score": 0,
            "priority_band": BAND_DEFERRED,
            "ranking_position": 0,
            "priority_reasons": [],
            "research_only": True,
        }
    return {
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "priority_score": _bounded_int(value.get("priority_score"), 0, 100),
        "priority_band": _closed(
            value.get("priority_band"), PRIORITY_BANDS, BAND_DEFERRED
        ),
        "ranking_position": _bounded_int(
            value.get("ranking_position"), 0, MAX_LIST
        ),
        "priority_reasons": _bounded_strings(
            value.get("priority_reasons"), MAX_LIST, 80
        ),
        "research_only": True,
    }


def sanitize_correlation_reference(value: object) -> dict:
    """Project the correlation context reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "correlation_id": "",
            "correlation_rule_version": "",
            "conflict_state": CONFLICT_UNKNOWN,
            "conflict_sources": [],
            "relationship_types": [],
            "duplicate_present": False,
            "research_only": True,
        }
    return {
        "correlation_id": _safe_text(value.get("correlation_id")),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "conflict_state": _closed(
            value.get("conflict_state"),
            CONFLICT_STATES,
            CONFLICT_UNKNOWN,
        ),
        "conflict_sources": _bounded_strings(
            value.get("conflict_sources"), MAX_LIST, 80
        ),
        "relationship_types": _bounded_strings(
            value.get("relationship_types"), MAX_LIST, 40
        ),
        "duplicate_present": bool(value.get("duplicate_present")) is True,
        "research_only": True,
    }


def sanitize_finding_reference(value: object) -> dict:
    """Project the upstream finding reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "source_kind": "",
            "finding_rule_version": "",
            "category": "",
            "agent_id": "",
            "orchestration_id": "",
            "state": "",
            "confidence": "UNKNOWN",
            "evidence_completeness": "UNKNOWN",
            "severity": CVSS_UNKNOWN,
            "severity_source": SEVERITY_SOURCE_NOT_ASSESSED,
            "impact_state": "UNKNOWN",
            "research_only": True,
        }
    source_kind = _safe_text(value.get("source_kind")).strip().upper()
    if source_kind not in SOURCE_KINDS:
        source_kind = ""
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    return {
        "source_kind": source_kind,
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "category": category,
        "agent_id": _safe_text(value.get("agent_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "state": _ordered_codes_placeholder(value.get("state")),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "evidence_completeness": _closed(
            value.get("evidence_completeness"),
            EVIDENCE_COMPLETENESS_LEVELS,
            "UNKNOWN",
        ),
        "severity": _closed(
            value.get("severity"), CVSS_SEVERITIES, CVSS_UNKNOWN
        ),
        "severity_source": _closed(
            value.get("severity_source"),
            SEVERITY_SOURCES,
            SEVERITY_SOURCE_NOT_ASSESSED,
        ),
        "impact_state": _closed(
            value.get("impact_state"), IMPACT_STATES, "UNKNOWN"
        ),
        "research_only": True,
    }


def _ordered_codes_placeholder(value: object) -> str:
    """Finding state is a single closed value (not a code list)."""

    text = _safe_text(value).strip().upper()
    return text if text in FINDING_STATES else ""


def sanitize_decision_rationale(value: object) -> dict:
    """Project the human rationale onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rationale_state": RATIONALE_STATE_NOT_PROVIDED,
            "rationale_codes": [RATIONALE_NOT_PROVIDED],
            "rationale_note": "",
        }
    codes = [
        code
        for code in _ordered_codes(
            value.get("rationale_codes"),
            HUMAN_RATIONALE_CODES,
            MAX_RATIONALE_CODES,
        )
        if code != RATIONALE_NOT_PROVIDED
    ]
    note = _safe_text(value.get("rationale_note"), MAX_RATIONALE_NOTE_LEN)
    state = _closed(
        value.get("rationale_state"),
        RATIONALE_STATES,
        RATIONALE_STATE_NOT_PROVIDED,
    )
    if not codes and not note:
        state = RATIONALE_STATE_NOT_PROVIDED
        codes = [RATIONALE_NOT_PROVIDED]
    else:
        state = RATIONALE_STATE_PROVIDED
    return {
        "rationale_state": state,
        "rationale_codes": codes,
        "rationale_note": note,
    }


def sanitize_evidence_request(value: object) -> dict:
    """Project a structured evidence request onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "requested_evidence_type": EVIDENCE_REQUEST_UNKNOWN,
            "source_finding_id": "",
            "reason": EVIDENCE_REQUEST_REASON_NOT_SPECIFIED,
            "priority": "UNKNOWN",
            "originating_reference": "",
            "research_only": True,
        }
    source_finding_id = _safe_text(value.get("source_finding_id"))
    if source_finding_id and not FINDING_ID_RE.match(source_finding_id):
        source_finding_id = ""
    return {
        "requested_evidence_type": _closed(
            value.get("requested_evidence_type"),
            EVIDENCE_REQUEST_TYPES,
            EVIDENCE_REQUEST_UNKNOWN,
        ),
        "source_finding_id": source_finding_id,
        "reason": _safe_text(value.get("reason")) or (
            EVIDENCE_REQUEST_REASON_NOT_SPECIFIED
        ),
        "priority": _closed(
            value.get("priority"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "originating_reference": _safe_text(
            value.get("originating_reference"), 120
        ),
        "research_only": True,
    }


def sanitize_escalation_provenance(value: object) -> dict:
    """Project escalation provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "prioritization_id": "",
            "correlation_id": "",
            "finding_rule_version": "",
            "priority_rule_version": "",
            "orchestration_id": "",
            "research_only": True,
        }
    return {
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "research_only": True,
    }


def sanitize_escalation(value: object) -> dict:
    """Project an escalation representation onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "escalation_target": ESCALATION_TARGET_UNKNOWN,
            "reason": ESCALATION_REASON_NOT_SPECIFIED,
            "finding_id": "",
            "priority_band": BAND_DEFERRED,
            "evidence_context": "",
            "provenance": sanitize_escalation_provenance(None),
            "research_only": True,
        }
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    return {
        "escalation_target": _closed(
            value.get("escalation_target"),
            ESCALATION_TARGETS,
            ESCALATION_TARGET_UNKNOWN,
        ),
        "reason": _closed(
            value.get("reason"),
            ESCALATION_REASONS,
            ESCALATION_REASON_NOT_SPECIFIED,
        ),
        "finding_id": finding_id,
        "priority_band": _closed(
            value.get("priority_band"), PRIORITY_BANDS, BAND_DEFERRED
        ),
        "evidence_context": _safe_text(value.get("evidence_context"), 240),
        "provenance": sanitize_escalation_provenance(
            value.get("provenance")
        ),
        "research_only": True,
    }


def sanitize_decision_option(value: object) -> dict:
    """Project one explicit workflow option onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    option = _safe_text(value.get("option")).strip().upper()
    if option not in DECISION_OPTION_CODES:
        return {}
    enabled = value.get("enabled") is True
    disabled_reason = _safe_text(value.get("disabled_reason"))
    if option == OPTION_EXECUTION_PLACEHOLDER:
        enabled = False
        disabled_reason = (
            disabled_reason or OPTION_DISABLED_EXECUTION
        )
    return {
        "option": option,
        "enabled": enabled,
        "disabled_reason": "" if enabled else disabled_reason,
    }


def sanitize_decision_options(value: object) -> list[dict]:
    """Project the bounded option list (order preserved, deduplicated)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_decision_option(item)
        if projected and projected not in out:
            out.append(projected)
        if len(out) >= MAX_OPTIONS:
            break
    return out


def sanitize_human_provenance(value: object) -> dict:
    """Project decision provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decisor_rule_version": HUMAN_DECISION_RULE_VERSION,
            "prioritization_id": "",
            "correlation_id": "",
            "orchestration_id": "",
            "agent_id": "",
            "category": "",
            "decision_source": DECISION_SOURCE_HUMAN,
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    source_stages = _bounded_strings(value.get("source_stages"), MAX_LIST, 80)
    return {
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "decisor_rule_version": HUMAN_DECISION_RULE_VERSION,
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "agent_id": _safe_text(value.get("agent_id")),
        "category": category,
        "decision_source": DECISION_SOURCE_HUMAN,
        "source_stages": source_stages,
        "deterministic": True,
        "research_only": True,
    }


def sanitize_human_governance(value: object) -> dict:
    """Project the R37 governance reference (R53 shape, reused read-only)."""

    return sanitize_finding_governance(value)


def not_authorized_projection() -> list[str]:
    """Deterministic list of actions this decision never authorizes."""

    return list(NOT_AUTHORIZED_CODES)


def sanitize_human_audit(value: object) -> dict:
    """Project the deterministic audit representation onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "audit_id": "",
            "finding_id": "",
            "automated_recommendation": {},
            "human_decision_type": "",
            "human_decision_state": DECISION_STATE_PENDING,
            "decision_rationale_state": RATIONALE_STATE_NOT_PROVIDED,
            "decision_rationale_codes": [],
            "evidence_references": [],
            "governance_state": "UNKNOWN",
            "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
            "execution_authorized": False,
            "not_authorized": list(NOT_AUTHORIZED_CODES),
            "audit_state": AUDIT_UNKNOWN,
            "research_only": True,
            "deterministic": True,
        }
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    recommendation = value.get("automated_recommendation")
    if not isinstance(recommendation, dict):
        recommendation = {}
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "audit_id": _safe_text(value.get("audit_id")),
        "finding_id": finding_id,
        "automated_recommendation": {
            "priority_band": _closed(
                recommendation.get("priority_band"),
                PRIORITY_BANDS,
                BAND_DEFERRED,
            ),
            "priority_score": _bounded_int(
                recommendation.get("priority_score"), 0, 100
            ),
            "priority_reasons": _bounded_strings(
                recommendation.get("priority_reasons"), MAX_LIST, 80
            ),
        },
        "human_decision_type": _closed(
            value.get("human_decision_type"),
            HUMAN_DECISION_TYPES + ("",),
            "",
        ),
        "human_decision_state": _closed(
            value.get("human_decision_state"),
            HUMAN_DECISION_STATES,
            DECISION_STATE_PENDING,
        ),
        "decision_rationale_state": _closed(
            value.get("decision_rationale_state"),
            RATIONALE_STATES,
            RATIONALE_STATE_NOT_PROVIDED,
        ),
        "decision_rationale_codes": _ordered_codes(
            value.get("decision_rationale_codes"),
            HUMAN_RATIONALE_CODES,
            MAX_RATIONALE_CODES,
        ),
        "evidence_references": _bounded_strings(
            value.get("evidence_references"),
            MAX_EVIDENCE_REFERENCES,
            120,
        ),
        "governance_state": _safe_text(
            value.get("governance_state")
        ).strip().upper()
        or "UNKNOWN",
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "execution_authorized": False,
        "not_authorized": list(NOT_AUTHORIZED_CODES),
        "audit_state": _closed(
            value.get("audit_state"), AUDIT_STATES, AUDIT_UNKNOWN
        ),
        "research_only": True,
        "deterministic": True,
    }


def sanitize_human_decision(value: object) -> dict:
    """Project a human decision onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_decision()
    finding_id = _safe_text(value.get("finding_id"))
    if not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    decision_type = _safe_text(value.get("decision_type")).strip().upper()
    if decision_type not in HUMAN_DECISION_TYPES:
        decision_type = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "decision_id": _safe_text(value.get("decision_id")),
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
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "priority_reference": sanitize_priority_reference(
            value.get("priority_reference")
        ),
        "correlation_reference": sanitize_correlation_reference(
            value.get("correlation_reference")
        ),
        "finding_reference": sanitize_finding_reference(
            value.get("finding_reference")
        ),
        "rationale": sanitize_decision_rationale(value.get("rationale")),
        "evidence_request": sanitize_evidence_request(
            value.get("evidence_request")
        ),
        "escalation": sanitize_escalation(value.get("escalation")),
        "decision_options": sanitize_decision_options(
            value.get("decision_options")
        ),
        "audit": sanitize_human_audit(value.get("audit")),
        "provenance": sanitize_human_provenance(value.get("provenance")),
        "governance": sanitize_human_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _default_decision() -> dict:
    return {
        "rule_version": "",
        "decision_id": "",
        "finding_id": "",
        "decision_type": "",
        "decision_state": DECISION_STATE_DECIDED,
        "decision_source": DECISION_SOURCE_HUMAN,
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "human_authority": True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "priority_reference": sanitize_priority_reference(None),
        "correlation_reference": sanitize_correlation_reference(None),
        "finding_reference": sanitize_finding_reference(None),
        "rationale": sanitize_decision_rationale(None),
        "evidence_request": sanitize_evidence_request(None),
        "escalation": sanitize_escalation(None),
        "decision_options": [],
        "audit": sanitize_human_audit(None),
        "provenance": sanitize_human_provenance(None),
        "governance": sanitize_human_governance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class HumanPriorityReferencePlan(BaseModel):
    """Immutable reference to the R55 recommendation (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    prioritization_id: str = ""
    priority_rule_version: str = ""
    priority_score: int = 0
    priority_band: str = BAND_DEFERRED
    ranking_position: int = 0
    priority_reasons: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("priority_band")
    @classmethod
    def _valid_band(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITY_BANDS:
            raise ValueError(f"invalid priority_band: {value!r}")
        return text

    @field_validator("priority_score")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        return _bounded_int(value, 0, 100)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("priority references are research-only")
        return True


class HumanCorrelationReferencePlan(BaseModel):
    """Correlation context reference of one reviewed finding (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: str = ""
    correlation_rule_version: str = ""
    conflict_state: str = CONFLICT_UNKNOWN
    conflict_sources: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    duplicate_present: bool = False
    research_only: bool = True

    @field_validator("conflict_state")
    @classmethod
    def _valid_conflict(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFLICT_STATES:
            raise ValueError(f"invalid conflict_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("correlation references are research-only")
        return True


class HumanFindingReferencePlan(BaseModel):
    """Upstream finding reference of one reviewed finding (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    source_kind: str = ""
    finding_rule_version: str = ""
    category: str = ""
    agent_id: str = ""
    orchestration_id: str = ""
    state: str = ""
    confidence: str = "UNKNOWN"
    evidence_completeness: str = "UNKNOWN"
    severity: str = CVSS_UNKNOWN
    severity_source: str = SEVERITY_SOURCE_NOT_ASSESSED
    impact_state: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding references are research-only")
        return True


class HumanRationalePlan(BaseModel):
    """Explicit human rationale (codes + optional bounded note) (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    rationale_state: str = RATIONALE_STATE_NOT_PROVIDED
    rationale_codes: list[str] = Field(default_factory=list)
    rationale_note: str = ""

    @field_validator("rationale_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RATIONALE_STATES:
            raise ValueError(f"invalid rationale_state: {value!r}")
        return text

    @field_validator("rationale_codes")
    @classmethod
    def _valid_codes(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, HUMAN_RATIONALE_CODES, MAX_RATIONALE_CODES
        )

    @field_validator("rationale_note")
    @classmethod
    def _bounded_note(cls, value: object) -> str:
        return _safe_text(value, MAX_RATIONALE_NOTE_LEN)


class HumanEvidenceRequestPlan(BaseModel):
    """Structured human request for more evidence (recorded only) (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    requested_evidence_type: str = EVIDENCE_REQUEST_UNKNOWN
    source_finding_id: str = ""
    reason: str = EVIDENCE_REQUEST_REASON_NOT_SPECIFIED
    priority: str = "UNKNOWN"
    originating_reference: str = ""
    research_only: bool = True

    @field_validator("requested_evidence_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_REQUEST_TYPES:
            raise ValueError(f"invalid requested_evidence_type: {value!r}")
        return text

    @field_validator("source_finding_id")
    @classmethod
    def _valid_source(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed source_finding_id: {value!r}")
        return text

    @field_validator("priority")
    @classmethod
    def _valid_priority(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid request priority: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("evidence requests are research-only")
        return True


class HumanEscalationPlan(BaseModel):
    """Structured escalation representation (recorded only) (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    escalation_target: str = ESCALATION_TARGET_UNKNOWN
    reason: str = ESCALATION_REASON_NOT_SPECIFIED
    finding_id: str = ""
    priority_band: str = BAND_DEFERRED
    evidence_context: str = ""
    provenance: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("escalation_target")
    @classmethod
    def _valid_target(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ESCALATION_TARGETS:
            raise ValueError(f"invalid escalation_target: {value!r}")
        return text

    @field_validator("reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ESCALATION_REASONS:
            raise ValueError(f"invalid escalation reason: {value!r}")
        return text

    @field_validator("priority_band")
    @classmethod
    def _valid_band(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITY_BANDS:
            raise ValueError(f"invalid priority_band: {value!r}")
        return text

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_escalation_provenance(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("escalations are research-only")
        return True


class HumanDecisionOptionPlan(BaseModel):
    """One explicit workflow option (execution is never enabled) (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    option: str
    enabled: bool = False
    disabled_reason: str = ""

    @field_validator("option")
    @classmethod
    def _valid_option(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DECISION_OPTION_CODES:
            raise ValueError(f"invalid option: {value!r}")
        return text

    @field_validator("disabled_reason")
    @classmethod
    def _bounded_reason(cls, value: object) -> str:
        return _safe_text(value)

    @model_validator(mode="after")
    def _execution_never_enabled(self) -> "HumanDecisionOptionPlan":
        if self.option == OPTION_EXECUTION_PLACEHOLDER and self.enabled:
            raise ValueError("execution is never an enabled option")
        return self


class HumanDecisionPlan(BaseModel):
    """Deterministic recorded human decision (R56.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_DECISION_RULE_VERSION
    decision_id: str
    finding_id: str
    decision_type: str
    decision_state: str = DECISION_STATE_DECIDED
    decision_source: str = DECISION_SOURCE_HUMAN
    decision_authority: str = DECISION_AUTHORITY_HUMAN
    ai_role: str = AI_ROLE_ADVISORY
    human_authority: bool = True
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    exploit_authorized: bool = False
    confirmation_state: str = CONFIRMATION_NOT_CONFIRMED
    priority_reference: dict = Field(default_factory=dict)
    correlation_reference: dict = Field(default_factory=dict)
    finding_reference: dict = Field(default_factory=dict)
    rationale: dict = Field(default_factory=dict)
    evidence_request: dict = Field(default_factory=dict)
    escalation: dict = Field(default_factory=dict)
    decision_options: list[dict] = Field(default_factory=list)
    audit: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_DECISION_RULE_VERSION

    @field_validator("decision_id")
    @classmethod
    def _valid_decision_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not DECISION_ID_RE.match(text):
            raise ValueError(f"malformed decision_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("decision_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HUMAN_DECISION_TYPES:
            raise ValueError(f"invalid decision_type: {value!r}")
        return text

    @field_validator("decision_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HUMAN_DECISION_STATES:
            raise ValueError(f"invalid decision_state: {value!r}")
        return text

    @field_validator("decision_source")
    @classmethod
    def _human_source(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != DECISION_SOURCE_HUMAN:
            raise ValueError("decisions must come from a human source")
        return DECISION_SOURCE_HUMAN

    @field_validator("decision_authority")
    @classmethod
    def _human_authority(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != DECISION_AUTHORITY_HUMAN:
            raise ValueError("decision authority must be HUMAN")
        return DECISION_AUTHORITY_HUMAN

    @field_validator("ai_role")
    @classmethod
    def _advisory_ai(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != AI_ROLE_ADVISORY:
            raise ValueError("the AI role is advisory only")
        return AI_ROLE_ADVISORY

    @field_validator("human_authority")
    @classmethod
    def _human_authority_flag(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("human authority must be explicitly true")
        return True

    @field_validator(
        "execution_authorized",
        "vulnerability_confirmed",
        "exploit_authorized",
    )
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "human research decisions never authorize execution, "
                "confirmation or exploitation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != CONFIRMATION_NOT_CONFIRMED:
            raise ValueError("human decisions never confirm a vulnerability")
        return CONFIRMATION_NOT_CONFIRMED

    @field_validator("priority_reference")
    @classmethod
    def _bounded_priority(cls, value: object) -> dict:
        return HumanPriorityReferencePlan(
            **sanitize_priority_reference(value)
        ).model_dump(mode="json")

    @field_validator("correlation_reference")
    @classmethod
    def _bounded_correlation(cls, value: object) -> dict:
        return HumanCorrelationReferencePlan(
            **sanitize_correlation_reference(value)
        ).model_dump(mode="json")

    @field_validator("finding_reference")
    @classmethod
    def _bounded_finding(cls, value: object) -> dict:
        return HumanFindingReferencePlan(
            **sanitize_finding_reference(value)
        ).model_dump(mode="json")

    @field_validator("rationale")
    @classmethod
    def _bounded_rationale(cls, value: object) -> dict:
        return HumanRationalePlan(
            **sanitize_decision_rationale(value)
        ).model_dump(mode="json")

    @field_validator("evidence_request")
    @classmethod
    def _bounded_evidence(cls, value: object) -> dict:
        return HumanEvidenceRequestPlan(
            **sanitize_evidence_request(value)
        ).model_dump(mode="json")

    @field_validator("escalation")
    @classmethod
    def _bounded_escalation(cls, value: object) -> dict:
        return HumanEscalationPlan(**sanitize_escalation(value)).model_dump(
            mode="json"
        )

    @field_validator("decision_options")
    @classmethod
    def _bounded_options(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            try:
                projected = HumanDecisionOptionPlan(
                    **sanitize_decision_option(item)
                ).model_dump(mode="json")
            except (TypeError, ValueError):
                continue
            if projected not in out:
                out.append(projected)
            if len(out) >= MAX_OPTIONS:
                break
        return out

    @field_validator("audit")
    @classmethod
    def _bounded_audit(cls, value: object) -> dict:
        return sanitize_human_audit(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_human_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_human_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("human decisions are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("human decisions are deterministic")
        return True


def human_decision_plan_projection(value: HumanDecisionPlan) -> dict:
    """Serialize a human decision to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "HUMAN_DECISION_RULE_VERSION",
    "RULE_VERSION",
    "HUMAN_DECISION_TYPES",
    "HUMAN_DECISION_STATES",
    "DECISION_SOURCES",
    "DECISION_AUTHORITIES",
    "AI_ROLES",
    "HUMAN_RATIONALE_CODES",
    "RATIONALE_STATES",
    "EVIDENCE_REQUEST_TYPES",
    "EVIDENCE_REQUEST_REASON_NOT_SPECIFIED",
    "ESCALATION_TARGETS",
    "ESCALATION_REASONS",
    "NOT_AUTHORIZED_CODES",
    "DECISION_OPTION_CODES",
    "OPTION_DISABLED_EXECUTION",
    "DECISION_TYPE_TO_OPTION",
    "TRANSITION_REASONS",
    "ALLOWED_TRANSITIONS",
    "HUMAN_DECISION_LIMITATIONS",
    "DECISION_ID_PREFIX",
    "DECISION_ID_RE",
    "DECISION_APPROVE_RESEARCH",
    "DECISION_REQUEST_MORE_EVIDENCE",
    "DECISION_DEFER",
    "DECISION_REJECT",
    "DECISION_ESCALATE",
    "DECISION_NEEDS_REVIEW",
    "DECISION_STATE_PENDING",
    "DECISION_STATE_DECIDED",
    "DECISION_STATE_EXPIRED",
    "DECISION_STATE_INVALID",
    "DECISION_SOURCE_HUMAN",
    "DECISION_AUTHORITY_HUMAN",
    "AI_ROLE_ADVISORY",
    "RATIONALE_EVIDENCE_SUFFICIENT",
    "RATIONALE_EVIDENCE_INCOMPLETE",
    "RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING",
    "RATIONALE_CONFLICT_REQUIRES_RESOLUTION",
    "RATIONALE_DUPLICATE_RESEARCH_OVERLAP",
    "RATIONALE_FAILS_RESEARCH_SCOPE",
    "RATIONALE_RESEARCH_VALUE_LOW",
    "RATIONALE_ESCALATION_REQUIRED",
    "RATIONALE_GOVERNANCE_REVIEW_REQUIRED",
    "RATIONALE_PROVENANCE_INCOMPLETE",
    "RATIONALE_SEVERITY_CONTEXT_REQUIRED",
    "RATIONALE_PRIORITY_CONTEXT_ACKNOWLEDGED",
    "RATIONALE_OTHER",
    "RATIONALE_NOT_PROVIDED",
    "RATIONALE_STATE_PROVIDED",
    "RATIONALE_STATE_NOT_PROVIDED",
    "EVIDENCE_REQUEST_OBSERVATION",
    "EVIDENCE_REQUEST_CONTEXT",
    "EVIDENCE_REQUEST_HYPOTHESIS",
    "EVIDENCE_REQUEST_CONFLICT",
    "EVIDENCE_REQUEST_PROVENANCE",
    "EVIDENCE_REQUEST_SEVERITY",
    "EVIDENCE_REQUEST_IMPACT",
    "EVIDENCE_REQUEST_OTHER",
    "EVIDENCE_REQUEST_UNKNOWN",
    "ESCALATION_TARGET_ANALYST",
    "ESCALATION_TARGET_RESEARCH_LEAD",
    "ESCALATION_TARGET_GOVERNANCE",
    "ESCALATION_TARGET_SECURITY_REVIEW",
    "ESCALATION_TARGET_UNKNOWN",
    "ESCALATION_REASON_CONFLICT",
    "ESCALATION_REASON_EVIDENCE",
    "ESCALATION_REASON_GOVERNANCE",
    "ESCALATION_REASON_PROVENANCE",
    "ESCALATION_REASON_SEVERITY",
    "ESCALATION_REASON_SCOPE",
    "ESCALATION_REASON_NOT_SPECIFIED",
    "NOT_AUTHORIZED_EXECUTION",
    "NOT_AUTHORIZED_VULNERABILITY_CONFIRMATION",
    "NOT_AUTHORIZED_EXPLOIT",
    "NOT_AUTHORIZED_PAYLOAD",
    "NOT_AUTHORIZED_ATTACK_PLANNING",
    "NOT_AUTHORIZED_AUTOMATED_DECISION",
    "OPTION_APPROVE_RESEARCH",
    "OPTION_REQUEST_MORE_EVIDENCE",
    "OPTION_DEFER",
    "OPTION_REJECT",
    "OPTION_ESCALATE",
    "OPTION_NEEDS_REVIEW",
    "OPTION_EXECUTION_PLACEHOLDER",
    "TRANSITION_INITIAL_DECISION",
    "TRANSITION_DECISION_SUPERSEDED",
    "TRANSITION_REVIEW_EXPIRED",
    "TRANSITION_REJECTED",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_AI_ADVISORY_ONLY",
    "LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM",
    "LIMITATION_EXECUTION_NOT_AUTHORIZED",
    "LIMITATION_NOT_CONFIRMED",
    "LIMITATION_DECISION_RECORDED_ONLY",
    "LIMITATION_RATIONALE_NOT_PROVIDED",
    "LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY",
    "LIMITATION_ESCALATION_RECORDED_ONLY",
    "LIMITATION_CONFLICT_PRESENT",
    "LIMITATION_DUPLICATE_PRESENT",
    "LIMITATION_PRIORITY_PRESERVED",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "LIMITATION_CORRELATION_UNAVAILABLE",
    "LIMITATION_PENDING_HUMAN_DECISION",
    "LIMITATION_DECISION_HISTORY_PRESENT",
    "LIMITATION_REVIEW_EXPIRED",
    "LIMITATION_SAFETY_DEFERRED",
    "LIMITATION_NOT_AUTHORIZED_LISTED",
    "MAX_DECISION_TYPES",
    "MAX_RATIONALE_CODES",
    "MAX_RATIONALE_NOTE_LEN",
    "MAX_OPTIONS",
    "MAX_HISTORY",
    "MAX_LIMITATIONS",
    "MAX_EVIDENCE_REFERENCES",
    "MAX_VALUE_LEN",
    "sanitize_priority_reference",
    "sanitize_correlation_reference",
    "sanitize_finding_reference",
    "sanitize_decision_rationale",
    "sanitize_evidence_request",
    "sanitize_escalation_provenance",
    "sanitize_escalation",
    "sanitize_decision_option",
    "sanitize_decision_options",
    "sanitize_human_provenance",
    "sanitize_human_governance",
    "sanitize_human_audit",
    "sanitize_human_decision",
    "not_authorized_projection",
    "HumanPriorityReferencePlan",
    "HumanCorrelationReferencePlan",
    "HumanFindingReferencePlan",
    "HumanRationalePlan",
    "HumanEvidenceRequestPlan",
    "HumanEscalationPlan",
    "HumanDecisionOptionPlan",
    "HumanDecisionPlan",
    "human_decision_plan_projection",
]

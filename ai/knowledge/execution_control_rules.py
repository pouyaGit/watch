"""Stage R58.5 deterministic execution-control rules (pure engine).

Provides the deterministic primitives behind the R58 controlled-execution
gate:

    R53 findings / R54 correlation / R55 prioritization /
    R56 human decisions / R57 learning
      -> structured execution request
      -> fail-closed authorization evaluation primitives
      -> declarative plan content
      -> deterministic safety gate
      -> deterministic ids, provenance and limitations

Hard boundaries encoded here:

- Gate only: R58 never executes, sends, scans, browses, resolves, spawns or
  modifies anything. The only side effect of this module is returning data.
- Human authority only: only an explicit ``HUMAN`` source and ``HUMAN``
  authority can authorize; AI, automated, autonomous and bypass attempts are
  converted into closed rejection reasons.
- Fail closed: malformed, mis-versioned, ambiguous, mismatched, expired or
  unsafe inputs are rejected with structured reasons; nothing is repaired,
  downgraded or silently mapped onto a safe action.
- Exact matching: action, target, scope, finding and decision must match
  exactly; wildcards are rejected; no implicit expansion is permitted.
- Deterministic: content-derived ids only; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids, randomness or wall-clock time.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no database.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.schemas.calibration_recommendation import (
    CALIB_REQUEST_MORE_EVIDENCE,
    CALIB_REVIEW_SAFETY_BOUNDARY,
    CALIBRATION_RECOMMENDATION_CODES,
)
from ai.schemas.controlled_execution_authorization import (
    APPROVAL_CONSTRAINTS,
    AUTHORIZATION_STATUS_AUTHORIZED,
    AUTHORIZATION_STATUS_BLOCKED,
    AUTHORIZATION_STATUS_EXPIRED,
    AUTHORIZATION_STATUS_INVALID,
    AUTHORIZATION_STATUS_NOT_REQUESTED,
    AUTHORIZATION_STATUS_REQUESTED,
    VALIDITY_EXPIRED,
    VALIDITY_INVALID,
)
from ai.schemas.controlled_execution_plan import (
    EXECUTION_PLAN_PRECONDITIONS,
    EXECUTION_SAFETY_CHECKS,
    EXECUTION_STOP_CONDITIONS,
    MAX_STEPS,
    PLAN_STATUS_AUTHORIZED,
    PLAN_STATUS_BLOCKED,
    PLAN_STATUS_EXPIRED,
    PLAN_STATUS_INVALID,
    PLAN_STATUS_NOT_REQUESTED,
    PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    PLAN_STATUS_REQUESTED,
    STEP_ASSERT_SAFETY_CONSTRAINTS,
    STEP_CONFIRM_SCOPE_METADATA,
    STEP_LOAD_RECORDED_EVIDENCE,
    STEP_PREPARE_RESEARCH_NOTE,
    STEP_RECONFIRM_CONTEXT_SUMMARY,
    STEP_REQUEST_HUMAN_REVIEW,
    STEP_REVIEW_STORED_RESPONSE,
    STEP_VERIFY_HUMAN_AUTHORIZATION,
)
from ai.schemas.execution_control_result import (
    CONTROL_OUTCOME_ALLOW,
    CONTROL_OUTCOME_DENY,
    CONTROL_OUTCOME_INVALID,
    CONTROL_OUTCOME_NOT_REQUESTED,
    CONTROL_STATUS_BLOCKED,
    CONTROL_STATUS_COMPLETED,
    CONTROL_STATUS_FAILED,
    CONTROL_STATUS_INVALID,
    CONTROL_STATUS_NOT_REQUESTED,
    EXECUTION_CONTROL_LIMITATIONS,
    REASON_INVALID_INPUT,
    REASON_MALFORMED_INPUT,
    REASON_RULE_VERSION_MISMATCH,
    SAFETY_INVALID,
    SAFETY_PASS,
    SAFETY_REASON_ATTACK_PLANNING,
    SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    SAFETY_REASON_BROWSER_AUTOMATION,
    SAFETY_REASON_CODE_EXECUTION,
    SAFETY_REASON_COMMAND_EXECUTION,
    SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    SAFETY_REASON_NETWORK_EXECUTION,
    SAFETY_REASON_PAYLOAD_GENERATION,
    SAFETY_REASON_POLICY_BYPASS,
    SAFETY_REASON_SCANNER_EXECUTION,
    SAFETY_REASON_SUBPROCESS_EXECUTION,
    SAFETY_REASON_UNSAFE_ACTION,
    SAFETY_REASON_UNSAFE_INPUT,
    SAFETY_REASON_VULNERABILITY_CONFIRMATION,
    SAFETY_REJECTION_REASONS,
)
from ai.schemas.execution_request import (
    ACTION_COLLECT_EXISTING_EVIDENCE,
    ACTION_PREPARE_RESEARCH_STEP,
    ACTION_REASSESS_CONTEXT,
    ACTION_RECHECK_SCOPE,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_REVIEW_EXISTING_RESPONSE,
    EXECUTION_ACTIONS,
    EXECUTION_REQUEST_RULE_VERSION,
    REJECTION_ACTION_NOT_SUPPORTED,
    REJECTION_FINDING_ID_REQUIRED,
    REJECTION_MALFORMED_REQUEST,
    REJECTION_PURPOSE_REQUIRED,
    REJECTION_REQUESTER_REQUIRED,
    REJECTION_SCOPE_REQUIRED,
    REJECTION_TARGET_REQUIRED,
    REJECTION_UNSAFE_REQUEST,
    REJECTION_WILDCARD_SCOPE,
    REJECTION_WILDCARD_TARGET,
    REQUEST_STATE_BLOCKED,
    REQUEST_STATE_INVALID,
    REQUEST_STATE_NOT_REQUESTED,
    REQUEST_STATE_REQUESTED,
    REQUESTER_UNSPECIFIED,
    normalize_execution_scope,
    normalize_target_reference,
)
from ai.schemas.finding_correlation_result import (
    FINDING_CORRELATION_RESULT_RULE_VERSION,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import FINDING_RESULT_RULE_VERSION
from ai.schemas.human_decision import (
    DECISION_APPROVE_RESEARCH,
    DECISION_DEFER,
    DECISION_ESCALATE,
    DECISION_NEEDS_REVIEW,
    DECISION_REJECT,
    DECISION_REQUEST_MORE_EVIDENCE,
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_TYPES,
    sanitize_human_decision,
)
from ai.schemas.human_decision_result import (
    HUMAN_REVIEW_RESULT_RULE_VERSION,
)
from ai.schemas.human_review import sanitize_human_review_plan
from ai.schemas.research_priority_result import (
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
)
from ai.schemas.continuous_learning_result import (
    CONTINUOUS_LEARNING_RESULT_RULE_VERSION,
)

EXECUTION_CONTROL_RULES_RULE_VERSION = "r58-5"
RULE_VERSION = EXECUTION_CONTROL_RULES_RULE_VERSION

#: Rule versions this gate understands for its upstream context layers.
EXPECTED_FINDING_RULE_VERSION = FINDING_RESULT_RULE_VERSION
EXPECTED_CORRELATION_RULE_VERSION = FINDING_CORRELATION_RESULT_RULE_VERSION
EXPECTED_PRIORITY_RULE_VERSION = RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
EXPECTED_DECISION_RULE_VERSION = HUMAN_REVIEW_RESULT_RULE_VERSION
EXPECTED_LEARNING_RULE_VERSION = CONTINUOUS_LEARNING_RESULT_RULE_VERSION

#: R57 recommendations that keep execution blocked (review still required).
BLOCKING_LEARNING_RECOMMENDATIONS: tuple[str, ...] = (
    CALIB_REQUEST_MORE_EVIDENCE,
    CALIB_REVIEW_SAFETY_BOUNDARY,
)

#: R57 recommendations that are informational only; they never authorize.
INFORMATIONAL_LEARNING_RECOMMENDATIONS: tuple[str, ...] = tuple(
    code
    for code in CALIBRATION_RECOMMENDATION_CODES
    if code not in BLOCKING_LEARNING_RECOMMENDATIONS
)

#: Only APPROVE_RESEARCH may precede an authorization; it never authorizes
#: by itself and never authorizes anything beyond the explicit request.
AUTHORIZING_DECISION_TYPES: tuple[str, ...] = (DECISION_APPROVE_RESEARCH,)

#: Decision types that block execution outright.
BLOCKING_DECISION_TYPES: tuple[str, ...] = (
    DECISION_REQUEST_MORE_EVIDENCE,
    DECISION_DEFER,
    DECISION_REJECT,
    DECISION_NEEDS_REVIEW,
)

#: Decision types that require additional review before any authorization.
REVIEW_REQUIRED_DECISION_TYPES: tuple[str, ...] = (DECISION_ESCALATE,)

#: Closed safety flags: a *true* value maps to a closed rejection reason.
FORBIDDEN_FLAG_REASONS: dict[str, str] = {
    "exploit_authorized": SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    "exploit_execution": SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    "execute_exploit": SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    "run_exploit": SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    "weaponize": SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    "vulnerability_confirmed": SAFETY_REASON_VULNERABILITY_CONFIRMATION,
    "confirmation_claim": SAFETY_REASON_VULNERABILITY_CONFIRMATION,
    "confirm_vulnerability": SAFETY_REASON_VULNERABILITY_CONFIRMATION,
    "payload": SAFETY_REASON_PAYLOAD_GENERATION,
    "payload_generation": SAFETY_REASON_PAYLOAD_GENERATION,
    "generate_payload": SAFETY_REASON_PAYLOAD_GENERATION,
    "attack_plan": SAFETY_REASON_ATTACK_PLANNING,
    "attack_planning": SAFETY_REASON_ATTACK_PLANNING,
    "plan_attack": SAFETY_REASON_ATTACK_PLANNING,
    "command": SAFETY_REASON_COMMAND_EXECUTION,
    "command_execution": SAFETY_REASON_COMMAND_EXECUTION,
    "execute_command": SAFETY_REASON_COMMAND_EXECUTION,
    "shell_command": SAFETY_REASON_COMMAND_EXECUTION,
    "run_command": SAFETY_REASON_COMMAND_EXECUTION,
    "arbitrary_code": SAFETY_REASON_CODE_EXECUTION,
    "code_execution": SAFETY_REASON_CODE_EXECUTION,
    "execute_code": SAFETY_REASON_CODE_EXECUTION,
    "network_execution": SAFETY_REASON_NETWORK_EXECUTION,
    "network_io": SAFETY_REASON_NETWORK_EXECUTION,
    "send_request": SAFETY_REASON_NETWORK_EXECUTION,
    "http_request": SAFETY_REASON_NETWORK_EXECUTION,
    "dns_query": SAFETY_REASON_NETWORK_EXECUTION,
    "scanner_execution": SAFETY_REASON_SCANNER_EXECUTION,
    "run_scanner": SAFETY_REASON_SCANNER_EXECUTION,
    "launch_scanner": SAFETY_REASON_SCANNER_EXECUTION,
    "browser_automation": SAFETY_REASON_BROWSER_AUTOMATION,
    "automate_browser": SAFETY_REASON_BROWSER_AUTOMATION,
    "run_browser": SAFETY_REASON_BROWSER_AUTOMATION,
    "subprocess": SAFETY_REASON_SUBPROCESS_EXECUTION,
    "subprocess_execution": SAFETY_REASON_SUBPROCESS_EXECUTION,
    "spawn_process": SAFETY_REASON_SUBPROCESS_EXECUTION,
    "autonomous_authorization": SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    "auto_authorize": SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    "auto_execute": SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    "policy_bypass": SAFETY_REASON_POLICY_BYPASS,
    "bypass_policy": SAFETY_REASON_POLICY_BYPASS,
    "disable_safety": SAFETY_REASON_POLICY_BYPASS,
    "disable_governance": SAFETY_REASON_POLICY_BYPASS,
    "human_approval_bypass": SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    "bypass_human": SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    "bypass_approval": SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    "skip_human_approval": SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    "unsafe_action": SAFETY_REASON_UNSAFE_ACTION,
}

#: Closed text markers: a marker in free text maps to a rejection reason.
FORBIDDEN_TEXT_MARKERS: tuple[tuple[str, str], ...] = (
    ("EXECUTE_EXPLOIT", SAFETY_REASON_EXPLOIT_AUTHORIZATION),
    ("RUN_EXPLOIT", SAFETY_REASON_EXPLOIT_AUTHORIZATION),
    ("WEAPONIZE", SAFETY_REASON_EXPLOIT_AUTHORIZATION),
    ("GENERATE_PAYLOAD", SAFETY_REASON_PAYLOAD_GENERATION),
    ("PAYLOAD_GENERATION", SAFETY_REASON_PAYLOAD_GENERATION),
    ("ATTACK_PLAN", SAFETY_REASON_ATTACK_PLANNING),
    ("PLAN_ATTACK", SAFETY_REASON_ATTACK_PLANNING),
    ("RUN_COMMAND", SAFETY_REASON_COMMAND_EXECUTION),
    ("EXECUTE_COMMAND", SAFETY_REASON_COMMAND_EXECUTION),
    ("SHELL_EXEC", SAFETY_REASON_COMMAND_EXECUTION),
    ("OS_SYSTEM", SAFETY_REASON_COMMAND_EXECUTION),
    ("ARBITRARY_CODE_EXECUTION", SAFETY_REASON_CODE_EXECUTION),
    ("EXECUTE_CODE", SAFETY_REASON_CODE_EXECUTION),
    ("NETWORK_EXECUTION", SAFETY_REASON_NETWORK_EXECUTION),
    ("SEND_REQUEST", SAFETY_REASON_NETWORK_EXECUTION),
    ("DNS_QUERY", SAFETY_REASON_NETWORK_EXECUTION),
    ("RUN_SCANNER", SAFETY_REASON_SCANNER_EXECUTION),
    ("LAUNCH_SCANNER", SAFETY_REASON_SCANNER_EXECUTION),
    ("SCANNER_EXECUTION", SAFETY_REASON_SCANNER_EXECUTION),
    ("BROWSER_AUTOMATION", SAFETY_REASON_BROWSER_AUTOMATION),
    ("AUTOMATE_BROWSER", SAFETY_REASON_BROWSER_AUTOMATION),
    ("SUBPROCESS_EXECUTION", SAFETY_REASON_SUBPROCESS_EXECUTION),
    ("SPAWN_PROCESS", SAFETY_REASON_SUBPROCESS_EXECUTION),
    ("AUTONOMOUS_EXECUTION", SAFETY_REASON_AUTONOMOUS_AUTHORIZATION),
    ("AUTO_EXECUTE", SAFETY_REASON_AUTONOMOUS_AUTHORIZATION),
    ("DISABLE_SAFETY", SAFETY_REASON_POLICY_BYPASS),
    ("DISABLE_GOVERNANCE", SAFETY_REASON_POLICY_BYPASS),
    ("BYPASS_HUMAN", SAFETY_REASON_HUMAN_APPROVAL_BYPASS),
    ("BYPASS_APPROVAL", SAFETY_REASON_HUMAN_APPROVAL_BYPASS),
    ("SKIP_HUMAN_APPROVAL", SAFETY_REASON_HUMAN_APPROVAL_BYPASS),
    ("CONFIRM_VULNERABILITY", SAFETY_REASON_VULNERABILITY_CONFIRMATION),
    ("VULNERABILITY_CONFIRMED", SAFETY_REASON_VULNERABILITY_CONFIRMATION),
)

#: Negation prefixes that make a marker explicitly safe (defense in depth).
SAFE_MARKER_PREFIXES: tuple[str, ...] = (
    "NO_",
    "NOT_",
    "NON_",
    "WITHOUT_",
    "AVOID_",
    "PREVENT_",
)

#: Field names whose values are closed vocabularies, not free text.
CLOSED_CODE_KEYS: frozenset[str] = frozenset(
    {
        "safety_reasons",
        "rejection_codes",
        "block_reasons",
        "allow_reasons",
        "request_rejection_codes",
        "limitations",
        "preconditions",
        "safety_checks",
        "stop_conditions",
        "approval_constraints",
        "decision_options",
        "not_authorized",
    }
)

#: Action -> declarative step sequence (safe research/control steps only).
ACTION_STEPS: dict[str, tuple[str, ...]] = {
    ACTION_COLLECT_EXISTING_EVIDENCE: (
        STEP_LOAD_RECORDED_EVIDENCE,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
    ACTION_REVIEW_EXISTING_RESPONSE: (
        STEP_REVIEW_STORED_RESPONSE,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
    ACTION_RECHECK_SCOPE: (
        STEP_CONFIRM_SCOPE_METADATA,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
    ACTION_REASSESS_CONTEXT: (
        STEP_RECONFIRM_CONTEXT_SUMMARY,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
    ACTION_PREPARE_RESEARCH_STEP: (
        STEP_PREPARE_RESEARCH_NOTE,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
    ACTION_REQUEST_HUMAN_REVIEW: (
        STEP_REQUEST_HUMAN_REVIEW,
        STEP_VERIFY_HUMAN_AUTHORIZATION,
        STEP_ASSERT_SAFETY_CONSTRAINTS,
    ),
}

#: Base limitations carried by every request/authorization/plan/result.
BASE_LIMITATIONS: tuple[str, ...] = (
    "NO_EXECUTION_PERFORMED",
    "NO_NETWORK_REQUESTS",
    "NO_VULNERABILITY_CONFIRMATION",
    "NO_EXPLOIT_GENERATION",
    "RESEARCH_ONLY",
    "CONTROL_GATE_ONLY_NOT_EXECUTOR",
    "DECLARATIVE_ONLY",
    "EXTERNAL_EXECUTOR_ABSENT",
    "FUTURE_EXECUTION_LAYER_REQUIRED",
    "HUMAN_AUTHORITY_REQUIRED",
    "AUTHORIZATION_IS_NOT_EXECUTION",
    "HUMAN_APPROVAL_IS_NOT_EXECUTION",
    "PRIORITY_NOT_AUTHORIZATION",
    "FINDING_NOT_CONFIRMATION",
    "CORRELATION_NOT_AUTHORIZATION",
    "LEARNING_NOT_AUTHORIZATION",
    "DECISION_DOES_NOT_AUTHORIZE_ACTION",
    "SCOPE_NOT_EXPANDABLE",
    "ACTION_NOT_TRANSFERABLE",
    "TARGET_NOT_TRANSFERABLE",
    "VALIDITY_EXPLICIT_ONLY",
    "PAYLOAD_AUTHORIZATION_NOT_AUTHORIZED",
    "ATTACK_PLANNING_NOT_AUTHORIZED",
    "AUTONOMOUS_EXECUTION_NOT_AUTHORIZED",
    "NO_LLM_INVOLVEMENT",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def limitations_for(*extra: str) -> list[str]:
    """Deterministic ordered limitation list (base + explicit extras)."""

    found = set(BASE_LIMITATIONS)
    for code in extra:
        if code:
            found.add(code)
    return [code for code in EXECUTION_CONTROL_LIMITATIONS if code in found]


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------


def execution_request_id(
    *,
    finding_id: str,
    action_type: str,
    requested_action_type: str,
    action_scope: str,
    target_reference: str,
    purpose: str,
    requested_by: str,
    decision_reference: str,
    execution_requested: bool,
) -> str:
    """Content-derived execution request id (no runtime ordering)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": EXECUTION_REQUEST_RULE_VERSION,
                "finding_id": finding_id,
                "action_type": action_type,
                "requested_action_type": requested_action_type,
                "action_scope": action_scope,
                "target_reference": target_reference,
                "purpose": purpose,
                "requested_by": requested_by,
                "decision_reference": decision_reference,
                "execution_requested": execution_requested,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "exr-" + digest[:16]


def execution_authorization_id(
    *,
    request_id: str,
    finding_id: str,
    decision_reference: str,
    approved_action: str,
    approved_scope: str,
    approved_target: str,
    validity_state: str,
    authorization_status: str,
) -> str:
    """Content-derived authorization id (no runtime ordering)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r58-2",
                "request_id": request_id,
                "finding_id": finding_id,
                "decision_reference": decision_reference,
                "approved_action": approved_action,
                "approved_scope": approved_scope,
                "approved_target": approved_target,
                "validity_state": validity_state,
                "authorization_status": authorization_status,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "exa-" + digest[:16]


def controlled_execution_plan_id(
    *,
    request_id: str,
    finding_id: str,
    action_type: str,
    target_reference: str,
    action_scope: str,
    step_codes: object,
) -> str:
    """Content-derived controlled execution plan id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r58-3",
                "request_id": request_id,
                "finding_id": finding_id,
                "action_type": action_type,
                "target_reference": target_reference,
                "action_scope": action_scope,
                "step_codes": list(step_codes or ()),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "exp-" + digest[:16]


def execution_control_id(
    *,
    request_id: str,
    authorization_id: str,
    plan_id: str,
    finding_id: str,
    action_type: str,
    target_reference: str,
    action_scope: str,
    safety_result: str,
    control_outcome: str,
    reasons: object,
) -> str:
    """Content-derived execution control result id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r58-4",
                "request_id": request_id,
                "authorization_id": authorization_id,
                "plan_id": plan_id,
                "finding_id": finding_id,
                "action_type": action_type,
                "target_reference": target_reference,
                "action_scope": action_scope,
                "safety_result": safety_result,
                "control_outcome": control_outcome,
                "reasons": list(reasons or ()),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "exc-" + digest[:16]


def execution_audit_id(
    *,
    request_id: str,
    decision_id: str,
    authorization_id: str,
    action_type: str,
    target_reference: str,
    action_scope: str,
    safety_result: str,
    control_outcome: str,
    reasons: object,
) -> str:
    """Content-derived audit id for one controlled execution decision."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r58-5",
                "request_id": request_id,
                "decision_id": decision_id,
                "authorization_id": authorization_id,
                "action_type": action_type,
                "target_reference": target_reference,
                "action_scope": action_scope,
                "safety_result": safety_result,
                "control_outcome": control_outcome,
                "reasons": list(reasons or ()),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "exd-" + digest[:16]


# ---------------------------------------------------------------------------
# Safety gate (defense in depth)
# ---------------------------------------------------------------------------


def _collect_forbidden_flags(
    value: object, depth: int = 0
) -> dict[str, str]:
    """Collect true safety-flag violations (keys -> reason)."""

    found: dict[str, str] = {}
    if depth > 8:
        return found
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).strip().lower()
            reason = FORBIDDEN_FLAG_REASONS.get(key_text)
            if reason is not None and item is True:
                found[key_text] = reason
            for nested_key, nested_reason in _collect_forbidden_flags(
                item, depth + 1
            ).items():
                found.setdefault(nested_key, nested_reason)
    elif isinstance(value, (list, tuple)):
        for item in value:
            for nested_key, nested_reason in _collect_forbidden_flags(
                item, depth + 1
            ).items():
                found.setdefault(nested_key, nested_reason)
    return found


def _collect_text(value: object, depth: int = 0) -> str:
    """Collect free-text content only (closed code fields are skipped)."""

    if depth > 8:
        return ""
    parts: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in CLOSED_CODE_KEYS:
                continue
            parts.append(_collect_text(item, depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in value:
            parts.append(_collect_text(item, depth + 1))
    elif isinstance(value, str):
        parts.append(value)
    return " ".join(parts)


def _marker_present(text: str, marker: str) -> bool:
    """True when a forbidden marker occurs without a safe negation prefix."""

    start = 0
    while True:
        index = text.find(marker, start)
        if index == -1:
            return False
        window = text[max(0, index - 10):index]
        if not any(
            window.endswith(prefix) for prefix in SAFE_MARKER_PREFIXES
        ):
            return True
        start = index + len(marker)


def safety_reasons_for(value: object) -> list[str]:
    """Closed, deterministically ordered safety rejection reasons.

    Scans both true safety flags and free-text markers. Never mutates or
    repairs the input; never downgrades an unsafe request into a safe one.
    """

    found: set[str] = set(_collect_forbidden_flags(value).values())
    text = _collect_text(value).upper()
    for marker, reason in FORBIDDEN_TEXT_MARKERS:
        if _marker_present(text, marker):
            found.add(reason)
    if isinstance(value, (list, tuple)):
        found.add(SAFETY_REASON_UNSAFE_INPUT)
    return [reason for reason in SAFETY_REJECTION_REASONS if reason in found]


def unsafe_input_reason(value: object) -> str:
    """Primary closed safety reason, or ``""`` when nothing was detected."""

    reasons = safety_reasons_for(value)
    return reasons[0] if reasons else ""


def structured_safety_reasons(value: object) -> list[str]:
    """Ordered safety reasons already recorded in structured safety fields.

    A previously blocked request/result carries its safety evidence in
    ``safety_context.safety_reasons`` / ``safety_reasons`` rather than in free
    text or true flags; the gate must preserve that evidence on re-evaluation.
    """

    if not isinstance(value, dict):
        return []
    codes: list[object] = []
    safety_context = value.get("safety_context")
    if isinstance(safety_context, dict):
        codes.extend(safety_context.get("safety_reasons") or ())
    codes.extend(value.get("safety_reasons") or ())
    found = set()
    for code in codes:
        text = _text(code).upper()
        if text in SAFETY_REJECTION_REASONS:
            found.add(text)
    return [reason for reason in SAFETY_REJECTION_REASONS if reason in found]


def has_wildcard(value: object) -> bool:
    """True when a target/scope text carries a wildcard."""

    return "*" in _text(value)


# ---------------------------------------------------------------------------
# Exact matching (no expansion)
# ---------------------------------------------------------------------------


def scope_matches(requested: object, approved: object) -> bool:
    """Exact scope equality after bounded normalization."""

    return normalize_execution_scope(requested) == normalize_execution_scope(
        approved
    ) and bool(normalize_execution_scope(requested))


def target_matches(requested: object, approved: object) -> bool:
    """Exact target equality after bounded normalization."""

    return normalize_target_reference(
        requested
    ) == normalize_target_reference(approved) and bool(
        normalize_target_reference(requested)
    )


def action_matches(requested: object, approved: object) -> bool:
    """Exact closed-vocabulary action equality; unsupported never matches."""

    requested_text = _text(requested).upper()
    approved_text = _text(approved).upper()
    if requested_text not in EXECUTION_ACTIONS:
        return False
    return requested_text == approved_text


def finding_matches(requested: object, approved: object) -> bool:
    """Exact finding identity match (validated finding ids only)."""

    requested_text = _text(requested)
    approved_text = _text(approved)
    if not FINDING_ID_RE.match(requested_text):
        return False
    return requested_text == approved_text


def decision_matches(requested: object, approved: object) -> bool:
    """Exact decision reference match when a reference was supplied."""

    requested_text = _text(requested)
    approved_text = _text(approved)
    if not requested_text:
        return True
    return requested_text == approved_text


# ---------------------------------------------------------------------------
# Decision resolution (R56)
# ---------------------------------------------------------------------------


def decision_type_is_known(decision_type: object) -> bool:
    return _text(decision_type).upper() in HUMAN_DECISION_TYPES


def decision_is_human(decision: object) -> bool:
    """True only for an explicit, bounded human decision record."""

    if not isinstance(decision, dict):
        return False
    if _text(decision.get("decision_source")).upper() != "HUMAN":
        return False
    if _text(decision.get("decision_authority")).upper() != "HUMAN":
        return False
    if decision.get("human_authority") is not True:
        return False
    for key in (
        "execution_authorized",
        "vulnerability_confirmed",
        "exploit_authorized",
    ):
        if decision.get(key) is not False:
            return False
    return True


def review_decisions(review_result: object, finding_id: str) -> dict:
    """Resolve the R56 decisions relevant to one finding (fail closed).

    Returns a bounded dict:
    ``{"decisions": [...], "pending": bool, "invalid": bool, "error": str}``.
    An error means the review container itself could not be trusted.
    """

    if not isinstance(review_result, dict):
        if review_result is None:
            return {
                "decisions": [],
                "pending": False,
                "invalid": False,
                "error": "",
            }
        return {
            "decisions": [],
            "pending": False,
            "invalid": False,
            "error": REASON_MALFORMED_INPUT,
        }
    if (
        _text(review_result.get("rule_version"))
        != HUMAN_REVIEW_RESULT_RULE_VERSION
    ):
        return {
            "decisions": [],
            "pending": False,
            "invalid": False,
            "error": REASON_RULE_VERSION_MISMATCH,
        }
    safety = safety_reasons_for(review_result)
    if safety:
        return {
            "decisions": [],
            "pending": False,
            "invalid": False,
            "error": REASON_INVALID_INPUT,
        }
    if (
        review_result.get("human_authority_required", True) is False
        or review_result.get("ai_role") not in (None, "", "ADVISORY")
    ):
        return {
            "decisions": [],
            "pending": False,
            "invalid": False,
            "error": REASON_INVALID_INPUT,
        }
    if (
        review_result.get("execution_authorized") is True
        or review_result.get("vulnerability_confirmed") is True
    ):
        return {
            "decisions": [],
            "pending": False,
            "invalid": False,
            "error": REASON_INVALID_INPUT,
        }

    decisions: list[dict] = []
    pending = False
    invalid = False
    for raw_review in review_result.get("reviews") or ():
        review = sanitize_human_review_plan(raw_review)
        if review.get("finding_id") != finding_id:
            continue
        if (
            review.get("human_authority") is not True
            or review.get("execution_authorized") is not False
            or review.get("vulnerability_confirmed") is not False
        ):
            return {
                "decisions": [],
                "pending": False,
                "invalid": False,
                "error": REASON_INVALID_INPUT,
            }
        decision = review.get("decision") or {}
        if review.get("review_state") == DECISION_STATE_DECIDED and decision:
            sanitized = sanitize_human_decision(decision)
            if sanitized.get("decision_state") != DECISION_STATE_DECIDED:
                invalid = True
                continue
            decisions.append(sanitized)
        elif review.get("review_state") == DECISION_STATE_PENDING:
            pending = True
        elif review.get("review_state") == DECISION_STATE_EXPIRED:
            invalid = True
    for raw_invalid in review_result.get("invalid_decisions") or ():
        if isinstance(raw_invalid, dict) and _text(
            raw_invalid.get("finding_id")
        ) == finding_id:
            invalid = True
    return {
        "decisions": decisions,
        "pending": pending,
        "invalid": invalid,
        "error": "",
    }


def decision_authorizes(decision_type: object) -> bool:
    """Only APPROVE_RESEARCH may precede a controlled authorization."""

    return _text(decision_type).upper() == DECISION_APPROVE_RESEARCH


def decision_blocks(decision_type: object) -> bool:
    """Decision types that block execution outright (never authorize)."""

    return _text(decision_type).upper() in BLOCKING_DECISION_TYPES


def decision_requires_review(decision_type: object) -> bool:
    """Decision types that require further review before authorization."""

    return _text(decision_type).upper() in REVIEW_REQUIRED_DECISION_TYPES


# ---------------------------------------------------------------------------
# R57 learning integration (context only; never authorization)
# ---------------------------------------------------------------------------


def learning_recommendation_codes(learning_result: object) -> list[str]:
    """Bounded, ordered R57 recommendation codes (empty when unavailable)."""

    if not isinstance(learning_result, dict):
        return []
    if _text(learning_result.get("rule_version")) != (
        CONTINUOUS_LEARNING_RESULT_RULE_VERSION
    ):
        return []
    found = set()
    for recommendation in learning_result.get(
        "calibration_recommendations"
    ) or ():
        if isinstance(recommendation, dict):
            code = _text(recommendation.get("recommendation_code")).upper()
            if code in CALIBRATION_RECOMMENDATION_CODES:
                found.add(code)
    return [code for code in CALIBRATION_RECOMMENDATION_CODES if code in found]


def blocking_learning_recommendations(learning_result: object) -> list[str]:
    """R57 recommendations that keep execution blocked (review required)."""

    return [
        code
        for code in learning_recommendation_codes(learning_result)
        if code in BLOCKING_LEARNING_RECOMMENDATIONS
    ]


# ---------------------------------------------------------------------------
# Request evaluation primitives
# ---------------------------------------------------------------------------


def request_rejection_codes(
    *,
    finding_id: str,
    action_type: str,
    action_scope: str,
    target_reference: str,
    purpose: str,
    requested_by: str,
    wildcard_scope: bool,
    wildcard_target: bool,
    safety_reasons: object,
) -> list[str]:
    """Closed ordered rejection codes for one proposed request."""

    found: set[str] = set()
    if not FINDING_ID_RE.match(_text(finding_id)):
        found.add(REJECTION_FINDING_ID_REQUIRED)
    if _text(action_type).upper() not in EXECUTION_ACTIONS:
        found.add(REJECTION_ACTION_NOT_SUPPORTED)
    if not normalize_execution_scope(action_scope):
        found.add(REJECTION_SCOPE_REQUIRED)
    if not normalize_target_reference(target_reference):
        found.add(REJECTION_TARGET_REQUIRED)
    if _text(requested_by).upper() in ("", REQUESTER_UNSPECIFIED):
        found.add(REJECTION_REQUESTER_REQUIRED)
    if not _text(purpose):
        found.add(REJECTION_PURPOSE_REQUIRED)
    if wildcard_scope:
        found.add(REJECTION_WILDCARD_SCOPE)
    if wildcard_target:
        found.add(REJECTION_WILDCARD_TARGET)
    if list(safety_reasons or ()):
        found.add(REJECTION_UNSAFE_REQUEST)
    return [
        code
        for code in (
            REJECTION_FINDING_ID_REQUIRED,
            REJECTION_ACTION_NOT_SUPPORTED,
            REJECTION_SCOPE_REQUIRED,
            REJECTION_TARGET_REQUIRED,
            REJECTION_REQUESTER_REQUIRED,
            REJECTION_PURPOSE_REQUIRED,
            REJECTION_MALFORMED_REQUEST,
            REJECTION_UNSAFE_REQUEST,
            REJECTION_WILDCARD_SCOPE,
            REJECTION_WILDCARD_TARGET,
        )
        if code in found
    ]


def request_state_for(
    *,
    execution_requested: bool,
    rejection_codes: object,
    safety_reasons: object,
    wildcard_present: bool,
) -> str:
    """Deterministic fail-closed request state."""

    if not execution_requested:
        return REQUEST_STATE_NOT_REQUESTED
    if list(safety_reasons or ()) or wildcard_present:
        return REQUEST_STATE_BLOCKED
    if list(rejection_codes or ()):
        return REQUEST_STATE_INVALID
    return REQUEST_STATE_REQUESTED


# ---------------------------------------------------------------------------
# Declarative plan content
# ---------------------------------------------------------------------------


def action_steps(action_type: object) -> list[str]:
    """Declarative step codes for a supported action (empty otherwise)."""

    return list(ACTION_STEPS.get(_text(action_type).upper(), ()))


def plan_preconditions() -> list[str]:
    return list(EXECUTION_PLAN_PRECONDITIONS)


def plan_safety_checks() -> list[str]:
    return list(EXECUTION_SAFETY_CHECKS)


def plan_stop_conditions() -> list[str]:
    return list(EXECUTION_STOP_CONDITIONS)


def plan_status_for(
    *,
    request_state: str,
    authorization_status: str,
    validity_state: str,
    safety_result: str,
    preconditions_met: bool,
) -> str:
    """Deterministic declarative plan status (no EXECUTED state exists)."""

    if request_state == REQUEST_STATE_NOT_REQUESTED:
        return PLAN_STATUS_NOT_REQUESTED
    if request_state == REQUEST_STATE_INVALID:
        return PLAN_STATUS_INVALID
    if request_state == REQUEST_STATE_BLOCKED:
        return PLAN_STATUS_BLOCKED
    if validity_state == VALIDITY_EXPIRED or (
        authorization_status == AUTHORIZATION_STATUS_EXPIRED
    ):
        return PLAN_STATUS_EXPIRED
    if validity_state == VALIDITY_INVALID or (
        authorization_status == AUTHORIZATION_STATUS_INVALID
    ):
        return PLAN_STATUS_INVALID
    if authorization_status == AUTHORIZATION_STATUS_BLOCKED:
        return PLAN_STATUS_BLOCKED
    if authorization_status in ("", AUTHORIZATION_STATUS_REQUESTED):
        return PLAN_STATUS_REQUESTED
    if authorization_status == AUTHORIZATION_STATUS_AUTHORIZED:
        if safety_result != SAFETY_PASS:
            return PLAN_STATUS_BLOCKED
        if preconditions_met:
            return PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        return PLAN_STATUS_AUTHORIZED
    if authorization_status == AUTHORIZATION_STATUS_NOT_REQUESTED:
        return PLAN_STATUS_NOT_REQUESTED
    return PLAN_STATUS_INVALID


def plan_status_is_ready(status: object) -> bool:
    return _text(status).upper() == PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR


# ---------------------------------------------------------------------------
# Control evaluation
# ---------------------------------------------------------------------------


def control_outcome_for(*, request_state: str, safety_result: str,
                        authorization_status: str) -> str:
    """Deterministic control outcome (ALLOW is eligibility, not execution)."""

    if request_state == REQUEST_STATE_NOT_REQUESTED:
        return CONTROL_OUTCOME_NOT_REQUESTED
    if request_state == REQUEST_STATE_INVALID:
        return CONTROL_OUTCOME_INVALID
    if safety_result == SAFETY_INVALID:
        return CONTROL_OUTCOME_INVALID
    if (
        request_state == REQUEST_STATE_REQUESTED
        and safety_result == SAFETY_PASS
        and authorization_status == AUTHORIZATION_STATUS_AUTHORIZED
    ):
        return CONTROL_OUTCOME_ALLOW
    return CONTROL_OUTCOME_DENY


def control_status_for(*, control_outcome: str, fatal: bool = False) -> str:
    if fatal:
        return CONTROL_STATUS_FAILED
    if control_outcome == CONTROL_OUTCOME_ALLOW:
        return CONTROL_STATUS_COMPLETED
    if control_outcome == CONTROL_OUTCOME_NOT_REQUESTED:
        return CONTROL_STATUS_NOT_REQUESTED
    if control_outcome == CONTROL_OUTCOME_INVALID:
        return CONTROL_STATUS_INVALID
    return CONTROL_STATUS_BLOCKED


def control_summary(
    *,
    request_present: bool,
    block_reasons: object,
    safety_reasons: object,
    authorization_reasons: object,
    step_count: int,
) -> dict:
    """Bounded deterministic summary of one control evaluation."""

    return {
        "request_count": 1 if request_present else 0,
        "block_reason_count": len(list(block_reasons or ())),
        "safety_reason_count": len(list(safety_reasons or ())),
        "authorization_reason_count": len(list(authorization_reasons or ())),
        "step_count": max(0, min(MAX_STEPS, int(step_count or 0))),
        "research_only": True,
    }


__all__ = [
    "EXECUTION_CONTROL_RULES_RULE_VERSION",
    "RULE_VERSION",
    "EXPECTED_FINDING_RULE_VERSION",
    "EXPECTED_CORRELATION_RULE_VERSION",
    "EXPECTED_PRIORITY_RULE_VERSION",
    "EXPECTED_DECISION_RULE_VERSION",
    "EXPECTED_LEARNING_RULE_VERSION",
    "BLOCKING_LEARNING_RECOMMENDATIONS",
    "INFORMATIONAL_LEARNING_RECOMMENDATIONS",
    "AUTHORIZING_DECISION_TYPES",
    "BLOCKING_DECISION_TYPES",
    "REVIEW_REQUIRED_DECISION_TYPES",
    "FORBIDDEN_FLAG_REASONS",
    "FORBIDDEN_TEXT_MARKERS",
    "SAFE_MARKER_PREFIXES",
    "CLOSED_CODE_KEYS",
    "ACTION_STEPS",
    "BASE_LIMITATIONS",
    "APPROVAL_CONSTRAINTS",
    "limitations_for",
    "execution_request_id",
    "execution_authorization_id",
    "controlled_execution_plan_id",
    "execution_control_id",
    "execution_audit_id",
    "safety_reasons_for",
    "unsafe_input_reason",
    "structured_safety_reasons",
    "has_wildcard",
    "scope_matches",
    "target_matches",
    "action_matches",
    "finding_matches",
    "decision_matches",
    "review_decisions",
    "decision_authorizes",
    "decision_blocks",
    "decision_requires_review",
    "decision_type_is_known",
    "decision_is_human",
    "learning_recommendation_codes",
    "blocking_learning_recommendations",
    "request_rejection_codes",
    "request_state_for",
    "action_steps",
    "plan_preconditions",
    "plan_safety_checks",
    "plan_stop_conditions",
    "plan_status_for",
    "plan_status_is_ready",
    "control_outcome_for",
    "control_status_for",
    "control_summary",
]

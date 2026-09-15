"""Stage R60.5 deterministic copilot rules (pure engine).

Provides the deterministic primitives behind the Watch Bug Bounty Copilot:

    validated R53-R59 artifacts
      -> bounded context facts (human / learning / execution / workflow)
      -> deterministic research opportunities and recommendations
      -> confidence and review requirements
      -> advisory copilot brief
      -> deterministic ids, provenance and limitations

Hard boundaries encoded here:

- Advisory composition only: no primitive executes, sends, scans, browses or
  modifies anything; the only side effect is returning data.
- No duplicated intelligence: priorities, evidence, findings, correlation,
  decisions, learning and execution status are consumed verbatim from their
  existing rule versions; the R58 safety scanner is imported, never
  re-implemented.
- Fail closed: malformed, mis-versioned or contradictory inputs produce
  closed structured errors and a safe (blocked/review-required) advisory
  state; nothing is silently skipped or optimistically authorized.
- Deterministic: content-derived ids only; stable ordering; no timestamps,
  UUIDs, pids, randomness or wall-clock time.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no database.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.execution_control_rules import (
    BLOCKING_LEARNING_RECOMMENDATIONS,
    safety_reasons_for,
    structured_safety_reasons,
)
from ai.schemas.copilot_brief import (
    BASIS_CONFLICT_PRESENT,
    BASIS_DUPLICATE_PRESENT,
    BASIS_EVIDENCE_COMPLETE,
    BASIS_EVIDENCE_INSUFFICIENT,
    BASIS_EVIDENCE_PARTIAL,
    BASIS_HUMAN_DECISION_PENDING,
    BASIS_HUMAN_REVIEW_REQUIRED,
    BASIS_NO_OPPORTUNITIES,
    BASIS_OPPORTUNITIES_PRESENT,
    BASIS_SAFETY_BLOCKED,
    BASIS_WORKFLOW_BLOCKED,
    BRIEF_BASE_LIMITATIONS,
    CONFIDENCE_BASES,
    COPILOT_BRIEF_LIMITATIONS,
    HIGH_PRIORITY_CLASSES,
    sanitize_recommended_actions,
)
from ai.schemas.copilot_opportunity import (
    COPILOT_OPPORTUNITY_RULE_VERSION,
    COPILOT_RATIONALE_CODES,
    COPILOT_REVIEW_REASONS,
    LIMITATION_WORKFLOW_CONTEXT_MISSING,
    OPPORTUNITY_BASE_LIMITATIONS,
    OPPORTUNITY_BLOCKED,
    OPPORTUNITY_DEFERRED,
    OPPORTUNITY_HIGH_PRIORITY,
    OPPORTUNITY_INSUFFICIENT,
    OPPORTUNITY_PRIORITY,
    OPPORTUNITY_STANDARD,
    RATIONALE_CONFLICT_CONTEXT,
    RATIONALE_DEFERRED_PRIORITY,
    RATIONALE_DUPLICATE_CONTEXT,
    RATIONALE_ELEVATED_PRIORITY,
    RATIONALE_EVIDENCE_COMPLETE,
    RATIONALE_EVIDENCE_INSUFFICIENT,
    RATIONALE_EVIDENCE_PARTIAL,
    RATIONALE_EXECUTION_BLOCKED,
    RATIONALE_EXECUTION_CONTEXT,
    RATIONALE_HIGH_PRIORITY,
    RATIONALE_HUMAN_DECISION_PENDING,
    RATIONALE_HUMAN_DECISION_PRESENT,
    RATIONALE_HUMAN_REVIEW_REQUIRED,
    RATIONALE_INSUFFICIENT_DATA,
    RATIONALE_LEARNING_CONTEXT,
    RATIONALE_RELATED_FINDINGS_PRESENT,
    RATIONALE_SAFETY_BLOCKED,
    RATIONALE_STANDARD_PRIORITY,
    RATIONALE_WORKFLOW_CONTEXT_AVAILABLE,
    RATIONALE_WORKFLOW_CONTEXT_MISSING,
    REVIEW_CONFLICTED_FINDING,
    REVIEW_EXECUTION_CONTROL_BLOCKED,
    REVIEW_HUMAN_DECISION_PENDING,
    REVIEW_HUMAN_NEEDS_REVIEW,
    REVIEW_INVALID_UPSTREAM_CONTEXT,
    REVIEW_LEARNING_REVIEW_REQUIRED,
    REVIEW_LOW_CONFIDENCE,
    REVIEW_MISSING_EVIDENCE,
    sanitize_copilot_opportunity,
    sanitize_copilot_recommendation,
)
from ai.schemas.copilot_result import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_CONTEXT,
    STATUS_PARTIAL,
)
from ai.schemas.execution_request import (
    ACTION_COLLECT_EXISTING_EVIDENCE,
    ACTION_PREPARE_RESEARCH_STEP,
    ACTION_REASSESS_CONTEXT,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_REVIEW_EXISTING_RESPONSE,
)
from ai.schemas.finding_assessment import (
    STATE_CONFLICTED,
    STATE_INSUFFICIENT_EVIDENCE,
    STATE_NEEDS_MORE_EVIDENCE,
)
from ai.schemas.finding_correlation import (
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
)
from ai.schemas.finding_evidence import (
    COMPLETENESS_COMPLETE as EVIDENCE_COMPLETE,
    COMPLETENESS_MISSING as EVIDENCE_MISSING,
    COMPLETENESS_PARTIAL as EVIDENCE_PARTIAL,
    COMPLETENESS_UNKNOWN as EVIDENCE_UNKNOWN,
)
from ai.schemas.human_decision import (
    RATIONALE_CONFLICT_REQUIRES_RESOLUTION,
    RATIONALE_DUPLICATE_RESEARCH_OVERLAP,
    RATIONALE_EVIDENCE_INCOMPLETE,
    RATIONALE_ESCALATION_REQUIRED,
    RATIONALE_GOVERNANCE_REVIEW_REQUIRED,
    RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING,
    RATIONALE_PROVENANCE_INCOMPLETE,
    RATIONALE_SEVERITY_CONTEXT_REQUIRED,
)
from ai.schemas.research_priority import (
    BAND_CRITICAL,
    BAND_DEFERRED,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    CONFLICT_PRESENT,
)
from ai.schemas.security_research_workflow_result import (
    SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
    SAFETY_STATUS_EXECUTION_BLOCKED,
    SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
    SAFETY_STATUS_INVALID,
    SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    SAFETY_STATUS_RESEARCH_ONLY,
    SAFETY_STATUS_SAFETY_BLOCKED,
    STATE_BLOCKED,
    STATE_INVALID,
    WORKFLOW_STATES,
)

BUG_BOUNTY_COPILOT_RULES_RULE_VERSION = "r60-5"
RULE_VERSION = BUG_BOUNTY_COPILOT_RULES_RULE_VERSION

#: Upstream rule versions this copilot understands (fail closed).
EXPECTED_WORKFLOW_RULE_VERSION = "r59-4"
EXPECTED_FINDING_RULE_VERSION = "r53-6"
EXPECTED_CORRELATION_RULE_VERSION = "r54-2"
EXPECTED_PRIORITIZATION_RULE_VERSION = "r55-2"
EXPECTED_HUMAN_REVIEW_RULE_VERSION = "r56-3"
EXPECTED_LEARNING_RULE_VERSION = "r57-4"
EXPECTED_EXECUTION_CONTROL_RULE_VERSION = "r58-4"

#: Fatal error categories that force FAILED.
FATAL_ERROR_CATEGORIES: tuple[str, ...] = (
    "INVALID_INPUT",
    "MALFORMED_INPUT",
    "RULE_VERSION_MISMATCH",
)

#: Confidence ranks (conservative minimum composition).
_CONFIDENCE_RANK: dict[str, int] = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}
_RANK_CONFIDENCE: tuple[str, ...] = ("UNKNOWN", "LOW", "MEDIUM", "HIGH")

_EVIDENCE_RANK: dict[str, int] = {
    EVIDENCE_COMPLETE: 3,
    EVIDENCE_PARTIAL: 2,
    EVIDENCE_UNKNOWN: 1,
    EVIDENCE_MISSING: 0,
}

MAX_LIST = 24
MAX_TEXT = 240

_STATE_INSUFFICIENT_STATES: tuple[str, ...] = (
    STATE_NEEDS_MORE_EVIDENCE,
    STATE_INSUFFICIENT_EVIDENCE,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def copilot_error(
    error_category: str, input_kind: str = "", message: str = ""
) -> dict:
    """Closed structured copilot error (never silently skipped)."""

    return {
        "stage": "BUG_BOUNTY_COPILOT",
        "error_category": error_category,
        "input_kind": input_kind,
        "message": message[:MAX_TEXT],
    }


def has_fatal_error(errors: object) -> bool:
    """True when any structured error is a fatal (FAILED) category."""

    if not isinstance(errors, (list, tuple)):
        return False
    for entry in errors:
        if isinstance(entry, dict) and entry.get(
            "error_category"
        ) in FATAL_ERROR_CATEGORIES:
            return True
    return False


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------


def copilot_id(descriptor: object) -> str:
    """Content-derived copilot input id."""

    digest = hashlib.sha256(
        _canonical({"rule_version": "r60-1", "descriptor": descriptor}).encode(
            "utf-8"
        )
    ).hexdigest()
    return "bbc-" + digest[:16]


def opportunity_id(finding_id: str, priority_band: str, ranking_position: int) -> str:
    """Content-derived opportunity id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r60-2",
                "finding_id": finding_id,
                "priority_band": priority_band,
                "ranking_position": ranking_position,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "bco-" + digest[:16]


def recommendation_id(
    finding_id: str, workflow_action: str, research_action: str
) -> str:
    """Content-derived recommendation id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r60-2",
                "finding_id": finding_id,
                "workflow_next_action": workflow_action,
                "research_action": research_action,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "bcr-" + digest[:16]


def brief_id(
    copilot_id_value: str,
    workflow_id_value: str,
    opportunity_ids: object,
    action_keys: object,
) -> str:
    """Content-derived brief id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r60-3",
                "copilot_id": copilot_id_value,
                "workflow_id": workflow_id_value,
                "opportunity_ids": sorted(
                    _text(item)
                    for item in (opportunity_ids or ())
                    if _text(item)
                ),
                "action_keys": sorted(
                    _text(item) for item in (action_keys or ()) if _text(item)
                ),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "bcb-" + digest[:16]


def result_id(
    brief_id_value: str,
    status: str,
    safety_status: str,
    errors: object,
) -> str:
    """Content-derived copilot result id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r60-4",
                "brief_id": brief_id_value,
                "status": status,
                "safety_status": safety_status,
                "error_categories": sorted(
                    _text((entry or {}).get("error_category"))
                    for entry in (errors or ())
                    if isinstance(entry, dict)
                    and _text((entry or {}).get("error_category"))
                ),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "bbr-" + digest[:16]


# ---------------------------------------------------------------------------
# Safety gate (reuses the R58 scanner; never duplicated)
# ---------------------------------------------------------------------------


def copilot_safety_reasons(value: object) -> list[str]:
    """Closed safety reasons detected in one input (R58 scanner reused).

    A top-level list is scanned element by element so that a list of valid
    structured results never creates a false safety block.
    """

    reasons: list[str] = []
    candidates = list(value) if isinstance(value, (list, tuple)) else [value]
    for candidate in candidates:
        for reason in safety_reasons_for(candidate):
            if reason not in reasons:
                reasons.append(reason)
        for reason in structured_safety_reasons(candidate):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


def collect_safety_reasons(*values: object) -> list[str]:
    """Ordered union of safety reasons across copilot inputs."""

    reasons: list[str] = []
    for value in values:
        if value is None:
            continue
        for reason in copilot_safety_reasons(value):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


# ---------------------------------------------------------------------------
# Context facts
# ---------------------------------------------------------------------------


def workflow_facts(workflow_result: object) -> dict:
    """Deterministic summary of the R59 workflow result (read-only)."""

    if not isinstance(workflow_result, dict) or not workflow_result:
        return {
            "present": False,
            "workflow_id": "",
            "state": "",
            "safety_status": "",
            "next_action": "",
            "next_action_reason": "",
            "blocked": False,
            "error_count": 0,
            "error": "",
        }
    if _text(workflow_result.get("rule_version")) != (
        EXPECTED_WORKFLOW_RULE_VERSION
    ):
        facts = workflow_facts(None)
        facts["error"] = "RULE_VERSION_MISMATCH"
        return facts
    state = _upper(workflow_result.get("workflow_state"))
    next_action = workflow_result.get("next_action")
    next_action_code = ""
    next_action_reason = ""
    if isinstance(next_action, dict):
        next_action_code = _upper(next_action.get("action_code"))
        next_action_reason = _upper(next_action.get("reason"))
    if not next_action_reason:
        next_action_reason = _upper(
            workflow_result.get("next_action_reason")
        )
    return {
        "present": True,
        "workflow_id": _text(workflow_result.get("workflow_id")),
        "state": state if state in WORKFLOW_STATES else "",
        "safety_status": _upper(workflow_result.get("safety_status")),
        "next_action": next_action_code,
        "next_action_reason": next_action_reason,
        "blocked": state in (STATE_BLOCKED, STATE_INVALID),
        "error_count": len(workflow_result.get("errors") or ()),
        "error": "",
    }


def human_context_facts(review_result: object) -> dict:
    """Deterministic summary of the R56 human decision boundary."""

    if not isinstance(review_result, dict) or not review_result:
        return _empty_human_facts()
    if (
        _text(review_result.get("rule_version"))
        != EXPECTED_HUMAN_REVIEW_RULE_VERSION
    ):
        facts = _empty_human_facts()
        facts["error"] = "RULE_VERSION_MISMATCH"
        return facts
    decided = 0
    pending = 0
    types: list[str] = []
    for review in review_result.get("reviews") or ():
        if not isinstance(review, dict):
            continue
        decision = review.get("decision")
        state = _upper(review.get("review_state"))
        if state == "DECIDED" and isinstance(decision, dict) and decision:
            decided += 1
            dtype = _upper(decision.get("decision_type"))
            if dtype and dtype not in types:
                types.append(dtype)
        elif state == "PENDING_HUMAN_REVIEW":
            pending += 1
    return {
        "present": True,
        "decided_count": decided,
        "pending_count": pending,
        "decision_types": types,
        "approved": "APPROVE_RESEARCH" in types,
        "escalated": "ESCALATE" in types,
        "needs_review": "NEEDS_REVIEW" in types,
        "blocking": any(
            dtype in ("REQUEST_MORE_EVIDENCE", "DEFER", "REJECT")
            for dtype in types
        ),
        "pending": pending > 0 and decided == 0,
        "conflict": len(
            {
                "APPROVE" if "APPROVE_RESEARCH" in types else "",
                "BLOCK"
                if any(
                    dtype in ("REQUEST_MORE_EVIDENCE", "DEFER", "REJECT")
                    for dtype in types
                )
                else "",
                "REVIEW"
                if any(
                    dtype in ("ESCALATE", "NEEDS_REVIEW")
                    for dtype in types
                )
                else "",
            }
            - {""}
        )
        > 1,
        "error": "",
    }


def _empty_human_facts() -> dict:
    return {
        "present": False,
        "decided_count": 0,
        "pending_count": 0,
        "decision_types": [],
        "approved": False,
        "escalated": False,
        "needs_review": False,
        "blocking": False,
        "pending": False,
        "conflict": False,
        "error": "",
    }


def learning_context_facts(learning_result: object) -> dict:
    """Deterministic summary of the R57 learning context."""

    if not isinstance(learning_result, dict) or not learning_result:
        return {
            "present": False,
            "pattern_count": 0,
            "recommendation_count": 0,
            "blocking_codes": [],
            "blocking_count": 0,
            "error": "",
        }
    if (
        _text(learning_result.get("rule_version"))
        != EXPECTED_LEARNING_RULE_VERSION
    ):
        return {
            "present": False,
            "pattern_count": 0,
            "recommendation_count": 0,
            "blocking_codes": [],
            "blocking_count": 0,
            "error": "RULE_VERSION_MISMATCH",
        }
    codes: list[str] = []
    for recommendation in learning_result.get(
        "calibration_recommendations"
    ) or ():
        if isinstance(recommendation, dict):
            code = _upper(recommendation.get("recommendation_code"))
            if code and code not in codes:
                codes.append(code)
    blocking = [
        code for code in codes if code in BLOCKING_LEARNING_RECOMMENDATIONS
    ]
    return {
        "present": True,
        "pattern_count": len(learning_result.get("patterns") or ()),
        "recommendation_count": len(
            learning_result.get("calibration_recommendations") or ()
        ),
        "blocking_codes": blocking,
        "blocking_count": len(blocking),
        "error": "",
    }


def execution_context_facts(control_result: object) -> dict:
    """Deterministic summary of the R58 controlled execution gate."""

    if not isinstance(control_result, dict) or not control_result:
        return {
            "present": False,
            "control_outcome": "",
            "authorization_status": "",
            "execution_status": "",
            "safety_result": "",
            "authorized": False,
            "blocked": False,
            "ready": False,
            "unsafe_claim": False,
            "error": "",
        }
    if (
        _text(control_result.get("rule_version"))
        != EXPECTED_EXECUTION_CONTROL_RULE_VERSION
    ):
        facts = execution_context_facts(None)
        facts["error"] = "RULE_VERSION_MISMATCH"
        return facts
    outcome = _upper(control_result.get("control_outcome"))
    safety = _upper(control_result.get("safety_result"))
    return {
        "present": True,
        "control_outcome": outcome,
        "authorization_status": _upper(
            control_result.get("authorization_status")
        ),
        "execution_status": _upper(control_result.get("execution_status")),
        "safety_result": safety,
        "authorized": outcome == "ALLOW",
        "blocked": outcome in ("DENY", "INVALID")
        or safety in ("BLOCKED", "INVALID"),
        "ready": _upper(control_result.get("execution_status"))
        == "READY_FOR_EXTERNAL_EXECUTOR",
        "unsafe_claim": (
            control_result.get("execution_performed") is True
            or control_result.get("vulnerability_confirmed") is True
            or control_result.get("exploit_authorized") is True
        ),
        "error": "",
    }


# ---------------------------------------------------------------------------
# Correlation index (R54)
# ---------------------------------------------------------------------------


def correlation_index(correlation_result: object) -> dict:
    """Index R54 relationships by finding id (read-only).

    Returns ``{finding_id: {"related_ids", "relationship_types",
    "conflict", "duplicate"}}`` plus ``{"counts": ...}`` under ``"_meta"``.
    """

    index: dict = {
        "_meta": {
            "present": False,
            "related_finding_ids": [],
            "relationship_types": [],
            "conflict_count": 0,
            "duplicate_count": 0,
            "error": "",
        }
    }
    if not isinstance(correlation_result, dict) or not correlation_result:
        return index
    if (
        _text(correlation_result.get("rule_version"))
        != EXPECTED_CORRELATION_RULE_VERSION
    ):
        index["_meta"]["error"] = "RULE_VERSION_MISMATCH"
        return index
    meta = index["_meta"]
    meta["present"] = True
    for relationship in correlation_result.get("relationships") or ():
        if not isinstance(relationship, dict):
            continue
        source = _text(relationship.get("source_finding_id"))
        target = _text(relationship.get("target_finding_id"))
        relationship_type = _upper(relationship.get("relationship_type"))
        if not source or not target:
            continue
        for finding_id, other_id in ((source, target), (target, source)):
            entry = index.setdefault(
                finding_id,
                {
                    "related_ids": [],
                    "relationship_types": [],
                    "conflict": False,
                    "duplicate": False,
                },
            )
            if other_id not in entry["related_ids"]:
                entry["related_ids"].append(other_id)
            if (
                relationship_type
                and relationship_type not in entry["relationship_types"]
            ):
                entry["relationship_types"].append(relationship_type)
            if relationship_type == RELATIONSHIP_CONFLICTING:
                entry["conflict"] = True
            if relationship_type == RELATIONSHIP_DUPLICATE:
                entry["duplicate"] = True
        if relationship_type == RELATIONSHIP_CONFLICTING:
            meta["conflict_count"] += 1
        if relationship_type == RELATIONSHIP_DUPLICATE:
            meta["duplicate_count"] += 1
        if relationship_type and relationship_type not in meta[
            "relationship_types"
        ]:
            meta["relationship_types"].append(relationship_type)
        for finding_id in (source, target):
            if finding_id and finding_id not in meta[
                "related_finding_ids"
            ]:
                meta["related_finding_ids"].append(finding_id)
    meta["related_finding_ids"].sort()
    meta["relationship_types"].sort()
    return index


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def opportunity_confidence(
    evidence_completeness: object,
    upstream_confidence: object,
    *,
    conflict_present: bool,
    duplicate_present: bool,
) -> tuple[str, list[str]]:
    """Conservative deterministic confidence for one opportunity."""

    evidence = _upper(evidence_completeness)
    confidence = _upper(upstream_confidence)
    score = min(
        _CONFIDENCE_RANK.get(confidence, 0),
        _EVIDENCE_RANK.get(evidence, 0),
    )
    basis: list[str] = []
    if evidence == EVIDENCE_COMPLETE:
        basis.append(BASIS_EVIDENCE_COMPLETE)
    elif evidence == EVIDENCE_PARTIAL:
        basis.append(BASIS_EVIDENCE_PARTIAL)
    else:
        basis.append(BASIS_EVIDENCE_INSUFFICIENT)
    if conflict_present:
        score = min(score, 1)
        basis.append(BASIS_CONFLICT_PRESENT)
    if duplicate_present:
        score = min(score, 2)
        basis.append(BASIS_DUPLICATE_PRESENT)
    return _RANK_CONFIDENCE[max(0, min(3, score))], basis


def brief_confidence(
    opportunities: object,
    *,
    conflict_present: bool,
    duplicate_present: bool,
    human_pending: bool,
    workflow_blocked: bool,
    safety_blocked: bool,
) -> tuple[str, list[str]]:
    """Conservative deterministic confidence for the brief."""

    entries = list(opportunities or ())
    if not entries:
        return "UNKNOWN", [BASIS_NO_OPPORTUNITIES]
    primary = entries[0] if isinstance(entries[0], dict) else {}
    score = _CONFIDENCE_RANK.get(_upper(primary.get("confidence")), 0)
    basis: list[str] = [BASIS_OPPORTUNITIES_PRESENT]
    if conflict_present:
        basis.append(BASIS_CONFLICT_PRESENT)
    if duplicate_present:
        basis.append(BASIS_DUPLICATE_PRESENT)
    if safety_blocked:
        score = min(score, 1)
        basis.append(BASIS_SAFETY_BLOCKED)
    elif workflow_blocked:
        score = min(score, 1)
        basis.append(BASIS_WORKFLOW_BLOCKED)
    elif human_pending:
        score = min(score, 2)
        basis.append(BASIS_HUMAN_DECISION_PENDING)
    if score < 3 and BASIS_HUMAN_REVIEW_REQUIRED not in basis:
        basis.append(BASIS_HUMAN_REVIEW_REQUIRED)
    return _RANK_CONFIDENCE[max(0, min(3, score))], [
        code for code in CONFIDENCE_BASES if code in set(basis)
    ]


# ---------------------------------------------------------------------------
# Opportunity composition
# ---------------------------------------------------------------------------


def opportunity_class(
    priority_band: object,
    evidence_completeness: object,
    conflict_state: object,
    *,
    safety_blocked: bool,
    deferred: bool,
) -> str:
    """Deterministic research-attention class (never a vulnerability verdict)."""

    if safety_blocked:
        return OPPORTUNITY_BLOCKED
    evidence = _upper(evidence_completeness)
    if evidence in (EVIDENCE_MISSING, EVIDENCE_UNKNOWN):
        return OPPORTUNITY_INSUFFICIENT
    band = _upper(priority_band)
    if deferred or band == BAND_DEFERRED:
        return OPPORTUNITY_DEFERRED
    if band in (BAND_CRITICAL, BAND_HIGH):
        return OPPORTUNITY_HIGH_PRIORITY
    if band == BAND_MEDIUM:
        return OPPORTUNITY_PRIORITY
    if band == BAND_LOW:
        return OPPORTUNITY_STANDARD
    return OPPORTUNITY_INSUFFICIENT


def research_action_for(
    *,
    opportunity_class_value: str,
    human_boundary_blocking: bool,
    evidence_completeness: object,
    conflict_present: bool,
    duplicate_present: bool,
    priority_band: object,
    deferred: bool,
) -> str:
    """Deterministic mapping to a verbatim R58 safe research/control action.

    The human boundary takes precedence: when a pending decision, escalation,
    review requirement, learning block, execution block or workflow block is
    present, the next step is explicitly human review. Otherwise the action
    describes the concrete advisory research step (still subject to R56/R58).
    """

    if opportunity_class_value == OPPORTUNITY_BLOCKED:
        return ""
    if human_boundary_blocking:
        return ACTION_REQUEST_HUMAN_REVIEW
    evidence = _upper(evidence_completeness)
    if evidence in (EVIDENCE_MISSING, EVIDENCE_UNKNOWN, EVIDENCE_PARTIAL):
        return ACTION_COLLECT_EXISTING_EVIDENCE
    if conflict_present:
        return ACTION_REASSESS_CONTEXT
    if duplicate_present:
        return ACTION_REVIEW_EXISTING_RESPONSE
    if deferred or _upper(priority_band) == BAND_DEFERRED:
        return ""
    return ACTION_PREPARE_RESEARCH_STEP


def opportunity_review_reasons(
    *,
    evidence_completeness: object,
    confidence: object,
    conflict_state: object,
    conflict_present: bool,
    duplicate_present: bool,
    finding_state: object,
    severity: object,
    severity_source: object,
    provenance: object,
    governance: object,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    upstream_error: bool = False,
) -> list[str]:
    """Deterministic human-review requirements for one opportunity."""

    found: set[str] = set()
    evidence = _upper(evidence_completeness)
    if evidence in (EVIDENCE_MISSING, EVIDENCE_UNKNOWN):
        found.add(REVIEW_MISSING_EVIDENCE)
    elif evidence == EVIDENCE_PARTIAL:
        found.add(RATIONALE_EVIDENCE_INCOMPLETE)
    state = _upper(finding_state)
    if conflict_present or _upper(conflict_state) == CONFLICT_PRESENT:
        found.add(RATIONALE_CONFLICT_REQUIRES_RESOLUTION)
    if state == STATE_CONFLICTED:
        found.add(REVIEW_CONFLICTED_FINDING)
    if duplicate_present:
        found.add(RATIONALE_DUPLICATE_RESEARCH_OVERLAP)
    if state in _STATE_INSUFFICIENT_STATES:
        found.add(RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING)
    if _upper(confidence) in ("LOW", "UNKNOWN"):
        found.add(REVIEW_LOW_CONFIDENCE)
    if not _text(severity_source) or _upper(severity_source) in (
        "NOT_ASSESSED",
        "UNKNOWN",
    ):
        found.add(RATIONALE_SEVERITY_CONTEXT_REQUIRED)
    provenance_value = provenance if isinstance(provenance, dict) else {}
    if not _text(provenance_value.get("orchestration_id")):
        found.add(RATIONALE_PROVENANCE_INCOMPLETE)
    governance_value = governance if isinstance(governance, dict) else {}
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        found.add(RATIONALE_GOVERNANCE_REVIEW_REQUIRED)
    if human_facts.get("pending"):
        found.add(REVIEW_HUMAN_DECISION_PENDING)
    if human_facts.get("escalated"):
        found.add(RATIONALE_ESCALATION_REQUIRED)
    if human_facts.get("needs_review"):
        found.add(REVIEW_HUMAN_NEEDS_REVIEW)
    if human_facts.get("conflict"):
        found.add(RATIONALE_CONFLICT_REQUIRES_RESOLUTION)
    if learning_facts.get("blocking_count"):
        found.add(REVIEW_LEARNING_REVIEW_REQUIRED)
    if execution_facts.get("blocked"):
        found.add(REVIEW_EXECUTION_CONTROL_BLOCKED)
    if upstream_error:
        found.add(REVIEW_INVALID_UPSTREAM_CONTEXT)
    return [code for code in COPILOT_REVIEW_REASONS if code in found]


def opportunity_rationale_codes(
    *,
    priority_band: object,
    evidence_completeness: object,
    conflict_present: bool,
    duplicate_present: bool,
    related_finding_count: int,
    human_review_required: bool,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    workflow_present: bool,
    safety_blocked: bool,
) -> list[str]:
    """Deterministic copilot rationale codes for one opportunity."""

    found: list[str] = []
    band = _upper(priority_band)
    if band == BAND_CRITICAL:
        found.append(RATIONALE_HIGH_PRIORITY)
    elif band == BAND_HIGH:
        found.append(RATIONALE_ELEVATED_PRIORITY)
    elif band in (BAND_MEDIUM, BAND_LOW):
        found.append(RATIONALE_STANDARD_PRIORITY)
    else:
        found.append(RATIONALE_DEFERRED_PRIORITY)
    evidence = _upper(evidence_completeness)
    if evidence == EVIDENCE_COMPLETE:
        found.append(RATIONALE_EVIDENCE_COMPLETE)
    elif evidence == EVIDENCE_PARTIAL:
        found.append(RATIONALE_EVIDENCE_PARTIAL)
    else:
        found.append(RATIONALE_EVIDENCE_INSUFFICIENT)
    if related_finding_count:
        found.append(RATIONALE_RELATED_FINDINGS_PRESENT)
    if conflict_present:
        found.append(RATIONALE_CONFLICT_CONTEXT)
    if duplicate_present:
        found.append(RATIONALE_DUPLICATE_CONTEXT)
    if human_review_required:
        found.append(RATIONALE_HUMAN_REVIEW_REQUIRED)
    if human_facts.get("approved") or human_facts.get("decided_count"):
        found.append(RATIONALE_HUMAN_DECISION_PRESENT)
    if human_facts.get("pending"):
        found.append(RATIONALE_HUMAN_DECISION_PENDING)
    if learning_facts.get("present"):
        found.append(RATIONALE_LEARNING_CONTEXT)
    if execution_facts.get("present"):
        found.append(RATIONALE_EXECUTION_CONTEXT)
    if execution_facts.get("blocked"):
        found.append(RATIONALE_EXECUTION_BLOCKED)
    found.append(
        RATIONALE_WORKFLOW_CONTEXT_AVAILABLE
        if workflow_present
        else RATIONALE_WORKFLOW_CONTEXT_MISSING
    )
    if safety_blocked:
        found.append(RATIONALE_SAFETY_BLOCKED)
    return [code for code in COPILOT_RATIONALE_CODES if code in set(found)]


def build_opportunity(
    plan: object,
    *,
    correlation_entry: object,
    workflow_facts_value: dict,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    safety_blocked: bool,
    deferred: bool,
    upstream_error: bool,
) -> dict:
    """Build one sanitized copilot opportunity from an R55 plan (read-only)."""

    source = plan if isinstance(plan, dict) else {}
    finding_id = _text(source.get("finding_id"))
    entry = (
        correlation_entry
        if isinstance(correlation_entry, dict)
        else {}
    )
    conflict_present = bool(entry.get("conflict")) is True
    duplicate_present = bool(entry.get("duplicate")) is True
    correlation_summary = source.get("correlation_summary")
    if isinstance(correlation_summary, dict):
        if (
            _bounded_int(
                correlation_summary.get("duplicate_count"), 0, MAX_LIST
            )
            > 0
        ):
            duplicate_present = True
    if _upper(source.get("conflict_state")) == CONFLICT_PRESENT:
        conflict_present = True
    related_ids = [
        _text(item)
        for item in (entry.get("related_ids") or [])[:MAX_LIST]
        if _text(item) and _text(item) != finding_id
    ]
    relationship_types = [
        _text(item)
        for item in (entry.get("relationship_types") or [])[:MAX_LIST]
        if _text(item)
    ]
    confidence, _confidence_basis = opportunity_confidence(
        source.get("evidence_completeness"),
        source.get("confidence"),
        conflict_present=conflict_present,
        duplicate_present=duplicate_present,
    )
    review_reasons = opportunity_review_reasons(
        evidence_completeness=source.get("evidence_completeness"),
        confidence=confidence,
        conflict_state=source.get("conflict_state"),
        conflict_present=conflict_present,
        duplicate_present=duplicate_present,
        finding_state=source.get("state"),
        severity=source.get("severity"),
        severity_source=source.get("severity_source"),
        provenance=source.get("provenance"),
        governance=source.get("governance"),
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        upstream_error=upstream_error,
    )
    human_review_required = bool(review_reasons)
    class_value = opportunity_class(
        source.get("priority_band"),
        source.get("evidence_completeness"),
        source.get("conflict_state"),
        safety_blocked=safety_blocked,
        deferred=deferred,
    )
    human_boundary_blocking = bool(
        human_facts.get("pending")
        or human_facts.get("escalated")
        or human_facts.get("needs_review")
        or human_facts.get("blocking")
        or human_facts.get("conflict")
        or learning_facts.get("blocking_count")
        or execution_facts.get("blocked")
        or workflow_facts_value.get("blocked")
    )
    research_action = research_action_for(
        opportunity_class_value=class_value,
        human_boundary_blocking=human_boundary_blocking,
        evidence_completeness=source.get("evidence_completeness"),
        conflict_present=conflict_present,
        duplicate_present=duplicate_present,
        priority_band=source.get("priority_band"),
        deferred=deferred,
    )
    rationale_codes = opportunity_rationale_codes(
        priority_band=source.get("priority_band"),
        evidence_completeness=source.get("evidence_completeness"),
        conflict_present=conflict_present,
        duplicate_present=duplicate_present,
        related_finding_count=len(related_ids),
        human_review_required=human_review_required,
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        workflow_present=bool(workflow_facts_value.get("present")),
        safety_blocked=safety_blocked,
    )
    recommendation = sanitize_copilot_recommendation(
        {
            "recommendation_id": recommendation_id(
                finding_id,
                _text(workflow_facts_value.get("next_action")),
                research_action,
            ),
            "workflow_next_action": _text(
                workflow_facts_value.get("next_action")
            ),
            "research_action": research_action,
            "human_review_required": human_review_required,
            "review_reasons": review_reasons,
            "limitations": list(OPPORTUNITY_BASE_LIMITATIONS),
        }
    )
    safety_status = _text(workflow_facts_value.get("safety_status"))
    if safety_blocked:
        safety_status = SAFETY_STATUS_SAFETY_BLOCKED
    return sanitize_copilot_opportunity(
        {
            "rule_version": COPILOT_OPPORTUNITY_RULE_VERSION,
            "opportunity_id": opportunity_id(
                finding_id,
                _upper(source.get("priority_band")),
                _bounded_int(source.get("ranking_position"), 0, MAX_LIST),
            ),
            "finding_id": finding_id,
            "category": _upper(source.get("category")),
            "specialist_name": _text(source.get("specialist_name")),
            "agent_id": _text(source.get("agent_id")),
            "finding_state": _upper(source.get("state")),
            "confidence": confidence,
            "evidence_state": _upper(source.get("evidence_state")),
            "evidence_completeness": _upper(
                source.get("evidence_completeness")
            ),
            "evidence_origin": _upper(source.get("evidence_origin")),
            "severity": _upper(source.get("severity")),
            "severity_source": _upper(source.get("severity_source")),
            "impact_state": _upper(source.get("impact_state")),
            "priority_band": _upper(source.get("priority_band")),
            "priority_score": _bounded_int(
                source.get("priority_score"), 0, 100
            ),
            "ranking_position": _bounded_int(
                source.get("ranking_position"), 0, MAX_LIST
            ),
            "opportunity_class": class_value,
            "conflict_state": _upper(source.get("conflict_state")),
            "duplicate_present": duplicate_present,
            "related_finding_count": len(related_ids),
            "related_finding_ids": related_ids,
            "relationship_types": relationship_types,
            "research_rationale_codes": source.get("priority_reasons"),
            "copilot_rationale_codes": rationale_codes,
            "recommendation": recommendation,
            "safety_status": safety_status,
            "provenance": source.get("provenance"),
            "governance": source.get("governance"),
            "limitations": list(OPPORTUNITY_BASE_LIMITATIONS),
        }
    )


# ---------------------------------------------------------------------------
# Brief composition
# ---------------------------------------------------------------------------


def opportunity_plans(
    prioritization_result: object,
    *,
    workflow_facts_value: dict,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    correlation_index_value: dict,
    safety_blocked: bool,
    upstream_error: bool,
    max_opportunities: int,
) -> list[dict]:
    """Build the ordered opportunity list from the R55 prioritization."""

    if not isinstance(prioritization_result, dict) or not (
        prioritization_result
    ):
        return []
    if (
        _text(prioritization_result.get("rule_version"))
        != EXPECTED_PRIORITIZATION_RULE_VERSION
    ):
        return []
    plans: list[tuple[dict, bool]] = []
    for plan in prioritization_result.get("ranked_findings") or ():
        if isinstance(plan, dict):
            plans.append((plan, False))
    for plan in prioritization_result.get("deferred_findings") or ():
        if isinstance(plan, dict):
            plans.append((plan, True))
    opportunities: list[dict] = []
    seen: set[str] = set()
    for plan, deferred in plans:
        if len(opportunities) >= max_opportunities:
            break
        finding_id = _text(plan.get("finding_id"))
        if not finding_id or finding_id in seen:
            continue
        seen.add(finding_id)
        opportunities.append(
            build_opportunity(
                plan,
                correlation_entry=(
                    correlation_index_value.get(finding_id) or {}
                ),
                workflow_facts_value=workflow_facts_value,
                human_facts=human_facts,
                learning_facts=learning_facts,
                execution_facts=execution_facts,
                safety_blocked=safety_blocked,
                deferred=deferred,
                upstream_error=upstream_error,
            )
        )
    return opportunities


def brief_review_reasons(
    opportunities: object,
    *,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    workflow_facts_value: dict,
    safety_blocked: bool,
    upstream_error: bool,
) -> list[str]:
    """Aggregate deterministic human-review requirements for the brief."""

    found: set[str] = set()
    for opportunity in opportunities or ():
        if not isinstance(opportunity, dict):
            continue
        for reason in opportunity.get("recommendation", {}).get(
            "review_reasons"
        ) or ():
            found.add(_text(reason))
    if human_facts.get("pending"):
        found.add(REVIEW_HUMAN_DECISION_PENDING)
    if human_facts.get("escalated"):
        found.add(RATIONALE_ESCALATION_REQUIRED)
    if human_facts.get("needs_review"):
        found.add(REVIEW_HUMAN_NEEDS_REVIEW)
    if human_facts.get("blocking"):
        found.add(RATIONALE_CONFLICT_REQUIRES_RESOLUTION)
    if human_facts.get("conflict"):
        found.add(RATIONALE_CONFLICT_REQUIRES_RESOLUTION)
    if learning_facts.get("blocking_count"):
        found.add(REVIEW_LEARNING_REVIEW_REQUIRED)
    if execution_facts.get("blocked"):
        found.add(REVIEW_EXECUTION_CONTROL_BLOCKED)
    if workflow_facts_value.get("blocked"):
        found.add(REVIEW_INVALID_UPSTREAM_CONTEXT)
    if safety_blocked:
        found.add(REVIEW_INVALID_UPSTREAM_CONTEXT)
    if upstream_error:
        found.add(REVIEW_INVALID_UPSTREAM_CONTEXT)
    return [code for code in COPILOT_REVIEW_REASONS if code in found]


def brief_rationale_codes(
    opportunities: object,
    *,
    workflow_facts_value: dict,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    safety_blocked: bool,
) -> list[str]:
    """Aggregate deterministic copilot rationale codes for the brief."""

    found: set[str] = set()
    for opportunity in opportunities or ():
        if isinstance(opportunity, dict):
            for code in opportunity.get("copilot_rationale_codes") or ():
                found.add(_text(code))
    if not opportunities:
        found.add(RATIONALE_INSUFFICIENT_DATA)
    found.add(
        RATIONALE_WORKFLOW_CONTEXT_AVAILABLE
        if workflow_facts_value.get("present")
        else RATIONALE_WORKFLOW_CONTEXT_MISSING
    )
    if human_facts.get("approved") or human_facts.get("decided_count"):
        found.add(RATIONALE_HUMAN_DECISION_PRESENT)
    if human_facts.get("pending"):
        found.add(RATIONALE_HUMAN_DECISION_PENDING)
    if learning_facts.get("present"):
        found.add(RATIONALE_LEARNING_CONTEXT)
    if execution_facts.get("present"):
        found.add(RATIONALE_EXECUTION_CONTEXT)
    if execution_facts.get("blocked"):
        found.add(RATIONALE_EXECUTION_BLOCKED)
    if safety_blocked:
        found.add(RATIONALE_SAFETY_BLOCKED)
    return [code for code in COPILOT_RATIONALE_CODES if code in found]


def brief_safety_status(
    *,
    safety_blocked: bool,
    workflow_facts_value: dict,
    human_review_required: bool,
) -> str:
    """Deterministic copilot brief safety status (reuses R59 vocabulary)."""

    if safety_blocked:
        return SAFETY_STATUS_SAFETY_BLOCKED
    workflow_safety = _upper(workflow_facts_value.get("safety_status"))
    if workflow_safety in (
        SAFETY_STATUS_SAFETY_BLOCKED,
        SAFETY_STATUS_EXECUTION_BLOCKED,
        SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
        SAFETY_STATUS_INVALID,
    ):
        return workflow_safety
    if workflow_facts_value.get("state") == STATE_INVALID:
        return SAFETY_STATUS_INVALID
    if workflow_safety in (
        SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
        SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
    ):
        return workflow_safety
    if human_review_required:
        return SAFETY_STATUS_HUMAN_REVIEW_REQUIRED
    if workflow_safety:
        return workflow_safety
    return SAFETY_STATUS_RESEARCH_ONLY


def evidence_summary(
    prioritization_result: object,
    opportunities: object,
    correlation_index_value: dict,
) -> dict:
    """Deterministic evidence summary (verbatim counts, no new severity)."""

    finding_count = 0
    complete = 0
    partial = 0
    incomplete = 0
    if isinstance(prioritization_result, dict):
        plans = list(prioritization_result.get("ranked_findings") or ()) + (
            list(prioritization_result.get("deferred_findings") or ())
        )
        finding_count = len(plans)
        for plan in plans:
            if not isinstance(plan, dict):
                continue
            completeness = _upper(plan.get("evidence_completeness"))
            if completeness == EVIDENCE_COMPLETE:
                complete += 1
            elif completeness == EVIDENCE_PARTIAL:
                partial += 1
            else:
                incomplete += 1
    meta = (
        correlation_index_value.get("_meta")
        if isinstance(correlation_index_value, dict)
        else {}
    ) or {}
    return {
        "finding_count": finding_count,
        "evidence_complete_count": complete,
        "evidence_partial_count": partial,
        "evidence_incomplete_count": incomplete,
        "conflict_count": _bounded_int(meta.get("conflict_count"), 0, 4096),
        "duplicate_count": _bounded_int(
            meta.get("duplicate_count"), 0, 4096
        ),
        "related_finding_count": len(
            _text_list(meta.get("related_finding_ids"))
        ),
    }


def _text_list(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return out


def recommended_actions(opportunities: object) -> list[dict]:
    """Compact deterministic recommended-action list (deduplicated)."""

    out: list[dict] = []
    seen: set[tuple] = set()
    for opportunity in opportunities or ():
        if not isinstance(opportunity, dict):
            continue
        recommendation = opportunity.get("recommendation") or {}
        key = (
            _text(recommendation.get("workflow_next_action")),
            _text(recommendation.get("research_action")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "finding_id": _text(opportunity.get("finding_id")),
                "workflow_next_action": key[0],
                "research_action": key[1],
                "priority_band": _text(opportunity.get("priority_band")),
                "human_review_required": bool(
                    recommendation.get("human_review_required")
                )
                is True,
            }
        )
        if len(out) >= MAX_LIST:
            break
    return sanitize_recommended_actions(out)


def brief_limitations(
    *, safety_blocked: bool, workflow_present: bool
) -> list[str]:
    """Deterministic ordered brief limitations."""

    found = set(BRIEF_BASE_LIMITATIONS)
    if not workflow_present:
        found.add(LIMITATION_WORKFLOW_CONTEXT_MISSING)
    return [code for code in COPILOT_BRIEF_LIMITATIONS if code in found]


def copilot_status(
    *,
    errors: object,
    workflow_present: bool,
    any_context: bool,
) -> str:
    """Deterministic copilot result status (safe failure)."""

    if not any_context:
        return STATUS_NO_CONTEXT
    if has_fatal_error(errors):
        return STATUS_FAILED
    if list(errors or ()):
        return STATUS_PARTIAL
    if not workflow_present:
        return STATUS_PARTIAL
    return STATUS_COMPLETED


def copilot_summary(brief: dict, errors: object) -> dict:
    """Compact deterministic copilot summary."""

    opportunities = brief.get("opportunities") or ()
    return {
        "opportunity_count": len(opportunities),
        "high_priority_count": sum(
            1
            for entry in opportunities
            if entry.get("opportunity_class") in HIGH_PRIORITY_CLASSES
        ),
        "recommended_action_count": len(
            brief.get("recommended_actions") or ()
        ),
        "human_review_required": bool(
            brief.get("human_review_required")
        )
        is True,
        "confidence": _text(brief.get("confidence")) or "UNKNOWN",
        "workflow_state": _text(brief.get("workflow_state")),
        "safety_status": _text(brief.get("safety_status"))
        or SAFETY_STATUS_RESEARCH_ONLY,
        "error_count": len(list(errors or ())),
    }


__all__ = [
    "BUG_BOUNTY_COPILOT_RULES_RULE_VERSION",
    "RULE_VERSION",
    "EXPECTED_WORKFLOW_RULE_VERSION",
    "EXPECTED_FINDING_RULE_VERSION",
    "EXPECTED_CORRELATION_RULE_VERSION",
    "EXPECTED_PRIORITIZATION_RULE_VERSION",
    "EXPECTED_HUMAN_REVIEW_RULE_VERSION",
    "EXPECTED_LEARNING_RULE_VERSION",
    "EXPECTED_EXECUTION_CONTROL_RULE_VERSION",
    "FATAL_ERROR_CATEGORIES",
    "MAX_LIST",
    "MAX_TEXT",
    "copilot_error",
    "has_fatal_error",
    "copilot_id",
    "opportunity_id",
    "recommendation_id",
    "brief_id",
    "result_id",
    "copilot_safety_reasons",
    "collect_safety_reasons",
    "workflow_facts",
    "human_context_facts",
    "learning_context_facts",
    "execution_context_facts",
    "correlation_index",
    "opportunity_confidence",
    "brief_confidence",
    "opportunity_class",
    "research_action_for",
    "opportunity_review_reasons",
    "opportunity_rationale_codes",
    "build_opportunity",
    "opportunity_plans",
    "brief_review_reasons",
    "brief_rationale_codes",
    "brief_safety_status",
    "evidence_summary",
    "recommended_actions",
    "brief_limitations",
    "copilot_status",
    "copilot_summary",
]

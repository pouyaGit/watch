"""Finding result schema (Stage R53.6).

Defines the deterministic research finding candidate and the R53 finding
intelligence result that groups finding candidates produced from structured
R38-R52 research outputs. It answers:

    "Which research finding candidates were derived, in which state, with
     which evidence and provenance?"

Hard boundaries encoded here:

- Research finding candidates only: a finding is a structured research
  artifact. It is never an exploitation proof and never a confirmed
  vulnerability (``confirmation_state`` is forced ``NOT_CONFIRMED``).
- No duplicated contracts: identity, context, hypothesis linkage, evidence
  linkage and assessment are their own bounded R53 plans; R43 correlation
  records and R44 learning recommendations are consumed through their own
  sanitizers.
- No isolation loss: correlation never discards a finding or its evidence;
  duplicate/related/conflicting relationships are preserved as references.
- Deterministic: content-derived ids only; no timestamps, UUIDs, pids or
  randomness.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_orchestrator_registry import ORCHESTRATION_STAGES
from ai.schemas.decision_provenance import PROVENANCE_STATES
from ai.schemas.governance_rule_trace import TRACE_STATES
from ai.schemas.research_audit_event import AUDIT_STATES
from ai.schemas.research_explanation import EXPLANATION_STATES
from ai.schemas.research_governance_export import (
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
)
from ai.schemas.collaboration_conflict import (
    sanitize_collaboration_conflict,
)
from ai.schemas.finding_assessment import (
    FINDING_STATES,
    sanitize_finding_assessment,
)
from ai.schemas.finding_context import sanitize_finding_context
from ai.schemas.finding_evidence import sanitize_finding_evidence
from ai.schemas.finding_hypothesis import sanitize_finding_hypothesis_linkage
from ai.schemas.finding_identity import sanitize_finding_identity
from ai.schemas.hypothesis_correlation import sanitize_hypothesis_group
from ai.schemas.learning_recommendation import (
    sanitize_learning_recommendation,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

FINDING_RESULT_RULE_VERSION = "r53-6"
RULE_VERSION = FINDING_RESULT_RULE_VERSION

INTELLIGENCE_ID_PREFIX = "fni-"
INTELLIGENCE_ID_RE = re.compile(r"^fni-[0-9a-f]{16}$")

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NO_FINDINGS = "NO_FINDINGS"
STATUS_FAILED = "FAILED"

INTELLIGENCE_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
)

REFERENCE_REFERENCED = "REFERENCED"
REFERENCE_UNKNOWN = "UNKNOWN"

REFERENCE_STATES: tuple[str, ...] = (
    REFERENCE_REFERENCED,
    REFERENCE_UNKNOWN,
)

SKIP_SAFETY_FAILURE = "SAFETY_FAILURE"
SKIP_FORBIDDEN_CLAIM = "FORBIDDEN_CLAIM"
SKIP_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
SKIP_MALFORMED_RESULT = "MALFORMED_RESULT"
SKIP_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

FINDING_SKIP_REASONS: tuple[str, ...] = (
    SKIP_SAFETY_FAILURE,
    SKIP_FORBIDDEN_CLAIM,
    SKIP_UNSUPPORTED_CATEGORY,
    SKIP_MALFORMED_RESULT,
    SKIP_LIMIT_EXCEEDED,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_SPECIALIST_RESULT = "MALFORMED_SPECIALIST_RESULT"
ERROR_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

FINDING_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_SPECIALIST_RESULT,
    ERROR_UNSUPPORTED_CATEGORY,
    ERROR_SAFETY_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_NO_EVIDENCE_COLLECTED = "NO_EVIDENCE_COLLECTED"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_EVALUATION_UNAVAILABLE = "EVALUATION_UNAVAILABLE"
LIMITATION_COLLABORATION_UNAVAILABLE = "COLLABORATION_UNAVAILABLE"
LIMITATION_FEEDBACK_UNAVAILABLE = "FEEDBACK_UNAVAILABLE"
LIMITATION_ADVISORY_UNAVAILABLE = "ADVISORY_UNAVAILABLE"
LIMITATION_CONFLICT_PRESENT = "CONFLICT_PRESENT"
LIMITATION_DUPLICATE_CORRELATION_PRESENT = "DUPLICATE_CORRELATION_PRESENT"
LIMITATION_REMEDIATION_UNAVAILABLE = "REMEDIATION_UNAVAILABLE"
LIMITATION_IMPACT_NOT_OBSERVED = "IMPACT_NOT_OBSERVED"
LIMITATION_ASSET_CONTEXT_UNAVAILABLE = "ASSET_CONTEXT_UNAVAILABLE"
LIMITATION_SEVERITY_NOT_ASSESSED = "SEVERITY_NOT_ASSESSED"
LIMITATION_RESEARCH_CANDIDATE_ONLY = "RESEARCH_CANDIDATE_ONLY"
LIMITATION_CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"

FINDING_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_EVIDENCE_COLLECTED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_EVALUATION_UNAVAILABLE,
    LIMITATION_COLLABORATION_UNAVAILABLE,
    LIMITATION_FEEDBACK_UNAVAILABLE,
    LIMITATION_ADVISORY_UNAVAILABLE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DUPLICATE_CORRELATION_PRESENT,
    LIMITATION_REMEDIATION_UNAVAILABLE,
    LIMITATION_IMPACT_NOT_OBSERVED,
    LIMITATION_ASSET_CONTEXT_UNAVAILABLE,
    LIMITATION_SEVERITY_NOT_ASSESSED,
    LIMITATION_RESEARCH_CANDIDATE_ONLY,
    LIMITATION_CORRELATION_UNAVAILABLE,
)

FINDING_STAGE_CODES: tuple[str, ...] = ORCHESTRATION_STAGES + (
    "FINDING_INTELLIGENCE",
)

MAX_FINDINGS = 8
MAX_SKIPPED = 16
MAX_ERRORS = 16
MAX_LIMITATIONS = 24
MAX_CORRELATION_GROUPS = 8
MAX_CORRELATION_CONFLICTS = 8
MAX_LEARNING_RECOMMENDATIONS = 8
MAX_REFERENCE_IDS = 8
MAX_LIST = 16
MAX_VALUE_LEN = 160
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in FINDING_LIMITATIONS:
            found.add(text)
    return [code for code in FINDING_LIMITATIONS if code in found]


# ---------------------------------------------------------------------------
# References, correlation and provenance
# ---------------------------------------------------------------------------


def sanitize_finding_reference(value: object) -> dict:
    """Project one upstream reference onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {"reference_state": REFERENCE_UNKNOWN}
    state = _closed(
        value.get("reference_state"),
        REFERENCE_STATES,
        REFERENCE_UNKNOWN,
    )
    out = {"reference_state": state}
    for key in (
        "reference_id",
        "collaboration_id",
        "feedback_id",
        "advisory_id",
        "overall_rating",
        "safety_state",
        "hard_gate_state",
        "validation_state",
        "provider_state",
        "provider_kind",
    ):
        text = _safe_text(value.get(key))
        if text:
            out[key] = text
    for key in ("diagnostic_codes", "recommendation_ids"):
        items = _bounded_strings(value.get(key), MAX_REFERENCE_IDS)
        if items:
            out[key] = items
    return out


def sanitize_finding_references(value: object) -> dict:
    """Project the four upstream reference slots onto bounded keys."""

    if not isinstance(value, dict):
        value = {}
    return {
        "evaluation": sanitize_finding_reference(value.get("evaluation")),
        "collaboration": sanitize_finding_reference(
            value.get("collaboration")
        ),
        "feedback": sanitize_finding_reference(value.get("feedback")),
        "advisory": sanitize_finding_reference(value.get("advisory")),
    }


def sanitize_finding_correlation(value: object) -> dict:
    """Project correlation groups and conflicts onto bounded keys.

    Duplicate/related/conflicting relationships are preserved: R53 never
    deletes a finding or evidence reference because of correlation.
    """

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "groups": [],
            "conflicts": [],
            "duplicate_group_count": 0,
            "related_group_count": 0,
            "conflicting_group_count": 0,
            "conflict_count": 0,
            "research_only": True,
        }
    groups: list[dict] = []
    for item in value.get("groups") or ():
        if isinstance(item, dict):
            groups.append(sanitize_hypothesis_group(item))
        if len(groups) >= MAX_CORRELATION_GROUPS:
            break
    conflicts: list[dict] = []
    for item in value.get("conflicts") or ():
        if isinstance(item, dict):
            conflicts.append(sanitize_collaboration_conflict(item))
        if len(conflicts) >= MAX_CORRELATION_CONFLICTS:
            break
    duplicate = 0
    related = 0
    conflicting = 0
    for group in groups:
        correlation_type = group.get("correlation_type")
        if correlation_type == "DUPLICATE":
            duplicate += 1
        elif correlation_type == "RELATED":
            related += 1
        elif correlation_type == "CONFLICTING":
            conflicting += 1
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "groups": groups,
        "conflicts": conflicts,
        "duplicate_group_count": duplicate,
        "related_group_count": related,
        "conflicting_group_count": conflicting,
        "conflict_count": len(conflicts),
        "research_only": True,
    }


def sanitize_finding_provenance(value: object) -> dict:
    """Project finding provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "category": "",
            "specialist_name": "",
            "agent_id": "",
            "orchestration_id": "",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    stages: list[str] = []
    for item in value.get("source_stages") or ():
        text = _safe_text(item).strip().upper()
        if text in FINDING_STAGE_CODES and text not in stages:
            stages.append(text)
        if len(stages) >= len(FINDING_STAGE_CODES):
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "source_stages": stages,
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": True,
    }


def sanitize_finding_skip(value: object) -> dict:
    """Project one skipped specialist candidate onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    reason = _closed(
        value.get("reason"), FINDING_SKIP_REASONS, SKIP_MALFORMED_RESULT
    )
    return {
        "category": category,
        "agent_id": _safe_text(value.get("agent_id")),
        "reason": reason,
    }


def sanitize_finding_error(value: object) -> dict:
    """Project one finding-intelligence error onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in FINDING_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "category": _safe_text(value.get("category")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_learning_recommendations(value: object) -> list[dict]:
    """Project R44 learning recommendations (bounded, order preserved)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_learning_recommendation(item)
        if projected:
            out.append(projected)
        if len(out) >= MAX_LEARNING_RECOMMENDATIONS:
            break
    return out


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def sanitize_finding(value: object) -> dict:
    """Project a finding candidate onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "finding_id": "",
            "state": "",
            "identity": sanitize_finding_identity(None),
            "context": sanitize_finding_context(None),
            "hypotheses": sanitize_finding_hypothesis_linkage(None),
            "evidence": sanitize_finding_evidence(None),
            "assessment": sanitize_finding_assessment(None),
            "correlation": sanitize_finding_correlation(None),
            "references": sanitize_finding_references(None),
            "learning_recommendations": [],
            "provenance": sanitize_finding_provenance(None),
            "governance": sanitize_finding_governance(None),
            "limitations": [],
            "research_only": True,
            "deterministic": True,
        }
    identity = sanitize_finding_identity(value.get("identity"))
    assessment = sanitize_finding_assessment(value.get("assessment"))
    state = _closed(value.get("state"), FINDING_STATES, "")
    if not state:
        state = assessment.get("state") or ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_id": _safe_text(value.get("finding_id")),
        "state": state,
        "identity": identity,
        "context": sanitize_finding_context(value.get("context")),
        "hypotheses": sanitize_finding_hypothesis_linkage(
            value.get("hypotheses")
        ),
        "evidence": sanitize_finding_evidence(value.get("evidence")),
        "assessment": assessment,
        "correlation": sanitize_finding_correlation(
            value.get("correlation")
        ),
        "references": sanitize_finding_references(value.get("references")),
        "learning_recommendations": sanitize_learning_recommendations(
            value.get("learning_recommendations")
        ),
        "provenance": sanitize_finding_provenance(value.get("provenance")),
        "governance": sanitize_finding_governance(
            value.get("governance")
        ),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }



def sanitize_evaluation_summary(value: object) -> dict:
    """Project the upstream evaluation summary onto bounded keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "evaluated_count": 0,
            "safety_states": [],
            "diagnostic_count": 0,
        }
    states: list[str] = []
    for item in value.get("safety_states") or ():
        text = _safe_text(item).strip().upper()
        if text in ("PASS", "DEGRADED", "FAILED", "UNKNOWN") and (
            text not in states
        ):
            states.append(text)
    count = value.get("evaluated_count")
    if isinstance(count, bool) or not isinstance(count, int):
        count = 0
    diagnostics = value.get("diagnostic_count")
    if isinstance(diagnostics, bool) or not isinstance(diagnostics, int):
        diagnostics = 0
    return {
        "present": bool(value.get("present")) is True,
        "evaluated_count": max(0, min(MAX_FINDINGS, count)),
        "safety_states": states,
        "diagnostic_count": max(0, min(64, diagnostics)),
    }


def sanitize_reference_summary(value: object) -> dict:
    """Project a bounded upstream summary reference (container level)."""

    if not isinstance(value, dict):
        return {"present": False}
    out: dict = {"present": bool(value.get("present")) is True}
    for key in (
        "reference_id",
        "collaboration_id",
        "provider_state",
        "provider_kind",
        "validation_state",
        "safety_state",
        "advisory_id",
    ):
        text = _safe_text(value.get(key))
        if text:
            out[key] = text
    for key in (
        "participant_count",
        "conflict_count",
        "duplicate_group_count",
        "related_group_count",
        "event_count",
        "classification_count",
        "signal_count",
        "recommendation_count",
    ):
        count = value.get(key)
        if isinstance(count, bool) or not isinstance(count, int):
            continue
        out[key] = max(0, min(256, count))
    return out


def sanitize_result_provenance(value: object) -> dict:
    """Project container-level provenance onto bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "orchestration_id": "",
            "finding_count": 0,
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
    stages: list[str] = []
    for item in value.get("source_stages") or ():
        text = _safe_text(item).strip().upper()
        if text in FINDING_STAGE_CODES and text not in stages:
            stages.append(text)
        if len(stages) >= len(FINDING_STAGE_CODES):
            break
    count = value.get("finding_count")
    if isinstance(count, bool) or not isinstance(count, int):
        count = 0
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "finding_count": max(0, min(MAX_FINDINGS, count)),
        "source_stages": stages,
        "deterministic": True,
        "research_only": True,
    }


def sanitize_finding_governance(value: object) -> dict:
    """Project the R37 governance reference onto bounded keys.

    R53 never invents a governance record: a reference is ``REFERENCED``
    only when the supplied plan carries the R37 governance export rule
    version and the four governance components. The projection mirrors the
    reference shape used by the specialist and orchestration layers.
    """

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": "UNKNOWN",
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "ready": bool(value.get("ready")) is True,
        "provenance_state": _closed(
            value.get("provenance_state"), PROVENANCE_STATES, "UNKNOWN"
        ),
        "trace_state": _closed(
            value.get("trace_state"), TRACE_STATES, "UNKNOWN"
        ),
        "audit_state": _closed(
            value.get("audit_state"), AUDIT_STATES, "UNKNOWN"
        ),
        "explanation_state": _closed(
            value.get("explanation_state"), EXPLANATION_STATES, "UNKNOWN"
        ),
        "reference_state": _closed(
            value.get("reference_state"),
            ("REFERENCED", "UNKNOWN"),
            "UNKNOWN",
        ),
    }


def build_finding_governance_reference(
    governance_plan: object = None,
) -> dict:
    """Build a bounded R37 governance reference (read-only).

    A reference is ``REFERENCED`` only when the supplied plan is a valid R37
    governance export; missing, malformed or foreign plans degrade to
    ``UNKNOWN`` and R53 never claims governed execution.
    """

    if (
        not isinstance(governance_plan, dict)
        or governance_plan.get("rule_version")
        != RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION
        or not all(
            isinstance(governance_plan.get(key), dict)
            for key in (
                "provenance",
                "rule_trace",
                "audit_event",
                "explanation",
            )
        )
    ):
        return sanitize_finding_governance(None)
    return sanitize_finding_governance(
        {
            "rule_version": governance_plan.get("rule_version"),
            "ready": governance_plan.get("ready"),
            "provenance_state": (
                governance_plan.get("provenance") or {}
            ).get("provenance_state"),
            "trace_state": (
                governance_plan.get("rule_trace") or {}
            ).get("trace_state"),
            "audit_state": (
                governance_plan.get("audit_event") or {}
            ).get("audit_state"),
            "explanation_state": (
                governance_plan.get("explanation") or {}
            ).get("explanation_state"),
            "reference_state": "REFERENCED",
        }
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FindingPlan(BaseModel):
    """Structured research finding candidate (R53.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_RESULT_RULE_VERSION
    finding_id: str
    state: str
    identity: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    hypotheses: dict = Field(default_factory=dict)
    evidence: dict = Field(default_factory=dict)
    assessment: dict = Field(default_factory=dict)
    correlation: dict = Field(default_factory=dict)
    references: dict = Field(default_factory=dict)
    learning_recommendations: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_RESULT_RULE_VERSION

    @field_validator("finding_id")
    @classmethod
    def _bounded_finding_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FINDING_STATES:
            raise ValueError(f"invalid finding state: {value!r}")
        return text

    @field_validator("identity")
    @classmethod
    def _bounded_identity(cls, value: object) -> dict:
        projected = sanitize_finding_identity(value)
        if not projected.get("finding_id") or not projected.get("category"):
            raise ValueError("finding identity is malformed")
        return projected

    @field_validator("context")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_finding_context(value)

    @field_validator("hypotheses")
    @classmethod
    def _bounded_hypotheses(cls, value: object) -> dict:
        return sanitize_finding_hypothesis_linkage(value)

    @field_validator("evidence")
    @classmethod
    def _bounded_evidence(cls, value: object) -> dict:
        return sanitize_finding_evidence(value)

    @field_validator("assessment")
    @classmethod
    def _bounded_assessment(cls, value: object) -> dict:
        return sanitize_finding_assessment(value)

    @field_validator("correlation")
    @classmethod
    def _bounded_correlation(cls, value: object) -> dict:
        return sanitize_finding_correlation(value)

    @field_validator("references")
    @classmethod
    def _bounded_references(cls, value: object) -> dict:
        return sanitize_finding_references(value)

    @field_validator("learning_recommendations")
    @classmethod
    def _bounded_learning(cls, value: object) -> list[dict]:
        return sanitize_learning_recommendations(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_finding_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)[:MAX_LIMITATIONS]

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("findings are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("findings must be deterministic")
        return True


class FindingIntelligenceResultPlan(BaseModel):
    """Deterministic R53 finding-intelligence result (R53.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_RESULT_RULE_VERSION
    intelligence_id: str = ""
    orchestration_id: str = ""
    status: str = STATUS_NO_FINDINGS
    findings: list[dict] = Field(default_factory=list)
    skipped_candidates: list[dict] = Field(default_factory=list)
    evaluation_summary: dict = Field(default_factory=dict)
    collaboration_reference: dict = Field(default_factory=dict)
    learning_reference: dict = Field(default_factory=dict)
    advisory_reference: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_RESULT_RULE_VERSION

    @field_validator("intelligence_id")
    @classmethod
    def _bounded_intelligence_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not INTELLIGENCE_ID_RE.match(text):
            raise ValueError(f"malformed intelligence_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in INTELLIGENCE_STATUSES:
            raise ValueError(f"invalid intelligence status: {value!r}")
        return text

    @field_validator("findings")
    @classmethod
    def _bounded_findings(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_finding(item))
            if len(out) >= MAX_FINDINGS:
                break
        return out

    @field_validator("skipped_candidates")
    @classmethod
    def _bounded_skipped(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_finding_skip(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SKIPPED:
                break
        return out

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_finding_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)[:MAX_LIMITATIONS]

    @field_validator("evaluation_summary")
    @classmethod
    def _bounded_evaluation(cls, value: object) -> dict:
        return sanitize_evaluation_summary(value)

    @field_validator(
        "collaboration_reference",
        "learning_reference",
        "advisory_reference",
    )
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_reference_summary(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_result_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("orchestration_id")
    @classmethod
    def _bounded_orchestration_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding intelligence results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("finding intelligence results are deterministic")
        return True


def sanitize_finding_intelligence_result(value: object) -> dict:
    """Project an R53 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "intelligence_id": "",
            "orchestration_id": "",
            "status": STATUS_NO_FINDINGS,
            "findings": [],
            "skipped_candidates": [],
            "evaluation_summary": sanitize_evaluation_summary(None),
            "collaboration_reference": sanitize_reference_summary(None),
            "learning_reference": sanitize_reference_summary(None),
            "advisory_reference": sanitize_reference_summary(None),
            "errors": [],
            "provenance": sanitize_result_provenance(None),
            "governance": sanitize_finding_governance(None),
            "limitations": [],
            "research_only": True,
            "deterministic": True,
        }
    findings: list[dict] = []
    for item in value.get("findings") or ():
        if isinstance(item, dict):
            findings.append(sanitize_finding(item))
        if len(findings) >= MAX_FINDINGS:
            break
    skipped: list[dict] = []
    for item in value.get("skipped_candidates") or ():
        projected = sanitize_finding_skip(item)
        if projected and projected not in skipped:
            skipped.append(projected)
        if len(skipped) >= MAX_SKIPPED:
            break
    errors: list[dict] = []
    for item in value.get("errors") or ():
        projected = sanitize_finding_error(item)
        if projected and projected not in errors:
            errors.append(projected)
        if len(errors) >= MAX_ERRORS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "intelligence_id": _safe_text(value.get("intelligence_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "status": _closed(
            value.get("status"), INTELLIGENCE_STATUSES, STATUS_NO_FINDINGS
        ),
        "findings": findings,
        "skipped_candidates": skipped,
        "evaluation_summary": sanitize_evaluation_summary(
            value.get("evaluation_summary")
        ),
        "collaboration_reference": sanitize_reference_summary(
            value.get("collaboration_reference")
        ),
        "learning_reference": sanitize_reference_summary(
            value.get("learning_reference")
        ),
        "advisory_reference": sanitize_reference_summary(
            value.get("advisory_reference")
        ),
        "errors": errors,
        "provenance": sanitize_result_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_finding_governance(
            value.get("governance")
        ),
        "limitations": _ordered_limitations(value.get("limitations"))[
            :MAX_LIMITATIONS
        ],
        "research_only": True,
        "deterministic": True,
    }


def finding_intelligence_result_plan_projection(
    value: FindingIntelligenceResultPlan,
) -> dict:
    """Serialize an R53 result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "INTELLIGENCE_ID_PREFIX",
    "INTELLIGENCE_ID_RE",
    "INTELLIGENCE_STATUSES",
    "REFERENCE_STATES",
    "FINDING_SKIP_REASONS",
    "FINDING_ERROR_CATEGORIES",
    "FINDING_LIMITATIONS",
    "FINDING_STAGE_CODES",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_NO_FINDINGS",
    "STATUS_FAILED",
    "REFERENCE_REFERENCED",
    "REFERENCE_UNKNOWN",
    "SKIP_SAFETY_FAILURE",
    "SKIP_FORBIDDEN_CLAIM",
    "SKIP_UNSUPPORTED_CATEGORY",
    "SKIP_MALFORMED_RESULT",
    "SKIP_LIMIT_EXCEEDED",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_SPECIALIST_RESULT",
    "ERROR_UNSUPPORTED_CATEGORY",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_NO_EVIDENCE_COLLECTED",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_EVALUATION_UNAVAILABLE",
    "LIMITATION_COLLABORATION_UNAVAILABLE",
    "LIMITATION_FEEDBACK_UNAVAILABLE",
    "LIMITATION_ADVISORY_UNAVAILABLE",
    "LIMITATION_CONFLICT_PRESENT",
    "LIMITATION_DUPLICATE_CORRELATION_PRESENT",
    "LIMITATION_REMEDIATION_UNAVAILABLE",
    "LIMITATION_IMPACT_NOT_OBSERVED",
    "LIMITATION_ASSET_CONTEXT_UNAVAILABLE",
    "LIMITATION_SEVERITY_NOT_ASSESSED",
    "LIMITATION_RESEARCH_CANDIDATE_ONLY",
    "LIMITATION_CORRELATION_UNAVAILABLE",
    "CONFIRMATION_NOT_CONFIRMED",
    "MAX_FINDINGS",
    "MAX_SKIPPED",
    "MAX_ERRORS",
    "MAX_LIMITATIONS",
    "MAX_CORRELATION_GROUPS",
    "MAX_CORRELATION_CONFLICTS",
    "MAX_LEARNING_RECOMMENDATIONS",
    "MAX_REFERENCE_IDS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "MAX_MESSAGE_LEN",
    "sanitize_finding_reference",
    "sanitize_finding_references",
    "sanitize_finding_correlation",
    "sanitize_finding_provenance",
    "sanitize_finding_skip",
    "sanitize_finding_error",
    "sanitize_learning_recommendations",
    "sanitize_evaluation_summary",
    "sanitize_reference_summary",
    "sanitize_result_provenance",
    "sanitize_finding_governance",
    "build_finding_governance_reference",
    "sanitize_finding",
    "sanitize_finding_intelligence_result",
    "FindingPlan",
    "FindingIntelligenceResultPlan",
    "finding_intelligence_result_plan_projection",
]

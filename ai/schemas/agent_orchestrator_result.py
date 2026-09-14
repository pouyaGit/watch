"""Agent orchestration result schema (Stage R52.6).

A :class:`AgentOrchestrationResultPlan` is the final, deterministic,
read-only result of one orchestration run. It answers the orchestration
question:

    "Which specialists were selected, what did they produce, and how were the
     existing evaluation/collaboration/feedback/advisory layers applied?"

Hard boundaries encoded here:

- Orchestration only: the result is a bounded research summary. There is no
  exploit output, no payload, no execution log, no finding and no
  vulnerability claim.
- Reuse, never recompute: specialist results are projected through their own
  R39-R50 sanitizers; evaluation through R42; collaboration through R43;
  feedback through R44; advisory through R45/R51. No layer is re-implemented.
- Deterministic: the result carries a content-derived orchestration id and a
  fixed key order; it contains no timestamp, UUID, pid, nonce or randomness.
- Bounded, privacy-safe, JSON serializable: nested structures are bounded by
  the existing layer contracts.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_result import (
    sanitize_agent_evaluation_result_plan,
)
from ai.schemas.agent_orchestrator_policy import (
    MODE_AUTOMATIC,
    SELECTION_MODES,
)
from ai.schemas.agent_orchestrator_registry import (
    ORCHESTRATION_STAGES,
    SPECIALIST_CATEGORIES,
)
from ai.schemas.api_security_agent_result import (
    sanitize_api_security_agent_result_plan,
)
from ai.schemas.cve_research_agent_result import (
    sanitize_cve_research_agent_result_plan,
)
from ai.schemas.decision_provenance import PROVENANCE_STATES
from ai.schemas.governance_rule_trace import TRACE_STATES
from ai.schemas.idor_bola_agent_result import (
    sanitize_idor_bola_agent_result_plan,
)
from ai.schemas.jwt_authentication_agent_result import (
    sanitize_jwt_authentication_agent_result_plan,
)
from ai.schemas.learning_recommendation import (
    sanitize_learning_recommendation,
)
from ai.schemas.learning_signal import sanitize_learning_signal
from ai.schemas.llm_advisory_result import sanitize_llm_advisory_result
from ai.schemas.llm_provider_error import sanitize_provider_error
from ai.schemas.llm_provider_telemetry import sanitize_provider_telemetry
from ai.schemas.multi_agent_collaboration_result import (
    sanitize_multi_agent_collaboration_result,
)
from ai.schemas.oauth_agent_result import sanitize_oauth_agent_result_plan
from ai.schemas.research_audit_event import AUDIT_STATES
from ai.schemas.research_explanation import EXPLANATION_STATES
from ai.schemas.research_feedback_classification import (
    sanitize_research_feedback_classification,
)
from ai.schemas.research_feedback_event import (
    sanitize_research_feedback_event,
)
from ai.schemas.research_governance_export import (
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
)
from ai.schemas.sqli_agent_result import sanitize_sqli_agent_result_plan
from ai.schemas.ssrf_agent_result import sanitize_ssrf_agent_result_plan
from ai.schemas.xss_agent_result import sanitize_xss_agent_result_plan

AGENT_ORCHESTRATOR_RESULT_RULE_VERSION = "r52-6"
RULE_VERSION = AGENT_ORCHESTRATOR_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "FAILED"
STATUS_NO_ELIGIBLE_SPECIALISTS = "NO_ELIGIBLE_SPECIALISTS"

ORCHESTRATION_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_FAILED,
    STATUS_NO_ELIGIBLE_SPECIALISTS,
)

STAGE_CONTEXT = "CONTEXT"
STAGE_POLICY = "POLICY"
STAGE_SELECTION = "SELECTION"
STAGE_INVOCATION = "INVOCATION"
STAGE_EVALUATION = "EVALUATION"
STAGE_COLLABORATION = "COLLABORATION"
STAGE_FEEDBACK = "FEEDBACK"
STAGE_ADVISORY = "ADVISORY"
STAGE_GOVERNANCE = "GOVERNANCE"

ORCHESTRATION_ERROR_STAGES: tuple[str, ...] = (
    STAGE_CONTEXT,
    STAGE_POLICY,
    STAGE_SELECTION,
    STAGE_INVOCATION,
    STAGE_EVALUATION,
    STAGE_COLLABORATION,
    STAGE_FEEDBACK,
    STAGE_ADVISORY,
    STAGE_GOVERNANCE,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_INVALID_POLICY = "INVALID_POLICY"
ERROR_NO_ELIGIBLE_SPECIALISTS = "NO_ELIGIBLE_SPECIALISTS"
ERROR_SPECIALIST_SELECTION = "SPECIALIST_SELECTION_ERROR"
ERROR_SPECIALIST_EXECUTION = "SPECIALIST_EXECUTION_ERROR"
ERROR_EVALUATION = "EVALUATION_ERROR"
ERROR_COLLABORATION = "COLLABORATION_ERROR"
ERROR_FEEDBACK = "FEEDBACK_ERROR"
ERROR_ADVISORY = "ADVISORY_ERROR"
ERROR_SAFETY = "SAFETY_ERROR"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

ORCHESTRATION_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_INVALID_POLICY,
    ERROR_NO_ELIGIBLE_SPECIALISTS,
    ERROR_SPECIALIST_SELECTION,
    ERROR_SPECIALIST_EXECUTION,
    ERROR_EVALUATION,
    ERROR_COLLABORATION,
    ERROR_FEEDBACK,
    ERROR_ADVISORY,
    ERROR_SAFETY,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

SKIP_NOT_ELIGIBLE = "NOT_ELIGIBLE"
SKIP_NOT_REQUESTED = "NOT_REQUESTED"
SKIP_DISABLED = "DISABLED"
SKIP_MAX_SPECIALISTS_EXCEEDED = "MAX_SPECIALISTS_EXCEEDED"
SKIP_STOPPED_AFTER_ERROR = "STOPPED_AFTER_ERROR"

SPECIALIST_SKIP_REASONS: tuple[str, ...] = (
    SKIP_NOT_ELIGIBLE,
    SKIP_NOT_REQUESTED,
    SKIP_DISABLED,
    SKIP_MAX_SPECIALISTS_EXCEEDED,
    SKIP_STOPPED_AFTER_ERROR,
)

REFERENCE_REFERENCED = "REFERENCED"
REFERENCE_UNKNOWN = "UNKNOWN"

ORCHESTRATION_REFERENCE_STATES: tuple[str, ...] = (
    REFERENCE_REFERENCED,
    REFERENCE_UNKNOWN,
)

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_UNKNOWN = "UNKNOWN"

ORCHESTRATION_PROVENANCE_STATES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)

GOVERNANCE_REFERENCED = "REFERENCED"
GOVERNANCE_UNKNOWN = "UNKNOWN"

GOVERNANCE_REFERENCE_STATES: tuple[str, ...] = (
    GOVERNANCE_REFERENCED,
    GOVERNANCE_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_ADVISORY_DISABLED = "ADVISORY_DISABLED"
LIMITATION_COLLABORATION_SKIPPED = "COLLABORATION_SKIPPED"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_NO_ELIGIBLE_SPECIALISTS = "NO_ELIGIBLE_SPECIALISTS"
LIMITATION_SPECIALIST_ERRORS = "SPECIALIST_ERRORS"
LIMITATION_EVALUATION_ERRORS = "EVALUATION_ERRORS"
LIMITATION_FEEDBACK_ERRORS = "FEEDBACK_ERRORS"
LIMITATION_ADVISORY_ERRORS = "ADVISORY_ERRORS"
LIMITATION_STAGE_LIMIT = "STAGE_LIMIT"
LIMITATION_RESOURCE_LIMIT = "RESOURCE_LIMIT"
LIMITATION_SELECTION_LIMITED = "SELECTION_LIMITED"

ORCHESTRATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_ADVISORY_DISABLED,
    LIMITATION_COLLABORATION_SKIPPED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_NO_ELIGIBLE_SPECIALISTS,
    LIMITATION_SPECIALIST_ERRORS,
    LIMITATION_EVALUATION_ERRORS,
    LIMITATION_FEEDBACK_ERRORS,
    LIMITATION_ADVISORY_ERRORS,
    LIMITATION_STAGE_LIMIT,
    LIMITATION_RESOURCE_LIMIT,
    LIMITATION_SELECTION_LIMITED,
)

ORCHESTRATION_ID_PREFIX = "orch-"
ORCHESTRATION_ID_RE = re.compile(r"^orch-[0-9a-f]{16}$")

MAX_SPECIALIST_RESULTS = len(SPECIALIST_CATEGORIES)
MAX_EVALUATION_RESULTS = 8
MAX_ERRORS = 32
MAX_LIMITATIONS = 16
MAX_SKIPPED = 8
MAX_REFERENCES = 8
MAX_LIST = 16
MAX_VALUE_LEN = 160
MAX_MESSAGE_LEN = 240
MAX_STAGES = len(ORCHESTRATION_STAGES)

SPECIALIST_RESULT_SANITIZERS: dict[str, object] = {
    "XSS": sanitize_xss_agent_result_plan,
    "SSRF": sanitize_ssrf_agent_result_plan,
    "SQLI": sanitize_sqli_agent_result_plan,
    "IDOR": sanitize_idor_bola_agent_result_plan,
    "JWT": sanitize_jwt_authentication_agent_result_plan,
    "OAUTH": sanitize_oauth_agent_result_plan,
    "RECON": sanitize_api_security_agent_result_plan,
    "CVE_RESEARCH": sanitize_cve_research_agent_result_plan,
}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_specialist_result(value: object) -> dict:
    """Project a specialist result through its own category sanitizer."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("category")).strip().upper()
    if category not in SPECIALIST_CATEGORIES:
        return {}
    sanitizer = SPECIALIST_RESULT_SANITIZERS.get(category)
    if sanitizer is None:
        return {}
    return sanitizer(value.get("result"))


def sanitize_orchestration_reference(value: object) -> dict:
    """Project one provenance reference onto bounded keys."""

    if not isinstance(value, dict):
        return {"reference_state": REFERENCE_UNKNOWN}
    state = _closed(
        value.get("reference_state"),
        ORCHESTRATION_REFERENCE_STATES,
        REFERENCE_UNKNOWN,
    )
    out = {"reference_state": state}
    for key in ("reference_id", "overall_rating", "safety_state",
                "hard_gate_state", "confidence", "collaboration_id",
                "feedback_id", "advisory_id"):
        text = _safe_text(value.get(key))
        if text:
            out[key] = text
    return out


def sanitize_orchestration_error(value: object) -> dict:
    """Project one orchestration error onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in ORCHESTRATION_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _closed(value.get("stage"), ORCHESTRATION_ERROR_STAGES, ""),
        "error_category": category,
        "specialist_category": _safe_text(
            value.get("specialist_category")
        ).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_skipped_specialist(value: object) -> dict:
    """Project one skipped specialist entry onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("category")).strip().upper()
    if category not in SPECIALIST_CATEGORIES:
        return {}
    return {
        "category": category,
        "reason": _closed(
            value.get("reason"), SPECIALIST_SKIP_REASONS, SKIP_NOT_ELIGIBLE
        ),
    }


def sanitize_feedback_aggregation(value: object) -> dict:
    """Project the R44 feedback aggregation onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    events: list[dict] = []
    for item in value.get("events") or ():
        projected = sanitize_research_feedback_event(item)
        if projected not in events:
            events.append(projected)
        if len(events) >= MAX_LIST:
            break
    classifications: list[dict] = []
    for item in value.get("classifications") or ():
        projected = sanitize_research_feedback_classification(item)
        if projected not in classifications:
            classifications.append(projected)
        if len(classifications) >= MAX_LIST:
            break
    signals: list[dict] = []
    for item in value.get("learning_signals") or ():
        projected = sanitize_learning_signal(item)
        if projected not in signals:
            signals.append(projected)
        if len(signals) >= MAX_LIST:
            break
    recommendations: list[dict] = []
    for item in value.get("recommendations") or ():
        projected = sanitize_learning_recommendation(item)
        if projected not in recommendations:
            recommendations.append(projected)
        if len(recommendations) >= MAX_LIST:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "events": events,
        "classifications": classifications,
        "learning_signals": signals,
        "recommendations": recommendations,
        "research_only": True,
    }


def sanitize_advisory_envelope(value: object) -> dict:
    """Project one R51 advisory envelope onto bounded keys."""

    if not isinstance(value, dict):
        return {}
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "provider_kind": _safe_text(value.get("provider_kind")),
        "provider_state": _safe_text(value.get("provider_state")),
        "advisory_result": (
            sanitize_llm_advisory_result(value.get("advisory_result"))
            if isinstance(value.get("advisory_result"), dict)
            else None
        ),
        "provider_error": sanitize_provider_error(value.get("provider_error")),
        "provider_telemetry": sanitize_provider_telemetry(
            value.get("provider_telemetry")
        ),
        "content_deterministic": (
            bool(value.get("content_deterministic")) is True
        ),
        "research_only": True,
        "deterministic": True,
    }


def sanitize_orchestration_provenance(value: object) -> dict:
    """Project orchestration provenance onto bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "stages": [],
            "skipped_stages": [],
            "specialist_origins": [],
            "provenance_state": PROVENANCE_UNKNOWN,
            "research_only": True,
        }
    origins: list[dict] = []
    for item in value.get("specialist_origins") or ():
        if not isinstance(item, dict):
            continue
        category = _safe_text(item.get("category")).strip().upper()
        if category not in SPECIALIST_CATEGORIES:
            continue
        origins.append(
            {
                "category": category,
                "specialist_name": _safe_text(item.get("specialist_name")),
                "agent_id": _safe_text(item.get("agent_id")),
                "stage": _closed(
                    item.get("stage"), ORCHESTRATION_STAGES, ""
                ),
            }
        )
        if len(origins) >= MAX_SPECIALIST_RESULTS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "stages": _bounded_codes(
            value.get("stages"), ORCHESTRATION_STAGES, MAX_STAGES
        ),
        "skipped_stages": _bounded_codes(
            value.get("skipped_stages"), ORCHESTRATION_STAGES, MAX_STAGES
        ),
        "specialist_origins": origins,
        "provenance_state": _closed(
            value.get("provenance_state"),
            ORCHESTRATION_PROVENANCE_STATES,
            PROVENANCE_UNKNOWN,
        ),
        "research_only": True,
    }


def sanitize_orchestration_governance(value: object) -> dict:
    """Project the R37 governance reference onto bounded keys.

    R52 never invents a governance record: a reference is ``REFERENCED`` only
    when the supplied plan carries the R37 governance export rule version and
    the four governance components.
    """

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": GOVERNANCE_UNKNOWN,
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
            GOVERNANCE_REFERENCE_STATES,
            GOVERNANCE_UNKNOWN,
        ),
    }


def build_orchestration_governance_reference(
    governance_plan: object = None,
) -> dict:
    """Build a bounded R37 governance reference (read-only).

    A reference is ``REFERENCED`` only when the supplied plan is a valid R37
    governance export; missing, malformed or foreign plans degrade to
    ``UNKNOWN`` and R52 never claims governed execution.
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
        return sanitize_orchestration_governance(None)
    return sanitize_orchestration_governance(
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
            "reference_state": GOVERNANCE_REFERENCED,
        }
    )


def sanitize_agent_orchestration_result_plan(value: object) -> dict:
    """Project an R52.6 orchestration result onto its bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "orchestration_id": "",
            "status": "",
            "mode": "",
            "selected_specialists": [],
            "skipped_specialists": [],
            "specialist_results": [],
            "evaluation_results": [],
            "collaboration_result": None,
            "feedback_result": None,
            "advisory_result": None,
            "errors": [],
            "provenance": sanitize_orchestration_provenance(None),
            "governance": sanitize_orchestration_governance(None),
            "limitations": [],
            "research_only": True,
            "deterministic": True,
        }
    selected: list[str] = []
    for item in value.get("selected_specialists") or ():
        text = _safe_text(item).strip().upper()
        if text in SPECIALIST_CATEGORIES and text not in selected:
            selected.append(text)
        if len(selected) >= MAX_SPECIALIST_RESULTS:
            break
    skipped: list[dict] = []
    for item in value.get("skipped_specialists") or ():
        projected = sanitize_skipped_specialist(item)
        if projected and projected not in skipped:
            skipped.append(projected)
        if len(skipped) >= MAX_SKIPPED:
            break
    specialist_results: list[dict] = []
    for item in value.get("specialist_results") or ():
        if not isinstance(item, dict):
            continue
        category = _safe_text(item.get("category")).strip().upper()
        if category not in SPECIALIST_CATEGORIES:
            continue
        sanitized = SPECIALIST_RESULT_SANITIZERS.get(category)
        result = sanitized(item.get("result")) if sanitized else {}
        if not result:
            continue
        specialist_results.append(
            {
                "category": category,
                "specialist_name": _safe_text(item.get("specialist_name")),
                "agent_id": _safe_text(item.get("agent_id")),
                "stage": _closed(
                    item.get("stage"), ORCHESTRATION_STAGES, ""
                ),
                "result": result,
                "evaluation_reference": sanitize_orchestration_reference(
                    item.get("evaluation_reference")
                ),
                "collaboration_reference": sanitize_orchestration_reference(
                    item.get("collaboration_reference")
                ),
                "feedback_reference": sanitize_orchestration_reference(
                    item.get("feedback_reference")
                ),
                "advisory_reference": sanitize_orchestration_reference(
                    item.get("advisory_reference")
                ),
            }
        )
        if len(specialist_results) >= MAX_SPECIALIST_RESULTS:
            break
    evaluations: list[dict] = []
    for item in value.get("evaluation_results") or ():
        if isinstance(item, dict):
            evaluations.append(sanitize_agent_evaluation_result_plan(item))
        if len(evaluations) >= MAX_EVALUATION_RESULTS:
            break
    collaboration = value.get("collaboration_result")
    if not isinstance(collaboration, dict) or not collaboration:
        collaboration = None
    else:
        collaboration = sanitize_multi_agent_collaboration_result(
            collaboration
        )
    feedback = value.get("feedback_result")
    feedback = sanitize_feedback_aggregation(feedback) if feedback else None
    if feedback is not None and not feedback.get("events"):
        feedback = {
            **feedback,
            "research_only": True,
        }
    advisory = value.get("advisory_result")
    advisory = sanitize_advisory_envelope(advisory) if advisory else None
    errors: list[dict] = []
    for item in value.get("errors") or ():
        projected = sanitize_orchestration_error(item)
        if projected and projected not in errors:
            errors.append(projected)
        if len(errors) >= MAX_ERRORS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "status": _safe_text(value.get("status")).strip().upper(),
        "mode": _safe_text(value.get("mode")).strip().upper(),
        "selected_specialists": selected,
        "skipped_specialists": skipped,
        "specialist_results": specialist_results,
        "evaluation_results": evaluations,
        "collaboration_result": collaboration,
        "feedback_result": feedback,
        "advisory_result": advisory,
        "errors": errors,
        "provenance": sanitize_orchestration_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_orchestration_governance(
            value.get("governance")
        ),
        "limitations": _bounded_codes(
            value.get("limitations"), ORCHESTRATION_LIMITATIONS, MAX_LIMITATIONS
        ),
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentOrchestrationResultPlan(BaseModel):
    """Deterministic, research-only orchestration result (R52.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_ORCHESTRATOR_RESULT_RULE_VERSION
    orchestration_id: str = ""
    status: str = STATUS_FAILED
    mode: str = MODE_AUTOMATIC
    selected_specialists: list[str] = Field(default_factory=list)
    skipped_specialists: list[dict] = Field(default_factory=list)
    specialist_results: list[dict] = Field(default_factory=list)
    evaluation_results: list[dict] = Field(default_factory=list)
    collaboration_result: dict | None = None
    feedback_result: dict | None = None
    advisory_result: dict | None = None
    errors: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_ORCHESTRATOR_RESULT_RULE_VERSION

    @field_validator("orchestration_id")
    @classmethod
    def _valid_orchestration_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not ORCHESTRATION_ID_RE.match(text):
            raise ValueError(f"malformed orchestration_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ORCHESTRATION_STATUSES:
            raise ValueError(f"invalid orchestration status: {value!r}")
        return text

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SELECTION_MODES:
            raise ValueError(f"invalid orchestration mode: {value!r}")
        return text

    @field_validator("selected_specialists")
    @classmethod
    def _valid_selected(cls, value: list) -> list[str]:
        selected: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in SPECIALIST_CATEGORIES and text not in selected:
                selected.append(text)
            if len(selected) >= MAX_SPECIALIST_RESULTS:
                break
        return selected

    @field_validator("skipped_specialists")
    @classmethod
    def _valid_skipped(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_skipped_specialist(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SKIPPED:
                break
        return out

    @field_validator("specialist_results")
    @classmethod
    def _valid_specialist_results(cls, value: list) -> list[dict]:
        projected = sanitize_agent_orchestration_result_plan(
            {"specialist_results": value}
        )
        return projected["specialist_results"]

    @field_validator("evaluation_results")
    @classmethod
    def _valid_evaluations(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_agent_evaluation_result_plan(item))
            if len(out) >= MAX_EVALUATION_RESULTS:
                break
        return out

    @field_validator("collaboration_result")
    @classmethod
    def _valid_collaboration(cls, value: object) -> dict | None:
        if not isinstance(value, dict) or not value:
            return None
        return sanitize_multi_agent_collaboration_result(value)

    @field_validator("feedback_result")
    @classmethod
    def _valid_feedback(cls, value: object) -> dict | None:
        if not isinstance(value, dict) or not value:
            return None
        return sanitize_feedback_aggregation(value)

    @field_validator("advisory_result")
    @classmethod
    def _valid_advisory(cls, value: object) -> dict | None:
        if not isinstance(value, dict) or not value:
            return None
        return sanitize_advisory_envelope(value)

    @field_validator("errors")
    @classmethod
    def _valid_errors(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_orchestration_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("provenance")
    @classmethod
    def _valid_provenance(cls, value: object) -> dict:
        return sanitize_orchestration_provenance(value)

    @field_validator("governance")
    @classmethod
    def _valid_governance(cls, value: object) -> dict:
        return sanitize_orchestration_governance(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in ORCHESTRATION_LIMITATIONS and text not in out:
                out.append(text)
            if len(out) >= MAX_LIMITATIONS:
                break
        return out

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("orchestration results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("orchestration results must be deterministic")
        return True


def agent_orchestration_result_plan_projection(
    value: AgentOrchestrationResultPlan,
) -> dict:
    """Serialize an orchestration result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_ORCHESTRATOR_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "ORCHESTRATION_STATUSES",
    "ORCHESTRATION_ERROR_STAGES",
    "ORCHESTRATION_ERROR_CATEGORIES",
    "ORCHESTRATION_LIMITATIONS",
    "SPECIALIST_SKIP_REASONS",
    "ORCHESTRATION_PROVENANCE_STATES",
    "GOVERNANCE_REFERENCE_STATES",
    "ORCHESTRATION_REFERENCE_STATES",
    "ORCHESTRATION_ID_PREFIX",
    "ORCHESTRATION_ID_RE",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_FAILED",
    "STATUS_NO_ELIGIBLE_SPECIALISTS",
    "STAGE_CONTEXT",
    "STAGE_POLICY",
    "STAGE_SELECTION",
    "STAGE_INVOCATION",
    "STAGE_EVALUATION",
    "STAGE_COLLABORATION",
    "STAGE_FEEDBACK",
    "STAGE_ADVISORY",
    "STAGE_GOVERNANCE",
    "ERROR_INVALID_INPUT",
    "ERROR_INVALID_POLICY",
    "ERROR_NO_ELIGIBLE_SPECIALISTS",
    "ERROR_SPECIALIST_SELECTION",
    "ERROR_SPECIALIST_EXECUTION",
    "ERROR_EVALUATION",
    "ERROR_COLLABORATION",
    "ERROR_FEEDBACK",
    "ERROR_ADVISORY",
    "ERROR_SAFETY",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "SKIP_NOT_ELIGIBLE",
    "SKIP_NOT_REQUESTED",
    "SKIP_DISABLED",
    "SKIP_MAX_SPECIALISTS_EXCEEDED",
    "SKIP_STOPPED_AFTER_ERROR",
    "REFERENCE_REFERENCED",
    "REFERENCE_UNKNOWN",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "GOVERNANCE_REFERENCED",
    "GOVERNANCE_UNKNOWN",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_ADVISORY_DISABLED",
    "LIMITATION_COLLABORATION_SKIPPED",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_NO_ELIGIBLE_SPECIALISTS",
    "LIMITATION_SPECIALIST_ERRORS",
    "LIMITATION_EVALUATION_ERRORS",
    "LIMITATION_FEEDBACK_ERRORS",
    "LIMITATION_ADVISORY_ERRORS",
    "LIMITATION_STAGE_LIMIT",
    "LIMITATION_RESOURCE_LIMIT",
    "LIMITATION_SELECTION_LIMITED",
    "MAX_SPECIALIST_RESULTS",
    "MAX_EVALUATION_RESULTS",
    "MAX_ERRORS",
    "MAX_LIMITATIONS",
    "MAX_SKIPPED",
    "MAX_MESSAGE_LEN",
    "AGENT_ORCHESTRATOR_RESULT_RULE_VERSION",
    "SPECIALIST_RESULT_SANITIZERS",
    "sanitize_specialist_result",
    "sanitize_orchestration_reference",
    "sanitize_orchestration_error",
    "sanitize_skipped_specialist",
    "sanitize_feedback_aggregation",
    "sanitize_advisory_envelope",
    "sanitize_orchestration_provenance",
    "sanitize_orchestration_governance",
    "build_orchestration_governance_reference",
    "sanitize_agent_orchestration_result_plan",
    "AgentOrchestrationResultPlan",
    "agent_orchestration_result_plan_projection",
]

"""Multi-agent collaboration input schema (Stage R43.1).

A :class:`MultiAgentCollaborationInputPlan` is the bounded, read-only
projection of several specialist agent results (and optionally their R42
evaluation results) used by the collaboration layer. It answers:

    "Which specialist research artifacts are collaborating?"

Hard boundaries encoded here:

- Collaboration only: the input is a bounded projection of already-produced
  structured results. No agent execution, no subprocess, no network, no
  database, no browser, no LLM call, no payloads, no scanning.
- No invented identity: agent attribution comes only from the supplied
  results; malformed results are preserved with flags and diagnostics
  rather than silently discarded.
- No runtime identity: ``collaboration_id`` is a deterministic content token
  or a caller-supplied validated token; no timestamps, UUID generation,
  randomness or runtime ids.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES
from ai.schemas.shared_research_context import (
    sanitize_shared_research_context,
)

MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION = "r43-1"
RULE_VERSION = MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT = "MALFORMED_SPECIALIST_RESULT"
DIAGNOSTIC_MISSING_AGENT_IDENTITY = "MISSING_AGENT_IDENTITY"
DIAGNOSTIC_DUPLICATE_AGENT_ID = "DUPLICATE_AGENT_ID"
DIAGNOSTIC_UNKNOWN_AGENT_CATEGORY = "UNKNOWN_AGENT_CATEGORY"
DIAGNOSTIC_MISSING_PROVENANCE = "MISSING_PROVENANCE"
DIAGNOSTIC_INVALID_EVALUATION_RESULT = "INVALID_EVALUATION_RESULT"
DIAGNOSTIC_EVALUATION_AGENT_MISMATCH = "EVALUATION_AGENT_MISMATCH"
DIAGNOSTIC_MISSING_SPECIALIST_RESULTS = "MISSING_SPECIALIST_RESULTS"
DIAGNOSTIC_NON_DETERMINISTIC_INPUT = "NON_DETERMINISTIC_INPUT"

COLLABORATION_DIAGNOSTIC_CODES: tuple[str, ...] = (
    DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT,
    DIAGNOSTIC_MISSING_AGENT_IDENTITY,
    DIAGNOSTIC_DUPLICATE_AGENT_ID,
    DIAGNOSTIC_UNKNOWN_AGENT_CATEGORY,
    DIAGNOSTIC_MISSING_PROVENANCE,
    DIAGNOSTIC_INVALID_EVALUATION_RESULT,
    DIAGNOSTIC_EVALUATION_AGENT_MISMATCH,
    DIAGNOSTIC_MISSING_SPECIALIST_RESULTS,
    DIAGNOSTIC_NON_DETERMINISTIC_INPUT,
)

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

COLLABORATION_DIAGNOSTIC_SEVERITIES: tuple[str, ...] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
)

GENERIC_PROVENANCE_LAYERS: tuple[str, ...] = (
    "REASONING",
    "MEMORY",
    "LEARNING",
    "STRATEGY",
    "ORCHESTRATION",
    "AUTHORIZATION",
    "GOVERNANCE",
)

GENERIC_PROVENANCE_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "UNKNOWN",
)

GENERIC_GOVERNANCE_STATES: tuple[str, ...] = (
    "REFERENCED",
    "UNKNOWN",
)

COLLABORATION_ID_PREFIX = "collab-"
COLLABORATION_ID_RE = re.compile(r"^collab-[0-9a-f]{16}$")

MAX_AGENTS = 12
MAX_RESULTS = 12
MAX_EVALUATIONS = 12
MAX_DIAGNOSTICS = 32
MAX_LIST = 16
MAX_VALUE_LEN = 160

_RULE_VERSION_RE = re.compile(r"^r[0-9]{2,3}-[0-9]{1,2}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_list(value: object, limit: int) -> list:
    if isinstance(value, (list, tuple)):
        return list(value)[:limit]
    return []


def sanitize_collaboration_provenance(value: object) -> dict:
    """Project provenance onto a bounded generic shape."""

    if not isinstance(value, dict):
        return {}
    state = _safe_text(value.get("provenance_state")).strip().upper()
    if state not in GENERIC_PROVENANCE_STATES:
        state = "UNKNOWN"
    layers: list[str] = []
    for item in value.get("source_layers") or ():
        text = _safe_text(item).strip().upper()
        if text in GENERIC_PROVENANCE_LAYERS and text not in layers:
            layers.append(text)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "source_layers": layers,
        "provenance_state": state,
        "research_only": bool(value.get("research_only")) is True,
    }


def sanitize_participating_agent(value: object) -> dict:
    """Project a participating agent onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "agent_rule_version": "",
            "result_rule_version": "",
            "research_only": True,
            "provenance": {},
        }
    category = _safe_text(value.get("agent_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    return {
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_category": category,
        "agent_rule_version": _safe_text(
            value.get("agent_rule_version")
        ),
        "result_rule_version": _safe_text(
            value.get("result_rule_version")
        ),
        "research_only": bool(value.get("research_only", True)) is True,
        "provenance": sanitize_collaboration_provenance(
            value.get("provenance")
        ),
    }


def sanitize_collaboration_evaluation(value: object) -> dict:
    """Project an R42 evaluation result onto a bounded collaboration view."""

    if not isinstance(value, dict):
        return {
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "overall_score": 0,
            "overall_rating": "CRITICAL",
            "hard_gate_state": "PASS",
            "safety_state": "FAILED",
            "structural_score": 0,
            "safety_score": 0,
            "deterministic": True,
            "research_only": True,
            "present": False,
        }
    category = (
        _safe_text(value.get("evaluated_agent_category"))
        or _safe_text(value.get("agent_category"))
    ).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    score = value.get("overall_score")
    if isinstance(score, bool) or not isinstance(score, int):
        score = 0
    score = max(0, min(100, score))
    structural_score = 0
    safety_score = 0
    for item in value.get("dimension_scores") or ():
        if not isinstance(item, dict):
            continue
        dimension = _safe_text(item.get("dimension")).strip().upper()
        item_score = item.get("score")
        if isinstance(item_score, bool) or not isinstance(item_score, int):
            continue
        item_score = max(0, min(100, item_score))
        if dimension == "STRUCTURAL_VALIDITY":
            structural_score = item_score
        elif dimension == "SAFETY_COMPLIANCE":
            safety_score = item_score
    return {
        "agent_id": _safe_text(
            value.get("evaluated_agent_id")
        ) or _safe_text(value.get("agent_id")),
        "agent_category": category,
        "overall_score": score,
        "overall_rating": _safe_text(
            value.get("overall_rating")
        ).strip().upper(),
        "hard_gate_state": _safe_text(
            value.get("hard_gate_state")
        ).strip().upper(),
        "safety_state": _safe_text(
            value.get("safety_state")
        ).strip().upper(),
        "structural_score": structural_score,
        "safety_score": safety_score,
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": bool(value.get("research_only", True)) is True,
        "present": True,
    }


def sanitize_collaboration_diagnostic(value: object) -> dict:
    """Project a collaboration diagnostic onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    code = _safe_text(value.get("diagnostic_code")).strip().upper()
    if code not in COLLABORATION_DIAGNOSTIC_CODES:
        return {}
    severity = _safe_text(value.get("severity")).strip().upper()
    if severity not in COLLABORATION_DIAGNOSTIC_SEVERITIES:
        severity = SEVERITY_LOW
    return {
        "diagnostic_code": code,
        "severity": severity,
        "agent_reference": _safe_text(
            value.get("agent_reference"), 120
        ),
        "message": _safe_text(value.get("message"), 240),
    }


def sanitize_specialist_result(value: object) -> dict:
    """Project a normalized specialist result onto fixed bounded keys.

    The projection mirrors the R42 evaluation input shape plus per-result
    structural flags, so malformed results remain visible with their
    attribution.
    """

    if not isinstance(value, dict):
        return {
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "agent_rule_version": "",
            "result_rule_version": "",
            "result_status": "UNKNOWN",
            "result_confidence": "UNKNOWN",
            "context_analysis": {},
            "hypotheses": [],
            "evidence_plan": {},
            "limitations": [],
            "provenance": {},
            "governance_reference": {},
            "research_only": True,
            "structural_flags": ["MALFORMED_SPECIALIST_RESULT"],
        }
    category = _safe_text(value.get("agent_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    confidence = _safe_text(value.get("result_confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    hypotheses: list[dict] = []
    for item in _bounded_list(value.get("hypotheses"), MAX_LIST):
        if isinstance(item, dict):
            hypotheses.append(item)
    return {
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_category": category,
        "agent_rule_version": _safe_text(
            value.get("agent_rule_version")
        ),
        "result_rule_version": _safe_text(
            value.get("result_rule_version")
        ),
        "result_status": _safe_text(
            value.get("result_status")
        ).strip().upper(),
        "result_confidence": confidence,
        "context_analysis": (
            value.get("context_analysis")
            if isinstance(value.get("context_analysis"), dict)
            else {}
        ),
        "hypotheses": hypotheses,
        "evidence_plan": (
            value.get("evidence_plan")
            if isinstance(value.get("evidence_plan"), dict)
            else {}
        ),
        "limitations": [
            _safe_text(item).strip().upper()
            for item in _bounded_list(value.get("limitations"), MAX_LIST)
            if _safe_text(item)
        ],
        "provenance": sanitize_collaboration_provenance(
            value.get("provenance")
        ),
        "governance_reference": (
            value.get("governance_reference")
            if isinstance(value.get("governance_reference"), dict)
            else {}
        ),
        "research_only": bool(value.get("research_only", True)) is True,
        "structural_flags": [
            _safe_text(item).strip().upper()
            for item in _bounded_list(
                value.get("structural_flags"), MAX_LIST
            )
            if _safe_text(item)
        ],
    }


def sanitize_multi_agent_collaboration_input(value: object) -> dict:
    """Project a collaboration input onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "collaboration_rule_version": "",
            "collaboration_id": "",
            "participating_agents": [],
            "specialist_results": [],
            "evaluation_results": [],
            "shared_context": sanitize_shared_research_context(None),
            "collaboration_diagnostics": [],
            "research_only": True,
        }
    agents: list[dict] = []
    for item in _bounded_list(value.get("participating_agents"), MAX_AGENTS):
        if isinstance(item, dict):
            agents.append(sanitize_participating_agent(item))
    results: list[dict] = []
    for item in _bounded_list(value.get("specialist_results"), MAX_RESULTS):
        results.append(sanitize_specialist_result(item))
    evaluations: list[dict] = []
    for item in _bounded_list(value.get("evaluation_results"), MAX_EVALUATIONS):
        if isinstance(item, dict):
            evaluations.append(sanitize_collaboration_evaluation(item))
    diagnostics: list[dict] = []
    for item in _bounded_list(
        value.get("collaboration_diagnostics"), MAX_DIAGNOSTICS
    ):
        projected = sanitize_collaboration_diagnostic(item)
        if projected:
            diagnostics.append(projected)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "collaboration_rule_version": _safe_text(
            value.get("collaboration_rule_version")
        ),
        "collaboration_id": _safe_text(value.get("collaboration_id")),
        "participating_agents": agents,
        "specialist_results": results,
        "evaluation_results": evaluations,
        "shared_context": sanitize_shared_research_context(
            value.get("shared_context")
        ),
        "collaboration_diagnostics": diagnostics,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class MultiAgentCollaborationInputPlan(BaseModel):
    """Bounded, read-only multi-agent collaboration input (R43.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION
    collaboration_rule_version: str = (
        MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION
    )
    collaboration_id: str = ""
    participating_agents: list[dict] = Field(default_factory=list)
    specialist_results: list[dict] = Field(default_factory=list)
    evaluation_results: list[dict] = Field(default_factory=list)
    shared_context: dict = Field(default_factory=dict)
    collaboration_diagnostics: list[dict] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version", "collaboration_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION

    @field_validator("collaboration_id")
    @classmethod
    def _bounded_collab_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("participating_agents")
    @classmethod
    def _valid_agents(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            if isinstance(item, dict):
                out.append(sanitize_participating_agent(item))
            if len(out) >= MAX_AGENTS:
                break
        return out

    @field_validator("specialist_results")
    @classmethod
    def _valid_results(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            out.append(sanitize_specialist_result(item))
            if len(out) >= MAX_RESULTS:
                break
        return out

    @field_validator("evaluation_results")
    @classmethod
    def _valid_evaluations(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            if isinstance(item, dict):
                out.append(sanitize_collaboration_evaluation(item))
            if len(out) >= MAX_EVALUATIONS:
                break
        return out

    @field_validator("shared_context")
    @classmethod
    def _valid_shared_context(cls, value: object) -> dict:
        return sanitize_shared_research_context(value)

    @field_validator("collaboration_diagnostics")
    @classmethod
    def _valid_diagnostics(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            projected = sanitize_collaboration_diagnostic(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_DIAGNOSTICS:
                break
        return out

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "multi-agent collaboration inputs are research-only"
            )
        return True


def multi_agent_collaboration_input_plan_projection(
    value: MultiAgentCollaborationInputPlan,
) -> dict:
    """Serialize a collaboration input to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "MULTI_AGENT_COLLABORATION_INPUT_RULE_VERSION",
    "RULE_VERSION",
    "COLLABORATION_DIAGNOSTIC_CODES",
    "COLLABORATION_DIAGNOSTIC_SEVERITIES",
    "GENERIC_PROVENANCE_LAYERS",
    "GENERIC_PROVENANCE_STATES",
    "GENERIC_GOVERNANCE_STATES",
    "COLLABORATION_ID_PREFIX",
    "COLLABORATION_ID_RE",
    "DIAGNOSTIC_MALFORMED_SPECIALIST_RESULT",
    "DIAGNOSTIC_MISSING_AGENT_IDENTITY",
    "DIAGNOSTIC_DUPLICATE_AGENT_ID",
    "DIAGNOSTIC_UNKNOWN_AGENT_CATEGORY",
    "DIAGNOSTIC_MISSING_PROVENANCE",
    "DIAGNOSTIC_INVALID_EVALUATION_RESULT",
    "DIAGNOSTIC_EVALUATION_AGENT_MISMATCH",
    "DIAGNOSTIC_MISSING_SPECIALIST_RESULTS",
    "DIAGNOSTIC_NON_DETERMINISTIC_INPUT",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "MAX_AGENTS",
    "MAX_RESULTS",
    "MAX_EVALUATIONS",
    "MAX_DIAGNOSTICS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "sanitize_collaboration_provenance",
    "sanitize_participating_agent",
    "sanitize_collaboration_evaluation",
    "sanitize_collaboration_diagnostic",
    "sanitize_specialist_result",
    "sanitize_multi_agent_collaboration_input",
    "MultiAgentCollaborationInputPlan",
    "multi_agent_collaboration_input_plan_projection",
]

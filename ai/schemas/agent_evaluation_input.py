"""Agent evaluation input schema (Stage R42.1).

An :class:`AgentEvaluationInputPlan` is the bounded, read-only projection of
a structured security-agent result (R38-compatible) used by the evaluation
layer. It answers the evaluation question:

    "What structured result is being evaluated?"

Hard boundaries encoded here:

- Evaluation only: the input is a bounded projection of an already-produced
  structured result. No execution, no network, no database, no browser, no
  LLM call, no payloads, no arbitrary executable objects.
- Generic specialist support: the input treats hypotheses, evidence,
  provenance and governance generically; no specialist-specific security
  logic lives here.
- Malformed values are projected deterministically to bounded placeholders
  and recorded in ``structural_flags``; the evaluator never silently treats
  malformed input as valid.
- ``research_only`` is preserved as supplied (including ``False``) so the
  safety evaluator can detect and fail it.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES
from ai.schemas.security_agent_result import AGENT_RESULT_STATUSES

AGENT_EVALUATION_INPUT_RULE_VERSION = "r42-1"
RULE_VERSION = AGENT_EVALUATION_INPUT_RULE_VERSION

# ---------------------------------------------------------------------------
# Structural flags (closed)
# ---------------------------------------------------------------------------

FLAG_MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
FLAG_INVALID_RULE_VERSION = "INVALID_RULE_VERSION"
FLAG_INVALID_ENUM_VALUE = "INVALID_ENUM_VALUE"
FLAG_UNKNOWN_AGENT_CATEGORY = "UNKNOWN_AGENT_CATEGORY"
FLAG_MALFORMED_HYPOTHESIS = "MALFORMED_HYPOTHESIS"
FLAG_MALFORMED_EVIDENCE_PLAN = "MALFORMED_EVIDENCE_PLAN"
FLAG_MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"
FLAG_MALFORMED_GOVERNANCE = "MALFORMED_GOVERNANCE"
FLAG_MALFORMED_LIMITATIONS = "MALFORMED_LIMITATIONS"
FLAG_PROVENANCE_INVENTED_LAYER = "PROVENANCE_INVENTED_LAYER"
FLAG_NON_DETERMINISTIC_OUTPUT = "NON_DETERMINISTIC_OUTPUT"

STRUCTURAL_FLAGS: tuple[str, ...] = (
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_INVALID_RULE_VERSION,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_UNKNOWN_AGENT_CATEGORY,
    FLAG_MALFORMED_HYPOTHESIS,
    FLAG_MALFORMED_EVIDENCE_PLAN,
    FLAG_MALFORMED_PROVENANCE,
    FLAG_MALFORMED_GOVERNANCE,
    FLAG_MALFORMED_LIMITATIONS,
    FLAG_PROVENANCE_INVENTED_LAYER,
    FLAG_NON_DETERMINISTIC_OUTPUT,
)

# ---------------------------------------------------------------------------
# Generic contract vocabularies
# ---------------------------------------------------------------------------

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

GENERIC_COMPONENT_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "VALID",
    "INVALID",
    "UNKNOWN",
)

HYPOTHESIS_SAFETY_LIMITATIONS: tuple[str, ...] = (
    "NO_EXPLOIT_CLAIM",
    "NO_VULNERABILITY_CONFIRMATION",
    "HYPOTHESIS_ONLY",
    "EVIDENCE_REQUIRED",
)

SAFETY_REQUIRED_LIMITATIONS: tuple[str, ...] = (
    "NO_EXECUTION_PERFORMED",
    "NO_VULNERABILITY_CONFIRMATION",
)

MAX_CONTEXT_KEYS = 16
MAX_HYPOTHESES = 12
MAX_LIST = 16
MAX_FLAGS = 12
MAX_VALUE_LEN = 160
MAX_REFERENCE_LEN = 120

_RULE_VERSION_RE = re.compile(r"^r[0-9]{2,3}-[0-9]{1,2}$")
_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

KNOWN_CONTEXT_KEYS: tuple[str, ...] = (
    "rule_version",
    "research_only",
    "input_location",
    "output_context",
    "reflection_state",
    "encoding_state",
    "framework_context",
    "url_handling",
    "server_side_fetch",
    "protocol_context",
    "redirect_behavior",
    "hostname_validation",
    "ip_validation",
    "allowlist_behavior",
    "parameter_type",
    "data_flow",
    "query_context",
    "database_context",
    "input_handling",
    "type_handling",
    "error_behavior",
    "behavioral_signal",
)


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_tokens(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text or not _TOKEN_RE.match(text) or text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_scalar_list(value: object, limit: int) -> list:
    out: list = []
    for item in value or ():
        if isinstance(item, bool):
            out.append(item)
        elif isinstance(item, (int, float)):
            out.append(item)
        elif isinstance(item, str):
            text = _safe_text(item)
            if text:
                out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_evaluation_context(value: object) -> dict:
    """Project a context-analysis dict onto a bounded generic key set."""

    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in sorted(value.keys(), key=lambda item: str(item)):
        if len(out) >= MAX_CONTEXT_KEYS:
            break
        name = str(key if key is not None else "")
        if name not in KNOWN_CONTEXT_KEYS:
            continue
        raw = value.get(key)
        if isinstance(raw, bool):
            out[name] = raw
        elif isinstance(raw, (int, float)):
            out[name] = raw
        elif isinstance(raw, str):
            text = _safe_text(raw)
            if text:
                out[name] = text
        elif isinstance(raw, (list, tuple)):
            items = _bounded_scalar_list(raw, MAX_LIST)
            if items:
                out[name] = items
    return out


def sanitize_evaluation_hypothesis(value: object) -> dict:
    """Project a hypothesis onto a bounded generic shape."""

    hypothesis_type = _safe_text(
        value.get("hypothesis_type") if isinstance(value, dict) else ""
    ).strip().upper()
    if not hypothesis_type or not _TOKEN_RE.match(hypothesis_type):
        return {}
    confidence = _safe_text(
        value.get("confidence") if isinstance(value, dict) else ""
    ).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(
        value.get("priority") if isinstance(value, dict) else ""
    ).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(
            value.get("rule_version") if isinstance(value, dict) else ""
        ),
        "hypothesis_type": hypothesis_type,
        "supporting_signals": _bounded_tokens(
            value.get("supporting_signals") if isinstance(value, dict)
            else None,
            12,
        ),
        "confidence": confidence,
        "priority": priority,
        "limitations": _bounded_tokens(
            value.get("limitations") if isinstance(value, dict) else None,
            8,
        ),
        "research_only": True,
    }


def sanitize_evaluation_evidence_plan(value: object) -> dict:
    """Project an evidence plan onto a bounded generic shape."""

    if not isinstance(value, dict):
        return {}
    state = _safe_text(value.get("evidence_state")).strip().upper()
    if state not in ("COMPLETE", "PARTIAL", "UNKNOWN"):
        state = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": _bounded_tokens(value.get("evidence_items"), 16),
        "evidence_state": state,
        "confidence": confidence,
        "limitations": _bounded_tokens(value.get("limitations"), 8),
        "research_only": True,
    }


def sanitize_evaluation_provenance(value: object) -> dict:
    """Project a provenance record onto a bounded generic shape.

    Layers outside the declared generic set are dropped; the caller records
    the invented-layer flag from the raw value.
    """

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


def sanitize_evaluation_governance(value: object) -> dict:
    """Project a governance reference onto a bounded generic shape."""

    if not isinstance(value, dict):
        return {}
    reference_state = _safe_text(
        value.get("reference_state")
    ).strip().upper()
    if reference_state not in GENERIC_GOVERNANCE_STATES:
        reference_state = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "ready": bool(value.get("ready")) is True,
        "provenance_state": _closed_component(value.get("provenance_state")),
        "trace_state": _closed_component(value.get("trace_state")),
        "audit_state": _closed_component(value.get("audit_state")),
        "explanation_state": _closed_component(value.get("explanation_state")),
        "reference_state": reference_state,
    }


def _closed_component(value: object) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in GENERIC_COMPONENT_STATES else "UNKNOWN"


def sanitize_agent_evaluation_input(value: object) -> dict:
    """Project an evaluation input onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
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
            "structural_flags": [],
        }
    category = _safe_text(value.get("agent_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    status = _safe_text(value.get("result_status")).strip().upper()
    if status not in AGENT_RESULT_STATUSES:
        status = "UNKNOWN"
    confidence = _safe_text(value.get("result_confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    hypotheses: list[dict] = []
    raw_hypotheses = value.get("hypotheses")
    if isinstance(raw_hypotheses, (list, tuple)):
        for item in raw_hypotheses:
            if not isinstance(item, dict):
                continue
            projected = sanitize_evaluation_hypothesis(item)
            if projected:
                hypotheses.append(projected)
            if len(hypotheses) >= MAX_HYPOTHESES:
                break
    raw_limitations = value.get("limitations")
    limitations = (
        _bounded_tokens(raw_limitations, MAX_LIST)
        if isinstance(raw_limitations, (list, tuple))
        else []
    )
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_category": category,
        "agent_rule_version": _safe_text(value.get("agent_rule_version")),
        "result_rule_version": _safe_text(
            value.get("result_rule_version")
        ),
        "result_status": status,
        "result_confidence": confidence,
        "context_analysis": sanitize_evaluation_context(
            value.get("context_analysis")
        ),
        "hypotheses": hypotheses,
        "evidence_plan": sanitize_evaluation_evidence_plan(
            value.get("evidence_plan")
        ),
        "limitations": limitations,
        "provenance": sanitize_evaluation_provenance(
            value.get("provenance")
        ),
        "governance_reference": sanitize_evaluation_governance(
            value.get("governance_reference")
        ),
        "research_only": bool(value.get("research_only", True)) is True,
        "structural_flags": _bounded_tokens(
            value.get("structural_flags"), MAX_FLAGS
        ),
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentEvaluationInputPlan(BaseModel):
    """Bounded, read-only evaluation input (R42.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_EVALUATION_INPUT_RULE_VERSION
    agent_id: str = ""
    agent_category: str = "UNKNOWN"
    agent_rule_version: str = ""
    result_rule_version: str = ""
    result_status: str = "UNKNOWN"
    result_confidence: str = "UNKNOWN"
    context_analysis: dict = Field(default_factory=dict)
    hypotheses: list[dict] = Field(default_factory=list)
    evidence_plan: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance_reference: dict = Field(default_factory=dict)
    research_only: bool = True
    structural_flags: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_EVALUATION_INPUT_RULE_VERSION

    @field_validator("agent_id")
    @classmethod
    def _bounded_agent_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid agent_category: {value!r}")
        return text

    @field_validator("agent_rule_version", "result_rule_version")
    @classmethod
    def _bounded_rule_version(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("result_status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_RESULT_STATUSES:
            raise ValueError(f"invalid result_status: {value!r}")
        return text

    @field_validator("result_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid result_confidence: {value!r}")
        return text

    @field_validator("context_analysis")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_evaluation_context(value)

    @field_validator("hypotheses")
    @classmethod
    def _bounded_hypotheses(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            if not isinstance(item, dict):
                continue
            projected = sanitize_evaluation_hypothesis(item)
            if projected:
                out.append(projected)
            if len(out) >= MAX_HYPOTHESES:
                break
        return out

    @field_validator("evidence_plan")
    @classmethod
    def _bounded_evidence(cls, value: object) -> dict:
        return sanitize_evaluation_evidence_plan(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: list) -> list[str]:
        return _bounded_tokens(value, MAX_LIST)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_evaluation_provenance(value)

    @field_validator("governance_reference")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_evaluation_governance(value)

    @field_validator("research_only")
    @classmethod
    def _preserved_research_only(cls, value: object) -> bool:
        return bool(value) is True

    @field_validator("structural_flags")
    @classmethod
    def _valid_flags(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in STRUCTURAL_FLAGS and text not in out:
                out.append(text)
            if len(out) >= MAX_FLAGS:
                break
        return out


def agent_evaluation_input_plan_projection(
    value: AgentEvaluationInputPlan,
) -> dict:
    """Serialize an evaluation input to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_EVALUATION_INPUT_RULE_VERSION",
    "RULE_VERSION",
    "STRUCTURAL_FLAGS",
    "FLAG_MISSING_REQUIRED_FIELD",
    "FLAG_INVALID_RULE_VERSION",
    "FLAG_INVALID_ENUM_VALUE",
    "FLAG_UNKNOWN_AGENT_CATEGORY",
    "FLAG_MALFORMED_HYPOTHESIS",
    "FLAG_MALFORMED_EVIDENCE_PLAN",
    "FLAG_MALFORMED_PROVENANCE",
    "FLAG_MALFORMED_GOVERNANCE",
    "FLAG_MALFORMED_LIMITATIONS",
    "FLAG_PROVENANCE_INVENTED_LAYER",
    "FLAG_NON_DETERMINISTIC_OUTPUT",
    "GENERIC_PROVENANCE_LAYERS",
    "GENERIC_PROVENANCE_STATES",
    "GENERIC_GOVERNANCE_STATES",
    "GENERIC_COMPONENT_STATES",
    "HYPOTHESIS_SAFETY_LIMITATIONS",
    "SAFETY_REQUIRED_LIMITATIONS",
    "MAX_CONTEXT_KEYS",
    "MAX_HYPOTHESES",
    "MAX_LIST",
    "MAX_FLAGS",
    "MAX_VALUE_LEN",
    "MAX_REFERENCE_LEN",
    "KNOWN_CONTEXT_KEYS",
    "sanitize_evaluation_context",
    "sanitize_evaluation_hypothesis",
    "sanitize_evaluation_evidence_plan",
    "sanitize_evaluation_provenance",
    "sanitize_evaluation_governance",
    "sanitize_agent_evaluation_input",
    "AgentEvaluationInputPlan",
    "agent_evaluation_input_plan_projection",
]

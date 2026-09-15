"""Copilot opportunity and recommendation schema (Stage R60.2).

Defines one bounded, deterministic bug-bounty research opportunity and its
advisory recommendation. It answers:

    "Why is this research finding worth investigating, how strong is the
     evidence, what should I do next, and what requires human review?"

Hard boundaries encoded here:

- Advisory only: an opportunity is a research-attention abstraction derived
  verbatim from the existing R53/R54/R55/R59 outputs. It never confirms a
  vulnerability, never authorizes exploitation and never executes anything.
  ``advisory`` is forced ``True`` and ``auto_execute`` is forced ``False``.
- No new action vocabulary: ``recommended_workflow_action`` is a verbatim
  R59 next-action code and ``recommended_research_action`` is a verbatim R58
  safe research/control action code (or empty). R60 never invents actions.
- Why-codes are reused: ``research_rationale_codes`` are the verbatim R55
  priority reason codes; copilot-specific ``copilot_rationale_codes`` only
  describe briefing composition.
- Human review reasons reuse the existing R56 rationale codes where they
  already express the requirement.
- Bounded, privacy-safe, JSON serializable; no timestamps, UUIDs or
  randomness.

No I/O, no network, no LLM, no Mongo, no subprocess, no execution of any kind
is represented here.
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

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.execution_request import EXECUTION_ACTIONS
from ai.schemas.finding_assessment import FINDING_STATES, IMPACT_STATES
from ai.schemas.finding_evidence import EVIDENCE_COMPLETENESS_LEVELS
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.human_decision import (
    RATIONALE_CONFLICT_REQUIRES_RESOLUTION,
    RATIONALE_DUPLICATE_RESEARCH_OVERLAP,
    RATIONALE_EVIDENCE_INCOMPLETE,
    RATIONALE_ESCALATION_REQUIRED,
    RATIONALE_FAILS_RESEARCH_SCOPE,
    RATIONALE_GOVERNANCE_REVIEW_REQUIRED,
    RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING,
    RATIONALE_PROVENANCE_INCOMPLETE,
    RATIONALE_SEVERITY_CONTEXT_REQUIRED,
)
from ai.schemas.research_priority import (
    CONFLICT_STATES,
    PRIORITY_BANDS,
    PRIORITY_BAND_RANK,
    PRIORITY_REASONS,
)
from ai.schemas.workflow_next_action import WORKFLOW_NEXT_ACTIONS

COPILOT_OPPORTUNITY_RULE_VERSION = "r60-2"
RULE_VERSION = COPILOT_OPPORTUNITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Opportunity class vocabulary (closed; research attention only)
# ---------------------------------------------------------------------------

OPPORTUNITY_HIGH_PRIORITY = "HIGH_PRIORITY_RESEARCH"
OPPORTUNITY_PRIORITY = "PRIORITY_RESEARCH"
OPPORTUNITY_STANDARD = "STANDARD_RESEARCH"
OPPORTUNITY_DEFERRED = "DEFERRED_RESEARCH"
OPPORTUNITY_BLOCKED = "BLOCKED_RESEARCH"
OPPORTUNITY_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

OPPORTUNITY_CLASSES: tuple[str, ...] = (
    OPPORTUNITY_HIGH_PRIORITY,
    OPPORTUNITY_PRIORITY,
    OPPORTUNITY_STANDARD,
    OPPORTUNITY_DEFERRED,
    OPPORTUNITY_BLOCKED,
    OPPORTUNITY_INSUFFICIENT,
)

# ---------------------------------------------------------------------------
# Human-review reason vocabulary (closed; reuses R56 rationale codes)
# ---------------------------------------------------------------------------

REVIEW_HUMAN_DECISION_PENDING = "HUMAN_DECISION_PENDING"
REVIEW_HUMAN_NEEDS_REVIEW = "HUMAN_NEEDS_REVIEW"
REVIEW_LEARNING_REVIEW_REQUIRED = "LEARNING_REVIEW_REQUIRED"
REVIEW_EXECUTION_CONTROL_BLOCKED = "EXECUTION_CONTROL_BLOCKED"
REVIEW_INVALID_UPSTREAM_CONTEXT = "INVALID_UPSTREAM_CONTEXT"
REVIEW_LOW_CONFIDENCE = "LOW_CONFIDENCE"
REVIEW_MISSING_EVIDENCE = "MISSING_EVIDENCE"
REVIEW_CONFLICTED_FINDING = "CONFLICTED_FINDING_STATE"

COPILOT_REVIEW_REASONS: tuple[str, ...] = (
    RATIONALE_EVIDENCE_INCOMPLETE,
    RATIONALE_CONFLICT_REQUIRES_RESOLUTION,
    RATIONALE_DUPLICATE_RESEARCH_OVERLAP,
    RATIONALE_HYPOTHESIS_NEEDS_STRENGTHENING,
    RATIONALE_GOVERNANCE_REVIEW_REQUIRED,
    RATIONALE_PROVENANCE_INCOMPLETE,
    RATIONALE_SEVERITY_CONTEXT_REQUIRED,
    RATIONALE_ESCALATION_REQUIRED,
    RATIONALE_FAILS_RESEARCH_SCOPE,
    REVIEW_HUMAN_DECISION_PENDING,
    REVIEW_HUMAN_NEEDS_REVIEW,
    REVIEW_LEARNING_REVIEW_REQUIRED,
    REVIEW_EXECUTION_CONTROL_BLOCKED,
    REVIEW_INVALID_UPSTREAM_CONTEXT,
    REVIEW_LOW_CONFIDENCE,
    REVIEW_MISSING_EVIDENCE,
    REVIEW_CONFLICTED_FINDING,
)

# ---------------------------------------------------------------------------
# Copilot rationale vocabulary (closed; briefing composition only)
# ---------------------------------------------------------------------------

RATIONALE_HIGH_PRIORITY = "HIGH_PRIORITY"
RATIONALE_ELEVATED_PRIORITY = "ELEVATED_PRIORITY"
RATIONALE_STANDARD_PRIORITY = "STANDARD_PRIORITY"
RATIONALE_DEFERRED_PRIORITY = "DEFERRED_PRIORITY"
RATIONALE_EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE"
RATIONALE_EVIDENCE_PARTIAL = "EVIDENCE_PARTIAL"
RATIONALE_EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
RATIONALE_RELATED_FINDINGS_PRESENT = "RELATED_FINDINGS_PRESENT"
RATIONALE_CONFLICT_CONTEXT = "CONFLICT_CONTEXT"
RATIONALE_DUPLICATE_CONTEXT = "DUPLICATE_CONTEXT"
RATIONALE_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
RATIONALE_HUMAN_DECISION_PRESENT = "HUMAN_DECISION_PRESENT"
RATIONALE_HUMAN_DECISION_PENDING = "HUMAN_DECISION_PENDING"
RATIONALE_LEARNING_CONTEXT = "LEARNING_CONTEXT"
RATIONALE_EXECUTION_CONTEXT = "EXECUTION_CONTEXT_AVAILABLE"
RATIONALE_EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
RATIONALE_WORKFLOW_CONTEXT_AVAILABLE = "WORKFLOW_CONTEXT_AVAILABLE"
RATIONALE_WORKFLOW_CONTEXT_MISSING = "WORKFLOW_CONTEXT_MISSING"
RATIONALE_SAFETY_BLOCKED = "SAFETY_BLOCKED"
RATIONALE_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

COPILOT_RATIONALE_CODES: tuple[str, ...] = (
    RATIONALE_HIGH_PRIORITY,
    RATIONALE_ELEVATED_PRIORITY,
    RATIONALE_STANDARD_PRIORITY,
    RATIONALE_DEFERRED_PRIORITY,
    RATIONALE_EVIDENCE_COMPLETE,
    RATIONALE_EVIDENCE_PARTIAL,
    RATIONALE_EVIDENCE_INSUFFICIENT,
    RATIONALE_RELATED_FINDINGS_PRESENT,
    RATIONALE_CONFLICT_CONTEXT,
    RATIONALE_DUPLICATE_CONTEXT,
    RATIONALE_HUMAN_REVIEW_REQUIRED,
    RATIONALE_HUMAN_DECISION_PRESENT,
    RATIONALE_HUMAN_DECISION_PENDING,
    RATIONALE_LEARNING_CONTEXT,
    RATIONALE_EXECUTION_CONTEXT,
    RATIONALE_EXECUTION_BLOCKED,
    RATIONALE_WORKFLOW_CONTEXT_AVAILABLE,
    RATIONALE_WORKFLOW_CONTEXT_MISSING,
    RATIONALE_SAFETY_BLOCKED,
    RATIONALE_INSUFFICIENT_DATA,
)

# ---------------------------------------------------------------------------
# Safety restriction vocabulary (closed)
# ---------------------------------------------------------------------------

RESTRICTION_RESEARCH_ONLY = "RESEARCH_ONLY"
RESTRICTION_NO_NETWORK_EXECUTION = "NO_NETWORK_EXECUTION"
RESTRICTION_NO_SCANNER_EXECUTION = "NO_SCANNER_EXECUTION"
RESTRICTION_NO_BROWSER_AUTOMATION = "NO_BROWSER_AUTOMATION"
RESTRICTION_NO_SUBPROCESS_EXECUTION = "NO_SUBPROCESS_EXECUTION"
RESTRICTION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
RESTRICTION_NO_ATTACK_PLANNING = "NO_ATTACK_PLANNING"
RESTRICTION_NO_EXPLOIT_AUTHORIZATION = "NO_EXPLOIT_AUTHORIZATION"
RESTRICTION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
RESTRICTION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
RESTRICTION_R58_GATE_REQUIRED = "R58_GATE_REQUIRED"

COPILOT_SAFETY_RESTRICTIONS: tuple[str, ...] = (
    RESTRICTION_RESEARCH_ONLY,
    RESTRICTION_NO_NETWORK_EXECUTION,
    RESTRICTION_NO_SCANNER_EXECUTION,
    RESTRICTION_NO_BROWSER_AUTOMATION,
    RESTRICTION_NO_SUBPROCESS_EXECUTION,
    RESTRICTION_NO_PAYLOAD_GENERATION,
    RESTRICTION_NO_ATTACK_PLANNING,
    RESTRICTION_NO_EXPLOIT_AUTHORIZATION,
    RESTRICTION_NO_VULNERABILITY_CONFIRMATION,
    RESTRICTION_HUMAN_AUTHORITY_REQUIRED,
    RESTRICTION_R58_GATE_REQUIRED,
)

# ---------------------------------------------------------------------------
# Opportunity / recommendation limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_AUTHORIZATION = "NO_EXPLOIT_AUTHORIZATION"
LIMITATION_NOT_AN_EXECUTION_INSTRUCTION = "NOT_AN_EXECUTION_INSTRUCTION"
LIMITATION_PRIORITY_PRESERVED = "PRIORITY_PRESERVED"
LIMITATION_EVIDENCE_VERBATIM = "EVIDENCE_VERBATIM"
LIMITATION_CORRELATION_NOT_CAUSALITY = "CORRELATION_NOT_CAUSALITY"
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_R58_GATE_REQUIRED = "R58_GATE_REQUIRED"
LIMITATION_WORKFLOW_CONTEXT_MISSING = "WORKFLOW_CONTEXT_MISSING"

COPILOT_OPPORTUNITY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_EVIDENCE_VERBATIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_R58_GATE_REQUIRED,
    LIMITATION_WORKFLOW_CONTEXT_MISSING,
)

OPPORTUNITY_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_EVIDENCE_VERBATIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_R58_GATE_REQUIRED,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

OPPORTUNITY_ID_PREFIX = "bco-"
OPPORTUNITY_ID_RE = re.compile(r"^bco-[0-9a-f]{16}$")
RECOMMENDATION_ID_PREFIX = "bcr-"
RECOMMENDATION_ID_RE = re.compile(r"^bcr-[0-9a-f]{16}$")

MAX_LIMITATIONS = 16
MAX_RATIONALE_CODES = 24
MAX_REVIEW_REASONS = 12
MAX_LIST = 24
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


def _bounded_ids(value: object, limit: int, pattern: str) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(pattern, text) and text not in out:
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
        codes, COPILOT_OPPORTUNITY_LIMITATIONS, MAX_LIMITATIONS
    )


def _ordered_review_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, COPILOT_REVIEW_REASONS, MAX_REVIEW_REASONS)


def _ordered_rationales(codes: object) -> list[str]:
    return _ordered_codes(
        codes, COPILOT_RATIONALE_CODES, MAX_RATIONALE_CODES
    )


def _ordered_priority_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, PRIORITY_REASONS, MAX_RATIONALE_CODES)


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_copilot_provenance(value: object) -> dict:
    """Project copilot provenance onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decision_rule_version": "",
            "learning_rule_version": "",
            "execution_control_rule_version": "",
            "workflow_rule_version": "",
            "prioritization_id": "",
            "correlation_id": "",
            "intelligence_id": "",
            "review_result_id": "",
            "workflow_id": "",
            "deterministic": True,
            "research_only": True,
        }
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
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "learning_rule_version": _safe_text(
            value.get("learning_rule_version")
        ),
        "execution_control_rule_version": _safe_text(
            value.get("execution_control_rule_version")
        ),
        "workflow_rule_version": _safe_text(
            value.get("workflow_rule_version")
        ),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "intelligence_id": _safe_text(value.get("intelligence_id")),
        "review_result_id": _safe_text(value.get("review_result_id")),
        "workflow_id": _safe_text(value.get("workflow_id")),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_copilot_recommendation(value: object) -> dict:
    """Project one advisory recommendation onto fixed keys."""

    if not isinstance(value, dict) or not value:
        return _default_recommendation()
    workflow_action = _safe_text(value.get("workflow_next_action")).upper()
    if workflow_action not in WORKFLOW_NEXT_ACTIONS:
        workflow_action = ""
    research_action = _safe_text(value.get("research_action")).upper()
    if research_action not in EXECUTION_ACTIONS:
        research_action = ""
    return {
        "recommendation_id": _safe_text(value.get("recommendation_id")),
        "workflow_next_action": workflow_action,
        "research_action": research_action,
        "human_review_required": bool(
            value.get("human_review_required")
        )
        is True,
        "review_reasons": _ordered_review_reasons(
            value.get("review_reasons")
        ),
        "advisory": True,
        "auto_execute": False,
        "limitations": _ordered_limitations(value.get("limitations"))
        or list(OPPORTUNITY_BASE_LIMITATIONS),
        "research_only": True,
    }


def _default_recommendation() -> dict:
    return {
        "recommendation_id": "",
        "workflow_next_action": "",
        "research_action": "",
        "human_review_required": True,
        "review_reasons": [REVIEW_INVALID_UPSTREAM_CONTEXT],
        "advisory": True,
        "auto_execute": False,
        "limitations": list(OPPORTUNITY_BASE_LIMITATIONS),
        "research_only": True,
    }


def sanitize_copilot_opportunity(value: object) -> dict:
    """Project one research opportunity onto its fixed key set."""

    if not isinstance(value, dict) or not value:
        return _default_opportunity()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    category = _safe_text(value.get("category")).strip().upper()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "opportunity_id": _safe_text(value.get("opportunity_id")),
        "finding_id": finding_id,
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "finding_state": _closed(
            value.get("finding_state"), FINDING_STATES, ""
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "evidence_state": _safe_text(value.get("evidence_state")).upper(),
        "evidence_completeness": _closed(
            value.get("evidence_completeness"),
            EVIDENCE_COMPLETENESS_LEVELS,
            "UNKNOWN",
        ),
        "evidence_origin": _safe_text(
            value.get("evidence_origin")
        ).upper(),
        "severity": _safe_text(value.get("severity")).upper(),
        "severity_source": _safe_text(
            value.get("severity_source")
        ).upper(),
        "impact_state": _closed(
            value.get("impact_state"), IMPACT_STATES, "UNKNOWN"
        ),
        "priority_band": _closed(
            value.get("priority_band"), PRIORITY_BANDS, "DEFERRED"
        ),
        "priority_score": _bounded_int(
            value.get("priority_score"), 0, 100
        ),
        "ranking_position": _bounded_int(
            value.get("ranking_position"), 0, MAX_LIST
        ),
        "opportunity_class": _closed(
            value.get("opportunity_class"),
            OPPORTUNITY_CLASSES,
            OPPORTUNITY_INSUFFICIENT,
        ),
        "conflict_state": _closed(
            value.get("conflict_state"), CONFLICT_STATES, "UNKNOWN"
        ),
        "duplicate_present": bool(value.get("duplicate_present")) is True,
        "related_finding_count": _bounded_int(
            value.get("related_finding_count"), 0, MAX_LIST
        ),
        "related_finding_ids": _bounded_ids(
            value.get("related_finding_ids"),
            MAX_LIST,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "relationship_types": _bounded_strings(
            value.get("relationship_types"), MAX_LIST, 40
        ),
        "research_rationale_codes": _ordered_priority_reasons(
            value.get("research_rationale_codes")
        ),
        "copilot_rationale_codes": _ordered_rationales(
            value.get("copilot_rationale_codes")
        ),
        "recommendation": sanitize_copilot_recommendation(
            value.get("recommendation")
        ),
        "safety_status": _safe_text(
            value.get("safety_status")
        ).strip().upper(),
        "provenance": sanitize_copilot_provenance(value.get("provenance")),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations"))
        or list(OPPORTUNITY_BASE_LIMITATIONS),
        "research_only": True,
        "deterministic": True,
    }


def _default_opportunity() -> dict:
    return {
        "rule_version": "",
        "opportunity_id": "",
        "finding_id": "",
        "category": "",
        "specialist_name": "",
        "agent_id": "",
        "finding_state": "",
        "confidence": "UNKNOWN",
        "evidence_state": "",
        "evidence_completeness": "UNKNOWN",
        "evidence_origin": "",
        "severity": "",
        "severity_source": "",
        "impact_state": "UNKNOWN",
        "priority_band": "DEFERRED",
        "priority_score": 0,
        "ranking_position": 0,
        "opportunity_class": OPPORTUNITY_INSUFFICIENT,
        "conflict_state": "UNKNOWN",
        "duplicate_present": False,
        "related_finding_count": 0,
        "related_finding_ids": [],
        "relationship_types": [],
        "research_rationale_codes": [],
        "copilot_rationale_codes": [],
        "recommendation": _default_recommendation(),
        "safety_status": "",
        "provenance": sanitize_copilot_provenance(None),
        "governance": {},
        "limitations": list(OPPORTUNITY_BASE_LIMITATIONS),
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CopilotRecommendationPlan(BaseModel):
    """Deterministic advisory copilot recommendation (R60.2)."""

    model_config = ConfigDict(extra="forbid")

    recommendation_id: str = ""
    workflow_next_action: str = ""
    research_action: str = ""
    human_review_required: bool = True
    review_reasons: list[str] = Field(default_factory=list)
    advisory: bool = True
    auto_execute: bool = False
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("recommendation_id")
    @classmethod
    def _valid_recommendation_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not RECOMMENDATION_ID_RE.match(text):
            raise ValueError(f"malformed recommendation_id: {value!r}")
        return text

    @field_validator("workflow_next_action")
    @classmethod
    def _valid_workflow_action(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_NEXT_ACTIONS:
            raise ValueError(f"invalid workflow_next_action: {value!r}")
        return text

    @field_validator("research_action")
    @classmethod
    def _valid_research_action(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in EXECUTION_ACTIONS:
            raise ValueError(f"invalid research_action: {value!r}")
        return text

    @field_validator("review_reasons")
    @classmethod
    def _bounded_review_reasons(cls, value: object) -> list[str]:
        return _ordered_review_reasons(value)

    @field_validator("advisory", "research_only")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("recommendations are advisory research-only")
        return True

    @field_validator("auto_execute")
    @classmethod
    def _never_auto_executes(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("recommendations never auto-execute")
        return False

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)


class CopilotOpportunityPlan(BaseModel):
    """Deterministic bug-bounty research opportunity (R60.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COPILOT_OPPORTUNITY_RULE_VERSION
    opportunity_id: str
    finding_id: str = ""
    category: str = ""
    specialist_name: str = ""
    agent_id: str = ""
    finding_state: str = ""
    confidence: str = "UNKNOWN"
    evidence_state: str = ""
    evidence_completeness: str = "UNKNOWN"
    evidence_origin: str = ""
    severity: str = ""
    severity_source: str = ""
    impact_state: str = "UNKNOWN"
    priority_band: str = "DEFERRED"
    priority_score: int = 0
    ranking_position: int = 0
    opportunity_class: str = OPPORTUNITY_INSUFFICIENT
    conflict_state: str = "UNKNOWN"
    duplicate_present: bool = False
    related_finding_count: int = 0
    related_finding_ids: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    research_rationale_codes: list[str] = Field(default_factory=list)
    copilot_rationale_codes: list[str] = Field(default_factory=list)
    recommendation: dict = Field(default_factory=dict)
    safety_status: str = ""
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COPILOT_OPPORTUNITY_RULE_VERSION

    @field_validator("opportunity_id")
    @classmethod
    def _valid_opportunity_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not OPPORTUNITY_ID_RE.match(text):
            raise ValueError(f"malformed opportunity_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("finding_state")
    @classmethod
    def _valid_finding_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in FINDING_STATES:
            raise ValueError(f"invalid finding_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("evidence_completeness")
    @classmethod
    def _valid_evidence_completeness(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_COMPLETENESS_LEVELS:
            raise ValueError(f"invalid evidence_completeness: {value!r}")
        return text

    @field_validator("impact_state")
    @classmethod
    def _valid_impact_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IMPACT_STATES:
            raise ValueError(f"invalid impact_state: {value!r}")
        return text

    @field_validator("priority_band")
    @classmethod
    def _valid_priority_band(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITY_BANDS:
            raise ValueError(f"invalid priority_band: {value!r}")
        return text

    @field_validator("priority_score")
    @classmethod
    def _valid_priority_score(cls, value: object) -> int:
        return _bounded_int(value, 0, 100)

    @field_validator("opportunity_class")
    @classmethod
    def _valid_opportunity_class(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OPPORTUNITY_CLASSES:
            raise ValueError(f"invalid opportunity_class: {value!r}")
        return text

    @field_validator("conflict_state")
    @classmethod
    def _valid_conflict_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFLICT_STATES:
            raise ValueError(f"invalid conflict_state: {value!r}")
        return text

    @field_validator("related_finding_ids")
    @classmethod
    def _bounded_related_ids(cls, value: object) -> list[str]:
        return _bounded_ids(value, MAX_LIST, r"^fnd-[0-9a-f]{16}$")

    @field_validator("relationship_types")
    @classmethod
    def _bounded_relationship_types(cls, value: object) -> list[str]:
        return _bounded_strings(value, MAX_LIST, 40)

    @field_validator("research_rationale_codes")
    @classmethod
    def _bounded_research_rationales(cls, value: object) -> list[str]:
        return _ordered_priority_reasons(value)

    @field_validator("copilot_rationale_codes")
    @classmethod
    def _bounded_copilot_rationales(cls, value: object) -> list[str]:
        return _ordered_rationales(value)

    @field_validator("recommendation")
    @classmethod
    def _bounded_recommendation(cls, value: object) -> dict:
        return CopilotRecommendationPlan(
            **sanitize_copilot_recommendation(value)
        ).model_dump(mode="json")

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_copilot_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("copilot opportunities are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("copilot opportunities are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_blocked_class(self) -> "CopilotOpportunityPlan":
        if self.opportunity_class == OPPORTUNITY_BLOCKED and (
            self.recommendation.get("research_action")
        ):
            raise ValueError(
                "blocked opportunities cannot recommend a research action"
            )
        return self


def copilot_opportunity_plan_projection(value: CopilotOpportunityPlan) -> dict:
    """Serialize one copilot opportunity to a deterministic dict."""

    return value.model_dump(mode="json")


def copilot_recommendation_plan_projection(
    value: CopilotRecommendationPlan,
) -> dict:
    """Serialize one copilot recommendation to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "COPILOT_OPPORTUNITY_RULE_VERSION",
    "RULE_VERSION",
    "OPPORTUNITY_HIGH_PRIORITY",
    "OPPORTUNITY_PRIORITY",
    "OPPORTUNITY_STANDARD",
    "OPPORTUNITY_DEFERRED",
    "OPPORTUNITY_BLOCKED",
    "OPPORTUNITY_INSUFFICIENT",
    "OPPORTUNITY_CLASSES",
    "REVIEW_HUMAN_DECISION_PENDING",
    "REVIEW_HUMAN_NEEDS_REVIEW",
    "REVIEW_LEARNING_REVIEW_REQUIRED",
    "REVIEW_EXECUTION_CONTROL_BLOCKED",
    "REVIEW_INVALID_UPSTREAM_CONTEXT",
    "REVIEW_LOW_CONFIDENCE",
    "REVIEW_MISSING_EVIDENCE",
    "REVIEW_CONFLICTED_FINDING",
    "COPILOT_REVIEW_REASONS",
    "RATIONALE_HIGH_PRIORITY",
    "RATIONALE_ELEVATED_PRIORITY",
    "RATIONALE_STANDARD_PRIORITY",
    "RATIONALE_DEFERRED_PRIORITY",
    "RATIONALE_EVIDENCE_COMPLETE",
    "RATIONALE_EVIDENCE_PARTIAL",
    "RATIONALE_EVIDENCE_INSUFFICIENT",
    "RATIONALE_RELATED_FINDINGS_PRESENT",
    "RATIONALE_CONFLICT_CONTEXT",
    "RATIONALE_DUPLICATE_CONTEXT",
    "RATIONALE_HUMAN_REVIEW_REQUIRED",
    "RATIONALE_HUMAN_DECISION_PRESENT",
    "RATIONALE_HUMAN_DECISION_PENDING",
    "RATIONALE_LEARNING_CONTEXT",
    "RATIONALE_EXECUTION_CONTEXT",
    "RATIONALE_EXECUTION_BLOCKED",
    "RATIONALE_WORKFLOW_CONTEXT_AVAILABLE",
    "RATIONALE_WORKFLOW_CONTEXT_MISSING",
    "RATIONALE_SAFETY_BLOCKED",
    "RATIONALE_INSUFFICIENT_DATA",
    "COPILOT_RATIONALE_CODES",
    "RESTRICTION_RESEARCH_ONLY",
    "RESTRICTION_NO_NETWORK_EXECUTION",
    "RESTRICTION_NO_SCANNER_EXECUTION",
    "RESTRICTION_NO_BROWSER_AUTOMATION",
    "RESTRICTION_NO_SUBPROCESS_EXECUTION",
    "RESTRICTION_NO_PAYLOAD_GENERATION",
    "RESTRICTION_NO_ATTACK_PLANNING",
    "RESTRICTION_NO_EXPLOIT_AUTHORIZATION",
    "RESTRICTION_NO_VULNERABILITY_CONFIRMATION",
    "RESTRICTION_HUMAN_AUTHORITY_REQUIRED",
    "RESTRICTION_R58_GATE_REQUIRED",
    "COPILOT_SAFETY_RESTRICTIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_AUTHORIZATION",
    "LIMITATION_NOT_AN_EXECUTION_INSTRUCTION",
    "LIMITATION_PRIORITY_PRESERVED",
    "LIMITATION_EVIDENCE_VERBATIM",
    "LIMITATION_CORRELATION_NOT_CAUSALITY",
    "LIMITATION_HUMAN_AUTHORITY_REQUIRED",
    "LIMITATION_R58_GATE_REQUIRED",
    "LIMITATION_WORKFLOW_CONTEXT_MISSING",
    "COPILOT_OPPORTUNITY_LIMITATIONS",
    "OPPORTUNITY_BASE_LIMITATIONS",
    "OPPORTUNITY_ID_PREFIX",
    "OPPORTUNITY_ID_RE",
    "RECOMMENDATION_ID_PREFIX",
    "RECOMMENDATION_ID_RE",
    "MAX_LIMITATIONS",
    "MAX_RATIONALE_CODES",
    "MAX_REVIEW_REASONS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "PRIORITY_BAND_RANK",
    "sanitize_copilot_provenance",
    "sanitize_copilot_recommendation",
    "sanitize_copilot_opportunity",
    "CopilotRecommendationPlan",
    "CopilotOpportunityPlan",
    "copilot_opportunity_plan_projection",
    "copilot_recommendation_plan_projection",
]

"""Copilot brief schema (Stage R60.3).

Defines the bounded, deterministic bug-bounty research briefing produced by
the Watch Bug Bounty Copilot. It answers:

    "What should I investigate, why, what evidence already exists, what is
     related, how strong is it, what should I do next, what requires human
     review, and what must not be executed automatically?"

Hard boundaries encoded here:

- Advisory briefing only: the brief composes existing structured intelligence
  into a researcher-facing view. It never confirms a vulnerability, never
  authorizes exploitation and never executes anything.
- No fabricated intelligence: opportunities, priorities, evidence, findings
  and confidence are projected from the existing R53-R59 artifacts (or
  bounded references when unavailable); nothing is invented, re-scored or
  rewritten.
- Human authority preserved: ``human_review_required`` and its reasons are
  explicit, and the non-execution boundary is a fixed structural record.
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

from ai.schemas.copilot_opportunity import (
    COPILOT_REVIEW_REASONS,
    COPILOT_RATIONALE_CODES,
    COPILOT_SAFETY_RESTRICTIONS,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_EVIDENCE_VERBATIM,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_RESEARCH_ONLY,
    MAX_LIST,
    MAX_LIMITATIONS,
    MAX_VALUE_LEN,
    OPPORTUNITY_HIGH_PRIORITY,
    CopilotOpportunityPlan,
    sanitize_copilot_opportunity,
    sanitize_copilot_provenance,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_research_workflow_result import (
    WORKFLOW_SAFETY_STATUSES,
    WORKFLOW_STATES,
)
from ai.schemas.workflow_next_action import WORKFLOW_NEXT_ACTIONS

COPILOT_BRIEF_RULE_VERSION = "r60-3"
RULE_VERSION = COPILOT_BRIEF_RULE_VERSION

# ---------------------------------------------------------------------------
# Confidence basis vocabulary (closed)
# ---------------------------------------------------------------------------

BASIS_EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE"
BASIS_EVIDENCE_PARTIAL = "EVIDENCE_PARTIAL"
BASIS_EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
BASIS_CONFLICT_PRESENT = "CONFLICT_PRESENT"
BASIS_DUPLICATE_PRESENT = "DUPLICATE_PRESENT"
BASIS_HUMAN_DECISION_PENDING = "HUMAN_DECISION_PENDING"
BASIS_WORKFLOW_BLOCKED = "WORKFLOW_BLOCKED"
BASIS_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
BASIS_SAFETY_BLOCKED = "SAFETY_BLOCKED"
BASIS_NO_OPPORTUNITIES = "NO_OPPORTUNITIES"
BASIS_OPPORTUNITIES_PRESENT = "OPPORTUNITIES_PRESENT"

CONFIDENCE_BASES: tuple[str, ...] = (
    BASIS_EVIDENCE_COMPLETE,
    BASIS_EVIDENCE_PARTIAL,
    BASIS_EVIDENCE_INSUFFICIENT,
    BASIS_CONFLICT_PRESENT,
    BASIS_DUPLICATE_PRESENT,
    BASIS_HUMAN_DECISION_PENDING,
    BASIS_WORKFLOW_BLOCKED,
    BASIS_HUMAN_REVIEW_REQUIRED,
    BASIS_SAFETY_BLOCKED,
    BASIS_NO_OPPORTUNITIES,
    BASIS_OPPORTUNITIES_PRESENT,
)

# ---------------------------------------------------------------------------
# Brief limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION = "AUTHORIZATION_IS_NOT_EXECUTION"
LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE = (
    "WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE"
)
LIMITATION_HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
LIMITATION_R58_GATE_REQUIRED = "R58_GATE_REQUIRED"
LIMITATION_NO_LLM_INVOLVEMENT = "NO_LLM_INVOLVEMENT"
LIMITATION_NO_WALL_CLOCK_METADATA = "NO_WALL_CLOCK_METADATA"
LIMITATION_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
LIMITATION_WORKFLOW_CONTEXT_MISSING = "WORKFLOW_CONTEXT_MISSING"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"

COPILOT_BRIEF_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_EVIDENCE_VERBATIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION,
    LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_R58_GATE_REQUIRED,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_NO_WALL_CLOCK_METADATA,
    LIMITATION_INSUFFICIENT_DATA,
    LIMITATION_WORKFLOW_CONTEXT_MISSING,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
)

BRIEF_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_AUTHORIZATION,
    LIMITATION_NOT_AN_EXECUTION_INSTRUCTION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_EVIDENCE_VERBATIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_AUTHORIZATION_IS_NOT_EXECUTION,
    LIMITATION_WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE,
    LIMITATION_HUMAN_AUTHORITY_REQUIRED,
    LIMITATION_R58_GATE_REQUIRED,
    LIMITATION_NO_LLM_INVOLVEMENT,
    LIMITATION_NO_WALL_CLOCK_METADATA,
)

# ---------------------------------------------------------------------------
# Non-execution boundary (fixed structural record)
# ---------------------------------------------------------------------------

NON_EXECUTION_BOUNDARY: dict = {
    "execution_performed": False,
    "external_executor_present": False,
    "vulnerability_confirmed": False,
    "exploit_authorized": False,
    "confirmation_state": "NOT_CONFIRMED",
    "human_authority_required": True,
    "r58_gate_required": True,
    "advisory_only": True,
    "research_only": True,
}

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

BRIEF_ID_PREFIX = "bcb-"
BRIEF_ID_RE = re.compile(r"^bcb-[0-9a-f]{16}$")

MAX_OPPORTUNITIES = 24
MAX_ACTIONS = 24

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
    return _ordered_codes(codes, COPILOT_BRIEF_LIMITATIONS, MAX_LIMITATIONS)


def _ordered_review_reasons(codes: object) -> list[str]:
    return _ordered_codes(codes, COPILOT_REVIEW_REASONS, MAX_LIST)


def _ordered_rationales(codes: object) -> list[str]:
    return _ordered_codes(codes, COPILOT_RATIONALE_CODES, MAX_LIST)


def _ordered_bases(codes: object) -> list[str]:
    return _ordered_codes(codes, CONFIDENCE_BASES, MAX_LIST)


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_evidence_summary(value: object) -> dict:
    """Project the deterministic evidence summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "finding_count": 0,
            "evidence_complete_count": 0,
            "evidence_partial_count": 0,
            "evidence_incomplete_count": 0,
            "conflict_count": 0,
            "duplicate_count": 0,
            "related_finding_count": 0,
        }
    return {
        "finding_count": _bounded_int(value.get("finding_count"), 0, 4096),
        "evidence_complete_count": _bounded_int(
            value.get("evidence_complete_count"), 0, 4096
        ),
        "evidence_partial_count": _bounded_int(
            value.get("evidence_partial_count"), 0, 4096
        ),
        "evidence_incomplete_count": _bounded_int(
            value.get("evidence_incomplete_count"), 0, 4096
        ),
        "conflict_count": _bounded_int(
            value.get("conflict_count"), 0, 4096
        ),
        "duplicate_count": _bounded_int(
            value.get("duplicate_count"), 0, 4096
        ),
        "related_finding_count": _bounded_int(
            value.get("related_finding_count"), 0, 4096
        ),
    }


def sanitize_recommended_actions(value: object) -> list[dict]:
    """Project the compact recommended-action list (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        workflow_action = _safe_text(
            item.get("workflow_next_action")
        ).upper()
        if workflow_action and workflow_action not in WORKFLOW_NEXT_ACTIONS:
            continue
        out.append(
            {
                "finding_id": _safe_text(item.get("finding_id")),
                "workflow_next_action": workflow_action,
                "research_action": _safe_text(
                    item.get("research_action")
                ).upper(),
                "priority_band": _safe_text(
                    item.get("priority_band")
                ).upper(),
                "human_review_required": bool(
                    item.get("human_review_required")
                )
                is True,
            }
        )
        if len(out) >= MAX_ACTIONS:
            break
    return out


def sanitize_copilot_brief(value: object) -> dict:
    """Project an R60 copilot brief onto its fixed key set."""

    if not isinstance(value, dict) or not value:
        return _default_brief()
    workflows = []
    for item in value.get("opportunities") or ():
        try:
            projected = CopilotOpportunityPlan(
                **sanitize_copilot_opportunity(item)
            )
        except (TypeError, ValueError):
            continue
        workflows.append(projected.model_dump(mode="json"))
        if len(workflows) >= MAX_OPPORTUNITIES:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "brief_id": _safe_text(value.get("brief_id")),
        "target_reference": _safe_text(value.get("target_reference")),
        "research_context": value.get("research_context")
        if isinstance(value.get("research_context"), dict)
        else {},
        "workflow_id": _safe_text(value.get("workflow_id")),
        "workflow_state": _closed(
            value.get("workflow_state"), WORKFLOW_STATES + ("",), ""
        ),
        "workflow_safety_status": _closed(
            value.get("workflow_safety_status"),
            WORKFLOW_SAFETY_STATUSES + ("",),
            "",
        ),
        "workflow_next_action": _closed(
            value.get("workflow_next_action"),
            WORKFLOW_NEXT_ACTIONS + ("",),
            "",
        ),
        "workflow_next_action_reason": _safe_text(
            value.get("workflow_next_action_reason")
        ).upper(),
        "opportunities": workflows,
        "opportunity_count": _bounded_int(
            value.get("opportunity_count"), 0, MAX_OPPORTUNITIES
        ),
        "high_priority_count": _bounded_int(
            value.get("high_priority_count"), 0, MAX_OPPORTUNITIES
        ),
        "evidence_summary": sanitize_evidence_summary(
            value.get("evidence_summary")
        ),
        "related_finding_ids": _bounded_ids(
            value.get("related_finding_ids"),
            MAX_LIST,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "relationship_types": _bounded_strings(
            value.get("relationship_types"), MAX_LIST, 40
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "confidence_basis": _ordered_bases(value.get("confidence_basis")),
        "copilot_rationale_codes": _ordered_rationales(
            value.get("copilot_rationale_codes")
        ),
        "recommended_actions": sanitize_recommended_actions(
            value.get("recommended_actions")
        ),
        "human_review_required": bool(
            value.get("human_review_required")
        )
        is True,
        "human_review_reasons": _ordered_review_reasons(
            value.get("human_review_reasons")
        ),
        "safety_status": _closed(
            value.get("safety_status"),
            WORKFLOW_SAFETY_STATUSES,
            "RESEARCH_ONLY",
        ),
        "safety_restrictions": _ordered_codes(
            value.get("safety_restrictions"),
            COPILOT_SAFETY_RESTRICTIONS,
            len(COPILOT_SAFETY_RESTRICTIONS),
        )
        or list(COPILOT_SAFETY_RESTRICTIONS),
        "non_execution_boundary": dict(NON_EXECUTION_BOUNDARY),
        "provenance": sanitize_copilot_provenance(value.get("provenance")),
        "governance": value.get("governance")
        if isinstance(value.get("governance"), dict)
        else {},
        "limitations": _ordered_limitations(value.get("limitations")),
        "advisory": True,
        "human_authority_preserved": True,
        "research_only": True,
        "deterministic": True,
    }


def _default_brief() -> dict:
    return {
        "rule_version": "",
        "brief_id": "",
        "target_reference": "",
        "research_context": {},
        "workflow_id": "",
        "workflow_state": "",
        "workflow_safety_status": "",
        "workflow_next_action": "",
        "workflow_next_action_reason": "",
        "opportunities": [],
        "opportunity_count": 0,
        "high_priority_count": 0,
        "evidence_summary": sanitize_evidence_summary(None),
        "related_finding_ids": [],
        "relationship_types": [],
        "confidence": "UNKNOWN",
        "confidence_basis": [BASIS_NO_OPPORTUNITIES],
        "copilot_rationale_codes": [],
        "recommended_actions": [],
        "human_review_required": True,
        "human_review_reasons": [],
        "safety_status": "RESEARCH_ONLY",
        "safety_restrictions": list(COPILOT_SAFETY_RESTRICTIONS),
        "non_execution_boundary": dict(NON_EXECUTION_BOUNDARY),
        "provenance": sanitize_copilot_provenance(None),
        "governance": {},
        "limitations": list(BRIEF_BASE_LIMITATIONS),
        "advisory": True,
        "human_authority_preserved": True,
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CopilotBriefPlan(BaseModel):
    """Deterministic R60 bug bounty copilot brief (R60.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COPILOT_BRIEF_RULE_VERSION
    brief_id: str
    target_reference: str = ""
    research_context: dict = Field(default_factory=dict)
    workflow_id: str = ""
    workflow_state: str = ""
    workflow_safety_status: str = ""
    workflow_next_action: str = ""
    workflow_next_action_reason: str = ""
    opportunities: list[dict] = Field(default_factory=list)
    opportunity_count: int = 0
    high_priority_count: int = 0
    evidence_summary: dict = Field(default_factory=dict)
    related_finding_ids: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    confidence_basis: list[str] = Field(default_factory=list)
    copilot_rationale_codes: list[str] = Field(default_factory=list)
    recommended_actions: list[dict] = Field(default_factory=list)
    human_review_required: bool = True
    human_review_reasons: list[str] = Field(default_factory=list)
    safety_status: str = "RESEARCH_ONLY"
    safety_restrictions: list[str] = Field(
        default_factory=lambda: list(COPILOT_SAFETY_RESTRICTIONS)
    )
    non_execution_boundary: dict = Field(
        default_factory=lambda: dict(NON_EXECUTION_BOUNDARY)
    )
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    advisory: bool = True
    human_authority_preserved: bool = True
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COPILOT_BRIEF_RULE_VERSION

    @field_validator("brief_id")
    @classmethod
    def _valid_brief_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not BRIEF_ID_RE.match(text):
            raise ValueError(f"malformed brief_id: {value!r}")
        return text

    @field_validator("workflow_state")
    @classmethod
    def _valid_workflow_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_STATES:
            raise ValueError(f"invalid workflow_state: {value!r}")
        return text

    @field_validator("workflow_safety_status")
    @classmethod
    def _valid_workflow_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_SAFETY_STATUSES:
            raise ValueError(f"invalid workflow_safety_status: {value!r}")
        return text

    @field_validator("workflow_next_action")
    @classmethod
    def _valid_workflow_action(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in WORKFLOW_NEXT_ACTIONS:
            raise ValueError(f"invalid workflow_next_action: {value!r}")
        return text

    @field_validator("opportunities")
    @classmethod
    def _bounded_opportunities(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            try:
                projected = CopilotOpportunityPlan(
                    **sanitize_copilot_opportunity(item)
                )
            except (TypeError, ValueError):
                continue
            out.append(projected.model_dump(mode="json"))
            if len(out) >= MAX_OPPORTUNITIES:
                break
        return out

    @field_validator("opportunity_count", "high_priority_count")
    @classmethod
    def _bounded_counts(cls, value: object) -> int:
        return _bounded_int(value, 0, MAX_OPPORTUNITIES)

    @field_validator("evidence_summary")
    @classmethod
    def _bounded_evidence_summary(cls, value: object) -> dict:
        return sanitize_evidence_summary(value)

    @field_validator("related_finding_ids")
    @classmethod
    def _bounded_related_ids(cls, value: object) -> list[str]:
        return _bounded_ids(value, MAX_LIST, r"^fnd-[0-9a-f]{16}$")

    @field_validator("relationship_types")
    @classmethod
    def _bounded_relationship_types(cls, value: object) -> list[str]:
        return _bounded_strings(value, MAX_LIST, 40)

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("confidence_basis")
    @classmethod
    def _bounded_bases(cls, value: object) -> list[str]:
        return _ordered_bases(value)

    @field_validator("copilot_rationale_codes")
    @classmethod
    def _bounded_rationales(cls, value: object) -> list[str]:
        return _ordered_rationales(value)

    @field_validator("recommended_actions")
    @classmethod
    def _bounded_actions(cls, value: object) -> list[dict]:
        return sanitize_recommended_actions(value)

    @field_validator("human_review_reasons")
    @classmethod
    def _bounded_review_reasons(cls, value: object) -> list[str]:
        return _ordered_review_reasons(value)

    @field_validator("safety_status")
    @classmethod
    def _valid_safety_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in WORKFLOW_SAFETY_STATUSES:
            raise ValueError(f"invalid safety_status: {value!r}")
        return text

    @field_validator("safety_restrictions")
    @classmethod
    def _bounded_restrictions(cls, value: object) -> list[str]:
        return _ordered_codes(
            value,
            COPILOT_SAFETY_RESTRICTIONS,
            len(COPILOT_SAFETY_RESTRICTIONS),
        ) or list(COPILOT_SAFETY_RESTRICTIONS)

    @field_validator("non_execution_boundary")
    @classmethod
    def _fixed_boundary(cls, value: object) -> dict:
        return dict(NON_EXECUTION_BOUNDARY)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_copilot_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator(
        "advisory", "human_authority_preserved", "research_only"
    )
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "copilot briefs are advisory and preserve human authority"
            )
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("copilot briefs are deterministic")
        return True

    @model_validator(mode="after")
    def _consistent_brief(self) -> "CopilotBriefPlan":
        if self.opportunity_count != len(self.opportunities):
            raise ValueError(
                "opportunity_count must match the projected opportunities"
            )
        if self.human_review_required and not self.human_review_reasons:
            raise ValueError(
                "human review requirements need explicit reasons"
            )
        if not self.human_review_required and self.human_review_reasons:
            raise ValueError(
                "review reasons require human_review_required"
            )
        if self.workflow_state in FORBIDDEN_BRIEF_FLAGS:
            raise ValueError("brief state never implies execution")
        return self


#: Defensive list: a brief state/action never names execution.
FORBIDDEN_BRIEF_FLAGS: tuple[str, ...] = (
    "EXECUTED",
    "EXECUTION_PERFORMED",
    "CONFIRMED",
    "EXPLOITED",
)

#: Opportunity class that counts as high priority in the brief summary.
HIGH_PRIORITY_CLASSES: tuple[str, ...] = (OPPORTUNITY_HIGH_PRIORITY,)


def copilot_brief_plan_projection(value: CopilotBriefPlan) -> dict:
    """Serialize an R60 copilot brief to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "COPILOT_BRIEF_RULE_VERSION",
    "RULE_VERSION",
    "BASIS_EVIDENCE_COMPLETE",
    "BASIS_EVIDENCE_PARTIAL",
    "BASIS_EVIDENCE_INSUFFICIENT",
    "BASIS_CONFLICT_PRESENT",
    "BASIS_DUPLICATE_PRESENT",
    "BASIS_HUMAN_DECISION_PENDING",
    "BASIS_WORKFLOW_BLOCKED",
    "BASIS_HUMAN_REVIEW_REQUIRED",
    "BASIS_SAFETY_BLOCKED",
    "BASIS_NO_OPPORTUNITIES",
    "BASIS_OPPORTUNITIES_PRESENT",
    "CONFIDENCE_BASES",
    "COPILOT_BRIEF_LIMITATIONS",
    "BRIEF_BASE_LIMITATIONS",
    "NON_EXECUTION_BOUNDARY",
    "BRIEF_ID_PREFIX",
    "BRIEF_ID_RE",
    "MAX_OPPORTUNITIES",
    "MAX_ACTIONS",
    "FORBIDDEN_BRIEF_FLAGS",
    "HIGH_PRIORITY_CLASSES",
    "sanitize_evidence_summary",
    "sanitize_recommended_actions",
    "sanitize_copilot_brief",
    "CopilotBriefPlan",
    "copilot_brief_plan_projection",
]

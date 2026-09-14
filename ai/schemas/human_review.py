"""Human review schema (Stage R56.2).

Defines the bounded, deterministic human review of one structured research
finding and the optional review batch. It answers:

    "Which finding was reviewed, what did the human decide, and what is
     preserved?"

Hard boundaries encoded here:

- Review only: a review records a human research-workflow state. It never
  confirms a vulnerability, authorizes or performs execution, and never
  modifies the upstream R53/R54/R55 artifacts.
- Recommendation preservation: the R55 priority reference is carried
  read-only (``priority_immutable = True``); a human decision overrides
  workflow direction without rewriting the automated recommendation.
- Explicit decision boundary: a review is either pending, decided, expired
  or invalid; decided reviews must carry a valid human decision plan.
- No timestamps as identity: every id is content-derived; repeated
  evaluation is byte-identical.
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

from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.human_decision import (
    AI_ROLE_ADVISORY,
    DECISION_STATE_DECIDED,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_LIMITATIONS,
    HUMAN_DECISION_STATES,
    HUMAN_DECISION_TYPES,
    HUMAN_RATIONALE_CODES,
    NOT_AUTHORIZED_CODES,
    RATIONALE_STATES,
    TRANSITION_REASONS,
    HumanCorrelationReferencePlan,
    HumanDecisionOptionPlan,
    HumanDecisionPlan,
    HumanFindingReferencePlan,
    HumanPriorityReferencePlan,
    sanitize_decision_option,
    sanitize_decision_options,
    sanitize_human_audit,
    sanitize_human_decision,
    sanitize_human_governance,
    sanitize_human_provenance,
    sanitize_priority_reference,
    sanitize_correlation_reference,
    sanitize_finding_reference,
)
from ai.schemas.research_audit_event import AUDIT_UNKNOWN
from ai.schemas.research_priority import PRIORITY_BANDS

HUMAN_REVIEW_RULE_VERSION = "r56-2"
RULE_VERSION = HUMAN_REVIEW_RULE_VERSION

REVIEW_ID_PREFIX = "hrv-"
REVIEW_ID_RE = re.compile(r"^hrv-[0-9a-f]{16}$")

BATCH_ID_PREFIX = "hrb-"
BATCH_ID_RE = re.compile(r"^hrb-[0-9a-f]{16}$")

AUDIT_ID_PREFIX = "hda-"
AUDIT_ID_RE = re.compile(r"^hda-[0-9a-f]{16}$")

REVIEW_STATES: tuple[str, ...] = HUMAN_DECISION_STATES

MAX_REVIEWS = 8
MAX_HISTORY = 8
MAX_OPTIONS = 8
MAX_LIST = 24
MAX_VALUE_LEN = 160
MAX_NOTE_LEN = 240

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


def _bounded_ids(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if FINDING_ID_RE.match(text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_review_transition(value: object) -> dict:
    """Project a decision transition onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "from_state": DECISION_STATE_PENDING,
            "to_state": DECISION_STATE_PENDING,
            "allowed": False,
            "transition_reason": "",
        }
    from_state = _closed(
        value.get("from_state"), REVIEW_STATES, DECISION_STATE_PENDING
    )
    to_state = _closed(
        value.get("to_state"), REVIEW_STATES, DECISION_STATE_PENDING
    )
    reason = _closed(value.get("transition_reason"), TRANSITION_REASONS, "")
    return {
        "from_state": from_state,
        "to_state": to_state,
        "allowed": bool(value.get("allowed")) is True,
        "transition_reason": reason,
    }


def sanitize_decision_history_entry(value: object) -> dict:
    """Project one prior decision summary onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    decision_id = _safe_text(value.get("decision_id"))
    if decision_id and not re.match(r"^hdc-[0-9a-f]{16}$", decision_id):
        decision_id = ""
    return {
        "decision_id": decision_id,
        "decision_type": _closed(
            value.get("decision_type"), HUMAN_DECISION_TYPES, ""
        ),
        "decision_state": _closed(
            value.get("decision_state"), REVIEW_STATES, DECISION_STATE_DECIDED
        ),
        "rationale_state": _closed(
            value.get("rationale_state"),
            RATIONALE_STATES,
            "RATIONALE_NOT_PROVIDED",
        ),
        "rationale_codes": [
            code
            for code in (
                _safe_text(item).strip().upper()
                for item in value.get("rationale_codes") or ()
            )
            if code in HUMAN_RATIONALE_CODES
        ][:8],
        "transition_reason": _closed(
            value.get("transition_reason"), TRANSITION_REASONS, ""
        ),
    }


def sanitize_decision_history(value: object) -> list[dict]:
    """Project the bounded decision history (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_decision_history_entry(item)
        if projected and projected not in out:
            out.append(projected)
        if len(out) >= MAX_HISTORY:
            break
    return out


def sanitize_human_audit_entry(value: object) -> dict:
    """Project the deterministic audit entry onto fixed bounded keys."""

    return sanitize_human_audit(value)


def sanitize_ranked_snapshot(value: object) -> list[dict]:
    """Project the immutable R55 ranking snapshot (read-only copy)."""

    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        finding_id = _safe_text(item.get("finding_id"))
        if not FINDING_ID_RE.match(finding_id):
            continue
        band = _closed(
            item.get("priority_band"), PRIORITY_BANDS, "DEFERRED"
        )
        out.append(
            {
                "finding_id": finding_id,
                "priority_band": band,
                "priority_score": _bounded_int(
                    item.get("priority_score"), 0, 100
                ),
                "ranking_position": _bounded_int(
                    item.get("ranking_position"), 0, MAX_LIST
                ),
            }
        )
        if len(out) >= MAX_REVIEWS:
            break
    return out


def sanitize_decisions_by_finding(value: object) -> list[dict]:
    """Project the per-finding decision summary list (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        finding_id = _safe_text(item.get("finding_id"))
        if not FINDING_ID_RE.match(finding_id):
            continue
        decision_id = _safe_text(item.get("decision_id"))
        if decision_id and not re.match(r"^hdc-[0-9a-f]{16}$", decision_id):
            decision_id = ""
        out.append(
            {
                "finding_id": finding_id,
                "decision_id": decision_id,
                "decision_type": _closed(
                    item.get("decision_type"), HUMAN_DECISION_TYPES, ""
                ),
                "decision_state": _closed(
                    item.get("decision_state"),
                    REVIEW_STATES,
                    DECISION_STATE_PENDING,
                ),
            }
        )
        if len(out) >= MAX_REVIEWS:
            break
    return out


def sanitize_human_review_plan(value: object) -> dict:
    """Project a human review plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_review_plan()
    finding_id = _safe_text(value.get("finding_id"))
    if not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    review_state = _closed(
        value.get("review_state"), REVIEW_STATES, DECISION_STATE_PENDING
    )
    decision = value.get("decision")
    decisions: list[dict] = []
    if isinstance(decision, dict) and decision:
        decisions.append(sanitize_human_decision(decision))
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "review_id": _safe_text(value.get("review_id")),
        "finding_id": finding_id,
        "finding_reference": sanitize_finding_reference(
            value.get("finding_reference")
        ),
        "priority_reference": sanitize_priority_reference(
            value.get("priority_reference")
        ),
        "correlation_reference": sanitize_correlation_reference(
            value.get("correlation_reference")
        ),
        "review_state": review_state,
        "review_order": _bounded_int(value.get("review_order"), 0, MAX_LIST),
        "decision_options": sanitize_decision_options(
            value.get("decision_options")
        ),
        "decision": decisions[0] if decisions else {},
        "previous_decision": (
            sanitize_decision_history_entry(value.get("previous_decision"))
            if isinstance(value.get("previous_decision"), dict)
            and value.get("previous_decision")
            else {}
        ),
        "decision_history": sanitize_decision_history(
            value.get("decision_history")
        ),
        "transition": sanitize_review_transition(value.get("transition")),
        "audit": sanitize_human_audit_entry(value.get("audit")),
        "priority_immutable": True,
        "recommendation_preserved": True,
        "human_authority": True,
        "ai_role": AI_ROLE_ADVISORY,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "governance": sanitize_human_governance(value.get("governance")),
        "provenance": sanitize_human_provenance(value.get("provenance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in HUMAN_DECISION_LIMITATIONS:
            found.add(text)
    return [code for code in HUMAN_DECISION_LIMITATIONS if code in found][
        :MAX_LIST
    ]


def _default_review_plan() -> dict:
    return {
        "rule_version": "",
        "review_id": "",
        "finding_id": "",
        "finding_reference": sanitize_finding_reference(None),
        "priority_reference": sanitize_priority_reference(None),
        "correlation_reference": sanitize_correlation_reference(None),
        "review_state": DECISION_STATE_PENDING,
        "review_order": 0,
        "decision_options": [],
        "decision": {},
        "previous_decision": {},
        "decision_history": [],
        "transition": sanitize_review_transition(None),
        "audit": sanitize_human_audit_entry(None),
        "priority_immutable": True,
        "recommendation_preserved": True,
        "human_authority": True,
        "ai_role": AI_ROLE_ADVISORY,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "governance": sanitize_human_governance(None),
        "provenance": sanitize_human_provenance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


def sanitize_human_review_batch(value: object) -> dict:
    """Project a review batch onto its fixed bounded key set."""

    if not isinstance(value, dict) or not value:
        return {}
    out = {
        "rule_version": _safe_text(value.get("rule_version")),
        "batch_id": _safe_text(value.get("batch_id")),
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "review_order": _bounded_ids(value.get("review_order"), MAX_REVIEWS),
        "finding_ids": sorted(
            _bounded_ids(value.get("finding_ids"), MAX_REVIEWS)
        ),
        "ranked_snapshot": sanitize_ranked_snapshot(
            value.get("ranked_snapshot")
        ),
        "decisions_by_finding": sanitize_decisions_by_finding(
            value.get("decisions_by_finding")
        ),
        "conflict_finding_ids": sorted(
            _bounded_ids(value.get("conflict_finding_ids"), MAX_REVIEWS)
        ),
        "duplicate_finding_ids": sorted(
            _bounded_ids(value.get("duplicate_finding_ids"), MAX_REVIEWS)
        ),
        "priority_immutable": True,
        "research_only": True,
        "deterministic": True,
    }
    return out


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class HumanDecisionAuditEntryPlan(BaseModel):
    """Deterministic audit representation of one reviewed finding (R56.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_REVIEW_RULE_VERSION
    audit_id: str = ""
    finding_id: str = ""
    automated_recommendation: dict = Field(default_factory=dict)
    human_decision_type: str = ""
    human_decision_state: str = DECISION_STATE_PENDING
    decision_rationale_state: str = "RATIONALE_NOT_PROVIDED"
    decision_rationale_codes: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    governance_state: str = "UNKNOWN"
    confirmation_state: str = "NOT_CONFIRMED"
    execution_authorized: bool = False
    not_authorized: list[str] = Field(
        default_factory=lambda: list(NOT_AUTHORIZED_CODES)
    )
    audit_state: str = AUDIT_UNKNOWN
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_REVIEW_RULE_VERSION

    @field_validator("audit_id")
    @classmethod
    def _valid_audit_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not AUDIT_ID_RE.match(text):
            raise ValueError(f"malformed audit_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("human_decision_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in HUMAN_DECISION_TYPES:
            raise ValueError(f"invalid human_decision_type: {value!r}")
        return text

    @field_validator("human_decision_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REVIEW_STATES:
            raise ValueError(f"invalid human_decision_state: {value!r}")
        return text

    @field_validator("decision_rationale_codes")
    @classmethod
    def _valid_codes(cls, value: object) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in HUMAN_RATIONALE_CODES and text not in out:
                out.append(text)
        return out

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("audit entries never confirm a vulnerability")
        return "NOT_CONFIRMED"

    @field_validator("execution_authorized")
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("audit entries never authorize execution")
        return False

    @field_validator("not_authorized")
    @classmethod
    def _bounded_not_authorized(cls, value: object) -> list[str]:
        return [code for code in NOT_AUTHORIZED_CODES if code in set(
            _safe_text(item).strip().upper() for item in value or ()
        )]

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("audit entries are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("audit entries are deterministic")
        return True


class HumanReviewPlan(BaseModel):
    """Deterministic human review of one research finding (R56.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_REVIEW_RULE_VERSION
    review_id: str
    finding_id: str
    finding_reference: dict = Field(default_factory=dict)
    priority_reference: dict = Field(default_factory=dict)
    correlation_reference: dict = Field(default_factory=dict)
    review_state: str = DECISION_STATE_PENDING
    review_order: int = 0
    decision_options: list[dict] = Field(default_factory=list)
    decision: dict = Field(default_factory=dict)
    previous_decision: dict = Field(default_factory=dict)
    decision_history: list[dict] = Field(default_factory=list)
    transition: dict = Field(default_factory=dict)
    audit: dict = Field(default_factory=dict)
    priority_immutable: bool = True
    recommendation_preserved: bool = True
    human_authority: bool = True
    ai_role: str = AI_ROLE_ADVISORY
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    governance: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_REVIEW_RULE_VERSION

    @field_validator("review_id")
    @classmethod
    def _valid_review_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not REVIEW_ID_RE.match(text):
            raise ValueError(f"malformed review_id: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("review_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REVIEW_STATES:
            raise ValueError(f"invalid review_state: {value!r}")
        return text

    @field_validator("finding_reference")
    @classmethod
    def _bounded_finding(cls, value: object) -> dict:
        return HumanFindingReferencePlan(
            **sanitize_finding_reference(value)
        ).model_dump(mode="json")

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

    @field_validator("decision_options")
    @classmethod
    def _bounded_options(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_decision_option(item)
            if not projected:
                continue
            try:
                projected = HumanDecisionOptionPlan(
                    **projected
                ).model_dump(mode="json")
            except (TypeError, ValueError):
                continue
            if projected not in out:
                out.append(projected)
            if len(out) >= MAX_OPTIONS:
                break
        return out

    @field_validator("decision")
    @classmethod
    def _bounded_decision(cls, value: object) -> dict:
        if not isinstance(value, dict) or not value:
            return {}
        return HumanDecisionPlan(**sanitize_human_decision(value)).model_dump(
            mode="json"
        )

    @field_validator("previous_decision")
    @classmethod
    def _bounded_previous(cls, value: object) -> dict:
        if not isinstance(value, dict) or not value:
            return {}
        return sanitize_decision_history_entry(value)

    @field_validator("decision_history")
    @classmethod
    def _bounded_history(cls, value: object) -> list[dict]:
        return sanitize_decision_history(value)

    @field_validator("transition")
    @classmethod
    def _bounded_transition(cls, value: object) -> dict:
        return sanitize_review_transition(value)

    @field_validator("audit")
    @classmethod
    def _bounded_audit(cls, value: object) -> dict:
        return HumanDecisionAuditEntryPlan(
            **sanitize_human_audit_entry(value)
        ).model_dump(mode="json")

    @field_validator("priority_immutable", "recommendation_preserved")
    @classmethod
    def _immutable_priority(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("the R55 recommendation is immutable in R56")
        return True

    @field_validator("human_authority")
    @classmethod
    def _human_authority(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("reviews require explicit human authority")
        return True

    @field_validator("ai_role")
    @classmethod
    def _advisory_ai(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != AI_ROLE_ADVISORY:
            raise ValueError("the AI role is advisory only")
        return AI_ROLE_ADVISORY

    @field_validator(
        "execution_authorized",
        "vulnerability_confirmed",
    )
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "reviews never authorize execution or confirmation"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("reviews never confirm a vulnerability")
        return "NOT_CONFIRMED"

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_human_governance(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_human_provenance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("reviews are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("reviews are deterministic")
        return True

    @model_validator(mode="after")
    def _state_matches_decision(self) -> "HumanReviewPlan":
        if self.review_state == DECISION_STATE_DECIDED:
            if not self.decision:
                raise ValueError("decided reviews require a human decision")
            if self.decision.get("decision_state") != DECISION_STATE_DECIDED:
                raise ValueError(
                    "decided reviews require a decided decision"
                )
        elif self.decision:
            raise ValueError(
                "only decided reviews may carry a human decision"
            )
        return self


class HumanReviewBatchPlan(BaseModel):
    """Deterministic review batch over one R55 prioritization result (R56.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_REVIEW_RULE_VERSION
    batch_id: str = ""
    prioritization_id: str = ""
    review_order: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    ranked_snapshot: list[dict] = Field(default_factory=list)
    decisions_by_finding: list[dict] = Field(default_factory=list)
    conflict_finding_ids: list[str] = Field(default_factory=list)
    duplicate_finding_ids: list[str] = Field(default_factory=list)
    priority_immutable: bool = True
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_REVIEW_RULE_VERSION

    @field_validator("batch_id")
    @classmethod
    def _valid_batch_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not BATCH_ID_RE.match(text):
            raise ValueError(f"malformed batch_id: {value!r}")
        return text

    @field_validator("review_order", "finding_ids")
    @classmethod
    def _bounded_ids_field(cls, value: object) -> list[str]:
        return _bounded_ids(value, MAX_REVIEWS)

    @field_validator("finding_ids", "conflict_finding_ids",
                     "duplicate_finding_ids")
    @classmethod
    def _sorted_ids(cls, value: object) -> list[str]:
        return sorted(_bounded_ids(value, MAX_REVIEWS))

    @field_validator("ranked_snapshot")
    @classmethod
    def _bounded_snapshot(cls, value: object) -> list[dict]:
        return sanitize_ranked_snapshot(value)

    @field_validator("decisions_by_finding")
    @classmethod
    def _bounded_decisions(cls, value: object) -> list[dict]:
        return sanitize_decisions_by_finding(value)

    @field_validator("priority_immutable")
    @classmethod
    def _immutable_priority(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("the R55 recommendation is immutable in R56")
        return True

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("review batches are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("review batches are deterministic")
        return True


def human_review_plan_projection(value: HumanReviewPlan) -> dict:
    """Serialize a human review plan to a deterministic dict."""

    return value.model_dump(mode="json")


def human_review_batch_plan_projection(value: HumanReviewBatchPlan) -> dict:
    """Serialize a human review batch to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "HUMAN_REVIEW_RULE_VERSION",
    "RULE_VERSION",
    "REVIEW_ID_PREFIX",
    "REVIEW_ID_RE",
    "BATCH_ID_PREFIX",
    "BATCH_ID_RE",
    "AUDIT_ID_PREFIX",
    "AUDIT_ID_RE",
    "REVIEW_STATES",
    "MAX_REVIEWS",
    "MAX_HISTORY",
    "MAX_OPTIONS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "MAX_NOTE_LEN",
    "sanitize_review_transition",
    "sanitize_decision_history_entry",
    "sanitize_decision_history",
    "sanitize_human_audit_entry",
    "sanitize_ranked_snapshot",
    "sanitize_decisions_by_finding",
    "sanitize_human_review_plan",
    "sanitize_human_review_batch",
    "HumanDecisionAuditEntryPlan",
    "HumanReviewPlan",
    "HumanReviewBatchPlan",
    "human_review_plan_projection",
    "human_review_batch_plan_projection",
]

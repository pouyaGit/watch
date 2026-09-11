"""Opportunity Action Queue schema (Stage R26.2).

A :class:`OpportunityAction` is a read-only decision/presentation view built
on top of the existing R26.1 :class:`ResearchOpportunity`. It answers the
researcher-oriented question *"What should I work on first, and what exactly
is blocking the other items?"* — without modifying the Money Score, without
introducing a new numeric score, and without executing anything.

Hard boundaries encoded here:

- ``current_status`` is a closed action-state vocabulary (READY / BLOCKED /
  IN_PROGRESS / COMPLETED / DEFERRED), never a vulnerability verdict.
- ``recommended_action`` is a closed action vocabulary (VERIFY_ASSET_MATCH /
  GATHER_EVIDENCE / START_RESEARCH / CONTINUE_RESEARCH / REVIEW_OUTCOME /
  DEFER), never an execution verb.
- ``action_id`` is deterministic from rule_version + lead_id.
- ``rule_version`` is fixed to ``r26-2``; ``research_only`` is forced ``True``.
- no payout / bounty / reward / target URL / IP / domain / credential /
  exploit-command / execution-command / production-finding fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no execution of any kind is represented here.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict, field_validator

ACTION_RULE_VERSION = "r26-2"

# Closed action-status vocabulary (research planning only, never a verdict).
ACTION_STATUSES: tuple[str, ...] = (
    "READY",
    "BLOCKED",
    "IN_PROGRESS",
    "COMPLETED",
    "DEFERRED",
)

# Closed recommended-action vocabulary (research planning only, never
# execution).
ACTION_CODES: tuple[str, ...] = (
    "VERIFY_ASSET_MATCH",
    "GATHER_EVIDENCE",
    "START_RESEARCH",
    "CONTINUE_RESEARCH",
    "REVIEW_OUTCOME",
    "DEFER",
)

# Status order used for deterministic queue ordering (best -> worst).
ACTION_STATUS_ORDER: dict[str, int] = {
    "IN_PROGRESS": 0,
    "READY": 1,
    "BLOCKED": 2,
    "DEFERRED": 3,
    "COMPLETED": 4,
}

CONFIDENCE_CLASSES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")
EVIDENCE_QUALITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "NONE")
OPPORTUNITY_CLASSES: tuple[str, ...] = (
    "HIGH_VALUE",
    "GOOD_OPPORTUNITY",
    "RESEARCH_FIRST",
    "LOW_CONFIDENCE",
    "BLOCKED",
    "DEFER",
)

ACTION_ID_PREFIX = "oa-"
ACTION_ID_RE = re.compile(r"^oa-[0-9a-f]{16}$")
OPPORTUNITY_ID_RE = re.compile(r"^op-[0-9a-f]{16}$")
LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_BLOCKERS = 16
MAX_WHY_NOW = 16
MAX_REASON_LEN = 512


def action_id_for(
    lead_id: str,
    rule_version: str = ACTION_RULE_VERSION,
) -> str:
    """Deterministic action id from rule_version + lead_id.

    Same stable-hashing pattern as ``opportunity_id_for`` / ``lead_id_for``.
    No randomness, no clock, idempotent within a rule version.
    """

    basis = "\n".join([str(rule_version or ""), str(lead_id or "")])
    return ACTION_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


class OpportunityAction(BaseModel):
    """Read-only researcher action view for one R21 lead (research-only)."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    opportunity_id: str
    lead_id: str
    cve_id: str
    program: str

    opportunity_class: str = "DEFER"
    money_score: int = 0
    priority: str = ""
    confidence: str = "LOW"
    evidence_quality: str = "NONE"
    effort_score: int = 0
    estimated_minutes: int = 0

    current_status: str = "DEFERRED"
    recommended_action: str = "DEFER"
    action_reason: str = ""
    blockers: list[str] = []
    why_now: list[str] = []
    next_step: str = ""

    # Stage R30.1 additive asset <-> CVE match context (read-only). These never
    # change the Money Score, the opportunity class or the action precedence.
    asset_match_confidence: str = "NONE"
    asset_match_state: str = "UNKNOWN"
    strongest_match_type: str = ""
    matched_component: str = ""
    matched_version: str = ""
    matched_parameter: str = ""
    resolved_blockers: list[str] = []
    remaining_blockers: list[str] = []
    asset_match_reason: str = ""

    research_only: bool = True
    rule_version: str = ACTION_RULE_VERSION

    @field_validator("action_id")
    @classmethod
    def _valid_action_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not ACTION_ID_RE.match(text):
            raise ValueError(f"malformed action_id: {value!r}")
        return text

    @field_validator("opportunity_id")
    @classmethod
    def _valid_opportunity_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text or not OPPORTUNITY_ID_RE.match(text):
            raise ValueError(f"malformed opportunity_id: {value!r}")
        return text

    @field_validator("lead_id")
    @classmethod
    def _valid_lead_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not LEAD_ID_RE.match(text):
            raise ValueError(f"malformed lead_id: {value!r}")
        return text

    @field_validator("cve_id")
    @classmethod
    def _valid_cve(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if not CVE_RE.match(text):
            raise ValueError(f"malformed cve_id: {value!r}")
        return text

    @field_validator("program")
    @classmethod
    def _valid_program(cls, value: str) -> str:
        text = str(value or "").strip()
        if not PROGRAM_RE.match(text):
            raise ValueError(f"malformed program: {value!r}")
        return text

    @field_validator("opportunity_class")
    @classmethod
    def _valid_opportunity_class(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in OPPORTUNITY_CLASSES:
            raise ValueError(f"invalid opportunity_class: {value!r}")
        return text

    @field_validator("current_status")
    @classmethod
    def _valid_current_status(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in ACTION_STATUSES:
            raise ValueError(f"invalid current_status: {value!r}")
        return text

    @field_validator("recommended_action")
    @classmethod
    def _valid_recommended_action(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in ACTION_CODES:
            raise ValueError(f"invalid recommended_action: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: str) -> str:
        text = str(value or "LOW").strip().upper()
        if text not in CONFIDENCE_CLASSES:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("evidence_quality")
    @classmethod
    def _valid_evidence_quality(cls, value: str) -> str:
        text = str(value or "NONE").strip().upper()
        if text not in EVIDENCE_QUALITIES:
            raise ValueError(f"invalid evidence_quality: {value!r}")
        return text

    @field_validator("action_reason", "next_step")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        text = str(value or "").strip()
        return text[:MAX_REASON_LEN]

    @field_validator("blockers", "why_now")
    @classmethod
    def _bounded_lists(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
        return out[:MAX_BLOCKERS]

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return ACTION_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("opportunity actions are research-only")
        return True


def action_projection(value: OpportunityAction) -> dict:
    """Serialize one action to a deterministic dict."""

    return value.model_dump(mode="json")
"""Opportunity intelligence schema (Stage R26.1).

A :class:`ResearchOpportunity` is a read-only presentation/decision view built
around an existing R21 research lead. It composes the already-persisted
R18/R21/R22/R23/R24/R25 signals and answers "why is this research lead worth
my time right now?" — without inventing new vulnerability facts and without
replacing the Money Score.

Hard boundaries encoded here:

- opportunity_class is a research-attention class (HIGH_VALUE /
  GOOD_OPPORTUNITY / RESEARCH_FIRST / LOW_CONFIDENCE / BLOCKED / DEFER),
  never a vulnerability verdict.
- no payout / bounty / reward / target URL / IP / domain / credential /
  exploit-command / execution-command / production-finding fields exist;
  unknown fields are rejected (``extra="forbid"``).
- ``opportunity_id`` is deterministic from rule_version + lead_id.
- ``rule_version`` is fixed to ``r26-1``; ``research_only`` is forced ``True``.

No I/O, no network, no LLM, no execution of any kind is represented here.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict, field_validator

OPPORTUNITY_RULE_VERSION = "r26-1"

OPPORTUNITY_CLASSES: tuple[str, ...] = (
    "HIGH_VALUE",
    "GOOD_OPPORTUNITY",
    "RESEARCH_FIRST",
    "LOW_CONFIDENCE",
    "BLOCKED",
    "DEFER",
)

OPPORTUNITY_ACTIONS: tuple[str, ...] = (
    "START_RESEARCH",
    "RESEARCH_WITH_EVIDENCE",
    "GATHER_EVIDENCE",
    "VERIFY_ASSET_MATCH",
    "CONTINUE_SESSION",
    "DEFER",
)

CONFIDENCE_CLASSES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")
EVIDENCE_QUALITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "NONE")
SESSION_STATUSES: tuple[str, ...] = (
    "NONE",
    "PLANNED",
    "ACTIVE",
    "COMPLETED",
    "ABANDONED",
)
HISTORICAL_TIME_STATUSES: tuple[str, ...] = (
    "NONE",
    "IN_PROGRESS",
    "COMPLETED",
    "ABANDONED",
)

OPPORTUNITY_ID_PREFIX = "op-"
OPPORTUNITY_ID_RE = re.compile(r"^op-[0-9a-f]{16}$")
LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_REASONS = 32
MAX_LIST_ITEMS = 50


def opportunity_id_for(
    lead_id: str,
    rule_version: str = OPPORTUNITY_RULE_VERSION,
) -> str:
    """Deterministic opportunity id from rule_version + lead_id."""

    basis = "\n".join([str(rule_version or ""), str(lead_id or "")])
    return OPPORTUNITY_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


class ResearchOpportunity(BaseModel):
    """Read-only opportunity view for one R21 research lead (research-only)."""

    model_config = ConfigDict(extra="forbid")

    opportunity_id: str
    lead_id: str
    cve_id: str
    program: str

    money_score: int = 0
    money_priority: str = ""
    confidence: str = "LOW"
    confidence_score: int = 0
    value_score: int = 0
    effort_score: int = 0
    risk_score: int = 0

    asset_match: str = "NONE"
    evidence_quality: str = "NONE"
    research_status: str = "NONE"
    outcome_status: str = "NONE"
    session_status: str = "NONE"

    estimated_minutes: int = 0
    actual_minutes: int = 0
    time_delta_minutes: int = 0
    efficiency_ratio: float | None = None
    historical_time_status: str = "NONE"

    accepted: int = 0
    duplicate: int = 0
    rejected: int = 0
    wasted: int = 0
    acceptance_rate: float = 0.0
    wasted_rate: float = 0.0

    opportunity_class: str = "DEFER"
    recommended_action: str = "DEFER"
    why_now: list[str] = []
    why_valuable: list[str] = []
    blockers: list[str] = []
    evidence_summary: dict = {}

    rule_version: str = OPPORTUNITY_RULE_VERSION
    research_only: bool = True

    @field_validator("opportunity_id")
    @classmethod
    def _valid_opportunity_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not OPPORTUNITY_ID_RE.match(text):
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
    def _valid_class(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in OPPORTUNITY_CLASSES:
            raise ValueError(f"invalid opportunity_class: {value!r}")
        return text

    @field_validator("recommended_action")
    @classmethod
    def _valid_action(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in OPPORTUNITY_ACTIONS:
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

    @field_validator("session_status")
    @classmethod
    def _valid_session_status(cls, value: str) -> str:
        text = str(value or "NONE").strip().upper()
        if text not in SESSION_STATUSES:
            raise ValueError(f"invalid session_status: {value!r}")
        return text

    @field_validator("historical_time_status")
    @classmethod
    def _valid_historical_time(cls, value: str) -> str:
        text = str(value or "NONE").strip().upper()
        if text not in HISTORICAL_TIME_STATUSES:
            raise ValueError(f"invalid historical_time_status: {value!r}")
        return text

    @field_validator("why_now", "why_valuable", "blockers")
    @classmethod
    def _bounded_reasons(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
        return out[:MAX_REASONS]

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return OPPORTUNITY_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("opportunity views are research-only")
        return True


def opportunity_projection(value: ResearchOpportunity) -> dict:
    """Serialize one opportunity to a deterministic dict."""

    return value.model_dump(mode="json")

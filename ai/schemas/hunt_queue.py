"""Personal hunt queue schema (Stage R29.1).

A :class:`HuntItem` is a deterministic **personal-workflow** projection over
the existing R26.2 Action Queue, R25.5 outcomes and R25.7 sessions. It answers
*"What should I personally investigate next?"* to maximize useful bug-bounty
research and minimize wasted time.

Important boundaries:

- ``hunt_priority`` is **not** a replacement for the R25.2 Money Score. It is a
  small closed-vocabulary tier for personal work ordering (see
  ``ai/knowledge/hunt_queue.py`` for the documented difference).
- Historical outcomes/sessions are context only: they never modify the Money
  Score and never imply a new vulnerability is confirmed.
- ``research_only`` is forced ``True``; no execution/scanning is represented.

No payout / bounty / reward / target URL / IP / domain / credential /
exploit-command / execution-command / production-finding fields exist;
unknown fields are rejected (``extra="forbid"``).
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

HUNT_RULE_VERSION = "r29-1"

HUNT_PRIORITIES: tuple[str, ...] = (
    "HUNT_NOW",
    "HUNT_NEXT",
    "VERIFY_FIRST",
    "RESEARCH_LATER",
    "SKIP_FOR_NOW",
)

TIME_BOXES: tuple[str, ...] = (
    "30 MIN",
    "60 MIN",
    "120 MIN",
    "120 MIN + REVIEW",
)

HUNT_ID_PREFIX = "hq-"
HUNT_ID_RE = re.compile(r"^hq-[0-9a-f]{16}$")
LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_REASONS = 32


def hunt_id_for(lead_id: str,
                rule_version: str = HUNT_RULE_VERSION) -> str:
    """Deterministic personal hunt id from rule_version + lead_id."""

    basis = "\n".join([str(rule_version or ""), str(lead_id or "")])
    return HUNT_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")).hexdigest()[:16]


class HuntItem(BaseModel):
    """Read-only personal hunt-queue item (research-only)."""

    model_config = ConfigDict(extra="forbid")

    hunt_id: str
    lead_id: str
    cve_id: str
    program: str

    money_score: int = 0
    money_priority: str = ""
    opportunity_class: str = "DEFER"
    current_status: str = "DEFERRED"
    recommended_action: str = "DEFER"
    confidence: str = "LOW"
    evidence_quality: str = "NONE"
    estimated_minutes: int = 0

    why_now: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_step: str = ""

    historical_outcome: dict = Field(default_factory=dict)
    historical_time: dict = Field(default_factory=dict)

    hunt_priority: str = "SKIP_FOR_NOW"
    recommended_time_box: str = "30 MIN"
    hunt_reason: str = ""
    hunt_reason_code: str = ""

    # Stage R30.1 additive asset <-> CVE match context (read-only). These never
    # change the Money Score or the hunt priority.
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
    rule_version: str = HUNT_RULE_VERSION

    @field_validator("hunt_id")
    @classmethod
    def _valid_hunt_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not HUNT_ID_RE.match(text):
            raise ValueError(f"malformed hunt_id: {value!r}")
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

    @field_validator("hunt_priority")
    @classmethod
    def _valid_priority(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in HUNT_PRIORITIES:
            raise ValueError(f"invalid hunt_priority: {value!r}")
        return text

    @field_validator("recommended_time_box")
    @classmethod
    def _valid_time_box(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in TIME_BOXES:
            raise ValueError(f"invalid recommended_time_box: {value!r}")
        return text

    @field_validator("why_now", "blockers")
    @classmethod
    def _bounded_lists(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_REASONS:
                break
        return out

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return HUNT_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("hunt items are research-only")
        return True


def hunt_item_projection(value: HuntItem) -> dict:
    """Serialize one hunt item deterministically."""

    return value.model_dump(mode="json")

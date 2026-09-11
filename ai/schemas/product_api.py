"""Product API v1 response schema (Stage R28.1).

``ResearchOpportunityResponse`` is the consumer-oriented projection of an
internal ``ResearchOpportunity`` (R26.1) + ``OpportunityAction`` (R26.2).
Internal models must be mapped explicitly through
``ai.schemas.product_api.opportunity_response`` so internal changes never
become accidental public API contracts.

Hard boundaries encoded here:

- research-only semantics: ``research_only`` is forced ``True``.
- ``api_version`` is fixed to ``"v1"``.
- no payout / bounty / reward / target URL / IP / domain / credentials /
  HTTP response / exploit-command / execution-command / production-finding
  fields exist; unknown fields are rejected (``extra="forbid"``).

The resource NEVER represents a confirmed vulnerability, a bounty
prediction, exploitability against a target, or a target scan result.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

PRODUCT_API_VERSION = "v1"

LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_REASONS = 32
MAX_LIST_ITEMS = 50

#: Deterministic v1 error codes (no stack traces, no paths, no secrets).
ERROR_CODES: tuple[str, ...] = (
    "INVALID_REQUEST",
    "NOT_FOUND",
    "UNAUTHORIZED",
    "INTERNAL_READ_ERROR",
)


class ErrorDetail(BaseModel):
    """Machine-readable error payload (safe by construction)."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str

    @field_validator("code")
    @classmethod
    def _valid_code(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in ERROR_CODES:
            raise ValueError(f"invalid error code: {value!r}")
        return text


class ProductApiError(BaseModel):
    """v1 error envelope returned for every API failure."""

    model_config = ConfigDict(extra="forbid")

    api_version: str = PRODUCT_API_VERSION
    error: ErrorDetail
    research_only: bool = True

    @field_validator("api_version")
    @classmethod
    def _fixed_version(cls, value: str) -> str:
        return PRODUCT_API_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("product API errors are research-only")
        return True


def product_error(code: str, message: str) -> dict:
    """Build a deterministic v1 error envelope (message must be pre-sanitized)."""

    return ProductApiError(
        error=ErrorDetail(code=code, message=str(message or "")),
    ).model_dump(mode="json")


class ResearchOpportunityResponse(BaseModel):
    """Public v1 research-opportunity record (consumer-oriented, read-only)."""

    model_config = ConfigDict(extra="forbid")

    opportunity_id: str
    lead_id: str
    cve_id: str
    program: str

    opportunity_class: str = "DEFER"
    money_score: int = 0
    money_priority: str = ""
    confidence: str = "LOW"
    evidence_quality: str = "NONE"
    estimated_minutes: int = 0

    current_status: str = "DEFERRED"
    recommended_action: str = "DEFER"
    why_now: list[str] = Field(default_factory=list)
    why_valuable: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_step: str = ""

    research_status: str = "NONE"
    outcome_status: str = "NONE"
    session_status: str = "NONE"

    research_only: bool = True
    api_version: str = PRODUCT_API_VERSION

    @field_validator("lead_id")
    @classmethod
    def _valid_lead_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not LEAD_ID_RE.match(text):
            raise ValueError(f"malformed lead_id: {value!r}")
        return text

    @field_validator("opportunity_id")
    @classmethod
    def _non_empty_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("opportunity_id is required")
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

    @field_validator("why_now", "why_valuable", "blockers")
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

    @field_validator("api_version")
    @classmethod
    def _fixed_version(cls, value: str) -> str:
        return PRODUCT_API_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("product responses are research-only")
        return True


def opportunity_response(opportunity: dict, action: dict) -> dict:
    """Explicit mapping: internal opportunity/action -> public v1 response.

    Only whitelisted consumer fields are carried across. Internal-only fields
    (ids beyond opportunity/lead, subscores, rates, counts, templates,
    reasons provenance) are deliberately dropped so internal refactors never
    leak into the public contract.
    """

    opportunity = opportunity or {}
    action = action or {}
    why_now = list(opportunity.get("why_now") or action.get("why_now") or [])
    return ResearchOpportunityResponse(
        opportunity_id=str(
            opportunity.get("opportunity_id") or action.get("opportunity_id")
            or ""),
        lead_id=str(opportunity.get("lead_id") or action.get("lead_id")
                    or ""),
        cve_id=str(opportunity.get("cve_id") or action.get("cve_id") or ""),
        program=str(opportunity.get("program") or action.get("program")
                    or ""),
        opportunity_class=str(
            opportunity.get("opportunity_class") or "DEFER"),
        money_score=int(opportunity.get("money_score")
                        or action.get("money_score") or 0),
        money_priority=str(
            opportunity.get("money_priority") or action.get("priority")
            or ""),
        confidence=str(opportunity.get("confidence")
                       or action.get("confidence") or "LOW"),
        evidence_quality=str(
            opportunity.get("evidence_quality") or "NONE"),
        estimated_minutes=int(
            opportunity.get("estimated_minutes")
            if opportunity.get("estimated_minutes") is not None
            else action.get("estimated_minutes") or 0),
        current_status=str(action.get("current_status") or "DEFERRED"),
        recommended_action=str(
            action.get("recommended_action")
            or opportunity.get("recommended_action") or "DEFER"),
        why_now=why_now,
        why_valuable=list(opportunity.get("why_valuable") or []),
        blockers=list(action.get("blockers")
                      or opportunity.get("blockers") or []),
        next_step=str(action.get("next_step") or ""),
        research_status=str(
            opportunity.get("research_status") or "NONE"),
        outcome_status=str(opportunity.get("outcome_status") or "NONE"),
        session_status=str(opportunity.get("session_status") or "NONE"),
    ).model_dump(mode="json")

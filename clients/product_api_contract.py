"""Product API v1 public contract (Stage R28.2).

This module is the **consumer-side** contract for the Watch Product API v1.
It is deliberately standalone: it imports only the Python standard library
and NEVER imports Watch internals (``backend.*``, ``ai.knowledge.*``,
``ai.schemas.*``). The public field set is pinned here so unexpected schema
changes are rejected rather than silently accepted.

Contract:
- ``api_version`` must be ``"v1"``.
- ``research_only`` must be ``true``.
- Opportunity items must contain EXACTLY the 21 public fields (extras
  rejected) and satisfy closed enums / bounds.
- Only Product API v1 fields are allowed; target/credential/payout/execution
  fields are rejected by construction (they are not in the field set).
"""

from __future__ import annotations

import re
from typing import Any

PRODUCT_API_VERSION = "v1"

#: The exact public opportunity field set (added in v1; never extended in v1).
REQUIRED_FIELDS: tuple[str, ...] = (
    "opportunity_id",
    "lead_id",
    "cve_id",
    "program",
    "opportunity_class",
    "money_score",
    "money_priority",
    "confidence",
    "evidence_quality",
    "estimated_minutes",
    "current_status",
    "recommended_action",
    "why_now",
    "why_valuable",
    "blockers",
    "next_step",
    "research_status",
    "outcome_status",
    "session_status",
    "research_only",
    "api_version",
)

FIELD_SET = frozenset(REQUIRED_FIELDS)

#: Fields that must never appear in a v1 opportunity item.
FORBIDDEN_FIELDS: tuple[str, ...] = (
    "payout", "bounty", "reward", "payout_amount", "bounty_amount",
    "target_url", "target_host", "ip", "domain", "credentials", "cookies",
    "exploit_command", "execution_command", "production_finding",
    "http_response", "scan_result", "nuclei", "masscan", "curl", "bash",
)

OPPORTUNITY_CLASSES: tuple[str, ...] = (
    "HIGH_VALUE",
    "GOOD_OPPORTUNITY",
    "RESEARCH_FIRST",
    "LOW_CONFIDENCE",
    "BLOCKED",
    "DEFER",
)

RECOMMENDED_ACTIONS: tuple[str, ...] = (
    "VERIFY_ASSET_MATCH",
    "GATHER_EVIDENCE",
    "START_RESEARCH",
    "CONTINUE_RESEARCH",
    "REVIEW_OUTCOME",
    "DEFER",
)

CURRENT_STATUSES: tuple[str, ...] = (
    "READY",
    "BLOCKED",
    "IN_PROGRESS",
    "COMPLETED",
    "DEFERRED",
)

CONFIDENCE_CLASSES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")
EVIDENCE_QUALITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "NONE")

ERROR_CODES: tuple[str, ...] = (
    "INVALID_REQUEST",
    "NOT_FOUND",
    "UNAUTHORIZED",
    "INTERNAL_READ_ERROR",
)

_LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")
_OPPORTUNITY_ID_RE = re.compile(r"^op-[0-9a-f]{16}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
_PRIORITY_RE = re.compile(r"^P[1-5]_[A-Z]+$")
_STATUS_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ContractError(ValueError):
    """Raised when a response violates the public v1 contract."""

    def __init__(self, message: str, *, code: str = "CONTRACT_ERROR"):
        super().__init__(message)
        self.code = code


def _require_mapping(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _require_int(value: Any, label: str, *, lo: int | None = None,
                 hi: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an integer")
    if lo is not None and value < lo:
        raise ContractError(f"{label} must be >= {lo}")
    if hi is not None and value > hi:
        raise ContractError(f"{label} must be <= {hi}")
    return value


def _require_str_list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be a list")
    for item in value:
        if not isinstance(item, str):
            raise ContractError(f"{label} entries must be strings")
    return value


def _require_enum(value: Any, label: str, allowed: tuple) -> str:
    text = _require_str(value, label)
    if text not in allowed:
        raise ContractError(f"{label} has an unsupported value: {text!r}")
    return text


def validate_opportunity(data: Any) -> dict:
    """Validate one v1 opportunity item (exact field set + typed values)."""

    item = _require_mapping(data, "opportunity")
    keys = set(item)
    extra = keys - FIELD_SET
    missing = FIELD_SET - keys
    if extra:
        raise ContractError(
            f"unexpected field(s) in v1 opportunity: {sorted(extra)}")
    if missing:
        raise ContractError(
            f"missing field(s) in v1 opportunity: {sorted(missing)}")

    opportunity_id = _require_str(item["opportunity_id"], "opportunity_id")
    if not _OPPORTUNITY_ID_RE.match(opportunity_id):
        raise ContractError("opportunity_id has an invalid format")
    lead_id = _require_str(item["lead_id"], "lead_id")
    if not _LEAD_ID_RE.match(lead_id):
        raise ContractError("lead_id has an invalid format")
    cve_id = _require_str(item["cve_id"], "cve_id")
    if not _CVE_RE.match(cve_id):
        raise ContractError("cve_id has an invalid format")
    program = _require_str(item["program"], "program")
    if not _PROGRAM_RE.match(program):
        raise ContractError("program has an invalid format")

    _require_enum(item["opportunity_class"], "opportunity_class",
                  OPPORTUNITY_CLASSES)
    _require_int(item["money_score"], "money_score", lo=0, hi=100)
    priority = _require_str(item["money_priority"], "money_priority")
    if not _PRIORITY_RE.match(priority):
        raise ContractError("money_priority has an invalid format")
    _require_enum(item["confidence"], "confidence", CONFIDENCE_CLASSES)
    _require_enum(item["evidence_quality"], "evidence_quality",
                  EVIDENCE_QUALITIES)
    _require_int(item["estimated_minutes"], "estimated_minutes", lo=0)
    _require_enum(item["current_status"], "current_status",
                  CURRENT_STATUSES)
    _require_enum(item["recommended_action"], "recommended_action",
                  RECOMMENDED_ACTIONS)

    _require_str_list(item["why_now"], "why_now")
    _require_str_list(item["why_valuable"], "why_valuable")
    _require_str_list(item["blockers"], "blockers")
    _require_str(item["next_step"], "next_step")

    research_status = _require_str(item["research_status"], "research_status")
    if not _STATUS_TOKEN_RE.match(research_status):
        raise ContractError("research_status has an invalid format")
    outcome_status = _require_str(item["outcome_status"], "outcome_status")
    if not _STATUS_TOKEN_RE.match(outcome_status):
        raise ContractError("outcome_status has an invalid format")
    session_status = _require_str(item["session_status"], "session_status")
    if not _STATUS_TOKEN_RE.match(session_status):
        raise ContractError("session_status has an invalid format")

    if item["research_only"] is not True:
        raise ContractError("research_only must be true")
    if item["api_version"] != PRODUCT_API_VERSION:
        raise ContractError(
            f"api_version must be {PRODUCT_API_VERSION!r}, "
            f"got {item['api_version']!r}")
    return item


def validate_list_envelope(data: Any) -> dict:
    """Validate the ``GET /api/v1/opportunities`` envelope + its items."""

    body = _require_mapping(data, "response")
    for key in ("api_version", "research_only", "total", "offset", "limit",
                "items"):
        if key not in body:
            raise ContractError(f"missing envelope field: {key}")
    if body["api_version"] != PRODUCT_API_VERSION:
        raise ContractError("api_version must be 'v1'")
    if body["research_only"] is not True:
        raise ContractError("research_only must be true")
    _require_int(body["total"], "total", lo=0)
    _require_int(body["offset"], "offset", lo=0)
    _require_int(body["limit"], "limit", lo=1, hi=100)
    if not isinstance(body["items"], list):
        raise ContractError("items must be a list")
    for item in body["items"]:
        validate_opportunity(item)
    return body


def validate_detail(data: Any) -> dict:
    """Validate the ``GET /api/v1/opportunities/{lead_id}`` response."""

    return validate_opportunity(data)


def validate_summary(data: Any) -> dict:
    """Validate the ``GET /api/v1/opportunities/summary`` response."""

    body = _require_mapping(data, "summary")
    for key in ("api_version", "research_only", "total", "by_class",
                "by_action", "by_status", "top_opportunities"):
        if key not in body:
            raise ContractError(f"missing summary field: {key}")
    if body["api_version"] != PRODUCT_API_VERSION:
        raise ContractError("api_version must be 'v1'")
    if body["research_only"] is not True:
        raise ContractError("research_only must be true")
    _require_int(body["total"], "total", lo=0)
    for key in ("by_class", "by_action", "by_status"):
        _require_mapping(body[key], key)
    if not isinstance(body["top_opportunities"], list):
        raise ContractError("top_opportunities must be a list")
    for item in body["top_opportunities"]:
        validate_opportunity(item)
    return body


def validate_research_status(data: Any) -> dict:
    """Validate the ``GET /api/v1/research/status`` response."""

    body = _require_mapping(data, "status")
    for key in ("api_version", "research_only", "product_api_version",
                "opportunity_count", "ready_count", "blocked_count",
                "in_progress_count", "completed_count",
                "evidence_available", "outcomes_available",
                "sessions_available"):
        if key not in body:
            raise ContractError(f"missing status field: {key}")
    if body["api_version"] != PRODUCT_API_VERSION:
        raise ContractError("api_version must be 'v1'")
    if body["product_api_version"] != PRODUCT_API_VERSION:
        raise ContractError("product_api_version must be 'v1'")
    if body["research_only"] is not True:
        raise ContractError("research_only must be true")
    for key in ("opportunity_count", "ready_count", "blocked_count",
                "in_progress_count", "completed_count"):
        _require_int(body[key], key, lo=0)
    for key in ("evidence_available", "outcomes_available",
                "sessions_available"):
        if not isinstance(body[key], bool):
            raise ContractError(f"{key} must be a boolean")
    return body


def validate_error_envelope(data: Any) -> dict:
    """Validate a v1 error envelope (safe, deterministic)."""

    body = _require_mapping(data, "error response")
    if body.get("api_version") != PRODUCT_API_VERSION:
        raise ContractError("error api_version must be 'v1'")
    if body.get("research_only") is not True:
        raise ContractError("error research_only must be true")
    error = body.get("error")
    if not isinstance(error, dict):
        raise ContractError("error must be an object")
    code = error.get("code")
    if code not in ERROR_CODES:
        raise ContractError(f"unsupported error code: {code!r}")
    _require_str(error.get("message"), "error.message")
    return body

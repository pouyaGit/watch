"""SSRF context analysis schema (Stage R40.2).

An :class:`SSRFContextAnalysisPlan` is the deterministic, descriptive
classification of SSRF-relevant research context. It answers the research
question:

    "Is there possible SSRF-relevant input, and was any server-side fetch
     behavior observed?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/network request, no DNS resolution, no
  localhost/private-IP connection, no port scan, no URL probing, no payload
  execution, no metadata access, no redirect following, no browser, no
  subprocess or socket. Nothing is performed.
- A URL parameter alone is NOT a finding: the model explicitly separates
  ``possible SSRF-relevant input`` from observed ``server-side fetch``
  behavior, and confidence is capped unless a server-side fetch was
  observed.
- Closed vocabularies: every classification field is a closed set; unknown
  and malformed values remain ``UNKNOWN`` and are never promoted.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no DNS, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SSRF_CONTEXT_ANALYSIS_RULE_VERSION = "r40-2"
RULE_VERSION = SSRF_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

INPUT_QUERY = "QUERY"
INPUT_BODY = "BODY"
INPUT_HEADER = "HEADER"
INPUT_COOKIE = "COOKIE"
INPUT_PATH = "PATH"
INPUT_UNKNOWN = "UNKNOWN"

INPUT_LOCATIONS: tuple[str, ...] = (
    INPUT_QUERY,
    INPUT_BODY,
    INPUT_HEADER,
    INPUT_COOKIE,
    INPUT_PATH,
    INPUT_UNKNOWN,
)

URL_FULL = "FULL_URL"
URL_HOST_ONLY = "HOST_ONLY"
URL_PATH_OR_URL = "PATH_OR_URL"
URL_REDIRECT_TARGET = "REDIRECT_TARGET"
URL_WEBHOOK_TARGET = "WEBHOOK_TARGET"
URL_RESOURCE_URL = "RESOURCE_URL"
URL_UNKNOWN = "UNKNOWN"

URL_HANDLING_VALUES: tuple[str, ...] = (
    URL_FULL,
    URL_HOST_ONLY,
    URL_PATH_OR_URL,
    URL_REDIRECT_TARGET,
    URL_WEBHOOK_TARGET,
    URL_RESOURCE_URL,
    URL_UNKNOWN,
)

FETCH_OBSERVED = "OBSERVED"
FETCH_NOT_OBSERVED = "NOT_OBSERVED"
FETCH_UNKNOWN = "UNKNOWN"

SERVER_SIDE_FETCH_STATES: tuple[str, ...] = (
    FETCH_OBSERVED,
    FETCH_NOT_OBSERVED,
    FETCH_UNKNOWN,
)

PROTOCOL_HTTP = "HTTP"
PROTOCOL_HTTPS = "HTTPS"
PROTOCOL_FILE = "FILE"
PROTOCOL_FTP = "FTP"
PROTOCOL_GOPHER = "GOPHER"
PROTOCOL_OTHER = "OTHER"
PROTOCOL_UNKNOWN = "UNKNOWN"

PROTOCOL_CONTEXTS: tuple[str, ...] = (
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_FILE,
    PROTOCOL_FTP,
    PROTOCOL_GOPHER,
    PROTOCOL_OTHER,
    PROTOCOL_UNKNOWN,
)

REDIRECT_FOLLOWED = "FOLLOWED"
REDIRECT_NOT_FOLLOWED = "NOT_FOLLOWED"
REDIRECT_UNKNOWN = "UNKNOWN"

REDIRECT_BEHAVIORS: tuple[str, ...] = (
    REDIRECT_FOLLOWED,
    REDIRECT_NOT_FOLLOWED,
    REDIRECT_UNKNOWN,
)

VALIDATION_PRESENT = "PRESENT"
VALIDATION_ABSENT = "ABSENT"
VALIDATION_UNKNOWN = "UNKNOWN"

VALIDATION_STATES: tuple[str, ...] = (
    VALIDATION_PRESENT,
    VALIDATION_ABSENT,
    VALIDATION_UNKNOWN,
)

ENCODING_NORMALIZED = "NORMALIZED"
ENCODING_ENCODED = "ENCODED"
ENCODING_PARTIAL = "PARTIAL"
ENCODING_UNKNOWN = "UNKNOWN"

ENCODING_BEHAVIORS: tuple[str, ...] = (
    ENCODING_NORMALIZED,
    ENCODING_ENCODED,
    ENCODING_PARTIAL,
    ENCODING_UNKNOWN,
)

MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_ssrf_context_analysis_plan(value: object) -> dict:
    """Project an R40.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "input_location": INPUT_UNKNOWN,
            "url_handling": URL_UNKNOWN,
            "server_side_fetch": FETCH_UNKNOWN,
            "protocol_context": PROTOCOL_UNKNOWN,
            "redirect_behavior": REDIRECT_UNKNOWN,
            "hostname_validation": VALIDATION_UNKNOWN,
            "ip_validation": VALIDATION_UNKNOWN,
            "allowlist_behavior": VALIDATION_UNKNOWN,
            "encoding_behavior": ENCODING_UNKNOWN,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "input_location": _closed(
            value.get("input_location"), INPUT_LOCATIONS, INPUT_UNKNOWN
        ),
        "url_handling": _closed(
            value.get("url_handling"), URL_HANDLING_VALUES, URL_UNKNOWN
        ),
        "server_side_fetch": _closed(
            value.get("server_side_fetch"),
            SERVER_SIDE_FETCH_STATES,
            FETCH_UNKNOWN,
        ),
        "protocol_context": _closed(
            value.get("protocol_context"),
            PROTOCOL_CONTEXTS,
            PROTOCOL_UNKNOWN,
        ),
        "redirect_behavior": _closed(
            value.get("redirect_behavior"),
            REDIRECT_BEHAVIORS,
            REDIRECT_UNKNOWN,
        ),
        "hostname_validation": _closed(
            value.get("hostname_validation"),
            VALIDATION_STATES,
            VALIDATION_UNKNOWN,
        ),
        "ip_validation": _closed(
            value.get("ip_validation"), VALIDATION_STATES,
            VALIDATION_UNKNOWN,
        ),
        "allowlist_behavior": _closed(
            value.get("allowlist_behavior"), VALIDATION_STATES,
            VALIDATION_UNKNOWN,
        ),
        "encoding_behavior": _closed(
            value.get("encoding_behavior"),
            ENCODING_BEHAVIORS,
            ENCODING_UNKNOWN,
        ),
        "context_confidence": _closed(
            value.get("context_confidence"),
            CONFIDENCE_LEVELS,
            "UNKNOWN",
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SSRFContextAnalysisPlan(BaseModel):
    """Deterministic descriptive SSRF context analysis (R40.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SSRF_CONTEXT_ANALYSIS_RULE_VERSION
    input_location: str = INPUT_UNKNOWN
    url_handling: str = URL_UNKNOWN
    server_side_fetch: str = FETCH_UNKNOWN
    protocol_context: str = PROTOCOL_UNKNOWN
    redirect_behavior: str = REDIRECT_UNKNOWN
    hostname_validation: str = VALIDATION_UNKNOWN
    ip_validation: str = VALIDATION_UNKNOWN
    allowlist_behavior: str = VALIDATION_UNKNOWN
    encoding_behavior: str = ENCODING_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SSRF_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("input_location")
    @classmethod
    def _valid_input(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in INPUT_LOCATIONS:
            raise ValueError(f"invalid input_location: {value!r}")
        return text

    @field_validator("url_handling")
    @classmethod
    def _valid_url_handling(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in URL_HANDLING_VALUES:
            raise ValueError(f"invalid url_handling: {value!r}")
        return text

    @field_validator("server_side_fetch")
    @classmethod
    def _valid_fetch(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SERVER_SIDE_FETCH_STATES:
            raise ValueError(f"invalid server_side_fetch: {value!r}")
        return text

    @field_validator("protocol_context")
    @classmethod
    def _valid_protocol(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PROTOCOL_CONTEXTS:
            raise ValueError(f"invalid protocol_context: {value!r}")
        return text

    @field_validator("redirect_behavior")
    @classmethod
    def _valid_redirect(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REDIRECT_BEHAVIORS:
            raise ValueError(f"invalid redirect_behavior: {value!r}")
        return text

    @field_validator(
        "hostname_validation", "ip_validation", "allowlist_behavior"
    )
    @classmethod
    def _valid_validation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in VALIDATION_STATES:
            raise ValueError(f"invalid validation state: {value!r}")
        return text

    @field_validator("encoding_behavior")
    @classmethod
    def _valid_encoding(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ENCODING_BEHAVIORS:
            raise ValueError(f"invalid encoding_behavior: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("ssrf context analyses are research-only")
        return True


def ssrf_context_analysis_plan_projection(
    value: SSRFContextAnalysisPlan,
) -> dict:
    """Serialize an SSRF context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SSRF_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "INPUT_QUERY",
    "INPUT_BODY",
    "INPUT_HEADER",
    "INPUT_COOKIE",
    "INPUT_PATH",
    "INPUT_UNKNOWN",
    "INPUT_LOCATIONS",
    "URL_FULL",
    "URL_HOST_ONLY",
    "URL_PATH_OR_URL",
    "URL_REDIRECT_TARGET",
    "URL_WEBHOOK_TARGET",
    "URL_RESOURCE_URL",
    "URL_UNKNOWN",
    "URL_HANDLING_VALUES",
    "FETCH_OBSERVED",
    "FETCH_NOT_OBSERVED",
    "FETCH_UNKNOWN",
    "SERVER_SIDE_FETCH_STATES",
    "PROTOCOL_HTTP",
    "PROTOCOL_HTTPS",
    "PROTOCOL_FILE",
    "PROTOCOL_FTP",
    "PROTOCOL_GOPHER",
    "PROTOCOL_OTHER",
    "PROTOCOL_UNKNOWN",
    "PROTOCOL_CONTEXTS",
    "REDIRECT_FOLLOWED",
    "REDIRECT_NOT_FOLLOWED",
    "REDIRECT_UNKNOWN",
    "REDIRECT_BEHAVIORS",
    "VALIDATION_PRESENT",
    "VALIDATION_ABSENT",
    "VALIDATION_UNKNOWN",
    "VALIDATION_STATES",
    "ENCODING_NORMALIZED",
    "ENCODING_ENCODED",
    "ENCODING_PARTIAL",
    "ENCODING_UNKNOWN",
    "ENCODING_BEHAVIORS",
    "MAX_VALUE_LEN",
    "sanitize_ssrf_context_analysis_plan",
    "SSRFContextAnalysisPlan",
    "ssrf_context_analysis_plan_projection",
]

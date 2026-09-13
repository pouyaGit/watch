"""Stage R40.2 deterministic SSRF context analyzer (pure engine).

Classifies SSRF-relevant research context from bounded observations:

    "Is there possible SSRF-relevant input, and was any server-side fetch
     behavior observed?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP/network request, no DNS resolution, no
  localhost/private-IP connection, no port scan, no URL probing, no payload
  execution, no metadata access, no redirect following, no browser, no
  socket, no subprocess. Nothing is performed.
- A URL parameter alone is NOT a finding: confidence is capped below HIGH
  and MEDIUM unless a server-side fetch was observed.
- Pure and offline: no I/O, no network, no DNS, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Malformed or missing observations degrade to ``UNKNOWN``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.ssrf_context_analysis import (
    ENCODING_BEHAVIORS,
    ENCODING_UNKNOWN,
    FETCH_OBSERVED,
    FETCH_UNKNOWN,
    INPUT_LOCATIONS,
    INPUT_UNKNOWN,
    PROTOCOL_CONTEXTS,
    PROTOCOL_UNKNOWN,
    REDIRECT_BEHAVIORS,
    REDIRECT_UNKNOWN,
    SERVER_SIDE_FETCH_STATES,
    SSRF_CONTEXT_ANALYSIS_RULE_VERSION,
    SSRFContextAnalysisPlan,
    URL_HANDLING_VALUES,
    URL_UNKNOWN,
    VALIDATION_STATES,
    VALIDATION_UNKNOWN,
    sanitize_ssrf_context_analysis_plan,
    ssrf_context_analysis_plan_projection,
)

SSRF_CONTEXT_ANALYZER_RULE_VERSION = "r40-2"
RULE_VERSION = SSRF_CONTEXT_ANALYZER_RULE_VERSION

KNOWN_FIELDS: tuple[str, ...] = (
    "input_location",
    "url_handling",
    "server_side_fetch",
    "protocol_context",
    "redirect_behavior",
    "hostname_validation",
    "ip_validation",
    "allowlist_behavior",
    "encoding_behavior",
)

UNKNOWN_VALUES: tuple[str, ...] = (
    INPUT_UNKNOWN,
    URL_UNKNOWN,
    FETCH_UNKNOWN,
    PROTOCOL_UNKNOWN,
    REDIRECT_UNKNOWN,
    VALIDATION_UNKNOWN,
    ENCODING_UNKNOWN,
)

_CONFIDENCE_ORDER: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _text(value).upper()
    return text if text in allowed else fallback


def _base_confidence(known_count: int) -> str:
    if known_count >= 8:
        return CONFIDENCE_HIGH
    if known_count >= 5:
        return CONFIDENCE_MEDIUM
    if known_count >= 2:
        return CONFIDENCE_LOW
    return CONFIDENCE_UNKNOWN


def _cap(confidence: str, ceiling: str) -> str:
    if _CONFIDENCE_ORDER[confidence] <= _CONFIDENCE_ORDER[ceiling]:
        return confidence
    return ceiling


def _confidence_for(fetch: str, url: str, known_count: int) -> str:
    confidence = _base_confidence(known_count)
    if fetch != FETCH_OBSERVED:
        confidence = _cap(confidence, CONFIDENCE_LOW)
    if fetch != FETCH_OBSERVED and url == URL_UNKNOWN:
        confidence = _cap(confidence, CONFIDENCE_LOW)
    return confidence


def analyze_ssrf_context(
    input_location: object = None,
    url_handling: object = None,
    server_side_fetch: object = None,
    protocol_context: object = None,
    redirect_behavior: object = None,
    hostname_validation: object = None,
    ip_validation: object = None,
    allowlist_behavior: object = None,
    encoding_behavior: object = None,
) -> dict:
    """Build the deterministic descriptive SSRF context analysis.

    Confidence is a pure function of supplied facts with a hard safety cap:
    unless a server-side fetch was observed, confidence can never exceed
    LOW. A URL parameter by itself is only possible SSRF-relevant input,
    never a confirmed server-side fetch.
    """

    resolved_input = _closed(input_location, INPUT_LOCATIONS, INPUT_UNKNOWN)
    resolved_url = _closed(url_handling, URL_HANDLING_VALUES, URL_UNKNOWN)
    resolved_fetch = _closed(
        server_side_fetch, SERVER_SIDE_FETCH_STATES, FETCH_UNKNOWN
    )
    resolved_protocol = _closed(
        protocol_context, PROTOCOL_CONTEXTS, PROTOCOL_UNKNOWN
    )
    resolved_redirect = _closed(
        redirect_behavior, REDIRECT_BEHAVIORS, REDIRECT_UNKNOWN
    )
    resolved_hostname = _closed(
        hostname_validation, VALIDATION_STATES, VALIDATION_UNKNOWN
    )
    resolved_ip = _closed(
        ip_validation, VALIDATION_STATES, VALIDATION_UNKNOWN
    )
    resolved_allowlist = _closed(
        allowlist_behavior, VALIDATION_STATES, VALIDATION_UNKNOWN
    )
    resolved_encoding = _closed(
        encoding_behavior, ENCODING_BEHAVIORS, ENCODING_UNKNOWN
    )

    values = (
        resolved_input,
        resolved_url,
        resolved_fetch,
        resolved_protocol,
        resolved_redirect,
        resolved_hostname,
        resolved_ip,
        resolved_allowlist,
        resolved_encoding,
    )
    known_count = sum(1 for value in values if value not in UNKNOWN_VALUES)
    confidence = _confidence_for(
        resolved_fetch, resolved_url, known_count
    )

    plan = SSRFContextAnalysisPlan(
        rule_version=SSRF_CONTEXT_ANALYSIS_RULE_VERSION,
        input_location=resolved_input,
        url_handling=resolved_url,
        server_side_fetch=resolved_fetch,
        protocol_context=resolved_protocol,
        redirect_behavior=resolved_redirect,
        hostname_validation=resolved_hostname,
        ip_validation=resolved_ip,
        allowlist_behavior=resolved_allowlist,
        encoding_behavior=resolved_encoding,
        context_confidence=confidence,
        research_only=True,
    )
    return ssrf_context_analysis_plan_projection(plan)


def ssrf_context_confidence_of(value: object) -> str:
    """Recompute the deterministic confidence from bounded observations.

    The stored ``context_confidence`` is ignored and recomputed, so partial
    context dicts supplied directly to the hypothesis or evidence planner
    still receive the correct, safety-capped confidence.
    """

    plan = sanitize_ssrf_context_analysis_plan(value)
    known_count = sum(
        1 for key in KNOWN_FIELDS if plan[key] not in UNKNOWN_VALUES
    )
    return _confidence_for(
        plan["server_side_fetch"], plan["url_handling"], known_count
    )


def server_side_fetch_confirmed(value: object) -> bool:
    """True only when server-side fetch behavior was observed."""

    plan = sanitize_ssrf_context_analysis_plan(value)
    return plan["server_side_fetch"] == FETCH_OBSERVED


def ssrf_input_possible(value: object) -> bool:
    """True when there is possible SSRF-relevant input.

    This is deliberately weaker than :func:`server_side_fetch_confirmed`:
    URL-handling or input-location context indicates a candidate input, not
    a confirmed fetch.
    """

    plan = sanitize_ssrf_context_analysis_plan(value)
    return (
        plan["url_handling"] != URL_UNKNOWN
        or plan["input_location"] != INPUT_UNKNOWN
    )


__all__ = [
    "SSRF_CONTEXT_ANALYZER_RULE_VERSION",
    "RULE_VERSION",
    "KNOWN_FIELDS",
    "UNKNOWN_VALUES",
    "analyze_ssrf_context",
    "ssrf_context_confidence_of",
    "server_side_fetch_confirmed",
    "ssrf_input_possible",
]

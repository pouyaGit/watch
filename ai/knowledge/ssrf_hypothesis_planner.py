"""Stage R40.3 deterministic SSRF hypothesis planner (pure engine).

Creates deterministic research hypotheses from observed SSRF context:

    "Which SSRF review hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no executable payload, no concrete exploitation instructions, no network
  request, no DNS resolution, no metadata access, no redirect following.
- Pure and offline: no I/O, no network, no DNS, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic closed mapping: hypothesis type, signals, confidence,
  priority and limitations are pure functions of the bounded context.
- Possibility is never promoted to confirmation: hypotheses whose key fact
  was not observed stay LOW and explicitly research-only.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.ssrf_context_analyzer import (
    ssrf_context_confidence_of,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.ssrf_context_analysis import (
    ENCODING_ENCODED,
    ENCODING_NORMALIZED,
    ENCODING_PARTIAL,
    FETCH_NOT_OBSERVED,
    FETCH_OBSERVED,
    INPUT_BODY,
    INPUT_COOKIE,
    INPUT_HEADER,
    INPUT_PATH,
    INPUT_QUERY,
    INPUT_UNKNOWN,
    PROTOCOL_FILE,
    PROTOCOL_FTP,
    PROTOCOL_GOPHER,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_OTHER,
    REDIRECT_FOLLOWED,
    REDIRECT_NOT_FOLLOWED,
    URL_REDIRECT_TARGET,
    URL_UNKNOWN,
    URL_WEBHOOK_TARGET,
    VALIDATION_ABSENT,
    VALIDATION_PRESENT,
    sanitize_ssrf_context_analysis_plan,
)
from ai.schemas.ssrf_hypothesis import (
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    SIGNAL_ALLOWLIST_ABSENT,
    SIGNAL_ALLOWLIST_PRESENT,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_ENCODING_ENCODED,
    SIGNAL_ENCODING_NORMALIZED,
    SIGNAL_ENCODING_PARTIAL,
    SIGNAL_HOSTNAME_VALIDATION_ABSENT,
    SIGNAL_HOSTNAME_VALIDATION_PRESENT,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_PATH,
    SIGNAL_INPUT_QUERY,
    SIGNAL_IP_VALIDATION_ABSENT,
    SIGNAL_IP_VALIDATION_PRESENT,
    SIGNAL_PROTOCOL_HTTP,
    SIGNAL_PROTOCOL_NON_HTTP,
    SIGNAL_PROTOCOL_UNKNOWN,
    SIGNAL_REDIRECT_FOLLOWED,
    SIGNAL_REDIRECT_NOT_FOLLOWED,
    SIGNAL_REDIRECT_TARGET,
    SIGNAL_REDIRECT_UNKNOWN,
    SIGNAL_SERVER_FETCH_NOT_OBSERVED,
    SIGNAL_SERVER_FETCH_OBSERVED,
    SIGNAL_SERVER_FETCH_UNKNOWN,
    SIGNAL_URL_HANDLING_OBSERVED,
    SIGNAL_URL_HANDLING_UNKNOWN,
    SIGNAL_WEBHOOK_TARGET,
    SSRF_HYPOTHESIS_RULE_VERSION,
    TYPE_CLOUD_METADATA_BOUNDARY_REVIEW,
    TYPE_DNS_REBINDING_REVIEW,
    TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW,
    TYPE_IP_VALIDATION_REVIEW,
    TYPE_PROTOCOL_HANDLING_REVIEW,
    TYPE_REDIRECT_HANDLING_REVIEW,
    TYPE_SERVER_SIDE_FETCH_ANALYSIS,
    TYPE_UNKNOWN,
    TYPE_URL_VALIDATION_REVIEW,
    TYPE_WEBHOOK_FETCH_REVIEW,
    SSRFHypothesisPlan,
    ssrf_hypothesis_plan_projection,
)

SSRF_HYPOTHESIS_PLANNER_RULE_VERSION = "r40-3"
RULE_VERSION = SSRF_HYPOTHESIS_PLANNER_RULE_VERSION

_INPUT_SIGNALS: dict[str, str] = {
    INPUT_QUERY: SIGNAL_INPUT_QUERY,
    INPUT_BODY: SIGNAL_INPUT_BODY,
    INPUT_HEADER: SIGNAL_INPUT_HEADER,
    INPUT_COOKIE: SIGNAL_INPUT_COOKIE,
    INPUT_PATH: SIGNAL_INPUT_PATH,
}

_FETCH_SIGNALS: dict[str, str] = {
    FETCH_OBSERVED: SIGNAL_SERVER_FETCH_OBSERVED,
    FETCH_NOT_OBSERVED: SIGNAL_SERVER_FETCH_NOT_OBSERVED,
}

_PROTOCOL_SIGNALS: dict[str, str] = {
    PROTOCOL_HTTP: SIGNAL_PROTOCOL_HTTP,
    PROTOCOL_HTTPS: SIGNAL_PROTOCOL_HTTP,
    PROTOCOL_FILE: SIGNAL_PROTOCOL_NON_HTTP,
    PROTOCOL_FTP: SIGNAL_PROTOCOL_NON_HTTP,
    PROTOCOL_GOPHER: SIGNAL_PROTOCOL_NON_HTTP,
    PROTOCOL_OTHER: SIGNAL_PROTOCOL_NON_HTTP,
}

_REDIRECT_SIGNALS: dict[str, str] = {
    REDIRECT_FOLLOWED: SIGNAL_REDIRECT_FOLLOWED,
    REDIRECT_NOT_FOLLOWED: SIGNAL_REDIRECT_NOT_FOLLOWED,
}

_HOSTNAME_SIGNALS: dict[str, str] = {
    VALIDATION_PRESENT: SIGNAL_HOSTNAME_VALIDATION_PRESENT,
    VALIDATION_ABSENT: SIGNAL_HOSTNAME_VALIDATION_ABSENT,
}

_IP_SIGNALS: dict[str, str] = {
    VALIDATION_PRESENT: SIGNAL_IP_VALIDATION_PRESENT,
    VALIDATION_ABSENT: SIGNAL_IP_VALIDATION_ABSENT,
}

_ALLOWLIST_SIGNALS: dict[str, str] = {
    VALIDATION_PRESENT: SIGNAL_ALLOWLIST_PRESENT,
    VALIDATION_ABSENT: SIGNAL_ALLOWLIST_ABSENT,
}

_ENCODING_SIGNALS: dict[str, str] = {
    ENCODING_NORMALIZED: SIGNAL_ENCODING_NORMALIZED,
    ENCODING_ENCODED: SIGNAL_ENCODING_ENCODED,
    ENCODING_PARTIAL: SIGNAL_ENCODING_PARTIAL,
}

_NON_HTTP_PROTOCOLS: tuple[str, ...] = (
    PROTOCOL_FILE,
    PROTOCOL_FTP,
    PROTOCOL_GOPHER,
    PROTOCOL_OTHER,
)


def _signal(mapping: dict, value: object, fallback: str = "") -> str:
    return mapping.get(str(value), fallback)


def _hypothesis(
    hypothesis_type: str,
    confidence: str,
    signals: object,
) -> dict:
    bounded_signals: list[str] = []
    for signal in signals or ():
        if signal and signal not in bounded_signals:
            bounded_signals.append(signal)

    limitations = [
        LIMITATION_NO_EXPLOIT_CLAIM,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
        LIMITATION_HYPOTHESIS_ONLY,
        LIMITATION_EVIDENCE_REQUIRED,
    ]
    if confidence == CONFIDENCE_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)

    plan = SSRFHypothesisPlan(
        rule_version=SSRF_HYPOTHESIS_RULE_VERSION,
        hypothesis_type=hypothesis_type,
        supporting_signals=bounded_signals,
        confidence=confidence,
        priority=confidence,
        limitations=limitations,
        research_only=True,
    )
    return ssrf_hypothesis_plan_projection(plan)


def plan_ssrf_hypotheses(context_analysis: object = None) -> list[dict]:
    """Build the deterministic SSRF research hypotheses (read-only).

    The mapping is conservative and never claims SSRF:

    - an observed server-side fetch yields a HIGH/MEDIUM
      ``SERVER_SIDE_FETCH_ANALYSIS``; a URL parameter without an observed
      fetch yields the same review at LOW only;
    - missing hostname/IP/allowlist validation yields validation review
      hypotheses;
    - redirect targets, non-HTTP protocols, webhook targets, and (only with
      an observed fetch) cloud-boundary review each add their own review;
    - nothing known degrades to ``UNKNOWN``.
    """

    context = sanitize_ssrf_context_analysis_plan(context_analysis)
    input_location = context["input_location"]
    url_handling = context["url_handling"]
    fetch = context["server_side_fetch"]
    protocol = context["protocol_context"]
    redirect = context["redirect_behavior"]
    hostname = context["hostname_validation"]
    ip_validation = context["ip_validation"]
    allowlist = context["allowlist_behavior"]
    encoding = context["encoding_behavior"]
    context_confidence = ssrf_context_confidence_of(context)

    if context_confidence == CONFIDENCE_UNKNOWN:
        return [
            _hypothesis(
                TYPE_UNKNOWN,
                CONFIDENCE_UNKNOWN,
                (SIGNAL_CONTEXT_UNKNOWN,),
            )
        ]

    observed = fetch == FETCH_OBSERVED
    url_known = url_handling != URL_UNKNOWN

    input_signal = _signal(_INPUT_SIGNALS, input_location)
    fetch_signal = _signal(
        _FETCH_SIGNALS, fetch, SIGNAL_SERVER_FETCH_UNKNOWN
    )
    protocol_signal = _signal(
        _PROTOCOL_SIGNALS, protocol, SIGNAL_PROTOCOL_UNKNOWN
    )
    redirect_signal = _signal(
        _REDIRECT_SIGNALS, redirect, SIGNAL_REDIRECT_UNKNOWN
    )
    hostname_signal = _signal(_HOSTNAME_SIGNALS, hostname)
    ip_signal = _signal(_IP_SIGNALS, ip_validation)
    allowlist_signal = _signal(_ALLOWLIST_SIGNALS, allowlist)
    encoding_signal = _signal(_ENCODING_SIGNALS, encoding)
    url_signal = (
        SIGNAL_URL_HANDLING_OBSERVED if url_known
        else SIGNAL_URL_HANDLING_UNKNOWN
    )
    target_signal = ""
    if url_handling == URL_REDIRECT_TARGET:
        target_signal = SIGNAL_REDIRECT_TARGET
    elif url_handling == URL_WEBHOOK_TARGET:
        target_signal = SIGNAL_WEBHOOK_TARGET

    hypotheses: list[dict] = []

    def add(hypothesis_type: str, confidence: str, signals: object) -> None:
        if any(
            item["hypothesis_type"] == hypothesis_type
            for item in hypotheses
        ):
            return
        hypotheses.append(
            _hypothesis(hypothesis_type, confidence, signals)
        )

    # 1. Server-side fetch analysis (possible or observed fetch).
    if observed:
        confidence = (
            CONFIDENCE_HIGH
            if context_confidence == CONFIDENCE_HIGH
            else CONFIDENCE_MEDIUM
        )
        add(
            TYPE_SERVER_SIDE_FETCH_ANALYSIS,
            confidence,
            (fetch_signal, url_signal, protocol_signal, input_signal),
        )
    elif url_known or input_location != INPUT_UNKNOWN:
        add(
            TYPE_SERVER_SIDE_FETCH_ANALYSIS,
            CONFIDENCE_LOW,
            (fetch_signal, url_signal, input_signal, encoding_signal),
        )

    # 2. URL validation review.
    if url_known:
        validation_absent = any(
            value == VALIDATION_ABSENT
            for value in (hostname, ip_validation, allowlist)
        )
        confidence = (
            CONFIDENCE_MEDIUM
            if observed and validation_absent
            else CONFIDENCE_LOW
        )
        add(
            TYPE_URL_VALIDATION_REVIEW,
            confidence,
            (url_signal, hostname_signal, ip_signal, allowlist_signal,
             encoding_signal, target_signal),
        )

    # 3. IP validation review.
    if ip_validation == VALIDATION_ABSENT:
        add(
            TYPE_IP_VALIDATION_REVIEW,
            CONFIDENCE_MEDIUM if observed else CONFIDENCE_LOW,
            (ip_signal, hostname_signal, allowlist_signal),
        )

    # 4. Redirect handling review.
    if url_handling == URL_REDIRECT_TARGET or redirect == REDIRECT_FOLLOWED:
        add(
            TYPE_REDIRECT_HANDLING_REVIEW,
            CONFIDENCE_MEDIUM
            if redirect == REDIRECT_FOLLOWED
            else CONFIDENCE_LOW,
            (redirect_signal, target_signal, url_signal, fetch_signal),
        )

    # 5. Protocol handling review (non-HTTP schemes only).
    if protocol in _NON_HTTP_PROTOCOLS:
        add(
            TYPE_PROTOCOL_HANDLING_REVIEW,
            CONFIDENCE_MEDIUM if observed else CONFIDENCE_LOW,
            (SIGNAL_PROTOCOL_NON_HTTP, protocol_signal, fetch_signal,
             url_signal),
        )

    # 6. DNS rebinding review (hostname check missing, IP check present).
    if (
        hostname == VALIDATION_ABSENT
        and ip_validation == VALIDATION_PRESENT
    ):
        add(
            TYPE_DNS_REBINDING_REVIEW,
            CONFIDENCE_LOW,
            (hostname_signal, ip_signal, url_signal),
        )

    # 7. Internal address restriction review (both checks missing).
    if (
        hostname == VALIDATION_ABSENT
        and ip_validation == VALIDATION_ABSENT
    ):
        add(
            TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW,
            CONFIDENCE_LOW,
            (hostname_signal, ip_signal, allowlist_signal, fetch_signal),
        )

    # 8. Cloud metadata boundary review (observed fetch, no restrictions).
    if (
        observed
        and allowlist == VALIDATION_ABSENT
        and ip_validation == VALIDATION_ABSENT
    ):
        add(
            TYPE_CLOUD_METADATA_BOUNDARY_REVIEW,
            CONFIDENCE_LOW,
            (fetch_signal, allowlist_signal, ip_signal, hostname_signal),
        )

    # 9. Webhook fetch review.
    if url_handling == URL_WEBHOOK_TARGET:
        add(
            TYPE_WEBHOOK_FETCH_REVIEW,
            CONFIDENCE_MEDIUM if observed else CONFIDENCE_LOW,
            (target_signal, fetch_signal, allowlist_signal, input_signal),
        )

    if not hypotheses:
        hypotheses.append(
            _hypothesis(
                TYPE_UNKNOWN,
                CONFIDENCE_UNKNOWN,
                (SIGNAL_CONTEXT_UNKNOWN,),
            )
        )

    return hypotheses


__all__ = [
    "SSRF_HYPOTHESIS_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_ssrf_hypotheses",
]

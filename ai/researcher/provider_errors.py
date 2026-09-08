"""Fail-soft classification for LLM provider errors (research-only).

Temporary provider-side failures (HTTP 402/429/5xx, timeouts, network
errors) are classified as *transient* degradation candidates: the CVE
must be preserved via deterministic fallback instead of dropped.

Programming errors (TypeError, AttributeError, KeyError, ValueError
from response parsing, AssertionError, ImportError, etc.) are NEVER
classified as transient: they fail loudly as ``failed``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Provider outages that must degrade quickly instead of retrying
# indefinitely or dropping the CVE.
TRANSIENT_HTTP_STATUSES = frozenset({402, 429, 500, 502, 503, 504})

# Exception type names that indicate a timeout/network failure even
# when no HTTP status code is available.
TRANSIENT_NETWORK_NAMES = frozenset(
    {
        "APITimeoutError",
        "APIConnectionError",
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "RemoteProtocolError",
        "TimeoutException",
        "TimeoutError",
        "SocketTimeout",
        "TemporaryFailure",
        "ServiceUnavailable",
    }
)

# Exception type names that are always programming errors and must
# never be hidden as degraded provider failures.
PROGRAMMING_ERROR_NAMES = frozenset(
    {
        "TypeError",
        "AttributeError",
        "KeyError",
        "IndexError",
        "AssertionError",
        "ImportError",
        "ModuleNotFoundError",
        "NameError",
        "SyntaxError",
        "StopIteration",
        "RecursionError",
    }
)

_STATUS_RE = re.compile(r"HTTP\s+(\d{3})", re.IGNORECASE)
_STATUS_ATTR_RE = re.compile(r"status(?:_code)?\s*[:=]?\s*(\d{3})", re.IGNORECASE)


@dataclass(frozen=True)
class ProviderFailureInfo:
    """Classification result for one LLM failure."""

    transient: bool
    status_code: int | None
    kind: str
    public_message: str


def _extract_status_code(exc: BaseException) -> int | None:
    """Best-effort status-code extraction (attributes, cause, text)."""
    seen: set[int] = set()
    chain: list[BaseException] = [exc]
    cause = exc.__cause__
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        chain.append(cause)
        cause = cause.__cause__
    context = getattr(exc, "__context__", None)
    if context is not None and context is not exc.__cause__:
        chain.append(context)

    for item in chain:
        for attr in ("status_code", "status", "http_status"):
            value = getattr(item, attr, None)
            if isinstance(value, int) and 100 <= value <= 599:
                return value
        response = getattr(item, "response", None)
        if response is not None:
            for attr in ("status_code", "status"):
                value = getattr(response, attr, None)
                if isinstance(value, int) and 100 <= value <= 599:
                    return value

    for item in chain:
        text = f"{type(item).__name__}: {item}"
        match = _STATUS_RE.search(text)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                pass
        match = _STATUS_ATTR_RE.search(text)
        if match:
            try:
                code = int(match.group(1))
            except ValueError:
                continue
            if 100 <= code <= 599:
                return code
    return None


def _chain_type_names(exc: BaseException) -> list[str]:
    names = [type(exc).__name__]
    cause = exc.__cause__
    seen: set[int] = set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        names.append(type(cause).__name__)
        cause = cause.__cause__
    return names


def _sanitize_message(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    # Never echo long blobs; keep the classification signal only.
    if len(text) > 500:
        text = text[:500] + "…"
    return text.replace("\n", " ").strip()


def classify_provider_failure(exc: BaseException) -> ProviderFailureInfo:
    """Classify an LLM failure as transient (degrade) or not (fail).

    Rules (in order):

    1. Programming-error type names are never transient.
    2. A transient HTTP status (402/429/500/502/503/504) is transient.
    3. Any other explicit HTTP status is NOT transient.
    4. Known timeout/network exception names without a status are
       transient.
    5. Textual timeout/network signals in provider-wrapped messages
       (e.g. OpenRouter "connection error") are transient.
    6. Everything else (ValueError/JSON parse errors, generic
       RuntimeError, programming bugs) is NOT transient.
    """
    names = _chain_type_names(exc)
    for name in names:
        if name in PROGRAMMING_ERROR_NAMES:
            return ProviderFailureInfo(
                transient=False,
                status_code=_extract_status_code(exc),
                kind="programming_error",
                public_message=f"non-transient error ({name}): {_sanitize_message(exc)}",
            )

    status_code = _extract_status_code(exc)
    if status_code is not None:
        if status_code in TRANSIENT_HTTP_STATUSES:
            return ProviderFailureInfo(
                transient=True,
                status_code=status_code,
                kind=f"http_{status_code}",
                public_message=(
                    f"LLM provider transient failure (HTTP {status_code}): "
                    f"{_sanitize_message(exc)}"
                ),
            )
        return ProviderFailureInfo(
            transient=False,
            status_code=status_code,
            kind=f"http_{status_code}",
            public_message=(
                f"LLM provider non-transient failure (HTTP {status_code}): "
                f"{_sanitize_message(exc)}"
            ),
        )

    for name in names:
        if name in TRANSIENT_NETWORK_NAMES:
            return ProviderFailureInfo(
                transient=True,
                status_code=None,
                kind="network_timeout",
                public_message=(
                    f"LLM provider network/timeout failure ({name}): "
                    f"{_sanitize_message(exc)}"
                ),
            )

    lowered = f"{' '.join(names)} {exc}".lower()
    network_signals = (
        "connection error",
        "connectionerror",
        "connect error",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "service unavailable",
        "network error",
        "networkerror",
        "remote protocol",
        "dns",
        "econnreset",
        "econnrefused",
        "broken pipe",
    )
    if any(signal in lowered for signal in network_signals):
        # Guard: a message that merely mentions "timeout" inside a
        # programming bug (e.g. ValueError text) was already handled
        # above only if the type name matched; here the provider
        # wrapper (OpenRouterProviderError "connection error") is the
        # carrier, which is a genuine transport failure.
        wrapper_names = {"OpenRouterProviderError", "LLMProviderError"}
        if any(name in wrapper_names for name in names) or any(
            name in TRANSIENT_NETWORK_NAMES or "timeout" in name.lower()
            or "connect" in name.lower()
            for name in names
        ):
            return ProviderFailureInfo(
                transient=True,
                status_code=None,
                kind="network_timeout",
                public_message=(
                    "LLM provider network/timeout failure: "
                    f"{_sanitize_message(exc)}"
                ),
            )

    return ProviderFailureInfo(
        transient=False,
        status_code=None,
        kind="unexpected",
        public_message=f"non-transient error ({names[0]}): {_sanitize_message(exc)}",
    )


def is_transient_provider_failure(exc: BaseException) -> bool:
    """Return True when ``exc`` is a degrade-instead-of-drop candidate."""
    return classify_provider_failure(exc).transient


# ---------------------------------------------------------------------------
# Aggregate outage telemetry (counts only, no payloads/secrets)
# ---------------------------------------------------------------------------

#: Stable aggregate histogram keys, in serialized order.
OUTAGE_BUCKETS = ("http_402", "http_429", "http_5xx", "network")


def empty_outage_histogram() -> dict[str, int]:
    """Return a zeroed outage histogram (stable schema)."""
    return {bucket: 0 for bucket in OUTAGE_BUCKETS}


def outage_bucket_for_info(info: ProviderFailureInfo) -> str | None:
    """Map one classifier result to a single aggregate outage bucket.

    This is the ONLY mapping from classification to telemetry: there
    is no second classification system. Non-transient results map to
    ``None`` (no outage bucket). Exactly one bucket (or ``None``) is
    returned per failure, so one CVE failure increments exactly one
    counter.
    """
    if not info.transient:
        return None
    if info.status_code == 402:
        return "http_402"
    if info.status_code == 429:
        return "http_429"
    if info.status_code in TRANSIENT_HTTP_STATUSES:
        return "http_5xx"
    if info.kind == "network_timeout":
        return "network"
    if info.status_code is None:
        # Defensive: any other transient failure without a status is
        # a transport-level outage, not an HTTP-classified one.
        return "network"
    return None

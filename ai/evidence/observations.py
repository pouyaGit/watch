"""URL / header / body observation contracts (Phase 5H-core).

Pure, deterministic helpers implementing the architecture's content
policy. These helpers produce OBSERVATION-ONLY values: nothing they
return may be used as a request target, allowlist entry, or replay
input. There is deliberately no ``fetch(redacted_url)``-shaped API in
this module, and none may be added.

Caps (frozen):

- redirect chain: 5 hops (+ overflow flag, never silent truncation)
- headers: 32 per message, 128-char names, 1 KiB values, 8 KiB total
- request body: 16 KiB transport ceiling, <=2 KiB evidence sample
- response: 512 KiB transport read, <=8 KiB evidence sample,
  2 MiB decompressed ceiling, 10x compression-ratio ceiling
- binary content: hash-only (no sample)
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ai.evidence import hashing, scrubber
from ai.schemas import evidence as ev

__all__ = [
    "MAX_REDIRECT_HOPS",
    "MAX_HEADERS",
    "MAX_HEADER_NAME",
    "MAX_HEADER_VALUE",
    "MAX_HEADERS_TOTAL",
    "MAX_REQUEST_BODY",
    "MAX_REQUEST_SAMPLE",
    "MAX_RESPONSE_TRANSPORT",
    "MAX_RESPONSE_SAMPLE",
    "MAX_DECOMPRESSED",
    "MAX_COMPRESSION_RATIO",
    "canonicalize_url",
    "observe_url",
    "observe_redirect_chain",
    "filter_headers",
    "observe_body",
    "REQUEST_HEADER_ALLOWLIST",
    "RESPONSE_HEADER_ALLOWLIST",
]

MAX_REDIRECT_HOPS = 5
MAX_HEADERS = 32
MAX_HEADER_NAME = 128
MAX_HEADER_VALUE = 1024
MAX_HEADERS_TOTAL = 8192
MAX_REQUEST_BODY = 16 * 1024
MAX_REQUEST_SAMPLE = 2 * 1024
MAX_RESPONSE_TRANSPORT = 512 * 1024
MAX_RESPONSE_SAMPLE = 8 * 1024
MAX_DECOMPRESSED = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 10

REQUEST_HEADER_ALLOWLIST = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "content-type",
        "content-length",
        "referer",
        "origin",
        "x-requested-with",
        "if-none-match",
        "if-modified-since",
    }
)

RESPONSE_HEADER_ALLOWLIST = frozenset(
    {
        "content-type",
        "content-length",
        "content-encoding",
        "server",
        "x-powered-by",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "location",
        "strict-transport-security",
        "etag",
        "last-modified",
        "date",
        "status",
    }
)

#: Response vendor-banner names preserved (truncated) for WAF forensics.
RESPONSE_VENDOR_HINTS = (
    "cloudflare",
    "akamai",
    "sucuri",
    "incapsula",
    "imperva",
)

_TEXT_CONTENT_MARKERS = (
    "text/",
    "json",
    "xml",
    "x-www-form-urlencoded",
    "javascript",
)


def _is_sample_eligible_text(content_type: str) -> bool:
    lowered = (content_type or "").casefold()
    return any(marker in lowered for marker in _TEXT_CONTENT_MARKERS)


def canonicalize_url(url: str) -> str:
    """Deterministic canonical URL form (comparison key, NOT persisted).

    Lowercases scheme/host, strips trailing-dot host suffixes and
    userinfo, drops fragments. Query is preserved byte-exact (it is
    transport content, hashed/masked — never normalized away).
    Raises ``EvidenceError(EVIDENCE_MALFORMED)`` on unparseable or
    non-http(s) input (fail closed).
    """
    if not isinstance(url, str) or not url.strip():
        raise ev.EvidenceError("EVIDENCE_MALFORMED", "empty url")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ev.EvidenceError("EVIDENCE_MALFORMED", "unsupported url scheme")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ev.EvidenceError("EVIDENCE_MALFORMED", "url has no host")
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    canonical = f"{scheme}://{netloc}{path}"
    if parts.query:
        canonical += f"?{parts.query}"
    return canonical


def observe_url(url: str) -> ev.RedactedUrl:
    """Observation-only URL record: redacted form + hashes.

    Persists the redacted canonical URL (capped), the SHA-256 of the
    full canonical form, and the SHA-256 of the redacted query. Raw
    secret query values and userinfo never persist.
    """
    canonical = canonicalize_url(url)
    redacted = scrubber.redact_url(canonical)
    if len(redacted) > 2048:
        redacted = redacted[:2048]
    query = urlsplit(canonical).query
    return ev.RedactedUrl(
        redacted_url=redacted,
        canonical_hash=hashing.hash_text(canonical),
        redacted_query_hash=(
            hashing.hash_text(urlsplit(redacted).query) if query else None
        ),
    )


def observe_redirect_chain(urls: list[str]) -> tuple[list[ev.RedactedUrl], bool]:
    """Bounded redirect-chain observation (5 hops + overflow flag)."""
    if not isinstance(urls, list):
        raise TypeError(
            "observe_redirect_chain accepts only a list, "
            f"not {type(urls).__name__}"
        )
    observed = [observe_url(url) for url in urls[:MAX_REDIRECT_HOPS + 1]]
    if len(urls) > MAX_REDIRECT_HOPS + 1:
        return observed[: MAX_REDIRECT_HOPS + 1], True
    truncated = len(urls) > MAX_REDIRECT_HOPS
    return observed[:MAX_REDIRECT_HOPS] if truncated else observed, truncated


def filter_headers(
    headers: dict[str, str],
    *,
    allowlist: frozenset[str],
) -> ev.HeaderSnapshot:
    """Allowlist + redact + bound a header mapping.

    Unknown headers are dropped (their count is folded into the
    ``truncated`` flag when anything was dropped). Secret-shaped
    values are redacted. Names/values/total are capped.
    """
    if not isinstance(headers, dict):
        raise TypeError(
            "filter_headers accepts only a mapping, "
            f"not {type(headers).__name__}"
        )
    kept: dict[str, str] = {}
    total = 0
    truncated = False
    lowered_allowlist = {entry.casefold() for entry in allowlist}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("header names and values must be strings")
        lowered = name.strip().casefold()
        vendor = any(hint in lowered for hint in RESPONSE_VENDOR_HINTS)
        if lowered not in lowered_allowlist and not vendor:
            truncated = True
            continue
        if len(kept) >= MAX_HEADERS:
            truncated = True
            continue
        capped_name = name.strip()[:MAX_HEADER_NAME]
        capped_value = value[:MAX_HEADER_VALUE]
        if len(capped_name) != len(name.strip()) or len(capped_value) != len(
            value
        ):
            truncated = True
        if total + len(capped_name) + len(capped_value) > MAX_HEADERS_TOTAL:
            truncated = True
            break
        kept[capped_name] = capped_value
        total += len(capped_name) + len(capped_value)
    redacted = scrubber.scrub_headers(kept)
    return ev.HeaderSnapshot(headers=redacted, truncated=truncated)


def observe_body(
    body: bytes,
    *,
    content_type: str = "",
    sample_budget: int = MAX_RESPONSE_SAMPLE,
) -> tuple[str, str | None, str | None]:
    """Hash-always/sample-sometimes body observation.

    Returns ``(body_hash, sample_or_None, omitted_reason_or_None)``.
    Binary content is hash-only. Samples are newline-normalized text
    capped at ``sample_budget``; anything beyond the budget sets an
    explicit omission reason (never silent truncation).
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(
            "observe_body accepts only bytes, "
            f"not {type(body).__name__}"
        )
    raw = bytes(body)
    body_hash = hashing.sha256_hex(raw)
    if not _is_sample_eligible_text(content_type):
        return body_hash, None, "binary-content-type"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return body_hash, None, "undecodable-bytes"
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized.encode("utf-8")) <= sample_budget:
        return body_hash, normalized, None
    capped = normalized.encode("utf-8")[:sample_budget].decode(
        "utf-8", errors="ignore"
    )
    return body_hash, capped, "over-sample-budget"

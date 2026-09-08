"""One shared evidence redaction module (Phase 5H-core).

The single scrubber used by HTTP, Nuclei, browser, audit, and error
paths. No per-executor variants exist: a secret shape redacted on one
path is redacted on all paths.

Policy (frozen):

- Secret-shaped header VALUES are replaced with ``[REDACTED]`` (the
  header name is preserved for forensic correlation).
- Secret-shaped query/form VALUES are replaced with ``[REDACTED]``
  (parameter names preserved).
- URL userinfo is stripped entirely.
- High-confidence operational secret VALUES in free text (connection
  URIs, private-key blocks, bearer/basic credentials, known API-key
  shapes) are replaced with ``[REDACTED]``.
- Raw exception strings never enter evidence: :func:`sanitized_reason`
  maps failures to closed codes with a bounded, secret-screened suffix.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

__all__ = [
    "REDACTED",
    "ERROR_REASON_LIMIT",
    "scrub_headers",
    "scrub_query",
    "scrub_text",
    "strip_userinfo",
    "redact_url",
    "sanitized_reason",
    "contains_secret_shape",
]

REDACTED = "[REDACTED]"

ERROR_REASON_LIMIT = 200

#: Header names whose VALUES never persist (case-insensitive exact).
_SECRET_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "proxy-authenticate",
        "www-authenticate",
        "x-api-key",
        "api-key",
    }
)

#: Header-name substrings marking a secret-shaped custom header.
_SECRET_HEADER_SUBSTRINGS = ("token", "secret", "apikey", "api_key",
                             "session", "auth")


def _is_secret_header(name: str) -> bool:
    lowered = (name or "").strip().casefold()
    if lowered in _SECRET_HEADER_NAMES:
        return True
    compact = lowered.replace("-", "").replace("_", "")
    return any(
        marker.replace("_", "") in compact
        for marker in _SECRET_HEADER_SUBSTRINGS
    )


#: Query/form parameter-name substrings marking a secret-shaped value.
_SECRET_PARAM_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    "auth",
    "bearer",
    "private_key",
    "connection",
    "mongo",
)


def _is_secret_param(name: str) -> bool:
    lowered = (name or "").casefold()
    return any(marker in lowered for marker in _SECRET_PARAM_SUBSTRINGS)


#: High-confidence operational-secret shapes in free text. Each is a
#: (pattern, replacement-count) pair applied with ``re.sub``.
_SECRET_TEXT_PATTERNS = (
    re.compile(r"(?i)\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"<>]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]+"),
    re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bxox[bpas]-[A-Za-z0-9\-]+"),
    re.compile(r"\bsk-(?:live|test)-[A-Za-z0-9]+\b"),
    # H1 fix: additional patterns for Nuclei observation output
    re.compile(r"(?i)\bcookie\s*:\s*[^\s;]+"),
    re.compile(r"(?i)\bset-cookie\s*:\s*[^\s;]+"),
    re.compile(r"(?i)\bx-api-key\s*:\s*\S+"),
    re.compile(r"(?i)\bapi[_-]?key\s*[=:]\s*\S+"),
    re.compile(r"(?i)\b(?:session|token|secret|password|passwd)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\b(?:auth|access|refresh)[_-]?(?:token|key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bsession[_-]?(?:id|key|token)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\b(?:db_)?(?:password|passwd|secret)\s*(?:[=:]\s*|\s+)\S+"),
    re.compile(r"(?i)\bauthorization\s*:\s*\S+"),
)

#: Markers that prove a detail string carries secret material and must
#: be refused (not merely redacted) at error boundaries.
_REFUSE_MARKERS = (
    "mongodb://",
    "postgres://",
    "mysql://",
    "redis://",
    "amqp://",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "private_key",
    "-----begin",
)


def contains_secret_shape(text: str) -> bool:
    """True when ``text`` carries a high-confidence secret shape."""
    if not isinstance(text, str) or not text:
        return False
    if any(pattern.search(text) for pattern in _SECRET_TEXT_PATTERNS):
        return True
    lowered = text.casefold()
    return any(marker in lowered for marker in _REFUSE_MARKERS)


def scrub_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact secret-shaped header values (names preserved)."""
    if not isinstance(headers, dict):
        raise TypeError(
            "scrub_headers accepts only a mapping, "
            f"not {type(headers).__name__}"
        )
    scrubbed: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("header names and values must be strings")
        if _is_secret_header(name) or contains_secret_shape(value):
            scrubbed[name] = REDACTED
        else:
            scrubbed[name] = value
    return scrubbed


def scrub_query(query: str) -> str:
    """Redact secret-shaped query values (names preserved, order kept)."""
    if not isinstance(query, str):
        raise TypeError(
            f"scrub_query accepts only str, not {type(query).__name__}"
        )
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    scrubbed = [
        (name, REDACTED if _is_secret_param(name) else value)
        for name, value in pairs
    ]
    return urlencode(scrubbed)


def scrub_text(text: str) -> str:
    """Replace operational-secret shapes in free text with ``[REDACTED]``."""
    if not isinstance(text, str):
        raise TypeError(
            f"scrub_text accepts only str, not {type(text).__name__}"
        )
    scrubbed = text
    for pattern in _SECRET_TEXT_PATTERNS:
        scrubbed = pattern.sub(REDACTED, scrubbed)
    return scrubbed


def strip_userinfo(url: str) -> str:
    """Remove ``user[:pass]@`` authority from a URL (fail closed)."""
    if not isinstance(url, str):
        raise TypeError(
            f"strip_userinfo accepts only str, not {type(url).__name__}"
        )
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def redact_url(url: str) -> str:
    """Observation-only URL form: no userinfo, no fragment, secrets out."""
    if not isinstance(url, str):
        raise TypeError(
            f"redact_url accepts only str, not {type(url).__name__}"
        )
    no_userinfo = strip_userinfo(url)
    parts = urlsplit(no_userinfo)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         scrub_query(parts.query), "")
    )


#: Closed error-code vocabulary for evidence/audit reason strings.
ERROR_CODES = frozenset(
    {
        "transport_timeout",
        "connection_error",
        "process_timeout",
        "process_killed",
        "process_died",
        "limit_exceeded",
        "redirect_limit",
        "redirect_cycle",
        "scope_deny",
        "binding_mismatch",
        "hash_mismatch",
        "incomplete_observations",
        "audit_gap",
        "orphan_reindexed",
        "unknown_outcome",
    }
)


def sanitized_reason(code: str, hint: str = "") -> str:
    """Closed-code error reason (``code`` + bounded screened suffix).

    Raw exception strings must never reach this function: callers pass
    the classified code. ``hint`` carries only caller-chosen safe
    context (never exception text); secret-shaped hints raise instead
    of leaking.
    """
    if code not in ERROR_CODES:
        raise ValueError(f"unknown evidence error code: {code!r}")
    safe_hint = (hint or "")[: ERROR_REASON_LIMIT - len(code) - 2]
    if "\n" in safe_hint or "\r" in safe_hint:
        raise ValueError("error hint must be single-line")
    if contains_secret_shape(safe_hint):
        raise ValueError(
            "error hint carries suspected secret material"
        )
    reason = code if not safe_hint else f"{code}:{safe_hint}"
    return reason[:ERROR_REASON_LIMIT]

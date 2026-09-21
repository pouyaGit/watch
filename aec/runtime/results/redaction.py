"""EPIC7 Part 9: deterministic redaction policy.

Applied before persistence and logging. Header names that are
authorization, credentials, cookies, tokens, or API keys are dropped
entirely; values in remaining headers are scrubbed by deterministic
content rules. Bodies are never retained — only a digest and a size.
The policy is explicit and does not claim perfect secret detection.
"""

from __future__ import annotations

import hashlib
import re

RULE_VERSION = "aec-runtime-redaction/v1"

#: Header names never retained, whatever their value.
REDACTED_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-amz-security-token",
    "x-ms-version", "session", "sessionid", "token", "access-token",
})

#: Content patterns: credential-shaped values scrubbed in place.
_SECRET_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"token[=:\s]+[A-Za-z0-9._-]{8,}", re.IGNORECASE),
    re.compile(r"password[=:\s]+[^\s,;]+", re.IGNORECASE),
    re.compile(r"api[_-]?key[=:\s]+[A-Za-z0-9._-]{8,}", re.IGNORECASE),
    re.compile(r"session[=:\s]+[A-Za-z0-9._-]{8,}", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}", re.IGNORECASE),  # JWT-ish
)

#: Header names permits the BODY of a response style to survive redaction.
_ALLOWED_VALUE_HEADERS = frozenset({
    "host", "content-type", "content-length", "server", "x-powered-by",
    "x-frame-options", "x-content-type-options", "cache-control",
    "pragma", "expires", "etag", "last-modified", "accept-ranges",
    "vary", "location",
})


def _scrub_value(value: str) -> str:
    scrubbed = value
    for pattern in _SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop secret headers; scrub remaining values deterministically."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.strip().lower() if isinstance(name, str) else ""
        if lowered in REDACTED_HEADER_NAMES:
            continue
        if not isinstance(value, str):
            continue
        if lowered in _ALLOWED_VALUE_HEADERS:
            out[lowered] = _scrub_value(value)
        else:
            out[lowered] = _scrub_value(value)
    return dict(sorted(out.items()))


def project_body(body: bytes) -> tuple[str, int]:
    """Never retain response bodies — only a digest and a byte size."""
    if not isinstance(body, bytes):
        body = b""
    digest = hashlib.sha256(body).hexdigest()
    return "sha256:" + digest, len(body)


def redact_trace(message: str) -> str:
    """Scrub credential-shaped content from failure/log text."""
    if not isinstance(message, str):
        return ""
    return _scrub_value(message)


def redact_log(line: str) -> str:
    return redact_trace(line)


__all__ = [
    "REDACTED_HEADER_NAMES", "RULE_VERSION", "project_body", "redact_headers",
    "redact_log", "redact_trace",
]
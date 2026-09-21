"""aec/redaction.py — AEC-1 T2 (S5): metadata allowlist + secret/PII scrubbing.

The projector in T7 tags evidence; nothing may reach a case artifact before the
redaction rules exist, so this module comes first (execution plan §1.2, S5).

Design constraints (execution plan §2.2):

- **stdlib only** — `re` + `hashlib`. It must not import `ai.*`, `backend.*`, any
  transport, or anything that can open a socket or a file. The allowlists are
  *mirrored* from the frozen evidence module rather than imported, and a test
  pins the mirror against `ai.evidence.observations` so the two cannot drift.
- **Deterministic** — sorted records, no timestamps, digests instead of values.
- **Fail-closed** — an unknown header/metadata key is dropped, never passed
  through; a credential-shaped value is never retained, whatever its key.
- **Never verdicts** — this module scrubs and records; it never classifies.

Two rules run over every value, in this order:

1. **Structural**: identity/credential keys are removed entirely
   (`NEVER_RETAINED_KEYS`), non-allowlisted names are dropped.
2. **Content**: secret pairs, bearer tokens, userinfo, connection-URI
   credentials, private-key material, emails, JWTs and long high-entropy tokens
   are replaced in place.

Retained values are length-capped; request/response *bodies* are never retained
at all — only `sha256` plus byte length (`project_body`).

Every removal or replacement is recorded as
``{"field", "action", "reason"}`` with a closed vocabulary, so a reviewer can see
exactly what was withheld and why.
"""

from __future__ import annotations

import hashlib
import re

RULE_VERSION = "aec-redaction/v1"

#: Mirrors ``ai.evidence.observations.REQUEST_HEADER_ALLOWLIST`` (pinned by test).
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

#: Mirrors ``ai.evidence.observations.RESPONSE_HEADER_ALLOWLIST`` (pinned by test).
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

#: Identity/credential surfaces: never retained, under any spelling.
NEVER_RETAINED_KEYS = frozenset(
    {
        "authentication-info",
        "authorization",
        "cookie",
        "proxy-authenticate",
        "proxy-authorization",
        "set-cookie",
        "set-cookie2",
        "www-authenticate",
        "ww-authenticate",
        "x-amz-security-token",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-session-id",
        "x-xsrf-token",
    }
)

#: Substrings that make an arbitrary field name sensitive.
SENSITIVE_NAME_MARKERS = (
    "apikey",
    "api-key",
    "api_key",
    "auth",
    "cookie",
    "credential",
    "csrf",
    "jwt",
    "nonce",
    "passwd",
    "password",
    "private",
    "secret",
    "session",
    "signature",
    "token",
    "xsrf",
)

#: Query parameters whose value is digested instead of retained.
SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "assertion",
        "auth",
        "code",
        "credential",
        "id_token",
        "jwt",
        "key",
        "nonce",
        "password",
        "refresh_token",
        "samlresponse",
        "session",
        "sessionid",
        "sid",
        "sig",
        "signature",
        "state",
        "ticket",
        "token",
    }
)

#: Metadata keys the artifact projector may retain (everything else is dropped).
ALLOWED_METADATA_KEYS = frozenset(
    {
        "content_encoding",
        "content_length",
        "content_sha256",
        "content_type",
        "elapsed_ms",
        "method",
        "observation_role",
        "pair_id",
        "parameter_name",
        "request_body_sha256",
        "response_body_sha256",
        "redirect_count",
        "scheme",
        "server",
        "status",
        "status_code",
        "varying_variable",
        "x_powered_by",
    }
)

#: Mirrors ``ai.schemas.shared_research_context.MAX_VALUE_LEN`` (pinned by test).
MAX_RETAINED_VALUE_LEN = 160

#: Hard cap on retained headers per snapshot.
MAX_HEADER_COUNT = 24

ACTIONS = ("KEPT", "DROPPED", "REDACTED", "DIGESTED", "TRUNCATED")

REASONS = (
    "BEARER_TOKEN",
    "BODY_NOT_RETAINED",
    "CONNECTION_URI",
    "CONTROL_CHARS",
    "EMAIL",
    "FRAGMENT",
    "HEADER_LIMIT",
    "JWT",
    "LONG_TOKEN",
    "NON_SCALAR",
    "NOT_ALLOWLISTED",
    "PRIVATE_KEY",
    "SECRET_PAIR",
    "SENSITIVE_HEADER",
    "SENSITIVE_NAME",
    "TOO_LONG",
    "UNKNOWN_METADATA_KEY",
    "USERINFO",
    "VALUE_TOKEN",
)

KIND_REQUEST = "request"
KIND_RESPONSE = "response"
_KINDS = {
    KIND_REQUEST: REQUEST_HEADER_ALLOWLIST,
    KIND_RESPONSE: RESPONSE_HEADER_ALLOWLIST,
}

REDACTION_LABEL = "[redacted:{reason}]"

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WHITESPACE_RE = re.compile(r"\s+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PRIVATE_KEY_RE = re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}")
_CONNECTION_URI_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{40,}\b")
_HASH_LIKE_RE = re.compile(r"^[0-9a-fA-F]{64}$")
#: ``key=value`` / ``key: value`` pairs whose value looks like a credential even
#: though the key itself is innocuous (``note=s3cr3t-value-...``).
_TOKEN_VALUE_RE = re.compile(
    r"(?i)\b([A-Za-z][A-Za-z0-9_.\-]{0,40})\s*[:=]\s*([A-Za-z0-9._\-]{12,})"
)

_FIELD_ORDER_KEY = staticmethod(lambda record: (record["field"], record["action"], record["reason"]))


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def digest(value: object) -> str:
    """Stable sha256 hex of a value (used instead of retaining it)."""
    if isinstance(value, bytes):
        payload = value
    else:
        payload = str(value if value is not None else "").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def short_digest(value: object) -> str:
    """First 16 hex characters of :func:`digest` (safe to embed in a URL copy)."""
    return digest(value)[:16]


def canonical_name(name: object) -> str:
    """Canonical header/query name: lower-case, ``_`` -> ``-``."""
    text = str(name if name is not None else "")
    text = text.strip().lower().replace("_", "-")
    text = _WHITESPACE_RE.sub("", text)
    return text


def canonical_key(name: object) -> str:
    """Canonical *metadata* key: lower-case, underscores kept (``status_code``)."""
    text = str(name if name is not None else "")
    text = text.strip().lower()
    return _WHITESPACE_RE.sub("", text)


def is_sensitive_name(name: object) -> bool:
    """True when a field name is (or contains) a credential-shaped marker."""
    canonical = canonical_name(name)
    if not canonical:
        return False
    if canonical in NEVER_RETAINED_KEYS:
        return True
    variants = (canonical, canonical.replace("-", "_"))
    return any(marker in variant for variant in variants for marker in SENSITIVE_NAME_MARKERS)


def is_allowlisted_header(name: object, kind: str = KIND_RESPONSE) -> bool:
    allowlist = _allowlist_for(kind)
    canonical = canonical_name(name)
    if not canonical or is_sensitive_name(canonical):
        return False
    return canonical in allowlist


def is_allowed_metadata_key(key: object) -> bool:
    canonical = canonical_key(key)
    if not canonical or is_sensitive_name(canonical):
        return False
    return canonical in ALLOWED_METADATA_KEYS


def _allowlist_for(kind: str) -> frozenset:
    if kind not in _KINDS:
        raise ValueError(f"unknown header kind: {kind!r} (expected request|response)")
    return _KINDS[kind]


def _record(field: str, action: str, reason: str) -> dict:
    if action not in ACTIONS:
        raise ValueError(f"unknown redaction action: {action!r}")
    if reason not in REASONS:
        raise ValueError(f"unknown redaction reason: {reason!r}")
    return {"field": field, "action": action, "reason": reason}


def _sorted_records(records) -> list:
    return sorted(records, key=lambda record: (record["field"], record["action"], record["reason"]))


def redaction_summary(records) -> dict:
    """Deterministic counts by action and reason."""
    by_action: dict = {}
    by_reason: dict = {}
    total = 0
    for record in records or ():
        total += 1
        action = str(record.get("action", ""))
        reason = str(record.get("reason", ""))
        by_action[action] = by_action.get(action, 0) + 1
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {
        "total": total,
        "by_action": {key: by_action[key] for key in sorted(by_action)},
        "by_reason": {key: by_reason[key] for key in sorted(by_reason)},
    }


# --------------------------------------------------------------------------
# Content scrubbing
# --------------------------------------------------------------------------


def scrub_text(text: object, field: str = "text", detect_long_tokens: bool = True):
    """Replace secret/PII-shaped content in text. Returns ``(safe_text, records)``."""
    raw = str(text if text is not None else "")
    if isinstance(text, bytes):
        raw = text.decode("utf-8", "replace")
    records: list = []
    safe = raw

    if _CONTROL_RE.search(safe):
        safe = _CONTROL_RE.sub(" ", safe)
        records.append(_record(field, "REDACTED", "CONTROL_CHARS"))

    def _replace(pattern, reason):
        nonlocal safe
        if pattern.search(safe):
            safe = pattern.sub(REDACTION_LABEL.format(reason=reason), safe)
            records.append(_record(field, "REDACTED", reason))

    if _PRIVATE_KEY_RE.search(safe):
        safe = _PRIVATE_KEY_RE.sub(REDACTION_LABEL.format(reason="PRIVATE_KEY"), safe)
        records.append(_record(field, "REDACTED", "PRIVATE_KEY"))
    if _CONNECTION_URI_RE.search(safe):
        safe = _CONNECTION_URI_RE.sub("://[redacted:CONNECTION_URI]@", safe)
        records.append(_record(field, "REDACTED", "CONNECTION_URI"))
    if _BEARER_RE.search(safe):
        safe = _BEARER_RE.sub(REDACTION_LABEL.format(reason="BEARER_TOKEN"), safe)
        records.append(_record(field, "REDACTED", "BEARER_TOKEN"))
    if _USERINFO_RE.search(safe):
        safe = _USERINFO_RE.sub("://[redacted:USERINFO]@", safe)
        records.append(_record(field, "REDACTED", "USERINFO"))
    if _SECRET_PAIR_RE.search(safe):
        safe = _SECRET_PAIR_RE.sub(
            lambda match: f"{match.group(1)}={REDACTION_LABEL.format(reason='SECRET_PAIR')}", safe
        )
        records.append(_record(field, "REDACTED", "SECRET_PAIR"))
    if _TOKEN_VALUE_RE.search(safe):
        def _scrub_token_pair(match):
            value = match.group(2)
            if (
                re.search(r"[A-Za-z]", value)
                and re.search(r"\d", value)
                and re.search(r"[._\-]", value)
            ):
                return f"{match.group(1)}={REDACTION_LABEL.format(reason='VALUE_TOKEN')}"
            return match.group(0)

        candidate = _TOKEN_VALUE_RE.sub(_scrub_token_pair, safe)
        if candidate != safe:
            safe = candidate
            records.append(_record(field, "REDACTED", "VALUE_TOKEN"))
    if _JWT_RE.search(safe):
        safe = _JWT_RE.sub(REDACTION_LABEL.format(reason="JWT"), safe)
        records.append(_record(field, "REDACTED", "JWT"))
    if detect_long_tokens and _LONG_TOKEN_RE.search(safe):
        safe = _LONG_TOKEN_RE.sub(REDACTION_LABEL.format(reason="LONG_TOKEN"), safe)
        records.append(_record(field, "REDACTED", "LONG_TOKEN"))
    if _EMAIL_RE.search(safe):
        safe = _EMAIL_RE.sub(REDACTION_LABEL.format(reason="EMAIL"), safe)
        records.append(_record(field, "REDACTED", "EMAIL"))

    if len(safe) > MAX_RETAINED_VALUE_LEN:
        safe = safe[:MAX_RETAINED_VALUE_LEN]
        records.append(_record(field, "TRUNCATED", "TOO_LONG"))

    return safe, _sorted_records(records)


# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------


def redact_headers(headers: object, kind: str = KIND_RESPONSE):
    """Allowlist + scrub a header mapping. Returns ``(safe_headers, records)``."""
    allowlist = _allowlist_for(kind)
    safe: dict = {}
    records: list = []
    if headers is None:
        return safe, records
    if not isinstance(headers, dict):
        raise ValueError("headers must be a mapping")

    for name in sorted(headers, key=lambda item: canonical_name(item)):
        canonical = canonical_name(name)
        value = headers[name]
        if not canonical:
            continue
        if canonical in NEVER_RETAINED_KEYS or is_sensitive_name(canonical):
            records.append(_record(canonical, "DROPPED", "SENSITIVE_HEADER"))
            continue
        if canonical not in allowlist:
            records.append(_record(canonical, "DROPPED", "NOT_ALLOWLISTED"))
            continue
        if len(safe) >= MAX_HEADER_COUNT:
            records.append(_record(canonical, "DROPPED", "HEADER_LIMIT"))
            continue
        if value is None:
            safe[canonical] = ""
            continue
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        elif not isinstance(value, (str, int, float, bool)):
            records.append(_record(canonical, "DIGESTED", "NON_SCALAR"))
            safe[canonical] = short_digest(value)
            continue
        text = str(value)
        scrubbed, scrub_records = scrub_text(text, field=canonical)
        for record in scrub_records:
            record["field"] = canonical
        records.extend(scrub_records)
        safe[canonical] = scrubbed
    return safe, _sorted_records(records)


# --------------------------------------------------------------------------
# URLs
# --------------------------------------------------------------------------


def _scrub_query_pair(pair: str):
    records: list = []
    key, sep, value = pair.partition("=")
    if not sep:
        return pair, records
    canonical = canonical_key(key).replace("-", "_")
    if canonical in SENSITIVE_QUERY_KEYS or is_sensitive_name(key):
        return f"{key}={short_digest(value)}", [
            _record(f"query.{canonical}", "DIGESTED", "SENSITIVE_NAME")
        ]
    scrubbed, scrub_records = scrub_text(value, field=f"query.{canonical}")
    if scrubbed != value:
        return f"{key}={scrubbed}", scrub_records
    return pair, records


def redact_url(url: object):
    """Redact a URL: strip userinfo, digest sensitive query values, drop fragment."""
    text = str(url if url is not None else "").strip()
    records: list = []
    if not text:
        return "", records
    scheme, sep, rest = text.partition("://")
    if not sep:
        return text, records

    authority, slash, remainder = rest.partition("/")
    if "@" in authority:
        _, _, authority = authority.rpartition("@")
        records.append(_record("url.userinfo", "DROPPED", "USERINFO"))

    path, hash_sep, fragment = remainder.partition("#")
    if hash_sep:
        reason = "SENSITIVE_NAME" if any(
            is_sensitive_name(part.partition("=")[0])
            for part in fragment.replace("/", "&").replace("?", "&").split("&")
            if part
        ) else "FRAGMENT"
        records.append(_record("url.fragment", "DROPPED", reason))

    path_only, query_sep, query = path.partition("?")
    new_query = query
    if query_sep and query:
        parts = []
        for pair in query.split("&"):
            scrubbed_pair, pair_records = _scrub_query_pair(pair)
            parts.append(scrubbed_pair)
            records.extend(pair_records)
        new_query = "&".join(parts)

    rebuilt = f"{scheme}://{authority}"
    if slash:
        rebuilt += f"/{path_only}"
    if query_sep and new_query:
        rebuilt += f"?{new_query}"
    return rebuilt, _sorted_records(records)


# --------------------------------------------------------------------------
# Bodies
# --------------------------------------------------------------------------


def project_body(body: object, field: str = "body") -> dict:
    """Never retain a body: return digest + length only."""
    if body is None:
        length = 0
        checksum = None
    elif isinstance(body, bytes):
        length = len(body)
        checksum = hashlib.sha256(body).hexdigest()
    elif isinstance(body, str):
        encoded = body.encode("utf-8")
        length = len(encoded)
        checksum = hashlib.sha256(encoded).hexdigest()
    else:
        encoded = str(body).encode("utf-8")
        length = len(encoded)
        checksum = hashlib.sha256(encoded).hexdigest()
    return {
        "field": field,
        "retained": False,
        "sha256": checksum,
        "length": length,
        "sample": None,
        "sample_omitted": "BODY_NOT_RETAINED",
        "records": [_record(field, "DROPPED", "BODY_NOT_RETAINED")],
    }


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------


def _project_metadata_value(key: str, value: object):
    records: list = []
    if value is None:
        return None, records
    if isinstance(value, bool):
        return value, records
    if isinstance(value, (int, float)):
        return value, records
    if isinstance(value, str) and _HASH_LIKE_RE.match(value):
        # A digest is already non-secret: keep it verbatim, do not shorten it.
        return value, records
    if isinstance(value, bytes):
        records.append(_record(key, "DIGESTED", "NON_SCALAR"))
        return short_digest(value), records
    if not isinstance(value, str):
        records.append(_record(key, "DIGESTED", "NON_SCALAR"))
        return short_digest(repr(value)), records
    scrubbed, scrub_records = scrub_text(value, field=key)
    for record in scrub_records:
        record["field"] = key
    return scrubbed, scrub_records


def project_metadata(raw: object) -> dict:
    """Allowlist + scrub a metadata mapping. Unknown keys are dropped."""
    metadata: dict = {}
    records: list = []
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("metadata must be a mapping")

    for key in sorted(raw, key=lambda item: canonical_key(item)):
        canonical = canonical_key(key)
        value = raw[key]
        if not canonical:
            continue
        if is_sensitive_name(canonical):
            records.append(_record(canonical, "DROPPED", "SENSITIVE_NAME"))
            continue
        if canonical not in ALLOWED_METADATA_KEYS:
            records.append(_record(canonical, "DROPPED", "UNKNOWN_METADATA_KEY"))
            continue
        projected, value_records = _project_metadata_value(canonical, value)
        metadata[canonical] = projected
        records.extend(value_records)

    ordered = _sorted_records(records)
    return {
        "rule_version": RULE_VERSION,
        "metadata": metadata,
        "records": ordered,
        "summary": redaction_summary(ordered),
    }


__all__ = [
    "ACTIONS",
    "ALLOWED_METADATA_KEYS",
    "KIND_REQUEST",
    "KIND_RESPONSE",
    "MAX_HEADER_COUNT",
    "MAX_RETAINED_VALUE_LEN",
    "NEVER_RETAINED_KEYS",
    "REASONS",
    "REQUEST_HEADER_ALLOWLIST",
    "RESPONSE_HEADER_ALLOWLIST",
    "RULE_VERSION",
    "SENSITIVE_QUERY_KEYS",
    "canonical_key",
    "canonical_name",
    "digest",
    "is_allowlisted_header",
    "is_allowed_metadata_key",
    "is_sensitive_name",
    "project_body",
    "project_metadata",
    "redact_headers",
    "redact_url",
    "redaction_summary",
    "scrub_text",
    "short_digest",
]

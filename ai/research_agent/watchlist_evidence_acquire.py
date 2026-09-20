"""Controlled watchlist evidence acquisition (first executable workflow).

Pipeline position: Watchlist Snapshot -> Delta Intelligence -> Evidence Gap
Analysis -> Evidence Acquisition Plan -> **Controlled Evidence Acquisition**
-> Candidate Finding. This module implements only the controlled acquisition
step.

Boundary (encoded here, not just documented):

- The engine accepts one explicit :class:`AcquisitionRequest`; it never
  discovers targets, never enumerates, never crawls, never expands a scope,
  never runs the watchlist, never reads MongoDB and never escalates to a
  second acquisition. One explicit request -> one bounded HTTP acquisition
  -> one evidence result.
- Scope is mandatory and explicit. The request must carry the program, the
  target, the evidence type, the acquisition method and an explicit allowed
  host scope. Incomplete/ambiguous requests are rejected before any network
  activity.
- SSRF/scope guards are reused from the existing R24.3
  :mod:`ai.research_agent.netguard` (DNS pre-resolution fail-closed on
  loopback/private/link-local/reserved/metadata; scheme/credentials/port
  rules; explicit allowlist membership). No new networking abstraction.
- The collector is the existing bounded transport seam
  (:mod:`ai.research_agent.transport`): no redirect following at the
  transport layer, caller-supplied sensitive headers refused, finite
  timeout, and an explicit small request budget enforced here as well.
  Only ``HEAD`` / ``GET`` are ever sent; nothing is fetched from links
  discovered in a response.
- Honest evidence only: an HTTP response yields status/header/body metadata
  observations (bounded digest, never the full body). It never asserts
  component identity, plugin ownership, version identity or exploitability.
  ``identity_claims`` is always empty in this version, and the result never
  uses CONFIRMED / EXPLOITABLE / VULNERABLE as an acquisition state.
- No secrets: sensitive request headers are rejected outright; no
  Authorization/Cookie/API-key header values are ever persisted; query
  strings are stripped from every recorded URL (only ``query_present`` is
  recorded). Response bodies are never persisted.
- Additive: the original watchlist snapshot is never modified. Acquired
  evidence is attached to a copy for deterministic gap re-evaluation through
  the existing gap layer; if the acquired metadata cannot establish the
  missing evidence, the readiness remains unchanged (expected, not a
  failure).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import urljoin, urlparse

from ai.research_agent.netguard import (
    NetGuardError,
    resolve_public_ips,
    validate_url,
)
from ai.research_agent.watchlist_evidence_gaps import analyze_candidate
from ai.research_agent.transport import (
    NEUTRAL_USER_AGENT,
    SENSITIVE_HEADERS,
    TransportResult,
)

RULE_VERSION = "watchlist-evidence-acquire-1"
EVIDENCE_VERSION = "watchlist-evidence-1"

# ---------------------------------------------------------------------------
# Acquisition vocabulary
# ---------------------------------------------------------------------------

HTTP_HEAD = "HTTP_HEAD"
HTTP_GET = "HTTP_GET"

ACQUISITION_METHODS: tuple[str, ...] = (HTTP_HEAD, HTTP_GET)
_HTTP_VERB = {HTTP_HEAD: "HEAD", HTTP_GET: "GET"}

APPLICATION_RESPONSE = "APPLICATION_RESPONSE"
SOURCE_CONTEXT = "SOURCE_CONTEXT"

EVIDENCE_TYPES: tuple[str, ...] = (APPLICATION_RESPONSE, SOURCE_CONTEXT)
_EVIDENCE_SOURCE = {
    APPLICATION_RESPONSE: APPLICATION_RESPONSE,
    SOURCE_CONTEXT: "SOURCE_ASSET",
}

REDIRECT_NONE = "NONE"
REDIRECT_SAME_HOST = "SAME_HOST"

REDIRECT_POLICIES: tuple[str, ...] = (REDIRECT_NONE, REDIRECT_SAME_HOST)

# Acquisition result states. Never a security verdict.
STATE_ACQUIRED = "ACQUIRED"
STATE_EMPTY = "EMPTY"
STATE_BLOCKED = "BLOCKED"
STATE_OUT_OF_SCOPE = "OUT_OF_SCOPE"
STATE_FAILED = "FAILED"

RESULT_STATES: tuple[str, ...] = (
    STATE_ACQUIRED,
    STATE_EMPTY,
    STATE_BLOCKED,
    STATE_OUT_OF_SCOPE,
    STATE_FAILED,
)

CONFIDENCE_NONE = "NONE"
CONFIDENCE_LOW = "LOW"

# Conservative defaults and hard caps.
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 30.0
DEFAULT_MAX_BYTES = 65536
MAX_BYTES = 1_000_000
DEFAULT_MAX_REQUESTS = 1
MAX_REQUESTS = 5
MAX_REDIRECTS = 2

NEXT_ACTION = "EXPLICIT_REQUEST_REQUIRED"

_PROGRAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_EVIDENCE_ID_RE = re.compile(r"^wev-[0-9a-f]{16}$")
_SAFE_SEGMENT_RE = re.compile(r"[^a-z0-9_-]+")

#: Error codes produced by the mandatory scope guards (mapped to
#: OUT_OF_SCOPE). Every other validation code yields BLOCKED.
SCOPE_ERROR_CODES: frozenset[str] = frozenset(
    {
        "OUT_OF_SCOPE_HOST",
        "PRIVATE_OR_RESERVED",
        "BLOCKED_HOST",
        "NON_DEFAULT_PORT",
        "UNSUPPORTED_SCHEME",
        "EMBEDDED_CREDENTIALS",
    }
)

_NETGUARD_REASON_CODES = {
    "allowlist": "OUT_OF_SCOPE_HOST",
    "private_ip": "PRIVATE_OR_RESERVED",
    "host": "BLOCKED_HOST",
    "port": "NON_DEFAULT_PORT",
    "scheme": "UNSUPPORTED_SCHEME",
    "scheme_downgrade": "UNSUPPORTED_SCHEME",
    "embedded_credentials": "EMBEDDED_CREDENTIALS",
    "invalid_url": "INVALID_TARGET",
}


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcquisitionRequest:
    """One explicit, scoped acquisition request (never built implicitly)."""

    program: str
    target: str
    evidence_type: str
    method: str
    scope_allowed_hosts: tuple[str, ...] = ()
    scope_id: str = ""
    timeout: float = DEFAULT_TIMEOUT
    max_bytes: int = DEFAULT_MAX_BYTES
    max_requests: int = DEFAULT_MAX_REQUESTS
    redirect_policy: str = REDIRECT_NONE
    headers: tuple[tuple[str, str], ...] = ()


SendFn = Callable[..., "TransportResult | None"]
ResolverFn = Callable[[str], list[str]]


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _program_segment(program: str) -> str:
    return _SAFE_SEGMENT_RE.sub("_", program.lower()).strip("_") or "unknown"


def _utc_text(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redacted_url(url: str) -> str:
    """URL without query/fragment (queries may carry tokens/secrets)."""

    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return ""
    scheme = parsed.scheme or ""
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return f"{scheme}://{netloc}{parsed.path or ''}"


def _url_target_block(url: str) -> dict:
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return {
            "scheme": "",
            "host": "",
            "port": None,
            "path": "",
            "query_present": False,
        }
    return {
        "scheme": (parsed.scheme or "").lower(),
        "host": (parsed.hostname or "").strip().lower().rstrip("."),
        "port": parsed.port,
        "path": parsed.path or "",
        "query_present": bool(parsed.query),
    }


def _error(field_name: str, code: str, message: str) -> dict:
    return {"field": field_name, "code": code, "message": message}


# ---------------------------------------------------------------------------
# Validation (structural + mandatory scope)
# ---------------------------------------------------------------------------


def validate_request(
    request: AcquisitionRequest | None,
    *,
    resolver: ResolverFn | None = None,
) -> tuple[dict, list[dict]]:
    """Validate one request; return ``(normalized_request, errors)``.

    Deterministic error ordering; no network activity. Scope guard
    failures are tagged with a code in :data:`SCOPE_ERROR_CODES`.
    """

    errors: list[dict] = []
    normalized: dict = {
        "program": "",
        "target": "",
        "evidence_type": "",
        "method": "",
        "scope_allowed_hosts": [],
        "scope_id": "",
        "timeout": DEFAULT_TIMEOUT,
        "max_bytes": DEFAULT_MAX_BYTES,
        "max_requests": DEFAULT_MAX_REQUESTS,
        "redirect_policy": REDIRECT_NONE,
        "headers": [],
    }
    if not isinstance(request, AcquisitionRequest):
        errors.append(_error("request", "INVALID_REQUEST", "request object required"))
        return normalized, errors

    program = _text(request.program)
    if not program:
        errors.append(_error("program", "MISSING_PROGRAM", "program is required"))
    elif not _PROGRAM_RE.match(program):
        errors.append(
            _error("program", "INVALID_PROGRAM", "program has invalid characters")
        )
    normalized["program"] = program

    target = _text(request.target)
    if not target:
        errors.append(_error("target", "MISSING_TARGET", "target is required"))
    normalized["target"] = _redacted_url(target)

    evidence_type = _text(request.evidence_type).upper()
    if not evidence_type:
        errors.append(
            _error("evidence_type", "MISSING_EVIDENCE_TYPE", "evidence type required")
        )
    elif evidence_type not in EVIDENCE_TYPES:
        errors.append(
            _error(
                "evidence_type",
                "UNSUPPORTED_EVIDENCE_TYPE",
                f"unsupported evidence type: {evidence_type}",
            )
        )
    normalized["evidence_type"] = evidence_type

    method = _text(request.method).upper()
    if not method:
        errors.append(
            _error("method", "MISSING_METHOD", "acquisition method required")
        )
    elif method not in ACQUISITION_METHODS:
        errors.append(
            _error("method", "UNSUPPORTED_METHOD", f"unsupported method: {method}")
        )
    normalized["method"] = method

    scope_hosts: list[str] = []
    for host in request.scope_allowed_hosts or ():
        text = _text(host).lower().rstrip(".")
        if not text:
            continue
        if not _HOST_RE.match(text):
            errors.append(
                _error(
                    "scope_allowed_hosts",
                    "INVALID_SCOPE_HOST",
                    "scope host must be a plain DNS host",
                )
            )
            continue
        if text not in scope_hosts:
            scope_hosts.append(text)
    if not scope_hosts:
        errors.append(
            _error(
                "scope_allowed_hosts",
                "MISSING_SCOPE",
                "an explicit non-empty allowed host scope is required",
            )
        )
    normalized["scope_allowed_hosts"] = sorted(scope_hosts)
    normalized["scope_id"] = _text(request.scope_id)

    try:
        timeout = float(request.timeout)
    except (TypeError, ValueError):
        timeout = -1.0
    if not (0.0 < timeout <= MAX_TIMEOUT):
        errors.append(
            _error(
                "timeout",
                "INVALID_TIMEOUT",
                f"timeout must be within (0, {MAX_TIMEOUT}]",
            )
        )
    normalized["timeout"] = timeout if timeout > 0 else DEFAULT_TIMEOUT

    try:
        max_bytes = int(request.max_bytes)
    except (TypeError, ValueError):
        max_bytes = -1
    if not (0 < max_bytes <= MAX_BYTES):
        errors.append(
            _error(
                "max_bytes",
                "INVALID_MAX_BYTES",
                f"max_bytes must be within (0, {MAX_BYTES}]",
            )
        )
    normalized["max_bytes"] = max_bytes if max_bytes > 0 else DEFAULT_MAX_BYTES

    try:
        max_requests = int(request.max_requests)
    except (TypeError, ValueError):
        max_requests = -1
    if not (0 < max_requests <= MAX_REQUESTS):
        errors.append(
            _error(
                "max_requests",
                "INVALID_MAX_REQUESTS",
                f"max_requests must be within [1, {MAX_REQUESTS}]",
            )
        )
    normalized["max_requests"] = (
        max_requests if max_requests > 0 else DEFAULT_MAX_REQUESTS
    )

    policy = _text(request.redirect_policy).upper() or REDIRECT_NONE
    if policy not in REDIRECT_POLICIES:
        errors.append(
            _error(
                "redirect_policy",
                "INVALID_REDIRECT_POLICY",
                f"unsupported redirect policy: {policy}",
            )
        )
    normalized["redirect_policy"] = policy

    headers: list[tuple[str, str]] = []
    for name, value in request.headers or ():
        header_name = _text(name)
        if header_name.lower() in SENSITIVE_HEADERS:
            errors.append(
                _error(
                    "headers",
                    "SENSITIVE_HEADER",
                    "sensitive request headers are never accepted or persisted",
                )
            )
            continue
        if not _HEADER_NAME_RE.match(header_name):
            errors.append(
                _error("headers", "INVALID_HEADER_NAME", "invalid header name")
            )
            continue
        if not _text(value):
            errors.append(
                _error("headers", "INVALID_HEADER_VALUE", "empty header value")
            )
            continue
        headers.append((header_name.lower(), _text(value)))
    normalized["headers"] = sorted(headers)

    # Mandatory scope guard (only when a structural target survives).
    structure_ok = not any(
        error["code"] not in SCOPE_ERROR_CODES for error in errors
    )
    if structure_ok and target:
        parsed = _url_target_block(target)
        host = parsed["host"]
        if not host:
            errors.append(
                _error("target", "INVALID_TARGET", "target has no host")
            )
        else:
            public = resolve_public_ips(host, resolver=resolver)
            if not public:
                errors.append(
                    _error(
                        "target",
                        "PRIVATE_OR_RESERVED",
                        "target host is non-public or unresolvable",
                    )
                )
            else:
                try:
                    validate_url(target, allowed_hosts=scope_hosts)
                except NetGuardError as exc:
                    reason = getattr(exc, "reason", "guard")
                    code = _NETGUARD_REASON_CODES.get(reason, "OUT_OF_SCOPE_HOST")
                    errors.append(
                        _error(
                            "target",
                            code,
                            f"target rejected by scope guard ({reason})",
                        )
                    )

    return normalized, errors


def _result_state_for(errors: Iterable[dict]) -> str:
    codes = [str(error.get("code") or "") for error in errors]
    if codes and all(code in SCOPE_ERROR_CODES for code in codes):
        return STATE_OUT_OF_SCOPE
    return STATE_BLOCKED


# ---------------------------------------------------------------------------
# Collector (bounded, metadata-only)
# ---------------------------------------------------------------------------


def _header_value(headers: Mapping, name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).strip().lower() == wanted:
            return _text(value)
    return ""


def _default_send_fn() -> SendFn:
    """Lazy default bounded transport send (httpx only when actually used)."""

    from ai.research_agent.transport import default_send

    return default_send


def _observations(
    *,
    method: str,
    status: int,
    headers: Mapping,
    body: bytes,
    truncated: bool,
    location_host: str,
) -> list[dict]:
    """Deterministic evidence-bearing observations (metadata only).

    The status line alone is not treated as content: a response with no
    body and no metadata headers yields no observations (-> EMPTY).
    """

    observations: list[dict] = []
    content_type = _header_value(headers, "content-type")
    if content_type:
        observations.append({"observation": "content_type", "value": content_type})
    content_length = _header_value(headers, "content-length")
    if content_length:
        observations.append({"observation": "content_length", "value": content_length})
    server = _header_value(headers, "server")
    if server:
        observations.append({"observation": "server", "value": server})
    if location_host:
        observations.append(
            {"observation": "redirect_location_host", "value": location_host}
        )
    if method == HTTP_GET and body:
        observations.append({"observation": "body_bytes", "value": len(body)})
        observations.append(
            {
                "observation": "body_sha256",
                "value": hashlib.sha256(body).hexdigest(),
            }
        )
    if truncated:
        observations.append({"observation": "body_truncated", "value": True})
    return observations


def _evidence_id(
    program: str, redacted_url: str, method: str, evidence_type: str,
    status: int, observations: list[dict],
) -> str:
    payload = {
        "program": program,
        "url": redacted_url,
        "method": method,
        "evidence_type": evidence_type,
        "status": status,
        "observations": observations,
    }
    return "wev-" + _digest(payload)[:16]


def _empty_result(
    *,
    state: str,
    normalized: dict,
    errors: list[dict] | None = None,
    blocked_reason: str = "",
    redirect_block: Mapping | None = None,
    collected_at: str,
) -> dict:
    redirect = {
        "policy": normalized.get("redirect_policy", REDIRECT_NONE),
        "followed": False,
        "hops": 0,
        "final_url": "",
        "not_followed_reason": "",
        "target_host": "",
    }
    if redirect_block:
        redirect.update(dict(redirect_block))
    return {
        "rule_version": RULE_VERSION,
        "evidence_version": EVIDENCE_VERSION,
        "state": state,
        "program": normalized.get("program", ""),
        "target": normalized.get("target", ""),
        "evidence_type": normalized.get("evidence_type", ""),
        "method": normalized.get("method", ""),
        "scope_id": normalized.get("scope_id", ""),
        "scope_allowed_hosts": list(normalized.get("scope_allowed_hosts") or []),
        "request_metadata": _request_metadata(normalized, requests_made=0),
        "response_metadata": {},
        "redirect": redirect,
        "evidence": [],
        "evidence_count": 0,
        "errors": list(errors or []),
        "blocked_reason": blocked_reason,
        "identity_claims": [],
        "confidence_state": CONFIDENCE_NONE,
        "collected_at": collected_at,
        "next_action": NEXT_ACTION,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _request_metadata(normalized: Mapping, *, requests_made: int) -> dict:
    return {
        "http_method": _HTTP_VERB.get(
            str(normalized.get("method") or ""), ""
        ),
        "url": str(normalized.get("target") or ""),
        "timeout_s": float(normalized.get("timeout") or DEFAULT_TIMEOUT),
        "max_bytes": int(normalized.get("max_bytes") or DEFAULT_MAX_BYTES),
        "max_requests": int(
            normalized.get("max_requests") or DEFAULT_MAX_REQUESTS
        ),
        "requests_made": int(requests_made),
        "redirect_policy": str(
            normalized.get("redirect_policy") or REDIRECT_NONE
        ),
        "sent_header_names": sorted(
            {name for name, _value in (normalized.get("headers") or [])}
            | {"user-agent"}
        ),
    }


def acquire_evidence(
    request: AcquisitionRequest | None,
    *,
    send: SendFn | None = None,
    resolver: ResolverFn | None = None,
    now: datetime | None = None,
) -> dict:
    """Execute one bounded, explicitly scoped acquisition.

    Returns a deterministic result envelope. Exactly one acquisition is
    performed; there is no automatic iteration over acquisition-plan steps
    and no follow-up request when the evidence remains insufficient.
    """

    collected_at = _utc_text(now)
    normalized, errors = validate_request(request, resolver=resolver)
    if errors:
        return _empty_result(
            state=_result_state_for(errors),
            normalized=normalized,
            errors=errors,
            blocked_reason=str(errors[0].get("code") or "INVALID_REQUEST"),
            collected_at=collected_at,
        )

    verb = _HTTP_VERB[normalized["method"]]
    method = normalized["method"]
    target = str(request.target).strip() if request is not None else ""
    timeout = float(normalized["timeout"])
    max_bytes = int(normalized["max_bytes"])
    max_requests = int(normalized["max_requests"])
    policy = str(normalized["redirect_policy"])
    send_fn = send or _default_send_fn()

    out_headers = {"User-Agent": NEUTRAL_USER_AGENT}
    for name, value in normalized.get("headers") or []:
        out_headers[name] = value

    scope_hosts = tuple(normalized.get("scope_allowed_hosts") or ())
    original = _url_target_block(target)
    observed_host = original["host"]

    requests_made = 0
    redirect_hops = 0
    chain: list[str] = []
    location_host = ""
    not_followed_reason = ""
    response: TransportResult | None = None
    current = target

    while True:
        if requests_made >= max_requests:
            return _empty_result(
                state=STATE_BLOCKED,
                normalized=normalized,
                blocked_reason="REQUEST_BUDGET",
                redirect_block={
                    "policy": policy,
                    "followed": redirect_hops > 0,
                    "hops": redirect_hops,
                    "final_url": _redacted_url(current),
                    "not_followed_reason": "REQUEST_BUDGET",
                    "target_host": observed_host,
                },
                collected_at=collected_at,
            )
        requests_made += 1
        try:
            response = send_fn(verb, current, out_headers, timeout, None)
        except Exception:
            response = None
        if response is None:
            return _empty_result(
                state=STATE_FAILED,
                normalized=normalized,
                blocked_reason="TRANSPORT_FAILURE",
                redirect_block={
                    "policy": policy,
                    "followed": redirect_hops > 0,
                    "hops": redirect_hops,
                    "final_url": _redacted_url(current),
                    "not_followed_reason": "",
                    "target_host": observed_host,
                },
                collected_at=collected_at,
            )
        chain.append(_redacted_url(current))
        status = int(response.status or 0)
        headers = response.headers if isinstance(response.headers, Mapping) else {}
        body = bytes(response.body or b"")
        location = _header_value(headers, "Location") or _header_value(
            headers, "location"
        )
        location_host = ""
        if 300 <= status < 400 and location:
            try:
                hop_url = urljoin(current, location)
            except Exception:
                hop_url = ""
            location_host = _url_target_block(hop_url)["host"] if hop_url else ""
        if 300 <= status < 400 and location and policy == REDIRECT_SAME_HOST:
            try:
                hop_url = urljoin(current, location)
            except Exception:
                hop_url = ""
            hop = _url_target_block(hop_url)
            if (
                not hop_url
                or not hop["host"]
                or hop["host"] != observed_host
                or hop["host"] not in scope_hosts
            ):
                not_followed_reason = "OUT_OF_SCOPE"
            elif (urlparse(hop_url).scheme or "").lower() != "https" and (
                urlparse(current).scheme or ""
            ).lower() == "https":
                not_followed_reason = "SCHEME_DOWNGRADE"
            elif not resolve_public_ips(hop["host"], resolver=resolver):
                not_followed_reason = "PRIVATE_OR_RESERVED"
            elif redirect_hops >= MAX_REDIRECTS:
                not_followed_reason = "REDIRECT_LIMIT"
            if not_followed_reason:
                return _empty_result(
                    state=STATE_BLOCKED,
                    normalized=normalized,
                    blocked_reason=f"REDIRECT_{not_followed_reason}",
                    redirect_block={
                        "policy": policy,
                        "followed": redirect_hops > 0,
                        "hops": redirect_hops,
                        "final_url": _redacted_url(current),
                        "not_followed_reason": not_followed_reason,
                        "target_host": location_host or observed_host,
                    },
                    collected_at=collected_at,
                )
            redirect_hops += 1
            current = hop_url
            continue
        if 300 <= status < 400 and policy == REDIRECT_NONE:
            not_followed_reason = "POLICY_NONE"
        break

    body_truncated = len(body) > max_bytes
    bounded_body = body[:max_bytes] if body_truncated else body
    observations = _observations(
        method=method,
        status=status,
        headers=headers,
        body=bounded_body,
        truncated=body_truncated,
        location_host=location_host,
    )
    # A response with no body and no metadata headers carries no
    # evidence-bearing observation (-> EMPTY). The status line alone is
    # recorded for audit but is never treated as acquired evidence.
    state = STATE_ACQUIRED if observations else STATE_EMPTY

    response_metadata = {
        "status": status,
        "content_type": _header_value(headers, "content-type"),
        "content_length": _header_value(headers, "content-length"),
        "server": _header_value(headers, "server"),
        "location_host": location_host,
        "body_bytes": len(bounded_body),
        "body_sha256": (
            hashlib.sha256(bounded_body).hexdigest() if bounded_body else ""
        ),
        "body_truncated": body_truncated,
        "final_url": _redacted_url(response.url or response.final_url or current),
    }
    redirect_block = {
        "policy": policy,
        "followed": redirect_hops > 0,
        "hops": redirect_hops,
        "final_url": _redacted_url(current),
        "not_followed_reason": not_followed_reason,
        "target_host": location_host or observed_host,
    }

    evidence_records: list[dict] = []
    if state == STATE_ACQUIRED:
        redacted = _redacted_url(target)
        evidence_records.append(
            {
                "evidence_id": _evidence_id(
                    normalized["program"], redacted, method,
                    normalized["evidence_type"], status, observations,
                ),
                "evidence_type": normalized["evidence_type"],
                "target": _url_target_block(target),
                "source": _EVIDENCE_SOURCE[normalized["evidence_type"]],
                "method": method,
                "timestamp": collected_at,
                "request_metadata": _request_metadata(
                    normalized, requests_made=requests_made
                ),
                "response_metadata": response_metadata,
                "artifact_reference": None,
                "observations": observations,
                "provenance": {
                    "program": normalized["program"],
                    "scope_id": normalized["scope_id"],
                    "scope_allowed_hosts": list(scope_hosts),
                    "requested_target": redacted,
                    "redirect_chain": list(chain),
                    "collected_at": collected_at,
                    "method": method,
                    "evidence_type": normalized["evidence_type"],
                    "collector": "bounded_http_metadata",
                    "rule_version": RULE_VERSION,
                },
                "confidence_state": CONFIDENCE_LOW,
                "identity_claims": [],
                "state": STATE_ACQUIRED,
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )

    return {
        "rule_version": RULE_VERSION,
        "evidence_version": EVIDENCE_VERSION,
        "state": state,
        "program": normalized["program"],
        "target": normalized["target"],
        "evidence_type": normalized["evidence_type"],
        "method": normalized["method"],
        "scope_id": normalized["scope_id"],
        "scope_allowed_hosts": list(scope_hosts),
        "request_metadata": _request_metadata(
            normalized, requests_made=requests_made
        ),
        "response_metadata": response_metadata,
        "redirect": redirect_block,
        "evidence": evidence_records,
        "evidence_count": len(evidence_records),
        "errors": [],
        "blocked_reason": "",
        "identity_claims": [],
        "confidence_state": (
            CONFIDENCE_LOW if state == STATE_ACQUIRED else CONFIDENCE_NONE
        ),
        "collected_at": collected_at,
        "next_action": NEXT_ACTION,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


# ---------------------------------------------------------------------------
# Gap re-evaluation (additive; the source candidate is never mutated)
# ---------------------------------------------------------------------------

_REEVALUATION_NOTE = (
    "acquired HTTP metadata cannot establish component, version, or "
    "technology identity; evidence-gap states remain unchanged unless the "
    "existing gap layer derives otherwise"
)


def reevaluate_candidate_with_evidence(
    candidate: Mapping | None, acquisition_result: Mapping | None
) -> dict:
    """Re-run the existing evidence-gap layer with acquired evidence attached.

    The original candidate is deep-copied; acquired evidence records are
    attached under the additive ``acquired_evidence`` field (which the gap
    layer deliberately ignores, so states only change when the existing gap
    logic says so). Never writes to the watchlist snapshot.
    """

    base_candidate: Mapping = candidate if isinstance(candidate, Mapping) else {}
    result: Mapping = (
        acquisition_result if isinstance(acquisition_result, Mapping) else {}
    )
    records = result.get("evidence")
    evidence = [dict(item) for item in records] if isinstance(records, list) else []

    updated_candidate = copy.deepcopy(dict(base_candidate))
    updated_candidate["acquired_evidence"] = copy.deepcopy(evidence)

    base_gap = analyze_candidate(base_candidate)
    updated_gap = analyze_candidate(updated_candidate)

    base_states = {
        str(dim.get("evidence_type")): str(dim.get("state"))
        for dim in base_gap.get("dimensions") or []
    }
    updated_states = {
        str(dim.get("evidence_type")): str(dim.get("state"))
        for dim in updated_gap.get("dimensions") or []
    }
    state_changes = [
        {
            "evidence_type": evidence_type,
            "before": base_states.get(evidence_type, ""),
            "after": updated_states.get(evidence_type, ""),
        }
        for evidence_type in sorted(set(base_states) | set(updated_states))
        if base_states.get(evidence_type) != updated_states.get(evidence_type)
    ]

    return {
        "cve_id": str(base_gap.get("cve_id") or ""),
        "base_finding_readiness": str(base_gap.get("finding_readiness") or ""),
        "updated_finding_readiness": str(updated_gap.get("finding_readiness") or ""),
        "changed": bool(state_changes),
        "state_changes": state_changes,
        "base_gap": base_gap,
        "updated_gap": updated_gap,
        "acquired_evidence_count": len(evidence),
        "identity_claims": [],
        "note": _REEVALUATION_NOTE,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


# ---------------------------------------------------------------------------
# Local persistence (atomic, no-overwrite; never production paths)
# ---------------------------------------------------------------------------


def evidence_result_dir(snapshot_root: object, program: str) -> Path:
    return Path(snapshot_root) / "evidence" / _program_segment(program)


def evidence_result_path(
    snapshot_root: object, program: str, evidence_id: str
) -> Path:
    safe_id = _text(evidence_id)
    if not _EVIDENCE_ID_RE.match(safe_id):
        raise ValueError(f"invalid evidence id: {evidence_id!r}")
    return evidence_result_dir(snapshot_root, program) / f"{safe_id}.json"


def store_evidence_result(
    result: Mapping, snapshot_root: object, program: str
) -> tuple[Path | None, bool]:
    """Atomic, no-overwrite persistence of one ACQUIRED evidence result.

    Non-ACQUIRED results are not evidence and are therefore not persisted.
    Returns ``(path, written)``; ``(None, False)`` when nothing was written.
    """

    if not isinstance(result, Mapping) or result.get("state") != STATE_ACQUIRED:
        return None, False
    records = result.get("evidence")
    if not isinstance(records, list) or not records:
        return None, False
    evidence_id = _text(records[0].get("evidence_id"))
    dest = evidence_result_path(snapshot_root, program, evidence_id)
    if dest.exists():
        return dest, False
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    payload = dict(result)
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    os.replace(tmp, dest)
    return dest, True


__all__ = [
    "RULE_VERSION",
    "EVIDENCE_VERSION",
    "HTTP_HEAD",
    "HTTP_GET",
    "ACQUISITION_METHODS",
    "APPLICATION_RESPONSE",
    "SOURCE_CONTEXT",
    "EVIDENCE_TYPES",
    "REDIRECT_NONE",
    "REDIRECT_SAME_HOST",
    "REDIRECT_POLICIES",
    "STATE_ACQUIRED",
    "STATE_EMPTY",
    "STATE_BLOCKED",
    "STATE_OUT_OF_SCOPE",
    "STATE_FAILED",
    "RESULT_STATES",
    "CONFIDENCE_NONE",
    "CONFIDENCE_LOW",
    "DEFAULT_TIMEOUT",
    "MAX_TIMEOUT",
    "DEFAULT_MAX_BYTES",
    "MAX_BYTES",
    "DEFAULT_MAX_REQUESTS",
    "MAX_REQUESTS",
    "MAX_REDIRECTS",
    "NEXT_ACTION",
    "SCOPE_ERROR_CODES",
    "AcquisitionRequest",
    "validate_request",
    "acquire_evidence",
    "reevaluate_candidate_with_evidence",
    "evidence_result_dir",
    "evidence_result_path",
    "store_evidence_result",
]

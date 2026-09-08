"""IP-pinned HTTP executor (Phase 5E).

READ-ONLY posture: this module performs NO live internet traffic.
The live execution gate is explicit in code (not a comment):

- ``LIVE_TRAFFIC_ENABLED`` is ``False`` and there is no code path
  that sets it to ``True``.
- ``RealSocketFactory.connect`` and ``SystemTlsWrapper.wrap`` always
  raise ``ExecutorError(LIVE_GATE_BLOCKED)``. Production adapters
  (B1: production AddressSource selection/review; B2: production
  Mongo authorization/ledger/audit/evidence adapters + sweep) do not
  exist in 5E, so no implementation path can perform a live HTTP
  request.
- Offline execution proceeds only through injected fakes
  (``SocketFactory`` / ``TlsWrapper`` / ``HopResolver`` test doubles
  supplied by the caller).

Security property: SCOPE-EVALUATED == ACTUALLY-DIALED. The transport
dials only the pinned IP literal from the current hop's ``DialBinding``
via ``connect(ip_literal, port, timeout)``. Hostname strings never
reach any resolver after approval: this module contains no DNS
primitive (no ``getaddrinfo``, no ``create_connection`` with a
hostname, no high-level HTTP client).

Frozen contracts reused (never duplicated):

- 5B: ``IssuedExecutionAuthorization``, liveness, CAS consume,
  method-pair contract, artifact identity.
- 5C: ``TargetResolution``, ``DialBinding``, canonical target,
  address classification/ordering, resolution identity.
- 5D: ``ScopeEvaluation``, ``require_allowed()``, per-hop evaluation.
- 5H-core: ``EvidenceRecord``, ``HttpObservation``,
  ``EvidenceBuilder``, scrubber, hashing, ledger, audit, ceilings,
  crash/orphan semantics.

This module is OFFLINE and DETERMINISTIC (caller-supplied clocks
only): no network, no subprocess, no database driver, no LLM, no
browser, no Nuclei, no findings, no verdicts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit

from ai.audit.trail import AuditRecord, gap_record
from ai.evidence import hashing as hash_mod
from ai.evidence import observations as obs
from ai.evidence import scrubber
from ai.evidence.builder import EvidenceBuilder
from ai.evidence.handoff import require_live_for_execution
from ai.limits.ceilings import CEILINGS
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import DnsError, classify_address, validate_answers
from ai.schemas import evidence as ev
from ai.schemas.artifact import ArtifactReference, content_hash_for_bytes
from ai.schemas.execution_authorization import (
    ALLOWED_METHODS,
    FORBIDDEN_METHODS,
    AuthzError,
    IssuedExecutionAuthorization,
    check_method_pair,
)
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import (
    DialBinding,
    TargetResolution,
    canonical_target_hash_for,
)

__all__ = [
    "LIVE_TRAFFIC_ENABLED",
    "B1_STATUS",
    "B2_STATUS",
    "EXECUTOR_ERROR_CODES",
    "ExecutorError",
    "SAFE_REQUEST_HEADERS",
    "FIXED_USER_AGENT",
    "FIXED_CONTENT_TYPE",
    "MAX_QUERY_PARAMS",
    "MAX_QUERY_VALUE",
    "MAX_LOCATION_LENGTH",
    "MAX_REDIRECT_EDGES",
    "MAX_REQUESTS_PER_EXECUTION",
    "REDIRECT_STATUSES",
    "BoundedHttpRequest",
    "translate_bounded_request",
    "SocketFactory",
    "RealSocketFactory",
    "TlsWrapper",
    "SystemTlsWrapper",
    "HopResolver",
    "AuditSink",
    "InMemoryAuditSink",
    "ExecutorDeps",
    "HopRecord",
    "HttpExecutionResult",
    "execute_http",
    "compute_request_fingerprint",
]

# ------------------------------------------------------------------
# Live-traffic gate (explicit, B1+B2 blockers)
# ------------------------------------------------------------------

#: Master live-traffic switch. Frozen ``False`` for Phase 5E. No code
#: path in 5E sets this to ``True``: flipping it requires the B1
#: (production AddressSource selection/review) and B2 (production
#: Mongo authorization/ledger/audit/evidence adapters + sweep)
#: reviews, which are tracked as remaining blockers below.
LIVE_TRAFFIC_ENABLED = False

#: B1 BLOCKING (live traffic): production ``AddressSource``
#: selection + review deferred. Interface (``HopResolver``) frozen;
#: source deferred. Nothing dials real IPs until B1 closes.
B1_STATUS = "BLOCKED: production AddressSource selection/review deferred"

#: B2 BLOCKING (live/multi-worker): production Mongo adapters for
#: authorization store + execution ledger + audit/evidence backends +
#: orphan sweep deferred. Semantics frozen; mechanism deferred.
B2_STATUS = (
    "BLOCKED: production authorization/ledger/audit/evidence "
    "adapters + sweep deferred"
)

# ------------------------------------------------------------------
# Frozen ceilings (re-exported from 5H-core, never redefined)
# ------------------------------------------------------------------

_HTTP_WALL = CEILINGS["http_wall_seconds"]
_CONNECT_TIMEOUT = CEILINGS["connect_timeout_seconds"]
_READ_TIMEOUT = CEILINGS["read_timeout_seconds"]
_STALL_TIMEOUT = CEILINGS["chunk_stall_timeout_seconds"]
_REQUEST_BODY_MAX = CEILINGS["request_body_bytes"]
_RESPONSE_TRANSPORT_MAX = CEILINGS["response_transport_bytes"]
_RESPONSE_SAMPLE_MAX = CEILINGS["response_evidence_sample_bytes"]
_DECOMPRESSED_MAX = CEILINGS["decompressed_bytes"]
_COMPRESSION_RATIO = CEILINGS["compression_ratio"]
_DNS_ANSWERS_MAX = CEILINGS["dns_answers"]
MAX_REDIRECT_EDGES = CEILINGS["redirect_hops"]
MAX_REQUESTS_PER_EXECUTION = CEILINGS["requests_per_execution"]

#: Bound on one raw Location value (reject, never truncate).
MAX_LOCATION_LENGTH = 2048

#: Translator bounds on artifact query construction.
MAX_QUERY_PARAMS = 16
MAX_QUERY_VALUE = 1024
MAX_QUERY_NAME = 128

#: Transport header-block bounds (framing safety, not evidence caps).
_MAX_HEADER_BLOCK = 65536
_MAX_HEADER_LINES = 100
_MAX_HEADER_LINE = 8192

#: Statuses the redirect state machine processes manually.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_DEFAULT_PORTS = {"http": 80, "https": 443}

# ------------------------------------------------------------------
# Closed error vocabulary (deterministic, secret-free)
# ------------------------------------------------------------------

EXECUTOR_ERROR_CODES = frozenset(
    {
        "TRANSLATION_REJECTED",
        "METHOD_NOT_ALLOWED",
        "AUTHZ_NOT_LIVE",
        "AUTHZ_BINDING_MISMATCH",
        "TARGET_BINDING_MISMATCH",
        "RESOLUTION_BINDING_MISMATCH",
        "DIAL_BINDING_MISMATCH",
        "UNSAFE_ADDRESS",
        "TARGET_NOT_IN_SCOPE",
        "TARGET_EXCLUDED",
        "SCOPE_DRIFT",
        "ARTIFACT_REVALIDATION_FAILED",
        "EXECUTION_ALREADY_CONSUMED",
        "EXECUTION_REPLAY",
        "AUDIT_GAP",
        "TRANSPORT_TIMEOUT",
        "TRANSPORT_BINDING_FAILURE",
        "TRANSPORT_FAILURE",
        "TLS_FAILURE",
        "DNS_OBSERVATION_FAILED",
        "RESPONSE_LIMIT",
        "DECOMPRESSION_LIMIT",
        "REDIRECT_LIMIT",
        "REDIRECT_NOT_IN_SCOPE",
        "REDIRECT_INVALID",
        "EVIDENCE_SEAL_FAILED",
        "OUTCOME_UNKNOWN",
        "LIVE_GATE_BLOCKED",
    }
)


class ExecutorError(ValueError):
    """Bounded, secret-free 5E failure with an explicit closed code."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in EXECUTOR_ERROR_CODES:
            raise ValueError(f"unknown executor error code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("executor error detail must be single-line")
        if scrubber.contains_secret_shape(safe_detail):
            raise ValueError(
                "executor error detail carries suspected secret material"
            )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


# ------------------------------------------------------------------
# 5E.1 — Bounded HTTP request + translator
# ------------------------------------------------------------------

#: Artifact-supplied headers admitted at translation (lowercase).
SAFE_REQUEST_HEADERS = frozenset(
    {"accept", "accept-language", "user-agent", "content-type"}
)

#: Fixed request identity values (single source of truth).
FIXED_USER_AGENT = "WatchSecurityResearch/1.0"
FIXED_CONTENT_TYPE = "application/x-www-form-urlencoded"

#: Header names that must never be supplied by the artifact.
_FORBIDDEN_HEADER_NAMES = frozenset(
    {
        "host",
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "proxy-authenticate",
        "content-length",
        "transfer-encoding",
        "connection",
        "expect",
        "x-forwarded-host",
        "x-forwarded-for",
    }
)

_SECRET_PARAM_MARKERS = (
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


def _is_secret_param_name(name: str) -> bool:
    lowered = (name or "").casefold()
    return any(marker in lowered for marker in _SECRET_PARAM_MARKERS)


def _has_controls(value: str) -> bool:
    for char in value:
        code = ord(char)
        if char in ("\n", "\r", "\0") or code < 32 or code == 127:
            return True
    return False


@dataclass(frozen=True)
class BoundedHttpRequest:
    """Immutable, fully validated HTTP request (5E.1).

    Contains only data that has already passed 5B authorization,
    artifact validation, and method/path/query/header/body validation.
    Carries no raw URL authority: the authority derives from the
    resolved target binding, the path/query from the validated
    artifact. ``Host`` and framing headers are generated by the
    transport, never stored here.
    """

    method: str
    scheme: str
    canonical_host: str
    effective_port: int
    path: str
    query_string: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    artifact_id: str
    artifact_content_hash: str
    canonical_url: str
    authorization_id: str
    execution_id: str
    resolution_id: str
    evaluation_id: str
    program_name: str

    @property
    def request_target(self) -> str:
        """Origin-form request target (``/path`` or ``/path?query``)."""
        if self.query_string:
            return f"{self.path}?{self.query_string}"
        return self.path

    @property
    def body_hash(self) -> str:
        """SHA-256 over the exact request body bytes (empty if none)."""
        return hashlib.sha256(self.body if self.body is not None else b"").hexdigest()


def _parse_http_artifact_bytes(artifact_bytes: bytes) -> dict[str, Any]:
    try:
        text = bytes(artifact_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact bytes are not utf-8"
        ) from exc
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact bytes are not json"
        ) from exc
    if not isinstance(payload, dict):
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact content not an object"
        )
    allowed_keys = {"method", "path", "query_params", "headers", "body"}
    for key in payload:
        if key not in allowed_keys:
            raise ExecutorError(
                "ARTIFACT_REVALIDATION_FAILED", "artifact has unknown field"
            )
    return payload


def _revalidate_artifact(
    *,
    authorization: IssuedExecutionAuthorization,
    artifact_reference: ArtifactReference,
    artifact_bytes: bytes,
) -> dict[str, Any]:
    """Exact artifact revalidation (hash + identity + H2 + method)."""
    if not isinstance(artifact_reference, ArtifactReference):
        raise TypeError(
            "artifact revalidation accepts only ArtifactReference, "
            f"not {type(artifact_reference).__name__}"
        )
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise TypeError(
            "artifact content must be bytes, "
            f"not {type(artifact_bytes).__name__}"
        )
    raw = bytes(artifact_bytes)
    if artifact_reference.validation_state != "VALID":
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact reference not valid"
        )
    if content_hash_for_bytes(raw) != artifact_reference.content_hash:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact bytes hash mismatch"
        )
    bound = authorization.artifact
    if (
        artifact_reference.artifact_id != bound.artifact_id
        or artifact_reference.content_hash != bound.content_hash
        or artifact_reference.artifact_type != bound.artifact_type
        or artifact_reference.test_plan_id != bound.test_plan_id
    ):
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact binding mismatch"
        )
    payload = _parse_http_artifact_bytes(raw)
    # H2 safety re-run (shared validators via the artifact gate).
    from ai.researcher.artifact_validator import validate_http_safety
    from ai.researcher.artifact_validator import (
        HttpArtifactContent as TypedContent,
    )

    try:
        typed = TypedContent.model_validate(payload)
    except Exception as exc:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact content malformed"
        ) from exc
    violations = validate_http_safety(typed)
    if violations:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact failed safety recheck"
        )
    return payload


def translate_bounded_request(
    *,
    authorization: object,
    resolution: object,
    evaluation: object,
    artifact_reference: object,
    artifact_bytes: bytes,
    execution_id: str,
) -> BoundedHttpRequest:
    """Translate authorized inputs into an immutable request (5E.1).

    Accepts only typed records. Fails with ``METHOD_NOT_ALLOWED`` for
    forbidden method pairs, ``ARTIFACT_REVALIDATION_FAILED`` for
    artifact drift, and ``TRANSLATION_REJECTED`` for every other
    translation rejection. No socket exists if translation fails:
    this function performs no I/O.
    """
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "translator accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if not isinstance(resolution, TargetResolution):
        raise TypeError(
            "translator accepts only TargetResolution, "
            f"not {type(resolution).__name__}"
        )
    if not isinstance(evaluation, ScopeEvaluation):
        raise TypeError(
            "translator accepts only ScopeEvaluation, "
            f"not {type(evaluation).__name__}"
        )
    if not isinstance(execution_id, str) or not re.match(
        r"^ex-[0-9a-f]{32}$", execution_id
    ):
        raise ExecutorError("TRANSLATION_REJECTED", "malformed execution id")
    if (
        resolution.authorization_id != authorization.authorization_id
        or resolution.execution_id != execution_id
        or evaluation.authorization_id != authorization.authorization_id
        or evaluation.execution_id != execution_id
        or evaluation.resolution_id != resolution.resolution_id
    ):
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "execution binding mismatch"
        )
    # Method-pair re-check at execution time (never schema-only).
    try:
        check_method_pair(
            authorization.plan_method, authorization.artifact_method
        )
    except AuthzError as exc:
        code = exc.code if exc.code in EXECUTOR_ERROR_CODES else "METHOD_NOT_ALLOWED"
        if code == "TRANSLATION_REJECTED":
            raise ExecutorError("TRANSLATION_REJECTED", "method pair mismatch") from exc
        raise ExecutorError("METHOD_NOT_ALLOWED", "forbidden method pair") from exc
    payload = _revalidate_artifact(
        authorization=authorization,
        artifact_reference=artifact_reference,  # type: ignore[arg-type]
        artifact_bytes=artifact_bytes,
    )
    method = payload.get("method", "GET")
    if method not in ALLOWED_METHODS or method in FORBIDDEN_METHODS:
        raise ExecutorError("METHOD_NOT_ALLOWED", "forbidden artifact method")
    if (
        method != authorization.plan_method
        or method != authorization.artifact_method
    ):
        raise ExecutorError("TRANSLATION_REJECTED", "artifact method mismatch")
    path = payload.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048:
        raise ExecutorError("TRANSLATION_REJECTED", "artifact path rejected")
    if _has_controls(path):
        raise ExecutorError("TRANSLATION_REJECTED", "artifact path rejected")
    query_params = payload.get("query_params", {})
    if not isinstance(query_params, dict):
        raise ExecutorError("TRANSLATION_REJECTED", "artifact query rejected")
    if len(query_params) > MAX_QUERY_PARAMS:
        raise ExecutorError("TRANSLATION_REJECTED", "too many query params")
    clean_params: list[tuple[str, str]] = []
    for name, value in query_params.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ExecutorError("TRANSLATION_REJECTED", "query types rejected")
        if not name or len(name) > MAX_QUERY_NAME or len(value) > MAX_QUERY_VALUE:
            raise ExecutorError("TRANSLATION_REJECTED", "query bounds rejected")
        if _has_controls(name) or _has_controls(value):
            raise ExecutorError("TRANSLATION_REJECTED", "query controls rejected")
        if _is_secret_param_name(name) or scrubber.contains_secret_shape(value):
            raise ExecutorError(
                "TRANSLATION_REJECTED", "credential-shaped query rejected"
            )
        clean_params.append((name, value))
    query_string = urlencode(clean_params)
    if len(query_string) > MAX_QUERY_PARAMS * (MAX_QUERY_NAME + MAX_QUERY_VALUE + 2):
        raise ExecutorError("TRANSLATION_REJECTED", "query encoding rejected")
    raw_headers = payload.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise ExecutorError("TRANSLATION_REJECTED", "artifact headers rejected")
    headers: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, value in raw_headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ExecutorError("TRANSLATION_REJECTED", "header types rejected")
        lowered = name.strip().casefold()
        if (
            lowered not in SAFE_REQUEST_HEADERS
            or lowered in _FORBIDDEN_HEADER_NAMES
            or lowered.startswith("proxy-")
        ):
            raise ExecutorError("TRANSLATION_REJECTED", "header not allowlisted")
        if lowered in seen:
            raise ExecutorError("TRANSLATION_REJECTED", "duplicate header rejected")
        seen.add(lowered)
        if _has_controls(name) or _has_controls(value):
            raise ExecutorError("TRANSLATION_REJECTED", "header controls rejected")
        if len(value) > 1024:
            raise ExecutorError("TRANSLATION_REJECTED", "header value too long")
        if scrubber.contains_secret_shape(value):
            raise ExecutorError("TRANSLATION_REJECTED", "header secret rejected")
        headers.append((lowered, value))
    body_raw = payload.get("body")
    body: bytes | None = None
    if body_raw is not None:
        if not isinstance(body_raw, str):
            raise ExecutorError("TRANSLATION_REJECTED", "body type rejected")
        body = body_raw.encode("utf-8")
        if len(body) > _REQUEST_BODY_MAX:
            raise ExecutorError("TRANSLATION_REJECTED", "body over ceiling")
    has_content_type = "content-type" in seen
    if body is None and has_content_type:
        raise ExecutorError("TRANSLATION_REJECTED", "content-type without body")
    if body is not None and not has_content_type:
        raise ExecutorError("TRANSLATION_REJECTED", "body without content-type")
    final_headers: list[tuple[str, str]] = []
    has_ua = False
    for name, value in headers:
        if name == "user-agent":
            has_ua = True
            if value != FIXED_USER_AGENT:
                raise ExecutorError("TRANSLATION_REJECTED", "user-agent rejected")
            final_headers.append((name, FIXED_USER_AGENT))
        elif name == "content-type":
            if value.strip().casefold() != FIXED_CONTENT_TYPE:
                raise ExecutorError("TRANSLATION_REJECTED", "content-type rejected")
            final_headers.append((name, FIXED_CONTENT_TYPE))
        else:
            final_headers.append((name, value))
    if not has_ua:
        final_headers.append(("user-agent", FIXED_USER_AGENT))
    canonical_url = (
        f"{resolution.scheme}://{resolution.canonical_host}"
        + (
            ""
            if resolution.effective_port == _DEFAULT_PORTS[resolution.scheme]
            else f":{resolution.effective_port}"
        )
        + path
        + (f"?{query_string}" if query_string else "")
    )
    return BoundedHttpRequest(
        method=method,
        scheme=resolution.scheme,
        canonical_host=resolution.canonical_host,
        effective_port=resolution.effective_port,
        path=path,
        query_string=query_string,
        headers=tuple(final_headers),
        body=body,
        artifact_id=authorization.artifact.artifact_id,
        artifact_content_hash=authorization.artifact.content_hash,
        canonical_url=canonical_url,
        authorization_id=authorization.authorization_id,
        execution_id=execution_id,
        resolution_id=resolution.resolution_id,
        evaluation_id=evaluation.evaluation_id,
        program_name=authorization.target.program_name,
    )


# ------------------------------------------------------------------
# 5E.2 — IP-pinned transport seam
# ------------------------------------------------------------------

class SocketFactory(Protocol):
    """Explicit IP-literal connection seam (the core security boundary).

    ``connect`` dials an IP literal only and MUST raise on hostnames,
    empty strings, URLs, or non-literal destinations. The transport
    never performs resolution: there is no hostname-taking method on
    this interface by design.
    """

    def connect(self, ip_literal: str, port: int, timeout: float): ...


def require_ip_literal(value: object) -> str:
    """Fail-closed IP-literal gate shared by transport and tests."""
    if not isinstance(value, str) or not value:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "dial target not a string")
    if "/" in value or "?" in value or "#" in value or "@" in value:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "dial target not literal")
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "dial target not literal") from exc
    if value.strip() != str(parsed):
        # Non-canonical text (padding, zones, mapped aliases) is not
        # a literal the factory may dial.
        if "%" in value:
            raise ExecutorError("DIAL_BINDING_MISMATCH", "scoped address denied")
    return str(parsed)


class RealSocketFactory:
    """Production socket factory: permanently gated in Phase 5E.

    Always raises ``LIVE_GATE_BLOCKED``. A live adapter requires the
    B1+B2 reviews; until then no implementation path can dial.
    """

    def connect(self, ip_literal: str, port: int, timeout: float):  # noqa: ARG002
        raise ExecutorError(
            "LIVE_GATE_BLOCKED",
            "live dial blocked pending B1 production source review",
        )


# ------------------------------------------------------------------
# 5E.3 — TLS wrapper seam
# ------------------------------------------------------------------

class TlsWrapper(Protocol):
    """Explicit TLS seam: wrap a connected IP socket with SNI pinning."""

    def wrap(self, raw_sock: object, *, sni_host: str, timeout: float): ...


class SystemTlsWrapper:
    """Production TLS wrapper: permanently gated in Phase 5E.

    The normative pattern (dial IP literally, SNI + hostname
    verification against the canonical hostname, system CA store,
    TLS >= 1.2, no custom roots, no insecure mode) is specified here
    and enforced by tests against fakes; the live mechanism requires
    the B1+B2 reviews.
    """

    def wrap(self, raw_sock: object, *, sni_host: str, timeout: float):  # noqa: ARG002
        raise ExecutorError(
            "LIVE_GATE_BLOCKED",
            "live TLS blocked pending B1 production source review",
        )


def check_sni_binding(sni_host: str, canonical_host: str) -> None:
    """SNI must equal the canonical hostname exactly (never the IP)."""
    if not isinstance(sni_host, str) or sni_host != canonical_host:
        raise ExecutorError("TRANSPORT_BINDING_FAILURE", "sni binding mismatch")
    try:
        ipaddress.ip_address(sni_host)
    except ValueError:
        return
    raise ExecutorError("TRANSPORT_BINDING_FAILURE", "sni must not be an ip")


# ------------------------------------------------------------------
# 5E.4 — bounded HTTP/1.1 response pipeline
# ------------------------------------------------------------------

@dataclass
class HttpResponse:
    """Bounded parsed HTTP/1.1 response (transport facts only)."""

    status: int
    headers: list[tuple[str, str]]
    body_raw: bytes
    truncated: bool = False
    over_cap: bool = False


def _read_head(
    recv: Callable[[int], bytes],
    pending: bytearray,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, bytearray]:
    """Read one header block, serving previously buffered bytes first."""
    buf = bytearray(pending)
    pending.clear()
    index = buf.find(b"\r\n\r\n")
    while index == -1:
        if clock() > deadline:
            raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
        try:
            chunk = recv(4096)
        except TimeoutError as exc:
            raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
        except (ConnectionError, OSError) as exc:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
        if chunk is None:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error")
        if not isinstance(chunk, (bytes, bytearray)):
            raise ExecutorError("TRANSPORT_FAILURE", "connection error")
        if len(chunk) == 0:
            break
        buf += chunk
        if len(buf) > _MAX_HEADER_BLOCK:
            raise ExecutorError("RESPONSE_LIMIT", "header block over cap")
        index = buf.find(b"\r\n\r\n")
    return bytes(buf), pending


def _read_until_marker(
    recv: Callable[[int], bytes],
    marker: bytes,
    cap: int,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    buf = bytearray()
    while True:
        if clock() > deadline:
            raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
        try:
            chunk = recv(4096)
        except TimeoutError as exc:
            raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
        except (ConnectionError, OSError) as exc:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
        if chunk is None:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error")
        if not isinstance(chunk, (bytes, bytearray)):
            raise ExecutorError("TRANSPORT_FAILURE", "connection error")
        if len(chunk) == 0:
            break
        buf += chunk
        if len(buf) > cap:
            raise ExecutorError("RESPONSE_LIMIT", "header block over cap")
        index = buf.find(marker)
        if index != -1:
            return bytes(buf)
    return bytes(buf)


def _parse_status_line(line: bytes) -> tuple[str, int]:
    try:
        text = line.decode("latin-1")
    except ValueError as exc:
        raise ExecutorError("TRANSPORT_FAILURE", "malformed status line") from exc
    parts = text.strip().split(" ", 2)
    if len(parts) < 2:
        raise ExecutorError("TRANSPORT_FAILURE", "malformed status line")
    version, code_text = parts[0], parts[1]
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise ExecutorError("TRANSPORT_FAILURE", "unsupported http version")
    if not re.fullmatch(r"[0-9]{3}", code_text or ""):
        raise ExecutorError("TRANSPORT_FAILURE", "malformed status code")
    code = int(code_text)
    if not 100 <= code <= 599:
        raise ExecutorError("TRANSPORT_FAILURE", "status code out of range")
    return version, code


def _parse_header_block(block: bytes) -> tuple[str, int, list[tuple[str, str]]]:
    text = block.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ExecutorError("TRANSPORT_FAILURE", "malformed status line")
    _, status = _parse_status_line(lines[0].encode("latin-1"))
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line == "":
            break
        if ":" not in line:
            raise ExecutorError("TRANSPORT_FAILURE", "malformed header line")
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if not name or _has_controls(name) or _has_controls(value):
            raise ExecutorError("TRANSPORT_FAILURE", "malformed header line")
        if len(name) > 128 or len(value) > 8192:
            raise ExecutorError("TRANSPORT_FAILURE", "header field over cap")
        headers.append((name.casefold(), value))
    if len(headers) > _MAX_HEADER_LINES:
        raise ExecutorError("TRANSPORT_FAILURE", "too many headers")
    return lines[0], status, headers


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key == name]


def _read_body_stream(
    recv: Callable[[int], bytes],
    *,
    framing: str,
    content_length: int | None,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, bool, bool]:
    """Stream a framed body under the transport cap.

    Returns ``(bytes, truncated, over_cap)``. Never preallocates on
    Content-Length. ``truncated`` marks close/EOF before the framing
    promise completed; ``over_cap`` marks the 512 KiB stop.
    """
    out = bytearray()
    if framing == "none":
        return b"", False, False
    if framing == "content-length":
        assert content_length is not None
        remaining = content_length
        while remaining > 0:
            if clock() > deadline:
                raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
            try:
                chunk = recv(min(16384, remaining))
            except TimeoutError as exc:
                raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
            except (ConnectionError, OSError) as exc:
                raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
            if not chunk:
                return bytes(out), True, False
            out += chunk
            if len(out) > _RESPONSE_TRANSPORT_MAX:
                return bytes(out[:_RESPONSE_TRANSPORT_MAX]), False, True
            remaining -= len(chunk)
        if len(out) > _RESPONSE_TRANSPORT_MAX:
            return bytes(out[:_RESPONSE_TRANSPORT_MAX]), False, True
        return bytes(out), False, False
    if framing == "chunked":
        while True:
            line = _read_chunk_line(recv, deadline, clock)
            size_text = line.split(b";", 1)[0].strip().decode("latin-1")
            if not re.fullmatch(r"[0-9a-fA-F]{1,8}", size_text or ""):
                raise ExecutorError("TRANSPORT_FAILURE", "malformed chunk size")
            size = int(size_text, 16)
            if size == 0:
                _read_chunk_line(recv, deadline, clock)
                break
            remaining = size
            while remaining > 0:
                if clock() > deadline:
                    raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
                try:
                    chunk = recv(min(16384, remaining))
                except TimeoutError as exc:
                    raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
                except (ConnectionError, OSError) as exc:
                    raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
                if not chunk:
                    return bytes(out), True, False
                out += chunk
                if len(out) > _RESPONSE_TRANSPORT_MAX:
                    return bytes(out[:_RESPONSE_TRANSPORT_MAX]), False, True
                remaining -= len(chunk)
            _read_chunk_line(recv, deadline, clock)
        return bytes(out), False, False
    # close-delimited
    while True:
        if clock() > deadline:
            raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
        try:
            chunk = recv(16384)
        except TimeoutError as exc:
            raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
        except (ConnectionError, OSError) as exc:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
        if not chunk:
            return bytes(out), False, False
        out += chunk
        if len(out) > _RESPONSE_TRANSPORT_MAX:
            return bytes(out[:_RESPONSE_TRANSPORT_MAX]), False, True


def _read_chunk_line(
    recv: Callable[[int], bytes],
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    buf = bytearray()
    while True:
        if clock() > deadline:
            raise ExecutorError("TRANSPORT_TIMEOUT", "wall deadline exceeded")
        try:
            chunk = recv(1)
        except TimeoutError as exc:
            raise ExecutorError("TRANSPORT_TIMEOUT", "stall timeout") from exc
        except (ConnectionError, OSError) as exc:
            raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
        if not chunk:
            raise ExecutorError("TRANSPORT_FAILURE", "truncated chunk framing")
        buf += chunk
        if len(buf) > _MAX_HEADER_LINE:
            raise ExecutorError("TRANSPORT_FAILURE", "chunk line over cap")
        if buf.endswith(b"\r\n"):
            return bytes(buf[:-2])


def receive_http_response(
    recv: Callable[[int], bytes],
    *,
    method: str,
    deadline: float,
    clock: Callable[[], float],
) -> HttpResponse:
    """Bounded HTTP/1.1 receive: 1xx skip, framing, caps (5E.4)."""
    pending = bytearray()
    while True:
        raw, pending = _read_head(recv, pending, deadline, clock)
        marker = raw.find(b"\r\n\r\n")
        if marker == -1:
            raise ExecutorError("TRANSPORT_FAILURE", "malformed header block")
        head, status, headers = _parse_header_block(raw[: marker + 4])
        _ = head
        leftover = raw[marker + 4 :]
        if 100 <= status < 200:
            # 1xx is interim: any pipelined bytes belong to the final
            # response and are carried forward, never discarded.
            pending = bytearray(leftover) + pending
            continue
        if method == "HEAD" or status in (204, 304):
            return HttpResponse(status=status, headers=headers, body_raw=b"")
        te_values = _header_values(headers, "transfer-encoding")
        cl_values = _header_values(headers, "content-length")
        framing = "close"
        content_length: int | None = None
        if te_values:
            tokens = [t.strip().casefold() for v in te_values for t in v.split(",")]
            tokens = [t for t in tokens if t]
            if not tokens or tokens[-1] != "chunked":
                if "chunked" in tokens:
                    raise ExecutorError(
                        "TRANSPORT_FAILURE", "chunked not final coding"
                    )
                raise ExecutorError(
                    "TRANSPORT_FAILURE", "unsupported transfer coding"
                )
            framing = "chunked"
        elif cl_values:
            if len(cl_values) > 1 and len(set(cl_values)) > 1:
                raise ExecutorError("TRANSPORT_FAILURE", "ambiguous content length")
            text = cl_values[0].strip()
            if not re.fullmatch(r"[0-9]{1,10}", text or ""):
                raise ExecutorError("TRANSPORT_FAILURE", "malformed content length")
            content_length = int(text)
            framing = "content-length"
        buffered = leftover
        if framing == "none":
            body, truncated, over_cap = b"", False, False
        else:
            queue: list[bytes] = []
            if buffered:
                queue.append(buffered)
            if pending:
                queue.append(bytes(pending))
                pending.clear()
            def _recv(n: int) -> bytes:
                if queue:
                    piece = queue.pop(0)
                    if len(piece) > n:
                        queue.insert(0, piece[n:])
                        return piece[:n]
                    return piece
                return recv(n)
            body, truncated, over_cap = _read_body_stream(
                _recv, framing=framing, content_length=content_length,
                deadline=deadline, clock=clock,
            )
        return HttpResponse(
            status=status, headers=headers, body_raw=body,
            truncated=truncated, over_cap=over_cap,
        )


def decode_body(
    body: bytes, content_encoding: str | None
) -> tuple[bytes, str | None]:
    """Bounded gzip/deflate decode with ratio + output caps (5E.4).

    Returns ``(decoded, None)`` on success. Identity/absence passes
    through. Unsupported encodings map deterministically to
    ``DECOMPRESSION_LIMIT`` (only identity/gzip/deflate are
    implemented; anything else is never passed through raw).
    """
    encoding = (content_encoding or "").strip().casefold()
    if encoding in ("", "identity"):
        return bytes(body), None
    if encoding not in ("gzip", "x-gzip", "deflate"):
        raise ExecutorError("DECOMPRESSION_LIMIT", "unsupported content encoding")
    wbits = 31 if encoding in ("gzip", "x-gzip") else -15
    try:
        decoder = zlib.decompressobj(wbits)
    except Exception as exc:
        raise ExecutorError("DECOMPRESSION_LIMIT", "decoder init failed") from exc
    out = bytearray()
    compressed_len = len(body)
    try:
        chunk = decoder.decompress(body, _DECOMPRESSED_MAX + 1)
    except Exception as exc:
        raise ExecutorError("DECOMPRESSION_LIMIT", "decompression failed") from exc
    out += chunk
    if decoder.eof is False and decoder.unused_data:
        pass
    if len(out) > _DECOMPRESSED_MAX:
        raise ExecutorError("DECOMPRESSION_LIMIT", "decompressed output over cap")
    if compressed_len > 0 and len(out) > _COMPRESSION_RATIO * compressed_len:
        raise ExecutorError("DECOMPRESSION_LIMIT", "compression ratio exceeded")
    if len(out) == _DECOMPRESSED_MAX + 1:
        raise ExecutorError("DECOMPRESSION_LIMIT", "decompressed output over cap")
    return bytes(out), None


def _text_eligible(content_type: str) -> bool:
    lowered = (content_type or "").casefold()
    return any(
        marker in lowered
        for marker in ("text/", "json", "xml", "x-www-form-urlencoded", "javascript")
    )


def observe_transport_body(
    body: bytes, *, content_type: str = "", sample_budget: int
) -> tuple[str, str | None, str | None]:
    """Hash-what-you-store body observation (5E.7/5E.8).

    Text samples are scrubbed with the shared scrubber BEFORE hashing:
    ``body_hash`` covers exactly the stored (redacted, capped) sample
    bytes when a sample is stored, else the raw bytes for
    hash-only (binary/undecodable) content.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("observe_transport_body accepts only bytes")
    raw = bytes(body)
    if not _text_eligible(content_type):
        return hash_mod.sha256_hex(raw), None, "binary-content-type"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return hash_mod.sha256_hex(raw), None, "undecodable-bytes"
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    redacted = scrubber.scrub_text(normalized)
    encoded = redacted.encode("utf-8")
    if len(encoded) <= sample_budget:
        return hash_mod.sha256_hex(encoded), redacted, None
    capped = encoded[:sample_budget].decode("utf-8", errors="ignore")
    return hash_mod.sha256_hex(capped.encode("utf-8")), capped, "over-sample-budget"


# ------------------------------------------------------------------
# 5E.5 — redirect helpers
# ------------------------------------------------------------------

def _visited_key(scheme: str, host: str, port: int, path: str, query: str) -> str:
    return f"{scheme}://{host}:{port}{path}" + (f"?{query}" if query else "")


def parse_redirect_location(
    *,
    location: str | None,
    locations: list[str],
    current_url: str,
    execution_class: str,
) -> tuple[str, str, str, int, str, str]:
    """Validate + absolutize one redirect Location (5E.5).

    Returns ``(canonical_url, host, scheme, port, path, query)``.
    Rejects (``REDIRECT_INVALID``): missing/multiple/userinfo/
    controls/backslash/over-long/unsafe-scheme/malformed/ambiguous
    authority/invalid port/encoded tricks. Downgrade https->http is
    ``REDIRECT_INVALID``; upgrade http->https only for ``http_probe``.
    IP-literal destinations are ``REDIRECT_NOT_IN_SCOPE`` (no-IP
    policy). Credential-bearing values are ``REDIRECT_INVALID``.
    """
    if location is None or len(locations) != 1:
        raise ExecutorError("REDIRECT_INVALID", "location missing or ambiguous")
    if not isinstance(location, str) or not location:
        raise ExecutorError("REDIRECT_INVALID", "location empty")
    if len(location) > MAX_LOCATION_LENGTH:
        raise ExecutorError("REDIRECT_INVALID", "location over cap")
    if any(ord(c) < 32 or ord(c) == 127 for c in location):
        raise ExecutorError("REDIRECT_INVALID", "location controls rejected")
    if "\\" in location:
        raise ExecutorError("REDIRECT_INVALID", "location backslash rejected")
    try:
        joined = urljoin(current_url, location)
    except ValueError as exc:
        raise ExecutorError("REDIRECT_INVALID", "location join failed") from exc
    try:
        parts = urlsplit(joined)
    except ValueError as exc:
        raise ExecutorError("REDIRECT_INVALID", "location parse failed") from exc
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ExecutorError("REDIRECT_INVALID", "location scheme rejected")
    netloc = parts.netloc or ""
    if "@" in netloc or parts.username is not None or parts.password is not None:
        raise ExecutorError("REDIRECT_INVALID", "location userinfo rejected")
    raw_host = parts.hostname or ""
    if not raw_host:
        raise ExecutorError("REDIRECT_INVALID", "location host missing")
    # Decoded-once re-check for %00/%2e-at-authority tricks.
    try:
        decoded = unquote(raw_host + parts.path)
    except Exception as exc:
        raise ExecutorError("REDIRECT_INVALID", "location decode failed") from exc
    if "\x00" in decoded or "@" in unquote(raw_host) or "\\" in decoded:
        raise ExecutorError("REDIRECT_INVALID", "location encoding trick")
    try:
        host, kind = canonicalize_host(raw_host)
    except (CanonicalizationError, TypeError) as exc:
        raise ExecutorError("REDIRECT_INVALID", "location host rejected") from exc
    if kind != "dns":
        raise ExecutorError("REDIRECT_NOT_IN_SCOPE", "ip redirect not in scope")
    try:
        port = parts.port
    except ValueError as exc:
        raise ExecutorError("REDIRECT_INVALID", "location port rejected") from exc
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise ExecutorError("REDIRECT_INVALID", "location port rejected")
    current_scheme = (urlsplit(current_url).scheme or "").lower()
    if current_scheme == "https" and scheme == "http":
        raise ExecutorError("REDIRECT_INVALID", "https downgrade denied")
    if current_scheme == "http" and scheme == "https":
        if execution_class != "http_probe":
            raise ExecutorError("REDIRECT_INVALID", "http upgrade denied")
    path = parts.path or "/"
    query = parts.query or ""
    if len(path) > 2048 or _has_controls(path) or _has_controls(query):
        raise ExecutorError("REDIRECT_INVALID", "location target rejected")
    if scrubber.contains_secret_shape(query):
        raise ExecutorError("REDIRECT_INVALID", "credential-bearing redirect")
    canonical_url = _visited_key(scheme, host, port, path, query)
    display = f"{scheme}://{host}" + (
        "" if port == _DEFAULT_PORTS[scheme] else f":{port}"
    ) + path + (f"?{query}" if query else "")
    _ = display
    return canonical_url, host, scheme, port, path, query


def redirect_method_for(status: int, method: str) -> tuple[str, bool]:
    """Explicit redirect method mapping (never library behavior).

    Returns ``(next_method, keep_body)``. 303 always becomes GET;
    301/302 convert POST/PUT/PATCH to GET (legacy-compatible); 307/308
    preserve. Bodies are re-attached only by the hop builder when the
    status preserves AND the hop stays on the same exact host.
    """
    if status == 303:
        return ("GET", False)
    if status in (301, 302) and method in ("POST", "PUT", "PATCH"):
        return ("GET", False)
    return (method, True)


# ------------------------------------------------------------------
# Deps / records / result
# ------------------------------------------------------------------

class HopResolver(Protocol):
    """Per-hop re-resolution + re-evaluation boundary (B1 interface).

    Production implementation deferred (B1). Tests inject fakes that
    return genuine ``TargetResolution`` + ``ScopeEvaluation`` records.
    """

    def resolve_hop(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        canonical_host: str,
        scheme: str,
        effective_port: int,
        path: str,
        query: str,
        now: str,
    ) -> tuple[TargetResolution, ScopeEvaluation]: ...


class AuditSink(Protocol):
    """Append-only audit boundary (B2 interface for production)."""

    def append(self, record: AuditRecord) -> None: ...


class InMemoryAuditSink:
    """Deterministic offline audit sink (raises only via ``fail_from``)."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self.fail_from: int | None = None

    def append(self, record: AuditRecord) -> None:
        if not isinstance(record, AuditRecord):
            raise TypeError(
                "audit sink accepts only AuditRecord, "
                f"not {type(record).__name__}"
            )
        if self.fail_from is not None and record.seq >= self.fail_from:
            raise ev.EvidenceError("AUDIT_GAP", "audit sink unavailable")
        self.records.append(record.model_copy(deep=True))


def compute_request_fingerprint(
    *, canonical_url: str, method: str, body_hash: str, dialed_ip: str
) -> str:
    """Per-hop request fingerprint binding evaluated==dialed."""
    return hash_mod.hash_payload(
        {
            "body_hash": body_hash,
            "canonical_url": canonical_url,
            "dialed_ip": dialed_ip,
            "method": method,
        }
    )


@dataclass(frozen=True)
class HopRecord:
    """Per-hop transport facts binding authorized/evaluated/dialed."""

    hop_index: int
    execution_id: str
    authorization_id: str
    resolution_id: str
    evaluation_id: str
    program_name: str
    canonical_host: str
    scheme: str
    effective_port: int
    dialed_ip: str
    sni_host: str
    method: str
    artifact_id: str
    canonical_url: str
    request_fingerprint: str
    status: int | None = None


@dataclass
class ExecutorDeps:
    """Injected executor dependencies (all offline fakes in 5E)."""

    authz_store: Any = None
    ledger: Any = None
    audit: Any = None
    hop_resolver: Any = None
    socket_factory: Any = None
    tls_wrapper: Any = None
    now_iso: Callable[[], str] | None = None
    monotonic: Callable[[], float] | None = None

    def now(self) -> str:
        if self.now_iso is None:
            return datetime.now(timezone.utc).isoformat()
        return self.now_iso()

    def clock(self) -> float:
        if self.monotonic is None:
            return time.monotonic()
        return self.monotonic()


@dataclass(frozen=True)
class HttpExecutionResult:
    """Terminal execution outcome (accounting, never a verdict)."""

    execution_id: str
    authorization_id: str
    outcome: str
    error_code: str | None
    error_detail: str
    evidence: ev.EvidenceRecord | None
    hops: tuple[HopRecord, ...]
    dial_ips: tuple[str, ...]
    redirect_chain: tuple[str, ...]
    transport_outcome: str
    audit_gap: bool = False


# ------------------------------------------------------------------
# Internal guards
# ------------------------------------------------------------------

_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")


def _check_binding(
    *,
    authorization: IssuedExecutionAuthorization,
    resolution: TargetResolution,
    evaluation: ScopeEvaluation,
    execution_id: str,
) -> None:
    if resolution.authorization_id != authorization.authorization_id:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "resolution authorization mismatch"
        )
    if resolution.execution_id != execution_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "resolution execution mismatch"
        )
    if evaluation.authorization_id != authorization.authorization_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "evaluation authorization mismatch"
        )
    if evaluation.execution_id != execution_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "evaluation execution mismatch"
        )
    if evaluation.resolution_id != resolution.resolution_id:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "evaluation resolution mismatch"
        )
    if resolution.status != "RESOLVED":
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "resolution not resolved"
        )
    bound = authorization.target
    if resolution.program_name != bound.program_name:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "program mismatch")
    try:
        authz_host, _ = canonicalize_host(bound.host)
    except (CanonicalizationError, TypeError) as exc:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "target not canonical") from exc
    if authz_host != resolution.canonical_host:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "canonical host mismatch"
        )
    if (
        resolution.scheme != bound.scheme
        or resolution.effective_port != bound.effective_port
    ):
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "scheme or port mismatch"
        )
    recomputed = canonical_target_hash_for(
        program_name=resolution.program_name,
        canonical_host=resolution.canonical_host,
        scheme=resolution.scheme,
        effective_port=resolution.effective_port,
    )
    if recomputed != resolution.canonical_target_hash:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "canonical target hash mismatch"
        )
    dial = resolution.dial
    if (
        dial is None
        or tuple(dial.addresses) != tuple(resolution.resolved_addresses)
        or dial.effective_port != resolution.effective_port
        or dial.sni_host != resolution.canonical_host
        or dial.pin_required is not True
    ):
        raise ExecutorError("DIAL_BINDING_MISMATCH", "dial binding incoherent")
    if len(resolution.resolved_addresses) == 0:
        raise ExecutorError("DNS_OBSERVATION_FAILED", "empty address set")
    if len(resolution.resolved_addresses) > _DNS_ANSWERS_MAX:
        raise ExecutorError("DNS_OBSERVATION_FAILED", "answer set over ceiling")
    for address in resolution.resolved_addresses:
        try:
            classify_address(address)
        except DnsError as exc:
            raise ExecutorError("UNSAFE_ADDRESS", "unsafe dial address") from exc
    if resolution.scope_lists_hash_current != bound.scope_lists_hash:
        raise ExecutorError("SCOPE_DRIFT", "resolution scope stale")


# ------------------------------------------------------------------
# 5E.6 — lifecycle orchestration
# ------------------------------------------------------------------

_NON_IDEMPOTENT = frozenset({"POST", "PUT", "PATCH"})

_TRANSPORT_OUTCOME_MAP = {
    None: "responded",
    "TRANSPORT_TIMEOUT": "timeout",
    "TLS_FAILURE": "connection_error",
    "TRANSPORT_FAILURE": "connection_error",
    "TRANSPORT_BINDING_FAILURE": "connection_error",
    "DNS_OBSERVATION_FAILED": "connection_error",
    "RESPONSE_LIMIT": "aborted_limit",
    "DECOMPRESSION_LIMIT": "aborted_limit",
    "REDIRECT_LIMIT": "aborted_limit",
    "REDIRECT_INVALID": "aborted_limit",
    "REDIRECT_NOT_IN_SCOPE": "aborted_limit",
}


class _PinnedHttpExecutor:
    """Single-execution lifecycle driver (5E.6, exact 16-step order)."""

    def __init__(self, deps: ExecutorDeps) -> None:
        if not isinstance(deps, ExecutorDeps):
            raise TypeError(
                "executor accepts only ExecutorDeps, "
                f"not {type(deps).__name__}"
            )
        for attr in (
            "authz_store",
            "ledger",
            "audit",
            "hop_resolver",
            "socket_factory",
            "tls_wrapper",
        ):
            if getattr(deps, attr, None) is None:
                raise TypeError(f"executor deps missing: {attr}")
        for attr in ("authz_store", "ledger", "audit", "hop_resolver",
                     "socket_factory", "tls_wrapper"):
            value = getattr(deps, attr)
            if not isinstance(value, (dict, list, str, bytes, int)):
                continue
            raise TypeError(f"executor dep not injectable: {attr}")
        self._deps = deps
        self._audit_seq = 0

    # -- gates ------------------------------------------------------

    def _check_live_gate(self) -> None:
        # B1 seam (reviewed, still disabled): the ONLY live pair ever
        # admitted is the exact reviewed (LiveSocketFactory,
        # LiveTlsWrapper) type pair from ai.execution.live_transport,
        # and only when LIVE_TRAFFIC_ENABLED is True under a
        # separately authorized activation. Class-name tricks are
        # rejected: admission requires exact type identity against
        # the imported classes, never a name comparison.
        factory = self._deps.socket_factory
        if self._is_reviewed_b1_live_pair(
            factory, self._deps.tls_wrapper
        ):
            if LIVE_TRAFFIC_ENABLED:
                return
            raise ExecutorError(
                "LIVE_GATE_BLOCKED", "live traffic disabled (B1)"
            )
        if LIVE_TRAFFIC_ENABLED:
            raise ExecutorError(
                "LIVE_GATE_BLOCKED", "live traffic switch must stay off in 5E"
            )
        if isinstance(factory, RealSocketFactory):
            raise ExecutorError(
                "LIVE_GATE_BLOCKED", "production dial path not reviewed (B1)"
            )
        if type(factory).__name__ == "RealSocketFactory":
            raise ExecutorError(
                "LIVE_GATE_BLOCKED", "production dial path not reviewed (B1)"
            )

    @staticmethod
    def _is_reviewed_b1_live_pair(factory: object, tls: object) -> bool:
        """True only for the exact reviewed B1 live type pair."""

        try:
            from ai.execution import live_transport as _live
        except Exception:
            return False
        return (
            type(factory) is _live.LiveSocketFactory
            and type(factory).__module__ == _live.__name__
            and type(tls) is _live.LiveTlsWrapper
            and type(tls).__module__ == _live.__name__
        )

    # -- audit ------------------------------------------------------

    def _audit_append(
        self,
        *,
        execution_id: str,
        authorization: IssuedExecutionAuthorization,
        transition: str,
        evidence: ev.EvidenceRecord | None = None,
        error_code: str | None = None,
        scope_decision: str | None = None,
    ) -> None:
        record = AuditRecord(
            seq=self._audit_seq,
            execution_id=execution_id,
            authorization_id=authorization.authorization_id,
            evidence_id=evidence.evidence_id if evidence is not None else None,
            transition=transition,  # type: ignore[arg-type]
            at=self._deps.now(),
            actor="http-executor/5E",
            program_name=authorization.target.program_name,
            host=authorization.target.host,
            scope_decision=scope_decision,
            artifact_id=authorization.artifact.artifact_id,
            artifact_content_hash=authorization.artifact.content_hash,
            evidence_hashes=(
                {
                    "bindings_hash": evidence.bindings_hash,
                    "observations_hash": evidence.observations_hash,
                    "content_hash": evidence.content_hash,
                }
                if evidence is not None
                and evidence.bindings_hash is not None
                and evidence.observations_hash is not None
                and evidence.content_hash is not None
                else {}
            ),
            error_code=error_code,
        )
        self._deps.audit.append(record)
        self._audit_seq += 1

    def _audit_gap(
        self,
        *,
        execution_id: str,
        authorization: IssuedExecutionAuthorization,
        missing_from: str,
    ) -> None:
        try:
            self._deps.audit.append(
                gap_record(
                    seq=self._audit_seq,
                    execution_id=execution_id,
                    authorization_id=authorization.authorization_id,
                    missing_from=missing_from,
                    at=self._deps.now(),
                    actor="http-executor/5E",
                )
            )
            self._audit_seq += 1
        except Exception:
            pass

    # -- ledger + consume (steps 8-10) --------------------------------

    def _claim_and_consume(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
    ):
        """Ledger claim + authorization CAS + STARTED (at-most-once)."""
        from ai.authorizer.service import consume_authorization
        from ai.execution.ledger import (
            ExecutionRecord,
            InProgressExecutionError,
            LedgerError,
            ReplayExecutionError,
        )

        ledger = self._deps.ledger
        for method_name in (
            "put_new",
            "mark_started",
            "mark_sealed",
            "mark_incomplete",
            "mark_unknown",
        ):
            if not callable(getattr(ledger, method_name, None)):
                raise TypeError(f"ledger missing capability: {method_name}")
        now = self._deps.now()
        try:
            ledger.put_new(
                ExecutionRecord(
                    execution_id=execution_id,
                    authorization_id=authorization.authorization_id,
                    execution_stage="single",
                    idempotency_key=authorization.idempotency_key,
                )
            )
        except ReplayExecutionError as exc:
            raise ExecutorError("EXECUTION_REPLAY", "authorization already used") from exc
        except Exception as exc:
            if type(exc).__name__ in (
                "ReplayExecutionError",
                "DuplicateExecutionError",
            ):
                raise ExecutorError(
                    "EXECUTION_REPLAY", "authorization already used"
                ) from exc
            if type(exc).__name__ == "InProgressExecutionError":
                raise ExecutorError("EXECUTION_REPLAY", "execution in progress") from exc
            raise ExecutorError("OUTCOME_UNKNOWN", "ledger claim ambiguous") from exc
        try:
            consumed = consume_authorization(
                self._deps.authz_store,
                authorization.authorization_id,
                now=now,
            )
        except AuthzError as exc:
            raise ExecutorError(
                "EXECUTION_ALREADY_CONSUMED", "authorization consume lost"
            ) from exc
        except Exception as exc:
            raise ExecutorError(
                "EXECUTION_ALREADY_CONSUMED", "authorization consume lost"
            ) from exc
        try:
            ledger.mark_started(execution_id, started_at=now)
        except Exception as exc:
            if type(exc).__name__ == "InProgressExecutionError":
                raise ExecutorError("EXECUTION_REPLAY", "execution in progress") from exc
            # Consume succeeded but STARTED is ambiguous: never retry
            # under this authorization (5H crash semantics).
            try:
                ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            raise ExecutorError("OUTCOME_UNKNOWN", "start state ambiguous") from exc
        return consumed

    # -- wire framing ---------------------------------------------------

    def _build_wire_bytes(
        self,
        request: BoundedHttpRequest,
        host_header: str,
        *,
        for_method: str,
        body_bytes: bytes | None,
    ) -> bytes:
        target = request.path + (
            f"?{request.query_string}" if request.query_string else ""
        )
        lines = [f"{for_method} {target} HTTP/1.1"]
        lines.append(f"Host: {host_header}")
        lines.append("Connection: close")
        lines.append("Accept-Encoding: identity, gzip, deflate")
        for name, value in request.headers:
            if name == "content-type" and body_bytes is None:
                continue
            lines.append(f"{name}: {value}")
        if body_bytes is not None:
            lines.append(f"Content-Length: {len(body_bytes)}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        if body_bytes is not None:
            return head + body_bytes
        return head

    def _host_header(self, request: BoundedHttpRequest) -> str:
        if request.effective_port == _DEFAULT_PORTS[request.scheme]:
            return request.canonical_host
        return f"{request.canonical_host}:{request.effective_port}"

    # -- single-hop transport (5E.2/5E.3/5E.4) ---------------------------

    def _run_transport(
        self,
        *,
        request: BoundedHttpRequest,
        dial: DialBinding,
        hop_index: int,
        deadline: float,
        for_method: str | None = None,
        body_bytes: bytes | None = ...,  # type: ignore[assignment]
    ) -> dict[str, Any]:
        """Dial the pinned IP and perform one bounded exchange."""
        method = for_method or request.method
        body = request.body if body_bytes is ... else body_bytes
        if not dial.addresses:
            raise ExecutorError("DIAL_BINDING_MISMATCH", "empty dial binding")
        dial_ip = require_ip_literal(dial.addresses[0])
        if dial_ip not in [require_ip_literal(a) for a in dial.addresses]:
            raise ExecutorError("DIAL_BINDING_MISMATCH", "dial ip not pinned")
        if dial.effective_port != request.effective_port:
            raise ExecutorError("DIAL_BINDING_MISMATCH", "dial port mismatch")
        if dial.sni_host != request.canonical_host:
            raise ExecutorError("DIAL_BINDING_MISMATCH", "dial sni mismatch")
        is_tls = request.scheme == "https"
        sni_host = request.canonical_host
        host_header = self._host_header(request)
        sent_any = False
        received_any = False
        try:
            self._check_live_gate()
            try:
                sock = self._deps.socket_factory.connect(
                    dial_ip, dial.effective_port, _CONNECT_TIMEOUT
                )
            except ExecutorError:
                raise
            except TimeoutError as exc:
                raise ExecutorError("TRANSPORT_TIMEOUT", "connect timeout") from exc
            except (ConnectionError, OSError) as exc:
                raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
            except Exception as exc:
                raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
            try:
                if is_tls:
                    check_sni_binding(sni_host, request.canonical_host)
                    try:
                        sock = self._deps.tls_wrapper.wrap(
                            sock, sni_host=sni_host, timeout=_CONNECT_TIMEOUT
                        )
                    except ExecutorError:
                        raise
                    except Exception as exc:
                        raise ExecutorError("TLS_FAILURE", "tls handshake failed") from exc
                try:
                    peer = sock.getpeername()
                except Exception as exc:
                    raise ExecutorError(
                        "TRANSPORT_BINDING_FAILURE", "peer identity unavailable"
                    ) from exc
                actual_peer = peer[0] if isinstance(peer, (list, tuple)) and peer else None
                if actual_peer != dial_ip:
                    raise ExecutorError(
                        "TRANSPORT_BINDING_FAILURE", "peer address mismatch"
                    )
                try:
                    if hasattr(sock, "settimeout"):
                        sock.settimeout(_READ_TIMEOUT)
                except Exception as exc:
                    raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
                wire = self._build_wire_bytes(
                    request, host_header, for_method=method, body_bytes=body,
                )
                try:
                    offset = 0
                    while offset < len(wire):
                        if self._deps.clock() > deadline:
                            raise ExecutorError(
                                "TRANSPORT_TIMEOUT", "wall deadline exceeded"
                            )
                        sock.sendall(wire[offset : offset + 16384])
                        sent_any = True
                        offset += 16384
                except ExecutorError:
                    raise
                except TimeoutError as exc:
                    raise ExecutorError("TRANSPORT_TIMEOUT", "send stall") from exc
                except (ConnectionError, OSError) as exc:
                    raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
                except Exception as exc:
                    raise ExecutorError("TRANSPORT_FAILURE", "connection error") from exc
                underlying_recv = sock.recv

                def _counting_recv(n: int) -> bytes:
                    nonlocal received_any
                    chunk = underlying_recv(n)
                    if chunk:
                        received_any = True
                    return chunk

                response = receive_http_response(
                    _counting_recv, method=method,
                    deadline=deadline, clock=self._deps.clock,
                )
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except ExecutorError as exc:
            if (
                exc.code == "TRANSPORT_TIMEOUT"
                and method in _NON_IDEMPOTENT
                and sent_any
                and not received_any
            ):
                # A non-idempotent request with bytes on the wire may
                # have acted server-side; claiming bytes would be
                # dishonest: UNKNOWN with no evidence bytes.
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "transport outcome unknown"
                ) from exc
            raise
        encodings = [v for k, v in response.headers if k == "content-encoding"]
        decoded = response.body_raw
        if encodings:
            if len(encodings) > 1 or "," in encodings[0]:
                raise ExecutorError("DECOMPRESSION_LIMIT", "multi-coded body")
            decoded, _ = decode_body(response.body_raw, encodings[0])
        return {
            "dial_ip": dial_ip,
            "sni_host": sni_host,
            "host_header": host_header,
            "method": method,
            "response": response,
            "decoded_body": decoded,
        }

    # -- redirect state machine (5E.5) ------------------------------------

    def _redirect_loop(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        request: BoundedHttpRequest,
        dial: DialBinding,
        deadline: float,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Manual redirect loop: at most 5 edges, 7 requests (5E.5).

        Returns ``(hop_transports, terminal_error_code)`` where the
        terminal code is ``None`` on a final (non-redirect) response.
        Every hop repeats parse -> canonicalize -> scheme-gate ->
        fresh resolve -> fresh evaluate -> require_allowed -> pin ->
        dial -> bounded exchange -> observation. No stage skippable.
        """
        hops: list[dict[str, Any]] = []
        hop_entries: list[dict[str, Any]] = [
            {
                "request": request,
                "dial": dial,
                "resolution_id": request.resolution_id,
                "evaluation_id": request.evaluation_id,
                "canonical_url": request.canonical_url,
                "for_method": request.method,
                "body_bytes": request.body,
            }
        ]
        visited = {
            _visited_key(
                request.scheme, request.canonical_host,
                request.effective_port, request.path, request.query_string,
            )
        }
        edges = 0
        terminal: str | None = None
        index = 0
        while index < len(hop_entries):
            if len(hops) >= MAX_REQUESTS_PER_EXECUTION:
                terminal = "REDIRECT_LIMIT"
                break
            entry = hop_entries[index]
            hop_request = entry["request"]
            transport = self._run_transport(
                request=hop_request,
                dial=entry["dial"],
                hop_index=index,
                deadline=deadline,
                for_method=entry["for_method"],
                body_bytes=entry["body_bytes"],
            )
            transport["resolution_id"] = entry["resolution_id"]
            transport["evaluation_id"] = entry["evaluation_id"]
            transport["canonical_url"] = entry["canonical_url"]
            transport["hop_request"] = hop_request
            hops.append(transport)
            response: HttpResponse = transport["response"]
            if response.over_cap:
                terminal = "RESPONSE_LIMIT"
                break
            if response.truncated:
                raise ExecutorError("TRANSPORT_FAILURE", "truncated body")
            if response.status not in REDIRECT_STATUSES:
                break
            # --- redirect edge processing (manual, no inheritance) ---
            edges += 1
            if edges > MAX_REDIRECT_EDGES:
                terminal = "REDIRECT_LIMIT"
                break
            locations = [v for k, v in response.headers if k == "location"]
            location = locations[0] if locations else None
            try:
                canonical_url, host, scheme, port, path, query = (
                    parse_redirect_location(
                        location=location,
                        locations=locations,
                        current_url=transport["canonical_url"],
                        execution_class=authorization.execution_class,
                    )
                )
            except ExecutorError as exc:
                if exc.code in ("REDIRECT_INVALID", "REDIRECT_NOT_IN_SCOPE"):
                    terminal = exc.code
                    break
                raise
            if canonical_url in visited:
                terminal = "REDIRECT_INVALID"
                break
            allowed_ports = {80, 443, request.effective_port}
            if port not in allowed_ports:
                terminal = "REDIRECT_NOT_IN_SCOPE"
                break
            try:
                hop_resolution, hop_evaluation = self._deps.hop_resolver.resolve_hop(
                    authorization=authorization,
                    execution_id=execution_id,
                    canonical_host=host,
                    scheme=scheme,
                    effective_port=port,
                    path=path,
                    query=query,
                    now=self._deps.now(),
                )
            except ExecutorError as exc:
                terminal = exc.code
                break
            except (DnsError, ValueError) as exc:
                terminal = "DNS_OBSERVATION_FAILED"
                break
            except Exception as exc:
                raise ExecutorError("DNS_OBSERVATION_FAILED", "hop resolve failed") from exc
            if not isinstance(hop_resolution, TargetResolution) or not isinstance(
                hop_evaluation, ScopeEvaluation
            ):
                raise ExecutorError(
                    "RESOLUTION_BINDING_MISMATCH", "hop binding not typed"
                )
            self._validate_hop_binding(
                authorization=authorization,
                execution_id=execution_id,
                hop_resolution=hop_resolution,
                hop_evaluation=hop_evaluation,
                expect_host=host,
                expect_scheme=scheme,
                expect_port=port,
            )
            next_method, keep_body = redirect_method_for(
                response.status, transport["method"]
            )
            hop_body: bytes | None = None
            if keep_body and response.status in (307, 308) and host == hop_request.canonical_host:
                hop_body = entry["body_bytes"]
                next_method = transport["method"]
            hop_request_next = BoundedHttpRequest(
                method=next_method,
                scheme=scheme,
                canonical_host=host,
                effective_port=port,
                path="/" + path.lstrip("/") if not path.startswith("/") else path,
                query_string=query,
                headers=hop_request.headers,
                body=hop_body,
                artifact_id=hop_request.artifact_id,
                artifact_content_hash=hop_request.artifact_content_hash,
                canonical_url=(
                    f"{scheme}://{host}"
                    + ("" if port == _DEFAULT_PORTS[scheme] else f":{port}")
                    + (path if path.startswith("/") else "/" + path)
                    + (f"?{query}" if query else "")
                ),
                authorization_id=hop_request.authorization_id,
                execution_id=execution_id,
                resolution_id=hop_resolution.resolution_id,
                evaluation_id=hop_evaluation.evaluation_id,
                program_name=hop_request.program_name,
            )
            visited.add(canonical_url)
            hop_entries.append(
                {
                    "request": hop_request_next,
                    "dial": hop_resolution.dial,  # type: ignore[union-attr]
                    "resolution_id": hop_resolution.resolution_id,
                    "evaluation_id": hop_evaluation.evaluation_id,
                    "canonical_url": hop_request_next.canonical_url,
                    "for_method": next_method,
                    "body_bytes": hop_body,
                }
            )
            index += 1
            continue
        return hops, terminal

    def _validate_hop_binding(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        hop_resolution: TargetResolution,
        hop_evaluation: ScopeEvaluation,
        expect_host: str,
        expect_scheme: str,
        expect_port: int,
    ) -> None:
        """Fresh-hop authorization: never inherits the previous hop."""
        from ai.scope.evaluator import require_allowed

        if hop_resolution.authorization_id != authorization.authorization_id:
            raise ExecutorError(
                "RESOLUTION_BINDING_MISMATCH", "hop authorization mismatch"
            )
        if hop_resolution.execution_id != execution_id:
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "hop execution mismatch"
            )
        if hop_resolution.program_name != authorization.target.program_name:
            raise ExecutorError("TARGET_BINDING_MISMATCH", "hop program mismatch")
        if (
            hop_resolution.canonical_host != expect_host
            or hop_resolution.scheme != expect_scheme
            or hop_resolution.effective_port != expect_port
        ):
            raise ExecutorError(
                "RESOLUTION_BINDING_MISMATCH", "hop target mismatch"
            )
        if hop_resolution.status != "RESOLVED":
            raise ExecutorError(
                "RESOLUTION_BINDING_MISMATCH", "hop not resolved"
            )
        recomputed = canonical_target_hash_for(
            program_name=hop_resolution.program_name,
            canonical_host=hop_resolution.canonical_host,
            scheme=hop_resolution.scheme,
            effective_port=hop_resolution.effective_port,
        )
        if recomputed != hop_resolution.canonical_target_hash:
            raise ExecutorError(
                "RESOLUTION_BINDING_MISMATCH", "hop target hash mismatch"
            )
        hop_dial = hop_resolution.dial
        if (
            hop_dial is None
            or tuple(hop_dial.addresses) != tuple(hop_resolution.resolved_addresses)
            or hop_dial.effective_port != hop_resolution.effective_port
            or hop_dial.sni_host != hop_resolution.canonical_host
            or hop_dial.pin_required is not True
        ):
            raise ExecutorError("DIAL_BINDING_MISMATCH", "hop dial incoherent")
        if not hop_resolution.resolved_addresses:
            raise ExecutorError("DNS_OBSERVATION_FAILED", "hop address set empty")
        if len(hop_resolution.resolved_addresses) > _DNS_ANSWERS_MAX:
            raise ExecutorError("DNS_OBSERVATION_FAILED", "hop answers over ceiling")
        for address in hop_resolution.resolved_addresses:
            try:
                classify_address(address)
            except DnsError as exc:
                raise ExecutorError("UNSAFE_ADDRESS", "hop address unsafe") from exc
        if hop_evaluation.decision != "ALLOWED":
            # Preserve the 5D hop code (drift/exclusion) instead of
            # collapsing everything through the transport gate.
            if hop_evaluation.failure_code == "SCOPE_DRIFT":
                raise ExecutorError("SCOPE_DRIFT", "hop policy drift")
            if hop_evaluation.failure_code == "TARGET_EXCLUDED":
                raise ExecutorError("REDIRECT_NOT_IN_SCOPE", "hop excluded")
        try:
            require_allowed(
                hop_evaluation,
                authorization_id=authorization.authorization_id,
                execution_id=execution_id,
                resolution_id=hop_resolution.resolution_id,
            )
        except TypeError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == "AUTHZ_BINDING_MISMATCH":
                raise ExecutorError(
                    "AUTHZ_BINDING_MISMATCH", "hop evaluation mismatch"
                ) from exc
            if code in ("TARGET_EXCLUDED", "TARGET_NOT_IN_SCOPE"):
                raise ExecutorError("REDIRECT_NOT_IN_SCOPE", "hop not in scope") from exc
            if code == "SCOPE_DRIFT":
                raise ExecutorError("SCOPE_DRIFT", "hop policy drift") from exc
            raise ExecutorError("REDIRECT_NOT_IN_SCOPE", "hop not allowed") from exc

    # -- evidence (5E.7/5E.8) -----------------------------------------------

    def _observe_and_seal(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        request: BoundedHttpRequest,
        hops: list[dict[str, Any]],
        terminal: str | None,
    ) -> tuple[ev.EvidenceRecord, str, bool]:
        """Build the 5H observation and seal SEALED/INCOMPLETE (5E.7).

        Returns ``(record, transport_outcome, complete)``. Transport
        failure before any byte still seals an INCOMPLETE observation;
        only an empty hop list (nothing dialed) seals a no-response
        INCOMPLETE record.
        """
        if not hops:
            observation = self._build_no_response_observation(
                request=request, error_code=terminal or "TRANSPORT_FAILURE"
            )
            sealed = self._seal_evidence(
                authorization=authorization,
                execution_id=execution_id,
                observation=observation,
                complete=False,
                reasons=("response_missing",),
            )
            return sealed, _TRANSPORT_OUTCOME_MAP.get(terminal, "connection_error"), False
        last = hops[-1]
        response: HttpResponse | None = last.get("response")
        observation = self._build_final_observation(
            authorization=authorization,
            execution_id=execution_id,
            request=request,
            hops=hops,
            response=response,
            decoded_body=last.get("decoded_body", b""),
            error_code=terminal,
        )
        complete = terminal is None and response is not None
        if complete and (response.status is None or observation.response_body_hash is None):
            complete = False
        if complete:
            sealed = self._seal_evidence(
                authorization=authorization,
                execution_id=execution_id,
                observation=observation,
                complete=True,
                reasons=(),
            )
            return sealed, "responded", True
        reasons = ("response_missing",) if response is None else ("channels_partial",)
        if terminal in ("RESPONSE_LIMIT", "DECOMPRESSION_LIMIT", "REDIRECT_LIMIT"):
            reasons = ("body_over_cap",) if terminal != "REDIRECT_LIMIT" else ("chain_over_cap",)
        sealed = self._seal_evidence(
            authorization=authorization,
            execution_id=execution_id,
            observation=observation,
            complete=False,
            reasons=reasons,
        )
        return sealed, _TRANSPORT_OUTCOME_MAP.get(terminal, "connection_error"), False

    def _build_no_response_observation(
        self, *, request: BoundedHttpRequest, error_code: str
    ) -> ev.HttpObservation:
        request_url = obs.observe_url(request.canonical_url)
        request_headers = obs.filter_headers(
            {name: value for name, value in request.headers},
            allowlist=obs.REQUEST_HEADER_ALLOWLIST,
        )
        body_hash, body_sample, omitted = observe_transport_body(
            request.body or b"",
            content_type="application/x-www-form-urlencoded"
            if request.body is not None
            else "text/plain",
            sample_budget=obs.MAX_REQUEST_SAMPLE,
        )
        return ev.HttpObservation(
            method=request.method,  # type: ignore[arg-type]
            request_url=request_url,
            request_headers=request_headers,
            request_body_hash=body_hash,
            request_body_sample=body_sample,
            response_status=None,
            response_headers=ev.HeaderSnapshot(headers={}, truncated=False),
            response_body_hash=hash_mod.sha256_hex(b""),
            response_body_sample=None,
            sample_omitted="no-response",
            redirect_chain=[],
            chain_truncated=False,
            dial_ips=(),
            transport_outcome=_TRANSPORT_OUTCOME_MAP.get(  # type: ignore[arg-type]
                error_code, "connection_error"
            ),
        )

    def _build_final_observation(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        request: BoundedHttpRequest,
        hops: list[dict[str, Any]],
        response: HttpResponse | None,
        decoded_body: bytes,
        error_code: str | None,
    ) -> ev.HttpObservation:
        _ = authorization
        _ = execution_id
        last = hops[-1]
        last_request: BoundedHttpRequest = last["hop_request"]
        request_url = obs.observe_url(last_request.canonical_url)
        request_headers = obs.filter_headers(
            {name: value for name, value in last_request.headers},
            allowlist=obs.REQUEST_HEADER_ALLOWLIST,
        )
        req_hash, req_sample, _req_omitted = observe_transport_body(
            last_request.body or b"",
            content_type="application/x-www-form-urlencoded"
            if last_request.body is not None
            else "text/plain",
            sample_budget=obs.MAX_REQUEST_SAMPLE,
        )
        chain_urls = [str(h["canonical_url"]) for h in hops]
        redirect_chain, chain_truncated = obs.observe_redirect_chain(chain_urls)
        dial_ips = tuple(str(h["dial_ip"]) for h in hops)
        if response is None:
            return ev.HttpObservation(
                method=last_request.method,  # type: ignore[arg-type]
                request_url=request_url,
                request_headers=request_headers,
                request_body_hash=req_hash,
                request_body_sample=req_sample,
                response_status=None,
                response_headers=ev.HeaderSnapshot(headers={}, truncated=False),
                response_body_hash=hash_mod.sha256_hex(b""),
                response_body_sample=None,
                sample_omitted="no-response",
                redirect_chain=redirect_chain,
                chain_truncated=chain_truncated,
                dial_ips=dial_ips,
                transport_outcome=_TRANSPORT_OUTCOME_MAP.get(  # type: ignore[arg-type]
                    error_code, "connection_error"
                ),
            )
        resp_headers_raw = {name: value for name, value in response.headers}
        resp_headers = obs.filter_headers(
            resp_headers_raw, allowlist=obs.RESPONSE_HEADER_ALLOWLIST
        )
        content_type = resp_headers_raw.get("content-type", "")
        body_hash, body_sample, omitted = observe_transport_body(
            decoded_body,
            content_type=content_type,
            sample_budget=_RESPONSE_SAMPLE_MAX,
        )
        if response.truncated and omitted is None:
            omitted = "over-sample-budget"
        return ev.HttpObservation(
            method=last_request.method,  # type: ignore[arg-type]
            request_url=request_url,
            request_headers=request_headers,
            request_body_hash=req_hash,
            request_body_sample=req_sample,
            response_status=response.status,
            response_headers=resp_headers,
            response_body_hash=body_hash,
            response_body_sample=body_sample,
            sample_omitted=omitted,
            redirect_chain=redirect_chain,
            chain_truncated=chain_truncated,
            dial_ips=dial_ips,
            transport_outcome=_TRANSPORT_OUTCOME_MAP.get(  # type: ignore[arg-type]
                error_code, "responded"
            ),
        )

    def _seal_evidence(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        observation: ev.HttpObservation,
        complete: bool,
        reasons: tuple[str, ...],
    ) -> ev.EvidenceRecord:
        try:
            builder = EvidenceBuilder.begin(
                authorization=authorization,
                execution_id=execution_id,
                execution_stage="single",
                execution_class=authorization.execution_class,
                started_at=self._deps.now(),
            )
            builder.attach_http(observation)
            if complete:
                return builder.seal(
                    finished_at=self._deps.now(), sealed_at=self._deps.now()
                )
            return builder.seal_partial(
                reasons=reasons,
                finished_at=self._deps.now(),
                sealed_at=self._deps.now(),
            )
        except ev.EvidenceError as exc:
            raise ExecutorError("EVIDENCE_SEAL_FAILED", "evidence seal failed") from exc
        except ExecutorError:
            raise
        except Exception as exc:
            raise ExecutorError("EVIDENCE_SEAL_FAILED", "evidence seal failed") from exc

    # -- terminal accounting --------------------------------------------------

    def _hop_records(
        self,
        *,
        execution_id: str,
        hops: list[dict[str, Any]],
    ) -> tuple[HopRecord, ...]:
        records: list[HopRecord] = []
        for index, hop in enumerate(hops):
            hop_request: BoundedHttpRequest = hop["hop_request"]
            response = hop.get("response")
            status = response.status if response is not None else None
            records.append(
                HopRecord(
                    hop_index=index,
                    execution_id=execution_id,
                    authorization_id=hop_request.authorization_id,
                    resolution_id=str(hop.get("resolution_id", "")),
                    evaluation_id=str(hop.get("evaluation_id", "")),
                    program_name=hop_request.program_name,
                    canonical_host=hop_request.canonical_host,
                    scheme=hop_request.scheme,
                    effective_port=hop_request.effective_port,
                    dialed_ip=str(hop.get("dial_ip", "")),
                    sni_host=str(hop.get("sni_host", "")),
                    method=str(hop.get("method", hop_request.method)),
                    artifact_id=hop_request.artifact_id,
                    canonical_url=str(hop.get("canonical_url", "")),
                    request_fingerprint=compute_request_fingerprint(
                        canonical_url=str(hop.get("canonical_url", "")),
                        method=str(hop.get("method", hop_request.method)),
                        body_hash=hop_request.body_hash,
                        dialed_ip=str(hop.get("dial_ip", "")),
                    ),
                    status=status,
                )
            )
        return tuple(records)

    def _terminate(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
        hops: list[dict[str, Any]],
        sealed: ev.EvidenceRecord | None,
        complete: bool,
        error: ExecutorError | None,
        transport_outcome: str,
        audit_gap: bool,
    ) -> HttpExecutionResult:
        ledger = self._deps.ledger
        now = self._deps.now()
        outcome = "sealed" if (sealed is not None and complete) else (
            "incomplete" if sealed is not None else "unknown"
        )
        if sealed is not None and complete:
            try:
                ledger.mark_sealed(execution_id, sealed.evidence_id, terminal_at=now)
            except Exception:
                pass
        elif sealed is not None:
            try:
                ledger.mark_incomplete(execution_id, sealed.evidence_id, terminal_at=now)
            except Exception:
                pass
        else:
            try:
                ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
        if sealed is not None:
            try:
                self._audit_append(
                    execution_id=execution_id,
                    authorization=authorization,
                    transition="EVIDENCE_SEALED",
                    evidence=sealed,
                    scope_decision="sealed" if complete else "incomplete",
                )
            except Exception:
                audit_gap = True
                self._audit_gap(
                    execution_id=execution_id,
                    authorization=authorization,
                    missing_from="EVIDENCE_SEALED",
                )
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=authorization,
                transition="EXECUTION_TERMINAL",
                evidence=sealed,
                error_code=error.code if error is not None else None,
                scope_decision=outcome,
            )
        except Exception:
            audit_gap = True
            self._audit_gap(
                execution_id=execution_id,
                authorization=authorization,
                missing_from="EXECUTION_TERMINAL",
            )
        hop_records = self._hop_records(execution_id=execution_id, hops=hops)
        chain = tuple(h.canonical_url for h in hop_records)
        return HttpExecutionResult(
            execution_id=execution_id,
            authorization_id=authorization.authorization_id,
            outcome=outcome,
            error_code=error.code if error is not None else None,
            error_detail=error.detail if error is not None else "",
            evidence=sealed,
            hops=hop_records,
            dial_ips=tuple(h.dialed_ip for h in hop_records),
            redirect_chain=tuple(
                scrubber.redact_url(url)[:2048] for url in chain
            ),
            transport_outcome=transport_outcome,
            audit_gap=audit_gap,
        )

    # -- main entry -------------------------------------------------------------

    def run(
        self,
        *,
        authorization: object,
        resolution: object,
        evaluation: object,
        artifact_reference: object,
        artifact_bytes: bytes,
        execution_id: str,
    ) -> HttpExecutionResult:
        """Exact 16-step lifecycle ordering (5E.6)."""
        # 1. typed input validation.
        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "execution accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}"
            )
        if not isinstance(resolution, TargetResolution):
            raise TypeError(
                "execution accepts only TargetResolution, "
                f"not {type(resolution).__name__}"
            )
        if not isinstance(evaluation, ScopeEvaluation):
            raise TypeError(
                "execution accepts only ScopeEvaluation, "
                f"not {type(evaluation).__name__}"
            )
        if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
            execution_id
        ):
            raise TypeError("execution_id must be a valid ex- handle")
        if not isinstance(artifact_bytes, (bytes, bytearray)):
            raise TypeError("artifact_bytes must be bytes")
        authz = authorization
        res = resolution
        evaln = evaluation
        now = self._deps.now()
        # 2. authorization liveness, re-asserted against a fresh store
        # read (the presented record alone is not rechecked: a stale
        # in-memory copy must never resurrect consumed authority).
        store_get = getattr(self._deps.authz_store, "get", None)
        if not callable(store_get):
            raise TypeError("authorization store missing typed get")
        fresh = store_get(authz.authorization_id)
        if not isinstance(fresh, IssuedExecutionAuthorization):
            raise ExecutorError("AUTHZ_NOT_LIVE", "unknown authorization")
        if fresh.authorization_id != authz.authorization_id:
            raise ExecutorError("AUTHZ_NOT_LIVE", "authorization mismatch")
        try:
            require_live_for_execution(fresh, now=now)
        except Exception as exc:
            raise ExecutorError("AUTHZ_NOT_LIVE", "authorization not live") from exc
        # 3. target/resolution binding validation.
        _check_binding(
            authorization=authz,
            resolution=res,
            evaluation=evaln,
            execution_id=execution_id,
        )
        # 4-5. fresh scope validation + require_allowed().
        from ai.scope.evaluator import require_allowed as _require_allowed

        if evaln.decision != "ALLOWED":
            # Preserve the specific 5D failure code (drift, exclusion,
            # scope miss) instead of collapsing it at the gate.
            code = evaln.failure_code
            if code == "TARGET_EXCLUDED":
                raise ExecutorError("TARGET_EXCLUDED", "target excluded")
            if code == "SCOPE_DRIFT":
                raise ExecutorError("SCOPE_DRIFT", "scope policy drift")
            if code in EXECUTOR_ERROR_CODES:
                raise ExecutorError(code, "scope not allowing")
            raise ExecutorError("TARGET_NOT_IN_SCOPE", "scope not allowing")
        if evaln.scope_lists_hash_current != authz.target.scope_lists_hash:
            raise ExecutorError("SCOPE_DRIFT", "evaluation scope stale")
        try:
            _require_allowed(
                evaln,
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                resolution_id=res.resolution_id,
            )
        except TypeError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == "AUTHZ_BINDING_MISMATCH":
                raise ExecutorError(
                    "AUTHZ_BINDING_MISMATCH", "scope binding mismatch"
                ) from exc
            if code in ("TARGET_EXCLUDED",):
                raise ExecutorError("TARGET_EXCLUDED", "target excluded") from exc
            raise ExecutorError("TARGET_NOT_IN_SCOPE", "scope not allowing") from exc
        # 6-7. artifact revalidation + translation (no socket on failure).
        try:
            request = translate_bounded_request(
                authorization=authz,
                resolution=res,
                evaluation=evaln,
                artifact_reference=artifact_reference,
                artifact_bytes=bytes(artifact_bytes),
                execution_id=execution_id,
            )
        except TypeError:
            raise
        except ExecutorError:
            raise
        # 8-10. ledger claim + authorization CAS + STARTED.
        try:
            self._claim_and_consume(authorization=authz, execution_id=execution_id)
        except ExecutorError as exc:
            # Pre-transport accounting failure: no socket has been
            # opened; the authorization slot stays bound (replay-safe)
            # and retry requires a new authorization.
            return self._terminate(
                authorization=authz,
                execution_id=execution_id,
                hops=[],
                sealed=None,
                complete=False,
                error=exc,
                transport_outcome="connection_error",
                audit_gap=False,
            )
        # 11. audit authorization/execution start (blocks transport).
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=authz,
                transition="AUTHORIZATION",
                scope_decision="authorized",
            )
            self._audit_append(
                execution_id=execution_id,
                authorization=authz,
                transition="EXECUTION_STARTED",
                scope_decision="allowed",
            )
        except Exception as exc:
            try:
                self._deps.ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            self._audit_gap(
                execution_id=execution_id,
                authorization=authz,
                missing_from="EXECUTION_STARTED",
            )
            return self._terminate(
                authorization=authz,
                execution_id=execution_id,
                hops=[],
                sealed=None,
                complete=False,
                error=ExecutorError("AUDIT_GAP", "audit start failed"),
                transport_outcome="connection_error",
                audit_gap=True,
            )
        # 12-13. transport + observation.
        deadline = self._deps.clock() + _HTTP_WALL
        hops: list[dict[str, Any]] = []
        terminal: str | None = None
        terminal_error: ExecutorError | None = None
        try:
            hops, terminal = self._redirect_loop(
                authorization=authz,
                execution_id=execution_id,
                request=request,
                dial=res.dial,  # type: ignore[arg-type]
                deadline=deadline,
            )
            if terminal is not None:
                terminal_error = ExecutorError(terminal, "hop terminal")
        except ExecutorError as exc:
            terminal = exc.code
            terminal_error = exc
        if terminal_error is not None and terminal_error.code == "OUTCOME_UNKNOWN":
            # 15. transport-ambiguous: UNKNOWN, no evidence bytes claimed.
            try:
                self._deps.ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            try:
                self._audit_append(
                    execution_id=execution_id,
                    authorization=authz,
                    transition="EXECUTION_TERMINAL",
                    error_code="OUTCOME_UNKNOWN",
                    scope_decision="unknown",
                )
            except Exception:
                self._audit_gap(
                    execution_id=execution_id,
                    authorization=authz,
                    missing_from="EXECUTION_TERMINAL",
                )
                return self._terminate(
                    authorization=authz,
                    execution_id=execution_id,
                    hops=hops,
                    sealed=None,
                    complete=False,
                    error=terminal_error,
                    transport_outcome="timeout",
                    audit_gap=True,
                )
            return self._terminate(
                authorization=authz,
                execution_id=execution_id,
                hops=hops,
                sealed=None,
                complete=False,
                error=terminal_error,
                transport_outcome="timeout",
                audit_gap=False,
            )
        # 14-16. evidence seal + ledger terminal + audit terminal.
        try:
            sealed, outcome, complete = self._observe_and_seal(
                authorization=authz,
                execution_id=execution_id,
                request=request,
                hops=hops,
                terminal=terminal,
            )
        except ExecutorError as exc:
            try:
                self._deps.ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            return self._terminate(
                authorization=authz,
                execution_id=execution_id,
                hops=hops,
                sealed=None,
                complete=False,
                error=exc,
                transport_outcome="connection_error",
                audit_gap=False,
            )
        return self._terminate(
            authorization=authz,
            execution_id=execution_id,
            hops=hops,
            sealed=sealed,
            complete=complete,
            error=terminal_error,
            transport_outcome=outcome,
            audit_gap=False,
        )


def execute_http(
    *,
    authorization: object,
    resolution: object,
    evaluation: object,
    artifact_reference: object,
    artifact_bytes: bytes,
    execution_id: str,
    deps: ExecutorDeps,
) -> HttpExecutionResult:
    """Typed 5E entry point: the only public call path performing I/O.

    Typed records only (``TypeError`` on dicts/URLs/strings). No other
    public function in this module opens a socket.
    """
    return _PinnedHttpExecutor(deps).run(
        authorization=authorization,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference,
        artifact_bytes=artifact_bytes,
        execution_id=execution_id,
    )
"""Closed-spec Browser/XSS executor (Phase 5G v1).

FAIL-CLOSED posture: this module performs NO live execution, NO
browser launch, NO transport, NO name resolution, and NO process
creation. The live gate is explicit in code (not a comment):

- ``LIVE_BROWSER`` is ``False`` and no code path in this module can
  set it to ``True`` (literal constant; not configurable).
- ``LiveBrowserRunner.launch`` always raises
  ``ExecutorError(BROWSER_EXECUTION_BLOCKED)`` before any browser,
  process, or transport primitive. This module imports no browser
  automation, process-creation, transport, or name-resolution
  facility.
- Offline execution proceeds only through the injected
  ``FakeBrowserRunner`` (deterministic, scripted, no I/O).

A real browser is an autonomous network agent (own DNS, redirect
chain, subresources, script-initiated traffic, frames, workers,
prefetch, update and certificate-status traffic). In-browser hooks
are telemetry, never enforcement, so
``SCOPE-EVALUATED == ACTUALLY-DIALED`` cannot be established here.
Live execution requires the future, separately reviewed B5
network/containment boundary, which is BLOCKING and is NOT
implemented in this phase.

Trust semantics:

- P (authorized/submitted payload) and O (executor-owned executed
  oracle) have separate identities and hashes. Submitted payload is
  never proof of execution; the executor only records observations
  and never compares P and O to issue a classification.
- The browser produces execution facts and observation-only
  evidence. Only deterministic verifier logic in 5I may eventually
  classify evidence; this module emits no classification.
- OOB/callback-based proof is DENIED; no OOB infrastructure exists
  here.

Frozen contracts reused (never duplicated):

- 5B: ``IssuedExecutionAuthorization`` liveness, CAS consume,
  artifact identity, ``XSSDerivationContract`` (P-side binding),
  ``RUN_SALT_AUTHORITY``.
- 5C: ``TargetResolution``, canonical target tuple, dial
  coherence, resolution identity.
- 5D: ``ScopeEvaluation``, ``require_allowed()``.
- 4C: ``ArtifactReference``, ``content_hash_for_bytes``,
  ``max_bytes_for``, ``build_validated_reference``.
- Oracle: ``oracle_seed``, ``oracle_value_from_seed``,
  ``validate_oracle_pair``, ``evaluate_e1_dialog``,
  ``evaluate_e2_network``, ``evaluate_e3_eval``,
  ``ORACLE_PATH_PREFIX``. No new crypto is created here.
- 5H-core: ``EvidenceRecord``, ``BrowserObservation``,
  ``EvidenceBuilder``, ``observe_url``, scrubber, hashing,
  ledger, audit, ceilings.

This module is OFFLINE and DETERMINISTIC (caller-supplied clocks
only).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Callable, Protocol

from ai.audit.trail import AuditRecord, gap_record
from ai.evidence import hashing as hash_mod
from ai.evidence import scrubber
from ai.evidence.builder import EvidenceBuilder
from ai.evidence.observations import observe_url
from ai.limits.ceilings import CEILINGS
from ai.researcher.artifact_validator import build_validated_reference
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.schemas import evidence as ev
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
    max_bytes_for,
)
from ai.schemas.execution_authorization import (
    RUN_SALT_AUTHORITY,
    AuthzError,
    IssuedExecutionAuthorization,
)
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import (
    TargetResolution,
    canonical_target_hash_for,
)
from ai.scope.evaluator import require_allowed
from ai.verification.oracle import (
    evaluate_e1_dialog,
    evaluate_e2_network,
    evaluate_e3_eval,
    oracle_seed,
    oracle_value_from_seed,
    validate_oracle_pair,
)

__all__ = [
    "LIVE_BROWSER",
    "B1_STATUS",
    "B2_STATUS",
    "B4_STATUS",
    "B5_STATUS",
    "SCHEMA_VERSION",
    "SERVER_CONTROLLED_BROWSER_ID",
    "EXECUTOR_ERROR_CODES",
    "ExecutorError",
    "PayloadSafetyReport",
    "validate_browser_payload",
    "OracleBinding",
    "derive_oracle_binding",
    "BrowserContextDescriptor",
    "ResourceLimitsSpec",
    "BROWSER_EVENT_BOUNDS",
    "default_resource_limits",
    "BrowserExecutionSpec",
    "build_target_string",
    "build_browser_environment",
    "context_dir_for",
    "ScriptedHop",
    "ScriptedDialog",
    "ScriptedOracleEvent",
    "ScriptedEvalEvent",
    "ScriptedPostMessage",
    "BrowserRunResult",
    "BrowserRunner",
    "FakeBrowserRunner",
    "LiveBrowserRunner",
    "B5IsolatedBrowserRunner",
    "BrowserExecutorDeps",
    "BrowserExecutionResult",
    "execute_browser",
]

# ------------------------------------------------------------------
# Live gate (explicit, B1+B2+B4+B5 blockers)
# ------------------------------------------------------------------

#: Master live-execution switch. Frozen ``False`` for Phase 5G v1.
#: Literal constant: no configuration, constructor argument, artifact
#: value, CLI flag, database value, or caller input can change it.
LIVE_BROWSER = False

#: B1 BLOCKED (live execution): production ``AddressSource``
#: selection + review deferred. Only injected deterministic fakes
#: supply resolution facts.
B1_STATUS = "BLOCKED: production AddressSource selection/review deferred"

#: B2 BLOCKED (live/multi-worker): production adapters for the
#: authorization store, execution ledger, audit backend, and evidence
#: backend (plus sweep) remain pending. Semantics frozen;
#: mechanism deferred.
B2_STATUS = (
    "BLOCKED: production authorization/ledger/audit/evidence "
    "adapters + sweep deferred"
)

#: B4 deferred/blocking for the later production payload-corpus
#: workflow: payload corpus source-of-truth review outstanding.
B4_STATUS = (
    "BLOCKED: production payload-corpus source-of-truth review deferred"
)

#: B5 BLOCKED: the future browser network/containment boundary
#: (isolated network namespace, forced egress proxy, literal-IP-only
#: DNS stub, egress firewall, process containment, browser sandbox,
#: cgroup controls, seccomp/landlock, process-tree cleanup, pinned
#: browser build) remains pending under separate review. Until B5
#: closes, the offline harness is the only runner and live browser
#: execution is refused before any browser/process primitive.
B5_STATUS = "BLOCKED: browser network/containment boundary remains pending"

#: Executor schema version for the closed execution specification.
SCHEMA_VERSION = "browser_executor/v1"

#: Server-controlled browser identifier. A label only: it is never
#: resolved to a path, never launched, and never passed to any
#: process primitive in 5G v1. It enters the closed spec so a future
#: B5 runner has a single server-owned identity to pin.
SERVER_CONTROLLED_BROWSER_ID = "browser/stable"

# ------------------------------------------------------------------
# Frozen ceilings (reused from 5H-core, never redefined)
# ------------------------------------------------------------------

_BROWSER_WALL = CEILINGS["browser_wall_seconds"]
_BROWSER_PAGES = CEILINGS["browser_pages"]
_BROWSER_CONTEXTS = CEILINGS["browser_contexts"]
_REDIRECT_HOPS = CEILINGS["redirect_hops"]
_TRANSPORT_BYTES = CEILINGS["response_transport_bytes"]
_DECOMPRESSED_BYTES = CEILINGS["decompressed_bytes"]
_TEMP_STORAGE = CEILINGS["temp_storage_bytes"]

#: Compatibility alias over the 5H-centralized browser ceiling keys
#: (single source of truth: ``CEILINGS`` in ``ai/limits/ceilings.py``).
#: This mapping is a read-through view, never authoritative: 5H owns
#: the values. Key names here are the legacy 5G short names; the
#: central keys carry the ``browser_`` prefix.
_BROWSER_EVENT_KEYMAP: tuple[tuple[str, str], ...] = (
    ("dialog_events", "browser_dialog_events"),
    ("frame_events", "browser_frame_events"),
    ("popup_events", "browser_popup_events"),
    ("console_entries", "browser_console_entries"),
    ("oracle_events", "browser_oracle_events"),
    ("dom_observation_bytes", "browser_dom_observation_bytes"),
    ("storage_keys", "browser_storage_keys"),
)


class _BrowserEventBoundsView(dict):  # type: ignore[type-arg]
    """Read-through alias of central browser ceilings (5H-owned)."""

    def __init__(self) -> None:
        super().__init__(
            (short, CEILINGS[central])
            for short, central in _BROWSER_EVENT_KEYMAP
        )


BROWSER_EVENT_BOUNDS: dict[str, int] = _BrowserEventBoundsView()

#: Scratch-profile identity root (pure string derivation; no
#: filesystem access occurs in 5G v1).
_SCRATCH_ROOT = "/srv/watch/scratch/browser"

_DEFAULT_PORTS = {"http": 80, "https": 443}

# ------------------------------------------------------------------
# Closed error vocabulary (deterministic, secret-free)
# ------------------------------------------------------------------

EXECUTOR_ERROR_CODES = frozenset(
    {
        "PAYLOAD_REJECTED",
        "ORACLE_BINDING_MISMATCH",
        "ARTIFACT_REVALIDATION_FAILED",
        "AUTHZ_NOT_FOUND",
        "AUTHZ_NOT_LIVE",
        "AUTHZ_BINDING_MISMATCH",
        "TARGET_BINDING_MISMATCH",
        "RESOLUTION_BINDING_MISMATCH",
        "DIAL_BINDING_MISMATCH",
        "SCOPE_DRIFT",
        "TARGET_NOT_IN_SCOPE",
        "TARGET_EXCLUDED",
        "NAV_MISMATCH",
        "NAV_SCHEME",
        "NAV_USERINFO",
        "NAV_CROSS_ORIGIN",
        "NAV_DOWNGRADE",
        "NAV_PORT_CHANGE",
        "NAV_IP_AUTHORITY",
        "NAV_LOOP",
        "NAV_LIMIT",
        "POPUP_BLOCKED",
        "DOWNLOAD_BLOCKED",
        "SERVICEWORKER_BLOCKED",
        "DOCUMENT_DOMAIN",
        "CHANNELS_OVER_CAP",
        "BROWSER_TIMEOUT",
        "BROWSER_CRASH",
        "BROWSER_EXECUTION_BLOCKED",
        "EVIDENCE_SEAL_FAILED",
        "EXECUTION_REPLAY",
        "EXECUTION_ALREADY_CONSUMED",
        "OUTCOME_UNKNOWN",
        "AUDIT_GAP",
    }
)


class ExecutorError(ValueError):
    """Bounded, secret-free 5G failure with an explicit closed code."""

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
# URL origin parsing without network libraries
# ------------------------------------------------------------------

_ORIGIN_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(/[^?#]*)?(\?[^#]*)?$"
)


def _parse_http_origin(url: object) -> tuple[str, str, int] | None:
    """Parse an http(s) URL into ``(scheme, host, port)``.

    Returns ``None`` for non-http(s) schemes, userinfo-bearing,
    malformed, or out-of-range authorities. Pure string parsing;
    no resolution is performed.
    """
    if not isinstance(url, str):
        return None
    match = _ORIGIN_RE.match(url.strip())
    if match is None:
        return None
    scheme = match.group(1).lower()
    if scheme not in ("http", "https"):
        return None
    authority = match.group(2)
    if not authority or "@" in authority:
        return None
    for char in authority:
        code = ord(char)
        if code <= 32 or code == 127:
            return None
    host: str
    port = _DEFAULT_PORTS[scheme]
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None
        host = authority[1:end].lower()
        rest = authority[end + 1:]
        if rest:
            if not rest.startswith(":"):
                return None
            port_text = rest[1:]
            if not port_text.isdigit():
                return None
            port = int(port_text)
    elif authority.count(":") > 1:
        return None
    else:
        host, sep, port_text = authority.partition(":")
        host = host.lower()
        if sep:
            if not port_text.isdigit():
                return None
            port = int(port_text)
    host = host.rstrip(".")
    if not host or " " in host:
        return None
    if not 1 <= port <= 65535:
        return None
    return (scheme, host, port)


def _has_userinfo(url: str) -> bool:
    match = _ORIGIN_RE.match(url.strip())
    if match is None:
        return False
    return "@" in match.group(2)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _canonical_nav_url(url: str) -> str:
    """Canonical navigation identity for loop detection."""
    match = _ORIGIN_RE.match(url.strip())
    if match is None:  # pragma: no cover - callers pre-validate
        raise ExecutorError("NAV_SCHEME", "navigation not parseable")
    origin = _parse_http_origin(url)
    if origin is None:  # pragma: no cover - callers pre-validate
        raise ExecutorError("NAV_SCHEME", "navigation not parseable")
    scheme, host, port = origin
    path = match.group(3) or "/"
    query = match.group(4) or ""
    return f"{scheme}://{host}:{port}{path}{query}"


# ------------------------------------------------------------------
# 5G payload safety gate (executor-time, P-side only)
# ------------------------------------------------------------------

_ABSOLUTE_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_WS_URL_RE = re.compile(r"wss?://", re.IGNORECASE)
_SCHEME_TRICK_RE = re.compile(
    r"(?<![A-Za-z0-9_.:\-])(?:file|data|blob|javascript):",
    re.IGNORECASE,
)
_OAST_RE = re.compile(r"(?<![A-Za-z])oast(?![A-Za-z])", re.IGNORECASE)
_SCHEME_RELATIVE_AUTHORITY_RE = re.compile(r"""["'(=,]\s*//[A-Za-z0-9]""")

_OOB_MARKERS = (
    "interactsh",
    "oastify",
    "webhook",
    "dnslog",
    "ngrok",
    "burpcollaborator",
    "canarytokens",
    "requestbin",
    "pipedream",
)

#: Payload substrings denied as active destination/escape
#: primitives (casefolded). The payload is DATA for the target's
#: own reflection/storage semantics; it must not carry its own
#: navigation, framing, peer-to-peer, persistence, or exfiltration
#: agency in v1.
_DENIED_PAYLOAD_PRIMITIVES = (
    "<iframe",
    "window.open",
    "showmodaldialog",
    "new websocket",
    "rtcpeerconnection",
    "rtcdatachannel",
    "getusermedia",
    "serviceworker",
    "createobjecturl",
    "mssaveblob",
    ".download(",
)


@dataclass(frozen=True)
class PayloadSafetyReport:
    """Deterministic outcome of the 5G executor-time payload gate."""

    decision: str
    payload_hash: str
    reasons: tuple[str, ...] = ()
    denied_features: tuple[str, ...] = ()


def validate_browser_payload(payload_bytes: object) -> PayloadSafetyReport:
    """5G executor-time XSS payload gate (pure, fail-closed).

    Reuses the central ``xss_payload`` size ceiling and denies
    authority escapes: foreign schemes, absolute URLs, OOB/callback
    markers, framing/popup destinations, peer-to-peer primitives,
    persistence primitives, and download primitives. Script content
    itself (the target's own reflection semantics) is NOT judged
    here; only the payload's outbound agency is denied.
    """
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError(
            "payload validation accepts only bytes, "
            f"not {type(payload_bytes).__name__}"
        )
    raw = bytes(payload_bytes)
    reasons: list[str] = []
    denied: list[str] = []

    def _deny(feature: str, reason: str) -> None:
        denied.append(feature)
        reasons.append(reason)

    ceiling = max_bytes_for("xss_payload")
    digest = content_hash_for_bytes(raw)
    if not raw:
        _deny("payload-empty", "payload must be non-empty")
        return PayloadSafetyReport(
            decision="DENY",
            payload_hash=digest,
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    if len(raw) > ceiling:
        _deny("payload-size", f"payload exceeds {ceiling} bytes")
        return PayloadSafetyReport(
            decision="DENY",
            payload_hash=digest,
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _deny("encoding", "payload bytes are not utf-8")
        return PayloadSafetyReport(
            decision="DENY",
            payload_hash=digest,
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    if "\x00" in text:
        _deny("encoding", "payload must not contain NUL")
    folded = text.casefold()
    if _SCHEME_TRICK_RE.search(text):
        _deny("foreign-scheme", "foreign url scheme denied")
    if _ABSOLUTE_URL_RE.search(text):
        _deny("absolute-url", "absolute url denied in payload")
    if _WS_URL_RE.search(text):
        _deny("websocket", "websocket destination denied")
    if _SCHEME_RELATIVE_AUTHORITY_RE.search(text):
        _deny("external-authority", "scheme-relative authority denied")
    for marker in _OOB_MARKERS:
        if marker in folded:
            _deny("oob-callback", f"oob marker denied: {marker!r}")
            break
    if _OAST_RE.search(text):
        _deny("oob-callback", "oob marker denied: 'oast'")
    for primitive in _DENIED_PAYLOAD_PRIMITIVES:
        if primitive in folded:
            _deny("active-primitive", f"primitive denied: {primitive!r}")
    if denied:
        return PayloadSafetyReport(
            decision="DENY",
            payload_hash=digest,
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    return PayloadSafetyReport(
        decision="ALLOW",
        payload_hash=digest,
        reasons=("payload passed executor-time safety gate",),
        denied_features=(),
    )


# ------------------------------------------------------------------
# Oracle binding (O-side; reuse of frozen oracle math)
# ------------------------------------------------------------------

@dataclass(frozen=True)
class OracleBinding:
    """Executor-owned oracle descriptor bound to one execution.

    ``seed`` (S) travels only inside the closed spec; ``value`` (D)
    is derived deterministically via the frozen ``W`` so the 5I
    verifier can recompute it. ``origin_*`` pins the only origin
    whose signals may become oracle observations.
    """

    seed: str
    value: str
    origin_scheme: str
    origin_host: str
    origin_port: int
    phase: str


def derive_oracle_binding(
    *,
    execution_id: str,
    authorization: IssuedExecutionAuthorization,
    origin: tuple[str, str, str | int],
) -> OracleBinding:
    """Derive and validate the per-execution oracle (pure)."""
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "oracle binding accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    scheme, host, port = origin
    try:
        port_int = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ExecutorError(
            "ORACLE_BINDING_MISMATCH", "oracle origin port rejected"
        ) from exc
    derivation = authorization.xss_derivation
    phase = derivation.execution_phase if derivation is not None else "oracle"
    seed = oracle_seed(RUN_SALT_AUTHORITY, execution_id, phase)
    value = oracle_value_from_seed(seed)
    try:
        validate_oracle_pair(seed, value)
    except ValueError as exc:
        raise ExecutorError(
            "ORACLE_BINDING_MISMATCH", "oracle pair invalid"
        ) from exc
    return OracleBinding(
        seed=seed,
        value=value,
        origin_scheme=scheme,
        origin_host=host,
        origin_port=port_int,
        phase=phase,
    )


# ------------------------------------------------------------------
# Closed execution specification
# ------------------------------------------------------------------

@dataclass(frozen=True)
class BrowserContextDescriptor:
    """Ephemeral single-use context profile (structural, v1).

    Exactly one context and one page; no extensions, credentials,
    stored state, or persistent profile. A persistent profile is
    unrepresentable: any non-``None`` value fails closed here.
    """

    ephemeral: bool = True
    contexts: int = 1
    pages: int = 1
    extensions: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    storage: str = "none"
    credentials: bool = False
    password_manager: bool = False
    sync: bool = False
    permissions: tuple[str, ...] = ()
    persistent_profile: str | None = None
    popups_denied: bool = True
    downloads_denied: bool = True
    serviceworkers_denied: bool = True

    def __post_init__(self) -> None:
        if self.ephemeral is not True:
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "context must be ephemeral"
            )
        if self.contexts != 1 or self.pages != 1:
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "single context/page only"
            )
        if self.extensions or self.cookies or self.permissions:
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "no inherited browser state"
            )
        if self.storage != "none":
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "no browser storage profile"
            )
        if self.credentials or self.password_manager or self.sync:
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "no credentials or sync"
            )
        if self.persistent_profile is not None:
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "persistent profile denied"
            )
        if not (
            self.popups_denied
            and self.downloads_denied
            and self.serviceworkers_denied
        ):
            raise ExecutorError(
                "TARGET_BINDING_MISMATCH", "deny flags must hold"
            )


@dataclass(frozen=True)
class ResourceLimitsSpec:
    """Recorded resource bounds (5G.7).

    Ceiling values are read from 5H ``CEILINGS``; the event-count
    dimensions resolve through the ``BROWSER_EVENT_BOUNDS``
    read-through alias of the central ``browser_*`` ceiling keys
    (5H-owned single source of truth). No active enforcement
    lives here: enforcement belongs to the future B5 boundary.
    """

    wall_seconds: int
    pages: int
    contexts: int
    redirects: int
    exchanges: int
    response_bytes: int
    decompressed_bytes: int
    scratch_bytes: int
    dialogs: int
    frames: int
    popups: int
    console_entries: int
    oracle_events: int
    dom_bytes: int
    storage_keys: int


def default_resource_limits() -> ResourceLimitsSpec:
    """Record the frozen limit set (central ceilings via alias)."""
    return ResourceLimitsSpec(
        wall_seconds=_BROWSER_WALL,
        pages=_BROWSER_PAGES,
        contexts=_BROWSER_CONTEXTS,
        redirects=_REDIRECT_HOPS,
        exchanges=CEILINGS["requests_per_execution"],
        response_bytes=_TRANSPORT_BYTES,
        decompressed_bytes=_DECOMPRESSED_BYTES,
        scratch_bytes=_TEMP_STORAGE,
        dialogs=BROWSER_EVENT_BOUNDS["dialog_events"],
        frames=BROWSER_EVENT_BOUNDS["frame_events"],
        popups=BROWSER_EVENT_BOUNDS["popup_events"],
        console_entries=BROWSER_EVENT_BOUNDS["console_entries"],
        oracle_events=BROWSER_EVENT_BOUNDS["oracle_events"],
        dom_bytes=BROWSER_EVENT_BOUNDS["dom_observation_bytes"],
        storage_keys=BROWSER_EVENT_BOUNDS["storage_keys"],
    )


@dataclass(frozen=True)
class BrowserExecutionSpec:
    """Immutable closed browser execution specification.

    Carries only validated, bound values. No arbitrary target,
    executable, flags, environment, proxy, DNS server, or callback
    field exists: those inputs are structurally unrepresentable.
    """

    execution_id: str
    authorization_id: str
    program_name: str
    canonical_host: str
    scheme: str
    effective_port: int
    target_string: str
    artifact_id: str
    payload_hash: str
    oracle: OracleBinding
    context: BrowserContextDescriptor
    environment: tuple[tuple[str, str], ...]
    limits: ResourceLimitsSpec
    schema_version: str = SCHEMA_VERSION


# ------------------------------------------------------------------
# Pure deterministic builders
# ------------------------------------------------------------------

def build_target_string(
    *,
    scheme: str,
    canonical_host: str,
    effective_port: int,
    path: str = "/",
) -> str:
    """Authority-bound initial navigation URL (binding only)."""
    if scheme not in ("http", "https"):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "scheme rejected")
    if not isinstance(effective_port, int) or isinstance(
        effective_port, bool
    ):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "port rejected")
    if not 1 <= effective_port <= 65535:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "port rejected")
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or _ABSOLUTE_URL_RE.search(path) is not None
    ):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "path rejected")
    base = f"{scheme}://{canonical_host}"
    if effective_port != _DEFAULT_PORTS[scheme]:
        base += f":{effective_port}"
    return base + path


def build_browser_environment(
    *, context_dir: str
) -> tuple[tuple[str, str], ...]:
    """Closed environment allowlist (pure; no inherited values).

    The only input is the validated context directory. There is no
    caller-environment parameter by construction, and no proxy,
    PAC, DNS, or secret variable exists in the allowlist.
    """
    if not isinstance(context_dir, str) or not context_dir.startswith(
        _SCRATCH_ROOT + "/"
    ):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "context dir rejected")
    return (
        ("HOME", context_dir),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("TMPDIR", context_dir),
    )


def context_dir_for(execution_id: str) -> str:
    """Deterministic context path bound to the execution."""
    if not isinstance(execution_id, str) or not re.fullmatch(
        r"ex-[0-9a-f]{32}", execution_id
    ):
        raise ExecutorError("AUTHZ_BINDING_MISMATCH", "execution id rejected")
    return f"{_SCRATCH_ROOT}/{execution_id}"


# ------------------------------------------------------------------
# Runner model (offline harness + blocked live runners)
# ------------------------------------------------------------------

@dataclass(frozen=True)
class ScriptedHop:
    """One scripted navigation fact (URL only; no I/O occurs)."""

    url: str


@dataclass(frozen=True)
class ScriptedDialog:
    """One scripted dialog fact with its origin."""

    kind: str
    message: str
    origin: str


@dataclass(frozen=True)
class ScriptedOracleEvent:
    """One scripted oracle-channel fact (E1/E2 shape carrier)."""

    channel: str
    marker: str
    url: str
    is_navigation: bool
    origin: str


@dataclass(frozen=True)
class ScriptedEvalEvent:
    """One scripted eval-family invocation fact (E3 shape carrier)."""

    operator: str
    value: str


@dataclass(frozen=True)
class ScriptedPostMessage:
    """One scripted postMessage fact (observation only, never proof)."""

    origin: str
    data: str


@dataclass(frozen=True)
class BrowserRunResult:
    """Offline navigation/execution facts from the injected runner."""

    navigations: tuple[ScriptedHop, ...] = ()
    final_url: str = ""
    dialogs: tuple[ScriptedDialog, ...] = ()
    oracle_events: tuple[ScriptedOracleEvent, ...] = ()
    eval_events: tuple[ScriptedEvalEvent, ...] = ()
    console: tuple[str, ...] = ()
    storage_keys: tuple[str, ...] = ()
    postmessages: tuple[ScriptedPostMessage, ...] = ()
    document_domain_relaxed: bool = False
    popup_attempted: bool = False
    download_attempted: bool = False
    serviceworker_attempted: bool = False
    timed_out: bool = False
    crashed: bool = False
    channels_truncated: bool = False


class BrowserRunner(Protocol):
    """Injected runner seam. Receives only the closed spec."""

    def launch(self, spec: BrowserExecutionSpec) -> BrowserRunResult: ...


class FakeBrowserRunner:
    """Deterministic offline runner (the only v1 execution path).

    Never launches browsers, never creates processes, never resolves
    names, never opens transports. Records every invocation and
    returns the scripted navigation/oracle/dialog/error facts.
    """

    def __init__(self, scripted: BrowserRunResult | None = None) -> None:
        self._scripted = scripted or BrowserRunResult()
        self.invocations: list[BrowserExecutionSpec] = []

    def launch(self, spec: BrowserExecutionSpec) -> BrowserRunResult:
        if not isinstance(spec, BrowserExecutionSpec):
            raise TypeError(
                "runner accepts only BrowserExecutionSpec, "
                f"not {type(spec).__name__}"
            )
        if LIVE_BROWSER:
            raise ExecutorError(
                "BROWSER_EXECUTION_BLOCKED", "live gate must stay closed"
            )
        self.invocations.append(spec)
        scripted = self._scripted
        return BrowserRunResult(
            navigations=tuple(scripted.navigations),
            final_url=scripted.final_url,
            dialogs=tuple(scripted.dialogs),
            oracle_events=tuple(scripted.oracle_events),
            eval_events=tuple(scripted.eval_events),
            console=tuple(scripted.console),
            storage_keys=tuple(scripted.storage_keys),
            postmessages=tuple(scripted.postmessages),
            document_domain_relaxed=scripted.document_domain_relaxed,
            popup_attempted=scripted.popup_attempted,
            download_attempted=scripted.download_attempted,
            serviceworker_attempted=scripted.serviceworker_attempted,
            timed_out=scripted.timed_out,
            crashed=scripted.crashed,
            channels_truncated=scripted.channels_truncated,
        )


class LiveBrowserRunner:
    """Permanently blocked live runner (5G v1 ships blocked).

    Raises ``BROWSER_EXECUTION_BLOCKED`` before any browser, process,
    or transport primitive. No escape hatch exists.
    """

    def launch(self, spec: BrowserExecutionSpec) -> BrowserRunResult:
        raise ExecutorError(
            "BROWSER_EXECUTION_BLOCKED",
            "live browser execution blocked pending B5 review",
        )


class B5IsolatedBrowserRunner:
    """Documented future live-runner interface (placeholder only).

    Represents the only acceptable future live runner shape
    (isolated network namespace with explicit egress under B5). It
    cannot execute: every call raises ``BROWSER_EXECUTION_BLOCKED``
    until the B5 review lands and replaces this placeholder under
    that review. No B5 mechanism is implemented here.
    """

    def launch(self, spec: BrowserExecutionSpec) -> BrowserRunResult:
        raise ExecutorError(
            "BROWSER_EXECUTION_BLOCKED",
            "B5 boundary not reviewed; cannot execute",
        )


# ------------------------------------------------------------------
# Deps / result
# ------------------------------------------------------------------

@dataclass
class BrowserExecutorDeps:
    """Injected executor dependencies (offline fakes in 5G v1)."""

    authz_store: Any = None
    ledger: Any = None
    audit: Any = None
    now_iso: Callable[[], str] | None = None
    monotonic: Callable[[], float] | None = None

    def now(self) -> str:
        if self.now_iso is None:
            return datetime.now(timezone.utc).isoformat()
        return self.now_iso()

    def clock(self) -> float:
        if self.monotonic is None:
            import time as _time

            return _time.monotonic()
        return self.monotonic()


@dataclass(frozen=True)
class BrowserExecutionResult:
    """Terminal execution outcome (accounting, never a classification)."""

    execution_id: str
    authorization_id: str
    outcome: str
    error_code: str | None
    error_detail: str
    evidence: ev.EvidenceRecord | None
    spec: BrowserExecutionSpec | None
    navigations_evaluated: int = 0
    dialogs_recorded: int = 0
    oracle_events_recorded: int = 0
    cross_origin_dropped: int = 0
    postmessages_observed: int = 0
    audit_gap: bool = False


_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")


# ------------------------------------------------------------------
# Internal guards
# ------------------------------------------------------------------

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
        authz_host, authz_kind = canonicalize_host(bound.host)
    except (CanonicalizationError, TypeError) as exc:
        raise ExecutorError(
            "TARGET_BINDING_MISMATCH", "target not canonical"
        ) from exc
    if authz_kind != "dns":
        # No IP-based authorization in v1 (separately supported only).
        raise ExecutorError(
            "TARGET_BINDING_MISMATCH", "non-dns authority denied in v1"
        )
    try:
        resolution_host, resolution_kind = canonicalize_host(
            resolution.canonical_host
        )
    except (CanonicalizationError, TypeError) as exc:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "resolution host not canonical"
        ) from exc
    if resolution_kind != "dns":
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "non-dns resolution denied"
        )
    if authz_host != resolution_host:
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
        raise ExecutorError("DIAL_BINDING_MISMATCH", "empty address set")
    if len(resolution.resolved_addresses) > CEILINGS["dns_answers"]:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "answer set over ceiling")
    if resolution.scope_lists_hash_current != bound.scope_lists_hash:
        raise ExecutorError("SCOPE_DRIFT", "resolution scope stale")


def _revalidate_artifact(
    *,
    authorization: IssuedExecutionAuthorization,
    artifact_reference: ArtifactReference,
    artifact_bytes: bytes,
    test_plan: object = None,
) -> str:
    """Exact artifact revalidation; returns the payload text (P)."""
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
    if artifact_reference.artifact_type != "xss_payload":
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact type not xss payload"
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
    expected_id = artifact_id_for(
        artifact_type="xss_payload",
        test_plan_id=artifact_reference.test_plan_id,
        content_hash=artifact_reference.content_hash,
    )
    if artifact_reference.artifact_id != expected_id:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact identity mismatch"
        )
    if test_plan is not None:
        recheck = build_validated_reference(
            test_plan, raw, "xss_payload"
        )
        if recheck.state != "VALID":
            raise ExecutorError(
                "ARTIFACT_REVALIDATION_FAILED",
                "artifact failed validation recheck",
            )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact content not utf-8"
        ) from exc


def _evaluate_navigations(
    *,
    target_string: str,
    authorized_origin: tuple[str, str, int],
    navigations: tuple[ScriptedHop, ...],
    redirect_ceiling: int,
) -> tuple[str, int]:
    """Deterministically evaluate scripted navigation facts.

    Returns ``(final_url, hop_count)``. Every hop is a new scope
    decision against the exact authorized origin; any deviation
    fails closed. No request occurs: facts are evaluated, not
    performed.
    """
    if not isinstance(navigations, tuple) or not navigations:
        raise ExecutorError("NAV_MISMATCH", "navigation facts missing")
    for hop in navigations:
        if not isinstance(hop, ScriptedHop) or not isinstance(hop.url, str):
            raise ExecutorError("NAV_MISMATCH", "navigation fact malformed")
    if navigations[0].url != target_string:
        raise ExecutorError(
            "NAV_MISMATCH", "initial navigation is not the bound target"
        )
    scheme, host, port = authorized_origin
    seen: set[str] = set()
    for index, hop in enumerate(navigations):
        if _has_userinfo(hop.url):
            raise ExecutorError("NAV_USERINFO", "userinfo in navigation")
        parsed = _parse_http_origin(hop.url)
        if parsed is None:
            raise ExecutorError("NAV_SCHEME", "navigation scheme rejected")
        hop_scheme, hop_host, hop_port = parsed
        if hop_host != host:
            if _is_ip_literal(hop_host):
                raise ExecutorError(
                    "NAV_IP_AUTHORITY", "ip-literal navigation denied"
                )
            raise ExecutorError(
                "NAV_CROSS_ORIGIN", "cross-origin navigation denied"
            )
        if hop_scheme != scheme:
            if scheme == "https" and hop_scheme == "http":
                raise ExecutorError(
                    "NAV_DOWNGRADE", "scheme downgrade denied"
                )
            raise ExecutorError("NAV_SCHEME", "scheme change denied")
        if hop_port != port:
            raise ExecutorError("NAV_PORT_CHANGE", "port change denied")
        canonical = _canonical_nav_url(hop.url)
        if canonical in seen:
            raise ExecutorError("NAV_LOOP", "navigation loop detected")
        seen.add(canonical)
    hops = len(navigations) - 1
    if hops > redirect_ceiling:
        raise ExecutorError("NAV_LIMIT", "redirect ceiling exceeded")
    return navigations[-1].url, len(navigations)


def _origin_of(origin_value: object) -> tuple[str, str, int] | None:
    """Parse a scripted ``scheme://host[:port]`` origin fact."""
    if not isinstance(origin_value, str):
        return None
    text = origin_value.strip()
    if "://" not in text:
        return None
    parsed = _parse_http_origin(text + "/")
    return parsed


def _observe_text_list(
    values: tuple[str, ...], *, cap_items: int, cap_bytes: int
) -> tuple[tuple[str, ...], bool]:
    """Bound, normalize, and scrub text facts.

    Returns ``(hashes, truncated)`` where hashes cover exactly the
    stored (scrubbed, capped) samples. Raw text never persists.
    """
    hashes: list[str] = []
    truncated = False
    for value in values[: cap_items + 1]:
        normalized = value.replace("\r\n", "\n").replace("\r", "\n")
        redacted = scrubber.scrub_text(normalized)
        encoded = redacted.encode("utf-8")[:cap_bytes]
        hashes.append(hash_mod.sha256_hex(encoded))
    if len(values) > cap_items:
        truncated = True
        hashes = hashes[:cap_items]
    return tuple(hashes), truncated


# ------------------------------------------------------------------
# Lifecycle orchestration (20-step order, mirrors 5F)
# ------------------------------------------------------------------

class _BrowserExecutor:
    """Single-execution lifecycle driver (5G, exact 20-step order)."""

    def __init__(
        self, deps: BrowserExecutorDeps, runner: BrowserRunner
    ) -> None:
        if not isinstance(deps, BrowserExecutorDeps):
            raise TypeError(
                "executor accepts only BrowserExecutorDeps, "
                f"not {type(deps).__name__}"
            )
        for attr in ("authz_store", "ledger", "audit"):
            if getattr(deps, attr, None) is None:
                raise TypeError(f"executor deps missing: {attr}")
        if not isinstance(runner, (FakeBrowserRunner, LiveBrowserRunner,
                                   B5IsolatedBrowserRunner)):
            raise TypeError(
                "executor accepts only a 5G runner, "
                f"not {type(runner).__name__}"
            )
        self._deps = deps
        self._runner = runner
        self._audit_seq = 0

    # -- audit --------------------------------------------------------

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
            actor="browser-executor/5G",
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
                    actor="browser-executor/5G",
                )
            )
            self._audit_seq += 1
        except Exception:
            pass

    # -- ledger + consume ----------------------------------------------

    def _claim_and_consume(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
    ) -> IssuedExecutionAuthorization:
        """Ledger claim + authorization CAS + STARTED (at-most-once)."""
        from ai.authorizer.service import consume_authorization
        from ai.execution.ledger import (
            ExecutionRecord,
            LedgerError,
        )

        _ = LedgerError
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
        except Exception as exc:
            if type(exc).__name__ in (
                "ReplayExecutionError",
                "DuplicateExecutionError",
                "InProgressExecutionError",
            ):
                raise ExecutorError(
                    "EXECUTION_REPLAY", "authorization already used"
                ) from exc
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "ledger claim ambiguous"
            ) from exc
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
                raise ExecutorError(
                    "EXECUTION_REPLAY", "execution in progress"
                ) from exc
            try:
                ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "start state ambiguous"
            ) from exc
        return consumed

    # -- main -----------------------------------------------------------

    def run(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        resolution: TargetResolution,
        evaluation: ScopeEvaluation,
        artifact_reference: ArtifactReference,
        artifact_bytes: bytes,
        execution_id: str,
        test_plan: object = None,
    ) -> BrowserExecutionResult:
        # 1. typed input validation.
        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "executor accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}"
            )
        if not isinstance(resolution, TargetResolution):
            raise TypeError(
                "executor accepts only TargetResolution, "
                f"not {type(resolution).__name__}"
            )
        if not isinstance(evaluation, ScopeEvaluation):
            raise TypeError(
                "executor accepts only ScopeEvaluation, "
                f"not {type(evaluation).__name__}"
            )
        if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
            execution_id
        ):
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "malformed execution id"
            )
        # 2. authorization liveness re-read (never trust the caller
        # copy; the store record is authority).
        from ai.authorizer.service import get_issued_authorization

        live = get_issued_authorization(
            self._deps.authz_store, authorization.authorization_id
        )
        if live is None:
            raise ExecutorError("AUTHZ_NOT_FOUND", "unknown authorization")
        if live.lifecycle != "ISSUED":
            raise ExecutorError("AUTHZ_NOT_LIVE", "authorization not live")
        try:
            expired = datetime.fromisoformat(
                live.expires_at
            ) <= datetime.fromisoformat(self._deps.now())
        except ValueError as exc:
            raise ExecutorError(
                "AUTHZ_NOT_LIVE", "authorization time unreadable"
            ) from exc
        if expired:
            raise ExecutorError("AUTHZ_NOT_LIVE", "authorization expired")
        if live.execution_class != "browser_verification":
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "execution class not browser"
            )
        if live.max_executions != 1:
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "max executions not one"
            )
        if (
            live.authorization_id != authorization.authorization_id
            or live.artifact.artifact_id != authorization.artifact.artifact_id
            or live.target.program_name != authorization.target.program_name
        ):
            raise ExecutorError("AUTHZ_BINDING_MISMATCH", "authorization drift")
        # 3. target/resolution binding validation.
        _check_binding(
            authorization=live,
            resolution=resolution,
            evaluation=evaluation,
            execution_id=execution_id,
        )
        # 4-5. fresh scope evaluation + require_allowed().
        try:
            require_allowed(
                evaluation,
                authorization_id=live.authorization_id,
                execution_id=execution_id,
                resolution_id=resolution.resolution_id,
            )
        except TypeError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == "TARGET_EXCLUDED":
                raise ExecutorError(
                    "TARGET_EXCLUDED", "scope excluded target"
                ) from exc
            raise ExecutorError(
                "TARGET_NOT_IN_SCOPE", "scope did not allow target"
            ) from exc
        # 6. artifact revalidation (returns P text).
        payload_text = _revalidate_artifact(
            authorization=live,
            artifact_reference=artifact_reference,
            artifact_bytes=artifact_bytes,
            test_plan=test_plan,
        )
        # 7. payload safety gate (executor-time, P-side only).
        payload_report = validate_browser_payload(artifact_bytes)
        if payload_report.decision != "ALLOW":
            raise ExecutorError(
                "PAYLOAD_REJECTED", "payload denied at executor gate"
            )
        # 8. oracle binding validation (O-side; P never proves O).
        authorized_origin = (
            resolution.scheme,
            resolution.canonical_host,
            resolution.effective_port,
        )
        oracle = derive_oracle_binding(
            execution_id=execution_id,
            authorization=live,
            origin=authorized_origin,
        )
        if oracle.value in payload_text or oracle.seed in payload_text:
            # Anti-harvest: D/S must never occur in pre-execution
            # material. A payload carrying the oracle value is
            # rejected, not rewarded.
            raise ExecutorError(
                "ORACLE_BINDING_MISMATCH", "oracle value in payload"
            )
        # 9. closed BrowserExecutionSpec construction.
        path_scope = live.target.path_scope or "/"
        target_string = build_target_string(
            scheme=resolution.scheme,
            canonical_host=resolution.canonical_host,
            effective_port=resolution.effective_port,
            path=path_scope,
        )
        context_dir = context_dir_for(execution_id)
        limits = default_resource_limits()
        spec = BrowserExecutionSpec(
            execution_id=execution_id,
            authorization_id=live.authorization_id,
            program_name=resolution.program_name,
            canonical_host=resolution.canonical_host,
            scheme=resolution.scheme,
            effective_port=resolution.effective_port,
            target_string=target_string,
            artifact_id=live.artifact.artifact_id,
            payload_hash=payload_report.payload_hash,
            oracle=oracle,
            context=BrowserContextDescriptor(),
            environment=build_browser_environment(context_dir=context_dir),
            limits=limits,
        )
        # 10-12. ledger registration + authorization CAS consume +
        # STARTED.
        consumed = self._claim_and_consume(
            authorization=live, execution_id=execution_id
        )
        # 13-14. pre-launch audit pair. Any failure here blocks the
        # runner: no launch, no browser, deterministic AUDIT_GAP.
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="AUTHORIZATION",
                scope_decision="ALLOWED",
            )
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EXECUTION_STARTED",
            )
        except Exception as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            self._audit_gap(
                execution_id=execution_id,
                authorization=consumed,
                missing_from="EXECUTION_STARTED",
            )
            raise ExecutorError(
                "AUDIT_GAP", "pre-launch audit unavailable"
            ) from exc
        # 15. runner invocation (fake only; live raises blocked).
        try:
            run_result = self._runner.launch(spec)
        except ExecutorError:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise
        if not isinstance(run_result, BrowserRunResult):
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "runner returned unknown shape"
            )
        # 16. bounded BrowserRunResult processing.
        if run_result.timed_out:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "BROWSER_TIMEOUT", "runner wall deadline exceeded"
            )
        if run_result.crashed:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "BROWSER_CRASH", "runner reports crashed browser"
            )
        if run_result.popup_attempted:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError("POPUP_BLOCKED", "popup attempt aborted")
        if run_result.download_attempted:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "DOWNLOAD_BLOCKED", "download attempt aborted"
            )
        if run_result.serviceworker_attempted:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "SERVICEWORKER_BLOCKED", "service worker attempt aborted"
            )
        if run_result.document_domain_relaxed:
            # Origin relaxation never merges origins: abort rather
            # than reason about a weakened boundary.
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "DOCUMENT_DOMAIN", "origin relaxation aborted"
            )
        try:
            final_url, nav_count = _evaluate_navigations(
                target_string=spec.target_string,
                authorized_origin=authorized_origin,
                navigations=run_result.navigations,
                redirect_ceiling=spec.limits.redirects,
            )
        except ExecutorError as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise exc
        if run_result.final_url != navigations_last_url(run_result):
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "NAV_MISMATCH", "final url diverges from navigation facts"
            )
        # 17. BrowserObservation construction (observation only:
        # never a classification, never severity, never proof).
        try:
            observation, counts = self._build_observation(
                spec=spec,
                payload_text=payload_text,
                run_result=run_result,
                final_url=final_url,
                round_id=_round_id_for(consumed),
            )
        except ExecutorError as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise exc
        # 18. EvidenceBuilder integration + seal.
        partial = run_result.channels_truncated or counts["truncated"]
        try:
            builder = EvidenceBuilder.begin(
                authorization=consumed,
                execution_id=execution_id,
                execution_stage="single",
                execution_class="browser_verification",
                started_at=self._deps.now(),
            )
            builder.attach_browser(
                observation,
                executed_payload_hash=hash_mod.hash_text(oracle.value),
            )
            if partial:
                evidence = builder.seal_partial(
                    reasons=("channels_partial",),
                    finished_at=self._deps.now(),
                    sealed_at=self._deps.now(),
                )
            else:
                evidence = builder.seal(
                    finished_at=self._deps.now(),
                    sealed_at=self._deps.now(),
                )
        except Exception as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "EVIDENCE_SEAL_FAILED", "evidence seal refused"
            ) from exc
        # 19. ledger terminal state.
        try:
            if partial:
                self._deps.ledger.mark_incomplete(
                    execution_id,
                    evidence.evidence_id,
                    terminal_at=self._deps.now(),
                )
            else:
                self._deps.ledger.mark_sealed(
                    execution_id,
                    evidence.evidence_id,
                    terminal_at=self._deps.now(),
                )
        except Exception as exc:
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "ledger terminal ambiguous"
            ) from exc
        # 20. terminal audit.
        audit_gap = False
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EVIDENCE_SEALED",
                evidence=evidence,
            )
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EXECUTION_TERMINAL",
                evidence=evidence,
            )
        except Exception:
            audit_gap = True
            self._audit_gap(
                execution_id=execution_id,
                authorization=consumed,
                missing_from="EXECUTION_TERMINAL",
            )
        return BrowserExecutionResult(
            execution_id=execution_id,
            authorization_id=consumed.authorization_id,
            outcome="incomplete" if partial else "sealed",
            error_code=None,
            error_detail="",
            evidence=evidence,
            spec=spec,
            navigations_evaluated=nav_count,
            dialogs_recorded=counts["dialogs"],
            oracle_events_recorded=counts["oracle_events"],
            cross_origin_dropped=counts["dropped"],
            postmessages_observed=counts["postmessages"],
            audit_gap=audit_gap,
        )

    # -- observation ----------------------------------------------------

    def _build_observation(
        self,
        *,
        spec: BrowserExecutionSpec,
        payload_text: str,
        run_result: BrowserRunResult,
        final_url: str,
        round_id: str | None,
    ) -> tuple[ev.BrowserObservation, dict[str, int]]:
        """Build the observation-only record from runner facts."""
        authorized_origin = (
            spec.oracle.origin_scheme,
            spec.oracle.origin_host,
            spec.oracle.origin_port,
        )
        limits = spec.limits
        dropped = 0

        def _same_origin(origin_value: object) -> bool:
            parsed = _origin_of(origin_value)
            if parsed is None:
                return False
            scheme, host, port = parsed
            return (
                scheme == authorized_origin[0]
                and host == authorized_origin[1]
                and port == authorized_origin[2]
            )

        # Dialogs: same-origin facts only; E1 shape reused.
        dialog_probes: list[Any] = []
        dialog_texts: list[str] = []
        for dialog in run_result.dialogs:
            if not isinstance(dialog, ScriptedDialog):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "dialog fact malformed"
                )
            if not _same_origin(dialog.origin):
                dropped += 1
                continue
            dialog_probes.append(
                SimpleNamespace(kind=dialog.kind, message=dialog.message)
            )
            dialog_texts.append(f"{dialog.kind}:{dialog.message}")
        dialog_hashes, dialog_truncated = _observe_text_list(
            tuple(dialog_texts),
            cap_items=limits.dialogs,
            cap_bytes=limits.dom_bytes,
        )
        e1_observed = evaluate_e1_dialog(dialog_probes, spec.oracle.value)

        # Oracle events: same-origin facts only; E2 shape reused.
        # Cross-origin oracle-shaped signals are dropped and can
        # never become oracle observations.
        oracle_probes: list[Any] = []
        oracle_texts: list[str] = []
        for event in run_result.oracle_events:
            if not isinstance(event, ScriptedOracleEvent):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "oracle fact malformed"
                )
            if event.channel not in ("dialog", "network", "eval"):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "oracle channel rejected"
                )
            if not _same_origin(event.origin):
                dropped += 1
                continue
            oracle_probes.append(
                SimpleNamespace(
                    is_navigation=event.is_navigation, url=event.url
                )
            )
            oracle_texts.append(f"{event.channel}:{event.marker}")
        oracle_hashes, oracle_truncated = _observe_text_list(
            tuple(oracle_texts),
            cap_items=limits.oracle_events,
            cap_bytes=limits.dom_bytes,
        )
        e2_observed = evaluate_e2_network(
            oracle_probes, spec.oracle.value, spec.target_string
        )

        # Eval events: E3 shape reused against P text.
        eval_probes: list[Any] = []
        eval_texts: list[str] = []
        for event in run_result.eval_events:
            if not isinstance(event, ScriptedEvalEvent):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "eval fact malformed"
                )
            if event.operator not in ("eval", "setTimeout:string"):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "eval operator rejected"
                )
            eval_probes.append(
                SimpleNamespace(operator=event.operator, value=event.value)
            )
            eval_texts.append(f"{event.operator}:{event.value}")
        eval_hashes, eval_truncated = _observe_text_list(
            tuple(eval_texts),
            cap_items=limits.oracle_events,
            cap_bytes=limits.dom_bytes,
        )
        e3_result = evaluate_e3_eval(eval_probes, payload_text)
        e3_observed = e3_result is True

        # Console: bounded scrubbed counts only (no 5H channel in
        # v1); over-cap truncates into the partial path.
        console_count = len(run_result.console)
        console_truncated = console_count > limits.console_entries
        for line in run_result.console[: limits.console_entries]:
            scrubber.scrub_text(line)

        # Storage keys: key hashes only, values never persist.
        storage_keys = tuple(run_result.storage_keys)
        for key in storage_keys:
            if not isinstance(key, str):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "storage fact malformed"
                )
        storage_truncated = len(storage_keys) > limits.storage_keys
        storage_keys = storage_keys[: limits.storage_keys]
        storage_hash = (
            hash_mod.hash_text("\x00".join(sorted(storage_keys)))
            if storage_keys
            else None
        )

        # postMessage: observation counts only (no 5H channel in
        # v1); cross-origin messages are dropped, never proof.
        postmessages = 0
        for message in run_result.postmessages:
            if not isinstance(message, ScriptedPostMessage):
                raise ExecutorError(
                    "OUTCOME_UNKNOWN", "postmessage fact malformed"
                )
            if not _same_origin(message.origin):
                dropped += 1
                continue
            scrubber.scrub_text(message.data)
            postmessages += 1

        try:
            page_url = observe_url(final_url)
        except Exception as exc:
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "final url not observable"
            ) from exc

        truncated = (
            dialog_truncated
            or oracle_truncated
            or eval_truncated
            or console_truncated
            or storage_truncated
        )
        observation = ev.BrowserObservation(
            dialog_marker_hashes=dialog_hashes,
            oracle_event_hashes=oracle_hashes,
            eval_marker_hashes=eval_hashes,
            e1_observed=e1_observed,
            e2_observed=e2_observed,
            e3_observed=e3_observed,
            executed_payload_hash=hash_mod.hash_text(spec.oracle.value),
            page_url=page_url,
            storage_keys_hash=storage_hash,
            channels_truncated=(truncated or run_result.channels_truncated),
            round_id=round_id,
            submit_evidence_ref=None,
        )
        counts = {
            "dialogs": len(dialog_hashes),
            "oracle_events": len(oracle_hashes),
            "dropped": dropped,
            "postmessages": postmessages,
            "truncated": 1 if truncated else 0,
        }
        return observation, counts

def navigations_last_url(run_result: BrowserRunResult) -> str:
    """Final navigation fact URL (empty when no facts)."""
    if not run_result.navigations:
        return ""
    return run_result.navigations[-1].url


def execute_browser(
    *,
    authorization: object,
    resolution: object,
    evaluation: object,
    artifact_reference: object,
    artifact_bytes: bytes,
    execution_id: str,
    deps: BrowserExecutorDeps,
    runner: BrowserRunner,
    test_plan: object = None,
) -> BrowserExecutionResult:
    """Execute one authorized browser exchange (offline, fail-closed).

    Exact 20-step security ordering (see ``_BrowserExecutor.run``).
    Only the injected offline runner performs step 15; the blocked
    live runners raise ``BROWSER_EXECUTION_BLOCKED`` before any
    browser, process, or transport primitive.
    """
    driver = _BrowserExecutor(deps, runner)
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "execute_browser accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if not isinstance(resolution, TargetResolution):
        raise TypeError(
            "execute_browser accepts only TargetResolution, "
            f"not {type(resolution).__name__}"
        )
    if not isinstance(evaluation, ScopeEvaluation):
        raise TypeError(
            "execute_browser accepts only ScopeEvaluation, "
            f"not {type(evaluation).__name__}"
        )
    if not isinstance(artifact_reference, ArtifactReference):
        raise TypeError(
            "execute_browser accepts only ArtifactReference, "
            f"not {type(artifact_reference).__name__}"
        )
    return driver.run(
        authorization=authorization,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference,
        artifact_bytes=artifact_bytes,
        execution_id=execution_id,
        test_plan=test_plan,
    )


def _round_id_for(
    authorization: IssuedExecutionAuthorization,
) -> str | None:
    """Round identity from stored leases when present (else None)."""
    leases = authorization.stored_leases
    if leases is None:
        return None
    round_id = leases.round_id
    if not isinstance(round_id, str) or not round_id:
        return None
    return round_id

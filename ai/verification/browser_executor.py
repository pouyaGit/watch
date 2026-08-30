from __future__ import annotations

import multiprocessing as mp
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from ai.schemas.xss_verification import (
    AttemptStatus,
    BrowserExecutionObservation,
    ReflectionObservation,
    ReflectionLocation,
    SourceToSinkStep,
    StoredXSSPhase,
    StoredXSSPhaseObservation,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    WAFObservation,
    WAFObservationKind,
)


try:
    from playwright.sync_api import (  # noqa: F401
        Browser as _PlaywrightBrowser,
        BrowserContext as _PlaywrightContext,
        Page as _PlaywrightPage,
        Response as _PlaywrightResponse,
        Route as _PlaywrightRoute,
        sync_playwright,
    )
except ImportError:  # pragma: no cover
    sync_playwright = None  # type: ignore[assignment]
    _PlaywrightBrowser = None  # type: ignore[assignment]
    _PlaywrightContext = None  # type: ignore[assignment]
    _PlaywrightPage = None  # type: ignore[assignment]
    _PlaywrightResponse = None  # type: ignore[assignment]
    _PlaywrightRoute = None  # type: ignore[assignment]


_TOKEN_SEPARATOR = "~~"

# Resource limits. The brief is explicit and these are
# hard upper bounds; overflow means STOP APPENDING.
_MAX_RUNTIME_ENTRIES = 64
_MAX_ENTRY_LENGTH = 240
_MAX_CHAIN_STEPS = 8
_MAX_DESCRIPTION_LENGTH = 120
_MAX_ERROR_REASON_LENGTH = 200
_MAX_NAVIGATION_HOPS = 5
_MAX_BODY_BYTES = 512 * 1024
_OBSERVATION_WINDOW_SECONDS = 5.0
_NAVIGATION_TIMEOUT_SECONDS = 10.0

_REDACTED_PLACEHOLDER = "[REDACTED]"

# Initial DOM snapshot descriptions are NEVER injected into
# dom_changes. Only event-driven mutations are allowed.
# The init script below is installed via
# ``context.add_init_script`` so it runs before any
# application script.
#
# TRUSTED EVENT TRANSPORT
# -----------------------
# The instrumentation does NOT park evidence in a page-global
# buffer. Every observed event is pushed immediately through
# the executor-owned Playwright binding
# (``context.expose_binding``), whose callback lives in
# Python. The authoritative event buffer therefore lives
# entirely Python-side (``state.chain_events`` plus the
# ``_EventSink`` channels); the page never receives a
# reference to it.
#
# Trust boundary: the page can only CALL the binding. Each
# call must carry the per-attempt capability generated in
# Python (``secrets.token_hex``) and held only inside the
# init script's closure, which page JavaScript cannot read.
# Binding calls without the exact capability are dropped by
# the executor. A hostile page can therefore neither append
# fabricated events, replace the transport's destination,
# nor rewrite previously recorded events.
#
# ``label`` is a short structural descriptor; ``value`` is a
# bounded excerpt of the runtime value (parameter value,
# assigned sink string, or mutation text). The Python side
# correlates values across source / sink / observable events
# to build a defensible chain.
_INIT_VALUE_LIMIT = 240
_INIT_LABEL_LIMIT = 80
_INIT_BUFFER_LIMIT = 512

# Name of the executor-owned binding. Security does NOT rest
# on the secrecy of this name: the binding callable is
# intentionally page-callable, but every invocation must
# carry the per-attempt capability held only inside the init
# script's closure.
_BINDING_NAME = "__watchTransport"

# Hard upper bound on instrumentation events absorbed per
# attempt. Overflow means STOP APPENDING (Python side).
_MAX_CHAIN_EVENTS = 512

_INIT_SCRIPT_INSTRUMENTATION = r"""
(() => {
  if (window.__watch_instrumented__) return;
  var __emit = window["__WATCH_BINDING_NAME__"];
  if (typeof __emit !== "function") return;
  window.__watch_instrumented__ = true;
  var __watchCapability = "__WATCH_CAPABILITY__";
  var __sent = 0;

  function emit(channel, op, label, value) {
    try {
      if (__sent >= __INIT_BUFFER_LIMIT__) return;
      __sent = __sent + 1;
      __emit(channel, op, label, value, __watchCapability);
    } catch (e) {}
  }
  function _val(v) {
    try {
      if (v === null || v === undefined) return '';
      return String(v).slice(0, __INIT_VALUE_LIMIT__);
    } catch (e) {
      return '';
    }
  }
  function _label(s) {
    try { return String(s).slice(0, __INIT_LABEL_LIMIT__); }
    catch (e) { return ''; }
  }

  // Source: URLSearchParams.get
  try {
    const origGet = URLSearchParams.prototype.get;
    URLSearchParams.prototype.get = function (name) {
      try {
        if (name) {
          const v = origGet.apply(this, arguments);
          emit('sources', 'URLSearchParams.get', _label(name), _val(v));
          return v;
        }
      } catch (e) {}
      return origGet.apply(this, arguments);
    };
  } catch (e) {}

  // Source: URLSearchParams.getAll
  try {
    const origGetAll = URLSearchParams.prototype.getAll;
    URLSearchParams.prototype.getAll = function (name) {
      try {
        const v = origGetAll.apply(this, arguments);
        if (name) {
          emit(
            'sources',
            'URLSearchParams.getAll',
            _label(name),
            _val(Array.isArray(v) ? v.join(',') : v)
          );
        }
        return v;
      } catch (e) {
        return origGetAll.apply(this, arguments);
      }
    };
  } catch (e) {}

  // Sink: innerHTML setter (only on Element prototype)
  try {
    const proto = Element.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
    if (desc && desc.set) {
      const origSet = desc.set;
      Object.defineProperty(proto, 'innerHTML', {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          try {
            emit(
              'sinks',
              'innerHTML',
              _label(this.tagName || ''),
              _val(v)
            );
          } catch (e) {}
          return origSet.call(this, v);
        },
      });
    }
  } catch (e) {}

  // Sink: insertAdjacentHTML
  try {
    const orig = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, html) {
      try {
        emit(
          'sinks',
          'insertAdjacentHTML',
          _label(this.tagName || ''),
          _val(html)
        );
      } catch (e) {}
      return orig.apply(this, arguments);
    };
  } catch (e) {}

  // Sink: document.write / writeln
  try {
    const origWrite = document.write;
    document.write = function () {
      try {
        let joined = '';
        for (let i = 0; i < arguments.length; i++) {
          joined += _val(arguments[i]);
        }
        emit('sinks', 'document.write', '', joined);
      } catch (e) {}
      return origWrite.apply(this, arguments);
    };
  } catch (e) {}

  // Sink: eval / Function
  try {
    const origEval = window.eval;
    window.eval = function (code) {
      try {
        emit('sinks', 'eval', '', _val(code));
      } catch (e) {}
      return origEval.apply(this, arguments);
    };
  } catch (e) {}

  // Sink: setTimeout/setInterval with string callback
  try {
    const _origST = window.setTimeout;
    window.setTimeout = function (cb, delay) {
      if (typeof cb === 'string') {
        try {
          emit('sinks', 'setTimeout:string', '', _val(cb));
        } catch (e) {}
      }
      return _origST.apply(this, arguments);
    };
  } catch (e) {}

  // Observable: MutationObserver. The value side of each
  // observable event carries a bounded concatenation of
  // addedNodes textContent (or attribute mutations) so the
  // executor can correlate sink-output with mutation-input.
  try {
    const _origMO = window.MutationObserver;
    function WatchMO(cb) {
      const wrapped = function (records, obs) {
        try {
          for (let i = 0; i < records.length; i++) {
            const r = records[i];
            if (!r) continue;
            const t = r && r.type ? r.type : 'mutation';
            const tgt = r && r.target
              ? (r.target.tagName || r.target.nodeName || 'node')
              : 'node';
            let mv = '';
            try {
              if (t === 'characterData') {
                mv = _val(r.data);
              } else if (t === 'attributes') {
                mv = _label(r.attributeName || '') + '=' + _val(r.target && r.target.getAttribute ? r.target.getAttribute(r.attributeName) : '');
              } else if (t === 'childList') {
                if (r.addedNodes && r.addedNodes.length) {
                  const parts = [];
                  for (let j = 0; j < r.addedNodes.length; j++) {
                    const n = r.addedNodes[j];
                    if (!n) continue;
                    if (n.nodeType === 3) {
                      parts.push(n.nodeValue || '');
                    } else if (n.nodeType === 1) {
                      parts.push(n.outerHTML || n.textContent || '');
                    }
                  }
                  mv = parts.join('|');
                }
              }
              mv = _val(mv);
            } catch (e) {
              mv = '';
            }
            emit('observables', String(t), _label(tgt), mv);
          }
        } catch (e) {}
        return cb.apply(this, arguments);
      };
      return new _origMO(wrapped);
    }
    WatchMO.prototype = _origMO.prototype;
    window.MutationObserver = WatchMO;
  } catch (e) {}

  // Storage writes. Only actual runtime setItem calls are
  // recorded: the hook fires on writes made by the page
  // during this attempt, never on pre-existing storage.
  try {
    const origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) {
      try {
        const area = (this === window.localStorage)
          ? 'localStorage'
          : 'sessionStorage';
        emit('storage', area, _label(k), _val(v));
      } catch (e) {}
      return origSetItem.apply(this, arguments);
    };
  } catch (e) {}
})();
""".replace(
    "__WATCH_BINDING_NAME__", _BINDING_NAME
).replace(
    "__WATCH_CAPABILITY__", "__WATCH_CAPABILITY__"
).replace(
    "__INIT_VALUE_LIMIT__", str(_INIT_VALUE_LIMIT)
).replace(
    "__INIT_LABEL_LIMIT__", str(_INIT_LABEL_LIMIT)
).replace(
    "__INIT_BUFFER_LIMIT__", str(_INIT_BUFFER_LIMIT)
)


def _new_capability() -> str:
    """Generate the per-attempt transport capability.

    Generated in Python. It is embedded ONLY inside the init
    script's closure, which page JavaScript cannot inspect;
    it is never stored in any page-visible object.
    """

    return secrets.token_hex(32)


def _build_init_script(capability: str) -> str:
    """Build the per-attempt instrumentation init script.

    The script carries the capability in a closure so the
    page can call the executor-owned binding but cannot
    forge authenticated events. Rejects empty capabilities
    so a misconfigured attempt cannot silently open an
    unauthenticated transport.
    """

    if not capability:
        raise _BrowserSecurityError("missing_transport_capability")
    return _INIT_SCRIPT_INSTRUMENTATION.replace(
        "__WATCH_CAPABILITY__", capability
    )


def _chain_label_for(channel: str, op: str, label: str) -> str:
    """Map a transport event to the label used in evidence.

    The first field of sink/storage records is the observed
    operation/area, not merely metadata. Keep it in the
    evidence so actual innerHTML and storage writes remain
    identifiable after decoding.
    """

    if channel == "sinks":
        return op
    if channel == "storage":
        return f"{op}:{label}"
    return label


def _canonical_target_origin(endpoint: str) -> tuple[str, str, str]:
    """Return (scheme, host, port) of the target endpoint.

    Raises ``_UnsupportedBrowserRequest`` if the endpoint
    is not a usable http(s) URL.
    """

    parts = urlsplit(endpoint)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise _UnsupportedBrowserRequest(
            f"unsupported_browser_endpoint_scheme:{parts.scheme!r}"
        )
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), str(port)


def _origin_of(url: str) -> tuple[str, str, str] | None:
    """Best-effort origin extraction for arbitrary URLs."""

    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), str(port)


def _is_downgrade(current_scheme: str, target_scheme: str) -> bool:
    return current_scheme == "https" and target_scheme != "https"


def _bound_value(payload: str, correlation_token: str) -> str:
    return f"{payload}{_TOKEN_SEPARATOR}{correlation_token}"


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit]


def _append_bounded(buffer: list[str], value: str, limit: int = _MAX_RUNTIME_ENTRIES) -> None:
    """Append a bounded runtime entry. STOP APPENDING on overflow.

    The brief is explicit: "On overflow: STOP APPENDING. Do
    not use unbounded queues. Do not introduce nondeterministic
    drop-oldest behavior." We stop appending once the cap is
    hit; older entries are preserved.
    """

    if len(buffer) >= limit:
        return
    buffer.append(_truncate(value, _MAX_ENTRY_LENGTH))


@dataclass
class _EventSink:
    """The bounded, per-attempt event channels.

    The fake populates these via explicit ``simulate_*`` calls;
    the production executor populates them via Playwright event
    listeners. Both write through ``append`` which enforces the
    hard upper bounds.

    Entries are kept as ``str`` for verifiability with the
    verifier's ``_runtime_token_observed`` substring check.
    For instrumentation-collected entries the wire-side value
    is folded into the entry string via a structured
    ``"<label>|<value>"`` form so the verifier can scan the
    literal token across the channel uniformly.
    """

    dom_changes: list[str] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    network_requests: list[str] = field(default_factory=list)
    storage_writes: list[str] = field(default_factory=list)

    def append_dom(self, value: str) -> None:
        _append_bounded(self.dom_changes, value)

    def append_console(self, value: str) -> None:
        _append_bounded(self.console_messages, value)

    def append_network(self, value: str) -> None:
        _append_bounded(self.network_requests, value)

    def append_storage(self, value: str) -> None:
        _append_bounded(self.storage_writes, value)

    def has_token(self, token: str) -> bool:
        if not token:
            return False
        for channel in (
            self.dom_changes,
            self.console_messages,
            self.network_requests,
            self.storage_writes,
        ):
            for entry in channel:
                if isinstance(entry, str) and token in entry:
                    return True
        return False

    def find_token(self, token: str) -> str | None:
        """Return the literal token substring if present."""

        if not token:
            return None
        for channel in (
            self.dom_changes,
            self.console_messages,
            self.network_requests,
            self.storage_writes,
        ):
            for entry in channel:
                if isinstance(entry, str) and token in entry:
                    return token
        return None


@dataclass
class _ChainEvent:
    """One instrumentation-collected entry.

    The trusted instrumentation pushes each observed event
    through the executor-owned binding; the Python-side
    transport callback converts each call into a
    ``_ChainEvent``. ``value`` carries the bounded runtime
    value the instrumentation actually observed; this is the
    substrate the executor uses for value-flow correlation.
    ``label`` carries the structural descriptor.

    De-duplication uses ``(kind, label, value)``. Identical
    events collapse; structurally similar events with
    distinct values do not.
    """

    kind: str
    label: str
    value: str

    def signature(self) -> tuple[str, str, str]:
        return (self.kind, self.label, self.value)


# Exceptions raised by the executor itself. The brief states
# every exception must produce bound ERROR/TIMEOUT evidence;
# these classes let the executor distinguish error categories.


class _UnsupportedBrowserRequest(Exception):
    """The attempt cannot be turned into a safe browser attempt."""


class _BrowserSecurityError(Exception):
    """The browser interaction violated the executor's security policy."""


class _BrowserTimeout(Exception):
    """The browser interaction timed out."""


class _BrowserCrash(Exception):
    """The browser or page crashed during the attempt."""


# ----------------------------------------------------------------------
# BrowserSession protocol
# ----------------------------------------------------------------------


class _BrowserContextLike(Protocol):
    """A minimal interface the executor needs from a context."""

    def new_page(self) -> "_BrowserPageLike": ...
    def route(
        self,
        pattern: str | re.Pattern,
        handler: Callable[["_BrowserRouteLike"], None],
    ) -> None: ...
    def add_init_script(self, script: str) -> None: ...
    def expose_binding(self, name: str, handler: Callable[..., None]) -> None: ...
    def close(self) -> None: ...


class _BrowserPageLike(Protocol):
    url: str

    def on(self, event: str, handler: Callable[..., None]) -> None: ...
    def goto(
        self, url: str, *, timeout: float, wait_until: str
    ) -> "_BrowserResponseLike": ...
    def evaluate(
        self, script: str, arg: object = None
    ) -> object: ...
    def close(self) -> None: ...
    # ``main_frame`` is set by Playwright on ``Page``
    # instances; it is captured via ``getattr`` rather
    # than declared on the protocol so non-Playwright
    # fakes (which do not model frame identity) can
    # still satisfy the protocol without crashing.


class _BrowserRouteLike(Protocol):
    request: "_BrowserRequestLike"

    def fulfill(
        self,
        *,
        status: int = 200,
        body: str = "",
        headers: dict[str, str] | None = None,
        content_type: str | None = None,
    ) -> None: ...
    def abort(self, reason: str = "blockedbyclient") -> None: ...
    def continue_(self) -> None: ...


class _BrowserRequestLike(Protocol):
    url: str
    method: str
    resource_type: str
    headers: dict[str, str]


class _BrowserResponseLike(Protocol):
    url: str
    status: int


class _BrowserSessionLike(Protocol):
    def new_context(self) -> _BrowserContextLike: ...
    def close(self) -> None: ...


# ----------------------------------------------------------------------
# Real Playwright session (guarded import)
# ----------------------------------------------------------------------


class _PlaywrightSession:
    """Production session using Playwright Chromium.

    The session is constructed lazily because the import
    is guarded. ``execute`` is the only public entry point
    and is called from the ``BrowserEvidenceExecutor``.
    """

    def __init__(self) -> None:
        if sync_playwright is None:
            raise RuntimeError(
                "BrowserEvidenceExecutor requires the 'playwright' "
                "library; install it or inject a session."
            )
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)

    def new_context(self) -> _PlaywrightContext:
        context = self._browser.new_context(
            ignore_https_errors=False,
            java_script_enabled=True,
        )
        return context

    def close(self) -> None:
        try:
            self._browser.close()
        finally:
            self._pw.stop()


# ----------------------------------------------------------------------
# Executor
# ----------------------------------------------------------------------


@dataclass
class _BrowserAttemptState:
    """Mutable per-attempt state assembled by the executor."""

    target_origin: tuple[str, str, str]
    bound_url: str
    correlation_token: str
    sinks: _EventSink = field(default_factory=_EventSink)
    # Chain events captured from the trusted instrumentation
    # transport. Each entry is a ``_ChainEvent(kind, label,
    # value)`` and the buffer is de-duplicated by
    # ``(kind, label, value)``. The ``value`` side is used for
    # value-flow correlation. This buffer lives ONLY in
    # Python; the page never holds a reference to it.
    chain_events: list[_ChainEvent] = field(default_factory=list)
    # De-duplication set: re-delivered instrumentation events
    # must not double-count. Keyed by ``event.signature()``.
    seen_chain_signatures: set[tuple[str, str, str]] = field(
        default_factory=set
    )
    # Initial-navigation nav hops. Real Playwright follows
    # redirects internally and exposes the chain via
    # ``request.redirected_from``. We record only the
    # ``final_url`` and a bounded count of distinct
    # origins encountered; the executor's role is to
    # report whether the page reached the target origin,
    # not to enumerate every hop.
    final_url: str | None = None
    distinct_hop_origins: list[tuple[str, str, str]] = field(
        default_factory=list
    )
    redirect_hop_count: int = 0
    cross_origin_blocked_count: int = 0
    crashed: bool = False
    timed_out: bool = False
    nav_redirects: list[tuple[str, str]] = field(default_factory=list)
    error_reason: str | None = None
    sink_observed: bool = False
    token_observed: bool = False
    # Per-attempt transport capability. Generated in Python;
    # embedded only inside the init script's closure. Every
    # instrumentation event that reaches the Python-side
    # buffer must carry this value.
    capability: str = ""


class BrowserEvidenceExecutor:
    """
    The real browser-facing :class:`VerificationExecutor`.

    Security contract: this executor is an EVIDENCE PROVIDER,
    never a verdict authority. It launches a fresh isolated
    browser context, navigates to the bound input URL, observes
    only page-initiated runtime events, and reports structured
    evidence. It never emits security verdict labels (the
    verifier's status vocabulary is absent from this module by
    invariant). ``XSSVerifier`` remains the sole classification
    authority and treats this executor's output as untrusted
    input.

    Correlation-token binding: the bound input value is
    ``payload + "~~" + correlation_token`` and is carried
    exclusively in the navigation URL's query string for the
    ``parameter_location == "query"`` case. The token is never
    injected as a header, cookie, fragment, console message,
    or DOM marker. Reflection of the token therefore evidences
    that the input containing the payload reached the runtime.

    Token-fabrication protection: the initial navigation
    request and any redirect hops are NOT inserted into
    ``network_requests``. Only page-initiated runtime
    requests enter that channel. ``observed_correlation_token``
    is set only when the exact token appears literally in an
    event-driven runtime observation, and never derived from
    the attempt, initial URL, payload, or page snapshot.

    Network policy: only the target origin (scheme + host +
    port of ``attempt.endpoint``) is allowed. All other
    traffic is blocked. Cross-origin top-level navigation,
    HTTPS→HTTP downgrade, and bounded redirect loops are
    detected and surfaced as ERROR evidence.

    Evidence-channel tamper resistance: the trusted event
    buffer lives entirely Python-side. The instrumentation
    init script pushes each observed event through the
    executor-owned Playwright binding
    (``context.expose_binding``); page JavaScript holds only
    a write-only callable and never a reference to the
    Python-side buffer. Every binding invocation must carry
    the per-attempt capability that was generated in Python
    and is held only inside the init script's closure, which
    page JavaScript cannot read. A hostile page therefore
    cannot access, replace, append to, or rewrite the
    executor's evidence buffer by manipulating page globals.
    """

    DEFAULT_TIMEOUT_SECONDS = _NAVIGATION_TIMEOUT_SECONDS
    DEFAULT_OBSERVATION_WINDOW_SECONDS = _OBSERVATION_WINDOW_SECONDS
    DEFAULT_MAX_NAVIGATION_HOPS = _MAX_NAVIGATION_HOPS
    DEFAULT_MAX_BODY_BYTES = _MAX_BODY_BYTES

    def __init__(
        self,
        *,
        session: _BrowserSessionLike | None = None,
        navigation_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        observation_window_seconds: float = (
            DEFAULT_OBSERVATION_WINDOW_SECONDS
        ),
        max_navigation_hops: int = DEFAULT_MAX_NAVIGATION_HOPS,
    ) -> None:
        self._session = session
        self._navigation_timeout = navigation_timeout_seconds
        self._observation_window = observation_window_seconds
        self._max_navigation_hops = max_navigation_hops

    # ------------------------------------------------------------------
    # Protocol entry point
    # ------------------------------------------------------------------

    def execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        """Execute one browser attempt and return structured evidence.

        Every failure path returns bound evidence. An exception
        can never become SUCCEEDED evidence.
        """

        try:
            if self._session is None:
                return self._execute_with_wall_clock_bound(attempt)
            return self._execute(attempt)
        except _BrowserTimeout as exc:
            return self._error_evidence(
                attempt, str(exc), AttemptStatus.TIMEOUT
            )
        except (
            _BrowserSecurityError,
            _UnsupportedBrowserRequest,
        ) as exc:
            return self._error_evidence(
                attempt, str(exc), AttemptStatus.ERROR
            )
        except _BrowserCrash as exc:
            return self._error_evidence(
                attempt, str(exc), AttemptStatus.ERROR
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_evidence(
                attempt,
                f"unexpected_browser_failure:{type(exc).__name__}:{exc}"[
                    :_MAX_ERROR_REASON_LENGTH
                ],
                AttemptStatus.ERROR,
            )

    def _execute_with_wall_clock_bound(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        """Run an owned browser attempt in a killable worker process."""
        result_queue = mp.Queue(maxsize=1)
        worker = mp.Process(
            target=_execute_browser_worker,
            args=(
                result_queue,
                attempt,
                self._navigation_timeout,
                self._observation_window,
                self._max_navigation_hops,
            ),
            daemon=True,
        )
        worker.start()
        worker.join(
            max(0.001, self._navigation_timeout + self._observation_window)
        )
        if worker.is_alive():
            worker.terminate()
            worker.join(1.0)
            raise _BrowserTimeout("attempt_timeout")
        try:
            ok, value = result_queue.get(timeout=0.5)
        except Exception as exc:  # noqa: BLE001
            raise _BrowserCrash("browser_worker_failed") from exc
        if ok:
            return value
        raise RuntimeError(value)

    # ------------------------------------------------------------------
    # Internal entry point
    # ------------------------------------------------------------------

    def _execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        if attempt.mode != VerificationMode.BROWSER_EXECUTION:
            raise _UnsupportedBrowserRequest(
                f"mode_not_supported_by_browser_executor:"
                f"{attempt.mode.value}"
            )

        # The browser executor drives top-level navigation only,
        # which is inherently a GET. POST/PUT/... attempts must
        # NOT be silently downgraded to a GET navigation: they
        # return explicit error evidence so the verifier sees an
        # INCONCLUSIVE transport failure instead of a wrongly
        # executed request. Body-parameter browser verification
        # is unsupported by design and fails the same way.
        method = (attempt.method or "GET").strip().upper()
        if method != "GET":
            raise _UnsupportedBrowserRequest(
                "method_not_supported_by_browser_executor:"
                f"{method}"
            )

        target_origin = _canonical_target_origin(attempt.endpoint)
        state = _BrowserAttemptState(
            target_origin=target_origin,
            bound_url="",
            correlation_token=attempt.correlation_token,
        )

        # The bound input value is built once and used for the
        # initial navigation URL. The token is part of this
        # string and is therefore present on the wire during the
        # initial nav. The brief explicitly forbids injecting the
        # token as anything other than the input value. For the
        # current executor, the only allowed carrier is the URL
        # query string. The bound URL is constructed here.
        bound_input = _bound_value(attempt.payload, attempt.correlation_token)
        state.bound_url = self._build_bound_url(
            attempt.endpoint, attempt.parameter, bound_input,
            parameter_location=attempt.parameter_location,
        )

        session = self._session or _PlaywrightSession()
        context = session.new_context()
        try:
            return self._run_attempt(attempt, context, state)
        finally:
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            if self._session is None:
                # Only the production session is owned by the
                # executor; injected sessions are closed by the
                # caller.
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------
    # URL construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_bound_url(
        endpoint: str,
        parameter: str | None,
        bound_input: str,
        *,
        parameter_location: str,
    ) -> str:
        """Construct the initial navigation URL.

        The bound input is placed in the query string under
        the attempt's parameter. For non-query parameter
        locations the executor refuses: the brief does not
        permit injecting the token via header, cookie,
        fragment, or DOM marker, and the body of a GET is
        not a legal carrier. ``parameter_location == "query"``
        is the only supported form.
        """

        location = (parameter_location or "").strip().lower()
        if location != "query":
            raise _UnsupportedBrowserRequest(
                f"unsupported_browser_parameter_location:{location!r}"
            )
        if not parameter:
            raise _UnsupportedBrowserRequest(
                "query_parameter_location_requires_parameter_name"
            )
        parts = urlsplit(endpoint)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise _UnsupportedBrowserRequest(
                f"unsupported_browser_endpoint_scheme:{parts.scheme!r}"
            )
        pairs = [
            (name, existing)
            for name, existing in parse_qsl(parts.query, keep_blank_values=True)
            if name != parameter
        ]
        pairs.append((parameter, bound_input))
        return urlunsplit(parts._replace(query=urlencode(pairs)))

    # ------------------------------------------------------------------
    # Attempt runtime
    # ------------------------------------------------------------------

    def _run_attempt(
        self,
        attempt: VerificationAttempt,
        context: _BrowserContextLike,
        state: _BrowserAttemptState,
    ) -> VerificationEvidence:
        # Install cross-origin block as the default route. This
        # runs after any per-attempt route registration so
        # tests can register target-origin handlers first.
        self._install_network_policy(context, state)

        page = context.new_page()
        try:
            self._install_listeners(page, state)
            # Trusted transport. The capability is generated
            # in Python; the binding is registered before the
            # init script so the instrumentation can reach the
            # executor's callback from the very first script.
            # The page receives only a write-only callable; the
            # authoritative event buffer stays Python-side.
            state.capability = _new_capability()
            self._install_transport(context, page, state)
            context.add_init_script(
                _build_init_script(state.capability)
            )
            self._navigate(page, state)
            self._post_navigation_observation(page, state)
            return self._assemble_evidence(attempt, state)
        finally:
            try:
                page.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Trusted instrumentation transport
    # ------------------------------------------------------------------

    def _install_transport(
        self,
        context: _BrowserContextLike,
        page: _BrowserPageLike,
        state: _BrowserAttemptState,
    ) -> None:
        """Install the executor-owned event transport.

        ``context.expose_binding`` installs a callable in the
        page whose invocation is marshalled by the Playwright
        driver into the Python callback below. The collected
        evidence lives exclusively in Python-side state; the
        page cannot read or mutate it. The callback is the
        ONLY write path into the buffer, and it authenticates
        every call against the per-attempt capability.
        """

        def _handler(source: object, *args: object) -> None:
            self._absorb_binding_event(state, source, args, page)

        context.expose_binding(_BINDING_NAME, _handler)

    @staticmethod
    def _absorb_binding_event(
        state: _BrowserAttemptState,
        source: object,
        args: tuple,
        page: _BrowserPageLike,
    ) -> None:
        """Receive one instrumentation event. Python-side only.

        This callback is the sole writer of the trusted event
        buffer. It authenticates the event against the
        per-attempt capability, validates the wire shape, and
        drops anything else SILENTLY. A page may call the
        binding with arbitrary arguments; without the exact
        capability the call is never recorded. The callback
        must never raise into the page.
        """

        try:
            # The binding reports which page invoked it. Only
            # events from the executor's own page are accepted.
            if isinstance(source, dict):
                src_page = source.get("page")
                if (
                    src_page is not None
                    and page is not None
                    and src_page is not page
                ):
                    return
            if len(args) != 5:
                return
            channel, op, label, value, capability = args
            if channel not in ("sources", "sinks", "observables", "storage"):
                return
            if not isinstance(capability, str) or not capability:
                return
            if state.capability == "" or not secrets.compare_digest(
                capability, state.capability
            ):
                # Unauthenticated transport call: drop. The page
                # can guess, brute-force, or omit the capability;
                # none of those calls become executor evidence.
                return
            if not (
                isinstance(op, str)
                and isinstance(label, str)
                and isinstance(value, str)
            ):
                return
            kind = channel
            ev_label = _chain_label_for(kind, op, label)
            ev = _ChainEvent(kind=kind, label=ev_label, value=value)
            sig = ev.signature()
            if sig in state.seen_chain_signatures:
                return
            # Hard upper bound: STOP APPENDING on overflow.
            if len(state.chain_events) >= _MAX_CHAIN_EVENTS:
                return
            state.seen_chain_signatures.add(sig)
            state.chain_events.append(ev)
            # Wire-side channels. The bounded entry carries the
            # value alongside the label so the verifier's
            # runtime-token substring scan remains meaningful.
            if kind == "sources":
                # Sources are not written to any evidence
                # channel; they live in the sidecar and feed
                # the chain builder.
                return
            truncated = _truncate(
                f"{ev.label}|{ev.value}", _MAX_ENTRY_LENGTH
            )
            if kind == "sinks":
                state.sink_observed = True
                state.sinks.append_dom(truncated)
            elif kind == "observables":
                state.sinks.append_dom(truncated)
            elif kind == "storage":
                state.sinks.append_storage(truncated)
        except Exception:  # noqa: BLE001
            # Never let a transport error escape into the page.
            return

    # ------------------------------------------------------------------
    # Network policy
    # ------------------------------------------------------------------

    def _install_network_policy(
        self,
        context: _BrowserContextLike,
        state: _BrowserAttemptState,
    ) -> None:
        def _policy_handler(route: _BrowserRouteLike) -> None:
            target = _origin_of(route.request.url)
            req_type = (route.request.resource_type or "").lower()

            if target is None:
                # Non-http(s) URL. Abort. Examples: data:,
                # blob:, file:, ftp:. We never let the page
                # reach these.
                route.abort("blockedbyclient")
                state.cross_origin_blocked_count += 1
                return

            target_scheme, target_host, target_port = target
            (
                expected_scheme,
                expected_host,
                expected_port,
            ) = state.target_origin

            if (
                target_scheme == expected_scheme
                and target_host == expected_host
                and target_port == expected_port
            ):
                # Same-origin. Allow; the registered route
                # handler (if any) will fulfill.
                route.continue_()
                return

            # Cross-origin runtime requests are blocked without
            # becoming runtime evidence. A blocked document request,
            # however, is a rejected top-level/frame navigation and
            # must surface as an error. Runtime fetches should not
            # make an otherwise successfully loaded page fail.
            if req_type == "document":
                state.error_reason = state.error_reason or (
                    f"cross_origin_request_blocked:{req_type}:"
                    f"{target_scheme}://{target_host}:{target_port}"
                )
            route.abort("blockedbyclient")
            state.cross_origin_blocked_count += 1

        context.route(re.compile(r".*"), _policy_handler)

    # ------------------------------------------------------------------
    # Event listeners
    # ------------------------------------------------------------------

    def _install_listeners(
        self, page: _BrowserPageLike, state: _BrowserAttemptState
    ) -> None:
        # Cache the top-level frame. Playwright's Python
        # ``Request`` does NOT expose ``from_main_frame``;
        # the canonical check is ``request.frame is
        # page.main_frame``. ``_is_navigation_request`` is
        # a small helper that uses both that comparison AND
        # ``request.is_navigation_request()`` so the
        # invariant holds across Chromium versions.
        main_frame = getattr(page, "main_frame", None)

        def _is_navigation_request(req: object) -> bool:
            # A request from the main frame is not necessarily a
            # navigation: fetch/XHR requests use the same frame.
            # Require Playwright's navigation marker as well as
            # frame identity when both are available.
            try:
                frame = getattr(req, "frame", None)
                if (
                    main_frame is not None
                    and frame is not None
                    and frame is main_frame
                ):
                    is_nav = getattr(req, "is_navigation_request", None)
                    if callable(is_nav):
                        return bool(is_nav())
            except Exception:  # noqa: BLE001
                pass
            try:
                is_nav = getattr(
                    req, "is_navigation_request", None
                )
                if callable(is_nav):
                    try:
                        if is_nav():
                            return True
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass
            try:
                # Defense in depth: any document-typed
                # request (top-level or frame) is treated
                # as a navigation request by the executor
                # and must not appear in runtime channels.
                req_type = (
                    getattr(req, "resource_type", "") or ""
                ).lower()
                if req_type == "document":
                    return True
            except Exception:  # noqa: BLE001
                pass
            return False

        def _on_console(msg: object) -> None:
            try:
                text = getattr(msg, "text", "")
                state.sinks.append_console(str(text))
            except Exception:  # noqa: BLE001
                pass

        def _on_pageerror(err: object) -> None:
            try:
                state.sinks.append_console(f"pageerror:{err}")
            except Exception:  # noqa: BLE001
                pass

        def _on_dialog(dlg: object) -> None:
            try:
                kind = getattr(dlg, "type", "alert")
                msg = getattr(dlg, "message", "")
                state.sinks.append_console(f"dialog:{kind}:{msg}")
                accept = getattr(dlg, "accept", None)
                if callable(accept):
                    try:
                        accept()
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    dismiss = getattr(dlg, "dismiss", None)
                    if callable(dismiss):
                        try:
                            dismiss()
                        except Exception:  # noqa: BLE001
                            pass
            except Exception:  # noqa: BLE001
                pass

        def _on_request(req: object) -> None:
            # ``request`` fires for every request including
            # the initial navigation and every redirect hop.
            # We use it ONLY to track the redirect chain
            # (``request.redirected_from`` / ``frame``).
            # Runtime network_requests are populated from
            # ``requestfinished`` and ``response``.
            try:
                if _is_navigation_request(req):
                    try:
                        prev = getattr(req, "redirected_from", None)
                        if prev is not None:
                            state.redirect_hop_count += 1
                            prev_url = getattr(prev, "url", "")
                            if prev_url:
                                state.nav_redirects.append(
                                    (prev_url, getattr(req, "url", ""))
                                )
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass

        def _on_request_finished(req: object) -> None:
            # Initial nav and navigation-machinery redirect
            # hops are excluded from runtime channels. The
            # executor constructs the initial navigation
            # request, so it is not page-initiated runtime
            # evidence. The check uses ``frame is
            # main_frame`` AND ``is_navigation_request()``
            # AND ``resource_type == "document"`` so the
            # invariant holds across Chromium versions.
            try:
                if _is_navigation_request(req):
                    return
                url = getattr(req, "url", "")
                if not url:
                    return
                url = _redact_credentials_in_url(url)
                state.sinks.append_network(url)
            except Exception:  # noqa: BLE001
                pass

        def _on_response(resp: object) -> None:
            try:
                url = getattr(resp, "url", "")
                if not url:
                    return
                req = getattr(resp, "request", None)
                if req is not None and _is_navigation_request(req):
                    return
                url = _redact_credentials_in_url(url)
                if url not in state.sinks.network_requests:
                    state.sinks.append_network(url)
            except Exception:  # noqa: BLE001
                pass

        def _on_request_failed(req: object) -> None:
            # ``requestfailed`` is the failure-side counterpart
            # to ``requestfinished``. Cross-origin / aborted
            # requests land here. We do NOT add failed
            # requests to ``network_requests`` (the policy
            # handler in ``_install_network_policy`` is the
            # authority on cross-origin blocks). We use this
            # hook ONLY to surface "the navigation failed
            # partway through" via the page-error path.
            try:
                if _is_navigation_request(req):
                    err = getattr(req, "failure", None)
                    if err is not None:
                        # Surface navigation failures as
                        # error_reason candidates. The
                        # ``requestfailed`` event itself is
                        # not turned into evidence; the
                        # downstream attempt status is set
                        # by the navigation path.
                        state.error_reason = (
                            state.error_reason
                            or f"navigation_request_failed:{err}"
                        )
            except Exception:  # noqa: BLE001
                pass

        def _on_crash(_: object) -> None:
            state.crashed = True
            state.error_reason = state.error_reason or "browser_page_crashed"

        def _on_close(_: object) -> None:
            if not state.timed_out:
                state.crashed = True

        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("dialog", _on_dialog)
        page.on("request", _on_request)
        page.on("requestfinished", _on_request_finished)
        page.on("requestfailed", _on_request_failed)
        page.on("response", _on_response)
        page.on("crash", _on_crash)
        page.on("close", _on_close)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _navigate(
        self, page: _BrowserPageLike, state: _BrowserAttemptState
    ) -> None:
        """Navigate to the bound URL exactly once.

        ``page.goto`` in real Playwright follows server-side
        redirects internally. The executor MUST NOT manually
        walk the redirect chain with repeated ``goto`` calls.
        Instead, the executor:

        1. Pre-validates the bound URL against the target
           origin and HTTPS→HTTP downgrade (defence in
           depth; ``context.route`` would catch the
           redirect anyway).
        2. Issues a single ``page.goto`` and lets Chromium
           resolve the chain. ``context.route`` aborts any
           cross-origin hop (including top-level nav
           redirects), which surfaces as a Playwright
           navigation error.
        3. After ``goto`` returns, walks the
           ``response.request.redirected_from`` chain to
           verify that every hop stayed inside the target
           origin (the route policy is the runtime
           enforcer; this is an audit step).
        4. Records the final URL in ``state.final_url``.

        The number of redirect hops is bounded; an excessive
        chain raises ``_BrowserSecurityError`` regardless of
        origin policy.
        """

        # Pre-check: bound URL must parse and be on the
        # target origin and not an HTTPS downgrade.
        origin = _origin_of(state.bound_url)
        if origin is None:
            raise _BrowserSecurityError(
                f"unparseable_navigation_url:{state.bound_url!r}"
            )
        ts, th, tp = origin
        es, eh, ep = state.target_origin
        if (
            ts != es
            or th != eh
            or tp != ep
        ):
            if _is_downgrade(es, ts):
                raise _BrowserSecurityError(
                    f"https_downgrade_rejected:{ts}"
                )
            raise _BrowserSecurityError(
                f"cross_origin_navigation_rejected:"
                f"{ts}://{th}:{tp}"
            )
        try:
            response = page.goto(
                state.bound_url,
                timeout=self._navigation_timeout * 1000.0,
                wait_until="domcontentloaded",
            )
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "timeout" in msg:
                state.timed_out = True
                raise _BrowserTimeout("navigation_timeout")
            if state.crashed:
                raise _BrowserCrash("browser_page_crashed")
            # A cross-origin redirect or any other
            # route-aborted navigation surfaces here. We
            # preserve the original error text so callers
            # (and tests) can identify the cause. If the
            # exception already carries a structured
            # ``_BrowserSecurityError``, we re-raise it
            # verbatim. Otherwise we wrap it as a
            # navigation_aborted error.
            if isinstance(exc, _BrowserSecurityError):
                raise
            err_text = _truncate(
                f"navigation_aborted:{type(exc).__name__}",
                _MAX_ERROR_REASON_LENGTH,
            )
            raise _BrowserSecurityError(err_text)

        if state.crashed:
            raise _BrowserCrash("browser_page_crashed")

        # Audit the redirect chain. ``response.request``
        # is the final request; ``redirected_from`` chains
        # back through intermediate requests. The runtime
        # origin enforcement is the policy in
        # ``_install_network_policy``; this loop is a
        # bounded audit step.
        final_request = getattr(response, "request", None)
        final_url = getattr(response, "url", "") or state.bound_url
        state.final_url = final_url

        hop_count = 0
        seen_origins: set[tuple[str, str, str]] = set()
        current = final_request
        while current is not None and hop_count <= self._max_navigation_hops:
            req_url = getattr(current, "url", "")
            o = _origin_of(req_url)
            if o is None:
                raise _BrowserSecurityError(
                    f"unparseable_redirect_url:{req_url!r}"
                )
            if o not in seen_origins:
                seen_origins.add(o)
                state.distinct_hop_origins.append(o)
            hts, hth, htp = o
            if (
                hts != es
                or hth != eh
                or htp != ep
            ):
                raise _BrowserSecurityError(
                    f"cross_origin_redirect_rejected:"
                    f"{hts}://{hth}:{htp}"
                )
            if _is_downgrade(es, hts):
                raise _BrowserSecurityError(
                    f"https_downgrade_redirect_rejected:{hts}"
                )
            prev = getattr(current, "redirected_from", None)
            if prev is None:
                break
            current = prev
            hop_count += 1
        if hop_count > self._max_navigation_hops:
            raise _BrowserSecurityError(
                f"redirect_limit_exceeded:{hop_count}"
            )

        # Non-2xx final response (e.g. 4xx/5xx) is
        # allowed. The page may still produce runtime
        # events; the executor's role is to observe, not
        # to interpret HTTP status.
        return

    @staticmethod
    def _extract_location(
        response: _BrowserResponseLike,
    ) -> str | None:
        # Deprecated: page.goto follows redirects internally
        # in real Playwright; the executor audits the resolved
        # chain via ``response.request.redirected_from`` and
        # delegates enforcement to ``context.route``. This
        # helper is retained as a structural hook that the
        # fake harness does not currently use.
        try:
            headers = getattr(response, "headers", None)
            if headers is None:
                return None
            value = headers.get("location")
            if value is None:
                value = headers.get("Location")
        except Exception:  # noqa: BLE001
            return None
        if isinstance(value, str) and value:
            return value
        return None

    # ------------------------------------------------------------------
    # Post-navigation observation
    # ------------------------------------------------------------------

    def _post_navigation_observation(
        self, page: _BrowserPageLike, state: _BrowserAttemptState
    ) -> None:
        """Run the bounded observation window.

        The trusted instrumentation pushes events into the
        executor-owned Python-side buffer as they happen (the
        binding callback fires while the page runs, including
        during navigation). The observation window simply
        waits, dispatching those callbacks, for page-initiated
        runtime events to arrive. It is bounded. There is no
        page-side state to drain and no page-controlled
        serialiser is ever evaluated.
        """

        # Wait the observation window. Real Playwright's
        # ``wait_for_timeout`` runs the event loop, so binding
        # callbacks and page events are dispatched during the
        # wait. The fake implementation overrides this as a
        # no-op (its events have already been pushed).
        waiter = getattr(page, "wait_for_timeout", None)
        if callable(waiter):
            try:
                waiter(int(self._observation_window * 1000.0))
                return
            except Exception:  # noqa: BLE001
                pass
        self._sleep(self._observation_window)

    @staticmethod
    def _sleep(seconds: float) -> None:
        # Indirection so the fake can override it.
        import time as _time
        _time.sleep(seconds)

    # ------------------------------------------------------------------
    # Evidence assembly
    # ------------------------------------------------------------------

    def _assemble_evidence(
        self,
        attempt: VerificationAttempt,
        state: _BrowserAttemptState,
    ) -> VerificationEvidence:
        # Build source_to_sink chain. The chain is built ONLY
        # from the events the instrumentation actually saw.
        chain = self._build_chain(attempt, state)

        # Token observation: scan runtime channels for the
        # exact token. ``observed_correlation_token`` is the
        # literal token substring if found; it is never
        # derived from the attempt, initial URL, payload, or
        # page snapshot.
        observed_token = state.sinks.find_token(attempt.correlation_token)

        executed_script = state.sink_observed
        correlation_token_in_runtime = observed_token is not None

        browser = BrowserExecutionObservation(
            executed_script=executed_script,
            dom_changes=list(state.sinks.dom_changes),
            console_messages=list(state.sinks.console_messages),
            network_requests=list(state.sinks.network_requests),
            storage_writes=list(state.sinks.storage_writes),
            correlation_token_in_runtime=correlation_token_in_runtime,
            observed_correlation_token=observed_token,
            source_to_sink=chain,
        )

        # Stored phase evidence. For stored XSS, we record
        # a READ observation if the token is in any runtime
        # channel. The orchestrator is responsible for
        # triggering SUBMIT (not in scope here).
        stored_phases: list[StoredXSSPhaseObservation] = []
        if (attempt.phase or "").strip().lower() == "stored":
            if observed_token is not None:
                stored_phases.append(
                    StoredXSSPhaseObservation(
                        phase=StoredXSSPhase.READ,
                        attempt_id=attempt.attempt_id,
                        observed_correlation_token=observed_token,
                    )
                )
            # If the token is not observed, the executor
            # reports nothing for stored phases. The
            # orchestrator must drive a SUBMIT pass.

        # WAF observations: kept empty. The browser executor
        # has no WAF classification logic; WAF metadata is
        # the HTTP executor's responsibility.
        waf: list[WAFObservation] = []

        # If a security error was raised during navigation
        # we still produce ERROR evidence here, not
        # SUCCEEDED.
        if state.error_reason is not None:
            return self._error_evidence(
                attempt, state.error_reason, AttemptStatus.ERROR
            )

        # Default: SUCCEEDED.
        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            request_headers_redacted={},
            response_status=None,
            response_headers_redacted={},
            response_body_truncated=None,
            reflection=ReflectionObservation(
                reflected=False,
                location=ReflectionLocation.NONE,
            ),
            browser=browser,
            waf_observations=waf,
            stored_phases=stored_phases,
        )

    # ------------------------------------------------------------------
    # Chain construction
    # ------------------------------------------------------------------

    def _build_chain(
        self, attempt: VerificationAttempt, state: _BrowserAttemptState
    ) -> list[SourceToSinkStep]:
        """Build the source-to-sink chain from observed events.

        Value-flow contract
        -------------------

        The chain is built ONLY when the executor can prove a
        defensible value flow:

        1. ``source.value`` matches ``attempt.parameter`` (the
           source event label contains the parameter name
           AND the source event carries a non-empty captured
           value).
        2. ``sink.value`` overlaps ``source.value``: the
           bounded value the sink received contains the
           bounded value the source returned (or vice-versa
           for cases where the page slices the parameter
           value). Empty source/sink values are rejected.
        3. ``observable.value`` overlaps ``sink.value``: the
           bounded mutation text the MutationObserver
           captured contains the bounded value the sink
           received (or vice-versa).

        If any step fails, the chain is empty. Partial chains
        are forbidden by the brief; we do not invent steps.
        A defensible chain requires a complete value flow.

        Each emitted step carries a bounded description of
        the form ``"<kind>|<label>|<value excerpt>"`` so the
        verifier can still perform its own structural
        binding. The value-flow gate is executor-side; the
        verifier remains the final authority.
        """

        param = attempt.parameter or ""
        # Collect source events that actually reference
        # the attempt's parameter name in their label AND
        # carry a non-empty value. These are the candidate
        # sources of the parameter value.
        param_sources: list[_ChainEvent] = []
        for ev in state.chain_events:
            if ev.kind != "sources":
                continue
            if param and param in ev.label and ev.value:
                param_sources.append(ev)
        if not param_sources:
            return []

        # Candidate sinks: any sink event with a non-empty
        # value that overlaps the source value.
        sink_pairs: list[tuple[_ChainEvent, _ChainEvent]] = []
        for src in param_sources:
            for ev in state.chain_events:
                if ev.kind != "sinks":
                    continue
                if not ev.value:
                    continue
                if src.value in ev.value or ev.value in src.value:
                    sink_pairs.append((src, ev))
        if not sink_pairs:
            return []

        # Candidate observables: any observable event whose
        # value overlaps the matched sink's value.
        full_pairs: list[
            tuple[_ChainEvent, _ChainEvent, _ChainEvent]
        ] = []
        for src, sink in sink_pairs:
            for ev in state.chain_events:
                if ev.kind != "observables":
                    continue
                if not ev.value:
                    continue
                if (
                    sink.value in ev.value
                    or ev.value in sink.value
                ):
                    full_pairs.append((src, sink, ev))
        if not full_pairs:
            return []

        # Pick the first source / sink / observable that
        # form a complete chain (by sidecar order). The
        # selection is deterministic.
        src, sink, obs = full_pairs[0]

        def _desc(kind: str, label: str, value: str) -> str:
            excerpt = _truncate(value, _MAX_DESCRIPTION_LENGTH)
            return f"{kind}|{label}|{excerpt}"[:_MAX_DESCRIPTION_LENGTH]

        parameter_step = SourceToSinkStep(
            kind="parameter",
            description=_desc("parameter", param, src.value),
            location=None,
            parameter_name=attempt.parameter,
            parameter_location=attempt.parameter_location,
            endpoint=attempt.endpoint,
        )
        sink_step = SourceToSinkStep(
            kind="sink",
            description=_desc(sink.label or "sink", sink.label, sink.value),
            location=None,
        )
        observable_step = SourceToSinkStep(
            kind="observable",
            description=_desc(obs.label or "observable", obs.label, obs.value),
            location=None,
        )
        chain = [parameter_step, sink_step, observable_step]
        if len(chain) > _MAX_CHAIN_STEPS:
            chain = chain[:_MAX_CHAIN_STEPS]
        return chain

    # ------------------------------------------------------------------
    # Error evidence
    # ------------------------------------------------------------------

    @staticmethod
    def _error_evidence(
        attempt: VerificationAttempt,
        reason: str,
        status: AttemptStatus,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=status,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            request_headers_redacted={},
            response_status=None,
            response_headers_redacted={},
            response_body_truncated=None,
            reflection=ReflectionObservation(
                reflected=False,
                location=ReflectionLocation.NONE,
            ),
            browser=None,
            waf_observations=[],
            error_reason=_truncate(reason, _MAX_ERROR_REASON_LENGTH),
        )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _redact_credentials_in_url(url: str) -> str:
    """Redact well-known credential-bearing query parameters.

    The brief states: "No Cookie or Authorization values
    may appear in evidence." The runtime channels record
    URLs of page-initiated requests. Those URLs may contain
    session credentials in the query string, so a bounded
    allowlist of well-known credential parameter names is
    redacted. The executor's own correlation token is NOT a
    credential (the schema explicitly does not rely on its
    secrecy) and must remain observable in runtime channels
    for the verifier's independent token match, so a bare
    ``token`` parameter name is not in the allowlist;
    credential-bearing names such as ``access_token``,
    ``api_key``, ``secret``, ``password`` are.
    """

    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    except ImportError:  # pragma: no cover
        return url
    parts = urlsplit(url)
    if not parts.query:
        return url
    sensitive = {
        "access_token",
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "session",
        "sid",
        "auth",
        "authorization",
    }
    pairs = []
    redacted = False
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in sensitive:
            pairs.append((name, _REDACTED_PLACEHOLDER))
            redacted = True
        else:
            pairs.append((name, value))
    if not redacted:
        return url
    # The "[REDACTED]" placeholder must remain human-readable
    # in the recorded URL, so "[" and "]" are marked safe.
    return urlunsplit(
        parts._replace(
            query=urlencode(pairs, safe="[]")
        )
    )


def _resolve_redirect(current_url: str, location: str) -> str:
    from urllib.parse import urljoin
    return urljoin(current_url, location)


def _execute_browser_worker(
    result_queue: "mp.Queue[tuple[bool, object]]",
    attempt: "VerificationAttempt",
    navigation_timeout: float,
    observation_window: float,
    max_navigation_hops: int,
) -> None:
    """Worker process entry point for wall-clock-bounded execution."""
    try:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=navigation_timeout,
            observation_window_seconds=observation_window,
            max_navigation_hops=max_navigation_hops,
        )
        evidence = ex._execute(attempt)
        result_queue.put((True, evidence))
    except Exception as exc:  # noqa: BLE001
        result_queue.put((False, str(exc)))


__all__ = [
    "BrowserEvidenceExecutor",
]

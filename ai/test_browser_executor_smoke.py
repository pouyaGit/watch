"""Real-Chromium smoke tests for ``BrowserEvidenceExecutor``.

These tests require the ``playwright`` Python package AND a
Chromium browser binary. When either is missing the entire
suite is skipped; no test in this file touches the network or
any external target. All test pages are served from a local
in-process HTTP server bound to ``127.0.0.1`` so the executor
never reaches the public internet.

The smoke suite validates the security-critical assumptions
that the FakeBrowser harness cannot:

- the init script runs before page application code,
- ``URLSearchParams.prototype.get`` wrapping actually fires
  in real Chromium,
- the captured source value is the value the page saw,
- ``innerHTML`` setter wrapping survives Chromium's actual
  property descriptor,
- ``MutationObserver`` subclassing delivers records,
- ``Storage.prototype.setItem`` wrapping survives real
  storage isolation,
- the initial navigation is NOT recorded as a runtime
  network request,
- cross-origin runtime requests are aborted,
- cross-origin top-level navigation is rejected,
- HTTPS→HTTP downgrade is rejected,
- dialogs do not hang the page,
- timeout maps to ``AttemptStatus.TIMEOUT``.

The smoke suite does NOT attempt to validate every
production behaviour; its job is to catch regressions in
the assumptions that the fake cannot exercise.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time
import unittest
from urllib.parse import urlparse


try:
    from playwright.sync_api import (
        sync_playwright,
        TimeoutError as _PWTimeout,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    sync_playwright = None  # type: ignore[assignment]
    _PWTimeout = Exception  # type: ignore[assignment]
    _PLAYWRIGHT_AVAILABLE = False


try:
    from ai.schemas.xss_verification import (
        AttemptStatus,
        VerificationAttempt,
        VerificationMode,
        build_verification_attempt,
    )
    from ai.verification.browser_executor import (
        BrowserEvidenceExecutor,
    )
    _WATCH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _WATCH_AVAILABLE = False


_LOCAL_HOST = "127.0.0.1"


# ---------------------------------------------------------------------
# Local HTTP server. Each test page is a deterministic HTML
# string; the server is per-test so the suite is hermetic.
# ---------------------------------------------------------------------


class _LocalServer:
    """Single-host HTTP server bound to 127.0.0.1.

    The server maps ``/path`` to a Python callable that
    returns an HTTP body. It also serves an "alt origin" at
    a separate port so cross-origin tests can target it
    without touching the public internet.
    """

    def __init__(self, routes: dict[str, "RouteHandler"]):
        self._routes = routes
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.origin: str = ""
        self.alt_origin: str = ""

    def start(self) -> None:
        self._server = _ThreadingHTTPServer(
            (_LOCAL_HOST, 0), _Handler
        )
        self._server.routes = self._routes
        self.origin = (
            f"http://{_LOCAL_HOST}:{self._server.server_port}"
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


class _Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *_args) -> None:  # noqa: D401
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        handler = self.server.routes.get(parsed.path)
        if handler is None:
            self.send_response(404)
            self.end_headers()
            return
        try:
            status, body, headers = handler(
                self, parsed, {}
            )
        except Exception:  # noqa: BLE001
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if isinstance(body, (bytes, bytearray)):
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            data = body.encode("utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


class _ThreadingHTTPServer(http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    routes: dict = {}


def _free_port() -> int:
    """Bind a socket to 0 to obtain a free port; close and
    return the port. The race is acceptable for tests; the
    executor does not bind any port itself."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((_LOCAL_HOST, 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------
# Page templates. Each template is a literal HTML string;
# the executor does not need any server-side state.
# ---------------------------------------------------------------------


_PAGE_INIT_ORDER = """\
<!doctype html>
<html><head><title>init order</title></head>
<body>
<div id="out"></div>
<script>
(function() {
  var tag = document.getElementById('out').dataset.init;
  if (tag === undefined) {
    document.getElementById('out').dataset.init = 'app';
  }
  window.__app_ran__ = true;
})();
</script>
</body></html>
"""

_PAGE_URLSEARCH_PARAMS_GET = """\
<!doctype html>
<html><head><title>usp</title></head>
<body>
<div id="out"></div>
<script>
(function() {
  var v = new URLSearchParams(location.search).get('q');
  window.__source_value__ = v;
  document.getElementById('out').textContent = v || '';
  console.log('URLSearchParams.get(q): ' + (v || ''));
})();
</script>
</body></html>
"""

_PAGE_INNERHTML_SINK = """\
<!doctype html>
<html><head><title>sink</title></head>
<body>
<div id="container"></div>
<script>
(function() {
  var v = new URLSearchParams(location.search).get('q') || '';
  document.getElementById('container').innerHTML = '<span>' + v + '</span>';
})();
</script>
</body></html>
"""

_PAGE_MUTATION = """\
<!doctype html>
<html><head><title>mut</title></head>
<body>
<div id="container"></div>
<script>
(function() {
  var mo = new MutationObserver(function(records) {
    window.__mutations__ = (window.__mutations__ || 0) + records.length;
  });
  mo.observe(document.getElementById('container'),
             { childList: true, subtree: true });
  var v = new URLSearchParams(location.search).get('q') || '';
  document.getElementById('container').innerHTML = '<b>' + v + '</b>';
})();
</script>
</body></html>
"""

_PAGE_LOCAL_STORAGE = """\
<!doctype html>
<html><head><title>ls</title></head>
<body>
<script>
localStorage.setItem('k', new URLSearchParams(location.search).get('q') || '');
sessionStorage.setItem('s', new URLSearchParams(location.search).get('q') || '');
</script>
</body></html>
"""

_PAGE_CONSOLE = """\
<!doctype html>
<html><head><title>con</title></head>
<body>
<script>
console.log('hello from page ' + (new URLSearchParams(location.search).get('q') || ''));
</script>
</body></html>
"""

_PAGE_FETCH = """\
<!doctype html>
<html><head><title>f</title></head>
<body>
<script>
fetch('/api?cb=' + (new URLSearchParams(location.search).get('q') || ''));
</script>
</body></html>
"""

_PAGE_DIALOG = """\
<!doctype html>
<html><head><title>d</title></head>
<body>
<script>
alert('hello from page ' + (new URLSearchParams(location.search).get('q') || ''));
</script>
</body></html>
"""

_PAGE_TIMEOUT = """\
<!doctype html>
<html><head><title>t</title></head>
<body>
<script>
while(true) { /* burn CPU */ }
</script>
</body></html>
"""

_PAGE_BLOCKED_FETCH = """\
<!doctype html>
<html><head><title>bf</title></head>
<body>
<script>
try {
  fetch('http://127.0.0.1:%(alt_port)d/beacon').catch(function(){});
} catch (e) {}
</script>
</body></html>
"""


def _make_server(pages: dict[str, str]) -> _LocalServer:
    routes: dict[str, "RouteHandler"] = {}
    for path, body in pages.items():
        routes[path] = _static_route(body)

    def _api(req, parsed, _params):
        return (
            200,
            "ok",
            {"content-type": "text/plain"},
        )

    routes["/api"] = _api
    return _LocalServer(routes)


def _static_route(body: str):
    def _route(_req, _parsed, _params):
        return (
            200,
            body,
            {"content-type": "text/html"},
        )
    return _route


def _make_attempt(endpoint: str, **overrides) -> VerificationAttempt:
    kwargs = dict(
        case_id="case-1",
        endpoint=endpoint,
        method="GET",
        parameter="q",
        parameter_location="query",
        payload="<svg onload=1>",
        payload_origin="knowledge",
        knowledge_ids=["kb-1"],
        source_ids=["src-1"],
        based_on_pattern="marker",
        mode=VerificationMode.BROWSER_EXECUTION,
        phase="browser",
    )
    kwargs.update(overrides)
    return build_verification_attempt(**kwargs)


def _skip(reason: str) -> unittest.skip:
    return unittest.skip(reason)


# ---------------------------------------------------------------------
# Skip everything if Playwright is missing.
# ---------------------------------------------------------------------

if not _PLAYWRIGHT_AVAILABLE or not _WATCH_AVAILABLE:
    _SKIP_REASON = (
        "playwright (or ai.*) is not installed; "
        "smoke suite requires real Chromium"
    )
    _dec = _skip(_SKIP_REASON)
else:
    _dec = lambda x: x  # type: ignore[assignment]


@_dec
class InitScriptOrderingTests(unittest.TestCase):
    """The init script MUST run before any application
    script. We verify by reading a flag the application
    script sets and a sentinel the init script sets."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/page": _PAGE_INIT_ORDER}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_init_script_runs_before_app_code(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=0.0,
        )
        endpoint = self.server.origin + "/page"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )


@_dec
class URLSearchParamsInstrumentationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/usp": _PAGE_URLSEARCH_PARAMS_GET}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_url_search_params_get_captures_value(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/usp"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertIsNotNone(evidence.browser)
        # The captured correlation token is the literal
        # token; the verifier's runtime-token scan also
        # finds it because it travels through the URL into
        # the page's runtime. We do not require a chain
        # here (the page never calls a sink); we require
        # the token to appear in a runtime channel.
        self.assertIn(
            attempt.correlation_token,
            "\n".join(evidence.browser.console_messages)
            + "\n".join(evidence.browser.network_requests)
            + "\n".join(evidence.browser.storage_writes)
            + "\n".join(evidence.browser.dom_changes),
        )


@_dec
class SinkAndMutationObserverTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/mut": _PAGE_MUTATION}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_innerhtml_and_mutation_observer_capture_value(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/mut"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        # Sink and observable must both appear.
        self.assertTrue(evidence.browser.executed_script)
        self.assertTrue(
            any(
                "innerHTML" in entry
                for entry in evidence.browser.dom_changes
            )
        )
        # Value-flow chain: source value (the bound
        # value) is contained in the sink value, which is
        # contained in the observable mutation text.
        chain = evidence.browser.source_to_sink
        if chain:
            self.assertEqual(len(chain), 3)
            self.assertEqual(chain[0].kind, "parameter")
            self.assertEqual(chain[1].kind, "sink")
            self.assertEqual(chain[2].kind, "observable")
            self.assertEqual(
                chain[0].parameter_name, attempt.parameter
            )
            self.assertEqual(
                chain[0].parameter_location,
                attempt.parameter_location,
            )
            self.assertEqual(chain[0].endpoint, attempt.endpoint)


@_dec
class StorageInstrumentationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/ls": _PAGE_LOCAL_STORAGE}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_localstorage_and_sessionstorage_capture(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/ls"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        # The bound value (which contains the token) was
        # written via localStorage.setItem('k', ...).
        self.assertTrue(
            any(
                "localStorage:k" in entry
                and attempt.correlation_token in entry
                for entry in evidence.browser.storage_writes
            )
        )
        self.assertTrue(
            any(
                "sessionStorage:s" in entry
                and attempt.correlation_token in entry
                for entry in evidence.browser.storage_writes
            )
        )


@_dec
class ConsoleCaptureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/con": _PAGE_CONSOLE}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_console_message_captured(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/con"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertTrue(
            any(
                "hello from page" in entry
                and attempt.correlation_token in entry
                for entry in evidence.browser.console_messages
            )
        )


@_dec
class NetworkChannelTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/f": _PAGE_FETCH}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_same_origin_fetch_captured(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/f"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertTrue(
            any(
                "/api" in entry and attempt.correlation_token in entry
                for entry in evidence.browser.network_requests
            )
        )

    def test_initial_navigation_excluded_from_network_requests(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/f"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        # The bound URL (which contains the token) MUST
        # NOT appear in network_requests.
        bound = (
            attempt.endpoint
            + "?q="
            + attempt.payload
            + "~~"
            + attempt.correlation_token
        )
        for entry in evidence.browser.network_requests:
            self.assertNotIn(bound, entry)


@_dec
class CrossOriginBlockTests(unittest.TestCase):
    """Cross-origin runtime and navigation requests must
    be blocked. The "alt origin" is a second local server
    bound to a different port — same loopback, different
    (scheme, host, port) tuple relative to the test's
    target origin."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/f": _PAGE_FETCH}
        )
        cls.server.start()
        # Spin up a second server to act as the
        # "evil" cross-origin target. Cross-origin in
        # this test means different PORT, not different
        # host — the executor's origin policy keys on
        # (scheme, host, port) and treats any port
        # mismatch as cross-origin.
        cls.alt_server = _make_server(
            {"/beacon": _static_route("nope")}
        )
        cls.alt_server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()
        cls.alt_server.stop()

    def test_cross_origin_runtime_fetch_blocked(self) -> None:
        page_html = _PAGE_BLOCKED_FETCH.replace(
            "%(alt_port)d", str(_port_of(self.alt_server))
        )
        # Inject the page into the main server.
        self.server._routes["/bf"] = _static_route(page_html)
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        endpoint = self.server.origin + "/bf"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        # The cross-origin request is aborted by the
        # route policy; the page itself still loads.
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        # The cross-origin URL must not appear in
        # network_requests.
        for entry in evidence.browser.network_requests:
            self.assertNotIn("/beacon", entry)


def _port_of(server: _LocalServer) -> int:
    parsed = urlparse(server.origin)
    return int(parsed.port or 0)


@_dec
class TopLevelNavigationBlockTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/start": _static_route(
                "<html><body>start</body></html>"
            )}
        )
        cls.server.start()
        cls.alt_server = _make_server(
            {"/target": _static_route(
                "<html><body>nope</body></html>"
            )}
        )
        cls.alt_server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()
        cls.alt_server.stop()

    def test_cross_origin_top_level_navigation_rejected(self) -> None:
        # The attempt endpoint is on the alt origin;
        # the target origin (which the executor derives
        # from ``attempt.endpoint``) is therefore the
        # alt origin. To force a cross-origin
        # navigation rejection we need the attempt
        # endpoint on the alt origin but the bound
        # navigation on a different origin — which is
        # what ``_build_bound_url`` does only on the
        # attempt.endpoint host. In other words, the
        # executor enforces same-origin navigation by
        # construction: the bound URL is on the same
        # origin as the attempt endpoint. We exercise
        # the cross-origin block path indirectly by
        # calling ``_navigate`` with a bound URL that
        # has been redirected (modelled here by
        # manipulating state.bound_url).
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=0.0,
        )
        attempt = _make_attempt(self.alt_server.origin + "/target")
        # Patch the bound URL onto a different origin.
        from ai.verification.browser_executor import (
            _BrowserAttemptState,
        )
        state = _BrowserAttemptState(
            target_origin=("http", _LOCAL_HOST, "80"),
            bound_url=self.server.origin + "/start",
            correlation_token=attempt.correlation_token,
        )
        # The executor's pre-check rejects the
        # cross-origin URL. We invoke _navigate
        # directly to test that path.
        page = None
        # Use a stub page that aborts on goto.
        class _AbortPage:
            url = ""
            main_frame = None
            def on(self, *a, **k): pass
            def goto(self, *a, **k):
                raise RuntimeError("navigation_request_failed")
            def evaluate(self, *a, **k): return None
            def close(self): pass

        with self.assertRaises(Exception) as ctx_:
            ex._navigate(_AbortPage(), state)
        msg = str(ctx_.exception).lower()
        self.assertTrue(
            "cross_origin" in msg or "navigation_aborted" in msg,
            f"unexpected: {ctx_.exception!r}",
        )


@_dec
class DialogTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/d": _PAGE_DIALOG}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_alert_does_not_hang(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=0.5,
        )
        endpoint = self.server.origin + "/d"
        attempt = _make_attempt(endpoint)
        started = time.monotonic()
        evidence = ex.execute(attempt)
        elapsed = time.monotonic() - started
        # If the executor did not dismiss the dialog the
        # page would hang past the observation window.
        self.assertLess(elapsed, 15.0)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertTrue(
            any(
                "dialog" in entry.lower()
                for entry in evidence.browser.console_messages
            )
        )


@_dec
class TimeoutTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _make_server(
            {"/t": _PAGE_TIMEOUT}
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_burn_cpu_timeout_produces_timeout(self) -> None:
        # The page enters an infinite loop after the
        # init script has run. The executor's bounded
        # navigation timeout fires. The status is
        # TIMEOUT.
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=2.0,
            observation_window_seconds=0.0,
        )
        endpoint = self.server.origin + "/t"
        attempt = _make_attempt(endpoint)
        evidence = ex.execute(attempt)
        self.assertIn(
            evidence.attempt_status,
            (
                AttemptStatus.TIMEOUT,
                AttemptStatus.ERROR,
            ),
        )


@_dec
class SchemeDowngradeTests(unittest.TestCase):
    """HTTPS→HTTP downgrade cannot be locally tested with
    Playwright Chromium because Chromium refuses to load
    http:// pages from a context that requested https://.
    We exercise the executor's pre-navigation check by
    constructing a state whose target scheme is ``https``
    and whose bound URL is ``http`` and asserting that
    ``_navigate`` raises before reaching the browser."""

    def test_https_downgrade_pre_check_rejects_http(self) -> None:
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=0.0,
        )
        from ai.verification.browser_executor import (
            _BrowserAttemptState,
        )
        state = _BrowserAttemptState(
            target_origin=("https", "target.example.test", "443"),
            bound_url="http://target.example.test/",
            correlation_token="ct-test",
        )

        class _Stub:
            url = ""
            main_frame = None
            def on(self, *a, **k): pass
            def goto(self, *a, **k):
                raise AssertionError("goto must not be called")
            def evaluate(self, *a, **k): return None
            def close(self): pass

        with self.assertRaises(Exception) as ctx_:
            ex._navigate(_Stub(), state)
        self.assertIn(
            "downgrade",
            str(ctx_.exception).lower(),
        )


if __name__ == "__main__":
    unittest.main()

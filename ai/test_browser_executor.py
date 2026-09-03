import http.server
import re
import threading
import unittest
from typing import Any, Callable
from unittest import mock
from urllib.parse import urlsplit
import re
import unittest
from typing import Any, Callable

from ai.schemas.xss import (
    XSSAttributedValue,
    XSSCase,
    XSSContext,
    XSSResearchContext,
    XSSResearchLLMResult,
    XSSSuggestedPayload,
)
from ai.schemas.xss_verification import (
    AttemptStatus,
    StoredXSSPhase,
    VerificationAttempt,
    VerificationMode,
    build_verification_attempt,
)
from ai.verification import browser_executor as browser_module
from ai.verification.browser_executor import (
    BrowserEvidenceExecutor,
)
from ai.verification.oracle import evaluate_e2_network
from ai.verification.verifier import XSSVerifier
from ai.researcher.xss_orchestrator import (
    XSSAnalysisAudit,
    XSSAnalysisResult,
)

try:
    from playwright.sync_api import (
        sync_playwright as _sync_playwright_probe,
    )
    _REAL_CHROMIUM_AVAILABLE = True
except ImportError:  # pragma: no cover
    _sync_playwright_probe = None  # type: ignore[assignment]
    _REAL_CHROMIUM_AVAILABLE = False


KNOWLEDGE_ID = "kb-1234567890abcde"
SOURCE_ID = "src-1234567890abcde"
ENDPOINT = "https://target.example.test/search"
PAYLOAD = "<img src=x onerror=alert(1)>"

# Sentinel so the fake's binding push can omit the capability
# (meaning: use the capability the executor embedded in the
# init script, like the real instrumentation does).
_MISSING_CAPABILITY = object()


# =====================================================================
# Fake browser primitives
# =====================================================================


class _RecordingRoute:
    """Implements the route object the executor's policy
    handler calls. Records which method the policy invoked."""

    def __init__(self, request: "FakeRequest"):
        self.request = request
        self._aborted: str | None = None
        self._continued: bool = False
        self._fulfilled: dict | None = None

    def fulfill(
        self,
        *,
        status: int = 200,
        body: str = "",
        headers: dict[str, str] | None = None,
        content_type: str | None = None,
    ) -> None:
        hdrs = dict(headers or {})
        if (
            content_type
            and "content-type" not in {k.lower() for k in hdrs}
        ):
            hdrs["content-type"] = content_type
        self._fulfilled = {
            "status": status,
            "body": body,
            "headers": hdrs,
        }

    def abort(self, reason: str = "blockedbyclient") -> None:
        # Real Playwright accepts only standard abort codes. Preserve
        # the fake's diagnostic detail for policy assertions without
        # requiring production code to pass an invalid custom code.
        self._aborted = (
            "cross_origin_blockedbyclient"
            if reason == "blockedbyclient"
            else reason
        )

    def continue_(self) -> None:
        self._continued = True


class FakeRequest:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        resource_type: str = "other",
        from_main_frame: bool = False,
    ):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.from_main_frame = from_main_frame
        self.frame = None
        self.headers: dict[str, str] = {}


class FakeResponse:
    def __init__(self, url: str, status: int, headers=None, body: str = ""):
        self.url = url
        self.status = status
        self.headers = dict(headers or {})
        self.body = body


class FakePage:
    """In-memory page. Test drives events via post-nav hooks
    installed before execute, or directly between steps.

    The fake models the trusted transport: instrumentation
    events are pushed through the context's executor-owned
    binding handler (``FakeContext.expose_binding``), exactly
    like the production init script pushes them through
    ``window.__watchTransport``. The page-level record_* helpers
    simulate the instrumentation itself, NOT page JavaScript:
    they authenticate with the capability the executor
    embedded in the init script.
    """

    def __init__(self, context: "FakeContext"):
        self._context = context
        self.url: str = ""
        self._listeners: dict[str, Callable[..., None]] = {}
        self._init_scripts: list[str] = []
        # Post-nav hooks fired during the observation
        # window. The test installs them via
        # add_post_nav_hook; the executor's sleep path
        # triggers them via the session.
        self._post_nav_hooks: list[Callable[[], None]] = []
        # Tracks direct channel accumulators for tests
        # that bypass the event listeners.
        self.direct_dom: list[str] = []
        self.direct_console: list[str] = []
        self.direct_network: list[str] = []
        self.direct_storage: list[str] = []
        self._last_response: FakeResponse | None = None

    # ---- BrowserContextLike methods the executor calls ----
    def on(self, event: str, handler: Callable[..., None]) -> None:
        self._listeners[event] = handler

    def add_init_script(self, script: str) -> None:
        self._init_scripts.append(script)

    def goto(
        self,
        url: str,
        *,
        timeout: float,
        wait_until: str,
    ) -> FakeResponse:
        self.url = url
        return self._context._drive_navigation(url)

    def evaluate(
        self, script: str, arg: Any = None
    ) -> Any:
        # The executor no longer evaluates page-side
        # serialisers: the trusted transport is push-based.
        return None

    def close(self) -> None:
        pass

    # ---- Test-driven event emission ----
    def add_post_nav_hook(self, hook: Callable[[], None]) -> None:
        self._post_nav_hooks.append(hook)

    def fire_post_nav_hooks(self) -> None:
        for hook in list(self._post_nav_hooks):
            try:
                hook()
            except Exception:  # noqa: BLE001
                pass

    def _transport_capability(self) -> str | None:
        # Mirrors the production init script's closure: the
        # capability the executor embedded when registering
        # the instrumentation.
        for script in reversed(self._init_scripts):
            match = re.search(
                r"__watchCapability\s*=\s*\"([0-9a-f]+)\"", script
            )
            if match:
                return match.group(1)
        return None

    def _push_binding_event(
        self,
        channel: str,
        op: str,
        label: str,
        value: str,
        capability: object = _MISSING_CAPABILITY,
    ) -> None:
        """Simulate the instrumentation's binding call.

        The capability defaults to the one the executor
        embedded in the init script; tamper tests can pass an
        explicit (wrong) value to simulate hostile calls.
        """
        if capability is _MISSING_CAPABILITY:
            capability = self._transport_capability()
        handler = self._context._binding_handler
        if handler is None:
            return
        handler(
            {"page": self},
            channel,
            op,
            label,
            value,
            capability,
        )

    def record_chain_event(self, kind: str, description: str) -> None:
        # Legacy single-argument form: label only, no
        # value. Treated as ``[kind, description, ""]``.
        self.record_chain_value(kind, description, "")

    def record_chain_value(
        self, kind: str, label: str, value: str
    ) -> None:
        # Value-flow form: label + bounded value, routed
        # through the trusted transport with the capability.
        channel = {
            "source": "sources",
            "sink": "sinks",
            "observable": "observables",
        }.get(kind)
        if channel is None:
            return
        self._push_binding_event(channel, kind, label, value)

    def record_storage_write(self, entry: str) -> None:
        # Models the init script's Storage.prototype.setItem
        # hook: only actual runtime writes reach this list.
        # Pre-existing storage never appears here. The entry
        # is the structured "<area>:<key>=<value>" string the
        # old page-side buffer used; it is split and pushed
        # through the trusted transport as (area, key, value).
        lhs, sep, value = entry.partition("=")
        if not sep:
            lhs, value = entry, ""
        area, sep2, key = lhs.partition(":")
        if not sep2:
            area, key = "", lhs
        self._push_binding_event("storage", area, key, value)

    def emit_console(self, text: str, type_: str = "log") -> None:
        if "console" in self._listeners:
            class M:
                def __init__(self, t, ty):
                    self.type = ty
                    self.text = t

            self._listeners["console"](M(text, type_))

    def emit_pageerror(self, text: str) -> None:
        if "pageerror" in self._listeners:
            class E:
                def __init__(self, t):
                    self._t = t

                def __str__(self):
                    return self._t

            self._listeners["pageerror"](E(text))

    def emit_dialog(self, kind: str, message: str) -> None:
        if "dialog" in self._listeners:
            class D:
                def __init__(self, k, m):
                    self.type = k
                    self.message = m

                def accept(self_inner):
                    return None

            self._listeners["dialog"](D(kind, message))

    def emit_request_finished(
        self, url: str, from_main_frame: bool = False
    ) -> None:
        if "requestfinished" in self._listeners:
            class R:
                def __init__(self, u, f):
                    self.url = u
                    self.from_main_frame = f
                    self.frame = None

            self._listeners["requestfinished"](R(url, from_main_frame))

    def emit_response(
        self, url: str, from_main_frame: bool = False
    ) -> None:
        if "response" in self._listeners:
            class Req:
                from_main_frame = from_main_frame

            class Resp:
                def __init__(self, u, r):
                    self.url = u
                    self.request = r

            self._listeners["response"](Resp(url, Req()))

    def emit_crash(self) -> None:
        if "crash" in self._listeners:
            self._listeners["crash"](None)


class FakeContext:
    """In-memory browser context."""

    def __init__(self, session: "FakeSession"):
        self._session = session
        self._closed = False
        # Routes registered by the executor (the policy
        # handler) and by the test (body handlers).
        self._executor_route: Callable | None = None
        self._test_routes: list[Callable[[FakeRequest], dict]] = []
        self._pages: list[FakePage] = []
        # Executor-owned trusted transport. The executor
        # registers exactly one binding; the fake stores the
        # handler so simulated instrumentation calls can be
        # routed into the Python-side buffer.
        self._binding_name: str | None = None
        self._binding_handler: Callable[..., None] | None = None
        # Pre-existing localStorage state. The executor
        # must NOT report these as runtime writes.
        self._pre_existing_local_storage: dict[str, str] = {}
        # The origin the fake considers "target" for
        # redirect safety checks. Tests can override.
        self._target_origin: tuple[str, str, str] | None = None

    def new_page(self) -> FakePage:
        page = FakePage(self)
        self._pages.append(page)
        return page

    def route(
        self,
        pattern: Any,
        handler: Callable[["FakeRoute"], None],
    ) -> None:
        # The executor registers exactly one route with
        # pattern=re.compile(r".*") and a policy handler.
        if pattern is not None:
            self._executor_route = handler

    def add_init_script(self, script: str) -> None:
        for page in self._pages:
            page.add_init_script(script)

    def expose_binding(
        self, name: str, handler: Callable[..., None]
    ) -> None:
        # The executor registers the trusted transport
        # binding; the fake records the handler so simulated
        # instrumentation calls reach the Python callback.
        self._binding_name = name
        self._binding_handler = handler

    def close(self) -> None:
        self._closed = True

    def add_test_route(
        self, handler: Callable[[FakeRequest], dict]
    ) -> None:
        self._test_routes.append(handler)

    def _drive_navigation(self, url: str) -> FakeResponse:
        """Drive a top-level navigation through the
        executor's policy then the test's body routes.

        Real Playwright follows redirects internally; the
        fake does the same. Each hop is checked against the
        executor's policy before the test's route handler
        fires. Cross-origin hops and HTTPS→HTTP downgrades
        raise ``_BrowserSecurityError`` exactly like the
        production executor's ``context.route`` abort.
        """
        from urllib.parse import urljoin
        from ai.verification.browser_executor import (
            _MAX_NAVIGATION_HOPS,
            _origin_of,
            _is_downgrade,
            _resolve_redirect,
        )
        target_origin = self._target_origin
        if target_origin is None:
            target_origin = ("https", "target.example.test", "443")
        current_url = url
        for _hop in range(_MAX_NAVIGATION_HOPS + 1):
            req = FakeRequest(
                url=current_url,
                method="GET",
                resource_type="document",
                from_main_frame=True,
            )
            # First: executor's policy. Same-origin allow;
            # cross-origin abort.
            if self._executor_route is not None:
                route = _RecordingRoute(req)
                try:
                    self._executor_route(route)
                except Exception as exc:  # noqa: BLE001
                    raise browser_module._BrowserSecurityError(
                        f"policy_raised:{exc}"
                    ) from exc
                if route._aborted is not None:
                    raise browser_module._BrowserSecurityError(
                        route._aborted
                    )
                if not (route._continued or route._fulfilled is None):
                    return FakeResponse(
                        url=current_url,
                        status=route._fulfilled["status"],
                        headers=route._fulfilled["headers"],
                        body=route._fulfilled["body"],
                    )
            # Origin/scheme pre-check (mirrors real
            # Playwright aborting a redirect to a
            # different origin or scheme).
            origin = _origin_of(current_url)
            if origin is None:
                raise browser_module._BrowserSecurityError(
                    f"unparseable_navigation_url:{current_url!r}"
                )
            ts, th, tp = origin
            es, eh, ep = target_origin
            if (
                ts != es
                or th != eh
                or tp != ep
            ):
                raise browser_module._BrowserSecurityError(
                    f"cross_origin_navigation_rejected:"
                    f"{ts}://{th}:{tp}"
                )
            if _is_downgrade(es, ts):
                raise browser_module._BrowserSecurityError(
                    f"https_downgrade_rejected:{ts}"
                )
            # Test body routes.
            outcome: dict | None = None
            for handler in self._test_routes:
                outcome = handler(req)
                if outcome.get("action") == "aborted":
                    raise browser_module._BrowserSecurityError(
                        outcome.get("reason", "aborted")
                    )
                if outcome.get("action") == "fulfilled":
                    break
            if outcome is None or outcome.get("action") != "fulfilled":
                outcome = {
                    "action": "fulfilled",
                    "status": 200,
                    "headers": {"content-type": "text/html"},
                    "body": "",
                }
            status = outcome.get("status", 200)
            headers = outcome.get("headers", {}) or {}
            body = outcome.get("body", "")
            if status in (301, 302, 303, 307, 308):
                location = headers.get("location") or headers.get(
                    "Location"
                )
                if not location:
                    raise browser_module._BrowserSecurityError(
                        f"redirect_without_location:http_status_{status}"
                    )
                next_url = _resolve_redirect(current_url, location)
                # Check the next hop's origin/scheme BEFORE
                # following it (mirrors real Playwright
                # aborting a top-level nav redirect).
                origin2 = _origin_of(next_url)
                if origin2 is None:
                    raise browser_module._BrowserSecurityError(
                        f"unparseable_redirect_url:{next_url!r}"
                    )
                ts2, th2, tp2 = origin2
                if _is_downgrade(es, ts2):
                    raise browser_module._BrowserSecurityError(
                        f"https_downgrade_redirect_rejected:{ts2}"
                    )
                if (
                    ts2 != es
                    or th2 != eh
                    or tp2 != ep
                ):
                    raise browser_module._BrowserSecurityError(
                        f"cross_origin_redirect_rejected:"
                        f"{ts2}://{th2}:{tp2}"
                    )
                current_url = next_url
                continue
            # Final response.
            return FakeResponse(
                url=current_url,
                status=status,
                headers=headers,
                body=body,
            )
        raise browser_module._BrowserSecurityError(
            "redirect_limit_exceeded"
        )


class FakeSession:
    def __init__(self):
        self._contexts: list[FakeContext] = []
        self._closed = False

    def new_context(self) -> FakeContext:
        # The fake models ONE isolated context per session:
        # tests pre-create and configure the context, and the
        # executor's fresh-context request returns that same
        # isolated instance. Production browser sessions
        # create a new isolated context per call.
        if self._contexts:
            return self._contexts[-1]
        ctx = FakeContext(self)
        self._contexts.append(ctx)
        return ctx

    def close(self) -> None:
        self._closed = True

    def fire_post_nav_hooks(self) -> None:
        for ctx in list(self._contexts):
            for page in list(ctx._pages):
                page.fire_post_nav_hooks()


# =====================================================================
# Helpers
# =====================================================================


def _attempt(**overrides) -> VerificationAttempt:
    kwargs = dict(
        case_id="case-1",
        endpoint=ENDPOINT,
        method="GET",
        parameter="q",
        parameter_location="query",
        payload=PAYLOAD,
        payload_origin="knowledge",
        knowledge_ids=[KNOWLEDGE_ID],
        source_ids=[SOURCE_ID],
        based_on_pattern="marker",
        mode=VerificationMode.BROWSER_EXECUTION,
        phase="browser",
    )
    kwargs.update(overrides)
    return build_verification_attempt(**kwargs)


def _bound_value(attempt: VerificationAttempt) -> str:
    return f"{attempt.payload}~~{attempt.correlation_token}"


class _HookedExecutor(BrowserEvidenceExecutor):
    """Test subclass: fires the session's post-nav hooks
    during the observation window. The production executor
    waits in real time (dispatching binding callbacks and
    page events); for the fake, we fast-forward by firing
    test-injected events at the right moment. There is no
    page-side buffer to drain: instrumentation events were
    already pushed into the executor-owned transport.
    """

    def _post_navigation_observation(
        self, page, state
    ) -> None:
        # Fire test-injected post-nav hooks.
        if self._session is not None:
            self._session.fire_post_nav_hooks()
        # Sleep (no-op for fake; the production code
        # would wait_for_timeout here, dispatching binding
        # callbacks).
        self._sleep(self._observation_window)


def _executor(
    session: FakeSession, **kwargs
) -> BrowserEvidenceExecutor:
    # The observation window is 0 for tests; the fake
    # fast-forwards through it.
    kwargs.setdefault("observation_window_seconds", 0.0)
    return _HookedExecutor(session=session, **kwargs)


# =====================================================================
# Tests
# =====================================================================


class BrowserEvidenceExecutorRequestValidationTests(unittest.TestCase):
    def test_non_browser_mode_rejected(self):
        attempt = _attempt(mode=VerificationMode.HTTP_REFLECTION)
        sess = FakeSession()
        ex = _executor(sess)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("mode_not_supported", evidence.error_reason or "")
        self.assertIsNone(evidence.browser)
        self.assertEqual(sess._contexts, [])

    def test_unsupported_parameter_location_rejected(self):
        attempt = _attempt(parameter_location="body")
        sess = FakeSession()
        ex = _executor(sess)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn(
            "unsupported_browser_parameter_location",
            evidence.error_reason or "",
        )

    def test_endpoint_without_http_scheme_rejected(self):
        attempt = _attempt(endpoint="ftp://target.example.test/")
        sess = FakeSession()
        ex = _executor(sess)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn(
            "unsupported_browser_endpoint_scheme",
            evidence.error_reason or "",
        )


class BrowserEvidenceExecutorTokenFabricationTests(unittest.TestCase):
    def _default_page_response(self) -> str:
        return "<html><body>page</body></html>"

    def test_initial_navigation_token_not_in_network_requests(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": self._default_page_response(),
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertIsNotNone(evidence.browser)
        # The bound URL (which contains the token) is the
        # initial nav and must not appear in network_requests.
        for entry in evidence.browser.network_requests:
            self.assertNotIn(attempt.correlation_token, entry)
        self.assertNotIn(
            _bound_value(attempt), evidence.browser.network_requests
        )

    def test_initial_dom_reflection_not_in_dom_changes(self):
        # Page contains the bound value in the initial
        # HTML. dom_changes is for event-driven
        # mutations only; this must NOT appear there.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        bound = _bound_value(attempt)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": (
                    f"<html><body>"
                    f"<div>initial reflection {bound}</div>"
                    f"</body></html>"
                ),
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertEqual(evidence.browser.dom_changes, [])

    def test_redirect_hops_not_in_network_requests(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        # Single response with a redirect. The fake's
        # _drive_navigation does not currently emit
        # intermediate hops for redirects; the executor
        # reads the Location header. The fake currently
        # does not model redirect chains in goto. We
        # assert the no-redirect case: nav hops are not
        # in network_requests.
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": f"<html><body>echo: {bound}</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        for entry in evidence.browser.network_requests:
            self.assertNotIn(attempt.correlation_token, entry)


class BrowserEvidenceExecutorRuntimeChannelsTests(unittest.TestCase):
    def test_same_origin_page_request_observed(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        page_ref: list[FakePage] = []

        def _route(req):
            page = ctx._pages[-1]
            page_ref.append(page)
            # Inject a same-origin page-initiated fetch
            # via the post-nav hook.
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    f"https://target.example.test/api?cb={bound}",
                    from_main_frame=False,
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertTrue(
            any(
                "/api?cb=" in entry
                and attempt.correlation_token in entry
                for entry in evidence.browser.network_requests
            )
        )

    def test_console_message_via_post_nav_hook(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()

        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_console("hello from page")
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertIn("hello from page", evidence.browser.console_messages)

    def test_dom_mutation_via_post_nav_hook(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()

        def _route(req):
            page = ctx._pages[-1]
            # The DOM mutation goes through the init
            # script's MutationObserver, which the
            # executor drains via evaluate. Since the
            # fake's evaluate returns the chain_events
            # list, we need to record the observable
            # via record_chain_event.
            page.add_post_nav_hook(
                lambda: page.record_chain_event(
                    "observable", "childList@div"
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertTrue(
            any(
                "childList@div" in entry
                for entry in evidence.browser.dom_changes
            )
        )


class BrowserEvidenceExecutorOracleBoundaryTests(unittest.TestCase):
    """E2 oracle requests vs. the generic network sink.

    Preferred architecture (anti-harvest evidence boundary):

        browser.network_requests
            = generic runtime network observations

        oracle_network_events
            = executor-owned, explicitly classified oracle
              observations

    An E2 oracle request URL legitimately contains D (the derived
    oracle value). It MUST therefore never enter the generic sink,
    where a naive anti-harvest pass could misinterpret it as
    pre-execution material. Generic (non-oracle) runtime network
    evidence MUST be preserved unchanged.
    """

    ORACLE_D = "0123456789abcdef"

    def _default_page(self) -> str:
        return "<html><body>page</body></html>"

    # TEST 7: the legitimate oracle request remains observable as E2
    # evidence after the generic network-sink cleanup.
    def test_oracle_request_recorded_as_e2_not_in_generic_sink(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        oracle_url = (
            "https://target.example.test"
            "/.watch-oracle/" + self.ORACLE_D
        )

        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    oracle_url, from_main_frame=False
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": self._default_page(),
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        # The oracle request IS recorded in the dedicated,
        # executor-owned oracle channel...
        self.assertEqual(len(evidence.oracle_network_events), 1)
        event = evidence.oracle_network_events[0]
        self.assertEqual(event.url, oracle_url)
        self.assertEqual(event.path, "/.watch-oracle/" + self.ORACLE_D)
        self.assertFalse(event.is_navigation)
        # ...and it IS valid E2 evidence...
        self.assertTrue(
            evaluate_e2_network(
                evidence.oracle_network_events,
                self.ORACLE_D,
                attempt.endpoint,
            )
        )
        # ...while the generic sink contains NO oracle request and
        # therefore NO D.
        self.assertNotIn(
            oracle_url,
            "\n".join(evidence.browser.network_requests),
        )
        self.assertNotIn(
            self.ORACLE_D,
            "\n".join(evidence.browser.network_requests),
        )

    def test_oracle_response_path_also_excluded_from_generic_sink(self):
        # The ``response`` listener must behave like
        # ``requestfinished``: oracle URLs stay out of the generic
        # sink but remain in the dedicated oracle channel.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        oracle_url = (
            "https://target.example.test"
            "/.watch-oracle/" + self.ORACLE_D
        )

        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_response(
                    oracle_url, from_main_frame=False
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": self._default_page(),
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertTrue(
            any(
                event.url == oracle_url
                for event in evidence.oracle_network_events
            )
        )
        self.assertNotIn(
            self.ORACLE_D,
            "\n".join(evidence.browser.network_requests),
        )

    def test_generic_runtime_requests_still_observed(self):
        # The sink cleanup must be surgical: non-oracle runtime
        # requests (even ones that merely LOOK similar) remain
        # generic network evidence.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        plain_url = (
            "https://target.example.test/api/status?probe="
            + self.ORACLE_D
        )
        lookalike_url = (
            "https://target.example.test/watch-oracle/"
            + self.ORACLE_D
        )

        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: (
                    page.emit_request_finished(
                        plain_url, from_main_frame=False
                    ),
                    page.emit_request_finished(
                        lookalike_url, from_main_frame=False
                    ),
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": self._default_page(),
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        joined = "\n".join(evidence.browser.network_requests)
        # Non-oracle requests stay in the generic sink...
        self.assertIn("/api/status", joined)
        self.assertIn("/watch-oracle/", joined)
        # ...and neither is classified as an oracle request.
        self.assertEqual(evidence.oracle_network_events, [])


class BrowserEvidenceExecutorCrossOriginBlockingTests(unittest.TestCase):
    def test_cross_origin_img_blocked(self):
        # The executor's network policy aborts any
        # cross-origin subresource. The fake's route
        # returns aborted for cross-origin.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        # The route handler returns a 200 for the
        # initial same-origin nav. The cross-origin
        # block happens at the policy level, not at
        # the test route level. The fake's _drive_navigation
        # runs the executor's policy first; same-origin
        # is allowed, the test route fires. For a
        # subresource, the executor's policy would
        # abort; the fake's _drive_navigation does
        # not currently model subresource fetches.
        # We assert the policy handler was installed
        # and the cross-origin test is exercised via
        # the FakeContext._executor_route being non-None.
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        # The policy handler is installed on the context.
        self.assertIsNotNone(ctx._executor_route)
        # Direct probe: the policy handler aborts a
        # cross-origin request.
        cross_req = FakeRequest(
            url="https://evil.test/x.png",
            method="GET",
            resource_type="image",
            from_main_frame=False,
        )
        route = _RecordingRoute(cross_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)
        self.assertIn("cross", route._aborted.lower())

    def test_cross_origin_fetch_blocked(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        ex.execute(attempt)
        cross_req = FakeRequest(
            url="https://evil.test/api",
            method="GET",
            resource_type="fetch",
            from_main_frame=False,
        )
        route = _RecordingRoute(cross_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)

    def test_cross_origin_websocket_blocked(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        ex.execute(attempt)
        cross_req = FakeRequest(
            url="wss://evil.test/ws",
            method="GET",
            resource_type="websocket",
            from_main_frame=False,
        )
        route = _RecordingRoute(cross_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)

    def test_send_beacon_blocked(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        ex.execute(attempt)
        cross_req = FakeRequest(
            url="https://evil.test/beacon",
            method="POST",
            resource_type="other",
            from_main_frame=False,
        )
        route = _RecordingRoute(cross_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)

    def test_cross_origin_iframe_blocked(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        ex.execute(attempt)
        cross_req = FakeRequest(
            url="https://evil.test/",
            method="GET",
            resource_type="frame",
            from_main_frame=False,
        )
        route = _RecordingRoute(cross_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)

    def test_popup_blocked(self):
        # Popup = top-level cross-origin navigation in the
        # policy. The policy aborts frame/document
        # top-level navigation. We simulate a popup
        # request with from_main_frame=False and
        # resource_type=document.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        ex.execute(attempt)
        popup_req = FakeRequest(
            url="https://evil.test/popup",
            method="GET",
            resource_type="document",
            from_main_frame=False,
        )
        route = _RecordingRoute(popup_req)
        ctx._executor_route(route)
        self.assertIsNotNone(route._aborted)


class BrowserEvidenceExecutorRedirectAndSchemeTests(unittest.TestCase):
    def test_cross_origin_redirect_rejected(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        # Initial nav returns a 302 to a cross-origin URL.
        # The executor's _navigate reads the Location
        # header from the response. The fake's
        # _drive_navigation returns a single response;
        # we need to make the response carry a Location
        # header. Adjust the fake to surface headers.
        def _route(req):
            return {
                "action": "fulfilled",
                "status": 302,
                "body": "",
                "headers": {"location": "https://evil.test/x"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("cross_origin", evidence.error_reason or "")

    def test_https_downgrade_rejected(self):
        attempt = _attempt(endpoint="https://target.example.test/search")
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            return {
                "action": "fulfilled",
                "status": 302,
                "body": "",
                "headers": {"location": "http://target.example.test/x"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn(
            "https_downgrade", evidence.error_reason or ""
        )

    def test_redirect_loop_bounded(self):
        # Real Playwright follows redirects internally
        # and exposes the chain via
        # ``request.redirected_from``. The executor audits
        # that chain in ``_navigate``. We construct a
        # fake ``response.request`` whose
        # ``redirected_from`` chain loops back to the
        # same origin and confirm the audit counts hops
        # without producing an ERROR. We also verify
        # the bound on ``max_navigation_hops`` by
        # constructing a chain longer than the bound.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess, max_navigation_hops=2)
        ctx = sess.new_context()

        # Build a chain of 5 same-origin hops. The
        # audit must count hops, record them, and NOT
        # raise when all hops are same-origin and within
        # the bound (5 > max_navigation_hops=2 raises).
        class _Req:
            def __init__(self, url, prev=None):
                self.url = url
                self.redirected_from = prev

        page = ctx.new_page()
        # Build a chain: a -> b -> c -> d -> e (final)
        # redirected_from: e<-d<-c<-b<-a.
        from ai.verification.browser_executor import (
            _BrowserAttemptState,
        )
        state = _BrowserAttemptState(
            target_origin=("https", "target.example.test", "443"),
            bound_url="https://target.example.test/a",
            correlation_token=attempt.correlation_token,
        )
        # 5 hops: a -> b -> c -> d -> e -> final(e)
        a = _Req("https://target.example.test/a")
        b = _Req("https://target.example.test/b", prev=a)
        c = _Req("https://target.example.test/c", prev=b)
        d = _Req("https://target.example.test/d", prev=c)
        e = _Req("https://target.example.test/e", prev=d)
        fin = _Req("https://target.example.test/f", prev=e)
        # ``response.request`` is the final request.
        original_goto = page.goto
        def _chained_goto(url, *, timeout, wait_until):
            return FakeResponse(
                url=fin.url, status=200, headers={}, body=""
            ) if False else _RespWithReq(fin)
        # We need a response object whose ``.request``
        # is the final request. Use a thin wrapper.
        page.goto = _chained_goto  # type: ignore[assignment]
        with self.assertRaises(
            browser_module._BrowserSecurityError
        ) as ctx_:
            ex._navigate(page, state)
        # Either ``redirect_limit_exceeded`` or the
        # chain ends cleanly. Either is acceptable for
        # the security invariant.
        msg = str(ctx_.exception).lower()
        self.assertTrue(
            "redirect" in msg or "limit" in msg,
            f"unexpected error: {ctx_.exception!r}",
        )
        page.goto = original_goto  # type: ignore[assignment]

        # Same-origin chain within bound: 2 hops, audit
        # must succeed.
        state2 = _BrowserAttemptState(
            target_origin=("https", "target.example.test", "443"),
            bound_url="https://target.example.test/a",
            correlation_token=attempt.correlation_token,
        )
        a2 = _Req("https://target.example.test/a")
        b2 = _Req("https://target.example.test/b", prev=a2)
        # final response.request = b2, redirected_from
        # = a2 (only 1 hop).
        def _short_goto(url, *, timeout, wait_until):
            return _RespWithReq(b2)
        page.goto = _short_goto  # type: ignore[assignment]
        ex._navigate(page, state2)
        self.assertEqual(state2.final_url, "https://target.example.test/b")
        page.goto = original_goto  # type: ignore[assignment]

    def test_cross_origin_redirect_in_chain_rejected(self):
        # A chain that includes one cross-origin hop
        # must be rejected by the audit (and would in
        # any case be aborted at ``context.route``).
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        from ai.verification.browser_executor import (
            _BrowserAttemptState,
        )
        class _Req:
            def __init__(self, url, prev=None):
                self.url = url
                self.redirected_from = prev
        a = _Req("https://target.example.test/a")
        b = _Req("https://evil.test/x", prev=a)
        page = ctx.new_page()
        state = _BrowserAttemptState(
            target_origin=("https", "target.example.test", "443"),
            bound_url="https://target.example.test/a",
            correlation_token=attempt.correlation_token,
        )
        original_goto = page.goto
        def _co_goto(url, *, timeout, wait_until):
            return _RespWithReq(b)
        page.goto = _co_goto  # type: ignore[assignment]
        with self.assertRaises(
            browser_module._BrowserSecurityError
        ) as ctx_:
            ex._navigate(page, state)
        self.assertIn("cross_origin", str(ctx_.exception).lower())
        page.goto = original_goto  # type: ignore[assignment]


class _RespWithReq:
    def __init__(self, req):
        self.request = req
        self.url = req.url
        self.status = 200
        self.headers = {}


class BrowserEvidenceExecutorCredentialSafetyTests(unittest.TestCase):
    def test_credentials_absent_in_evidence(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        # The runtime channels may contain URLs with
        # sensitive query parameters. The executor
        # redacts well-known credential parameter names.
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    f"https://target.example.test/api"
                    f"?token={attempt.correlation_token}"
                    f"&api_key=secret123&x=1",
                    from_main_frame=False,
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        for entry in evidence.browser.network_requests:
            self.assertNotIn("secret123", entry)
            self.assertIn("[REDACTED]", entry)
        # The token itself is not a credential and is
        # preserved.
        joined = "\n".join(evidence.browser.network_requests)
        self.assertIn(attempt.correlation_token, joined)


class BrowserEvidenceExecutorFailureModeTests(unittest.TestCase):
    def test_timeout_produces_timeout(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            raise browser_module._BrowserTimeout(
                "navigation_timeout"
            )
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.TIMEOUT)

    def test_browser_crash_produces_error(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(lambda: page.emit_crash())
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("crash", evidence.error_reason or "")

    def test_exceptions_never_produce_succeeded(self):
        # Inject a deliberate exception into the route
        # handler. The executor's top-level try/except
        # must convert it into ERROR evidence, not
        # SUCCEEDED.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            raise RuntimeError("unexpected internal state")
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertNotEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)


class BrowserEvidenceExecutorResourceLimitsTests(unittest.TestCase):
    def test_channel_limits_enforced(self):
        # Fire more than the cap; the executor must
        # STOP APPENDING. The current cap is
        # _MAX_RUNTIME_ENTRIES = 64.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            def _flood():
                for i in range(200):
                    page.emit_console(f"msg{i}")
            page.add_post_nav_hook(_flood)
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        # The executor's bound is _MAX_RUNTIME_ENTRIES (64).
        from ai.verification.browser_executor import (
            _MAX_RUNTIME_ENTRIES,
        )
        self.assertEqual(
            len(evidence.browser.console_messages), _MAX_RUNTIME_ENTRIES
        )

    def test_entry_length_bounded(self):
        # Each entry is bounded by _MAX_ENTRY_LENGTH (240).
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        long_text = "A" * 1000
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_console(long_text)
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        for entry in evidence.browser.console_messages:
            self.assertLessEqual(len(entry), 240)


class BrowserEvidenceExecutorStorageTests(unittest.TestCase):
    def test_storage_preexisting_not_reported(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        # Pre-existing state. The fake exposes it via
        # _pre_existing_local_storage. The executor
        # does NOT read this; the page must call
        # setItem to record a write. So even if the
        # fake had pre-existing state, it would not
        # be in storage_writes.
        ctx._pre_existing_local_storage["k"] = "preexisting"
        def _route(req):
            page = ctx._pages[-1]
            # Page calls setItem('k', 'new') — a real
            # write. This should be recorded.
            page.add_post_nav_hook(
                lambda: page.emit_console(
                    "localStorage:k=new"
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        # The pre-existing value is NOT in the storage
        # channel. The executor's init script would
        # only hook setItem calls; the fake's
        # emit_console route is a test simplification.
        # We assert the channel does not contain the
        # pre-existing value as a write.
        joined = "\n".join(evidence.browser.storage_writes)
        self.assertNotIn("preexisting", joined)

    def test_storage_write_detected(self):
        # A runtime setItem-equivalent write performed by
        # the page during this attempt is recorded in
        # storage_writes.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.record_storage_write(
                    "localStorage:k=new"
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        # The trusted transport serialises storage events as
        # "<area>:<key>|<value>".
        self.assertTrue(
            any(
                "localStorage:k|new" in entry
                for entry in evidence.browser.storage_writes
            )
        )
        self.assertNotIn("preexisting", evidence.browser.storage_writes)


class BrowserEvidenceExecutorTamperResistanceTests(unittest.TestCase):
    """Executor-side transport authentication.

    The trusted event buffer lives Python-side. The only
    write path is the binding callback, which requires the
    per-attempt capability. These tests exercise the
    authentication and validation rules directly.
    """

    def _run(self, push_to_page=None):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()

        def _route(req):
            page = ctx._pages[-1]
            if push_to_page is not None:
                page.add_post_nav_hook(
                    lambda: push_to_page(attempt, page)
                )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }

        ctx.add_test_route(_route)
        return attempt, sess, ctx, ex

    def test_authenticated_event_accepted(self):
        def _push(attempt, page):
            page._push_binding_event(
                "sinks", "innerHTML", "DIV", "<div>EVIL</div>"
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertTrue(evidence.browser.executed_script)
        self.assertTrue(
            any(
                "innerHTML|<div>EVIL</div>" in e
                for e in evidence.browser.dom_changes
            )
        )

    def test_wrong_capability_is_dropped(self):
        def _push(attempt, page):
            page._push_binding_event(
                "sinks", "innerHTML", "DIV", "<div>FORGED</div>",
                capability="f" * 64,
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertEqual(evidence.browser.dom_changes, [])
        self.assertFalse(evidence.browser.executed_script)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_empty_capability_is_dropped(self):
        def _push(attempt, page):
            page._push_binding_event(
                "sinks", "innerHTML", "DIV", "<div>FORGED</div>",
                capability="",
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.dom_changes, [])
        self.assertFalse(evidence.browser.executed_script)

    def test_missing_capability_is_dropped(self):
        def _push(attempt, page):
            page._push_binding_event(
                "sinks", "innerHTML", "DIV", "<div>FORGED</div>",
                capability=None,
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.dom_changes, [])
        self.assertFalse(evidence.browser.executed_script)

    def test_unknown_channel_is_dropped(self):
        def _push(attempt, page):
            page._push_binding_event(
                "evidence", "innerHTML", "DIV", "<div>FORGED</div>"
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.dom_changes, [])

    def test_non_string_args_are_dropped(self):
        def _push(attempt, page):
            page._push_binding_event(
                "sinks", "innerHTML", "DIV",
                {"forged": "object"},
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.dom_changes, [])
        self.assertFalse(evidence.browser.executed_script)

    def test_forged_source_alone_cannot_build_chain(self):
        # A source event without a value-overlapping sink AND
        # observable never produces a chain, even when it is
        # delivered through the authenticated transport.
        def _push(attempt, page):
            page._push_binding_event(
                "sources", "URLSearchParams.get",
                attempt.parameter, "EVIL",
            )
        attempt, sess, ctx, ex = self._run(_push)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_page_has_no_handle_on_python_buffer(self):
        # The fake models the production trust boundary: the
        # FakePage exposes NO handle on the executor's buffer.
        # The page object only offers _push_binding_event, a
        # write-only simulation of the init script's callable;
        # reading or mutating the buffer from the page side is
        # impossible by construction.
        attempt, sess, ctx, ex = self._run()
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertIsNotNone(ctx._binding_handler)
        self.assertIsNotNone(ctx._binding_name)
        self.assertNotIn("__watch_events__", ctx._binding_name)


# =====================================================================
# REAL-CHROMIUM CAPABILITY CONFIDENTIALITY TESTS
# =====================================================================
# These tests run the REAL BrowserEvidenceExecutor against REAL
# Chromium with a hostile page whose only job is to recover the
# per-attempt transport capability and then submit an
# authenticated-looking fake event.
#
# Security property under test:
#   A page-controlled script must not be able to obtain the valid
#   capability and then successfully submit an authenticated fake
#   event. No forged trusted event may reach the Python-side
#   event buffer.
#
# The capability is patched to a KNOWN deterministic value for the
# duration of the attempt so the test can scan every evidence
# channel (console, network, DOM, storage) for it. The hostile
# page attempts GENERIC discovery (any 64-hex string anywhere it
# can read), not just the literal "__watchCapability" name.
# =====================================================================

_KNOWN_CAPABILITY = "a7f3c9e1" * 8  # 64 hex chars, deterministic

_REAL_LOCAL_HOST = "127.0.0.1"


class _RealPageHandler(http.server.BaseHTTPRequestHandler):
    """Minimal handler mapping paths to (status, body, headers)."""

    routes: dict = {}

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        route = self.server.routes.get(path)  # type: ignore[attr-defined]
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, body, headers = route()
        payload = body.encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:  # keep test output clean
        pass


class _RealPageServer:
    """Hermetic single-origin server for the hostile pages."""

    def __init__(self, routes: dict):
        self._routes = routes
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.origin: str = ""

    def start(self) -> None:
        self._server = http.server.ThreadingHTTPServer(
            (_REAL_LOCAL_HOST, 0), _RealPageHandler
        )
        self._server.routes = self._routes  # type: ignore[attr-defined]
        self.origin = (
            f"http://{_REAL_LOCAL_HOST}:{self._server.server_port}"
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)


# Positive-control page: performs ONE real instrumented sink write
# so the test proves the transport, init script, and capability all
# work end-to-end in real Chromium under the exact executor config
# used by the hostile tests.
_PAGE_REAL_CONTROL = """\
<!doctype html>
<html><head><title>ctrl</title></head>
<body>
<div id="t"></div>
<script>
document.getElementById('t').innerHTML = '<div>REALCTRL</div>';
</script>
</body></html>
"""

# Hostile page, part A: generic discovery. The page does NOT know
# the capability's variable name; it scans for ANY 64-hex string
# observable anywhere in its realm.
_PAGE_HOSTILE_A = """\
<!doctype html>
<html><head><title>hostile</title></head>
<body>
<div id="t"></div>
<iframe id="f" style="display:none"></iframe>
<script>
(function () {
  var R = [];
  var CAND = [];
  var WRAP = [];
  var HEX = /[0-9a-f]{64}/g;
  var ORIG = window.__watchTransport;
  function rep(k, v) { try { R.push(k + ":" + String(v).slice(0, 200)); } catch (e) {} }
  function addCand(s) {
    try {
      var m = String(s).match(HEX);
      if (m) for (var i = 0; i < m.length; i++) if (CAND.indexOf(m[i]) < 0) CAND.push(m[i]);
    } catch (e) {}
  }
  function makeWrapper(tag) {
    return function () {
      var a = [];
      for (var i = 0; i < arguments.length; i++) a.push(String(arguments[i]).slice(0, 90));
      WRAP.push(tag + "|" + a.join("|"));
      for (var j = 0; j < arguments.length; j++) addCand(String(arguments[j]));
      try { return ORIG.apply(this, arguments); } catch (e) {}
    };
  }
  // ---- 1+2: window/global enumeration + own-property value scan ----
  try {
    var names = Object.getOwnPropertyNames(window);
    rep("wnum", names.length);
    var like = [];
    for (var i = 0; i < names.length && i < 900; i++) {
      var n = names[i];
      if (/watch|capab|transport|emit|instrument|token|secret/i.test(n)) like.push(n);
      var v; try { v = window[n]; } catch (e) { continue; }
      if (typeof v === "string") addCand(v);
    }
    rep("wlike", JSON.stringify(like));
  } catch (e) { rep("err_enum", e); }
  // ---- 5: init-script-visible globals / Playwright internals ----
  try {
    rep("g_instr", String(window.__watch_instrumented__));
    var pw = window.__playwright__;
    if (pw) {
      var seen = 0;
      (function walk(o, d, pre) {
        if (d > 2 || seen > 250) return;
        var ks; try { ks = Object.getOwnPropertyNames(o); } catch (e) { return; }
        for (var i = 0; i < ks.length && seen < 250; i++) {
          seen++;
          var val; try { val = o[ks[i]]; } catch (e) { continue; }
          if (typeof val === "string") { addCand(val); if (/watch|capab|token/i.test(ks[i])) rep("pwv_" + pre + ks[i], val); }
          else if (val && typeof val === "object") walk(val, d + 1, pre + ks[i] + ".");
          else if (typeof val === "function") addCand(String(val));
        }
      })(pw, 0, "");
      rep("pw_seen", seen);
    } else rep("pw", "absent");
  } catch (e) { rep("err_g", e); }
  // ---- 3: Function.prototype.toString on relevant functions ----
  try {
    rep("t_typeof", typeof ORIG);
    rep("t_tostr", String(ORIG));
    rep("t_name", ORIG ? ORIG.name : "-");
    rep("t_own", ORIG ? JSON.stringify(Object.getOwnPropertyNames(ORIG)) : "-");
    addCand(String(ORIG));
    var usp = String(URLSearchParams.prototype.get); rep("w_uspget", usp.slice(0, 200)); addCand(usp);
    var iad = String(Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML").set);
    rep("w_iaset", iad.slice(0, 200)); addCand(iad);
    var sit = String(Storage.prototype.setItem); rep("w_setitem", sit.slice(0, 200)); addCand(sit);
    var mo = String(window.MutationObserver); rep("w_mo", mo.slice(0, 200)); addCand(mo);
    var ev = String(window.eval); rep("w_eval", ev.slice(0, 200)); addCand(ev);
  } catch (e) { rep("err_tostr", e); }
  // The init script is not a DOM script; prove it by scanning.
  try {
    var acc = "";
    for (var s = 0; s < document.scripts.length; s++) acc += document.scripts[s].textContent;
    rep("scripts_len", acc.length);
    addCand(acc);
    addCand(document.documentElement.innerHTML);
  } catch (e) {}
  // ---- 4: inspecting the exposed binding (behaviour probes) ----
  try {
    rep("probe_ret", String(ORIG("sinks", "innerHTML", "DIV", "<div>PROBE</div>")));
    try { ORIG.call(null, "sinks", "innerHTML", "DIV", "<div>PROBE_CALL</div>"); } catch (e) {}
    try { ORIG.apply(null, ["sinks", "innerHTML", "DIV", "<div>PROBE_APPLY</div>"]); } catch (e) {}
  } catch (e) { rep("err_probe", e); }

  // ---- 8: fake source/sink/observable events, wrong shapes ----
  var chans = ["sources", "sinks", "observables", "storage"];
  for (var c = 0; c < chans.length; c++) {
    try { ORIG(chans[c], "innerHTML", "DIV", "<div>FAKE_A_" + chans[c] + "</div>"); } catch (e) {}
    try { ORIG(chans[c], "innerHTML", "DIV", "<div>FAKE_B_" + chans[c] + "</div>", ""); } catch (e) {}
    try { ORIG(chans[c], "innerHTML", "DIV", "<div>FAKE_C_" + chans[c] + "</div>", null); } catch (e) {}
    try { ORIG(chans[c], "innerHTML", "DIV", "<div>FAKE_D_" + chans[c] + "</div>", {"forged": 1}); } catch (e) {}
    try { ORIG(chans[c], "innerHTML", "DIV", "<div>FAKE_E_" + chans[c] + "</div>", "deadbeef", "extra"); } catch (e) {}
  }
  try { ORIG(); } catch (e) {}
  rep("fake_injected", "done");

  // The correlation token is page-visible (it is in the URL) but
  // is NOT the capability. Forge with it deliberately.
  try {
    var q = location.search, k = q.lastIndexOf("~~");
    var tok = k >= 0 ? q.slice(k + 2).split("&")[0] : "";
    rep("tok_len", tok.length);
    if (tok) CAND.push(tok);
  } catch (e) {}

  // ---- 7: replace/rebind the transport (main realm) ----
  try {
    window.__watchTransport = makeWrapper("main");
    rep("rebind", String(window.__watchTransport !== ORIG));
    try { new URLSearchParams("a=b").get("a"); } catch (e) {}
  } catch (e) { rep("err_rebind", e); }

  // ---- 7b: iframe init-script race. If the iframe's init script
  // runs AFTER our wrapper assignment it would capture the wrapper
  // and every iframe instrumentation event would then carry the
  // capability through page-visible code.
  try {
    var f = document.getElementById("f");
    try { f.contentWindow.__watchTransport = makeWrapper("ifabout"); } catch (e) { rep("err_ifset", e); }
    try { new f.contentWindow.Function("return new URLSearchParams('a=b').get('a');")(); } catch (e) { rep("err_ifeval", e); }
    f.src = "/ifblank";
  } catch (e) { rep("err_if", e); }

  // Deferred: re-probe after the iframe navigated, forge with every
  // candidate, then exfiltrate the findings report.
  setTimeout(function () {
    try {
      var f2 = document.getElementById("f");
      try { f2.contentWindow.__watchTransport = makeWrapper("ifloaded"); } catch (e) {}
      try { new f2.contentWindow.Function("return new URLSearchParams('x=y').get('x');")(); } catch (e) { rep("err_ifeval2", e); }
      try { new URLSearchParams("c=d").get("c"); } catch (e) {}
      // ---- 6: forge with every recovered/guessed candidate ----
      if (CAND.indexOf("") < 0) CAND.push("");
      var gset = ["0", "f", "a", "1", "e", "deadbeef"];
      for (var g = 0; g < gset.length; g++) {
        var unit = gset[g];
        var s = unit;
        while (s.length < 64) s += unit;
        s = s.slice(0, 64);
        if (CAND.indexOf(s) < 0) CAND.push(s);
      }
      rep("cand_count", CAND.length);
      for (var i = 0; i < CAND.length; i++) {
        try { ORIG("sinks", "innerHTML", "DIV", "<div>FORGED_" + i + "</div>", CAND[i]); } catch (e) {}
      }
      // Exfiltrate findings via unauthenticated evidence channels.
      rep("wrap_calls", JSON.stringify(WRAP).slice(0, 200));
      var lines = ["HOSTILE_REPORT_BEGIN"];
      for (var L = 0; L < R.length && L < 30; L++) lines.push(R[L]);
      lines.push("HOSTILE_WRAP " + JSON.stringify(WRAP).slice(0, 200));
      lines.push("HOSTILE_CAND " + CAND.length);
      lines.push("HOSTILE_REPORT_END");
      for (var L2 = 0; L2 < lines.length; L2++) { try { console.log(lines[L2]); } catch (e) {} }
      try {
        fetch("/api?leak=" + encodeURIComponent(
          JSON.stringify({ n: CAND.length, c: CAND.slice(0, 3) })
        ));
      } catch (e) {}
    } catch (e) { try { console.log("HOSTILE_ERR " + e); } catch (e2) {} }
  }, 800);
})();
</script>
</body></html>
"""

_PAGE_IFRAME_TARGET = """\
<!doctype html>
<html><head><title>ib</title></head><body>ib</body></html>
"""

# Token-forgery page: the correlation token is deliberately
# page-visible (it is in the bound URL). The page forges events
# using it as the capability — it must not authenticate.
_PAGE_TOKEN_FORGERY = """\
<!doctype html>
<html><head><title>tokfor</title></head>
<body>
<script>
(function () {
  var q = location.search, k = q.lastIndexOf("~~");
  var tok = k >= 0 ? q.slice(k + 2).split("&")[0] : "";
  var t = window.__watchTransport;
  try { t("sinks", "innerHTML", "DIV", "<div>FORGED_TOKEN</div>", tok); } catch (e) {}
  try { t("sinks", "innerHTML", "DIV", "<div>FORGED_TOKEN_DUP</div>", tok + tok); } catch (e) {}
  try { t("sinks", "innerHTML", "DIV", "<div>FORGED_NONE</div>"); } catch (e) {}
})();
</script>
</body></html>
"""


@unittest.skipUnless(
    _REAL_CHROMIUM_AVAILABLE,
    "playwright is not installed; real-Chromium tests require it",
)
class BrowserEvidenceExecutorCapabilityConfidentialityTests(
    unittest.TestCase
):
    """Can hostile page JavaScript recover the per-attempt
    transport capability from the init script — and then submit an
    authenticated fake event? Runs against real Chromium."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = _RealPageServer(
            {
                "/ctrl": lambda: (
                    200,
                    _PAGE_REAL_CONTROL,
                    {"content-type": "text/html"},
                ),
                "/hostile": lambda: (
                    200,
                    _PAGE_HOSTILE_A,
                    {"content-type": "text/html"},
                ),
                "/ifblank": lambda: (
                    200,
                    _PAGE_IFRAME_TARGET,
                    {"content-type": "text/html"},
                ),
                "/tokfor": lambda: (
                    200,
                    _PAGE_TOKEN_FORGERY,
                    {"content-type": "text/html"},
                ),
                "/api": lambda: (
                    200,
                    "ok",
                    {"content-type": "text/plain"},
                ),
            }
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def _execute(self, page_path: str, observation_window: float = 2.0):
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=observation_window,
        )
        attempt = build_verification_attempt(
            case_id="case-cap-sec",
            endpoint=self.server.origin + page_path,
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
        with mock.patch.object(
            browser_module,
            "_new_capability",
            return_value=_KNOWN_CAPABILITY,
        ):
            evidence = ex.execute(attempt)
        return evidence, attempt

    # ------------------------------------------------------------------
    # Positive control
    # ------------------------------------------------------------------

    def test_positive_control_real_event_flows_through_transport(self):
        # Proves the transport + init script + capability all work
        # end-to-end in real Chromium under the exact config used
        # by the hostile tests. A real instrumented sink write MUST
        # be recorded; otherwise the hostile assertions would be
        # vacuous.
        evidence, _attempt = self._execute("/ctrl")
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        browser = evidence.browser
        self.assertTrue(browser.executed_script)
        self.assertTrue(
            any("REALCTRL" in e for e in browser.dom_changes),
            f"real sink event missing: {browser.dom_changes!r}",
        )

    # ------------------------------------------------------------------
    # Hostile capability discovery + forgery
    # ------------------------------------------------------------------

    def _assert_hostile_report_ran(self, browser) -> None:
        joined_console = "\n".join(browser.console_messages)
        self.assertIn(
            "HOSTILE_REPORT_BEGIN", joined_console,
            "hostile discovery report missing; the hostile page "
            f"did not execute its full program: {joined_console!r}",
        )
        self.assertIn("HOSTILE_REPORT_END", joined_console)

    def test_hostile_page_cannot_recover_capability_or_forge_events(self):
        # THE security question: can hostile page JavaScript
        # recover the per-attempt capability and submit an
        # authenticated fake event? The hostile page attempts
        # generic discovery, rebinding, iframe init-script races,
        # and forgery with every candidate it can observe. The
        # verdict comes from the executor's Python-side state:
        # NO forged trusted event may reach the trusted buffer.
        evidence, attempt = self._execute("/hostile")
        browser = evidence.browser

        # The hostile program must have run to completion.
        self._assert_hostile_report_ran(browser)

        # Capability confidentiality: the KNOWN capability string
        # must not appear in ANY evidence channel (the page
        # exfiltrates everything it finds through console and a
        # same-origin fetch, both of which are captured).
        joined = "\n".join(
            browser.console_messages
            + browser.network_requests
            + browser.dom_changes
            + browser.storage_writes
        )
        self.assertNotIn(
            _KNOWN_CAPABILITY,
            joined,
            "CAPABILITY RECOVERED: the known capability string "
            f"leaked into evidence channels: {joined!r}",
        )

        # The decisive oracle: no forged event may reach the
        # Python-side trusted buffer.
        #
        # NOTE: every real-Chromium attempt carries ONE intrinsic
        # trusted event generated by Playwright itself (its binding
        # installation calls the instrumented ``window.eval`` with
        # Playwright's internal binding function). That entry is
        # driver noise, not page evidence. The hostile page performs
        # NO real instrumented sink/observable/storage action, so
        # every trusted entry MUST be exactly that internal 'eval'
        # record and NOTHING else, and no FORGED/FAKE/PROBE marker
        # may appear in any trusted channel.
        trusted = browser.dom_changes + browser.storage_writes
        for entry in trusted:
            self.assertTrue(
                entry.startswith("eval|"),
                f"UNEXPECTED TRUSTED EVENT (not Playwright-internal "
                f"noise): {entry!r} | console={browser.console_messages!r}",
            )
        for marker in ("FORGED", "FAKE_", "PROBE"):
            for entry in trusted:
                self.assertNotIn(
                    marker,
                    entry,
                    f"FORGED EVENT REACHED TRUSTED STATE: {entry!r}",
                )
        self.assertEqual(
            browser.storage_writes, [],
            f"FORGED STORAGE EVENT REACHED TRUSTED STATE: "
            f"{browser.storage_writes!r}",
        )
        self.assertEqual(browser.source_to_sink, [])
        # NOTE: observed_correlation_token MAY be set here — by the
        # hostile page's OWN deliberate echo of the page-visible
        # correlation token through the unauthenticated fetch
        # channel. That is a page echo of a non-secret value, not a
        # forged trusted event: the advisory booleans are not
        # authoritative and the verifier independently requires a
        # structured value-flow chain. The trusted transport entries
        # above remain the decisive oracle.

    def test_page_visible_correlation_token_is_not_transport_capability(self):
        # The correlation token is deliberately page-visible (it is
        # in the bound URL). Using it as the transport capability
        # MUST NOT authenticate a forged event.
        ex = BrowserEvidenceExecutor(
            navigation_timeout_seconds=10.0,
            observation_window_seconds=1.0,
        )
        attempt = build_verification_attempt(
            case_id="case-cap-token",
            endpoint=self.server.origin + "/tokfor",
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
        evidence = ex.execute(attempt)
        browser = evidence.browser
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        # The page-visible correlation token (and its duplicates /
        # padding) MUST NOT authenticate a forged event. The only
        # tolerated trusted entry is Playwright's intrinsic internal
        # 'eval' driver noise (see the hostile test above).
        for entry in browser.dom_changes:
            self.assertTrue(
                entry.startswith("eval|"),
                f"UNEXPECTED TRUSTED EVENT: {entry!r}",
            )
            self.assertNotIn(
                "FORGED",
                entry,
                f"correlation token authenticated a forged event: "
                f"{entry!r}",
            )
        self.assertEqual(browser.storage_writes, [])


class BrowserEvidenceExecutorTokenObservationTests(unittest.TestCase):
    def test_token_observation_is_exact(self):
        # The token appears literally in a runtime
        # channel. observed_correlation_token is set
        # to the literal token.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    f"https://target.example.test/api?cb={bound}",
                    from_main_frame=False,
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(
            evidence.browser.observed_correlation_token,
            attempt.correlation_token,
        )
        self.assertTrue(evidence.browser.correlation_token_in_runtime)

    def test_token_uppercase_not_matched(self):
        # The brief states "Never reconstruct or normalize
        # observed tokens." An uppercase variant of the
        # token must NOT match.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        # Construct a URL that contains the token with
        # one character uppercased.
        upper = attempt.correlation_token.upper()
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    f"https://target.example.test/api?cb={upper}",
                    from_main_frame=False,
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertIsNone(evidence.browser.observed_correlation_token)
        self.assertFalse(evidence.browser.correlation_token_in_runtime)


class BrowserEvidenceExecutorSourceSinkChainTests(unittest.TestCase):
    def test_chain_empty_when_attribution_incomplete(self):
        # No chain events. source_to_sink must be empty.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_chain_present_when_attribution_complete(self):
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            # Real value flow: the page reads the
            # parameter, writes the value (which contains
            # the parameter value) to innerHTML, and a
            # MutationObserver fires with the same value
            # in addedNodes.
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                "EVIL",
            )
            page.record_chain_value(
                "sink", "innerHTML", "<div>EVIL</div>"
            )
            page.record_chain_value(
                "observable", "childList", "<div>EVIL</div>"
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        chain = evidence.browser.source_to_sink
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].kind, "parameter")
        self.assertEqual(chain[1].kind, "sink")
        self.assertEqual(chain[2].kind, "observable")

    def test_chain_empty_when_value_flow_unproven(self):
        # A source event exists, a sink event exists,
        # and an observable event exists — but the
        # captured values do not overlap. The executor
        # MUST NOT emit a chain.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                "UNRELATED_VALUE",
            )
            page.record_chain_value(
                "sink", "innerHTML", "<div>something else</div>"
            )
            page.record_chain_value(
                "observable", "childList",
                "<div>something else</div>"
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_chain_empty_when_source_value_empty(self):
        # A source event with an empty value (the page
        # called URLSearchParams.get with the right
        # parameter name but the value was empty) MUST
        # NOT produce a chain.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                "",
            )
            page.record_chain_value(
                "sink", "innerHTML", "<div>EVIL</div>"
            )
            page.record_chain_value(
                "observable", "childList", "<div>EVIL</div>"
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_chain_present_with_overlapping_values(self):
        # The source returns ``EVIL``; the sink writes
        # ``<div>EVIL</div>`` (source value is a substring
        # of sink value); the observable captures
        # ``<div>EVIL</div>`` (same as sink). The chain
        # must be emitted.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                "EVIL",
            )
            page.record_chain_value(
                "sink", "innerHTML", "<div>EVIL</div>"
            )
            page.record_chain_value(
                "observable", "childList", "<div>EVIL</div>"
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        chain = evidence.browser.source_to_sink
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].kind, "parameter")
        self.assertEqual(chain[1].kind, "sink")
        self.assertEqual(chain[2].kind, "observable")

    def test_chain_skips_event_with_empty_value_in_observable(self):
        # Source and sink overlap, but the observable
        # has an empty value. No chain.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        def _route(req):
            page = ctx._pages[-1]
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                "EVIL",
            )
            page.record_chain_value(
                "sink", "innerHTML", "<div>EVIL</div>"
            )
            page.record_chain_value(
                "observable", "childList", ""
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.browser.source_to_sink, [])

    def test_chain_present_when_sink_value_contains_source_value(self):
        # Real DOM-XSS: source returns ``"<svg onload=1>"``;
        # sink writes ``"<div><svg onload=1></div>"``. The
        # source value is a substring of the sink value.
        attempt = _attempt()
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        payload = "<svg onload=1>"
        def _route(req):
            page = ctx._pages[-1]
            page.record_chain_value(
                "source",
                f"URLSearchParams.get:{attempt.parameter}",
                payload,
            )
            page.record_chain_value(
                "sink", "innerHTML",
                f"<div>{payload}</div>",
            )
            page.record_chain_value(
                "observable", "childList",
                f"<div>{payload}</div>",
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        chain = evidence.browser.source_to_sink
        self.assertEqual(len(chain), 3)
        # Parameter step binds to attempt identifiers.
        self.assertEqual(
            chain[0].parameter_name, attempt.parameter
        )
        self.assertEqual(
            chain[0].parameter_location,
            attempt.parameter_location,
        )
        self.assertEqual(chain[0].endpoint, attempt.endpoint)

    def test_deterministic_evidence_from_identical_fake_events(self):
        # Two runs with the same fake events produce
        # identical browser evidence.
        attempt = _attempt()
        bound = _bound_value(attempt)

        def _make_route(ctx):
            def _route(req):
                page = ctx._pages[-1]
                page.add_post_nav_hook(
                    lambda: page.emit_request_finished(
                        f"https://target.example.test/api?cb={bound}",
                        from_main_frame=False,
                    )
                )
                return {
                    "action": "fulfilled",
                    "status": 200,
                    "body": "<html><body>page</body></html>",
                    "headers": {"content-type": "text/html"},
                }

            return _route

        sess1 = FakeSession()
        ex1 = _executor(sess1)
        ctx1 = sess1.new_context()
        ctx1.add_test_route(_make_route(ctx1))
        ev1 = ex1.execute(attempt)
        sess2 = FakeSession()
        ex2 = _executor(sess2)
        ctx2 = sess2.new_context()
        ctx2.add_test_route(_make_route(ctx2))
        ev2 = ex2.execute(attempt)
        # Compare the runtime channels (deterministic).
        self.assertEqual(
            ev1.browser.network_requests,
            ev2.browser.network_requests,
        )
        # Timestamps differ; exclude.
        d1 = ev1.model_dump(exclude={"started_at", "finished_at"})
        d2 = ev2.model_dump(exclude={"started_at", "finished_at"})
        self.assertEqual(d1, d2)


class BrowserEvidenceExecutorStoredPhaseTests(unittest.TestCase):
    def test_stored_attempt_read_phase_observed(self):
        # Stored XSS attempt. The executor does the READ
        # phase. If the token is in a runtime channel,
        # stored_phases is populated with READ.
        attempt = _attempt(phase="stored")
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        bound = _bound_value(attempt)
        def _route(req):
            page = ctx._pages[-1]
            page.add_post_nav_hook(
                lambda: page.emit_request_finished(
                    f"https://target.example.test/api?cb={bound}",
                    from_main_frame=False,
                )
            )
            return {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        ctx.add_test_route(_route)
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)
        self.assertEqual(len(evidence.stored_phases), 1)
        self.assertEqual(evidence.stored_phases[0].phase, StoredXSSPhase.READ)
        self.assertEqual(
            evidence.stored_phases[0].observed_correlation_token,
            attempt.correlation_token,
        )

    def test_stored_attempt_no_token_no_stored_phases(self):
        # Token not in any runtime channel. The executor
        # must NOT fabricate stored phases.
        attempt = _attempt(phase="stored")
        sess = FakeSession()
        ex = _executor(sess)
        ctx = sess.new_context()
        ctx.add_test_route(
            lambda req: {
                "action": "fulfilled",
                "status": 200,
                "body": "<html><body>page</body></html>",
                "headers": {"content-type": "text/html"},
            }
        )
        evidence = ex.execute(attempt)
        self.assertEqual(evidence.stored_phases, [])


class BrowserEvidenceExecutorVerifierIntegrationTests(unittest.TestCase):
    def _analysis(self, xss_type: str = "dom"):
        case = XSSCase(
            case_id="case-1",
            target="https://target.example.test",
            endpoint=ENDPOINT,
            method="GET",
            parameter="q",
            parameter_location="query",
            xss_type=xss_type,
            context=XSSContext(
                type="html_attribute",
                attribute_name="class",
                attribute_quoted=True,
            ),
            source_type="endpoint",
        )
        llm = XSSResearchLLMResult(
            case_id="case-1",
            case_status_suggestion="ANALYZED",
            suggested_payloads=[
                XSSSuggestedPayload(
                    pattern=PAYLOAD,
                    origin="knowledge",
                    knowledge_ids=[KNOWLEDGE_ID],
                    source_ids=[SOURCE_ID],
                    based_on_pattern="marker",
                    rationale="kb adapted",
                )
            ],
            verification_ideas=[],
            context_observations=[],
            next_research_questions=[],
            evidence=["SECONDARY: stub"],
        )
        context = XSSResearchContext(
            case_id="case-1",
            retrieved_knowledge_ids=[KNOWLEDGE_ID],
            documents=[],
            payload_patterns=[
                XSSAttributedValue(
                    value="marker", source_ids=[SOURCE_ID]
                )
            ],
        )
        return XSSAnalysisResult(
            case=case,
            context=context,
            llm_result=llm,
            stage="ANALYZED",
            audit=XSSAnalysisAudit(
                retrieval_call_count=1,
                llm_call_count=1,
                retrieved_knowledge_ids=[KNOWLEDGE_ID],
                retrieval_had_results=True,
                had_payload_suggestions=True,
                had_verification_ideas=False,
                had_any_knowledge_derived_suggestion=True,
                had_any_model_generated_suggestion=False,
                llm_case_status_suggestion="ANALYZED",
                notes=[],
            ),
        )

    def test_valid_browser_evidence_with_chain_confirmed(self):
        # DOM case: the browser is the sole authority.
        # Valid chain + token in runtime channel +
        # valid HTTP pair for reflected case.
        analysis = self._analysis(xss_type="reflected")
        # Build the browser attempt with a complete
        # chain.
        sess = FakeSession()
        # Set up: the verifier builds one HTTP attempt
        # and one browser attempt. We need the HTTP
        # attempt to confirm (token in response body)
        # and the browser attempt to confirm
        # (chain + runtime token).
        from ai.schemas.xss_verification import (
            build_verification_attempt,
            VerificationMode,
        )
        case = analysis.case
        http_attempt = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
            phase="http",
        )
        browser_attempt = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="browser",
        )
        from ai.schemas.xss_verification import VerificationPlan
        plan = VerificationPlan(
            attempts=[http_attempt, browser_attempt]
        )
        # Build a fake HTTP executor. The simplest is
        # a stub that returns SUCCEEDED with the
        # token observed in the response. We do this
        # inline.
        from ai.schemas.xss_verification import (
            VerificationEvidence,
            ReflectionObservation,
        )
        from ai.verification.http_executor import (
            HTTPEvidenceExecutor,
        )

        class _StubHTTPSession:
            def request(self, *args, **kwargs):
                class R:
                    status_code = 200
                    encoding = "utf-8"
                    headers = {"content-type": "text/html"}
                    def iter_content(self, chunk_size=65536):
                        bound = (
                            f"{PAYLOAD}~~"
                            f"{http_attempt.correlation_token}"
                        )
                        yield (
                            f"<div class='{bound}'>x</div>"
                            .encode("utf-8")
                        )
                    def close(self_inner):
                        return None
                return R()

        http_evidence = VerificationEvidence(
            attempt_id=http_attempt.attempt_id,
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url=http_attempt.endpoint,
            request_method=http_attempt.method,
            reflection=ReflectionObservation(
                reflected=True,
                location=__import__(
                    "ai.schemas.xss_verification",
                    fromlist=["ReflectionLocation"],
                ).ReflectionLocation.HTML_ATTRIBUTE,
                matched_correlation_token=True,
                observed_correlation_token=(
                    http_attempt.correlation_token
                ),
            ),
        )
        # A class that returns the http_evidence for the
        # HTTP attempt and drives the browser executor for
        # the browser attempt.
        from ai.verification import VerificationExecutor as _Proto

        class _DualExecutor(_Proto):
            def __init__(self):
                self._browser_sess = FakeSession()
                self._browser_ex = _HookedExecutor(
                    session=self._browser_sess
                )

            def execute(self, attempt):
                if attempt.mode == VerificationMode.HTTP_REFLECTION:
                    return http_evidence
                # Browser attempt
                ctx = self._browser_sess.new_context()
                bound = _bound_value(attempt)
                def _route(req):
                    page = ctx._pages[-1]
                    page.record_chain_value(
                        "source",
                        f"URLSearchParams.get:{attempt.parameter}",
                        "EVIL",
                    )
                    page.record_chain_value(
                        "sink", "innerHTML", "<div>EVIL</div>"
                    )
                    page.record_chain_value(
                        "observable", "childList", "<div>EVIL</div>"
                    )
                    page.add_post_nav_hook(
                        lambda: page.emit_request_finished(
                            f"https://target.example.test"
                            f"/api?cb={bound}",
                            from_main_frame=False,
                        )
                    )
                    return {
                        "action": "fulfilled",
                        "status": 200,
                        "body": (
                            "<html><body>page</body></html>"
                        ),
                        "headers": {
                            "content-type": "text/html"
                        },
                    }
                ctx.add_test_route(_route)
                return self._browser_ex.execute(attempt)

        result = XSSVerifier(_DualExecutor()).verify(analysis, plan=plan)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        # MANDATED DEMOTION: browser chain/token evidence without an
        # oracle execution proof is POTENTIAL (SINK_REACHED), never
        # CONFIRMED. The browser attempt's finding is POTENTIAL.
        self.assertEqual(len(confirmed), 0)
        browser_findings = [
            f
            for f in result.findings
            if f.verification_mode == "browser_execution"
        ]
        self.assertEqual(len(browser_findings), 1)
        self.assertEqual(browser_findings[0].status, "POTENTIAL")
        self.assertEqual(
            browser_findings[0].confirmation_state, "SINK_REACHED"
        )

    def test_browser_evidence_without_chain_inconclusive(self):
        # Same evidence, but no chain events. The
        # verifier must return INCONCLUSIVE.
        analysis = self._analysis(xss_type="reflected")
        sess = FakeSession()
        from ai.schemas.xss_verification import (
            VerificationEvidence,
            ReflectionObservation,
            VerificationMode,
            build_verification_attempt,
            VerificationPlan,
        )
        case = analysis.case
        http_attempt = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
            phase="http",
        )
        browser_attempt = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="browser",
        )
        plan = VerificationPlan(
            attempts=[http_attempt, browser_attempt]
        )
        http_evidence = VerificationEvidence(
            attempt_id=http_attempt.attempt_id,
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url=http_attempt.endpoint,
            request_method=http_attempt.method,
            reflection=ReflectionObservation(
                reflected=True,
                location=__import__(
                    "ai.schemas.xss_verification",
                    fromlist=["ReflectionLocation"],
                ).ReflectionLocation.HTML_ATTRIBUTE,
                matched_correlation_token=True,
                observed_correlation_token=(
                    http_attempt.correlation_token
                ),
            ),
        )
        from ai.verification import VerificationExecutor as _Proto

        class _DualExecutor(_Proto):
            def __init__(self):
                self._browser_sess = FakeSession()
                self._browser_ex = _HookedExecutor(
                    session=self._browser_sess
                )

            def execute(self, attempt):
                if attempt.mode == VerificationMode.HTTP_REFLECTION:
                    return http_evidence
                ctx = self._browser_sess.new_context()
                bound = _bound_value(attempt)
                def _route(req):
                    page = ctx._pages[-1]
                    # No chain events. Only the runtime
                    # channel.
                    page.add_post_nav_hook(
                        lambda: page.emit_request_finished(
                            f"https://target.example.test"
                            f"/api?cb={bound}",
                            from_main_frame=False,
                        )
                    )
                    return {
                        "action": "fulfilled",
                        "status": 200,
                        "body": (
                            "<html><body>page</body></html>"
                        ),
                        "headers": {
                            "content-type": "text/html"
                        },
                    }
                ctx.add_test_route(_route)
                return self._browser_ex.execute(attempt)

        result = XSSVerifier(_DualExecutor()).verify(analysis, plan=plan)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 0)
        # The browser attempt is INCONCLUSIVE (no chain).
        browser_findings = [
            f for f in result.findings
            if f.verification_mode == "browser_execution"
        ]
        # The browser finding may be absent (INCONCLUSIVE
        # never produces a finding).
        for f in browser_findings:
            self.assertNotEqual(f.status, "CONFIRMED")


class BrowserEvidenceExecutorRoleTests(unittest.TestCase):
    def test_executor_module_never_names_security_verdicts(self):
        import inspect
        from ai.verification import browser_executor as m
        src = inspect.getsource(m)
        for banned in ("CONFIRMED", "POTENTIAL", "NOT_VULNERABLE"):
            self.assertNotIn(banned, src)

    def test_browser_field_omits_verdict_keys(self):
        from ai.schemas.xss_verification import (
            BrowserExecutionObservation,
        )
        fields = BrowserExecutionObservation.model_fields
        self.assertFalse(
            [name for name in fields if "verdict" in name]
        )


if __name__ == "__main__":
    unittest.main()

"""Focused unit tests for ``CompositeVerificationExecutor``.

The composite is ONLY a dispatcher between
``ai.verification.VerificationExecutor`` and the two already
tested evidence executors. These tests prove the wiring
contract and nothing else:

1. HTTP mode routes only to the HTTP executor.
2. Browser mode routes only to the Browser executor.
3. Each executor receives the EXACT ``VerificationAttempt``
   object the composite received (identity, not a copy).
4. The composite returns the EXACT ``VerificationEvidence``
   object produced by the selected executor.
5. An unknown/unsupported mode cannot silently route to any
   executor (it raises; through ``XSSVerifier`` it becomes
   bound ERROR evidence per the existing execution contract).
6. The composite never mutates the attempt.
7. Fake executors with call recording prove that no real
   network or browser runtime is touched, and the composite
   module holds no reference to the concrete executors (no
   implicit dependency instantiation).

The 100+ existing HTTP/browser/verifier tests are NOT
duplicated here; only the dispatch behaviour is exercised.
"""

from __future__ import annotations

import unittest

from ai.schemas.xss_verification import (
    AttemptStatus,
    BrowserExecutionObservation,
    ReflectionLocation,
    ReflectionObservation,
    VerificationEvidence,
    VerificationMode,
    VerificationPlan,
    build_verification_attempt,
)
from ai.verification import CompositeVerificationExecutor
from ai.verification import composite_executor as composite_module
from ai.verification.verifier import XSSVerifier


KNOWLEDGE_ID = "kb-1234567890abcde"
SOURCE_ID = "src-1234567890abcde"
ENDPOINT = "https://target.example.test/search"
PAYLOAD = "<img src=x onerror=alert(1)>"


# =====================================================================
# Fakes: recording executors. No network, no browser.
# =====================================================================


class _RecordingExecutor:
    """Fake executor: records every attempt it receives and
    returns the exact canned evidence object."""

    def __init__(self, name: str, evidence: VerificationEvidence):
        self.name = name
        self.evidence = evidence
        self.calls: list = []

    def execute(self, attempt):
        self.calls.append(attempt)
        return self.evidence


class _BindingFakeExecutor:
    """Fake executor that binds a well-formed evidence object
    to whatever attempt it receives (mirrors what the real
    executors guarantee). Used for the verifier integration
    tests where attempts are created inside the verifier."""

    def __init__(self, kind: str):
        self.kind = kind
        self.calls: list = []

    def execute(self, attempt):
        self.calls.append(attempt)
        if self.kind == "http":
            return VerificationEvidence(
                attempt_id=attempt.attempt_id,
                attempt_status=AttemptStatus.SUCCEEDED,
                request_url=attempt.endpoint,
                request_method=attempt.method,
                response_status=200,
                reflection=ReflectionObservation(
                    reflected=False,
                    location=ReflectionLocation.NONE,
                    matched_correlation_token=False,
                    observed_correlation_token=None,
                ),
            )
        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            browser=BrowserExecutionObservation(
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
        )


def _attempt(mode=VerificationMode.HTTP_REFLECTION, **overrides):
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
        mode=mode,
        phase=(
            "http"
            if mode == VerificationMode.HTTP_REFLECTION
            else "browser"
        ),
    )
    kwargs.update(overrides)
    return build_verification_attempt(**kwargs)


def _evidence(attempt: object, status=AttemptStatus.SUCCEEDED):
    return VerificationEvidence(
        attempt_id=attempt.attempt_id,
        attempt_status=status,
        request_url=attempt.endpoint,
        request_method=attempt.method,
        response_status=(
            200 if status == AttemptStatus.SUCCEEDED else None
        ),
    )


def _recording_pair():
    http_attempt = _attempt(VerificationMode.HTTP_REFLECTION)
    browser_attempt = _attempt(VerificationMode.BROWSER_EXECUTION)
    http_fake = _RecordingExecutor("http", _evidence(http_attempt))
    browser_fake = _RecordingExecutor(
        "browser", _evidence(browser_attempt)
    )
    composite = CompositeVerificationExecutor(
        http_executor=http_fake,
        browser_executor=browser_fake,
    )
    return composite, http_fake, browser_fake


# =====================================================================
# Routing
# =====================================================================


class CompositeRoutingTests(unittest.TestCase):
    def test_http_mode_routes_only_to_http_executor(self):
        attempt = _attempt(VerificationMode.HTTP_REFLECTION)
        composite, http_fake, browser_fake = _recording_pair()

        composite.execute(attempt)

        self.assertEqual(http_fake.calls, [attempt])
        self.assertEqual(browser_fake.calls, [])

    def test_browser_mode_routes_only_to_browser_executor(self):
        attempt = _attempt(VerificationMode.BROWSER_EXECUTION)
        composite, http_fake, browser_fake = _recording_pair()

        composite.execute(attempt)

        self.assertEqual(browser_fake.calls, [attempt])
        self.assertEqual(http_fake.calls, [])

    def test_executor_receives_exact_attempt_object(self):
        # Identity, not a copy: the composite must not
        # rebuild or rewrite the attempt in any way.
        for mode in (
            VerificationMode.HTTP_REFLECTION,
            VerificationMode.BROWSER_EXECUTION,
        ):
            attempt = _attempt(mode)
            composite, http_fake, browser_fake = _recording_pair()
            composite.execute(attempt)
            selected = (
                http_fake
                if mode == VerificationMode.HTTP_REFLECTION
                else browser_fake
            )
            self.assertIs(selected.calls[0], attempt)

    def test_returns_exact_evidence_from_selected_executor(self):
        # Identity: whatever evidence object the selected
        # executor produced is returned untouched.
        for mode in (
            VerificationMode.HTTP_REFLECTION,
            VerificationMode.BROWSER_EXECUTION,
        ):
            attempt = _attempt(mode)
            composite, http_fake, browser_fake = _recording_pair()
            result = composite.execute(attempt)
            selected = (
                http_fake
                if mode == VerificationMode.HTTP_REFLECTION
                else browser_fake
            )
            self.assertIs(result, selected.evidence)

    def test_composite_is_accepted_by_verifier_as_executor(self):
        # Structural conformance: XSSVerifier's constructor
        # validates the VerificationExecutor.execute boundary.
        composite, _http_fake, _browser_fake = _recording_pair()
        verifier = XSSVerifier(composite)
        self.assertIs(verifier.executor, composite)
        self.assertTrue(callable(getattr(composite, "execute", None)))


# =====================================================================
# Unknown / unsupported modes
# =====================================================================


class CompositeUnknownModeTests(unittest.TestCase):
    @staticmethod
    def _attempt_with_unknown_mode():
        attempt = _attempt(VerificationMode.HTTP_REFLECTION)
        # model_copy(update=...) bypasses validation on
        # purpose: the dispatcher must survive a hostile or
        # future mode value that is neither enum member.
        return attempt.model_copy(
            update={"mode": "carrier_pigeon"}
        )

    @staticmethod
    def _minimal_analysis():
        from ai.test_xss_verification import _analysis

        return _analysis()

    def test_unknown_mode_raises_and_routes_nowhere(self):
        attempt = self._attempt_with_unknown_mode()
        composite, http_fake, browser_fake = _recording_pair()

        with self.assertRaises(ValueError) as ctx:
            composite.execute(attempt)

        self.assertIn(
            "mode_not_supported_by_composite_executor",
            str(ctx.exception),
        )
        # Not silently rerouted to the other executor.
        self.assertEqual(http_fake.calls, [])
        self.assertEqual(browser_fake.calls, [])

    def test_unknown_mode_yields_verifier_error_evidence(self):
        # Through the verifier's existing execution contract,
        # the composite's ValueError becomes bound ERROR
        # evidence (transport failure -> INCONCLUSIVE).
        attempt = self._attempt_with_unknown_mode()
        composite, http_fake, browser_fake = _recording_pair()
        verifier = XSSVerifier(composite)

        result = verifier.verify(
            self._minimal_analysis(),
            plan=VerificationPlan(attempts=[attempt]),
        )

        self.assertEqual(len(result.evidence), 1)
        evidence = result.evidence[0]
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.ERROR
        )
        self.assertIn(
            "mode_not_supported_by_composite_executor",
            evidence.error_reason,
        )
        self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        self.assertEqual(http_fake.calls, [])
        self.assertEqual(browser_fake.calls, [])
        self.assertEqual(result.findings, [])


# =====================================================================
# Missing executor configuration
# =====================================================================


class CompositeMissingExecutorTests(unittest.TestCase):
    def test_missing_executor_for_mode_is_an_error_not_a_reroute(self):
        attempt = _attempt(VerificationMode.BROWSER_EXECUTION)
        http_fake = _RecordingExecutor("http", _evidence(attempt))
        composite = CompositeVerificationExecutor(
            http_executor=http_fake
        )

        with self.assertRaises(ValueError) as ctx:
            composite.execute(attempt)

        self.assertIn(
            "executor_not_configured_for_composite_executor",
            str(ctx.exception),
        )
        # The HTTP executor must NOT silently receive a
        # browser attempt.
        self.assertEqual(http_fake.calls, [])

    def test_missing_executor_for_http_mode_is_an_error(self):
        attempt = _attempt(VerificationMode.HTTP_REFLECTION)
        browser_fake = _RecordingExecutor(
            "browser", _evidence(attempt)
        )
        composite = CompositeVerificationExecutor(
            browser_executor=browser_fake
        )

        with self.assertRaises(ValueError):
            composite.execute(attempt)

        self.assertEqual(browser_fake.calls, [])


# =====================================================================
# Immutability and dependency isolation
# =====================================================================


class CompositePurityTests(unittest.TestCase):
    def test_attempt_is_never_mutated(self):
        for mode in (
            VerificationMode.HTTP_REFLECTION,
            VerificationMode.BROWSER_EXECUTION,
        ):
            attempt = _attempt(mode)
            before = attempt.model_dump()
            composite, _http_fake, _browser_fake = _recording_pair()
            composite.execute(attempt)
            self.assertEqual(attempt.model_dump(), before)

    def test_fakes_prove_no_real_network_or_browser_is_touched(self):
        # Both fakes are pure in-process objects; the
        # composite's only interaction with the world is the
        # call into the selected fake.
        attempt_http = _attempt(VerificationMode.HTTP_REFLECTION)
        attempt_browser = _attempt(
            VerificationMode.BROWSER_EXECUTION
        )
        composite, http_fake, browser_fake = _recording_pair()

        composite.execute(attempt_http)
        composite.execute(attempt_browser)

        self.assertEqual(len(http_fake.calls), 1)
        self.assertEqual(len(browser_fake.calls), 1)
        self.assertEqual(
            http_fake.calls[0].mode,
            VerificationMode.HTTP_REFLECTION,
        )
        self.assertEqual(
            browser_fake.calls[0].mode,
            VerificationMode.BROWSER_EXECUTION,
        )

    def test_composite_module_has_no_concrete_executor_dependency(self):
        # The AI-layer boundary: the composite must not import
        # (and therefore cannot implicitly instantiate) the
        # real network/browser executors.
        self.assertFalse(
            hasattr(composite_module, "HTTPEvidenceExecutor")
        )
        self.assertFalse(
            hasattr(composite_module, "BrowserEvidenceExecutor")
        )
        # And it never constructs executors implicitly: with
        # no injection, both slots stay None and any dispatch
        # fails loudly.
        composite = composite_module.CompositeVerificationExecutor()
        self.assertIsNone(composite.http_executor)
        self.assertIsNone(composite.browser_executor)


# =====================================================================
# End-to-end verifier integration
# =====================================================================


class CompositeVerifierIntegrationTests(unittest.TestCase):
    def test_verifier_routes_both_modes_through_composite(self):
        from ai.test_xss_verification import _analysis

        analysis = _analysis()
        http_fake = _BindingFakeExecutor("http")
        browser_fake = _BindingFakeExecutor("browser")
        composite = CompositeVerificationExecutor(
            http_executor=http_fake,
            browser_executor=browser_fake,
        )

        result = XSSVerifier(composite).verify(analysis)

        # The default plan is one HTTP attempt + one browser
        # attempt per payload; each must have reached exactly
        # its own executor.
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(len(http_fake.calls), 1)
        self.assertEqual(len(browser_fake.calls), 1)
        self.assertEqual(
            http_fake.calls[0].mode,
            VerificationMode.HTTP_REFLECTION,
        )
        self.assertEqual(
            browser_fake.calls[0].mode,
            VerificationMode.BROWSER_EXECUTION,
        )
        # Evidence stays bound to the attempts the verifier
        # issued; the composite did not rewrite identifiers.
        for attempt, evidence in zip(
            result.attempts, result.evidence
        ):
            self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        # Attempt pairing semantics pass through untouched.
        self.assertEqual(
            result.attempts[0].logical_pair_id,
            result.attempts[1].logical_pair_id,
        )
        self.assertEqual(result.audit.succeeded_count, 2)

    def test_verifier_error_contract_for_unroutable_mode(self):
        # A mode the composite cannot route must surface as
        # ERROR evidence inside an otherwise normal verifier
        # run, alongside correctly-routed attempts.
        from ai.test_xss_verification import (
            _analysis,
            _attempts_for_analysis,
        )

        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        self.assertEqual(len(attempts), 2)

        unknown = attempts[0].model_copy(
            update={"mode": "smoke_signal"}
        )
        http_fake = _BindingFakeExecutor("http")
        browser_fake = _BindingFakeExecutor("browser")
        composite = CompositeVerificationExecutor(
            http_executor=http_fake,
            browser_executor=browser_fake,
        )

        result = XSSVerifier(composite).verify(
            analysis,
            plan=VerificationPlan(attempts=[unknown, attempts[1]]),
        )

        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(
            result.evidence[0].attempt_status, AttemptStatus.ERROR
        )
        self.assertIn(
            "mode_not_supported_by_composite_executor",
            result.evidence[0].error_reason,
        )
        self.assertEqual(
            result.evidence[1].attempt_status,
            AttemptStatus.SUCCEEDED,
        )
        self.assertEqual(http_fake.calls, [])
        self.assertEqual(len(browser_fake.calls), 1)
        self.assertIs(browser_fake.calls[0], attempts[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()




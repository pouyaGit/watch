"""Composite production executor for XSS verification.

This module is the small production adapter that wires the
already-tested evidence executors to the
:class:`ai.verification.VerificationExecutor` protocol consumed
by :class:`ai.verification.verifier.XSSVerifier`.

Design constraints (intentional and enforced by tests):

- The composite is ONLY a dispatcher. It never classifies
  vulnerabilities, never produces CONFIRMED / POTENTIAL /
  NOT_VULNERABLE labels, never inspects LLM rationale, and
  never generates payloads. Classification remains the
  exclusive authority of ``XSSVerifier``.
- Routing is deterministic and driven solely by
  ``attempt.mode``:
      VerificationMode.HTTP_REFLECTION   -> http_executor
      VerificationMode.BROWSER_EXECUTION -> browser_executor
- The composite never touches the network or a browser
  itself. Executors are injected by the caller; none are
  instantiated implicitly, and this module does not import
  the concrete executor implementations at all (the AI layer
  boundary: real network/browser runtimes live outside it).
- The composite never mutates the attempt: the exact
  ``VerificationAttempt`` object it receives is handed to the
  selected executor untouched (identifiers, payload and the
  correlation token pass through byte-identically), and the
  exact ``VerificationEvidence`` object produced by that
  executor is returned without copying or rewriting.
- An unknown/unsupported mode raises a clear ``ValueError``
  instead of silently routing to the other executor. When
  driven through ``XSSVerifier``, that exception is converted
  by the verifier's existing execution contract into bound
  ERROR evidence, exactly like any other executor failure.
"""

from __future__ import annotations

from ai.schemas.xss_verification import (
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
)
from ai.verification import VerificationExecutor

__all__ = [
    "CompositeVerificationExecutor",
]


class CompositeVerificationExecutor:
    """
    Dispatch :class:`VerificationAttempt` objects to the
    executor that owns their ``VerificationMode``.

    Both executors are injected; ``None`` is allowed at
    construction time so callers can configure only the
    runtimes they intend to use. A mode whose executor was
    never injected raises ``ValueError`` (it must never fall
    through to the other executor).

    The composite satisfies the
    :class:`ai.verification.VerificationExecutor` protocol
    structurally and can be passed directly to
    ``XSSVerifier(executor)``.
    """

    def __init__(
        self,
        http_executor=None,
        browser_executor=None,
    ) -> None:
        """
        ``http_executor`` and ``browser_executor`` are the
        injected mode handlers (typically
        ``HTTPEvidenceExecutor`` and
        ``BrowserEvidenceExecutor``). Any object exposing
        ``execute(attempt) -> VerificationEvidence`` is
        accepted, which keeps the composite unit-testable
        with fakes.
        """

        self.http_executor = http_executor
        self.browser_executor = browser_executor

    def execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        """Route one attempt by mode and return its evidence.

        The exact ``attempt`` object is forwarded untouched
        and the exact evidence object produced by the
        selected executor is returned. No supported mode is
        ever silently rerouted; no unknown mode is ever
        executed at all.
        """

        mode = attempt.mode

        if mode == VerificationMode.HTTP_REFLECTION:
            return self._dispatch(
                "http_executor", self.http_executor, attempt, mode
            )

        if mode == VerificationMode.BROWSER_EXECUTION:
            return self._dispatch(
                "browser_executor",
                self.browser_executor,
                attempt,
                mode,
            )

        raise ValueError(
            "mode_not_supported_by_composite_executor:"
            f"{mode!r}"
        )

    @staticmethod
    def _dispatch(
        attribute: str,
        executor,
        attempt: VerificationAttempt,
        mode: VerificationMode,
    ) -> VerificationEvidence:
        if executor is None:
            # A missing executor must fail loudly, never
            # silently reroute the attempt elsewhere.
            raise ValueError(
                "executor_not_configured_for_composite_executor:"
                f"missing_{attribute}_for_mode_{mode.value}"
            )
        return executor.execute(attempt)

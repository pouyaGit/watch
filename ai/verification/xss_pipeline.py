"""Production integration layer for the XSS analysis +
verification pipeline.

This module is the small, production-facing use-case that
connects two fully tested stages without redesigning either:

    XSSOrchestrator.analyze(case)
        ↓
    XSSAnalysisResult
        ↓
    XSSVerifier.verify(analysis)
        ↓
    XSSVerificationResult
        ↓
    XSSFinding

Design constraints (intentional and enforced by tests):

- The pipeline receives BOTH stages via dependency
  injection. It never constructs an orchestrator, a
  verifier, an HTTP executor, or a browser executor, and it
  never hides credentials, API keys, browser configuration,
  or network configuration. Composition remains the
  caller's explicit decision (see
  :func:`build_default_verifier` for the verifier-side
  composition helper).
- The pipeline is a pure connector. It does not modify the
  case, does not modify the analysis, does not interpret
  LLM status suggestions, does not generate payloads, does
  not classify vulnerabilities, does not duplicate verifier
  logic, and does not perform any HTTP or browser operation
  itself.
- Exceptions are never swallowed and never converted into
  security verdicts. If ``orchestrator.analyze`` raises, or
  ``verifier.verify`` raises, the exception propagates
  unchanged so the caller can see exactly which stage
  failed. Infrastructure failures therefore never become
  CONFIRMED / POTENTIAL / NOT_VULNERABLE output.
"""

from __future__ import annotations

from ai.schemas.xss import XSSCase
from ai.schemas.xss_verification import XSSVerificationResult
from ai.verification.composite_executor import (
    CompositeVerificationExecutor,
)
from ai.verification.verifier import XSSVerifier

__all__ = [
    "XSSVerificationPipeline",
    "build_default_verifier",
]


class XSSVerificationPipeline:
    """
    Run one XSS case through analysis and then verification.

    Flow::

        run(case)
            → orchestrator.analyze(case)   (exactly once)
            → verifier.verify(analysis)    (exactly once)
            → XSSVerificationResult

    Both collaborators are injected and used exactly as
    they are; the pipeline owns neither stage's
    configuration. The returned result (including its
    ``findings``) is produced entirely by the verifier; the
    pipeline never reads, interprets, or rewrites it.
    """

    def __init__(self, orchestrator, verifier) -> None:
        """
        ``orchestrator`` is any object exposing
        ``analyze(case) -> XSSAnalysisResult`` (the production
        type is
        :class:`ai.researcher.xss_orchestrator.XSSOrchestrator`).

        ``verifier`` is any object exposing
        ``verify(analysis) -> XSSVerificationResult`` (the
        production type is
        :class:`ai.verification.verifier.XSSVerifier`).

        Both are accepted structurally, consistent with the
        repository's dependency-injection style (see
        ``XSSOrchestrator`` and ``VerificationExecutor``), so
        tests can inject fakes without weakening the
        production contracts.
        """

        self.orchestrator = orchestrator
        self.verifier = verifier

    def run(self, case: XSSCase) -> XSSVerificationResult:
        """Analyze one case and verify the analysis result.

        The exact ``case`` object is handed to
        ``orchestrator.analyze`` unchanged, the exact
        analysis result is handed to ``verifier.verify``
        unchanged, and the exact verification result
        returned by the verifier is returned unchanged.
        """

        analysis = self.orchestrator.analyze(case)
        return self.verifier.verify(analysis)


def build_default_verifier(
    http_executor,
    browser_executor,
) -> XSSVerifier:
    """
    Production composition helper for the verifier side.

    Wires the two already-tested evidence executors into the
    composite dispatcher and wraps it in a verifier::

        CompositeVerificationExecutor
            ├── http_executor   (injected)
            └── browser_executor (injected)
            ↓
        XSSVerifier

    The concrete executors (``HTTPEvidenceExecutor``,
    ``BrowserEvidenceExecutor``) are deliberately NOT
    constructed here: their network/browser configuration
    (sessions, timeouts, Playwright runtimes, credentials)
    belongs to the caller, keeping dependency injection
    explicit at every layer. This helper only composes the
    already-injected executors into the verifier.
    """

    return XSSVerifier(
        CompositeVerificationExecutor(
            http_executor=http_executor,
            browser_executor=browser_executor,
        )
    )

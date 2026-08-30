"""Focused unit tests for the XSS analysis + verification
pipeline integration layer (``XSSVerificationPipeline``).

The pipeline is a pure connector between two fully tested
stages::

    XSSOrchestrator.analyze(case)
        ↓ XSSAnalysisResult
    XSSVerifier.verify(analysis)
        ↓ XSSVerificationResult
        ↓ XSSFinding

These tests prove ONLY the wiring contract:

1. ``run()`` calls ``orchestrator.analyze()`` exactly once.
2. The exact ``XSSCase`` object is passed to ``analyze()``.
3. The returned ``XSSAnalysisResult`` is passed unchanged to
   ``verifier.verify()``.
4. The exact ``XSSVerificationResult`` returned by the
   verifier is returned by the pipeline.
5. Exceptions from ``analyze`` propagate unchanged.
6. Exceptions from ``verify`` propagate unchanged.
7. The pipeline never interprets findings or statuses.
8. No network/browser dependencies are touched (pure fakes
   only; the pipeline module never imports executors).

Plus ONE production-composition test proving that
``CompositeVerificationExecutor`` + injected fake executors +
``XSSVerifier`` + ``XSSVerificationPipeline`` can be
constructed and driven end-to-end without circular imports.

The existing executor/verifier test suites are NOT duplicated.
"""

from __future__ import annotations

import unittest

from ai.researcher.xss_orchestrator import XSSAnalysisResult
from ai.schemas.xss import XSSCase, XSSContext
from ai.schemas.xss_finding import XSSFinding
from ai.schemas.xss_verification import (
    XSSVerificationAudit,
    XSSVerificationResult,
)
from ai.verification import XSSVerificationPipeline
from ai.verification import xss_pipeline as pipeline_module
from ai.verification.verifier import XSSVerifier
from ai.verification.xss_pipeline import build_default_verifier


# =====================================================================
# Fakes. Pure in-process objects: no network, no browser.
# =====================================================================


class _FakeOrchestrator:
    """Fake XSSOrchestrator: records the case it receives and
    returns a canned analysis (or raises a canned exception)."""

    def __init__(self, analysis=None, exc=None):
        self.analysis = analysis
        self.exc = exc
        self.cases = []

    def analyze(self, case):
        self.cases.append(case)
        if self.exc is not None:
            raise self.exc
        return self.analysis


class _FakeVerifier:
    """Fake XSSVerifier: records the analysis it receives and
    returns a canned result (or raises a canned exception)."""

    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc
        self.analyses = []

    def verify(self, analysis):
        self.analyses.append(analysis)
        if self.exc is not None:
            raise self.exc
        return self.result


class _ModeAwareFakeExecutor:
    """Fake VerificationExecutor that binds a minimal
    well-formed evidence object to whatever attempt it
    receives. Used only in the composition test."""

    def __init__(self, kind: str):
        self.kind = kind
        self.calls = []

    def execute(self, attempt):
        self.calls.append(attempt)
        from ai.schemas.xss_verification import (
            AttemptStatus,
            BrowserExecutionObservation,
            ReflectionLocation,
            ReflectionObservation,
            VerificationEvidence,
        )

        evidence = VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url=attempt.endpoint,
            request_method=attempt.method,
        )
        if self.kind == "http":
            evidence.reflection = ReflectionObservation(
                reflected=False,
                location=ReflectionLocation.NONE,
                matched_correlation_token=False,
                observed_correlation_token=None,
            )
        else:
            evidence.browser = BrowserExecutionObservation(
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            )
        return evidence


# =====================================================================
# Fixtures
# =====================================================================


def _make_case() -> XSSCase:
    return XSSCase(
        case_id="case-1",
        target="https://target.example.test",
        endpoint="https://target.example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        xss_type="reflected",
        context=XSSContext(
            type="html_attribute",
            attribute_name="class",
            attribute_quoted=True,
        ),
    )


def _make_analysis() -> XSSAnalysisResult:
    from ai.test_xss_verification import _analysis

    return _analysis()


def _make_audit() -> XSSVerificationAudit:
    return XSSVerificationAudit(
        retrieval_call_count=1,
        llm_call_count=1,
        retrieved_knowledge_ids=["kb-1234567890abcde"],
        retrieval_had_results=True,
        had_payload_suggestions=True,
        had_verification_ideas=False,
        had_any_knowledge_derived_suggestion=True,
        had_any_model_generated_suggestion=False,
        llm_case_status_suggestion="ANALYZED",
        notes=[],
    )


def _make_result(findings=None) -> XSSVerificationResult:
    return XSSVerificationResult(
        case_id="case-1",
        attempts=[],
        evidence=[],
        findings=findings or [],
        audit=_make_audit(),
    )


def _make_finding(status: str) -> XSSFinding:
    return XSSFinding(
        finding_id="find-1",
        case_id="case-1",
        target="https://target.example.test",
        endpoint="https://target.example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        xss_type="reflected",
        context_type="html_attribute",
        status=status,
        confidence=0.9,
        payload_reference="<img src=x onerror=alert(1)>",
        verification_mode="http_reflection",
        attempt_id="att-1",
        knowledge_references=["kb-1234567890abcde"],
    )


def _make_pipeline(analysis=None, result=None, orch_exc=None,
                   ver_exc=None):
    orchestrator = _FakeOrchestrator(
        analysis=analysis, exc=orch_exc
    )
    verifier = _FakeVerifier(result=result, exc=ver_exc)
    pipeline = XSSVerificationPipeline(
        orchestrator=orchestrator,
        verifier=verifier,
    )
    return pipeline, orchestrator, verifier


# =====================================================================
# Wiring contract
# =====================================================================


class PipelineWiringTests(unittest.TestCase):
    def test_run_calls_orchestrator_analyze_exactly_once(self):
        case = _make_case()
        analysis = _make_analysis()
        result = _make_result()
        pipeline, orchestrator, verifier = _make_pipeline(
            analysis=analysis, result=result
        )

        pipeline.run(case)

        self.assertEqual(len(orchestrator.cases), 1)
        self.assertEqual(len(verifier.analyses), 1)

    def test_run_twice_calls_analyze_once_per_run(self):
        case = _make_case()
        analysis = _make_analysis()
        result = _make_result()
        pipeline, orchestrator, verifier = _make_pipeline(
            analysis=analysis, result=result
        )

        pipeline.run(case)
        pipeline.run(case)

        self.assertEqual(len(orchestrator.cases), 2)
        self.assertEqual(len(verifier.analyses), 2)

    def test_exact_case_object_passed_to_analyze(self):
        case = _make_case()
        pipeline, orchestrator, _verifier = _make_pipeline(
            analysis=_make_analysis(), result=_make_result()
        )

        pipeline.run(case)

        # Identity, not a copy or rebuild: the pipeline must
        # not modify or re-create the case.
        self.assertIs(orchestrator.cases[0], case)

    def test_exact_analysis_passed_to_verify_unchanged(self):
        case = _make_case()
        analysis = _make_analysis()
        pipeline, _orchestrator, verifier = _make_pipeline(
            analysis=analysis, result=_make_result()
        )

        pipeline.run(case)

        self.assertEqual(len(verifier.analyses), 1)
        # Identity: the exact object returned by analyze is
        # handed to verify, untouched.
        self.assertIs(verifier.analyses[0], analysis)
        self.assertEqual(
            verifier.analyses[0].model_dump(), analysis.model_dump()
        )

    def test_exact_verification_result_returned(self):
        case = _make_case()
        result = _make_result()
        pipeline, _orchestrator, _verifier = _make_pipeline(
            analysis=_make_analysis(), result=result
        )

        returned = pipeline.run(case)

        # Identity: the exact object produced by the verifier
        # is returned, not a copy or a rebuild.
        self.assertIs(returned, result)


# =====================================================================
# Error propagation
# =====================================================================


class PipelineErrorPropagationTests(unittest.TestCase):
    def test_analyze_exception_propagates_unchanged(self):
        boom = RuntimeError("knowledge store offline")
        case = _make_case()
        pipeline, _orchestrator, verifier = _make_pipeline(
            orch_exc=boom, result=_make_result()
        )

        with self.assertRaises(RuntimeError) as ctx:
            pipeline.run(case)

        # The pipeline must not swallow, wrap, or convert the
        # infrastructure failure into a security verdict.
        self.assertIs(ctx.exception, boom)
        self.assertEqual(verifier.analyses, [])

    def test_verify_exception_propagates_unchanged(self):
        boom = ValueError("evidence binding violated")
        case = _make_case()
        pipeline, orchestrator, _verifier = _make_pipeline(
            analysis=_make_analysis(), ver_exc=boom
        )

        with self.assertRaises(ValueError) as ctx:
            pipeline.run(case)

        self.assertIs(ctx.exception, boom)
        # analyze ran; verify failed; nothing was masked.
        self.assertEqual(len(orchestrator.cases), 1)


# =====================================================================
# Interpretation purity and dependency isolation
# =====================================================================


class PipelinePurityTests(unittest.TestCase):
    def test_pipeline_never_interprets_findings_or_statuses(self):
        # A result containing findings with arbitrary verdict
        # labels passes through byte-identically, whatever the
        # labels are. The pipeline owns no verdict vocabulary
        # and performs no branching on statuses.
        confirmed = _make_finding("CONFIRMED")
        potential = _make_finding("POTENTIAL")
        case = _make_case()

        for findings in ([confirmed], [potential], [confirmed,
                                                    potential]):
            result = _make_result(findings=findings)
            pipeline, _orchestrator, _verifier = _make_pipeline(
                analysis=_make_analysis(), result=result
            )

            returned = pipeline.run(case)

            self.assertIs(returned, result)
            self.assertEqual(returned.findings, findings)

    def test_case_and_analysis_are_not_mutated(self):
        case = _make_case()
        analysis = _make_analysis()
        case_before = case.model_dump()
        analysis_before = analysis.model_dump()
        pipeline, _orchestrator, _verifier = _make_pipeline(
            analysis=analysis, result=_make_result()
        )

        pipeline.run(case)

        self.assertEqual(case.model_dump(), case_before)
        self.assertEqual(analysis.model_dump(), analysis_before)

    def test_no_network_or_browser_dependencies_are_touched(self):
        # Every collaborator in this test module is a pure
        # in-process fake. The pipeline module itself must not
        # import (and therefore cannot implicitly construct)
        # the real network/browser executors.
        self.assertFalse(
            hasattr(pipeline_module, "HTTPEvidenceExecutor")
        )
        self.assertFalse(
            hasattr(pipeline_module, "BrowserEvidenceExecutor")
        )
        self.assertFalse(hasattr(pipeline_module, "requests"))
        self.assertFalse(hasattr(pipeline_module, "playwright"))

        case = _make_case()
        pipeline, orchestrator, verifier = _make_pipeline(
            analysis=_make_analysis(), result=_make_result()
        )
        pipeline.run(case)
        self.assertEqual(len(orchestrator.cases), 1)
        self.assertEqual(len(verifier.analyses), 1)


# =====================================================================
# Production composition (ONE integration construction test)
# =====================================================================


class PipelineCompositionTests(unittest.TestCase):
    def test_production_composition_builds_and_runs_without_circular_imports(self):
        # CompositeVerificationExecutor + injected fake
        # executors + XSSVerifier + XSSVerificationPipeline:
        # the full production shape, executable end to end
        # with no real network or browser and no circular
        # imports (this import chain already succeeded if the
        # test is running).
        from ai.verification import (
            CompositeVerificationExecutor,
        )

        http_fake = _ModeAwareFakeExecutor("http")
        browser_fake = _ModeAwareFakeExecutor("browser")
        verifier = build_default_verifier(
            http_executor=http_fake,
            browser_executor=browser_fake,
        )
        self.assertIsInstance(verifier, XSSVerifier)

        case = _make_case()
        orchestrator = _FakeOrchestrator(
            analysis=_make_analysis()
        )
        pipeline = XSSVerificationPipeline(
            orchestrator=orchestrator,
            verifier=verifier,
        )

        result = pipeline.run(case)

        # The chain ran: analyze once, both attempts routed
        # through the composite to their own executors, and a
        # real verifier-produced result came back.
        self.assertIsInstance(result, XSSVerificationResult)
        self.assertEqual(len(orchestrator.cases), 1)
        self.assertIs(orchestrator.cases[0], case)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(len(http_fake.calls), 1)
        self.assertEqual(len(browser_fake.calls), 1)
        for attempt, evidence in zip(
            result.attempts, result.evidence
        ):
            self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        self.assertEqual(
            result.attempts[0].logical_pair_id,
            result.attempts[1].logical_pair_id,
        )
        self.assertEqual(result.audit.succeeded_count, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()




import unittest
from typing import Iterable

from pydantic import ValidationError

from ai.schemas.xss import (
    XSSAttributedValue,
    XSSCase,
    XSSContext,
    XSSResearchContext,
    XSSResearchLLMResult,
    XSSSuggestedPayload,
)
from ai.schemas.xss_finding import XSSFinding
from ai.schemas.xss_verification import (
    AttemptStatus,
    BrowserExecutionObservation,
    ReflectionLocation,
    ReflectionObservation,
    SourceToSinkStep,
    StoredXSSPhase,
    StoredXSSPhaseObservation,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    VerificationPlan,
    WAFObservation,
    WAFObservationKind,
    XSSVerificationAudit,
    XSSVerificationResult,
    attempt_id_from_canonical,
    build_verification_attempt,
    correlation_token_from_attempt,
)
from ai.verification.verifier import XSSVerifier
from ai.researcher.xss_orchestrator import (
    XSSAnalysisAudit,
    XSSAnalysisResult,
)


KNOWLEDGE_ID = "kb-1234567890abcde"
SOURCE_ID = "src-1234567890abcde"
PAYLOAD = "<kb payload>"
PATTERN = "attribute breakout marker"


# Default target/endpoint/parameter used by the standard
# chain fixture and the analysis helpers. Kept module-level
# so the chain fixture and the analysis helpers stay in
# lockstep.
_DEFAULT_ENDPOINT = "https://target.example.test/search"
_DEFAULT_PARAMETER = "q"
_DEFAULT_PARAMETER_LOCATION = "query"


def _default_valid_chain() -> list[SourceToSinkStep]:
    """
    Single source of truth for the standard valid
    parameter -> sink -> observable chain used by the
    positive cases, the confirmed path, the stored XSS
    round trip, and the deterministic-finding fixture.

    Every test that needs a *well-formed* chain uses this
    helper so the binding identifiers stay consistent
    with the default analysis fixtures.
    """

    return [
        SourceToSinkStep(
            kind="parameter",
            description="q",
            parameter_name=_DEFAULT_PARAMETER,
            parameter_location=_DEFAULT_PARAMETER_LOCATION,
            endpoint=_DEFAULT_ENDPOINT,
        ),
        SourceToSinkStep(kind="sink", description="innerHTML"),
        SourceToSinkStep(
            kind="observable", description="mutation"
        ),
    ]


def _case(
    *,
    xss_type: str = "reflected",
    waf: str | None = "Strict WAF",
    technology: list[str] | None = None,
    endpoint: str = _DEFAULT_ENDPOINT,
    parameter: str = _DEFAULT_PARAMETER,
    parameter_location: str = _DEFAULT_PARAMETER_LOCATION,
) -> XSSCase:
    return XSSCase(
        case_id="case-1",
        target="https://target.example.test",
        endpoint=endpoint,
        method="GET",
        parameter=parameter,
        parameter_location=parameter_location,
        xss_type=xss_type,
        context=XSSContext(
            type="html_attribute",
            attribute_name="class",
            attribute_quoted=True,
        ),
        technology=technology
        if technology is not None
        else ["Example Framework"],
        waf=waf,
        source_type="endpoint",
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
    )


def _context() -> XSSResearchContext:
    return XSSResearchContext(
        case_id="case-1",
        retrieved_knowledge_ids=[KNOWLEDGE_ID],
        documents=[],
        payload_patterns=[
            XSSAttributedValue(
                value=PATTERN, source_ids=[SOURCE_ID]
            )
        ],
    )


def _llm_result(
    *,
    payload_origin: str = "knowledge",
    case_status_suggestion: str = "ANALYZED",
    payloads: list[dict] | None = None,
    rationale: str = "kb adapted",
) -> XSSResearchLLMResult:
    if payloads is None:
        payloads = [
            {
                "pattern": PAYLOAD,
                "origin": payload_origin,
                "knowledge_ids": [KNOWLEDGE_ID]
                if payload_origin == "knowledge"
                else [],
                "source_ids": [SOURCE_ID]
                if payload_origin == "knowledge"
                else [],
                "based_on_pattern": PATTERN,
                "rationale": rationale,
            }
        ]
    return XSSResearchLLMResult(
        case_id="case-1",
        case_status_suggestion=case_status_suggestion,
        suggested_payloads=[
            XSSSuggestedPayload(**p) for p in payloads
        ],
        verification_ideas=[],
        context_observations=[],
        next_research_questions=[],
        evidence=["SECONDARY: stub"],
    )


def _analysis(
    *,
    case: XSSCase | None = None,
    llm: XSSResearchLLMResult | None = None,
    ctx: XSSResearchContext | None = None,
) -> XSSAnalysisResult:
    return XSSAnalysisResult(
        case=case or _case(),
        context=ctx or _context(),
        llm_result=llm or _llm_result(),
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


def _attempts_for_analysis(
    analysis: XSSAnalysisResult,
) -> list[VerificationAttempt]:
    """Test mirror of the verifier's plan construction.

    The plan builder in :class:`XSSVerifier` produces a
    HTTP attempt and a browser attempt per LLM payload.
    For ``xss_type == "stored"`` the browser attempt is
    built with ``phase="stored"`` from the start (no
    post-hoc mutation), so its ``attempt_id`` and
    ``correlation_token`` are derived against the final
    phase. This helper mirrors that behaviour so the
    tests can correlate executor responses to attempts
    by ``attempt_id`` and ``logical_pair_id``.

    Note: the tests intentionally do not re-derive the
    attempt_id and correlation_token here. Identity is
    asserted separately by reconstructing the expected
    attempt via ``build_verification_attempt``.
    """

    case = analysis.case
    xss_type = (case.xss_type or "").strip().lower()
    is_dom = xss_type in {"dom", "mutation"}
    is_stored = xss_type == "stored"
    attempts: list[VerificationAttempt] = []
    for suggested in analysis.llm_result.suggested_payloads:
        if not is_dom:
            attempts.append(
                build_verification_attempt(
                    case_id=case.case_id,
                    endpoint=case.endpoint,
                    method=case.method,
                    parameter=case.parameter,
                    parameter_location=case.parameter_location,
                    payload=suggested.pattern,
                    payload_origin=suggested.origin,
                    knowledge_ids=list(suggested.knowledge_ids),
                    source_ids=list(suggested.source_ids),
                    based_on_pattern=suggested.based_on_pattern,
                    mode=VerificationMode.HTTP_REFLECTION,
                    phase="http",
                )
            )
        # Stored XSS: the browser attempt uses phase="stored"
        # from the start so identity is internally consistent.
        browser_phase = "stored" if is_stored else "browser"
        attempts.append(
            build_verification_attempt(
                case_id=case.case_id,
                endpoint=case.endpoint,
                method=case.method,
                parameter=case.parameter,
                parameter_location=case.parameter_location,
                payload=suggested.pattern,
                payload_origin=suggested.origin,
                knowledge_ids=list(suggested.knowledge_ids),
                source_ids=list(suggested.source_ids),
                based_on_pattern=suggested.based_on_pattern,
                mode=VerificationMode.BROWSER_EXECUTION,
                phase=browser_phase,
            )
        )
    return attempts


def _http_evidence(
    *,
    attempt: VerificationAttempt | None = None,
    attempt_id: str | None = None,
    reflected: bool = True,
    location: ReflectionLocation = (
        ReflectionLocation.HTML_ATTRIBUTE
    ),
    matched_correlation_token: bool = True,
    observed_correlation_token: str | None = None,
    waf_observations: list[WAFObservation] | None = None,
    status: AttemptStatus = AttemptStatus.SUCCEEDED,
    error_reason: str | None = None,
    request_url: str = _DEFAULT_ENDPOINT,
    request_method: str = "GET",
) -> VerificationEvidence:
    if attempt is not None:
        if attempt_id is None:
            attempt_id = attempt.attempt_id
        if observed_correlation_token is None:
            observed_correlation_token = attempt.correlation_token
    if attempt_id is None:
        raise ValueError("attempt_id or attempt is required")
    if observed_correlation_token is None and reflected:
        # Default to a stable placeholder so unrelated tests
        # still construct valid evidence.
        observed_correlation_token = "ct-placeholder"
    return VerificationEvidence(
        attempt_id=attempt_id,
        attempt_status=status,
        request_url=request_url,
        request_method=request_method,
        response_status=200 if status is AttemptStatus.SUCCEEDED else None,
        reflection=ReflectionObservation(
            reflected=reflected,
            location=location,
            matched_correlation_token=matched_correlation_token,
            observed_correlation_token=observed_correlation_token,
        ),
        waf_observations=waf_observations or [],
        error_reason=error_reason,
    )


def _browser_evidence(
    *,
    attempt: VerificationAttempt | None = None,
    attempt_id: str | None = None,
    executed_script: bool = True,
    correlation_token_in_runtime: bool = True,
    observed_correlation_token: str | None = None,
    source_to_sink: list[SourceToSinkStep] | None = None,
    waf_observations: list[WAFObservation] | None = None,
    status: AttemptStatus = AttemptStatus.SUCCEEDED,
    dom_changes: list[str] | None = None,
    console_messages: list[str] | None = None,
    network_requests: list[str] | None = None,
    storage_writes: list[str] | None = None,
    request_url: str = _DEFAULT_ENDPOINT,
    request_method: str = "GET",
    stored_phases: list[StoredXSSPhaseObservation] | None = None,
) -> VerificationEvidence:
    if attempt is not None:
        if attempt_id is None:
            attempt_id = attempt.attempt_id
        if observed_correlation_token is None:
            observed_correlation_token = attempt.correlation_token
    if attempt_id is None:
        raise ValueError("attempt_id or attempt is required")
    if observed_correlation_token is None:
        observed_correlation_token = "ct-placeholder"
    if source_to_sink is None:
        source_to_sink = _default_valid_chain()
    return VerificationEvidence(
        attempt_id=attempt_id,
        attempt_status=status,
        request_url=request_url,
        request_method=request_method,
        response_status=200,
        reflection=ReflectionObservation(
            reflected=True,
            location=ReflectionLocation.HTML_ATTRIBUTE,
            matched_correlation_token=True,
            observed_correlation_token=observed_correlation_token,
        ),
        browser=BrowserExecutionObservation(
            executed_script=executed_script,
            correlation_token_in_runtime=correlation_token_in_runtime,
            observed_correlation_token=observed_correlation_token,
            dom_changes=dom_changes or [],
            console_messages=console_messages or [],
            network_requests=network_requests or [],
            storage_writes=storage_writes or [],
            source_to_sink=source_to_sink,
        ),
        waf_observations=waf_observations or [],
        stored_phases=stored_phases or [],
    )


class _FakeExecutor:
    """In-memory VerificationExecutor that returns canned
    evidence for each attempt in order, or raises if no
    canned response is available."""

    def __init__(
        self,
        responses: Iterable[VerificationEvidence | Exception] | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._index = 0
        self.calls: list[VerificationAttempt] = []

    def execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        self.calls.append(attempt)
        if self._index >= len(self._responses):
            raise AssertionError(
                f"unexpected executor call {self._index}"
            )
        response = self._responses[self._index]
        self._index += 1
        if isinstance(response, Exception):
            raise response
        return response


# ============================================================================
# 1. Reflection only → POTENTIAL (only when meaningful
#    reflection + token match)
# ============================================================================
class XSSVerifierReflectionOnlyTests(unittest.TestCase):
    def test_http_reflection_only_yields_potential(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        self.assertEqual(len(attempts), 2)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.status, "POTENTIAL")
        self.assertEqual(finding.verification_mode, "http_reflection")
        self.assertEqual(finding.attempt_id, attempts[0].attempt_id)
        self.assertEqual(finding.knowledge_references, [KNOWLEDGE_ID])
        self.assertEqual(result.audit.succeeded_count, 2)

    def test_no_reflection_yields_inconclusive(self):
        # H1: a clean HTTP attempt with no reflection is
        # INCONCLUSIVE, not POTENTIAL. INCONCLUSIVE never
        # produces a finding.
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    reflected=False,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(result.findings, [])
        self.assertEqual(
            [e.attempt_status.value for e in result.evidence],
            ["succeeded", "succeeded"],
        )

    def test_plain_html_body_reflection_does_not_yield_potential(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    location=ReflectionLocation.HTML_BODY,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(len(result.findings), 0)


# ============================================================================
# 2. Correlated browser execution → CONFIRMED
# ============================================================================
class XSSVerifierConfirmedTests(unittest.TestCase):
    def test_reflection_plus_correlated_browser_yields_confirmed(
        self,
    ):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        http_token = attempts[0].correlation_token
        browser_token = attempts[1].correlation_token

        # HTTP and browser attempts for the same logical
        # verification share ``logical_pair_id`` while
        # their ``attempt_id`` values remain distinct.
        self.assertEqual(
            attempts[0].logical_pair_id, attempts[1].logical_pair_id
        )
        self.assertNotEqual(
            attempts[0].attempt_id, attempts[1].attempt_id
        )

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    observed_correlation_token=http_token,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=browser_token,
                    network_requests=[
                        f"https://x.test/{browser_token}"
                    ],
                    source_to_sink=_default_valid_chain(),
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = sorted(f.status for f in result.findings)
        self.assertEqual(statuses, ["CONFIRMED", "POTENTIAL"])
        confirmed = next(
            f for f in result.findings if f.status == "CONFIRMED"
        )
        self.assertEqual(confirmed.verification_mode, "browser_execution")
        self.assertEqual(confirmed.attempt_id, attempts[1].attempt_id)
        self.assertEqual(confirmed.knowledge_references, [KNOWLEDGE_ID])
        self.assertTrue(confirmed.browser_verified)


# ============================================================================
# 3. Browser execution without correlation → INCONCLUSIVE
# ============================================================================
class XSSVerifierInconclusiveTests(unittest.TestCase):
    def test_browser_executed_without_correlation_token(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=False,
                    observed_correlation_token=None,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)
        self.assertIn("POTENTIAL", statuses)

    def test_browser_not_executed(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)

    def test_no_browser_observation(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                ).model_copy(update={"browser": None}),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)


# ============================================================================
# 4. Unrelated browser execution → INCONCLUSIVE
# ============================================================================
class XSSVerifierUnrelatedExecutionTests(unittest.TestCase):
    def test_unrelated_script_activity_is_treated_as_baseline(
        self,
    ):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=False,
                    observed_correlation_token=None,
                    source_to_sink=_default_valid_chain(),
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)


# ============================================================================
# 5+6. WAF behaviors → INCONCLUSIVE (never NOT_VULNERABLE)
# ============================================================================
class XSSVerifierWAFTests(unittest.TestCase):
    def test_waf_blocked_yields_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.BLOCK, note="403"
                        )
                    ],
                    status=AttemptStatus.WAF_BLOCKED,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.BLOCK, note="403"
                        )
                    ],
                    status=AttemptStatus.WAF_BLOCKED,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("NOT_VULNERABLE", statuses)
        self.assertNotIn("CONFIRMED", statuses)
        self.assertEqual(result.audit.waf_blocked_count, 2)

    def test_waf_transformed_yields_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.TRANSFORM,
                            note="body length altered",
                        )
                    ],
                    status=AttemptStatus.WAF_TRANSFORMED,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.TRANSFORM,
                            note="body length altered",
                        )
                    ],
                    status=AttemptStatus.WAF_TRANSFORMED,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("NOT_VULNERABLE", statuses)
        self.assertNotIn("CONFIRMED", statuses)
        self.assertEqual(result.audit.waf_transformed_count, 2)

    def test_waf_info_does_not_suppress(self):
        # H3: structured INFO WAF observations are
        # metadata only; they must NOT force
        # INCONCLUSIVE on a clean attempt.
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.INFO,
                            note="strict CSP detected",
                        )
                    ],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    network_requests=[
                        f"https://x.test/{attempts[1].correlation_token}"
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = sorted(f.status for f in result.findings)
        self.assertIn("CONFIRMED", statuses)
        self.assertIn("POTENTIAL", statuses)


# ============================================================================
# 7+8. Timeout / executor error → INCONCLUSIVE
# ============================================================================
class XSSVerifierFailureTests(unittest.TestCase):
    def test_timeout_yields_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    status=AttemptStatus.TIMEOUT,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    status=AttemptStatus.TIMEOUT,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(result.findings, [])
        self.assertEqual(result.audit.timeout_count, 2)

    def test_executor_raises_returns_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                RuntimeError("executor crashed"),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    network_requests=[
                        f"https://x.test/{attempts[1].correlation_token}"
                    ],
                    source_to_sink=_default_valid_chain(),
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(result.audit.error_count, 1)
        self.assertEqual(result.audit.succeeded_count, 1)
        # HTTP attempt errored → no paired HTTP evidence
        # for the browser's logical_pair_id. Reflected
        # XSS requires a confirming HTTP pair, so the
        # browser verdict is INCONCLUSIVE (no finding),
        # not CONFIRMED. This is the security behaviour
        # the logical-pairing fix establishes.
        self.assertEqual(
            [f.status for f in result.findings], []
        )

    def test_executor_returns_malformed_evidence(self):
        analysis = _analysis()

        class _BadExecutor:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                return {"missing": "required fields"}

        result = XSSVerifier(_BadExecutor()).verify(analysis)
        self.assertEqual(result.audit.error_count, 2)
        self.assertEqual(result.findings, [])


# ============================================================================
# 9+10. Determinism of attempt_id and correlation_token
# ============================================================================
class XSSVerifierDeterminismTests(unittest.TestCase):
    def test_attempt_id_is_deterministic(self):
        kwargs = dict(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        a1 = build_verification_attempt(**kwargs)
        a2 = build_verification_attempt(**kwargs)
        self.assertEqual(a1.attempt_id, a2.attempt_id)
        self.assertTrue(a1.attempt_id.startswith("va-"))
        self.assertEqual(len(a1.attempt_id), 3 + 64)

    def test_attempt_id_changes_with_payload_origin_or_knowledge(
        self,
    ):
        base = dict(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        a_kb = build_verification_attempt(**base)
        a_mg = build_verification_attempt(
            **{**base, "payload_origin": "model_generated"}
        )
        self.assertNotEqual(a_kb.attempt_id, a_mg.attempt_id)

        a_no_kb = build_verification_attempt(
            **{
                **base,
                "knowledge_ids": [],
                "source_ids": [],
            }
        )
        self.assertNotEqual(a_kb.attempt_id, a_no_kb.attempt_id)

    def test_correlation_token_is_deterministic(self):
        kwargs = dict(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        a1 = build_verification_attempt(**kwargs)
        a2 = build_verification_attempt(**kwargs)
        self.assertEqual(a1.correlation_token, a2.correlation_token)
        self.assertTrue(a1.correlation_token.startswith("ct-"))

    def test_correlation_token_distinct_per_phase(self):
        kwargs = dict(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.BROWSER_EXECUTION,
        )
        a_primary = build_verification_attempt(
            **kwargs, phase="primary"
        )
        a_stored = build_verification_attempt(
            **kwargs, phase="stored"
        )
        self.assertNotEqual(a_primary.attempt_id, a_stored.attempt_id)
        self.assertNotEqual(
            a_primary.correlation_token, a_stored.correlation_token
        )

    def test_attempt_id_and_token_helpers_are_pure(self):
        a1 = build_verification_attempt(
            case_id="c",
            endpoint="e",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[],
            source_ids=[],
            based_on_pattern=None,
            mode=VerificationMode.HTTP_REFLECTION,
        )
        aid = attempt_id_from_canonical({"x": 1})
        tok = correlation_token_from_attempt(aid, phase="primary")
        self.assertTrue(aid.startswith("va-"))
        self.assertTrue(tok.startswith("ct-"))

    def test_logical_pair_id_differs_by_method(self):
        # Two otherwise-identical verification attempts
        # that differ only in HTTP method must carry
        # different ``logical_pair_id`` values. A GET and
        # a POST to the same endpoint+parameter+payload
        # are not the same logical verification: the
        # request shape, the reflection surface, and the
        # browser runtime path all differ. Pairing a GET
        # HTTP evidence with a POST browser evidence (or
        # vice versa) would let an executor that fabricates
        # a confirming HTTP GET response cause a POST-route
        # browser to confirm.
        get_attempt = build_verification_attempt(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        post_attempt = build_verification_attempt(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="POST",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        self.assertNotEqual(
            get_attempt.logical_pair_id, post_attempt.logical_pair_id
        )
        # ``attempt_id`` already includes method, so it
        # also differs; assert it explicitly to keep the
        # existing test invariant visible.
        self.assertNotEqual(
            get_attempt.attempt_id, post_attempt.attempt_id
        )

    def test_logical_pair_id_same_method_same_verification(self):
        # HTTP and browser attempts for the same logical
        # verification (same method, same endpoint, same
        # parameter, same payload) share
        # ``logical_pair_id`` while their ``attempt_id``
        # values remain distinct. This is the contract the
        # browser classification relies on.
        http_attempt = build_verification_attempt(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
        )
        browser_attempt = build_verification_attempt(
            case_id="case-1",
            endpoint="https://x.test/q",
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<x>",
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.BROWSER_EXECUTION,
        )
        self.assertEqual(
            http_attempt.logical_pair_id, browser_attempt.logical_pair_id
        )
        self.assertNotEqual(
            http_attempt.attempt_id, browser_attempt.attempt_id
        )


# ============================================================================
# 11+12. Attribution preservation
# ============================================================================
class XSSVerifierAttributionTests(unittest.TestCase):
    def test_knowledge_attribution_preserved(self):
        analysis = _analysis(
            llm=_llm_result(payload_origin="knowledge")
        )
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        for finding in result.findings:
            self.assertEqual(
                finding.knowledge_references, [KNOWLEDGE_ID]
            )

    def test_model_generated_attribution_is_empty(self):
        analysis = _analysis(
            llm=_llm_result(payload_origin="model_generated")
        )
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        for finding in result.findings:
            self.assertEqual(finding.knowledge_references, [])


# ============================================================================
# 13+14. Endpoint / parameter correlation
# ============================================================================
class XSSVerifierCorrelationTests(unittest.TestCase):
    def test_endpoint_is_carried_into_attempt(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        for attempt in attempts:
            self.assertEqual(
                attempt.endpoint,
                "https://target.example.test/search",
            )
            self.assertEqual(attempt.method, "GET")
            self.assertEqual(attempt.parameter, "q")
            self.assertEqual(attempt.parameter_location, "query")

    def test_parameter_correlation_token_must_be_set(self):
        with self.assertRaises(ValidationError):
            VerificationAttempt(
                attempt_id="va-x",
                case_id="case-1",
                endpoint="e",
                method="GET",
                parameter="q",
                parameter_location="query",
                payload="<x>",
                payload_origin="knowledge",
                knowledge_ids=[],
                source_ids=[],
                based_on_pattern=None,
                mode=VerificationMode.HTTP_REFLECTION,
                correlation_token="",
                phase="primary",
            )


# ============================================================================
# 15+16. DOM XSS source-to-sink
# ============================================================================
class XSSVerifierDOMXSSTests(unittest.TestCase):
    def test_dom_no_sink_chain_yields_inconclusive(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(
            attempts[0].mode, VerificationMode.BROWSER_EXECUTION
        )

        executor = _FakeExecutor(
            [
                _browser_evidence(
                    attempt=attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    source_to_sink=[],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(result.findings, [])

    def test_dom_complete_source_to_sink_yields_confirmed(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _browser_evidence(
                    attempt=attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    source_to_sink=[
                        SourceToSinkStep(
                            kind="parameter",
                            description="q",
                            parameter_name="q",
                            parameter_location="query",
                            endpoint="https://target.example.test/search",
                        ),
                        SourceToSinkStep(
                            kind="sink",
                            description="document.write",
                        ),
                        SourceToSinkStep(
                            kind="observable",
                            description="DOM mutation",
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.status, "CONFIRMED")
        self.assertEqual(finding.verification_mode, "browser_execution")
        self.assertEqual(finding.xss_type, "dom")
        self.assertTrue(finding.browser_verified)

    def test_dom_chain_must_start_with_parameter(self):
        with self.assertRaises(ValidationError):
            BrowserExecutionObservation(
                executed_script=True,
                correlation_token_in_runtime=True,
                source_to_sink=[
                    SourceToSinkStep(
                        kind="sink", description="innerHTML"
                    ),
                    SourceToSinkStep(
                        kind="observable", description="mutation"
                    ),
                ],
            )

    def test_dom_parameter_step_requires_binding(self):
        # The parameter step must carry parameter_name,
        # parameter_location, and endpoint.
        with self.assertRaises(ValidationError):
            BrowserExecutionObservation(
                executed_script=True,
                source_to_sink=[
                    SourceToSinkStep(
                        kind="parameter", description="q"
                    ),
                    SourceToSinkStep(
                        kind="sink", description="innerHTML"
                    ),
                    SourceToSinkStep(
                        kind="observable", description="m"
                    ),
                ],
            )


# ============================================================================
# 17. Stored XSS round-trip
# ============================================================================
class XSSVerifierStoredXSSTests(unittest.TestCase):
    def test_stored_xss_without_round_trip_yields_no_confirmed(
        self,
    ):
        # Stored case: only one phase observed. The
        # verifier must NOT produce CONFIRMED.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        self.assertTrue(
            any(a.phase == "stored" for a in attempts)
        )
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)
        self.assertNotIn("NOT_VULNERABLE", statuses)

    def test_stored_xss_with_complete_round_trip_yields_confirmed(
        self,
    ):
        # H2: a complete SUBMIT/READ round trip with
        # matching observed correlation tokens must yield
        # CONFIRMED.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        stored_attempt = next(
            a for a in attempts if a.phase == "stored"
        )
        token = stored_attempt.correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    stored_phases=[
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.SUBMIT,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.READ,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertIn("CONFIRMED", statuses)
        self.assertNotIn("NOT_VULNERABLE", statuses)

    def test_stored_xss_mismatched_phase_tokens_yield_potential(
        self,
    ):
        # H2: a round trip with mismatched observed
        # correlation tokens is at most POTENTIAL.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        stored_attempt = next(
            a for a in attempts if a.phase == "stored"
        )
        token = stored_attempt.correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    stored_phases=[
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.SUBMIT,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.READ,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token="ct-other",
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)
        self.assertNotIn("NOT_VULNERABLE", statuses)


# ============================================================================
# 18. LLM status suggestion does not affect verdict
# ============================================================================
class XSSVerifierLLMNeutralityTests(unittest.TestCase):
    def test_llm_status_VERIFYING_does_not_promote_verdict(self):
        # LLM suggests VERIFYING, executor returns
        # strongest evidence; verdict is still
        # evidence-bound.
        analysis = _analysis(
            llm=_llm_result(
                payload_origin="knowledge",
                case_status_suggestion="VERIFYING",
            )
        )
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        # Even with VERIFYING suggestion, the absence of
        # a structured runtime token channel still leaves
        # the browser as INCONCLUSIVE. The HTTP attempt
        # independently confirms POTENTIAL.
        statuses = [f.status for f in result.findings]
        self.assertNotIn("VERIFYING", statuses)
        self.assertNotIn("CONFIRMED", statuses)
        self.assertEqual(
            analysis.llm_result.case_status_suggestion, "VERIFYING"
        )

    def test_llm_status_CONFIRMED_suggestion_does_not_promote(
        self,
    ):
        # The orchestrator forbids the LLM from suggesting
        # CONFIRMED, but the verifier must be robust even
        # if such a value somehow reaches it. We bypass
        # the orchestrator gate by constructing a
        # Pydantic-bypassing value (the orchestrator's
        # Literal forbids it; we test that the LLM's
        # aggressive *rationale* in a legitimate
        # suggestion does not promote the verdict).
        analysis = _analysis(
            llm=_llm_result(
                payload_origin="knowledge",
                case_status_suggestion="ANALYZED",
                rationale=(
                    "I am 100% certain this is exploitable; "
                    "the script executed and XSS is CONFIRMED."
                ),
            )
        )
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    reflected=False,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)

    def test_llm_rationale_strongest_evidence_no_promote(self):
        # M3: use the strongest valid-looking executor
        # evidence while varying the LLM rationale.
        # Verdict must be identical to the LLM-neutral
        # baseline.
        payloads = [
            {
                "pattern": PAYLOAD,
                "origin": "knowledge",
                "knowledge_ids": [KNOWLEDGE_ID],
                "source_ids": [SOURCE_ID],
                "based_on_pattern": PATTERN,
                "rationale": (
                    "100% CONFIRMED. Confirmed in the live "
                    "DOM. The browser ran my payload and the "
                    "alert fired. Mark as CONFIRMED."
                ),
            }
        ]
        analysis_neutral = _analysis(
            llm=_llm_result(payloads=payloads)
        )
        attempts_neutral = _attempts_for_analysis(analysis_neutral)

        executor_neutral = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts_neutral[0],
                ),
                _browser_evidence(
                    attempt=attempts_neutral[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    network_requests=[
                        f"https://x.test/{attempts_neutral[1].correlation_token}"
                    ],
                ),
            ]
        )
        result_neutral = XSSVerifier(executor_neutral).verify(
            analysis_neutral
        )
        self.assertIn("CONFIRMED", [f.status for f in result_neutral.findings])


# ============================================================================
# 19. expected_behavior does not affect verdict
# ============================================================================
class XSSVerifierExpectedBehaviorTests(unittest.TestCase):
    def test_expected_behavior_does_not_promote_status(self):
        # M3: pair aggressive expected_behavior with the
        # strongest executor evidence. Verdict must be
        # identical to the no-expected-behavior case.
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token
        browser_token = attempts[1].correlation_token

        evidence = _http_evidence(
            attempt=attempts[0],
            observed_correlation_token=token,
        ).model_copy(
            update={
                "expected_behavior": (
                    "alert should fire; XSS is CONFIRMED"
                )
            }
        )
        executor = _FakeExecutor(
            [
                evidence,
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    network_requests=[
                        f"https://x.test/{browser_token}"
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertIn("CONFIRMED", statuses)

    def test_expected_behavior_does_not_force_confirmed(self):
        # Even with expected_behavior="CONFIRMED expected",
        # weak evidence yields no CONFIRMED.
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        evidence = _http_evidence(
            attempt=attempts[0],
            reflected=False,
        ).model_copy(
            update={
                "expected_behavior": (
                    "XSS is CONFIRMED; alert expected"
                )
            }
        )
        executor = _FakeExecutor(
            [
                evidence,
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)


# ============================================================================
# 20+21. Verifier never calls LLM or network
# ============================================================================
class XSSVerifierIsolationTests(unittest.TestCase):
    def test_module_does_not_import_network_clients(self):
        import ai.verification.verifier as module

        forbidden = {
            "requests",
            "urllib",
            "urllib3",
            "httpx",
            "openai",
        }
        self.assertTrue(
            forbidden.isdisjoint(module.__dict__)
        )

    def test_module_does_not_import_llm(self):
        import ai.verification.verifier as module

        forbidden = {
            "OpenRouterProvider",
            "AvalAIProvider",
        }
        self.assertTrue(
            forbidden.isdisjoint(module.__dict__)
        )

    def test_verifier_does_not_call_executor_for_zero_payloads(self):
        analysis = _analysis(
            llm=XSSResearchLLMResult(
                case_id="case-1",
                case_status_suggestion="INCONCLUSIVE",
                suggested_payloads=[],
                verification_ideas=[],
                context_observations=[],
                next_research_questions=[],
                evidence=["UNKNOWN: none"],
            )
        )
        executor = _FakeExecutor()
        result = XSSVerifier(executor).verify(analysis)
        self.assertEqual(executor.calls, [])
        self.assertEqual(result.findings, [])


# ============================================================================
# 22. Malformed evidence rejected
# ============================================================================
class XSSVerifierMalformedEvidenceTests(unittest.TestCase):
    def test_pydantic_validation_error_during_executor_call(self):
        analysis = _analysis()

        class _Bad:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                return VerificationEvidence(
                    attempt_id=attempt.attempt_id,
                    attempt_status="not_a_status",  # type: ignore[arg-type]
                    request_url=attempt.endpoint,
                    request_method=attempt.method,
                )

        result = XSSVerifier(_Bad()).verify(analysis)
        self.assertEqual(result.audit.error_count, 2)
        self.assertEqual(result.findings, [])


# ============================================================================
# 23. No accidental NOT_VULNERABLE
# ============================================================================
class XSSVerifierNoNotVulnerableTests(unittest.TestCase):
    def test_never_returns_not_vulnerable_for_no_reflection(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    reflected=False,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("NOT_VULNERABLE", statuses)

    def test_never_returns_not_vulnerable_for_waf_block(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    status=AttemptStatus.WAF_BLOCKED,
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.BLOCK, note="403"
                        )
                    ],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    status=AttemptStatus.WAF_BLOCKED,
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.BLOCK, note="403"
                        )
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)

        statuses = [f.status for f in result.findings]
        self.assertNotIn("NOT_VULNERABLE", statuses)

    def test_never_returns_not_vulnerable_even_with_control_evidence(
        self,
    ):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    reflected=False,
                ).model_copy(
                    update={
                        "control_request_unchanged": True,
                        "control_response_status": 200,
                    }
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        statuses = [f.status for f in result.findings]
        self.assertNotIn("NOT_VULNERABLE", statuses)


# ============================================================================
# 24. Deterministic findings for identical evidence
# ============================================================================
class XSSVerifierDeterministicFindingsTests(unittest.TestCase):
    def test_identical_evidence_produces_identical_finding(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor_responses = [
            _http_evidence(
                attempt=attempts[0],
            ),
            _browser_evidence(
                attempt=attempts[1],
                executed_script=True,
                correlation_token_in_runtime=True,
                observed_correlation_token=token,
                network_requests=[f"https://x.test/{token}"],
                source_to_sink=_default_valid_chain(),
            ),
        ]

        a_result = XSSVerifier(_FakeExecutor(executor_responses)).verify(
            analysis
        )
        b_result = XSSVerifier(_FakeExecutor(executor_responses)).verify(
            analysis
        )

        def _stripped(result) -> dict:
            return {
                "findings": [
                    f.model_dump(mode="json")
                    | {"created_at": None}
                    for f in result.findings
                ],
                "audit": result.audit.model_dump(mode="json"),
                "case_id": result.case_id,
                "attempt_ids": [a.attempt_id for a in result.attempts],
            }

        self.assertEqual(_stripped(a_result), _stripped(b_result))
        self.assertEqual(
            a_result.findings[0].finding_id,
            b_result.findings[0].finding_id,
        )


# ============================================================================
# 25. Schema-level tests
# ============================================================================
class XSSFindingOptionalFieldsTests(unittest.TestCase):
    def test_finding_optional_fields_default_to_none(self):
        finding = XSSFinding(
            finding_id="f1",
            case_id="c1",
            target="t",
            endpoint="e",
            method="GET",
            xss_type="reflected",
            context_type="html_attribute",
            status="POTENTIAL",
            confidence=0.5,
        )
        self.assertIsNone(finding.verification_mode)
        self.assertIsNone(finding.attempt_id)

    def test_finding_supports_new_fields(self):
        finding = XSSFinding(
            finding_id="f1",
            case_id="c1",
            target="t",
            endpoint="e",
            method="GET",
            xss_type="reflected",
            context_type="html_attribute",
            status="CONFIRMED",
            confidence=0.95,
            verification_mode="browser_execution",
            attempt_id="va-abc",
        )
        self.assertEqual(
            finding.verification_mode, "browser_execution"
        )
        self.assertEqual(finding.attempt_id, "va-abc")

    def test_existing_finding_construction_is_unchanged(self):
        finding = XSSFinding(
            finding_id="f1",
            case_id="c1",
            target="t",
            endpoint="e",
            method="GET",
            parameter="q",
            parameter_location="query",
            xss_type="reflected",
            context_type="html_attribute",
            status="POTENTIAL",
            confidence=0.5,
            payload_reference="<x>",
            reflection_evidence=["reflected=html_attribute"],
            verification_evidence=["attempt_id=va-x"],
            browser_verified=False,
            waf_observations=[],
            knowledge_references=[],
            remediation_notes=[],
        )
        self.assertIsNone(finding.verification_mode)
        self.assertIsNone(finding.attempt_id)


class XSSVerificationSchemaTests(unittest.TestCase):
    def test_source_to_sink_chain_validator(self):
        chain = _default_valid_chain()
        obs = BrowserExecutionObservation(
            executed_script=True,
            correlation_token_in_runtime=True,
            source_to_sink=chain,
        )
        self.assertEqual(obs.source_to_sink, chain)

    def test_source_to_sink_chain_rejects_missing_parameter(self):
        with self.assertRaises(ValidationError):
            BrowserExecutionObservation(
                executed_script=True,
                source_to_sink=[
                    SourceToSinkStep(
                        kind="sink", description="innerHTML"
                    ),
                    SourceToSinkStep(
                        kind="observable", description="m"
                    ),
                ],
            )

    def test_source_to_sink_chain_rejects_missing_sink(self):
        with self.assertRaises(ValidationError):
            BrowserExecutionObservation(
                executed_script=True,
                source_to_sink=[
                    SourceToSinkStep(
                        kind="parameter",
                        description="q",
                        parameter_name="q",
                        parameter_location="query",
                        endpoint="https://x.test/q",
                    ),
                    SourceToSinkStep(
                        kind="observable", description="m"
                    ),
                ],
            )

    def test_attempt_correlation_token_required(self):
        with self.assertRaises(ValidationError):
            VerificationAttempt(
                attempt_id="va-x",
                case_id="c1",
                endpoint="e",
                method="GET",
                parameter="q",
                parameter_location="query",
                payload="<x>",
                payload_origin="knowledge",
                knowledge_ids=[],
                source_ids=[],
                based_on_pattern=None,
                mode=VerificationMode.HTTP_REFLECTION,
                correlation_token="",
                phase="primary",
            )

    def test_evidence_waf_observations_default_empty(self):
        ev = VerificationEvidence(
            attempt_id="va-x",
            attempt_status=AttemptStatus.SUCCEEDED,
            request_url="e",
            request_method="GET",
        )
        self.assertEqual(ev.waf_observations, [])

    def test_default_plan_is_empty(self):
        result = XSSVerificationResult(
            case_id="c1",
            attempts=[],
            evidence=[],
            findings=[],
            audit=XSSVerificationAudit(),
        )
        self.assertEqual(result.attempts, [])

    def test_waf_observation_rejects_free_text(self):
        # WAF observations are now structured; free-form
        # strings are no longer accepted.
        with self.assertRaises(ValidationError):
            VerificationEvidence(
                attempt_id="va-x",
                attempt_status=AttemptStatus.SUCCEEDED,
                request_url="e",
                request_method="GET",
                waf_observations=["just a free-form string"],  # type: ignore[list-item]
            )


# ============================================================================
# 26. Evidence binding (M7)
# ============================================================================
class XSSVerifierEvidenceBindingTests(unittest.TestCase):
    def test_mismatched_attempt_id_downgrades_to_error(self):
        analysis = _analysis()

        class _WrongAttemptId:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                # Mismatched attempt_id
                return _http_evidence(
                    attempt=attempt,
                    observed_correlation_token=attempt.correlation_token,
                ).model_copy(update={"attempt_id": "va-other"})

        result = XSSVerifier(_WrongAttemptId()).verify(analysis)
        # No finding can be produced from mismatched
        # evidence; the verifier treats the attempt as
        # an executor error and INCONCLUSIVE never
        # produces a finding.
        self.assertEqual(result.findings, [])
        self.assertEqual(result.audit.error_count, 2)

    def test_mismatched_request_url_downgrades_to_error(self):
        analysis = _analysis()

        class _WrongUrl:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                return _http_evidence(
                    attempt=attempt,
                    observed_correlation_token=attempt.correlation_token,
                ).model_copy(
                    update={
                        "request_url": (
                            "https://attacker.example.test/other"
                        )
                    }
                )

        result = XSSVerifier(_WrongUrl()).verify(analysis)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.audit.error_count, 2)

    def test_mismatched_request_method_downgrades_to_error(self):
        analysis = _analysis()

        class _WrongMethod:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                return _http_evidence(
                    attempt=attempt,
                    observed_correlation_token=attempt.correlation_token,
                ).model_copy(update={"request_method": "POST"})

        result = XSSVerifier(_WrongMethod()).verify(analysis)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.audit.error_count, 2)


# ============================================================================
# 27. Adversarial executor tests
#
# Each of the following must NEVER produce CONFIRMED, even
# if the executor returns the strongest-looking evidence.
# ============================================================================
class XSSVerifierAdversarialTests(unittest.TestCase):
    def _strongest_browser_evidence(
        self,
        attempt: VerificationAttempt,
        **overrides,
    ) -> VerificationEvidence:
        token = attempt.correlation_token
        kwargs = dict(
            attempt=attempt,
            executed_script=True,
            correlation_token_in_runtime=True,
            observed_correlation_token=token,
            network_requests=[f"https://x.test/{token}"],
            source_to_sink=_default_valid_chain(),
        )
        kwargs.update(overrides)
        return _browser_evidence(**kwargs)

    # 1. matched_correlation_token=True but actual token
    #    absent.
    def test_adversarial_1_matched_token_true_but_actual_absent(
        self,
    ):
        # C2: a true ``matched_correlation_token`` flag
        # with no observed_correlation_token value (or a
        # wrong one) cannot yield CONFIRMED.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        wrong_token = "ct-not-the-real-token"

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    observed_correlation_token=wrong_token,
                    network_requests=[
                        f"https://x.test/{attempts[0].correlation_token}"
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 2. executed_script=True but no correlated
    #    observable.
    def test_adversarial_2_executed_script_no_observable(self):
        # C3: ``executed_script=True`` alone is not
        # enough; the verifier must independently confirm
        # the token in a structured runtime channel.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=None,
                    dom_changes=[],
                    console_messages=[],
                    network_requests=[],
                    storage_writes=[],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 3. correlation_token_in_runtime=True but token
    #    absent from any structured channel.
    def test_adversarial_3_runtime_flag_no_token_in_channels(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    dom_changes=["alert('hi')"],
                    console_messages=["some message"],
                    network_requests=["https://x.test/other"],
                    storage_writes=["key=value"],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 4. source parameter != attempt.parameter.
    def test_adversarial_4_chain_parameter_mismatch(self):
        # C1: the chain's parameter step must bind to
        # attempt.parameter.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    source_to_sink=[
                        SourceToSinkStep(
                            kind="parameter",
                            description="q",
                            parameter_name="different_param",
                            parameter_location="query",
                            endpoint="https://target.example.test/search",
                        ),
                        SourceToSinkStep(
                            kind="sink", description="innerHTML"
                        ),
                        SourceToSinkStep(
                            kind="observable", description="m"
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 5. source endpoint != attempt.endpoint.
    def test_adversarial_5_chain_endpoint_mismatch(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    source_to_sink=[
                        SourceToSinkStep(
                            kind="parameter",
                            description="q",
                            parameter_name="q",
                            parameter_location="query",
                            endpoint="https://attacker.example.test/x",
                        ),
                        SourceToSinkStep(
                            kind="sink", description="innerHTML"
                        ),
                        SourceToSinkStep(
                            kind="observable", description="m"
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 6. source parameter_location != attempt.parameter_location.
    def test_adversarial_6_chain_location_mismatch(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    source_to_sink=[
                        SourceToSinkStep(
                            kind="parameter",
                            description="q",
                            parameter_name="q",
                            parameter_location="body",
                            endpoint="https://target.example.test/search",
                        ),
                        SourceToSinkStep(
                            kind="sink", description="innerHTML"
                        ),
                        SourceToSinkStep(
                            kind="observable", description="m"
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 7. unrelated browser execution (already covered
    #    under UnrelatedExecutionTests but the brief
    #    asks for the explicit adversarial form).
    def test_adversarial_7_unrelated_browser_execution(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                self._strongest_browser_evidence(
                    attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=False,
                    observed_correlation_token=None,
                    dom_changes=[],
                    console_messages=[],
                    network_requests=[],
                    storage_writes=[],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 8. stored XSS without submit/read round trip.
    def test_adversarial_8_stored_no_round_trip(self):
        # H2: a stored-XSS case with only a single
        # observation cannot yield CONFIRMED.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                self._strongest_browser_evidence(
                    attempts[1],
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    stored_phases=[],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 9. malformed evidence.
    def test_adversarial_9_malformed_evidence(self):
        analysis = _analysis()

        class _Bad:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, attempt):
                self.calls += 1
                return {"malformed": "no required fields"}

        result = XSSVerifier(_Bad()).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )
        self.assertEqual(result.audit.error_count, 2)

    # 10. evidence from another attempt.
    def test_adversarial_10_evidence_for_other_attempt(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        other_attempt = build_verification_attempt(
            case_id="case-1",
            endpoint="https://other.example.test/x",
            method="GET",
            parameter="x",
            parameter_location="query",
            payload="<other>",
            payload_origin="knowledge",
            knowledge_ids=[],
            source_ids=[],
            based_on_pattern=None,
            mode=VerificationMode.BROWSER_EXECUTION,
        )

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                # Browser evidence claims to be from
                # ``other_attempt`` rather than
                # ``attempts[1]``.
                self._strongest_browser_evidence(
                    other_attempt,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 11. LLM suggests CONFIRMED but evidence is weak.
    def test_adversarial_11_llm_says_confirmed_weak_evidence(self):
        # The LLM cannot promote the verdict. The
        # orchestrator forbids CONFIRMED suggestions, but
        # we test the verifier's robustness: even with
        # strong LLM rationale, weak evidence yields no
        # CONFIRMED.
        analysis = _analysis(
            llm=_llm_result(
                payload_origin="knowledge",
                case_status_suggestion="ANALYZED",
                rationale=(
                    "MARKED AS CONFIRMED by the model. "
                    "XSS is exploitable."
                ),
            )
        )
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    reflected=False,
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    # 12. expected_behavior says confirmed but evidence
    #     is insufficient.
    def test_adversarial_12_expected_behavior_says_confirmed(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)
        evidence = _http_evidence(
            attempt=attempts[0],
            reflected=False,
        ).model_copy(
            update={
                "expected_behavior": (
                    "XSS is CONFIRMED. alert() expected."
                )
            }
        )
        executor = _FakeExecutor(
            [
                evidence,
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=False,
                    correlation_token_in_runtime=False,
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )


# ============================================================================
# 28. Positive cases (must produce CONFIRMED only when
#     every precondition is satisfied)
# ============================================================================
class XSSVerifierPositiveCasesTests(unittest.TestCase):
    # 1. reflected XSS with independently matched token
    #    → POTENTIAL.
    def test_positive_1_reflected_token_match_potential(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        # POTENTIAL is produced by the HTTP attempt;
        # the browser attempt is INCONCLUSIVE.
        potential = [
            f
            for f in result.findings
            if f.status == "POTENTIAL"
        ]
        self.assertEqual(len(potential), 1)
        self.assertEqual(potential[0].verification_mode, "http_reflection")

    # 2. reflected/browser execution with valid binding
    #    + independent correlated runtime observation →
    #    CONFIRMED.
    def test_positive_2_reflected_browser_confirmed(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    network_requests=[
                        f"https://x.test/{attempts[1].correlation_token}"
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].verification_mode, "browser_execution"
        )

    # 3. DOM XSS with typed source→sink→observable chain
    #    + independent correlation → CONFIRMED.
    def test_positive_3_dom_chain_confirmed(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token

        executor = _FakeExecutor(
            [
                _browser_evidence(
                    attempt=attempts[0],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    source_to_sink=[
                        SourceToSinkStep(
                            kind="parameter",
                            description="q",
                            parameter_name="q",
                            parameter_location="query",
                            endpoint="https://target.example.test/search",
                        ),
                        SourceToSinkStep(
                            kind="sink", description="eval"
                        ),
                        SourceToSinkStep(
                            kind="observable",
                            description="DOM mutation",
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].xss_type, "dom")

    # 4. stored XSS with complete structured round trip
    #    + correlation → CONFIRMED.
    def test_positive_4_stored_round_trip_confirmed(self):
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        stored_attempt = next(
            a for a in attempts if a.phase == "stored"
        )
        token = stored_attempt.correlation_token

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                ),
                _browser_evidence(
                    attempt=attempts[1],
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    stored_phases=[
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.SUBMIT,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.READ,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)


# ============================================================================
# 29. WAF structured gating
# ============================================================================
class XSSVerifierWAFStructuredTests(unittest.TestCase):
    def test_block_observation_forces_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        # A SUCCEEDED attempt with a structured BLOCK
        # observation must still be INCONCLUSIVE.
        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.BLOCK,
                            note="403",
                        )
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "POTENTIAL", [f.status for f in result.findings]
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_transform_observation_forces_inconclusive(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor = _FakeExecutor(
            [
                _http_evidence(
                    attempt=attempts[0],
                    waf_observations=[
                        WAFObservation(
                            kind=WAFObservationKind.TRANSFORM,
                            note="body length altered",
                        )
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn(
            "POTENTIAL", [f.status for f in result.findings]
        )


# ============================================================================
# 30. Caller mutation safety
# ============================================================================
class XSSVerifierCallerMutationTests(unittest.TestCase):
    def test_caller_mutation_does_not_alter_finding(self):
        analysis = _analysis()
        attempts = _attempts_for_analysis(analysis)

        executor_responses = [
            _http_evidence(
                attempt=attempts[0],
            ),
            _browser_evidence(
                attempt=attempts[1],
                executed_script=True,
                correlation_token_in_runtime=True,
                network_requests=[
                    f"https://x.test/{attempts[1].correlation_token}"
                ],
            ),
        ]
        result = XSSVerifier(_FakeExecutor(executor_responses)).verify(
            analysis
        )
        # Caller mutates the analysis after the fact.
        analysis.llm_result.suggested_payloads.clear()
        analysis.case.endpoint = "https://attacker.example.test/evil"
        self.assertEqual(
            sorted(f.status for f in result.findings),
            ["CONFIRMED", "POTENTIAL"],
        )


# ============================================================================
# 31. Logical pairing + stored-phase identity (post-refactor)
#
# The verifier routes HTTP and browser evidence for the
# same ``logical_pair_id`` to the browser classification
# path. These tests assert:
#   - a browser evidence with no matching HTTP attempt
#     cannot produce CONFIRMED for reflected XSS
#   - an HTTP attempt whose ``logical_pair_id`` differs
#     from the browser attempt's cannot satisfy the pair
#   - a correctly paired reflected pair produces CONFIRMED
#   - a DOM case is browser-only and produces CONFIRMED
#     without an HTTP pair
#   - a stored case requires a complete SUBMIT/READ round
#     trip
#   - the stored browser attempt is built with
#     ``phase="stored"`` from the start, and its
#     identity is independently reconstructable via
#     ``build_verification_attempt(..., phase="stored")``
# ============================================================================
class XSSVerifierLogicalPairingTests(unittest.TestCase):
    def _http_attempt_for(
        self,
        *,
        case: XSSCase,
        payload: str = PAYLOAD,
    ) -> VerificationAttempt:
        return build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=payload,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern=PATTERN,
            mode=VerificationMode.HTTP_REFLECTION,
            phase="http",
        )

    def _browser_attempt_for(
        self,
        *,
        case: XSSCase,
        payload: str = PAYLOAD,
        phase: str = "browser",
    ) -> VerificationAttempt:
        return build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=payload,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern=PATTERN,
            mode=VerificationMode.BROWSER_EXECUTION,
            phase=phase,
        )

    def _strong_browser_evidence(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        token = attempt.correlation_token
        return _browser_evidence(
            attempt=attempt,
            executed_script=True,
            correlation_token_in_runtime=True,
            observed_correlation_token=token,
            network_requests=[f"https://x.test/{token}"],
            source_to_sink=_default_valid_chain(),
        )

    def _matching_http_evidence(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        return _http_evidence(
            attempt=attempt,
            observed_correlation_token=attempt.correlation_token,
        )

    def test_reflected_browser_without_http_pair_yields_no_confirmed(
        self,
    ):
        # Reflected case, but the plan contains only the
        # browser attempt (no HTTP attempt). The browser
        # evidence alone must not produce CONFIRMED.
        case = _case(xss_type="reflected")
        analysis = _analysis(case=case)
        browser_attempt = self._browser_attempt_for(case=case)

        plan = VerificationPlan(attempts=[browser_attempt])
        executor = _FakeExecutor(
            [self._strong_browser_evidence(browser_attempt)]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_reflected_browser_with_unrelated_http_pair_yields_no_confirmed(
        self,
    ):
        # Reflected case. The HTTP attempt and the browser
        # attempt carry different ``logical_pair_id``
        # values (different payloads). The browser evidence
        # is strong on its own but the pair does not match,
        # so CONFIRMED is not produced.
        case = _case(xss_type="reflected")
        analysis = _analysis(case=case)
        http_attempt = self._http_attempt_for(
            case=case, payload="<other payload>"
        )
        browser_attempt = self._browser_attempt_for(
            case=case, payload=PAYLOAD
        )
        # Defence-in-depth: assert the two attempts really
        # do not share a logical_pair_id.
        self.assertNotEqual(
            http_attempt.logical_pair_id,
            browser_attempt.logical_pair_id,
        )

        plan = VerificationPlan(
            attempts=[http_attempt, browser_attempt]
        )
        executor = _FakeExecutor(
            [
                self._matching_http_evidence(http_attempt),
                self._strong_browser_evidence(browser_attempt),
            ]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_reflected_paired_http_and_browser_yield_confirmed(
        self,
    ):
        # Reflected case, HTTP and browser attempts share
        # ``logical_pair_id``, both evidence streams are
        # strong, the browser evidence confirms. Must
        # produce CONFIRMED.
        case = _case(xss_type="reflected")
        analysis = _analysis(case=case)
        http_attempt = self._http_attempt_for(case=case)
        browser_attempt = self._browser_attempt_for(case=case)
        self.assertEqual(
            http_attempt.logical_pair_id,
            browser_attempt.logical_pair_id,
        )

        plan = VerificationPlan(
            attempts=[http_attempt, browser_attempt]
        )
        executor = _FakeExecutor(
            [
                self._matching_http_evidence(http_attempt),
                self._strong_browser_evidence(browser_attempt),
            ]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].attempt_id, browser_attempt.attempt_id)

    def test_dom_browser_only_yields_confirmed(self):
        # DOM case: the production plan builder does not
        # create a paired HTTP attempt. The browser path
        # must produce CONFIRMED without an HTTP pair.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(
            attempts[0].mode, VerificationMode.BROWSER_EXECUTION
        )

        plan = VerificationPlan(attempts=attempts)
        executor = _FakeExecutor(
            [self._strong_browser_evidence(attempts[0])]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].verification_mode, "browser_execution"
        )

    def test_mutation_browser_only_yields_confirmed(self):
        # Mutation case: the production plan builder does
        # not create a paired HTTP attempt. The browser
        # path must produce CONFIRMED without an HTTP pair.
        case = _case(xss_type="mutation")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(
            attempts[0].mode, VerificationMode.BROWSER_EXECUTION
        )

        plan = VerificationPlan(attempts=attempts)
        executor = _FakeExecutor(
            [self._strong_browser_evidence(attempts[0])]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)

    def test_stored_complete_round_trip_yields_confirmed(self):
        # Stored case: HTTP attempt (phase="http") and a
        # stored browser attempt (phase="stored" from the
        # start) share ``logical_pair_id``. The browser
        # evidence carries SUBMIT + READ observations with
        # matching correlation tokens, and the runtime
        # independently observed the token. Must produce
        # CONFIRMED.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        # Sanity: the browser attempt is built with
        # ``phase="stored"`` from the start, not mutated
        # afterwards.
        self.assertEqual(attempts[1].phase, "stored")
        self.assertNotEqual(attempts[0].phase, "stored")

        http_attempt = attempts[0]
        stored_attempt = attempts[1]
        token = stored_attempt.correlation_token

        plan = VerificationPlan(attempts=attempts)
        executor = _FakeExecutor(
            [
                self._matching_http_evidence(http_attempt),
                _browser_evidence(
                    attempt=stored_attempt,
                    executed_script=True,
                    correlation_token_in_runtime=True,
                    observed_correlation_token=token,
                    network_requests=[f"https://x.test/{token}"],
                    stored_phases=[
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.SUBMIT,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.READ,
                            attempt_id=stored_attempt.attempt_id,
                            observed_correlation_token=token,
                        ),
                    ],
                ),
            ]
        )
        result = XSSVerifier(executor).verify(analysis, plan=plan)

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertNotIn(
            "NOT_VULNERABLE", [f.status for f in result.findings]
        )

    def test_stored_attempt_identity_uses_final_phase(self):
        # The stored browser attempt in the plan must
        # have ``attempt_id`` and ``correlation_token``
        # derived against ``phase="stored"`` from the
        # start, not against ``phase="browser"`` followed
        # by a post-hoc mutation.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        stored_attempt = attempts[1]

        expected = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern=PATTERN,
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="stored",
        )
        self.assertEqual(stored_attempt.attempt_id, expected.attempt_id)
        self.assertEqual(
            stored_attempt.correlation_token,
            expected.correlation_token,
        )
        self.assertEqual(stored_attempt.phase, expected.phase)

        # And the plan produced by the verifier must also
        # contain an attempt with this exact identity.
        result = XSSVerifier(
            _FakeExecutor(
                [
                    self._matching_http_evidence(attempts[0]),
                    _browser_evidence(
                        attempt=stored_attempt,
                        executed_script=False,
                        correlation_token_in_runtime=False,
                    ),
                ]
            )
        ).verify(analysis)
        produced_stored = next(
            a
            for a in result.attempts
            if a.phase == "stored"
        )
        self.assertEqual(
            produced_stored.attempt_id, expected.attempt_id
        )
        self.assertEqual(
            produced_stored.correlation_token,
            expected.correlation_token,
        )


if __name__ == "__main__":
    unittest.main()

import unittest
from typing import Iterable
from urllib.parse import urlsplit

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
    DialogEvent,
    EvalInvocation,
    NetworkOracleEvent,
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
from ai.verification.verifier import (
    STORED_READ_PHASE,
    STORED_SUBMIT_PHASE,
    XSSVerifier,
    build_oracle_verification_attempt,
    build_stored_round,
    stored_round_id,
)
from ai.verification.oracle import (
    ORACLE_PATH_PREFIX,
    oracle_seed,
    oracle_value_from_seed,
    validate_oracle_pair,
)
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
    Stored XSS cases instead produce gated oracle rounds
    (``stored_submit`` + ``stored_read`` sharing a
    ``round_id``); use :func:`build_stored_round` for those.
    This helper mirrors the non-stored behaviour so the
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
        # Plain browser candidate for non-stored classes.
        # Stored XSS cases use gated oracle rounds built by
        # :func:`build_stored_round`, not mirrored here.
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
                phase="browser",
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


# Fixed round timestamps (READ strictly after SUBMIT).
_STORED_T0 = "2026-09-01T00:00:00+00:00"
_STORED_T1 = "2026-09-01T00:00:01+00:00"
_STORED_T2 = "2026-09-01T00:00:02+00:00"
_STORED_T3 = "2026-09-01T00:00:03+00:00"


def _stored_round_for(
    case, *, run_salt: str = "test-run-salt"
) -> tuple[VerificationAttempt, VerificationAttempt]:
    """Build one stored oracle round exactly as the verifier does."""

    built = build_stored_round(
        case=case,
        suggested_payload=PAYLOAD,
        payload_origin="knowledge",
        knowledge_ids=[KNOWLEDGE_ID],
        source_ids=[SOURCE_ID],
        based_on_pattern=PATTERN,
        run_salt=run_salt,
    )
    assert built is not None, (
        "fixture context must be planner-supported"
    )
    return built


def _stored_submit_evidence(
    submit: VerificationAttempt,
    *,
    status: int = 201,
    location: str | None = None,
    attempt_status: AttemptStatus = AttemptStatus.SUCCEEDED,
) -> VerificationEvidence:
    if location is None:
        location = _DEFAULT_ENDPOINT
    return VerificationEvidence(
        attempt_id=submit.attempt_id,
        attempt_status=attempt_status,
        request_url=submit.endpoint,
        request_method=submit.method,
        response_status=status
        if attempt_status == AttemptStatus.SUCCEEDED
        else None,
        location_header=location,
        object_hint=location,
        intended_request_url=submit.endpoint,
        actual_request_url=submit.endpoint,
        started_at=_STORED_T0,
        finished_at=_STORED_T1,
    )


def _stored_read_evidence(
    read: VerificationAttempt,
    url: str,
    *,
    dialogs: list | None = None,
    oracle_net: list | None = None,
    evals: list | None = None,
    dom: list | None = None,
) -> VerificationEvidence:
    return VerificationEvidence(
        attempt_id=read.attempt_id,
        attempt_status=AttemptStatus.SUCCEEDED,
        request_url=read.endpoint,
        request_method="GET",
        response_status=200,
        dialog_events=list(dialogs or []),
        oracle_network_events=list(oracle_net or []),
        eval_invocations=list(evals or []),
        browser=BrowserExecutionObservation(
            executed_script=bool(dialogs or oracle_net or evals),
            dom_changes=list(dom or []),
        ),
        intended_request_url=url,
        actual_request_url=url,
        started_at=_STORED_T2,
        finished_at=_STORED_T3,
    )


class _SaltedStoredExecutor:
    """Dynamic stored-round executor for production-builder tests.

    Answers a SUBMIT with acceptance (``Location`` == endpoint,
    so no READ rebuild is needed) and a READ with exact E1 proof
    of the attempt's own oracle value. Binding-safe by
    construction: every evidence field derives from the attempt
    it answers.
    """

    def __init__(self):
        self.calls: list[VerificationAttempt] = []

    def execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        self.calls.append(attempt)
        phase = (attempt.phase or "").strip().lower()
        if phase == STORED_SUBMIT_PHASE:
            return _stored_submit_evidence(attempt)
        if phase == STORED_READ_PHASE:
            return _stored_read_evidence(
                attempt,
                attempt.endpoint,
                dialogs=[
                    DialogEvent(
                        kind="alert",
                        message=attempt.oracle_value or "",
                    )
                ],
            )
        raise AssertionError(f"unexpected phase {phase!r}")


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
# Oracle fixtures
# ============================================================================

_TEST_RUN_SALT = "test-run-salt"


def _oracle_attempt_for(
    candidate: VerificationAttempt,
    *,
    case: XSSCase | None = None,
    run_salt: str = _TEST_RUN_SALT,
) -> VerificationAttempt:
    """Build the oracle attempt exactly as the verifier does."""
    case = case or _case()
    built = build_oracle_verification_attempt(
        case=case,
        candidate=candidate,
        run_salt=run_salt,
    )
    assert built is not None, (
        "fixture context must be planner-supported"
    )
    return built


def _short_oracle_attempt(
    candidate: VerificationAttempt,
    *,
    case: XSSCase | None = None,
    run_salt: str = _TEST_RUN_SALT,
    payload: str | None = None,
) -> VerificationAttempt:
    """An oracle attempt with a SHORT (<=240 char) planner-shaped
    payload so E3 (exact eval equality) can fire. The planner's real
    payloads exceed 240 chars and disable E3; this mirrors the same
    seed/value/identity contract with a short payload."""
    case = case or _case()
    seed = oracle_seed(run_salt, candidate.attempt_id, "oracle")
    value = oracle_value_from_seed(seed)
    if payload is None:
        payload = f"<script>var s='{seed}';</script>"
    assert len(payload) <= 240
    assert payload.count(seed) == 1
    assert value not in payload
    base = build_verification_attempt(
        case_id=case.case_id,
        endpoint=case.endpoint,
        method=case.method,
        parameter=case.parameter,
        parameter_location=case.parameter_location,
        payload=payload,
        payload_origin="model_generated",
        knowledge_ids=[],
        source_ids=[],
        based_on_pattern=candidate.based_on_pattern,
        mode=VerificationMode.BROWSER_EXECUTION,
        phase="oracle",
    )
    return base.model_copy(
        update={
            "logical_pair_id": candidate.logical_pair_id,
            "oracle_seed": seed,
            "oracle_value": value,
            "oracle_version": 1,
            "oracle_identity": candidate.attempt_id,
        }
    )


def _oracle_evidence(
    *,
    attempt: VerificationAttempt,
    dialog: bool = False,
    network: bool = False,
    eval_invoke: bool = False,
    wrong_value: str | None = None,
    intended_request_url: str | None = None,
    actual_request_url: str | None = None,
    dialog_events: list | None = None,
    oracle_network_events: list | None = None,
    eval_invocations: list | None = None,
    **kwargs,
) -> VerificationEvidence:
    """Well-bound browser evidence for an oracle attempt with
    executor-owned oracle events. Defaults to the endpoint origin
    so binding and same-origin checks pass. ``wrong_value`` injects
    a mismatched oracle value into the dialog/network events. The
    explicit ``*_events``/``*_invocations`` lists override the
    boolean shortcuts for negative-matrix construction."""
    value = wrong_value or attempt.oracle_value
    endpoint = attempt.endpoint
    if intended_request_url is None:
        intended_request_url = endpoint + "?q=probe"
    if actual_request_url is None:
        actual_request_url = intended_request_url
    base = _browser_evidence(
        attempt=attempt,
        executed_script=False,
        correlation_token_in_runtime=False,
        observed_correlation_token=None,
        request_url=endpoint,
        **kwargs,
    )
    parts = urlsplit(endpoint)
    origin = f"{parts.scheme}://{parts.netloc}"
    if dialog_events is None:
        dialog_events = (
            [DialogEvent(kind="alert", message=value)] if dialog else []
        )
    if oracle_network_events is None:
        oracle_network_events = (
            [
                NetworkOracleEvent(
                    url=origin + ORACLE_PATH_PREFIX + value,
                    path=ORACLE_PATH_PREFIX + value,
                )
            ]
            if network
            else []
        )
    if eval_invocations is None:
        eval_invocations = (
            [EvalInvocation(operator="eval", value=attempt.payload)]
            if eval_invoke
            else []
        )
    return base.model_copy(
        update={
            "dialog_events": dialog_events,
            "oracle_network_events": oracle_network_events,
            "eval_invocations": eval_invocations,
            "intended_request_url": intended_request_url,
            "actual_request_url": actual_request_url,
        }
    )


def _run_oracle_scenario(
    analysis: XSSAnalysisResult,
    plain_attempts: list[VerificationAttempt],
    oracle_attempt: VerificationAttempt,
    oracle_evidence: VerificationEvidence,
    *,
    http_evidence: VerificationEvidence | None = None,
    run_salt: str | None = _TEST_RUN_SALT,
    include_http: bool = True,
) -> XSSVerificationResult:
    """Drive a plan of [http?, browser, oracle] with canned
    evidence and return the verification result."""
    plan_attempts = list(plain_attempts)
    responses: list[VerificationEvidence] = []
    for attempt in plain_attempts:
        if attempt.mode == VerificationMode.HTTP_REFLECTION:
            if not include_http:
                continue
            responses.append(
                http_evidence
                if http_evidence is not None
                else _http_evidence(attempt=attempt)
            )
        else:
            responses.append(
                _browser_evidence(
                    attempt=attempt,
                    executed_script=False,
                    correlation_token_in_runtime=False,
                    observed_correlation_token=None,
                )
            )
    if not include_http:
        plan_attempts = [
            a
            for a in plain_attempts
            if a.mode != VerificationMode.HTTP_REFLECTION
        ]
    responses.append(oracle_evidence)
    return _verify_with_plan(
        analysis,
        attempts=[*plan_attempts, oracle_attempt],
        responses=responses,
        run_salt=run_salt,
    )


def _plan_with_oracle(
    analysis: XSSAnalysisResult,
    *,
    run_salt: str = _TEST_RUN_SALT,
) -> tuple[list[VerificationAttempt], list[VerificationAttempt]]:
    """Mirror of the verifier's plan construction with oracle
    attempts. Returns (attempts, oracle_attempts)."""

    attempts = _attempts_for_analysis(analysis)
    case = analysis.case
    oracle_attempts: list[VerificationAttempt] = []
    xss_type = (case.xss_type or "").strip().lower()
    if xss_type != "stored":
        for attempt in attempts:
            if (
                attempt.mode == VerificationMode.BROWSER_EXECUTION
                and attempt.phase != "stored"
            ):
                built = build_oracle_verification_attempt(
                    case=case,
                    candidate=attempt,
                    run_salt=run_salt,
                )
                if built is not None:
                    oracle_attempts.append(built)
    return attempts, oracle_attempts


def _verify_with_plan(
    analysis: XSSAnalysisResult,
    attempts: list[VerificationAttempt],
    responses: list[VerificationEvidence],
    *,
    run_salt: str | None = _TEST_RUN_SALT,
) -> XSSVerificationResult:
    verifier = XSSVerifier(_FakeExecutor(responses))
    if run_salt is not None:
        verifier = XSSVerifier(
            _FakeExecutor(responses), run_salt=run_salt
        )
    return verifier.verify(
        analysis, plan=VerificationPlan(attempts=attempts)
    )


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
# 2. Correlated browser execution → POTENTIAL (demoted); CONFIRMED
#    requires oracle execution proof
# ============================================================================
class XSSVerifierConfirmedTests(unittest.TestCase):
    def test_reflection_plus_correlated_browser_yields_potential(
        self,
    ):
        # MANDATED DEMOTION: browser chain/token/data-stage evidence
        # caps at POTENTIAL (SINK_REACHED). It is never execution
        # proof and never yields CONFIRMED.
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
        self.assertEqual(statuses, ["POTENTIAL", "POTENTIAL"])
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )
        browser_potential = next(
            f
            for f in result.findings
            if f.verification_mode == "browser_execution"
        )
        self.assertEqual(
            browser_potential.confirmation_state, "SINK_REACHED"
        )
        self.assertEqual(browser_potential.oracle_channels, [])

    def test_reflection_plus_oracle_e1_yields_confirmed(self):
        # Reflected: meaningful HTTP reflection AND valid oracle E1
        # execution proof => CONFIRMED (JAVASCRIPT_EXECUTION).
        analysis = _analysis()
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        self.assertEqual(len(oracle_attempts), 1)
        oracle_attempt = oracle_attempts[0]
        http_attempt = attempts[0]
        browser_attempt = attempts[1]

        responses = [
            _http_evidence(attempt=http_attempt),
            _browser_evidence(
                attempt=browser_attempt,
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempt, dialog=True),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        confirmed = confirmed[0]
        self.assertEqual(
            confirmed.confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(confirmed.oracle_channels, ["E1"])
        self.assertEqual(confirmed.attempt_id, oracle_attempt.attempt_id)
        self.assertEqual(confirmed.verification_mode, "browser_execution")


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
        # INCONCLUSIVE on an oracle-confirmed attempt.
        analysis = _analysis()
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        http_attempt = attempts[0]
        browser_attempt = attempts[1]
        oracle_attempt = oracle_attempts[0]

        responses = [
            _http_evidence(
                attempt=http_attempt,
                waf_observations=[
                    WAFObservation(
                        kind=WAFObservationKind.INFO,
                        note="strict CSP detected",
                    )
                ],
            ),
            _browser_evidence(
                attempt=browser_attempt,
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempt, dialog=True),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )

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

    def test_dom_complete_source_to_sink_yields_potential(self):
        # MANDATED DEMOTION: DOM chain + token without an oracle
        # execution proof is SINK_REACHED -> POTENTIAL, never
        # CONFIRMED.
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
        self.assertEqual(finding.status, "POTENTIAL")
        self.assertEqual(
            finding.confirmation_state, "SINK_REACHED"
        )
        self.assertEqual(finding.xss_type, "dom")

    def test_dom_oracle_e1_yields_confirmed(self):
        # DOM confirmation requires ONLY a valid oracle execution
        # proof (no HTTP pair). Source/sink evidence is advisory.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        self.assertEqual(len(oracle_attempts), 1)
        oracle_attempt = oracle_attempts[0]

        responses = [
            _browser_evidence(
                attempt=attempts[0],
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempt, dialog=True),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].xss_type, "dom")
        self.assertEqual(
            confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])

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
        # Stored round whose SUBMIT is rejected: the READ is
        # gated out (never executed) and nothing can confirm.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        submit, read = _stored_round_for(case)
        executor = _FakeExecutor(
            [
                _stored_submit_evidence(
                    submit,
                    status=500,
                    location=None,
                    attempt_status=AttemptStatus.FAILED,
                )
            ]
        )
        result = XSSVerifier(
            executor, run_salt="test-run-salt"
        ).verify(
            analysis,
            plan=VerificationPlan(attempts=[submit, read]),
        )

        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)
        self.assertNotIn("NOT_VULNERABLE", statuses)
        # Gating: only SUBMIT was executed, READ never ran.
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual(executor.calls[0].phase, STORED_SUBMIT_PHASE)

    def test_stored_xss_with_complete_round_trip_yields_confirmed(
        self,
    ):
        # Stored oracle round: accepted SUBMIT, clean READ, exact
        # E1 execution proof of the round's own D must yield
        # CONFIRMED (JAVASCRIPT_EXECUTION via E1).
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        submit, read = _stored_round_for(case)
        value = submit.oracle_value or ""
        read_evidence = _stored_read_evidence(
            read,
            _DEFAULT_ENDPOINT,
            dialogs=[DialogEvent(kind="alert", message=value)],
        )
        executor = _FakeExecutor(
            [
                _stored_submit_evidence(submit),
                read_evidence,
            ]
        )
        result = XSSVerifier(
            executor, run_salt="test-run-salt"
        ).verify(
            analysis,
            plan=VerificationPlan(attempts=[submit, read]),
        )

        statuses = [f.status for f in result.findings]
        self.assertIn("CONFIRMED", statuses)
        self.assertNotIn("NOT_VULNERABLE", statuses)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(
            confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])
        self.assertEqual(confirmed[0].round_id, submit.round_id)

    def test_stored_xss_mismatched_phase_tokens_yield_potential(
        self,
    ):
        # Stored round whose READ carries the wrong oracle value:
        # execution proof fails, so no CONFIRMED. The ceiling is
        # POTENTIAL only when a storage signal exists.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        submit, read = _stored_round_for(case)
        read_evidence = _stored_read_evidence(
            read,
            _DEFAULT_ENDPOINT,
            dialogs=[
                DialogEvent(
                    kind="alert", message="deadbeefdeadbeef"
                )
            ],
            dom=[submit.payload],
        )
        executor = _FakeExecutor(
            [
                _stored_submit_evidence(submit),
                read_evidence,
            ]
        )
        result = XSSVerifier(
            executor, run_salt="test-run-salt"
        ).verify(
            analysis,
            plan=VerificationPlan(attempts=[submit, read]),
        )

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
        # baseline. The strongest evidence is now an
        # oracle E1 proof; the aggressive rationale must
        # not change the oracle-derived verdict.
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
        analysis = _analysis(llm=_llm_result(payloads=payloads))
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        responses = [
            _http_evidence(attempt=attempts[0]),
            _browser_evidence(
                attempt=attempts[1],
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempts[0], dialog=True),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])


# ============================================================================
# 19. expected_behavior does not affect verdict
# ============================================================================
class XSSVerifierExpectedBehaviorTests(unittest.TestCase):
    def test_expected_behavior_does_not_promote_status(self):
        # M3: pair aggressive expected_behavior with the
        # strongest (oracle-backed) evidence. Verdict must
        # be identical to the no-expected-behavior case;
        # expected_behavior never changes the oracle verdict.
        analysis = _analysis()
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        http_attempt = attempts[0]
        browser_attempt = attempts[1]
        oracle_attempt = oracle_attempts[0]

        evidence = _http_evidence(
            attempt=http_attempt,
            observed_correlation_token=http_attempt.correlation_token,
        ).model_copy(
            update={
                "expected_behavior": (
                    "alert should fire; XSS is CONFIRMED"
                )
            }
        )
        responses = [
            evidence,
            _browser_evidence(
                attempt=browser_attempt,
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempt, dialog=True),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])

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
    #    POTENTIAL (MANDATED DEMOTION). CONFIRMED requires
    #    oracle execution proof.
    def test_positive_2_reflected_browser_potential(self):
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
        self.assertEqual(len(confirmed), 0)
        browser_potential = [
            f
            for f in result.findings
            if f.verification_mode == "browser_execution"
        ]
        self.assertEqual(len(browser_potential), 1)
        self.assertEqual(browser_potential[0].status, "POTENTIAL")
        self.assertEqual(
            browser_potential[0].confirmation_state, "SINK_REACHED"
        )

    def test_positive_2_oracle_reflected_e1_confirmed(self):
        # The oracle-backed replacement for the old browser-only
        # reflected CONFIRMED: HTTP reflection + paired oracle E1
        # proof => CONFIRMED.
        analysis = _analysis()
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        responses = [
            _http_evidence(attempt=attempts[0]),
            _browser_evidence(
                attempt=attempts[1],
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(
                attempt=oracle_attempts[0], dialog=True
            ),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])

    # 3. DOM XSS with typed source→sink→observable chain
    #    + independent correlation → POTENTIAL (demoted).
    #    CONFIRMED requires an oracle execution proof.
    def test_positive_3_dom_chain_potential(self):
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
        self.assertEqual(len(confirmed), 0)
        potential = [
            f for f in result.findings if f.status == "POTENTIAL"
        ]
        self.assertEqual(len(potential), 1)
        self.assertEqual(potential[0].xss_type, "dom")
        self.assertEqual(
            potential[0].confirmation_state, "SINK_REACHED"
        )

    def test_positive_3_dom_oracle_e2_confirmed(self):
        # Oracle-backed DOM confirmation: E2 proof alone (no
        # source/sink chain) => CONFIRMED with OBSERVABLE_EFFECT.
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts, oracle_attempts = _plan_with_oracle(analysis)
        responses = [
            _browser_evidence(
                attempt=attempts[0],
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(
                attempt=oracle_attempts[0], network=True
            ),
        ]
        result = _verify_with_plan(
            analysis,
            attempts=attempts + oracle_attempts,
            responses=responses,
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        confirmed = confirmed[0]
        self.assertEqual(confirmed.xss_type, "dom")
        self.assertEqual(confirmed.oracle_channels, ["E2"])
        self.assertEqual(
            confirmed.confirmation_state, "OBSERVABLE_EFFECT"
        )

    # 4. stored XSS with complete structured round trip
    #    + correlation → CONFIRMED.
    def test_positive_4_stored_round_trip_confirmed(self):
        # Stored oracle round through the production plan
        # builder: accepted SUBMIT + clean READ + exact E1 proof
        # of the round's own D yields exactly one CONFIRMED.
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        executor = _SaltedStoredExecutor()
        result = XSSVerifier(
            executor, run_salt="test-run-salt"
        ).verify(analysis)
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
            ["POTENTIAL", "POTENTIAL"],
        )
        # The demoted browser finding is SINK_REACHED.
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
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

    def test_dom_browser_only_yields_no_confirmed(self):
        # MANDATED DEMOTION: a DOM case with only the plain browser
        # attempt (chain + token, no oracle) yields POTENTIAL, never
        # CONFIRMED. CONFIRMED requires oracle execution proof.
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
        self.assertEqual(len(confirmed), 0)
        potential = [
            f for f in result.findings if f.status == "POTENTIAL"
        ]
        self.assertEqual(len(potential), 1)
        self.assertEqual(
            potential[0].confirmation_state, "SINK_REACHED"
        )

    def test_mutation_browser_only_yields_no_confirmed(self):
        # MANDATED DEMOTION (shared browser branch): mutation chain +
        # token without an oracle proof yields POTENTIAL. No
        # mutation-specific redesign is introduced.
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
        self.assertEqual(len(confirmed), 0)
        potential = [
            f for f in result.findings if f.status == "POTENTIAL"
        ]
        self.assertEqual(len(potential), 1)

    def test_reflected_paired_http_and_browser_yield_no_confirmed(
        self,
    ):
        # MANDATED DEMOTION: a correctly paired reflected pair with
        # strong chain/token evidence yields POTENTIAL for both
        # attempts, never CONFIRMED. CONFIRMED requires the oracle.
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
        self.assertEqual(len(confirmed), 0)
        statuses = sorted(f.status for f in result.findings)
        self.assertEqual(statuses, ["POTENTIAL", "POTENTIAL"])

    def test_reflected_paired_http_and_oracle_e2_yield_confirmed(self):
        # Reflected: HTTP reflection + paired oracle attempt with a
        # valid E2 proof => CONFIRMED (OBSERVABLE_EFFECT). The
        # plain-browser attempt is POTENTIAL.
        case = _case(xss_type="reflected")
        analysis = _analysis(case=case)
        http_attempt = self._http_attempt_for(case=case)
        browser_attempt = self._browser_attempt_for(case=case)
        oracle_attempt = _oracle_attempt_for(
            browser_attempt, case=case
        )
        self.assertEqual(
            oracle_attempt.logical_pair_id,
            http_attempt.logical_pair_id,
        )

        plan = VerificationPlan(
            attempts=[http_attempt, browser_attempt, oracle_attempt]
        )
        responses = [
            self._matching_http_evidence(http_attempt),
            _browser_evidence(
                attempt=browser_attempt,
                executed_script=False,
                correlation_token_in_runtime=False,
                observed_correlation_token=None,
            ),
            _oracle_evidence(attempt=oracle_attempt, network=True),
        ]
        result = _verify_with_plan(
            analysis, attempts=plan.attempts, responses=responses
        )

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        confirmed = confirmed[0]
        self.assertEqual(confirmed.attempt_id, oracle_attempt.attempt_id)
        self.assertEqual(confirmed.oracle_channels, ["E2"])
        self.assertEqual(
            confirmed.confirmation_state, "OBSERVABLE_EFFECT"
        )

    def test_stored_complete_round_trip_yields_confirmed(self):
        # Stored case: the plan holds a gated SUBMIT + READ round
        # sharing ``round_id``. Accepted SUBMIT, clean READ, and
        # exact E2 execution proof of the round's own D must
        # produce CONFIRMED (OBSERVABLE_EFFECT via E2).
        case = _case(xss_type="stored")
        analysis = _analysis(case=case)
        submit, read = _stored_round_for(case)
        # Sanity: distinct phases and attempt ids, one round.
        self.assertEqual(submit.phase, STORED_SUBMIT_PHASE)
        self.assertEqual(read.phase, STORED_READ_PHASE)
        self.assertNotEqual(submit.attempt_id, read.attempt_id)
        self.assertEqual(submit.round_id, read.round_id)

        value = submit.oracle_value or ""
        origin = "{0}://{1}".format(
            *urlsplit(_DEFAULT_ENDPOINT)[:2]
        )
        plan = VerificationPlan(attempts=[submit, read])
        executor = _FakeExecutor(
            [
                _stored_submit_evidence(submit),
                _stored_read_evidence(
                    read,
                    _DEFAULT_ENDPOINT,
                    oracle_net=[
                        NetworkOracleEvent(
                            url=(
                                f"{origin}/.watch-oracle/{value}"
                            ),
                            path=f"/.watch-oracle/{value}",
                            is_navigation=False,
                        )
                    ],
                ),
            ]
        )
        result = XSSVerifier(
            executor, run_salt="test-run-salt"
        ).verify(analysis, plan=plan)

        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertNotIn(
            "NOT_VULNERABLE", [f.status for f in result.findings]
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E2"])
        self.assertEqual(
            confirmed[0].confirmation_state, "OBSERVABLE_EFFECT"
        )

    def test_stored_attempt_identity_uses_final_phase(self):
        # The stored round's SUBMIT and READ attempts carry the
        # oracle identity of the SUBMIT-candidate derivation, a
        # shared run-salted round_id, and distinct phases from
        # the start (no post-hoc mutation).
        case = _case(xss_type="stored")
        submit, read = _stored_round_for(case)

        self.assertEqual(submit.phase, STORED_SUBMIT_PHASE)
        self.assertEqual(read.phase, STORED_READ_PHASE)
        self.assertIsNotNone(submit.oracle_identity)
        self.assertEqual(
            submit.oracle_identity, read.oracle_identity
        )
        self.assertEqual(
            submit.oracle_seed,
            oracle_seed(
                "test-run-salt",
                submit.oracle_identity or "",
                STORED_SUBMIT_PHASE,
            ),
        )
        self.assertEqual(
            submit.round_id,
            stored_round_id(
                "test-run-salt", submit.oracle_identity or ""
            ),
        )
        self.assertEqual(submit.payload, read.payload)
        self.assertIn(submit.oracle_seed or "x", submit.payload)
        self.assertNotIn(
            submit.oracle_value or "y", submit.payload
        )

        # And the production plan builder must emit the same
        # round shape for a stored case.
        analysis = _analysis(case=case)
        result = XSSVerifier(
            _SaltedStoredExecutor(), run_salt="test-run-salt"
        ).verify(analysis)
        phases = [a.phase for a in result.attempts]
        self.assertEqual(
            phases, [STORED_SUBMIT_PHASE, STORED_READ_PHASE]
        )
        produced_submit, produced_read = result.attempts
        self.assertEqual(
            produced_submit.round_id, produced_read.round_id
        )
        self.assertEqual(
            produced_submit.oracle_identity,
            produced_read.oracle_identity,
        )


# ============================================================================
# Oracle-integration matrix tests
# ============================================================================


class XSSVerifierOraclePlanTests(unittest.TestCase):
    """The plan builder must add oracle attempts when run_salt is
    configured and drop them (candidate stays POTENTIAL) when it is
    not, or when the context is unsupported."""

    def test_plan_builder_adds_oracle_attempt_when_salted(self):
        analysis = _analysis()
        # Executor returns ERROR evidence for every attempt so no
        # finding is produced; we inspect the plan shape.
        result = XSSVerifier(
            _FakeExecutor(), run_salt=_TEST_RUN_SALT
        ).verify(analysis)
        phases = [a.phase for a in result.attempts]
        self.assertEqual(phases, ["http", "browser", "oracle"])
        oracle = result.attempts[2]
        self.assertEqual(oracle.oracle_identity, result.attempts[1].attempt_id)
        self.assertEqual(
            oracle.logical_pair_id, result.attempts[1].logical_pair_id
        )
        self.assertEqual(
            oracle.oracle_value,
            oracle_value_from_seed(oracle.oracle_seed or ""),
        )

    def test_plan_builder_unsalted_has_no_oracle_attempt(self):
        # run_salt None: backward-compatible two-attempt plan.
        analysis = _analysis()
        result = XSSVerifier(_FakeExecutor()).verify(analysis)
        phases = [a.phase for a in result.attempts]
        self.assertEqual(phases, ["http", "browser"])
        self.assertTrue(
            all(a.oracle_value is None for a in result.attempts)
        )

    def test_plan_builder_dom_adds_oracle_attempt_when_salted(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        result = XSSVerifier(
            _FakeExecutor(), run_salt=_TEST_RUN_SALT
        ).verify(analysis)
        phases = [a.phase for a in result.attempts]
        self.assertEqual(phases, ["browser", "oracle"])

    def test_plan_builder_unsupported_context_keeps_candidate_potential(
        self,
    ):
        # unknown context => no oracle attempt; candidate remains in
        # the plan (plain browser + http).
        case = _case().model_copy(
            update={
                "context": XSSContext(type="unknown")
            }
        )
        analysis = _analysis(case=case)
        result = XSSVerifier(
            _FakeExecutor(), run_salt=_TEST_RUN_SALT
        ).verify(analysis)
        phases = [a.phase for a in result.attempts]
        self.assertEqual(phases, ["http", "browser"])


class XSSVerifierOracleReflectedMatrixTests(unittest.TestCase):
    """Reflected XSS oracle matrix (CONFIRMED requires S1 + S4)."""

    def _reflected(self):
        analysis = _analysis()
        plain, oracles = _plan_with_oracle(analysis)
        return analysis, plain, oracles[0]

    def test_E1_confirmed(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True))
        confirmed = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].oracle_channels, ["E1"])
        self.assertEqual(confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION")

    def test_E2_confirmed(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, network=True))
        confirmed = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].oracle_channels, ["E2"])
        self.assertEqual(confirmed[0].confirmation_state, "OBSERVABLE_EFFECT")

    def test_E3_confirmed(self):
        analysis, plain, _ = self._reflected()
        oracle = _short_oracle_attempt(plain[1])
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, eval_invoke=True))
        confirmed = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].oracle_channels, ["E3"])
        self.assertEqual(confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION")

    def test_E1_plus_E2_channels(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True, network=True))
        c = [f for f in result.findings if f.status == "CONFIRMED"][0]
        self.assertEqual(c.oracle_channels, ["E1", "E2"])
        self.assertEqual(c.confirmation_state, "OBSERVABLE_EFFECT")

    def test_wrong_d_rejected(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True, wrong_value="deadbeefdeadbeef"))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_d_in_intended_url_rejected(self):
        analysis, plain, oracle = self._reflected()
        intended = oracle.endpoint + "?" + (oracle.oracle_value or "")
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True, intended_request_url=intended))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_d_in_actual_url_rejected(self):
        analysis, plain, oracle = self._reflected()
        actual = oracle.endpoint + "?" + (oracle.oracle_value or "")
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True, actual_request_url=actual))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_stale_run_salt_rejected(self):
        analysis, plain, _ = self._reflected()
        oracle = _oracle_attempt_for(plain[1], run_salt="old-salt")
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True),
            run_salt="new-salt")
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_wrong_logical_pair_rejected(self):
        analysis, plain, oracle = self._reflected()
        oracle = oracle.model_copy(
            update={"logical_pair_id": "lp-other"})
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_wrong_oracle_identity_rejected(self):
        analysis, plain, oracle = self._reflected()
        oracle = oracle.model_copy(
            update={"oracle_identity": "va-wrong"})
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_cross_origin_final_url_rejected(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(
                attempt=oracle, dialog=True,
                actual_request_url="https://evil.example.test/x"))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_missing_http_pair_not_confirmed(self):
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True),
            include_http=False)
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_duplicate_oracle_attempt_per_pair_fails_closed(self):
        # Two oracle attempts for the SAME logical_pair_id is
        # ambiguous pairing. Only the registered oracle attempt is
        # eligible; the duplicate must fail closed, never confirm
        # via the other candidate's identity.
        analysis, plain, _ = self._reflected()
        candidate = plain[1]

        # Both oracle attempts share the same candidate/seed/pair
        # but have DIFFERENT payloads => distinct attempt_ids.
        seed = oracle_seed(_TEST_RUN_SALT, candidate.attempt_id, "oracle")
        value = oracle_value_from_seed(seed)
        first_payload = f"<script>var s='{seed}';x</script>"
        second_payload = f"<script>var s='{seed}';y</script>"
        first = _short_oracle_attempt(candidate, payload=first_payload)
        second = _short_oracle_attempt(candidate, payload=second_payload)
        self.assertNotEqual(first.attempt_id, second.attempt_id)
        self.assertEqual(first.logical_pair_id, second.logical_pair_id)
        # Both are valid oracle pairs (verified: seed/value match).
        validate_oracle_pair(first.oracle_seed or "", first.oracle_value or "")
        validate_oracle_pair(second.oracle_seed or "", second.oracle_value or "")

        plan_attempts = [plain[0], candidate, first, second]
        responses = [
            _http_evidence(attempt=plain[0]),
            _browser_evidence(attempt=candidate),
            _oracle_evidence(attempt=first, dialog=True),
            _oracle_evidence(attempt=second, dialog=True),
        ]
        result = _verify_with_plan(
            analysis, attempts=plan_attempts, responses=responses
        )
        # Only the FIRST registered oracle attempt may confirm; the
        # duplicate cannot produce a second CONFIRMED.
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].attempt_id, first.attempt_id)


class XSSVerifierOracleDOMatrixTests(unittest.TestCase):
    """DOM XSS oracle matrix (CONFIRMED = S4 only; no HTTP pair)."""

    def _dom(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        plain, oracles = _plan_with_oracle(analysis)
        return analysis, plain, oracles[0]

    def test_E1_confirmed(self):
        analysis, plain, oracle = self._dom()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True))
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].oracle_channels, ["E1"])

    def test_E2_confirmed(self):
        analysis, plain, oracle = self._dom()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, network=True))
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].oracle_channels, ["E2"])

    def test_E3_confirmed(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        plain, _ = _plan_with_oracle(analysis)
        oracle = _short_oracle_attempt(plain[0])
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, eval_invoke=True))
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].oracle_channels, ["E3"])

    def test_E2_without_chain_confirmed(self):
        analysis, plain, oracle = self._dom()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, network=True, source_to_sink=[]))
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].oracle_channels, ["E2"])
        self.assertEqual(c[0].xss_type, "dom")

    def test_browser_only_potential(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        attempts = _attempts_for_analysis(analysis)
        token = attempts[0].correlation_token
        executor = _FakeExecutor([
            _browser_evidence(
                attempt=attempts[0],
                executed_script=True,
                correlation_token_in_runtime=True,
                observed_correlation_token=token,
                network_requests=[f"https://x.test/{token}"],
                source_to_sink=_default_valid_chain(),
            )])
        result = XSSVerifier(executor).verify(analysis)
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])
        potential = [f for f in result.findings if f.status == "POTENTIAL"]
        self.assertEqual(len(potential), 1)
        self.assertEqual(potential[0].confirmation_state, "SINK_REACHED")

    def test_benign_echo_page_not_confirmed(self):
        # DOM with full token-in-every-channel but no oracle => POTENTIAL
        analysis, plain, oracle = self._dom()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=False, network=False, eval_invoke=False,
                             dom_changes=["token: ct-abc"],
                             console_messages=["token: ct-abc"],
                             network_requests=["https://x.test/ct-abc"],
                             storage_writes=["key=ct-abc"]))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_stale_run_rejected(self):
        analysis, plain, _ = self._dom()
        oracle = _oracle_attempt_for(plain[0], run_salt="old-salt")
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True),
            run_salt="new-salt")
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_d_preharvest_rejected(self):
        analysis, plain, oracle = self._dom()
        intended = oracle.endpoint + "?" + (oracle.oracle_value or "")
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True,
                             intended_request_url=intended))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])


class XSSVerifierOracleSecurityTests(unittest.TestCase):
    """Negative security matrix — verifier-level rejection checks."""

    def _reflected(self):
        analysis = _analysis()
        plain, oracles = _plan_with_oracle(analysis)
        return analysis, plain, oracles[0]

    def _dom(self):
        case = _case(xss_type="dom")
        analysis = _analysis(case=case)
        plain, oracles = _plan_with_oracle(analysis)
        return analysis, plain, oracles[0]

    def test_seed_copied_not_e1(self):
        # alert(seed) => message is 32-char hex (seed), not 16-char D
        analysis, plain, oracle = self._reflected()
        seed_dialog = [DialogEvent(kind="alert", message=oracle.oracle_seed or "")]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog_events=seed_dialog))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_d_in_generic_network_not_e2(self):
        # D in browser.network_requests but NOT in oracle_network_events
        analysis, plain, oracle = self._reflected()
        value = oracle.oracle_value or ""
        generic_url = oracle.endpoint + "/.watch-oracle/" + value
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=False, network=False,
                             network_requests=[generic_url]))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_E2_navigation_rejected(self):
        analysis, plain, oracle = self._reflected()
        parts = urlsplit(oracle.endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        value = oracle.oracle_value or ""
        bad = [NetworkOracleEvent(
            url=origin + ORACLE_PATH_PREFIX + value,
            path=ORACLE_PATH_PREFIX + value,
            is_navigation=True)]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, oracle_network_events=bad))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_E2_cross_origin_rejected(self):
        analysis, plain, oracle = self._reflected()
        value = oracle.oracle_value or ""
        bad = [NetworkOracleEvent(
            url="https://evil.example.test" + ORACLE_PATH_PREFIX + value,
            path=ORACLE_PATH_PREFIX + value)]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, oracle_network_events=bad))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_E2_path_suffix_rejected(self):
        analysis, plain, oracle = self._reflected()
        parts = urlsplit(oracle.endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        value = oracle.oracle_value or ""
        bad = [NetworkOracleEvent(
            url=origin + ORACLE_PATH_PREFIX + value + "/x",
            path=ORACLE_PATH_PREFIX + value + "/x")]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, oracle_network_events=bad))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_E2_double_encoded_rejected(self):
        # Double-encoded: %25DD => single decode gives %DD, not D
        analysis, plain, oracle = self._reflected()
        parts = urlsplit(oracle.endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        value = oracle.oracle_value or ""
        import urllib.parse
        double_encoded = origin + ORACLE_PATH_PREFIX + urllib.parse.quote("%" + format(ord(value[0]), "02x")) + value[1:]
        bad = [NetworkOracleEvent(url=double_encoded, path="/.watch-oracle/" + "%" + format(ord(value[0]), "02x") + value[1:])]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, oracle_network_events=bad))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_E3_payload_over_240_disabled(self):
        # Real planner payload (405 chars) with an eval record => E3 disabled
        analysis, plain, oracle = self._reflected()
        self.assertGreater(len(oracle.payload), 240)
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, eval_invoke=True))
        # Without E1/E2, no oracle channel fires
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        # E1/E2 not fired; E3 disabled => no confirmation
        self.assertEqual(len(c), 0)

    def test_E3_prefix_match_rejected(self):
        analysis, plain, _ = self._reflected()
        oracle = _short_oracle_attempt(plain[1])
        # A truncated PREFIX of the payload must NEVER satisfy the
        # exact-equality E3 predicate.
        prefix = oracle.payload[: len(oracle.payload) // 2]
        assert prefix != oracle.payload
        bad = [EvalInvocation(operator="eval", value=prefix)]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, eval_invocations=bad))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_duplicate_events_do_not_change_classification(self):
        analysis, plain, oracle = self._reflected()
        dup_dialog = [
            DialogEvent(kind="alert", message=oracle.oracle_value or ""),
            DialogEvent(kind="alert", message=oracle.oracle_value or ""),
        ]
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog_events=dup_dialog))
        c = [f for f in result.findings if f.status == "CONFIRMED"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].oracle_channels, ["E1"])

    def test_d_in_payload_rejected(self):
        # Hand-craft an oracle attempt whose payload contains D
        analysis, plain, _ = self._reflected()
        candidate = plain[1]
        run_salt = _TEST_RUN_SALT
        seed = oracle_seed(run_salt, candidate.attempt_id, "oracle")
        value = oracle_value_from_seed(seed)
        payload = f"<script>var s='{seed}';var d='{value}';</script>"
        base = build_verification_attempt(
            case_id=candidate.case_id,
            endpoint=candidate.endpoint,
            method=candidate.method,
            parameter=candidate.parameter,
            parameter_location=candidate.parameter_location,
            payload=payload,
            payload_origin="model_generated",
            knowledge_ids=[], source_ids=[],
            based_on_pattern=None,
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="oracle",
        )
        oracle = base.model_copy(update={
            "logical_pair_id": candidate.logical_pair_id,
            "oracle_seed": seed, "oracle_value": value,
            "oracle_version": 1, "oracle_identity": candidate.attempt_id,
        })
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=True))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])

    def test_d_in_console_not_oracle(self):
        # D in console_messages but no dialog_events => not E1
        analysis, plain, oracle = self._reflected()
        result = _run_oracle_scenario(
            analysis, plain, oracle,
            _oracle_evidence(attempt=oracle, dialog=False, network=False,
                             console_messages=[f"dialog:alert:{oracle.oracle_value or 'x'}"]))
        self.assertNotIn("CONFIRMED", [f.status for f in result.findings])


if __name__ == "__main__":
    unittest.main()

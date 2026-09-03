"""Stored XSS v1 oracle-round tests.

Covers the gated SUBMIT -> clean READ -> E1/E2/E3 flow through
``XSSVerifier.verify()``: positives (P1-P5), negatives (N1-N20),
security (S1-S14), failures (F1-F8), a localhost real-browser
integration test, and a production-composition regression test.

No external targets are touched; the only network use is
localhost in the real-browser test.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ai.schemas.xss import XSSCase, XSSContext
from ai.schemas.xss_verification import (
    AttemptStatus,
    BrowserExecutionObservation,
    DialogEvent,
    EvalInvocation,
    NetworkOracleEvent,
    ReflectionLocation,
    ReflectionObservation,
    StoredXSSPhase,
    StoredXSSPhaseObservation,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    VerificationPlan,
    WAFObservation,
    WAFObservationKind,
    build_verification_attempt,
)
from ai.verification.verifier import (
    STORED_READ_PHASE,
    STORED_SUBMIT_PHASE,
    XSSVerifier,
    build_stored_round,
    stored_round_id,
)
from ai.verification.oracle import (
    oracle_seed,
    oracle_value_from_seed,
)
from ai.researcher.xss_orchestrator import (
    XSSAnalysisAudit,
    XSSAnalysisResult,
)
from ai.schemas.xss import XSSResearchContext, XSSResearchLLMResult
from ai.schemas.xss import XSSSuggestedPayload


SALT = "stored-test-run-salt-001"
OTHER_SALT = "stored-test-run-salt-002"
BOARD = "https://target.example.test/board"
ITEM = "https://target.example.test/board/1"
EVIL = "https://evil.example.net/x"
SISTER = "https://www.target.example.test/board/1"

T0 = "2026-09-01T00:00:00+00:00"
T1 = "2026-09-01T00:00:01+00:00"
T2 = "2026-09-01T00:00:02+00:00"
T3 = "2026-09-01T00:00:03+00:00"


def _stored_case(
    *,
    context_type: str = "html_attribute",
    endpoint: str = BOARD,
    method: str = "POST",
    parameter: str = "comment",
    parameter_location: str = "body",
) -> XSSCase:
    return XSSCase(
        case_id="stored-case-1",
        target="https://target.example.test",
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        parameter_location=parameter_location,
        xss_type="stored",
        context=XSSContext(
            type=context_type,
            attribute_name="class",
            attribute_quoted=True,
        ),
        technology=["Example Framework"],
        waf=None,
        source_type="endpoint",
        created_at=T0,
        updated_at=T0,
    )


def _analysis_for(case: XSSCase, pattern: str = "<stored pattern>"):
    return XSSAnalysisResult(
        case=case,
        context=XSSResearchContext(
            case_id=case.case_id,
            retrieved_knowledge_ids=[],
            documents=[],
        ),
        llm_result=XSSResearchLLMResult(
            case_id=case.case_id,
            case_status_suggestion="ANALYZED",
            suggested_payloads=[
                XSSSuggestedPayload(
                    origin="knowledge",
                    knowledge_ids=["kb-1"],
                    source_ids=["src-1"],
                    based_on_pattern="stored-pattern",
                    rationale="test",
                    pattern=pattern,
                )
            ],
            verification_ideas=[],
            context_observations=[],
            next_research_questions=[],
            evidence=[],
        ),
        stage="ANALYZED",
        audit=XSSAnalysisAudit(
            retrieval_call_count=1,
            llm_call_count=1,
            retrieved_knowledge_ids=[],
            retrieval_had_results=True,
            had_payload_suggestions=True,
            had_verification_ideas=False,
            had_any_knowledge_derived_suggestion=True,
            had_any_model_generated_suggestion=False,
            llm_case_status_suggestion="ANALYZED",
            notes=[],
        ),
    )


def _round(case: XSSCase, salt: str = SALT):
    built = build_stored_round(
        case=case,
        suggested_payload="<stored pattern>",
        payload_origin="knowledge",
        knowledge_ids=["kb-1"],
        source_ids=["src-1"],
        based_on_pattern="stored-pattern",
        run_salt=salt,
    )
    assert built is not None, "fixture context must be supported"
    return built


def _submit_ev(
    submit: VerificationAttempt,
    *,
    status: int = 201,
    location: str | None = ITEM,
    object_hint: str | None = None,
    attempt_status: AttemptStatus = AttemptStatus.SUCCEEDED,
) -> VerificationEvidence:
    return VerificationEvidence(
        attempt_id=submit.attempt_id,
        attempt_status=attempt_status,
        request_url=submit.endpoint,
        request_method=submit.method,
        response_status=status
        if attempt_status == AttemptStatus.SUCCEEDED
        else None,
        location_header=location,
        object_hint=object_hint
        if object_hint is not None
        else location,
        intended_request_url=submit.endpoint,
        actual_request_url=submit.endpoint,
        started_at=T0,
        finished_at=T1,
    )


def _expected_read(
    read: VerificationAttempt, url: str
) -> VerificationAttempt:
    """Mirror the verifier's post-discovery READ rebuild."""

    rebuilt = build_verification_attempt(
        case_id=read.case_id,
        endpoint=url,
        method="GET",
        parameter=read.parameter,
        parameter_location=read.parameter_location,
        payload=read.payload,
        payload_origin="model_generated",
        knowledge_ids=[],
        source_ids=[],
        based_on_pattern=read.based_on_pattern,
        mode=VerificationMode.BROWSER_EXECUTION,
        phase=STORED_READ_PHASE,
    )
    return rebuilt.model_copy(
        update={
            "logical_pair_id": read.logical_pair_id,
            "oracle_seed": read.oracle_seed,
            "oracle_value": read.oracle_value,
            "oracle_version": read.oracle_version,
            "oracle_identity": read.oracle_identity,
            "round_id": read.round_id,
        }
    )


def _read_ev(
    read: VerificationAttempt,
    url: str,
    *,
    dialogs: list | None = None,
    oracle_net: list | None = None,
    evals: list | None = None,
    dom: list | None = None,
    console: list | None = None,
    network: list | None = None,
    storage: list | None = None,
    attempt_status: AttemptStatus = AttemptStatus.SUCCEEDED,
) -> VerificationEvidence:
    return VerificationEvidence(
        attempt_id=read.attempt_id,
        attempt_status=attempt_status,
        request_url=read.endpoint,
        request_method="GET",
        response_status=200
        if attempt_status == AttemptStatus.SUCCEEDED
        else None,
        dialog_events=list(dialogs or []),
        oracle_network_events=list(oracle_net or []),
        eval_invocations=list(evals or []),
        browser=BrowserExecutionObservation(
            executed_script=bool(dialogs or oracle_net or evals),
            dom_changes=list(dom or []),
            console_messages=list(console or []),
            network_requests=list(network or []),
            storage_writes=list(storage or []),
        ),
        intended_request_url=url,
        actual_request_url=url,
        started_at=T2,
        finished_at=T3,
    )


def _e1(read: VerificationAttempt):
    return DialogEvent(kind="alert", message=read.oracle_value or "")


def _e2(read: VerificationAttempt, url: str):
    value = read.oracle_value or ""
    origin = "{0}://{1}".format(*urlsplit(url)[:2])
    return NetworkOracleEvent(
        url=f"{origin}/.watch-oracle/{value}",
        path=f"/.watch-oracle/{value}",
        method="GET",
        resource_type="image",
        is_navigation=False,
    )


class _FakeExecutor:
    def __init__(self, responses):
        self._responses = list(responses)
        self._index = 0
        self.calls: list[VerificationAttempt] = []

    def execute(self, attempt):
        self.calls.append(attempt)
        if self._index >= len(self._responses):
            raise AssertionError("unexpected executor call")
        response = self._responses[self._index]
        self._index += 1
        if isinstance(response, Exception):
            raise response
        return response


def _verify(
    case: XSSCase,
    submit: VerificationAttempt,
    read: VerificationAttempt,
    responses,
    *,
    salt: str = SALT,
):
    executor = _FakeExecutor(responses)
    verifier = XSSVerifier(executor, run_salt=salt)
    plan = VerificationPlan(attempts=[submit, read])
    result = verifier.verify(_analysis_for(case), plan=plan)
    return result, executor


class StoredRoundShapeTests(unittest.TestCase):
    def test_round_has_distinct_attempt_ids_and_shared_round_id(self):
        case = _stored_case()
        submit, read = _round(case)
        self.assertNotEqual(submit.attempt_id, read.attempt_id)
        self.assertEqual(submit.phase, STORED_SUBMIT_PHASE)
        self.assertEqual(read.phase, STORED_READ_PHASE)
        self.assertIsNotNone(submit.round_id)
        self.assertEqual(submit.round_id, read.round_id)
        self.assertTrue(submit.round_id.startswith("sr-"))
        self.assertEqual(
            submit.round_id,
            stored_round_id(SALT, submit.oracle_identity or ""),
        )

    def test_oracle_identity_shared_and_seed_owned_by_submit(self):
        case = _stored_case()
        submit, read = _round(case)
        self.assertIsNotNone(submit.oracle_identity)
        self.assertEqual(
            submit.oracle_identity, read.oracle_identity
        )
        self.assertEqual(
            submit.oracle_seed,
            oracle_seed(
                SALT, submit.oracle_identity or "", STORED_SUBMIT_PHASE
            ),
        )
        self.assertEqual(submit.oracle_seed, read.oracle_seed)
        self.assertEqual(submit.oracle_value, read.oracle_value)
        self.assertEqual(
            read.oracle_value,
            oracle_value_from_seed(submit.oracle_seed or ""),
        )

    def test_payload_contains_seed_never_value(self):
        case = _stored_case()
        submit, read = _round(case)
        self.assertEqual(submit.payload, read.payload)
        self.assertIn(submit.oracle_seed or "x", submit.payload)
        self.assertNotIn(submit.oracle_value or "y", submit.payload)

    def test_unsupported_context_yields_no_round(self):
        case = _stored_case(context_type="url")
        built = build_stored_round(
            case=case,
            suggested_payload="<stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        self.assertIsNone(built)

    def test_round_ids_differ_per_candidate(self):
        case = _stored_case()
        first = _round(case)
        case2 = _stored_case()
        built = build_stored_round(
            case=case2,
            suggested_payload="<different stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        assert built is not None
        self.assertNotEqual(first[0].round_id, built[0].round_id)
        self.assertNotEqual(
            first[0].oracle_value, built[0].oracle_value
        )


class StoredPositiveTests(unittest.TestCase):
    def test_P1_submit_location_clean_read_e1_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        finding = confirmed[0]
        self.assertEqual(
            finding.confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(finding.oracle_channels, ["E1"])
        self.assertEqual(finding.round_id, submit.round_id)
        self.assertEqual(finding.read_url, ITEM)

    def test_P2_e2_confirmed_observable_effect(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, oracle_net=[_e2(rebuilt, ITEM)]),
            ],
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].confirmation_state, "OBSERVABLE_EFFECT"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E2"])

    def test_P3_e1_plus_e2_confirmed_both_channels(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    dialogs=[_e1(rebuilt)],
                    oracle_net=[_e2(rebuilt, ITEM)],
                ),
            ],
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].confirmation_state, "OBSERVABLE_EFFECT"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E1", "E2"])

    def test_P4_short_payload_e3_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        seed = submit.oracle_seed or ""
        short = f"<script>var s='{seed}';</script>"
        self.assertLessEqual(len(short), 240)
        submit_short = submit.model_copy(update={"payload": short})
        read_short = read.model_copy(update={"payload": short})
        rebuilt = _expected_read(read_short, ITEM)
        rebuilt = rebuilt.model_copy(update={"payload": short})
        result, _ = _verify(
            case,
            submit_short,
            read_short,
            [
                _submit_ev(submit_short),
                _read_ev(
                    rebuilt,
                    ITEM,
                    evals=[
                        EvalInvocation(operator="eval", value=short)
                    ],
                ),
            ],
        )
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].confirmation_state, "JAVASCRIPT_EXECUTION"
        )
        self.assertEqual(confirmed[0].oracle_channels, ["E3"])

    def test_P5_retry_fresh_round_confirms_old_d_rejected(self):
        case = _stored_case()
        first_submit, first_read = _round(case)
        # First round fails at SUBMIT.
        result, executor = _verify(
            case,
            first_submit,
            first_read,
            [
                _submit_ev(
                    first_submit,
                    status=500,
                    location=None,
                    attempt_status=AttemptStatus.FAILED,
                )
            ],
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )
        # Retry mints a fresh round (round_seq=1).
        built = build_stored_round(
            case=case,
            suggested_payload="<stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
            round_seq=1,
        )
        assert built is not None
        new_submit, new_read = built
        self.assertNotEqual(
            new_submit.round_id, first_submit.round_id
        )
        self.assertNotEqual(
            new_submit.oracle_value, first_submit.oracle_value
        )
        new_rebuilt = _expected_read(new_read, ITEM)
        # Old D replayed into the new round must not confirm.
        stale = _read_ev(
            new_rebuilt,
            ITEM,
            dialogs=[
                DialogEvent(
                    kind="alert",
                    message=first_submit.oracle_value or "",
                )
            ],
        )
        result, _ = _verify(
            case, new_submit, new_read, [_submit_ev(new_submit), stale]
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )
        # New D confirms.
        result, _ = _verify(
            case,
            new_submit,
            new_read,
            [
                _submit_ev(new_submit),
                _read_ev(
                    new_rebuilt, ITEM, dialogs=[_e1(new_rebuilt)]
                ),
            ],
        )
        self.assertIn(
            "CONFIRMED", [f.status for f in result.findings]
        )


class StoredNegativeTests(unittest.TestCase):
    def test_N1_stored_text_only_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dom=[submit.payload]),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N2_submit_reflection_only_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        submit_ev = _submit_ev(submit, location=None)
        submit_ev = submit_ev.model_copy(
            update={
                "reflection": ReflectionObservation(
                    reflected=True,
                    location=ReflectionLocation.HTML_ATTRIBUTE,
                    matched_correlation_token=True,
                    observed_correlation_token=(
                        submit.correlation_token
                    ),
                )
            }
        )
        rebuilt = _expected_read(read, BOARD)
        result, _ = _verify(
            case,
            submit,
            read,
            [submit_ev, _read_ev(rebuilt, BOARD)],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N3_preexisting_d_old_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        other = build_stored_round(
            case=_stored_case(),
            suggested_payload="<older stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        assert other is not None
        old_value = other[0].oracle_value or ""
        self.assertNotEqual(old_value, submit.oracle_value)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    dialogs=[
                        DialogEvent(kind="alert", message=old_value)
                    ],
                    oracle_net=[
                        NetworkOracleEvent(
                            url=(
                                "https://target.example.test/"
                                f".watch-oracle/{old_value}"
                            ),
                            path=f"/.watch-oracle/{old_value}",
                            is_navigation=False,
                        )
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N4_wrong_d_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    dialogs=[
                        DialogEvent(
                            kind="alert", message="deadbeefdeadbeef"
                        )
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N5_wrong_s_freshness_failure(self):
        case = _stored_case()
        submit, read = _round(case)
        tampered = read.model_copy(
            update={"oracle_seed": "f" * 32}
        )
        rebuilt = _expected_read(tampered, ITEM)
        result, _ = _verify(
            case,
            submit,
            tampered,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N6_wrong_round_id_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        other_read = read.model_copy(update={"round_id": "sr-other"})
        rebuilt = _expected_read(other_read, ITEM)
        result, _ = _verify(
            case,
            submit,
            other_read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N7_wrong_attempt_id_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        read_ev = _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)])
        read_ev = read_ev.model_copy(
            update={"attempt_id": "va-tampered"}
        )
        result, _ = _verify(
            case, submit, read, [_submit_ev(submit), read_ev]
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N8_old_run_salt_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case, salt=SALT)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
            salt=OTHER_SALT,
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N9_cross_candidate_evidence_not_confirmed(self):
        case = _stored_case()
        submit_a, _ = _round(case)
        built_b = build_stored_round(
            case=case,
            suggested_payload="<candidate b pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        assert built_b is not None
        _, read_b = built_b
        rebuilt_b = _expected_read(read_b, ITEM)
        # A's SUBMIT paired with B's READ must not confirm.
        result, _ = _verify(
            case,
            submit_a,
            read_b,
            [
                _submit_ev(submit_a),
                _read_ev(
                    rebuilt_b, ITEM, dialogs=[_e1(rebuilt_b)]
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N10_d_only_in_generic_network_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        value = submit.oracle_value or ""
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    network=[
                        f"https://target.example.test/log?m={value}"
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N11_d_only_in_console_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    console=[f"dialog:alert:{submit.oracle_value}"],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N12_d_only_in_dom_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt, ITEM, dom=[submit.oracle_value or ""]
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N13_token_everywhere_never_confirms(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        token = rebuilt.correlation_token
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    dom=[token],
                    console=[token],
                    network=[f"https://target.example.test/{token}"],
                    storage=[token],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N14_read_url_with_seed_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        polluted = f"{BOARD}?x={submit.oracle_seed}"
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=polluted)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N15_read_url_with_payload_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        polluted = f"{BOARD}?x={submit.payload[:64]}"
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=polluted)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N16_read_url_with_d_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        polluted = (
            f"https://target.example.test/.watch-oracle/"
            f"{submit.oracle_value}"
        )
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=polluted)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N17_cross_origin_read_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=EVIL)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N18_https_downgrade_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        downgrade = "http://target.example.test/board/1"
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=downgrade)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N19_legacy_phase_never_confirmed(self):
        case = _stored_case()
        analysis = _analysis_for(case)
        legacy = build_verification_attempt(
            case_id=case.case_id,
            endpoint=case.endpoint,
            method=case.method,
            parameter=case.parameter,
            parameter_location=case.parameter_location,
            payload="<stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="stored",
        )
        token = legacy.correlation_token
        executor = _FakeExecutor(
            [
                VerificationEvidence(
                    attempt_id=legacy.attempt_id,
                    attempt_status=AttemptStatus.SUCCEEDED,
                    request_url=legacy.endpoint,
                    request_method=legacy.method,
                    response_status=200,
                    browser=BrowserExecutionObservation(
                        executed_script=True,
                        correlation_token_in_runtime=True,
                        observed_correlation_token=token,
                        dom_changes=[token],
                        network_requests=[
                            f"https://target.example.test/{token}"
                        ],
                    ),
                    stored_phases=[
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.SUBMIT,
                            attempt_id=legacy.attempt_id,
                            observed_correlation_token=token,
                        ),
                        StoredXSSPhaseObservation(
                            phase=StoredXSSPhase.READ,
                            attempt_id=legacy.attempt_id,
                            observed_correlation_token=token,
                        ),
                    ],
                    started_at=T0,
                    finished_at=T1,
                )
            ]
        )
        result = XSSVerifier(executor, run_salt=SALT).verify(
            analysis, plan=VerificationPlan(attempts=[legacy])
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_N20_accepted_submit_silent_read_at_most_potential(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case, submit, read, [_submit_ev(submit), _read_ev(rebuilt, ITEM)]
        )
        statuses = [f.status for f in result.findings]
        self.assertNotIn("CONFIRMED", statuses)


class StoredSecurityTests(unittest.TestCase):
    def test_S1_interleaved_candidates_cannot_cross_confirm(self):
        case = _stored_case()
        submit_a, read_a = _round(case)
        built_b = build_stored_round(
            case=case,
            suggested_payload="<candidate b pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        assert built_b is not None
        submit_b, read_b = built_b
        rebuilt_a = _expected_read(read_a, ITEM)
        rebuilt_b = _expected_read(read_b, ITEM)
        executor = _FakeExecutor(
            [
                _submit_ev(submit_a),
                _read_ev(
                    rebuilt_a, ITEM, dialogs=[_e1(rebuilt_b)]
                ),
                _submit_ev(submit_b),
                _read_ev(
                    rebuilt_b, ITEM, dialogs=[_e1(rebuilt_b)]
                ),
            ]
        )
        verifier = XSSVerifier(executor, run_salt=SALT)
        plan = VerificationPlan(
            attempts=[submit_a, read_a, submit_b, read_b]
        )
        result = verifier.verify(_analysis_for(case), plan=plan)
        by_attempt = {f.attempt_id: f for f in result.findings}
        # A-READ with B's D must not confirm A.
        self.assertNotEqual(
            by_attempt.get(rebuilt_a.attempt_id, None) and
            by_attempt[rebuilt_a.attempt_id].status,
            "CONFIRMED",
        )
        # B-READ with B's D confirms B.
        self.assertEqual(
            by_attempt[rebuilt_b.attempt_id].status, "CONFIRMED"
        )

    def test_S2_previous_run_d_rejected(self):
        case = _stored_case()
        submit, read = _round(case, salt=SALT)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
            salt=OTHER_SALT,
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S3_previous_round_d_rejected(self):
        case = _stored_case()
        first, _ = _round(case)
        built = build_stored_round(
            case=case,
            suggested_payload="<stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
            round_seq=1,
        )
        assert built is not None
        new_submit, new_read = built
        new_rebuilt = _expected_read(new_read, ITEM)
        result, _ = _verify(
            case,
            new_submit,
            new_read,
            [
                _submit_ev(new_submit),
                _read_ev(
                    new_rebuilt,
                    ITEM,
                    dialogs=[
                        DialogEvent(
                            kind="alert",
                            message=first.oracle_value or "",
                        )
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S4_read_before_submit_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        read_ev = _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)])
        read_ev = read_ev.model_copy(
            update={"started_at": T0, "finished_at": T0}
        )
        result, _ = _verify(
            case, submit, read, [_submit_ev(submit), read_ev]
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S5_unrelated_origin_location_rejected(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case, submit, read, [_submit_ev(submit, location=EVIL)]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S5c_read_final_origin_must_match_endpoint_origin(self):
        # Intended and final READ URLs agree with each other but
        # point at an unrelated origin while the attempt endpoint
        # is the case endpoint: endpoint-origin parity rejects.
        # Location == endpoint, so no READ rebuild occurs and the
        # evidence binds; only step 5 can reject.
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, BOARD)
        self.assertEqual(rebuilt.attempt_id, read.attempt_id)
        read_ev = _read_ev(rebuilt, EVIL, dialogs=[_e1(rebuilt)])
        result, _ = _verify(
            case,
            submit,
            read,
            [_submit_ev(submit, location=BOARD), read_ev],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S5d_same_host_different_port_location_rejected(self):
        # Same registrable domain and host, different port: the
        # discovery fallback must not accept it as a READ target.
        case = _stored_case()
        submit, read = _round(case)
        other_port = "https://target.example.test:8443/board/1"
        result, executor = _verify(
            case,
            submit,
            read,
            [_submit_ev(submit, location=other_port)],
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )
        self.assertTrue(
            any(
                "read_location_unknown" in note
                for note in result.audit.notes
            )
        )

    def test_S5b_same_registrable_hint_accepted_as_hint_only(self):
        # www.target... shares eTLD+1 with the case endpoint, so
        # the hint is accepted as a navigation target — but the
        # verdict still depends entirely on the round's own D.
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, SISTER)
        result, executor = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit, location=SISTER),
                _read_ev(
                    rebuilt, SISTER, dialogs=[_e1(rebuilt)]
                ),
            ],
        )
        self.assertEqual(len(executor.calls), 2)
        self.assertIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S6_page_controlled_object_hint_ignored(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit, object_hint="sr-evil-round"),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ],
        )
        self.assertIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S7_seed_copy_into_beacon_not_e2(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        seed = submit.oracle_seed or ""
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    network=[
                        "https://target.example.test/beacon"
                        f"?x={seed}"
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S9_old_payload_e1_e2_wrong_d_no_confirmation(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        other = build_stored_round(
            case=_stored_case(),
            suggested_payload="<older stored pattern>",
            payload_origin="knowledge",
            knowledge_ids=["kb-1"],
            source_ids=["src-1"],
            based_on_pattern="stored-pattern",
            run_salt=SALT,
        )
        assert other is not None
        old_value = other[0].oracle_value or ""
        old_origin = "https://target.example.test"
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    dialogs=[
                        DialogEvent(kind="alert", message=old_value)
                    ],
                    oracle_net=[
                        NetworkOracleEvent(
                            url=(
                                f"{old_origin}/.watch-oracle/{old_value}"
                            ),
                            path=f"/.watch-oracle/{old_value}",
                            is_navigation=False,
                        )
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S10_plaintext_payload_no_confirmation(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dom=[submit.payload]),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S11_console_payload_no_confirmation(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt, ITEM, console=[submit.payload]
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S12_generic_network_payload_no_confirmation(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(submit),
                _read_ev(
                    rebuilt,
                    ITEM,
                    network=[
                        "https://target.example.test/c?"
                        f"x={submit.payload[:32]}"
                    ],
                ),
            ],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_S13_duplicate_read_fails_closed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        dup = rebuilt.model_copy(
            update={"endpoint": BOARD + "/2"}
        )
        executor = _FakeExecutor(
            [
                _submit_ev(submit),
                _read_ev(rebuilt, ITEM, dialogs=[_e1(rebuilt)]),
            ]
        )
        verifier = XSSVerifier(executor, run_salt=SALT)
        plan = VerificationPlan(attempts=[submit, read, dup])
        result = verifier.verify(_analysis_for(case), plan=plan)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertEqual(len(confirmed), 1)
        self.assertTrue(
            any("duplicate" in note for note in result.audit.notes)
        )

    def test_S14_unsupported_context_submits_nothing(self):
        case = _stored_case(context_type="url")
        analysis = _analysis_for(case)
        executor = _FakeExecutor([])
        result = XSSVerifier(executor, run_salt=SALT).verify(analysis)
        self.assertEqual(executor.calls, [])
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )


class StoredFailureTests(unittest.TestCase):
    def test_F1_submit_timeout_no_read(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case,
            submit,
            read,
            [
                VerificationEvidence(
                    attempt_id=submit.attempt_id,
                    attempt_status=AttemptStatus.TIMEOUT,
                    request_url=submit.endpoint,
                    request_method=submit.method,
                    error_reason="timeout",
                    started_at=T0,
                    finished_at=T1,
                )
            ],
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F2_submit_5xx_no_read(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case,
            submit,
            read,
            [
                _submit_ev(
                    submit,
                    status=500,
                    location=None,
                    attempt_status=AttemptStatus.FAILED,
                )
            ],
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F3_waf_block_no_read(self):
        case = _stored_case()
        submit, read = _round(case)
        submit_ev = _submit_ev(submit)
        submit_ev = submit_ev.model_copy(
            update={
                "attempt_status": AttemptStatus.WAF_BLOCKED,
                "waf_observations": [
                    WAFObservation(
                        kind=WAFObservationKind.BLOCK, note="403"
                    )
                ],
            }
        )
        result, executor = _verify(
            case, submit, read, [submit_ev]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F4_unsupported_submit_shape_no_read(self):
        case = _stored_case(
            method="DELETE", parameter_location="query"
        )
        submit, read = _round(case)
        from ai.verification.http_executor import (
            HTTPEvidenceExecutor,
        )

        executor = HTTPEvidenceExecutor(
            session=_DeadSession(), timeout=1, max_redirects=0
        )
        evidence = executor.execute(submit)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.ERROR
        )
        self.assertIn("unsupported_submit_shape", evidence.error_reason or "")

    def test_F5_unsupported_oracle_context_no_submit(self):
        case = _stored_case(context_type="url")
        analysis = _analysis_for(case)
        executor = _FakeExecutor([])
        result = XSSVerifier(executor, run_salt=SALT).verify(analysis)
        self.assertEqual(executor.calls, [])
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F6_browser_unavailable_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case,
            submit,
            read,
            [_submit_ev(submit), RuntimeError("no browser")],
        )
        self.assertEqual(len(executor.calls), 2)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F7_malformed_evidence_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case,
            submit,
            read,
            [_submit_ev(submit), {"not": "evidence"}],
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_F8_missing_oracle_events_not_confirmed(self):
        case = _stored_case()
        submit, read = _round(case)
        rebuilt = _expected_read(read, ITEM)
        result, _ = _verify(
            case, submit, read, [_submit_ev(submit), _read_ev(rebuilt, ITEM)]
        )
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )


class _DeadSession:
    def __init__(self):
        self.headers = {}

    def request(self, *args, **kwargs):
        raise AssertionError("network must not be touched")


class StoredAuthTests(unittest.TestCase):
    def test_auth_required_submit_fails_closed(self):
        case = _stored_case()
        submit, read = _round(case)
        result, executor = _verify(
            case,
            submit,
            read,
            [_submit_ev(submit, status=401, location=None)],
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_csrf_marked_submit_fails_closed(self):
        case = _stored_case()
        submit, read = _round(case)
        submit_ev = _submit_ev(submit)
        submit_ev = submit_ev.model_copy(
            update={
                "response_body_truncated": (
                    "<html>invalid csrf token, request rejected</html>"
                )
            }
        )
        result, executor = _verify(
            case, submit, read, [submit_ev]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )

    def test_csrf_field_name_is_not_failure(self):
        # A normal form carrying csrf_token / csrfmiddlewaretoken
        # fields and CSRF help text is NOT a CSRF failure: the
        # bare word "csrf" must not match.
        case = _stored_case()
        submit, _ = _round(case)
        submit_ev = _submit_ev(submit)
        submit_ev = submit_ev.model_copy(
            update={
                "response_body_truncated": (
                    '<form><input type="hidden" name="csrf_token" '
                    'value="abc123">'
                    '<input name="csrfmiddlewaretoken" value="xyz">'
                    "</form><p>CSRF protection enabled</p>"
                )
            }
        )
        verifier = XSSVerifier(_FakeExecutor([]), run_salt=SALT)
        accepted, signal = verifier._submit_accepted(
            submit_attempt=submit, submit_evidence=submit_ev
        )
        self.assertTrue(accepted)
        self.assertNotEqual(signal, "csrf_required")

    def test_explicit_csrf_failure_wording_rejected(self):
        # Explicit failure semantics still fail closed.
        case = _stored_case()
        submit, _ = _round(case)
        submit_ev = _submit_ev(submit)
        submit_ev = submit_ev.model_copy(
            update={
                "response_body_truncated": (
                    "<html>CSRF validation failed: missing csrf "
                    "token. Request rejected.</html>"
                )
            }
        )
        verifier = XSSVerifier(_FakeExecutor([]), run_salt=SALT)
        accepted, signal = verifier._submit_accepted(
            submit_attempt=submit, submit_evidence=submit_ev
        )
        self.assertFalse(accepted)
        self.assertEqual(signal, "csrf_required")

    def test_explicit_csrf_failure_no_read_no_confirm(self):
        case = _stored_case()
        submit, read = _round(case)
        submit_ev = _submit_ev(submit)
        submit_ev = submit_ev.model_copy(
            update={
                "response_body_truncated": (
                    "<html>CSRF validation failed: csrf token "
                    "invalid.</html>"
                )
            }
        )
        result, executor = _verify(
            case, submit, read, [submit_ev]
        )
        self.assertEqual(len(executor.calls), 1)
        self.assertNotIn(
            "CONFIRMED", [f.status for f in result.findings]
        )


class StoredProductionCompositionTests(unittest.TestCase):
    def test_default_verifier_forwards_run_salt_and_plans_round(self):
        from ai.verification.xss_pipeline import (
            build_default_verifier,
        )

        verifier = build_default_verifier(
            http_executor=_FakeExecutor([]),
            browser_executor=_FakeExecutor([]),
            run_salt=SALT,
        )
        self.assertEqual(verifier.run_salt, SALT)
        result = verifier.verify(_analysis_for(_stored_case()))
        self.assertTrue(
            any(
                a.phase == STORED_SUBMIT_PHASE
                for a in result.attempts
            )
        )
        self.assertTrue(
            any(
                a.phase == STORED_READ_PHASE
                for a in result.attempts
            )
        )

    def test_entrypoint_pipeline_mints_fresh_salt(self):
        try:
            import watch_xss_verify
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"entrypoint import unavailable: {exc}")
            return
        original = watch_xss_verify.build_orchestrator
        watch_xss_verify.build_orchestrator = lambda **kwargs: (
            _FakeOrchestrator()
        )
        try:
            first = watch_xss_verify.build_production_pipeline()
            second = watch_xss_verify.build_production_pipeline()
        finally:
            watch_xss_verify.build_orchestrator = original
        self.assertIsNotNone(first.verifier.run_salt)
        self.assertIsNotNone(second.verifier.run_salt)
        self.assertNotEqual(
            first.verifier.run_salt, second.verifier.run_salt
        )


class _FakeOrchestrator:
    def analyze(self, case):
        raise AssertionError("orchestrator must not run in this test")


class StoredLocalBrowserTests(unittest.TestCase):
    """Localhost end-to-end: real HTTP + real browser executors."""

    def test_localhost_submit_store_read_confirmed(self):
        try:
            from ai.verification.http_executor import (
                HTTPEvidenceExecutor,
            )
            from ai.verification.browser_executor import (
                BrowserEvidenceExecutor,
            )
            from ai.verification.composite_executor import (
                CompositeVerificationExecutor,
            )
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"executors unavailable: {exc}")
            return
        try:
            import playwright  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("playwright unavailable")
            return

        store: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(
                    self.headers.get("Content-Length", "0")
                )
                body = self.rfile.read(length).decode(
                    "utf-8", errors="replace"
                )
                values = parse_qs(body)
                store["comment"] = values.get("comment", [""])[0]
                payload = (
                    f"stored {len(store['comment'])} chars"
                )
                raw = payload.encode("utf-8")
                self.send_response(201)
                self.send_header("Location", "/item/0")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path.startswith("/.watch-oracle/"):
                    raw = b"ok"
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header(
                        "Content-Length", str(len(raw))
                    )
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path == "/item/0":
                    content = store.get("comment", "")
                    page = (
                        "<html><head><title>item</title></head>"
                        f"<body><div>{content}</div></body></html>"
                    )
                    raw = page.encode("utf-8")
                    self.send_response(200)
                    self.send_header(
                        "Content-Type", "text/html; charset=utf-8"
                    )
                    self.send_header(
                        "Content-Length", str(len(raw))
                    )
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                raw = b"not found"
                self.send_response(404)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(
            target=server.serve_forever, daemon=True
        )
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{port}/submit"
            case = _stored_case(
                endpoint=endpoint,
                method="POST",
                parameter="comment",
                parameter_location="body",
            )
            case = case.model_copy(
                update={"target": f"http://127.0.0.1:{port}"}
            )
            composite = CompositeVerificationExecutor(
                http_executor=HTTPEvidenceExecutor(),
                browser_executor=BrowserEvidenceExecutor(),
            )
            verifier = XSSVerifier(
                composite, run_salt="stored-localhost-salt"
            )
            result = verifier.verify(_analysis_for(case))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        statuses = [f.status for f in result.findings]
        self.assertIn("CONFIRMED", statuses)
        confirmed = [
            f for f in result.findings if f.status == "CONFIRMED"
        ]
        self.assertTrue(
            any(
                ch in ("E1", "E2")
                for f in confirmed
                for ch in f.oracle_channels
            )
        )


if __name__ == "__main__":
    unittest.main()

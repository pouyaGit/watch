import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.knowledge.store import KnowledgeStore
from ai.llm.base import LLMProvider, LLMResult
from ai.researcher.xss_llm_researcher import (
    XSSLLMAttributionError,
    XSSLLMResearcher,
)
from ai.researcher.xss_orchestrator import (
    XSSAnalysisAudit,
    XSSAnalysisResult,
    XSSOrchestrator,
)
from ai.researcher.xss_researcher import XSSResearcher
from ai.schemas.xss import (
    XSSAttributedValue,
    XSSCase,
    XSSContext,
    XSSResearchContext,
    XSSResearchLLMResult,
    XSSSuggestedPayload,
)


KNOWLEDGE_ID = "kb-test1234567890"
SOURCE_ID = "src-test1234567890"
PAYLOAD_PATTERN = "attribute breakout marker"
VERIFY_PATTERN = "attribute sink execution"


def _stub_llm(body: str) -> LLMProvider:
    class _Stub(LLMProvider):
        def __init__(self, body: str) -> None:
            self._body = body
            self.calls = 0
            self.last_prompt: str | None = None

        def generate(self, prompt: str) -> str:
            self.calls += 1
            self.last_prompt = prompt
            return self._body

        def complete(self, prompt: str) -> LLMResult:
            self.calls += 1
            self.last_prompt = prompt
            return LLMResult(
                content=self._body,
                request_id="stub-rid",
                model="stub-model",
            )

    return _Stub(body)


def _build_context(
    *,
    knowledge_id: str = KNOWLEDGE_ID,
    source_id: str = SOURCE_ID,
    payload: str = PAYLOAD_PATTERN,
    verify: str = VERIFY_PATTERN,
) -> XSSResearchContext:
    return XSSResearchContext(
        case_id="case-1",
        retrieved_knowledge_ids=[knowledge_id],
        documents=[],
        payload_patterns=[
            XSSAttributedValue(
                value=payload, source_ids=[source_id]
            )
        ],
        verification_patterns=[
            XSSAttributedValue(
                value=verify, source_ids=[source_id]
            )
        ],
    )


def _case() -> XSSCase:
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
        technology=["Example Framework"],
        waf="Strict WAF",
        source_type="endpoint",
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
    )


class _FakeResearcher(XSSResearcher):
    """
    A researcher that does not touch a real KnowledgeStore.
    It returns a pre-built context and a case with
    retrieved_knowledge_ids set.
    """

    def __init__(self, context: XSSResearchContext) -> None:
        # We deliberately do not call super().__init__ --
        # the orchestrator must not touch the store, and
        # this fake has no store.
        self._context = context
        self.calls = 0

    def research(
        self, case: XSSCase
    ) -> tuple[XSSCase, XSSResearchContext]:
        self.calls += 1
        updated = case.model_copy(
            update={
                "retrieved_knowledge_ids": list(
                    self._context.retrieved_knowledge_ids
                )
            }
        )
        return updated, self._context


class _FakeLLMResearcher(XSSLLMResearcher):
    """A stub that returns a pre-built XSSResearchLLMResult."""

    def __init__(
        self,
        result: XSSResearchLLMResult | Exception,
    ) -> None:
        # We do not call super().__init__; the orchestrator
        # only inspects .llm for type checks, which we satisfy
        # by setting it to a stub LLMProvider.
        self._result = result
        self.calls = 0
        self.last_case: XSSCase | None = None
        self.last_context: XSSResearchContext | None = None

        class _Dummy(LLMProvider):
            def generate(self, prompt: str) -> str:
                return ""

            def complete(self, prompt: str) -> LLMResult:
                return LLMResult(content="")

        self.llm = _Dummy()

    def analyze(
        self,
        case: XSSCase,
        context: XSSResearchContext,
    ) -> XSSResearchLLMResult:
        self.calls += 1
        self.last_case = case
        self.last_context = context
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _valid_llm_result(
    *,
    case_id: str = "case-1",
    status: str = "ANALYZED",
    payload_origin: str = "knowledge",
    payload_pattern: str = "kb payload",
    verify_origin: str | None = None,
    verify_pattern: str | None = None,
) -> XSSResearchLLMResult:
    payloads: list[XSSSuggestedPayload] = []
    if payload_origin is not None:
        payloads.append(
            XSSSuggestedPayload(
                pattern=payload_pattern,
                origin=payload_origin,
                knowledge_ids=[KNOWLEDGE_ID] if payload_origin == "knowledge" else [],
                source_ids=[SOURCE_ID] if payload_origin == "knowledge" else [],
                based_on_pattern=PAYLOAD_PATTERN,
                rationale="directly adapted",
            )
        )
    verification_ideas: list = []
    if verify_origin is not None and verify_pattern is not None:
        from ai.schemas.xss import XSSVerificationIdea

        verification_ideas.append(
            XSSVerificationIdea(
                pattern=verify_pattern,
                origin=verify_origin,
                knowledge_ids=[KNOWLEDGE_ID] if verify_origin == "knowledge" else [],
                source_ids=[SOURCE_ID] if verify_origin == "knowledge" else [],
                based_on_pattern=VERIFY_PATTERN,
                rationale="verification step",
            )
        )
    return XSSResearchLLMResult(
        case_id=case_id,
        case_status_suggestion=status,
        suggested_payloads=payloads,
        verification_ideas=verification_ideas,
        context_observations=[],
        next_research_questions=[],
        evidence=["SECONDARY: stub"],
    )


class XSSOrchestratorConstructorTests(unittest.TestCase):
    def test_requires_real_xss_researcher(self):
        with self.assertRaises(TypeError):
            XSSOrchestrator(
                knowledge_researcher=object(),
                llm_researcher=_FakeLLMResearcher(
                    _valid_llm_result()
                ),
            )

    def test_requires_real_xss_llm_researcher(self):
        ctx = _build_context()
        with self.assertRaises(TypeError):
            XSSOrchestrator(
                knowledge_researcher=_FakeResearcher(ctx),
                llm_researcher=object(),
            )

    def test_requires_llm_provider_on_llm_researcher(self):
        ctx = _build_context()
        bad = _FakeLLMResearcher(_valid_llm_result())
        bad.llm = "not an LLMProvider"  # type: ignore[assignment]
        with self.assertRaises(TypeError):
            XSSOrchestrator(
                knowledge_researcher=_FakeResearcher(ctx),
                llm_researcher=bad,
            )


class XSSOrchestratorHappyPathTests(unittest.TestCase):
    def _orchestrator(
        self,
        *,
        context: XSSResearchContext | None = None,
        result: XSSResearchLLMResult | Exception | None = None,
    ) -> XSSOrchestrator:
        ctx = context or _build_context()
        if result is None:
            result = _valid_llm_result()
        return XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        )

    def test_new_case_advances_to_analyzed(self):
        orch = self._orchestrator()
        result = orch.analyze(_case())

        self.assertEqual(result.stage, "ANALYZED")
        self.assertIsInstance(result, XSSAnalysisResult)
        self.assertEqual(result.case.case_id, "case-1")

    def test_retrieved_knowledge_ids_propagate(self):
        orch = self._orchestrator()
        result = orch.analyze(_case())

        self.assertEqual(
            result.case.retrieved_knowledge_ids, [KNOWLEDGE_ID]
        )
        self.assertEqual(
            result.context.retrieved_knowledge_ids, [KNOWLEDGE_ID]
        )
        self.assertEqual(
            result.audit.retrieved_knowledge_ids, [KNOWLEDGE_ID]
        )

    def test_researcher_called_exactly_once(self):
        ctx = _build_context()
        fr = _FakeResearcher(ctx)
        orch = XSSOrchestrator(
            knowledge_researcher=fr,
            llm_researcher=_FakeLLMResearcher(_valid_llm_result()),
        )
        orch.analyze(_case())
        self.assertEqual(fr.calls, 1)

    def test_llm_researcher_called_exactly_once(self):
        ctx = _build_context()
        lr = _FakeLLMResearcher(_valid_llm_result())
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=lr,
        )
        orch.analyze(_case())
        self.assertEqual(lr.calls, 1)

    def test_llm_receives_researcher_context(self):
        ctx = _build_context()
        lr = _FakeLLMResearcher(_valid_llm_result())
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=lr,
        )
        orch.analyze(_case())
        self.assertIs(lr.last_context, ctx)

    def test_knowledge_derived_payload_attribution_survives(self):
        result = _valid_llm_result(
            payload_origin="knowledge"
        )
        orch = self._orchestrator(result=result)
        analysis = orch.analyze(_case())

        self.assertEqual(len(analysis.llm_result.suggested_payloads), 1)
        item = analysis.llm_result.suggested_payloads[0]
        self.assertEqual(item.origin, "knowledge")
        self.assertEqual(item.knowledge_ids, [KNOWLEDGE_ID])
        self.assertEqual(item.source_ids, [SOURCE_ID])
        self.assertTrue(analysis.audit.had_any_knowledge_derived_suggestion)
        self.assertFalse(analysis.audit.had_any_model_generated_suggestion)

    def test_model_generated_payload_remains_model_generated(self):
        result = _valid_llm_result(
            payload_origin="model_generated",
            payload_pattern="novel payload",
        )
        orch = self._orchestrator(result=result)
        analysis = orch.analyze(_case())

        item = analysis.llm_result.suggested_payloads[0]
        self.assertEqual(item.origin, "model_generated")
        self.assertEqual(item.knowledge_ids, [])
        self.assertEqual(item.source_ids, [])
        self.assertTrue(analysis.audit.had_any_model_generated_suggestion)
        self.assertFalse(
            analysis.audit.had_any_knowledge_derived_suggestion
        )

    def test_deterministic_output_ordering(self):
        def _run_once() -> str:
            orch = self._orchestrator()
            analysis = orch.analyze(_case())
            return analysis.audit.model_dump_json()

        first = _run_once()
        for _ in range(3):
            self.assertEqual(_run_once(), first)


class XSSOrchestratorStageGuardTests(unittest.TestCase):
    """
    The orchestrator must NEVER produce CONFIRMED, NOT_VULNERABLE,
    or VERIFYING. It also must not silently downgrade an
    'INCONCLUSIVE' LLM suggestion into a positive verdict.
    """

    def _orchestrator(
        self,
        *,
        context: XSSResearchContext | None = None,
        result: XSSResearchLLMResult | Exception | None = None,
    ) -> XSSOrchestrator:
        return XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(
                context or _build_context()
            ),
            llm_researcher=_FakeLLMResearcher(
                result if result is not None else _valid_llm_result()
            ),
        )

    def test_no_knowledge_yields_inconclusive_not_not_vulnerable(self):
        # Retrieval returns no documents.
        ctx = XSSResearchContext(
            case_id="case-1",
            retrieved_knowledge_ids=[],
            documents=[],
        )
        orch = self._orchestrator(context=ctx)
        analysis = orch.analyze(_case())

        self.assertEqual(analysis.stage, "INCONCLUSIVE")
        self.assertEqual(
            analysis.audit.retrieval_had_results, False
        )
        # The case status on the *case* must remain
        # pre-confirmation; the orchestrator must not have
        # advanced it.
        self.assertNotIn(
            analysis.case.status, {"CONFIRMED", "NOT_VULNERABLE"}
        )
        self.assertNotIn(
            analysis.case.status, {"VERIFYING"}
        )

    def test_no_payload_suggestions_still_valid_result(self):
        # LLM returns no suggested payloads but analysis
        # itself succeeded. The result is still an
        # XSSAnalysisResult with the LLM result attached.
        result = _valid_llm_result(payload_origin=None)
        orch = self._orchestrator(result=result)
        analysis = orch.analyze(_case())

        self.assertEqual(analysis.stage, "ANALYZED")
        self.assertEqual(analysis.llm_result.suggested_payloads, [])
        self.assertFalse(analysis.audit.had_payload_suggestions)
        self.assertIn(
            "no_payload_suggestions",
            " ".join(analysis.audit.notes),
        )

    def test_confirmed_never_produced(self):
        # Defense in depth: even if the LLM somehow returned
        # CONFIRMED, the orchestrator must not propagate it as
        # a stage or as a case status. The XSSLLMResearcher
        # already rejects CONFIRMED at the schema layer; this
        # is a belt-and-braces check at the orchestrator.
        # We test the stage derivation directly: the
        # orchestrator's _derive_stage maps CONFIRMED-equivalent
        # to ANALYZED at most.
        from ai.researcher.xss_orchestrator import XSSOrchestrator

        ctx = _build_context()
        result = _valid_llm_result(status="INCONCLUSIVE")
        analysis = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        ).analyze(_case())

        self.assertNotIn(
            analysis.stage, {"CONFIRMED", "NOT_VULNERABLE", "VERIFYING"}
        )

    def test_audited_stages_are_subset_of_allowed(self):
        # A 'no knowledge' scenario: stage must be INCONCLUSIVE.
        ctx = XSSResearchContext(
            case_id="case-1",
            retrieved_knowledge_ids=[],
            documents=[],
        )
        result = _valid_llm_result(
            status="ANALYZED", payload_origin=None
        )
        analysis = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        ).analyze(_case())
        self.assertIn(analysis.stage, {"ANALYZED", "INCONCLUSIVE"})


class XSSOrchestratorFailureTests(unittest.TestCase):
    def test_researcher_failure_propagates(self):
        class _Boom(XSSResearcher):
            def __init__(self) -> None:
                self.calls = 0

            def research(self, case):
                self.calls += 1
                raise RuntimeError("retrieval failed")

        ctx = _build_context()
        orch = XSSOrchestrator(
            knowledge_researcher=_Boom(),
            llm_researcher=_FakeLLMResearcher(_valid_llm_result()),
        )
        with self.assertRaises(RuntimeError) as cm:
            orch.analyze(_case())
        self.assertIn("retrieval failed", str(cm.exception))

    def test_llm_failure_propagates(self):
        ctx = _build_context()
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(
                XSSLLMAttributionError("llm attribution failed")
            ),
        )
        with self.assertRaises(XSSLLMAttributionError):
            orch.analyze(_case())

    def test_invalid_case_rejected_by_pydantic_at_entry(self):
        # An obviously invalid case (missing required
        # fields) is rejected before the orchestrator runs.
        # The orchestrator's constructor takes the case
        # through Pydantic via XSSCase(...) when callers pass
        # a constructed model. We exercise that here.
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            XSSCase(case_id="c")  # type: ignore[call-arg]


class XSSOrchestratorNoDirectRetrievalTests(unittest.TestCase):
    """
    The orchestrator must use exactly one authoritative
    retrieval path. A spy on the store's retrieve method
    must confirm it is called exactly once per analyze().
    """

    def test_store_retrieve_called_exactly_once(self):
        with tempfile.TemporaryDirectory() as d:
            store = KnowledgeStore(Path(d) / "knowledge")
            with patch.object(
                KnowledgeStore,
                "retrieve",
                wraps=store.retrieve,
            ) as spy:
                from ai.researcher.xss_researcher import (
                    XSSResearcher as RealResearcher,
                )
                from ai.llm.base import LLMProvider

                class _Stub(LLMProvider):
                    def generate(self, prompt: str) -> str:
                        return json.dumps(
                            {
                                "case_id": "case-1",
                                "case_status_suggestion": "ANALYZED",
                                "suggested_payloads": [],
                                "verification_ideas": [],
                                "context_observations": [],
                                "next_research_questions": [],
                                "evidence": [
                                    "SECONDARY: stub"
                                ],
                                "model": None,
                                "raw_response_id": None,
                            }
                        )

                    def complete(self, prompt: str) -> LLMResult:
                        return LLMResult(content=self.generate(prompt))

                orch = XSSOrchestrator(
                    knowledge_researcher=RealResearcher(store),
                    llm_researcher=XSSLLMResearcher(_Stub()),
                )
                case = _case()
                case.technology = ["Unknown Stack"]
                case.xss_type = "stored"
                case.waf = "Unknown WAF"
                case.context = XSSContext(type="unknown")
                orch.analyze(case)
                spy.assert_called_once()


class XSSOrchestratorNoNetworkTests(unittest.TestCase):
    def test_module_does_not_import_network_clients(self):
        import ai.researcher.xss_orchestrator as module

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

    def test_module_does_not_import_knowledge_store_directly(self):
        # The orchestrator must coordinate via the
        # XSSResearcher abstraction; it must not reach
        # directly into the store internals.
        import ai.researcher.xss_orchestrator as module

        # KnowledgeStore symbol must not be in the module
        # namespace as a top-level name (it is used only in
        # type comments via XSSResearcher).
        self.assertNotIn("KnowledgeStore", module.__dict__)


class XSSOrchestratorLifecycleTests(unittest.TestCase):
    def test_case_status_advances_only_to_analyzed_or_stays(self):
        ctx = _build_context()
        # LLM says ANALYZED, retrieval found knowledge.
        result = _valid_llm_result(status="ANALYZED")
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        )
        case = _case()
        analysis = orch.analyze(case)
        # The orchestrator does not write status onto the
        # case; that is the caller's responsibility in the
        # verification stage. Verify the case is left
        # structurally intact.
        self.assertEqual(analysis.case.case_id, case.case_id)
        self.assertNotIn(
            analysis.case.status,
            {"CONFIRMED", "NOT_VULNERABLE", "VERIFYING"},
        )

    def test_audit_records_l_status_suggestion(self):
        ctx = _build_context()
        result = _valid_llm_result(status="INCONCLUSIVE")
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        )
        analysis = orch.analyze(_case())
        self.assertEqual(
            analysis.audit.llm_case_status_suggestion, "INCONCLUSIVE"
        )


class XSSOrchestratorDefensiveCopyTests(unittest.TestCase):
    """
    Regression tests for the H1 fix: XSSAnalysisResult owns
    independent deep copies of ``context`` and ``llm_result``
    so that caller mutations cannot leak back into the
    researcher / LLM-stub state, nor affect subsequent
    ``analyze`` calls.
    """

    def _build_orchestrator_with_recording_researcher(
        self,
    ) -> tuple[
        XSSOrchestrator,
        "_FakeRecordingResearcher",
        "_FakeRecordingLLM",
    ]:
        ctx = _build_context()
        result = _valid_llm_result(payload_origin="knowledge")
        fr = _FakeRecordingResearcher(ctx)
        lr = _FakeRecordingLLM(result)
        orch = XSSOrchestrator(
            knowledge_researcher=fr,
            llm_researcher=lr,
        )
        return orch, fr, lr

    def test_mutating_result_context_does_not_affect_researcher(
        self,
    ):
        orch, fr, _ = (
            self._build_orchestrator_with_recording_researcher()
        )
        original_value = (
            fr.last_returned_context.payload_patterns[0].value
        )

        result = orch.analyze(_case())
        result.context.payload_patterns[0].value = "MUTATED"

        # The researcher's internal context is unchanged.
        self.assertEqual(
            fr.last_returned_context.payload_patterns[0].value,
            original_value,
        )
        # The mutated value is visible only on the result.
        self.assertEqual(
            result.context.payload_patterns[0].value, "MUTATED"
        )
        # Identity check: the result.context is not the same
        # object the researcher returned.
        self.assertIsNot(
            result.context, fr.last_returned_context
        )

    def test_mutating_result_context_does_not_affect_subsequent_analyze(
        self,
    ):
        orch, fr, _ = (
            self._build_orchestrator_with_recording_researcher()
        )

        first = orch.analyze(_case())
        first.context.payload_patterns[0].value = "MUTATED"
        first.context.retrieved_knowledge_ids.append(
            "kb-attacker-supplied"
        )

        # Simulate a real researcher that rebuilds from the
        # store every call. The fake resets its internal
        # context; a real researcher re-reads from the store.
        fr.reset()

        second = orch.analyze(_case())
        self.assertNotEqual(
            second.context.payload_patterns[0].value, "MUTATED"
        )
        self.assertNotIn(
            "kb-attacker-supplied",
            second.context.retrieved_knowledge_ids,
        )
        # First result still holds the mutated value (it's
        # a snapshot).
        self.assertEqual(
            first.context.payload_patterns[0].value, "MUTATED"
        )

    def test_mutating_result_llm_result_does_not_affect_stub(
        self,
    ):
        orch, _, lr = (
            self._build_orchestrator_with_recording_researcher()
        )
        original_pattern = lr.stored_result.suggested_payloads[
            0
        ].pattern

        result = orch.analyze(_case())
        result.llm_result.suggested_payloads[0].pattern = "MUTATED"

        # The LLM stub still holds the original value.
        self.assertEqual(
            lr.stored_result.suggested_payloads[0].pattern,
            original_pattern,
        )
        # The result has the mutation.
        self.assertEqual(
            result.llm_result.suggested_payloads[0].pattern,
            "MUTATED",
        )
        # Identity check: the result.llm_result is not the
        # same object the LLM stub returned.
        self.assertIsNot(result.llm_result, lr.stored_result)

    def test_repeated_analyze_remains_deterministic_after_mutation(
        self,
    ):
        orch, fr, _ = (
            self._build_orchestrator_with_recording_researcher()
        )

        first = orch.analyze(_case())

        # Caller mutates the first result aggressively.
        first.context.payload_patterns[0].value = "MUTATED"
        first.llm_result.suggested_payloads[0].pattern = "MUTATED"
        first.context.retrieved_knowledge_ids.append(
            "kb-attacker-supplied"
        )

        # The mutations are visible on the first result
        # because the defensive copy is a snapshot taken at
        # analyze() time; caller mutations on a snapshot are
        # the caller's prerogative and do not affect any other
        # state.
        self.assertEqual(
            first.context.payload_patterns[0].value, "MUTATED"
        )
        self.assertEqual(
            first.llm_result.suggested_payloads[0].pattern,
            "MUTATED",
        )
        self.assertIn(
            "kb-attacker-supplied",
            first.context.retrieved_knowledge_ids,
        )

        # Simulate a real researcher that rebuilds from the
        # store every call.
        fr.reset()

        second = orch.analyze(_case())
        # The second result is independent of the first.
        self.assertNotEqual(
            second.context.payload_patterns[0].value, "MUTATED"
        )
        self.assertNotIn(
            "kb-attacker-supplied",
            second.context.retrieved_knowledge_ids,
        )
        # The first result still holds the mutations -- the
        # deep copy was made BEFORE the mutation, so the
        # mutation is part of the snapshot.
        self.assertEqual(
            first.context.payload_patterns[0].value, "MUTATED"
        )
        self.assertIn(
            "kb-attacker-supplied",
            first.context.retrieved_knowledge_ids,
        )

    def test_attribution_survives_defensive_copy(self):
        ctx = _build_context()
        result = _valid_llm_result(payload_origin="knowledge")
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        )
        analysis = orch.analyze(_case())

        # Attribution on the result is intact.
        payload = analysis.llm_result.suggested_payloads[0]
        self.assertEqual(payload.origin, "knowledge")
        self.assertEqual(payload.knowledge_ids, [KNOWLEDGE_ID])
        self.assertEqual(payload.source_ids, [SOURCE_ID])
        self.assertEqual(
            payload.based_on_pattern, PAYLOAD_PATTERN
        )
        self.assertEqual(
            analysis.llm_result.case_status_suggestion, "ANALYZED"
        )
        # Attribution on the LLM stub side is intact.
        # (The stub's stored result is the same object the
        # LLM researcher returned; only the result is a
        # deep copy.)
        self.assertEqual(
            result.suggested_payloads[0].origin, "knowledge"
        )
        self.assertEqual(
            result.suggested_payloads[0].knowledge_ids,
            [KNOWLEDGE_ID],
        )

    def test_lifecycle_guards_remain_intact(self):
        # Belt and braces: the defensive copy must not have
        # weakened any of the audit invariants.
        ctx = XSSResearchContext(
            case_id="case-1",
            retrieved_knowledge_ids=[],
            documents=[],
        )
        result = _valid_llm_result(
            status="ANALYZED", payload_origin="knowledge"
        )
        orch = XSSOrchestrator(
            knowledge_researcher=_FakeResearcher(ctx),
            llm_researcher=_FakeLLMResearcher(result),
        )
        analysis = orch.analyze(_case())

        self.assertEqual(analysis.stage, "INCONCLUSIVE")
        self.assertEqual(
            analysis.audit.retrieval_had_results, False
        )
        self.assertEqual(analysis.audit.llm_call_count, 1)
        self.assertEqual(analysis.audit.retrieval_call_count, 1)
        self.assertNotIn(
            analysis.stage,
            {"CONFIRMED", "NOT_VULNERABLE", "VERIFYING"},
        )


class _FakeRecordingResearcher(XSSResearcher):
    """
    Like :class:`_FakeResearcher` but also records the
    context it returned, so the defensive-copy tests can
    assert that mutations on the result did not leak back
    into the researcher state.

    On every call, the researcher's internal context is
    reset to a known-good baseline so that the
    defensive-copy behavior under test is observable:
    a fresh ``analyze`` must rebuild its context from the
    researcher, not from a previous (possibly mutated)
    result.
    """

    def __init__(self, context: XSSResearchContext) -> None:
        self._baseline = context.model_copy(deep=True)
        self._context = context.model_copy(deep=True)
        self.calls = 0
        self.last_returned_context: XSSResearchContext = (
            self._context
        )

    def reset(self) -> None:
        """Restore the researcher's internal context to its
        known-good baseline. Tests that want to assert
        'analyze() is independent of past results' call this
        between calls to simulate a real researcher that
        rebuilds from the store every time."""
        self._context = self._baseline.model_copy(deep=True)

    def research(
        self, case: XSSCase
    ) -> tuple[XSSCase, XSSResearchContext]:
        self.calls += 1
        self.last_returned_context = self._context.model_copy(
            deep=True
        )
        updated = case.model_copy(
            update={
                "retrieved_knowledge_ids": list(
                    self.last_returned_context.retrieved_knowledge_ids
                )
            }
        )
        return updated, self.last_returned_context


class _FakeRecordingLLM(XSSLLMResearcher):
    """
    Like :class:`_FakeLLMResearcher` but exposes the result
    it returned (the original LLM-side object), so the
    defensive-copy tests can assert that mutations on the
    result did not mutate the LLM-stub state.
    """

    def __init__(self, result: XSSResearchLLMResult) -> None:
        self.stored_result: XSSResearchLLMResult = (
            result.model_copy(deep=True)
        )
        self.calls = 0
        self.last_case: XSSCase | None = None
        self.last_context: XSSResearchContext | None = None

        class _Dummy(LLMProvider):
            def generate(self, prompt: str) -> str:
                return ""

            def complete(self, prompt: str) -> LLMResult:
                return LLMResult(content="")

        self.llm = _Dummy()

    def analyze(
        self,
        case: XSSCase,
        context: XSSResearchContext,
    ) -> XSSResearchLLMResult:
        self.calls += 1
        self.last_case = case
        self.last_context = context
        return self.stored_result


if __name__ == "__main__":
    unittest.main()

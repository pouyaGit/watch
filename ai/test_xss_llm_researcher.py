import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.knowledge.store import KnowledgeStore
from ai.llm.base import LLMProvider
from ai.researcher.xss_llm_researcher import (
    XSSLLMAttributionError,
    XSSLLMResearcher,
)
from ai.researcher.xss_researcher import XSSResearcher
from ai.schemas.knowledge import KnowledgeDocument
from ai.schemas.xss import XSSCase, XSSContext


FIXTURE_DIR = (
    Path(__file__).parent
    / "tests"
    / "fixtures"
    / "knowledge"
)


KNOWLEDGE_ID = "kb-5d8a7d783ec1e92d"
SOURCE_ID = "src-c565fa0194443d16"
PAYLOAD_PATTERN = "attribute breakout marker"
VERIFY_PATTERN = "attribute sink execution"


def _load_fixture(name: str) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        json.loads(
            (FIXTURE_DIR / name).read_text(
                encoding="utf-8"
            )
        )
    )


def _make_case() -> XSSCase:
    return XSSCase(
        case_id="case-1",
        target="https://target.example.test",
        endpoint="https://target.example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        input_value="marker",
        xss_type="reflected",
        context=XSSContext(
            type="html_attribute",
            attribute_name="class",
            attribute_quoted=True,
        ),
        framework=None,
        technology=["Example Framework"],
        waf="Strict WAF",
        source_type="endpoint",
        discovery_evidence=["observed reflection"],
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
    )


def _build_context():
    temp_dir = tempfile.TemporaryDirectory()
    store = KnowledgeStore(
        Path(temp_dir.name) / "knowledge"
    )
    store.ingest(
        _load_fixture("attribute_quoted_writeup.json")
    )
    researcher = XSSResearcher(store)
    case = _make_case()
    _updated, context = researcher.research(case)
    return temp_dir, case, context


class StubLLM(LLMProvider):
    """LLMProvider that returns a configured response verbatim."""

    def __init__(self, response: str) -> None:
        self._response = response
        self.call_count = 0
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> str:
        self.call_count += 1
        self.last_prompt = prompt
        return self._response


class MetadataStubLLM(LLMProvider):
    """
    LLMProvider stub that returns a configurable LLMResult so
    provider-side metadata can be injected into the XSS LLM
    researcher's output.
    """

    def __init__(
        self,
        content: str,
        *,
        request_id: str | None = "or-stub-id",
        model: str | None = "minimax/minimax-m3:free",
    ) -> None:
        self._content = content
        self._request_id = request_id
        self._model = model
        self.call_count = 0

    def generate(self, prompt: str) -> str:
        self.call_count += 1
        return self._content

    def complete(self, prompt: str):
        from ai.llm.base import LLMResult

        self.call_count += 1
        return LLMResult(
            content=self._content,
            request_id=self._request_id,
            model=self._model,
        )


class XSSLLMResearcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx_resources = _build_context()
        cls._temp_dir, cls.case, cls.context = (
            cls._ctx_resources
        )

    @classmethod
    def tearDownClass(cls):
        cls._ctx_resources[0].cleanup()

    def _make_researcher(self, response: str) -> XSSLLMResearcher:
        return XSSLLMResearcher(StubLLM(response))

    def _valid_knowledge_payload(self) -> dict:
        return {
            "pattern": "kb-derived payload",
            "origin": "knowledge",
            "knowledge_ids": [KNOWLEDGE_ID],
            "source_ids": [SOURCE_ID],
            "based_on_pattern": PAYLOAD_PATTERN,
            "rationale": "directly adapted from supplied pattern",
        }

    def _valid_knowledge_verification(self) -> dict:
        return {
            "pattern": "kb-derived verification",
            "origin": "knowledge",
            "knowledge_ids": [KNOWLEDGE_ID],
            "source_ids": [SOURCE_ID],
            "based_on_pattern": VERIFY_PATTERN,
            "rationale": "matches supplied verification pattern",
        }

    def _valid_response(self) -> dict:
        return {
            "case_id": self.case.case_id,
            "case_status_suggestion": "ANALYZED",
            "suggested_payloads": [
                self._valid_knowledge_payload()
            ],
            "verification_ideas": [
                self._valid_knowledge_verification()
            ],
            "context_observations": [],
            "next_research_questions": ["probe sink"],
            "evidence": [
                "SECONDARY: knowledge base supports attribute breakout"
            ],
            "model": "stub",
            "raw_response_id": "stub-1",
        }

    # ---- 1. Valid knowledge-derived payload accepted. ----
    def test_valid_knowledge_derived_payload_accepted(
        self,
    ):
        payload = self._valid_response()
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(len(result.suggested_payloads), 1)
        item = result.suggested_payloads[0]
        self.assertEqual(item.origin, "knowledge")
        self.assertEqual(item.knowledge_ids, [KNOWLEDGE_ID])
        self.assertEqual(item.source_ids, [SOURCE_ID])
        self.assertEqual(item.based_on_pattern, PAYLOAD_PATTERN)

    # ---- 2. Valid knowledge-derived verification accepted. ----
    def test_valid_knowledge_derived_verification_accepted(
        self,
    ):
        payload = self._valid_response()
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(len(result.verification_ideas), 1)
        item = result.verification_ideas[0]
        self.assertEqual(item.origin, "knowledge")
        self.assertEqual(item.based_on_pattern, VERIFY_PATTERN)

    # ---- 3. model_generated payload accepted. ----
    def test_model_generated_payload_accepted_with_empty_attribution(
        self,
    ):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            {
                "pattern": "novel payload idea",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": None,
                "rationale": (
                    "extends supplied context with a new idea"
                ),
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        result = researcher.analyze(self.case, self.context)

        item = result.suggested_payloads[0]
        self.assertEqual(item.origin, "model_generated")
        self.assertEqual(item.knowledge_ids, [])
        self.assertEqual(item.source_ids, [])
        self.assertIsNone(item.based_on_pattern)

    # ---- 4. Mixed knowledge / model_generated results. ----
    def test_mixed_origins_preserve_tags(self):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            self._valid_knowledge_payload(),
            {
                "pattern": "novel payload idea",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": None,
                "rationale": "novel",
            },
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        result = researcher.analyze(self.case, self.context)

        origins = [
            item.origin
            for item in result.suggested_payloads
        ]
        self.assertEqual(
            origins, ["knowledge", "model_generated"]
        )

    # ---- 5. Unknown knowledge_id rejected. ----
    def test_unknown_knowledge_id_rejected(self):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            {
                "pattern": "kb-derived payload",
                "origin": "knowledge",
                "knowledge_ids": ["kb-deadbeefdeadbeef"],
                "source_ids": [SOURCE_ID],
                "based_on_pattern": PAYLOAD_PATTERN,
                "rationale": "bogus",
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 6. Unknown source_id rejected. ----
    def test_unknown_source_id_rejected(self):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            {
                "pattern": "kb-derived payload",
                "origin": "knowledge",
                "knowledge_ids": [KNOWLEDGE_ID],
                "source_ids": ["src-deadbeefdeadbeef"],
                "based_on_pattern": PAYLOAD_PATTERN,
                "rationale": "bogus",
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 7. Invalid based_on_pattern rejected. ----
    def test_invalid_based_on_pattern_rejected(self):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            {
                "pattern": "kb-derived payload",
                "origin": "knowledge",
                "knowledge_ids": [KNOWLEDGE_ID],
                "source_ids": [SOURCE_ID],
                "based_on_pattern": "nonexistent pattern",
                "rationale": "bogus",
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 8. CONFIRMED status rejected. ----
    def test_confirmed_status_rejected(self):
        payload = self._valid_response()
        payload["case_status_suggestion"] = "CONFIRMED"
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 9. NOT_VULNERABLE status rejected. ----
    def test_not_vulnerable_status_rejected(self):
        payload = self._valid_response()
        payload["case_status_suggestion"] = "NOT_VULNERABLE"
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 10. Malformed JSON rejected. ----
    def test_malformed_json_rejected(self):
        researcher = self._make_researcher(
            "this is not json at all"
        )

        with self.assertRaises(ValueError):
            researcher.analyze(self.case, self.context)

    # ---- 11. Wrong Pydantic shape rejected. ----
    def test_wrong_pydantic_shape_rejected(self):
        bad = {
            "case_id": self.case.case_id,
            # case_status_suggestion missing entirely
            "suggested_payloads": [],
        }
        researcher = self._make_researcher(json.dumps(bad))

        with self.assertRaises(Exception):
            researcher.analyze(self.case, self.context)

    # ---- 12. LLM called exactly once. ----
    def test_llm_called_exactly_once(self):
        stub = StubLLM(json.dumps(self._valid_response()))
        researcher = XSSLLMResearcher(stub)

        researcher.analyze(self.case, self.context)
        researcher.analyze(self.case, self.context)

        self.assertEqual(stub.call_count, 2)

    # ---- 13. Same stub response is byte-equivalent. ----
    def test_same_stub_response_byte_equivalent(self):
        body = json.dumps(self._valid_response())

        researcher_a = self._make_researcher(body)
        researcher_b = self._make_researcher(body)

        result_a = researcher_a.analyze(self.case, self.context)
        result_b = researcher_b.analyze(self.case, self.context)

        self.assertEqual(
            result_a.model_dump(mode="json"),
            result_b.model_dump(mode="json"),
        )

    # ---- 14. case_id mismatch rejected. ----
    def test_case_id_mismatch_rejected(self):
        payload = self._valid_response()
        payload["case_id"] = "different-case-id"
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- 15. model_generated never gets injected attribution. ----
    def test_model_generated_never_gets_injected_attribution(
        self,
    ):
        payload = self._valid_response()
        payload["suggested_payloads"] = [
            {
                "pattern": "novel payload idea",
                "origin": "model_generated",
                "knowledge_ids": [KNOWLEDGE_ID],
                "source_ids": [SOURCE_ID],
                "based_on_pattern": None,
                "rationale": "claims to be model_generated but carries ids",
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- Evidence prefix enforcement. ----
    def test_evidence_prefix_required(self):
        payload = self._valid_response()
        payload["evidence"] = ["no prefix here"]
        researcher = self._make_researcher(
            json.dumps(payload)
        )

        with self.assertRaises(XSSLLMAttributionError):
            researcher.analyze(self.case, self.context)

    # ---- No network / no retrieval / no store access. ----
    def test_module_does_not_import_io_modules(self):
        import ai.researcher.xss_llm_researcher as module

        forbidden = {
            "requests",
            "urllib",
            "urllib3",
            "httpx",
            "openai",
            "KnowledgeStore",
            "XSSResearcher",
        }
        self.assertTrue(
            forbidden.isdisjoint(module.__dict__)
        )

    def test_module_does_not_call_llm_more_than_once(
        self,
    ):
        stub = StubLLM(json.dumps(self._valid_response()))
        researcher = XSSLLMResearcher(stub)

        researcher.analyze(self.case, self.context)

        self.assertEqual(stub.call_count, 1)


def _build_multi_context():
    """Build a context that retrieves three knowledge documents."""
    temp_dir = tempfile.TemporaryDirectory()
    store = KnowledgeStore(
        Path(temp_dir.name) / "knowledge"
    )
    store.ingest(
        _load_fixture("attribute_quoted_writeup.json")
    )
    store.ingest(_load_fixture("dom_writeup.json"))
    store.ingest(_load_fixture("reflected_writeup.json"))

    researcher = XSSResearcher(store)
    case = XSSCase(
        case_id="case-multi",
        target="https://target.example.test",
        endpoint="https://target.example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        xss_type="",
        context=XSSContext(type=""),
        technology=[],
        waf="",
        source_type="endpoint",
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
    )
    _updated, context = researcher.research(case)

    source_ids_by_kid: dict[str, list[str]] = {}
    for document in context.documents:
        source_ids_by_kid[document.knowledge_id] = sorted(
            provenance.source_id
            for provenance in document.provenance
            if provenance.source_id is not None
        )

    source_id_by_kid: dict[str, str] = {
        kid: sids[0]
        for kid, sids in source_ids_by_kid.items()
        if sids
    }

    return (
        temp_dir,
        case,
        context,
        source_ids_by_kid,
        source_id_by_kid,
    )


class XSSLLMResearcherMultiKnowledgeTests(unittest.TestCase):
    """
    Attribution edge cases where one item references more than
    one knowledge document. The LLM result schema carries flat
    knowledge_ids + source_ids, so the attribution check must
    accept any source_id that belongs to at least one of the
    referenced knowledge_ids.
    """

    @classmethod
    def setUpClass(cls):
        cls._ctx_resources = _build_multi_context()
        (
            cls._temp_dir,
            cls.case,
            cls.context,
            cls.source_ids_by_kid,
            cls.source_id_by_kid,
        ) = cls._ctx_resources

    @classmethod
    def tearDownClass(cls):
        cls._ctx_resources[0].cleanup()

    def _researcher(self, response: str) -> XSSLLMResearcher:
        return XSSLLMResearcher(StubLLM(response))

    def _base_response(self) -> dict:
        return {
            "case_id": self.case.case_id,
            "case_status_suggestion": "ANALYZED",
            "suggested_payloads": [],
            "verification_ideas": [],
            "context_observations": [],
            "next_research_questions": [],
            "evidence": ["UNKNOWN: multi-knowledge attribution test"],
            "model": "stub",
            "raw_response_id": "stub-multi",
        }

    def _pick_payload_pattern(self) -> str:
        for item in self.context.payload_patterns:
            return item.value
        return ""

    def test_single_knowledge_single_source_accepted(self):
        kid = next(iter(self.source_id_by_kid))
        sid = self.source_id_by_kid[kid]
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "single-kb payload",
                "origin": "knowledge",
                "knowledge_ids": [kid],
                "source_ids": [sid],
                "based_on_pattern": self._pick_payload_pattern(),
                "rationale": "single knowledge single source",
            }
        ]

        result = self._researcher(
            json.dumps(response)
        ).analyze(self.case, self.context)

        self.assertEqual(
            result.suggested_payloads[0].knowledge_ids, [kid]
        )
        self.assertEqual(
            result.suggested_payloads[0].source_ids, [sid]
        )

    def test_multi_knowledge_both_sources_accepted(self):
        kids = list(self.source_id_by_kid.keys())
        first_kid, second_kid = kids[0], kids[1]
        first_sid = self.source_id_by_kid[first_kid]
        second_sid = self.source_id_by_kid[second_kid]
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "multi-kb payload",
                "origin": "knowledge",
                "knowledge_ids": [first_kid, second_kid],
                "source_ids": [first_sid, second_sid],
                "based_on_pattern": self._pick_payload_pattern(),
                "rationale": "multi knowledge both sources",
            }
        ]

        result = self._researcher(
            json.dumps(response)
        ).analyze(self.case, self.context)

        self.assertEqual(
            sorted(
                result.suggested_payloads[0].knowledge_ids
            ),
            sorted([first_kid, second_kid]),
        )
        self.assertEqual(
            sorted(
                result.suggested_payloads[0].source_ids
            ),
            sorted([first_sid, second_sid]),
        )

    def test_multi_knowledge_subset_of_sources_accepted(self):
        kids = list(self.source_id_by_kid.keys())
        first_kid, second_kid = kids[0], kids[1]
        first_sid = self.source_id_by_kid[first_kid]
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "multi-kb subset payload",
                "origin": "knowledge",
                "knowledge_ids": [first_kid, second_kid],
                "source_ids": [first_sid],
                "based_on_pattern": self._pick_payload_pattern(),
                "rationale": (
                    "every source_id is attributable to at "
                    "least one referenced knowledge_id"
                ),
            }
        ]

        result = self._researcher(
            json.dumps(response)
        ).analyze(self.case, self.context)

        self.assertEqual(
            sorted(
                result.suggested_payloads[0].knowledge_ids
            ),
            sorted([first_kid, second_kid]),
        )
        self.assertEqual(
            result.suggested_payloads[0].source_ids, [first_sid]
        )

    def test_source_belonging_to_no_referenced_kid_rejected(
        self,
    ):
        kids = list(self.source_id_by_kid.keys())
        first_kid = kids[0]
        second_kid = kids[1]
        second_sid = self.source_id_by_kid[second_kid]
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "mismatched attribution",
                "origin": "knowledge",
                "knowledge_ids": [first_kid],
                "source_ids": [second_sid],
                "based_on_pattern": self._pick_payload_pattern(),
                "rationale": (
                    "source_id is not in the referenced "
                    "knowledge document"
                ),
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            self._researcher(
                json.dumps(response)
            ).analyze(self.case, self.context)

    def test_unknown_knowledge_id_among_valid_rejected(self):
        kids = list(self.source_id_by_kid.keys())
        first_kid = kids[0]
        first_sid = self.source_id_by_kid[first_kid]
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "unknown mixed in",
                "origin": "knowledge",
                "knowledge_ids": [
                    first_kid,
                    "kb-deadbeefdeadbeef",
                ],
                "source_ids": [first_sid],
                "based_on_pattern": self._pick_payload_pattern(),
                "rationale": "unknown kid mixed with valid",
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            self._researcher(
                json.dumps(response)
            ).analyze(self.case, self.context)


class XSSLLMResearcherMetadataPropagationTests(unittest.TestCase):
    """
    Provider metadata (model, request id) must reach
    :class:`XSSResearchLLMResult` even when the model's own
    JSON attempts to override those values.
    """

    @classmethod
    def setUpClass(cls):
        cls._ctx_resources = _build_context()
        cls._temp_dir, cls.case, cls.context = (
            cls._ctx_resources
        )

    @classmethod
    def tearDownClass(cls):
        cls._ctx_resources[0].cleanup()

    def _valid_response(self, **overrides) -> dict:
        payload = {
            "case_id": self.case.case_id,
            "case_status_suggestion": "ANALYZED",
            "suggested_payloads": [],
            "verification_ideas": [],
            "context_observations": [],
            "next_research_questions": [],
            "evidence": [
                "SECONDARY: metadata propagation test"
            ],
            "model": None,
            "raw_response_id": None,
        }
        payload.update(overrides)
        return payload

    def _make_researcher(
        self,
        body: str,
        *,
        provider_request_id: str | None = "or-prov-123",
        provider_model: str | None = "minimax/minimax-m3:free",
    ) -> XSSLLMResearcher:
        provider = MetadataStubLLM(
            body,
            request_id=provider_request_id,
            model=provider_model,
        )
        return XSSLLMResearcher(provider)

    def test_provider_model_reaches_result(self):
        response = self._valid_response()
        researcher = self._make_researcher(
            json.dumps(response),
            provider_model="minimax/minimax-m3:free",
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(result.model, "minimax/minimax-m3:free")

    def test_provider_request_id_reaches_result(self):
        response = self._valid_response()
        researcher = self._make_researcher(
            json.dumps(response),
            provider_request_id="or-prov-abc",
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(
            result.raw_response_id, "or-prov-abc"
        )

    def test_model_self_reporting_cannot_override_provider(
        self,
    ):
        response = self._valid_response(
            model="self-reported/model",
            raw_response_id="self-reported-id",
        )
        researcher = self._make_researcher(
            json.dumps(response),
            provider_model="provider/model",
            provider_request_id="provider-id",
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(result.model, "provider/model")
        self.assertEqual(
            result.raw_response_id, "provider-id"
        )
        self.assertNotEqual(result.model, "self-reported/model")
        self.assertNotEqual(
            result.raw_response_id, "self-reported-id"
        )

    def test_missing_provider_metadata_results_in_none(self):
        response = self._valid_response()
        researcher = self._make_researcher(
            json.dumps(response),
            provider_request_id=None,
            provider_model=None,
        )

        result = researcher.analyze(self.case, self.context)

        self.assertIsNone(result.model)
        self.assertIsNone(result.raw_response_id)

    def test_existing_attribution_validation_unchanged(self):
        payload = self._valid_response()
        kid = self.context.retrieved_knowledge_ids[0]
        sid = self.context.payload_patterns[0].source_ids[0]
        payload["suggested_payloads"] = [
            {
                "pattern": "kb payload",
                "origin": "knowledge",
                "knowledge_ids": [kid],
                "source_ids": [sid],
                "based_on_pattern": (
                    self.context.payload_patterns[0].value
                ),
                "rationale": "directly adapted",
            }
        ]
        researcher = self._make_researcher(
            json.dumps(payload),
            provider_model="provider/model",
            provider_request_id="provider-id",
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(
            result.suggested_payloads[0].origin, "knowledge"
        )
        self.assertEqual(
            result.suggested_payloads[0].knowledge_ids, [kid]
        )
        self.assertEqual(result.model, "provider/model")
        self.assertEqual(
            result.raw_response_id, "provider-id"
        )

    def test_json_parsing_unchanged(self):
        body = (
            "```json\n"
            + json.dumps(self._valid_response())
            + "\n```"
        )
        researcher = self._make_researcher(
            body,
            provider_model="provider/model",
            provider_request_id="provider-id",
        )

        result = researcher.analyze(self.case, self.context)

        self.assertEqual(result.case_id, self.case.case_id)
        self.assertEqual(
            result.case_status_suggestion, "ANALYZED"
        )
        self.assertEqual(result.model, "provider/model")
        self.assertEqual(
            result.raw_response_id, "provider-id"
        )


class XSSLLMResearcherBasedOnPatternTests(unittest.TestCase):
    """
    Regression tests for audit finding C2: the
    ``based_on_pattern`` field on a model_generated or
    knowledge suggestion must anchor to the *corresponding*
    list only.

    For ``suggested_payloads`` the anchor must be a payload
    pattern. For ``verification_ideas`` it must be a
    verification pattern. A context, technology, or WAF
    observation must NOT satisfy ``based_on_pattern``.
    """

    @classmethod
    def setUpClass(cls):
        cls._ctx_resources = _build_context()
        cls._temp_dir, cls.case, cls.context = (
            cls._ctx_resources
        )

    @classmethod
    def tearDownClass(cls):
        cls._ctx_resources[0].cleanup()

    def _base_response(self) -> dict:
        return {
            "case_id": self.case.case_id,
            "case_status_suggestion": "ANALYZED",
            "suggested_payloads": [],
            "verification_ideas": [],
            "context_observations": [],
            "next_research_questions": [],
            "evidence": ["UNKNOWN: based_on_pattern test"],
            "model": None,
            "raw_response_id": None,
        }

    def test_model_generated_payload_anchored_to_payload_pattern(
        self,
    ):
        payload_value = self.context.payload_patterns[0].value
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "novel payload",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": payload_value,
                "rationale": "anchored to a real payload pattern",
            }
        ]

        result = XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
            self.case, self.context
        )

        self.assertEqual(
            result.suggested_payloads[0].based_on_pattern,
            payload_value,
        )

    def test_model_generated_payload_anchored_to_context_rejected(
        self,
    ):
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "novel payload",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": "html_attribute",
                "rationale": (
                    "anchored to a context label, not a payload"
                ),
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
                self.case, self.context
            )

    def test_model_generated_payload_anchored_to_technology_rejected(
        self,
    ):
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "novel payload",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": "Example Framework",
                "rationale": "anchored to a technology label",
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
                self.case, self.context
            )

    def test_model_generated_payload_anchored_to_waf_rejected(
        self,
    ):
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "novel payload",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": "Strict WAF",
                "rationale": "anchored to a WAF label",
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
                self.case, self.context
            )

    def test_model_generated_verification_anchored_to_verification_pattern(
        self,
    ):
        verify_value = self.context.verification_patterns[0].value
        response = self._base_response()
        response["verification_ideas"] = [
            {
                "pattern": "novel verification",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": verify_value,
                "rationale": "anchored to a real verification pattern",
            }
        ]

        result = XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
            self.case, self.context
        )

        self.assertEqual(
            result.verification_ideas[0].based_on_pattern,
            verify_value,
        )

    def test_model_generated_verification_anchored_to_payload_pattern_rejected(
        self,
    ):
        # A verification idea anchored to a *payload* pattern
        # (the wrong list) must be rejected.
        payload_value = self.context.payload_patterns[0].value
        response = self._base_response()
        response["verification_ideas"] = [
            {
                "pattern": "novel verification",
                "origin": "model_generated",
                "knowledge_ids": [],
                "source_ids": [],
                "based_on_pattern": payload_value,
                "rationale": "wrong list anchor",
            }
        ]

        with self.assertRaises(XSSLLMAttributionError):
            XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
                self.case, self.context
            )

    def test_knowledge_attribution_rules_remain_intact(self):
        # A knowledge-derived payload still requires
        # knowledge_ids and source_ids, and a based_on_pattern
        # that anchors to a payload pattern.
        kid = self.context.retrieved_knowledge_ids[0]
        sid = self.context.payload_patterns[0].source_ids[0]
        payload_value = self.context.payload_patterns[0].value
        response = self._base_response()
        response["suggested_payloads"] = [
            {
                "pattern": "kb payload",
                "origin": "knowledge",
                "knowledge_ids": [kid],
                "source_ids": [sid],
                "based_on_pattern": payload_value,
                "rationale": "directly anchored",
            }
        ]

        result = XSSLLMResearcher(StubLLM(json.dumps(response))).analyze(
            self.case, self.context
        )

        self.assertEqual(
            result.suggested_payloads[0].origin, "knowledge"
        )
        self.assertEqual(
            result.suggested_payloads[0].knowledge_ids, [kid]
        )
        self.assertEqual(
            result.suggested_payloads[0].source_ids, [sid]
        )
        self.assertEqual(
            result.suggested_payloads[0].based_on_pattern,
            payload_value,
        )

        # A knowledge-derived payload with no source_ids
        # must still be rejected (no semantic relaxation).
        response2 = self._base_response()
        response2["suggested_payloads"] = [
            {
                "pattern": "kb payload",
                "origin": "knowledge",
                "knowledge_ids": [kid],
                "source_ids": [],
                "based_on_pattern": payload_value,
                "rationale": "missing source_ids",
            }
        ]
        with self.assertRaises(XSSLLMAttributionError):
            XSSLLMResearcher(StubLLM(json.dumps(response2))).analyze(
                self.case, self.context
            )


if __name__ == "__main__":
    unittest.main()

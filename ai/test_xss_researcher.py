import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.knowledge.store import KnowledgeStore, source_id
from ai.researcher.xss_researcher import XSSResearcher
from ai.schemas.xss import XSSCase, XSSContext


FIXTURE_DIR = (
    Path(__file__).parent
    / "tests"
    / "fixtures"
    / "knowledge"
)


def _load_fixture(name: str):
    from ai.schemas.knowledge import KnowledgeDocument

    return KnowledgeDocument.model_validate(
        json.loads(
            (FIXTURE_DIR / name).read_text(
                encoding="utf-8"
            )
        )
    )


def _make_case(**overrides) -> XSSCase:
    base = dict(
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
    )
    base.update(overrides)
    return XSSCase(**base)


class XSSResearcherTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = KnowledgeStore(
            Path(self.temp_dir.name) / "knowledge"
        )
        self.researcher = XSSResearcher(self.store)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _ingest(self, *names: str) -> None:
        for name in names:
            self.store.ingest(_load_fixture(name))

    def test_retrieved_knowledge_ids_update_case(
        self,
    ):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
        )

        case = _make_case()
        original_ids_snapshot = list(
            case.retrieved_knowledge_ids
        )

        updated_case, context = self.researcher.research(case)

        self.assertEqual(
            case.retrieved_knowledge_ids,
            original_ids_snapshot,
        )
        self.assertNotEqual(
            id(case),
            id(updated_case),
        )
        self.assertEqual(
            updated_case.retrieved_knowledge_ids,
            context.retrieved_knowledge_ids,
        )
        self.assertTrue(context.retrieved_knowledge_ids)

        stored = self.store.get_by_id(
            context.retrieved_knowledge_ids[0]
        )
        self.assertIsNotNone(stored)
        self.assertIn(
            stored.knowledge_id,
            context.retrieved_knowledge_ids,
        )

    def test_xss_type_filter(self):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
            "dom_writeup.json",
        )

        case = _make_case(xss_type="reflected")

        _updated, context = self.researcher.research(case)

        for document in context.documents:
            xss_type_values = {
                item.value
                for item in document.aggregate.xss_types
            }
            self.assertEqual(xss_type_values, {"reflected"})

        all_xss_types = {
            item.value
            for document in context.documents
            for item in document.aggregate.xss_types
        }
        self.assertNotIn("dom", all_xss_types)

    def test_context_filter(self):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
            "dom_writeup.json",
        )

        case = _make_case(
            xss_type="reflected",
            context=XSSContext(type="html_attribute"),
        )

        _updated, context = self.researcher.research(case)

        for document in context.documents:
            context_values = {
                item.value
                for item in document.aggregate.contexts
            }
            self.assertIn("html_attribute", context_values)

    def test_waf_filter_when_present(self):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
            "dom_writeup.json",
        )

        case = _make_case(waf="Strict WAF")

        _updated, context = self.researcher.research(case)

        for document in context.documents:
            waf_values = {
                item.value
                for item in document.aggregate.wafs
            }
            self.assertIn("Strict WAF", waf_values)

    def test_irrelevant_knowledge_is_excluded(self):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
            "dom_writeup.json",
        )

        case = _make_case(
            xss_type="stored",
            technology=["Unknown Stack"],
        )

        _updated, context = self.researcher.research(case)

        self.assertEqual(context.documents, [])
        self.assertEqual(context.retrieved_knowledge_ids, [])
        self.assertEqual(context.payload_patterns, [])
        self.assertEqual(context.verification_patterns, [])
        self.assertEqual(context.contexts, [])
        self.assertEqual(context.technologies, [])
        self.assertEqual(context.waf_observations, [])

    def test_payload_patterns_preserve_source_attribution(
        self,
    ):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
        )

        case = _make_case()

        _updated, context = self.researcher.research(case)

        expected_attribute = _load_fixture(
            "attribute_quoted_writeup.json"
        )
        expected_source_id = source_id(
            expected_attribute.source_type,
            expected_attribute.source_url,
        )

        expected = [
            (value, [expected_source_id])
            for value in expected_attribute.payload_patterns
        ]
        actual = [
            (item.value, list(item.source_ids))
            for item in context.payload_patterns
        ]
        self.assertEqual(
            sorted(actual),
            sorted(expected),
        )
        for _value, source_ids in actual:
            for source_id_value in source_ids:
                self.assertTrue(
                    source_id_value.startswith("src-")
                )

    def test_verification_patterns_preserve_source_attribution(
        self,
    ):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
        )

        case = _make_case()

        _updated, context = self.researcher.research(case)

        expected_attribute = _load_fixture(
            "attribute_quoted_writeup.json"
        )
        expected_source_id = source_id(
            expected_attribute.source_type,
            expected_attribute.source_url,
        )

        expected = [
            (value, [expected_source_id])
            for value in expected_attribute.verification_patterns
        ]
        actual = [
            (item.value, list(item.source_ids))
            for item in context.verification_patterns
        ]
        self.assertEqual(
            sorted(actual),
            sorted(expected),
        )
        for _value, source_ids in actual:
            self.assertTrue(source_ids)

    def test_multiple_sources_remain_separately_attributable(
        self,
    ):
        base = _load_fixture("reflected_writeup.json")
        mirror = _load_fixture("reflected_writeup_mirror.json").model_copy(
            update={
                "xss_types": ["reflected"],
                "contexts": ["html_attribute"],
                "wafs": ["Example WAF"],
                "payload_patterns": ["marker-only"],
                "verification_patterns": [
                    "browser execution"
                ],
                "content": base.content,
            }
        )

        self.store.ingest(base)
        self.store.ingest(mirror)

        case = _make_case(waf=None)

        _updated, context = self.researcher.research(case)

        self.assertEqual(len(context.documents), 1)
        document = context.documents[0]
        self.assertEqual(len(document.provenance), 2)

        payload = next(
            item
            for item in context.payload_patterns
            if item.value == "marker-only"
        )
        self.assertEqual(len(payload.source_ids), 2)

        base_source_id = source_id(
            base.source_type,
            base.source_url,
        )
        mirror_source_id = source_id(
            mirror.source_type,
            mirror.source_url,
        )
        self.assertEqual(
            payload.source_ids,
            sorted([base_source_id, mirror_source_id]),
        )

        self.assertFalse(hasattr(context, "confidence"))

    def test_no_matching_knowledge_returns_empty_context(
        self,
    ):
        case = _make_case(
            xss_type="mutation",
            technology=["Nonexistent Stack"],
        )

        _updated, context = self.researcher.research(case)

        self.assertEqual(context.case_id, case.case_id)
        self.assertEqual(context.retrieved_knowledge_ids, [])
        self.assertEqual(context.documents, [])
        self.assertEqual(context.payload_patterns, [])
        self.assertEqual(context.verification_patterns, [])
        self.assertEqual(context.contexts, [])
        self.assertEqual(context.technologies, [])
        self.assertEqual(context.waf_observations, [])

    def test_research_is_repeatably_deterministic(self):
        self._ingest(
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
        )

        case = _make_case()

        updated_a, context_a = self.researcher.research(case)
        updated_b, context_b = self.researcher.research(case)

        self.assertEqual(
            context_a.model_dump(mode="json"),
            context_b.model_dump(mode="json"),
        )
        self.assertEqual(
            updated_a.model_dump(mode="json"),
            updated_b.model_dump(mode="json"),
        )

    def test_research_is_order_independent_across_stores(
        self,
    ):
        fixtures = [
            "reflected_writeup.json",
            "attribute_quoted_writeup.json",
            "dom_writeup.json",
        ]

        def _load_deterministic(name: str):
            return _load_fixture(name).model_copy(
                update={
                    "indexed_at": (
                        "2026-08-01T00:00:00+00:00"
                    ),
                }
            )

        with tempfile.TemporaryDirectory() as dir_a:
            store_a = KnowledgeStore(Path(dir_a) / "knowledge")
            researcher_a = XSSResearcher(store_a)
            for name in fixtures:
                store_a.ingest(_load_deterministic(name))

            case_a = _make_case(
                waf=None,
                created_at="2026-08-01T00:00:00+00:00",
                updated_at="2026-08-01T00:00:00+00:00",
            )
            updated_a, context_a = researcher_a.research(case_a)

        with tempfile.TemporaryDirectory() as dir_b:
            store_b = KnowledgeStore(Path(dir_b) / "knowledge")
            researcher_b = XSSResearcher(store_b)
            for name in reversed(fixtures):
                store_b.ingest(_load_deterministic(name))

            case_b = _make_case(
                waf=None,
                created_at="2026-08-01T00:00:00+00:00",
                updated_at="2026-08-01T00:00:00+00:00",
            )
            updated_b, context_b = researcher_b.research(case_b)

        self.assertEqual(
            context_a.model_dump(mode="json"),
            context_b.model_dump(mode="json"),
        )
        self.assertEqual(
            updated_a.model_dump(mode="json"),
            updated_b.model_dump(mode="json"),
        )

    def test_no_network_or_llm_calls(self):
        import ai.researcher.xss_researcher as module

        forbidden = {
            "requests",
            "urllib",
            "urllib3",
            "httpx",
            "openai",
            "OpenRouterProvider",
            "AvalAIProvider",
        }
        self.assertTrue(forbidden.isdisjoint(module.__dict__))

        self._ingest("reflected_writeup.json")

        case = _make_case()

        with patch.object(
            KnowledgeStore,
            "retrieve",
            wraps=self.store.retrieve,
        ) as retrieve_spy:
            _updated, _context = self.researcher.research(case)

        retrieve_spy.assert_called_once()


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.ingestion.agent import (
    IngestionReport,
    KnowledgeIngestionAgent,
    _build_prompt,
)
from ai.ingestion.grounding import contains_forbidden
from ai.knowledge.store import KnowledgeStore
from ai.llm.base import LLMProvider, LLMResult
from ai.schemas.ingestion import (
    ExtractedClaim,
    ExtractionResult,
    IngestionError,
    SourceDocument,
)


SOURCE_TEXT = (
    "We observed a reflected XSS in the q parameter of "
    "the search endpoint. The reflection lands inside a "
    "quoted class attribute. The application runs behind "
    "Strict WAF. We labelled the technique 'attribute "
    "breakout marker' for sink execution."
)


def _source(**overrides) -> SourceDocument:
    base = dict(
        title="Reflected XSS writeup",
        source_url="https://example.test/writeup/abc",
        source_type="writeup",
        published_at="2026-08-04",
        content=SOURCE_TEXT,
        tags=["reflected-xss", "fixture"],
    )
    base.update(overrides)
    return SourceDocument(**base)


def _exclaim(
    *,
    evidence_class: str = "EXPLICIT",
    snippet_text: str = "reflected XSS in the q parameter",
    snippet_section: str | None = "summary",
    xss_types: list[str] | None = None,
    wafs: list[str] | None = None,
    contexts: list[str] | None = None,
    payload_patterns: list[str] | None = None,
    verification_patterns: list[str] | None = None,
    technologies: list[str] | None = None,
    techniques: list[str] | None = None,
    tags: list[str] | None = None,
    title: str | None = None,
    summary: str | None = None,
    rationale: str = "directly observed",
    confidence: float = 0.9,
    evidence_quality: str = "HIGH_CONFIDENCE",
    strict_payloads: bool = True,
    source: SourceDocument | None = None,
) -> dict:
    source = source or _source()
    payload_patterns = (
        list(payload_patterns)
        if payload_patterns is not None
        else ["attribute breakout marker"]
    )
    verification_patterns = (
        list(verification_patterns)
        if verification_patterns is not None
        else ["attribute sink execution"]
    )
    return {
        "evidence_class": evidence_class,
        "rationale": rationale,
        "evidence_snippets": [
            {
                "text": snippet_text,
                "section": snippet_section,
            }
        ],
        "title": title,
        "summary": summary,
        "technologies": list(
            technologies or ["Example Framework"]
        ),
        "xss_types": list(xss_types or ["reflected"]),
        "contexts": list(contexts or ["html_attribute"]),
        "wafs": list(wafs or ["Strict WAF"]),
        "techniques": list(techniques or []),
        "payload_patterns": payload_patterns,
        "verification_patterns": verification_patterns,
        "tags": list(tags or []),
        "evidence_quality": evidence_quality,
        "confidence": confidence,
        "forbidden_values": [],
        "strict_payloads": strict_payloads,
    }


def _extraction_payload(
    source: SourceDocument,
    claims: list[dict],
    notes: list[str] | None = None,
) -> str:
    payload = {
        "source": {
            "title": source.title,
            "source_url": source.source_url,
            "source_type": source.source_type,
            "published_at": source.published_at,
            "content": source.content,
            "tags": list(source.tags),
        },
        "claims": claims,
        "extraction_notes": list(notes or []),
    }
    return json.dumps(payload)


class StubProvider(LLMProvider):
    """In-memory LLMProvider that returns a configured response."""

    def __init__(self, response: str) -> None:
        self._response = response
        self.calls = 0
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> str:
        self.calls += 1
        self.last_prompt = prompt
        return self._response

    def complete(self, prompt: str) -> LLMResult:
        self.calls += 1
        self.last_prompt = prompt
        return LLMResult(
            content=self._response,
            request_id="stub-rid",
            model="stub-model",
        )


class _Store:
    """Helper that builds a fresh temp KnowledgeStore per test."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = KnowledgeStore(
            Path(self._tmp.name) / "knowledge"
        )
        return self.store

    def __exit__(self, exc_type, exc, tb):
        self._tmp.cleanup()


class KnowledgeIngestionAgentHappyPathTests(unittest.TestCase):
    def test_valid_source_to_persisted_document(self):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertTrue(report.created)
        self.assertIsNotNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 1)
        self.assertEqual(report.rejected_claim_count, 0)
        self.assertEqual(report.quarantined_claim_count, 0)

    def test_provider_metadata_is_not_exposed(self):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        # The report does not carry provider-specific metadata.
        self.assertFalse(hasattr(report, "model"))
        self.assertFalse(hasattr(report, "request_id"))
        self.assertFalse(hasattr(report, "raw_response_id"))
        for attribute in (
            "model",
            "request_id",
            "raw_response_id",
        ):
            self.assertNotIn(
                attribute, dir(report)
            )

    def test_persistence_uses_knowledge_store_deduplication(
        self,
    ):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            first = agent.ingest(source)
            second = agent.ingest(source)

        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(
            first.persisted_knowledge_id,
            second.persisted_knowledge_id,
        )

    def test_result_reports_accepted_and_rejected_counts(self):
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(),
                _exclaim(
                    snippet_text="not in source at all",
                    rationale="unsupported",
                ),
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertEqual(report.rejected_claim_count, 1)
        self.assertTrue(report.persisted_knowledge_id)

    def test_no_accepted_claims_does_not_persist(self):
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(
                    snippet_text="not present in source",
                    rationale="unsupported",
                )
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.rejected_claim_count, 1)
        # Nothing was written to disk.
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )


class KnowledgeIngestionAgentPromptTests(unittest.TestCase):
    def test_prompt_contains_source_metadata(self):
        source = _source()
        prompt = _build_prompt(source)
        self.assertIn(source.title, prompt)
        self.assertIn(source.source_url, prompt)
        self.assertIn(source.source_type, prompt)
        self.assertIn(source.published_at, prompt)

    def test_prompt_contains_source_content(self):
        source = _source()
        prompt = _build_prompt(source)
        self.assertIn(source.content, prompt)

    def test_prompt_instructs_no_invention(self):
        source = _source()
        prompt = _build_prompt(source).lower()
        for phrase in (
            "do not invent",
            "model_inference",
            "evidence_class",
            "executable",
        ):
            self.assertIn(phrase, prompt)


class KnowledgeIngestionAgentParsingTests(unittest.TestCase):
    def test_malformed_json_rejected(self):
        source = _source()
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider("not json at all"), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertTrue(
            any(
                note.startswith("malformed_json")
                for note in report.notes
            )
        )

    def test_fenced_json_parsed(self):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        fenced = "```json\n" + body + "\n```"
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(fenced), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertTrue(report.persisted_knowledge_id)

    def test_schema_invalid_json_rejected(self):
        source = _source()
        bad = {
            "source": source.model_dump(),
            # "claims" missing -> ExtractionResult validator rejects
        }
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(json.dumps(bad)), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertTrue(
            any(
                note.startswith("schema_invalid")
                for note in report.notes
            )
        )

    def test_claim_missing_evidence_snippet_rejected(self):
        source = _source()
        bad_claim = _exclaim()
        bad_claim["evidence_snippets"] = []
        body = _extraction_payload(source, [bad_claim])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.rejected_claim_count, 1)
        self.assertIsNone(report.persisted_knowledge_id)

    def test_ungrounded_evidence_snippet_rejected(self):
        source = _source()
        bad_claim = _exclaim(
            snippet_text="a string that does not appear anywhere"
        )
        body = _extraction_payload(source, [bad_claim])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.rejected_claim_count, 1)
        self.assertIsNone(report.persisted_knowledge_id)


class KnowledgeIngestionAgentEvidenceClassTests(unittest.TestCase):
    def test_explicit_claim_becomes_trusted(self):
        source = _source()
        body = _extraction_payload(
            source, [_exclaim(evidence_class="EXPLICIT")]
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)
            document = store.get_by_id(report.persisted_knowledge_id)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertEqual(report.quarantined_claim_count, 0)
        self.assertIsNotNone(document)
        self.assertEqual(
            document.aggregate.source_confidence[0].evidence_quality,
            "HIGH_CONFIDENCE",
        )

    def test_strongly_implied_becomes_secondary(self):
        source = _source()
        body = _extraction_payload(
            source,
            [_exclaim(evidence_class="STRONGLY_IMPLIED", confidence=0.7)],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)
            document = store.get_by_id(report.persisted_knowledge_id)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertEqual(report.quarantined_claim_count, 0)
        self.assertIsNotNone(document)
        self.assertEqual(
            document.aggregate.source_confidence[0].evidence_quality,
            "SECONDARY",
        )

    def test_model_inference_quarantined(self):
        source = _source()
        body = _extraction_payload(
            source,
            [_exclaim(evidence_class="MODEL_INFERENCE", confidence=0.3)],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.quarantined_claim_count, 1)
        self.assertIsNone(report.persisted_knowledge_id)
        # Nothing was written to disk.
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )

    def test_only_model_inference_never_creates_document(self):
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(evidence_class="MODEL_INFERENCE", confidence=0.3),
                _exclaim(evidence_class="MODEL_INFERENCE", confidence=0.2),
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.quarantined_claim_count, 2)
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )

    def test_mixed_classes_only_trust_non_inference(self):
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(evidence_class="MODEL_INFERENCE", confidence=0.3),
                _exclaim(evidence_class="EXPLICIT", confidence=0.9),
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)
            document = store.get_by_id(report.persisted_knowledge_id)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertEqual(report.quarantined_claim_count, 1)
        self.assertTrue(report.persisted_knowledge_id)
        self.assertIsNotNone(document)
        # The aggregate is built only from the EXPLICIT claim.
        xss_types = {
            item.value for item in document.aggregate.xss_types
        }
        self.assertEqual(xss_types, {"reflected"})


class KnowledgeIngestionAgentPayloadSafetyTests(unittest.TestCase):
    def test_executable_payload_rejected(self):
        source = _source()
        body = _extraction_payload(
            source,
            [_exclaim(payload_patterns=["<script>alert(1)</script>"])],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        # The schema-level forbidden-payload check raises
        # before the per-claim loop; the agent records a
        # schema_invalid audit note and persists nothing.
        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(report.rejected_claim_count, 0)
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )
        self.assertTrue(
            any(
                "schema_invalid" in note or "payload" in note
                for note in report.notes
            )
        )

    def test_javascript_url_in_verification_rejected(self):
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(
                    verification_patterns=[
                        'href="javascript:alert(1)"'
                    ]
                )
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.rejected_claim_count, 0)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )
        self.assertTrue(report.notes)

    def test_long_base64_blob_rejected(self):
        source = _source()
        body = _extraction_payload(
            source,
            [_exclaim(payload_patterns=["A" * 250])],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertIsNone(report.persisted_knowledge_id)
        self.assertEqual(report.rejected_claim_count, 0)
        self.assertEqual(report.accepted_claim_count, 0)
        self.assertEqual(
            len(list(store.documents_dir.glob("*.json"))), 0
        )
        self.assertTrue(report.notes)

    def test_normal_research_terminology_accepted(self):
        # The terminological examples from the spec are
        # conservatively allowed.
        source = _source()
        body = _extraction_payload(
            source,
            [
                _exclaim(
                    payload_patterns=["onerror bypass technique"],
                    verification_patterns=[
                        "script context analysis"
                    ],
                )
            ],
        )
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)

        self.assertEqual(report.accepted_claim_count, 1)
        self.assertTrue(report.persisted_knowledge_id)


class KnowledgeIngestionAgentProviderInjectionTests(unittest.TestCase):
    def test_does_not_instantiate_openrouter(self):
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider("{}"), store
            )
            self.assertNotIsInstance(
                agent.llm,
                __import__(
                    "ai.llm.openrouter",
                    fromlist=["OpenRouterProvider"],
                ).OpenRouterProvider,
            )

    def test_module_does_not_import_openrouter(self):
        import ai.ingestion.agent as module

        self.assertNotIn("OpenRouterProvider", module.__dict__)

    def test_no_network_module_imports(self):
        import ai.ingestion.agent as module

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

    def test_stub_provider_is_called_exactly_once(self):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            stub = StubProvider(body)
            agent = KnowledgeIngestionAgent(stub, store)
            agent.ingest(source)

        self.assertEqual(stub.calls, 1)
        self.assertIn(source.title, stub.last_prompt or "")


class KnowledgeIngestionAgentAttributionTests(unittest.TestCase):
    def test_persisted_document_carries_source_attribution(self):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)
            document = store.get_by_id(report.persisted_knowledge_id)

        self.assertIsNotNone(document)
        self.assertEqual(document.source_url, source.source_url)
        self.assertEqual(
            document.source_type, source.source_type
        )
        self.assertEqual(document.title, source.title)
        self.assertEqual(
            document.published_at, source.published_at
        )
        self.assertEqual(len(document.provenance), 1)
        provenance = document.provenance[0]
        self.assertEqual(provenance.title, source.title)
        self.assertEqual(
            provenance.claims[0].payload_patterns,
            ["attribute breakout marker"],
        )

    def test_duplicate_content_two_sources_merges_provenance(
        self,
    ):
        source_a = _source(
            source_url="https://a.example.test/doc",
            source_type="writeup",
        )
        body_a = _extraction_payload(source_a, [_exclaim()])

        source_b = _source(
            source_url="https://b.example.test/doc",
            source_type="mirror",
        )
        body_b = _extraction_payload(source_b, [_exclaim()])

        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(""), store
            )

            class _TwoResponses(LLMProvider):
                def __init__(self, a, b):
                    self._a = a
                    self._b = b
                    self.calls = 0

                def generate(self, prompt):
                    self.calls += 1
                    return self._a if self.calls == 1 else self._b

                def complete(self, prompt):
                    self.calls += 1
                    return LLMResult(
                        content=(
                            self._a if self.calls == 1 else self._b
                        ),
                        request_id=f"rid-{self.calls}",
                        model="stub",
                    )

            agent.llm = _TwoResponses(body_a, body_b)
            first = agent.ingest(source_a)
            second = agent.ingest(source_b)
            document = store.get_by_id(first.persisted_knowledge_id)

        self.assertEqual(
            first.persisted_knowledge_id,
            second.persisted_knowledge_id,
        )
        self.assertIsNotNone(document)
        self.assertEqual(len(document.provenance), 2)


class KnowledgeIngestionAgentRegressionTests(unittest.TestCase):
    """
    Confirm the XSS research path still works after a successful
    ingestion, and confirm existing knowledge-store invariants
    are not bypassed.
    """

    def test_ingested_payload_retrievable_by_xss_researcher(
        self,
    ):
        source = _source()
        body = _extraction_payload(source, [_exclaim()])
        with _Store() as store:
            agent = KnowledgeIngestionAgent(
                StubProvider(body), store
            )
            report = agent.ingest(source)
            self.assertTrue(report.persisted_knowledge_id)

            # Build an XSS case that matches the ingested
            # document's technology + context + WAF and
            # confirm the new payload is visible in the
            # XSSResearchContext.
            from ai.researcher.xss_researcher import XSSResearcher
            from ai.schemas.xss import XSSCase, XSSContext

            case = XSSCase(
                case_id="c-ingest",
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
            )
            researcher = XSSResearcher(store)
            _updated, context = researcher.research(case)
            payload_values = {
                item.value for item in context.payload_patterns
            }
            self.assertIn(
                "attribute breakout marker", payload_values
            )


class KnowledgeIngestionAgentHelperTests(unittest.TestCase):
    def test_contains_forbidden_is_conservative(self):
        # Defensive: the helper used by the agent must
        # not over-match.
        self.assertFalse(contains_forbidden(""))
        self.assertFalse(
            contains_forbidden("onerror bypass technique")
        )
        self.assertTrue(contains_forbidden("<script>x</script>"))


if __name__ == "__main__":
    unittest.main()

import unittest

from pydantic import ValidationError

from ai.schemas.ingestion import (
    EvidenceSnippet,
    ExtractedClaim,
    ExtractionResult,
    IngestionError,
    SourceDocument,
)
from ai.schemas.knowledge import KnowledgeSourceClaims


def _source(**overrides) -> SourceDocument:
    base = dict(
        title="Reflected XSS in search parameter",
        source_url="https://example.test/writeup/abc",
        source_type="writeup",
        published_at="2026-08-04",
        content=(
            "We observed a reflected XSS in the q parameter of "
            "the search endpoint. The reflection lands inside a "
            "quoted class attribute. The application runs behind "
            "Strict WAF."
        ),
        tags=["reflected-xss", "fixture"],
    )
    base.update(overrides)
    return SourceDocument(**base)


def _valid_claim(**overrides) -> ExtractedClaim:
    base = dict(
        evidence_class="EXPLICIT",
        technologies=["Example Framework"],
        xss_types=["reflected"],
        contexts=["html_attribute"],
        wafs=["Strict WAF"],
        techniques=["context analysis"],
        payload_patterns=["attribute breakout marker"],
        verification_patterns=["attribute sink execution"],
        tags=["reflected-xss"],
        confidence=0.9,
        rationale="Direct observation described in writeup.",
        evidence_snippets=[
            EvidenceSnippet(
                text="reflected XSS in the q parameter",
                section="summary",
            )
        ],
    )
    base.update(overrides)
    return ExtractedClaim(**base)


class SourceDocumentTests(unittest.TestCase):
    def test_valid_source_document(self):
        doc = _source()
        self.assertEqual(doc.title, "Reflected XSS in search parameter")
        self.assertEqual(
            doc.source_url, "https://example.test/writeup/abc"
        )
        self.assertEqual(doc.source_type, "writeup")
        self.assertEqual(doc.published_at, "2026-08-04")
        self.assertIn("Strict WAF", doc.content)

    def test_required_fields(self):
        for missing in (
            "title",
            "source_url",
            "source_type",
            "content",
        ):
            kwargs = {
                "title": "t",
                "source_url": "https://x.test",
                "source_type": "writeup",
                "content": "body",
            }
            kwargs.pop(missing)
            with self.assertRaises(ValidationError):
                SourceDocument(**kwargs)

    def test_published_at_optional(self):
        doc = _source(published_at=None)
        self.assertIsNone(doc.published_at)

    def test_does_not_perform_network(self):
        import ai.schemas.ingestion as module

        forbidden = {
            "requests",
            "urllib",
            "httpx",
        }
        self.assertTrue(
            forbidden.isdisjoint(module.__dict__)
        )


class ExtractedClaimTests(unittest.TestCase):
    def test_valid_claim(self):
        claim = _valid_claim()
        self.assertEqual(claim.evidence_class, "EXPLICIT")
        self.assertEqual(claim.technologies, ["Example Framework"])
        self.assertEqual(claim.xss_types, ["reflected"])
        self.assertEqual(claim.contexts, ["html_attribute"])
        self.assertEqual(claim.wafs, ["Strict WAF"])
        self.assertEqual(claim.confidence, 0.9)

    def test_evidence_classification_required(self):
        with self.assertRaises(ValidationError):
            ExtractedClaim(
                technologies=["Example Framework"],
                confidence=0.9,
            )

    def test_evidence_class_rejects_unknown_value(self):
        with self.assertRaises(ValidationError):
            _valid_claim(evidence_class="MAYBE")

    def test_confidence_below_zero_rejected(self):
        with self.assertRaises(ValidationError):
            _valid_claim(confidence=-0.1)

    def test_confidence_above_one_rejected(self):
        with self.assertRaises(ValidationError):
            _valid_claim(confidence=1.5)

    def test_empty_claim_rejected(self):
        with self.assertRaises(IngestionError):
            ExtractedClaim(evidence_class="EXPLICIT")

    def test_summary_only_claim_accepted(self):
        claim = ExtractedClaim(
            evidence_class="EXPLICIT",
            summary="A short verbatim quote from the document.",
            confidence=0.9,
        )
        self.assertEqual(
            claim.summary,
            "A short verbatim quote from the document.",
        )

    def test_title_only_claim_accepted(self):
        claim = ExtractedClaim(
            evidence_class="EXPLICIT",
            title="Reflected XSS via unquoted attribute",
            confidence=0.9,
        )
        self.assertEqual(
            claim.title, "Reflected XSS via unquoted attribute"
        )

    def test_evidence_snippet_preserved(self):
        snippet = EvidenceSnippet(
            text="reflected XSS in the q parameter",
            section="summary",
        )
        claim = _valid_claim(evidence_snippets=[snippet])
        self.assertEqual(
            claim.evidence_snippets[0].text,
            "reflected XSS in the q parameter",
        )
        self.assertEqual(
            claim.evidence_snippets[0].section, "summary"
        )

    def test_evidence_snippet_must_be_non_empty(self):
        with self.assertRaises(ValidationError):
            EvidenceSnippet(text="", section="x")
        with self.assertRaises(ValidationError):
            EvidenceSnippet(text="   ", section="x")

    def test_source_attribution_via_evidence_snippets(self):
        snippet_a = EvidenceSnippet(
            text="reflected XSS in the q parameter",
            section="summary",
        )
        snippet_b = EvidenceSnippet(
            text="The reflection lands inside a quoted class "
            "attribute",
            section="body",
        )
        claim = _valid_claim(
            evidence_snippets=[snippet_a, snippet_b]
        )
        self.assertEqual(len(claim.evidence_snippets), 2)
        for snippet in claim.evidence_snippets:
            self.assertTrue(snippet.text)
            self.assertIsNotNone(snippet.section)


class ModelInferenceDistinctionTests(unittest.TestCase):
    def test_explicit_projects_to_high_confidence(self):
        claim = _valid_claim(
            evidence_class="EXPLICIT", confidence=0.9
        )
        self.assertEqual(
            claim.projected_evidence_quality(),
            "HIGH_CONFIDENCE",
        )

    def test_strongly_implied_projects_to_secondary(self):
        claim = _valid_claim(
            evidence_class="STRONGLY_IMPLIED", confidence=0.7
        )
        self.assertEqual(
            claim.projected_evidence_quality(), "SECONDARY"
        )

    def test_model_inference_projects_to_unverified(self):
        claim = _valid_claim(
            evidence_class="MODEL_INFERENCE", confidence=0.4
        )
        self.assertEqual(
            claim.projected_evidence_quality(), "UNVERIFIED"
        )

    def test_model_inference_cannot_use_high_confidence(self):
        # The band is [0.00, 0.54] for MODEL_INFERENCE; a
        # confidence of 0.9 must be rejected at validation
        # time.
        with self.assertRaises(IngestionError):
            _valid_claim(
                evidence_class="MODEL_INFERENCE",
                confidence=0.9,
            )

    def test_explicit_cannot_use_low_confidence(self):
        # The band is [0.80, 1.00] for EXPLICIT; a
        # confidence of 0.4 must be rejected.
        with self.assertRaises(IngestionError):
            _valid_claim(
                evidence_class="EXPLICIT", confidence=0.4
            )

    def test_model_inference_distinguishable_from_explicit(self):
        # The two claim classes must round-trip
        # unambiguously through serialization.
        explicit = _valid_claim(
            evidence_class="EXPLICIT", confidence=0.9
        )
        inferred = _valid_claim(
            evidence_class="MODEL_INFERENCE", confidence=0.3
        )
        self.assertNotEqual(
            explicit.evidence_class, inferred.evidence_class
        )
        self.assertNotEqual(
            explicit.projected_evidence_quality(),
            inferred.projected_evidence_quality(),
        )
        self.assertNotEqual(
            explicit.model_dump(),
            inferred.model_dump(),
        )


class ExecutablePayloadRejectionTests(unittest.TestCase):
    def test_executable_script_payload_rejected(self):
        with self.assertRaises(IngestionError):
            _valid_claim(
                payload_patterns=[
                    "<script>alert(1)</script>"
                ]
            )

    def test_executable_javascript_url_rejected(self):
        with self.assertRaises(IngestionError):
            _valid_claim(
                payload_patterns=[
                    'href="javascript:alert(1)"'
                ]
            )

    def test_executable_event_handler_rejected(self):
        with self.assertRaises(IngestionError):
            _valid_claim(
                payload_patterns=["x onerror=alert(1)"]
            )

    def test_executable_verification_pattern_rejected(self):
        with self.assertRaises(IngestionError):
            _valid_claim(
                verification_patterns=[
                    "document.write('<x>')"
                ]
            )

    def test_executable_evidence_snippet_rejected(self):
        with self.assertRaises(IngestionError):
            _valid_claim(
                evidence_snippets=[
                    EvidenceSnippet(
                        text="<script>alert(1)</script>",
                        section="body",
                    )
                ]
            )

    def test_normal_research_terminology_accepted(self):
        # Conservative terminology must not trip the
        # executable-payload filter.
        for value in (
            "onerror bypass technique",
            "script context",
            "JavaScript context",
            "DOM-based sink analysis",
            "attribute breakout marker",
        ):
            claim = _valid_claim(
                payload_patterns=[value],
                confidence=0.9,
            )
            self.assertEqual(claim.payload_patterns[0], value)

    def test_long_base64_blob_in_payload_rejected(self):
        long_blob = "A" * 250
        with self.assertRaises(IngestionError):
            _valid_claim(payload_patterns=[long_blob])

    def test_strict_payloads_false_relaxes_rejection(self):
        # The agent layer can opt out of strict payload
        # checking by setting ``strict_payloads=False``.
        claim = _valid_claim(
            payload_patterns=["<script>alert(1)</script>"],
            strict_payloads=False,
        )
        self.assertEqual(
            claim.payload_patterns[0],
            "<script>alert(1)</script>",
        )
        # The agent layer records the offenders in
        # ``forbidden_values``; the schema exposes that
        # field for downstream audit.
        self.assertIn(
            "<script>alert(1)</script>",
            claim.forbidden_values,
        )


class ExtractionResultTests(unittest.TestCase):
    def test_valid_extraction_result(self):
        result = ExtractionResult(
            source=_source(),
            claims=[_valid_claim()],
        )
        self.assertEqual(len(result.claims), 1)
        self.assertEqual(
            result.source.source_url,
            "https://example.test/writeup/abc",
        )

    def test_empty_claims_rejected(self):
        with self.assertRaises(IngestionError):
            ExtractionResult(
                source=_source(),
                claims=[],
            )

    def test_extraction_notes_default_empty(self):
        result = ExtractionResult(
            source=_source(), claims=[_valid_claim()]
        )
        self.assertEqual(result.extraction_notes, [])

    def test_extraction_notes_can_carry_observations(self):
        result = ExtractionResult(
            source=_source(),
            claims=[_valid_claim()],
            extraction_notes=[
                "one claim rejected for missing snippet",
            ],
        )
        self.assertEqual(
            result.extraction_notes[0],
            "one claim rejected for missing snippet",
        )

    def test_result_does_not_expose_provider_metadata(self):
        # No LLM provider fields. The result is
        # provider-agnostic.
        result = ExtractionResult(
            source=_source(), claims=[_valid_claim()]
        )
        self.assertNotIn("model", result.model_dump())
        self.assertNotIn("request_id", result.model_dump())
        self.assertNotIn("raw_response_id", result.model_dump())


class SerializationTests(unittest.TestCase):
    def test_round_trip_extracted_claim(self):
        claim = _valid_claim(
            evidence_class="STRONGLY_IMPLIED", confidence=0.7
        )
        payload = claim.model_dump(mode="json")
        restored = ExtractedClaim.model_validate(payload)
        self.assertEqual(restored, claim)

    def test_round_trip_extraction_result(self):
        result = ExtractionResult(
            source=_source(),
            claims=[_valid_claim(), _valid_claim()],
        )
        payload = result.model_dump(mode="json")
        restored = ExtractionResult.model_validate(payload)
        self.assertEqual(restored, result)

    def test_round_trip_preserves_evidence_class(self):
        for evidence_class in (
            "EXPLICIT",
            "STRONGLY_IMPLIED",
            "MODEL_INFERENCE",
        ):
            with self.subTest(evidence_class=evidence_class):
                confidence = {
                    "EXPLICIT": 0.9,
                    "STRONGLY_IMPLIED": 0.7,
                    "MODEL_INFERENCE": 0.3,
                }[evidence_class]
                claim = _valid_claim(
                    evidence_class=evidence_class,
                    confidence=confidence,
                )
                restored = ExtractedClaim.model_validate(
                    claim.model_dump(mode="json")
                )
                self.assertEqual(
                    restored.evidence_class, evidence_class
                )
                self.assertEqual(
                    restored.projected_evidence_quality(),
                    claim.projected_evidence_quality(),
                )

    def test_to_knowledge_source_claims_projection(self):
        claim = _valid_claim(
            evidence_class="EXPLICIT", confidence=0.9
        )
        projected: KnowledgeSourceClaims = (
            claim.to_knowledge_source_claims()
        )
        self.assertEqual(
            projected.evidence_quality, "HIGH_CONFIDENCE"
        )
        self.assertEqual(projected.confidence, 0.9)
        self.assertEqual(
            projected.technologies, ["Example Framework"]
        )
        self.assertEqual(
            projected.payload_patterns,
            ["attribute breakout marker"],
        )
        self.assertEqual(
            projected.verification_patterns,
            ["attribute sink execution"],
        )
        self.assertEqual(
            projected.wafs, ["Strict WAF"]
        )


class PublicSurfaceTests(unittest.TestCase):
    def test_models_are_pydantic_v2(self):
        from pydantic import BaseModel

        for model in (
            SourceDocument,
            ExtractedClaim,
            ExtractionResult,
            EvidenceSnippet,
        ):
            self.assertTrue(
                issubclass(model, BaseModel),
                f"{model.__name__} must be a Pydantic model",
            )
            self.assertTrue(
                hasattr(model, "model_validate"),
                f"{model.__name__} missing model_validate",
            )
            self.assertTrue(
                hasattr(model, "model_dump"),
                f"{model.__name__} missing model_dump",
            )


if __name__ == "__main__":
    unittest.main()

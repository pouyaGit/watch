"""Deterministic intelligence extraction rules (Stage R12 tests).

Offline fixtures only: synthetic research payloads and reference
records exercising the extractor's conservative boundaries. No network,
no LLM, no Mongo, no subprocess.
"""

import unittest

from ai.knowledge.intelligence import (
    INTELLIGENCE_RULE_VERSION,
    MAX_EVIDENCE_SNIPPET_CHARS,
    extract_research_intelligence,
)


def _payload(research_texts, cwes=None):
    return {
        "cve": {"id": "CVE-2026-0001", "cwes": list(cwes or [])},
        "metadata": {"technologies": []},
        "research": dict(research_texts),
    }


def _record(url, title="", chunks=()):
    return {
        "source_url": url,
        "source_type": "reference",
        "title": title,
        "context_chunks": list(chunks),
    }


def _run(cve, research_texts=None, records=(), cwes=None):
    return extract_research_intelligence(
        cve, _payload(research_texts or {}, cwes), list(records)
    )


def _evidence_for(result, field, value):
    return [
        item
        for item in result.evidence
        if item.field == field and item.value == value
    ]

class ExplicitXssTypeTests(unittest.TestCase):
    def test_reflected_xss_extraction(self):
        text = "The CVE-2026-0001 advisory confirms reflected XSS via search."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.xss_types, ["reflected"])
        evidence = _evidence_for(result, "xss_type", "reflected")
        self.assertEqual(len(evidence), 1)
        item = evidence[0]
        self.assertEqual(item.source_url, "https://a.test/1")
        self.assertEqual(item.rule_id, "xss-type-reflected")
        self.assertEqual(item.rule_version, INTELLIGENCE_RULE_VERSION)
        self.assertIn("CVE-2026-0001", item.evidence)
        self.assertLessEqual(len(item.evidence), MAX_EVIDENCE_SNIPPET_CHARS)

    def test_stored_xss_extraction(self):
        text = "CVE-2026-0001: stored cross-site scripting in comments."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.xss_types, ["stored"])

    def test_dom_xss_extraction(self):
        text = "This is a DOM-based XSS in CVE-2026-0001 widgets."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.xss_types, ["dom"])


class ContextExtractionTests(unittest.TestCase):
    def test_html_attribute_context(self):
        text = "CVE-2026-0001 reflects input in an HTML attribute."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.contexts, ["html_attribute"])

    def test_script_context(self):
        text = "CVE-2026-0001 payload lands within a script."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.contexts, ["script"])

    def test_javascript_context(self):
        text = "CVE-2026-0001 executes in JavaScript code."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.contexts, ["javascript"])

    def test_url_context(self):
        text = "CVE-2026-0001 reflects the payload in the URL."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.contexts, ["url"])

    def test_context_without_cve_window_is_rejected(self):
        text = "HTML attribute reflection is possible in dashboards."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.contexts, [])
        self.assertEqual(result.evidence, [])


class ParameterExtractionTests(unittest.TestCase):
    def test_quoted_named_parameter(self):
        text = "CVE-2026-0001 reflects the 'q' parameter without encoding."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.parameters, ["q"])
        evidence = _evidence_for(result, "parameter", "q")
        self.assertEqual(len(evidence), 1)
        self.assertIn("CVE-2026-0001", evidence[0].evidence)

    def test_get_parameter_name(self):
        text = "CVE-2026-0001: GET parameter search reflects input."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.parameters, ["search"])

    def test_parameter_without_window_is_rejected(self):
        text = "The 'search' parameter echoes input in the demo."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.parameters, [])

    def test_generic_parameter_wording_rejected(self):
        text = "CVE-2026-0001 has parameters and arguments everywhere."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.parameters, [])

class ConservativeBehaviorTests(unittest.TestCase):
    def test_cwe79_does_not_invent_subtype_or_context(self):
        result = _run("CVE-2026-0001", cwes=["CWE-79"])
        self.assertEqual(result.vulnerability_types, ["xss"])
        self.assertEqual(result.cwes, ["CWE-79"])
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.contexts, [])
        self.assertEqual(result.parameters, [])

    def test_generic_xss_only_supports_broad_type(self):
        text = "CVE-2026-0001 is an XSS issue in widgets."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.vulnerability_types, ["xss"])
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.contexts, [])

    def test_cwe_alone_never_implies_context(self):
        result = _run("CVE-2026-0001", cwes=["CWE-79", "CWE-89"])
        self.assertEqual(sorted(result.vulnerability_types), ["sql_injection", "xss"])
        self.assertEqual(result.contexts, [])

    def test_neighboring_cve_evidence_is_not_attributed(self):
        text = (
            "CVE-2024-27954 is a path traversal issue, while "
            "CVE-2026-0001 remains unclassified."
        )
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.vulnerability_types, [])
        self.assertEqual(result.evidence, [])

    def test_sql_injection_and_sqli(self):
        text = "CVE-2026-0001: WordPress plugin SQLi in login."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.vulnerability_types, ["sql_injection"])

    def test_non_xss_rejection(self):
        text = "CVE-2026-0001 fixes a path traversal in uploads."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.vulnerability_types, ["path_traversal"])
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.contexts, [])


class DeterminismAndBoundsTests(unittest.TestCase):
    def test_deterministic_output_for_same_inputs(self):
        text = "CVE-2026-0001 stored XSS via the 'name' parameter."
        records = [_record("https://a.test/1", chunks=[text])]
        first = _run("CVE-2026-0001", records=records)
        second = _run("CVE-2026-0001", records=list(reversed(records)))
        self.assertEqual(first.vulnerability_types, second.vulnerability_types)
        self.assertEqual(first.xss_types, second.xss_types)
        self.assertEqual(first.parameters, second.parameters)
        self.assertEqual(
            [item.evidence for item in first.evidence],
            [item.evidence for item in second.evidence],
        )

    def test_empty_and_malformed_inputs(self):
        empty = extract_research_intelligence("CVE-2026-0001", {}, [])
        self.assertEqual(empty.vulnerability_types, [])
        self.assertEqual(empty.evidence, [])
        malformed = extract_research_intelligence("CVE-2026-0001", {}, [None, "url"])
        self.assertEqual(malformed.evidence, [])

    def test_evidence_snippet_is_bounded(self):
        text = f"{'padding text. ' * 20}CVE-2026-0001 reflected XSS{' padding text.' * 20}"
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        evidence = _evidence_for(result, "xss_type", "reflected")[0]
        self.assertIn("CVE-2026-0001", evidence.evidence)
        self.assertLessEqual(len(evidence.evidence), MAX_EVIDENCE_SNIPPET_CHARS)


class StructuralAttributionTests(unittest.TestCase):
    def test_research_artifact_text_is_structurally_attributed(self):
        # The research block of <CVE>.cli.json is about this CVE by
        # construction: no in-text CVE id is required for attribution.
        payload = {
            "cve": {"id": "CVE-2026-0001", "products": ["Widget Shop"]},
            "metadata": {},
            "research": {
                "summary": (
                    "Reflected XSS in the 'name' parameter rendered "
                    "into an HTML attribute."
                )
            },
        }
        result = extract_research_intelligence("CVE-2026-0001", payload, [])
        self.assertEqual(result.xss_types, ["reflected"])
        self.assertEqual(result.contexts, ["html_attribute"])
        self.assertEqual(result.parameters, ["name"])
        self.assertIn("xss", result.vulnerability_types)
        for item in result.evidence:
            self.assertIsNone(item.source_url)
            self.assertEqual(item.source_type, "research")

    def test_research_text_from_other_cve_is_not_structural(self):
        payload = {
            "cve": {"id": "CVE-2026-9999"},
            "metadata": {},
            "research": {"summary": "Reflected XSS without any id."},
        }
        result = extract_research_intelligence("CVE-2026-0001", payload, [])
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.evidence, [])


class NearestCveAttributionTests(unittest.TestCase):
    def test_phrase_nearest_another_cve_is_rejected(self):
        # Aggregator/list pages interleave many CVE ids; a phrase is
        # attributed to the nearest id, not merely to any nearby id.
        text = (
            "vpatch-CVE-2026-0002,enabled,0.1,Shop - Path Traversal "
            "(CVE-2026-0002) appsec vpatch-CVE-2026-0001,enabled,"
            "0.1,Widget - SQLi (CVE-2026-0001)"
        )
        result = _run("CVE-2026-0001", records=[_record("https://a.test/feed", chunks=[text])])
        self.assertNotIn("path_traversal", result.vulnerability_types)
        self.assertIn("sql_injection", result.vulnerability_types)
        for item in result.evidence:
            self.assertNotIn("2026-0002", item.value)

    def test_equal_distance_to_two_cves_is_rejected(self):
        text = "CVE-2026-0001Xreflected XSSXCVE-2026-0002"
        text = text.replace("X", " ")
        result = _run("CVE-2026-0001", records=[_record("https://a.test/1", chunks=[text])])
        self.assertEqual(result.xss_types, [])


class ProductAttributionTests(unittest.TestCase):
    _PRODUCTS = ("Widget Shop",)

    def _run_product(self, text):
        return extract_research_intelligence(
            "CVE-2026-0001",
            {},
            [_record("https://a.test/p", chunks=[text])],
            product_terms=self._PRODUCTS,
        )

    def test_cve_silent_document_with_product_link_is_attributed(self):
        result = self._run_product(
            "Widget Shop 1.0: reflected XSS via the item parameter."
        )
        self.assertEqual(result.xss_types, ["reflected"])
        self.assertEqual(result.parameters, ["item"])
        self.assertIn("xss", result.vulnerability_types)

    def test_cve_silent_document_without_product_link_is_rejected(self):
        result = self._run_product("Some unrelated page: reflected XSS exists.")
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.evidence, [])

    def test_product_attribution_still_requires_explicit_subtype_text(self):
        # Product-linked page naming only generic XSS: broad type yes,
        # subtype never.
        result = self._run_product("XSS in Widget Shop search.")
        self.assertEqual(result.vulnerability_types, ["xss"])
        self.assertEqual(result.xss_types, [])
        self.assertEqual(result.contexts, [])

    def test_short_or_generic_terms_never_attribute(self):
        result = extract_research_intelligence(
            "CVE-2026-0001",
            {},
            [_record("https://a.test/p", chunks=["shop: reflected XSS here."])],
            product_terms=("shop", "app"),
        )
        self.assertEqual(result.xss_types, [])


class ExtractionProvenanceTests(unittest.TestCase):
    def test_every_extracted_value_has_full_provenance(self):
        text = "CVE-2026-0001 stored XSS in an HTML attribute via the 'note' parameter."
        result = _run("CVE-2026-0001", records=[_record("https://a.test/2", chunks=[text])])
        values = {
            "vulnerability_type": set(result.vulnerability_types),
            "xss_type": set(result.xss_types),
            "context": set(result.contexts),
            "parameter": set(result.parameters),
        }
        for field, expected in values.items():
            traced = {
                item.value for item in result.evidence if item.field == field
            }
            self.assertEqual(traced, expected, field)
        for item in result.evidence:
            self.assertTrue(item.source_artifact)
            self.assertEqual(item.rule_version, INTELLIGENCE_RULE_VERSION)
            self.assertTrue(item.rule_id)
            self.assertIn("CVE-2026-0001", item.evidence)
            self.assertEqual(item.source_url, "https://a.test/2")


class SeedCompatibilityTests(unittest.TestCase):
    def test_bundled_seed_values_unchanged(self):
        from ai.researcher.xss_agent import (
            CONTEXT_KEYWORDS,
            SUPPORTED_CATEGORIES,
            TYPE_KEYWORDS,
        )

        self.assertIn("reflected", TYPE_KEYWORDS)
        self.assertIn("stored", TYPE_KEYWORDS)
        self.assertIn("dom", TYPE_KEYWORDS)
        self.assertIn("html_attribute", CONTEXT_KEYWORDS)
        self.assertIn("script", CONTEXT_KEYWORDS)
        self.assertIn("javascript", CONTEXT_KEYWORDS)
        self.assertEqual(len(SUPPORTED_CATEGORIES), 3)

    def test_seed_documents_still_load(self):
        from ai.researcher.xss_agent import load_seed_documents

        documents = load_seed_documents()
        self.assertGreaterEqual(len(documents), 3)


if __name__ == "__main__":
    unittest.main()

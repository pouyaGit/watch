"""tests/test_research_agent_r24_1.py — Stage R24.1 source-discovery contract tests.

Offline, deterministic. Covers the R24.1 contract: exact enum vocabularies,
deterministic query ids/ordering, query sanitization and the 200-char bound,
allowed CVE metadata inputs, the forbidden program/asset-input invariant,
target-host leakage prevention, duplicate-input normalization, empty/invalid
metadata handling, schema serialization, the production_finding safety invariant
and the import boundary (no network / no subprocess / no 5B-5J). Also checks
compatibility with the existing R23 source structures.

No network, no LLM, no Mongo, no subprocess.
"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.research_agent.discovery_contract import (
    QUERY_ID_PREFIX,
    SOURCE_ID_PREFIX,
    SourceCategory,
    TrustTier,
    Lifecycle,
    SearchProvider,
    ForbiddenInputError,
    contains_forbidden_token,
    assert_no_forbidden_input,
    query_id_for,
    discovered_source_id,
    DiscoveryQuery,
    DiscoveredSource,
)
from ai.research_agent.queries import (
    MAX_QUERY_CHARS,
    QUERY_TEMPLATE_IDS,
    TEMPLATE_CVE_ID,
    CVEResearchMetadata,
    QueryBuilder,
    normalize_cve_id,
    sanitize_query,
)
from ai.schemas.research_agent import (
    ResearchAgentSource,
    SOURCE_STATES,
    SOURCE_STORED_ONLY,
)


class TestEnumVocabularies(unittest.TestCase):
    """Exact enum value sets from the R24 scope."""

    def test_source_categories_exact(self):
        self.assertEqual(
            [c.value for c in SourceCategory],
            [
                "nvd_cve",
                "vendor_advisory",
                "wordfence",
                "wpscan",
                "github_advisory",
                "github_repo",
                "detection_rule",
                "exploit_reference",
                "writeup",
                "security_blog",
                "generic_search",
            ],
        )

    def test_trust_tiers_exact(self):
        self.assertEqual(
            [t.value for t in TrustTier],
            ["TRUSTED", "SEMI_TRUSTED", "DISCOVERY_ONLY", "GENERIC"],
        )

    def test_lifecycle_exact(self):
        self.assertEqual(
            [l.value for l in Lifecycle],
            [
                "DISCOVERED_SOURCE",
                "FETCHED_SOURCE",
                "RELEVANT_SOURCE",
                "EVIDENCE",
                "UNKNOWN",
                "INFERENCE",
            ],
        )


class TestQueryIdDeterminism(unittest.TestCase):
    def test_same_inputs_same_id(self):
        a = query_id_for("t", "nvd", "CVE-2026-1557", ["CVE-2026-1557"])
        b = query_id_for("t", "nvd", "CVE-2026-1557", ["CVE-2026-1557"])
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(QUERY_ID_PREFIX))

    def test_different_input_different_id(self):
        a = query_id_for("t", "nvd", "CVE-2026-1557", [])
        b = query_id_for("t", "nvd", "CVE-2026-1558", [])
        self.assertNotEqual(a, b)

    def test_input_order_does_not_change_id(self):
        a = query_id_for("t", "nvd", "q", ["x", "y", "x"])
        b = query_id_for("t", "nvd", "q", ["y", "x"])
        self.assertEqual(a, b)  # deduplicated + sorted


class TestQuerySanitization(unittest.TestCase):
    def test_control_chars_removed(self):
        self.assertEqual(sanitize_query("CVE-2026-1557\t\x00\n advisory"), "CVE-2026-1557 advisory")

    def test_whitespace_collapsed(self):
        self.assertEqual(sanitize_query("  a    b  c  "), "a b c")

    def test_quotes_removed(self):
        self.assertNotIn('"', sanitize_query('CVE-2026-1557 "foo"'))
        self.assertNotIn("'", sanitize_query("CVE-2026-1557 'foo'"))
        self.assertNotIn("\\", sanitize_query("CVE-2026-1557\\x"))

    def test_two_hundred_char_bound(self):
        long = "CVE-2026-1557 " + "product-" * 60
        result = sanitize_query(long)
        self.assertLessEqual(len(result), MAX_QUERY_CHARS)
        self.assertEqual(MAX_QUERY_CHARS, 200)

    def test_none_and_empty(self):
        self.assertEqual(sanitize_query(None), "")
        self.assertEqual(sanitize_query(""), "")


class TestCveIdNormalization(unittest.TestCase):
    def test_normalized(self):
        self.assertEqual(normalize_cve_id("cve-2026-1557"), "CVE-2026-1557")

    def test_invalid_empty(self):
        self.assertEqual(normalize_cve_id("not-a-cve"), "")
        self.assertEqual(normalize_cve_id("CVE-20"), "")


class TestQueryBuilderDeterminism(unittest.TestCase):
    def setUp(self):
        self.qb = QueryBuilder()

    def test_deterministic_rendering(self):
        md = CVEResearchMetadata(
            cve_id="CVE-2026-1557",
            product="WordPress Plugin",
            component="foo-forms",
            version="1.2.3",
            cwe="CWE-79",
            vulnerability_type="XSS",
        )
        a = self.qb.build_queries(md)
        b = self.qb.build_queries(md)
        self.assertEqual([q.query_id for q in a], [q.query_id for q in b])
        self.assertEqual([q.query for q in a], [q.query for q in b])
        self.assertEqual([q.inputs_used for q in a], [q.inputs_used for q in b])

    def test_fixed_template_order_and_ids(self):
        md = CVEResearchMetadata(cve_id="CVE-2026-1557")
        qs = self.qb.build_queries(md)
        # templates whose only required input is cve_id
        expected = [
            "r24-cve-id",
            "r24-cve-advisory",
            "r24-cve-vendor",
            "r24-cve-poc",
            "r24-cve-exploit",
            "r24-cve-detection",
        ]
        self.assertEqual([q.template_id for q in qs], expected)
        self.assertEqual(qs[0].template_id, TEMPLATE_CVE_ID)
        self.assertEqual(qs[0].query, "CVE-2026-1557")
        self.assertEqual(qs[0].inputs_used, ["CVE-2026-1557"])

    def test_unique_query_ids(self):
        md = CVEResearchMetadata(cve_id="CVE-2026-1557", product="p", version="1.0")
        qs = self.qb.build_queries(md)
        ids = [q.query_id for q in qs]
        self.assertEqual(len(ids), len(set(ids)))


class TestAllowedInputs(unittest.TestCase):
    def test_all_allowed_fields_render(self):
        md = CVEResearchMetadata(
            cve_id="CVE-2026-1557",
            product="WordPress Plugin",
            component="foo-forms",
            parameter="page",
            version="1.2.3",
            cwe="CWE-79",
            vulnerability_type="XSS",
            existing_references=("https://nvd.nist.gov/x",),
        )
        qs = QueryBuilder().build_queries(md)
        self.assertEqual(len(qs), 12)
        text = " ".join(q.query for q in qs)
        for token in ("CVE-2026-1557", "WordPress Plugin", "foo-forms", "1.2.3", "CWE-79", "XSS"):
            self.assertIn(token, text)

    def test_structurally_rejects_forbidden_fields(self):
        # program/target/asset have no representation on the dataclass.
        with self.assertRaises(TypeError):
            CVEResearchMetadata(cve_id="CVE-2026-1557", program="dell")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            CVEResearchMetadata(cve_id="CVE-2026-1557", target_url="https://dell.com")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            CVEResearchMetadata(cve_id="CVE-2026-1557", headers={"x": "y"})  # type: ignore[call-arg]


class TestForbiddenInputInvariant(unittest.TestCase):
    def test_contains_token_whole_word(self):
        self.assertTrue(contains_forbidden_token("dell advisory", ["dell"]))
        self.assertFalse(contains_forbidden_token("medellin", ["dell"]))

    def test_host_labels_without_tld(self):
        self.assertTrue(
            contains_forbidden_token("CVE-2026-1557 www.dell.com bulletins", ["dell.com"])
        )
        self.assertTrue(contains_forbidden_token("dell security", ["www.dell.com"]))

    def test_tld_not_forbidden(self):
        self.assertFalse(contains_forbidden_token("github.com advisory", ["dell.com"]))

    def test_ip_exact_only(self):
        self.assertTrue(contains_forbidden_token("server at 192.168.1.1", ["192.168.1.1"]))
        # numeric octets are not standalone tokens (no false positives on a
        # version like 1.2.3).
        self.assertFalse(contains_forbidden_token("1.2.3", ["192.168.1.1"]))

    def test_assert_raises(self):
        with self.assertRaises(ForbiddenInputError):
            assert_no_forbidden_input("dell.com host", ["dell.com"])
        assert_no_forbidden_input("CVE-2026-1557", ["dell.com"])  # no raise

    def test_builder_rejects_forbidden_product(self):
        qb = QueryBuilder(forbidden_tokens=["dell.com", "dell"])
        bad = CVEResearchMetadata(cve_id="CVE-2026-1557", product="dell-adapter")
        with self.assertRaises(ForbiddenInputError):
            qb.build_queries(bad)

    def test_no_target_host_leakage(self):
        qb = QueryBuilder(forbidden_tokens=["dell.com", "dell", "192.168.1.1"])
        md = CVEResearchMetadata(
            cve_id="CVE-2026-1557",
            product="WordPress Plugin",
            version="1.2.3",
            parameter="page",
        )
        qs = qb.build_queries(md)
        for q in qs:
            for itok in ("dell.com", "dell", "192.168.1.1"):
                self.assertNotIn(itok, q.query.lower())
            self.assertFalse(contains_forbidden_token(q.query, qb.forbidden_tokens))
class TestDuplicateNormalization(unittest.TestCase):
    def test_reference_dedup_order_preserved(self):
        md = CVEResearchMetadata(
            cve_id="CVE-2026-1557",
            existing_references=("https://a.io/1", "https://b.io/2", "https://a.io/1"),
        )
        builder = QueryBuilder()
        self.assertEqual(
            builder._clean(md)["existing_references"],
            ("https://a.io/1", "https://b.io/2"),
        )

    def test_inputs_used_sorted_deduped(self):
        md = CVEResearchMetadata(cve_id="CVE-2026-1557", product="b", component="a")
        qs = QueryBuilder().build_queries(md)
        product_cve = next(q for q in qs if q.template_id == "r24-product-cve")
        self.assertEqual(product_cve.inputs_used, ["CVE-2026-1557", "b"])


class TestEmptyInvalidMetadata(unittest.TestCase):
    def test_empty_metadata_yields_no_queries(self):
        self.assertEqual(QueryBuilder().build_queries(CVEResearchMetadata()), [])

    def test_invalid_cve_skips(self):
        md = CVEResearchMetadata(cve_id="garbage", product="p", component="c")
        qs = QueryBuilder().build_queries(md)
        for q in qs:
            self.assertNotEqual(q.template_id, TEMPLATE_CVE_ID)
        self.assertEqual([q.template_id for q in qs], ["r24-product-component-nuclei"])

    def test_partial_metadata_degrades_gracefully(self):
        md = CVEResearchMetadata(cve_id="CVE-2026-1557")
        qs = QueryBuilder().build_queries(md)
        self.assertEqual(
            [q.template_id for q in qs],
            [
                "r24-cve-id",
                "r24-cve-advisory",
                "r24-cve-vendor",
                "r24-cve-poc",
                "r24-cve-exploit",
                "r24-cve-detection",
            ],
        )


class TestSchemaSerialization(unittest.TestCase):
    def test_discovery_query_roundtrip(self):
        q = DiscoveryQuery(
            query_id="q" + "0" * 16,
            template_id=TEMPLATE_CVE_ID,
            provider="nvd",
            query="CVE-2026-1557",
            inputs_used=["CVE-2026-1557"],
        )
        data = json.loads(q.model_dump_json())
        self.assertEqual(data["query_id"], q.query_id)
        self.assertIs(data["production_finding"], False)

    def test_discovered_source_roundtrip(self):
        s = DiscoveredSource(
            source_id=discovered_source_id("https://NVD.NIST.gov/vuln/detail/CVE-2026-1557"),
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            category=SourceCategory.NVD_CVE,
            tier=TrustTier.TRUSTED,
            source_quality=0.9,
            lifecycle=Lifecycle.FETCHED_SOURCE,
            final_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            redirect_chain=["https://nvd.nist.gov/vuln/detail/CVE-2026-1557"],
            extraction_method="html_text",
        )
        self.assertTrue(s.source_id.startswith(SOURCE_ID_PREFIX))
        data = json.loads(s.model_dump_json())
        self.assertEqual(data["category"], "nvd_cve")
        self.assertEqual(data["tier"], "TRUSTED")
        self.assertEqual(data["lifecycle"], "FETCHED_SOURCE")
        self.assertIs(data["production_finding"], False)

    def test_source_id_deterministic(self):
        self.assertEqual(
            discovered_source_id("https://nvd.nist.gov/vuln/x"),
            discovered_source_id("https://nvd.nist.gov/vuln/x"),
        )

    def test_source_quality_bounded(self):
        with self.assertRaises(ValidationError):
            DiscoveredSource(source_id="x", url="u", source_quality=1.5)

    def test_query_with_quotes_rejected(self):
        with self.assertRaises(ValidationError):
            DiscoveryQuery(
                query_id="q" + "0" * 16,
                template_id=TEMPLATE_CVE_ID,
                provider="nvd",
                query='CVE-2026-1557 "x"',
            )
class TestProductionFindingSafety(unittest.TestCase):
    def test_source_pf_forced_false(self):
        s = DiscoveredSource(source_id="x", url="u")
        self.assertFalse(s.production_finding)
        with self.assertRaises(ValidationError):
            DiscoveredSource(source_id="x", url="u", production_finding=True)

    def test_query_pf_forced_false(self):
        q = DiscoveryQuery(query_id="a", template_id="t", provider="nvd")
        self.assertFalse(q.production_finding)

    def test_forbidden_result_states_absent(self):
        # The forbidden verdict terms must never appear as an affirmative state
        # value. Field *names* such as ``production_finding`` legitimately
        # contain "FINDING", so we check the state-valued fields, not raw JSON.
        s = DiscoveredSource(source_id="x", url="u")
        for field in (s.status, s.lifecycle.value, s.category.value, s.tier.value):
            self.assertNotIn(field, ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING"))
        q = DiscoveryQuery(query_id="a", template_id="t", provider="nvd")
        self.assertFalse(s.production_finding)
        self.assertFalse(q.production_finding)


class TestImportBoundary(unittest.TestCase):
    def _import_lines(self):
        root = Path("/opt/watch/ai/research_agent")
        pattern = re.compile(
            r"^(import [a-z0-9_\.]+(?:[ ]|$)|from [a-z0-9_\.]+ import )"
        )
        lines = []
        for name in ("discovery_contract.py", "queries.py"):
            for line in (root / name).read_text(encoding="utf-8").splitlines():
                stripped = line.strip().lower()
                if pattern.match(stripped):
                    lines.append(stripped)
        return "\n".join(lines)

    def test_no_forbidden_imports(self):
        text = self._import_lines()
        needles = [
            "ai.execution", "ai.verification", "ai.finding", "ai.resolver",
            "ai.authorizer", "ai.persistence", "nuclei_runner", "selenium",
            "playwright", "pyppeteer", "subprocess", "requests", "httpx",
            "socket", "urllib",
        ]
        for needle in needles:
            self.assertNotIn(needle, text, f"forbidden import present: {needle}")

    def test_allowed_imports_only(self):
        # Only stdlib + the neutral R23 schema/helpers + the sibling contract.
        allowed_prefixes = (
            "from __future__",
            "import hashlib",
            "import re",
            "from enum",
            "from typing",
            "from dataclasses",
            "from types",
            "from pydantic",
            "from ai.collectors.body_extraction",
            "from ai.researcher.reference_cache",
            "from ai.schemas.research_agent",
            "from ai.research_agent.discovery_contract",
        )
        for line in self._import_lines().splitlines():
            self.assertTrue(
                any(line.startswith(p) for p in allowed_prefixes),
                f"unexpected import: {line}",
            )

    def test_no_eval_or_exec(self):
        combined = ""
        root = Path("/opt/watch/ai/research_agent")
        for name in ("discovery_contract.py", "queries.py"):
            # ignore docstring prose mentions of exec/eval by removing strings
            combined += (root / name).read_text(encoding="utf-8")
        # Only actual calls (paren) matter; docstrings mention them in prose.
        for token in ("eval(", "exec(", "os.system("):
            self.assertNotIn(token, combined)


class TestR23Compatibility(unittest.TestCase):
    def test_to_r23_preserves_identity_status(self):
        s = DiscoveredSource(
            source_id="ds-abc",
            url="https://nvd.nist.gov/vuln/1",
            source_type="nvd",
            status=SOURCE_STORED_ONLY,
            final_url="https://nvd.nist.gov/vuln/1",
        )
        r23 = s.to_r23()
        self.assertIsInstance(r23, ResearchAgentSource)
        self.assertEqual(r23.source_id, "ds-abc")
        self.assertEqual(r23.url, "https://nvd.nist.gov/vuln/1")
        self.assertEqual(r23.status, SOURCE_STORED_ONLY)
        self.assertEqual(r23.source_type, "nvd")

    def test_status_uses_r23_vocabulary(self):
        s = DiscoveredSource(source_id="x", url="u")
        self.assertIn(s.status, SOURCE_STATES)
        with self.assertRaises(ValidationError):
            DiscoveredSource(source_id="x", url="u", status="BOGUS")


if __name__ == "__main__":
    unittest.main()
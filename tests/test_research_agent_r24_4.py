"""tests/test_research_agent_r24_4.py — Stage R24.4 ranking & dedup tests.

Offline, deterministic, network-free. Covers:

- exact tier base / category bonus / signal bonus / penalty values
- clamp at 0 and 200, source_quality calculation, deterministic scoring
- no program/asset influence
- deterministic ordering incl. tier / canonical-url / source-id tie-breaks
- URL canonicalization (whitespace, scheme/host case, fragment, default
  ports, utm_*/gclid/fbclid, non-tracking params, deterministic query order,
  GitHub blob/raw mapping)
- URL dedup (same canonical URL merges; meaningful URLs stay separate)
- content dedup (same hash merges, different hash separate, existing hash
  reused, no fetch, canonical selection by tier/quality/url/id, aliases and
  discovered_via/provenance preserved, deterministic alias ordering)
- evidence eligibility predicate
- schema safety (production_finding stays False, no target fields)
- import boundary (no 5B-5J, no network, no subprocess/eval/exec)
- R23 / R24.1 / R24.2 / R24.3 compatibility

No network, no LLM, no Mongo, no subprocess.
"""
import ast
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    Lifecycle,
    SearchProvider,
    SourceCategory,
    TrustTier,
    discovered_source_id,
)
from ai.research_agent.dedup import (
    DEFAULT_PORTS,
    TIER_ORDER,
    canonical_url,
    canonicalize_url,
    content_hash_for,
    dedup_by_content_hash,
    dedup_by_url,
    dedup_discovered_sources,
    github_raw_url,
    provenance_ledger,
    with_content_hash,
)
from ai.research_agent.ranking import (
    AGGREGATOR_HOSTS,
    CATEGORY_BONUS,
    EVIDENCE_FLOOR,
    MAX_SCORE,
    PENALTY_AGGREGATOR,
    PENALTY_GENERIC_NO_CORROBORATION,
    SIGNAL_CANONICAL_ADVISORY,
    SIGNAL_COMPONENT,
    SIGNAL_CWE,
    SIGNAL_EXACT_CVE,
    SIGNAL_PRODUCT,
    SIGNAL_VERSION,
    TIER_BASE,
    authoritative_advisory_reference,
    is_evidence_eligible,
    rank_sources,
    score_breakdown,
    score_source,
    tier_rank,
)
from ai.research_agent.queries import (
    CVEResearchMetadata,
    QueryBuilder,
)

META = CVEResearchMetadata(
    cve_id="CVE-2026-1557",
    product="Responsive Images",
    component="image_handler.php",
    version="1.0",
    cwe="CWE-79",
    vulnerability_type="reflected xss",
)


def mk(
    url,
    *,
    category=SourceCategory.GENERIC_SEARCH,
    tier=TrustTier.GENERIC,
    source_id=None,
    title=None,
    content_hash=None,
    source_quality=0.0,
    provider="",
    query="",
    template="",
    final_url=None,
    redirect_chain=None,
    aliases=None,
    note="",
    lifecycle=Lifecycle.DISCOVERED_SOURCE,
):
    return DiscoveredSource(
        source_id=source_id or discovered_source_id(url),
        url=url,
        category=category,
        tier=tier,
        title=title,
        content_hash=content_hash,
        source_quality=source_quality,
        discovery_provider=provider,
        discovery_query=query,
        discovery_template_id=template,
        final_url=final_url,
        redirect_chain=list(redirect_chain or []),
        aliases=list(aliases or []),
        note=note,
        lifecycle=lifecycle,
    )


def _highest_source():
    return mk(
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        title="Responsive Images image_handler.php CWE-79 1.0",
    )


class TestRankingTables(unittest.TestCase):
    def test_exact_tier_base_values(self):
        self.assertEqual(
            TIER_BASE,
            {
                TrustTier.TRUSTED: 100,
                TrustTier.SEMI_TRUSTED: 70,
                TrustTier.DISCOVERY_ONLY: 40,
                TrustTier.GENERIC: 10,
            },
        )

    def test_exact_category_bonus_values(self):
        self.assertEqual(
            CATEGORY_BONUS,
            {
                SourceCategory.NVD_CVE: 30,
                SourceCategory.VENDOR_ADVISORY: 30,
                SourceCategory.GITHUB_ADVISORY: 25,
                SourceCategory.WORDFENCE: 15,
                SourceCategory.WPSCAN: 15,
                SourceCategory.DETECTION_RULE: 10,
                SourceCategory.EXPLOIT_REFERENCE: 5,
                SourceCategory.WRITEUP: 0,
                SourceCategory.SECURITY_BLOG: 0,
                SourceCategory.GITHUB_REPO: 0,
                SourceCategory.GENERIC_SEARCH: 0,
            },
        )

    def test_exact_signal_values(self):
        source = _highest_source()
        breakdown = score_breakdown(source, META)
        self.assertEqual(breakdown.components["exact_cve_id"], SIGNAL_EXACT_CVE)
        self.assertEqual(breakdown.components["product_match"], SIGNAL_PRODUCT)
        self.assertEqual(breakdown.components["component_match"], SIGNAL_COMPONENT)
        self.assertEqual(breakdown.components["cwe_match"], SIGNAL_CWE)
        self.assertEqual(breakdown.components["version_match"], SIGNAL_VERSION)
        self.assertEqual(
            breakdown.components["canonical_advisory"], SIGNAL_CANONICAL_ADVISORY
        )

    def test_exact_penalty_values(self):
        aggregator = mk("https://cvedetails.com/CVE-2026-1")
        breakdown = score_breakdown(aggregator)
        self.assertEqual(breakdown.components["aggregator"], PENALTY_AGGREGATOR)
        generic = mk("https://example.org/x")
        breakdown = score_breakdown(generic)
        self.assertEqual(
            breakdown.components["generic_uncorroborated"],
            PENALTY_GENERIC_NO_CORROBORATION,
        )

    def test_aggregator_hosts_are_documented(self):
        self.assertIn("cvedetails.com", AGGREGATOR_HOSTS)
        self.assertNotIn("example.org", AGGREGATOR_HOSTS)

    def test_tier_rank_ordering(self):
        self.assertLess(tier_rank(TrustTier.TRUSTED), tier_rank(TrustTier.SEMI_TRUSTED))
        self.assertLess(
            tier_rank(TrustTier.SEMI_TRUSTED), tier_rank(TrustTier.DISCOVERY_ONLY)
        )
        self.assertLess(
            tier_rank(TrustTier.DISCOVERY_ONLY), tier_rank(TrustTier.GENERIC)
        )


class TestRankingClampAndQuality(unittest.TestCase):
    def test_clamp_at_zero(self):
        breakdown = score_breakdown(mk("https://cvedetails.com/CVE-2026-1"))
        self.assertLess(breakdown.raw_score, 0)
        self.assertEqual(breakdown.score, 0)

    def test_clamp_at_two_hundred(self):
        breakdown = score_breakdown(_highest_source(), META)
        self.assertGreater(breakdown.raw_score, MAX_SCORE)
        self.assertEqual(breakdown.score, MAX_SCORE)

    def test_source_quality_calculation(self):
        top = score_breakdown(_highest_source(), META)
        self.assertEqual(top.score, 200)
        self.assertEqual(top.source_quality, 1.0)
        bottom = score_breakdown(mk("https://cvedetails.com/CVE-2026-1"))
        self.assertEqual(bottom.source_quality, 0.0)
        # literal spec formula
        self.assertEqual(
            top.source_quality, round(top.score / MAX_SCORE, 2)
        )
        self.assertEqual(
            bottom.source_quality, round(bottom.score / MAX_SCORE, 2)
        )

    def test_deterministic_scoring(self):
        a = score_breakdown(_highest_source(), META)
        b = score_breakdown(_highest_source(), META)
        self.assertEqual(a.score, b.score)
        self.assertEqual(a.source_quality, b.source_quality)
        self.assertEqual(a.components, b.components)

    def test_metadata_has_no_program_or_asset_fields(self):
        fields = set(CVEResearchMetadata.__dataclass_fields__)
        for forbidden in (
            "program",
            "target",
            "asset",
            "target_url",
            "target_host",
            "target_ip",
            "endpoint",
            "response",
            "credentials",
            "cookies",
            "headers",
        ):
            self.assertNotIn(forbidden, fields)

    def test_score_source_rejects_program_kwarg(self):
        with self.assertRaises(TypeError):
            score_source(mk("https://x.example/a"), program="x")


class TestDeterministicOrdering(unittest.TestCase):
    def test_ordering_is_independent_of_input_order(self):
        a = mk("https://a.example/1", tier=TrustTier.DISCOVERY_ONLY)
        b = mk("https://b.example/2", tier=TrustTier.TRUSTED)
        c = mk("https://c.example/3", tier=TrustTier.GENERIC)
        r1 = [s.source_id for s in rank_sources([a, b, c])]
        r2 = [s.source_id for s in rank_sources([c, b, a])]
        r3 = [s.source_id for s in rank_sources([b, a, c])]
        self.assertEqual(r1, r2)
        self.assertEqual(r1, r3)

    def test_tier_ordering_on_score_tie(self):
        # TRUSTED + WRITEUP (no signals) == 100.
        trusted = mk(
            "https://trusted.example/x",
            category=SourceCategory.WRITEUP,
            tier=TrustTier.TRUSTED,
        )
        # SEMI_TRUSTED + product/component/cwe/version signals == 100.
        semi = mk(
            "https://semi.example/x",
            category=SourceCategory.GENERIC_SEARCH,
            tier=TrustTier.SEMI_TRUSTED,
            title="Responsive Images CWE-79 1.0",
        )
        meta = CVEResearchMetadata(
            product="Responsive Images",
            version="1.0",
            cwe="CWE-79",
        )
        self.assertEqual(score_source(trusted, meta), 100)
        self.assertEqual(score_source(semi, meta), 100)
        ranked = rank_sources([semi, trusted], meta)
        self.assertEqual(ranked[0].tier, TrustTier.TRUSTED)
        self.assertEqual(ranked[1].tier, TrustTier.SEMI_TRUSTED)

    def test_canonical_url_tiebreak(self):
        src_b = mk("https://b.example/x")
        src_a = mk("https://a.example/x")
        self.assertEqual(score_source(src_a), score_source(src_b))
        ranked = rank_sources([src_b, src_a])
        self.assertEqual(
            [canonical_url(s) for s in ranked],
            ["https://a.example/x", "https://b.example/x"],
        )

    def test_source_id_tiebreak(self):
        url = "https://same.example/x"
        src_2 = mk(url, source_id="ds-2222222222222222")
        src_1 = mk(url, source_id="ds-1111111111111111")
        self.assertEqual(canonical_url(src_1), canonical_url(src_2))
        ranked = rank_sources([src_2, src_1])
        self.assertEqual(
            [s.source_id for s in ranked],
            ["ds-1111111111111111", "ds-2222222222222222"],
        )

    def test_rank_assigns_source_quality(self):
        ranked = rank_sources([_highest_source()], META)
        self.assertEqual(ranked[0].source_quality, 1.0)


class TestUrlCanonicalization(unittest.TestCase):
    def test_trim_whitespace(self):
        self.assertEqual(
            canonicalize_url("  https://example.com/a  "), "https://example.com/a"
        )

    def test_scheme_and_host_lowercased(self):
        self.assertEqual(
            canonicalize_url("HTTPS://Example.COM/Path"), "https://example.com/Path"
        )

    def test_fragment_removed(self):
        self.assertEqual(
            canonicalize_url("https://example.com/a#section"), "https://example.com/a"
        )

    def test_default_ports_removed(self):
        self.assertEqual(
            canonicalize_url("https://example.com:443/a"), "https://example.com/a"
        )
        self.assertEqual(
            canonicalize_url("http://example.com:80/a"), "http://example.com/a"
        )

    def test_non_default_port_kept(self):
        self.assertEqual(
            canonicalize_url("https://example.com:8443/a"),
            "https://example.com:8443/a",
        )

    def test_tracking_params_removed(self):
        for name in ("utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid"):
            url = f"https://example.com/a?keep=1&{name}=x"
            self.assertEqual(canonicalize_url(url), "https://example.com/a?keep=1")

    def test_non_tracking_params_preserved(self):
        self.assertEqual(
            canonicalize_url("https://example.com/a?id=5&page=2"),
            "https://example.com/a?id=5&page=2",
        )

    def test_deterministic_query_ordering(self):
        self.assertEqual(
            canonicalize_url("https://example.com/a?b=2&a=1"),
            canonicalize_url("https://example.com/a?a=1&b=2"),
        )
        self.assertEqual(
            canonicalize_url("https://example.com/a?b=2&a=1"),
            "https://example.com/a?a=1&b=2",
        )

    def test_credentials_dropped(self):
        self.assertEqual(
            canonicalize_url("https://user:pass@example.com/a"),
            "https://example.com/a",
        )

    def test_github_blob_and_raw_mapping(self):
        expected = "https://raw.githubusercontent.com/o/r/main/a/b.py"
        self.assertEqual(
            canonicalize_url("https://github.com/o/r/blob/main/a/b.py"), expected
        )
        self.assertEqual(
            canonicalize_url("https://github.com/o/r/raw/main/a/b.py"), expected
        )
        self.assertEqual(github_raw_url("https://github.com/o/r/blob/main/a/b.py"), expected)
        # Non-blob github paths are untouched.
        self.assertEqual(
            canonicalize_url("https://github.com/o/r/pull/1"),
            "https://github.com/o/r/pull/1",
        )

    def test_github_blob_matches_equivalent_raw(self):
        self.assertEqual(
            canonicalize_url("https://github.com/o/r/blob/main/a/b.py"),
            canonicalize_url("https://raw.githubusercontent.com/o/r/main/a/b.py"),
        )

    def test_malformed_input_does_not_raise(self):
        self.assertEqual(canonicalize_url(""), "")
        self.assertEqual(canonicalize_url(None), "")
        self.assertEqual(canonicalize_url("not a url"), "not a url")

    def test_default_ports_table(self):
        self.assertEqual(DEFAULT_PORTS["http"], "80")
        self.assertEqual(DEFAULT_PORTS["https"], "443")


class TestUrlDedup(unittest.TestCase):
    def test_same_canonical_url_merges(self):
        a = mk("https://example.com/a?utm_source=x")
        b = mk("https://EXAMPLE.com:443/a#frag")
        merged = dedup_by_url([a, b])
        self.assertEqual(len(merged), 1)

    def test_different_meaningful_urls_stay_separate(self):
        a = mk("https://example.com/a")
        b = mk("https://example.com/b")
        self.assertEqual(len(dedup_by_url([a, b])), 2)

    def test_url_dedup_deterministic_regardless_of_order(self):
        a = mk("https://example.com/a?utm_source=x")
        b = mk("https://example.com/a")
        self.assertEqual(
            [s.source_id for s in dedup_by_url([a, b])],
            [s.source_id for s in dedup_by_url([b, a])],
        )

    def test_single_source_passthrough(self):
        a = mk("https://example.com/a")
        self.assertEqual(dedup_by_url([a]), [a])


class TestContentDedup(unittest.TestCase):
    def test_same_hash_merges(self):
        a = mk("https://example.com/a", content_hash="h1")
        b = mk("https://example.com/b", content_hash="h1")
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(len(merged), 1)

    def test_different_hash_stays_separate(self):
        a = mk("https://example.com/a", content_hash="h1")
        b = mk("https://example.com/b", content_hash="h2")
        self.assertEqual(len(dedup_by_content_hash([a, b])), 2)

    def test_content_dedup_keeps_unhashed(self):
        a = mk("https://example.com/a", content_hash="h1")
        b = mk("https://example.com/b")
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(len(merged), 2)

    def test_existing_content_hash_is_reused(self):
        src = mk("https://example.com/a", content_hash="trusted")
        result = with_content_hash(src, "entirely different body")
        self.assertIs(result, src)
        self.assertEqual(result.content_hash, "trusted")

    def test_content_hash_for_is_deterministic(self):
        self.assertEqual(content_hash_for("hello world"), content_hash_for("hello   world"))
        self.assertIsNone(content_hash_for(""))
        self.assertIsNone(content_hash_for("   "))

    def test_canonical_selected_by_tier(self):
        low = mk(
            "https://b.example/x",
            content_hash="h1",
            tier=TrustTier.GENERIC,
            source_quality=0.9,
        )
        high = mk(
            "https://a.example/x",
            content_hash="h1",
            tier=TrustTier.TRUSTED,
            source_quality=0.1,
        )
        merged = dedup_by_content_hash([low, high])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].tier, TrustTier.TRUSTED)

    def test_canonical_selected_by_quality(self):
        low = mk(
            "https://a.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.2,
        )
        high = mk(
            "https://b.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.9,
        )
        merged = dedup_by_content_hash([low, high])
        self.assertEqual(merged[0].source_quality, 0.9)

    def test_canonical_selected_by_canonical_url(self):
        a = mk(
            "https://b.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.5,
        )
        b = mk(
            "https://a.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.5,
        )
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(canonical_url(merged[0]), "https://a.example/x")

    def test_canonical_selected_by_source_id(self):
        a = mk(
            "https://same.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.5,
            source_id="ds-bbbbbbbbbbbbbbbb",
        )
        b = mk(
            "https://same.example/x",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            source_quality=0.5,
            source_id="ds-aaaaaaaaaaaaaaaa",
        )
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(merged[0].source_id, "ds-aaaaaaaaaaaaaaaa")

    def test_aliases_preserved_and_sorted(self):
        a = mk("https://example.com/a", content_hash="h1")
        b = mk("https://example.com/b", content_hash="h1")
        c = mk("https://example.com/c", content_hash="h1")
        merged = dedup_by_content_hash([a, b, c])
        self.assertEqual(len(merged), 1)
        self.assertEqual(
            merged[0].aliases,
            ["https://example.com/b", "https://example.com/c"],
        )
        self.assertEqual(merged[0].aliases, sorted(merged[0].aliases))

    def test_provenance_and_discovered_via_preserved(self):
        a = mk(
            "https://example.com/a",
            content_hash="h1",
            tier=TrustTier.SEMI_TRUSTED,
            provider="nvd",
            template="r24-cve-id",
            query="CVE-2026-1557",
            source_quality=0.9,
        )
        b = mk(
            "https://example.com/b",
            content_hash="h1",
            provider="github_search",
            template="r24-cve-poc",
            query="CVE-2026-1557 PoC",
        )
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(len(merged), 1)
        self.assertIn("discovered_via=", merged[0].note)
        self.assertIn("provider=github_search", merged[0].note)
        self.assertIn("provider=nvd", merged[0].note)
        self.assertIn("query=CVE-2026-1557 PoC", merged[0].note)

    def test_provenance_ledger_is_sorted_and_deduped(self):
        a = mk("https://example.com/a", provider="nvd", query="q")
        b = mk("https://example.com/a", provider="nvd", query="q")
        ledger = provenance_ledger([a, b])
        self.assertEqual(ledger, sorted(set(ledger)))
        self.assertEqual(len(ledger), 1)

    def test_redirect_chain_preserved(self):
        a = mk(
            "https://example.com/final",
            content_hash="h1",
            tier=TrustTier.TRUSTED,
            redirect_chain=["https://example.com/start", "https://example.com/final"],
        )
        b = mk("https://example.com/other", content_hash="h1")
        merged = dedup_by_content_hash([a, b])
        self.assertIn("https://example.com/start", merged[0].redirect_chain)

    def test_full_two_level_dedup(self):
        # URL duplicates + content duplicates resolve to one source.
        a = mk("https://example.com/a?utm_source=x", content_hash="h1")
        b = mk("https://EXAMPLE.com:443/a#f", content_hash="h1")
        c = mk("https://example.com/b", content_hash="h1")
        merged = dedup_discovered_sources([a, b, c])
        self.assertEqual(len(merged), 1)

    def test_content_dedup_deterministic_regardless_of_order(self):
        a = mk("https://a.example/x", content_hash="h1", tier=TrustTier.SEMI_TRUSTED)
        b = mk("https://b.example/x", content_hash="h1", tier=TrustTier.SEMI_TRUSTED)
        r1 = [s.source_id for s in dedup_by_content_hash([a, b])]
        r2 = [s.source_id for s in dedup_by_content_hash([b, a])]
        self.assertEqual(r1, r2)

    def test_no_network_occurs_during_dedup(self):
        a = mk("https://example.com/a", content_hash="h1")
        b = mk("https://example.com/b", content_hash="h1")
        with mock.patch("socket.socket", side_effect=AssertionError("network access")):
            merged = dedup_discovered_sources([a, b])
        self.assertEqual(len(merged), 1)


class TestEvidenceEligibility(unittest.TestCase):
    def _eligible(self, tier, category, quality=0.9):
        return mk(
            "https://example.com/x",
            tier=tier,
            category=category,
            source_quality=quality,
            content_hash="h1",
        )

    def test_trusted_with_hash_and_quality_is_eligible(self):
        self.assertTrue(
            is_evidence_eligible(
                self._eligible(TrustTier.TRUSTED, SourceCategory.NVD_CVE)
            )
        )

    def test_semi_trusted_with_hash_and_quality_is_eligible(self):
        self.assertTrue(
            is_evidence_eligible(
                self._eligible(TrustTier.SEMI_TRUSTED, SourceCategory.WORDFENCE)
            )
        )

    def test_generic_never_eligible(self):
        self.assertFalse(
            is_evidence_eligible(
                self._eligible(TrustTier.GENERIC, SourceCategory.GENERIC_SEARCH, 1.0)
            )
        )

    def test_below_floor_not_eligible(self):
        self.assertFalse(
            is_evidence_eligible(
                self._eligible(
                    TrustTier.TRUSTED, SourceCategory.NVD_CVE, quality=0.44
                )
            )
        )
        self.assertEqual(EVIDENCE_FLOOR, 0.45)

    def test_missing_content_hash_not_eligible(self):
        src = mk(
            "https://example.com/x",
            tier=TrustTier.TRUSTED,
            category=SourceCategory.NVD_CVE,
            source_quality=0.9,
            content_hash=None,
        )
        self.assertFalse(is_evidence_eligible(src))

    def test_discovery_only_detection_rule_without_advisory_not_eligible(self):
        src = mk(
            "https://github.com/o/r/blob/main/rules/x.yaml",
            tier=TrustTier.DISCOVERY_ONLY,
            category=SourceCategory.DETECTION_RULE,
            source_quality=0.9,
            content_hash="h1",
        )
        self.assertIsNone(authoritative_advisory_reference(src))
        self.assertFalse(is_evidence_eligible(src))

    def test_discovery_only_detection_rule_with_explicit_advisory_eligible(self):
        src = mk(
            "https://github.com/o/r/blob/main/rules/x.yaml",
            tier=TrustTier.DISCOVERY_ONLY,
            category=SourceCategory.DETECTION_RULE,
            source_quality=0.9,
            content_hash="h1",
        )
        self.assertTrue(
            is_evidence_eligible(src, advisory_reference="CVE-2026-1557")
        )

    def test_discovery_only_with_advisory_in_text_eligible(self):
        src = mk(
            "https://github.com/o/r/blob/main/rules/CVE-2026-1557.yaml",
            tier=TrustTier.DISCOVERY_ONLY,
            category=SourceCategory.DETECTION_RULE,
            source_quality=0.9,
            content_hash="h1",
        )
        self.assertEqual(authoritative_advisory_reference(src), "CVE-2026-1557")
        self.assertTrue(is_evidence_eligible(src))

    def test_evidence_predicate_does_not_set_production_finding(self):
        src = self._eligible(TrustTier.TRUSTED, SourceCategory.NVD_CVE)
        is_evidence_eligible(src)
        self.assertFalse(src.production_finding)


class TestSchemaSafety(unittest.TestCase):
    def test_discovered_source_has_no_target_fields(self):
        fields = set(DiscoveredSource.model_fields)
        for forbidden in (
            "program",
            "target",
            "asset",
            "target_url",
            "target_host",
            "target_ip",
            "endpoint",
            "response",
            "credentials",
            "cookies",
            "headers",
        ):
            self.assertNotIn(forbidden, fields)

    def test_production_finding_stays_false_through_pipeline(self):
        sources = [
            mk("https://a.example/x", content_hash="h1", tier=TrustTier.TRUSTED),
            mk("https://b.example/x", content_hash="h1", tier=TrustTier.SEMI_TRUSTED),
            mk("https://cvedetails.com/CVE-2026-1"),
        ]
        ranked = rank_sources(sources, META)
        merged = dedup_discovered_sources(ranked)
        for source in ranked + merged:
            self.assertFalse(source.production_finding)

    def test_lifecycle_preserved_by_dedup(self):
        a = mk("https://example.com/a", content_hash="h1", lifecycle=Lifecycle.FETCHED_SOURCE)
        b = mk("https://example.com/b", content_hash="h1", lifecycle=Lifecycle.FETCHED_SOURCE)
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(merged[0].lifecycle, Lifecycle.FETCHED_SOURCE)


class TestImportBoundary(unittest.TestCase):
    NEW_MODULES = (
        Path("/opt/watch/ai/research_agent/ranking.py"),
        Path("/opt/watch/ai/research_agent/dedup.py"),
    )

    def _imported_modules(self, path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".")[0])
                    roots.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    roots.add(node.module.split(".")[0])
                    roots.add(node.module)
        return roots

    def test_no_forbidden_imports(self):
        banned_prefixes = (
            "ai.execution",
            "ai.verification",
            "ai.finding",
            "ai.resolver",
            "ai.authorizer",
            "ai.persistence",
            "nuclei_runner",
            "selenium",
            "playwright",
            "pyppeteer",
            "subprocess",
            "socket",
            "httpx",
            "requests",
        )
        for path in self.NEW_MODULES:
            modules = self._imported_modules(path)
            for module in modules:
                for banned in banned_prefixes:
                    self.assertFalse(
                        module == banned or module.startswith(banned + "."),
                        f"{path.name} imports {module} (banned: {banned})",
                    )

    def test_no_network_or_exec_text(self):
        # Documentation may name forbidden subsystems; what matters is that no
        # import/usage form appears. The AST test above independently bans the
        # modules entirely.
        for path in self.NEW_MODULES:
            text = path.read_text(encoding="utf-8")
            for token in (
                "import httpx",
                "import requests",
                "import subprocess",
                "import socket",
                "from subprocess",
                "from httpx",
                "from requests",
                "urllib.request",
                "http.client",
                "socket.socket",
            ):
                self.assertNotIn(token, text, f"{path.name} mentions {token}")
            self.assertIsNone(
                re.search(r"\b(eval|exec)\s*\(", text),
                f"{path.name} contains eval/exec",
            )

    def test_no_network_calls_during_ranking(self):
        sources = [mk("https://a.example/x"), mk("https://b.example/x")]
        with mock.patch("socket.socket", side_effect=AssertionError("network access")):
            rank_sources(sources, META)


class TestCompatibility(unittest.TestCase):
    def test_r24_1_contract_compatible(self):
        from ai.research_agent.discovery_contract import (
            SourceCategory,
            TrustTier,
            Lifecycle,
        )

        self.assertEqual(SourceCategory.NVD_CVE.value, "nvd_cve")
        self.assertEqual(TrustTier.TRUSTED.value, "TRUSTED")
        self.assertEqual(Lifecycle.DISCOVERED_SOURCE.value, "DISCOVERED_SOURCE")

    def test_r24_1_query_builder_compatible_and_deterministic(self):
        builder = QueryBuilder()
        q1 = builder.build_queries(META)
        q2 = builder.build_queries(META)
        self.assertEqual([q.query_id for q in q1], [q.query_id for q in q2])
        self.assertEqual([q.template_id for q in q1], [q.template_id for q in q2])

    def test_r24_2_provider_built_source_ranks(self):
        from ai.research_agent.provider_base import make_discovered_source
        from ai.research_agent.queries import QueryBuilder

        query = QueryBuilder().build_queries(META)[0]
        source = make_discovered_source(
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            provider=SearchProvider.NVD,
            query=query,
            category=SourceCategory.NVD_CVE,
            tier=TrustTier.TRUSTED,
            title="CVE-2026-1557",
        )
        ranked = rank_sources([source], META)
        self.assertEqual(len(ranked), 1)
        self.assertGreaterEqual(ranked[0].source_quality, 0.8)

    def test_r24_3_netguard_importable(self):
        import ai.research_agent.netguard as netguard

        self.assertTrue(hasattr(netguard, "validate_url"))
        self.assertTrue(hasattr(netguard, "MAX_REDIRECTS"))

    def test_r23_to_r23_serialization_compatible(self):
        source = _highest_source()
        r23 = source.to_r23()
        self.assertEqual(r23.url, source.final_url or source.url)
        self.assertEqual(r23.source_id, source.source_id)
        self.assertFalse(r23.__dict__.get("production_finding", False))

    def test_ranked_source_still_serializes(self):
        ranked = rank_sources([_highest_source()], META)
        payload = ranked[0].model_dump(mode="json")
        self.assertIn("source_quality", payload)
        self.assertFalse(payload["production_finding"])


if __name__ == "__main__":
    unittest.main()

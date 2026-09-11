"""tests/test_research_agent_r24_10.py — Stage R24.10 fetch-ranking hardening.

Offline, deterministic, fake-only. Covers deterministic fetch priority, the
reserved high-value trusted slot, unchanged R24.4 scores, unchanged evidence
gate, unchanged dedup, unchanged discovery=false path, and a loop-level
integration proving NVD is fetched instead of a generic vendor search page.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.research_agent.dedup import (
    canonical_url,
    dedup_by_content_hash,
    dedup_by_url,
)
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    SourceCategory,
    TrustTier,
    discovered_source_id,
)
from ai.research_agent.evidence import build_evidence
from ai.research_agent.fetch_priority import (
    GENERIC_LEVEL,
    fetch_level,
    fetch_priority_key,
    is_generic_search_source,
    order_for_fetch,
    reserved_trusted_source,
    select_for_fetch,
)
from ai.research_agent.llm_loop import FetchedSource, LoopBudgets, run_llm_research_loop
from ai.research_agent.queries import CVEResearchMetadata
from ai.research_agent.ranking import score_breakdown, score_source

CVE = "CVE-2026-1557"
META = CVEResearchMetadata(
    cve_id=CVE,
    product="WP Responsive Images",
    version="1.0",
    cwe="CWE-22",
    vulnerability_type="Path Traversal",
)


def mk(url, *, category, tier, quality=0.82, **over):
    return DiscoveredSource(
        source_id=over.pop("source_id", discovered_source_id(url)),
        url=url,
        category=category,
        tier=tier,
        source_quality=quality,
        **over,
    )


def nvd():
    return mk(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE,
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        discovery_provider="nvd",
        discovery_template_id="r24-cve-id",
    )


def vendor_search():
    return mk(
        "https://msrc.microsoft.com/update-guide/search?query=" + CVE + "+advisory",
        category=SourceCategory.VENDOR_ADVISORY,
        tier=TrustTier.TRUSTED,
        discovery_provider="vendor_advisory",
    )


def vendor_advisory_cve():
    return mk(
        "https://www.redhat.com/security/data/cve/" + CVE + ".html",
        category=SourceCategory.VENDOR_ADVISORY,
        tier=TrustTier.TRUSTED,
        discovery_provider="vendor_advisory",
    )


def semi_advisory():
    return mk(
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/abc",
        category=SourceCategory.WORDFENCE,
        tier=TrustTier.SEMI_TRUSTED,
        quality=0.7,
        discovery_provider="wordfence",
    )


def detection():
    return mk(
        "https://github.com/o/r/blob/main/rules/x.yaml",
        category=SourceCategory.DETECTION_RULE,
        tier=TrustTier.DISCOVERY_ONLY,
        quality=0.5,
        discovery_provider="detection_rule",
    )


def generic_blog():
    return mk(
        "https://blog.example/post",
        category=SourceCategory.SECURITY_BLOG,
        tier=TrustTier.DISCOVERY_ONLY,
        quality=0.3,
    )


def generic_tier():
    return mk(
        "https://search.example/result",
        category=SourceCategory.GENERIC_SEARCH,
        tier=TrustTier.GENERIC,
        quality=0.1,
    )


class TestFetchPriority(unittest.TestCase):
    def test_nvd_outranks_generic_vendor_search(self):
        a, b = vendor_search(), nvd()
        self.assertLess(fetch_level(b, META), fetch_level(a, META))
        self.assertIs(order_for_fetch([a, b], META)[0].tier, TrustTier.TRUSTED)
        self.assertEqual(order_for_fetch([a, b], META)[0].source_id, b.source_id)

    def test_cve_specific_advisory_outranks_generic(self):
        generic, advisory = vendor_search(), vendor_advisory_cve()
        self.assertLess(fetch_level(advisory, META), fetch_level(generic, META))
        ordered = order_for_fetch([generic, advisory], META)
        self.assertEqual(ordered[0].source_id, advisory.source_id)

    def test_generic_search_detection(self):
        self.assertTrue(is_generic_search_source(vendor_search()))
        self.assertTrue(is_generic_search_source(generic_tier()))
        self.assertFalse(is_generic_search_source(nvd()))
        self.assertFalse(is_generic_search_source(vendor_advisory_cve()))
        self.assertEqual(fetch_level(vendor_search(), META), GENERIC_LEVEL)

    def test_preference_levels(self):
        self.assertEqual(fetch_level(vendor_advisory_cve(), META), 0)
        self.assertEqual(fetch_level(nvd(), META), 0)
        self.assertEqual(fetch_level(semi_advisory(), META), 3)
        self.assertEqual(fetch_level(detection(), META), 5)
        self.assertEqual(fetch_level(generic_tier(), META), GENERIC_LEVEL)

    def test_order_for_fetch_keeps_all_sources(self):
        items = [vendor_search(), nvd(), detection(), generic_blog(), generic_tier()]
        ordered = order_for_fetch(items, META)
        self.assertEqual(len(ordered), len(items))
        self.assertEqual({s.source_id for s in ordered}, {s.source_id for s in items})

    def test_generic_pages_do_not_starve_trusted(self):
        items = [vendor_search(), generic_blog(), nvd()]
        selected = select_for_fetch(items, 1, META)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].source_id, nvd().source_id)

    def test_reserved_slot_with_max_fetched_one(self):
        items = [vendor_search(), generic_tier(), nvd()]
        selected = select_for_fetch(items, 1, META)
        self.assertIn(nvd().source_id, [s.source_id for s in selected])
        # The reserved high-value trusted source is non-generic.
        reserved = reserved_trusted_source(items, META)
        self.assertIsNotNone(reserved)
        self.assertEqual(reserved.source_id, nvd().source_id)

    def test_select_returns_all_when_budget_exceeds(self):
        items = [vendor_search(), nvd()]
        self.assertEqual(len(select_for_fetch(items, 5, META)), 2)

    def test_deterministic_ordering(self):
        items = [generic_tier(), vendor_search(), nvd(), detection(), semi_advisory()]
        forward = [s.source_id for s in order_for_fetch(items, META)]
        backward = [s.source_id for s in order_for_fetch(list(reversed(items)), META)]
        self.assertEqual(forward, backward)
        # key is a pure function
        self.assertEqual(
            fetch_priority_key(items[0], META), fetch_priority_key(items[0], META)
        )


class TestUnchangedBehaviour(unittest.TestCase):
    def test_r24_4_scores_unchanged(self):
        # R24.4 scoring is untouched by the fetch-priority layer.
        b = score_breakdown(nvd(), META)
        self.assertEqual(b.score, score_source(nvd(), META))
        self.assertEqual(b.tier_base, 100)
        self.assertEqual(b.category_bonus, 30)
        self.assertEqual(b.components.get("exact_cve_id"), 25)
        self.assertEqual(b.source_quality, round(b.score / 200, 2))
        # fetch ordering only reads the source; it never mutates it.
        src = nvd()
        before = src.model_dump(mode="json")
        order_for_fetch([src], META)
        self.assertEqual(src.model_dump(mode="json"), before)

    def test_evidence_gate_unchanged(self):
        generic = vendor_search().model_copy(update={"content_hash": "h1"})
        self.assertIsNone(
            build_evidence(
                generic,
                "Security Update Guide - Microsoft",
                required_content_tokens=[CVE],
            )
        )
        self.assertIsNotNone(
            build_evidence(
                generic,
                "advisory: " + CVE + " affects WP Responsive Images",
                required_content_tokens=[CVE],
            )
        )

    def test_dedup_unchanged(self):
        a = mk(
            "https://example.com/a?utm_source=x",
            category=SourceCategory.NVD_CVE,
            tier=TrustTier.TRUSTED,
            content_hash="h1",
        )
        b = mk(
            "https://EXAMPLE.com:443/a#frag",
            category=SourceCategory.NVD_CVE,
            tier=TrustTier.TRUSTED,
            content_hash="h1",
        )
        self.assertEqual(len(dedup_by_url([a, b])), 1)
        self.assertEqual(len(dedup_by_content_hash([a, b])), 1)
        self.assertEqual(canonical_url(a), "https://example.com/a")

    def test_discovery_false_unchanged(self):
        from ai import research_cli
        from ai.research_agent.agent import ResearchAgent
        from ai.research_agent.discovery_runner import DiscoveryResearchAgent
        from ai.research_agent.scheduler import SchedulerConfig

        agent = research_cli._build_research_agent(SchedulerConfig())
        self.assertIsInstance(agent, ResearchAgent)
        self.assertNotIsInstance(agent, DiscoveryResearchAgent)


class _FakeRegistry:
    def __init__(self, sources):
        self._sources = sources

    def discover(self, provider_id, query):
        return list(self._sources)


class TestLoopFetchSelection(unittest.TestCase):
    def test_nvd_fetched_instead_of_generic_with_budget_one(self):
        fetched_urls = []

        def fetcher(url):
            fetched_urls.append(url)
            return FetchedSource(
                url=url,
                content="Public advisory for " + CVE + " describes the issue.",
                final_url=url,
                redirect_chain=(url,),
            )

        budgets = LoopBudgets(
            max_rounds=1,
            max_queries_per_plan=3,
            round2_reserve=0,
            max_queries_per_run=3,
            max_discovered=5,
            max_fetched_per_plan=1,
            max_fetched_per_run=1,
            max_bytes_per_run=4_000_000,
            max_llm_calls_per_plan=0,
            max_llm_calls_per_run=0,
        )
        result = run_llm_research_loop(
            plan={"plan_id": "r22-38d26f10681e9a0f", "cve_id": CVE},
            metadata=META,
            registry=_FakeRegistry([vendor_search(), nvd()]),
            fetcher=fetcher,
            llm=None,
            llm_enabled=False,
            budgets=budgets,
        )
        round0 = result.rounds[0]
        self.assertEqual(len(fetched_urls), 1)
        self.assertIn("services.nvd.nist.gov", fetched_urls[0])
        by_id = {s.source_id: s for s in round0.discovery.sources}
        self.assertIsNotNone(by_id[nvd().source_id].content_hash)
        self.assertIsNone(by_id[vendor_search().source_id].content_hash)
        self.assertEqual(round0.evidence_count, 1)
        self.assertIn("services.nvd.nist.gov", round0.discovery.evidence[0].source_url)


if __name__ == "__main__":
    unittest.main()

"""tests/test_research_agent_r24_6.py — Stage R24.6 LLM research-loop tests.

Fully offline and deterministic. All providers, HTTP transport/DNS, fetcher and
LLM are fakes; no live network, no API keys.

Covers: LLM context boundary, output schema/attribution/grounding, verdict
sanitization, round-1/round-2 loop behavior, budget limits, fail-soft handling,
provenance, trust immutability, storage, import boundary and compatibility with
R23 + R24.1–R24.5.
"""
import ast
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    SourceCategory,
    TrustTier,
    discovered_source_id,
)
from ai.research_agent.dedup import with_content_hash
from ai.research_agent.evidence import integrate_discovery
from ai.research_agent.llm_research import (
    FORBIDDEN_CONTEXT_FIELDS,
    LLMAnalysis,
    LLMContradiction,
    LLMInference,
    LLMSupportedClaim,
    ResearchLLMContext,
    ResearchContextSource,
    assert_context_safe,
    build_llm_context,
    is_safe_suggested_query,
    map_suggestion_to_discovery_query,
    parse_llm_analysis,
    validate_and_sanitize_analysis,
)
from ai.research_agent.llm_loop import (
    BudgetTracker,
    FetchedSource,
    LLMResearchLoopResult,
    LoopBudgets,
    run_llm_research_loop,
)
from ai.research_agent.queries import CVEResearchMetadata

CVE = "CVE-2026-1557"
PLAN = "r22-38d26f10681e9a0f"
NVD_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-1557"
META = CVEResearchMetadata(
    cve_id=CVE,
    product="Responsive Images",
    component="image_handler.php",
    version="1.0",
    cwe="CWE-79",
    vulnerability_type="reflected xss",
)
ADVISORY_TEXT = (
    "The public advisory for CVE-2026-1557 describes a reflected issue in "
    "Responsive Images version 1.0 via the image_handler.php component."
)


def src(url=NVD_URL, **over):
    base = dict(
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        source_quality=0.9,
        title=f"{CVE} advisory",
        discovery_provider="nvd",
        discovery_query=CVE,
        discovery_template_id="r24-cve-id",
    )
    base.update(over)
    source_id = base.pop("source_id", None) or discovered_source_id(url)
    return DiscoveredSource(source_id=source_id, url=url, **base)


class FakeRegistry:
    """Deterministic fake R24.2 registry (no network)."""

    def __init__(self, results=None, *, fail_from=None, sources_factory=None):
        self.calls = []
        self._results = results or {}
        self._fail_from = fail_from
        self._factory = sources_factory

    def discover(self, provider_id, query):
        self.calls.append((provider_id, query))
        if self._fail_from is not None and len(self.calls) >= self._fail_from:
            raise RuntimeError("provider boom")
        if self._factory is not None:
            return self._factory(provider_id, query)
        return list(self._results.get(provider_id, []))


def registry_with_nvd(count_unbounded=True):
    def factory(provider_id, query):
        if provider_id != "nvd":
            return []
        return [
            src(
                discovery_provider="nvd",
                discovery_query=query.query,
                discovery_template_id=query.template_id,
            )
        ]

    return FakeRegistry(sources_factory=factory)


class FakeFetcher:
    def __init__(self, content=ADVISORY_TEXT, *, fail=False, redirect=True):
        self.content = content
        self.fail = fail
        self.redirect = redirect
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if self.fail:
            return None
        return FetchedSource(
            url=url,
            content=self.content,
            final_url=url,
            redirect_chain=(url,) if self.redirect else (),
            extraction_method="html_text",
        )


class FakeLLM:
    model = "fake-model"

    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt):
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        if isinstance(self.response, str):
            return self.response
        return json.dumps(self.response)


def analysis_payload(**over):
    payload = {
        "summary": "Public advisory describes a reflected issue.",
        "supported_claims": [],
        "inferences": [],
        "unknowns": [],
        "contradictions": [],
        "gaps": [],
        "suggested_queries": [],
    }
    payload.update(over)
    return payload


# ---------------------------------------------------------------------------
# LLM context
# ---------------------------------------------------------------------------
class TestLLMContext(unittest.TestCase):
    def _block(self, source=None, content=None):
        source = source or src()
        body = content if content is not None else ADVISORY_TEXT
        source = with_content_hash(source, body)
        content = {source.source_id: body}
        block = integrate_discovery(
            [source], content, discovery_enabled=True, plan_id=PLAN
        )
        return block, content

    def test_context_has_only_allowed_fields(self):
        block, content = self._block()
        context = build_llm_context(block, META, content_by_source_id=content)
        fields = set(ResearchLLMContext.model_fields)
        self.assertEqual(fields & FORBIDDEN_CONTEXT_FIELDS, set())
        self.assertTrue(context.public_research_only)
        self.assertFalse(context.production_finding)
        assert_context_safe(context, ())

    def test_context_carries_public_material(self):
        block, content = self._block()
        context = build_llm_context(block, META, content_by_source_id=content)
        self.assertEqual(context.cve_id, CVE)
        self.assertEqual(context.cwe, "CWE-79")
        self.assertEqual(len(context.sources), 1)
        self.assertEqual(len(context.evidence), 1)

    def test_forbidden_program_token_excluded(self):
        hostile = src(
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            title="CVE-2026-1557 dell internal note",
            source_id="ds-hostile",
        )
        block = integrate_discovery(
            [hostile], {"ds-hostile": ADVISORY_TEXT}, discovery_enabled=True
        )
        context = build_llm_context(
            block, META, content_by_source_id={"ds-hostile": ADVISORY_TEXT},
            forbidden_tokens=["dell"],
        )
        self.assertEqual(context.sources, [])
        self.assertGreaterEqual(context.excluded_forbidden, 1)

    def test_assert_context_safe_rejects_forbidden_token(self):
        context = ResearchLLMContext(
            cve_id=CVE,
            sources=[
                ResearchContextSource(
                    source_id="ds-1",
                    canonical_url="https://x.example/a",
                    category=SourceCategory.NVD_CVE,
                    tier=TrustTier.TRUSTED,
                    content="dell internal",
                )
            ],
        )
        with self.assertRaises(ValueError):
            assert_context_safe(context, ["dell"])

    def test_forbidden_context_field_names(self):
        for name in (
            "program", "target", "asset", "target_url", "target_host",
            "target_ip", "endpoint", "response", "credentials", "cookies",
            "headers",
        ):
            self.assertIn(name, FORBIDDEN_CONTEXT_FIELDS)
        self.assertEqual(set(ResearchLLMContext.model_fields) & FORBIDDEN_CONTEXT_FIELDS, set())
        self.assertEqual(set(ResearchContextSource.model_fields) & FORBIDDEN_CONTEXT_FIELDS, set())

    def test_context_production_finding_forced_false(self):
        with self.assertRaises(Exception):
            ResearchLLMContext(production_finding=True)
        with self.assertRaises(Exception):
            ResearchLLMContext(public_research_only=False)


# ---------------------------------------------------------------------------
# LLM output
# ---------------------------------------------------------------------------
class TestLLMOutput(unittest.TestCase):
    def _context(self):
        source = with_content_hash(src(), ADVISORY_TEXT)
        block = integrate_discovery(
            [source], {source.source_id: ADVISORY_TEXT}, discovery_enabled=True
        )
        return build_llm_context(
            block, META, content_by_source_id={source.source_id: ADVISORY_TEXT}
        )

    def test_valid_structured_response(self):
        raw = json.dumps(analysis_payload(summary="ok", gaps=["version range"]))
        analysis = parse_llm_analysis(raw)
        self.assertEqual(analysis.summary, "ok")
        self.assertEqual(analysis.gaps, ["version range"])
        self.assertTrue(analysis.public_research_only)

    def test_malformed_response_rejected(self):
        with self.assertRaises(ValueError):
            parse_llm_analysis("not json at all")
        with self.assertRaises(ValueError):
            parse_llm_analysis("[1, 2, 3]")

    def test_missing_fields_handled(self):
        analysis = parse_llm_analysis("{}")
        self.assertEqual(analysis.summary, "")
        self.assertEqual(analysis.supported_claims, [])

    def test_invented_source_id_dropped(self):
        context = self._context()
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="reflected issue in Responsive Images",
                    source_ids=["ds-invented"],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertEqual(result.analysis.supported_claims, [])
        self.assertTrue(any("unknown attribution" in d for d in result.dropped))

    def test_invented_evidence_id_dropped(self):
        context = self._context()
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="reflected issue in Responsive Images",
                    evidence_ids=["de-invented"],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertEqual(result.analysis.supported_claims, [])

    def test_invented_url_dropped(self):
        context = self._context()
        sid = context.sources[0].source_id
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="see https://evil.example/leak for details about reflected issue",
                    source_ids=[sid],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertTrue(any("invented URL" in d for d in result.dropped))
        self.assertEqual(result.analysis.supported_claims, [])

    def test_invented_hash_field_ignored(self):
        analysis = parse_llm_analysis(
            json.dumps(analysis_payload(content_hash="deadbeef", source_url="https://evil"))
        )
        self.assertFalse(hasattr(analysis, "content_hash"))
        self.assertFalse(hasattr(analysis, "source_url"))

    def test_unsupported_claim_downgraded_to_unknown(self):
        context = self._context()
        sid = context.sources[0].source_id
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="unrelated completely different words xylophone",
                    source_ids=[sid],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertEqual(result.analysis.supported_claims, [])
        self.assertEqual(len(result.downgraded_unknowns), 1)
        self.assertTrue(any("unrelated" in u for u in result.analysis.unknowns))

    def test_grounded_claim_kept(self):
        context = self._context()
        eid = context.evidence[0].evidence_id
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="public advisory describes reflected issue in Responsive Images",
                    evidence_ids=[eid],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertEqual(len(result.analysis.supported_claims), 1)

    def test_inference_attribution(self):
        context = self._context()
        eid = context.evidence[0].evidence_id
        good = LLMInference(
            statement="reflected issue in Responsive Images",
            evidence_ids=[eid],
        )
        bad = LLMInference(statement="x", evidence_ids=["de-nope"])
        result = validate_and_sanitize_analysis(
            LLMAnalysis(inferences=[good, bad]), context
        )
        self.assertEqual(len(result.analysis.inferences), 1)


# ---------------------------------------------------------------------------
# Safety / verdicts / trust
# ---------------------------------------------------------------------------
class TestSafety(unittest.TestCase):
    def _context(self):
        source = with_content_hash(src(), ADVISORY_TEXT)
        block = integrate_discovery(
            [source], {source.source_id: ADVISORY_TEXT}, discovery_enabled=True
        )
        return build_llm_context(
            block, META, content_by_source_id={source.source_id: ADVISORY_TEXT}
        )

    def test_forbidden_verdict_words_rejected(self):
        context = self._context()
        sid = context.sources[0].source_id
        for word in ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING"):
            with self.subTest(word=word):
                analysis = LLMAnalysis(
                    summary=f"the target is {word}",
                    supported_claims=[
                        LLMSupportedClaim(
                            claim=f"the product is {word} for reflected issue",
                            source_ids=[sid],
                        )
                    ],
                )
                result = validate_and_sanitize_analysis(analysis, context)
                self.assertEqual(result.analysis.summary, "")
                self.assertEqual(result.analysis.supported_claims, [])

    def test_target_verdict_claim_rejected(self):
        context = self._context()
        sid = context.sources[0].source_id
        analysis = LLMAnalysis(
            supported_claims=[
                LLMSupportedClaim(
                    claim="the monitored target is vulnerable to reflected issue",
                    source_ids=[sid],
                )
            ]
        )
        result = validate_and_sanitize_analysis(analysis, context)
        self.assertEqual(result.analysis.supported_claims, [])
        self.assertTrue(result.dropped)

    def test_llm_cannot_upgrade_trust(self):
        generic = src(
            url="https://blog.example/post",
            category=SourceCategory.SECURITY_BLOG,
            tier=TrustTier.GENERIC,
            discovery_provider="generic_search",
        )
        original_tier = generic.tier
        registry = FakeRegistry(sources_factory=lambda p, q: [generic])
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry,
            fetcher=FakeFetcher(),
            llm=FakeLLM(
                analysis_payload(
                    summary="now TRUSTED",
                    supported_claims=[
                        {
                            "claim": "generic source is now trusted",
                            "source_ids": [generic.source_id],
                        }
                    ],
                )
            ),
            llm_enabled=True,
        )
        for round_result in res.rounds:
            for record in round_result.discovery.sources:
                self.assertEqual(record.tier, original_tier)
        self.assertEqual(res.production_finding, False)

    def test_llm_cannot_create_evidence(self):
        # No fetcher -> no content -> no R24.5 evidence, regardless of LLM.
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=None,
            llm=FakeLLM(
                analysis_payload(
                    supported_claims=[
                        {"claim": "invented evidence", "source_ids": ["ds-x"]}
                    ]
                )
            ),
            llm_enabled=True,
        )
        self.assertEqual(res.rounds[0].evidence_count, 0)

    def test_production_finding_never_true(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        self.assertFalse(res.production_finding)
        self.assertTrue(res.public_research_only)
        for round_result in res.rounds:
            self.assertFalse(round_result.production_finding)


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------
class TestResearchLoop(unittest.TestCase):
    def test_round1_works(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(summary="ok")),
            llm_enabled=True,
        )
        self.assertEqual(res.status, "RESEARCH_COMPLETED")
        self.assertEqual(res.llm_status, "ok")
        self.assertGreaterEqual(res.rounds[0].evidence_count, 1)
        self.assertTrue(res.rounds[0].queries)

    def test_no_evidence_is_partial(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=None,
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        self.assertEqual(res.status, "RESEARCH_PARTIAL")
        self.assertEqual(res.rounds[0].evidence_count, 0)

    def test_provider_failure_fail_soft(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=FakeRegistry(fail_from=1),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        self.assertEqual(res.status, "RESEARCH_BLOCKED")
        self.assertTrue(res.provider_failures)

    def test_fetch_failure_fail_soft(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(fail=True),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        self.assertEqual(res.rounds[0].evidence_count, 0)
        self.assertEqual(res.status, "RESEARCH_PARTIAL")

    def test_llm_failure_fail_soft_preserves_evidence(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(RuntimeError("llm boom")),
            llm_enabled=True,
        )
        self.assertEqual(res.llm_status, "failed")
        self.assertIn("llm boom", res.llm_error)
        self.assertGreaterEqual(res.rounds[0].evidence_count, 1)
        self.assertEqual(res.status, "RESEARCH_PARTIAL")

    def test_llm_malformed_json_fail_soft(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM("this is not json"),
            llm_enabled=True,
        )
        self.assertEqual(res.llm_status, "failed")
        self.assertGreaterEqual(res.rounds[0].evidence_count, 1)

    def test_round2_only_when_gaps_exist(self):
        # No gaps -> single round.
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(gaps=[], unknowns=[])),
            llm_enabled=True,
        )
        self.assertEqual(len(res.rounds), 1)

        # Gaps present -> second round.
        res2 = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(gaps=["version range unknown"])),
            llm_enabled=True,
        )
        self.assertEqual(len(res2.rounds), 2)

    def test_max_two_rounds(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(gaps=["more", "even more"])),
            llm_enabled=True,
        )
        self.assertLessEqual(len(res.rounds), 2)

    def test_round2_failure_preserves_round1(self):
        # Succeed for round 1 (2 calls), fail from round 2.
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=FakeRegistry(fail_from=3, sources_factory=lambda p, q: [src()] if p == "nvd" else []),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(gaps=["gap"])),
            llm_enabled=True,
            budgets=LoopBudgets(max_queries_per_plan=4, round2_reserve=2),
        )
        self.assertEqual(len(res.rounds), 2)
        self.assertGreaterEqual(res.rounds[0].evidence_count, 1)
        self.assertGreaterEqual(len(res.provider_failures), 1)

    def test_query_limits_enforced(self):
        budgets = LoopBudgets(max_queries_per_plan=4, round2_reserve=2)
        tracker = BudgetTracker(budgets=budgets)
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload(gaps=["gap"])),
            llm_enabled=True,
            budgets=budgets,
            tracker=tracker,
        )
        total = sum(len(r.queries) for r in res.rounds)
        self.assertLessEqual(total, budgets.max_queries_per_plan)
        self.assertLessEqual(tracker.queries_used, budgets.max_queries_per_run)

    def test_discovered_source_limit_enforced(self):
        def factory(provider_id, query):
            if provider_id != "nvd":
                return []
            out = []
            for i in range(5):
                out.append(src(url=f"https://nvd.nist.gov/vuln/detail/{CVE}?i={i}"))
            return out

        budgets = LoopBudgets(max_discovered=2)
        tracker = BudgetTracker(budgets=budgets)
        run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=FakeRegistry(sources_factory=factory),
            fetcher=None,
            llm=None,
            llm_enabled=False,
            budgets=budgets,
            tracker=tracker,
        )
        self.assertLessEqual(tracker.discovered_used, budgets.max_discovered)

    def test_byte_limit_enforced(self):
        big = "x" * 5_000_000
        budgets = LoopBudgets(max_bytes_per_run=1000)
        tracker = BudgetTracker(budgets=budgets)
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(content=big),
            llm=None,
            llm_enabled=False,
            budgets=budgets,
            tracker=tracker,
        )
        self.assertEqual(res.rounds[0].evidence_count, 0)
        self.assertLessEqual(tracker.bytes_used, budgets.max_bytes_per_run)

    def test_llm_disabled_runs_deterministically(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=None,
            llm_enabled=False,
        )
        self.assertEqual(res.llm_status, "disabled")
        self.assertEqual(res.status, "RESEARCH_COMPLETED")

    def test_llm_enabled_without_provider(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=None,
            llm_enabled=True,
        )
        self.assertEqual(res.llm_status, "unavailable")


class TestQuerySafety(unittest.TestCase):
    def test_safe_suggestion_accepted(self):
        self.assertTrue(is_safe_suggested_query("CVE-2026-1557 advisory"))
        self.assertTrue(is_safe_suggested_query("wordpress plugin cwe-79"))

    def test_forbidden_suggestions_rejected(self):
        for bad in (
            "https://dell.example.com/x",
            "dell internal host",
            "10.0.0.5",
            "target cookie",
            "program asset endpoint",
            "user:pass@host",
            "GET /admin?x=1",
        ):
            with self.subTest(bad=bad):
                self.assertFalse(is_safe_suggested_query(bad, ["dell"]))
                self.assertIsNone(map_suggestion_to_discovery_query(bad, META, forbidden_tokens=["dell"]))

    def test_suggestion_maps_to_approved_template(self):
        query = map_suggestion_to_discovery_query("CVE-2026-1557 advisory", META)
        self.assertIsNotNone(query)
        self.assertEqual(query.template_id, "r24-cve-advisory")

    def test_forbidden_suggested_query_not_used_in_loop(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(
                analysis_payload(
                    gaps=["gap"],
                    suggested_queries=["dell.example.com target", "CVE-2026-1557 advisory"],
                )
            ),
            llm_enabled=True,
            forbidden_tokens=["dell"],
        )
        # The forbidden suggestion must never be rendered into any query.
        provenance = [p for r in res.rounds for p in r.query_provenance]
        self.assertTrue(all("dell" not in json.dumps(p) for p in provenance))
        rendered = " ".join(q for r in res.rounds for q in r.queries)
        self.assertNotIn("dell", rendered)


# ---------------------------------------------------------------------------
# Provenance / trust
# ---------------------------------------------------------------------------
class TestProvenanceAndTrust(unittest.TestCase):
    def test_provenance_preserved(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        block = res.rounds[0].discovery
        self.assertEqual(len(block.evidence), block.evidence_count)
        item = block.evidence[0]
        self.assertTrue(item.source_id)
        self.assertTrue(item.evidence_id)
        self.assertEqual(item.content_hash, block.sources[0].content_hash)
        self.assertTrue(item.discovery_provider)
        self.assertTrue(item.discovery_query)
        self.assertTrue(item.discovery_template_id)
        self.assertTrue(item.redirect_chain)

    def test_content_hash_and_final_url_preserved(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=None,
            llm_enabled=False,
        )
        record = res.rounds[0].discovery.sources[0]
        self.assertTrue(record.content_hash)
        self.assertTrue(record.final_url)

    def test_detection_rule_stays_discovery_only_without_advisory(self):
        det = src(
            url="https://github.com/o/r/blob/main/rules/x.yaml",
            category=SourceCategory.DETECTION_RULE,
            tier=TrustTier.DISCOVERY_ONLY,
            discovery_provider="detection_rule",
        )
        registry = FakeRegistry(results={"detection_rule": [det]})
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry,
            fetcher=FakeFetcher(),
            llm=None,
            llm_enabled=False,
            budgets=LoopBudgets(max_rounds=1, round2_reserve=0),
        )
        record = res.rounds[0].discovery.sources[0]
        self.assertEqual(record.tier, TrustTier.DISCOVERY_ONLY)
        self.assertEqual(res.rounds[0].evidence_count, 0)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
class TestStorage(unittest.TestCase):
    def _result(self):
        return run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )

    def test_store_and_load_loop_result(self):
        from ai.research_agent import storage

        result = self._result()
        with tempfile.TemporaryDirectory() as tmp:
            path, written = storage.store_research_loop(result, base=tmp)
            self.assertTrue(written)
            self.assertTrue(str(path).endswith(".loop.json"))
            _, written2 = storage.store_research_loop(result, base=tmp)
            self.assertFalse(written2)
            loaded = storage.load_research_loop(PLAN, "r24-loop-1", base=tmp)
            self.assertEqual(loaded["plan_id"], PLAN)
            self.assertFalse(loaded["production_finding"])

    def test_no_secret_persisted(self):
        from ai.research_agent import storage

        result = self._result()
        payload = result.model_dump(mode="json")
        blob = json.dumps(payload)
        self.assertNotIn("sk-", blob)
        self.assertNotIn("OPENROUTER_API_KEY", blob)
        self.assertNotIn("api_key", blob.lower())
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = storage.store_research_loop(result, base=tmp)
            self.assertNotIn("sk-", path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Static boundary
# ---------------------------------------------------------------------------
class TestStaticBoundary(unittest.TestCase):
    MODULES = (
        Path("/opt/watch/ai/research_agent/llm_research.py"),
        Path("/opt/watch/ai/research_agent/llm_loop.py"),
    )
    BANNED = (
        "ai.execution", "ai.verification", "ai.finding", "ai.resolver",
        "ai.authorizer", "ai.persistence", "nuclei_runner", "selenium",
        "playwright", "pyppeteer", "subprocess", "socket", "httpx", "requests",
    )

    def test_import_boundary(self):
        for path in self.MODULES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            modules = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.add(node.module)
            for module in modules:
                for banned in self.BANNED:
                    self.assertFalse(
                        module == banned or module.startswith(banned + "."),
                        f"{path.name} imports {module}",
                    )

    def test_no_exec_or_live_network_text(self):
        for path in self.MODULES:
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\b(eval|exec)\s*\(", text), path.name)
            for token in ("import httpx", "import requests", "import socket", "import subprocess"):
                self.assertNotIn(token, text, path.name)

    def test_loop_makes_no_socket_calls(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network")):
            run_llm_research_loop(
                plan={"plan_id": PLAN, "cve_id": CVE},
                metadata=META,
                registry=registry_with_nvd(),
                fetcher=FakeFetcher(),
                llm=None,
                llm_enabled=False,
            )


class TestCompatibility(unittest.TestCase):
    def test_r23_and_r24_modules_importable(self):
        import ai.research_agent.agent as agent
        import ai.research_agent.evidence as evidence
        import ai.research_agent.ranking as ranking
        import ai.research_agent.dedup as dedup
        import ai.llm.openrouter as openrouter

        self.assertTrue(hasattr(agent, "ResearchAgent"))
        self.assertTrue(hasattr(evidence, "DiscoveryBlock"))
        self.assertTrue(hasattr(ranking, "is_evidence_eligible"))
        self.assertTrue(hasattr(dedup, "dedup_discovered_sources"))
        self.assertTrue(hasattr(openrouter, "OpenRouterProvider"))

    def test_loop_result_serializes(self):
        res = run_llm_research_loop(
            plan={"plan_id": PLAN, "cve_id": CVE},
            metadata=META,
            registry=registry_with_nvd(),
            fetcher=FakeFetcher(),
            llm=FakeLLM(analysis_payload()),
            llm_enabled=True,
        )
        payload = res.model_dump(mode="json")
        restored = LLMResearchLoopResult.model_validate(payload)
        self.assertEqual(restored.result_id, res.result_id)
        self.assertEqual(restored.status, res.status)


if __name__ == "__main__":
    unittest.main()

"""tests/test_research_agent_r24_5.py — Stage R24.5 evidence-integration tests.

Offline, deterministic, network-free. Covers:

- schema: old R23 results load unchanged; R24 discovery block
  serializes/deserializes; discovery block optional; production_finding=False;
  forbidden affirmative states rejected
- lifecycle transitions and derivations
- evidence eligibility (reusing R24.4)
- evidence grounding and provenance preservation
- dedup integration (canonical-only evidence, aliases, no duplicate evidence)
- safety (no target/program/asset fields, import boundary, no network/exec)
- R23 / R24.1 / R24.2 / R24.3 / R24.4 compatibility

No network, no LLM, no Mongo, no subprocess, no target interaction.
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
    Lifecycle,
    SourceCategory,
    TrustTier,
    discovered_source_id,
)
from ai.research_agent.dedup import (
    canonical_url,
    dedup_by_content_hash,
    dedup_discovered_sources,
)
from ai.research_agent.ranking import (
    EVIDENCE_FLOOR,
    is_evidence_eligible,
    rank_sources,
)
from ai.research_agent.evidence import (
    DISCOVERY_RULE_VERSION,
    EVIDENCE_ID_PREFIX,
    INFERENCE_ID_PREFIX,
    LIFECYCLE_ORDER,
    TERMINAL_LIFECYCLES,
    DiscoveryBlock,
    DiscoveryEvidence,
    DiscoveryInference,
    DiscoverySourceRecord,
    LifecycleError,
    attach_discovery_block,
    build_evidence,
    evidence_id_for,
    inference_id_for,
    integrate_discovery,
    is_valid_lifecycle_transition,
    next_lifecycle_for,
    transition_lifecycle,
    with_lifecycle,
)
from ai.research_agent.queries import CVEResearchMetadata
from ai.schemas.research_agent import ResearchAgentResult

CVE = "CVE-2026-1557"
PLAN = "r22-38d26f10681e9a0f"


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
        lifecycle=lifecycle,
    )


def trusted_source(content_hash="h1", **over):
    base = dict(
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        source_quality=0.9,
        content_hash=content_hash,
        title="CVE-2026-1557 advisory",
        provider="nvd",
        query=CVE,
        template="r24-cve-id",
    )
    base.update(over)
    return mk("https://nvd.nist.gov/vuln/detail/CVE-2026-1557", **base)


def semi_source(content_hash="h2", **over):
    base = dict(
        category=SourceCategory.WORDFENCE,
        tier=TrustTier.SEMI_TRUSTED,
        source_quality=0.7,
        content_hash=content_hash,
        provider="wordfence",
        query=CVE,
        template="r24-cve-advisory",
    )
    base.update(over)
    return mk("https://www.wordfence.com/threat-intel/x", **base)


def detection_source(**over):
    base = dict(
        category=SourceCategory.DETECTION_RULE,
        tier=TrustTier.DISCOVERY_ONLY,
        source_quality=0.8,
        content_hash="h3",
        provider="detection_rule",
        query=CVE,
        template="r24-cve-detection",
    )
    base.update(over)
    return mk("https://github.com/o/r/blob/main/rules/x.yaml", **base)


class TestSchema(unittest.TestCase):
    def test_old_r23_result_loads_unchanged(self):
        from ai.research_agent import storage

        path = Path("/opt/watch/ai_data/research/agent/r22-38d26f10681e9a0f.r23-1.json")
        if not path.exists():
            self.skipTest("R23 result fixture not present")
        raw = json.loads(path.read_text(encoding="utf-8"))
        loaded = storage.load_result(PLAN, "r23-1")
        self.assertEqual(loaded, raw)
        self.assertNotIn("discovery", raw)
        # Still deserializable by the unmodified R23 model.
        result = ResearchAgentResult.model_validate(raw)
        self.assertFalse(result.production_finding)

    def test_discovery_block_round_trips(self):
        block = integrate_discovery(
            [trusted_source()],
            {trusted_source().source_id: "advisory material"},
            discovery_enabled=True,
            plan_id=PLAN,
        )
        dumped = block.model_dump(mode="json")
        restored = DiscoveryBlock.model_validate(dumped)
        self.assertEqual(restored, block)
        self.assertEqual(restored.rule_version, DISCOVERY_RULE_VERSION)

    def test_discovery_block_is_optional(self):
        from ai.research_agent import storage

        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(storage.load_discovery(PLAN, "r24-1", base=tmp))

    def test_attach_does_not_mutate_or_change_r23(self):
        from ai.research_agent import storage

        r23 = storage.load_result(PLAN, "r23-1") or {"plan_id": PLAN, "status": "RESEARCH_PARTIAL"}
        original = dict(r23)
        block = integrate_discovery([], discovery_enabled=False, plan_id=PLAN)
        combined = attach_discovery_block(r23, block)
        self.assertNotIn("discovery", r23)
        self.assertEqual(r23, original)
        self.assertIn("discovery", combined)
        self.assertEqual(combined["plan_id"], r23.get("plan_id"))

    def test_production_finding_false_everywhere(self):
        block = integrate_discovery(
            [trusted_source()],
            {trusted_source().source_id: "advisory material"},
            discovery_enabled=True,
            plan_id=PLAN,
        )
        self.assertFalse(block.production_finding)
        for item in block.evidence:
            self.assertFalse(item.production_finding)
        for record in block.sources:
            self.assertFalse(record.production_finding)

    def test_forbidden_affirmative_states_rejected(self):
        with self.assertRaises(Exception):
            DiscoveryBlock(production_finding=True)
        with self.assertRaises(Exception):
            DiscoverySourceRecord(
                source_id="ds-1",
                canonical_url="https://x.example/a",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                category=SourceCategory.GENERIC_SEARCH,
                tier=TrustTier.GENERIC,
                production_finding=True,
            )
        with self.assertRaises(Exception):
            DiscoveryInference(inference_id="di-1", statement="x", production_finding=True)
        # VULNERABLE is not a valid Lifecycle value.
        with self.assertRaises(Exception):
            DiscoveryEvidence(
                evidence_id="de-1",
                source_id="ds-1",
                source_url="https://x.example/a",
                canonical_url="https://x.example/a",
                content_hash="h",
                source_category=SourceCategory.NVD_CVE,
                trust_tier=TrustTier.TRUSTED,
                claim="x",
                lifecycle="VULNERABLE",
            )


class TestLifecycle(unittest.TestCase):
    def test_happy_path_transitions(self):
        self.assertEqual(
            transition_lifecycle(
                Lifecycle.DISCOVERED_SOURCE, Lifecycle.FETCHED_SOURCE
            ),
            Lifecycle.FETCHED_SOURCE,
        )
        self.assertEqual(
            transition_lifecycle(
                Lifecycle.FETCHED_SOURCE, Lifecycle.RELEVANT_SOURCE
            ),
            Lifecycle.RELEVANT_SOURCE,
        )
        self.assertEqual(
            transition_lifecycle(Lifecycle.RELEVANT_SOURCE, Lifecycle.EVIDENCE),
            Lifecycle.EVIDENCE,
        )

    def test_terminal_states_reachable(self):
        self.assertTrue(
            is_valid_lifecycle_transition(
                Lifecycle.DISCOVERED_SOURCE, Lifecycle.UNKNOWN
            )
        )
        self.assertTrue(
            is_valid_lifecycle_transition(
                Lifecycle.FETCHED_SOURCE, Lifecycle.INFERENCE
            )
        )
        self.assertIn(Lifecycle.UNKNOWN, TERMINAL_LIFECYCLES)
        self.assertIn(Lifecycle.INFERENCE, TERMINAL_LIFECYCLES)

    def test_invalid_transitions_rejected(self):
        for current, target in (
            (Lifecycle.EVIDENCE, Lifecycle.RELEVANT_SOURCE),
            (Lifecycle.FETCHED_SOURCE, Lifecycle.DISCOVERED_SOURCE),
            (Lifecycle.DISCOVERED_SOURCE, Lifecycle.RELEVANT_SOURCE),
            (Lifecycle.UNKNOWN, Lifecycle.FETCHED_SOURCE),
            (Lifecycle.INFERENCE, Lifecycle.EVIDENCE),
        ):
            with self.subTest(current=current, target=target):
                self.assertFalse(is_valid_lifecycle_transition(current, target))
                with self.assertRaises(LifecycleError):
                    transition_lifecycle(current, target)

    def test_lifecycle_order_is_fixed(self):
        self.assertEqual(LIFECYCLE_ORDER[Lifecycle.DISCOVERED_SOURCE], 0)
        self.assertEqual(LIFECYCLE_ORDER[Lifecycle.FETCHED_SOURCE], 1)
        self.assertEqual(LIFECYCLE_ORDER[Lifecycle.RELEVANT_SOURCE], 2)
        self.assertEqual(LIFECYCLE_ORDER[Lifecycle.EVIDENCE], 3)

    def test_with_lifecycle_is_deterministic(self):
        source = trusted_source()
        a = with_lifecycle(source, Lifecycle.FETCHED_SOURCE)
        b = with_lifecycle(source, Lifecycle.FETCHED_SOURCE)
        self.assertEqual(a.lifecycle, b.lifecycle)
        self.assertEqual(source.lifecycle, Lifecycle.DISCOVERED_SOURCE)

    def test_next_lifecycle_derivation(self):
        no_hash = mk("https://x.example/a")
        self.assertEqual(
            next_lifecycle_for(no_hash, content_present=False, eligible=False),
            Lifecycle.DISCOVERED_SOURCE,
        )
        content_only = mk("https://x.example/a")
        self.assertEqual(
            next_lifecycle_for(content_only, content_present=True, eligible=False),
            Lifecycle.FETCHED_SOURCE,
        )
        ineligible = trusted_source()
        self.assertEqual(
            next_lifecycle_for(ineligible, content_present=True, eligible=False),
            Lifecycle.RELEVANT_SOURCE,
        )
        eligible = trusted_source()
        self.assertEqual(
            next_lifecycle_for(eligible, content_present=True, eligible=True),
            Lifecycle.EVIDENCE,
        )
        hash_only = trusted_source()
        self.assertEqual(
            next_lifecycle_for(hash_only, content_present=False, eligible=True),
            Lifecycle.FETCHED_SOURCE,
        )


class TestEligibility(unittest.TestCase):
    def test_reuses_r24_4_predicate(self):
        src = trusted_source()
        self.assertTrue(is_evidence_eligible(src))
        self.assertTrue(is_evidence_eligible(semi_source()))
        self.assertFalse(
            is_evidence_eligible(
                mk("https://x.example/a", content_hash="h", source_quality=1.0)
            )
        )
        self.assertFalse(
            is_evidence_eligible(trusted_source(source_quality=0.44))
        )
        self.assertEqual(EVIDENCE_FLOOR, 0.45)
        self.assertFalse(is_evidence_eligible(detection_source()))
        self.assertTrue(
            is_evidence_eligible(detection_source(), advisory_reference=CVE)
        )


class TestEvidence(unittest.TestCase):
    def test_evidence_references_known_source_and_preserves_fields(self):
        src = trusted_source(
            final_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            redirect_chain=["https://nvd.nist.gov/x"],
            aliases=["https://cve.org/CVE-2026-1557"],
        )
        content = "The advisory for CVE-2026-1557 describes the reflected issue."
        block = integrate_discovery(
            [src], {src.source_id: content}, discovery_enabled=True, plan_id=PLAN
        )
        self.assertEqual(len(block.evidence), 1)
        item = block.evidence[0]
        self.assertEqual(item.source_id, src.source_id)
        self.assertEqual(item.source_url, src.final_url)
        self.assertEqual(item.canonical_url, canonical_url(src))
        self.assertEqual(item.final_url, src.final_url)
        self.assertEqual(item.content_hash, src.content_hash)
        self.assertEqual(item.source_category, src.category)
        self.assertEqual(item.trust_tier, src.tier)
        self.assertEqual(item.source_quality, src.source_quality)
        self.assertEqual(item.lifecycle, Lifecycle.EVIDENCE)
        self.assertEqual(item.discovery_provider, src.discovery_provider)
        self.assertEqual(item.discovery_query, src.discovery_query)
        self.assertEqual(item.discovery_template_id, src.discovery_template_id)
        self.assertEqual(item.redirect_chain, src.redirect_chain)
        self.assertEqual(item.aliases, src.aliases)
        self.assertEqual(item.extraction_method, "content_excerpt")
        self.assertTrue(item.evidence_id.startswith(EVIDENCE_ID_PREFIX))

    def test_evidence_is_grounded_in_supplied_content(self):
        src = trusted_source()
        content = "Only this supplied text is available."
        block = integrate_discovery(
            [src], {src.source_id: content}, discovery_enabled=True
        )
        self.assertIn(block.evidence[0].claim, content)

    def test_explicit_claim_must_appear_in_content(self):
        src = trusted_source()
        good = build_evidence(src, "alpha beta gamma", claim="beta")
        self.assertIsNotNone(good)
        self.assertEqual(good.extraction_method, "grounded_claim")
        bad = build_evidence(src, "alpha beta gamma", claim="not present")
        self.assertIsNone(bad)

    def test_no_fabricated_hash_or_claim(self):
        src = trusted_source(content_hash="trusted-hash")
        content = "grounded material"
        item = build_evidence(src, content)
        self.assertEqual(item.content_hash, "trusted-hash")
        self.assertIn(item.claim, content)

    def test_evidence_id_is_deterministic(self):
        args = ("ds-1", "https://x.example/a", "h", "claim")
        self.assertEqual(evidence_id_for(*args), evidence_id_for(*args))
        self.assertTrue(evidence_id_for(*args).startswith(EVIDENCE_ID_PREFIX))

    def test_inference_id_is_deterministic(self):
        self.assertEqual(
            inference_id_for("s", "b"), inference_id_for("s", "b")
        )
        self.assertTrue(inference_id_for("s", "b").startswith(INFERENCE_ID_PREFIX))


class TestGrounding(unittest.TestCase):
    def test_missing_content_becomes_unknown_not_evidence(self):
        src = trusted_source()
        block = integrate_discovery([src], {}, discovery_enabled=True)
        self.assertEqual(block.evidence_count, 0)
        self.assertEqual(len(block.evidence), 0)
        self.assertGreaterEqual(block.unknown_count, 1)
        self.assertEqual(block.sources[0].lifecycle, Lifecycle.FETCHED_SOURCE)

    def test_ineligible_source_not_evidence(self):
        generic = mk(
            "https://blog.example/post",
            content_hash="h9",
            source_quality=0.9,
        )
        block = integrate_discovery(
            [generic], {generic.source_id: "some content"}, discovery_enabled=True
        )
        self.assertEqual(block.evidence_count, 0)
        self.assertFalse(block.sources[0].eligible)
        self.assertNotEqual(block.sources[0].lifecycle, Lifecycle.EVIDENCE)

    def test_detection_rule_requires_advisory(self):
        det = detection_source()
        block = integrate_discovery(
            [det], {det.source_id: "rule content"}, discovery_enabled=True
        )
        self.assertEqual(block.evidence_count, 0)
        block2 = integrate_discovery(
            [det],
            {det.source_id: "rule content"},
            advisory_reference_by_source_id={det.source_id: CVE},
            discovery_enabled=True,
        )
        self.assertEqual(block2.evidence_count, 1)

    def test_no_network_during_integration(self):
        src = trusted_source()
        with mock.patch("socket.socket", side_effect=AssertionError("network access")):
            block = integrate_discovery(
                [src], {src.source_id: "content"}, discovery_enabled=True
            )
        self.assertEqual(block.evidence_count, 1)


class TestDedupIntegration(unittest.TestCase):
    def test_only_canonical_deduped_source_becomes_evidence(self):
        a = trusted_source(content_hash="same")
        b = mk(
            "https://mirror.example/a",
            content_hash="same",
            category=SourceCategory.SECURITY_BLOG,
            tier=TrustTier.GENERIC,
            source_quality=0.2,
        )
        merged = dedup_by_content_hash([a, b])
        self.assertEqual(len(merged), 1)
        block = integrate_discovery(
            merged, {a.source_id: "canonical content"}, discovery_enabled=True
        )
        self.assertEqual(block.evidence_count, 1)
        self.assertEqual(block.evidence[0].source_id, a.source_id)

    def test_aliases_remain_attached(self):
        a = trusted_source(content_hash="same")
        b = mk("https://mirror.example/a", content_hash="same",
               category=SourceCategory.SECURITY_BLOG, tier=TrustTier.GENERIC)
        merged = dedup_by_content_hash([a, b])
        block = integrate_discovery(
            merged, {a.source_id: "canonical content"}, discovery_enabled=True
        )
        self.assertIn(canonical_url(b), block.evidence[0].aliases)

    def test_duplicate_source_cannot_create_duplicate_evidence(self):
        src = trusted_source()
        block = integrate_discovery(
            [src, src], {src.source_id: "content"}, discovery_enabled=True
        )
        self.assertEqual(block.evidence_count, 1)
        self.assertEqual(len(block.evidence), 1)

    def test_full_pipeline_dedups_before_evidence(self):
        a = mk(
            "https://example.com/a?utm_source=x",
            content_hash="h1",
            category=SourceCategory.NVD_CVE,
            tier=TrustTier.TRUSTED,
            source_quality=0.9,
        )
        b = mk("https://EXAMPLE.com:443/a#frag", content_hash="h1",
               category=SourceCategory.NVD_CVE, tier=TrustTier.TRUSTED,
               source_quality=0.9)
        ranked = rank_sources([b, a], CVEResearchMetadata(cve_id=CVE))
        merged = dedup_discovered_sources(ranked)
        block = integrate_discovery(
            merged, {merged[0].source_id: "content"}, discovery_enabled=True
        )
        self.assertEqual(block.discovered_sources, 1)
        self.assertEqual(block.evidence_count, 1)

    def test_provenance_lists_providers(self):
        src = trusted_source()
        block = integrate_discovery(
            [src], {src.source_id: "content"}, discovery_enabled=True
        )
        self.assertEqual(block.providers, ["nvd"])


class TestInferences(unittest.TestCase):
    def test_inference_from_known_evidence_is_kept(self):
        src = trusted_source()
        block = integrate_discovery(
            [src], {src.source_id: "content"}, discovery_enabled=True
        )
        ev_id = block.evidence[0].evidence_id
        inf = DiscoveryInference(
            inference_id=inference_id_for("derived", "basis"),
            statement="derived from the advisory",
            basis="evidence",
            source_ids=[src.source_id],
            evidence_ids=[ev_id],
        )
        block3 = integrate_discovery(
            [src],
            {src.source_id: "content"},
            inferences=[inf],
            discovery_enabled=True,
        )
        self.assertEqual(block3.inference_count, 1)
        self.assertEqual(block3.inferences[0].inference_id, inf.inference_id)

    def test_inference_referencing_unknown_is_dropped(self):
        src = trusted_source()
        inf = DiscoveryInference(
            inference_id="di-x", statement="x", source_ids=["ds-unknown"]
        )
        block = integrate_discovery(
            [src],
            {src.source_id: "content"},
            inferences=[inf],
            discovery_enabled=True,
        )
        self.assertEqual(block.inference_count, 0)
        self.assertGreaterEqual(block.unknown_count, 1)


class TestSafety(unittest.TestCase):
    MODULE = Path("/opt/watch/ai/research_agent/evidence.py")

    def test_no_target_or_program_fields_on_models(self):
        forbidden = {
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
        }
        for model in (
            DiscoveryEvidence,
            DiscoveryInference,
            DiscoverySourceRecord,
            DiscoveryBlock,
        ):
            self.assertEqual(forbidden & set(model.model_fields), set(), model.__name__)

    def test_import_boundary(self):
        tree = ast.parse(self.MODULE.read_text(encoding="utf-8"))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        banned = (
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
        for module in modules:
            for needle in banned:
                self.assertFalse(
                    module == needle or module.startswith(needle + "."),
                    f"evidence.py imports {module}",
                )

    def test_no_network_or_exec_text(self):
        text = self.MODULE.read_text(encoding="utf-8")
        for token in (
            "import httpx",
            "import requests",
            "import subprocess",
            "import socket",
            "urllib.request",
            "http.client",
            "socket.socket",
        ):
            self.assertNotIn(token, text)
        self.assertIsNone(re.search(r"\b(eval|exec)\s*\(", text))

    def test_no_target_validation_semantics(self):
        text = self.MODULE.read_text(encoding="utf-8").lower()
        for token in ("target_confirmed", "vulnerable", "exploited", "verified"):
            self.assertNotIn(token, text)


class TestStorage(unittest.TestCase):
    def test_store_and_load_discovery_block(self):
        from ai.research_agent import storage

        block = integrate_discovery(
            [trusted_source()],
            {trusted_source().source_id: "content"},
            discovery_enabled=True,
            plan_id=PLAN,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path, written = storage.store_discovery(block, base=tmp)
            self.assertTrue(written)
            self.assertTrue(str(path).endswith(".discovery.json"))
            path2, written2 = storage.store_discovery(block, base=tmp)
            self.assertFalse(written2)
            self.assertEqual(path, path2)
            loaded = storage.load_discovery(PLAN, "r24-1", base=tmp)
            self.assertEqual(loaded["rule_version"], DISCOVERY_RULE_VERSION)
            self.assertEqual(loaded["discovery_enabled"], True)

    def test_r23_result_storage_untouched(self):
        from ai.research_agent import storage

        result = ResearchAgentResult(
            result_id="ra-test",
            run_id="run-test",
            plan_id=PLAN,
            cve_id=CVE,
            program="p",
            status="RESEARCH_PARTIAL",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path, written = storage.store_result(result, base=tmp)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(written)
            self.assertNotIn("discovery", payload)


class TestCompatibility(unittest.TestCase):
    def test_r24_1_through_r24_4_importable(self):
        import ai.research_agent.discovery_contract as c
        import ai.research_agent.dedup as d
        import ai.research_agent.ranking as r
        import ai.research_agent.provider_base as pb
        import ai.research_agent.netguard as ng

        self.assertTrue(hasattr(c, "DiscoveredSource"))
        self.assertTrue(hasattr(d, "canonicalize_url"))
        self.assertTrue(hasattr(r, "is_evidence_eligible"))
        self.assertTrue(hasattr(pb, "make_discovered_source"))
        self.assertTrue(hasattr(ng, "validate_url"))

    def test_block_serializes_without_target_info(self):
        block = integrate_discovery(
            [trusted_source()], discovery_enabled=True, plan_id=PLAN
        )
        payload = block.model_dump(mode="json")
        blob = json.dumps(payload)
        for token in ("program", "target_url", "asset"):
            self.assertNotIn(token, blob)


if __name__ == "__main__":
    unittest.main()

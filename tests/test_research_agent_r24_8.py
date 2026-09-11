"""tests/test_research_agent_r24_8.py — Stage R24.8 integration tests.

Offline, deterministic. Uses fake transports/resolvers/registries/fetchers/LLMs
so no live network is required.

Covers: NVD canonical host fix, real transport bounds/fail-closed behaviour,
netguard-routed provider discovery (DNS + redirect revalidation + private host
rejection), vendor-page evidence classification gate, discovery on/off
scheduler integration, lock reuse, deadline enforcement, safety boundaries and
systemd default.
"""
import ast
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    DiscoveryQuery,
    SearchProvider,
    SourceCategory,
    TrustTier,
    discovered_source_id,
    query_id_for,
)
from ai.research_agent.evidence import (
    build_evidence,
    content_has_required_token,
    integrate_discovery,
)
from ai.research_agent.llm_loop import FetchedSource, LoopBudgets
from ai.research_agent.transport import (
    HTTPTransport,
    SENSITIVE_HEADERS,
    TransportResult,
)
from ai.research_agent.provider_base import (
    BoundedHTTPClient,
    ProviderResponse,
    build_default_registry,
    make_discovered_source,
)
from ai.research_agent.scheduler import ResearchScheduler, SchedulerConfig
from ai.research_agent.discovery_runner import (
    DiscoveryResearchAgent,
    DiscoveryPlanResult,
    build_discovery_registry,
    load_cve_metadata,
)
from ai.research_agent.queries import CVEResearchMetadata

CVE = "CVE-2026-1557"
PLAN = {"plan_id": "r22-38d26f10681e9a0f", "cve_id": CVE, "program": "dell"}
PUBLIC_IP = "93.184.216.34"


def _q(text="CVE-2026-1557", provider=SearchProvider.NVD.value, template="r24-cve-id"):
    return DiscoveryQuery(
        query_id=query_id_for(template, provider, text, [text]),
        template_id=template,
        provider=provider,
        query=text,
        inputs_used=[text],
    )


def _resp(url, status=200, body="{}", content_type="application/json", final_url=None):
    return ProviderResponse(
        url=url,
        status=status,
        body=body,
        content_type=content_type,
        final_url=final_url or url,
    )


def _public_resolver(ip=PUBLIC_IP):
    calls = []

    def resolver(host):
        calls.append(host)
        return [ip]

    resolver.calls = calls
    return resolver


class TestNvdHost(unittest.TestCase):
    def test_nvd_canonical_host_is_services(self):
        from ai.research_agent import providers as P

        self.assertEqual(P.NVD_CANONICAL_HOSTS, ("services.nvd.nist.gov",))
        url = P.NVDProvider.NVD_DETAIL_URL.format(
            host=P.NVD_CANONICAL_HOSTS[0], cve_id=CVE
        )
        self.assertEqual(
            url,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557",
        )
        self.assertNotIn("//nvd.nist.gov", url)

    def test_nvd_provider_requests_services_host(self):
        seen = []

        def transport(method, url, **_kw):
            seen.append(url)
            return _resp(url, body=json.dumps({"vulnerabilities": []}))

        client = BoundedHTTPClient(transport=transport)
        provider = __import__(
            "ai.research_agent.providers", fromlist=["NVDProvider"]
        ).NVDProvider(http_client=client)
        provider.discover(_q())
        nvd_urls = [u for u in seen if "services.nvd.nist.gov" in u]
        self.assertTrue(nvd_urls, seen)
        self.assertIn(f"cveId={CVE}", nvd_urls[0])
        self.assertFalse(any("//nvd.nist.gov" in u for u in seen))


class TestTransport(unittest.TestCase):
    def test_bounds_and_no_redirect_following(self):
        calls = []

        def send(method, url, headers, timeout, params, **_kw):
            calls.append((method, url, dict(headers), timeout, params))
            return TransportResult(
                status=302,
                headers={"Content-Type": "text/html", "Location": "https://elsewhere/x"},
                body=b"x" * 9999,
                final_url=url,
                url=url,
            )

        t = HTTPTransport(send=send, max_bytes=10)
        resp = t("GET", "https://example.com/a")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 302)  # NOT followed
        self.assertEqual(len(resp.body), 10)  # bounded
        self.assertEqual(resp.content_type, "text/html")
        self.assertTrue(calls[0][2]["User-Agent"].startswith("Watch"))

    def test_rejects_credentials_and_sensitive_headers(self):
        t = HTTPTransport(send=lambda *a, **k: TransportResult(status=200))
        self.assertIsNone(t("GET", "https://user:pass@example.com/a"))
        self.assertIsNone(t("GET", "ftp://example.com/a"))
        self.assertIsNone(t("GET", "https://example.com/a", headers={"Authorization": "x"}))
        for name in ("Cookie", "X-Api-Key", "Proxy-Authorization"):
            self.assertIsNone(t("GET", "https://example.com/a", headers={name: "x"}))
        self.assertIn("authorization", SENSITIVE_HEADERS)

    def test_fail_closed_on_network_error(self):
        def boom(*a, **k):
            raise RuntimeError("network down")

        t = HTTPTransport(send=boom)
        self.assertIsNone(t("GET", "https://example.com/a"))


class TestNetguardRouting(unittest.TestCase):
    def test_provider_discovery_routes_through_netguard(self):
        resolver = _public_resolver()
        seen_urls = []

        def transport(method, url, **kw):
            seen_urls.append(url)
            return _resp(url, body="{}")

        registry = build_discovery_registry(transport, resolver=resolver)
        results = registry.discover(SearchProvider.NVD.value, _q())
        self.assertTrue(results)
        # DNS pre-resolution ran for provider hosts (netguard path).
        self.assertIn("services.nvd.nist.gov", resolver.calls)

    def test_private_resolution_blocks_provider(self):
        resolver = _public_resolver(ip="10.0.0.5")
        called = {"n": 0}

        def transport(method, url, **kw):
            called["n"] += 1
            return _resp(url)

        registry = build_discovery_registry(transport, resolver=resolver)
        self.assertEqual(registry.discover(SearchProvider.NVD.value, _q()), [])
        self.assertEqual(called["n"], 0)  # transport never reached

    def test_redirect_hop_revalidated_private(self):
        resolver = _public_resolver()

        def transport(method, url, **kw):
            return _resp(
                url,
                status=302,
                content_type="location: http://10.0.0.5/steal",
            )

        registry = build_discovery_registry(transport, resolver=resolver)
        self.assertEqual(registry.discover(SearchProvider.NVD.value, _q()), [])

    def test_redirect_hop_revalidated_metadata(self):
        resolver = _public_resolver()

        def transport(method, url, **kw):
            return _resp(
                url,
                status=302,
                content_type="location: http://169.254.169.254/latest/meta-data/",
            )

        registry = build_discovery_registry(transport, resolver=resolver)
        self.assertEqual(registry.discover(SearchProvider.NVD.value, _q()), [])

    def test_same_host_redirect_followed(self):
        resolver = _public_resolver()
        state = {"n": 0}

        def transport(method, url, **kw):
            state["n"] += 1
            if state["n"] == 1:
                return _resp(
                    url,
                    status=302,
                    content_type="location: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557",
                )
            return _resp(url, body="{}")

        registry = build_discovery_registry(transport, resolver=resolver)
        results = registry.discover(SearchProvider.NVD.value, _q())
        self.assertTrue(results)

    def test_route_flag_off_keeps_raw_transport(self):
        urls = []

        def transport(method, url, **kw):
            urls.append(url)
            return _resp(url)

        client = BoundedHTTPClient(transport=transport)  # flag defaults False
        client.request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=x")
        self.assertEqual(len(urls), 1)


class TestVendorEvidenceGate(unittest.TestCase):
    def _src(self, url="https://msrc.microsoft.com/update-guide/search?query=x", content_hash="h1"):
        return DiscoveredSource(
            source_id=discovered_source_id(url),
            url=url,
            category=SourceCategory.VENDOR_ADVISORY,
            tier=TrustTier.TRUSTED,
            source_quality=0.82,
            content_hash=content_hash,
        )

    def test_generic_vendor_page_not_evidence(self):
        src = self._src()
        content = {src.source_id: "Security Update Guide - Microsoft Security Response Center"}
        block = integrate_discovery(
            [src], content, discovery_enabled=True, required_content_tokens=[CVE]
        )
        self.assertEqual(block.evidence_count, 0)
        self.assertFalse(block.sources[0].eligible)
        self.assertIn("CVE/advisory-specific", block.sources[0].ineligible_reason)
        self.assertNotEqual(block.sources[0].lifecycle.value, "EVIDENCE")

    def test_cve_specific_advisory_is_evidence(self):
        src = self._src()
        content = {
            src.source_id: "Microsoft advisory: CVE-2026-1557 affects WP Responsive Images."
        }
        block = integrate_discovery(
            [src], content, discovery_enabled=True, required_content_tokens=[CVE]
        )
        self.assertEqual(block.evidence_count, 1)
        self.assertTrue(block.sources[0].eligible)

    def test_trusted_tier_alone_insufficient(self):
        src = self._src()
        item = build_evidence(
            src, "generic landing page with no cve", required_content_tokens=[CVE]
        )
        self.assertIsNone(item)

    def test_existing_eligibility_rules_intact_without_gate(self):
        src = self._src()
        content = {src.source_id: "Some advisory text without the identifier."}
        block = integrate_discovery([src], content, discovery_enabled=True)
        self.assertEqual(block.evidence_count, 1)

    def test_content_gate_helper(self):
        self.assertTrue(content_has_required_token("x CVE-2026-1557 y", [CVE]))
        self.assertFalse(content_has_required_token("generic", [CVE]))
        self.assertTrue(content_has_required_token("anything", None))


class _FakeRegistry:
    def __init__(self, sources):
        self._sources = sources
        self.calls = 0

    def discover(self, provider_id, query):
        self.calls += 1
        return list(self._sources)


def _trusted_source(content=True):
    return DiscoveredSource(
        source_id="ds-nvd-000000000000",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1557",
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        source_quality=0.82,
        discovery_provider="nvd",
        discovery_query=CVE,
        discovery_template_id="r24-cve-id",
    )


def _finding_fetcher():
    def fetcher(url):
        return FetchedSource(
            url=url,
            content=f"Public advisory for {CVE} describes the issue.",
            final_url=url,
            redirect_chain=(url,),
        )

    return fetcher


class TestDiscoveryAgentIntegration(unittest.TestCase):
    def _agent(self, **over):
        budgets = LoopBudgets(
            max_rounds=1,
            max_queries_per_plan=3,
            round2_reserve=0,
            max_queries_per_run=3,
            max_discovered=5,
            max_fetched_per_plan=3,
            max_fetched_per_run=3,
            max_bytes_per_run=4_000_000,
            max_llm_calls_per_plan=1,
            max_llm_calls_per_run=1,
        )
        kwargs = dict(
            registry=_FakeRegistry([_trusted_source()]),
            fetcher=_finding_fetcher(),
            budgets=budgets,
            metadata_loader=lambda cve: CVEResearchMetadata(cve_id=cve),
        )
        kwargs.update(over)
        return DiscoveryResearchAgent(**kwargs)

    def test_bounded_invocation(self):
        agent = self._agent()
        results, failures = agent.run_plans([PLAN], run_id="run-x", deadline=None)
        self.assertEqual(len(results), 1)
        self.assertEqual(failures, [])
        r = results[0]
        self.assertEqual(r.plan_id, PLAN["plan_id"])
        self.assertTrue(r.evidence)
        self.assertFalse(r.production_finding)

    def test_max_one_plan_by_default(self):
        agent = self._agent()
        results, _ = agent.run_plans([PLAN, dict(PLAN)], run_id="run-x")
        self.assertEqual(len(results), 1)

    def test_deadline_stops_before_plan(self):
        agent = self._agent()
        results, failures = agent.run_plans(
            [PLAN], run_id="run-x", per_plan_timeout=lambda: True
        )
        self.assertEqual(results, [])
        self.assertEqual(failures[0]["error"], "time budget expired")

    def test_past_deadline_stops(self):
        agent = self._agent()
        results, failures = agent.run_plans(
            [PLAN], run_id="run-x", deadline=0.0
        )
        self.assertEqual(results, [])
        self.assertTrue(failures)

    def test_target_tokens_excluded_from_llm_context(self):
        from ai.research_agent.llm_research import build_llm_context

        agent = self._agent()
        results, _ = agent.run_plans([PLAN], run_id="run-x")
        loop = results[0].loop_result
        block = loop.rounds[0].discovery
        content = {s.source_id: "Public advisory for CVE-2026-1557." for s in block.sources}
        ctx = build_llm_context(
            block,
            CVEResearchMetadata(cve_id=CVE),
            content_by_source_id=content,
            forbidden_tokens=["dell", "indeed"],
        )
        blob = json.dumps(ctx.model_dump(mode="json")).lower()
        self.assertNotIn("dell", blob)
        self.assertNotIn("indeed", blob)

    def test_production_finding_false(self):
        results, _ = self._agent().run_plans([PLAN], run_id="run-x")
        loop = results[0].loop_result
        self.assertFalse(loop.production_finding)
        self.assertTrue(loop.public_research_only)
        self.assertEqual(loop.status in ("RESEARCH_COMPLETED", "RESEARCH_PARTIAL", "RESEARCH_BLOCKED"), True)


class TestSchedulerIntegration(unittest.TestCase):
    def test_discovery_disabled_builds_r23_agent(self):
        from ai import research_cli
        from ai.research_agent.agent import ResearchAgent

        agent = research_cli._build_research_agent(SchedulerConfig())
        self.assertIsInstance(agent, ResearchAgent)
        self.assertNotIsInstance(agent, DiscoveryResearchAgent)

    def test_discovery_enabled_builds_discovery_agent(self):
        from ai import research_cli

        agent = research_cli._build_research_agent(SchedulerConfig(discovery=True, llm=False))
        self.assertIsInstance(agent, DiscoveryResearchAgent)

    def test_status_exposes_discovery(self):
        sch = ResearchScheduler(SchedulerConfig(), plan_loader=lambda: [])
        status = sch.status()
        self.assertIn("discovery", status)
        self.assertFalse(status["discovery"])
        sch2 = ResearchScheduler(SchedulerConfig(discovery=True), plan_loader=lambda: [])
        self.assertTrue(sch2.status()["discovery"])
        self.assertIn("discovery_budget", sch2.status())

    def test_discovery_env_default_false_and_override(self):
        self.assertFalse(SchedulerConfig.from_env({}).discovery)
        self.assertTrue(SchedulerConfig.from_env({"WATCH_RESEARCH_DISCOVERY": "true"}).discovery)
        cfg = SchedulerConfig.from_env(
            {"WATCH_RESEARCH_DISCOVERY_MAX_QUERIES_PER_PLAN": "3"}
        )
        self.assertEqual(cfg.discovery_max_queries_per_plan, 3)

    def test_scheduler_reuses_its_lock(self):
        from ai.research_agent import scheduler as schmod

        class SpyAgent:
            def run_plans(self, plans, **kw):
                return [], []

        with tempfile.TemporaryDirectory() as tmp:
            cfg = SchedulerConfig(
                enabled=True,
                discovery=True,
                lock_path=os.path.join(tmp, "research.lock"),
                agent_dir=tmp,
                max_plans=1,
            )
            sch = ResearchScheduler(
                cfg,
                agent=SpyAgent(),
                plan_loader=lambda: [dict(PLAN)],
            )
            with mock.patch.object(
                schmod, "acquire_lock", wraps=schmod.acquire_lock
            ) as m:
                sch.run_once(force=True)
            m.assert_called_once()
            self.assertEqual(m.call_args[0][0], cfg.lock_path)

    def test_backend_status_exposes_discovery(self):
        from backend import research_agent as view

        status = view.agent_status()
        self.assertIn("discovery", status)
        self.assertIn("discovery_budget", status)


class TestSystemdAndSafety(unittest.TestCase):
    SERVICE = Path("/opt/watch/systemd/watch-research.service")

    def test_systemd_discovery_disabled_default(self):
        text = self.SERVICE.read_text(encoding="utf-8")
        self.assertIn('Environment="WATCH_RESEARCH_DISCOVERY=false"', text)
        self.assertNotIn('Environment="WATCH_RESEARCH_DISCOVERY=true"', text)

    def test_new_modules_import_boundary(self):
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
        )
        for path in (
            Path("/opt/watch/ai/research_agent/transport.py"),
            Path("/opt/watch/ai/research_agent/discovery_runner.py"),
        ):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            modules = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.add(node.module)
            for module in modules:
                for b in banned:
                    self.assertFalse(
                        module == b or module.startswith(b + "."),
                        f"{path.name} imports {module}",
                    )
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\b(eval|exec)\s*\(", text), path.name)
            self.assertNotIn("import subprocess", text)
            self.assertNotIn("import socket", text)

    def test_load_cve_metadata_public_fields(self):
        meta = load_cve_metadata(CVE)
        self.assertEqual(meta.cve_id, CVE)
        self.assertTrue(meta.product)
        self.assertTrue(meta.version)
        # No target/program field exists on the metadata structure.
        for forbidden in ("program", "target", "asset", "target_url"):
            self.assertNotIn(forbidden, set(CVEResearchMetadata.__dataclass_fields__))


if __name__ == "__main__":
    unittest.main()

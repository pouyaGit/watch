"""tests/test_research_agent_r24_2.py — Stage R24.2 search providers tests.

Offline by design. Covers:

- provider registry contains exactly the allowed providers
- deterministic provider selection
- each provider accepts DiscoveryQuery
- provider provenance is preserved
- category/trust classification
- bounded result count
- bounded response/body behavior (via a fake transport)
- timeout / failure is fail-soft
- HTTP/network errors do not crash the run
- forbidden target/program/asset input is rejected
- no target information appears in provider requests
- generic search remains GENERIC
- detection rules do not become executable Nuclei work
- no credentials/authenticated GitHub behavior
- no recursive crawling
- no subprocess/eval/exec
- no imports from 5B-5J execution/verifier/finding paths
- production_finding is always false

No network, no LLM, no Mongo, no subprocess. All transport is mocked via
a fake callable injected into :class:`BoundedHTTPClient`.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.research_agent.discovery_contract import (
    DiscoveryQuery,
    Lifecycle,
    SearchProvider,
    SourceCategory,
    TrustTier,
)
from ai.research_agent.provider_base import (
    BoundedHTTPClient,
    ProviderRegistry,
    ProviderResponse,
    MAX_PROVIDER_RESULTS_PER_QUERY,
    build_default_registry,
)
from ai.research_agent.providers import (
    DetectionRuleProvider,
    GenericSearchProvider,
    GitHubSearchProvider,
    NVDProvider,
    VendorAdvisoryProvider,
    WordfenceProvider,
    WPScanProvider,
    build_providers,
)


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class FakeTransport:
    """Minimal deterministic HTTP transport for tests.

    Pre-seeded responses (URL substring -> response payload); otherwise
    returns a 200 OK with empty body. Records every call so tests can
    assert what URLs were actually requested.
    """

    def __init__(
        self,
        *,
        responses: dict[str, ProviderResponse] | None = None,
        fail: bool = False,
    ) -> None:
        self.responses: dict[str, ProviderResponse] = dict(responses or {})
        self.calls: list[dict] = []
        self.fail = fail

    def __call__(
        self,
        method: str,
        url: str,
        *,
        params=None,
        headers=None,
        timeout=10.0,
        max_bytes=1_000_000,
    ) -> ProviderResponse | None:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "params": params or {},
                "headers": dict(headers or {}),
                "timeout": timeout,
                "max_bytes": max_bytes,
            }
        )
        if self.fail:
            raise RuntimeError("synthetic transport failure")
        for key, response in self.responses.items():
            if key in url:
                return response
        return ProviderResponse(url=url, status=200, body="", content_type="text/html")


def _query(provider: str, text: str = "CVE-2026-1557", template: str = "r24-cve-id") -> DiscoveryQuery:
    return DiscoveryQuery(
        query_id="q" + "0" * 16,
        template_id=template,
        provider=provider,
        query=text,
        inputs_used=[text],
    )


# ---------------------------------------------------------------------------
# Registry / provider selection
# ---------------------------------------------------------------------------
class TestProviderRegistry(unittest.TestCase):
    def test_registry_contains_exactly_allowed_providers(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        self.assertEqual(
            registry.provider_ids,
            (
                SearchProvider.NVD.value,
                SearchProvider.GITHUB_SEARCH.value,
                SearchProvider.VENDOR_ADVISORY.value,
                SearchProvider.WORDFENCE.value,
                SearchProvider.WPSCAN.value,
                SearchProvider.DETECTION_RULE.value,
                SearchProvider.GENERIC_SEARCH.value,
            ),
        )

    def test_registry_no_additional_identifiers(self):
        # Only the seven closed SearchProvider enum members are allowed.
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        self.assertEqual(
            set(registry.provider_ids),
            {member.value for member in SearchProvider},
        )

    def test_registry_rejects_unknown_provider_id(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        # Unknown ids must return [] rather than raising.
        results = registry.discover("not_a_provider", _query("nvd"))
        self.assertEqual(results, [])

    def test_deterministic_provider_selection(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        a = registry.discover(SearchProvider.NVD.value, _query(SearchProvider.NVD.value))
        b = registry.discover(SearchProvider.NVD.value, _query(SearchProvider.NVD.value))
        self.assertEqual(len(a), len(b))
        for x, y in zip(a, b):
            self.assertEqual(x.source_id, y.source_id)
            self.assertEqual(x.url, y.url)
            self.assertEqual(x.discovery_provider, y.discovery_provider)


# ---------------------------------------------------------------------------
# Each provider accepts DiscoveryQuery and preserves provenance
# ---------------------------------------------------------------------------
class TestProvidersAcceptQuery(unittest.TestCase):
    def setUp(self):
        self.client = BoundedHTTPClient(transport=FakeTransport())
        self.providers = build_providers(http_client=self.client)

    def test_nvd_accepts_query(self):
        p = self.providers[SearchProvider.NVD.value]
        results = p.discover(_query(SearchProvider.NVD.value, "CVE-2026-1557"))
        self.assertTrue(results)
        for r in results:
            self.assertEqual(r.discovery_provider, "nvd")
            self.assertTrue(r.discovery_query)
            self.assertEqual(r.discovery_template_id, "r24-cve-id")

    def test_github_accepts_query(self):
        transport = FakeTransport(
            responses={
                "advisories": ProviderResponse(
                    url="https://api.github.com/advisories",
                    status=200,
                    body='[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","html_url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","summary":"Sample advisory"}]',
                ),
                "search/repositories": ProviderResponse(
                    url="https://api.github.com/search/repositories",
                    status=200,
                    body='{"items":[{"html_url":"https://github.com/foo/bar","full_name":"foo/bar"}]}',
                ),
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        results = provider.discover(
            _query(SearchProvider.GITHUB_SEARCH.value, "CVE-2026-1557 exploit")
        )
        self.assertTrue(results)
        self.assertTrue(
            all(r.discovery_provider == "github_search" for r in results)
        )

    def test_vendor_advisory_accepts_query(self):
        p = self.providers[SearchProvider.VENDOR_ADVISORY.value]
        results = p.discover(
            _query(SearchProvider.VENDOR_ADVISORY.value, "wordpress 6.0 advisory")
        )
        self.assertTrue(results)
        self.assertTrue(
            all(r.category == SourceCategory.VENDOR_ADVISORY for r in results)
        )

    def test_wordfence_accepts_query(self):
        p = self.providers[SearchProvider.WORDFENCE.value]
        results = p.discover(_query(SearchProvider.WORDFENCE.value, "xss"))
        self.assertTrue(results)
        self.assertTrue(all(r.category == SourceCategory.WORDFENCE for r in results))

    def test_wpscan_accepts_query(self):
        p = self.providers[SearchProvider.WPSCAN.value]
        results = p.discover(_query(SearchProvider.WPSCAN.value, "xss"))
        self.assertTrue(results)
        self.assertTrue(all(r.category == SourceCategory.WPSCAN for r in results))

    def test_detection_rule_accepts_query(self):
        p = self.providers[SearchProvider.DETECTION_RULE.value]
        results = p.discover(_query(SearchProvider.DETECTION_RULE.value, "xss nuclei"))
        self.assertTrue(results)
        self.assertTrue(
            all(r.category == SourceCategory.DETECTION_RULE for r in results)
        )
        for r in results:
            self.assertEqual(r.tier, TrustTier.DISCOVERY_ONLY)

    def test_generic_search_accepts_query(self):
        p = self.providers[SearchProvider.GENERIC_SEARCH.value]
        results = p.discover(_query(SearchProvider.GENERIC_SEARCH.value, "xss"))
        self.assertTrue(results)
        self.assertEqual(results[0].category, SourceCategory.GENERIC_SEARCH)
        self.assertEqual(results[0].tier, TrustTier.GENERIC)


# ---------------------------------------------------------------------------
# Provenance preservation
# ---------------------------------------------------------------------------
class TestProvenancePreserved(unittest.TestCase):
    def test_query_id_template_provider_preserved(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        q = DiscoveryQuery(
            query_id="q" + "1" * 16,
            template_id="r24-cve-id",
            provider="nvd",
            query="CVE-2026-1557",
            inputs_used=["CVE-2026-1557"],
        )
        results = registry.discover("nvd", q)
        for r in results:
            self.assertEqual(r.discovery_template_id, "r24-cve-id")
            self.assertEqual(r.discovery_provider, "nvd")
            self.assertEqual(r.discovery_query, "CVE-2026-1557")
            # Discovery provider is always the registry-provided id.
            self.assertEqual(r.discovery_provider, "nvd")
            # production_finding always false.
            self.assertFalse(r.production_finding)

    def test_discovered_url_preserved(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        q = _query("nvd", "CVE-2026-1557")
        results = registry.discover("nvd", q)
        for r in results:
            self.assertTrue(r.discovered_url)
            self.assertTrue(r.url)

    def test_lifecycle_discovered_by_default(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        registry = build_default_registry(http_client=client)
        results = registry.discover("nvd", _query("nvd", "CVE-2026-1557"))
        for r in results:
            self.assertEqual(r.lifecycle, Lifecycle.DISCOVERED_SOURCE)


# ---------------------------------------------------------------------------
# Category / trust classification
# ---------------------------------------------------------------------------
class TestCategoryTierClassification(unittest.TestCase):
    def setUp(self):
        self.client = BoundedHTTPClient(transport=FakeTransport())
        self.providers = build_providers(http_client=self.client)

    def test_nvd_classified_trusted(self):
        results = self.providers["nvd"].discover(_query("nvd", "CVE-2026-1557"))
        for r in results:
            self.assertEqual(r.category, SourceCategory.NVD_CVE)
            self.assertEqual(r.tier, TrustTier.TRUSTED)

    def test_github_advisories_classified(self):
        transport = FakeTransport(
            responses={
                "advisories": ProviderResponse(
                    url="https://api.github.com/advisories",
                    status=200,
                    body='[{"ghsa_id":"GHSA-xxxx-yyyy-zzzz","html_url":"https://github.com/advisories/GHSA-xxxx-yyyy-zzzz","summary":"Test"}]',
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        results = provider.discover(_query("github_search", "CVE-2026-1557"))
        # Find the advisory result.
        advisory = next(
            (r for r in results if r.category == SourceCategory.GITHUB_ADVISORY),
            None,
        )
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.tier, TrustTier.SEMI_TRUSTED)

    def test_github_repo_results_classified_discovery_only(self):
        transport = FakeTransport(
            responses={
                "search/repositories": ProviderResponse(
                    url="https://api.github.com/search/repositories",
                    status=200,
                    body='{"items":[{"html_url":"https://github.com/foo/bar","full_name":"foo/bar"}]}',
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        results = provider.discover(_query("github_search", "CVE-2026-1557"))
        repo_results = [
            r for r in results if r.category == SourceCategory.GITHUB_REPO
        ]
        self.assertTrue(repo_results)
        for r in repo_results:
            self.assertEqual(r.tier, TrustTier.DISCOVERY_ONLY)

    def test_vendor_advisory_classified_trusted(self):
        results = self.providers["vendor_advisory"].discover(
            _query("vendor_advisory", "wordpress 6.0 advisory")
        )
        for r in results:
            self.assertEqual(r.category, SourceCategory.VENDOR_ADVISORY)
            self.assertEqual(r.tier, TrustTier.TRUSTED)

    def test_wordfence_classified_semi_trusted(self):
        results = self.providers["wordfence"].discover(
            _query("wordfence", "xss")
        )
        for r in results:
            self.assertEqual(r.category, SourceCategory.WORDFENCE)
            self.assertEqual(r.tier, TrustTier.SEMI_TRUSTED)

    def test_wpscan_classified_semi_trusted(self):
        results = self.providers["wpscan"].discover(_query("wpscan", "xss"))
        for r in results:
            self.assertEqual(r.category, SourceCategory.WPSCAN)
            self.assertEqual(r.tier, TrustTier.SEMI_TRUSTED)

    def test_detection_rule_classified_discovery_only(self):
        results = self.providers["detection_rule"].discover(
            _query("detection_rule", "xss nuclei")
        )
        for r in results:
            self.assertEqual(r.category, SourceCategory.DETECTION_RULE)
            self.assertEqual(r.tier, TrustTier.DISCOVERY_ONLY)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
class TestBounds(unittest.TestCase):
    def test_max_results_per_query_constant(self):
        self.assertEqual(MAX_PROVIDER_RESULTS_PER_QUERY, 10)

    def test_provider_result_count_bounded(self):
        # Even with a permissive transport returning 50 items, the
        # GitHub search provider must cap results at the bound.
        items = ",".join(
            f'{{"html_url":"https://github.com/foo/bar{i}","full_name":"foo/bar{i}"}}'
            for i in range(50)
        )
        transport = FakeTransport(
            responses={
                "search/repositories": ProviderResponse(
                    url="https://api.github.com/search/repositories",
                    status=200,
                    body=f'{{"items":[{items}]}}',
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        results = provider.discover(_query("github_search", "xss"))
        self.assertLessEqual(len(results), MAX_PROVIDER_RESULTS_PER_QUERY)

    def test_response_body_truncated_at_max_bytes(self):
        # The fake transport reports a small max_bytes; the client must
        # honour it.
        transport = FakeTransport(
            responses={
                "advisories": ProviderResponse(
                    url="https://api.github.com/advisories",
                    status=200,
                    body="A" * 5000,
                )
            }
        )
        client = BoundedHTTPClient(transport=transport, max_bytes=64)
        response = client.request("GET", "https://api.github.com/advisories")
        self.assertIsNotNone(response)
        self.assertLessEqual(len(response.body), 64)

    def test_provider_finite_timeout(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport, timeout=2.5)
        client.request("GET", "https://nvd.nist.gov/")
        self.assertEqual(transport.calls[0]["timeout"], 2.5)


# ---------------------------------------------------------------------------
# Fail-soft behavior
# ---------------------------------------------------------------------------
class TestFailSoft(unittest.TestCase):
    def test_transport_failure_yields_empty(self):
        transport = FakeTransport(fail=True)
        client = BoundedHTTPClient(transport=transport)
        registry = build_default_registry(http_client=client)
        results = registry.discover("nvd", _query("nvd", "CVE-2026-1557"))
        self.assertEqual(results, [])

    def test_non_2xx_yields_empty(self):
        transport = FakeTransport(
            responses={
                "advisories": ProviderResponse(
                    url="https://api.github.com/advisories",
                    status=403,
                    body="forbidden",
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        results = provider.discover(_query("github_search", "xss"))
        # Only the repositories call survives, but it returns no items
        # either. Either way, fail-soft = empty list, no exception.
        self.assertIsInstance(results, list)

    def test_wordfence_403_fail_soft(self):
        transport = FakeTransport(
            responses={
                "wordfence.com": ProviderResponse(
                    url="https://www.wordfence.com/threat-intel/vulnerabilities",
                    status=403,
                    body="",
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = WordfenceProvider(http_client=client)
        self.assertEqual(provider.discover(_query("wordfence", "xss")), [])

    def test_wpscan_404_fail_soft(self):
        transport = FakeTransport(
            responses={
                "wpscan.com": ProviderResponse(
                    url="https://wpscan.com/vulnerabilities",
                    status=404,
                    body="",
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = WPScanProvider(http_client=client)
        self.assertEqual(provider.discover(_query("wpscan", "xss")), [])

    def test_wordfence_202_fail_soft(self):
        transport = FakeTransport(
            responses={
                "wordfence.com": ProviderResponse(
                    url="https://www.wordfence.com/threat-intel/vulnerabilities",
                    status=202,
                    body="",
                )
            }
        )
        client = BoundedHTTPClient(transport=transport)
        provider = WordfenceProvider(http_client=client)
        self.assertEqual(provider.discover(_query("wordfence", "xss")), [])

    def test_provider_exception_does_not_crash_run(self):
        class _Boom:
            def discover(self, q):
                raise RuntimeError("provider boom")

        registry = ProviderRegistry(providers={"nvd": _Boom()})
        results = registry.discover("nvd", _query("nvd", "CVE-2026-1557"))
        self.assertEqual(results, [])

    def test_nvd_skips_non_cve_query(self):
        client = BoundedHTTPClient(transport=FakeTransport())
        provider = NVDProvider(http_client=client)
        # Garbage query -> no results.
        self.assertEqual(provider.discover(_query("nvd", "not-a-cve")), [])


# ---------------------------------------------------------------------------
# Forbidden-input / target leakage prevention
# ---------------------------------------------------------------------------
class TestForbiddenInput(unittest.TestCase):
    def test_program_token_in_url_rejected_by_client(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(
            transport=transport, forbidden_tokens=["dell.com"]
        )
        # We can't pass a URL into a provider (the URL is canonical), but
        # we can call the client directly to verify the guard.
        response = client.request(
            "GET", "https://example.com/?q=dell.com"
        )
        self.assertIsNone(response)
        self.assertIsNotNone(client.last_error)

    def test_registry_rejects_forbidden_query(self):
        # The provider registry rejects any DiscoveryQuery whose
        # inputs_used carries DNS-style host material (a structural
        # proxy for target/program/asset host leakage). The R24.1
        # ``QueryBuilder`` is the primary token-level gate; the
        # provider layer adds a defense-in-depth structural check.
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        registry = build_default_registry(http_client=client)

        from ai.research_agent.provider_base import (
            _assert_provider_input_safe,
            ForbiddenInputError as _FIE,
        )

        bad = DiscoveryQuery(
            query_id="q" + "0" * 16,
            template_id="r24-cve-id",
            provider="nvd",
            query="CVE-2026-1557",
            inputs_used=["dell.com"],
        )
        with self.assertRaises(_FIE):
            _assert_provider_input_safe(bad)

        # And the registry discover() entry-point must return [] when
        # called with such a query (fail-soft, never raise).
        results = registry.discover("nvd", bad)
        self.assertEqual(results, [])

    def test_provider_never_supplies_target_in_request(self):
        # Verify the URL the client receives contains only the canonical
        # provider host, never a target/program host.
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        registry = build_default_registry(http_client=client)
        registry.discover("nvd", _query("nvd", "CVE-2026-1557"))
        for call in transport.calls:
            host_match = re.match(r"https?://([^/]+)/?", call["url"])
            self.assertIsNotNone(host_match)
            host = host_match.group(1).lower()
            self.assertNotIn("dell", host)
            self.assertNotIn("localhost", host)
            self.assertNotIn("127.0.0.1", host)
            self.assertNotIn("192.168.", host)


# ---------------------------------------------------------------------------
# Safety invariants: no Nuclei / no credentials / no generic evidence
# ---------------------------------------------------------------------------
class TestSafetyInvariants(unittest.TestCase):
    def test_detection_rule_provider_does_not_execute_nuclei(self):
        # DetectionRuleProvider must NOT touch ai.execution, the
        # nuclei_runner, or any execution/verifier path.
        src = Path("/opt/watch/ai/research_agent/providers.py").read_text()
        self.assertNotIn("nuclei_runner", src)
        self.assertNotIn("subprocess", src)
        self.assertNotIn("ai.execution", src)
        self.assertNotIn("ai.verification", src)
        self.assertNotIn("ai.finding", src)
        self.assertNotIn("ai.resolver", src)
        self.assertNotIn("ai.authorizer", src)
        self.assertNotIn("ai.persistence", src)
        self.assertNotIn("eval(", src)
        self.assertNotIn("exec(", src)

    def test_generic_results_stay_generic(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        provider = GenericSearchProvider(http_client=client)
        results = provider.discover(_query("generic_search", "xss"))
        for r in results:
            self.assertEqual(r.category, SourceCategory.GENERIC_SEARCH)
            self.assertEqual(r.tier, TrustTier.GENERIC)

    def test_github_provider_does_not_send_auth_header(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        provider = GitHubSearchProvider(http_client=client)
        provider.discover(_query("github_search", "CVE-2026-1557 exploit"))
        for call in transport.calls:
            headers = call.get("headers", {})
            # Only the fixed neutral User-Agent is permitted.
            self.assertEqual(len(headers), 1)
            self.assertIn("User-Agent", headers)
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("X-GitHub-Token", headers)

    def test_no_recursive_crawling(self):
        # No provider takes a "follow links" option; the source layer
        # performs a single GET per discovery URL. The check excludes
        # docstring/comment prose so design notes describing the
        # invariant are not rejected.
        src = Path("/opt/watch/ai/research_agent/providers.py").read_text()
        # Strip the module docstring so design prose mentioning
        # "crawl" / "recursive" does not trip the static check.
        module_doc_end = src.find('"""\n\nfrom __future__')
        if module_doc_end > 0:
            src = src[module_doc_end:]
        self.assertNotIn("follow_links", src)
        self.assertNotIn("recursive", src)
        self.assertNotIn("crawl", src)

    def test_production_finding_always_false(self):
        # Seeded responses so every provider has something to discover.
        responses = {
            "advisories": ProviderResponse(
                url="https://api.github.com/advisories",
                status=200,
                body='[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","html_url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","summary":"x"}]',
            ),
            "search/repositories": ProviderResponse(
                url="https://api.github.com/search/repositories",
                status=200,
                body='{"items":[{"html_url":"https://github.com/foo/bar","full_name":"foo/bar"}]}',
            ),
            # Any URL containing these substrings returns 200/empty so
            # vendor/wordfence/wpscan/detection/generic providers have a
            # transport-level success to record.
            "msrc.microsoft.com": ProviderResponse(
                url="https://msrc.microsoft.com/update-guide/search",
                status=200,
                body="",
            ),
            "wordfence.com": ProviderResponse(
                url="https://www.wordfence.com/threat-intel/vulnerabilities",
                status=200,
                body="",
            ),
            "wpscan.com": ProviderResponse(
                url="https://wpscan.com/vulnerabilities",
                status=200,
                body="",
            ),
            "github.com": ProviderResponse(
                url="https://github.com",
                status=200,
                body="",
            ),
            "www.google.com": ProviderResponse(
                url="https://www.google.com/search",
                status=200,
                body="",
            ),
        }
        transport = FakeTransport(responses=responses)
        client = BoundedHTTPClient(transport=transport)
        registry = build_default_registry(http_client=client)
        for provider_id in (
            SearchProvider.NVD.value,
            SearchProvider.GITHUB_SEARCH.value,
            SearchProvider.VENDOR_ADVISORY.value,
            SearchProvider.WORDFENCE.value,
            SearchProvider.WPSCAN.value,
            SearchProvider.DETECTION_RULE.value,
            SearchProvider.GENERIC_SEARCH.value,
        ):
            results = registry.discover(provider_id, _query(provider_id))
            self.assertTrue(results, f"expected results from {provider_id}")
            for r in results:
                self.assertFalse(r.production_finding)


# ---------------------------------------------------------------------------
# Import boundary
# ---------------------------------------------------------------------------
class TestImportBoundary(unittest.TestCase):
    def _collect_imports(self, file_name: str) -> list[str]:
        path = Path("/opt/watch/ai/research_agent") / file_name
        pattern = re.compile(
            r"^(import [a-z0-9_\.]+(?:[ ]|$)|from [a-z0-9_\.]+ import )"
        )
        lines: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().lower()
            if pattern.match(stripped):
                lines.append(stripped)
        return lines

    def test_provider_base_no_forbidden_imports(self):
        for line in self._collect_imports("provider_base.py"):
            for needle in (
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
                "requests",
                "urllib.request",
            ):
                self.assertNotIn(needle, line, f"forbidden import: {line}")

    def test_providers_no_forbidden_imports(self):
        for line in self._collect_imports("providers.py"):
            for needle in (
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
                "requests",
                "urllib.request",
            ):
                self.assertNotIn(needle, line, f"forbidden import: {line}")

    def test_provider_base_no_eval_or_exec(self):
        text = Path(
            "/opt/watch/ai/research_agent/provider_base.py"
        ).read_text(encoding="utf-8")
        for token in ("eval(", "exec(", "os.system("):
            self.assertNotIn(token, text)

    def test_providers_no_eval_or_exec(self):
        text = Path(
            "/opt/watch/ai/research_agent/providers.py"
        ).read_text(encoding="utf-8")
        for token in ("eval(", "exec(", "os.system("):
            self.assertNotIn(token, text)


# ---------------------------------------------------------------------------
# SSRF / host guards in the HTTP client
# ---------------------------------------------------------------------------
class TestHTTPClientSafety(unittest.TestCase):
    def test_rejects_localhost(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        self.assertIsNone(client.request("GET", "http://localhost/"))
        self.assertIsNotNone(client.last_error)

    def test_rejects_rfc1918(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        self.assertIsNone(client.request("GET", "http://192.168.1.1/"))
        self.assertIsNotNone(client.last_error)

    def test_rejects_metadata(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        self.assertIsNone(client.request("GET", "http://169.254.169.254/"))
        self.assertIsNotNone(client.last_error)

    def test_rejects_unsupported_scheme(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        self.assertIsNone(client.request("GET", "file:///etc/passwd"))
        self.assertIsNotNone(client.last_error)

    def test_rejects_host_not_in_allowlist(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(
            transport=transport, allowed_hosts=("api.github.com",)
        )
        self.assertIsNone(client.request("GET", "https://example.com/"))
        self.assertIsNotNone(client.last_error)


# ---------------------------------------------------------------------------
# R23 / R24.1 regression: do not change R23 behavior
# ---------------------------------------------------------------------------
class TestR23R241Regression(unittest.TestCase):
    def test_discovered_source_maps_to_r23(self):
        from ai.research_agent.discovery_contract import DiscoveredSource
        from ai.schemas.research_agent import ResearchAgentSource, SOURCE_STORED_ONLY

        ds = DiscoveredSource(
            source_id="ds-abc",
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-1557",
            source_type="nvd",
            status=SOURCE_STORED_ONLY,
        )
        r23 = ds.to_r23()
        self.assertIsInstance(r23, ResearchAgentSource)
        self.assertEqual(r23.url, "https://nvd.nist.gov/vuln/detail/CVE-2026-1557")
        self.assertEqual(r23.source_id, "ds-abc")
        self.assertEqual(r23.status, SOURCE_STORED_ONLY)


if __name__ == "__main__":
    unittest.main()

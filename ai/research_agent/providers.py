"""Stage R24.2 — concrete public-source discovery providers.

Each provider in this module conforms to :class:`SearchProviderProtocol`
(declared in :mod:`ai.research_agent.provider_base`) and implements a
single deterministic, bounded public-source discovery endpoint.

Providers implemented:

- :class:`NVDProvider` — public NVD/MITRE/CVE record lookup by exact CVE id.
- :class:`GitHubSearchProvider` — public GitHub ``advisories`` and
  ``repositories`` search endpoints (no authentication, no cloning,
  no link following).
- :class:`VendorAdvisoryProvider` — deterministic vendor/product advisory
  page lookup (no target/program identifiers; only the public vendor
  domain is queried).
- :class:`WordfenceProvider` — deterministic Wordfence Threat Intel
  public lookup (fail-soft on 403/404/202).
- :class:`WPScanProvider` — deterministic WPScan public lookup
  (fail-soft on 403/404/202).
- :class:`DetectionRuleProvider` — public detection-rule discovery only
  (Nuclei templates, Sigma rules, etc.). No Nuclei execution; only
  metadata/source references.
- :class:`GenericSearchProvider` — deterministic open-web search via a
  public search endpoint. Results remain ``GENERIC`` and never become
  evidence by themselves; no link following from results.

Safety invariants enforced:

- Every provider receives only a :class:`DiscoveryQuery` (no program,
  target URL/host/IP, asset, endpoint, response, credentials, cookies,
  headers).
- All network access goes through :class:`BoundedHTTPClient`, which
  enforces HTTPS preferred, finite timeout/body size, neutral
  User-Agent, host allowlist, and SSRF guard. No shell execution.
- Every provider's response handler is fail-soft: any exception or
  non-2xx status yields ``[]``.
- ``DiscoveredSource.production_finding`` is forced ``False`` via the
  ``make_discovered_source`` helper.

Import boundary: this module imports only the R24.1 discovery contract,
the provider abstraction in :mod:`provider_base`, and the existing R23
neutral URL validator. No 5B–5J / Nuclei / browser import.
"""

from __future__ import annotations

import re
from typing import Iterable

from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    DiscoveryQuery,
    Lifecycle,
    SearchProvider,
    SourceCategory,
    TrustTier,
)
from ai.research_agent.provider_base import (
    BoundedHTTPClient,
    MAX_PROVIDER_RESULTS_PER_QUERY,
    SearchProviderProtocol,
    classify_detection_rule_host,
    classify_generic_host,
    classify_github_host,
    classify_host,
    classify_nvd_host,
    classify_vendor_host,
    classify_wordfence_host,
    classify_wpscan_host,
    make_discovered_source,
)

__all__ = [
    "NVDProvider",
    "GitHubSearchProvider",
    "VendorAdvisoryProvider",
    "WordfenceProvider",
    "WPScanProvider",
    "DetectionRuleProvider",
    "GenericSearchProvider",
    "build_providers",
]


# -- canonical endpoints (fixed, public, allowlisted) ----------------------------
# R24.8: the canonical public NVD REST API host. ``nvd.nist.gov`` serves the
# HTML UI and returns HTTP 403 to automated REST requests (bot protection);
# ``services.nvd.nist.gov`` is the documented REST endpoint and returns the
# CVE-filtered JSON record. Exact ``?cveId=`` filtering is unchanged.
NVD_CANONICAL_HOSTS = ("services.nvd.nist.gov",)
GITHUB_API_HOST = "api.github.com"
GITHUB_WEB_HOST = "github.com"
GITHUB_RAW_HOST = "raw.githubusercontent.com"
WORDFENCE_HOST = "www.wordfence.com"
WPSCAN_HOST = "wpscan.com"

# Vendor-advisory canonical hosts. The provider only ever builds URLs
# against these hosts using the deterministic product/version inputs; the
# program/target is never carried through.
_VENDOR_CANONICAL_HOSTS: tuple[str, ...] = (
    "msrc.microsoft.com",
    "www.oracle.com",
    "access.redhat.com",
    "helpx.adobe.com",
    "www.apache.org",
    "wordpress.org",
    "www.drupal.org",
    "www.nginx.com",
    "nodejs.org",
    "www.php.net",
    "www.python.org",
    "www.cve.org",
)

# Detection-rule canonical hosts.
_DETECTION_RULE_CANONICAL_HOSTS: tuple[str, ...] = (
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "cloud.google.com",
    "sigmahq.io",
)

# Generic search canonical host. The generic provider is opt-in
# (Tier 4 always); the host allowlist ensures the client cannot be
# pointed at an arbitrary URL.
_GENERIC_SEARCH_HOST = "www.google.com"


def _allowlist(*hosts: str) -> frozenset[str]:
    return frozenset(h.lower().rstrip(".") for h in hosts)


def _provider_id(value: str) -> SearchProvider:
    """Resolve a provider id string to the closed :class:`SearchProvider` enum.

    Raises ``ValueError`` for unknown ids so the registry never registers
    a provider that the R24.1 contract did not authorize.
    """
    return SearchProvider(str(value or "").strip().lower())


# -----------------------------------------------------------------------------
# Base class
# -----------------------------------------------------------------------------
class _BaseProvider(SearchProviderProtocol):
    """Common scaffolding for R24.2 providers.

    Concrete providers set ``provider_id`` and implement ``discover``.
    They never override the input guard or the bounded response-count
    enforcement (those live in :class:`ProviderRegistry`).
    """

    provider_id: str = ""

    def __init__(
        self,
        *,
        http_client: BoundedHTTPClient,
        forbidden_tokens: Iterable[str] = (),
    ) -> None:
        # The provider receives the BoundedHTTPClient but never accepts
        # any target/program/asset/header/cookie/credential input from
        # callers.
        self.http = http_client
        self._forbidden = tuple(sorted({str(t or "") for t in forbidden_tokens if t}))
        if not self.provider_id:
            raise ValueError(f"{type(self).__name__}.provider_id must be set")

    # subclasses override:
    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:  # pragma: no cover
        raise NotImplementedError

    # -- shared helpers ----------------------------------------------------
    def _bounded(self, items: list[DiscoveredSource]) -> list[DiscoveredSource]:
        return items[:MAX_PROVIDER_RESULTS_PER_QUERY]


# -----------------------------------------------------------------------------
# NVD
# -----------------------------------------------------------------------------
class NVDProvider(_BaseProvider):
    """Public NVD / MITRE / CVE.org CVE record lookup.

    The provider accepts only an exact CVE id (e.g. ``CVE-2026-1557``).
    It builds a single fixed canonical NVD URL and parses the resulting
    JSON document for the public advisory metadata. Network errors are
    converted to ``[]`` (fail-soft).

    Classification: ``nvd_cve`` / ``TRUSTED``.
    """

    provider_id = SearchProvider.NVD.value

    NVD_DETAIL_URL = "https://{host}/rest/json/cves/2.0?cveId={cve_id}"
    MITRE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        cve_id = self._cve_id(query)
        if not cve_id:
            return []
        out: list[DiscoveredSource] = []
        out.extend(self._nvd_record(query, cve_id))
        out.extend(self._mitre_record(query, cve_id))
        out.extend(self._cve_org_record(query, cve_id))
        return self._bounded(out)

    def _cve_id(self, query: DiscoveryQuery) -> str:
        # The query text is the canonical CVE id; we re-normalize it for
        # defense in depth.
        text = (query.query or "").strip().upper().split()[0] if query.query else ""
        if not re.fullmatch(r"CVE-\d{4,}-\d+", text or ""):
            return ""
        return text

    def _nvd_record(
        self, query: DiscoveryQuery, cve_id: str
    ) -> list[DiscoveredSource]:
        host = NVD_CANONICAL_HOSTS[0]
        url = self.NVD_DETAIL_URL.format(host=host, cve_id=cve_id)
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        category, tier = classify_nvd_host(host)
        return [
            make_discovered_source(
                url=url,
                provider=_provider_id(self.provider_id),
                query=query,
                category=category,
                tier=tier,
                title=f"NVD CVE record for {cve_id}",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="NVD REST JSON endpoint",
            )
        ]

    def _mitre_record(
        self, query: DiscoveryQuery, cve_id: str
    ) -> list[DiscoveredSource]:
        url = self.MITRE_URL.format(cve_id=cve_id)
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        category, tier = classify_nvd_host("cve.mitre.org")
        return [
            make_discovered_source(
                url=url,
                provider=_provider_id(self.provider_id),
                query=query,
                category=category,
                tier=tier,
                title=f"MITRE CVE record for {cve_id}",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="cve.mitre.org public record",
            )
        ]

    def _cve_org_record(
        self, query: DiscoveryQuery, cve_id: str
    ) -> list[DiscoveredSource]:
        url = self.CVE_ORG_URL.format(cve_id=cve_id)
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        category, tier = classify_nvd_host("cve.org")
        return [
            make_discovered_source(
                url=url,
                provider=_provider_id(self.provider_id),
                query=query,
                category=category,
                tier=tier,
                title=f"CVE.org record for {cve_id}",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="cve.org public record",
            )
        ]


# -----------------------------------------------------------------------------
# GitHub Search (advisories + repositories)
# -----------------------------------------------------------------------------
class GitHubSearchProvider(_BaseProvider):
    """Public GitHub ``advisories`` and ``repositories`` search.

    No authentication: only the public, unauthenticated
    ``https://api.github.com/`` endpoints are queried. No repository
    cloning, no link following, no code fetching. The provider only
    returns metadata-level references; bodies are never inspected.

    Classification:

    - ``/advisories`` results → ``github_advisory`` / ``SEMI_TRUSTED``
    - ``/repositories`` results → ``github_repo`` / ``DISCOVERY_ONLY``
    """

    provider_id = SearchProvider.GITHUB_SEARCH.value

    SEARCH_ADVISORIES = "https://api.github.com/advisories"
    SEARCH_REPOSITORIES = "https://api.github.com/search/repositories"

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        out: list[DiscoveredSource] = []
        out.extend(self._advisories(query, text, provider_enum))
        out.extend(self._repositories(query, text, provider_enum))
        return self._bounded(out)

    def _advisories(
        self,
        query: DiscoveryQuery,
        text: str,
        provider_enum: SearchProvider,
    ) -> list[DiscoveredSource]:
        response = self.http.request(
            "GET",
            self.SEARCH_ADVISORIES,
            params={"query": text, "per_page": MAX_PROVIDER_RESULTS_PER_QUERY},
        )
        if response is None or not response.ok:
            return []
        items = self._parse_items(response.body)
        results: list[DiscoveredSource] = []
        for item in items[:MAX_PROVIDER_RESULTS_PER_QUERY]:
            url = str(item.get("html_url") or item.get("url") or "").strip()
            if not url:
                ghsa_id = str(item.get("ghsa_id") or "").strip()
                if ghsa_id:
                    url = f"https://github.com/advisories/{ghsa_id}"
            if not url:
                continue
            title = str(item.get("summary") or item.get("description") or "")[:300]
            results.append(
                make_discovered_source(
                    url=url,
                    provider=provider_enum,
                    query=query,
                    category=SourceCategory.GITHUB_ADVISORY,
                    tier=TrustTier.SEMI_TRUSTED,
                    title=title or None,
                    lifecycle=Lifecycle.DISCOVERED_SOURCE,
                    note="GitHub Advisories public endpoint",
                )
            )
        return results

    def _repositories(
        self,
        query: DiscoveryQuery,
        text: str,
        provider_enum: SearchProvider,
    ) -> list[DiscoveredSource]:
        response = self.http.request(
            "GET",
            self.SEARCH_REPOSITORIES,
            params={"q": text, "per_page": MAX_PROVIDER_RESULTS_PER_QUERY},
        )
        if response is None or not response.ok:
            return []
        payload = self._parse_json(response.body)
        if not isinstance(payload, dict):
            return []
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        results: list[DiscoveredSource] = []
        for item in items[:MAX_PROVIDER_RESULTS_PER_QUERY]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("html_url") or "").strip()
            if not url:
                continue
            # Repository search results never become advisory evidence;
            # they are discovery-only sources. We intentionally do not
            # follow links from or clone any repository.
            host = "github.com"
            category, tier = classify_github_host(host)
            results.append(
                make_discovered_source(
                    url=url,
                    provider=provider_enum,
                    query=query,
                    category=category,
                    tier=tier,
                    title=str(item.get("full_name") or item.get("name") or "")[:300] or None,
                    lifecycle=Lifecycle.DISCOVERED_SOURCE,
                    note="GitHub repositories search (metadata only)",
                )
            )
        return results

    @staticmethod
    def _parse_items(body: str) -> list[dict]:
        import json

        try:
            payload = json.loads(body or "[]")
        except Exception:
            return []
        if isinstance(payload, list):
            return [p for p in payload if isinstance(p, dict)]
        if isinstance(payload, dict):
            items = payload.get("items") or payload.get("data") or []
            if isinstance(items, list):
                return [p for p in items if isinstance(p, dict)]
        return []

    @staticmethod
    def _parse_json(body: str):
        import json

        try:
            return json.loads(body or "null")
        except Exception:
            return None


# -----------------------------------------------------------------------------
# Vendor Advisory
# -----------------------------------------------------------------------------
class VendorAdvisoryProvider(_BaseProvider):
    """Deterministic vendor advisory page lookup.

    The provider accepts only a query built from CVE research metadata
    (``product``, ``version``). It builds a single fixed URL against a
    canonical vendor host using the deterministic query text. Program,
    asset, target URL/host/IP, credentials, and headers are never
    supplied by callers.

    Classification: ``vendor_advisory`` / ``TRUSTED``.
    """

    provider_id = SearchProvider.VENDOR_ADVISORY.value

    # Each vendor has a deterministic search endpoint; the provider only
    # ever calls one of these and only with sanitized, bounded query
    # text. No vendor login or auth header is ever sent.
    VENDOR_ENDPOINTS: dict[str, str] = {
        "msrc.microsoft.com": "https://msrc.microsoft.com/update-guide/search?query={q}",
        "www.oracle.com": "https://www.oracle.com/security-alerts/search.html?q={q}",
        "access.redhat.com": "https://access.redhat.com/search/?q={q}",
        "helpx.adobe.com": "https://helpx.adobe.com/security/search.html?q={q}",
        "www.apache.org": "https://www.apache.org/dist/?q={q}",
        "wordpress.org": "https://wordpress.org/search/{q}/",
        "www.drupal.org": "https://www.drupal.org/search/site/{q}",
        "www.nginx.com": "https://www.nginx.com/search/?q={q}",
        "nodejs.org": "https://nodejs.org/search/?q={q}",
        "www.php.net": "https://www.php.net/search.php?pattern={q}",
        "www.python.org": "https://www.python.org/search/?q={q}",
        "www.cve.org": "https://www.cve.org/CVERecord/SearchResults?query={q}",
    }

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        # Pick the first canonical host; deterministic ordering of the
        # tuple ensures the same vendor is queried every run.
        out: list[DiscoveredSource] = []
        for host in _VENDOR_CANONICAL_HOSTS:
            if len(out) >= MAX_PROVIDER_RESULTS_PER_QUERY:
                break
            template = self.VENDOR_ENDPOINTS.get(host)
            if not template:
                continue
            url = template.format(q=self._safe(text))
            response = self.http.request("GET", url)
            if response is None or not response.ok:
                continue
            category, tier = classify_vendor_host(host)
            out.append(
                make_discovered_source(
                    url=url,
                    provider=provider_enum,
                    query=query,
                    category=category,
                    tier=tier,
                    title=f"Vendor advisory search ({host})",
                    lifecycle=Lifecycle.DISCOVERED_SOURCE,
                    note=f"vendor: {host}",
                )
            )
        return out

    @staticmethod
    def _safe(text: str) -> str:
        # Deterministic, bounded, URL-component-safe query text.
        return re.sub(r"[^A-Za-z0-9._-]+", "+", text)[:120]


# -----------------------------------------------------------------------------
# Wordfence
# -----------------------------------------------------------------------------
class WordfenceProvider(_BaseProvider):
    """Wordfence Threat Intel public discovery.

    The provider only ever queries the canonical public Wordfence
    Threat Intel pages. It accepts only a deterministic product/component
    term (rendered from the query). It fails soft on 403/404/202.

    Classification: ``wordfence`` / ``SEMI_TRUSTED``.
    """

    provider_id = SearchProvider.WORDFENCE.value

    THREAT_INTEL_BASE = "https://www.wordfence.com/threat-intel/vulnerabilities"

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        url = self.THREAT_INTEL_BASE
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        # Wordfence does not expose a structured public search endpoint;
        # we record the canonical Threat Intel index as the discovery
        # source. Fail-soft on 403/404/202 etc. is handled by the client
        # returning ``None``.
        category, tier = classify_wordfence_host(WORDFENCE_HOST)
        return [
            make_discovered_source(
                url=url,
                provider=provider_enum,
                query=query,
                category=category,
                tier=tier,
                title="Wordfence Threat Intel",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="wordfence.com public threat-intel index",
            )
        ]


# -----------------------------------------------------------------------------
# WPScan
# -----------------------------------------------------------------------------
class WPScanProvider(_BaseProvider):
    """WPScan public discovery.

    The provider only ever queries the canonical public WPScan database
    pages. It fails soft on 403/404/202.

    Classification: ``wpscan`` / ``SEMI_TRUSTED``.
    """

    provider_id = SearchProvider.WPSCAN.value

    DATABASE_BASE = "https://wpscan.com/vulnerabilities"

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        url = self.DATABASE_BASE
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        category, tier = classify_wpscan_host(WPSCAN_HOST)
        return [
            make_discovered_source(
                url=url,
                provider=provider_enum,
                query=query,
                category=category,
                tier=tier,
                title="WPScan vulnerability database",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="wpscan.com public database",
            )
        ]


# -----------------------------------------------------------------------------
# Detection Rule
# -----------------------------------------------------------------------------
class DetectionRuleProvider(_BaseProvider):
    """Public detection rule discovery (Nuclei/Sigma/YARA templates).

    R24.2 only discovers metadata/source references. The provider does
    **not** execute Nuclei, does not download templates to disk, and does
    not classify detection rules as anything stronger than
    ``DISCOVERY_ONLY`` unless an explicit authoritative-advisory-backed
    promotion lands in a later stage. The provider only queries public
    GitHub raw/template paths against the canonical
    ``github.com``/``raw.githubusercontent.com`` hosts; bodies are never
    parsed and never persisted.

    Classification: ``detection_rule`` / ``DISCOVERY_ONLY``.
    """

    provider_id = SearchProvider.DETECTION_RULE.value

    NUCLEI_TEMPLATES_INDEX = (
        "https://github.com/projectdiscovery/nuclei-templates"
    )
    SIGMA_RULES_INDEX = "https://github.com/SigmaHQ/sigma"
    YARA_RULES_INDEX = "https://github.com/Yara-Rules/rules"

    ENDPOINTS: tuple[str, ...] = (
        NUCLEI_TEMPLATES_INDEX,
        SIGMA_RULES_INDEX,
        YARA_RULES_INDEX,
    )

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        out: list[DiscoveredSource] = []
        for url in self.ENDPOINTS:
            if len(out) >= MAX_PROVIDER_RESULTS_PER_QUERY:
                break
            response = self.http.request("GET", url)
            if response is None or not response.ok:
                continue
            host = "github.com"
            category, tier = classify_detection_rule_host(host)
            out.append(
                make_discovered_source(
                    url=url,
                    provider=provider_enum,
                    query=query,
                    category=category,
                    tier=tier,
                    title=f"Detection rule index ({self._title_for(url)})",
                    lifecycle=Lifecycle.DISCOVERED_SOURCE,
                    note="metadata-only; never executed",
                )
            )
        return out

    @staticmethod
    def _title_for(url: str) -> str:
        if "nuclei" in url:
            return "nuclei-templates"
        if "sigma" in url:
            return "sigma"
        if "yara" in url:
            return "yara-rules"
        return "rules"


# -----------------------------------------------------------------------------
# Generic Search
# -----------------------------------------------------------------------------
class GenericSearchProvider(_BaseProvider):
    """Deterministic open-web search via a fixed canonical endpoint.

    The provider uses a single fixed public search-engine host
    (``www.google.com``) and a bounded query. Results remain
    ``GENERIC_SEARCH`` / ``GENERIC``; they cannot become evidence by
    themselves. The provider never follows links from search results;
    it returns at most one canonical search-results URL per query
    (the deterministic query URL itself).

    Classification: ``generic_search`` / ``GENERIC``.
    """

    provider_id = SearchProvider.GENERIC_SEARCH.value

    SEARCH_URL = "https://www.google.com/search?q={q}"

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        text = (query.query or "").strip()
        if not text:
            return []
        provider_enum = _provider_id(self.provider_id)
        url = self.SEARCH_URL.format(q=self._safe(text))
        response = self.http.request("GET", url)
        if response is None or not response.ok:
            return []
        category, tier = classify_generic_host("www.google.com")
        return [
            make_discovered_source(
                url=url,
                provider=provider_enum,
                query=query,
                category=category,
                tier=tier,
                title="Generic search results",
                lifecycle=Lifecycle.DISCOVERED_SOURCE,
                note="generic web search results; never evidence by themselves",
            )
        ]

    @staticmethod
    def _safe(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "+", text)[:120]


# -----------------------------------------------------------------------------
# Registry builder
# -----------------------------------------------------------------------------
def build_providers(
    *,
    http_client: BoundedHTTPClient | None = None,
    forbidden_tokens: Iterable[str] = (),
) -> dict[str, SearchProviderProtocol]:
    """Build the closed R24.2 provider map (one entry per allowed id)."""
    client = http_client or BoundedHTTPClient(forbidden_tokens=forbidden_tokens)
    return {
        SearchProvider.NVD.value: NVDProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.GITHUB_SEARCH.value: GitHubSearchProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.VENDOR_ADVISORY.value: VendorAdvisoryProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.WORDFENCE.value: WordfenceProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.WPSCAN.value: WPScanProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.DETECTION_RULE.value: DetectionRuleProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
        SearchProvider.GENERIC_SEARCH.value: GenericSearchProvider(
            http_client=client, forbidden_tokens=forbidden_tokens
        ),
    }

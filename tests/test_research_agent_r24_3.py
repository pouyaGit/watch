"""tests/test_research_agent_r24_3.py — Stage R24.3 URL/Redirect Hardening.

Offline by design. Covers:

- DNS pre-resolution: rejects private/loopback/link-local/metadata/
  multicast/reserved/unspecified IPv4 + IPv6; fails closed on DNS
  errors; treats any-non-public address as host rejection.
- URL guards: scheme, default-port rule, embedded credentials,
  localhost / *.local / *.internal, program/asset host, allowlist.
- Manual redirect walker: per-hop validation, MAX_REDIRECTS=3,
  redirect to private/localhost/metadata IP, redirect to non-default
  port, scheme downgrade, embedded credentials in Location, redirect
  loop, relative Location resolved via urljoin.
- Provenance: redirect_chain lists every fetched URL, final_url is
  the last validated URL, discovered_url preserved.
- Fail-soft: transport failure, DNS failure, hop failure.
- Bounded: timeout, body size.
- HTTP seam: provider_base seam invokes netguard and returns a
  ProviderResponse-shaped object.
- Import boundary: no ai.execution/verification/finding/resolver/
  authorizer/persistence/nuclei_runner/browser/subprocess/eval/exec.
- production_finding is never touched.
- R23 / R24.1 / R24.2 regression: existing tests still importable
  and the R24.2 seam still works.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.research_agent.netguard import (
    MAX_REDIRECTS,
    NetGuardError,
    RedirectResult,
    resolve_public_ips,
    safe_fetch_with_redirects,
    validate_hop,
    validate_url,
)
from ai.research_agent.provider_base import (
    BoundedHTTPClient,
    ProviderResponse,
)


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class FakeTransport:
    """Bounded URL → response map.

    Accepts a mapping of URL (or URL prefix) → ProviderResponse.
    Records every call so tests can assert which URLs were actually
    fetched. Exact-match keys win over prefix-match keys, and among
    prefix-match keys the longest key wins (so ``/a`` does not
    accidentally match a request to ``/a/b``).
    """

    def __init__(
        self,
        *,
        responses: dict[str, ProviderResponse] | None = None,
    ) -> None:
        self.responses: dict[str, ProviderResponse] = dict(responses or {})
        self.calls: list[dict] = []

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
                "timeout": timeout,
                "max_bytes": max_bytes,
            }
        )
        # Exact match first.
        if url in self.responses:
            return self.responses[url]
        # Prefix match: longest key wins (deterministic ordering).
        for key in sorted(self.responses.keys(), key=len, reverse=True):
            if url.startswith(key):
                return self.responses[key]
        return None


def _resolver_for(mapping: dict[str, list[str]]):
    """Build a deterministic resolver from a hostname→IPs mapping."""

    def _resolver(host: str) -> list[str]:
        return list(mapping.get(host, []))

    return _resolver


def _provider(
    *,
    resolver=None,
    responses: dict[str, ProviderResponse] | None = None,
    allowed_hosts=None,
) -> tuple[BoundedHTTPClient, FakeTransport]:
    transport = FakeTransport(responses=responses)
    client = BoundedHTTPClient(
        transport=transport,
        timeout=10.0,
        max_bytes=1_000_000,
        allowed_hosts=allowed_hosts,
    )
    # Attach resolver for tests to consume (the seam doesn't take a
    # resolver argument; tests call safe_fetch_with_redirects directly).
    client._resolver = resolver  # type: ignore[attr-defined]
    return client, transport


# ---------------------------------------------------------------------------
# DNS pre-resolution
# ---------------------------------------------------------------------------
class TestDNSGuard(unittest.TestCase):
    def test_public_ipv4_accepted(self):
        self.assertTrue(resolve_public_ips("example.com", resolver=_resolver_for({"example.com": ["93.184.216.34"]})))

    def test_loopback_rejected(self):
        self.assertEqual(resolve_public_ips("localhost"), [])

    def test_loopback_literal_rejected(self):
        self.assertEqual(resolve_public_ips("127.0.0.1"), [])

    def test_private_10_rejected(self):
        self.assertEqual(
            resolve_public_ips("router.corp", resolver=_resolver_for({"router.corp": ["10.0.0.1"]})),
            [],
        )

    def test_private_192_rejected(self):
        self.assertEqual(
            resolve_public_ips("host.local", resolver=_resolver_for({"host.local": ["192.168.1.1"]})),
            [],
        )

    def test_private_172_rejected(self):
        self.assertEqual(
            resolve_public_ips("host", resolver=_resolver_for({"host": ["172.16.5.5"]})),
            [],
        )

    def test_link_local_rejected(self):
        self.assertEqual(
            resolve_public_ips("169.254.169.254"), []
        )

    def test_metadata_ipv4_rejected(self):
        # Even as a hostname with metadata IP resolution
        self.assertEqual(
            resolve_public_ips("metadata.google.internal")
            , []
        )

    def test_ipv6_loopback_rejected(self):
        self.assertEqual(resolve_public_ips("::1"), [])

    def test_ipv6_ula_rejected(self):
        self.assertEqual(
            resolve_public_ips("internal", resolver=_resolver_for({"internal": ["fd00::1"]})),
            [],
        )

    def test_ipv6_link_local_rejected(self):
        self.assertEqual(
            resolve_public_ips("host6", resolver=_resolver_for({"host6": ["fe80::1"]})),
            [],
        )

    def test_ipv6_documentation_rejected(self):
        # 2001:db8::/32 is reserved for documentation; is_reserved=True.
        self.assertEqual(
            resolve_public_ips("docs", resolver=_resolver_for({"docs": ["2001:db8::1"]})),
            [],
        )

    def test_any_non_public_rejects_host(self):
        # Mixed resolution: one public, one private → fail closed.
        self.assertEqual(
            resolve_public_ips("dual", resolver=_resolver_for({"dual": ["1.1.1.1", "10.0.0.1"]})),
            [],
        )

    def test_dns_failure_fail_closed(self):
        def _boom(host: str):
            raise OSError("synthetic DNS failure")

        self.assertEqual(resolve_public_ips("example.com", resolver=_boom), [])

    def test_dns_empty_fail_closed(self):
        self.assertEqual(resolve_public_ips("example.com", resolver=_resolver_for({})), [])

    def test_blocked_suffix_rejected(self):
        # Hostname suffix .local / .internal is rejected even without
        # resolution (belt-and-braces alongside the IP literal guard).
        self.assertEqual(
            resolve_public_ips("svc.internal", resolver=_resolver_for({"svc.internal": ["1.2.3.4"]})),
            [],
        )


# ---------------------------------------------------------------------------
# URL guards
# ---------------------------------------------------------------------------
class TestURLGuard(unittest.TestCase):
    def test_http_default_port_ok(self):
        self.assertEqual(validate_url("http://example.com/"), "http://example.com/")

    def test_https_default_port_ok(self):
        self.assertEqual(validate_url("https://example.com/"), "https://example.com/")

    def test_non_default_https_port_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://example.com:8443/")

    def test_non_default_http_port_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("http://example.com:81/")

    def test_embedded_user_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://user@example.com/")

    def test_embedded_user_password_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://user:pass@example.com/")

    def test_file_scheme_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("file:///etc/passwd")

    def test_data_scheme_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("data:text/plain,hello")

    def test_ftp_scheme_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("ftp://example.com/")

    def test_localhost_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://localhost/")

    def test_metadata_hostname_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://metadata.google.internal/")

    def test_metadata_ip_literal_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://169.254.169.254/")

    def test_program_host_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://dell.com/", program="dell")

    def test_program_label_match_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://dell.example.com/", program="dell")

    def test_allowlist_blocks_other(self):
        with self.assertRaises(NetGuardError):
            validate_url("https://other.com/", allowed_hosts=("example.com",))

    def test_allowlist_allows_match(self):
        self.assertEqual(
            validate_url("https://example.com/", allowed_hosts=("example.com",)),
            "https://example.com/",
        )

    def test_allowlist_subdomain_match(self):
        self.assertEqual(
            validate_url(
                "https://api.example.com/", allowed_hosts=("example.com",)
            ),
            "https://api.example.com/",
        )

    def test_empty_url_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("")

    def test_no_host_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_url("https:///path")


# ---------------------------------------------------------------------------
# Hop guard (redirect-specific rules)
# ---------------------------------------------------------------------------
class TestHopGuard(unittest.TestCase):
    def test_https_to_http_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_hop("https://example.com/a", "http://example.com/b")

    def test_http_to_https_allowed(self):
        # http→https upgrade is allowed (security improvement).
        self.assertEqual(
            validate_hop("http://example.com/a", "https://example.com/b"),
            "https://example.com/b",
        )

    def test_relative_location_resolved(self):
        self.assertEqual(
            validate_hop("https://example.com/a/b", "/c"),
            "https://example.com/c",
        )

    def test_relative_dotdot_resolved(self):
        self.assertEqual(
            validate_hop(
                "https://example.com/a/b/c", "../d"
            ),
            "https://example.com/a/d",
        )

    def test_hop_with_credentials_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_hop("https://example.com/", "https://user:pass@example.com/")

    def test_hop_non_default_port_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_hop("https://example.com/", "https://example.com:8443/")

    def test_hop_program_host_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_hop(
                "https://example.com/", "https://dell.com/", program="dell"
            )

    def test_hop_allowlist_enforced(self):
        with self.assertRaises(NetGuardError):
            validate_hop(
                "https://example.com/",
                "https://other.com/",
                allowed_hosts=("example.com",),
            )

    def test_hop_empty_location_rejected(self):
        with self.assertRaises(NetGuardError):
            validate_hop("https://example.com/", "")


# ---------------------------------------------------------------------------
# Manual redirect walker
# ---------------------------------------------------------------------------
def _ok(url: str, body: str = "OK") -> ProviderResponse:
    return ProviderResponse(url=url, status=200, body=body, content_type="text/plain")


def _redirect(url: str, location: str, status: int = 301) -> ProviderResponse:
    return ProviderResponse(
        url=url,
        status=status,
        body="",
        content_type=f"location:{location}",
    )


class TestRedirectWalker(unittest.TestCase):
    def test_initial_2xx_short_circuits(self):
        transport = FakeTransport(
            responses={"https://example.com/": _ok("https://example.com/")}
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, "OK")
        self.assertEqual(result.redirect_chain, ["https://example.com/"])
        self.assertEqual(result.final_url, "https://example.com/")

    def test_single_redirect(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://example.com/final"
                ),
                "https://example.com/final": _ok(
                    "https://example.com/final", "final-body"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.body, "final-body")
        self.assertEqual(
            result.redirect_chain,
            ["https://example.com/", "https://example.com/final"],
        )
        self.assertEqual(result.final_url, "https://example.com/final")
        self.assertEqual(result.hops, 1)

    def test_three_hops_ok(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://example.com/a"
                ),
                "https://example.com/a": _redirect(
                    "https://example.com/a", "https://example.com/b"
                ),
                "https://example.com/b": _redirect(
                    "https://example.com/b", "https://example.com/c"
                ),
                "https://example.com/c": _ok("https://example.com/c"),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.hops, 3)
        self.assertEqual(len(result.redirect_chain), 4)

    def test_fourth_redirect_hard_stop(self):
        # MAX_REDIRECTS = 3, so the 4th redirect must stop.
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://example.com/a"
                ),
                "https://example.com/a": _redirect(
                    "https://example.com/a", "https://example.com/b"
                ),
                "https://example.com/b": _redirect(
                    "https://example.com/b", "https://example.com/c"
                ),
                "https://example.com/c": _redirect(
                    "https://example.com/c", "https://example.com/d"
                ),
                "https://example.com/d": _ok("https://example.com/d"),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "redirect_limit")
        self.assertEqual(result.reason, "redirect_loop")
        # 4 fetches total (initial + 3 hops), then the 4th redirect is
        # the hard stop.
        self.assertEqual(len(transport.calls), 4)

    def test_max_redirects_constant(self):
        self.assertEqual(MAX_REDIRECTS, 3)

    def test_redirect_to_private_ip_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://10.0.0.5/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "private_ip")
        # Initial URL is in the chain; no hop succeeded.
        self.assertEqual(result.redirect_chain, ["https://example.com/"])

    def test_redirect_to_localhost_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://localhost/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        # Either rejected as a non-public host or as an off-allowlist.
        self.assertIn(result.reason, ("host", "private_ip"))

    def test_redirect_to_metadata_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "http://169.254.169.254/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)

    def test_redirect_to_non_default_port_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://example.com:8443/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "port")

    def test_redirect_with_credentials_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://user:pass@example.com/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "embedded_credentials")

    def test_scheme_downgrade_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "http://example.com/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "scheme_downgrade")

    def test_redirect_loop_detected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/a": _redirect(
                    "https://example.com/a", "https://example.com/b"
                ),
                "https://example.com/b": _redirect(
                    "https://example.com/b", "https://example.com/a"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/a",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "redirect_loop")

    def test_relative_location_resolved(self):
        transport = FakeTransport(
            responses={
                "https://example.com/a": _redirect(
                    "https://example.com/a", "/b"
                ),
                "https://example.com/b": _ok("https://example.com/b"),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/a",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.final_url, "https://example.com/b")

    def test_redirect_to_program_host_rejected(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://dell.com/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
            program="dell",
        )
        self.assertFalse(result.ok)
        # Either off-allowlist (host/allowlist) or program-host reason.
        self.assertIn(result.reason, ("host", "allowlist", "program_host"))


# ---------------------------------------------------------------------------
# DNS / transport fail-soft
# ---------------------------------------------------------------------------
class TestFailSoft(unittest.TestCase):
    def test_dns_failure_fail_closed(self):
        transport = FakeTransport()
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({}),  # NXDOMAIN-equivalent
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "private_ip")
        self.assertEqual(len(transport.calls), 0)

    def test_dns_resolver_exception_fail_closed(self):
        def _boom(host: str):
            raise OSError("gaierror")

        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=FakeTransport(),
            resolver=_boom,
        )
        self.assertFalse(result.ok)

    def test_transport_exception_fail_soft(self):
        def _boom(*a, **kw):
            raise RuntimeError("synthetic transport failure")

        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=_boom,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "transport")

    def test_no_transport_fail_soft(self):
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=None,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        self.assertFalse(result.ok)

    def test_initial_url_dns_rejected_empty_body(self):
        transport = FakeTransport(responses={})
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["10.0.0.1"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.body, "")
        self.assertEqual(result.redirect_chain, [])


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
class TestBounds(unittest.TestCase):
    def test_final_body_truncated_at_max_bytes(self):
        big_body = "A" * 5000
        transport = FakeTransport(
            responses={
                "https://example.com/": ProviderResponse(
                    url="https://example.com/",
                    status=200,
                    body=big_body,
                    content_type="text/plain",
                )
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
            max_bytes=128,
        )
        self.assertLessEqual(len(result.body), 128)

    def test_bounded_timeout_propagates(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _ok("https://example.com/")
            }
        )
        safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
            timeout=2.5,
        )
        self.assertEqual(transport.calls[0]["timeout"], 2.5)

    def test_no_recursive_crawling(self):
        # Two-hop redirect must not magically follow any other links.
        transport = FakeTransport(
            responses={
                "https://example.com/": _ok("https://example.com/")
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
        )
        # Single fetch for a non-3xx response.
        self.assertEqual(len(transport.calls), 1)


# ---------------------------------------------------------------------------
# HTTP seam integration
# ---------------------------------------------------------------------------
class TestHTTPSSeam(unittest.TestCase):
    def test_seam_returns_provider_response_on_success(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _ok("https://example.com/", "body")
            }
        )
        client = BoundedHTTPClient(transport=transport)
        response = client.request_via_netguard("GET", "https://example.com/")
        self.assertIsInstance(response, ProviderResponse)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, "body")

    def test_seam_returns_none_on_dns_failure(self):
        transport = FakeTransport()
        client = BoundedHTTPClient(transport=transport)
        response = client.request_via_netguard("GET", "https://example.com/")
        self.assertIsNone(response)
        self.assertIsNotNone(client.last_error)

    def test_seam_follows_redirect(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://example.com/final"
                ),
                "https://example.com/final": _ok(
                    "https://example.com/final", "final-body"
                ),
            }
        )
        client = BoundedHTTPClient(transport=transport)
        response = client.request_via_netguard("GET", "https://example.com/")
        self.assertIsNotNone(response)
        self.assertEqual(response.body, "final-body")
        self.assertEqual(response.final_url, "https://example.com/final")
        # redirect chain is preserved on content_type when populated.
        self.assertIn("chain=", response.content_type)

    def test_seam_rejects_https_to_http(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "http://example.com/"
                ),
            }
        )
        client = BoundedHTTPClient(transport=transport)
        response = client.request_via_netguard("GET", "https://example.com/")
        self.assertIsNone(response)
        self.assertIn("downgrade", client.last_error or "")

    def test_seam_allowlist_enforced(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _ok("https://example.com/")
            }
        )
        client = BoundedHTTPClient(transport=transport, allowed_hosts=("other.com",))
        response = client.request_via_netguard("GET", "https://example.com/")
        self.assertIsNone(response)


# ---------------------------------------------------------------------------
# No target / no production-finding
# ---------------------------------------------------------------------------
class TestSafety(unittest.TestCase):
    def test_no_target_resolution_path(self):
        # A transport/resolver combo would never be called for a
        # target host — the DNS guard rejects the request outright.
        transport = FakeTransport()
        result = safe_fetch_with_redirects(
            "https://dell.com/",
            transport=transport,
            resolver=_resolver_for({"dell.com": ["10.0.0.1"]}),
        )
        self.assertFalse(result.ok)
        self.assertEqual(len(transport.calls), 0)

    def test_redirect_result_has_no_production_finding(self):
        # RedirectResult must not carry a production_finding field at
        # all (or, if it does, it must be False).
        result = RedirectResult(discovered_url="https://example.com/")
        self.assertFalse(getattr(result, "production_finding", False))

    def test_no_target_in_redirect_chain(self):
        transport = FakeTransport(
            responses={
                "https://example.com/": _redirect(
                    "https://example.com/", "https://dell.com/"
                ),
            }
        )
        result = safe_fetch_with_redirects(
            "https://example.com/",
            transport=transport,
            resolver=_resolver_for({"example.com": ["93.184.216.34"]}),
            program="dell",
        )
        # Initial URL is rejected as a program-host by ``program="dell"``
        # only when ``dell.com`` is in DNS; here the initial URL is
        # ``example.com`` so initial validation succeeds. The hop is
        # then rejected and the chain ends with the initial URL.
        self.assertIn("https://example.com/", result.redirect_chain)
        # The target host is never appended.
        self.assertNotIn("https://dell.com/", result.redirect_chain)


# ---------------------------------------------------------------------------
# Import boundary
# ---------------------------------------------------------------------------
class TestImportBoundary(unittest.TestCase):
    def _import_lines(self, file_name: str) -> list[str]:
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

    def test_netguard_no_forbidden_imports(self):
        for line in self._import_lines("netguard.py"):
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
                "httpx",
                "urllib.request",
            ):
                self.assertNotIn(needle, line, f"forbidden import: {line}")

    def test_netguard_no_eval_exec(self):
        text = Path("/opt/watch/ai/research_agent/netguard.py").read_text(
            encoding="utf-8"
        )
        for token in ("eval(", "exec(", "os.system("):
            self.assertNotIn(token, text)

    def test_provider_base_netguard_seam_no_forbidden_imports(self):
        # The seam is a single ``from ai.research_agent.netguard``
        # import; verify nothing else slipped in. The check inspects
        # only ``import`` / ``from ... import`` statements (the same
        # static-scan pattern the R24.1 and R24.2 import-boundary
        # tests use) so descriptive prose such as ``requests_made`` or
        # "no credentials, cookies, or requests" does not trip the
        # scan.
        text = Path(
            "/opt/watch/ai/research_agent/provider_base.py"
        ).read_text(encoding="utf-8")
        start = text.find("# -- R24.3 seam:")
        self.assertGreater(start, 0)
        end = text.find("# -----------------------------------------------------------------------------", start)
        block = text[start:end if end > 0 else None]
        pattern = re.compile(
            r"^(import [a-z0-9_\.]+(?:[ ]|$)|from [a-z0-9_\.]+ import )"
        )
        import_lines: list[str] = []
        for line in block.splitlines():
            stripped = line.strip().lower()
            if pattern.match(stripped):
                import_lines.append(stripped)
        # Only one import statement is expected: the
        # ``from ai.research_agent.netguard`` lazy import.
        forbidden_substrings = (
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
            "httpx",
            "urllib.request",
        )
        for line in import_lines:
            for needle in forbidden_substrings:
                self.assertNotIn(needle, line, f"forbidden in seam import: {line}")
        # The seam must include the netguard import.
        self.assertTrue(
            any("from ai.research_agent.netguard" in line for line in import_lines),
            "seam must import ai.research_agent.netguard",
        )


# ---------------------------------------------------------------------------
# R23 / R24.1 / R24.2 regression smoke (import-only — full suites run in CI)
# ---------------------------------------------------------------------------
class TestRegressionImportOnly(unittest.TestCase):
    def test_r24_2_seam_still_works(self):
        # The R24.2 helpers must remain unchanged after R24.3.
        from ai.research_agent.provider_base import BoundedHTTPClient as _BC

        self.assertTrue(hasattr(_BC, "request"))
        self.assertTrue(hasattr(_BC, "get_json"))
        self.assertTrue(hasattr(_BC, "get_text"))
        # The R24.3 seam is additive.
        self.assertTrue(hasattr(_BC, "request_via_netguard"))

    def test_r24_1_enums_intact(self):
        from ai.research_agent.discovery_contract import (
            SourceCategory,
            TrustTier,
            Lifecycle,
            SearchProvider,
        )

        self.assertEqual(
            [m.value for m in SearchProvider],
            ["nvd", "github_search", "vendor_advisory", "wordfence", "wpscan", "detection_rule", "generic_search"],
        )
        self.assertEqual(
            [m.value for m in TrustTier],
            ["TRUSTED", "SEMI_TRUSTED", "DISCOVERY_ONLY", "GENERIC"],
        )
        self.assertEqual(
            [m.value for m in Lifecycle],
            [
                "DISCOVERED_SOURCE",
                "FETCHED_SOURCE",
                "RELEVANT_SOURCE",
                "EVIDENCE",
                "UNKNOWN",
                "INFERENCE",
            ],
        )

    def test_r24_2_registry_intact(self):
        from ai.research_agent.providers import build_providers
        from ai.research_agent.provider_base import BoundedHTTPClient

        client = BoundedHTTPClient(transport=FakeTransport())
        providers = build_providers(http_client=client)
        self.assertEqual(len(providers), 7)


if __name__ == "__main__":
    unittest.main()

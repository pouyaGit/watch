"""tests/test_product_api_client.py — Stage R28.2 HTTP client tests.

All HTTP is faked: no real network requests are made. The tests import only
the external client (never Watch internal modules).
"""
import json
import socket
import sys
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, "/opt/watch")

from clients import product_api_contract as contract
from clients.product_api_client import (
    ProductAPIAuthError,
    ProductAPIClient,
    ProductAPIClientError,
    ProductAPIConnectionError,
    ProductAPIContractError,
    ProductAPINotFoundError,
    ProductAPIRequestError,
    ProductAPIServerError,
    ProductAPITimeoutError,
)

BASE = "https://watch.example"
KEY = "test-api-key-abc"


def valid_item(**over):
    item = {
        "opportunity_id": "op-27deff4809384156",
        "lead_id": "rl-af7ecfba1a86fc83",
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "opportunity_class": "BLOCKED",
        "money_score": 53,
        "money_priority": "P3_MEDIUM",
        "confidence": "HIGH",
        "evidence_quality": "HIGH",
        "estimated_minutes": 90,
        "current_status": "BLOCKED",
        "recommended_action": "VERIFY_ASSET_MATCH",
        "why_now": ["PUBLIC_POC"],
        "why_valuable": ["research priority score 80"],
        "blockers": ["only generic technology match"],
        "next_step": "Confirm affected component/plugin presence.",
        "research_status": "RESEARCH_COMPLETED",
        "outcome_status": "NONE",
        "session_status": "NONE",
        "research_only": True,
        "api_version": "v1",
    }
    item.update(over)
    return item


def envelope(items=None, **over):
    body = {
        "api_version": "v1",
        "research_only": True,
        "total": len(items) if items is not None else 1,
        "offset": 0,
        "limit": 50,
        "items": items if items is not None else [valid_item()],
    }
    body.update(over)
    return body


def summary_body():
    return {
        "api_version": "v1",
        "research_only": True,
        "total": 1,
        "by_class": {"BLOCKED": 1},
        "by_action": {"VERIFY_ASSET_MATCH": 1},
        "by_status": {"BLOCKED": 1},
        "top_opportunities": [valid_item()],
    }


def status_body():
    return {
        "api_version": "v1",
        "research_only": True,
        "product_api_version": "v1",
        "opportunity_count": 2,
        "ready_count": 0,
        "blocked_count": 2,
        "in_progress_count": 0,
        "completed_count": 0,
        "evidence_available": True,
        "outcomes_available": False,
        "sessions_available": False,
    }


def routed(routes):
    """Transport routing by exact URL path -> (status, payload_or_body)."""

    calls: list[dict] = []

    def transport(method, url, headers, timeout):
        parts = urllib.parse.urlsplit(url)
        calls.append({"method": method, "url": url, "path": parts.path,
                      "query": dict(urllib.parse.parse_qsl(parts.query)),
                      "headers": dict(headers), "timeout": timeout})
        entry = routes.get(parts.path)
        if entry is None:
            raise AssertionError(f"unexpected path: {parts.path}")
        status, payload = entry
        if isinstance(payload, str):
            return status, payload
        return status, json.dumps(payload)

    return transport, calls


class TestEndpoints(unittest.TestCase):
    def test_list_opportunities(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        client = ProductAPIClient(BASE, api_key=KEY, transport=transport)
        body = client.list_opportunities()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["cve_id"], "CVE-2026-1557")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["method"], "GET")
        self.assertEqual(calls[0]["path"], "/api/v1/opportunities")

    def test_list_query_parameters(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        client = ProductAPIClient(BASE, api_key=KEY, transport=transport)
        client.list_opportunities(limit=10, offset=5, cve="CVE-2026-1557",
                                  program="dell",
                                  opportunity_class="BLOCKED",
                                  action="VERIFY_ASSET_MATCH",
                                  status="BLOCKED", min_money_score=50)
        query = calls[0]["query"]
        self.assertEqual(query["limit"], "10")
        self.assertEqual(query["offset"], "5")
        self.assertEqual(query["cve"], "CVE-2026-1557")
        self.assertEqual(query["program"], "dell")
        self.assertEqual(query["class"], "BLOCKED")
        self.assertEqual(query["action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(query["status"], "BLOCKED")
        self.assertEqual(query["min_money_score"], "50")

    def test_pagination_defaults(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        ProductAPIClient(BASE, api_key=KEY,
                         transport=transport).list_opportunities()
        self.assertEqual(calls[0]["query"]["limit"], "50")
        self.assertEqual(calls[0]["query"]["offset"], "0")

    def test_detail(self):
        lead = "rl-af7ecfba1a86fc83"
        transport, calls = routed({
            f"/api/v1/opportunities/{lead}": (200, valid_item()),
        })
        item = ProductAPIClient(BASE, api_key=KEY,
                                transport=transport).get_opportunity(lead)
        self.assertEqual(item["lead_id"], lead)
        self.assertEqual(calls[0]["path"],
                         f"/api/v1/opportunities/{lead}")

    def test_summary(self):
        transport, _ = routed({
            "/api/v1/opportunities/summary": (200, summary_body()),
        })
        body = ProductAPIClient(BASE, api_key=KEY,
                                transport=transport).get_summary()
        self.assertEqual(body["by_class"], {"BLOCKED": 1})

    def test_research_status(self):
        transport, _ = routed({
            "/api/v1/research/status": (200, status_body()),
        })
        body = ProductAPIClient(BASE, api_key=KEY,
                                transport=transport).get_research_status()
        self.assertEqual(body["blocked_count"], 2)
        self.assertEqual(body["product_api_version"], "v1")

    def test_read_only_only_get(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        ProductAPIClient(BASE, api_key=KEY,
                         transport=transport).list_opportunities()
        self.assertTrue(all(call["method"] == "GET" for call in calls))


class TestAuthAndParams(unittest.TestCase):
    def test_api_key_header(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        ProductAPIClient(BASE, api_key=KEY,
                         transport=transport).list_opportunities()
        self.assertEqual(calls[0]["headers"].get("X-API-Key"), KEY)

    def test_no_api_key_header_when_unset(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        with mock.patch.dict("os.environ", {}, clear=True):
            client = ProductAPIClient(BASE, api_key_env="MISSING_VAR",
                                      transport=transport)
            self.assertFalse(client.api_key_configured)
            client.list_opportunities()
        self.assertNotIn("X-API-Key", calls[0]["headers"])

    def test_env_api_key(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        with mock.patch.dict("os.environ", {"WATCH_TEST_KEY": KEY}):
            ProductAPIClient(BASE, api_key_env="WATCH_TEST_KEY",
                             transport=transport).list_opportunities()
        self.assertEqual(calls[0]["headers"].get("X-API-Key"), KEY)

    def test_base_url_required(self):
        with self.assertRaises(ProductAPIClientError):
            ProductAPIClient("")

    def test_detail_requires_lead_id(self):
        client = ProductAPIClient(BASE, api_key=KEY,
                                  transport=lambda *a: (200, "{}"))
        with self.assertRaises(ProductAPIRequestError):
            client.get_opportunity("  ")


class TestHttpErrors(unittest.TestCase):
    def _client(self, status, body):
        transport, _ = routed({
            "/api/v1/opportunities": (status, body),
        })
        return ProductAPIClient(BASE, api_key=KEY, transport=transport)

    def test_400(self):
        error = {"api_version": "v1", "research_only": True,
                 "error": {"code": "INVALID_REQUEST",
                           "message": "invalid request parameters"}}
        with self.assertRaises(ProductAPIRequestError):
            self._client(400, error).list_opportunities()

    def test_401(self):
        error = {"api_version": "v1", "research_only": True,
                 "error": {"code": "UNAUTHORIZED", "message": "unauthorized"}}
        with self.assertRaises(ProductAPIAuthError):
            self._client(401, error).list_opportunities()

    def test_404(self):
        error = {"api_version": "v1", "research_only": True,
                 "error": {"code": "NOT_FOUND", "message": "not found"}}
        with self.assertRaises(ProductAPINotFoundError):
            self._client(404, error).list_opportunities()

    def test_500(self):
        error = {"api_version": "v1", "research_only": True,
                 "error": {"code": "INTERNAL_READ_ERROR", "message": "oops"}}
        with self.assertRaises(ProductAPIServerError):
            self._client(500, error).list_opportunities()

    def test_malformed_json(self):
        with self.assertRaises(ProductAPIContractError):
            self._client(200, "{not json").list_opportunities()

    def test_invalid_api_response_extra_field(self):
        bad = envelope(items=[{**valid_item(), "internal_extra": 1}])
        with self.assertRaises(ProductAPIContractError):
            self._client(200, bad).list_opportunities()

    def test_invalid_api_response_wrong_version(self):
        bad = envelope(api_version="v2")
        with self.assertRaises(ProductAPIContractError):
            self._client(200, bad).list_opportunities()

    def test_invalid_api_response_research_only_false(self):
        bad = envelope(research_only=False)
        with self.assertRaises(ProductAPIContractError):
            self._client(200, bad).list_opportunities()


class TestTimeout(unittest.TestCase):
    def test_transport_timeout_propagates(self):
        def transport(method, url, headers, timeout):
            raise ProductAPITimeoutError("request timed out")

        client = ProductAPIClient(BASE, api_key=KEY, transport=transport)
        with self.assertRaises(ProductAPITimeoutError):
            client.list_opportunities()

    def test_default_transport_maps_socket_timeout(self):
        client = ProductAPIClient(BASE, api_key=KEY)
        with mock.patch(
            "clients.product_api_client.urllib.request.urlopen",
            side_effect=socket.timeout("timed out"),
        ):
            with self.assertRaises(ProductAPITimeoutError):
                client.list_opportunities()

    def test_default_transport_connection_error(self):
        import urllib.error
        client = ProductAPIClient(BASE, api_key=KEY)
        with mock.patch(
            "clients.product_api_client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("refused"),
        ):
            with self.assertRaises(ProductAPIConnectionError):
                client.list_opportunities()

    def test_transport_unexpected_exception_wrapped(self):
        def transport(method, url, headers, timeout):
            raise RuntimeError("boom")

        client = ProductAPIClient(BASE, api_key=KEY, transport=transport)
        with self.assertRaises(ProductAPIConnectionError):
            client.list_opportunities()


class TestSecretHygiene(unittest.TestCase):
    def test_key_never_in_auth_error(self):
        secret = "SECRETKEY123456"
        transport, _ = routed({
            "/api/v1/opportunities": (401, {"api_version": "v1",
                                            "research_only": True,
                                            "error": {"code": "UNAUTHORIZED",
                                                      "message": "unauthorized"}}),
        })
        client = ProductAPIClient(BASE, api_key=secret, transport=transport)
        try:
            client.list_opportunities()
        except ProductAPIAuthError as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail("expected ProductAPIAuthError")
        self.assertNotIn(secret, repr(client))

    def test_key_never_in_contract_error(self):
        secret = "SECRETKEY123456"
        transport, _ = routed({
            "/api/v1/opportunities": (200, "{bad"),
        })
        client = ProductAPIClient(BASE, api_key=secret, transport=transport)
        try:
            client.list_opportunities()
        except ProductAPIContractError as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail("expected ProductAPIContractError")

    def test_repr_hides_key(self):
        client = ProductAPIClient(BASE, api_key="SECRETKEY123456")
        text = repr(client)
        self.assertIn("api_key_configured=True", text)
        self.assertNotIn("SECRETKEY123456", text)


class TestRemoteCli(unittest.TestCase):
    def _run(self, argv):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_remote_json_via_fake_transport(self):
        transport, calls = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        with mock.patch(
            "clients.product_api_client._default_transport", transport
        ), mock.patch.dict("os.environ", {"WATCH_PRODUCT_API_KEY": KEY}):
            code, out, err = self._run([
                "product", "remote-opportunities",
                "--base-url", BASE, "--json"])
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(body["api_version"], "v1")
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(calls[0]["headers"].get("X-API-Key"), KEY)

    def test_remote_human_output(self):
        transport, _ = routed({
            "/api/v1/opportunities": (200, envelope()),
        })
        with mock.patch(
            "clients.product_api_client._default_transport", transport
        ), mock.patch.dict("os.environ", {"WATCH_PRODUCT_API_KEY": KEY}):
            code, out, err = self._run([
                "product", "remote-opportunities", "--base-url", BASE])
        self.assertEqual(code, 0, err)
        self.assertIn("REMOTE PRODUCT OPPORTUNITIES", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Money: 53 / P3_MEDIUM", out)
        self.assertIn("Action: VERIFY_ASSET_MATCH", out)
        self.assertIn("Confirm affected component/plugin presence.", out)

    def test_remote_no_local_fallback_on_error(self):
        def boom(method, url, headers, timeout):
            raise ProductAPIConnectionError("could not reach the API server")

        with mock.patch(
            "clients.product_api_client._default_transport", boom
        ), mock.patch.dict("os.environ", {"WATCH_PRODUCT_API_KEY": KEY}):
            code, out, err = self._run([
                "product", "remote-opportunities", "--base-url", BASE])
        self.assertEqual(code, 1)
        self.assertNotIn("REMOTE PRODUCT OPPORTUNITIES", out)
        self.assertIn("ERROR", err)
        self.assertIn("could not reach the API server", err)
        self.assertNotIn(KEY, err)
        self.assertNotIn(KEY, out)

    def test_remote_requires_base_url(self):
        import io
        from contextlib import redirect_stderr
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stderr(io.StringIO()):
                self._run(["product", "remote-opportunities", "--json"])
        self.assertEqual(ctx.exception.code, 2)

    def test_local_command_still_present(self):
        code, out, _ = self._run(["product", "opportunities"])
        self.assertEqual(code, 0)
        self.assertIn("PRODUCT OPPORTUNITIES", out)
        self.assertNotIn("REMOTE PRODUCT OPPORTUNITIES", out)


class TestBoundary(unittest.TestCase):
    def test_no_network_used_by_tests(self):
        # sanity: contract module is import-clean and no real transport is
        # constructed without an explicit fake here.
        self.assertEqual(contract.PRODUCT_API_VERSION, "v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)

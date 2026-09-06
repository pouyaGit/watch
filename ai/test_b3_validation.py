"""Stage 4 B3 validation-harness tests.

Two tiers (mirroring the harness safety model):

- Unit tier (always runs, zero privilege, zero network): fixture
  markers, dial-guard allow/deny, double-opt-in refusal, result
  accounting, capability-probe shape, module string hygiene (no
  public/bounty/production targets, no curl/wget/httpx/requests), and
  proof that every live gate is still closed.
- Gated integration tier (runs ONLY with ``WATCH_STAGE4_NETNS=1`` in
  the environment AND user+network namespaces permitted; otherwise
  SKIPS): the full isolated-namespace validation, the timeout-cleanup
  kill path, and per-check status accounting. All dials stay inside
  the RFC 5737 fixture subnet; nothing external is ever contacted.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from ai.execution import b3_validation as bv

OPT_IN = os.environ.get(bv.HARNESS_OPT_IN_ENV) == "1"


def _read_source() -> str:
    return (Path(__file__).resolve().parent / "execution" / "b3_validation.py").read_text()


class FixtureMarkerTests(unittest.TestCase):
    def test_fixture_identity(self) -> None:
        self.assertIn("TEST ONLY", bv.FIXTURE_LABEL)
        self.assertIn("STAGE4", bv.FIXTURE_LABEL)
        self.assertIn("NON-PRODUCTION", bv.FIXTURE_LABEL)

    def test_fixture_subnet_is_documentation_range(self) -> None:
        import ipaddress as _ip

        net = _ip.ip_network(bv.FIXTURE_SUBNET)
        self.assertEqual(str(net), "192.0.2.0/24")
        self.assertIn(_ip.ip_address(bv.FIXTURE_A), net)
        self.assertIn(_ip.ip_address(bv.FIXTURE_B), net)
        self.assertNotEqual(bv.FIXTURE_A, bv.FIXTURE_B)
        self.assertTrue(1 <= bv.FIXTURE_PORT <= 65535)


class DialGuardTests(unittest.TestCase):
    def test_guard_admits_fixture(self) -> None:
        self.assertEqual(bv.guard_fixture_address(bv.FIXTURE_A), bv.FIXTURE_A)
        self.assertEqual(bv.guard_fixture_address(bv.FIXTURE_B), bv.FIXTURE_B)
        self.assertEqual(bv.guard_fixture_address("127.0.0.1"), "127.0.0.1")

    def test_guard_rejects_everything_else(self) -> None:
        for hostile in (
            "8.8.8.8",
            "1.1.1.1",
            "10.9.9.9",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "169.254.10.20",
            "127.0.0.2",
            "192.0.2.10 ",
            "example.com",
            "stage4-fixture.invalid",
            "https://192.0.2.10:18080/",
            "192.0.2.10/32",
            "",
            None,
            12345,
            "2001:db8::1",
        ):
            with self.assertRaises(bv.ValidationRefused, msg=repr(hostile)):
                bv.guard_fixture_address(hostile)


class ChainGuardTests(unittest.TestCase):
    def test_chain_constants_sane(self) -> None:
        self.assertEqual(bv.CHAIN_FIXTURE_IP, "8.8.8.8")
        self.assertEqual(bv.CHAIN_FIXTURE_PORT, 18081)
        self.assertTrue(bv.CHAIN_FIXTURE_PORT > 1024)
        self.assertTrue(bv.CHAIN_FIXTURE_HOST.endswith(".example.com"))

    def test_chain_guard_exact_pair_only(self) -> None:
        self.assertEqual(
            bv.guard_chain_address("8.8.8.8", 18081), ("8.8.8.8", 18081)
        )
        for hostile in (
            ("8.8.8.8", 18080),
            ("8.8.8.8", 443),
            ("8.8.4.4", 18081),
            ("192.0.2.10", 18081),
            ("8.8.8.8 ", 18081),
            ("8.8.8.8", "18081"),
            (None, 18081),
        ):
            with self.assertRaises(bv.ValidationRefused, msg=repr(hostile)):
                bv.guard_chain_address(*hostile)


class OptInTests(unittest.TestCase):
    def test_refuses_without_explicit_enable(self) -> None:
        with self.assertRaises(bv.ValidationRefused):
            bv.run_full_validation(enable=False)
        with self.assertRaises(bv.ValidationRefused):
            bv.require_harness_enable(enable=False)

    def test_unknown_scenario_refused(self) -> None:
        try:
            bv.run_full_validation(enable=True, scenarios=("nope",))
        except bv.ValidationRefused:
            return
        self.fail("unknown scenario must refuse (or env opt-in missing, also refused)")


class ResultAccountingTests(unittest.TestCase):
    def test_check_result_vocab(self) -> None:
        for status in ("PASS", "FAIL", "UNPROVEN"):
            self.assertEqual(
                bv.CheckResult(name="x", status=status, detail="ok").status, status
            )
        with self.assertRaises(ValueError):
            bv.CheckResult(name="x", status="PASSISH", detail="ok")
        with self.assertRaises(ValueError):
            bv.CheckResult(name="x", status="PASS", detail="two\nlines")

    def test_capability_probe_shape_and_purity(self) -> None:
        before = os.readlink("/proc/self/ns/net")
        capabilities = bv.probe_capabilities()
        after = os.readlink("/proc/self/ns/net")
        self.assertEqual(
            set(capabilities),
            {"ip_cli_present", "env_opt_in", "userns_netns_permitted"},
        )
        self.assertTrue(all(isinstance(v, bool) for v in capabilities.values()))
        self.assertEqual(before, after)


class ModuleHygieneTests(unittest.TestCase):
    # Target-shaped literals only: the module docstring legitimately
    # NAMES threat categories (public/bounty/...) while referencing no
    # real target. Fetch-tool substrings are checked as code shapes.
    BANNED_LITERALS = (
        "8.8.4.4",
        "1.1.1.1",
        "9.9.9.9",
        "httpbin",
    )

    # Every IPv4 literal in the harness must be an explicitly reviewed
    # fixture address: TEST-NET-1 pair, the B1-admissible chain address
    # (local-only destination, see CHAIN_FIXTURE_* rationale), the
    # scripted-DNS server literal (never dialed — exchange is a fake),
    # namespace loopback (isolation tests), or blocked-destination
    # cases (refused before any socket).
    ALLOWED_IPV4 = frozenset(
        {
            "192.0.2.0",
            "192.0.2.10",
            "192.0.2.11",
            "192.0.2.53",
            "8.8.8.8",
            "127.0.0.1",
            "10.9.9.9",
            "169.254.10.20",
            "169.254.169.254",
        }
    )

    def test_no_real_targets_or_fetch_tools(self) -> None:
        source = _read_source()
        for literal in self.BANNED_LITERALS:
            self.assertNotIn(literal, source, f"banned literal: {literal}")
        for tool in ("curl", "wget", "httpx", "requests.get", "urlopen"):
            self.assertNotIn(tool, source, f"banned fetch tool: {tool}")

    def test_ipv4_allowlist(self) -> None:
        import re as _re

        source = _read_source()
        found = set(_re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", source))
        unknown = found - self.ALLOWED_IPV4
        self.assertEqual(unknown, set(), f"unreviewed IPv4 literals: {unknown}")
        # The chain address must appear ONLY as the reviewed constant
        # and behind the chain guard (no ad-hoc dial strings).
        self.assertIn('CHAIN_FIXTURE_IP = "8.8.8.8"', source)
        dials = [line for line in source.splitlines() if ".connect(" in line]
        self.assertTrue(dials)
        for line in dials:
            self.assertNotIn("8.8.8.8", line)
            self.assertNotIn("192.0.2", line)

    def test_live_gates_still_closed(self) -> None:
        from ai.execution import b3_boundary as b3
        from ai.execution import browser_executor as bx
        from ai.execution import http_executor as hx
        from ai.execution import nuclei_executor as nx

        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)
        self.assertIs(bx.LIVE_BROWSER, False)
        self.assertIs(b3.HTTP_PROBE_PILOT_ENABLED, False)


@unittest.skipUnless(OPT_IN, "needs WATCH_STAGE4_NETNS=1")
class GatedValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        capabilities = bv.probe_capabilities()
        if not capabilities["userns_netns_permitted"]:
            raise unittest.SkipTest("user+network namespaces not permitted here")
        if not capabilities["ip_cli_present"]:
            raise unittest.SkipTest("ip CLI unavailable")

    def _statuses(self, report: bv.ValidationReport) -> dict[str, str]:
        return {check.name: check.status for check in report.checks}

    def test_full_validation_runs_isolated(self) -> None:
        report = bv.run_full_validation(enable=True)
        self.assertEqual(report.label, bv.FIXTURE_LABEL)
        self.assertTrue(report.parent_netns_unchanged)
        self.assertTrue(report.child_reaped)
        statuses = self._statuses(report)
        for name in (
            "namespace-isolated",
            "no-host-interface-inheritance",
            "no-default-route",
            "egress-allowed-exact",
            "egress-fixture-roundtrip",
            "egress-wrong-port-blocked",
            "egress-unapproved-address",
            "egress-unapproved-address-port",
            "egress-loopback-blocked",
            "egress-private-blocked",
            "egress-linklocal-blocked",
            "egress-metadata-blocked",
            "dns-hostname-never-dials",
            "dns-pinned-no-lookup",
            "timeout-stall-enforced",
            "bytecap-transport-truncates",
            "bytecap-decompression-ratio",
            "syndrop-timeout",
            "chain-resolution",
            "chain-egress",
            "chain-peer-proof",
            "chain-http-exchange",
            "chain-evidence-sealed",
            "chain-dial-audit",
            "parent-netns-unchanged",
            "no-orphan-process",
        ):
            self.assertIn(name, statuses, f"missing check: {name}")
            self.assertIn(statuses[name], ("PASS", "FAIL", "UNPROVEN"), name)
        failed = sorted(n for n, s in statuses.items() if s == "FAIL")
        self.assertEqual(failed, [], f"failed checks: {failed}")

    def test_timeout_cleanup_kills_and_reaps(self) -> None:
        report = bv.run_full_validation(
            enable=True, wall_seconds=4.0, scenarios=("hang",)
        )
        statuses = self._statuses(report)
        self.assertEqual(statuses.get("timeout-cleanup"), "PASS")
        self.assertTrue(report.child_reaped)
        self.assertTrue(report.parent_netns_unchanged)


if __name__ == "__main__":
    unittest.main()

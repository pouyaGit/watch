"""Stage 4 pilot-readiness tests (no activation path exists to test).

- Matrix shape: exactly the 17 mandated items, closed statuses,
  single-line non-empty evidence.
- Live-proven items execute here (gates, B1 source, redirect, drift).
- Env items are UNPROVEN without evidence (mongo) or without a netns
  report, and STRICT items stay UNPROVEN even with a green report.
- `activation_eligible` is a pure conjunction (False while any item
  is not PASS); the module exposes no switch-writing API.
- Gated tier (WATCH_STAGE4_NETNS=1): a REAL harness report flips the
  netns/egress/cleanup items to PASS while items 8/9 stay UNPROVEN —
  proving the PASS/UNPROVEN discipline is evidence-driven, not
  hardcoded.
"""

from __future__ import annotations

import os
import unittest

from ai.execution import pilot_readiness as pr

OPT_IN = os.environ.get("WATCH_STAGE4_NETNS") == "1"


class MatrixShapeTests(unittest.TestCase):
    def test_seventeen_items_closed_vocab(self) -> None:
        items = pr.assess_readiness()
        self.assertEqual(len(items), 17)
        self.assertEqual([entry.item for entry in items], list(pr.READINESS_ITEMS))
        for entry in items:
            self.assertIn(entry.status, ("PASS", "FAIL", "UNPROVEN"), entry.item)
            self.assertTrue(entry.evidence, entry.item)
            self.assertNotIn("\n", entry.evidence, entry.item)

    def test_summary_and_eligibility(self) -> None:
        items = pr.assess_readiness()
        summary = pr.readiness_summary(items)
        self.assertEqual(
            summary["PASS"] + summary["FAIL"] + summary["UNPROVEN"], 17
        )
        self.assertFalse(pr.activation_eligible(items))
        with self.assertRaises(ValueError):
            pr.activation_eligible(items[:16])
        with self.assertRaises(TypeError):
            pr.readiness_summary([("x", "PASS")])  # type: ignore[list-item]
        rendered = pr.render_matrix(items)
        self.assertIn("SUMMARY", rendered)
        self.assertIn("eligible=False", rendered)

    def test_item_rejects_bad_values(self) -> None:
        with self.assertRaises(ValueError):
            pr.ReadinessItem(item="nope", status="PASS", evidence="x")
        with self.assertRaises(ValueError):
            pr.ReadinessItem(item="live-gates-closed", status="MAYBE", evidence="x")
        with self.assertRaises(ValueError):
            pr.ReadinessItem(item="live-gates-closed", status="PASS", evidence="")


class LiveProvenItemTests(unittest.TestCase):
    def _by_name(self):
        return {entry.item: entry for entry in pr.assess_readiness()}

    def test_gates_closed_pass(self) -> None:
        self.assertEqual(self._by_name()["live-gates-closed"].status, "PASS")

    def test_b1_source_pass(self) -> None:
        self.assertEqual(self._by_name()["b1-address-source"].status, "PASS")

    def test_redirect_and_drift_pass(self) -> None:
        by_name = self._by_name()
        self.assertEqual(by_name["redirect-fresh-scope"].status, "PASS")
        self.assertEqual(by_name["scope-drift"].status, "PASS")

    def test_pure_items_pass_with_suite_evidence(self) -> None:
        by_name = self._by_name()
        self.assertEqual(by_name["deterministic-verification"].status, "PASS")
        self.assertEqual(by_name["finding-eligibility-unchanged"].status, "PASS")

    def test_strict_unproven_without_env_evidence(self) -> None:
        by_name = self._by_name()
        for name in (
            "b2-mongo-authorization",
            "b2-ledger",
            "b2-audit",
            "b2-evidence-persistence",
            "b3-network-namespace",
            "b3-egress-filtering",
            "dial-proof-vs-actual-dial",
            "resource-enforcement",
            "real-mongo-concurrency",
            "cleanup",
            "evidence-path",
        ):
            self.assertEqual(by_name[name].status, "UNPROVEN", name)

    def test_no_activation_surface(self) -> None:
        import ast as _ast
        from pathlib import Path as _Path

        source = (_Path(__file__).resolve().parent / "execution" / "pilot_readiness.py").read_text()
        tree = _ast.parse(source)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Assign):
                for target in node.targets:
                    if isinstance(target, _ast.Name) and target.id in (
                        "LIVE_TRAFFIC_ENABLED",
                        "HTTP_PROBE_PILOT_ENABLED",
                        "LIVE_NUCLEI",
                        "LIVE_BROWSER",
                    ):
                        self.fail(f"readiness module assigns {target.id}")
        for shape in ("popen", "check_output", "os.system", "socket.socket("):
            self.assertNotIn(shape, source)

    def test_mongo_evidence_bridge_skips_without_uri(self) -> None:
        import unittest.mock as _mock

        with _mock.patch.dict(
            os.environ, {}, clear=False,
        ):
            saved_uri = os.environ.pop("WATCH_TEST_MONGO_URI", None)
            saved_db = os.environ.pop("WATCH_TEST_MONGO_DB", None)
            try:
                evidence = pr.mongo_evidence_from_suites()
            finally:
                if saved_uri is not None:
                    os.environ["WATCH_TEST_MONGO_URI"] = saved_uri
                if saved_db is not None:
                    os.environ["WATCH_TEST_MONGO_DB"] = saved_db
        self.assertEqual(
            set(evidence),
            {
                "b2-mongo-authorization",
                "b2-ledger",
                "b2-audit",
                "b2-evidence-persistence",
                "real-mongo-concurrency",
                "evidence-path",
            },
        )
        self.assertTrue(
            all(status == "UNPROVEN" for status in evidence.values()), evidence
        )
        items = pr.assess_readiness(mongo_evidence=evidence)
        by_name = {entry.item: entry for entry in items}
        self.assertEqual(by_name["b2-ledger"].status, "UNPROVEN")

    def test_switches_unchanged_after_assessment(self) -> None:
        from ai.execution import b3_boundary as b3
        from ai.execution import browser_executor as bx
        from ai.execution import http_executor as hx
        from ai.execution import nuclei_executor as nx

        pr.assess_readiness()
        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)
        self.assertIs(bx.LIVE_BROWSER, False)
        self.assertIs(b3.HTTP_PROBE_PILOT_ENABLED, False)


MONGO_URI_PRESENT = bool(os.environ.get("WATCH_TEST_MONGO_URI"))


@unittest.skipUnless(MONGO_URI_PRESENT, "needs WATCH_TEST_MONGO_URI")
class MongoEvidenceTests(unittest.TestCase):
    def test_mongo_evidence_bridge_passes_with_server(self) -> None:
        evidence = pr.mongo_evidence_from_suites()
        self.assertTrue(
            all(status == "PASS" for status in evidence.values()), evidence
        )
        items = pr.assess_readiness(mongo_evidence=evidence)
        by_name = {entry.item: entry for entry in items}
        for name in (
            "b2-mongo-authorization",
            "b2-ledger",
            "b2-audit",
            "b2-evidence-persistence",
            "real-mongo-concurrency",
            "evidence-path",
        ):
            self.assertEqual(by_name[name].status, "PASS", name)
        # Still not eligible: resource enforcement remains UNPROVEN.
        self.assertFalse(pr.activation_eligible(items))
        self.assertEqual(by_name["resource-enforcement"].status, "UNPROVEN")


@unittest.skipUnless(OPT_IN, "needs WATCH_STAGE4_NETNS=1")
class GatedReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from ai.execution import b3_validation as bv

        capabilities = bv.probe_capabilities()
        if not capabilities["userns_netns_permitted"]:
            raise unittest.SkipTest("user+network namespaces not permitted here")
        if not capabilities["ip_cli_present"]:
            raise unittest.SkipTest("ip CLI unavailable")
        cls._report = bv.run_full_validation(enable=True)

    def test_env_items_flip_with_real_evidence(self) -> None:
        items = pr.assess_readiness(netns_report=self.__class__._report)
        by_name = {entry.item: entry for entry in items}
        self.assertEqual(by_name["b3-network-namespace"].status, "PASS")
        self.assertEqual(by_name["b3-egress-filtering"].status, "PASS")
        self.assertEqual(by_name["cleanup"].status, "PASS")
        self.assertEqual(by_name["dial-proof-vs-actual-dial"].status, "PASS")
        # Strict items stay UNPROVEN despite the green report.
        self.assertEqual(by_name["resource-enforcement"].status, "UNPROVEN")
        # Mongo items stay UNPROVEN without server evidence.
        self.assertEqual(by_name["b2-ledger"].status, "UNPROVEN")
        self.assertEqual(by_name["real-mongo-concurrency"].status, "UNPROVEN")
        # Still not eligible: UNPROVEN items remain.
        self.assertFalse(pr.activation_eligible(items))
        summary = pr.readiness_summary(items)
        # Exact accounting: 6 live-proven + 3 netns-fed + chain = 10 PASS;
        # 7 strict-UNPROVEN (4 mongo + concurrency + resource +
        # evidence-path). Total 17, zero FAIL.
        self.assertEqual(summary["PASS"], 10)
        self.assertEqual(summary["UNPROVEN"], 7)


if __name__ == "__main__":
    unittest.main()

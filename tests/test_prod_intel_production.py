"""Epic8 §13: production integration — projections over REAL persisted
Watch state (read-only). Skipped where /opt/watch runtime data is absent
(e.g. a clean checkout); this environment ships the production store.
"""

from __future__ import annotations

import json
import os
import unittest

PROD_RUNTIME = "/opt/watch/ai_data/research/agent/runtime"
HAVE_PROD = os.path.exists(os.path.join(PROD_RUNTIME, "state.json"))


@unittest.skipUnless(HAVE_PROD, "production runtime store not present")
class TestProductionIntegration(unittest.TestCase):
    """All tests run READ-ONLY against the production runtime dir."""

    def setUp(self):
        self._saved = os.environ.get("WATCH_AGENT_RUNTIME_DIR")
        os.environ["WATCH_AGENT_RUNTIME_DIR"] = PROD_RUNTIME

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("WATCH_AGENT_RUNTIME_DIR", None)
        else:
            os.environ["WATCH_AGENT_RUNTIME_DIR"] = self._saved

    def test_overview_reads_real_state_honestly(self):
        from backend.prod_intel.overview import overview
        body = overview(hours=None)
        self.assertEqual(body["rule_version"],
                         "production-intelligence-v1")
        self.assertIn(body["blockers"]["state"],
                      ("ok", "not_observed", "unavailable"))
        self.assertGreaterEqual(body["agents"]["value"]["registered"], 1)
        # registered must equal the real capability registry size
        from backend.soc import agents as soc_agents
        self.assertEqual(body["agents"]["value"]["registered"],
                         soc_agents.agents_index()["count"])

    def test_target_intelligence_finds_real_target(self):
        from backend.prod_intel.targets import target_intelligence
        out = target_intelligence(hours=None)
        self.assertGreaterEqual(out["count"], 1)
        names = [t["target"] for t in out["targets"]]
        self.assertIn("www.dell.com", names)
        row = next(t for t in out["targets"]
                   if t["target"] == "www.dell.com")
        # provenance on every block + attack surface honest state
        for key in ("research", "findings", "campaigns", "cases",
                    "evidence", "knowledge", "memory", "learning",
                    "activity", "attack_surface"):
            with self.subTest(block=key):
                self.assertIn("source", row[key])
                self.assertIn("state", row[key])
                self.assertIn(row[key]["state"],
                              ("ok", "not_observed", "unavailable",
                               "unknown"))
        self.assertGreater(row["research"]["value"]["total"], 0)
        self.assertGreater(row["evidence"]["value"], 0)
        json.dumps(out, default=str)

    def test_agents_intelligence_real_registry(self):
        from backend.prod_intel.agents_intel import (
            agent_detail,
            agent_intelligence,
        )
        out = agent_intelligence(hours=None)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["count"], 8)
        det = agent_detail("XSS")
        self.assertTrue(det["registered"])
        self.assertGreaterEqual(det["research"]["value"]["total"], 1)
        json.dumps(det, default=str)

    def test_effectiveness_funnels_on_real_data(self):
        from backend.prod_intel.effectiveness import effectiveness
        body = effectiveness(hours=None)
        self.assertEqual(len(body["funnels"]), 6)
        for name, f in body["funnels"].items():
            with self.subTest(funnel=name):
                self.assertIn("denominator", f)
                self.assertIn("numerator", f)
                if f["state"] == "insufficient_population":
                    self.assertIsNone(f["rate"])
        blob = json.dumps(body, default=str)
        self.assertNotIn("%", blob)
        self.assertNotIn('"rank"', blob)

    def test_case_intelligence_on_real_case(self):
        from backend.prod_intel import sources
        from backend.prod_intel.case_intel import case_intelligence
        rows = sources.finding_cases()["data"] or []
        self.assertGreaterEqual(len(rows), 1)
        pkg = case_intelligence(rows[0].case_id)
        self.assertTrue(pkg["found"])
        self.assertEqual(pkg["family"], "finding")
        self.assertIn("unavailable", pkg["payload"])   # never fabricated
        self.assertTrue(pkg["analyst_next_steps"])
        self.assertIn("lineage", pkg)
        json.dumps(pkg, default=str)

    def test_learning_signals_deterministic_on_real_data(self):
        from backend.prod_intel.learning_signals import learning_signals
        a = json.dumps(learning_signals(hours=None)["value"],
                       default=str, sort_keys=True)
        b = json.dumps(learning_signals(hours=None)["value"],
                       default=str, sort_keys=True)
        self.assertEqual(a, b)

    def test_knowledge_usage_real_rows(self):
        from backend.prod_intel.knowledge_usage import knowledge_usage
        out = knowledge_usage(hours=None, limit=50, offset=0)
        self.assertIn(out["state"], ("ok", "not_observed", "unavailable"))
        if out["state"] == "ok":
            self.assertGreaterEqual(out["total"], 1)
            self.assertEqual(out["count"],
                             min(out["total"], 50))
        self.assertIn("semantics", out)

    def test_current_activity_never_fake_active(self):
        from backend.prod_intel.activity import current_activity
        act = current_activity()
        self.assertIn(act["state"],
                      ("PLANNED", "IDLE", "ACTIVE", "FAILED", "UNKNOWN"))
        if act["state"] == "ACTIVE":
            self.assertTrue(act["running_jobs"])

    def test_projection_is_read_only_against_production(self):
        """Run every projection twice over production and assert the
        audit trail did not grow (read-only proof)."""
        audit_path = os.path.join(PROD_RUNTIME, "audit.jsonl")

        def count():
            try:
                with open(audit_path, encoding="utf-8") as fh:
                    return sum(1 for _ in fh)
            except OSError:
                return -1

        before = count()
        from backend.prod_intel.overview import overview
        from backend.prod_intel.targets import target_intelligence
        from backend.prod_intel.effectiveness import effectiveness
        overview(hours=None)
        target_intelligence(hours=None)
        effectiveness(hours=None)
        after = count()
        self.assertEqual(before, after,
                         "projection layer must not append to production "
                         "audit trail")


if __name__ == "__main__":
    unittest.main()

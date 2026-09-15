"""Full offline R63 pipeline test: R61 fixture -> R62 -> R59 -> R60 -> R63.

No MongoDB, no network, no target interaction. Asserts the quality gate passes
for the deterministic fixture pipeline, that the evaluator never mutates its
input, and that the whole chain stays advisory-only and sampled.
"""

from __future__ import annotations

import unittest
from copy import deepcopy
from unittest import mock

from tests.local_e2e import r62_bridge as br
from tests.local_e2e import r63_evaluation as r63
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import client_from_fixture, load_fixture

CVE = "CVE-2024-27956"
FIXTURE = load_fixture()
SNAPSHOT = rs.build_snapshot("indeed", client=client_from_fixture(FIXTURE))
PIPELINE = br.pipeline(SNAPSHOT, cve=CVE)
GATE = r63.quality_gate(PIPELINE, snapshot=SNAPSHOT)


class TestOfflineR63Pipeline(unittest.TestCase):
    def test_gate_passes_for_fixture_pipeline(self):
        self.assertEqual(GATE["rule_version"], "r63-1")
        self.assertEqual(GATE["status"], "PASS", GATE["checks"])
        self.assertEqual(GATE["summary"]["failed"], 0)

    def test_expected_safety_sampling_and_bounds_pass(self):
        checks = GATE["checks"]
        for name in (
            "safety_workflow",
            "safety_copilot",
            "safety_boundary",
            "safety_recommendations",
            "no_confirmation_claims",
            "sampling_flag",
            "sampling_claims",
            "sampling_counters",
            "research_context_bounds",
            "intelligence_context_bounds",
            "specialist_categories",
            "specialist_eligibility",
            "specialist_evidence",
            "cve_integrity",
            "program_identity",
            "program_isolation",
            "no_fabricated_outputs",
            "r31_layer_consistency",
        ):
            self.assertIn(name, checks, name)
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_chain_stage_versions(self):
        self.assertEqual(PIPELINE["workflow"]["rule_version"], "r59-4")
        self.assertEqual(PIPELINE["copilot"]["rule_version"], "r60-4")
        self.assertEqual(
            PIPELINE["research_context"]["snapshot_rule_version"], "r61-1"
        )

    def test_gate_is_deterministic(self):
        first = r63.canonical_json(
            r63.quality_gate(PIPELINE, snapshot=SNAPSHOT)
        )
        second = r63.canonical_json(
            r63.quality_gate(PIPELINE, snapshot=SNAPSHOT)
        )
        self.assertEqual(first, second)

    def test_evaluator_never_mutates_input(self):
        data = deepcopy(PIPELINE)
        data["research_context"]["sampled"] = False
        before = r63.canonical_json(data)
        result = r63.evaluate_pipeline(data, snapshot=SNAPSHOT)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(before, r63.canonical_json(data))
        self.assertFalse(data["research_context"]["sampled"])

    def test_gate_output_is_safe(self):
        text = r63.canonical_json(GATE)
        self.assertNotIn("://", text)
        self.assertNotIn('"_id"', text)
        self.assertNotIn("other-program", text)
        self.assertNotIn("password", text)
        for check in GATE["checks"].values():
            self.assertIn(check["status"], ("PASS", "FAIL"))
            self.assertIsInstance(check["reason"], str)

    def test_full_chain_runs_offline(self):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            side_effect=AssertionError("mongo must not be read"),
        ), mock.patch(
            "backend.observed_inventory._fetch_documents",
            side_effect=AssertionError("mongo must not be read"),
        ), mock.patch(
            "pymongo.MongoClient",
            side_effect=AssertionError("mongo client must not be created"),
        ):
            pipeline = br.pipeline(SNAPSHOT, cve=CVE)
            gate = r63.quality_gate(pipeline, snapshot=SNAPSHOT)
        self.assertEqual(gate["status"], "PASS")

    def test_malformed_pipeline_fails_closed(self):
        for malformed in (
            None,
            {},
            {"inventory": {"program": "indeed"}},
            {"inventory": {"program": "indeed"}, "r31": None},
        ):
            with self.subTest(malformed=malformed):
                result = r63.quality_gate(malformed)
                self.assertEqual(result["status"], "FAIL")

    def test_advisory_output_is_not_interpreted_as_finding(self):
        copilot = PIPELINE["copilot"]
        self.assertEqual(copilot["brief"]["opportunity_count"], 0)
        self.assertEqual(copilot["brief"]["opportunities"], [])
        self.assertEqual(copilot["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(
            GATE["checks"]["no_fabricated_outputs"]["status"], "PASS"
        )


if __name__ == "__main__":
    unittest.main()

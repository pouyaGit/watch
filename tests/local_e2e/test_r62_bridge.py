"""Focused tests for the R62 offline bridge (snapshot -> R31-R38 -> R59/R60).

Coverage (A-T from the implementation task) plus sampling and safety
invariants. All tests are offline: the matching hub is always driven through
the injected-inventory seam, and Mongo accessors are patched to raise wherever
the non-injection path could be reached.
"""

from __future__ import annotations

import json
import unittest
from copy import deepcopy
from unittest import mock

from ai.knowledge.specialist_eligibility import specialist_is_eligible
from ai.researcher.target_intelligence import HttpRecord
from backend.asset_cve_matching import build_matches
from backend.observed_inventory import build_inventory
from tests.local_e2e import r62_bridge as br
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import client_from_fixture, load_fixture

CVE = "CVE-2024-27956"

_FIXTURE = load_fixture()
_SNAPSHOT = rs.build_snapshot(
    "indeed", client=client_from_fixture(_FIXTURE)
)
_INVENTORY = None
_PIPELINE = None


def fixture_snapshot() -> dict:
    return deepcopy(_SNAPSHOT)


def fixture_inventory() -> dict:
    global _INVENTORY
    if _INVENTORY is None:
        _INVENTORY = br.inventory_from_snapshot(_SNAPSHOT)
    return _INVENTORY


def fixture_pipeline() -> dict:
    global _PIPELINE
    if _PIPELINE is None:
        _PIPELINE = br.pipeline(_SNAPSHOT, cve=CVE)
    return _PIPELINE


def wordpress_inventory() -> dict:
    records = {
        "http_records": [
            HttpRecord(
                program_name="indeed",
                subdomain="www.indeed.com",
                scope="indeed.com",
                ips=("192.0.2.1",),
                tech=("WordPress:6.8.3", "nginx:1.24.0"),
                title="Indeed",
                status_code=200,
                headers=(),
                url="https://www.indeed.com/",
                final_url="https://www.indeed.com/",
                favicon="",
                last_update=None,
                record_id="rec-aaaaaaaaaaaaaaaa",
            )
        ]
    }
    return build_inventory("indeed", records=records)[0]


def mongo_guard():
    return mock.patch(
        "backend.observed_inventory.get_inventory",
        side_effect=AssertionError("mongo must not be read"),
    )


class TestSnapshotToInventory(unittest.TestCase):
    def test_inventory_from_fixture_snapshot(self):
        inventory = fixture_inventory()
        self.assertEqual(inventory["program"], "indeed")
        self.assertTrue(inventory["inventory_id"].startswith("inv-"))
        self.assertTrue(inventory["technologies"])
        self.assertTrue(inventory["versions"])
        self.assertTrue(inventory["parameters"])
        self.assertTrue(inventory["paths"])
        self.assertTrue(inventory["version_associations"])
        self.assertTrue(inventory["parameter_paths"])

    def test_inventory_is_deterministic(self):
        first = br.canonical_json(fixture_inventory())
        second = br.canonical_json(br.inventory_from_snapshot(_SNAPSHOT))
        self.assertEqual(first, second)

    def test_malformed_snapshot_fails_closed(self):
        for broken in (
            {},
            {"snapshot_version": 99, "rule_version": "x", "program": "indeed"},
            {"snapshot_version": 1, "rule_version": "r61-1"},
        ):
            with self.subTest(broken=broken):
                with self.assertRaises(rs.SnapshotError):
                    br.inventory_from_snapshot(broken)


class TestR31InjectionSeam(unittest.TestCase):
    def test_injected_inventory_produces_match_item(self):
        item = br.match_summary_for(fixture_inventory(), cve=CVE)
        self.assertIsNotNone(item)
        self.assertEqual(item["program"], "indeed")
        self.assertEqual(item["cve_id"], CVE)
        self.assertIn(item["asset_match_state"], ("CONFIRMED", "SUPPORTED", "WEAK", "UNKNOWN"))
        for key in (
            "hunt_priority",
            "evidence_quality",
            "research_intelligence_export_plan",
            "research_memory_export_plan",
            "research_learning_export_plan",
            "research_strategy_export_plan",
            "research_orchestration_export_plan",
            "research_execution_authorization_export_plan",
            "research_governance_export_plan",
            "security_agent_framework_plan",
        ):
            self.assertIn(key, item, key)

    def test_default_read_path_unchanged(self):
        fake_inventory = {
            "program": "indeed",
            "products": [],
            "components": [],
            "plugins": [],
            "technologies": [
                {
                    "value": "WordPress",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }
            ],
            "versions": [
                {
                    "value": "6.8.3",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }
            ],
            "parameters": [],
            "paths": [],
            "version_associations": [],
            "component_provenance": [],
            "parameter_paths": [],
            "sources": [],
            "evidence": [],
            "inventory_id": "inv-test",
            "rule_version": "r30-2",
            "research_only": True,
        }
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=fake_inventory,
        ):
            default = build_matches(cve=CVE, program="indeed")
        injected = build_matches(
            cve=CVE, program="indeed", inventories={"indeed": fake_inventory}
        )
        self.assertEqual(
            br.canonical_json(default), br.canonical_json(injected)
        )

    def test_injected_path_does_not_read_mongo(self):
        inventory = fixture_inventory()
        with mongo_guard(), mock.patch(
            "backend.observed_inventory._fetch_documents",
            side_effect=AssertionError("mongo must not be read"),
        ):
            item = br.match_summary_for(inventory, cve=CVE)
        self.assertIsNotNone(item)

    def test_unknown_cve_returns_none(self):
        self.assertIsNone(
            br.match_summary_for(fixture_inventory(), cve="CVE-1999-0001")
        )

    def test_empty_cve_is_rejected(self):
        with self.assertRaises(br.BridgeError):
            br.match_summary_for(fixture_inventory(), cve="")

    def test_match_is_matcher_output_only(self):
        inventory = wordpress_inventory()
        item = br.match_summary_for(inventory, cve=CVE)
        self.assertEqual(item["asset_match_state"], "WEAK")
        self.assertEqual(item["asset_match_confidence"], "MEDIUM")
        evidence = item.get("evidence") or []
        self.assertIn("observed technology: WordPress", evidence)
        self.assertIn("cve technology: wordpress", evidence)


class TestContextBounds(unittest.TestCase):
    def test_research_context_bounds(self):
        context = fixture_pipeline()["research_context"]
        br.validate_context(context)
        self.assertLessEqual(len(context), br.MAX_CONTEXT_KEYS)
        self.assertLessEqual(br._container_depth(context), br.MAX_CONTEXT_DEPTH)
        self.assertTrue(context["sampled"])
        self.assertEqual(context["program"], "indeed")
        self.assertEqual(context["snapshot_version"], 1)
        self.assertEqual(context["snapshot_rule_version"], "r61-1")

    def test_intelligence_context_bounds(self):
        context = fixture_pipeline()["intelligence_context"]
        br.validate_context(context)
        self.assertLessEqual(len(context), br.MAX_CONTEXT_KEYS)
        self.assertLessEqual(br._container_depth(context), br.MAX_CONTEXT_DEPTH)
        self.assertTrue(context["sampled"])
        self.assertEqual(context["program"], "indeed")

    def test_context_lists_are_bounded(self):
        for name in ("research_context", "intelligence_context"):
            context = fixture_pipeline()[name]
            for key, value in context.items():
                if isinstance(value, list):
                    self.assertLessEqual(
                        len(value), br.MAX_CONTEXT_LIST, f"{name}.{key}"
                    )

    def test_contexts_carry_no_full_urls(self):
        for name in ("research_context", "intelligence_context"):
            text = br.canonical_json(fixture_pipeline()[name])
            self.assertNotIn("http://", text, name)
            self.assertNotIn("https://", text, name)

    def test_cap_reached_flag_is_factual(self):
        context = fixture_pipeline()["research_context"]
        endpoints = context["collection_stats"]["endpoints"]
        self.assertEqual(endpoints["selected"], 4)
        self.assertEqual(endpoints["cap"], 1000)
        self.assertFalse(endpoints["cap_reached"])

        capped = rs.build_snapshot(
            "indeed",
            client=client_from_fixture(_FIXTURE),
            caps={"endpoints": 2},
        )
        context = br.build_research_context(capped, fixture_inventory())
        endpoints = context["collection_stats"]["endpoints"]
        self.assertEqual(endpoints["selected"], 2)
        self.assertTrue(endpoints["cap_reached"])
        self.assertTrue(context["sampled"])

    def test_validate_context_rejects_oversized_structures(self):
        with self.assertRaises(br.BridgeError):
            br.validate_context({"a": list(range(br.MAX_CONTEXT_LIST + 1))})
        with self.assertRaises(br.BridgeError):
            br.validate_context(
                {f"k{i}": 1 for i in range(br.MAX_CONTEXT_KEYS + 1)}
            )
        deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        with self.assertRaises(br.BridgeError):
            br.validate_context(deep)


class TestSpecialistSignals(unittest.TestCase):
    def test_recon_from_api_path(self):
        signals = fixture_pipeline()["specialist_signals"]
        self.assertEqual(signals["RECON"], {"api_type": "REST"})
        self.assertTrue(specialist_is_eligible("RECON", signals["RECON"]))

    def test_idor_from_normalized_path_with_params(self):
        signals = fixture_pipeline()["specialist_signals"]
        self.assertEqual(signals["IDOR"], {"object_reference": "PATH_PARAMETER"})
        self.assertTrue(specialist_is_eligible("IDOR", signals["IDOR"]))

    def test_cve_signal_only_when_matcher_matches(self):
        fixture_signals = fixture_pipeline()["specialist_signals"]
        self.assertNotIn("CVE_RESEARCH", fixture_signals)
        item = br.match_summary_for(wordpress_inventory(), cve=CVE)
        signals = br.specialist_signals(
            _SNAPSHOT, wordpress_inventory(), r31=item
        )
        self.assertEqual(
            signals["CVE_RESEARCH"], {"cve_metadata": CVE}
        )
        self.assertTrue(
            specialist_is_eligible("CVE_RESEARCH", signals["CVE_RESEARCH"])
        )

    def test_unsupported_categories_remain_absent(self):
        signals = fixture_pipeline()["specialist_signals"]
        for category in signals:
            self.assertIn(
                category, br.SUPPORTED_SPECIALIST_CATEGORIES
            )
        for unsupported in ("XSS", "SSRF", "SQLI", "JWT", "OAUTH"):
            self.assertNotIn(unsupported, signals)

    def test_signals_are_deterministic(self):
        first = br.specialist_signals(
            _SNAPSHOT, fixture_inventory(), r31=fixture_pipeline()["r31"]
        )
        second = br.specialist_signals(
            _SNAPSHOT, fixture_inventory(), r31=fixture_pipeline()["r31"]
        )
        self.assertEqual(br.canonical_json(first), br.canonical_json(second))

    def test_idor_requires_parameter_evidence(self):
        snapshot = fixture_snapshot()
        records = snapshot["collections"]["endpoints"]["records"]
        for record in records:
            if "{" in record["path"]:
                record["params"] = []
                record["params_from_crawl"] = []
                record["params_from_x8"] = []
                record["param_records"] = []
        signals = br.specialist_signals(snapshot, fixture_inventory())
        self.assertNotIn("IDOR", signals)

    def test_recon_absent_without_api_paths(self):
        snapshot = fixture_snapshot()
        snapshot["collections"]["endpoints"]["records"] = []
        snapshot["collections"]["urls"]["records"] = []
        inventory = dict(fixture_inventory())
        inventory["paths"] = []
        signals = br.specialist_signals(snapshot, inventory)
        self.assertNotIn("RECON", signals)

    def test_graphql_detection(self):
        snapshot = fixture_snapshot()
        snapshot["collections"]["endpoints"]["records"].append(
            {
                "record_ref": "rec-bbbbbbbbbbbbbbbb",
                "program_name": "indeed",
                "subdomain": "api.indeed.com",
                "path": "/graphql",
                "params": ["query"],
                "params_from_crawl": ["query"],
                "params_from_x8": [],
                "x8_checked": False,
                "hit_count": 1,
                "param_records": [],
            }
        )
        signals = br.specialist_signals(snapshot, fixture_inventory())
        self.assertEqual(signals["RECON"]["api_type"], "GRAPHQL")
        self.assertTrue(specialist_is_eligible("RECON", signals["RECON"]))


class TestSafetyAndSampling(unittest.TestCase):
    def test_contexts_are_explicitly_sampled(self):
        pipeline = fixture_pipeline()
        for name in ("research_context", "intelligence_context"):
            self.assertTrue(pipeline[name]["sampled"], name)
        self.assertTrue(pipeline["research_context"]["collection_stats"])

    def test_r59_safety_invariants(self):
        workflow = fixture_pipeline()["workflow"]
        self.assertTrue(workflow["advisory"])
        self.assertFalse(workflow["execution_performed"])
        self.assertFalse(workflow["vulnerability_confirmed"])
        self.assertFalse(workflow["exploit_authorized"])
        self.assertFalse(workflow["external_executor_present"])
        self.assertEqual(workflow["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(workflow["human_authority_preserved"])
        self.assertEqual(workflow["safety_status"], "RESEARCH_ONLY")
        next_action = workflow.get("next_action") or {}
        self.assertTrue(next_action.get("advisory"))
        self.assertFalse(next_action.get("auto_execute"))

    def test_r60_safety_invariants(self):
        copilot = fixture_pipeline()["copilot"]
        self.assertTrue(copilot["advisory"])
        self.assertFalse(copilot["execution_performed"])
        self.assertFalse(copilot["vulnerability_confirmed"])
        self.assertFalse(copilot["exploit_authorized"])
        self.assertFalse(copilot["external_executor_present"])
        self.assertEqual(copilot["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(copilot["human_authority_preserved"])
        boundary = copilot["brief"]["non_execution_boundary"]
        self.assertEqual(boundary["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(boundary["execution_performed"])
        self.assertFalse(boundary["vulnerability_confirmed"])
        self.assertTrue(boundary["r58_gate_required"])
        self.assertTrue(boundary["human_authority_required"])

    def test_empty_snapshot_pipeline_is_safe(self):
        snapshot = {
            "snapshot_version": 1,
            "rule_version": "r61-1",
            "program": "indeed",
            "sampled": True,
            "caps": {},
            "collections": {},
            "stats": {},
        }
        pipeline = br.pipeline(snapshot)
        self.assertEqual(pipeline["inventory"]["program"], "indeed")
        self.assertEqual(pipeline["inventory"]["technologies"], [])
        self.assertTrue(pipeline["research_context"]["sampled"])
        self.assertFalse(pipeline["copilot"]["vulnerability_confirmed"])
        self.assertFalse(pipeline["copilot"]["execution_performed"])

    def test_mixed_program_data_cannot_cross(self):
        snapshot = fixture_snapshot()
        snapshot["collections"]["endpoints"]["records"].append(
            {
                "record_ref": "rec-cccccccccccccccc",
                "program_name": "other-program",
                "subdomain": "www.other.example",
                "path": "/admin",
                "params": ["q"],
                "params_from_crawl": ["q"],
                "params_from_x8": [],
                "x8_checked": False,
                "hit_count": 1,
                "param_records": [],
            }
        )
        pipeline = br.pipeline(snapshot, cve=CVE)
        for name in (
            "research_context",
            "intelligence_context",
            "workflow",
            "copilot",
        ):
            text = br.canonical_json(pipeline[name])
            self.assertNotIn("other-program", text, name)
            self.assertNotIn("www.other.example", text, name)
        refs = pipeline["research_context"]["record_refs"]["endpoints"]
        self.assertNotIn("rec-cccccccccccccccc", refs)

    def test_r31_output_is_deterministic(self):
        first = fixture_pipeline()
        second = br.pipeline(_SNAPSHOT, cve=CVE)
        for key in ("r31", "research_context", "intelligence_context",
                    "specialist_signals", "workflow", "copilot"):
            self.assertEqual(
                br.canonical_json(first[key]),
                br.canonical_json(second[key]),
                key,
            )


if __name__ == "__main__":
    unittest.main()

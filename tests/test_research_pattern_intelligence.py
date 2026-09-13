"""tests/test_research_pattern_intelligence.py — Stage R33.1 tests.

Deterministic, offline tests for the research pattern intelligence planner
plus hermetic backend integration for the R33 learning layer:

- deterministic output
- empty history
- multiple records and frequency thresholds
- malformed input handling
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no operational attack content
- backend additive fields for R33.1-R33.4 (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import research_pattern_intelligence as rpi
from ai.knowledge.relevance import AssetRecord
from ai.schemas import research_pattern_intelligence as schema
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1560"


def memory_export(evidence=(), **over):
    plan = {
        "rule_version": "r32-4",
        "ready": True,
        "history": {},
        "patterns": {
            "rule_version": "r32-3",
            "dominant_pattern": "NO_PATTERN",
            "frequency": 0,
            "confidence": "UNKNOWN",
            "evidence": list(evidence),
            "research_only": True,
        },
        "limitations": [],
        "research_only": True,
    }
    plan.update(over)
    return plan


class TestPatternIntelligence(unittest.TestCase):
    def test_empty_history(self):
        for value in (None, {}, [], "x", {"patterns": None}):
            plan = rpi.plan_research_pattern_intelligence(value)
            self.assertEqual(plan["dominant_patterns"], [], repr(value))
            self.assertEqual(plan["pattern_scores"], [])
            self.assertEqual(plan["strongest_signal"], "NO_PATTERN")
            self.assertEqual(plan["confidence"], "UNKNOWN")

    def test_single_pattern_low(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export(
                [{"pattern": "VERSION_LIMITED", "count": 1}]
            )
        )
        self.assertEqual(plan["dominant_patterns"],
                         ["VERSION_LIMITED"])
        self.assertEqual(plan["strongest_signal"], "VERSION_LIMITED")
        self.assertEqual(plan["confidence"], "LOW")
        self.assertEqual(
            plan["pattern_scores"],
            [{"pattern": "VERSION_LIMITED", "frequency": 1,
              "confidence": "LOW"}],
        )

    def test_medium_frequency(self):
        for count, expected in ((2, "MEDIUM"), (4, "MEDIUM")):
            plan = rpi.plan_research_pattern_intelligence(
                memory_export([{"pattern": "PATH_LIMITED", "count": count}])
            )
            self.assertEqual(plan["confidence"], expected, count)

    def test_high_frequency(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export([{"pattern": "PATH_LIMITED", "count": 5}])
        )
        self.assertEqual(plan["confidence"], "HIGH")
        self.assertEqual(plan["strongest_signal"], "PATH_LIMITED")

    def test_multiple_records_sorted_by_frequency(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export(
                [
                    {"pattern": "VERSION_LIMITED", "count": 2},
                    {"pattern": "PATH_LIMITED", "count": 5},
                    {"pattern": "HUMAN_RESEARCH", "count": 2},
                ]
            )
        )
        self.assertEqual(
            plan["dominant_patterns"],
            ["PATH_LIMITED", "HUMAN_RESEARCH", "VERSION_LIMITED"],
        )
        self.assertEqual(plan["strongest_signal"], "PATH_LIMITED")
        self.assertEqual(plan["confidence"], "HIGH")

    def test_dominant_fallback_without_evidence(self):
        export = memory_export()
        export["patterns"]["dominant_pattern"] = "VERSION_LIMITED"
        export["patterns"]["frequency"] = 3
        plan = rpi.plan_research_pattern_intelligence(export)
        self.assertEqual(plan["strongest_signal"], "VERSION_LIMITED")
        self.assertEqual(plan["confidence"], "MEDIUM")

    def test_no_pattern_evidence_is_empty(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export([{"pattern": "NO_PATTERN", "count": 4}])
        )
        self.assertEqual(plan["dominant_patterns"], [])
        self.assertEqual(plan["strongest_signal"], "NO_PATTERN")

    def test_direct_pattern_plan_override(self):
        plan = rpi.plan_research_pattern_intelligence(
            None,
            pattern_plan={
                "dominant_pattern": "TECHNOLOGY_LIMITED",
                "frequency": 1,
                "evidence": [
                    {"pattern": "TECHNOLOGY_LIMITED", "count": 1},
                ],
            },
        )
        self.assertEqual(plan["strongest_signal"], "TECHNOLOGY_LIMITED")

    def test_malformed_evidence_is_skipped(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export(
                [
                    None, "x", {"pattern": "NOPE", "count": 5},
                    {"pattern": "VERSION_LIMITED", "count": "bad"},
                    {"pattern": "VERSION_LIMITED", "count": 2},
                ]
            )
        )
        self.assertEqual(plan["strongest_signal"], "VERSION_LIMITED")
        self.assertEqual(plan["confidence"], "MEDIUM")

    def test_pattern_confidence_helper(self):
        self.assertEqual(rpi.pattern_confidence(0), "UNKNOWN")
        self.assertEqual(rpi.pattern_confidence(1), "LOW")
        self.assertEqual(rpi.pattern_confidence(2), "MEDIUM")
        self.assertEqual(rpi.pattern_confidence(4), "MEDIUM")
        self.assertEqual(rpi.pattern_confidence(5), "HIGH")

    def test_deterministic_output(self):
        export = memory_export(
            [{"pattern": "VERSION_LIMITED", "count": 2}]
        )
        first = rpi.plan_research_pattern_intelligence(export)
        second = rpi.plan_research_pattern_intelligence(export)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        export = memory_export(
            [{"pattern": "VERSION_LIMITED", "count": 2}]
        )
        before = copy.deepcopy(export)
        rpi.plan_research_pattern_intelligence(export)
        self.assertEqual(export, before)

    def test_json_serializable(self):
        plan = rpi.plan_research_pattern_intelligence(
            memory_export([{"pattern": "VERSION_LIMITED", "count": 1}])
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for value in (
            None,
            memory_export([{"pattern": "VERSION_LIMITED", "count": 1}]),
        ):
            plan = rpi.plan_research_pattern_intelligence(value)
            self.assertIs(plan["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rpi.plan_research_pattern_intelligence(
                memory_export([{"pattern": "PATH_LIMITED", "count": 3}])
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchPatternIntelligencePlan(
                dominant_patterns=["WINNER"],
                pattern_scores=[],
                strongest_signal="NO_PATTERN",
                confidence="UNKNOWN",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternIntelligencePlan(
                dominant_patterns=[],
                pattern_scores=[{"pattern": "NO_PATTERN",
                                 "frequency": 1,
                                 "confidence": "CERTAIN"}],
                strongest_signal="NO_PATTERN",
                confidence="UNKNOWN",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternIntelligencePlan(
                dominant_patterns=[], pattern_scores=[],
                strongest_signal="NOPE", confidence="UNKNOWN",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternIntelligencePlan(
                dominant_patterns=[], pattern_scores=[],
                strongest_signal="NO_PATTERN", confidence="UNKNOWN",
                severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchPatternIntelligencePlan(
            rule_version="r99-9",
            dominant_patterns=[],
            pattern_scores=[],
            strongest_signal="NO_PATTERN",
            confidence="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r33-1")
        with self.assertRaises(ValidationError):
            schema.ResearchPatternIntelligencePlan(
                dominant_patterns=[], pattern_scores=[],
                strongest_signal="NO_PATTERN", confidence="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rpi.RESEARCH_PATTERN_INTELLIGENCE_PLANNER_RULE_VERSION,
            "r33-1",
        )
        plan = rpi.plan_research_pattern_intelligence()
        self.assertEqual(plan["rule_version"], "r33-1")


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R33.1-R33.4
# ---------------------------------------------------------------------------


def _projection(
    *,
    paths=(),
    components=(),
    provenance=(),
    versions=(),
    associations=(),
    parameters=(),
    parameter_paths=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": list(components),
        "plugins": [],
        "versions": [
            {"value": value, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"}
            for value in versions
        ],
        "version_associations": list(associations),
        "parameters": [
            {"value": value, "source": "PARAMETER_INVENTORY",
             "evidence_type": "STRUCTURED_PARAMETER"}
            for value in parameters
        ],
        "paths": [
            {"value": value, "source": "ENDPOINT_INVENTORY",
             "evidence_type": "STRUCTURED_ENDPOINT"}
            for value in paths
        ],
        "component_provenance": list(provenance),
        "parameter_paths": list(parameter_paths),
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(components=(), parameters=(), versions=()):
    document = SimpleNamespace(
        components=list(components),
        parameters=list(parameters),
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {"affected_versions": list(versions)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestBackendIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, inventory, *, components=(), parameters=(),
               versions=()):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(components, parameters, versions),
        ):
            return acm.build_matches(cve=CVE, program="dell")["items"][0]

    def test_backend_additive_fields_and_rule_versions(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key, version in (
            ("research_pattern_intelligence_plan", "r33-1"),
            ("historical_candidate_ranking_plan", "r33-2"),
            ("research_efficiency_plan", "r33-3"),
            ("research_learning_export_plan", "r33-4"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        for key in (
            "research_pattern_intelligence_plan_rule_version",
            "historical_candidate_ranking_plan_rule_version",
            "research_efficiency_plan_rule_version",
            "research_learning_export_plan_rule_version",
        ):
            self.assertIn(key, item)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_memory_export_plan_rule_version"], "r32-4"
        )

    def test_backend_immediate_plan_learning(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "STRUCTURED_COMPONENT",
                }],
                versions=["1.2.3"],
                associations=[{
                    "version": "1.2.3",
                    "technology_family": "CKEditor",
                    "component": "CKEditor",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
            versions=["<=1.2.3"],
        )
        ranking = item["historical_candidate_ranking_plan"]
        self.assertEqual(ranking["ranking_reason"], "SINGLE_CANDIDATE")
        self.assertEqual(len(ranking["candidate_scores"]), 1)
        self.assertGreater(ranking["candidate_scores"][0]["score"], 0)
        efficiency = item["research_efficiency_plan"]
        self.assertEqual(efficiency["successful_ratio"], 1.0)
        self.assertEqual(efficiency["efficiency_state"], "HIGH")
        export = item["research_learning_export_plan"]
        self.assertTrue(export["ready"])
        self.assertIn("PRIORITIZE_HISTORICAL_SUCCESS",
                      export["recommendations"])
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_learning(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        ranking = item["historical_candidate_ranking_plan"]
        self.assertEqual(ranking["candidate_scores"][0]["score"], 0)
        efficiency = item["research_efficiency_plan"]
        self.assertEqual(efficiency["efficiency_state"], "LOW")
        self.assertEqual(
            item["research_learning_export_plan"]["ready"], True
        )
        self.assertIn("NO_HISTORICAL_SUCCESS",
                      item["research_learning_export_plan"]["limitations"])

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "research_memory_snapshot",
            "research_history_plan",
            "research_memory_export_plan",
            "research_intelligence_export_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["research_pattern_intelligence_plan"],
            item["research_learning_export_plan"],
        )

    def test_backend_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)

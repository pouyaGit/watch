"""tests/test_research_strategy_generator.py — Stage R34.1 tests.

Deterministic, offline tests for the research strategy generator plus
hermetic backend integration for the R34 strategy layer:

- deterministic output
- every strategy branch
- empty history and malformed input
- no input mutation, JSON serialization, vocabulary validation
- research_only always true, no operational attack content
- backend additive fields for R34.1-R34.4 (no live Mongo)

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

from ai.knowledge import research_strategy_generator as rsg
from ai.knowledge.relevance import AssetRecord
from ai.schemas import research_strategy as schema
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1560"


def learning_export(strongest="NO_PATTERN", confidence="UNKNOWN",
                    candidates=(), efficiency_state="UNKNOWN"):
    return {
        "rule_version": "r33-4",
        "ready": True,
        "patterns": {
            "rule_version": "r33-1",
            "dominant_patterns": [],
            "pattern_scores": [],
            "strongest_signal": strongest,
            "confidence": confidence,
            "research_only": True,
        },
        "ranking": {
            "rule_version": "r33-2",
            "candidate_scores": list(candidates),
            "ranking_reason": "SINGLE_CANDIDATE",
            "historical_signals": [],
            "research_only": True,
        },
        "efficiency": {
            "rule_version": "r33-3",
            "efficiency_state": efficiency_state,
            "successful_ratio": 0.0,
            "evidence_gap_ratio": 0.0,
            "recurring_blocker_ratio": 0.0,
            "improvement_signal": "NONE",
            "research_only": True,
        },
        "limitations": [],
        "research_only": True,
    }


def memory_export(total=1, successful=0, deferred=0, waiting=0,
                  recurring_blockers=()):
    return {
        "rule_version": "r32-4",
        "ready": True,
        "history": {
            "rule_version": "r32-2",
            "total_records": total,
            "successful_count": successful,
            "deferred_count": deferred,
            "waiting_count": waiting,
            "recurring_blockers": list(recurring_blockers),
            "recurring_improvement_areas": [],
            "research_patterns": [],
            "research_only": True,
        },
        "patterns": {},
        "limitations": [],
        "research_only": True,
    }


def candidate(score=4):
    return {
        "candidate_identity": "rc-a",
        "score": score,
        "records": 1,
        "signals": ["HISTORICAL_SUCCESS"],
    }


class TestStrategyBranches(unittest.TestCase):
    def test_identity_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("IDENTITY_LIMITED", "HIGH"),
            memory_export(total=2, waiting=2),
        )
        self.assertEqual(plan["strategy_type"], "IDENTITY_FIRST")
        self.assertEqual(plan["strategy_reason"],
                         "IDENTITY_LIMITATION_DOMINANT")
        self.assertEqual(plan["historical_basis"], "IDENTITY_LIMITATION")
        self.assertEqual(plan["confidence_level"], "HIGH")

    def test_technology_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("TECHNOLOGY_LIMITED", "MEDIUM"),
            memory_export(total=2, waiting=2),
        )
        self.assertEqual(plan["strategy_type"], "TECHNOLOGY_FIRST")

    def test_scope_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("SCOPE_LIMITED", "MEDIUM"),
            memory_export(total=2, waiting=2),
        )
        self.assertEqual(plan["strategy_type"], "SCOPE_FIRST")

    def test_version_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("VERSION_LIMITED", "HIGH"),
            memory_export(total=2, waiting=2),
        )
        self.assertEqual(plan["strategy_type"], "VERSION_FIRST")

    def test_human_review_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("HUMAN_RESEARCH", "MEDIUM"),
            memory_export(total=1, waiting=1),
        )
        self.assertEqual(plan["strategy_type"], "HUMAN_REVIEW_FIRST")

    def test_deferred_outcome_dominant(self):
        plan = rsg.generate_research_strategy(
            learning_export("UNKNOWN", "LOW"),
            memory_export(total=2, deferred=2),
        )
        self.assertEqual(plan["strategy_type"], "DEFERRED")
        self.assertEqual(plan["strategy_reason"],
                         "DEFERRED_OUTCOME_DOMINANT")
        self.assertEqual(plan["confidence_level"], "MEDIUM")

    def test_deferred_single_record_low_confidence(self):
        plan = rsg.generate_research_strategy(
            learning_export("UNKNOWN", "LOW"),
            memory_export(total=1, deferred=1),
        )
        self.assertEqual(plan["strategy_type"], "DEFERRED")
        self.assertEqual(plan["confidence_level"], "LOW")

    def test_evidence_first(self):
        plan = rsg.generate_research_strategy(
            learning_export("NO_PATTERN", "UNKNOWN",
                            candidates=[candidate(4)],
                            efficiency_state="HIGH"),
            memory_export(total=1, successful=1),
        )
        self.assertEqual(plan["strategy_type"], "EVIDENCE_FIRST")
        self.assertEqual(plan["strategy_reason"],
                         "SUCCESSFUL_EVIDENCE_HISTORY")
        self.assertEqual(plan["historical_basis"],
                         "EVIDENCE_SUCCESS_PATTERN")
        self.assertEqual(plan["confidence_level"], "HIGH")

    def test_evidence_first_medium_efficiency(self):
        plan = rsg.generate_research_strategy(
            learning_export("NO_PATTERN", "UNKNOWN",
                            candidates=[candidate(2)],
                            efficiency_state="MEDIUM"),
            memory_export(total=2, successful=1, waiting=1),
        )
        self.assertEqual(plan["strategy_type"], "EVIDENCE_FIRST")
        self.assertEqual(plan["confidence_level"], "MEDIUM")

    def test_unmapped_pattern_is_unknown(self):
        plan = rsg.generate_research_strategy(
            learning_export("PATH_LIMITED", "MEDIUM"),
            memory_export(total=2, waiting=2),
        )
        self.assertEqual(plan["strategy_type"], "UNKNOWN")
        self.assertEqual(plan["strategy_reason"], "UNMAPPED_PATTERN")

    def test_no_pattern_without_success_is_unknown(self):
        plan = rsg.generate_research_strategy(
            learning_export("NO_PATTERN", "UNKNOWN",
                            efficiency_state="MEDIUM"),
            memory_export(total=1, waiting=1),
        )
        self.assertEqual(plan["strategy_type"], "UNKNOWN")
        self.assertEqual(plan["historical_basis"],
                         "UNKNOWN_PATTERN")

    def test_empty_history(self):
        plan = rsg.generate_research_strategy(
            learning_export(), memory_export(total=0)
        )
        self.assertEqual(plan["strategy_type"], "UNKNOWN")
        self.assertEqual(plan["strategy_reason"], "INSUFFICIENT_HISTORY")
        self.assertEqual(plan["historical_basis"], "NO_HISTORY")
        self.assertEqual(plan["confidence_level"], "UNKNOWN")

    def test_blockers_flow_through(self):
        plan = rsg.generate_research_strategy(
            learning_export("VERSION_LIMITED", "MEDIUM"),
            memory_export(total=2, waiting=2,
                          recurring_blockers=["VERSION_EVIDENCE_MISSING"]),
        )
        self.assertEqual(plan["blockers"], ["VERSION_EVIDENCE_MISSING"])

    def test_malformed_input(self):
        for args in ((None, None), ({}, {}), ("x", 0), ([], [])):
            plan = rsg.generate_research_strategy(*args)
            self.assertEqual(plan["strategy_type"], "UNKNOWN",
                             repr(args))
            self.assertEqual(plan["strategy_reason"], "MALFORMED_INPUT")
            self.assertEqual(plan["historical_basis"], "MALFORMED_INPUT")
            self.assertEqual(plan["confidence_level"], "UNKNOWN")

    def test_deterministic_output(self):
        args = (
            learning_export("VERSION_LIMITED", "HIGH"),
            memory_export(total=2, waiting=2),
        )
        first = rsg.generate_research_strategy(*args)
        second = rsg.generate_research_strategy(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        learning = learning_export("SCOPE_LIMITED", "MEDIUM")
        memory = memory_export(total=2, waiting=2,
                               recurring_blockers=["SCOPE_EVIDENCE_MISSING"])
        snapshots = (copy.deepcopy(learning), copy.deepcopy(memory))
        rsg.generate_research_strategy(learning, memory)
        self.assertEqual(learning, snapshots[0])
        self.assertEqual(memory, snapshots[1])

    def test_json_serializable(self):
        plan = rsg.generate_research_strategy(
            learning_export("VERSION_LIMITED", "HIGH")
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for args in ((None, None),
                     (learning_export("VERSION_LIMITED", "HIGH"),
                      memory_export())):
            plan = rsg.generate_research_strategy(*args)
            self.assertIs(plan["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rsg.generate_research_strategy(
                learning_export("VERSION_LIMITED", "HIGH"),
                memory_export(total=1, successful=1),
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "strategy_type": "VERSION_FIRST",
            "strategy_reason": "VERSION_LIMITATION_DOMINANT",
            "historical_basis": "VERSION_LIMITATION",
            "confidence_level": "HIGH",
        }
        for key, value in (
            ("strategy_type", "WIN_FIRST"),
            ("strategy_reason", "BECAUSE"),
            ("historical_basis", "MONEY"),
            ("confidence_level", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchStrategyPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyPlan(**base, severity="HIGH")
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyPlan(
                **{**base, "blockers": ["DEPLOY_EXPLOIT"]}
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchStrategyPlan(
            rule_version="r99-9",
            strategy_type="UNKNOWN",
            strategy_reason="MALFORMED_INPUT",
            historical_basis="MALFORMED_INPUT",
            confidence_level="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r34-1")
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyPlan(
                strategy_type="UNKNOWN",
                strategy_reason="MALFORMED_INPUT",
                historical_basis="MALFORMED_INPUT",
                confidence_level="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rsg.RESEARCH_STRATEGY_GENERATOR_RULE_VERSION, "r34-1"
        )
        plan = rsg.generate_research_strategy()
        self.assertEqual(plan["rule_version"], "r34-1")


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R34.1-R34.4
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
            ("research_strategy_plan", "r34-1"),
            ("research_path_plan", "r34-2"),
            ("research_budget_plan", "r34-3"),
            ("research_strategy_export_plan", "r34-4"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        for key in (
            "research_strategy_plan_rule_version",
            "research_path_plan_rule_version",
            "research_budget_plan_rule_version",
            "research_strategy_export_plan_rule_version",
        ):
            self.assertIn(key, item)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_learning_export_plan_rule_version"], "r33-4"
        )

    def test_backend_immediate_plan_evidence_first_continue(self):
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
        self.assertEqual(
            item["research_strategy_plan"]["strategy_type"],
            "EVIDENCE_FIRST",
        )
        self.assertEqual(
            item["research_path_plan"]["primary_path"],
            "COLLECT_EVIDENCE",
        )
        self.assertEqual(
            item["research_budget_plan"]["budget_state"], "CONTINUE"
        )
        self.assertTrue(item["research_strategy_export_plan"]["ready"])
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_deferred_stop(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["research_strategy_plan"]["strategy_type"], "DEFERRED"
        )
        self.assertEqual(item["research_path_plan"]["primary_path"], "STOP")
        self.assertEqual(
            item["research_budget_plan"]["budget_state"], "STOP"
        )
        self.assertIn(
            "DEFERRED_STRATEGY",
            item["research_strategy_export_plan"]["limitations"],
        )

    def test_backend_candidate_identity_is_privacy_preserving(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        identity = item["research_memory_snapshot"]["candidate_identity"]
        self.assertTrue(identity.startswith("rc-"))
        self.assertNotIn(CVE, json.dumps(item["research_strategy_plan"]))

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "research_memory_export_plan",
            "research_learning_export_plan",
            "research_intelligence_export_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["research_strategy_plan"],
            item["research_strategy_export_plan"],
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

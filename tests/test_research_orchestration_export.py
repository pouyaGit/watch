"""tests/test_research_orchestration_export.py — Stage R35.4 tests.

Deterministic, offline tests for the research orchestration exporter:

- deterministic output
- ready requires all three R35 plans to be valid
- limitation mappings
- malformed input handling
- no input mutation, JSON serialization, vocabulary validation
- research_only always true, no operational execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import research_orchestration_export as roe
from ai.schemas import research_orchestration_export as schema


def roles(role_list=("VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"),
          reason="VERSION_STRATEGY", confidence="HIGH"):
    return {
        "rule_version": "r35-1",
        "required_roles": list(role_list),
        "primary_role": role_list[0],
        "role_reason": reason,
        "confidence_level": confidence,
        "research_only": True,
    }


def workflow(nodes=("ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN",
                    "REVIEW_HISTORY")):
    nodes = list(nodes)
    edges = [
        {"from": nodes[index], "to": nodes[index + 1]}
        for index in range(len(nodes) - 1)
    ]
    return {
        "rule_version": "r35-2",
        "nodes": nodes,
        "edges": edges,
        "entry_nodes": [nodes[0]],
        "terminal_nodes": [nodes[-1]],
        "research_only": True,
    }


def coordination(mode="SEQUENTIAL",
                 sequence=("VERSION_ANALYSIS", "EVIDENCE_ANALYSIS")):
    sequence = list(sequence)
    return {
        "rule_version": "r35-3",
        "coordination_mode": mode,
        "role_sequence": sequence,
        "dependencies": [
            {"role": sequence[index + 1], "depends_on": sequence[index]}
            for index in range(len(sequence) - 1)
        ],
        "handoff_points": [
            {"from": sequence[index], "to": sequence[index + 1]}
            for index in range(len(sequence) - 1)
        ],
        "research_only": True,
    }


class TestOrchestrationExport(unittest.TestCase):
    def test_ready_when_all_valid(self):
        export = roe.export_research_orchestration(
            roles(), workflow(), coordination()
        )
        self.assertTrue(export["ready"])
        self.assertEqual(export["rule_version"], "r35-4")
        self.assertEqual(export["roles"]["primary_role"],
                         "VERSION_ANALYSIS")
        self.assertEqual(export["workflow"]["nodes"][0],
                         "ANALYZE_VERSION")
        self.assertEqual(export["coordination"]["coordination_mode"],
                         "SEQUENTIAL")
        self.assertEqual(export["limitations"], [])

    def test_not_ready_when_any_plan_missing(self):
        valid_roles = roles()
        valid_workflow = workflow()
        valid_coordination = coordination()
        for combo in (
            (None, valid_workflow, valid_coordination),
            (valid_roles, None, valid_coordination),
            (valid_roles, valid_workflow, None),
            (None, None, None),
        ):
            export = roe.export_research_orchestration(*combo)
            self.assertFalse(export["ready"], repr(combo))

    def test_not_ready_when_plan_malformed(self):
        export = roe.export_research_orchestration(
            {"primary_role": "NOPE"},
            {"nodes": []},
            {"coordination_mode": "NOPE"},
        )
        self.assertFalse(export["ready"])

    def test_unknown_strategy_limitation(self):
        export = roe.export_research_orchestration(
            roles(("HISTORY_ANALYSIS",), "UNKNOWN_STRATEGY", "UNKNOWN"),
            workflow(("REVIEW_HISTORY",)),
            coordination("UNKNOWN", ("HISTORY_ANALYSIS",)),
        )
        self.assertIn(schema.LIMITATION_UNKNOWN_STRATEGY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_LOW_CONFIDENCE,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_UNKNOWN_COORDINATION,
                      export["limitations"])

    def test_deferred_limitation(self):
        export = roe.export_research_orchestration(
            roles(("HUMAN_REVIEW",), "DEFERRED_STRATEGY", "LOW"),
            workflow(("STOP",)),
            coordination("REVIEW_GATE", ("HUMAN_REVIEW",)),
        )
        self.assertIn(schema.LIMITATION_DEFERRED_STRATEGY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_LOW_CONFIDENCE,
                      export["limitations"])

    def test_empty_workflow_limitation(self):
        export = roe.export_research_orchestration(
            roles(), {"nodes": []}, coordination()
        )
        self.assertFalse(export["ready"])
        self.assertIn(schema.LIMITATION_EMPTY_WORKFLOW,
                      export["limitations"])

    def test_limitations_are_ordered(self):
        export = roe.export_research_orchestration(
            roles(("HISTORY_ANALYSIS",), "UNKNOWN_STRATEGY", "UNKNOWN"),
            {"nodes": []},
            coordination("UNKNOWN", ("HISTORY_ANALYSIS",)),
        )
        self.assertEqual(
            export["limitations"],
            [
                schema.LIMITATION_UNKNOWN_STRATEGY,
                schema.LIMITATION_LOW_CONFIDENCE,
                schema.LIMITATION_UNKNOWN_COORDINATION,
                schema.LIMITATION_EMPTY_WORKFLOW,
            ],
        )

    def test_malformed_inputs(self):
        for args in ((None, None, None), ({}, {}, {}), ("x", 0, [])):
            export = roe.export_research_orchestration(*args)
            self.assertFalse(export["ready"], repr(args))
            self.assertEqual(
                export["limitations"],
                [
                    schema.LIMITATION_UNKNOWN_STRATEGY,
                    schema.LIMITATION_LOW_CONFIDENCE,
                    schema.LIMITATION_UNKNOWN_COORDINATION,
                    schema.LIMITATION_EMPTY_WORKFLOW,
                ],
            )

    def test_deterministic_output(self):
        args = (roles(), workflow(), coordination())
        first = roe.export_research_orchestration(*args)
        second = roe.export_research_orchestration(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        role_plan = roles()
        workflow_plan = workflow()
        coordination_plan = coordination()
        snapshots = (
            copy.deepcopy(role_plan),
            copy.deepcopy(workflow_plan),
            copy.deepcopy(coordination_plan),
        )
        roe.export_research_orchestration(
            role_plan, workflow_plan, coordination_plan
        )
        self.assertEqual(role_plan, snapshots[0])
        self.assertEqual(workflow_plan, snapshots[1])
        self.assertEqual(coordination_plan, snapshots[2])

    def test_embedded_snapshots_do_not_alias_inputs(self):
        role_plan = roles()
        workflow_plan = workflow()
        coordination_plan = coordination()
        export = roe.export_research_orchestration(
            role_plan, workflow_plan, coordination_plan
        )
        export["roles"]["required_roles"].clear()
        export["workflow"]["nodes"].clear()
        export["coordination"]["role_sequence"].clear()
        self.assertEqual(len(role_plan["required_roles"]), 2)
        self.assertEqual(len(workflow_plan["nodes"]), 3)
        self.assertEqual(len(coordination_plan["role_sequence"]), 2)

    def test_json_serializable(self):
        export = roe.export_research_orchestration(
            roles(), workflow(), coordination()
        )
        self.assertIsInstance(json.loads(json.dumps(export)), dict)

    def test_research_only_always_true(self):
        for export in (
            roe.export_research_orchestration(),
            roe.export_research_orchestration(
                roles(), workflow(), coordination()
            ),
        ):
            self.assertIs(export["research_only"], True)

    def test_no_operational_execution_content(self):
        blob = json.dumps(
            roe.export_research_orchestration(
                roles(), workflow(), coordination()
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body", "dispatch",
            "worker", "scheduler", "execute",
        ):
            self.assertNotIn(marker, blob)

    def test_limitation_vocabulary_is_closed(self):
        self.assertEqual(
            set(schema.LIMITATION_CODES),
            {
                "UNKNOWN_STRATEGY", "LOW_CONFIDENCE",
                "DEFERRED_STRATEGY", "UNKNOWN_COORDINATION",
                "EMPTY_WORKFLOW",
            },
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchOrchestrationExportPlan(
                ready=True, limitations=["WIN"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchOrchestrationExportPlan(
                ready=True, limitations=[], severity="HIGH"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchOrchestrationExportPlan(
            rule_version="r99-9",
            ready=False,
            limitations=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r35-4")
        with self.assertRaises(ValidationError):
            schema.ResearchOrchestrationExportPlan(
                ready=False, limitations=[], research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            roe.RESEARCH_ORCHESTRATION_EXPORTER_RULE_VERSION, "r35-4"
        )
        export = roe.export_research_orchestration()
        self.assertEqual(export["rule_version"], "r35-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)

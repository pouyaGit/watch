"""tests/test_research_workflow_graph.py — Stage R35.2 tests.

Deterministic, offline tests for the research workflow graph builder:

- deterministic output
- every strategy -> node chain
- acyclic ordered edges, entry/terminal nodes
- role-plan fallback decoding
- invalid input and empty strategy
- no mutation, JSON serialization, vocabulary validation
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

from ai.knowledge import research_workflow_graph as rwg
from ai.schemas import research_workflow_graph as schema


def strategy(strategy_type="UNKNOWN"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": "MALFORMED_INPUT",
        "historical_basis": "MALFORMED_INPUT",
        "confidence_level": "HIGH",
        "blockers": [],
        "research_only": True,
    }


def role_plan(reason="VERSION_STRATEGY"):
    return {
        "rule_version": "r35-1",
        "required_roles": ["VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"],
        "primary_role": "VERSION_ANALYSIS",
        "role_reason": reason,
        "confidence_level": "HIGH",
        "research_only": True,
    }


class TestWorkflowGraph(unittest.TestCase):
    def test_every_strategy_maps(self):
        expectations = (
            ("IDENTITY_FIRST",
             ["ANALYZE_ASSET", "ANALYZE_IDENTITY",
              "COLLECT_EVIDENCE_PLAN"]),
            ("VERSION_FIRST",
             ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN",
              "REVIEW_HISTORY"]),
            ("TECHNOLOGY_FIRST",
             ["ANALYZE_TECHNOLOGY", "COLLECT_EVIDENCE_PLAN",
              "REVIEW_HISTORY"]),
            ("EVIDENCE_FIRST",
             ["COLLECT_EVIDENCE_PLAN", "REVIEW_HISTORY"]),
            ("SCOPE_FIRST",
             ["ANALYZE_ASSET", "COLLECT_EVIDENCE_PLAN",
              "REVIEW_HISTORY"]),
            ("HUMAN_REVIEW_FIRST", ["HUMAN_REVIEW"]),
            ("DEFERRED", ["STOP"]),
            ("UNKNOWN", ["REVIEW_HISTORY"]),
        )
        for strategy_type, nodes in expectations:
            graph = rwg.build_research_workflow_graph(
                strategy(strategy_type)
            )
            self.assertEqual(graph["nodes"], nodes, strategy_type)
            self.assertEqual(graph["entry_nodes"], [nodes[0]],
                             strategy_type)
            self.assertEqual(graph["terminal_nodes"], [nodes[-1]],
                             strategy_type)

    def test_version_first_example_ordering(self):
        graph = rwg.build_research_workflow_graph(strategy("VERSION_FIRST"))
        self.assertEqual(
            graph["nodes"],
            ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN",
             "REVIEW_HISTORY"],
        )
        self.assertEqual(
            graph["edges"],
            [
                {"from": "ANALYZE_VERSION",
                 "to": "COLLECT_EVIDENCE_PLAN"},
                {"from": "COLLECT_EVIDENCE_PLAN",
                 "to": "REVIEW_HISTORY"},
            ],
        )

    def test_edges_follow_node_order_and_are_acyclic(self):
        for strategy_type in rwg.STRATEGY_WORKFLOW:
            graph = rwg.build_research_workflow_graph(
                strategy(strategy_type)
            )
            nodes = graph["nodes"]
            edges = graph["edges"]
            self.assertEqual(
                edges,
                [
                    {"from": nodes[index], "to": nodes[index + 1]}
                    for index in range(len(nodes) - 1)
                ],
                strategy_type,
            )
            self.assertTrue(
                schema._nodes_acyclic(nodes, edges), strategy_type
            )

    def test_deferred_is_stop_only(self):
        graph = rwg.build_research_workflow_graph(strategy("DEFERRED"))
        self.assertEqual(graph["nodes"], ["STOP"])
        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["entry_nodes"], ["STOP"])
        self.assertEqual(graph["terminal_nodes"], ["STOP"])

    def test_role_plan_fallback(self):
        graph = rwg.build_research_workflow_graph(
            None, role_plan("VERSION_STRATEGY")
        )
        self.assertEqual(graph["nodes"][0], "ANALYZE_VERSION")

    def test_role_fallback_mapping_is_complete(self):
        for strategy_type, (_roles, reason) in rwg.STRATEGY_ROLES.items():
            self.assertEqual(
                rwg.REASON_TO_STRATEGY[reason], strategy_type
            )

    def test_empty_strategy(self):
        for args in ((None, None), ({}, {}), ([], []), ("x", 0)):
            graph = rwg.build_research_workflow_graph(*args)
            self.assertEqual(graph["nodes"], ["REVIEW_HISTORY"],
                             repr(args))
            self.assertEqual(graph["entry_nodes"], ["REVIEW_HISTORY"])
            self.assertEqual(graph["terminal_nodes"], ["REVIEW_HISTORY"])

    def test_unrecognized_strategy_and_reason(self):
        graph = rwg.build_research_workflow_graph(
            strategy("WIN_FIRST"), role_plan("NOPE")
        )
        self.assertEqual(graph["nodes"], ["REVIEW_HISTORY"])

    def test_deterministic_output(self):
        plan = strategy("IDENTITY_FIRST")
        first = rwg.build_research_workflow_graph(plan)
        second = rwg.build_research_workflow_graph(plan)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        strategy_plan = strategy("TECHNOLOGY_FIRST")
        roles = role_plan("TECHNOLOGY_STRATEGY")
        snapshots = (copy.deepcopy(strategy_plan), copy.deepcopy(roles))
        rwg.build_research_workflow_graph(strategy_plan, roles)
        self.assertEqual(strategy_plan, snapshots[0])
        self.assertEqual(roles, snapshots[1])

    def test_json_serializable(self):
        graph = rwg.build_research_workflow_graph(strategy("DEFERRED"))
        self.assertIsInstance(json.loads(json.dumps(graph)), dict)

    def test_research_only_always_true(self):
        for args in ((None, None), (strategy("VERSION_FIRST"), None)):
            graph = rwg.build_research_workflow_graph(*args)
            self.assertIs(graph["research_only"], True)

    def test_no_operational_execution_content(self):
        blob = json.dumps(
            [
                rwg.build_research_workflow_graph(strategy(name))
                for name in rwg.STRATEGY_WORKFLOW
            ]
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body", "dispatch",
            "worker", "scheduler", "execute",
        ):
            self.assertNotIn(marker, blob)

    def test_vocabulary_is_closed(self):
        self.assertEqual(
            set(schema.WORKFLOW_NODES),
            {
                "ANALYZE_ASSET", "ANALYZE_IDENTITY",
                "ANALYZE_TECHNOLOGY", "ANALYZE_VERSION",
                "COLLECT_EVIDENCE_PLAN", "REVIEW_HISTORY",
                "HUMAN_REVIEW", "STOP",
            },
        )
        for nodes in rwg.STRATEGY_WORKFLOW.values():
            self.assertTrue(set(nodes).issubset(set(schema.WORKFLOW_NODES)))

    def test_schema_rejects_bad_values(self):
        base = {
            "nodes": ["ANALYZE_VERSION", "REVIEW_HISTORY"],
            "edges": [{"from": "ANALYZE_VERSION", "to": "REVIEW_HISTORY"}],
            "entry_nodes": ["ANALYZE_VERSION"],
            "terminal_nodes": ["REVIEW_HISTORY"],
        }
        for key, value in (
            ("nodes", ["RUN_SCAN"]),
            ("edges", [{"from": "ANALYZE_VERSION", "to": "RUN_SCAN"}]),
            ("entry_nodes", ["EXECUTOR"]),
            ("terminal_nodes", ["DEPLOY"]),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchWorkflowGraphPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchWorkflowGraphPlan(**base, severity="HIGH")

    def test_schema_rejects_self_loop_and_cycle(self):
        with self.assertRaises(ValidationError):
            schema.ResearchWorkflowGraphPlan(
                nodes=["REVIEW_HISTORY"],
                edges=[{"from": "REVIEW_HISTORY",
                        "to": "REVIEW_HISTORY"}],
                entry_nodes=["REVIEW_HISTORY"],
                terminal_nodes=["REVIEW_HISTORY"],
            )
        with self.assertRaises(ValidationError):
            schema.ResearchWorkflowGraphPlan(
                nodes=["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN"],
                edges=[
                    {"from": "ANALYZE_VERSION",
                     "to": "COLLECT_EVIDENCE_PLAN"},
                    {"from": "COLLECT_EVIDENCE_PLAN",
                     "to": "ANALYZE_VERSION"},
                ],
                entry_nodes=["ANALYZE_VERSION"],
                terminal_nodes=["COLLECT_EVIDENCE_PLAN"],
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchWorkflowGraphPlan(
            rule_version="r99-9",
            nodes=["STOP"],
            edges=[],
            entry_nodes=["STOP"],
            terminal_nodes=["STOP"],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r35-2")
        with self.assertRaises(ValidationError):
            schema.ResearchWorkflowGraphPlan(
                nodes=["STOP"],
                edges=[],
                entry_nodes=["STOP"],
                terminal_nodes=["STOP"],
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rwg.RESEARCH_WORKFLOW_GRAPH_BUILDER_RULE_VERSION, "r35-2"
        )
        graph = rwg.build_research_workflow_graph()
        self.assertEqual(graph["rule_version"], "r35-2")


if __name__ == "__main__":
    unittest.main(verbosity=2)

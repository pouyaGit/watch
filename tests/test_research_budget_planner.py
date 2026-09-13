"""tests/test_research_budget_planner.py — Stage R34.3 tests.

Deterministic, offline tests for the research budget planner:

- deterministic output
- every budget state (CONTINUE / LIMITED / PAUSE / STOP / UNKNOWN)
- precedence of deferred, blockers and confidence
- malformed input handling
- no input mutation, JSON serialization, vocabulary validation
- research_only always true, no operational attack content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import research_budget_planner as rbp
from ai.schemas import research_budget as schema


def strategy(strategy_type="VERSION_FIRST", confidence="MEDIUM"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": "VERSION_LIMITATION_DOMINANT",
        "historical_basis": "VERSION_LIMITATION",
        "confidence_level": confidence,
        "blockers": [],
        "research_only": True,
    }


def path(primary="VERIFY_VERSION"):
    return {
        "rule_version": "r34-2",
        "selected_path": [primary, "COLLECT_EVIDENCE"],
        "primary_path": primary,
        "path_reason": "VERSION_STRATEGY",
        "confidence_level": "MEDIUM",
        "research_only": True,
    }


def learning_export(efficiency_state="UNKNOWN", candidates=()):
    return {
        "rule_version": "r33-4",
        "ready": True,
        "patterns": {},
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


def memory_export(recurring_blockers=()):
    return {
        "rule_version": "r32-4",
        "ready": True,
        "history": {
            "rule_version": "r32-2",
            "total_records": 1,
            "successful_count": 0,
            "deferred_count": 0,
            "waiting_count": 1,
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


class TestBudgetStates(unittest.TestCase):
    def test_continue_state(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "HIGH"),
            path(),
            learning_export("HIGH", [candidate(4)]),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "CONTINUE")
        self.assertEqual(budget["reason"], "HIGH_CONFIDENCE_SUCCESS")
        self.assertEqual(budget["allowed_next_step"], "MORE_EVIDENCE")

    def test_high_confidence_without_success_is_unknown(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "HIGH"),
            path(),
            learning_export("UNKNOWN"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "UNKNOWN")

    def test_limited_state_medium(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "MEDIUM"),
            path(),
            learning_export("MEDIUM"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "LIMITED")
        self.assertEqual(budget["reason"], "MEDIUM_CONFIDENCE")
        self.assertEqual(budget["allowed_next_step"], "MORE_ANALYSIS")

    def test_limited_state_low(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "LOW"),
            path(),
            learning_export("LOW"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "LIMITED")
        self.assertEqual(budget["reason"], "LOW_CONFIDENCE")

    def test_pause_state(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "HIGH"),
            path(),
            learning_export("HIGH", [candidate(4)]),
            memory_export(recurring_blockers=["VERSION_EVIDENCE_MISSING"]),
        )
        self.assertEqual(budget["budget_state"], "PAUSE")
        self.assertEqual(budget["reason"], "REPEATED_BLOCKERS")
        self.assertEqual(budget["allowed_next_step"], "HUMAN_REVIEW")

    def test_stop_state(self):
        budget = rbp.plan_research_budget(
            strategy("DEFERRED", "LOW"),
            {"primary_path": "STOP"},
            learning_export("LOW"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "STOP")
        self.assertEqual(budget["reason"], "DEFERRED_STRATEGY")
        self.assertEqual(budget["allowed_next_step"], "NONE")

    def test_stop_from_path_without_deferred_strategy(self):
        budget = rbp.plan_research_budget(
            strategy("UNKNOWN", "UNKNOWN"),
            {"primary_path": "STOP"},
            learning_export("UNKNOWN"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "STOP")

    def test_unknown_state(self):
        budget = rbp.plan_research_budget(
            strategy("UNKNOWN", "UNKNOWN"),
            path("REVIEW_HISTORY"),
            learning_export("UNKNOWN"),
            memory_export(),
        )
        self.assertEqual(budget["budget_state"], "UNKNOWN")
        self.assertEqual(budget["reason"], "UNKNOWN_CONFIDENCE")
        self.assertEqual(budget["allowed_next_step"], "UNKNOWN")

    def test_deferred_beats_blockers_and_confidence(self):
        budget = rbp.plan_research_budget(
            strategy("DEFERRED", "HIGH"),
            {"primary_path": "STOP"},
            learning_export("HIGH", [candidate(4)]),
            memory_export(recurring_blockers=["VERSION_EVIDENCE_MISSING"]),
        )
        self.assertEqual(budget["budget_state"], "STOP")

    def test_blockers_beat_continue(self):
        budget = rbp.plan_research_budget(
            strategy("VERSION_FIRST", "HIGH"),
            path(),
            learning_export("HIGH", [candidate(4)]),
            memory_export(recurring_blockers=["VERSION_EVIDENCE_MISSING"]),
        )
        self.assertEqual(budget["budget_state"], "PAUSE")

    def test_malformed_input(self):
        for args in ((None, None, None, None), ({}, {}, {}, {}),
                     ("x", 0, [], "y")):
            budget = rbp.plan_research_budget(*args)
            self.assertEqual(budget["budget_state"], "UNKNOWN",
                             repr(args))
            self.assertEqual(budget["reason"], "UNKNOWN_CONFIDENCE")

    def test_all_states_map_to_allowed_next_step(self):
        self.assertEqual(
            set(rbp.BUDGET_NEXT_STEP),
            set(schema.BUDGET_STATES),
        )
        for step in rbp.BUDGET_NEXT_STEP.values():
            self.assertIn(step, schema.ALLOWED_NEXT_STEPS)

    def test_deterministic_output(self):
        args = (
            strategy("SCOPE_FIRST", "MEDIUM"),
            path("VERIFY_SCOPE"),
            learning_export("MEDIUM"),
            memory_export(),
        )
        first = rbp.plan_research_budget(*args)
        second = rbp.plan_research_budget(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (
            strategy("SCOPE_FIRST", "MEDIUM"),
            path("VERIFY_SCOPE"),
            learning_export("MEDIUM"),
            memory_export(recurring_blockers=["SCOPE_EVIDENCE_MISSING"]),
        )
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        rbp.plan_research_budget(*inputs)
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        budget = rbp.plan_research_budget()
        self.assertIsInstance(json.loads(json.dumps(budget)), dict)

    def test_research_only_always_true(self):
        for args in ((None, None, None, None),
                     (strategy("VERSION_FIRST", "MEDIUM"), path(),
                      learning_export("MEDIUM"), memory_export())):
            budget = rbp.plan_research_budget(*args)
            self.assertIs(budget["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rbp.plan_research_budget(
                strategy("VERSION_FIRST", "MEDIUM"),
                path(), learning_export("MEDIUM"), memory_export(),
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "budget_state": "LIMITED",
            "reason": "MEDIUM_CONFIDENCE",
            "allowed_next_step": "MORE_ANALYSIS",
        }
        for key, value in (
            ("budget_state", "SPEND"),
            ("reason", "BECAUSE"),
            ("allowed_next_step", "SCAN_TARGET"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchBudgetPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchBudgetPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchBudgetPlan(
            rule_version="r99-9",
            budget_state="UNKNOWN",
            reason="UNKNOWN_CONFIDENCE",
            allowed_next_step="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r34-3")
        with self.assertRaises(ValidationError):
            schema.ResearchBudgetPlan(
                budget_state="UNKNOWN",
                reason="UNKNOWN_CONFIDENCE",
                allowed_next_step="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rbp.RESEARCH_BUDGET_PLANNER_RULE_VERSION, "r34-3"
        )
        budget = rbp.plan_research_budget()
        self.assertEqual(budget["rule_version"], "r34-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)

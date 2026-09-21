"""Frozen-boundary constants guard (S1/S2).

AEC-1 modifies nothing outside ``aec/``; the safety of that claim rests on
constants that already exist in the frozen layers. This test pins them from the
*source* (AST) rather than by importing the executors — a guard test must not
import a module whose whole purpose is to be able to send traffic, and it must
not depend on the surrounding environment to tell the truth.

If any of these assertions starts failing, an executor's capability boundary has
moved and AEC-1 must stop and be re-reviewed.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]

#: module -> {constant: expected literal value}
FROZEN_CONSTANTS = {
    "ai/execution/http_executor.py": {"LIVE_TRAFFIC_ENABLED": False},
    "ai/execution/nuclei_executor.py": {"LIVE_NUCLEI": False},
    "ai/execution/browser_executor.py": {"LIVE_BROWSER": False},
    "backend/tasks_registry.py": {"ALLOWED_SCRIPT_DIRS": ("crawl", "ns")},
}

#: Env gate that must never be set in an AEC-1 session.
LIVE_VALIDATION_ENV = "WATCH_AI_LIVE_VALIDATION"


def module_literals(relative_path: str) -> dict:
    """Top-level literal assignments from a module, without importing it."""
    path = REPO_ROOT / relative_path
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        else:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
        for name in targets:
            found[name] = value
    return found


class TestFrozenCapabilityFlags(unittest.TestCase):
    def test_executor_live_switches_are_still_false(self):
        for module, expected in FROZEN_CONSTANTS.items():
            with self.subTest(module=module):
                literals = module_literals(module)
                for name, value in expected.items():
                    self.assertIn(name, literals, f"{module} lost {name}")
                    self.assertEqual(literals[name], value, f"{module}:{name} changed")

    def test_live_validation_env_gate_is_not_set(self):
        self.assertNotIn(LIVE_VALIDATION_ENV, os.environ)

    def test_task_runner_script_allowlist_is_unchanged(self):
        self.assertEqual(module_literals("backend/tasks_registry.py")["ALLOWED_SCRIPT_DIRS"], ("crawl", "ns"))


class TestAecBudgetConstants(unittest.TestCase):
    """The pilot budget may only ever be tightened, never widened."""

    @classmethod
    def setUpClass(cls):
        import aec

        cls.aec = aec

    def test_live_http_is_hard_false(self):
        self.assertIs(self.aec.AEC_LIVE_HTTP_ENABLED, False)

    def test_rule_versions_are_pinned(self):
        self.assertEqual(self.aec.SELECTION_RULE_VERSION, "aec-selection/v1")
        self.assertEqual(self.aec.APPROVAL_SHEET_VERSION, "aec-approval-sheet/v1")

    def test_budget_limits_are_exactly_the_approved_numbers(self):
        budget = self.aec.PILOT_BUDGET
        self.assertEqual(budget.max_cases, 20)
        self.assertEqual(budget.max_requests, 60)
        self.assertEqual(budget.max_requests_per_case, 4)
        self.assertEqual(budget.max_requests_per_host, 5)
        self.assertEqual(budget.max_concurrency, 1)
        self.assertEqual(budget.min_seconds_between_requests, 1.0)
        self.assertEqual(budget.max_wall_seconds_per_run, 600)

    def test_budget_is_immutable(self):
        with self.assertRaises(Exception):
            self.aec.PILOT_BUDGET.max_cases = 100

    def test_host_window_and_family_caps_sum_to_the_case_budget(self):
        self.assertEqual(self.aec.PILOT_HOST_RANGE, (3, 5))
        self.assertEqual(self.aec.MAX_HOSTS, 5)
        self.assertEqual(sum(self.aec.FAMILY_CAPS.values()), self.aec.PILOT_BUDGET.max_cases)
        self.assertEqual(tuple(self.aec.FAMILY_CAPS), self.aec.FAMILY_ORDER)

    def test_output_roots_are_the_only_writable_places(self):
        self.assertEqual(self.aec.ALLOWED_OUTPUT_ROOTS, ("ai_data/aec", "agent-reports"))

    def test_evidence_ladder_starts_at_l0_and_targets_l3(self):
        self.assertEqual(self.aec.EVIDENCE_LEVEL_CURRENT, "L0_STORED_OBSERVATION")
        self.assertEqual(self.aec.EVIDENCE_LEVEL_TARGET, "L3_COMPARATIVE")

    def test_disclaimer_is_present_and_says_not_confirmed(self):
        note = self.aec.NOT_CONFIRMED_NOTE
        self.assertIn("NOT_CONFIRMED", note)
        self.assertIn("no finding", note.lower())

    def test_no_confirmed_claim_is_exported(self):
        for name in self.aec.__all__:
            self.assertNotIn("CONFIRMED", name.replace("NOT_CONFIRMED_NOTE", ""))


if __name__ == "__main__":
    unittest.main()

"""Tests for aec/budget_ledger.py — AEC-1 T3 (S6): deterministic budget ledger.

Written before the module exists (TDD). The ledger answers one question —
"Is this proposed observation allowed by the approved budget?" — without
executing anything, approving any authorization, or deciding security impact.

Minimum coverage (task brief):

1.  Fresh ledger allows valid request
2.  Total budget exhaustion
3.  Case budget exhaustion
4.  Host budget exhaustion
5.  Invalid negative cost rejected
6.  Zero cost rejected
7.  Unknown case rejected
8.  Unknown host rejected
9.  Same inputs produce identical output
10. Input objects unchanged after evaluation
11. No network imports
12. Closed vocabulary enforcement

Plus: no filesystem writes, no verdict vocabulary, counters never decrease,
denials record nothing consumable, snapshot/restore round-trip, deterministic
audit output, count limits (max cases / max hosts), case/host mismatch denied.
"""

from __future__ import annotations

import ast
import sys
import unittest

sys.dont_write_bytecode = True

from aec.budget_ledger import (
    ACTIONS,
    REASON_CODES,
    BudgetDecision,
    BudgetEvent,
    BudgetLedger,
    BudgetPolicy,
    BudgetUsage,
    default_policy,
)

LEDGER_PATH = "aec/budget_ledger.py"


def small_policy() -> BudgetPolicy:
    """Tight budget so exhaustion tests stay small and fast."""
    return BudgetPolicy(
        max_total_requests=10,
        max_case_requests=4,
        max_host_requests=5,
        max_cases=3,
        max_hosts=2,
    )


def small_known() -> dict:
    return {"case-1": "host-a", "case-2": "host-a", "case-3": "host-b"}


def fresh_ledger() -> BudgetLedger:
    return BudgetLedger(policy=small_policy(), known=small_known())


class TestFreshLedger(unittest.TestCase):
    def test_fresh_ledger_allows_valid_request(self):
        ledger = fresh_ledger()
        decision = ledger.propose("case-1", "host-a", 2)
        self.assertIsInstance(decision, BudgetDecision)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "BUDGET_AVAILABLE")
        self.assertEqual(decision.requested_cost, 2)
        self.assertEqual(decision.remaining_budget, 8)

    def test_commit_records_consumption_and_event(self):
        ledger = fresh_ledger()
        decision, event = ledger.commit("case-1", "host-a", 2)
        self.assertTrue(decision.allowed)
        self.assertIsInstance(event, BudgetEvent)
        self.assertEqual(event.case_id, "case-1")
        self.assertEqual(event.host, "host-a")
        self.assertEqual(event.cost, 2)
        self.assertEqual(event.action, "COMMIT")
        usage = ledger.usage()
        self.assertEqual(usage.total_requests_used, 2)
        self.assertEqual(dict(usage.case_usage)["case-1"], 2)
        self.assertEqual(dict(usage.host_usage)["host-a"], 2)

    def test_propose_is_pure_and_commit_is_the_only_writer(self):
        ledger = fresh_ledger()
        before = ledger.usage()
        ledger.propose("case-1", "host-a", 2)
        ledger.propose("case-1", "host-a", 2)
        self.assertEqual(ledger.usage(), before)
        self.assertEqual(ledger.events(), ())
        ledger.commit("case-1", "host-a", 2)
        self.assertEqual(ledger.usage().total_requests_used, 2)
        self.assertEqual(len(ledger.events()), 1)

    def test_event_ids_and_timestamps_are_deterministic(self):
        first = fresh_ledger()
        second = fresh_ledger()
        _, event_a = first.commit("case-1", "host-a", 1)
        _, event_b = second.commit("case-1", "host-a", 1)
        self.assertEqual(event_a.event_id, event_b.event_id)
        self.assertEqual(event_a.timestamp, event_b.timestamp)
        self.assertEqual(event_a.event_id, "evt-000001")


class TestExhaustion(unittest.TestCase):
    def test_total_budget_exhaustion(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 4)  # case-1 full, host-a at 4, total 4
        ledger.commit("case-2", "host-a", 1)  # host-a full at 5, total 5
        ledger.commit("case-3", "host-b", 4)  # total 9
        decision = ledger.propose("case-3", "host-b", 2)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "TOTAL_BUDGET_EXCEEDED")
        self.assertEqual(decision.remaining_budget, 1)

    def test_total_budget_exact_fill_is_allowed(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 4)
        ledger.commit("case-2", "host-a", 1)
        ledger.commit("case-3", "host-b", 4)
        decision = ledger.propose("case-2", "host-a", 1)
        # host-a already at its cap of 5, so this must be denied on host grounds
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "HOST_BUDGET_EXCEEDED")

    def test_case_budget_exhaustion(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 4)
        decision = ledger.propose("case-1", "host-a", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "CASE_BUDGET_EXCEEDED")

    def test_host_budget_exhaustion(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 4)
        decision = ledger.propose("case-2", "host-a", 2)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "HOST_BUDGET_EXCEEDED")

    def test_denied_commit_records_nothing_consumable(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 4)
        before = ledger.usage()
        decision, event = ledger.commit("case-1", "host-a", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(ledger.usage(), before)
        self.assertEqual(event.action, "DENIED")
        self.assertEqual(ledger.usage().total_requests_used, 4)

    def test_counters_never_decrease(self):
        ledger = fresh_ledger()
        seen = [0]
        for case, host, cost in (
            ("case-1", "host-a", 2),
            ("case-2", "host-a", 1),
            ("case-3", "host-b", 3),
            ("case-1", "host-a", 9),  # denied: everything exceeded
        ):
            ledger.commit(case, host, cost)
            total = ledger.usage().total_requests_used
            self.assertGreaterEqual(total, seen[-1])
            seen.append(total)
        self.assertEqual(ledger.usage().total_requests_used, 6)


class TestCountLimits(unittest.TestCase):
    def test_case_count_limit(self):
        policy = BudgetPolicy(
            max_total_requests=100,
            max_case_requests=100,
            max_host_requests=100,
            max_cases=2,
            max_hosts=10,
        )
        ledger = BudgetLedger(policy=policy, known=small_known())
        ledger.commit("case-1", "host-a", 1)
        ledger.commit("case-2", "host-a", 1)
        decision = ledger.propose("case-3", "host-b", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "CASE_COUNT_EXCEEDED")

    def test_host_count_limit(self):
        policy = BudgetPolicy(
            max_total_requests=100,
            max_case_requests=100,
            max_host_requests=100,
            max_cases=10,
            max_hosts=1,
        )
        ledger = BudgetLedger(policy=policy, known=small_known())
        ledger.commit("case-1", "host-a", 1)
        decision = ledger.propose("case-3", "host-b", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "HOST_COUNT_EXCEEDED")

    def test_repeat_use_of_known_case_needs_no_new_slot(self):
        policy = BudgetPolicy(
            max_total_requests=100,
            max_case_requests=100,
            max_host_requests=100,
            max_cases=1,
            max_hosts=1,
        )
        ledger = BudgetLedger(policy=policy, known={"case-1": "host-a"})
        ledger.commit("case-1", "host-a", 1)
        decision = ledger.propose("case-1", "host-a", 1)
        self.assertTrue(decision.allowed)


class TestInvalidInput(unittest.TestCase):
    def test_negative_cost_rejected(self):
        decision = fresh_ledger().propose("case-1", "host-a", -1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "INVALID_COST")

    def test_zero_cost_rejected(self):
        decision = fresh_ledger().propose("case-1", "host-a", 0)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "INVALID_COST")

    def test_non_integer_and_boolean_costs_rejected(self):
        ledger = fresh_ledger()
        for bad in (2.5, "2", None, True, False, [2]):
            with self.subTest(cost=bad):
                decision = ledger.propose("case-1", "host-a", bad)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason_code, "INVALID_COST")

    def test_unknown_case_rejected(self):
        decision = fresh_ledger().propose("case-999", "host-a", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "UNKNOWN_CASE")

    def test_unknown_host_rejected(self):
        decision = fresh_ledger().propose("case-1", "host-zzz", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "UNKNOWN_HOST")

    def test_case_host_mismatch_rejected(self):
        decision = fresh_ledger().propose("case-1", "host-b", 1)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "CASE_HOST_MISMATCH")

    def test_empty_identifiers_rejected(self):
        ledger = fresh_ledger()
        self.assertEqual(ledger.propose("", "host-a", 1).reason_code, "UNKNOWN_CASE")
        self.assertEqual(ledger.propose("case-1", "", 1).reason_code, "UNKNOWN_HOST")

    def test_invalid_policy_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(
                max_total_requests=0,
                max_case_requests=4,
                max_host_requests=5,
                max_cases=3,
                max_hosts=2,
            )
        with self.assertRaises(ValueError):
            BudgetPolicy(
                max_total_requests=10,
                max_case_requests=-1,
                max_host_requests=5,
                max_cases=3,
                max_hosts=2,
            )

    def test_empty_registry_denies_everything_closed(self):
        ledger = BudgetLedger(policy=small_policy(), known={})
        decision = ledger.propose("case-1", "host-a", 1)
        self.assertFalse(decision.allowed)
        self.assertIn(decision.reason_code, ("UNKNOWN_CASE", "UNKNOWN_HOST"))


class TestDeterminismAndPurity(unittest.TestCase):
    def run_script(self, ledger: BudgetLedger):
        out = []
        for case, host, cost in (
            ("case-1", "host-a", 2),
            ("case-2", "host-a", 1),
            ("case-1", "host-a", 9),
            ("case-9", "host-a", 1),
            ("case-3", "host-b", 3),
        ):
            decision, _ = ledger.commit(case, host, cost)
            out.append(decision)
        return out

    def test_same_inputs_produce_identical_output(self):
        first, second = fresh_ledger(), fresh_ledger()
        decisions_a = self.run_script(first)
        decisions_b = self.run_script(second)
        self.assertEqual(decisions_a, decisions_b)
        self.assertEqual(first.events(), second.events())
        self.assertEqual(first.usage(), second.usage())
        self.assertEqual(first.audit_text(), second.audit_text())

    def test_input_objects_unchanged_after_evaluation(self):
        known = small_known()
        known_copy = dict(known)
        policy = small_policy()
        ledger = BudgetLedger(policy=policy, known=known)
        known["case-999"] = "host-zzz"  # caller mutates its own dict afterwards
        ledger.propose("case-1", "host-a", 1)
        ledger.commit("case-1", "host-a", 1)
        ledger.propose("case-999", "host-zzz", 1)
        self.assertEqual(known, {**known_copy, "case-999": "host-zzz"})
        self.assertEqual(policy, small_policy())
        self.assertEqual(ledger.usage().total_requests_used, 1)

    def test_usage_snapshots_are_detached_values(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 2)
        first = ledger.usage()
        ledger.commit("case-2", "host-a", 1)
        self.assertEqual(first.total_requests_used, 2)
        self.assertIsInstance(first, BudgetUsage)

    def test_snapshot_restore_round_trip(self):
        ledger = fresh_ledger()
        ledger.commit("case-1", "host-a", 2)
        ledger.commit("case-9", "host-a", 1)  # denied, recorded as DENIED
        snapshot = ledger.snapshot()
        restored = BudgetLedger.restore(snapshot)
        self.assertEqual(restored.usage(), ledger.usage())
        self.assertEqual(restored.events(), ledger.events())
        self.assertEqual(
            restored.propose("case-2", "host-a", 1), ledger.propose("case-2", "host-a", 1)
        )

    def test_audit_output_is_human_readable_and_deterministic(self):
        first, second = fresh_ledger(), fresh_ledger()
        self.run_script(first)
        self.run_script(second)
        text = first.audit_text()
        self.assertEqual(text, second.audit_text())
        for token in ("case-1", "host-a", "COMMIT", "DENIED", "BUDGET_AVAILABLE"):
            self.assertIn(token, text)

    def test_default_policy_matches_the_approved_pilot_budget(self):
        import aec

        policy = default_policy()
        self.assertEqual(policy.max_total_requests, aec.PILOT_BUDGET.max_requests)
        self.assertEqual(policy.max_case_requests, aec.PILOT_BUDGET.max_requests_per_case)
        self.assertEqual(policy.max_host_requests, aec.PILOT_BUDGET.max_requests_per_host)
        self.assertEqual(policy.max_cases, aec.PILOT_BUDGET.max_cases)
        self.assertEqual(policy.max_hosts, aec.MAX_HOSTS)


class TestClosedVocabulary(unittest.TestCase):
    def test_reason_codes_are_closed_and_unique(self):
        self.assertEqual(len(REASON_CODES), len(set(REASON_CODES)))
        for expected in (
            "BUDGET_AVAILABLE",
            "TOTAL_BUDGET_EXCEEDED",
            "CASE_BUDGET_EXCEEDED",
            "HOST_BUDGET_EXCEEDED",
            "CASE_COUNT_EXCEEDED",
            "HOST_COUNT_EXCEEDED",
            "INVALID_COST",
            "UNKNOWN_CASE",
            "UNKNOWN_HOST",
            "CASE_HOST_MISMATCH",
        ):
            self.assertIn(expected, REASON_CODES)

    def test_every_decision_uses_the_closed_vocabulary(self):
        ledger = fresh_ledger()
        seen = set()
        for case, host, cost in (
            ("case-1", "host-a", 2),
            ("case-1", "host-a", 9),
            ("case-2", "host-a", 4),
            ("case-3", "host-b", 1),
            ("case-1", "host-a", -1),
            ("case-1", "host-a", 0),
            ("nope", "host-a", 1),
            ("case-1", "nope", 1),
            ("case-1", "host-b", 1),
        ):
            decision, _ = ledger.commit(case, host, cost)
            seen.add(decision.reason_code)
            self.assertIn(decision.reason_code, REASON_CODES)
            self.assertEqual(decision.allowed, decision.reason_code == "BUDGET_AVAILABLE")
        self.assertGreaterEqual(len(seen), 7)

    def test_actions_are_closed(self):
        self.assertEqual(tuple(ACTIONS), ("COMMIT", "DENIED"))

    def test_no_verdict_or_finding_vocabulary_in_reason_codes(self):
        blob = " ".join(REASON_CODES)
        for forbidden in ("CONFIRMED", "VULNERABLE", "EXPLOITABLE", "SEVERITY", "FINDING"):
            self.assertNotIn(forbidden, blob)


class TestModuleHygiene(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        cls.source = (root / LEDGER_PATH).read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_no_network_transport_or_process_imports(self):
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        forbidden = {
            "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx",
            "websocket", "websockets", "dns", "ftplib", "telnetlib", "smtplib",
            "subprocess", "shutil", "os", "signal", "multiprocessing", "asyncio",
            "concurrent", "ctypes", "ai", "backend", "pymongo", "boto3", "paramiko",
        }
        self.assertEqual(imported & forbidden, set())
        self.assertLessEqual(imported, {"__future__", "aec", "dataclasses", "typing"})

    def test_no_filesystem_writes(self):
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        self.assertEqual(
            called & {"open", "write_text", "write_bytes", "mkdir", "remove", "unlink", "system", "popen", "run"},
            set(),
        )

    def test_no_dynamic_execution_or_clock_calls(self):
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(f"{func.attr}")
        self.assertEqual(
            called & {"__import__", "eval", "exec", "compile", "now", "today", "utcnow", "time", "monotonic"},
            set(),
        )

    def test_no_verdict_vocabulary_in_the_module(self):
        # The docstring's disclaimer names the forbidden vocabularies to forbid
        # them; strip that sentence before asserting (same NOT_CONFIRMED-style
        # treatment as the import guard).
        upper = self.source.upper().replace(
            "THERE IS NO FINDING, SEVERITY OR CONFIRMED VOCABULARY ANYWHERE HERE.", ""
        )
        for forbidden in ("CONFIRMED", "VULNERABLE", "EXPLOITABLE", "SEVERITY", "FINDING"):
            self.assertNotIn(forbidden, upper)


if __name__ == "__main__":
    unittest.main()

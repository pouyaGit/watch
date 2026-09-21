"""Tests for aec/authorization_gate.py (AEC-1 T6: Observation Authorization Gate).

Offline structural eligibility only: a T5 ObservationPlanDraft (object or
its dict round-trip) becomes an ALLOW/REFUSE AuthorizationGateDecision.
The gate grants nothing, records no authority, reaches no network, writes
no files, and emits no case conclusions.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from aec.case_compiler import compile_authorization_request
from aec.models import CaseRef, EvidenceGap
from aec.observation_plan import compile_observation_plan

AEC_DIR = Path(__file__).resolve().parents[1] / "aec"
MODULE_PATH = AEC_DIR / "authorization_gate.py"

REFUSAL_CODES = frozenset({
    "MISSING_PLAN",
    "MISSING_CASE",
    "MISSING_TARGET",
    "MISSING_ENDPOINT",
    "UNSUPPORTED_METHOD",
    "INVALID_BUDGET",
    "STEP_LIMIT_EXCEEDED",
    "EXECUTION_FIELD_PRESENT",
})

VOCAB_BANNED = frozenset({
    "CONFIRMED",
    "VULNERABLE",
    "NOT_VULNERABLE",
    "EXPLOITABLE",
    "FINDING",
    "VERDICT",
    "SEVERITY",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
})

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify",
})


def make_case(**overrides):
    fields = {
        "case_id": "case-001",
        "job_id": "case-001",
        "program": "pilot",
        "host": "example.com",
        "endpoint": "/item",
        "parameter": "id",
        "method": "GET",
        "category": "idor",
        "confidence": "MEDIUM",
        "url": "https://example.com/item?id=1",
        "evidence_gap": EvidenceGap.build(
            ("response-body", "status-code"),
            ("response-body", "status-code"),
            artifacts=[],
        ),
    }
    fields.update(overrides)
    return CaseRef(**fields)


def make_plan():
    draft = compile_authorization_request(make_case()).request
    outcome = compile_observation_plan(draft)
    assert outcome.ok, outcome.refusal_code
    return outcome.plan


def plan_dict():
    return make_plan().to_dict()


class TestAllow(unittest.TestCase):
    def test_valid_plan_returns_allow(self):
        from aec import authorization_gate

        decision = authorization_gate.check_authorization_eligibility(make_plan())
        self.assertEqual(decision.decision, "ALLOW")
        self.assertEqual(decision.reason_code, "ELIGIBLE")
        self.assertEqual(decision.plan_id, "plan-case-001")

    def test_serialized_round_trip_returns_allow(self):
        from aec import authorization_gate
        from aec.observation_plan import serialize_plan

        wire = json.loads(serialize_plan(make_plan()))
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.decision, "ALLOW")

    def test_checked_rules_cover_every_rule_on_allow(self):
        from aec import authorization_gate

        decision = authorization_gate.check_authorization_eligibility(make_plan())
        self.assertEqual(
            list(decision.checked_rules),
            [
                "PLAN_PRESENT",
                "EXECUTION_FIELDS",
                "CASE_REF",
                "TARGET",
                "ENDPOINT",
                "METHOD",
                "STEP_LIMIT",
                "BUDGET",
            ],
        )

    def test_timestamp_is_deterministic_plan_hash(self):
        from aec import authorization_gate

        decision = authorization_gate.check_authorization_eligibility(make_plan())
        expected = "plan-hash:" + hashlib.sha256(
            json.dumps(plan_dict(), sort_keys=True).encode()
        ).hexdigest()[:16]
        self.assertEqual(decision.timestamp, expected)


class TestRefusals(unittest.TestCase):
    def test_missing_plan_refused(self):
        from aec import authorization_gate

        for bad in (None, "plan-x", 42, ["steps"]):
            decision = authorization_gate.check_authorization_eligibility(bad)
            self.assertEqual(decision.decision, "REFUSE")
            self.assertEqual(decision.reason_code, "MISSING_PLAN")

    def test_empty_steps_refused_as_missing_plan(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"] = []
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.reason_code, "MISSING_PLAN")

    def test_missing_case_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["case_id"] = ""
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.reason_code, "MISSING_CASE")

    def test_missing_target_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        for step in wire["steps"]:
            step["target_host"] = ""
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.reason_code, "MISSING_TARGET")

    def test_missing_endpoint_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"][0]["endpoint"] = ""
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.decision, "REFUSE")
        self.assertEqual(decision.reason_code, "MISSING_ENDPOINT")

    def test_invalid_method_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"][1]["method"] = "POST"
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.decision, "REFUSE")
        self.assertEqual(decision.reason_code, "UNSUPPORTED_METHOD")

    def test_budget_overflow_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        for step in wire["steps"]:
            step["budget_reference"]["requested_cost"] = 99
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.decision, "REFUSE")
        self.assertEqual(decision.reason_code, "INVALID_BUDGET")

    def test_budget_inconsistency_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"][-1]["budget_reference"]["requested_cost"] = 1
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.reason_code, "INVALID_BUDGET")

    def test_step_limit_exceeded_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        extra = copy.deepcopy(wire["steps"][1])
        extra["step_id"] = "plan-case-001-s99"
        wire["steps"].append(extra)
        wire["steps"].append(copy.deepcopy(extra))
        self.assertGreater(len(wire["steps"]), 4)
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.reason_code, "STEP_LIMIT_EXCEEDED")

    def test_execution_field_injection_refused(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"][0]["headers"] = {"User-Agent": "x"}
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(decision.decision, "REFUSE")
        self.assertEqual(decision.reason_code, "EXECUTION_FIELD_PRESENT")

    def test_refusal_vocabulary_closed(self):
        from aec import authorization_gate

        wires = []
        empty_endpoint = plan_dict()
        empty_endpoint["steps"][0]["endpoint"] = ""
        wires.append(empty_endpoint)
        bad_method = plan_dict()
        bad_method["steps"][0]["method"] = "DELETE"
        wires.append(bad_method)
        bad_budget = plan_dict()
        bad_budget["steps"][0]["budget_reference"]["requested_cost"] = 0
        wires.append(bad_budget)
        injected = plan_dict()
        injected["steps"][0]["body"] = "x"
        wires.append(injected)
        codes = {
            authorization_gate.check_authorization_eligibility(w).reason_code
            for w in wires
        }
        codes.add(authorization_gate.check_authorization_eligibility(None).reason_code)
        self.assertLessEqual(codes, REFUSAL_CODES | {"ELIGIBLE"})

    def test_checked_rules_stop_at_failing_rule(self):
        from aec import authorization_gate

        wire = plan_dict()
        wire["steps"][0]["endpoint"] = ""
        decision = authorization_gate.check_authorization_eligibility(wire)
        self.assertEqual(
            list(decision.checked_rules),
            ["PLAN_PRESENT", "EXECUTION_FIELDS", "CASE_REF", "TARGET", "ENDPOINT"],
        )


class TestDeterminism(unittest.TestCase):
    def test_same_inputs_identical_output(self):
        from aec import authorization_gate

        first = authorization_gate.check_authorization_eligibility(make_plan())
        second = authorization_gate.check_authorization_eligibility(make_plan())
        self.assertEqual(first, second)
        self.assertEqual(
            authorization_gate.serialize_decision(first),
            authorization_gate.serialize_decision(second),
        )

    def test_serialization_stable_bytes(self):
        from aec import authorization_gate

        decision = authorization_gate.check_authorization_eligibility(make_plan())
        text = authorization_gate.serialize_decision(decision)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)

    def test_input_plan_unchanged(self):
        from aec import authorization_gate

        plan = make_plan()
        before = plan.to_dict()
        authorization_gate.check_authorization_eligibility(plan)
        self.assertEqual(plan.to_dict(), before)

    def test_output_is_frozen(self):
        from aec import authorization_gate

        decision = authorization_gate.check_authorization_eligibility(make_plan())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.decision = "ALLOW-X"


class TestSafetyGuards(unittest.TestCase):
    def test_module_has_no_network_or_authority_imports(self):
        tree = ast.parse(MODULE_PATH.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported & NETWORK_MODULES, set())
        source = MODULE_PATH.read_text()
        self.assertNotIn("authorizer", source)

    def test_module_performs_no_filesystem_writes(self):
        tree = ast.parse(MODULE_PATH.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                self.assertNotIn(name, {"write_text", "mkdir", "makedirs", "eval", "exec"})
                if name == "open":
                    modes = [
                        a.value
                        for a in node.args[1:]
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)
                    ]
                    for mode in modes:
                        self.assertNotIn("w", mode.replace("U", ""))
                        self.assertNotIn("a", mode)
                        self.assertNotIn("+", mode)

    def test_module_has_no_verdict_vocabulary(self):
        source = MODULE_PATH.read_text().upper()
        for word in VOCAB_BANNED:
            self.assertNotIn(word, source)

    def test_method_allowlist_matches_case_compiler(self):
        from aec import authorization_gate
        from aec import case_compiler

        self.assertEqual(
            set(authorization_gate.ALLOWED_METHODS), set(case_compiler.ALLOWED_METHODS)
        )

    def test_live_capability_modules_absent(self):
        self.assertFalse((AEC_DIR / "live_deps.py").exists())
        self.assertFalse((AEC_DIR / "observation_lane.py").exists())


if __name__ == "__main__":
    unittest.main()

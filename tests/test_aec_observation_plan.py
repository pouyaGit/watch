"""Tests for aec/observation_plan.py (AEC-1 T5: Observation Plan Compiler).

Offline planning only: an AuthorizationRequestDraft (T4 output) becomes an
ordered ObservationPlanDraft of BASELINE/COMPARISON/CONTEXT_CAPTURE steps
with exactly one varying variable per pair. No payloads, no execution
instructions, no verdicts, no network, no filesystem writes.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.dont_write_bytecode = True

from aec.case_compiler import AuthorizationRequestDraft, compile_authorization_request
from aec.models import CaseRef, EvidenceGap

AEC_DIR = Path(__file__).resolve().parents[1] / "aec"
MODULE_PATH = AEC_DIR / "observation_plan.py"

REFUSAL_CODES = frozenset({
    "INVALID_REQUEST",
    "MISSING_HOST",
    "MISSING_ENDPOINT",
    "MISSING_GAP",
    "UNSUPPORTED_METHOD",
    "NON_DETERMINISTIC_INPUT",
})

PURPOSES = frozenset({"BASELINE", "COMPARISON", "CONTEXT_CAPTURE"})

VERDICT_WORDS = frozenset({
    "CONFIRMED",
    "VULNERABLE",
    "NOT_VULNERABLE",
    "EXPLOITABLE",
    "FINDING",
    "VERDICT",
    "SEVERITY",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "PAYLOAD",
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


def make_draft(**overrides):
    outcome = compile_authorization_request(make_case())
    assert outcome.ok, outcome.refusal_code
    draft = outcome.request
    if overrides:
        draft = replace(draft, **overrides)
    return draft


class TestPlanValid(unittest.TestCase):
    def test_valid_draft_plans(self):
        from aec import observation_plan

        outcome = observation_plan.compile_observation_plan(make_draft())
        self.assertTrue(outcome.ok, outcome.refusal_code)
        self.assertIsNone(outcome.refusal_code)
        plan = outcome.plan
        self.assertEqual(plan.case_id, "case-001")
        self.assertGreaterEqual(len(plan.steps), 2)

    def test_step_shape_complete(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        for step in plan.steps:
            self.assertTrue(step.step_id)
            self.assertIn(step.purpose, PURPOSES)
            self.assertEqual(step.target_host, "example.com")
            self.assertEqual(step.endpoint, "/item")
            self.assertIn(step.method, ("GET", "HEAD"))
            self.assertTrue(step.expected_artifact_type)
            self.assertEqual(step.budget_reference.case_id, "case-001")

    def test_purpose_ordering(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        purposes = [s.purpose for s in plan.steps]
        self.assertEqual(purposes[0], "BASELINE")
        self.assertEqual(purposes[-1], "CONTEXT_CAPTURE")
        self.assertIn("COMPARISON", purposes)

    def test_step_ids_deterministic_format(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        self.assertEqual(
            [s.step_id for s in plan.steps],
            [f"plan-case-001-s{i:02d}" for i in range(1, len(plan.steps) + 1)],
        )

    def test_step_cap(self):
        from aec import observation_plan

        gap = EvidenceGap.build(
            ("a", "b", "c", "d", "e", "f"), ("a", "b", "c", "d", "e", "f"),
            artifacts=[],
        )
        draft = make_draft()
        draft = replace(draft, evidence_gap=gap.to_dict())
        plan = observation_plan.compile_observation_plan(draft).plan
        self.assertLessEqual(len(plan.steps), 4)

    def test_budget_cost_matches_steps(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        for step in plan.steps:
            self.assertEqual(step.budget_reference.requested_cost, len(plan.steps))


class TestRefusals(unittest.TestCase):
    def test_invalid_request_types_refused(self):
        from aec import observation_plan

        for bad in (None, "plan-x", 42, {"case_id": "case-001"}):
            outcome = observation_plan.compile_observation_plan(bad)
            self.assertFalse(outcome.ok)
            self.assertEqual(outcome.refusal_code, "INVALID_REQUEST")
            self.assertIsNone(outcome.plan)

    def test_missing_endpoint_refused(self):
        from aec import observation_plan

        outcome = observation_plan.compile_observation_plan(
            make_draft(endpoint=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_ENDPOINT")

    def test_missing_gap_refused(self):
        from aec import observation_plan

        outcome = observation_plan.compile_observation_plan(
            make_draft(evidence_gap={}))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_GAP")

    def test_unsupported_method_refused(self):
        from aec import observation_plan

        outcome = observation_plan.compile_observation_plan(
            make_draft(method="POST"))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "UNSUPPORTED_METHOD")

    def test_nondeterministic_input_refused(self):
        from aec import observation_plan

        draft = make_draft(evidence_gap={"missing": ["a", 42], "required": ["a"]})
        outcome = observation_plan.compile_observation_plan(draft)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "NON_DETERMINISTIC_INPUT")

    def test_refusal_vocabulary_closed(self):
        from aec import observation_plan

        probes = [
            None,
            make_draft(endpoint=""),
            make_draft(evidence_gap={}),
            make_draft(method="DELETE"),
            make_draft(evidence_gap={"missing": [None], "required": []}),
        ]
        codes = {observation_plan.compile_observation_plan(p).refusal_code for p in probes}
        self.assertTrue(codes)
        self.assertLessEqual(codes, REFUSAL_CODES)


class TestInvariants(unittest.TestCase):
    def test_one_varying_variable_per_pair(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        baseline = plan.steps[0]
        self.assertEqual(baseline.purpose, "BASELINE")
        self.assertIsNone(baseline.single_variable_change)
        for step in plan.steps[1:]:
            if step.purpose != "COMPARISON":
                continue
            self.assertEqual(dict(step.fixed_variables), dict(baseline.fixed_variables))
            change = step.single_variable_change
            self.assertIsNotNone(change)
            name, _role = change
            self.assertIn(name, dict(baseline.fixed_variables))

    def test_no_concrete_alternate_values(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        text = json.dumps([s.to_dict() for s in plan.steps])
        self.assertNotIn("example.com/item?", text)
        for step in plan.steps:
            if step.single_variable_change is not None:
                _name, role = step.single_variable_change
                self.assertEqual(role, "ALTERNATE")

    def test_same_inputs_identical_output(self):
        from aec import observation_plan

        first = observation_plan.compile_observation_plan(make_draft())
        second = observation_plan.compile_observation_plan(make_draft())
        self.assertEqual(first, second)
        self.assertEqual(
            observation_plan.serialize_plan(first.plan),
            observation_plan.serialize_plan(second.plan),
        )

    def test_serialization_stable_bytes(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        text = observation_plan.serialize_plan(plan)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)

    def test_input_draft_unchanged(self):
        from aec import observation_plan

        draft = make_draft()
        before = draft.to_dict()
        observation_plan.compile_observation_plan(draft)
        self.assertEqual(draft.to_dict(), before)

    def test_output_is_frozen(self):
        from aec import observation_plan

        plan = observation_plan.compile_observation_plan(make_draft()).plan
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.steps[0].purpose = "BASELINE-X"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.plan_id = "mutated"


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
                if isinstance(node.func, ast.Name):
                    name = func.id
                elif isinstance(node.func, ast.Attribute):
                    name = func.attr
                self.assertNotIn(name, {"write_text", "mkdir", "makedirs"})
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

    def test_module_has_no_verdict_or_payload_vocabulary(self):
        source = MODULE_PATH.read_text().upper()
        for word in VERDICT_WORDS:
            self.assertNotIn(word, source)

    def test_method_allowlist_matches_case_compiler(self):
        from aec import case_compiler
        from aec import observation_plan

        self.assertEqual(
            set(observation_plan.ALLOWED_METHODS), set(case_compiler.ALLOWED_METHODS)
        )

    def test_live_capability_modules_absent(self):
        self.assertFalse((AEC_DIR / "live_deps.py").exists())
        self.assertFalse((AEC_DIR / "observation_lane.py").exists())


if __name__ == "__main__":
    unittest.main()

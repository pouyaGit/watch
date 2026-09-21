"""Tests for aec/case_compiler.py (AEC-1 T4: Authorization Request Compiler).

The compiler converts a selected T1 pilot case into a deterministic
AuthorizationRequest *draft* plus a human approval sheet. It drafts only:
no authority, no contact, no verdicts, no network, no filesystem writes.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from aec.models import CaseRef, EvidenceGap, SelectionDecision

AEC_DIR = Path(__file__).resolve().parents[1] / "aec"
MODULE_PATH = AEC_DIR / "case_compiler.py"

REFUSAL_CODES = frozenset({
    "INVALID_INPUT",
    "NOT_SELECTED",
    "INVALID_CASE_ID",
    "MISSING_HOST",
    "MISSING_ENDPOINT",
    "MISSING_EVIDENCE_GAP",
    "GAP_COMPLETE",
    "UNSUPPORTED_METHOD",
})

# Words that would turn a draft into a claim. The module must never emit
# them (its own disclaimer sentence is stripped before the scan, mirroring
# the T2/T3 verdict-vocabulary tests).
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
})

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify",
})


def make_gap(missing=("response-body",), required=("response-body", "status-code")):
    return EvidenceGap.build(required, missing, artifacts=[])


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
        "evidence_gap": make_gap(),
    }
    fields.update(overrides)
    return CaseRef(**fields)


def make_decision(case=None, order=1, decision="SELECTED"):
    return SelectionDecision(case=case or make_case(), decision=decision, order=order)


class TestCompileValid(unittest.TestCase):
    def test_valid_case_compiles(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        self.assertTrue(outcome.ok)
        self.assertIsNone(outcome.refusal_code)
        request = outcome.request
        self.assertEqual(request.case_id, "case-001")
        self.assertEqual(request.host, "example.com")
        self.assertEqual(request.endpoint, "/item")

    def test_selected_decision_compiles(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_decision())
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.request.case_id, "case-001")

    def test_gap_snapshot_carried(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        gap = outcome.request.evidence_gap
        self.assertEqual(tuple(gap["missing"]), ("response-body",))
        self.assertIn("response-body", gap["required"])

    def test_purpose_present_and_deterministic(self):
        from aec import case_compiler

        first = case_compiler.compile_authorization_request(make_case())
        second = case_compiler.compile_authorization_request(make_case())
        self.assertTrue(first.request.purpose_code)
        self.assertEqual(first.request.purpose_code, second.request.purpose_code)
        self.assertEqual(first.request.purpose_detail, second.request.purpose_detail)

    def test_budget_reference_present(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        ref = outcome.request.budget_ref
        self.assertEqual(ref.case_id, "case-001")
        self.assertEqual(ref.host, "example.com")
        self.assertGreaterEqual(ref.requested_cost, 1)
        self.assertTrue(ref.policy)
        self.assertEqual(ref.to_dict()["case_id"], "case-001")


class TestRefusals(unittest.TestCase):
    def test_invalid_input_types_refused(self):
        from aec import case_compiler

        for bad in (None, "case-001", 42, {"case_id": "case-001"}, ["x"]):
            outcome = case_compiler.compile_authorization_request(bad)
            self.assertFalse(outcome.ok, f"input {bad!r} must be refused")
            self.assertEqual(outcome.refusal_code, "INVALID_INPUT")
            self.assertIsNone(outcome.request)

    def test_excluded_decision_refused(self):
        from aec import case_compiler

        decision = make_decision(order=0, decision="LOGIN_ENDPOINT")
        outcome = case_compiler.compile_authorization_request(decision)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "NOT_SELECTED")

    def test_missing_case_id_refused(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case(case_id=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_CASE_ID")

    def test_missing_host_refused(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case(host=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_HOST")

    def test_missing_endpoint_refused(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case(endpoint=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_ENDPOINT")

    def test_missing_gap_refused(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(
            make_case(evidence_gap=None)
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_EVIDENCE_GAP")

    def test_complete_gap_refused(self):
        from aec import case_compiler
        from aec.models import EvidenceGap

        # A gap that states requirements AND shows them held: nothing to ask.
        # (Note: EvidenceGap.build(required, ()) deliberately treats absent
        # missing_evidence as all-missing — absence is never read as held.)
        gap = EvidenceGap(
            required=("status-code",),
            missing=(),
            not_listed_missing=(),
            artifacts_collected=("status-code",),
            artifacts_missing=(),
        )
        outcome = case_compiler.compile_authorization_request(make_case(evidence_gap=gap))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "GAP_COMPLETE")

    def test_unsupported_method_refused(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case(method="POST"))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "UNSUPPORTED_METHOD")

    def test_refusal_vocabulary_closed(self):
        from aec import case_compiler

        probes = [
            None,
            make_decision(order=0, decision="LOGIN_ENDPOINT"),
            make_case(case_id=""),
            make_case(host=""),
            make_case(endpoint=""),
            make_case(evidence_gap=None),
            make_case(method="DELETE"),
        ]
        codes = {case_compiler.compile_authorization_request(p).refusal_code for p in probes}
        self.assertTrue(codes)
        self.assertLessEqual(codes, REFUSAL_CODES)


class TestDeterminism(unittest.TestCase):
    def test_same_inputs_identical_output(self):
        from aec import case_compiler

        first = case_compiler.compile_authorization_request(make_case())
        second = case_compiler.compile_authorization_request(make_case())
        self.assertEqual(first, second)
        self.assertEqual(
            case_compiler.serialize_request(first.request),
            case_compiler.serialize_request(second.request),
        )

    def test_serialization_stable_bytes(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        text = case_compiler.serialize_request(outcome.request)
        parsed = json.loads(text)
        self.assertEqual(json.dumps(parsed, sort_keys=True), text)
        self.assertEqual(json.loads(text), outcome.request.to_dict())

    def test_input_objects_unchanged(self):
        from aec import case_compiler

        case = make_case()
        before = case.to_dict()
        case_compiler.compile_authorization_request(case)
        self.assertEqual(case.to_dict(), before)

    def test_output_is_frozen(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.request.case_id = "mutated"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.ok = False


class TestApprovalSheet(unittest.TestCase):
    def test_sheet_contains_request_fields(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        sheet = case_compiler.render_approval_sheet(outcome)
        for token in ("case-001", "example.com", "/item", "response-body"):
            self.assertIn(token, sheet)
        self.assertIn("NOT AN AUTHORIZATION", sheet)

    def test_sheet_for_refusal_states_reason(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case(host=""))
        sheet = case_compiler.render_approval_sheet(outcome)
        self.assertIn("MISSING_HOST", sheet)
        self.assertIn("REFUSED", sheet)
        self.assertNotIn("purpose_code", sheet)

    def test_sheet_has_no_verdict_vocabulary(self):
        from aec import case_compiler

        outcome = case_compiler.compile_authorization_request(make_case())
        sheet = case_compiler.render_approval_sheet(outcome).upper()
        for word in VERDICT_WORDS:
            self.assertNotIn(word, sheet)


class TestSafetyGuards(unittest.TestCase):
    def test_module_has_no_network_or_authority_imports(self):
        tree = ast.parse(MODULE_PATH.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.asname or a.name.split(".")[0] for a in node.names)
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
                self.assertNotIn(name, {"write_text", "mkdir", "makedirs"})
                if name == "open":
                    modes = [
                        a.value
                        for a in node.args[1:]
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)
                    ] + [
                        kw.value.value
                        for kw in node.keywords
                        if kw.arg == "mode"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ]
                    for mode in modes:
                        self.assertNotIn("w", mode.replace("U", ""))
                        self.assertNotIn("a", mode)
                        self.assertNotIn("+", mode)

    def test_module_has_no_verdict_vocabulary(self):
        source = MODULE_PATH.read_text().upper()
        disclaimer = "DRAFT ONLY — NOT AN AUTHORIZATION. NO CONTACT HAS OCCURRED."
        source = source.replace(disclaimer, "")
        for word in VERDICT_WORDS:
            self.assertNotIn(word, source)

    def test_live_capability_modules_absent(self):
        self.assertFalse((AEC_DIR / "live_deps.py").exists())
        self.assertFalse((AEC_DIR / "observation_lane.py").exists())

    def test_method_allowlist_within_frozen_schema(self):
        from aec import case_compiler

        from ai.schemas.execution_authorization import AllowedMethod
        from typing import get_args

        frozen_methods = set(get_args(AllowedMethod))
        self.assertLessEqual(set(case_compiler.ALLOWED_METHODS), frozen_methods)
        self.assertIn("GET", case_compiler.ALLOWED_METHODS)


if __name__ == "__main__":
    unittest.main()

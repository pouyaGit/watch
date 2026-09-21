"""Tests for aec/orchestrator (EPIC 3 Part 1: Case Orchestrator).

Pure lifecycle coordination over the existing T1/T4/T5/T6/evidence
outputs: NEW → SELECTED → PLANNED → AUTHORIZED_PLAN → WAITING_EVIDENCE →
EVIDENCE_READY → REVIEW_REQUIRED, one step at a time, with append-only
audit history. No conclusions about targets, no network, no writes.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from aec.case_compiler import compile_authorization_request
from aec.evidence.state_machine import advance as advance_evidence
from aec.evidence.state_machine import initial_state as initial_gap
from aec.models import CaseRef, EvidenceGap
from aec.observation_plan import compile_observation_plan
from aec.orchestrator.models import STATES

ORCH_DIR = Path(__file__).resolve().parents[1] / "aec" / "orchestrator"
MODULES = ("models.py", "lifecycle.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
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


def make_inputs():
    draft = compile_authorization_request(make_case()).request
    plan = compile_observation_plan(draft).plan
    return draft, plan


class TestIntake(unittest.TestCase):
    def test_intake_creates_new_record(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        self.assertEqual(record.case_id, "case-001")
        self.assertEqual(record.state, "NEW")
        self.assertEqual(record.selection_order, 0)

    def test_intake_rejects_non_cases(self):
        from aec.orchestrator import lifecycle

        for bad in (None, "case-001", {"case_id": "case-001"}):
            with self.assertRaises(TypeError):
                lifecycle.intake(bad)

    def test_intake_rejects_empty_id(self):
        from aec.orchestrator import lifecycle

        with self.assertRaises(ValueError):
            lifecycle.intake(make_case(case_id=""))

    def test_intake_history_starts_with_birth_event(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        self.assertEqual(len(record.history), 1)
        event = record.history[0]
        self.assertEqual((event.seq, event.previous, event.current), (1, "", "NEW"))


class TestSelection(unittest.TestCase):
    def test_select_moves_new_to_selected(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        outcome = lifecycle.mark_selected(record, 3)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "SELECTED")
        self.assertEqual(outcome.record.selection_order, 3)

    def test_select_requires_new(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        selected = lifecycle.mark_selected(record, 1).record
        outcome = lifecycle.mark_selected(selected, 2)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_select_rejects_bad_order(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        for bad in (0, -1, "3", None):
            outcome = lifecycle.mark_selected(record, bad)
            self.assertFalse(outcome.ok)
            self.assertEqual(outcome.refusal_code, "MISSING_INPUT")

    def test_select_rejects_non_records(self):
        from aec.orchestrator import lifecycle

        outcome = lifecycle.mark_selected("not-a-record", 1)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_RECORD")


class TestPlanning(unittest.TestCase):
    def test_attach_plan_moves_selected_to_planned(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        outcome = lifecycle.attach_plan(record, plan)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "PLANNED")
        self.assertEqual(outcome.record.plan_id, plan.plan_id)

    def test_attach_plan_accepts_dict_round_trip(self):
        from aec.orchestrator import lifecycle
        from aec.observation_plan import serialize_plan

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        wire = json.loads(serialize_plan(plan))
        outcome = lifecycle.attach_plan(record, wire)
        self.assertTrue(outcome.ok)

    def test_attach_plan_requires_selected(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        outcome = lifecycle.attach_plan(lifecycle.intake(make_case()), plan)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_attach_plan_rejects_foreign_case(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        wire = plan.to_dict()
        wire["case_id"] = "case-999"
        outcome = lifecycle.attach_plan(record, wire)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "STALE_INPUT")

    def test_attach_plan_rejects_garbage(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        for bad in (None, "plan", {"nope": True}):
            outcome = lifecycle.attach_plan(record, bad)
            self.assertFalse(outcome.ok)
            self.assertIn(outcome.refusal_code, {"MISSING_INPUT", "STALE_INPUT"})


class TestAuthorization(unittest.TestCase):
    def test_allow_moves_planned_to_authorized(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        decision = check_authorization_eligibility(plan)
        outcome = lifecycle.record_authorized(planned, decision)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "AUTHORIZED_PLAN")

    def test_refused_gate_cannot_authorize(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        wire = plan.to_dict()
        wire["steps"][0]["endpoint"] = ""
        from aec.authorization_gate import check_authorization_eligibility

        refused = check_authorization_eligibility(wire)
        self.assertEqual(refused.decision, "REFUSE")
        outcome = lifecycle.record_authorized(planned, refused)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_authorize_requires_planned(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        outcome = lifecycle.record_authorized(
            record, check_authorization_eligibility(plan)
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_authorize_rejects_foreign_plan(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        other = make_case(case_id="case-999")
        other_plan = compile_observation_plan(
            compile_authorization_request(other).request
        ).plan
        outcome = lifecycle.record_authorized(
            planned, check_authorization_eligibility(other_plan)
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "STALE_INPUT")


class TestEvidenceRouting(unittest.TestCase):
    def test_evidence_state_flows_into_record(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility
        from aec.evidence import builder

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        authorized = lifecycle.record_authorized(
            planned, check_authorization_eligibility(plan)
        ).record
        artifacts = builder.build_artifacts(plan).artifacts
        gap = advance_evidence(initial_gap("case-001"), artifacts)
        outcome = lifecycle.route_evidence(authorized, gap)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "EVIDENCE_PARTIAL")
        self.assertEqual(outcome.record.evidence_state, "EVIDENCE_PARTIAL")

    def test_route_requires_authorized(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        gap = initial_gap("case-001")
        outcome = lifecycle.route_evidence(planned, gap)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_route_rejects_foreign_gap(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        authorized = lifecycle.record_authorized(
            planned, check_authorization_eligibility(plan)
        ).record
        outcome = lifecycle.route_evidence(authorized, initial_gap("case-999"))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "STALE_INPUT")


class TestReview(unittest.TestCase):
    def test_ready_submits_to_review(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        for hop in ("SELECTED", "PLANNED", "AUTHORIZED_PLAN", "EVIDENCE_READY"):
            record = dataclasses.replace(record, state=hop)
        outcome = lifecycle.submit_review(record, "operator triage")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "REVIEW_REQUIRED")
        self.assertEqual(outcome.record.review_note, "operator triage")

    def test_review_requires_ready(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        outcome = lifecycle.submit_review(record, "too early")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_review_note_is_plain_text(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        record = dataclasses.replace(record, state="EVIDENCE_READY")
        outcome = lifecycle.submit_review(record, "x" * 10)
        self.assertTrue(outcome.ok)


class TestHistoryAndSerialization(unittest.TestCase):
    def test_full_walk_appends_ordered_events(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility
        from aec.evidence import builder

        _draft, plan = make_inputs()
        record = lifecycle.intake(make_case())
        record = lifecycle.mark_selected(record, 2).record
        record = lifecycle.attach_plan(record, plan).record
        record = lifecycle.record_authorized(
            record, check_authorization_eligibility(plan)
        ).record
        artifacts = builder.build_artifacts(plan).artifacts
        gap = advance_evidence(initial_gap("case-001"), artifacts)
        record = lifecycle.route_evidence(record, gap).record
        seqs = [e.seq for e in record.history]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])
        states = [e.current for e in record.history]
        self.assertEqual(
            states,
            ["NEW", "SELECTED", "PLANNED", "AUTHORIZED_PLAN", "EVIDENCE_PARTIAL"],
        )

    def test_history_is_append_only(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        before = list(record.history)
        selected = lifecycle.mark_selected(record, 1).record
        self.assertEqual(list(selected.history)[:1], before)
        self.assertEqual(len(record.history), 1)

    def test_walk_is_deterministic(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        def walk():
            _draft, plan = make_inputs()
            record = lifecycle.intake(make_case())
            record = lifecycle.mark_selected(record, 1).record
            record = lifecycle.attach_plan(record, plan).record
            return lifecycle.record_authorized(
                record, check_authorization_eligibility(plan)
            ).record

        self.assertEqual(walk(), walk())
        self.assertEqual(
            lifecycle.serialize_record(walk()), lifecycle.serialize_record(walk())
        )

    def test_serialization_round_trip(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        text = lifecycle.serialize_record(record)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)
        self.assertEqual(json.loads(text)["state"], "SELECTED")

    def test_records_are_frozen(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.state = "SELECTED"

    def test_all_states_reachable_in_order(self):
        self.assertEqual(
            list(STATES),
            [
                "NEW", "SELECTED", "PLANNED", "AUTHORIZED_PLAN",
                "WAITING_EVIDENCE", "EVIDENCE_PARTIAL", "EVIDENCE_READY",
                "REVIEW_REQUIRED",
            ],
        )


class TestRefusalVocabulary(unittest.TestCase):
    def test_refusal_codes_are_closed(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        new = lifecycle.intake(make_case())
        selected = lifecycle.mark_selected(new, 1).record
        codes = {
            lifecycle.mark_selected("x", 1).refusal_code,
            lifecycle.mark_selected(new, 0).refusal_code,
            lifecycle.mark_selected(selected, 2).refusal_code,
            lifecycle.attach_plan(new, plan).refusal_code,
            lifecycle.attach_plan(selected, None).refusal_code,
            lifecycle.submit_review(new, "early").refusal_code,
        }
        self.assertLessEqual(
            codes, {"INVALID_RECORD", "INVALID_TRANSITION", "STALE_INPUT", "MISSING_INPUT"}
        )

    def test_none_inputs_refused_everywhere(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        for outcome in (
            lifecycle.mark_selected(None, 1),
            lifecycle.attach_plan(None, plan),
            lifecycle.attach_plan(record, None),
            lifecycle.record_authorized(None, None),
            lifecycle.route_evidence(None, None),
            lifecycle.route_evidence(record, None),
            lifecycle.submit_review(None, "x"),
        ):
            self.assertFalse(outcome.ok)

    def test_advance_returns_new_objects(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        outcome = lifecycle.mark_selected(record, 1)
        self.assertIsNot(outcome.record, record)
        self.assertEqual(record.state, "NEW")

    def test_event_reasons_are_deterministic(self):
        from aec.orchestrator import lifecycle

        def walk():
            _draft, plan = make_inputs()
            record = lifecycle.intake(make_case())
            record = lifecycle.mark_selected(record, 2).record
            return lifecycle.attach_plan(record, plan).record

        first, second = walk(), walk()
        self.assertEqual(
            [e.reason for e in first.history], [e.reason for e in second.history]
        )
        self.assertIn("order:2", first.history[1].reason)

    def test_record_dict_has_stable_keys(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        self.assertEqual(
            sorted(record.to_dict()),
            ["case_id", "evidence_state", "gate_plan_hash", "history",
             "plan_id", "review_note", "selection_order", "state"],
        )

    def test_event_dict_has_stable_keys(self):
        from aec.orchestrator import lifecycle

        event = lifecycle.intake(make_case()).history[0]
        self.assertEqual(
            sorted(event.to_dict()), ["current", "previous", "reason", "seq"]
        )

    def test_route_accepts_dict_gap(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility
        from aec.evidence import builder

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        authorized = lifecycle.record_authorized(
            planned, check_authorization_eligibility(plan)
        ).record
        artifacts = builder.build_artifacts(plan).artifacts
        gap = advance_evidence(initial_gap("case-001"), artifacts)
        outcome = lifecycle.route_evidence(authorized, gap.to_dict())
        self.assertTrue(outcome.ok)

    def test_route_rejects_unknown_evidence_state(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        authorized = lifecycle.record_authorized(
            planned, check_authorization_eligibility(plan)
        ).record
        gap = initial_gap("case-001").to_dict()
        gap["state"] = "EVIDENCE_MAYBE"
        outcome = lifecycle.route_evidence(authorized, gap)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "STALE_INPUT")

    def test_select_second_case_independent(self):
        from aec.orchestrator import lifecycle

        first = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        other = make_case(case_id="case-002")
        second = lifecycle.mark_selected(lifecycle.intake(other), 1).record
        self.assertEqual(first.case_id, "case-001")
        self.assertEqual(second.case_id, "case-002")

    def test_plan_id_and_hash_recorded_on_authorize(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        decision = check_authorization_eligibility(plan)
        authorized = lifecycle.record_authorized(planned, decision).record
        self.assertEqual(authorized.plan_id, plan.plan_id)
        self.assertEqual(authorized.gate_plan_hash, decision.timestamp)

    def test_history_grows_one_event_per_hop(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.intake(make_case())
        self.assertEqual(len(record.history), 1)
        record = lifecycle.mark_selected(record, 1).record
        self.assertEqual(len(record.history), 2)
        record = lifecycle.attach_plan(record, plan).record
        self.assertEqual(len(record.history), 3)
        record = lifecycle.record_authorized(
            record, check_authorization_eligibility(plan)
        ).record
        self.assertEqual(len(record.history), 4)

    def test_refusal_details_are_non_empty(self):
        from aec.orchestrator import lifecycle

        _draft, plan = make_inputs()
        new = lifecycle.intake(make_case())
        for outcome in (
            lifecycle.mark_selected("x", 1),
            lifecycle.mark_selected(new, 0),
            lifecycle.attach_plan(new, plan),
            lifecycle.submit_review(new, "early"),
        ):
            self.assertTrue(outcome.refusal_detail)

    def test_record_authorized_accepts_dict_decision(self):
        from aec.orchestrator import lifecycle
        from aec.authorization_gate import check_authorization_eligibility

        _draft, plan = make_inputs()
        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 1).record
        planned = lifecycle.attach_plan(record, plan).record
        wire = check_authorization_eligibility(plan).to_dict()
        outcome = lifecycle.record_authorized(planned, wire)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.state, "AUTHORIZED_PLAN")

    def test_submit_review_accepts_empty_note(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.intake(make_case())
        record = dataclasses.replace(record, state="EVIDENCE_READY")
        outcome = lifecycle.submit_review(record, "")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.record.review_note, "")

    def test_history_entries_carry_seqs(self):
        from aec.orchestrator import lifecycle

        record = lifecycle.mark_selected(lifecycle.intake(make_case()), 5).record
        dicts = record.to_dict()["history"]
        self.assertEqual([d["seq"] for d in dicts], [1, 2])
        self.assertEqual(dicts[1]["reason"], "order:5")


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_foreign_imports(self):
        for name in MODULES:
            tree = ast.parse((ORCH_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)

    def test_modules_perform_no_filesystem_writes(self):
        for name in MODULES:
            tree = ast.parse((ORCH_DIR / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = ""
                    if isinstance(func, ast.Name):
                        called = func.id
                    elif isinstance(func, ast.Attribute):
                        called = func.attr
                    self.assertNotIn(called, {"write_text", "mkdir", "makedirs"}, name)
                    if called == "open":
                        modes = [
                            a.value for a in node.args[1:]
                            if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        ]
                        for mode in modes:
                            self.assertNotIn("w", mode.replace("U", ""), name)


if __name__ == "__main__":
    unittest.main()

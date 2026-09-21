"""Cross-layer integration for EPIC 3 (operating system end to end).

Walks a real case through every offline stage — intake, selection,
planning, authorization, evidence, queue, memory, read-only views —
proving the packages compose deterministically without network,
writes, or conclusions about any target.
"""

from __future__ import annotations

import json
import sys
import unittest

sys.dont_write_bytecode = True

from aec.case_compiler import compile_authorization_request
from aec.models import CaseRef, EvidenceGap
from aec.observation_plan import compile_observation_plan


def make_case(case_id="case-001", category="idor", order_seed=0):
    return CaseRef(
        case_id=case_id,
        job_id=case_id,
        program="pilot",
        host="example.com",
        endpoint="/item",
        parameter="id",
        method="GET",
        category=category,
        confidence="MEDIUM",
        url=f"https://example.com/item?id={order_seed}",
        evidence_gap=EvidenceGap.build(
            ("response-body", "status-code"),
            ("response-body", "status-code"),
            artifacts=[],
        ),
    )


def full_walk(case_id="case-001", category="idor", order=1):
    """Run one case through every offline stage. Returns a dict of outputs."""
    from aec.authorization_gate import check_authorization_eligibility
    from aec.evidence import builder, quality
    from aec.evidence.state_machine import advance as advance_evidence
    from aec.evidence.state_machine import initial_state as initial_gap
    from aec.memory import store as memory_store
    from aec.orchestrator import lifecycle
    from aec.queue import priority

    case = make_case(case_id, category)
    draft = compile_authorization_request(case).request
    plan = compile_observation_plan(draft).plan
    decision = check_authorization_eligibility(plan)
    artifacts = builder.build_artifacts(plan).artifacts
    assessments = [quality.assess(a) for a in artifacts]
    gap = advance_evidence(initial_gap(case_id), artifacts)

    record = lifecycle.intake(case)
    record = lifecycle.mark_selected(record, order).record
    record = lifecycle.attach_plan(record, plan).record
    record = lifecycle.record_authorized(record, decision).record
    record = lifecycle.route_evidence(record, gap).record

    snapshot = priority.build_queue([{
        "case_id": case_id,
        "risk_category": case.risk_category,
        "evidence_state": record.evidence_state,
        "planned_cost": len(plan.steps),
        "selection_order": order,
    }])
    memory = memory_store.fresh_memory(case_id)
    memory = memory_store.remember(
        memory, "GAP_NOTE", f"planned {len(plan.steps)} steps"
    ).memory
    return {
        "case": case, "draft": draft, "plan": plan, "decision": decision,
        "artifacts": artifacts, "assessments": assessments, "gap": gap,
        "record": record, "snapshot": snapshot, "memory": memory,
    }


class TestEndToEnd(unittest.TestCase):
    def test_full_walk_reaches_partial(self):
        outputs = full_walk()
        self.assertEqual(outputs["record"].state, "EVIDENCE_PARTIAL")
        self.assertEqual(outputs["decision"].decision, "ALLOW")

    def test_walk_is_deterministic(self):
        from aec.orchestrator.lifecycle import serialize_record

        first, second = full_walk(), full_walk()
        self.assertEqual(
            serialize_record(first["record"]), serialize_record(second["record"])
        )
        self.assertEqual(first["snapshot"], second["snapshot"])
        self.assertEqual(first["memory"], second["memory"])

    def test_record_plan_matches_evidence_plan(self):
        outputs = full_walk()
        self.assertEqual(outputs["record"].plan_id, outputs["plan"].plan_id)
        self.assertEqual(
            [a.plan_id for a in outputs["artifacts"]],
            [outputs["plan"].plan_id] * len(outputs["artifacts"]),
        )

    def test_queue_reflects_record_state(self):
        outputs = full_walk()
        entry = outputs["snapshot"].entries[0]
        self.assertEqual(entry.case_id, "case-001")
        self.assertGreater(entry.score, 0)

    def test_memory_captures_plan_shape(self):
        from aec.memory.store import recall

        outputs = full_walk()
        notes = recall(outputs["memory"], "GAP_NOTE")
        self.assertEqual(len(notes), 1)
        self.assertIn("3 steps", notes[0].detail)

    def test_two_cases_queue_in_priority_order(self):
        from aec.queue import priority

        low = full_walk("case-001", "xss", 2)
        high = full_walk("case-002", "authz", 1)

        def entry(outputs, order):
            return {
                "case_id": outputs["record"].case_id,
                "risk_category": outputs["case"].risk_category,
                "evidence_state": outputs["record"].evidence_state,
                "planned_cost": len(outputs["plan"].steps),
                "selection_order": order,
            }

        snapshot = priority.build_queue([entry(low, 2), entry(high, 1)])
        self.assertEqual(snapshot.entries[0].case_id, "case-002")

    def test_record_exposes_router_allowlisted_fields(self):
        # Contract pin without importing backend: the read-only views
        # project exactly these keys, so the record must always carry them.
        outputs = full_walk()
        record_dict = outputs["record"].to_dict()
        for key in ("case_id", "state", "evidence_state", "selection_order"):
            self.assertIn(key, record_dict)

    def test_every_stage_serializes_stably(self):
        from aec.evidence.serialization import serialize_bundle
        from aec.observation_plan import serialize_plan
        from aec.orchestrator.lifecycle import serialize_record
        from aec.queue.priority import serialize_snapshot

        outputs = full_walk()
        for text in (
            serialize_plan(outputs["plan"]),
            serialize_bundle(
                outputs["artifacts"], outputs["assessments"], outputs["gap"]
            ),
            serialize_record(outputs["record"]),
            serialize_snapshot(outputs["snapshot"]),
        ):
            self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)

    def test_refused_plan_halts_the_walk(self):
        from aec.orchestrator import lifecycle

        outputs = full_walk()
        record = outputs["record"]
        # A record mid-walk cannot skip back to selection.
        outcome = lifecycle.mark_selected(record, 9)
        self.assertFalse(outcome.ok)

    def test_second_walk_leaves_first_untouched(self):
        first = full_walk("case-001")
        before = first["record"].to_dict()
        full_walk("case-002")
        self.assertEqual(first["record"].to_dict(), before)

    def test_snapshot_score_matches_manual_rubric(self):
        from aec.queue.priority import score_item

        outputs = full_walk()
        manual = score_item({
            "case_id": "case-001",
            "risk_category": outputs["case"].risk_category,
            "evidence_state": outputs["record"].evidence_state,
            "planned_cost": len(outputs["plan"].steps),
            "selection_order": 1,
        })
        self.assertEqual(outputs["snapshot"].entries[0].score, manual)

    def test_record_history_length_matches_hops(self):
        outputs = full_walk()
        self.assertEqual(len(outputs["record"].history), 5)

    def test_gap_state_case_matches_record(self):
        outputs = full_walk()
        self.assertEqual(outputs["gap"].case_id, outputs["record"].case_id)
        self.assertEqual(
            outputs["gap"].state, outputs["record"].evidence_state
        )


class TestNoCrossImports(unittest.TestCase):
    def test_layer_direction_is_downward_only(self):
        import ast
        from pathlib import Path

        base = Path(__file__).resolve().parents[1] / "aec"
        lower = {"orchestrator", "queue", "memory"}
        for package in ("evidence", "case_compiler.py", "observation_plan.py",
                        "authorization_gate.py", "budget_ledger.py", "selection.py",
                        "redaction.py", "models.py", "errors.py"):
            target = base / package
            files = (
                list(target.rglob("*.py")) if target.is_dir()
                else [target] if target.exists() else []
            )
            for path in files:
                tree = ast.parse(path.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        root = node.module.split(".")
                        if root[0] == "aec" and len(root) > 1:
                            self.assertNotIn(
                                root[1], lower,
                                f"{path.name} imports upward into {root[1]}",
                            )


if __name__ == "__main__":
    unittest.main()

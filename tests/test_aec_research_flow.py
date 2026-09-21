"""Tests for the EPIC 4 research flow end to end (integration).

Walks a Watch asset-intelligence record through every offline stage —
adapt → recall → prioritize → assign → case kwargs → orchestrator
intake → queue. Asserts stage handoffs, deterministic replay, and that
lower layers never reach upward.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True


def record(**overrides):
    entry = {
        "program": "pilot",
        "subdomain": "example.com",
        "url": "/admin/users?role=",
        "endpoint": "/admin/users",
        "parameter": "role",
        "method": "GET",
        "location": "query",
        "technology": ["php"],
        "source": "watch",
        "last_update": None,
    }
    entry.update(overrides)
    return entry


def full_research_walk():
    """Adapt → recall → prioritize → assign → case → intake. Pure data."""
    from aec.assignment import rules
    from aec.intelligence import scoring
    from aec.memory import connect, store
    from aec.models import CaseRef
    from aec.orchestrator import lifecycle
    from aec.surface import adapter

    outcome = adapter.adapt_record(record(), default_category="idor")
    assert outcome.ok, outcome.refusal_code
    draft = outcome.draft
    memories = {
        "case-000": store.fresh_memory("case-000"),
    }
    context = connect.find_related(memories, draft.to_dict())
    priority = scoring.prioritize(
        draft.to_dict(), connect.history_summary(context)
    )
    assignment = rules.assign(draft.to_dict())
    case = CaseRef(**adapter.to_case_kwargs(draft))
    case_record = lifecycle.intake(case)
    return {
        "draft": draft,
        "priority": priority,
        "assignment": assignment,
        "case": case,
        "record": case_record,
    }


class TestResearchFlow(unittest.TestCase):
    def test_walk_completes(self):
        outputs = full_research_walk()
        self.assertEqual(outputs["record"].state, "NEW")
        self.assertEqual(outputs["assignment"].role, "authorization-researcher")
        self.assertIn(outputs["priority"].band, ("LOW", "MEDIUM", "HIGH"))

    def test_priority_reflects_admin_surface(self):
        from aec.intelligence import scoring
        from aec.surface import adapter

        admin = adapter.adapt_record(
            record(), default_category="idor").draft.to_dict()
        plain = adapter.adapt_record(
            record(endpoint="/", parameter="", url="/"),
            default_category="idor").draft.to_dict()
        admin_score = scoring.prioritize(
            admin, {"researched": False, "related_patterns": 0}).score
        plain_score = scoring.prioritize(
            plain, {"researched": False, "related_patterns": 0}).score
        self.assertGreater(admin_score, plain_score)

    def test_duplicate_memory_lowers_priority(self):
        from aec.intelligence import scoring
        from aec.memory import connect, store
        from aec.surface import adapter

        draft = adapter.adapt_record(record(), default_category="idor").draft
        key = f"{draft.asset}{draft.endpoint}?{draft.parameters[0]}"
        other = store.fresh_memory("case-009")
        outcome = store.remember(other, "OBSERVATION", "checked", relates_to=(key,))
        assert outcome.ok
        context = connect.find_related(
            {"case-009": outcome.memory}, draft.to_dict()
        )
        dup = scoring.prioritize(
            draft.to_dict(), connect.history_summary(context))
        fresh = scoring.prioritize(
            draft.to_dict(), {"researched": False, "related_patterns": 0})
        self.assertLess(dup.score, fresh.score)

    def test_full_replay_is_deterministic(self):
        first = full_research_walk()
        second = full_research_walk()
        self.assertEqual(first["priority"], second["priority"])
        self.assertEqual(first["assignment"], second["assignment"])
        self.assertEqual(
            first["record"].to_dict(), second["record"].to_dict()
        )

    def test_every_stage_serializes_stably(self):
        import json
        from aec.intelligence.scoring import serialize_priority
        from aec.orchestrator.lifecycle import serialize_record
        from aec.surface.adapter import serialize_draft

        outputs = full_research_walk()
        for text in (
            serialize_draft(outputs["draft"]),
            serialize_priority(outputs["priority"]),
        ):
            self.assertEqual(
                json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
                text,
            )
        record_text = serialize_record(outputs["record"])
        self.assertEqual(
            json.dumps(json.loads(record_text), sort_keys=True), record_text
        )

    def test_case_kwargs_reach_selection_queue(self):
        from aec.orchestrator import lifecycle
        from aec.queue import priority as queue_priority

        outputs = full_research_walk()
        selected = lifecycle.mark_selected(outputs["record"], 1)
        assert selected.ok
        snapshot = queue_priority.build_queue([
            {
                "case_id": selected.record.case_id,
                "risk_category": "R1_OBJECT_REFERENCE",
                "evidence_state": selected.record.evidence_state,
                "planned_cost": 2,
                "selection_order": 1,
            }
        ])
        self.assertEqual(snapshot.entries[0].case_id, selected.record.case_id)

    def test_record_exposes_research_view_fields(self):
        outputs = full_research_walk()
        record_dict = outputs["record"].to_dict()
        for key in ("case_id", "state", "evidence_state", "selection_order"):
            self.assertIn(key, record_dict)


class TestNoCrossImports(unittest.TestCase):
    def test_layer_direction_is_downward_only(self):
        base = Path(__file__).resolve().parents[1] / "aec"
        upward = ("orchestrator", "queue", "memory", "intelligence", "assignment")
        for package in ("surface", "intelligence", "assignment", "memory"):
            for path in (base / package).glob("*.py"):
                tree = ast.parse(path.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        top = node.module.split(".")
                        if top[:1] == ["aec"] and len(top) > 1 and top[1] != package:
                            self.assertNotIn(top[1], upward, f"{path.name}:{node.module}")


class TestSecondCandidate(unittest.TestCase):
    def test_two_candidates_independent_ids(self):
        from aec.surface import adapter

        first = adapter.adapt_record(
            record(), default_category="idor").draft
        second = adapter.adapt_record(
            record(endpoint="/orders", parameter="order_id",
                   url="/orders?order_id="),
            default_category="idor").draft
        self.assertNotEqual(first.candidate_id, second.candidate_id)

    def test_ssrf_candidate_end_to_end_role(self):
        from aec.assignment import rules
        from aec.surface import adapter

        draft = adapter.adapt_record(
            record(endpoint="/fetch", parameter="target",
                   url="/fetch?target="),
            default_category="ssrf").draft
        self.assertEqual(
            rules.assign(draft.to_dict()).role, "server-researcher")

    def test_xss_candidate_end_to_end_role(self):
        from aec.assignment import rules
        from aec.surface import adapter

        draft = adapter.adapt_record(
            record(endpoint="/search", parameter="q", url="/search?q="),
            default_category="xss").draft
        self.assertEqual(
            rules.assign(draft.to_dict()).role, "input-researcher")

    def test_recorded_pattern_reused_as_context(self):
        from aec.memory import connect, store
        from aec.surface import adapter

        draft = adapter.adapt_record(record(), default_category="idor").draft
        key = connect.endpoint_key(draft.to_dict())
        memory = store.fresh_memory("case-100")
        outcome = store.remember(
            memory, "PATTERN", "baseline then comparison",
            relates_to=(key,),
        )
        assert outcome.ok
        context = connect.find_related(
            {"case-100": outcome.memory}, draft.to_dict())
        self.assertFalse(context.researched)
        self.assertEqual(
            context.related_patterns, ("baseline then comparison",)
        )

    def test_queue_head_is_highest_priority(self):
        from aec.intelligence import scoring
        from aec.queue import priority as queue_priority
        from aec.surface import adapter

        drafts = [
            adapter.adapt_record(
                record(endpoint=endpoint, parameter="id",
                       url=f"{endpoint}?id="),
                default_category="idor",
            ).draft.to_dict()
            for endpoint in ("/", "/admin/users")
        ]
        scored = [
            (fields["candidate_id"],
             scoring.prioritize(
                 fields, {"researched": False, "related_patterns": 0}).score)
            for fields in drafts
        ]
        head = max(scored, key=lambda pair: pair[1])[0]
        admin_id = next(
            fields["candidate_id"] for fields in drafts
            if fields["endpoint"] == "/admin/users"
        )
        self.assertEqual(head, admin_id)

    def test_refused_record_never_reaches_intake(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(record(endpoint=""))
        self.assertFalse(outcome.ok)
        self.assertIsNone(outcome.draft)

    def test_memory_summary_round_trip(self):
        from aec.memory import connect

        context = connect.find_related({}, candidate_fields())
        summary = connect.history_summary(context)
        self.assertEqual(
            summary, {"researched": False, "related_patterns": 0}
        )


def candidate_fields():
    return {
        "candidate_id": "rc-abc123",
        "asset": "example.com",
        "endpoint": "/api/user",
        "parameters": ("id",),
        "research_category": "idor",
    }


class TestWalkRendersInRouter(unittest.TestCase):
    def test_walk_outputs_render_in_candidates_view(self):
        from backend.routers import aec

        outputs = full_research_walk()
        rendered = dict(outputs["draft"].to_dict())
        rendered.update(outputs["priority"].to_dict())
        rendered.update(outputs["assignment"].to_dict())
        view = aec.build_candidates_view([rendered])
        shown = view["candidates"][0]
        self.assertEqual(shown["candidate_id"], outputs["draft"].candidate_id)
        self.assertEqual(shown["band"], outputs["priority"].band)
        self.assertEqual(shown["score"], outputs["priority"].score)
        self.assertEqual(shown["role"], outputs["assignment"].role)

    def test_walk_status_counts_render(self):
        from backend.routers import aec

        outputs = full_research_walk()
        status = aec.build_research_status_view({
            "bands": {outputs["priority"].band: 1},
            "roles": {outputs["assignment"].role: 1},
        })
        self.assertEqual(status["bands"][outputs["priority"].band], 1)


if __name__ == "__main__":
    unittest.main()

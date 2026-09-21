"""Tests for backend/routers/aec.py (EPIC 3 Part 4: read-only API layer).

The router exposes exactly three GET endpoints over explicitly supplied
views — no database, no sessions, no mutations, no secrets. Handlers are
pure projections; the route table itself is asserted read-only.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROUTER_PATH = (
    Path(__file__).resolve().parents[1] / "backend" / "routers" / "aec.py"
)

BANNED_IMPORT_ROOTS = frozenset({"ai", "backend", "pymongo", "socket", "subprocess"})


def sample_records():
    return [
        {
            "case_id": "case-001",
            "state": "EVIDENCE_PARTIAL",
            "evidence_state": "EVIDENCE_PARTIAL",
            "selection_order": 2,
            "secret_note": "must never surface",
        },
        {
            "case_id": "case-002",
            "state": "NEW",
            "evidence_state": "WAITING_EVIDENCE",
            "selection_order": 0,
        },
    ]


def sample_snapshot():
    return {
        "snapshot_id": "queue:abc123",
        "entries": [
            {"case_id": "case-001", "score": 87, "rank": 1},
            {"case_id": "case-002", "score": 40, "rank": 2},
        ],
        "total": 2,
    }


class TestCasesView(unittest.TestCase):
    def test_cases_project_allowlisted_fields_only(self):
        from backend.routers import aec

        view = aec.build_cases_view(sample_records())
        self.assertEqual(len(view["cases"]), 2)
        first = view["cases"][0]
        self.assertEqual(
            first,
            {
                "case_id": "case-001",
                "state": "EVIDENCE_PARTIAL",
                "evidence_state": "EVIDENCE_PARTIAL",
                "selection_order": 2,
            },
        )
        self.assertNotIn("secret_note", first)

    def test_cases_skips_malformed_records(self):
        from backend.routers import aec

        view = aec.build_cases_view([{"nope": True}, None, "x", *sample_records()])
        self.assertEqual(len(view["cases"]), 2)

    def test_cases_empty_is_valid(self):
        from backend.routers import aec

        self.assertEqual(aec.build_cases_view([]), {"cases": []})

    def test_cases_view_is_deterministic(self):
        from backend.routers import aec

        self.assertEqual(
            aec.build_cases_view(sample_records()),
            aec.build_cases_view(sample_records()),
        )


class TestQueueView(unittest.TestCase):
    def test_queue_view_passes_through_snapshot(self):
        from backend.routers import aec

        view = aec.build_queue_view(sample_snapshot())
        self.assertEqual(view["snapshot_id"], "queue:abc123")
        self.assertEqual(view["total"], 2)
        self.assertEqual(view["entries"][0]["rank"], 1)

    def test_queue_view_rejects_malformed_snapshot(self):
        from backend.routers import aec

        for bad in (None, "x", {"entries": "nope"}):
            with self.assertRaises(ValueError, msg=f"{bad!r}"):
                aec.build_queue_view(bad)


class TestStatusView(unittest.TestCase):
    def test_status_counts_by_state(self):
        from backend.routers import aec

        view = aec.build_status_view({"NEW": 5, "EVIDENCE_PARTIAL": 2})
        self.assertEqual(view["counts"], {"NEW": 5, "EVIDENCE_PARTIAL": 2})
        self.assertIn("aec", view["versions"])

    def test_status_rejects_non_counts(self):
        from backend.routers import aec

        for bad in (None, "x", {"NEW": "five"}, {"NEW": -1}):
            with self.assertRaises(ValueError, msg=f"{bad!r}"):
                aec.build_status_view(bad)


class TestRouteTable(unittest.TestCase):
    def test_exactly_nineteen_get_routes(self):
        from backend.routers import aec

        routes = [
            (sorted(r.methods), r.path)
            for r in aec.router.routes
            if hasattr(r, "methods")
        ]
        self.assertEqual(
            sorted(routes),
            [
                (["GET"], "/api/aec/candidates"),
                (["GET"], "/api/aec/cases"),
                (["GET"], "/api/aec/evidence"),
                (["GET"], "/api/aec/execution-runs"),
                (["GET"], "/api/aec/execution-summary"),
                (["GET"], "/api/aec/queue"),
                (["GET"], "/api/aec/research-jobs"),
                (["GET"], "/api/aec/research-queue"),
                (["GET"], "/api/aec/research-runs"),
                (["GET"], "/api/aec/research-status"),
                (["GET"], "/api/aec/research-summary"),
                (["GET"], "/api/aec/review"),
                (["GET"], "/api/aec/runtime"),
                (["GET"], "/api/aec/runtime/audit"),
                (["GET"], "/api/aec/runtime/health"),
                (["GET"], "/api/aec/runtime/limits"),
                (["GET"], "/api/aec/runtime/requests"),
                (["GET"], "/api/aec/specialists"),
                (["GET"], "/api/aec/status"),
            ],
        )

    def test_no_mutation_decorators_in_source(self):
        source = ROUTER_PATH.read_text()
        for decorator in ("@router.post", "@router.put", "@router.patch",
                          "@router.delete", "@router.options", "@router.head"):
            self.assertNotIn(decorator, source)

    def test_router_imports_are_narrow(self):
        tree = ast.parse(ROUTER_PATH.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported & BANNED_IMPORT_ROOTS, set())
        self.assertIn("fastapi", imported)

    def test_router_has_no_secrets_or_finding_words(self):
        words = [w.lower() for w in
                 ("password", "token", "secret", "finding", "severity", "verdict")]
        source_words = set(ast.parse(ROUTER_PATH.read_text()) and
                           __import__("re").findall(r"[A-Za-z_]+", ROUTER_PATH.read_text().lower()))
        for word in words:
            self.assertNotIn(word, source_words)

    def test_handlers_do_not_touch_storage(self):
        tree = ast.parse(ROUTER_PATH.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = ""
                if isinstance(func, ast.Name):
                    called = func.id
                elif isinstance(func, ast.Attribute):
                    called = func.attr
                self.assertNotIn(called, {"open", "write_text", "mkdir", "connect"})

    def test_views_are_json_serializable(self):
        import json as json_lib
        from backend.routers import aec

        for view in (
            aec.build_cases_view(sample_records()),
            aec.build_queue_view(sample_snapshot()),
            aec.build_status_view({"NEW": 1}),
        ):
            json_lib.dumps(view)

    def test_status_versions_pin_layer(self):
        from backend.routers import aec

        versions = aec.build_status_view({})["versions"]
        self.assertIn("aec", versions)
        self.assertTrue(versions["aec"])

    def test_cases_default_missing_order_to_zero(self):
        from backend.routers import aec

        view = aec.build_cases_view([{"case_id": "c", "state": "NEW"}])
        self.assertEqual(view["cases"][0]["selection_order"], 0)
        self.assertEqual(view["cases"][0]["evidence_state"], "WAITING_EVIDENCE")

    def test_cases_rejects_non_list(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_cases_view({"cases": []})

    def test_queue_entries_keep_rank_order(self):
        from backend.routers import aec

        view = aec.build_queue_view(sample_snapshot())
        self.assertEqual(
            [e["case_id"] for e in view["entries"]], ["case-001", "case-002"]
        )

    def test_status_counts_only_known_states(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_status_view({"NOPE_STATE": 1})

    def test_queue_total_matches_entries(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_queue_view({"snapshot_id": "s", "entries": [], "total": 3})

    def test_view_functions_are_sync(self):
        import inspect
        from backend.routers import aec

        for fn in (aec.build_cases_view, aec.build_queue_view, aec.build_status_view):
            self.assertFalse(inspect.iscoroutinefunction(fn))

    def test_cases_preserve_input_order(self):
        from backend.routers import aec

        records = list(reversed(sample_records()))
        view = aec.build_cases_view(records)
        self.assertEqual(view["cases"][0]["case_id"], "case-002")

    def test_status_empty_counts_ok(self):
        from backend.routers import aec

        view = aec.build_status_view({})
        self.assertEqual(view["counts"], {})

    def test_endpoint_handlers_return_empty_views(self):
        from backend.routers import aec

        self.assertEqual(aec.get_candidates(), {"candidates": []})
        self.assertEqual(
            aec.get_research_status(),
            {"bands": {}, "roles": {}, "versions": {"aec": aec.LAYER_VERSION}},
        )
        self.assertEqual(aec.get_cases(), {"cases": []})
        self.assertEqual(
            aec.get_queue(),
            {"snapshot_id": "", "entries": [], "total": 0},
        )
        self.assertEqual(
            aec.get_status(), {"counts": {}, "versions": {"aec": aec.LAYER_VERSION}}
        )

    def test_candidate_view_keys_constant(self):
        from backend.routers import aec

        self.assertEqual(
            tuple(aec.CANDIDATE_VIEW_KEYS),
            ("candidate_id", "asset", "endpoint", "research_category",
             "band", "score", "role"),
        )

    def test_queue_empty_entries_ok(self):
        from backend.routers import aec

        view = aec.build_queue_view({"snapshot_id": "s", "entries": [], "total": 0})
        self.assertEqual(view["entries"], [])

    def test_views_render_orchestrator_records(self):
        from aec.models import CaseRef, EvidenceGap
        from aec.orchestrator import lifecycle
        from backend.routers import aec

        case = CaseRef(
            case_id="case-001", job_id="case-001", program="pilot",
            host="example.com", endpoint="/item", parameter="id",
            method="GET", category="idor", confidence="MEDIUM",
            url="https://example.com/item",
            evidence_gap=EvidenceGap.build(("response-body",), ("response-body",)),
        )
        record = lifecycle.mark_selected(lifecycle.intake(case), 2).record
        view = aec.build_cases_view([record.to_dict()])
        self.assertEqual(view["cases"][0]["case_id"], "case-001")
        self.assertEqual(view["cases"][0]["state"], "SELECTED")
        self.assertEqual(view["cases"][0]["selection_order"], 2)


class TestCandidatesView(unittest.TestCase):
    def test_valid_items_projected(self):
        from backend.routers import aec

        view = aec.build_candidates_view([
            {
                "candidate_id": "rc-001",
                "asset": "example.com",
                "endpoint": "/admin",
                "research_category": "idor",
                "band": "HIGH",
                "score": 70,
                "role": "authorization-researcher",
                "extra": "dropped",
            }
        ])
        self.assertEqual(view["candidates"][0]["band"], "HIGH")
        self.assertNotIn("extra", view["candidates"][0])
        self.assertEqual(
            sorted(view["candidates"][0]),
            ["asset", "band", "candidate_id", "endpoint",
             "research_category", "role", "score"],
        )

    def test_unknown_band_dropped(self):
        from backend.routers import aec

        view = aec.build_candidates_view([
            {"candidate_id": "rc-001", "band": "URGENT"},
            {"candidate_id": "rc-002", "band": "LOW"},
        ])
        self.assertEqual(
            [c["candidate_id"] for c in view["candidates"]], ["rc-002"]
        )

    def test_unknown_role_defaults_general(self):
        from backend.routers import aec

        view = aec.build_candidates_view([
            {"candidate_id": "rc-001", "band": "MEDIUM", "role": "ninja"}
        ])
        self.assertEqual(
            view["candidates"][0]["role"], "general-researcher"
        )

    def test_non_mapping_items_skipped(self):
        from backend.routers import aec

        view = aec.build_candidates_view(["nope", {"candidate_id": "rc-1", "band": "LOW"}])
        self.assertEqual(len(view["candidates"]), 1)

    def test_non_sequence_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_candidates_view("nope")
        with self.assertRaises(ValueError):
            aec.build_candidates_view({"candidate_id": "rc-1"})

    def test_empty_view(self):
        from backend.routers import aec

        self.assertEqual(aec.build_candidates_view([]), {"candidates": []})


class TestResearchStatusView(unittest.TestCase):
    def test_valid_summary_aggregates(self):
        from backend.routers import aec

        view = aec.build_research_status_view({
            "bands": {"HIGH": 2, "LOW": 1},
            "roles": {"authorization-researcher": 3},
        })
        self.assertEqual(view["bands"], {"HIGH": 2, "LOW": 1})
        self.assertIn("aec", view["versions"])

    def test_unknown_band_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_status_view(
                {"bands": {"URGENT": 1}, "roles": {}})

    def test_unknown_role_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_status_view(
                {"bands": {}, "roles": {"ninja": 1}})

    def test_negative_and_bool_counts_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_status_view(
                {"bands": {"LOW": -1}, "roles": {}})
        with self.assertRaises(ValueError):
            aec.build_research_status_view(
                {"bands": {}, "roles": {"input-researcher": True}})

    def test_non_mapping_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_status_view(["bands"])

    def test_full_pipeline_renders(self):
        from aec.assignment import rules
        from aec.intelligence import scoring
        from aec.surface import adapter
        from backend.routers import aec

        record = {
            "program": "pilot", "subdomain": "example.com",
            "url": "/admin/users?role=", "endpoint": "/admin/users",
            "parameter": "role", "method": "GET", "location": "query",
            "technology": ["php"], "source": "watch", "last_update": None,
        }
        draft = adapter.adapt_record(record, default_category="idor").draft
        priority = scoring.prioritize(
            draft.to_dict(), {"researched": False, "related_patterns": 0})
        assignment = rules.assign(draft.to_dict())
        rendered = dict(draft.to_dict())
        rendered.update(priority.to_dict())
        rendered.update(assignment.to_dict())
        view = aec.build_candidates_view([rendered])
        self.assertEqual(view["candidates"][0]["candidate_id"], draft.candidate_id)
        self.assertEqual(view["candidates"][0]["role"], "authorization-researcher")


if __name__ == "__main__":
    unittest.main()

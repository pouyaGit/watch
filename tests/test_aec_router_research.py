"""Tests for the EPIC 5 research endpoints (Part 12: Command Center).

Builders project run, queue, review, and summary views; handlers serve
real simulation-derived data computed from the committed fixture —
deterministic, read-only, no storage, no I/O. Route table stays GET-only.
"""

from __future__ import annotations

import sys
import unittest

sys.dont_write_bytecode = True


def sample_run():
    from aec.coordinator import fixtures, pipeline

    return pipeline.run_research(list(fixtures.CANDIDATES)).to_dict()


class TestResearchRunsView(unittest.TestCase):
    def test_runs_project_allowlisted_fields(self):
        from backend.routers import aec

        view = aec.build_research_runs_view([sample_run()])
        self.assertEqual(len(view["runs"]), 1)
        run = view["runs"][0]
        self.assertEqual(
            sorted(run),
            ["candidates_processed", "cases_created", "cases_skipped",
             "completion_summary", "failures", "plans_generated",
             "review_items", "run_id"],
        )

    def test_runs_reject_non_sequence(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_runs_view({"run_id": "x"})

    def test_runs_skip_bad_entries(self):
        from backend.routers import aec

        view = aec.build_research_runs_view(["nope", sample_run()])
        self.assertEqual(len(view["runs"]), 1)

    def test_empty_runs(self):
        from backend.routers import aec

        self.assertEqual(aec.build_research_runs_view([]), {"runs": []})


class TestResearchQueueView(unittest.TestCase):
    def test_snapshot_projects(self):
        from backend.routers import aec

        run = sample_run()
        view = aec.build_research_queue_view(run["queue_snapshot"])
        self.assertEqual(view["total"], run["queue_snapshot"]["total"])
        self.assertEqual(view["snapshot_id"], run["queue_snapshot"]["snapshot_id"])

    def test_none_snapshot_empty(self):
        from backend.routers import aec

        self.assertEqual(
            aec.build_research_queue_view(None),
            {"snapshot_id": "", "entries": [], "total": 0},
        )

    def test_bad_snapshot_rejected(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_queue_view({"entries": []})


class TestReviewEndpointView(unittest.TestCase):
    def test_items_project(self):
        from backend.routers import aec

        run = sample_run()
        view = aec.build_review_view(run["review_items"])
        self.assertEqual(len(view["items"]), len(run["review_items"]))
        self.assertEqual(
            sorted(view["items"][0]),
            ["case_id", "current_state", "evidence_state", "missing_evidence",
             "reason", "recommended_next_action", "research_history"],
        )

    def test_bad_reasons_dropped(self):
        from backend.routers import aec

        view = aec.build_review_view([
            {"case_id": "c-1", "reason": "NOPE",
             "recommended_next_action": "HUMAN_TRIAGE"},
        ])
        self.assertEqual(view["items"], [])

    def test_empty_review(self):
        from backend.routers import aec

        self.assertEqual(aec.build_review_view([]), {"items": []})


class TestResearchSummaryView(unittest.TestCase):
    def test_summary_aggregates(self):
        from backend.routers import aec

        view = aec.build_research_summary_view(sample_run())
        self.assertEqual(
            sorted(view),
            ["assignments_by_specialist", "authorizations", "bands",
             "candidates_processed", "cases_created", "evidence_states",
             "failures", "run_id", "versions"],
        )
        self.assertGreater(view["candidates_processed"], 19)

    def test_summary_rejects_garbage(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_summary_view("nope")

    def test_band_counts_match_cases(self):
        from backend.routers import aec

        run = sample_run()
        view = aec.build_research_summary_view(run)
        self.assertEqual(
            sum(view["bands"].values()), len(run["cases"])
        )


class TestResearchHandlers(unittest.TestCase):
    def test_research_runs_returns_real_data(self):
        from backend.routers import aec

        view = aec.get_research_runs()
        self.assertEqual(len(view["runs"]), 1)
        self.assertGreaterEqual(view["runs"][0]["candidates_processed"], 20)

    def test_research_queue_returns_real_data(self):
        from backend.routers import aec

        view = aec.get_research_queue()
        self.assertGreater(view["total"], 0)

    def test_review_returns_real_data(self):
        from backend.routers import aec

        view = aec.get_review()
        self.assertGreater(len(view["items"]), 0)

    def test_research_summary_returns_real_data(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertGreaterEqual(view["candidates_processed"], 20)
        self.assertIn("versions", view)

    def test_new_routes_are_get_only(self):
        from backend.routers import aec

        routes = sorted(
            (tuple(sorted(r.methods or ())), r.path)
            for r in aec.router.routes
            if r.path.startswith("/api/aec/research")
            or r.path in (
                "/api/aec/review",
                "/api/aec/execution-runs",
                "/api/aec/research-jobs",
                "/api/aec/specialists",
                "/api/aec/evidence",
                "/api/aec/execution-summary",
            )
        )
        self.assertEqual(
            routes,
            [
                (("GET",), "/api/aec/evidence"),
                (("GET",), "/api/aec/execution-runs"),
                (("GET",), "/api/aec/execution-summary"),
                (("GET",), "/api/aec/research-jobs"),
                (("GET",), "/api/aec/research-queue"),
                (("GET",), "/api/aec/research-runs"),
                (("GET",), "/api/aec/research-status"),
                (("GET",), "/api/aec/research-summary"),
                (("GET",), "/api/aec/review"),
                (("GET",), "/api/aec/specialists"),
            ],
        )


class TestResearchHandlerDetails(unittest.TestCase):
    def test_handlers_are_deterministic(self):
        from backend.routers import aec

        self.assertEqual(aec.get_research_runs(), aec.get_research_runs())
        self.assertEqual(aec.get_research_summary(), aec.get_research_summary())
        self.assertEqual(aec.get_review(), aec.get_review())

    def test_runs_view_carries_summary(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(run["completion_summary"]["candidates_processed"], 21)
        self.assertIn("run_id", run)

    def test_queue_entries_shape(self):
        from backend.routers import aec

        view = aec.get_research_queue()
        self.assertTrue(view["entries"])
        self.assertEqual(
            sorted(view["entries"][0]), ["case_id", "rank", "score"]
        )

    def test_review_items_have_actions(self):
        from backend.routers import aec

        for item in aec.get_review()["items"]:
            self.assertTrue(item["recommended_next_action"])
            self.assertTrue(item["case_id"])

    def test_summary_bands_sum_to_cases(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertEqual(
            sum(view["bands"].values()), view["cases_created"]
        )

    def test_summary_specialists_known(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertLessEqual(
            set(view["assignments_by_specialist"]), set(aec.ASSIGNMENT_ROLES)
        )
        self.assertIn("technology-researcher", view["assignments_by_specialist"])

    def test_summary_authorizations(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        allows = sum(
            1 for state in view["authorizations"].values() if state == "ALLOW"
        )
        self.assertEqual(allows, 17)

    def test_summary_evidence_all_waiting(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertEqual(
            set(view["evidence_states"].values()), {"WAITING_EVIDENCE"}
        )

    def test_summary_failures_count(self):
        from backend.routers import aec

        self.assertEqual(aec.get_research_summary()["failures"], 3)

    def test_runs_view_skips_runtless(self):
        from backend.routers import aec

        view = aec.build_research_runs_view([{"no_id": True}])
        self.assertEqual(view, {"runs": []})

    def test_runs_view_rejects_mapping(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_runs_view({"run_id": "run-1"})

    def test_summary_rejects_bad_cases(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_summary_view({"cases": "nope"})

    def test_summary_rejects_bad_states(self):
        from backend.routers import aec

        run = sample_run()
        run["authorization_states"] = ["nope"]
        with self.assertRaises(ValueError):
            aec.build_research_summary_view(run)

    def test_review_view_rejects_non_sequence(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_review_view("nope")

    def test_review_view_skips_non_mappings(self):
        from backend.routers import aec

        run = sample_run()
        view = aec.build_review_view(["nope", *run["review_items"][:1]])
        self.assertEqual(len(view["items"]), 1)

    def test_queue_view_rejects_bad_snapshot(self):
        from backend.routers import aec

        with self.assertRaises(ValueError):
            aec.build_research_queue_view({"snapshot_id": "x"})

    def test_run_keys_constant(self):
        from backend.routers import aec

        self.assertIn("run_id", aec.RESEARCH_RUN_KEYS)
        self.assertIn("completion_summary", aec.RESEARCH_RUN_KEYS)

    def test_builders_do_not_mutate_inputs(self):
        import copy
        from backend.routers import aec

        run = sample_run()
        before = copy.deepcopy(run)
        aec.build_research_runs_view([run])
        aec.build_research_summary_view(run)
        aec.build_review_view(run["review_items"])
        self.assertEqual(run, before)

    def test_summary_cases_created_count(self):
        from backend.routers import aec

        self.assertEqual(aec.get_research_summary()["cases_created"], 18)

    def test_queue_total_matches(self):
        from backend.routers import aec

        self.assertEqual(aec.get_research_queue()["total"], 18)

    def test_summary_run_id_prefix(self):
        from backend.routers import aec

        self.assertTrue(
            aec.get_research_summary()["run_id"].startswith("run-")
        )

    def test_runs_view_failures_passthrough(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(len(run["failures"]), 3)

    def test_runs_view_review_passthrough(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(len(run["review_items"]), 18)

    def test_review_view_mixed_validity(self):
        from backend.routers import aec

        run = sample_run()
        view = aec.build_review_view([
            {"case_id": "", "reason": "EVIDENCE_INCOMPLETE"},
            *run["review_items"][:2],
        ])
        self.assertEqual(len(view["items"]), 2)

    def test_summary_versions_stamp(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertIn("aec", view["versions"])

    def test_runs_view_candidates_processed(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(run["candidates_processed"], 21)

    def test_runs_view_plans_passthrough(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(len(run["plans_generated"]), 17)

    def test_runs_view_skips_passthrough(self):
        from backend.routers import aec

        run = aec.get_research_runs()["runs"][0]
        self.assertEqual(len(run["cases_skipped"]), 1)

    def test_queue_snapshot_id_non_empty(self):
        from backend.routers import aec

        self.assertTrue(aec.get_research_queue()["snapshot_id"])

    def test_review_count_matches(self):
        from backend.routers import aec

        self.assertEqual(len(aec.get_review()["items"]), 18)

    def test_summary_bands_known(self):
        from backend.routers import aec

        view = aec.get_research_summary()
        self.assertLessEqual(set(view["bands"]), {"LOW", "MEDIUM", "HIGH"})

    def test_legacy_candidates_route_intact(self):
        from backend.routers import aec

        self.assertEqual(aec.get_candidates(), {"candidates": []})

    def test_legacy_status_routes_intact(self):
        from backend.routers import aec

        self.assertEqual(aec.get_cases(), {"cases": []})
        self.assertEqual(
            aec.get_status(), {"counts": {}, "versions": {"aec": aec.LAYER_VERSION}}
        )

    def test_fourteen_routes_total(self):
        from backend.routers import aec

        paths = [
            r.path for r in aec.router.routes if hasattr(r, "methods")
        ]
        self.assertEqual(len(paths), 14)


if __name__ == "__main__":
    unittest.main()

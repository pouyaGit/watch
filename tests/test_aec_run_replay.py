"""Tests for EPIC 5 replay, simulation, and invariants (Parts 9/11/14).

Runs the committed 20+ candidate fixture through the coordinator twice
and requires byte-identical output; enforces the offline invariants
(no skips, no invented evidence, no conclusions, no network, no
secrets, no source mutation, stable bytes, complete audit).
"""

from __future__ import annotations

import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

AEC_DIR = Path(__file__).resolve().parents[1] / "aec"

NEW_PACKAGES = ("coordinator", "review", "reporting")

FORBIDDEN_OUTPUT_WORDS = (
    "CONFIRMED", "VULNERABLE", "EXPLOITABLE",
)

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
})


def simulate():
    from aec.coordinator import fixtures, pipeline

    return pipeline.run_research(list(fixtures.CANDIDATES))


class TestFixture(unittest.TestCase):
    def test_fixture_has_twenty_plus_candidates(self):
        from aec.coordinator import fixtures

        self.assertGreaterEqual(len(fixtures.CANDIDATES), 20)

    def test_fixture_covers_categories(self):
        from aec.coordinator import fixtures

        categories = set()
        for candidate in fixtures.CANDIDATES:
            raw = str(candidate.get("category", "")).lower()
            categories.add(raw.replace("_candidate", ""))
        for expected in ("idor", "xss", "ssrf", "file_upload", "authz"):
            self.assertIn(expected, categories, expected)

    def test_fixture_entries_are_mappings(self):
        from aec.coordinator import fixtures

        for candidate in fixtures.CANDIDATES:
            self.assertIsInstance(candidate, dict)


class TestSimulation(unittest.TestCase):
    def test_simulation_processes_all_candidates(self):
        from aec.coordinator import fixtures

        run = simulate()
        self.assertEqual(run.candidates_processed, len(fixtures.CANDIDATES))

    def test_simulation_creates_cases(self):
        run = simulate()
        self.assertGreaterEqual(len(run.cases_created), 10)

    def test_multiple_specialists_exercised(self):
        run = simulate()
        specialists = {case["specialist"] for case in run.cases}
        self.assertGreaterEqual(len(specialists), 3)

    def test_plans_generated(self):
        run = simulate()
        self.assertGreaterEqual(len(run.plans_generated), 10)

    def test_review_items_created(self):
        run = simulate()
        self.assertGreaterEqual(len(run.review_items), 10)

    def test_failures_demonstrated(self):
        run = simulate()
        kinds = {failure["kind"] for failure in run.failures}
        self.assertIn("UNSUPPORTED_CATEGORY", kinds)
        self.assertIn("INVALID_DRAFT", kinds)

    def test_skip_demonstrated(self):
        run = simulate()
        reasons = {skip["reason"] for skip in run.cases_skipped}
        self.assertIn("DUPLICATE_CANDIDATE", reasons)

    def test_report_generates(self):
        from aec.reporting import report

        generated = report.generate_report(simulate().to_dict())
        self.assertTrue(generated.observed_facts)
        self.assertTrue(generated.next_steps)


class TestReplay(unittest.TestCase):
    def test_two_runs_byte_identical(self):
        from aec.coordinator import pipeline

        first = pipeline.serialize_run(simulate())
        second = pipeline.serialize_run(simulate())
        self.assertEqual(first, second)

    def test_case_ordering_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(first["cases_created"], second["cases_created"])
        self.assertEqual(
            [case["case_id"] for case in first["cases"]],
            [case["case_id"] for case in second["cases"]],
        )

    def test_assignments_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(first["assignments"], second["assignments"])

    def test_plans_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(first["plans_generated"], second["plans_generated"])
        self.assertEqual(
            first["authorization_states"], second["authorization_states"]
        )

    def test_states_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(first["evidence_states"], second["evidence_states"])
        self.assertEqual(first["state_reasons"], second["state_reasons"])

    def test_review_queue_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(first["review_items"], second["review_items"])

    def test_reports_stable(self):
        from aec.reporting import report

        first = report.serialize_report(
            report.generate_report(simulate().to_dict()))
        second = report.serialize_report(
            report.generate_report(simulate().to_dict()))
        self.assertEqual(first, second)

    def test_summary_stable(self):
        first = simulate().to_dict()
        second = simulate().to_dict()
        self.assertEqual(
            first["completion_summary"], second["completion_summary"]
        )


class TestInvariants(unittest.TestCase):
    def test_lifecycle_states_follow_valid_path(self):
        from aec.orchestrator.models import STATES

        run = simulate()
        order = {state: index for index, state in enumerate(STATES)}
        for case in run.cases:
            visited = [
                item["state"] for item in run.state_reasons
                if item["case_id"] == case["case_id"]
            ]
            indexes = [order[state] for state in visited]
            self.assertEqual(indexes, sorted(indexes))
            self.assertEqual(len(set(indexes)), len(indexes))

    def test_no_evidence_ready_without_evidence(self):
        run = simulate()
        for case in run.cases:
            self.assertNotIn(
                case["evidence_state"], ("EVIDENCE_READY", "EVIDENCE_PARTIAL")
            )
        for state in run.evidence_states.values():
            self.assertEqual(state, "WAITING_EVIDENCE")

    def test_no_conclusion_vocabulary_in_outputs(self):
        run = simulate()
        blob = json.dumps(run.to_dict())
        for word in FORBIDDEN_OUTPUT_WORDS:
            self.assertNotIn(word, blob, word)

    def test_no_severity_vocabulary_in_outputs(self):
        run = simulate()
        blob = json.dumps(run.to_dict()).lower()
        self.assertNotIn("severity", blob)
        self.assertNotIn("cvss", blob)

    def test_no_secret_shaped_values_in_outputs(self):
        import re
        from aec.coordinator import fixtures

        # Only hex digests the system itself mints (snapshots, hashes)
        # may run long; anything else opaque is refused.
        for blob in (
            json.dumps(simulate().to_dict()),
            json.dumps(list(fixtures.CANDIDATES)),
        ):
            for match in re.finditer(r"[A-Za-z0-9_-]{40,}", blob):
                self.assertIsNotNone(
                    re.fullmatch(r"[0-9a-f]+", match.group(0)),
                    match.group(0)[:20],
                )

    def test_fixture_not_mutated_by_run(self):
        from aec.coordinator import fixtures
        from aec.coordinator import pipeline

        before = copy.deepcopy(list(fixtures.CANDIDATES))
        pipeline.run_research(list(fixtures.CANDIDATES))
        self.assertEqual(list(fixtures.CANDIDATES), before)

    def test_audit_complete_for_every_case(self):
        run = simulate()
        for case in run.cases:
            reasons = [
                item for item in run.state_reasons
                if item["case_id"] == case["case_id"]
            ]
            self.assertGreaterEqual(len(reasons), 1)
            states = {item["state"] for item in reasons}
            self.assertIn(case["state"], states)
            if case["state"] != "WAITING_EVIDENCE":
                # Cases that never left SELECTED must explain why via
                # a recorded failure linked to their candidate.
                self.assertTrue(
                    any(failure["ref"] in (case["candidate_id"], case["case_id"])
                        for failure in run.failures),
                    case["case_id"],
                )

    def test_every_failure_has_ref_and_detail(self):
        run = simulate()
        for failure in run.failures:
            self.assertTrue(failure["ref"])
            self.assertTrue(failure["kind"])
            self.assertTrue(failure["detail"])

    def test_every_review_item_has_action(self):
        run = simulate()
        for item in run.review_items:
            self.assertTrue(item["recommended_next_action"])

    def test_new_packages_have_no_network_imports(self):
        for package in NEW_PACKAGES:
            for path in (AEC_DIR / package).glob("*.py"):
                tree = ast.parse(path.read_text())
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(a.name.split(".")[0] for a in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imported.add(node.module.split(".")[0])
                self.assertLessEqual(
                    imported & NETWORK_MODULES, set(), path.name
                )


class TestSimulationPins(unittest.TestCase):
    def test_exact_simulation_counts(self):
        run = simulate()
        self.assertEqual(run.candidates_processed, 21)
        self.assertEqual(len(run.cases_created), 18)
        self.assertEqual(len(run.cases_skipped), 1)
        self.assertEqual(len(run.plans_generated), 17)
        self.assertEqual(len(run.failures), 3)

    def test_authorization_outcomes(self):
        run = simulate()
        allows = [case for case, state in run.authorization_states.items()
                  if state == "ALLOW"]
        self.assertEqual(len(allows), 17)
        self.assertNotIn("REFUSE", set(run.authorization_states.values()))

    def test_failure_kinds_exact(self):
        run = simulate()
        self.assertEqual(
            sorted(failure["kind"] for failure in run.failures),
            ["INVALID_DRAFT", "MALFORMED_CANDIDATE", "UNSUPPORTED_CATEGORY"],
        )

    def test_post_entry_fails_with_method_detail(self):
        run = simulate()
        draft_failure = next(
            failure for failure in run.failures
            if failure["kind"] == "INVALID_DRAFT"
        )
        self.assertIn("UNSUPPORTED_METHOD", draft_failure["detail"])

    def test_unknown_category_detail(self):
        run = simulate()
        failure = next(
            item for item in run.failures
            if item["kind"] == "UNSUPPORTED_CATEGORY"
        )
        self.assertIn("UNKNOWN_CATEGORY", failure["detail"])

    def test_malformed_ref_is_positional(self):
        run = simulate()
        failure = next(
            item for item in run.failures
            if item["kind"] == "MALFORMED_CANDIDATE"
        )
        self.assertEqual(failure["ref"], "input[20]")

    def test_skip_ref_matches_first_candidate(self):
        run = simulate()
        self.assertEqual(run.cases_skipped[0]["ref"], run.cases_created[0])

    def test_specialists_exact_set(self):
        run = simulate()
        self.assertEqual(
            {case["specialist"] for case in run.cases},
            {"authorization-researcher", "input-researcher",
             "server-researcher", "technology-researcher"},
        )

    def test_technology_cases_staffed_technical(self):
        run = simulate()
        for case in run.cases:
            if case["technology"]:
                self.assertEqual(case["specialist"], "technology-researcher")

    def test_bands_present(self):
        run = simulate()
        bands = {case["band"] for case in run.cases}
        self.assertLessEqual(bands, {"LOW", "MEDIUM", "HIGH"})
        self.assertTrue(bands)

    def test_queue_total_matches_cases(self):
        run = simulate()
        self.assertIsNotNone(run.queue_snapshot)
        self.assertEqual(run.queue_snapshot["total"], len(run.cases_created))

    def test_review_reasons_distribution(self):
        from collections import Counter

        run = simulate()
        counts = Counter(item["reason"] for item in run.review_items)
        self.assertEqual(counts["EVIDENCE_INCOMPLETE"], 17)
        self.assertEqual(counts["DRAFT_INVALID"], 1)

    def test_completion_summary_exact(self):
        run = simulate()
        summary = run.completion_summary
        self.assertEqual(summary["candidates_processed"], 21)
        self.assertEqual(summary["cases_created"], 18)
        self.assertEqual(summary["cases_skipped"], 1)
        self.assertEqual(summary["plans_generated"], 17)
        self.assertEqual(summary["authorizations"], {"ALLOW": 17, "REFUSE": 0})
        self.assertEqual(summary["review_items"], 18)
        self.assertEqual(summary["failures"], 3)

    def test_run_id_shape(self):
        run = simulate()
        self.assertTrue(run.run_id.startswith("run-"))
        self.assertEqual(len(run.run_id), 16)
        self.assertEqual(len(run.input_snapshot), 64)

    def test_each_clean_category_allows(self):
        run = simulate()
        by_category: dict[str, list[str]] = {}
        for case in run.cases:
            by_category.setdefault(case["category"], []).append(case["case_id"])
        for category in ("idor", "xss", "ssrf", "file_upload", "authz"):
            self.assertIn(category, by_category, category)
            for case_id in by_category[category]:
                state = run.authorization_states.get(case_id)
                if state is None:
                    # The POST entry compiles no draft, so it never
                    # reaches the gate; every gated case allows.
                    self.assertEqual(
                        next(item for item in run.cases
                             if item["case_id"] == case_id)["state"],
                        "SELECTED",
                    )
                else:
                    self.assertEqual(state, "ALLOW", case_id)

    def test_queue_snapshot_id_stable(self):
        first = simulate().queue_snapshot or {}
        second = simulate().queue_snapshot or {}
        self.assertEqual(first.get("snapshot_id"), second.get("snapshot_id"))

    def test_post_case_stays_selected(self):
        run = simulate()
        draft_failure = next(
            failure for failure in run.failures
            if failure["kind"] == "INVALID_DRAFT"
        )
        case = next(
            item for item in run.cases
            if item["candidate_id"] == draft_failure["ref"]
        )
        self.assertEqual(case["state"], "SELECTED")
        self.assertEqual(case["plan_id"], "")


    def test_clean_case_visits_four_states(self):
        run = simulate()
        case = next(
            item for item in run.cases if item["state"] == "WAITING_EVIDENCE"
        )
        visited = [
            item["state"] for item in run.state_reasons
            if item["case_id"] == case["case_id"]
        ]
        self.assertEqual(
            visited,
            ["SELECTED", "PLANNED", "AUTHORIZED_PLAN", "WAITING_EVIDENCE"],
        )

    def test_queue_entries_ranked(self):
        run = simulate()
        assert run.queue_snapshot is not None
        ranks = [entry["rank"] for entry in run.queue_snapshot["entries"]]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))

    def test_queue_generated_from_sorted(self):
        run = simulate()
        assert run.queue_snapshot is not None
        generated = run.queue_snapshot["generated_from"]
        self.assertEqual(generated, sorted(generated))

    def test_run_items_validate_as_review(self):
        from aec.review import queue

        run = simulate()
        for fields in run.review_items:
            built = queue.build_review_item(fields)
            self.assertTrue(built.case_id)

    def test_report_actions_match_review(self):
        from aec.reporting import report

        run = simulate()
        generated = report.generate_report(run.to_dict())
        expected = {
            (item["case_id"], item["recommended_next_action"])
            for item in run.review_items
        }
        actual = {
            (step["case_id"], step["action"]) for step in generated.next_steps
        }
        self.assertEqual(actual, expected)

    def test_fixture_category_counts(self):
        from collections import Counter
        from aec.coordinator import fixtures

        counts = Counter(
            str(item.get("category", "")).lower().replace("_candidate", "")
            for item in fixtures.CANDIDATES
        )
        self.assertGreaterEqual(counts["idor"], 5)
        self.assertGreaterEqual(counts["xss"], 3)
        self.assertGreaterEqual(counts["ssrf"], 3)
        self.assertGreaterEqual(counts["file_upload"], 2)
        self.assertGreaterEqual(counts["authz"], 1)

    def test_fixture_methods(self):
        from aec.coordinator import fixtures

        methods = {str(item.get("method", "")) for item in fixtures.CANDIDATES}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_all_cases_have_scores(self):
        run = simulate()
        for case in run.cases:
            self.assertIsInstance(case["score"], int)
            self.assertGreaterEqual(case["score"], 0)

    def test_all_cases_have_specialists(self):
        from aec.coordinator.specialists import SPECIALISTS

        run = simulate()
        for case in run.cases:
            self.assertIn(case["specialist"], SPECIALISTS)

    def test_case_ids_unique(self):
        run = simulate()
        ids = [case["case_id"] for case in run.cases]
        self.assertEqual(len(ids), len(set(ids)))


    def test_evidence_dict_exact(self):
        run = simulate()
        self.assertEqual(
            run.completion_summary["evidence"], {"WAITING_EVIDENCE": 17}
        )

    def test_review_case_ids_subset_of_created(self):
        run = simulate()
        created = set(run.cases_created)
        for item in run.review_items:
            self.assertIn(item["case_id"], created)

    def test_report_missing_has_first_observation(self):
        from aec.reporting import report

        generated = report.generate_report(simulate().to_dict())
        self.assertIn("initial-observation", generated.missing_evidence)

    def test_report_blocked_kinds_match(self):
        from aec.reporting import report

        run = simulate()
        generated = report.generate_report(run.to_dict())
        self.assertEqual(
            {item["kind"] for item in generated.blocked_actions},
            {failure["kind"] for failure in run.failures},
        )

    def test_fixture_urls_are_relative(self):
        from aec.coordinator import fixtures

        for candidate in fixtures.CANDIDATES:
            self.assertNotIn("://", str(candidate.get("url", "")))

    def test_processed_matches_fixture(self):
        from aec.coordinator import fixtures

        run = simulate()
        self.assertEqual(run.candidates_processed, len(fixtures.CANDIDATES))

    def test_queue_entries_have_scores(self):
        run = simulate()
        assert run.queue_snapshot is not None
        for entry in run.queue_snapshot["entries"]:
            self.assertIsInstance(entry["score"], int)


if __name__ == "__main__":
    unittest.main()

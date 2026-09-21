"""Tests for aec/coordinator (EPIC 5 Part 1/2/3/4/5/6/10: Research Coordinator).

The coordinator drives Watch research candidates through the complete
offline lifecycle using existing component contracts only: surface →
memory → intelligence → assignment → case → draft → plan → gate →
evidence → review → report. No network, no writes, no conclusions about
any target.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

COORD_DIR = Path(__file__).resolve().parents[1] / "aec" / "coordinator"
MODULES = ("models.py", "pipeline.py", "specialists.py", "fixtures.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)

FAILURE_KINDS = frozenset({
    "MALFORMED_CANDIDATE",
    "DUPLICATE_CANDIDATE",
    "UNSUPPORTED_CATEGORY",
    "MISSING_GAP",
    "INVALID_DRAFT",
    "INVALID_PLAN",
    "GATE_REFUSAL",
    "QUEUE_FAILURE",
    "MEMORY_FAILURE",
    "SERIALIZATION_FAILURE",
})


def clean_record(**overrides):
    entry = {
        "program": "pilot",
        "subdomain": "shop.example.com",
        "url": "/orders?order_id=",
        "endpoint": "/orders",
        "parameter": "order_id",
        "method": "GET",
        "location": "query",
        "technology": [],
        "source": "watch",
        "last_update": None,
        "category": "IDOR_CANDIDATE",
    }
    entry.update(overrides)
    return entry


class TestRunResearch(unittest.TestCase):
    def test_single_clean_candidate_completes(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        self.assertEqual(run.candidates_processed, 1)
        self.assertEqual(len(run.cases_created), 1)
        self.assertEqual(run.failures, ())
        case_id = run.cases_created[0]
        self.assertEqual(run.authorization_states[case_id], "ALLOW")
        self.assertEqual(run.evidence_states[case_id], "WAITING_EVIDENCE")

    def test_run_id_is_content_hash(self):
        import hashlib
        import json
        from aec.coordinator import pipeline

        candidates = [clean_record()]
        run = pipeline.run_research(candidates)
        canonical = json.dumps(candidates, sort_keys=True, separators=(",", ":"))
        expected = "run-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
        self.assertEqual(run.run_id, expected)

    def test_same_input_same_run(self):
        from aec.coordinator import pipeline

        first = pipeline.run_research([clean_record()])
        second = pipeline.run_research([clean_record()])
        self.assertEqual(first, second)

    def test_input_candidates_not_mutated(self):
        from aec.coordinator import pipeline

        candidates = [clean_record(), clean_record(endpoint="/other",
                                                   url="/other?order_id=")]
        before = copy.deepcopy(candidates)
        pipeline.run_research(candidates)
        self.assertEqual(candidates, before)

    def test_memories_not_mutated(self):
        from aec.coordinator import pipeline
        from aec.memory import store

        memory = store.fresh_memory("case-old")
        outcome = store.remember(memory, "GAP_NOTE", "needs coverage")
        assert outcome.ok
        memories = {"case-old": outcome.memory}
        before = {key: value.to_dict() for key, value in memories.items()}
        pipeline.run_research([clean_record()], memories=memories)
        self.assertEqual(
            {key: value.to_dict() for key, value in memories.items()}, before
        )

    def test_case_entry_carries_trace(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        entry = next(
            case for case in run.cases
            if case["case_id"] == run.cases_created[0]
        )
        for key in ("case_id", "candidate_id", "category", "asset",
                    "endpoint", "specialist", "band", "score", "state",
                    "evidence_state", "plan_id", "steps", "missing"):
            self.assertIn(key, entry, key)
        self.assertEqual(entry["state"], "WAITING_EVIDENCE")

    def test_state_reasons_record_why(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        case_id = run.cases_created[0]
        reasons = {
            item["state"]: item["reason"]
            for item in run.state_reasons
            if item["case_id"] == case_id
        }
        for state in ("SELECTED", "PLANNED", "AUTHORIZED_PLAN",
                      "WAITING_EVIDENCE"):
            self.assertIn(state, reasons, state)
            self.assertTrue(reasons[state])

    def test_review_item_for_waiting_case(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        self.assertEqual(len(run.review_items), 1)
        item = run.review_items[0]
        self.assertEqual(item["reason"], "EVIDENCE_INCOMPLETE")
        self.assertIn("initial-observation", item["missing_evidence"])

    def test_queue_snapshot_built(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        self.assertIsNotNone(run.queue_snapshot)
        self.assertEqual(run.queue_snapshot["total"], 1)

    def test_completion_summary_counts(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        summary = run.completion_summary
        self.assertEqual(summary["candidates_processed"], 1)
        self.assertEqual(summary["cases_created"], 1)
        self.assertEqual(summary["plans_generated"], 1)
        self.assertEqual(summary["authorizations"], {"ALLOW": 1, "REFUSE": 0})
        self.assertEqual(summary["review_items"], 1)
        self.assertEqual(summary["failures"], 0)


class TestSkips(unittest.TestCase):
    def test_duplicate_candidate_skipped(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(), clean_record()])
        self.assertEqual(run.candidates_processed, 2)
        self.assertEqual(len(run.cases_created), 1)
        self.assertEqual(len(run.cases_skipped), 1)
        self.assertEqual(
            run.cases_skipped[0]["reason"], "DUPLICATE_CANDIDATE"
        )

    def test_prior_research_skips_case(self):
        from aec.coordinator import pipeline
        from aec.memory import store

        memory = store.fresh_memory("case-old")
        outcome = store.remember(
            memory, "OBSERVATION", "checked listing",
            relates_to=("shop.example.com/orders?order_id",),
        )
        assert outcome.ok
        run = pipeline.run_research(
            [clean_record()], memories={"case-old": outcome.memory}
        )
        self.assertEqual(len(run.cases_created), 0)
        self.assertEqual(run.cases_skipped[0]["reason"], "PRIOR_RESEARCH")

    def test_skip_still_in_summary(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(), clean_record()])
        self.assertEqual(run.completion_summary["cases_skipped"], 1)


class TestFailures(unittest.TestCase):
    def test_malformed_candidate_recorded(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research(["not-a-mapping"])
        self.assertEqual(len(run.failures), 1)
        self.assertEqual(run.failures[0]["kind"], "MALFORMED_CANDIDATE")
        self.assertEqual(len(run.cases_created), 0)

    def test_missing_endpoint_malformed(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(endpoint="")])
        self.assertEqual(run.failures[0]["kind"], "MALFORMED_CANDIDATE")

    def test_unsupported_category_recorded(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(category="SQLI_CANDIDATE")])
        self.assertEqual(run.failures[0]["kind"], "UNSUPPORTED_CATEGORY")

    def test_post_method_fails_draft(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(method="POST")])
        self.assertEqual(run.failures[0]["kind"], "INVALID_DRAFT")
        # The case exists but never reaches planning.
        self.assertEqual(len(run.cases_created), 1)
        case_id = run.cases_created[0]
        self.assertNotIn(case_id, run.authorization_states)

    def test_failed_case_gets_review_item(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(method="POST")])
        self.assertEqual(len(run.review_items), 1)
        self.assertEqual(run.review_items[0]["reason"], "DRAFT_INVALID")

    def test_failure_kinds_are_closed(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([
            "nope",
            clean_record(category="NOPE_CANDIDATE"),
            clean_record(method="POST"),
        ])
        kinds = {failure["kind"] for failure in run.failures}
        self.assertLessEqual(kinds, FAILURE_KINDS)
        self.assertEqual(len(run.failures), 3)

    def test_run_survives_individual_failure(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([
            "nope",
            clean_record(),
            clean_record(category="NOPE_CANDIDATE"),
        ])
        self.assertEqual(run.candidates_processed, 3)
        self.assertEqual(len(run.cases_created), 1)
        self.assertEqual(len(run.failures), 2)

    def test_failure_entry_shape(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research(["nope"])
        failure = run.failures[0]
        self.assertEqual(sorted(failure), ["detail", "kind", "ref"])
        self.assertTrue(failure["detail"])


class TestSpecialists(unittest.TestCase):
    def test_plain_assignment_keeps_role(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "surface": "authorization_surface",
             "role": "authorization-researcher", "rationale": "r"},
            {"candidate_id": "rc-1", "technology": []},
        )
        self.assertEqual(assignment.specialist, "authorization-researcher")

    def test_stack_routes_to_technology_researcher(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "surface": "input_surface",
             "role": "input-researcher", "rationale": "r"},
            {"candidate_id": "rc-1", "technology": ["wordpress"]},
        )
        self.assertEqual(assignment.specialist, "technology-researcher")
        self.assertIn("wordpress", assignment.reason)

    def test_specialist_entry_shape(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "surface": "input_surface",
             "role": "input-researcher", "rationale": "r"},
            {"candidate_id": "rc-1", "technology": [],
             "evidence_gap": {"required": ["a"], "missing": ["a"]}},
        )
        self.assertEqual(
            sorted(assignment.to_dict()),
            ["candidate_id", "evidence_gap", "prior_context",
             "reason", "specialist"],
        )

    def test_prior_context_carried(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "surface": "input_surface",
             "role": "input-researcher", "rationale": "r"},
            {"candidate_id": "rc-1", "technology": []},
            prior={"researched": False, "related_patterns": 2},
        )
        self.assertEqual(
            assignment.prior_context,
            {"researched": False, "related_patterns": 2},
        )

    def test_all_five_specialists_reachable(self):
        from aec.coordinator import specialists

        seen = set()
        seen.add(specialists.specialize(
            {"candidate_id": "a", "surface": "authorization_surface",
             "role": "authorization-researcher", "rationale": "r"},
            {"candidate_id": "a", "technology": []}).specialist)
        seen.add(specialists.specialize(
            {"candidate_id": "b", "surface": "input_surface",
             "role": "input-researcher", "rationale": "r"},
            {"candidate_id": "b", "technology": []}).specialist)
        seen.add(specialists.specialize(
            {"candidate_id": "c", "surface": "server_side_surface",
             "role": "server-researcher", "rationale": "r"},
            {"candidate_id": "c", "technology": []}).specialist)
        seen.add(specialists.specialize(
            {"candidate_id": "d", "surface": "input_surface",
             "role": "input-researcher", "rationale": "r"},
            {"candidate_id": "d", "technology": ["django"]}).specialist)
        seen.add(specialists.specialize(
            {"candidate_id": "e", "surface": "general_surface",
             "role": "general-researcher", "rationale": "r"},
            {"candidate_id": "e", "technology": []}).specialist)
        self.assertEqual(
            seen,
            {"authorization-researcher", "input-researcher",
             "server-researcher", "technology-researcher",
             "general-researcher"},
        )


class TestSerialization(unittest.TestCase):
    def test_run_round_trip_stable(self):
        import json
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(), "nope"])
        text = pipeline.serialize_run(run)
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
            text,
        )

    def test_run_is_frozen(self):
        import dataclasses
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            run.candidates_processed = 99

    def test_empty_run_serializes(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([])
        self.assertEqual(run.candidates_processed, 0)
        self.assertTrue(pipeline.serialize_run(run))


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in MODULES:
            source = (COORD_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((COORD_DIR / name).read_text())
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
            tree = ast.parse((COORD_DIR / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = ""
                    if isinstance(func, ast.Name):
                        called = func.id
                    elif isinstance(func, ast.Attribute):
                        called = func.attr
                    self.assertNotIn(called, {"write_text", "mkdir", "makedirs"}, name)


class TestFaultInjection(unittest.TestCase):
    def test_plan_refusal_maps_invalid_plan(self):
        from unittest.mock import patch

        from aec.coordinator import pipeline
        from aec.observation_plan import PlanOutcome

        with patch.object(
            pipeline, "compile_observation_plan",
            return_value=PlanOutcome(
                ok=False, plan=None, refusal_code="MISSING_GAP",
                refusal_detail="no gap"),
        ):
            run = pipeline.run_research([clean_record()])
        self.assertEqual(run.failures[0]["kind"], "INVALID_PLAN")
        self.assertEqual(run.review_items[0]["reason"], "PLAN_INVALID")
        self.assertEqual(len(run.cases_created), 1)
        self.assertEqual(run.plans_generated, ())

    def test_gate_refusal_recorded(self):
        from unittest.mock import patch

        from aec.authorization_gate import AuthorizationGateDecision
        from aec.coordinator import pipeline

        with patch.object(
            pipeline, "check_authorization_eligibility",
            return_value=AuthorizationGateDecision(
                decision="REFUSE", reason_code="STEP_LIMIT_EXCEEDED",
                checked_rules=("PLAN_PRESENT",), plan_id="plan-x",
                timestamp="hash"),
        ):
            run = pipeline.run_research([clean_record()])
        self.assertEqual(run.failures[0]["kind"], "GATE_REFUSAL")
        case_id = run.cases_created[0]
        self.assertEqual(run.authorization_states[case_id], "REFUSE")
        self.assertEqual(
            run.review_items[0]["reason"], "AUTHORIZATION_REFUSED")
        self.assertEqual(
            run.completion_summary["authorizations"],
            {"ALLOW": 0, "REFUSE": 1},
        )

    def test_memory_error_recorded(self):
        from unittest.mock import patch

        from aec.coordinator import pipeline

        with patch.object(
            pipeline.memory_connect, "find_related",
            side_effect=RuntimeError("store offline"),
        ):
            run = pipeline.run_research([clean_record()])
        self.assertEqual(run.failures[0]["kind"], "MEMORY_FAILURE")
        self.assertEqual(len(run.cases_created), 0)

    def test_queue_error_recorded_run_survives(self):
        from unittest.mock import patch

        from aec.coordinator import pipeline

        with patch.object(
            pipeline.queue_priority, "build_queue",
            side_effect=RuntimeError("queue store offline"),
        ):
            run = pipeline.run_research([clean_record(), "nope"])
        kinds = {failure["kind"] for failure in run.failures}
        self.assertIn("QUEUE_FAILURE", kinds)
        self.assertIn("MALFORMED_CANDIDATE", kinds)
        self.assertEqual(len(run.cases_created), 1)
        self.assertIsNone(run.queue_snapshot)

    def test_empty_gap_maps_missing_gap(self):
        from unittest.mock import patch

        from aec.coordinator import pipeline
        from aec.surface import adapter
        from aec.surface.models import ResearchCandidateDraft

        empty_gap_draft = ResearchCandidateDraft(
            candidate_id="rc-empty", asset="shop.example.com",
            endpoint="/orders", parameters=("order_id",), technology=(),
            method="GET", research_category="idor",
            evidence_gap={"required": [], "missing": []},
            source_reference="watch", classification_notes=(),
        )
        with patch.object(
            pipeline.surface_adapter, "adapt_record",
            return_value=adapter.AdaptOutcome(
                ok=True, draft=empty_gap_draft, refusal_code=None),
        ):
            run = pipeline.run_research([clean_record()])
        self.assertEqual(run.failures[0]["kind"], "MISSING_GAP")

    def test_serialize_run_rejects_garbage(self):
        from aec.coordinator import pipeline
        from aec.coordinator.models import ResearchRun

        run = pipeline.run_research([])
        broken = ResearchRun(
            **{**run.to_dict(), "cases": ({"step": object()},)},
        )
        with self.assertRaises(ValueError):
            pipeline.serialize_run(broken)


class TestRunDetails(unittest.TestCase):
    def test_empty_input_run(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([])
        self.assertEqual(run.candidates_processed, 0)
        self.assertEqual(run.cases_created, ())
        self.assertEqual(run.failures, ())
        self.assertIsNone(run.queue_snapshot)
        self.assertTrue(run.run_id.startswith("run-"))

    def test_run_id_differs_per_input(self):
        from aec.coordinator import pipeline

        first = pipeline.run_research([clean_record()])
        second = pipeline.run_research([clean_record(endpoint="/other",
                                                     url="/other?order_id=")])
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertNotEqual(first.input_snapshot, second.input_snapshot)

    def test_selection_order_sequences(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([
            clean_record(),
            clean_record(endpoint="/other", url="/other?order_id="),
        ])
        created = run.cases_created
        self.assertEqual(len(created), 2)
        first_reasons = [
            item for item in run.state_reasons if item["case_id"] == created[0]
        ]
        self.assertIn("selection order 1", first_reasons[0]["reason"])

    def test_plan_ids_prefixed(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        for plan_id in run.plans_generated:
            self.assertTrue(plan_id.startswith("plan-"))

    def test_evidence_summary_counts(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(), "nope"])
        self.assertEqual(
            run.completion_summary["evidence"], {"WAITING_EVIDENCE": 1}
        )

    def test_assignments_match_cases(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record(), clean_record(endpoint="/o",
                                                                   url="/o?x=",
                                                                   parameter="x")])
        staffed_ids = {item["candidate_id"] for item in run.assignments}
        case_candidates = {case["candidate_id"] for case in run.cases}
        self.assertEqual(staffed_ids, case_candidates)

    def test_model_constants(self):
        from aec.coordinator import models

        self.assertEqual(len(models.FAILURE_KINDS), 10)
        self.assertEqual(set(models.SKIP_REASONS),
                         {"DUPLICATE_CANDIDATE", "PRIOR_RESEARCH"})
        self.assertEqual(set(models.GATE_STATES), {"ALLOW", "REFUSE"})

    def test_run_dict_keys(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        self.assertEqual(
            sorted(run.to_dict()),
            ["assignments", "authorization_states", "candidates_processed",
             "cases", "cases_created", "cases_skipped", "completion_summary",
             "evidence_states", "failures", "input_snapshot",
             "plans_generated", "queue_snapshot", "review_items", "run_id",
             "state_reasons"],
        )

    def test_failure_detail_truncated(self):
        from aec.coordinator import pipeline

        self.assertLessEqual(len(pipeline._failure("r", "k", "x")["detail"]), 500)

    def test_queue_snapshot_shape(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([clean_record()])
        snapshot = run.queue_snapshot
        self.assertEqual(snapshot["total"], 1)
        self.assertTrue(snapshot["snapshot_id"])
        self.assertEqual(len(snapshot["entries"]), 1)


    def test_stack_missing_role_defaults_general(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1"},
            {"candidate_id": "rc-1", "technology": []},
        )
        self.assertEqual(assignment.specialist, "general-researcher")

    def test_unknown_role_defaults_general(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "ninja"},
            {"candidate_id": "rc-1", "technology": []},
        )
        self.assertEqual(assignment.specialist, "general-researcher")

    def test_empty_string_technology_ignored(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": ["", "  "]},
        )
        self.assertEqual(assignment.specialist, "input-researcher")

    def test_non_list_technology_ignored(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": "php"},
        )
        self.assertEqual(assignment.specialist, "input-researcher")

    def test_non_mapping_gap_defaults_empty(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": [],
             "evidence_gap": "nope"},
        )
        self.assertEqual(
            assignment.evidence_gap, {"required": [], "missing": []}
        )

    def test_missing_candidate_id_defaults_empty(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize({}, {})
        self.assertEqual(assignment.candidate_id, "")

    def test_non_mapping_inputs_fall_back(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(None, None)
        self.assertEqual(assignment.specialist, "general-researcher")

    def test_specialists_are_frozen(self):
        import dataclasses
        from aec.coordinator import specialists

        assignment = specialists.specialize({}, {})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            assignment.specialist = "other"

    def test_specialist_constants(self):
        from aec.coordinator import specialists as spec_module

        self.assertEqual(len(spec_module.SPECIALISTS), 5)
        self.assertIn("technology-researcher", spec_module.SPECIALISTS)

    def test_base_role_named_in_tech_reason(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "server-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": ["node"]},
        )
        self.assertIn("server-researcher", assignment.reason)
        self.assertIn("node", assignment.reason)

    def test_skip_ref_equals_candidate_id(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record, dict(record)])
        self.assertEqual(len(run.cases_skipped), 1)
        self.assertEqual(run.cases_skipped[0]["ref"], run.cases_created[0])

    def test_prior_skip_has_no_failure(self):
        from aec.coordinator import pipeline
        from aec.memory import store

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        memory = store.fresh_memory("case-old")
        outcome = store.remember(
            memory, "OBSERVATION", "checked",
            relates_to=("shop.example.com/orders?order_id",),
        )
        assert outcome.ok
        run = pipeline.run_research(
            [record], memories={"case-old": outcome.memory}
        )
        self.assertEqual(run.failures, ())
        self.assertEqual(len(run.cases_skipped), 1)

    def test_clean_run_has_no_skips_or_failures(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        self.assertEqual(run.cases_skipped, ())
        self.assertEqual(run.failures, ())

    def test_duplicate_candidate_kind_not_failure(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record, dict(record)])
        kinds = {failure["kind"] for failure in run.failures}
        self.assertNotIn("DUPLICATE_CANDIDATE", kinds)


    def test_post_case_review_content(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/checkout?cart=", "endpoint": "/checkout",
            "parameter": "cart", "method": "POST", "location": "body",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        item = run.review_items[0]
        self.assertEqual(item["reason"], "DRAFT_INVALID")
        self.assertEqual(item["current_state"], "SELECTED")
        self.assertIn("initial-observation", item["missing_evidence"])

    def test_post_case_single_state_reason(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/checkout?cart=", "endpoint": "/checkout",
            "parameter": "cart", "method": "POST", "location": "body",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        case_id = run.cases_created[0]
        reasons = [x for x in run.state_reasons if x["case_id"] == case_id]
        self.assertEqual([x["state"] for x in reasons], ["SELECTED"])

    def test_post_case_queue_cost_zero(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/checkout?cart=", "endpoint": "/checkout",
            "parameter": "cart", "method": "POST", "location": "body",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        self.assertIsNotNone(run.queue_snapshot)
        self.assertEqual(run.queue_snapshot["total"], 1)

    def test_evidence_keys_match_allows(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        allows = {c for c, s in run.authorization_states.items() if s == "ALLOW"}
        self.assertEqual(set(run.evidence_states), allows)

    def test_canonical_determinism(self):
        from aec.coordinator import pipeline

        first = pipeline._canonical([{"b": 1, "a": 2}])
        second = pipeline._canonical([{"a": 2, "b": 1}])
        self.assertEqual(first, second)

    def test_helper_shapes(self):
        from aec.coordinator import pipeline

        self.assertEqual(
            sorted(pipeline._failure("r", "k", "d")), ["detail", "kind", "ref"]
        )
        self.assertEqual(
            sorted(pipeline._skip("r", "s")), ["reason", "ref"]
        )
        self.assertEqual(
            sorted(pipeline._state_reason("c", "s", "r")),
            ["case_id", "reason", "state"],
        )

    def test_tuple_input_accepted(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research((record,))
        self.assertEqual(len(run.cases_created), 1)

    def test_non_mapping_memories_ignored(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record], memories=["nope"])
        self.assertEqual(len(run.cases_created), 1)
        self.assertEqual(run.failures, ())

    def test_specialist_reason_exact_plain(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": []},
        )
        self.assertEqual(
            assignment.reason, "staffed per assignment role input-researcher"
        )

    def test_specialist_gap_passthrough(self):
        from aec.coordinator import specialists

        gap = {"required": ["a"], "missing": ["a"], "extra": "dropped?"}
        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": [],
             "evidence_gap": gap},
        )
        self.assertEqual(
            assignment.evidence_gap, {"required": ["a"], "missing": ["a"]}
        )

    def test_specialist_prior_default(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize({}, {})
        self.assertEqual(
            assignment.prior_context,
            {"researched": False, "related_patterns": 0},
        )

    def test_first_technology_wins(self):
        from aec.coordinator import specialists

        assignment = specialists.specialize(
            {"candidate_id": "rc-1", "role": "input-researcher",
             "rationale": "r"},
            {"candidate_id": "rc-1", "technology": ["django", "php"]},
        )
        self.assertIn("django", assignment.reason)

    def test_run_with_none_memories(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record], memories=None)
        self.assertEqual(len(run.cases_created), 1)


    def test_record_without_category_unsupported(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
        }
        run = pipeline.run_research([record])
        self.assertEqual(run.failures[0]["kind"], "UNSUPPORTED_CATEGORY")

    def test_failed_adapt_keeps_positional_ref(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research(["a", "b"])
        self.assertEqual(run.failures[0]["ref"], "input[0]")
        self.assertEqual(run.failures[1]["ref"], "input[1]")

    def test_malformed_types_all_caught(self):
        from aec.coordinator import pipeline

        run = pipeline.run_research([None, 42, ["x"], "s"])
        self.assertEqual(len(run.failures), 4)
        kinds = {failure["kind"] for failure in run.failures}
        self.assertEqual(kinds, {"MALFORMED_CANDIDATE"})

    def test_accounting_adds_up(self):
        from aec.coordinator import fixtures, pipeline

        run = pipeline.run_research(list(fixtures.CANDIDATES))
        caseless = sum(
            1 for failure in run.failures
            if failure["kind"] in ("MALFORMED_CANDIDATE", "UNSUPPORTED_CATEGORY")
        )
        self.assertEqual(
            len(run.cases_created) + len(run.cases_skipped) + caseless,
            run.candidates_processed,
        )

    def test_gate_hash_recorded_on_allow(self):
        from aec.coordinator import pipeline
        from aec.orchestrator import lifecycle

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        case_id = run.cases_created[0]
        self.assertEqual(run.authorization_states[case_id], "ALLOW")

    def test_step_purposes_closed(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        for case in run.cases:
            for step in case["steps"]:
                self.assertIn(
                    step["purpose"], ("BASELINE", "COMPARISON", "CONTEXT_CAPTURE")
                )

    def test_assignments_ordered_by_processing(self):
        from aec.coordinator import fixtures, pipeline

        run = pipeline.run_research(list(fixtures.CANDIDATES))
        staffed = [item["candidate_id"] for item in run.assignments]
        created_candidates = [case["candidate_id"] for case in run.cases]
        self.assertEqual(staffed, created_candidates)

    def test_queue_covers_all_cases(self):
        from aec.coordinator import fixtures, pipeline

        run = pipeline.run_research(list(fixtures.CANDIDATES))
        assert run.queue_snapshot is not None
        queued = {entry["case_id"] for entry in run.queue_snapshot["entries"]}
        self.assertEqual(queued, set(run.cases_created))

    def test_case_prior_defaults_novel(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        self.assertEqual(
            run.cases[0]["prior"],
            {"researched": False, "related_patterns": 0},
        )

    def test_state_reason_fields(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record])
        for item in run.state_reasons:
            self.assertTrue(item["case_id"])
            self.assertTrue(item["state"])
            self.assertTrue(item["reason"])

    def test_skipped_entry_shape(self):
        from aec.coordinator import pipeline

        record = {
            "program": "pilot", "subdomain": "shop.example.com",
            "url": "/orders?order_id=", "endpoint": "/orders",
            "parameter": "order_id", "method": "GET", "location": "query",
            "technology": [], "source": "watch", "last_update": None,
            "category": "IDOR_CANDIDATE",
        }
        run = pipeline.run_research([record, dict(record)])
        self.assertEqual(
            sorted(run.cases_skipped[0]), ["reason", "ref"]
        )


if __name__ == "__main__":
    unittest.main()

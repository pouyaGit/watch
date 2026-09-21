"""Tests for aec/reporting (EPIC 5 Part 8: Research Report).

Deterministic research reports with strict section separation: observed
facts (what the intake records say), planned observations (what the
plans describe), missing evidence (what is still outstanding), analyst
context (prior work), blocked actions (what refused and why), and the
next recommended research step. Reports invent nothing and conclude
nothing.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPORTING_DIR = Path(__file__).resolve().parents[1] / "aec" / "reporting"
MODULES = ("models.py", "report.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)


def run_dict(**overrides):
    run = {
        "run_id": "run-abc123",
        "input_snapshot": "snap",
        "candidates_processed": 2,
        "cases_created": ["case-001"],
        "cases_skipped": [],
        "cases": [
            {
                "case_id": "case-001",
                "candidate_id": "rc-001",
                "category": "idor",
                "asset": "shop.example.com",
                "endpoint": "/orders",
                "parameter": "order_id",
                "technology": ["php"],
                "specialist": "technology-researcher",
                "band": "MEDIUM",
                "score": 45,
                "state": "WAITING_EVIDENCE",
                "evidence_state": "WAITING_EVIDENCE",
                "plan_id": "plan-case-001",
                "steps": [
                    {"step_id": "plan-case-001-s1", "purpose": "BASELINE",
                     "endpoint": "/orders"},
                ],
                "missing": ["initial-observation"],
                "prior": {"researched": False, "related_patterns": 0},
            }
        ],
        "assignments": [],
        "plans_generated": ["plan-case-001"],
        "authorization_states": {"case-001": "ALLOW"},
        "evidence_states": {"case-001": "WAITING_EVIDENCE"},
        "review_items": [
            {
                "case_id": "case-001",
                "reason": "EVIDENCE_INCOMPLETE",
                "current_state": "WAITING_EVIDENCE",
                "evidence_state": "WAITING_EVIDENCE",
                "missing_evidence": ["initial-observation"],
                "research_history": {"duplicates": [], "related_patterns": 0},
                "recommended_next_action": "COLLECT_FIRST_OBSERVATION",
            }
        ],
        "failures": [],
        "state_reasons": [],
        "queue_snapshot": None,
        "completion_summary": {},
    }
    run.update(overrides)
    return run


class TestGenerateReport(unittest.TestCase):
    def test_report_binds_to_run(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(generated.run_id, "run-abc123")
        self.assertTrue(generated.report_id.startswith("report-"))

    def test_observed_facts_only_intake_fields(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        facts = generated.observed_facts[0]
        self.assertEqual(
            sorted(facts),
            ["asset", "case_id", "category", "endpoint", "parameter",
             "technology"],
        )
        self.assertEqual(facts["asset"], "shop.example.com")

    def test_planned_observations_mirror_steps(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        planned = generated.planned_observations[0]
        self.assertEqual(planned["plan_id"], "plan-case-001")
        self.assertEqual(planned["steps"][0]["purpose"], "BASELINE")

    def test_missing_evidence_collected(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertIn("initial-observation", generated.missing_evidence)

    def test_blocked_actions_from_failures(self):
        from aec.reporting import report

        fields = run_dict(failures=[
            {"ref": "rc-9", "kind": "UNSUPPORTED_CATEGORY",
             "detail": "category nope unknown"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(len(generated.blocked_actions), 1)
        self.assertEqual(
            generated.blocked_actions[0]["kind"], "UNSUPPORTED_CATEGORY"
        )

    def test_next_steps_follow_review(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            generated.next_steps[0],
            {"case_id": "case-001",
             "action": "COLLECT_FIRST_OBSERVATION"},
        )

    def test_report_id_deterministic(self):
        from aec.reporting import report

        self.assertEqual(
            report.generate_report(run_dict()).report_id,
            report.generate_report(run_dict()).report_id,
        )

    def test_empty_run_reports_empty_sections(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict(
            cases=[], cases_created=[], review_items=[], plans_generated=[],
            authorization_states={}, evidence_states={},
        ))
        self.assertEqual(generated.observed_facts, ())
        self.assertEqual(generated.next_steps, ())

    def test_report_dict_keys(self):
        from aec.reporting import report

        self.assertEqual(
            sorted(report.generate_report(run_dict()).to_dict()),
            ["blocked_actions", "context", "missing_evidence", "next_steps",
             "observed_facts", "planned_observations", "report_id", "run_id"],
        )

    def test_reports_are_frozen(self):
        import dataclasses
        from aec.reporting import report

        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.generate_report(run_dict()).run_id = "other"

    def test_serialize_stable(self):
        import json
        from aec.reporting import report

        text = report.serialize_report(report.generate_report(run_dict()))
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
            text,
        )

    def test_non_mapping_run_refused(self):
        from aec.reporting import report

        with self.assertRaises(ValueError):
            report.generate_report("nope")


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in MODULES:
            source = (REPORTING_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((REPORTING_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)


class TestReportDetails(unittest.TestCase):
    def test_facts_sorted_by_case_id(self):
        from aec.reporting import report

        fields = run_dict(cases=[
            {**run_dict()["cases"][0], "case_id": "case-zzz",
             "asset": "z.example.com"},
            {**run_dict()["cases"][0], "case_id": "case-aaa",
             "asset": "a.example.com"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(
            [fact["case_id"] for fact in generated.observed_facts],
            ["case-aaa", "case-zzz"],
        )

    def test_missing_union_deduped_sorted(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[
            {**base, "case_id": "case-001", "missing": ["b", "a"]},
            {**base, "case_id": "case-002", "missing": ["a", "c"]},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(generated.missing_evidence, ("a", "b", "c"))

    def test_planned_excludes_planless_cases(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[
            {**base, "case_id": "case-001"},
            {**base, "case_id": "case-002", "plan_id": ""},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(len(generated.planned_observations), 1)
        self.assertEqual(
            generated.planned_observations[0]["case_id"], "case-001"
        )

    def test_context_duplicate_refs_from_skips(self):
        from aec.reporting import report

        fields = run_dict(cases_skipped=[
            {"ref": "rc-dup", "reason": "DUPLICATE_CANDIDATE"},
            {"ref": "rc-old", "reason": "PRIOR_RESEARCH"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(generated.context["duplicate_refs"], ["rc-dup"])

    def test_context_counts_prior_patterns(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[
            {**base, "prior": {"researched": False, "related_patterns": 2}},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(generated.context["related_pattern_count"], 2)

    def test_multiple_blocked_actions(self):
        from aec.reporting import report

        fields = run_dict(failures=[
            {"ref": "a", "kind": "MALFORMED_CANDIDATE", "detail": "x"},
            {"ref": "b", "kind": "GATE_REFUSAL", "detail": "y"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(len(generated.blocked_actions), 2)

    def test_no_failures_no_blocked(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(generated.blocked_actions, ())

    def test_next_steps_follow_review_order(self):
        from aec.reporting import report

        fields = run_dict(review_items=[
            {**run_dict()["review_items"][0], "case_id": "case-002",
             "recommended_next_action": "HUMAN_TRIAGE"},
            run_dict()["review_items"][0],
        ])
        generated = report.generate_report(fields)
        self.assertEqual(
            [step["case_id"] for step in generated.next_steps],
            ["case-002", "case-001"],
        )

    def test_report_id_changes_with_content(self):
        from aec.reporting import report

        first = report.generate_report(run_dict())
        fields = run_dict(run_id="run-other")
        second = report.generate_report(fields)
        self.assertNotEqual(first.report_id, second.report_id)

    def test_full_pipeline_report_sections(self):
        from aec.coordinator import fixtures, pipeline
        from aec.reporting import report

        run = pipeline.run_research(list(fixtures.CANDIDATES))
        generated = report.generate_report(run.to_dict())
        self.assertEqual(
            len(generated.observed_facts), len(run.cases_created)
        )
        self.assertEqual(
            len(generated.planned_observations), len(run.plans_generated)
        )
        self.assertEqual(
            len(generated.blocked_actions), len(run.failures)
        )
        self.assertEqual(
            len(generated.next_steps), len(run.review_items)
        )

    def test_technology_list_preserved(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            generated.observed_facts[0]["technology"], ["php"]
        )

    def test_steps_without_purpose_default(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[{**base, "steps": [{"step_id": "s1"}]}])
        generated = report.generate_report(fields)
        self.assertEqual(
            generated.planned_observations[0]["steps"][0]["purpose"], ""
        )

    def test_non_mapping_steps_skipped(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[{**base, "steps": ["nope"]}])
        generated = report.generate_report(fields)
        self.assertEqual(generated.planned_observations[0]["steps"], [])

    def test_missing_non_string_items_ignored(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[{**base, "missing": ["a", "", 42]}])
        generated = report.generate_report(fields)
        self.assertIn("a", generated.missing_evidence)
        self.assertNotIn("", generated.missing_evidence)


    def test_context_cases_with_prior(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[
            {**base, "prior": {"researched": True, "related_patterns": 0}},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(generated.context["cases_with_prior"], 1)

    def test_facts_parameter_field(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            generated.observed_facts[0]["parameter"], "order_id"
        )

    def test_facts_category_field(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(generated.observed_facts[0]["category"], "idor")

    def test_planned_sorted_by_case(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[
            {**base, "case_id": "case-zzz", "plan_id": "plan-case-zzz"},
            {**base, "case_id": "case-aaa", "plan_id": "plan-case-aaa"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(
            [item["case_id"] for item in generated.planned_observations],
            ["case-aaa", "case-zzz"],
        )

    def test_report_does_not_mutate_run(self):
        import copy
        from aec.reporting import report

        fields = run_dict()
        before = copy.deepcopy(fields)
        report.generate_report(fields)
        self.assertEqual(fields, before)

    def test_empty_steps_ok(self):
        from aec.reporting import report

        base = run_dict()["cases"][0]
        fields = run_dict(cases=[{**base, "steps": []}])
        generated = report.generate_report(fields)
        self.assertEqual(generated.planned_observations[0]["steps"], [])

    def test_context_empty_by_default(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(generated.context["duplicate_refs"], [])
        self.assertEqual(generated.context["related_pattern_count"], 0)

    def test_report_id_prefix(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertTrue(generated.report_id.startswith("report-"))
        self.assertEqual(len(generated.report_id), len("report-") + 12)


    def test_refused_case_report_sections(self):
        from aec.reporting import report

        fields = run_dict(
            review_items=[{
                "case_id": "case-001",
                "reason": "AUTHORIZATION_REFUSED",
                "current_state": "PLANNED",
                "evidence_state": "WAITING_EVIDENCE",
                "missing_evidence": ["initial-observation"],
                "research_history": {"duplicates": [], "related_patterns": 0},
                "recommended_next_action": "RESOLVE_REFUSAL",
            }],
            failures=[{"ref": "rc-001", "kind": "GATE_REFUSAL",
                       "detail": "STEP_LIMIT_EXCEEDED"}],
        )
        generated = report.generate_report(fields)
        self.assertEqual(
            generated.next_steps[0]["action"], "RESOLVE_REFUSAL"
        )
        self.assertEqual(len(generated.blocked_actions), 1)

    def test_blocked_detail_passthrough(self):
        from aec.reporting import report

        fields = run_dict(failures=[
            {"ref": "rc-1", "kind": "GATE_REFUSAL",
             "detail": "STEP_LIMIT_EXCEEDED"},
        ])
        generated = report.generate_report(fields)
        self.assertEqual(
            generated.blocked_actions[0]["detail"], "STEP_LIMIT_EXCEEDED"
        )

    def test_context_keys_exact(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            sorted(generated.context),
            ["cases_with_prior", "duplicate_refs", "related_pattern_count"],
        )

    def test_observed_endpoint_field(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            generated.observed_facts[0]["endpoint"], "/orders"
        )

    def test_next_step_actions_non_empty(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        for step in generated.next_steps:
            self.assertTrue(step["action"])
            self.assertTrue(step["case_id"])

    def test_planned_step_keys_exact(self):
        from aec.reporting import report

        generated = report.generate_report(run_dict())
        self.assertEqual(
            sorted(generated.planned_observations[0]["steps"][0]),
            ["endpoint", "purpose", "step_id"],
        )

    def test_minimal_run_mapping(self):
        from aec.reporting import report

        generated = report.generate_report({})
        self.assertEqual(generated.run_id, "")
        self.assertEqual(generated.observed_facts, ())
        self.assertEqual(generated.blocked_actions, ())


if __name__ == "__main__":
    unittest.main()

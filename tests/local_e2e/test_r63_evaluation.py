"""Focused tests for the R63 offline evaluation and quality gate.

Covers the positive contract (structure, sampling, safety, bounds, specialist
signals, CVE integrity, isolation, R31-R38 consistency, empty-safe output) and
the required mutation-style negative cases 1-18. All tests are offline: the
fixture pipeline is built once through the R62 injected-inventory seam.
"""

from __future__ import annotations

import unittest
from copy import deepcopy

from tests.local_e2e import r62_bridge as br
from tests.local_e2e import r63_evaluation as r63
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import client_from_fixture, load_fixture

CVE = "CVE-2024-27956"
FIXTURE = load_fixture()
SNAPSHOT = rs.build_snapshot("indeed", client=client_from_fixture(FIXTURE))
PIPELINE = br.pipeline(SNAPSHOT, cve=CVE)
FOREIGN = ("other-program", "www.other.example")


def evaluate(data, *, snapshot=SNAPSHOT):
    return r63.evaluate_pipeline(
        data, snapshot=snapshot, foreign_programs=FOREIGN
    )


def without_idor_evidence():
    snapshot = deepcopy(SNAPSHOT)
    for record in snapshot["collections"]["endpoints"]["records"]:
        if "{" in record.get("path", ""):
            record["params"] = []
            record["params_from_crawl"] = []
            record["params_from_x8"] = []
            record["param_records"] = []
    return snapshot


class TestEvaluationContract(unittest.TestCase):
    def test_pipeline_result_shape(self):
        self.assertEqual(PIPELINE["inventory"]["program"], "indeed")
        self.assertIsNotNone(PIPELINE["r31"])

    def test_pipeline_passes(self):
        result = evaluate(PIPELINE)
        self.assertEqual(result["status"], "PASS", result["checks"])
        self.assertEqual(result["rule_version"], "r63-1")
        self.assertGreater(result["summary"]["passed"], 0)
        self.assertEqual(result["summary"]["failed"], 0)

    def test_summary_matches_checks(self):
        result = evaluate(PIPELINE)
        total = sum(
            1 for check in result["checks"].values()
            if check["status"] == "PASS"
        )
        self.assertEqual(result["summary"]["passed"], total)
        self.assertEqual(
            result["summary"]["failed"],
            len(result["checks"]) - total,
        )

    def test_quality_gate_alias_matches(self):
        direct = evaluate(PIPELINE)
        alias = r63.quality_gate(
            PIPELINE, snapshot=SNAPSHOT, foreign_programs=FOREIGN
        )
        self.assertEqual(r63.canonical_json(direct), r63.canonical_json(alias))

    def test_evaluator_is_deterministic(self):
        first = r63.canonical_json(evaluate(PIPELINE))
        second = r63.canonical_json(evaluate(PIPELINE))
        self.assertEqual(first, second)

    def test_evaluator_output_has_no_unsafe_content(self):
        text = r63.canonical_json(evaluate(PIPELINE))
        self.assertNotIn("://", text)
        self.assertNotIn('"_id"', text)
        self.assertNotIn("timestamp", text)
        self.assertNotIn("other-program", text)

    def test_individual_evaluators_pass(self):
        self.assertEqual(
            r63.evaluate_r31(PIPELINE)["status"], "PASS"
        )
        self.assertEqual(
            r63.evaluate_context(
                PIPELINE["research_context"], label="research_context"
            )["status"],
            "PASS",
        )
        self.assertEqual(
            r63.evaluate_sampling(
                PIPELINE["research_context"],
                PIPELINE["intelligence_context"],
            )["status"],
            "PASS",
        )
        self.assertEqual(
            r63.evaluate_safety(
                PIPELINE["workflow"], PIPELINE["copilot"]
            )["status"],
            "PASS",
        )
        self.assertEqual(
            r63.evaluate_specialist_signals(
                PIPELINE["specialist_signals"],
                snapshot=SNAPSHOT,
                inventory=PIPELINE["inventory"],
                r31=PIPELINE["r31"],
            )["status"],
            "PASS",
        )
        self.assertEqual(
            r63.evaluate_program_isolation(
                PIPELINE,
                program="indeed",
                foreign_programs=FOREIGN,
                snapshot=SNAPSHOT,
            )["status"],
            "PASS",
        )

    def test_malformed_inputs_fail_closed(self):
        for malformed in (None, 5, "not-a-pipeline", {}, {"inventory": {}}):
            with self.subTest(malformed=malformed):
                result = r63.evaluate_pipeline(malformed)
                self.assertEqual(result["status"], "FAIL")
        self.assertEqual(
            r63.evaluate_context(None)["status"], "FAIL"
        )
        self.assertEqual(
            r63.evaluate_sampling(None, None)["status"], "FAIL"
        )
        self.assertEqual(
            r63.evaluate_safety(None, None)["status"], "FAIL"
        )
        self.assertEqual(
            r63.evaluate_specialist_signals(None)["status"], "FAIL"
        )
        self.assertEqual(
            r63.evaluate_determinism({})["status"], "FAIL"
        )


class TestPositiveChecks(unittest.TestCase):
    def test_stage_checks_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "pipeline_structure",
            "stage_snapshot_reference",
            "stage_inventory",
            "stage_r31",
            "stage_workflow",
            "stage_copilot",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_sampling_checks_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "sampling_flag",
            "sampling_claims",
            "sampling_counters",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_safety_checks_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "safety_workflow",
            "safety_copilot",
            "safety_boundary",
            "safety_recommendations",
            "no_confirmation_claims",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_context_bounds_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "research_context_bounds",
            "research_context_hygiene",
            "intelligence_context_bounds",
            "intelligence_context_hygiene",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_specialist_checks_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "specialist_categories",
            "specialist_eligibility",
            "specialist_evidence",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_cve_integrity_pass(self):
        checks = evaluate(PIPELINE)["checks"]
        self.assertEqual(checks["cve_integrity"]["status"], "PASS")
        self.assertEqual(checks["r31_item"]["status"], "PASS")
        self.assertEqual(
            checks["r31_layer_consistency"]["status"], "PASS"
        )

    def test_isolation_passes_for_fixture(self):
        checks = evaluate(PIPELINE)["checks"]
        for name in (
            "program_identity",
            "program_isolation",
            "record_ref_scope",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)

    def test_no_fabricated_outputs(self):
        checks = evaluate(PIPELINE)["checks"]
        self.assertEqual(
            checks["no_fabricated_outputs"]["status"], "PASS"
        )
        self.assertEqual(PIPELINE["copilot"]["brief"]["opportunity_count"], 0)

    def test_empty_safe_pipeline_passes(self):
        empty_snapshot = {
            "snapshot_version": 1,
            "rule_version": "r61-1",
            "program": "indeed",
            "sampled": True,
            "caps": {},
            "collections": {},
            "stats": {},
        }
        empty_pipeline = br.pipeline(empty_snapshot, cve=CVE)
        result = r63.evaluate_pipeline(empty_pipeline, snapshot=empty_snapshot)
        self.assertEqual(result["status"], "PASS", result["checks"])

    def test_determinism_evaluator_passes(self):
        result = r63.evaluate_determinism(SNAPSHOT, {"cve": CVE})
        self.assertEqual(result["status"], "PASS", result["checks"])
        self.assertEqual(
            result["checks"]["pipeline_determinism"]["status"], "PASS"
        )
        self.assertEqual(
            result["checks"]["evaluator_determinism"]["status"], "PASS"
        )

    def test_mixed_program_snapshot_isolated(self):
        mixed = deepcopy(SNAPSHOT)
        mixed["collections"]["endpoints"]["records"].append(
            {
                "record_ref": "rec-dddddddddddddddd",
                "program_name": "other-program",
                "subdomain": "www.other.example",
                "path": "/admin",
                "params": ["q"],
                "params_from_crawl": ["q"],
                "params_from_x8": [],
                "x8_checked": False,
                "hit_count": 1,
                "param_records": [],
            }
        )
        mixed_pipeline = br.pipeline(mixed, cve=CVE)
        result = r63.evaluate_pipeline(
            mixed_pipeline, snapshot=mixed, foreign_programs=FOREIGN
        )
        self.assertEqual(result["status"], "PASS", result["checks"])
        self.assertNotIn(
            "rec-dddddddddddddddd",
            r63.canonical_json(mixed_pipeline["research_context"]),
        )


class TestNegativeMutations(unittest.TestCase):
    def assert_check_fails(self, check_name, mutator, *, snapshot=SNAPSHOT):
        data = deepcopy(PIPELINE)
        mutator(data)
        result = r63.evaluate_pipeline(
            data, snapshot=snapshot, foreign_programs=FOREIGN
        )
        self.assertEqual(result["status"], "FAIL", check_name)
        self.assertEqual(
            result["checks"][check_name]["status"], "FAIL", check_name
        )
        return result

    def test_1_sampled_false(self):
        self.assert_check_fails(
            "sampling_flag",
            lambda data: data["research_context"].__setitem__(
                "sampled", False
            ),
        )

    def test_2_complete_true(self):
        self.assert_check_fails(
            "sampling_claims",
            lambda data: data["research_context"].__setitem__(
                "complete", True
            ),
        )

    def test_3_advisory_false(self):
        self.assert_check_fails(
            "safety_workflow",
            lambda data: data["workflow"].__setitem__("advisory", False),
        )

    def test_4_auto_execute_true(self):
        self.assert_check_fails(
            "safety_workflow",
            lambda data: data["workflow"]["next_action"].__setitem__(
                "auto_execute", True
            ),
        )

    def test_5_execution_performed_true(self):
        self.assert_check_fails(
            "safety_workflow",
            lambda data: data["workflow"].__setitem__(
                "execution_performed", True
            ),
        )

    def test_6_vulnerability_confirmed_true(self):
        self.assert_check_fails(
            "safety_copilot",
            lambda data: data["copilot"].__setitem__(
                "vulnerability_confirmed", True
            ),
        )

    def test_7_exploit_authorized_true(self):
        self.assert_check_fails(
            "safety_copilot",
            lambda data: data["copilot"].__setitem__(
                "exploit_authorized", True
            ),
        )

    def test_8_invalid_confirmation_state(self):
        self.assert_check_fails(
            "safety_workflow",
            lambda data: data["workflow"].__setitem__(
                "confirmation_state", "CONFIRMED"
            ),
        )

    def test_9_oversized_list(self):
        self.assert_check_fails(
            "research_context_bounds",
            lambda data: data["research_context"].__setitem__(
                "technologies", ["tech"] * (r63.MAX_CONTEXT_LIST + 1)
            ),
        )

    def test_10_excessive_depth(self):
        self.assert_check_fails(
            "research_context_bounds",
            lambda data: data["research_context"].__setitem__(
                "deep", {"a": {"b": {"c": {"d": {"e": 1}}}}}
            ),
        )

    def test_11_excessive_mapping_keys(self):
        def mutate(data):
            context = data["intelligence_context"]
            for index in range(r63.MAX_CONTEXT_KEYS + 1):
                context[f"extra_{index}"] = index

        self.assert_check_fails("intelligence_context_bounds", mutate)

    def test_12_fabricated_cve(self):
        self.assert_check_fails(
            "cve_integrity",
            lambda data: data["intelligence_context"].__setitem__(
                "cve_ids", ["CVE-2020-9999"]
            ),
        )

    def test_13_fabricated_idor_signal(self):
        def mutate(data):
            data["specialist_signals"]["IDOR"] = {
                "object_reference": "PATH_PARAMETER"
            }

        self.assert_check_fails(
            "specialist_evidence", mutate, snapshot=without_idor_evidence()
        )

    def test_14_graphql_without_evidence(self):
        self.assert_check_fails(
            "specialist_evidence",
            lambda data: data["specialist_signals"].__setitem__(
                "RECON", {"api_type": "GRAPHQL"}
            ),
        )

    def test_15_versioned_without_version_path(self):
        self.assert_check_fails(
            "specialist_evidence",
            lambda data: data["specialist_signals"].__setitem__(
                "RECON",
                {
                    "api_type": "REST",
                    "api_versioning": "VERSIONED_OBSERVED",
                },
            ),
        )

    def test_16_mixed_program_contamination(self):
        self.assert_check_fails(
            "program_isolation",
            lambda data: data["research_context"].__setitem__(
                "program", "other-program"
            ),
        )

    def test_17_unsupported_specialist_category(self):
        self.assert_check_fails(
            "specialist_categories",
            lambda data: data["specialist_signals"].__setitem__(
                "XSS", {"input_location": "QUERY"}
            ),
        )

    def test_18_fabricated_opportunity(self):
        def mutate(data):
            brief = data["copilot"]["brief"]
            brief["opportunity_count"] = 1
            brief["opportunities"] = [
                {"opportunity_id": "bco-fabricated"}
            ]

        self.assert_check_fails("no_fabricated_outputs", mutate)


if __name__ == "__main__":
    unittest.main()

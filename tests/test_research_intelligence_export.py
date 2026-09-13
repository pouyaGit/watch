"""tests/test_research_intelligence_export.py — Stage R31.22 tests.

Deterministic, offline tests for the research intelligence exporter:

- deterministic output
- READY / NOT_READY / UNKNOWN export statuses
- generated sections and malformed input handling
- no mutation of the R31.20/R31.21 inputs
- closed vocabulary enforcement, JSON serialization
- research_only always true, no operational attack content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import evidence_acquisition_planner as eap
from ai.knowledge import evidence_confidence_aggregator as eca
from ai.knowledge import evidence_decision_planner as edp
from ai.knowledge import evidence_feedback_calibration_planner as efp
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import evidence_research_outcome_tracker as eot
from ai.knowledge import research_consistency_validator as rcv
from ai.knowledge import research_intelligence_exporter as rie
from ai.knowledge import research_intelligence_summary_planner as risp
from ai.schemas import research_intelligence_export as schema

CVE = "CVE-2026-1560"

TARGETS_BY_METHOD = {
    eap.EXISTING_EVIDENCE_REVIEW: eap.TARGET_EXISTING_EVIDENCE,
    eap.COMPONENT_IDENTITY_LOOKUP: eap.TARGET_COMPONENT_IDENTITY,
    eap.VERSION_LOOKUP: eap.TARGET_VERSION,
    eap.SCOPE_EVIDENCE_REVIEW: eap.TARGET_SCOPE,
    eap.PATH_EVIDENCE_REVIEW: eap.TARGET_PATH,
    eap.PARAMETER_EVIDENCE_REVIEW: eap.TARGET_PARAMETER,
    eap.HTTP_BEHAVIOR_REVIEW: eap.TARGET_HTTP_BEHAVIOR,
    eap.TECHNOLOGY_EVIDENCE_REVIEW: eap.TARGET_TECHNOLOGY,
    eap.MANUAL_RESEARCH: eap.TARGET_EXISTING_EVIDENCE,
}


def acquisition_plan(method, target=None, **over):
    if target is None:
        if method == eap.NO_ACQUISITION:
            target = eap.TARGET_NONE
        else:
            target = TARGETS_BY_METHOD[method]
    plan = {
        "rule_version": "r31-13",
        "acquisition_method": method,
        "acquisition_rank": 0,
        "evidence_target": target,
        "evidence_gap": "GAP_NONE",
        "completion_condition": "EXISTING_EVIDENCE_REVIEWED",
        "reason_codes": ["SOURCE_ACTION"],
        "source_action": "VERIFY_EXISTING_EVIDENCE",
        "source_actionability": "IMMEDIATE_VERIFICATION",
        "source_priority": "P0",
        "source_hunt_score": 96,
        "confidence": "HIGH",
        "estimated_effort": "LOW",
        "acquisition_order_key": [0, 0, -96],
        "research_only": True,
    }
    plan.update(over)
    return plan


def chain(method, **over):
    acquisition = acquisition_plan(method, **over)
    prioritization = epp.plan_evidence_prioritization(acquisition)
    confidence = eca.aggregate_evidence_confidence(
        acquisition, prioritization
    )
    decision = edp.plan_evidence_decision(
        acquisition, prioritization, confidence
    )
    loop = erl.plan_evidence_research_loop(
        acquisition, prioritization, confidence, decision
    )
    outcome = eot.track_evidence_research_outcome(
        acquisition, prioritization, confidence, decision, loop
    )
    feedback = efp.plan_evidence_feedback_calibration(
        acquisition, prioritization, confidence, decision, loop, outcome
    )
    summary = risp.plan_research_intelligence_summary(
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback,
    )
    validation = rcv.validate_research_consistency(
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback, summary,
    )
    export = rie.export_research_intelligence(summary, validation)
    return {
        "summary": summary,
        "validation": validation,
        "export": export,
    }


# ---------------------------------------------------------------------------
# export statuses
# ---------------------------------------------------------------------------


class TestExportStatuses(unittest.TestCase):
    def test_valid_chain_is_ready(self):
        for method in TARGETS_BY_METHOD:
            export = chain(method)["export"]
            self.assertTrue(export["ready"], method)
            self.assertEqual(export["status"], schema.EXPORT_READY, method)
            self.assertEqual(
                export["generated_sections"],
                [schema.SECTION_SUMMARY, schema.SECTION_VALIDATION],
                method,
            )

    def test_deferred_chain_is_ready_and_consistent(self):
        result = chain(eap.NO_ACQUISITION)
        self.assertEqual(result["validation"]["validation_status"], "VALID")
        self.assertTrue(result["export"]["ready"])

    def test_invalid_validation_is_not_ready(self):
        result = chain(eap.VERSION_LOOKUP)
        invalid = dict(result["validation"])
        invalid["validation_status"] = "INVALID"
        invalid["valid"] = False
        export = rie.export_research_intelligence(result["summary"], invalid)
        self.assertFalse(export["ready"])
        self.assertEqual(export["status"], schema.EXPORT_NOT_READY)

    def test_unknown_validation_is_unknown(self):
        result = chain(eap.VERSION_LOOKUP)
        unknown = dict(result["validation"])
        unknown["validation_status"] = "UNKNOWN"
        unknown["valid"] = False
        export = rie.export_research_intelligence(result["summary"], unknown)
        self.assertFalse(export["ready"])
        self.assertEqual(export["status"], schema.EXPORT_UNKNOWN)

    def test_missing_both_inputs_is_unknown(self):
        export = rie.export_research_intelligence()
        self.assertFalse(export["ready"])
        self.assertEqual(export["status"], schema.EXPORT_UNKNOWN)
        self.assertEqual(export["generated_sections"], [])

    def test_summary_only_lists_summary_section(self):
        result = chain(eap.VERSION_LOOKUP)
        export = rie.export_research_intelligence(result["summary"])
        self.assertEqual(export["generated_sections"],
                         [schema.SECTION_SUMMARY])
        self.assertEqual(export["status"], schema.EXPORT_UNKNOWN)

    def test_validation_only_lists_validation_section(self):
        result = chain(eap.VERSION_LOOKUP)
        export = rie.export_research_intelligence(
            None, result["validation"]
        )
        self.assertEqual(export["generated_sections"],
                         [schema.SECTION_VALIDATION])
        self.assertEqual(export["status"], schema.EXPORT_READY)
        self.assertTrue(export["ready"])

    def test_lowercase_validation_status_is_normalized(self):
        export = rie.export_research_intelligence(
            {"research_status": "COMPLETE"},
            {"validation_status": "valid"},
        )
        self.assertTrue(export["ready"])
        self.assertEqual(export["status"], schema.EXPORT_READY)


# ---------------------------------------------------------------------------
# determinism, malformed input, no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_deterministic_output(self):
        result = chain(eap.VERSION_LOOKUP)
        first = rie.export_research_intelligence(
            result["summary"], result["validation"]
        )
        second = rie.export_research_intelligence(
            result["summary"], result["validation"]
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_key_insertion_order_does_not_matter(self):
        result = chain(eap.PATH_EVIDENCE_REVIEW)
        shuffled = dict(reversed(list(result["summary"].items())))
        first = rie.export_research_intelligence(
            result["summary"], result["validation"]
        )
        second = rie.export_research_intelligence(
            shuffled, result["validation"]
        )
        self.assertEqual(first, second)

    def test_malformed_inputs(self):
        for summary, validation in (
            (None, None),
            ({}, {}),
            ("x", 0),
            ([], "y"),
        ):
            export = rie.export_research_intelligence(summary, validation)
            self.assertFalse(export["ready"], repr((summary, validation)))
            self.assertEqual(export["status"], schema.EXPORT_UNKNOWN)

    def test_no_mutation_of_inputs(self):
        result = chain(eap.PARAMETER_EVIDENCE_REVIEW)
        summary_snapshot = copy.deepcopy(result["summary"])
        validation_snapshot = copy.deepcopy(result["validation"])
        rie.export_research_intelligence(
            result["summary"], result["validation"]
        )
        self.assertEqual(result["summary"], summary_snapshot)
        self.assertEqual(result["validation"], validation_snapshot)

    def test_embedded_snapshots_do_not_alias_inputs(self):
        result = chain(eap.VERSION_LOOKUP)
        export = rie.export_research_intelligence(
            result["summary"], result["validation"]
        )
        export["summary"]["research_status"] = "COMPLETE"
        export["validation"]["validation_status"] = "INVALID"
        self.assertEqual(result["summary"]["research_status"], "ACTIVE")
        self.assertEqual(
            result["validation"]["validation_status"], "VALID"
        )


# ---------------------------------------------------------------------------
# vocabulary validation, JSON, research_only, no operational content
# ---------------------------------------------------------------------------


class TestOutputShape(unittest.TestCase):
    def test_json_serializable(self):
        export = chain(eap.VERSION_LOOKUP)["export"]
        self.assertIsInstance(json.loads(json.dumps(export)), dict)

    def test_research_only_always_true(self):
        cases = [
            chain(method)["export"] for method in TARGETS_BY_METHOD
        ]
        cases.append(rie.export_research_intelligence())
        for export in cases:
            self.assertIs(export["research_only"], True)

    def test_closed_vocabulary(self):
        for method in TARGETS_BY_METHOD:
            export = chain(method)["export"]
            self.assertIn(export["status"], schema.EXPORT_STATUSES)
            for section in export["generated_sections"]:
                self.assertIn(section, schema.GENERATED_SECTIONS)

    def test_schema_rejects_invalid_status(self):
        with self.assertRaises(ValidationError):
            schema.ResearchIntelligenceExportPlan(
                ready=True, status="SHIPPED"
            )

    def test_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.ResearchIntelligenceExportPlan(
                ready=True, status="READY", severity="CRITICAL"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchIntelligenceExportPlan(
            rule_version="r99-9",
            ready=True,
            status="READY",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r31-22")
        with self.assertRaises(ValidationError):
            schema.ResearchIntelligenceExportPlan(
                ready=True, status="READY", research_only=False
            )

    def test_schema_bounds_and_filters_sections(self):
        plan = schema.ResearchIntelligenceExportPlan(
            ready=True,
            status="READY",
            generated_sections=[
                "NOT_A_SECTION",
                schema.SECTION_SUMMARY,
                schema.SECTION_SUMMARY,
                schema.SECTION_VALIDATION,
            ],
        )
        self.assertEqual(
            plan.generated_sections,
            [schema.SECTION_SUMMARY, schema.SECTION_VALIDATION],
        )

    def test_exact_rule_version(self):
        self.assertEqual(
            rie.RESEARCH_INTELLIGENCE_EXPORTER_RULE_VERSION, "r31-22"
        )
        export = rie.export_research_intelligence()
        self.assertEqual(export["rule_version"], "r31-22")

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            [chain(method)["export"] for method in TARGETS_BY_METHOD]
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""tests/test_research_intelligence_summary_planner.py — Stage R31.20 tests.

Deterministic, offline tests for the research intelligence summary planner:

- deterministic output
- all outcome -> status/category mappings
- malformed input handling
- no mutation of the R31.13-R31.19 inputs
- closed vocabulary enforcement (planner + pydantic schema)
- bounded, privacy-safe, JSON-serializable output
- research_only always true, no operational attack content
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import evidence_acquisition_planner as eap
from ai.knowledge import evidence_confidence_aggregator as eca
from ai.knowledge import evidence_decision_planner as edp
from ai.knowledge import evidence_feedback_calibration_planner as efp
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import evidence_research_outcome_tracker as eot
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge import research_intelligence_summary_planner as risp
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as conf_schema
from ai.schemas import evidence_feedback_calibration as fb_schema
from ai.schemas import evidence_research_loop as loop_schema
from ai.schemas import evidence_research_outcome as out_schema
from ai.schemas import research_intelligence_summary as schema
from ai.schemas.hunt_queue import HUNT_RULE_VERSION, hunt_item_projection
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

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
        "reason": "bounded reason",
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


def bundle(method, **over):
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
    return (
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback, summary,
    )


def quality(level="HIGH", *, consistency="CONSISTENT", conflicts=(),
            gaps=(), strength="STRONG"):
    return {
        "evidence_quality": level,
        "evidence_strength": strength,
        "evidence_consistency": consistency,
        "evidence_gaps": list(gaps),
        "conflicts": list(conflicts),
    }


def ppr(*, exact_path=False, parameter=False, scoped=True):
    rows = []
    if exact_path:
        rows.append({"evidence_type": "EXACT_PATH", "result": "MATCH",
                     "component_scoped": scoped})
    if parameter:
        rows.append({"evidence_type": "EXACT_PARAMETER", "result": "MATCH",
                     "component_scoped": scoped})
    return {
        "evidence": rows,
        "summary": {
            "path_match": exact_path,
            "parameter_match": parameter,
            "method": {"evidence_type": "HTTP_METHOD", "result": "NO_MATCH"},
        },
    }


def immediate_fixture(**over):
    base = dict(
        evidence_quality=quality("HIGH"),
        strongest_match_type="COMPONENT",
        strongest_confidence="HIGH",
        asset_match_state="CONFIRMED",
        matched_component="CKEditor",
        evidence_provenance="EXPLICIT",
        support_scope="COMPONENT_SCOPED",
        version_state="MATCH",
        version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
        version_normalization={
            "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                      "cve_evidence_class": "EXACT_OBSERVED"}],
            "observed_versions": [{}],
        },
        path_parameter_relevance=ppr(exact_path=True, parameter=True),
        cve_id=CVE,
    )
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# all decision paths
# ---------------------------------------------------------------------------


class TestSummaryMappings(unittest.TestCase):
    def test_completed_summary(self):
        (_, _, _, _, _, outcome, _, summary) = bundle(
            eap.EXISTING_EVIDENCE_REVIEW
        )
        self.assertEqual(outcome["outcome"], out_schema.OUTCOME_COMPLETED)
        self.assertEqual(summary["research_status"], schema.STATUS_COMPLETE)
        self.assertEqual(summary["summary_category"],
                         schema.CATEGORY_SUCCESSFUL)
        self.assertEqual(summary["evidence_status"], "COMPLETE")
        self.assertEqual(summary["confidence_level"], "HIGH")
        self.assertEqual(summary["final_state"],
                         loop_schema.LIFECYCLE_COMPLETED)
        self.assertEqual(summary["feedback_signal"], "SUCCESS_SIGNAL")
        self.assertEqual(summary["improvement_area"], "NONE")

    def test_in_progress_summary(self):
        for method, area in (
            (eap.COMPONENT_IDENTITY_LOOKUP, "IDENTITY"),
            (eap.VERSION_LOOKUP, "VERSION"),
            (eap.SCOPE_EVIDENCE_REVIEW, "SCOPE"),
        ):
            (_, _, _, _, _, outcome, _, summary) = bundle(method)
            self.assertEqual(outcome["outcome"],
                             out_schema.OUTCOME_IN_PROGRESS)
            self.assertEqual(summary["research_status"],
                             schema.STATUS_ACTIVE, method)
            self.assertEqual(summary["summary_category"],
                             schema.CATEGORY_ONGOING, method)
            self.assertEqual(summary["evidence_status"], "PARTIAL", method)
            self.assertEqual(summary["improvement_area"], area, method)
            self.assertEqual(summary["feedback_signal"],
                             "CONTINUE_SIGNAL", method)

    def test_waiting_summary(self):
        for method, area in (
            (eap.PATH_EVIDENCE_REVIEW, "PATH"),
            (eap.PARAMETER_EVIDENCE_REVIEW, "PARAMETER"),
            (eap.HTTP_BEHAVIOR_REVIEW, "HTTP_BEHAVIOR"),
            (eap.TECHNOLOGY_EVIDENCE_REVIEW, "TECHNOLOGY"),
            (eap.MANUAL_RESEARCH, "HUMAN_RESEARCH"),
        ):
            (_, _, _, _, _, outcome, _, summary) = bundle(method)
            self.assertEqual(outcome["outcome"],
                             out_schema.OUTCOME_WAITING_FOR_EVIDENCE)
            self.assertEqual(summary["research_status"],
                             schema.STATUS_WAITING, method)
            self.assertEqual(summary["summary_category"],
                             schema.CATEGORY_EVIDENCE_REQUIRED, method)
            self.assertEqual(summary["evidence_status"], "MINIMAL", method)
            self.assertEqual(summary["improvement_area"], area, method)
            self.assertEqual(summary["feedback_signal"],
                             "EVIDENCE_GAP_SIGNAL", method)

    def test_deferred_summary(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
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
        self.assertEqual(outcome["outcome"], out_schema.OUTCOME_DEFERRED)
        self.assertEqual(summary["research_status"], schema.STATUS_DEFERRED)
        self.assertEqual(summary["summary_category"],
                         schema.CATEGORY_PAUSED)
        self.assertEqual(summary["final_state"],
                         loop_schema.LIFECYCLE_DEFERRED)
        self.assertEqual(summary["feedback_signal"], "DEFER_SIGNAL")

    def test_unknown_summary(self):
        summary = risp.plan_research_intelligence_summary(
            None, None, None, None, None,
            {"outcome": "UNKNOWN"}, {"feedback_type": "UNKNOWN"},
        )
        self.assertEqual(summary["research_status"], schema.STATUS_UNKNOWN)
        self.assertEqual(summary["summary_category"],
                         schema.CATEGORY_INVALID)
        self.assertEqual(summary["evidence_status"], "NONE")
        self.assertEqual(summary["confidence_level"], "UNKNOWN")
        self.assertEqual(summary["final_state"], "UNKNOWN")
        self.assertEqual(summary["feedback_signal"], "UNKNOWN")

    def test_outcome_summary_table_is_closed(self):
        self.assertEqual(set(risp.OUTCOME_SUMMARY), set(out_schema.OUTCOMES))
        for outcome, row in risp.OUTCOME_SUMMARY.items():
            self.assertIn(row[0], schema.RESEARCH_STATUSES, outcome)
            self.assertIn(row[1], schema.SUMMARY_CATEGORIES, outcome)


# ---------------------------------------------------------------------------
# malformed inputs
# ---------------------------------------------------------------------------


class TestMalformedInputs(unittest.TestCase):
    def test_missing_inputs(self):
        for values in (
            (None,) * 7,
            ({},) * 7,
            ("x", [], 0, None, "loop", 1, "fb"),
        ):
            summary = risp.plan_research_intelligence_summary(*values)
            self.assertEqual(summary["research_status"],
                             schema.STATUS_UNKNOWN)
            self.assertEqual(summary["summary_category"],
                             schema.CATEGORY_INVALID)
            self.assertEqual(summary["evidence_status"], "NONE")
            self.assertEqual(summary["final_state"], "UNKNOWN")
            self.assertEqual(summary["feedback_signal"], "UNKNOWN")
            self.assertEqual(summary["improvement_area"], "UNKNOWN")

    def test_unrecognized_outcome(self):
        summary = risp.plan_research_intelligence_summary(
            None, None, None, None, None, {"outcome": "SHIP_IT"}, None
        )
        self.assertEqual(summary["research_status"], schema.STATUS_UNKNOWN)
        self.assertEqual(summary["summary_category"],
                         schema.CATEGORY_INVALID)

    def test_lowercase_outcome_is_normalized(self):
        summary = risp.plan_research_intelligence_summary(
            None, None, None, None, None, {"outcome": "completed"},
            {"feedback_type": "success_signal", "improvement_area": "none"},
        )
        self.assertEqual(summary["research_status"], schema.STATUS_COMPLETE)
        self.assertEqual(summary["summary_category"],
                         schema.CATEGORY_SUCCESSFUL)
        self.assertEqual(summary["feedback_signal"], "SUCCESS_SIGNAL")
        self.assertEqual(summary["improvement_area"], "NONE")

    def test_final_state_and_level_fallback(self):
        summary = risp.plan_research_intelligence_summary(
            None, None,
            {"confidence_level": "MEDIUM", "evidence_completeness": "PARTIAL"},
            None,
            {"lifecycle_state": "RESEARCH_ACTIVE"},
            {"outcome": "IN_PROGRESS"},
            None,
        )
        self.assertEqual(summary["confidence_level"], "MEDIUM")
        self.assertEqual(summary["final_state"], "RESEARCH_ACTIVE")
        self.assertEqual(summary["evidence_status"], "PARTIAL")


# ---------------------------------------------------------------------------
# determinism, no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_deterministic_output(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         feedback, _) = bundle(eap.VERSION_LOOKUP)
        first = risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, decision, loop, outcome,
            feedback,
        )
        second = risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, decision, loop, outcome,
            feedback,
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_key_insertion_order_does_not_matter(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         feedback, _) = bundle(eap.PATH_EVIDENCE_REVIEW)
        shuffled = dict(reversed(list(outcome.items())))
        first = risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, decision, loop, outcome,
            feedback,
        )
        second = risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, decision, loop, shuffled,
            feedback,
        )
        self.assertEqual(first, second)

    def test_no_mutation_of_inputs(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         feedback, _) = bundle(eap.PARAMETER_EVIDENCE_REVIEW)
        snapshots = [
            copy.deepcopy(value)
            for value in (
                acquisition, prioritization, confidence, decision, loop,
                outcome, feedback,
            )
        ]
        risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, decision, loop, outcome,
            feedback,
        )
        for before, after in zip(
            snapshots,
            (acquisition, prioritization, confidence, decision, loop, outcome,
             feedback),
        ):
            self.assertEqual(before, after)

    def test_source_snapshots_do_not_alias_inputs(self):
        (_, _, _, _, _, outcome, feedback, summary) = bundle(
            eap.VERSION_LOOKUP
        )
        summary["source_feedback_plan"]["feedback_type"] = "SUCCESS_SIGNAL"
        summary["source_outcome_plan"]["outcome"] = "COMPLETED"
        summary["source_loop_plan"]["lifecycle_state"] = "COMPLETED"
        self.assertEqual(feedback["feedback_type"], "CONTINUE_SIGNAL")
        self.assertEqual(outcome["outcome"], "IN_PROGRESS")


# ---------------------------------------------------------------------------
# vocabulary validation, JSON, research_only, no operational content
# ---------------------------------------------------------------------------


FORBIDDEN_OPERATIONAL_MARKERS = (
    "payload",
    "exploit",
    "fuzz",
    "nuclei",
    "sqlmap",
    "curl ",
    "wget ",
    "bypass",
    "request body",
    "<script",
    "union select",
    " or 1=1",
    "{{",
    "}}",
)


class TestOutputShape(unittest.TestCase):
    def _summaries(self):
        results = [bundle(method)[7] for method in TARGETS_BY_METHOD]
        results.append(risp.plan_research_intelligence_summary())
        return results

    def test_closed_vocabulary(self):
        for result in self._summaries():
            self.assertIn(result["research_status"],
                          schema.RESEARCH_STATUSES)
            self.assertIn(result["summary_category"],
                          schema.SUMMARY_CATEGORIES)
            self.assertIn(result["evidence_status"],
                          conf_schema.EVIDENCE_COMPLETENESS_LEVELS)
            self.assertIn(result["confidence_level"],
                          conf_schema.CONFIDENCE_LEVELS)
            self.assertIn(result["final_state"], loop_schema.LIFECYCLE_STATES)
            self.assertIn(result["feedback_signal"],
                          fb_schema.FEEDBACK_TYPES)
            self.assertIn(result["improvement_area"],
                          fb_schema.IMPROVEMENT_AREAS)
            for code in result["blockers"]:
                self.assertIn(code, conf_schema.CONFIDENCE_BLOCKERS)

    def test_schema_rejects_invalid_values(self):
        base = dict(
            research_status="COMPLETE",
            evidence_status="COMPLETE",
            confidence_level="HIGH",
            final_state="COMPLETED",
            feedback_signal="SUCCESS_SIGNAL",
            improvement_area="NONE",
            summary_category="SUCCESSFUL_RESEARCH",
        )
        for key, value in (
            ("research_status", "DONE"),
            ("evidence_status", "FULL"),
            ("confidence_level", "CERTAIN"),
            ("final_state", "RUNNING"),
            ("feedback_signal", "WIN_SIGNAL"),
            ("improvement_area", "MONEY"),
            ("summary_category", "VICTORY"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchIntelligenceSummaryPlan(
                    **{**base, key: value}
                )
        with self.assertRaises(ValidationError):
            schema.ResearchIntelligenceSummaryPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        result = schema.ResearchIntelligenceSummaryPlan(
            rule_version="r99-9",
            research_status="COMPLETE",
            evidence_status="COMPLETE",
            confidence_level="HIGH",
            final_state="COMPLETED",
            feedback_signal="SUCCESS_SIGNAL",
            improvement_area="NONE",
            summary_category="SUCCESSFUL_RESEARCH",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-20")
        with self.assertRaises(ValidationError):
            schema.ResearchIntelligenceSummaryPlan(
                research_status="COMPLETE",
                evidence_status="COMPLETE",
                confidence_level="HIGH",
                final_state="COMPLETED",
                feedback_signal="SUCCESS_SIGNAL",
                improvement_area="NONE",
                summary_category="SUCCESSFUL_RESEARCH",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            risp.RESEARCH_INTELLIGENCE_SUMMARY_PLANNER_RULE_VERSION,
            "r31-20",
        )
        summary = risp.plan_research_intelligence_summary()
        self.assertEqual(summary["rule_version"], "r31-20")

    def test_json_serializable(self):
        for result in self._summaries():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_research_only_always_true(self):
        for result in self._summaries():
            self.assertIs(result["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(self._summaries()).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_source_snapshots_are_sanitized(self):
        acquisition = acquisition_plan(
            eap.MANUAL_RESEARCH,
            source_action="token=SECRETVALUE",
            source_actionability="Bearer abc123",
        )
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = {
            "confidence_level": "LOW",
            "confidence_category": "RESEARCH_INCOMPLETE",
            "evidence_completeness": "MINIMAL",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        loop = {
            "lifecycle_state": "WAITING_FOR_EVIDENCE",
            "confidence_level": "LOW",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        outcome = {
            "outcome": "WAITING_FOR_EVIDENCE",
            "remaining_need": "HUMAN_RESEARCH",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        feedback = {
            "feedback_type": "EVIDENCE_GAP_SIGNAL",
            "signal_strength": "HIGH",
            "improvement_area": "HUMAN_RESEARCH",
            "confidence_level": "LOW",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        summary = risp.plan_research_intelligence_summary(
            acquisition, prioritization, confidence, None, loop, outcome,
            feedback,
        )
        blob = json.dumps(summary)
        for token in ("SECRETVALUE", "abc123"):
            self.assertNotIn(token, blob)


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R31.20-R31.22
# ---------------------------------------------------------------------------


def _projection(
    *,
    paths=(),
    components=(),
    provenance=(),
    versions=(),
    associations=(),
    parameters=(),
    parameter_paths=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": list(components),
        "plugins": [],
        "versions": [
            {"value": value, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"}
            for value in versions
        ],
        "version_associations": list(associations),
        "parameters": [
            {"value": value, "source": "PARAMETER_INVENTORY",
             "evidence_type": "STRUCTURED_PARAMETER"}
            for value in parameters
        ],
        "paths": [
            {"value": value, "source": "ENDPOINT_INVENTORY",
             "evidence_type": "STRUCTURED_ENDPOINT"}
            for value in paths
        ],
        "component_provenance": list(provenance),
        "parameter_paths": list(parameter_paths),
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(components=(), parameters=(), versions=()):
    document = SimpleNamespace(
        components=list(components),
        parameters=list(parameters),
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {"affected_versions": list(versions)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestBackendIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, inventory, *, components=(), parameters=(),
               versions=()):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(components, parameters, versions),
        ):
            return acm.build_matches(cve=CVE, program="dell")["items"][0]

    def test_backend_additive_fields_and_rule_versions(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["research_intelligence_summary_plan_rule_version"],
            "r31-20",
        )
        self.assertEqual(
            item["research_consistency_validation_plan_rule_version"],
            "r31-21",
        )
        self.assertEqual(
            item["research_intelligence_export_plan_rule_version"],
            "r31-22",
        )
        self.assertEqual(
            item["research_intelligence_summary_plan"]["rule_version"],
            "r31-20",
        )
        self.assertEqual(
            item["research_consistency_validation_plan"]["rule_version"],
            "r31-21",
        )
        self.assertEqual(
            item["research_intelligence_export_plan"]["rule_version"],
            "r31-22",
        )
        self.assertIs(
            item["research_intelligence_summary_plan"]["research_only"],
            True,
        )
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["evidence_feedback_calibration_plan_rule_version"],
            "r31-19",
        )

    def test_backend_immediate_plan_complete_and_export_ready(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "STRUCTURED_COMPONENT",
                }],
                versions=["1.2.3"],
                associations=[{
                    "version": "1.2.3",
                    "technology_family": "CKEditor",
                    "component": "CKEditor",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
            versions=["<=1.2.3"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.P0)
        self.assertEqual(
            item["research_intelligence_summary_plan"]["research_status"],
            schema.STATUS_COMPLETE,
        )
        self.assertEqual(
            item["research_consistency_validation_plan"][
                "validation_status"
            ],
            "VALID",
        )
        self.assertTrue(
            item["research_intelligence_export_plan"]["ready"]
        )
        self.assertEqual(
            item["research_intelligence_export_plan"]["status"],
            "READY",
        )
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_deferred_and_valid_chain(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["research_intelligence_summary_plan"]["research_status"],
            schema.STATUS_DEFERRED,
        )
        self.assertEqual(
            item["research_consistency_validation_plan"]["validation_status"],
            "VALID",
        )
        self.assertTrue(
            item["research_intelligence_export_plan"]["ready"]
        )

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "hunt_actionability",
            "hunt_action_plan",
            "evidence_acquisition_plan",
            "evidence_prioritization_plan",
            "evidence_confidence_plan",
            "evidence_decision_plan",
            "evidence_research_loop_plan",
            "evidence_research_outcome_plan",
            "evidence_feedback_calibration_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["research_intelligence_summary_plan"],
            item["research_intelligence_export_plan"],
        )

    def test_backend_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)

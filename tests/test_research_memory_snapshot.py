"""tests/test_research_memory_snapshot.py — Stage R32.1 tests.

Deterministic, offline tests for the research memory snapshot builder plus
hermetic backend integration for the R32 memory layer:

- deterministic output
- candidate identity and timestamp reference handling
- malformed/missing export handling
- immutability and schema validation
- no mutation of inputs, JSON serialization
- research_only always true, no operational attack content
- backend additive fields for R32.1-R32.4 (no live Mongo)

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
from ai.knowledge import research_consistency_validator as rcv
from ai.knowledge import research_intelligence_exporter as rie
from ai.knowledge import research_intelligence_summary_planner as risp
from ai.knowledge import research_memory_snapshot as rms
from ai.knowledge.relevance import AssetRecord
from ai.schemas import research_memory_snapshot as schema
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


def export_for(method, **over):
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
    return rie.export_research_intelligence(summary, validation)


# ---------------------------------------------------------------------------
# snapshot building
# ---------------------------------------------------------------------------


class TestSnapshotBuilder(unittest.TestCase):
    def test_completed_export_snapshot(self):
        snapshot = rms.create_research_memory_snapshot(
            export_for(eap.EXISTING_EVIDENCE_REVIEW),
            candidate_identity="rc-abc",
            timestamp_reference="ref-1",
        )
        self.assertEqual(snapshot["rule_version"], "r32-1")
        self.assertEqual(snapshot["candidate_identity"], "rc-abc")
        self.assertEqual(snapshot["research_status"], "COMPLETE")
        self.assertEqual(snapshot["outcome"], "COMPLETED")
        self.assertEqual(snapshot["confidence_level"], "HIGH")
        self.assertEqual(snapshot["feedback_signal"], "SUCCESS_SIGNAL")
        self.assertEqual(snapshot["improvement_area"], "NONE")
        self.assertEqual(snapshot["blockers"], [])
        self.assertEqual(snapshot["timestamp_reference"], "ref-1")
        self.assertEqual(snapshot["source_export"]["status"], "READY")

    def test_in_progress_export_snapshot(self):
        snapshot = rms.create_research_memory_snapshot(
            export_for(eap.VERSION_LOOKUP),
            candidate_identity="rc-abc",
        )
        self.assertEqual(snapshot["research_status"], "ACTIVE")
        self.assertEqual(snapshot["outcome"], "IN_PROGRESS")
        self.assertEqual(snapshot["improvement_area"], "VERSION")
        self.assertEqual(snapshot["feedback_signal"],
                         "CONTINUE_SIGNAL")
        self.assertIn("VERSION_EVIDENCE_MISSING", snapshot["blockers"])

    def test_deferred_export_snapshot(self):
        snapshot = rms.create_research_memory_snapshot(
            export_for(eap.NO_ACQUISITION)
        )
        self.assertEqual(snapshot["research_status"], "DEFERRED")
        self.assertEqual(snapshot["outcome"], "DEFERRED")
        self.assertEqual(snapshot["candidate_identity"], "UNSPECIFIED")
        self.assertEqual(snapshot["timestamp_reference"], "UNSPECIFIED")

    def test_defaults_for_missing_export(self):
        snapshot = rms.create_research_memory_snapshot()
        self.assertEqual(snapshot["research_status"], "UNKNOWN")
        self.assertEqual(snapshot["outcome"], "UNKNOWN")
        self.assertEqual(snapshot["confidence_level"], "UNKNOWN")
        self.assertEqual(snapshot["feedback_signal"], "UNKNOWN")
        self.assertEqual(snapshot["improvement_area"], "UNKNOWN")
        self.assertEqual(snapshot["blockers"], [])
        self.assertEqual(snapshot["source_export"]["ready"], False)

    def test_malformed_exports(self):
        for value in ({}, [], "x", 0, {"summary": "nope"}):
            snapshot = rms.create_research_memory_snapshot(value)
            self.assertEqual(snapshot["research_status"], "UNKNOWN")
            self.assertEqual(snapshot["outcome"], "UNKNOWN")
            self.assertEqual(snapshot["research_only"], True)

    def test_status_to_outcome_table_is_closed(self):
        self.assertEqual(
            set(rms.STATUS_TO_OUTCOME),
            {"COMPLETE", "ACTIVE", "WAITING", "DEFERRED", "UNKNOWN"},
        )
        self.assertEqual(
            set(rms.STATUS_TO_OUTCOME.values()),
            {"COMPLETED", "IN_PROGRESS", "WAITING_FOR_EVIDENCE",
             "DEFERRED", "UNKNOWN"},
        )

    def test_deterministic_output(self):
        export = export_for(eap.VERSION_LOOKUP)
        first = rms.create_research_memory_snapshot(
            export, candidate_identity="rc-abc",
            timestamp_reference="ref-1",
        )
        second = rms.create_research_memory_snapshot(
            export, candidate_identity="rc-abc",
            timestamp_reference="ref-1",
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        export = export_for(eap.PATH_EVIDENCE_REVIEW)
        snapshot = copy.deepcopy(export)
        rms.create_research_memory_snapshot(
            export, candidate_identity="rc-abc",
            timestamp_reference="ref-1",
        )
        self.assertEqual(export, snapshot)

    def test_source_export_does_not_alias_input(self):
        export = export_for(eap.VERSION_LOOKUP)
        snapshot = rms.create_research_memory_snapshot(export)
        snapshot["source_export"]["summary"]["research_status"] = "COMPLETE"
        self.assertEqual(
            export["summary"]["research_status"], "ACTIVE"
        )

    def test_privacy_redaction(self):
        export = export_for(eap.MANUAL_RESEARCH)
        export["summary"]["confidence_level"] = "token=SECRETVALUE"
        export["summary"]["research_status"] = "ACTIVE"
        snapshot = rms.create_research_memory_snapshot(
            export,
            candidate_identity="https://user:hunter2@x.test/p",
            timestamp_reference="Bearer abc123",
        )
        blob = json.dumps(snapshot)
        for token in ("SECRETVALUE", "hunter2", "abc123"):
            self.assertNotIn(token, blob)


# ---------------------------------------------------------------------------
# schema and output shape
# ---------------------------------------------------------------------------


class TestSchemaAndOutput(unittest.TestCase):
    def test_is_json_serializable(self):
        snapshot = rms.create_research_memory_snapshot(
            export_for(eap.VERSION_LOOKUP)
        )
        self.assertIsInstance(json.loads(json.dumps(snapshot)), dict)

    def test_research_only_always_true(self):
        for method in TARGETS_BY_METHOD:
            snapshot = rms.create_research_memory_snapshot(
                export_for(method)
            )
            self.assertIs(snapshot["research_only"], True)
        self.assertIs(
            rms.create_research_memory_snapshot()["research_only"], True
        )

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            [
                rms.create_research_memory_snapshot(export_for(m))
                for m in TARGETS_BY_METHOD
            ]
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_is_frozen(self):
        snapshot = schema.ResearchMemorySnapshot(
            candidate_identity="rc-abc",
            research_status="ACTIVE",
            outcome="IN_PROGRESS",
            confidence_level="MEDIUM",
            feedback_signal="CONTINUE_SIGNAL",
            improvement_area="VERSION",
        )
        with self.assertRaises(ValidationError):
            snapshot.outcome = "COMPLETED"

    def test_schema_rejects_unknown_fields_and_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchMemorySnapshot(severity="CRITICAL")
        for key, value in (
            ("research_status", "DONE"),
            ("outcome", "SHIP_IT"),
            ("confidence_level", "CERTAIN"),
            ("feedback_signal", "WIN_SIGNAL"),
            ("improvement_area", "MONEY"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchMemorySnapshot(**{key: value})

    def test_schema_forces_rule_version_and_research_only(self):
        snapshot = schema.ResearchMemorySnapshot(
            rule_version="r99-9", research_only=True
        )
        self.assertEqual(snapshot.rule_version, "r32-1")
        with self.assertRaises(ValidationError):
            schema.ResearchMemorySnapshot(research_only=False)

    def test_exact_rule_version(self):
        self.assertEqual(
            rms.RESEARCH_MEMORY_SNAPSHOT_BUILDER_RULE_VERSION, "r32-1"
        )
        snapshot = rms.create_research_memory_snapshot()
        self.assertEqual(snapshot["rule_version"], "r32-1")


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R32.1-R32.4
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
            item["research_memory_snapshot_rule_version"], "r32-1"
        )
        self.assertEqual(
            item["research_history_plan_rule_version"], "r32-2"
        )
        self.assertEqual(
            item["research_pattern_plan_rule_version"], "r32-3"
        )
        self.assertEqual(
            item["research_memory_export_plan_rule_version"], "r32-4"
        )
        for key, version in (
            ("research_memory_snapshot", "r32-1"),
            ("research_history_plan", "r32-2"),
            ("research_pattern_plan", "r32-3"),
            ("research_memory_export_plan", "r32-4"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_intelligence_export_plan_rule_version"],
            "r31-22",
        )

    def test_backend_immediate_plan_memory(self):
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
        snapshot = item["research_memory_snapshot"]
        self.assertEqual(snapshot["outcome"], "COMPLETED")
        self.assertEqual(snapshot["research_status"], "COMPLETE")
        self.assertTrue(snapshot["candidate_identity"].startswith("rc-"))
        self.assertEqual(
            item["research_history_plan"]["total_records"], 1
        )
        self.assertEqual(
            item["research_history_plan"]["successful_count"], 1
        )
        self.assertEqual(
            item["research_pattern_plan"]["dominant_pattern"],
            "NO_PATTERN",
        )
        export = item["research_memory_export_plan"]
        self.assertTrue(export["ready"])
        self.assertIn("SINGLE_RECORD_HISTORY", export["limitations"])
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_memory(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["research_memory_snapshot"]["outcome"], "DEFERRED"
        )
        self.assertEqual(
            item["research_history_plan"]["deferred_count"], 1
        )
        self.assertEqual(
            item["research_pattern_plan"]["dominant_pattern"], "UNKNOWN"
        )
        self.assertEqual(
            item["research_pattern_plan"]["confidence"], "LOW"
        )

    def test_backend_candidate_identity_is_privacy_preserving(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        identity = item["research_memory_snapshot"]["candidate_identity"]
        self.assertTrue(identity.startswith("rc-"))
        self.assertNotIn(CVE, identity)
        self.assertNotIn("dell", identity)

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "evidence_acquisition_plan",
            "research_intelligence_summary_plan",
            "research_intelligence_export_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["research_memory_snapshot"],
            item["research_memory_export_plan"],
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

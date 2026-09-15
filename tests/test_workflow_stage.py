"""tests/test_workflow_stage.py — Stage R59 workflow stage tests.

Deterministic, offline tests for the R59 workflow stage contract:

- closed fixed stage order and status vocabulary
- closed stage reasons and limitation ordering
- upstream-supplied deterministic metadata only (no wall clock)
- bounded references and fail-closed stage sanitizers
- forced research-only/no-execution/no-confirmation invariants
- deterministic stage ids and model round trips

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.security_research_workflow_rules import (
    make_stage,
    stage_id,
)
from ai.schemas.workflow_stage import (
    REASON_HUMAN_DECIDED,
    REASON_NOT_PROVIDED,
    REASON_SKIPPED_BY_OPTION,
    REASON_UPSTREAM_RESULT_INVALID,
    STAGE_COLLABORATION,
    STAGE_CORRELATION,
    STAGE_EVALUATION,
    STAGE_EXECUTION_CONTROL,
    STAGE_FEEDBACK,
    STAGE_FINDING,
    STAGE_HUMAN_REVIEW,
    STAGE_LEARNING,
    STAGE_PRIORITIZATION,
    STAGE_SPECIALIST_RESEARCH,
    STAGE_STATUS_BLOCKED,
    STAGE_STATUS_COMPLETED,
    STAGE_STATUS_INVALID,
    STAGE_STATUS_NOT_STARTED,
    STAGE_STATUS_READY,
    STAGE_STATUS_SKIPPED,
    WORKFLOW_STAGE_LIMITATIONS,
    WORKFLOW_STAGE_METADATA_KEYS,
    WORKFLOW_STAGE_ORDER,
    WORKFLOW_STAGE_REASONS,
    WORKFLOW_STAGE_RULE_VERSION,
    WORKFLOW_STAGE_STATUSES,
    WorkflowStagePlan,
    sanitize_stage_metadata,
    sanitize_stage_reference,
    sanitize_workflow_stage,
    workflow_stage_plan_projection,
)

WORKFLOW_ID = "wfr-" + "1" * 16


class TestStageVocabulary(unittest.TestCase):
    def test_stage_order_is_exact_and_fixed(self):
        self.assertEqual(
            WORKFLOW_STAGE_ORDER,
            (
                STAGE_SPECIALIST_RESEARCH,
                STAGE_EVALUATION,
                STAGE_COLLABORATION,
                STAGE_FEEDBACK,
                STAGE_FINDING,
                STAGE_CORRELATION,
                STAGE_PRIORITIZATION,
                STAGE_HUMAN_REVIEW,
                STAGE_LEARNING,
                STAGE_EXECUTION_CONTROL,
            ),
        )

    def test_rule_version_is_stable(self):
        self.assertEqual(WORKFLOW_STAGE_RULE_VERSION, "r59-2")

    def test_status_vocabulary_is_closed(self):
        self.assertEqual(
            WORKFLOW_STAGE_STATUSES,
            (
                STAGE_STATUS_NOT_STARTED,
                STAGE_STATUS_READY,
                STAGE_STATUS_COMPLETED,
                STAGE_STATUS_BLOCKED,
                STAGE_STATUS_SKIPPED,
                STAGE_STATUS_INVALID,
            ),
        )
        for forbidden in ("EXECUTED", "CONFIRMED", "EXPLOITED"):
            self.assertNotIn(forbidden, WORKFLOW_STAGE_STATUSES)

    def test_reason_vocabulary_is_closed_and_deduplicated(self):
        self.assertEqual(
            len(set(WORKFLOW_STAGE_REASONS)), len(WORKFLOW_STAGE_REASONS)
        )
        for reason in (
            REASON_NOT_PROVIDED,
            REASON_SKIPPED_BY_OPTION,
            REASON_UPSTREAM_RESULT_INVALID,
            REASON_HUMAN_DECIDED,
        ):
            self.assertIn(reason, WORKFLOW_STAGE_REASONS)

    def test_metadata_keys_are_closed(self):
        for key in WORKFLOW_STAGE_METADATA_KEYS:
            lowered = key.lower()
            for forbidden in (
                "timestamp",
                "started",
                "finished",
                "duration",
                "time",
                "uuid",
            ):
                self.assertNotIn(forbidden, lowered)


class TestMetadataAndReferences(unittest.TestCase):
    def test_metadata_only_retains_closed_keys(self):
        metadata = sanitize_stage_metadata(
            {
                "specialist_count": 7,
                "finding_count": -3,
                "decision_type": "APPROVE_RESEARCH",
                "priority_band": "CRITICAL",
                "unknown_key": "value",
                "started_at": "2026-01-01T00:00:00Z",
            }
        )
        self.assertEqual(metadata["specialist_count"], 7)
        self.assertEqual(metadata["finding_count"], 0)
        self.assertEqual(metadata["decision_type"], "APPROVE_RESEARCH")
        self.assertEqual(metadata["priority_band"], "CRITICAL")
        self.assertNotIn("unknown_key", metadata)
        self.assertNotIn("started_at", metadata)

    def test_metadata_rejects_invalid_codes(self):
        metadata = sanitize_stage_metadata(
            {"decision_type": "RUN_SCANNER", "priority_band": "APOCALYPSE"}
        )
        self.assertEqual(metadata["decision_type"], "")
        self.assertEqual(metadata["priority_band"], "")

    def test_metadata_bounds_large_counts(self):
        metadata = sanitize_stage_metadata({"specialist_count": 10**12})
        self.assertEqual(metadata["specialist_count"], 4096)

    def test_reference_is_bounded(self):
        reference = sanitize_stage_reference(
            {
                "present": True,
                "reference_kind": "finding",
                "reference_id": "fnd-" + "a" * 16,
                "rule_version": "r53-6",
                "status": "completed",
                "item_count": 4,
                "raw_target": "https://example.test",
            }
        )
        self.assertEqual(reference["reference_kind"], "FINDING")
        self.assertEqual(reference["item_count"], 4)
        self.assertNotIn("raw_target", reference)

    def test_default_reference_is_fail_closed(self):
        reference = sanitize_stage_reference(None)
        self.assertFalse(reference["present"])
        self.assertEqual(reference["item_count"], 0)


class TestStageModel(unittest.TestCase):
    def stage(self, **overrides):
        stage = make_stage(
            WORKFLOW_ID,
            STAGE_FINDING,
            STAGE_STATUS_COMPLETED,
            REASON_HUMAN_DECIDED,
        )
        stage.update(overrides)
        return stage

    def test_valid_stage_round_trips(self):
        stage = self.stage()
        model = WorkflowStagePlan(**stage)
        self.assertEqual(
            workflow_stage_plan_projection(model)["stage_id"],
            stage["stage_id"],
        )

    def test_stage_id_is_deterministic(self):
        first = stage_id(WORKFLOW_ID, STAGE_FINDING)
        second = stage_id(WORKFLOW_ID, STAGE_FINDING)
        other = stage_id(WORKFLOW_ID, STAGE_CORRELATION)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_model_rejects_bad_stage_id(self):
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(**self.stage(stage_id="nope"))

    def test_model_rejects_unknown_stage_type(self):
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(**self.stage(stage_type="RUN_SCANNER"))

    def test_model_rejects_execution_and_confirmation(self):
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(**self.stage(execution_performed=True))
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(**self.stage(vulnerability_confirmed=True))
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(**self.stage(exploit_authorized=True))

    def test_invalid_stage_requires_invalid_reason(self):
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(
                **self.stage(
                    stage_status=STAGE_STATUS_INVALID,
                    reason=REASON_NOT_PROVIDED,
                )
            )

    def test_skipped_stage_requires_skip_reason(self):
        with self.assertRaises(ValidationError):
            WorkflowStagePlan(
                **self.stage(
                    stage_status=STAGE_STATUS_SKIPPED,
                    reason=REASON_HUMAN_DECIDED,
                )
            )

    def test_limitations_are_ordered_by_vocabulary(self):
        stage = self.stage(
            limitations=list(reversed(WORKFLOW_STAGE_LIMITATIONS))
        )
        model = WorkflowStagePlan(**stage)
        ordered = [
            code
            for code in WORKFLOW_STAGE_LIMITATIONS
            if code in set(model.limitations)
        ]
        self.assertEqual(model.limitations, ordered)

    def test_sanitizer_defaults_are_fail_closed(self):
        projected = sanitize_workflow_stage(None)
        self.assertEqual(projected["stage_type"], "")
        self.assertEqual(projected["stage_status"], STAGE_STATUS_INVALID)
        self.assertFalse(projected["execution_performed"])
        self.assertFalse(projected["vulnerability_confirmed"])
        self.assertTrue(projected["research_only"])

    def test_stage_ready_and_blocked_statuses_are_supported(self):
        for status in (
            STAGE_STATUS_READY,
            STAGE_STATUS_BLOCKED,
            STAGE_STATUS_NOT_STARTED,
        ):
            reason = (
                REASON_NOT_PROVIDED
                if status == STAGE_STATUS_NOT_STARTED
                else REASON_HUMAN_DECIDED
            )
            model = WorkflowStagePlan(
                **self.stage(stage_status=status, reason=reason)
            )
            self.assertEqual(model.stage_status, status)


if __name__ == "__main__":
    unittest.main(verbosity=2)

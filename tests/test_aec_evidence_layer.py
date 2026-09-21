"""Tests for the aec.evidence package (AEC-1 EPIC 2: Evidence Intelligence).

Offline only: T5 observation plans become evidence artifact drafts with
completeness quality assessment and a WAITING→PARTIAL→READY state machine.
No collection happens here — nothing is contacted, nothing is concluded
about any target.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from aec.case_compiler import compile_authorization_request
from aec.models import CaseRef, EvidenceGap
from aec.observation_plan import compile_observation_plan

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "aec" / "evidence"
MODULES = ("models.py", "builder.py", "quality.py", "state_machine.py", "serialization.py")

VOCAB_BANNED = frozenset({
    "CONFIRMED",
    "VULNERABLE",
    "NOT_VULNERABLE",
    "EXPLOITABLE",
    "FINDING",
    "VERDICT",
    "SEVERITY",
    "CRITICAL",
    "CVSS",
})

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify",
})

STATES = ("WAITING_EVIDENCE", "EVIDENCE_PARTIAL", "EVIDENCE_READY")


def make_case(**overrides):
    fields = {
        "case_id": "case-001",
        "job_id": "case-001",
        "program": "pilot",
        "host": "example.com",
        "endpoint": "/item",
        "parameter": "id",
        "method": "GET",
        "category": "idor",
        "confidence": "MEDIUM",
        "url": "https://example.com/item?id=1",
        "evidence_gap": EvidenceGap.build(
            ("response-body", "status-code"),
            ("response-body", "status-code"),
            artifacts=[],
        ),
    }
    fields.update(overrides)
    return CaseRef(**fields)


def make_plan():
    draft = compile_authorization_request(make_case()).request
    outcome = compile_observation_plan(draft)
    assert outcome.ok, outcome.refusal_code
    return outcome.plan


def make_artifacts():
    from aec.evidence import builder

    outcome = builder.build_artifacts(make_plan())
    assert outcome.ok, outcome.refusal_code
    return outcome.artifacts


class TestBuilder(unittest.TestCase):
    def test_valid_plan_builds(self):
        from aec.evidence import builder

        outcome = builder.build_artifacts(make_plan())
        self.assertTrue(outcome.ok)
        self.assertIsNone(outcome.refusal_code)
        self.assertGreaterEqual(len(outcome.artifacts), 2)

    def test_artifact_kinds_cover_plan_purposes(self):
        from aec.evidence import builder

        kinds = [a.artifact_kind for a in make_artifacts()]
        self.assertEqual(kinds[0], "baseline")
        self.assertIn("comparison", kinds)
        self.assertEqual(kinds[-1], "context")

    def test_artifact_identity_fields(self):
        from aec.evidence import builder

        for artifact in make_artifacts():
            self.assertTrue(artifact.artifact_id)
            self.assertEqual(artifact.case_id, "case-001")
            self.assertTrue(artifact.plan_id.startswith("plan-case-001"))
            self.assertTrue(artifact.observation_ref)
            self.assertTrue(artifact.artifact_type)

    def test_observation_ref_matches_plan_step(self):
        from aec.evidence import builder

        plan = make_plan()
        step_ids = [s.step_id for s in plan.steps]
        refs = [a.observation_ref for a in builder.build_artifacts(plan).artifacts]
        self.assertEqual(refs, step_ids)

    def test_missing_fields_state_targets(self):
        from aec.evidence import builder

        for artifact in make_artifacts():
            self.assertGreaterEqual(len(artifact.missing_fields), 1)
            if artifact.artifact_kind == "context":
                self.assertIn("context", artifact.missing_fields)
            else:
                self.assertIn(artifact.artifact_type, artifact.missing_fields)

    def test_collected_fields_name_known_dimensions(self):
        from aec.evidence import builder

        for artifact in make_artifacts():
            self.assertIn("parameter", artifact.collected_fields)
            self.assertIn("method", artifact.collected_fields)

    def test_deterministic_ids_and_order(self):
        from aec.evidence import builder

        first = builder.build_artifacts(make_plan())
        second = builder.build_artifacts(make_plan())
        self.assertEqual(first, second)
        ids = [a.artifact_id for a in first.artifacts]
        self.assertEqual(ids, sorted(ids))

    def test_serialized_round_trip_builds(self):
        from aec.evidence import builder
        from aec.observation_plan import serialize_plan

        wire = json.loads(serialize_plan(make_plan()))
        outcome = builder.build_artifacts(wire)
        self.assertTrue(outcome.ok)

    def test_invalid_inputs_refused(self):
        from aec.evidence import builder

        for bad in (None, "x", 42, {"plan_id": "p"}):
            outcome = builder.build_artifacts(bad)
            self.assertFalse(outcome.ok)
            self.assertIsNotNone(outcome.refusal_code)
            self.assertEqual(outcome.artifacts, ())

    def test_empty_plan_refused(self):
        from aec.evidence import builder

        wire = make_plan().to_dict()
        wire["steps"] = []
        outcome = builder.build_artifacts(wire)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "EMPTY_PLAN")

    def test_unknown_purpose_refused(self):
        from aec.evidence import builder

        wire = make_plan().to_dict()
        wire["steps"][0]["purpose"] = "PROBE"
        outcome = builder.build_artifacts(wire)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "UNSUPPORTED_PURPOSE")

    def test_refusal_vocabulary_closed(self):
        from aec.evidence import builder

        codes = set()
        for bad in (None, {"plan_id": "p"}):
            codes.add(builder.build_artifacts(bad).refusal_code)
        wire = make_plan().to_dict()
        wire["steps"] = []
        codes.add(builder.build_artifacts(wire).refusal_code)
        # A valid plan is not a refusal; it must build.
        self.assertTrue(builder.build_artifacts(make_plan().to_dict()).ok)
        self.assertLessEqual(
            codes, {"INVALID_PLAN", "EMPTY_PLAN", "MISSING_CASE", "UNSUPPORTED_PURPOSE"}
        )

    def test_input_plan_unchanged(self):
        from aec.evidence import builder

        plan = make_plan()
        before = plan.to_dict()
        builder.build_artifacts(plan)
        self.assertEqual(plan.to_dict(), before)

    def test_output_is_frozen(self):
        from aec.evidence import builder

        artifact = make_artifacts()[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            artifact.artifact_id = "mutated"

    def test_artifact_type_mirrors_step_target(self):
        from aec.evidence import builder

        plan = make_plan()
        for artifact, step in zip(builder.build_artifacts(plan).artifacts, plan.steps):
            if artifact.artifact_kind == "context":
                self.assertEqual(artifact.artifact_type, "context")
            else:
                self.assertEqual(artifact.artifact_type, step.expected_artifact_type)

    def test_provenance_carries_plan_and_case(self):
        from aec.evidence import builder

        for artifact in make_artifacts():
            provenance = dict(artifact.provenance)
            self.assertEqual(provenance.get("plan_id"), artifact.plan_id)
            self.assertEqual(provenance.get("case_id"), "case-001")


class TestQuality(unittest.TestCase):
    def test_full_collection_scores_one(self):
        from aec.evidence import models, quality

        artifact = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="c", observation_ref="s01",
            artifact_kind="baseline", artifact_type="response-body",
            collected_fields=("parameter", "method", "response-body"),
            missing_fields=(),
            provenance=(("plan_id", "p"), ("case_id", "c")),
        )
        assessment = quality.assess(artifact)
        self.assertEqual(assessment.completeness, 1.0)
        self.assertEqual(assessment.overall, 1.0)

    def test_builder_drafts_score_partial_completeness(self):
        # Plan-known dimensions are described, values are outstanding:
        # a fresh draft is partially described, never complete, never empty.
        from aec.evidence import quality

        for artifact in make_artifacts():
            completeness = quality.assess(artifact).completeness
            self.assertGreater(completeness, 0.0)
            self.assertLess(completeness, 1.0)

    def test_completeness_is_collected_over_union(self):
        from aec.evidence import models, quality

        artifact = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="c", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("a", "b"), missing_fields=("c", "d"),
            provenance=(("plan_id", "p"),),
        )
        self.assertEqual(quality.assess(artifact).completeness, 0.5)

    def test_dimensions_bounded(self):
        from aec.evidence import quality

        for artifact in make_artifacts():
            assessment = quality.assess(artifact)
            for value in (
                assessment.completeness, assessment.consistency,
                assessment.reproducibility, assessment.provenance,
                assessment.overall,
            ):
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)

    def test_overall_is_mean_of_dimensions(self):
        from aec.evidence import quality

        assessment = quality.assess(make_artifacts()[0])
        expected = round(
            (assessment.completeness + assessment.consistency
             + assessment.reproducibility + assessment.provenance) / 4, 3
        )
        self.assertEqual(assessment.overall, expected)

    def test_duplicate_names_reduce_consistency(self):
        from aec.evidence import models, quality

        clean = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="c", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("a",), missing_fields=("b",),
            provenance=(("plan_id", "p"),),
        )
        dup = dataclasses.replace(
            clean, collected_fields=("a",), missing_fields=("a", "b")
        )
        self.assertGreater(
            quality.assess(clean).consistency, quality.assess(dup).consistency
        )

    def test_missing_refs_zero_reproducibility(self):
        from aec.evidence import models, quality

        artifact = models.EvidenceArtifactDraft(
            artifact_id="", plan_id="", case_id="", observation_ref="",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=(), missing_fields=("x",), provenance=(),
        )
        assessment = quality.assess(artifact)
        self.assertEqual(assessment.reproducibility, 0.0)
        self.assertEqual(assessment.provenance, 0.0)

    def test_assessment_is_deterministic(self):
        from aec.evidence import quality

        artifact = make_artifacts()[0]
        self.assertEqual(quality.assess(artifact), quality.assess(artifact))

    def test_assessment_binds_artifact(self):
        from aec.evidence import quality

        artifact = make_artifacts()[0]
        assessment = quality.assess(artifact)
        self.assertEqual(assessment.artifact_id, artifact.artifact_id)

    def test_no_textual_grades(self):
        from aec.evidence import quality

        text = json.dumps(quality.assess(make_artifacts()[0]).to_dict())
        for word in ("high", "medium", "low", "grade", "rating", "score"):
            self.assertNotIn(word, text.lower())

    def test_builder_artifacts_carry_full_provenance(self):
        from aec.evidence import quality

        for artifact in make_artifacts():
            self.assertEqual(quality.assess(artifact).provenance, 1.0)


class TestStateMachine(unittest.TestCase):
    def test_initial_state_waiting(self):
        from aec.evidence import state_machine

        state = state_machine.initial_state("case-001")
        self.assertEqual(state.state, "WAITING_EVIDENCE")
        self.assertEqual(state.case_id, "case-001")

    def test_no_artifacts_stays_waiting(self):
        from aec.evidence import state_machine

        state = state_machine.advance(state_machine.initial_state("case-001"), ())
        self.assertEqual(state.state, "WAITING_EVIDENCE")

    def test_planned_dimensions_hold_partial(self):
        # A built draft describes known dimensions with values outstanding:
        # the record is opened (PARTIAL), never complete, never empty.
        from aec.evidence import state_machine

        state = state_machine.advance(
            state_machine.initial_state("case-001"), make_artifacts()
        )
        self.assertEqual(state.state, "EVIDENCE_PARTIAL")

    def test_partial_collection_moves_to_partial(self):
        from aec.evidence import models, state_machine

        artifact = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="case-001", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("parameter", "t"), missing_fields=("other",),
            provenance=(("plan_id", "p"),),
        )
        state = state_machine.advance(
            state_machine.initial_state("case-001"), (artifact,)
        )
        self.assertEqual(state.state, "EVIDENCE_PARTIAL")

    def test_full_collection_moves_to_ready(self):
        from aec.evidence import models, state_machine

        artifact = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="case-001", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("parameter", "t"), missing_fields=(),
            provenance=(("plan_id", "p"),),
        )
        state = state_machine.advance(
            state_machine.initial_state("case-001"), (artifact,)
        )
        self.assertEqual(state.state, "EVIDENCE_READY")

    def test_partial_advances_to_ready(self):
        from aec.evidence import models, state_machine

        partial = models.EvidenceGapState(
            case_id="case-001", state="EVIDENCE_PARTIAL",
            known_fields=("parameter",), missing_fields=("t",), history=("WAITING_EVIDENCE",),
        )
        full = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="case-001", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("parameter", "t"), missing_fields=(),
            provenance=(("plan_id", "p"),),
        )
        state = state_machine.advance(partial, (full,))
        self.assertEqual(state.state, "EVIDENCE_READY")

    def test_ready_is_terminal(self):
        from aec.evidence import models, state_machine

        ready = models.EvidenceGapState(
            case_id="case-001", state="EVIDENCE_READY",
            known_fields=("parameter", "t"), missing_fields=(),
            history=("WAITING_EVIDENCE", "EVIDENCE_PARTIAL"),
        )
        self.assertEqual(state_machine.advance(ready, ()).state, "EVIDENCE_READY")

    def test_history_records_transitions(self):
        from aec.evidence import models, state_machine

        artifact = models.EvidenceArtifactDraft(
            artifact_id="a1", plan_id="p", case_id="case-001", observation_ref="s01",
            artifact_kind="baseline", artifact_type="t",
            collected_fields=("parameter", "t"), missing_fields=("x",),
            provenance=(("plan_id", "p"),),
        )
        state = state_machine.advance(
            state_machine.initial_state("case-001"), (artifact,)
        )
        self.assertEqual(list(state.history), ["WAITING_EVIDENCE"])
        self.assertIn("t", state.known_fields)
        self.assertIn("x", state.missing_fields)

    def test_direct_skip_refused(self):
        from aec.evidence import state_machine

        outcome = state_machine.transition("WAITING_EVIDENCE", "EVIDENCE_READY")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_adjacent_transition_allowed(self):
        from aec.evidence import state_machine

        outcome = state_machine.transition("WAITING_EVIDENCE", "EVIDENCE_PARTIAL")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.state, "EVIDENCE_PARTIAL")

    def test_backward_transition_refused(self):
        from aec.evidence import state_machine

        outcome = state_machine.transition("EVIDENCE_PARTIAL", "WAITING_EVIDENCE")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_TRANSITION")

    def test_unknown_state_refused(self):
        from aec.evidence import state_machine

        outcome = state_machine.transition("WAITING_EVIDENCE", "EVIDENCE_DONE")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_STATE")

    def test_advance_is_deterministic(self):
        from aec.evidence import state_machine

        artifacts = make_artifacts()
        first = state_machine.advance(state_machine.initial_state("case-001"), artifacts)
        second = state_machine.advance(state_machine.initial_state("case-001"), artifacts)
        self.assertEqual(first, second)

    def test_state_output_is_frozen(self):
        from aec.evidence import state_machine

        state = state_machine.initial_state("case-001")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            state.state = "EVIDENCE_READY"

    def test_union_coverage_across_artifacts(self):
        from aec.evidence import models, state_machine

        def part(collected, missing):
            return models.EvidenceArtifactDraft(
                artifact_id="a", plan_id="p", case_id="case-001",
                observation_ref="s01", artifact_kind="baseline",
                artifact_type="t", collected_fields=collected,
                missing_fields=missing, provenance=(("plan_id", "p"),),
            )

        first = part(("parameter", "x"), ("y",))
        second = part(("parameter", "y"), ("x",))
        state = state_machine.advance(
            state_machine.initial_state("case-001"), (first, second)
        )
        self.assertEqual(state.state, "EVIDENCE_READY")

    def test_non_sequence_artifacts_hold_state(self):
        from aec.evidence import state_machine

        state = state_machine.advance(
            state_machine.initial_state("case-001"), None
        )
        self.assertEqual(state.state, "WAITING_EVIDENCE")


class TestSerialization(unittest.TestCase):
    def test_artifact_round_trip(self):
        from aec.evidence import serialization

        artifact = make_artifacts()[0]
        text = serialization.serialize_artifact(artifact)
        self.assertEqual(json.loads(text), artifact.to_dict())
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)

    def test_assessment_round_trip(self):
        from aec.evidence import quality, serialization

        assessment = quality.assess(make_artifacts()[0])
        text = serialization.serialize_assessment(assessment)
        self.assertEqual(json.loads(text), assessment.to_dict())

    def test_state_round_trip(self):
        from aec.evidence import serialization, state_machine

        state = state_machine.advance(
            state_machine.initial_state("case-001"), make_artifacts()
        )
        text = serialization.serialize_state(state)
        self.assertEqual(json.loads(text), state.to_dict())

    def test_bundle_is_deterministic(self):
        from aec.evidence import quality, serialization, state_machine

        artifacts = make_artifacts()
        assessments = [quality.assess(a) for a in artifacts]
        state = state_machine.advance(state_machine.initial_state("case-001"), artifacts)
        first = serialization.serialize_bundle(artifacts, assessments, state)
        second = serialization.serialize_bundle(artifacts, assessments, state)
        self.assertEqual(first, second)
        bundle = json.loads(first)
        self.assertEqual(len(bundle["artifacts"]), len(artifacts))
        self.assertEqual(bundle["state"]["case_id"], "case-001")

    def test_bundle_assessments_bind_artifacts(self):
        from aec.evidence import quality, serialization, state_machine

        artifacts = make_artifacts()
        assessments = [quality.assess(a) for a in artifacts]
        state = state_machine.advance(state_machine.initial_state("case-001"), artifacts)
        bundle = json.loads(serialization.serialize_bundle(artifacts, assessments, state))
        self.assertEqual(
            [a["artifact_id"] for a in bundle["assessments"]],
            [a["artifact_id"] for a in bundle["artifacts"]],
        )


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_authority_imports(self):
        for name in MODULES:
            tree = ast.parse((EVIDENCE_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)
        for name in MODULES:
            self.assertNotIn("authorizer", (EVIDENCE_DIR / name).read_text(), name)

    def test_modules_perform_no_filesystem_writes(self):
        for name in MODULES:
            tree = ast.parse((EVIDENCE_DIR / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = ""
                    if isinstance(func, ast.Name):
                        called = func.id
                    elif isinstance(func, ast.Attribute):
                        called = func.attr
                    self.assertNotIn(called, {"write_text", "mkdir", "makedirs"}, name)
                    if called == "open":
                        modes = [
                            a.value for a in node.args[1:]
                            if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        ]
                        for mode in modes:
                            self.assertNotIn("w", mode.replace("U", ""), name)

    def test_modules_have_no_verdict_or_severity_vocabulary(self):
        for name in MODULES:
            source = (EVIDENCE_DIR / name).read_text()
            for word in VOCAB_BANNED:
                self.assertNotIn(
                    word, set(re.findall(r"[A-Za-z_]+", source.upper())), name
                )

    def test_live_capability_modules_absent(self):
        aec_dir = EVIDENCE_DIR.parent
        self.assertFalse((aec_dir / "live_deps.py").exists())
        self.assertFalse((aec_dir / "observation_lane.py").exists())


if __name__ == "__main__":
    unittest.main()

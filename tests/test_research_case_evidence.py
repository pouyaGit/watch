"""Stage R87 — focused tests for real case evidence completion.

Covers exactly the new behavior:

- genuine deterministic match evidence is accepted and moves the case along
  the existing readiness ladder only when the evidence genuinely supports it;
- unsupported, wrong-program, wrong-case, wrong-category and model-only
  claims never become evidence;
- missing provenance is rejected by the existing boundary;
- duplicate evidence is idempotent and repeated evaluation is byte-stable;
- insufficient evidence keeps the case WAITING_FOR_EVIDENCE;
- contradictory evidence is preserved as a conflict (never hidden);
- the source artifact is only read and nothing is written unless requested.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.knowledge.research_evidence_submission import (
    ERROR_CASE_MISMATCH,
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
    SUBMISSION_VERSION,
    submit_research_evidence,
)
from ai.knowledge.asset_cve_matching import match_component, match_plugin
from ai.knowledge.version_component_association import (
    evaluate_version_association,
)
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_case_workspace import update_research_case
from ai.research_agent.case_bridge import (
    activate_result,
    case_artifact_path,
)
from ai.research_agent.case_evidence import (
    REASON_ALL_REPLAYED,
    REASON_CASE_ID_MISMATCH,
    REASON_NO_ITEMS,
    STATUS_COMPLETED,
    STATUS_ERROR,
    STATUS_NO_EVIDENCE,
    STATUS_REPLAYED,
    build_completion_items,
    complete_case_evidence,
)
from ai.research_agent.llm_loop import loop_result_id_for

PLAN_A = "r22-" + "ab" * 8
CVE = "CVE-2026-99999"
HASH = "a" * 64
CASE_ID = "case-dell-a1-component-mapping"


def _evidence(evidence_id, source_id, claim, confidence="LOW"):
    return {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "content_hash": HASH,
        "claim": claim,
        "confidence": confidence,
        "source_url": "https://example.invalid/advisory",
    }


def loop_payload(*, cve_id=CVE, evidence=None, status="RESEARCH_COMPLETED"):
    if evidence is None:
        evidence = [
            _evidence(
                "de-1111111111111111",
                "ds-2222222222222222",
                "vendor advisory mentions the affected component",
            ),
            _evidence(
                "de-3333333333333333",
                "ds-4444444444444444",
                "documentation page lists affected versions",
                confidence="MEDIUM",
            ),
        ]
    return {
        "loop_rule_version": "r24-loop-1",
        "result_id": loop_result_id_for(PLAN_A, cve_id),
        "plan_id": PLAN_A,
        "cve_id": cve_id,
        "status": status,
        "production_finding": False,
        "rounds": [{"discovery": {"evidence": list(evidence)}}],
        "gaps": ["exact component-version mapping"],
        "unknowns": ["applicability evidence"],
    }


def plan_loader(plan_id):
    return {
        "plan_id": str(plan_id),
        "program": "dell",
        "cve_id": CVE,
        "metadata": {"priority_level": "CRITICAL_RESEARCH"},
    }


def match_row(
    *,
    program="dell",
    cve_id=CVE,
    technology="",
    version="",
    component="",
    match_id="am-2cf8fb279dde4632",
):
    all_matches = []
    if technology:
        all_matches.append(
            {
                "match_id": "am-1111111111111111",
                "match_type": "TECHNOLOGY",
                "matched_value": technology,
                "cve_id": cve_id,
                "program": program,
            }
        )
    if version:
        all_matches.append(
            {
                "match_id": "am-2222222222222222",
                "match_type": "VERSION",
                "matched_value": version,
                "cve_id": cve_id,
                "program": program,
            }
        )
    if component:
        all_matches.append(
            {
                "match_id": match_id,
                "match_type": "PLUGIN",
                "matched_value": component,
                "cve_id": cve_id,
                "program": program,
            }
        )
    return {
        "cve_id": cve_id,
        "program": program,
        "all_matches": all_matches,
        "matched_component": component,
        "matched_version": version,
    }


class CaseEvidenceTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cases = self.root / "cases"
        outcome = activate_result(
            loop_payload(), plan_loader=plan_loader, cases_dir=self.cases
        )
        self.assertEqual(outcome["status"], "ACTIVATED")
        self.case_path = case_artifact_path(CASE_ID, self.cases)
        self.assertTrue(self.case_path.is_file())

    def artifact(self):
        return json.loads(self.case_path.read_text(encoding="utf-8"))

    def stages(self, artifact):
        return {
            "case": artifact["research_case_workspace"]["cases"][0],
            "hypotheses": artifact["research"]["hypotheses"],
            "action_plan": artifact["action_plan"],
            "acquisition_plan": artifact["acquisition_plan"],
            "readiness_plan": artifact["readiness_plan"],
        }

    def loader(self, rows):
        return lambda _cve: rows

    def boundary_call(self, artifact, items, *, case_ref=None, submitted_by=""):
        stages = self.stages(artifact)
        envelope = {
            "submission_version": SUBMISSION_VERSION,
            "case_ref": case_ref or CASE_ID,
            "submitted_by": submitted_by,
            "items": items,
        }
        return submit_research_evidence(
            envelope,
            case=stages["case"],
            hypotheses=stages["hypotheses"],
            action_plan=stages["action_plan"],
            acquisition_plan=stages["acquisition_plan"],
            readiness_plan=stages["readiness_plan"],
        )


class TestEvidenceSelection(CaseEvidenceTestCase):
    def test_genuine_technology_item_is_built(self):
        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case, CVE, [match_row(technology="WordPress")]
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["requirement_kind"], "TECHNOLOGY_IDENTITY")
        self.assertEqual(item["evidence_ref"], "technology:WordPress")
        self.assertEqual(item["hypothesis_ref"], "H1")
        self.assertEqual(item["effect"], "PROVIDES")
        self.assertEqual(
            item["observations"][0]["ref"], "technology:WordPress"
        )
        self.assertEqual(unavailable.get("VERSION_IDENTITY"), "NO_MATCHING_OBSERVATION")

    def test_wrong_program_row_is_ignored(self):
        case = self.stages(self.artifact())["case"]
        items, _ = build_completion_items(
            case,
            CVE,
            [match_row(program="indeed", technology="WordPress")],
        )
        self.assertEqual(items, [])

    def test_model_text_never_becomes_evidence(self):
        case = self.stages(self.artifact())["case"]
        artifacts = self.artifact()
        self.assertTrue(
            any(
                "component" in (h.get("title") or "").lower()
                or "WordPress" in (h.get("title") or "")
                for h in artifacts["research"]["hypotheses"]
            )
        )
        items, _ = build_completion_items(case, CVE, [])
        self.assertEqual(items, [])

    def test_unavailable_rows_produce_no_items(self):
        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case, "CVE-0000-00000", [match_row(technology="WordPress")]
        )
        self.assertEqual(items, [])
        self.assertEqual(
            unavailable.get("TECHNOLOGY_IDENTITY"), "NO_MATCHING_OBSERVATION"
        )
        self.assertEqual(
            unavailable.get("WATCH_SIGNAL"), "HUMAN_REVIEW_ONLY"
        )


class TestCompletionRunner(CaseEvidenceTestCase):
    def test_genuine_evidence_is_accepted_and_persisted(self):
        before = self.case_path.read_bytes()
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertTrue(outcome["written"])
        self.assertEqual(outcome["accepted_items"], 1)
        self.assertEqual(outcome["after_status"], "ACTIVE")
        self.assertEqual(
            outcome["available_requirement_kinds"], ["TECHNOLOGY_IDENTITY"]
        )
        self.assertIn("COMPONENT_BINDING", outcome["missing_requirement_kinds"])
        self.assertEqual(outcome["provenance"]["conflict_count"], 0)
        self.assertFalse(outcome["provenance"]["human_review_required"])
        self.assertNotEqual(self.case_path.read_bytes(), before)

        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "ACTIVE")
        self.assertEqual(case["evidence"]["available_count"], 1)
        self.assertEqual(case["iteration_count"], 2)
        completed = artifact["evidence_completion"]
        self.assertEqual(completed["status"], "COMPLETED")
        self.assertEqual(completed["accepted_items"], 1)

    def test_insufficient_evidence_keeps_case_waiting(self):
        before = self.case_path.read_bytes()
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_NO_EVIDENCE)
        self.assertEqual(outcome["reason"], REASON_NO_ITEMS)
        self.assertFalse(outcome["written"])
        self.assertEqual(outcome["after_status"], "")
        self.assertEqual(self.case_path.read_bytes(), before)
        case = self.artifact()["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "WAITING_FOR_EVIDENCE")

    def test_duplicate_evidence_is_idempotent(self):
        rows = [match_row(technology="WordPress")]
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        after_first = self.case_path.read_bytes()
        second = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(second["status"], STATUS_REPLAYED)
        self.assertEqual(second["reason"], REASON_ALL_REPLAYED)
        self.assertFalse(second["written"])
        self.assertEqual(second["accepted_items"], 0)
        self.assertEqual(self.case_path.read_bytes(), after_first)
        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        self.assertEqual(case["iteration_count"], 2)
        self.assertEqual(
            artifact["evidence_provenance"]["summary"]["record_count"], 1
        )

    def test_repeated_evaluation_is_deterministic(self):
        rows = [match_row(technology="WordPress")]
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=False,
        )
        second = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=False,
        )
        self.assertEqual(first, second)
        self.assertFalse(first["written"])

        with tempfile.TemporaryDirectory() as other:
            cases = Path(other) / "cases"
            activate_result(
                loop_payload(), plan_loader=plan_loader, cases_dir=cases
            )
            path = case_artifact_path(CASE_ID, cases)
            complete_case_evidence(
                path,
                expected_case_id=CASE_ID,
                match_loader=self.loader(rows),
                write=True,
            )
            complete_case_evidence(
                self.case_path,
                expected_case_id=CASE_ID,
                match_loader=self.loader(rows),
                write=True,
            )
            self.assertEqual(path.read_bytes(), self.case_path.read_bytes())

    def test_wrong_case_id_fails_closed(self):
        before = self.case_path.read_bytes()
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id="case-somewhere-else",
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_ERROR)
        self.assertEqual(outcome["reason"], REASON_CASE_ID_MISMATCH)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_sufficient_evidence_allows_natural_transition(self):
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(
                [
                    match_row(
                        technology="WordPress",
                        version="1.0",
                        component="wp-responsive-images",
                    )
                ]
            ),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(outcome["accepted_items"], 3)
        self.assertEqual(outcome["after_status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            outcome["readiness"]["decision_state"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(
            outcome["missing_requirement_kinds"], ["WATCH_SIGNAL"]
        )

    def test_contradictory_evidence_is_preserved(self):
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        artifact = self.artifact()
        stages = self.stages(artifact)
        contradiction = {
            "hypothesis_ref": "H1",
            "requirement_kind": "TECHNOLOGY_IDENTITY",
            "effect": "CONTRADICTS",
            "source": "HUMAN_REVIEW",
            "evidence_ref": "technology:Nginx",
            "observations": [
                {"ref": "technology:Nginx", "fact": "different technology"}
            ],
        }
        submitted = self.boundary_call(artifact, [contradiction])
        self.assertEqual(submitted["status"], "ACCEPTED")
        provenance = analyze_evidence_provenance(
            submitted["intake"],
            hypotheses=stages["hypotheses"],
            action_plan=stages["action_plan"],
            acquisition_plan=stages["acquisition_plan"],
            readiness_plan=stages["readiness_plan"],
            previous_provenance=artifact["evidence_provenance"],
        )
        record = provenance["records"][0]
        self.assertEqual(record["relation_to_previous"], "CONTRADICTS_EXISTING")
        self.assertEqual(record["conflict_state"], "CONFLICTING")
        self.assertTrue(record["human_review_required"])
        reevaluation = submitted["intake"]["reevaluation"]
        updated = update_research_case(
            stages["case"],
            stages["action_plan"],
            reevaluation["acquisition_after"],
            reevaluation["readiness_after"],
            reevaluation["feedback"],
            evidence_intake=submitted["intake"],
            evidence_provenance=provenance,
        )
        self.assertTrue(updated["human_review_required"])
        self.assertIn(updated["status"], ("STOPPED", "READY_FOR_HUMAN_REVIEW"))


class TestBoundaryRejections(CaseEvidenceTestCase):
    def _technology_item(self, **overrides):
        item = {
            "hypothesis_ref": "H1",
            "requirement_kind": "TECHNOLOGY_IDENTITY",
            "effect": "PROVIDES",
            "source": "WATCH_DERIVED",
            "evidence_ref": "technology:WordPress",
            "observations": [
                {"ref": "technology:WordPress", "fact": "observed"}
            ],
        }
        item.update(overrides)
        return item

    def test_wrong_case_ref_is_rejected(self):
        submitted = self.boundary_call(
            self.artifact(),
            [self._technology_item()],
            case_ref="case-other-case",
        )
        self.assertEqual(submitted["status"], "SUBMISSION_REJECTED")
        self.assertEqual(submitted["rejections"][0]["code"], ERROR_CASE_MISMATCH)

    def test_wrong_requirement_category_is_rejected(self):
        submitted = self.boundary_call(
            self.artifact(),
            [self._technology_item(requirement_kind="METHOD_AUTH")],
        )
        self.assertEqual(submitted["status"], "SUBMISSION_REJECTED")
        self.assertEqual(
            submitted["rejections"][0]["code"],
            ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
        )

    def test_model_claim_ref_is_not_evidence(self):
        submitted = self.boundary_call(
            self.artifact(),
            [
                self._technology_item(
                    evidence_ref="claim:model-says-wordpress",
                    observations=[
                        {"ref": "claim:model-says-wordpress", "fact": "model"}
                    ],
                )
            ],
        )
        self.assertIsNotNone(submitted["intake"])
        self.assertEqual(submitted["intake"]["package_status"], "REJECTED")
        self.assertEqual(
            submitted["intake"]["rejections"][0]["code"],
            "INVALID_EVIDENCE_REF",
        )

    def test_missing_provenance_is_rejected(self):
        submitted = self.boundary_call(
            self.artifact(),
            [self._technology_item(observations=[], evidence_ref="")],
        )
        self.assertIsNotNone(submitted["intake"])
        self.assertEqual(submitted["intake"]["package_status"], "REJECTED")
        self.assertEqual(
            submitted["intake"]["rejections"][0]["code"],
            "MALFORMED_EVIDENCE",
        )


class TestComponentVersionCorrelation(CaseEvidenceTestCase):
    """R88: deterministic component/version correlation boundaries.

    The component/version rules are the existing R30.1/R30.3 authorities:
    a component binding exists only when the matcher produces an explicit
    row, and a version exists only when the association rule exposes an
    engine version owned by the affected component. Naming similarity, CVE
    research text and CVE affected ranges never become evidence.
    """

    COMPONENT = "wp-responsive-images"

    def _correlate(self, **kwargs):
        base = {
            "cve_families": ["WordPress"],
            "cve_plugins": ["WP Responsive Images"],
            "cve_versions": ["<=1.0"],
        }
        base.update(kwargs)
        return evaluate_version_association(**base)

    def test_exact_normalized_component_match_is_supported(self):
        match = match_plugin(["WP Responsive Images"], [self.COMPONENT])
        self.assertIsNotNone(match)
        self.assertEqual(match.match_type, "PLUGIN")
        self.assertEqual(match.normalized_value, "wp responsive images")

    def test_similar_or_wrong_components_are_not_matches(self):
        self.assertIsNone(
            match_plugin(["WP Responsive Images"], ["wp-smushit"])
        )
        self.assertIsNone(
            match_component(["WP Responsive Images"], ["TinyMCE"])
        )

    def test_component_match_row_becomes_component_binding_evidence(self):
        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case,
            CVE,
            [
                match_row(
                    technology="WordPress",
                    component=self.COMPONENT,
                    match_id="am-2cf8fb279dde4632",
                )
            ],
        )
        binding = [
            item
            for item in items
            if item["requirement_kind"] == "COMPONENT_BINDING"
        ]
        self.assertEqual(len(binding), 1)
        self.assertEqual(
            binding[0]["evidence_ref"], "record:am-2cf8fb279dde4632"
        )
        self.assertNotIn("COMPONENT_BINDING", unavailable)

    def test_no_component_row_means_no_binding(self):
        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case, CVE, [match_row(technology="WordPress")]
        )
        self.assertEqual(
            [
                item
                for item in items
                if item["requirement_kind"] == "COMPONENT_BINDING"
            ],
            [],
        )
        self.assertEqual(
            unavailable.get("COMPONENT_BINDING"), "NO_MATCHING_OBSERVATION"
        )

    def test_unowned_version_is_withheld(self):
        result = self._correlate(
            observed_versions=[
                {
                    "version": "1.0",
                    "technology_family": "WordPress",
                    "component": "",
                }
            ],
            observed_plugins=["wp-smushit"],
        )
        self.assertEqual(
            result.state, "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION"
        )
        self.assertEqual(result.engine_versions, ())
        self.assertFalse(result.component_available)

    def test_family_mismatch_is_withheld(self):
        result = self._correlate(
            observed_versions=[
                {
                    "version": "4.2.0",
                    "technology_family": "jQuery",
                    "component": "",
                }
            ]
        )
        self.assertEqual(result.state, "FAMILY_MISMATCH")
        self.assertEqual(result.engine_versions, ())

    def test_cve_affected_range_alone_is_not_version_evidence(self):
        result = self._correlate(observed_versions=[])
        self.assertEqual(result.state, "NO_VERSION_OBSERVATION")
        self.assertEqual(result.engine_versions, ())

        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case, CVE, [match_row(technology="WordPress")]
        )
        self.assertEqual(
            [
                item
                for item in items
                if item["requirement_kind"] == "VERSION_IDENTITY"
            ],
            [],
        )
        self.assertEqual(
            unavailable.get("VERSION_IDENTITY"), "NO_MATCHING_OBSERVATION"
        )

    def test_only_an_owned_matching_version_is_exposed(self):
        result = self._correlate(
            observed_versions=[
                {
                    "version": "1.0",
                    "technology_family": "WordPress",
                    "component": self.COMPONENT,
                }
            ],
            observed_plugins=[self.COMPONENT],
        )
        self.assertEqual(result.state, "VERSION_MATCH_WITHIN_SAME_FAMILY")
        self.assertEqual(result.engine_versions, ("1.0",))
        self.assertEqual(result.component, self.COMPONENT)

    def test_model_text_never_becomes_component_evidence(self):
        case = dict(self.stages(self.artifact())["case"])
        case["title"] = "WP Responsive Images plugin observed at 1.0"
        case["recommended_action"] = "bind wp-responsive-images"
        items, unavailable = build_completion_items(case, CVE, [])
        self.assertEqual(items, [])
        self.assertEqual(
            unavailable.get("COMPONENT_BINDING"), "NO_MATCHING_OBSERVATION"
        )

    def test_component_evidence_transitions_naturally_and_is_idempotent(self):
        rows = [
            match_row(
                technology="WordPress",
                component=self.COMPONENT,
                match_id="am-2cf8fb279dde4632",
            )
        ]
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        self.assertEqual(first["accepted_items"], 2)
        self.assertEqual(first["after_status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            first["readiness"]["decision_state"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(
            first["missing_requirement_kinds"],
            ["VERSION_IDENTITY", "WATCH_SIGNAL"],
        )
        after_first = self.case_path.read_bytes()

        second = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(second["status"], STATUS_REPLAYED)
        self.assertEqual(second["reason"], REASON_ALL_REPLAYED)
        self.assertFalse(second["written"])
        self.assertEqual(self.case_path.read_bytes(), after_first)

    def test_no_new_evidence_leaves_case_state_unchanged(self):
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        self.assertEqual(first["after_status"], "ACTIVE")
        after_first = self.case_path.read_bytes()

        second = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(second["status"], STATUS_NO_EVIDENCE)
        self.assertEqual(second["reason"], REASON_NO_ITEMS)
        self.assertFalse(second["written"])
        self.assertEqual(self.case_path.read_bytes(), after_first)
        case = self.artifact()["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "ACTIVE")
        self.assertEqual(
            case["evidence"]["available_requirement_kinds"],
            ["TECHNOLOGY_IDENTITY"],
        )

    def test_component_contradiction_is_preserved(self):
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(
                [
                    match_row(
                        technology="WordPress",
                        component=self.COMPONENT,
                        match_id="am-2cf8fb279dde4632",
                    )
                ]
            ),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        artifact = self.artifact()
        stages = self.stages(artifact)
        contradiction = {
            "hypothesis_ref": "H1",
            "requirement_kind": "COMPONENT_BINDING",
            "effect": "CONTRADICTS",
            "source": "HUMAN_REVIEW",
            "evidence_ref": "record:am-0000000000000000",
            "observations": [
                {
                    "ref": "record:am-0000000000000000",
                    "fact": "the affected component is not the observed one",
                }
            ],
        }
        submitted = self.boundary_call(artifact, [contradiction])
        self.assertEqual(submitted["status"], "ACCEPTED")
        provenance = analyze_evidence_provenance(
            submitted["intake"],
            hypotheses=stages["hypotheses"],
            action_plan=stages["action_plan"],
            acquisition_plan=stages["acquisition_plan"],
            readiness_plan=stages["readiness_plan"],
            previous_provenance=artifact["evidence_provenance"],
        )
        record = provenance["records"][0]
        self.assertEqual(record["conflict_state"], "CONFLICTING")
        self.assertTrue(record["human_review_required"])
        reevaluation = submitted["intake"]["reevaluation"]
        updated = update_research_case(
            stages["case"],
            stages["action_plan"],
            reevaluation["acquisition_after"],
            reevaluation["readiness_after"],
            reevaluation["feedback"],
            evidence_intake=submitted["intake"],
            evidence_provenance=provenance,
        )
        self.assertTrue(updated["human_review_required"])
        self.assertIn(
            updated["status"], ("STOPPED", "READY_FOR_HUMAN_REVIEW")
        )


class TestCli(CaseEvidenceTestCase):
    def test_agent_evidence_subcommand_parses(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "evidence", "--case", CASE_ID, "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "evidence")
        self.assertEqual(args.case, CASE_ID)
        self.assertFalse(args.apply)

    def test_cli_dry_run_writes_nothing_and_repeat_is_idempotent(self):
        from ai import research_cli

        before = self.case_path.read_bytes()
        loader = self.loader([match_row(technology="WordPress")])
        argv = [
            "agent",
            "evidence",
            "--case",
            CASE_ID,
            "--cases-dir",
            str(self.cases),
        ]
        with mock.patch(
            "ai.research_agent.case_evidence.default_match_loader", loader
        ):
            self.assertEqual(research_cli.main(argv), 0)
            self.assertEqual(self.case_path.read_bytes(), before)

            self.assertEqual(research_cli.main(argv + ["--apply"]), 0)
            after_first = self.case_path.read_bytes()
            self.assertNotEqual(after_first, before)

            self.assertEqual(research_cli.main(argv + ["--apply"]), 0)
            self.assertEqual(self.case_path.read_bytes(), after_first)

        case = self.artifact()["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "ACTIVE")
        self.assertEqual(case["iteration_count"], 2)
        self.assertEqual(case["evidence"]["available_count"], 1)


if __name__ == "__main__":
    unittest.main()

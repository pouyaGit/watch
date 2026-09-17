"""Stage R89 — focused tests for the controlled human evidence workflow.

Covers the new behavior only:

- a synthetic (explicitly NON-REAL/OFFLINE) human submission flows through the
  existing R80 -> R74 -> R75 -> R72 -> R73 -> R76 -> R77 authorities and is
  persisted atomically by the existing R89 path;
- the human boundary fail-closes on: wrong case, wrong case_ref, unsupported
  envelope, wrong requirement, missing provenance, non-human source, model
  claim refs and fabricated Watch-deterministic identities;
- an owned/matching deterministic reference is accepted; arbitrary component
  or version bindings are not;
- WATCH_SIGNAL can never be produced by the automated path and is only
  submittable from the existing HUMAN_REVIEW source;
- duplicates replay without writes; the production-style case is never
  modified by a dry-run;
- the new API route enforces authentication, persists exactly once and
  replays duplicates; the existing R81 in-memory route is untouched;
- the CLI parses and is dry-run by default.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.research_agent.case_evidence import (
    HUMAN_EVIDENCE_RULE_VERSION,
    HUMAN_EVIDENCE_SOURCE,
    REASON_ALL_REPLAYED,
    REASON_CASE_ID_MISMATCH,
    REASON_MALFORMED_SUBMISSION,
    REASON_NON_HUMAN_SOURCE,
    REASON_UNSUPPORTED_DETERMINISTIC_REF,
    STATUS_COMPLETED,
    STATUS_ERROR,
    STATUS_REJECTED,
    STATUS_REPLAYED,
    build_completion_items,
    submit_human_case_evidence,
)
from tests.test_research_case_evidence import (
    CASE_ID,
    CVE,
    CaseEvidenceTestCase,
    loop_payload,
    match_row,
    plan_loader,
)

SYNTHETIC_LABEL = "NON-REAL/OFFLINE synthetic human review fixture"


def human_envelope(items, *, case_ref=CASE_ID, submitter="human-reviewer-a"):
    return {
        "submission_version": "r80-1",
        "case_ref": case_ref,
        "submitted_by": submitter,
        "items": items,
    }


def human_item(
    ref="response:synthetic-human-observation-1",
    *,
    kind="COMPONENT_BINDING",
    effect="PROVIDES",
    source="HUMAN_REVIEW",
    hypothesis_ref="H1",
    fact=SYNTHETIC_LABEL,
    observations=None,
):
    if observations is None:
        observations = [{"ref": ref, "fact": fact}] if ref else []
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": kind,
        "effect": effect,
        "source": source,
        "evidence_ref": ref,
        "observations": observations,
    }


class HumanSubmissionTestCase(CaseEvidenceTestCase):
    def loader(self, rows):  # noqa: D102 - mirrors the R87 helper
        return lambda _cve: rows


class TestHumanWorkflow(HumanSubmissionTestCase):
    def test_synthetic_human_workflow_transitions_and_persists(self):
        before = self.case_path.read_bytes()
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item()]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(outcome["rule_version"], HUMAN_EVIDENCE_RULE_VERSION)
        self.assertEqual(outcome["accepted_items"], 1)
        self.assertEqual(outcome["rejected_items"], 0)
        self.assertEqual(outcome["after_status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            outcome["readiness"]["decision_state"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(
            outcome["available_requirement_kinds"], ["COMPONENT_BINDING"]
        )
        self.assertTrue(outcome["written"])
        self.assertNotEqual(self.case_path.read_bytes(), before)

        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(case["iteration_count"], 2)
        self.assertEqual(
            case["evidence"]["available_requirement_kinds"],
            ["COMPONENT_BINDING"],
        )
        intake = artifact["evidence_intake"]
        self.assertEqual(intake["package_status"], "ACCEPTED")
        accepted = intake["accepted_items"][0]
        self.assertEqual(accepted["source"], "HUMAN_REVIEW")
        self.assertEqual(accepted["source"], HUMAN_EVIDENCE_SOURCE)
        self.assertEqual(accepted["requirement_kind"], "COMPONENT_BINDING")
        completed = artifact["evidence_completion"]
        self.assertEqual(
            completed["rule_version"], HUMAN_EVIDENCE_RULE_VERSION
        )
        self.assertEqual(completed["accepted_items"], 1)
        provenance = artifact["evidence_provenance"]
        self.assertEqual(provenance["package_status"], "ACCEPTED")
        self.assertEqual(len(provenance["records"]), 1)
        self.assertFalse(
            provenance["summary"]["human_review_required"]
        )

    def test_dry_run_never_writes(self):
        before = self.case_path.read_bytes()
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item()]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_duplicate_human_submission_is_idempotent(self):
        payload = human_envelope([human_item()])
        first = submit_human_case_evidence(
            self.case_path,
            payload,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        after_first = self.case_path.read_bytes()

        second = submit_human_case_evidence(
            self.case_path,
            payload,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(second["status"], STATUS_REPLAYED)
        self.assertEqual(second["reason"], REASON_ALL_REPLAYED)
        self.assertEqual(second["replayed_items"], 1)
        self.assertFalse(second["written"])
        self.assertEqual(self.case_path.read_bytes(), after_first)

        artifact = self.artifact()
        self.assertEqual(
            len(artifact["evidence_provenance"]["records"]), 1
        )
        case = artifact["research_case_workspace"]["cases"][0]
        self.assertEqual(case["iteration_count"], 2)

    def test_contradicting_human_item_is_preserved(self):
        first = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item()]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)

        contradiction = human_item(
            ref="response:synthetic-human-contradiction-1",
            effect="CONTRADICTS",
            fact="NON-REAL/OFFLINE contradiction fixture",
        )
        second = submit_human_case_evidence(
            self.case_path,
            human_envelope([contradiction]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(second["status"], STATUS_COMPLETED)
        provenance = self.artifact()["evidence_provenance"]
        self.assertEqual(provenance["summary"]["conflict_count"], 1)
        record = provenance["records"][-1]
        self.assertEqual(record["conflict_state"], "CONFLICTING")
        self.assertTrue(record["human_review_required"])
        case = self.artifact()["research_case_workspace"]["cases"][0]
        self.assertTrue(case["human_review_required"])
        self.assertIn(
            case["status"], ("STOPPED", "READY_FOR_HUMAN_REVIEW")
        )


class TestHumanBoundaryFailClosed(HumanSubmissionTestCase):
    def test_wrong_case_id_fails_closed(self):
        before = self.case_path.read_bytes()
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item()]),
            expected_case_id="case-somewhere-else",
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_ERROR)
        self.assertEqual(outcome["reason"], REASON_CASE_ID_MISMATCH)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_wrong_case_ref_rejected(self):
        before = self.case_path.read_bytes()
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item()], case_ref="case-other"),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertIn("CASE_MISMATCH", outcome["rejection_codes"])
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_missing_case_ref_and_version_rejected(self):
        before = self.case_path.read_bytes()
        for body in (
            {"submission_version": "r80-1", "items": [human_item()]},
            {
                "submission_version": "r99",
                "case_ref": CASE_ID,
                "items": [human_item()],
            },
        ):
            outcome = submit_human_case_evidence(
                self.case_path,
                body,
                expected_case_id=CASE_ID,
                match_loader=self.loader([]),
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_REJECTED)
            self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_malformed_submission_rejected(self):
        before = self.case_path.read_bytes()
        for body in (
            None,
            human_envelope([]),
            human_envelope(["not-a-mapping"]),
        ):
            outcome = submit_human_case_evidence(
                self.case_path,
                body,
                expected_case_id=CASE_ID,
                match_loader=self.loader([]),
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_REJECTED)
            self.assertEqual(outcome["reason"], REASON_MALFORMED_SUBMISSION)
            self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_wrong_requirement_rejected(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item(kind="METHOD_AUTH")]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertIn(
            "UNKNOWN_REQUIREMENT_FOR_CASE", outcome["rejection_codes"]
        )
        self.assertFalse(outcome["written"])

    def test_missing_provenance_rejected(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope([human_item(ref="", observations=[])]),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertIn("MALFORMED_EVIDENCE", outcome["rejection_codes"])
        self.assertFalse(outcome["written"])

    def test_non_human_source_rejected(self):
        before = self.case_path.read_bytes()
        for source in ("WATCH_DERIVED", "EXISTING_CONTEXT", "STORED_RESPONSE"):
            outcome = submit_human_case_evidence(
                self.case_path,
                human_envelope([human_item(source=source)]),
                expected_case_id=CASE_ID,
                match_loader=self.loader([]),
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_REJECTED)
            self.assertEqual(outcome["reason"], REASON_NON_HUMAN_SOURCE)
            self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_model_claim_ref_is_rejected_by_the_boundary(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope(
                [
                    human_item(
                        ref="claim:model-says-plugin-installed",
                        fact="NON-REAL/OFFLINE model claim fixture",
                    )
                ]
            ),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertIn("INVALID_EVIDENCE_REF", outcome["rejection_codes"])
        self.assertFalse(outcome["written"])

    def test_fabricated_deterministic_refs_rejected(self):
        before = self.case_path.read_bytes()
        for ref in (
            "record:am-0000000000000000",
            "version:9.9.9",
            "technology:ASP.NET",
        ):
            outcome = submit_human_case_evidence(
                self.case_path,
                human_envelope([human_item(ref=ref)]),
                expected_case_id=CASE_ID,
                match_loader=self.loader([match_row(technology="WordPress")]),
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_REJECTED)
            self.assertEqual(
                outcome["reason"], REASON_UNSUPPORTED_DETERMINISTIC_REF
            )
            self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_genuine_deterministic_ref_is_accepted(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope(
                [
                    human_item(
                        ref="technology:WordPress",
                        kind="TECHNOLOGY_IDENTITY",
                        fact="NON-REAL/OFFLINE human attestation fixture",
                    )
                ]
            ),
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(outcome["accepted_items"], 1)

    def test_case_never_changes_without_genuine_evidence(self):
        before = self.case_path.read_bytes()
        for body in (
            human_envelope([]),
            human_envelope([human_item(ref="", observations=[])]),
            human_envelope([human_item(source="WATCH_DERIVED")]),
            human_envelope([human_item(ref="record:am-0000000000000000")]),
        ):
            submit_human_case_evidence(
                self.case_path,
                body,
                expected_case_id=CASE_ID,
                match_loader=self.loader([]),
                write=True,
            )
        self.assertEqual(self.case_path.read_bytes(), before)
        case = self.artifact()["research_case_workspace"]["cases"][0]
        self.assertEqual(case["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(case["iteration_count"], 1)


class TestWatchSignalSemantics(HumanSubmissionTestCase):
    def test_automated_completion_never_produces_watch_signal(self):
        case = self.stages(self.artifact())["case"]
        items, unavailable = build_completion_items(
            case,
            CVE,
            [
                match_row(
                    technology="WordPress",
                    version="1.0",
                    component="wp-responsive-images",
                )
            ],
        )
        kinds = [item["requirement_kind"] for item in items]
        self.assertNotIn("WATCH_SIGNAL", kinds)
        self.assertEqual(
            unavailable.get("WATCH_SIGNAL"), "HUMAN_REVIEW_ONLY"
        )

    def test_human_watch_signal_is_accepted_from_human_source(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope(
                [
                    human_item(
                        ref="response:synthetic-human-watch-signal-1",
                        kind="WATCH_SIGNAL",
                        fact="NON-REAL/OFFLINE human watch-signal fixture",
                    )
                ]
            ),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(
            outcome["available_requirement_kinds"], ["WATCH_SIGNAL"]
        )
        artifact = self.artifact()
        self.assertEqual(
            artifact["evidence_intake"]["accepted_items"][0]["source"],
            "HUMAN_REVIEW",
        )

    def test_watch_signal_from_non_human_source_is_rejected(self):
        outcome = submit_human_case_evidence(
            self.case_path,
            human_envelope(
                [
                    human_item(
                        ref="response:synthetic-human-watch-signal-2",
                        kind="WATCH_SIGNAL",
                        source="WATCH_DERIVED",
                    )
                ]
            ),
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertEqual(outcome["reason"], REASON_NON_HUMAN_SOURCE)
        self.assertFalse(outcome["written"])


class TestHumanEvidenceApi(unittest.TestCase):
    """Hermetic route tests: a temporary artifact root, no production writes."""

    @classmethod
    def setUpClass(cls):
        from config import config
        from fastapi.testclient import TestClient

        from api import app

        cls.api_key = config().get("API_KEY", "")
        cls.client = TestClient(app)

    def _post(self, path, body, *, key=True):
        params = {}
        if key and self.api_key:
            params["api_key"] = self.api_key
        return self.client.post(path, params=params, json=body)

    def _root(self):
        from ai.research_agent.case_bridge import (
            activate_result,
            case_artifact_path,
        )

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cases = Path(tmp.name) / "cases"
        outcome = activate_result(
            loop_payload(), plan_loader=plan_loader, cases_dir=cases
        )
        self.assertEqual(outcome["status"], "ACTIVATED")
        return Path(tmp.name), case_artifact_path(CASE_ID, cases)

    def test_human_route_persists_once_and_replays_duplicates(self):
        from backend import research_cases

        root, case_path = self._root()
        body = human_envelope([human_item()])
        with mock.patch.object(research_cases, "ARTIFACT_ROOT", root):
            response = self._post(
                f"/api/research/cases/{CASE_ID}/human-evidence", body
            )
            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["rule_version"], "r89-1")
            self.assertEqual(payload["submission_status"], "COMPLETED")
            self.assertEqual(payload["accepted_external_evidence"], 1)
            self.assertTrue(payload["persistence"]["written"])
            self.assertEqual(
                payload["accepted_requirement_kinds"], ["COMPONENT_BINDING"]
            )
            after_first = case_path.read_bytes()

            replay = self._post(
                f"/api/research/cases/{CASE_ID}/human-evidence", body
            )
            self.assertEqual(replay.status_code, 200, replay.text)
            replayed = replay.json()
            self.assertEqual(replayed["submission_status"], "REPLAYED")
            self.assertEqual(replayed["accepted_external_evidence"], 0)
            self.assertFalse(replayed["persistence"]["written"])
            self.assertEqual(case_path.read_bytes(), after_first)

    def test_human_route_rejections(self):
        from backend import research_cases

        root, case_path = self._root()
        before = case_path.read_bytes()
        with mock.patch.object(research_cases, "ARTIFACT_ROOT", root):
            non_human = self._post(
                f"/api/research/cases/{CASE_ID}/human-evidence",
                human_envelope([human_item(source="WATCH_DERIVED")]),
            )
            self.assertEqual(non_human.status_code, 400)
            self.assertIn("NON_HUMAN_SOURCE", non_human.json()["detail"])

            fabricated = self._post(
                f"/api/research/cases/{CASE_ID}/human-evidence",
                human_envelope([human_item(ref="record:am-0000000000000000")]),
            )
            self.assertEqual(fabricated.status_code, 409)
            self.assertIn(
                "UNSUPPORTED_DETERMINISTIC_REF", fabricated.json()["detail"]
            )

            mismatch = self._post(
                f"/api/research/cases/{CASE_ID}/human-evidence",
                human_envelope([human_item()], case_ref="case-other"),
            )
            self.assertEqual(mismatch.status_code, 409)
            self.assertIn("CASE_MISMATCH", mismatch.json()["detail"])

            unknown = self._post(
                "/api/research/cases/case-does-not-exist/human-evidence",
                human_envelope([human_item()], case_ref="case-does-not-exist"),
            )
            self.assertEqual(unknown.status_code, 404)
        self.assertEqual(case_path.read_bytes(), before)

    def test_human_route_requires_api_key(self):
        if not self.api_key:
            self.skipTest("API key not configured")
        response = self._post(
            f"/api/research/cases/{CASE_ID}/human-evidence",
            human_envelope([human_item()]),
            key=False,
        )
        self.assertEqual(response.status_code, 401)


class TestHumanEvidenceCli(HumanSubmissionTestCase):
    def test_human_evidence_subcommand_parses(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            [
                "agent",
                "human-evidence",
                "--case",
                CASE_ID,
                "--file",
                "/tmp/envelope.json",
                "--json",
            ]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "human-evidence")
        self.assertEqual(args.case, CASE_ID)
        self.assertEqual(args.file, "/tmp/envelope.json")
        self.assertFalse(args.apply)

    def test_cli_dry_run_then_apply_is_idempotent(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = Path(tmp) / "envelope.json"
            envelope_path.write_text(
                json.dumps(human_envelope([human_item()])), encoding="utf-8"
            )
            before = self.case_path.read_bytes()
            argv = [
                "agent",
                "human-evidence",
                "--case",
                CASE_ID,
                "--cases-dir",
                str(self.cases),
                "--file",
                str(envelope_path),
                "--json",
            ]
            self.assertEqual(research_cli.main(argv), 0)
            self.assertEqual(self.case_path.read_bytes(), before)

            self.assertEqual(
                research_cli.main(argv + ["--apply"]), 0
            )
            after_first = self.case_path.read_bytes()
            self.assertNotEqual(after_first, before)

            self.assertEqual(
                research_cli.main(argv + ["--apply"]), 0
            )
            self.assertEqual(self.case_path.read_bytes(), after_first)


if __name__ == "__main__":
    unittest.main()

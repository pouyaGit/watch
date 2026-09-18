"""Stage R95 — focused tests for the deterministic human evidence request.

Covers the new behavior only:

- a request is produced for a case whose R91 ledger is in ``PROVIDE_EVIDENCE``
  with the only remaining source ``HUMAN_REVIEW``;
- every request item is case-bound, requirement-specific, provenance-aware and
  carries the closed safety boundary and completion condition;
- the R80/R89 submission-envelope template is emitted with empty references
  and observations (nothing is fabricated) and is accepted by the existing
  R89 boundary once a real human observation is filled in;
- fail-closed behavior for missing/malformed/contradictory case or ledger and
  for an unknown next action;
- no request is emitted while the deterministic path is still open;
- idempotent, deterministic and side-effect free (inputs never mutated);
- provenance validation (unsupported deterministic refs and sensitive refs
  are rejected by the unchanged R80/R89 boundary);
- re-evaluation: accepted human evidence closes the requirement in the R91
  ledger through the existing R80 -> R76 path;
- the read-only CLI surface ``agent acquisitions --request``.

No network, no LLM, no Mongo, no subprocess, no live targets.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import unittest

from ai.knowledge.research_acquisition_ledger import (
    ACTION_HUMAN_REVIEW,
    ACTION_PROVIDE_EVIDENCE,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_HUMAN_REQUIRED,
    STATUS_SATISFIED,
    build_case_acquisition_ledger,
)
from ai.knowledge.research_evidence_request import (
    ACQUISITION_TYPE_HUMAN_REVIEW,
    ENVELOPE_VERSION,
    ERROR_CONTRADICTORY_CASE,
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_LEDGER,
    ERROR_UNKNOWN_NEXT_ACTION,
    EVIDENCE_REQUEST_ERROR_CODES,
    PROVENANCE_REQUIREMENTS,
    REQUEST_ITEM_SOURCE,
    REQUEST_STATE_NONE,
    REQUEST_STATE_REQUIRED,
    SAFETY_BOUNDARY,
    EvidenceRequestError,
    build_case_evidence_request,
)
from ai.research_agent.case_evidence import (
    REASON_BOUNDARY_REJECTED,
    REASON_UNSUPPORTED_DETERMINISTIC_REF,
    STATUS_COMPLETED,
    STATUS_REJECTED,
    complete_case_evidence,
    submit_human_case_evidence,
)
from ai.research_cli import run_agent_acquisitions
from tests.test_research_case_evidence import (
    CASE_ID,
    CaseEvidenceTestCase,
    match_row,
)
from tests.test_research_case_evidence_human import SYNTHETIC_LABEL

REQUESTABLE_KINDS = ("COMPONENT_BINDING", "VERSION_IDENTITY", "WATCH_SIGNAL")


class EvidenceRequestTestCase(CaseEvidenceTestCase):
    def exhaust(self):
        """Drive the fixture to the real PROVIDE_EVIDENCE state (R87)."""

        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        return outcome

    def ledger(self):
        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        return build_case_acquisition_ledger(
            case,
            acquisition_plan=artifact.get("acquisition_plan"),
            readiness_plan=artifact.get("readiness_plan"),
            evidence_provenance=artifact.get("evidence_provenance"),
            evidence_completion=artifact.get("evidence_completion"),
            evidence_acquisition=artifact.get("evidence_acquisition"),
        )

    def request(self, **kwargs):
        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        return build_case_evidence_request(
            case,
            self.ledger(),
            workbench=artifact.get("research_workbench"),
            source_cve=(artifact.get("result") or {}).get("cve_id"),
            **kwargs,
        )

    def fill(self, request, kind, *, ref="response:synthetic-r95-observation-1"):
        for item in request["requirements"]:
            if item["requirement_kind"] != kind:
                continue
            envelope = copy.deepcopy(item["submission_envelope"])
            template = envelope["items"][0]
            template["hypothesis_ref"] = "H1"
            template["evidence_ref"] = ref
            template["observations"] = [{"ref": ref, "fact": SYNTHETIC_LABEL}]
            return envelope
        raise AssertionError(f"no request item for {kind}")


# ---------------------------------------------------------------------------
# normal case
# ---------------------------------------------------------------------------


class TestRequestBuild(EvidenceRequestTestCase):
    def test_exhausted_case_produces_request(self):
        self.exhaust()
        request = self.request()
        self.assertEqual(request["rule_version"], "r95-1")
        self.assertEqual(request["request_state"], REQUEST_STATE_REQUIRED)
        self.assertEqual(request["case_id"], CASE_ID)
        self.assertEqual(request["next_action"], ACTION_PROVIDE_EVIDENCE)
        self.assertTrue(request["human_action_required"])
        self.assertTrue(request["offline_sources_exhausted"])
        self.assertEqual(request["requirement_count"], 3)
        kinds = [item["requirement_kind"] for item in request["requirements"]]
        self.assertEqual(sorted(kinds), sorted(REQUESTABLE_KINDS))
        case_refs = self.artifact()["research_case_workspace"]["cases"][0][
            "hypothesis_refs"
        ]
        for item in request["requirements"]:
            self.assertEqual(
                item["acquisition_type"], ACQUISITION_TYPE_HUMAN_REVIEW
            )
            self.assertIn("HUMAN_REVIEW", item["remaining_sources"])
            self.assertTrue(item["expected_output"])
            self.assertTrue(item["completion_condition"])
            self.assertEqual(item["hypothesis_refs"], case_refs)
        by_kind = {
            item["requirement_kind"]: item
            for item in request["requirements"]
        }
        self.assertEqual(
            by_kind["COMPONENT_BINDING"]["status"],
            STATUS_ATTEMPTED_NO_OBSERVATION,
        )
        self.assertEqual(
            by_kind["COMPONENT_BINDING"]["requirement_class"], "DECISION"
        )
        self.assertEqual(
            by_kind["WATCH_SIGNAL"]["status"], STATUS_HUMAN_REQUIRED
        )
        self.assertTrue(
            by_kind["COMPONENT_BINDING"]["attempts"]
        )
        self.assertEqual(
            request["advisory"], True
        )
        self.assertEqual(request["confirmation_state"], "NOT_CONFIRMED")

    def test_no_request_while_deterministic_path_is_open(self):
        request = self.request()  # fresh fixture: CONTINUE_RESEARCH
        self.assertEqual(request["next_action"], "CONTINUE_RESEARCH")
        self.assertEqual(request["request_state"], REQUEST_STATE_NONE)
        self.assertEqual(request["requirement_count"], 0)
        self.assertIsNone(request["submission_envelope"])
        self.assertTrue(request["reason"])

    def test_human_review_next_action_requires_no_evidence_request(self):
        ledger = self.ledger()
        ledger["next_action"] = ACTION_HUMAN_REVIEW
        request = build_case_evidence_request(
            self.artifact()["research_case_workspace"]["cases"][0], ledger
        )
        self.assertEqual(request["request_state"], REQUEST_STATE_NONE)
        self.assertIsNone(request["submission_envelope"])

    def test_missing_requirement_is_not_included(self):
        self.exhaust()
        ledger = self.ledger()
        ledger["requirements"] = [
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] != "WATCH_SIGNAL"
        ]
        artifact = self.artifact()
        request = build_case_evidence_request(
            artifact["research_case_workspace"]["cases"][0], ledger
        )
        kinds = [item["requirement_kind"] for item in request["requirements"]]
        self.assertEqual(
            sorted(kinds), ["COMPONENT_BINDING", "VERSION_IDENTITY"]
        )

    def test_item_cap_is_bounded(self):
        self.exhaust()
        request = self.request(max_items=1)
        self.assertEqual(request["requirement_count"], 1)


# ---------------------------------------------------------------------------
# fail closed
# ---------------------------------------------------------------------------


class TestFailClosed(EvidenceRequestTestCase):
    def test_missing_or_malformed_case(self):
        self.exhaust()
        ledger = self.ledger()
        for bad in (None, {}, {"case_id": ""}, {"status": "ACTIVE"}):
            with self.subTest(bad=bad):
                with self.assertRaises(EvidenceRequestError) as ctx:
                    build_case_evidence_request(bad, ledger)
                self.assertEqual(ctx.exception.code, ERROR_MALFORMED_CASE)

    def test_missing_or_malformed_ledger(self):
        self.exhaust()
        case = self.artifact()["research_case_workspace"]["cases"][0]
        for bad in (None, {}, {"case_id": ""}):
            with self.subTest(bad=bad):
                with self.assertRaises(EvidenceRequestError) as ctx:
                    build_case_evidence_request(case, bad)
                self.assertEqual(ctx.exception.code, ERROR_MALFORMED_LEDGER)

    def test_contradictory_case_id(self):
        self.exhaust()
        ledger = self.ledger()
        ledger["case_id"] = "case-other"
        with self.assertRaises(EvidenceRequestError) as ctx:
            build_case_evidence_request(
                self.artifact()["research_case_workspace"]["cases"][0], ledger
            )
        self.assertEqual(ctx.exception.code, ERROR_CONTRADICTORY_CASE)

    def test_unknown_next_action(self):
        self.exhaust()
        ledger = self.ledger()
        ledger["next_action"] = "DO_SOMETHING"
        with self.assertRaises(EvidenceRequestError) as ctx:
            build_case_evidence_request(
                self.artifact()["research_case_workspace"]["cases"][0], ledger
            )
        self.assertEqual(ctx.exception.code, ERROR_UNKNOWN_NEXT_ACTION)

    def test_malformed_requirement_list(self):
        self.exhaust()
        ledger = self.ledger()
        ledger["requirements"] = "not-a-list"
        with self.assertRaises(EvidenceRequestError) as ctx:
            build_case_evidence_request(
                self.artifact()["research_case_workspace"]["cases"][0], ledger
            )
        self.assertEqual(ctx.exception.code, ERROR_MALFORMED_LEDGER)

    def test_error_codes_are_closed(self):
        for code in (
            ERROR_MALFORMED_CASE,
            ERROR_MALFORMED_LEDGER,
            ERROR_CONTRADICTORY_CASE,
            ERROR_UNKNOWN_NEXT_ACTION,
        ):
            self.assertIn(code, EVIDENCE_REQUEST_ERROR_CODES)

    def test_requirement_without_human_source_is_skipped(self):
        self.exhaust()
        ledger = self.ledger()
        for entry in ledger["requirements"]:
            if entry["requirement_kind"] == "COMPONENT_BINDING":
                entry["remaining_sources"] = ["WATCH_DERIVED"]
        artifact = self.artifact()
        request = build_case_evidence_request(
            artifact["research_case_workspace"]["cases"][0], ledger
        )
        kinds = [item["requirement_kind"] for item in request["requirements"]]
        self.assertNotIn("COMPONENT_BINDING", kinds)


# ---------------------------------------------------------------------------
# template, determinism, safety
# ---------------------------------------------------------------------------


class TestTemplateAndDeterminism(EvidenceRequestTestCase):
    def test_envelope_template_contains_no_evidence(self):
        self.exhaust()
        request = self.request()
        envelope = request["submission_envelope"]
        self.assertEqual(envelope["submission_version"], ENVELOPE_VERSION)
        self.assertEqual(envelope["case_ref"], CASE_ID)
        self.assertTrue(envelope["template"])
        self.assertFalse(envelope["evidence_included"])
        self.assertEqual(len(envelope["items"]), 3)
        for item in envelope["items"]:
            self.assertEqual(item["source"], REQUEST_ITEM_SOURCE)
            self.assertEqual(item["hypothesis_ref"], "")
            self.assertEqual(item["evidence_ref"], "")
            self.assertEqual(item["observations"], [])
        for entry in request["requirements"]:
            single = entry["submission_envelope"]
            self.assertEqual(single["case_ref"], CASE_ID)
            self.assertEqual(len(single["items"]), 1)
            self.assertEqual(
                single["items"][0]["requirement_kind"],
                entry["requirement_kind"],
            )
            self.assertEqual(single["items"][0]["evidence_ref"], "")
            self.assertEqual(single["items"][0]["observations"], [])

    def test_repeated_build_is_deterministic_and_side_effect_free(self):
        self.exhaust()
        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        ledger = self.ledger()
        case_before = copy.deepcopy(case)
        ledger_before = copy.deepcopy(ledger)
        first = build_case_evidence_request(
            case, ledger, workbench=artifact.get("research_workbench")
        )
        second = build_case_evidence_request(
            case, ledger, workbench=artifact.get("research_workbench")
        )
        self.assertEqual(first, second)
        self.assertEqual(first["request_ref"], second["request_ref"])
        self.assertEqual(case, case_before)
        self.assertEqual(ledger, ledger_before)

    def test_provenance_and_safety_contracts(self):
        self.exhaust()
        request = self.request()
        self.assertEqual(
            list(request["provenance_requirements"]),
            list(PROVENANCE_REQUIREMENTS),
        )
        self.assertEqual(
            list(request["safety_boundary"]), list(SAFETY_BOUNDARY)
        )
        serialized = json.dumps(request, sort_keys=True).upper()
        self.assertNotIn('"AUTHORIZED": TRUE', serialized)
        self.assertNotIn('"EXECUTION_AUTHORIZED"', serialized)
        self.assertNotIn('"CONFIRMED": TRUE', serialized)
        self.assertTrue(request["research_only"])
        self.assertTrue(request["human_authority_required"])
        self.assertEqual(request["submission_boundary"]["boundary"],
                         "R80/R89 human evidence submission")


# ---------------------------------------------------------------------------
# R80/R89 compatibility, correlation, re-evaluation
# ---------------------------------------------------------------------------


class TestSubmissionCompatibility(EvidenceRequestTestCase):
    def test_envelope_case_ref_matches_case(self):
        self.exhaust()
        request = self.request()
        self.assertEqual(
            request["submission_envelope"]["case_ref"], request["case_id"]
        )

    def test_wrong_case_ref_is_rejected_by_r89(self):
        self.exhaust()
        request = self.request()
        envelope = self.fill(request, "COMPONENT_BINDING")
        envelope["case_ref"] = "case-other"
        outcome = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertIn(
            REASON_BOUNDARY_REJECTED, [outcome["reason"], *outcome["rejection_codes"]]
        )

    def test_filled_template_is_accepted_and_updates_ledger(self):
        self.exhaust()
        before = self.case_path.read_bytes()
        request = self.request()
        envelope = self.fill(request, "COMPONENT_BINDING")
        outcome = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(outcome["accepted_items"], 1)
        self.assertNotEqual(self.case_path.read_bytes(), before)

        ledger = self.ledger()
        statuses = {
            entry["requirement_kind"]: entry["status"]
            for entry in ledger["requirements"]
        }
        self.assertEqual(statuses["COMPONENT_BINDING"], STATUS_SATISFIED)

    def test_duplicate_filled_submission_replays(self):
        self.exhaust()
        envelope = self.fill(self.request(), "VERSION_IDENTITY")
        first = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        after_first = self.case_path.read_bytes()
        second = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(second["replayed_items"], 1)
        self.assertEqual(second["accepted_items"], 0)
        self.assertEqual(self.case_path.read_bytes(), after_first)

    def test_unsupported_deterministic_ref_is_rejected(self):
        self.exhaust()
        envelope = self.fill(
            self.request(),
            "COMPONENT_BINDING",
            ref="technology:NotARealProjection",
        )
        outcome = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)
        self.assertEqual(
            outcome["reason"], REASON_UNSUPPORTED_DETERMINISTIC_REF
        )

    def test_sensitive_ref_is_rejected_by_r80(self):
        self.exhaust()
        envelope = self.fill(
            self.request(),
            "COMPONENT_BINDING",
            ref="response:https://target.example/secret",
        )
        outcome = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_REJECTED)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestEvidenceRequestCli(EvidenceRequestTestCase):
    def test_cli_request_json(self):
        self.exhaust()
        args = argparse.Namespace(
            case=CASE_ID,
            cases_dir=str(self.cases),
            json=True,
            request=True,
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_acquisitions(args)
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["request_state"], REQUEST_STATE_REQUIRED)
        self.assertEqual(payload["case_id"], CASE_ID)
        self.assertEqual(len(payload["submission_envelope"]["items"]), 3)

    def test_cli_request_text_is_read_only(self):
        self.exhaust()
        before = self.case_path.read_bytes()
        args = argparse.Namespace(
            case=CASE_ID,
            cases_dir=str(self.cases),
            json=False,
            request=True,
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_acquisitions(args)
        self.assertEqual(code, 0)
        text = buffer.getvalue()
        self.assertIn("Case evidence request", text)
        self.assertIn("EVIDENCE_REQUESTED", text)
        self.assertIn("no evidence submitted", text)
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_cli_ledger_without_request_is_unchanged(self):
        self.exhaust()
        args = argparse.Namespace(
            case=CASE_ID,
            cases_dir=str(self.cases),
            json=True,
            request=False,
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_acquisitions(args)
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["next_action"], ACTION_PROVIDE_EVIDENCE)
        self.assertNotIn("submission_envelope", payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

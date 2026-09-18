"""Stage R100 — focused tests for the human triage decision boundary.

Covers the new behavior only:

- reuse of the existing R56 human decision vocabulary, rationale codes,
  escalation targets and non-authorized codes (no parallel vocabulary);
- explicit human authority (source/authority forced HUMAN, ai_role ADVISORY,
  execution/confirmation/exploit forced False), automated authority and
  sensitive authority labels rejected;
- case binding and R99 package-fingerprint binding (reviewed evidence);
- CURRENT / STALE / INVALID / NOT_DECIDED evaluation and stale safety;
- replay-safe persistence, bounded supersession, atomic writes and dry-run;
- no case state change, no confirmation, no execution, no fabrication;
- deterministic records and CLI behavior.

No network, no LLM, no Mongo, no subprocess, no live targets.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import inspect
import io
import json
import unittest

from ai.knowledge.research_triage_decision import (
    CASE_TRIAGE_DECISION_ERROR_CODES,
    DECISION_STATUS_CURRENT,
    DECISION_STATUS_INVALID,
    DECISION_STATUS_NOT_DECIDED,
    DECISION_STATUS_STALE,
    ERROR_AUTOMATED_AUTHORITY,
    ERROR_CONTRADICTORY_CASE,
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_PACKAGE,
    ERROR_MISSING_HUMAN_AUTHORITY,
    ERROR_UNKNOWN_DECISION,
    ERROR_UNKNOWN_ESCALATION_TARGET,
    ERROR_UNKNOWN_RATIONALE,
    RULE_VERSION,
    CaseTriageDecisionError,
    build_case_triage_decision,
    decision_signature,
    evaluate_case_triage_decision,
    package_fingerprint,
)
from ai.research_agent.case_decision import (
    MAX_DECISIONS,
    STATUS_ERROR,
    STATUS_PREVIEW,
    STATUS_RECORDED,
    STATUS_REPLAYED,
    build_case_package,
    load_case_triage_decisions,
    record_case_triage_decision,
)
from ai.research_agent.case_evidence import (
    STATUS_COMPLETED,
    complete_case_evidence,
    submit_human_case_evidence,
)
from ai.research_cli import run_agent_triage_decision
from ai.schemas.human_decision import (
    DECISION_AUTHORITY_HUMAN,
    DECISION_SOURCE_HUMAN,
    HUMAN_DECISION_TYPES,
    HUMAN_RATIONALE_CODES,
    HUMAN_DECISION_LIMITATIONS,
)
from tests.test_research_case_evidence import (
    CASE_ID,
    CaseEvidenceTestCase,
    match_row,
)


class HumanDecisionTestCase(CaseEvidenceTestCase):
    def exhaust(self):
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        return outcome

    def package(self):
        return build_case_package(self.artifact())

    def case(self):
        return self.artifact()["research_case_workspace"]["cases"][0]

    def decision(self, **overrides):
        kwargs = {
            "decision": "REQUEST_MORE_EVIDENCE",
            "decided_by": "operator-a",
            "rationale_code": "EVIDENCE_INCOMPLETE",
            "rationale_note": "component binding still missing",
            "decided_at": "2026-09-18T12:00:00Z",
        }
        kwargs.update(overrides)
        return build_case_triage_decision(self.case(), self.package(), **kwargs)


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------


class TestDecisionEngine(HumanDecisionTestCase):
    def test_vocabulary_is_reused_from_r56(self):
        self.exhaust()
        record = self.decision()
        self.assertEqual(record["rule_version"], RULE_VERSION)
        self.assertIn(record["decision"], HUMAN_DECISION_TYPES)
        self.assertIn(record["rationale_code"], HUMAN_RATIONALE_CODES)
        self.assertEqual(list(record["limitations"]), list(HUMAN_DECISION_LIMITATIONS))
        self.assertTrue(record["not_authorized"])

    def test_human_authority_is_forced_not_client_supplied(self):
        self.exhaust()
        record = self.decision()
        self.assertEqual(record["decision_source"], DECISION_SOURCE_HUMAN)
        self.assertEqual(record["decision_authority"], DECISION_AUTHORITY_HUMAN)
        self.assertEqual(record["ai_role"], "ADVISORY")
        self.assertFalse(record["execution_authorized"])
        self.assertFalse(record["vulnerability_confirmed"])
        self.assertFalse(record["exploit_authorized"])
        self.assertEqual(record["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(record["human_authority_required"])

    def test_escalation_target_only_for_escalate(self):
        self.exhaust()
        record = self.decision(decision="ESCALATE", escalation_target="HUMAN_ANALYST_REVIEW")
        self.assertEqual(record["escalation_target"], "HUMAN_ANALYST_REVIEW")
        other = self.decision()
        self.assertEqual(other["escalation_target"], "")
        default = self.decision(decision="ESCALATE")
        self.assertEqual(default["escalation_target"], "ESCALATION_UNKNOWN")

    def test_package_fingerprint_binding_and_staleness(self):
        self.exhaust()
        package = self.package()
        record = self.decision()
        self.assertEqual(
            record["reviewed_package_fingerprint"],
            package_fingerprint(package),
        )
        self.assertEqual(
            evaluate_case_triage_decision(record, package)["status"],
            DECISION_STATUS_CURRENT,
        )
        changed = copy.deepcopy(package)
        changed["case"]["status"] = "STOPPED"
        self.assertEqual(
            evaluate_case_triage_decision(record, changed)["status"],
            DECISION_STATUS_STALE,
        )
        self.assertEqual(
            evaluate_case_triage_decision(None, package)["status"],
            DECISION_STATUS_NOT_DECIDED,
        )
        self.assertEqual(
            evaluate_case_triage_decision(
                {"decision_ref": "hdc-x", "reviewed_package_fingerprint": "r99p-x"},
                package,
            )["status"],
            DECISION_STATUS_INVALID,
        )

    def test_fail_closed_inputs(self):
        self.exhaust()
        package = self.package()
        case = self.case()
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            build_case_triage_decision(
                {}, package, decision="REJECT", decided_by="operator-a"
            )
        self.assertEqual(ctx.exception.code, ERROR_MALFORMED_CASE)
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            build_case_triage_decision(
                case, {}, decision="REJECT", decided_by="operator-a"
            )
        self.assertEqual(ctx.exception.code, ERROR_MALFORMED_PACKAGE)
        wrong = copy.deepcopy(package)
        wrong["case"]["case_id"] = "case-other"
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            build_case_triage_decision(
                case, wrong, decision="REJECT", decided_by="operator-a"
            )
        self.assertEqual(ctx.exception.code, ERROR_CONTRADICTORY_CASE)
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            self.decision(decision="CONFIRM_VULNERABILITY")
        self.assertEqual(ctx.exception.code, ERROR_UNKNOWN_DECISION)
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            self.decision(rationale_code="BECAUSE_I_SAID_SO")
        self.assertEqual(ctx.exception.code, ERROR_UNKNOWN_RATIONALE)
        with self.assertRaises(CaseTriageDecisionError) as ctx:
            self.decision(decision="ESCALATE", escalation_target="EVERYONE")
        self.assertEqual(ctx.exception.code, ERROR_UNKNOWN_ESCALATION_TARGET)
        for code in CASE_TRIAGE_DECISION_ERROR_CODES:
            self.assertTrue(code)

    def test_missing_or_automated_authority_rejected(self):
        self.exhaust()
        for bad in ("", "   ", "https://example.invalid/operator", "Bearer token"):
            with self.subTest(bad=bad):
                with self.assertRaises(CaseTriageDecisionError) as ctx:
                    self.decision(decided_by=bad)
                self.assertEqual(
                    ctx.exception.code, ERROR_MISSING_HUMAN_AUTHORITY
                )

    def test_record_is_deterministic_and_content_addressed(self):
        self.exhaust()
        first = self.decision()
        second = self.decision()
        self.assertEqual(first, second)
        self.assertTrue(first["decision_ref"].startswith("hdc-"))
        self.assertEqual(decision_signature(first), decision_signature(second))
        different = self.decision(decision="REJECT")
        self.assertNotEqual(first["decision_ref"], different["decision_ref"])

    def test_record_does_not_modify_case_or_confirm(self):
        self.exhaust()
        before = copy.deepcopy(self.case())
        record = self.decision()
        self.assertEqual(before, self.case())
        serialized = json.dumps(record, sort_keys=True).upper()
        self.assertNotIn('"AUTHORIZED": TRUE', serialized)
        self.assertNotIn('"CONFIRMED": TRUE', serialized)
        self.assertNotIn("VULNERABILITY_CONFIRMED\": TRUE", serialized)

    def test_engine_has_no_clock_network_or_llm(self):
        source = inspect.getsource(
            __import__(
                "ai.knowledge.research_triage_decision",
                fromlist=["build_case_triage_decision"],
            )
        )
        for forbidden in (
            "import requests",
            "import httpx",
            "import urllib",
            "import socket",
            "pymongo",
            "openai",
            "anthropic",
            "subprocess",
            "datetime.now",
            "import random",
            "random.",
        ):
            self.assertNotIn(forbidden, source, forbidden)


# ---------------------------------------------------------------------------
# persistence writer
# ---------------------------------------------------------------------------


class TestDecisionWriter(HumanDecisionTestCase):
    def test_dry_run_previews_without_writing(self):
        self.exhaust()
        before = self.case_path.read_bytes()
        outcome = record_case_triage_decision(
            self.case_path,
            decision="NEEDS_REVIEW",
            decided_by="operator-a",
            decided_at="2026-09-18T12:00:00Z",
            write=False,
        )
        self.assertEqual(outcome["status"], STATUS_PREVIEW)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_record_replay_and_supersession(self):
        self.exhaust()
        first = record_case_triage_decision(
            self.case_path,
            decision="REQUEST_MORE_EVIDENCE",
            decided_by="operator-a",
            rationale_code="EVIDENCE_INCOMPLETE",
            decided_at="2026-09-18T12:00:00Z",
            write=True,
        )
        self.assertEqual(first["status"], STATUS_RECORDED)
        self.assertTrue(first["written"])
        artifact = self.artifact()
        self.assertEqual(artifact["research_case_workspace"]["cases"][0]["status"], "ACTIVE")
        self.assertEqual(len(load_case_triage_decisions(artifact)), 1)

        replay = record_case_triage_decision(
            self.case_path,
            decision="REQUEST_MORE_EVIDENCE",
            decided_by="operator-a",
            rationale_code="EVIDENCE_INCOMPLETE",
            decided_at="2026-09-18T12:05:00Z",
            write=True,
        )
        self.assertEqual(replay["status"], STATUS_REPLAYED)
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(load_case_triage_decisions(self.artifact())), 1)

        superseding = record_case_triage_decision(
            self.case_path,
            decision="DEFER",
            decided_by="operator-a",
            decided_at="2026-09-18T13:00:00Z",
            write=True,
        )
        self.assertEqual(superseding["status"], STATUS_RECORDED)
        self.assertEqual(len(load_case_triage_decisions(self.artifact())), 2)

    def test_record_is_bounded(self):
        self.exhaust()
        for index in range(MAX_DECISIONS + 3):
            outcome = record_case_triage_decision(
                self.case_path,
                decision="DEFER",
                decided_by="operator-a",
                rationale_note=f"round {index}",
                decided_at="2026-09-18T12:00:00Z",
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_RECORDED)
        self.assertEqual(
            len(load_case_triage_decisions(self.artifact())), MAX_DECISIONS
        )

    def test_stale_decision_after_evidence_change(self):
        self.exhaust()
        recorded = record_case_triage_decision(
            self.case_path,
            decision="APPROVE_RESEARCH",
            decided_by="operator-a",
            decided_at="2026-09-18T12:00:00Z",
            write=True,
        )
        self.assertEqual(recorded["status"], STATUS_RECORDED)
        package = self.package()
        record = load_case_triage_decisions(self.artifact())[-1]
        self.assertEqual(
            evaluate_case_triage_decision(record, package)["status"],
            DECISION_STATUS_CURRENT,
        )
        # new evidence changes the reviewed package -> decision becomes stale
        submission = submit_human_case_evidence(
            self.case_path,
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "submitted_by": "operator-a",
                "items": [
                    {
                        "hypothesis_ref": "H1",
                        "requirement_kind": "COMPONENT_BINDING",
                        "effect": "PROVIDES",
                        "source": "HUMAN_REVIEW",
                        "evidence_ref": "response:nonreal-r100-stale-1",
                        "observations": [
                            {
                                "ref": "response:nonreal-r100-stale-1",
                                "fact": "NON-REAL/OFFLINE r100 stale fixture",
                            }
                        ],
                    }
                ],
            },
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(submission["status"], STATUS_COMPLETED)
        after = load_case_triage_decisions(self.artifact())[-1]
        self.assertEqual(
            evaluate_case_triage_decision(after, self.package())["status"],
            DECISION_STATUS_STALE,
        )
        # the stale decision is historical only; the case is unchanged by it
        case = self.case()
        self.assertNotEqual(case["status"], "STOPPED")
        self.assertEqual(case["confirmation_state"], "NOT_CONFIRMED")

    def test_malformed_case_path_fails_closed(self):
        self.exhaust()
        outcome = record_case_triage_decision(
            self.case_path.parent / "missing.json",
            decision="REJECT",
            decided_by="operator-a",
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_ERROR)
        self.assertFalse(outcome["written"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestDecisionCli(HumanDecisionTestCase):
    def _args(self, **overrides):
        values = {
            "case": CASE_ID,
            "cases_dir": str(self.cases),
            "decision": "REQUEST_MORE_EVIDENCE",
            "by": "operator-a",
            "rationale": "EVIDENCE_INCOMPLETE",
            "note": "",
            "escalation_target": "",
            "decided_at": "2026-09-18T12:00:00Z",
            "json": True,
            "apply": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_cli_dry_run_is_read_only(self):
        self.exhaust()
        before = self.case_path.read_bytes()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_triage_decision(self._args())
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["status"], STATUS_PREVIEW)
        self.assertFalse(payload["written"])
        self.assertEqual(self.case_path.read_bytes(), before)

    def test_cli_apply_records(self):
        self.exhaust()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_triage_decision(self._args(apply=True))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["status"], STATUS_RECORDED)
        self.assertTrue(payload["written"])
        self.assertEqual(len(load_case_triage_decisions(self.artifact())), 1)

    def test_cli_rejects_unknown_decision(self):
        self.exhaust()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_agent_triage_decision(self._args(decision="WRONG"))
        self.assertEqual(code, 1)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["status"], STATUS_ERROR)
        self.assertEqual(payload["reason"], ERROR_UNKNOWN_DECISION)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

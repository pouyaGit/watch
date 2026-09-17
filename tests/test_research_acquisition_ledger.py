"""Stage R91 — focused tests for the case acquisition ledger.

Covers exactly the new behavior:

- per-requirement attempt/status derivation from persisted case blocks
  (satisfied / attempted-no-observation / human-required / not-attempted /
  conflict);
- reconstruction of a deterministic attempt from a persisted R87 completion
  block (and never from a human R89 block);
- recorded attempts take precedence over reconstruction; merge is
  latest-per-(requirement, source) with deterministic counts;
- fail-closed behavior for a malformed case and silent tolerance of
  malformed optional blocks (nothing is invented);
- deterministic output (byte-stable repeated builds) and read-only inputs;
- the R87/R89 write paths persist attempts exactly once (replay/no-evidence
  runs do not write);
- the API detail exposes the ledger, the portfolio endpoint is read-only and
  authenticated, and the CLI parses and renders both modes.
"""

from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.knowledge.research_acquisition_ledger import (
    OUTCOME_ACCEPTED,
    OUTCOME_HUMAN_REVIEW_ONLY,
    OUTCOME_NO_MATCHING_OBSERVATION,
    RULE_VERSION,
    SOURCE_HUMAN_REVIEW,
    SOURCE_WATCH_DERIVED,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_CONFLICT_REVIEW,
    STATUS_HUMAN_REQUIRED,
    STATUS_NOT_ATTEMPTED,
    STATUS_SATISFIED,
    AcquisitionLedgerError,
    build_acquisition_portfolio,
    build_case_acquisition_ledger,
    merge_acquisition_attempts,
)
from ai.research_agent.case_evidence import (
    STATUS_COMPLETED,
    STATUS_NO_EVIDENCE,
    STATUS_REPLAYED,
)
from tests.test_research_case_evidence import (
    CASE_ID,
    CVE,
    CaseEvidenceTestCase,
    loop_payload,
    match_row,
    plan_loader,
)


def case_fixture(
    *,
    status="ACTIVE",
    decision_state="NEEDS_EVIDENCE",
    sufficiency="INSUFFICIENT",
    available=(),
    missing=(
        "TECHNOLOGY_IDENTITY",
        "VERSION_IDENTITY",
        "COMPONENT_BINDING",
        "WATCH_SIGNAL",
    ),
    human_review=False,
    iteration=2,
):
    return {
        "case_id": CASE_ID,
        "case_version": "r76-1",
        "program": "dell",
        "status": status,
        "iteration_count": iteration,
        "human_review_required": human_review,
        "evidence": {
            "available_requirement_kinds": list(available),
            "missing_requirement_kinds": list(missing),
        },
        "readiness": {
            "sufficiency_state": sufficiency,
            "decision_state": decision_state,
            "blocking_codes": ["COMPONENT_BINDING"],
        },
    }


def readiness_fixture():
    return {
        "records": [
            {
                "required_evidence": [
                    {
                        "requirement_kind": "TECHNOLOGY_IDENTITY",
                        "requirement_class": "SUPPORT",
                    },
                    {
                        "requirement_kind": "VERSION_IDENTITY",
                        "requirement_class": "SUPPORT",
                    },
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "requirement_class": "DECISION",
                    },
                    {
                        "requirement_kind": "WATCH_SIGNAL",
                        "requirement_class": "SUPPORT",
                    },
                ]
            }
        ]
    }


def completion_fixture(rule_version="r87-1"):
    return {
        "rule_version": rule_version,
        "status": "COMPLETED",
        "accepted_items": 1,
        "requirement_kinds": ["TECHNOLOGY_IDENTITY"],
        "missing_requirement_kinds": [
            "VERSION_IDENTITY",
            "COMPONENT_BINDING",
            "WATCH_SIGNAL",
        ],
    }


class TestLedgerBuilder(unittest.TestCase):
    def _ledger(self, **overrides):
        case = overrides.pop("case", case_fixture(
            available=("TECHNOLOGY_IDENTITY",),
        ))
        kwargs = {
            "readiness_plan": readiness_fixture(),
            "evidence_completion": completion_fixture(),
        }
        kwargs.update(overrides)
        return build_case_acquisition_ledger(case, **kwargs)

    def test_requirement_statuses_and_next_action(self):
        ledger = self._ledger(
            case=case_fixture(available=("TECHNOLOGY_IDENTITY",)),
            readiness_plan=readiness_fixture(),
            evidence_completion=completion_fixture(),
        )
        self.assertEqual(ledger["rule_version"], RULE_VERSION)
        statuses = {
            entry["requirement_kind"]: entry["status"]
            for entry in ledger["requirements"]
        }
        self.assertEqual(statuses["TECHNOLOGY_IDENTITY"], STATUS_SATISFIED)
        self.assertEqual(
            statuses["COMPONENT_BINDING"], STATUS_ATTEMPTED_NO_OBSERVATION
        )
        self.assertEqual(
            statuses["VERSION_IDENTITY"], STATUS_ATTEMPTED_NO_OBSERVATION
        )
        self.assertEqual(statuses["WATCH_SIGNAL"], STATUS_HUMAN_REQUIRED)
        self.assertEqual(
            ledger["counts"],
            {
                "required": 4,
                "satisfied": 1,
                "missing": 3,
                "decision_missing": 1,
                "human_required": 1,
                "attempted_no_observation": 2,
                "attempted_unresolved": 0,
                "not_attempted": 0,
                "conflict_review": 0,
            },
        )
        self.assertTrue(ledger["offline_sources_exhausted"])
        self.assertEqual(ledger["next_action"], "PROVIDE_EVIDENCE")
        self.assertTrue(ledger["human_action_required"])
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        self.assertEqual(component["remaining_sources"], ["HUMAN_REVIEW"])
        self.assertTrue(component["offline_exhausted"])
        self.assertEqual(
            component["attempts"][0]["record_source"], "RECONSTRUCTED_R87"
        )

    def test_not_attempted_continues_research(self):
        ledger = self._ledger(
            case=case_fixture(
                available=("TECHNOLOGY_IDENTITY",),
                decision_state="NEEDS_EVIDENCE",
            ),
            readiness_plan=readiness_fixture(),
            evidence_completion=None,
        )
        statuses = {
            entry["requirement_kind"]: entry["status"]
            for entry in ledger["requirements"]
        }
        self.assertEqual(
            statuses["COMPONENT_BINDING"], STATUS_NOT_ATTEMPTED
        )
        self.assertFalse(ledger["offline_sources_exhausted"])
        self.assertEqual(ledger["next_action"], "CONTINUE_RESEARCH")
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        self.assertEqual(
            component["remaining_sources"],
            [SOURCE_WATCH_DERIVED, SOURCE_HUMAN_REVIEW],
        )

    def test_human_completion_never_reconstructs_deterministic_attempts(self):
        ledger = self._ledger(
            case=case_fixture(available=("TECHNOLOGY_IDENTITY",)),
            readiness_plan=readiness_fixture(),
            evidence_completion=completion_fixture("r89-1"),
        )
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        self.assertEqual(component["status"], STATUS_NOT_ATTEMPTED)
        self.assertEqual(component["attempts"], [])

    def test_recorded_attempts_take_precedence_over_reconstruction(self):
        ledger = self._ledger(
            case=case_fixture(available=("TECHNOLOGY_IDENTITY",)),
            readiness_plan=readiness_fixture(),
            evidence_completion=completion_fixture(),
            evidence_acquisition={
                "attempts": [
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "source": SOURCE_HUMAN_REVIEW,
                        "outcome": OUTCOME_ACCEPTED,
                        "evidence_refs": ["response:human-1"],
                        "last_iteration": 3,
                        "rule_version": "r89-1",
                    }
                ]
            },
        )
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        # The case says missing while an accepted human attempt exists:
        # recorded evidence wins over reconstruction and the state stays
        # explicit instead of being silently rewritten.
        self.assertEqual(len(component["attempts"]), 1)
        self.assertEqual(
            component["attempts"][0]["source"], SOURCE_HUMAN_REVIEW
        )
        self.assertNotEqual(component["status"], STATUS_SATISFIED)

    def test_conflict_is_preserved_for_human_review(self):
        ledger = self._ledger(
            case=case_fixture(
                available=("TECHNOLOGY_IDENTITY",), human_review=True
            ),
            readiness_plan=readiness_fixture(),
            evidence_completion=None,
            evidence_provenance={
                "records": [
                    {
                        "requirement_kind": "COMPONENT_BINDING",
                        "evidence_refs": ["response:conflict-1"],
                        "conflict_state": "CONFLICTING",
                        "human_review_required": True,
                    }
                ]
            },
        )
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        self.assertEqual(component["status"], STATUS_CONFLICT_REVIEW)
        self.assertEqual(ledger["counts"]["conflict_review"], 1)
        self.assertEqual(ledger["next_action"], "REVIEW_CONFLICT")
        self.assertTrue(ledger["human_action_required"])

    def test_malformed_case_fails_closed(self):
        for bad in (None, {}, {"case_id": ""}, "not-a-case"):
            with self.subTest(bad=bad):
                with self.assertRaises(AcquisitionLedgerError):
                    build_case_acquisition_ledger(bad)

    def test_malformed_optional_blocks_are_ignored(self):
        ledger = build_case_acquisition_ledger(
            case_fixture(),
            acquisition_plan="nope",
            readiness_plan=[1, 2],
            evidence_provenance={"records": ["bad"]},
            evidence_completion={"rule_version": ""},
            evidence_acquisition={"attempts": ["bad", {"source": "x"}]},
        )
        self.assertEqual(ledger["rule_version"], RULE_VERSION)
        self.assertEqual(ledger["counts"]["required"], 4)
        self.assertEqual(ledger["counts"]["not_attempted"], 3)
        self.assertEqual(ledger["counts"]["human_required"], 1)

    def test_output_is_deterministic_and_inputs_unchanged(self):
        case = case_fixture(available=("TECHNOLOGY_IDENTITY",))
        readiness = readiness_fixture()
        completion = completion_fixture()
        snapshot = json.dumps(
            [case, readiness, completion], sort_keys=True
        )
        first = build_case_acquisition_ledger(
            case,
            readiness_plan=readiness,
            evidence_completion=completion,
        )
        second = build_case_acquisition_ledger(
            case,
            readiness_plan=readiness,
            evidence_completion=completion,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps([case, readiness, completion], sort_keys=True),
            snapshot,
        )

    def test_no_io_or_execution_primitives(self):
        source = inspect.getsource(
            __import__(
                "ai.knowledge.research_acquisition_ledger",
                fromlist=["x"],
            )
        )
        for forbidden in (
            "import socket",
            "import subprocess",
            "import requests",
            "from openai",
            "write_text(",
            "MongoClient",
            "import datetime",
            "import random",
            "urllib",
        ):
            self.assertNotIn(forbidden, source, forbidden)


class TestAttemptMerge(unittest.TestCase):
    def test_latest_per_key_with_deterministic_counts(self):
        first = merge_acquisition_attempts(
            (),
            [
                {
                    "requirement_kind": "VERSION_IDENTITY",
                    "source": SOURCE_WATCH_DERIVED,
                    "outcome": OUTCOME_NO_MATCHING_OBSERVATION,
                },
                {
                    "requirement_kind": "WATCH_SIGNAL",
                    "source": SOURCE_WATCH_DERIVED,
                    "outcome": OUTCOME_HUMAN_REVIEW_ONLY,
                },
            ],
        )
        second = merge_acquisition_attempts(
            first,
            [
                {
                    "requirement_kind": "VERSION_IDENTITY",
                    "source": SOURCE_WATCH_DERIVED,
                    "outcome": OUTCOME_ACCEPTED,
                    "evidence_refs": ["version:1.0"],
                }
            ],
        )
        self.assertEqual(len(second), 2)
        version = next(
            item
            for item in second
            if item["requirement_kind"] == "VERSION_IDENTITY"
        )
        self.assertEqual(version["outcome"], OUTCOME_ACCEPTED)
        self.assertEqual(version["evidence_refs"], ["version:1.0"])
        self.assertEqual(version["count"], 2)
        self.assertEqual(
            [item["requirement_kind"] for item in second],
            ["VERSION_IDENTITY", "WATCH_SIGNAL"],
        )

    def test_malformed_attempts_are_dropped(self):
        merged = merge_acquisition_attempts(
            (),
            [
                None,
                {"requirement_kind": "", "source": "x", "outcome": "y"},
                {"requirement_kind": "K", "source": "", "outcome": "y"},
                {"requirement_kind": "K", "source": "S", "outcome": ""},
                {
                    "requirement_kind": "K" * 200,
                    "source": "S",
                    "outcome": "Y",
                },
            ],
        )
        self.assertEqual(merged, [])


class TestPortfolio(unittest.TestCase):
    def _ledger(self, case_id, action, decision_missing, missing):
        return {
            "case_id": case_id,
            "program": "p",
            "case_status": "ACTIVE",
            "sufficiency_state": "INSUFFICIENT",
            "decision_state": "NEEDS_EVIDENCE",
            "next_action": action,
            "iteration_count": 1,
            "offline_sources_exhausted": True,
            "human_action_required": True,
            "counts": {
                "missing": missing,
                "decision_missing": decision_missing,
                "human_required": 1,
            },
        }

    def test_attention_ordering_and_summary(self):
        portfolio = build_acquisition_portfolio(
            [
                self._ledger("case-c", "STOP", 0, 0),
                self._ledger("case-b", "PROVIDE_EVIDENCE", 1, 3),
                self._ledger("case-a", "PROVIDE_EVIDENCE", 2, 4),
                self._ledger("case-d", "REVIEW_CONFLICT", 0, 2),
                {"case_id": ""},
            ]
        )
        self.assertEqual(portfolio["total"], 4)
        self.assertEqual(
            [row["case_id"] for row in portfolio["items"]],
            ["case-a", "case-b", "case-d", "case-c"],
        )
        self.assertEqual(
            portfolio["summary"]["by_action"],
            {"PROVIDE_EVIDENCE": 2, "REVIEW_CONFLICT": 1, "STOP": 1},
        )
        self.assertEqual(portfolio["summary"]["human_action_required"], 4)
        self.assertEqual(portfolio["rule_version"], RULE_VERSION)

    def test_bounded_and_deterministic(self):
        rows = [
            self._ledger(f"case-{index:02d}", "PROVIDE_EVIDENCE", 0, 1)
            for index in range(50)
        ]
        first = build_acquisition_portfolio(rows)
        second = build_acquisition_portfolio(rows)
        self.assertEqual(first, second)
        self.assertLessEqual(first["total"], 32)


class TestLedgerIntegration(CaseEvidenceTestCase):
    def _artifact(self):
        return json.loads(self.case_path.read_text(encoding="utf-8"))

    def _ledger(self, artifact):
        case = artifact["research_case_workspace"]["cases"][0]
        return build_case_acquisition_ledger(
            case,
            acquisition_plan=artifact.get("acquisition_plan"),
            readiness_plan=artifact.get("readiness_plan"),
            evidence_provenance=artifact.get("evidence_provenance"),
            evidence_completion=artifact.get("evidence_completion"),
            evidence_acquisition=artifact.get("evidence_acquisition"),
        )

    def test_r87_write_persists_attempts_once(self):
        from ai.research_agent.case_evidence import complete_case_evidence

        rows = [match_row(technology="WordPress")]
        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)
        artifact = self._artifact()
        attempts = artifact["evidence_acquisition"]["attempts"]
        outcomes = {
            (item["requirement_kind"], item["source"]): item["outcome"]
            for item in attempts
        }
        self.assertEqual(
            outcomes[("TECHNOLOGY_IDENTITY", SOURCE_WATCH_DERIVED)],
            OUTCOME_ACCEPTED,
        )
        self.assertEqual(
            outcomes[("COMPONENT_BINDING", SOURCE_WATCH_DERIVED)],
            OUTCOME_NO_MATCHING_OBSERVATION,
        )
        self.assertEqual(
            outcomes[("WATCH_SIGNAL", SOURCE_WATCH_DERIVED)],
            OUTCOME_HUMAN_REVIEW_ONLY,
        )
        self.assertEqual(
            artifact["evidence_acquisition"]["rule_version"], RULE_VERSION
        )

        replay = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader(rows),
            write=True,
        )
        self.assertEqual(replay["status"], STATUS_REPLAYED)
        self.assertEqual(
            self._artifact()["evidence_acquisition"], artifact["evidence_acquisition"]
        )

    def test_human_write_records_human_attempt(self):
        from ai.research_agent.case_evidence import (
            complete_case_evidence,
            submit_human_case_evidence,
        )

        first = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(first["status"], STATUS_COMPLETED)

        envelope = {
            "submission_version": "r80-1",
            "case_ref": CASE_ID,
            "submitted_by": "synthetic",
            "items": [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "COMPONENT_BINDING",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "evidence_ref": "response:synthetic-human-1",
                    "observations": [
                        {
                            "ref": "response:synthetic-human-1",
                            "fact": "NON-REAL/OFFLINE fixture",
                        }
                    ],
                }
            ],
        }
        outcome = submit_human_case_evidence(
            self.case_path,
            envelope,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        artifact = self._artifact()
        ledger = self._ledger(artifact)
        self.assertEqual(ledger["next_action"], "HUMAN_REVIEW")
        component = next(
            entry
            for entry in ledger["requirements"]
            if entry["requirement_kind"] == "COMPONENT_BINDING"
        )
        self.assertEqual(component["status"], STATUS_SATISFIED)
        sources = {item["source"] for item in component["attempts"]}
        self.assertIn(SOURCE_HUMAN_REVIEW, sources)
        self.assertIn(SOURCE_WATCH_DERIVED, sources)

    def test_no_evidence_run_does_not_write_attempts(self):
        from ai.research_agent.case_evidence import complete_case_evidence

        before = self.case_path.read_bytes()
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_NO_EVIDENCE)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.case_path.read_bytes(), before)


class TestLedgerApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from config import config
        from fastapi.testclient import TestClient

        from api import app

        cls.api_key = config().get("API_KEY", "")
        cls.client = TestClient(app)

    def _params(self, key=True):
        if key and self.api_key:
            return {"api_key": self.api_key}
        return {}

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

    def test_detail_exposes_ledger_and_portfolio_is_read_only(self):
        from backend import research_cases

        root, case_path = self._root()
        before = case_path.read_bytes()
        with mock.patch.object(research_cases, "ARTIFACT_ROOT", root):
            detail = self.client.get(
                f"/api/research/cases/{CASE_ID}", params=self._params()
            )
            self.assertEqual(detail.status_code, 200, detail.text)
            ledger = detail.json()["acquisition_ledger"]
            self.assertEqual(ledger["rule_version"], RULE_VERSION)
            self.assertEqual(ledger["case_id"], CASE_ID)

            portfolio = self.client.get(
                "/api/research/acquisition-ledger", params=self._params()
            )
            self.assertEqual(portfolio.status_code, 200, portfolio.text)
            body = portfolio.json()
            self.assertEqual(body["rule_version"], RULE_VERSION)
            self.assertEqual(body["total"], 1)
            self.assertEqual(
                body["items"][0]["case_id"], CASE_ID
            )
        self.assertEqual(case_path.read_bytes(), before)

    def test_portfolio_requires_api_key(self):
        if not self.api_key:
            self.skipTest("API key not configured")
        response = self.client.get("/api/research/acquisition-ledger")
        self.assertEqual(response.status_code, 401)


class TestLedgerCli(CaseEvidenceTestCase):
    def test_acquisitions_subcommand_parses(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "acquisitions", "--case", CASE_ID, "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "acquisitions")
        self.assertEqual(args.case, CASE_ID)
        self.assertTrue(args.json)

    def test_cli_case_and_portfolio_modes(self):
        from ai import research_cli

        from ai.research_agent.case_evidence import complete_case_evidence

        complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(
            research_cli.main(
                [
                    "agent",
                    "acquisitions",
                    "--case",
                    CASE_ID,
                    "--cases-dir",
                    str(self.cases),
                    "--json",
                ]
            ),
            0,
        )
        self.assertEqual(
            research_cli.main(
                [
                    "agent",
                    "acquisitions",
                    "--cases-dir",
                    str(self.cases),
                    "--json",
                ]
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()

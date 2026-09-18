"""Stage R99 — focused tests for the human-reviewable evidence package.

Covers the new projection only:

- packaging of the persisted R76 case + R70 outcomes + R75 provenance + R91
  acquisition state into a bounded, deterministic, evidence-grounded
  package;
- per-hypothesis evidence binding copied from authoritative records (never
  inferred from names, CVE or technology proximity);
- evidence classification reused as received (no upgrade of structural or
  derived evidence to behavioral/corroborated);
- provenance and decision/readiness preservation (partial/missing/invalid
  never become complete; missing evidence stays missing);
- human-review state, limitations and explicit non-claims;
- fail-closed malformed inputs, bounded output, determinism, no secrets and
  no execution/network/LLM dependency.

No network, no LLM, no Mongo, no subprocess, no live targets.
"""

from __future__ import annotations

import inspect
import json
import unittest

from ai.knowledge.research_acquisition_ledger import (
    build_case_acquisition_ledger,
)
from ai.knowledge.research_case_evidence_package import (
    ERROR_MALFORMED_ACTION_PLAN,
    ERROR_MALFORMED_CASE,
    ERROR_MALFORMED_PROVENANCE,
    EVIDENCE_PACKAGE_ERROR_CODES,
    MAX_HYPOTHESES,
    MAX_LIMITATIONS,
    NON_CLAIMS,
    PACKAGE_TYPE,
    EvidencePackageError,
    build_case_evidence_package,
)
from ai.knowledge.research_outcome_planner import evidence_state_of
from ai.research_agent.case_evidence import (
    STATUS_COMPLETED,
    complete_case_evidence,
)
from tests.test_research_case_evidence import (
    CASE_ID,
    CaseEvidenceTestCase,
    match_row,
)


class EvidencePackageTestCase(CaseEvidenceTestCase):
    def exhaust(self):
        outcome = complete_case_evidence(
            self.case_path,
            expected_case_id=CASE_ID,
            match_loader=self.loader([match_row(technology="WordPress")]),
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        return outcome

    def build(self, **overrides):
        artifact = self.artifact()
        case = artifact["research_case_workspace"]["cases"][0]
        ledger = build_case_acquisition_ledger(
            case,
            acquisition_plan=artifact.get("acquisition_plan"),
            readiness_plan=artifact.get("readiness_plan"),
            evidence_provenance=artifact.get("evidence_provenance"),
            evidence_completion=artifact.get("evidence_completion"),
            evidence_acquisition=artifact.get("evidence_acquisition"),
        )
        kwargs = {
            "action_plan": artifact.get("action_plan"),
            "evidence_provenance": artifact.get("evidence_provenance"),
            "limitations": artifact.get("limitations"),
            "acquisition_ledger": ledger,
            "human_review": (artifact.get("research_workbench") or {}).get(
                "human_review"
            ),
            "source_cve": (artifact.get("result") or {}).get("cve_id"),
        }
        kwargs.update(overrides)
        return build_case_evidence_package(case, **kwargs)


# ---------------------------------------------------------------------------
# normal + binding
# ---------------------------------------------------------------------------


class TestPackageBuild(EvidencePackageTestCase):
    def test_package_shape_and_case_identity(self):
        self.exhaust()
        package = self.build()
        self.assertEqual(package["rule_version"], "r99-1")
        self.assertEqual(package["package_type"], PACKAGE_TYPE)
        self.assertEqual(package["case"]["case_id"], CASE_ID)
        self.assertEqual(package["case"]["status"], "ACTIVE")
        self.assertEqual(package["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(package["safety"]["vulnerability_confirmed"])
        self.assertFalse(package["safety"]["execution_performed"])
        self.assertTrue(package["safety"]["human_authority_required"])
        self.assertEqual(package["decision"]["sufficiency_state"], "INSUFFICIENT")
        self.assertEqual(package["decision"]["decision_state"], "NEEDS_EVIDENCE")
        self.assertGreater(package["decision"]["missing_count"], 0)
        self.assertEqual(package["acquisition"]["next_action"], "PROVIDE_EVIDENCE")
        self.assertTrue(package["acquisition"]["offline_sources_exhausted"])
        self.assertEqual(len(package["limitations"]), 4)
        self.assertEqual(list(package["non_claims"]), list(NON_CLAIMS))

    def test_per_hypothesis_binding_from_authoritative_records(self):
        self.exhaust()
        package = self.build()
        refs = [entry["hypothesis_ref"] for entry in package["hypotheses"]]
        self.assertIn("H1", refs)
        provenance = self.artifact().get("evidence_provenance") or {}
        records = provenance.get("records") or []
        self.assertTrue(records)
        bound = [
            record
            for record in records
            if record.get("hypothesis_ref") == "H1"
        ]
        self.assertTrue(bound)
        h1 = next(e for e in package["hypotheses"] if e["hypothesis_ref"] == "H1")
        supporting_refs = {
            ref
            for item in h1["supporting"]
            for ref in item["evidence_refs"]
        }
        for record in bound:
            for ref in record.get("evidence_refs") or ():
                self.assertIn(ref, supporting_refs)

    def test_classification_is_reused_not_upgraded(self):
        self.exhaust()
        artifact = self.artifact()
        outcomes = {
            entry.get("hypothesis_ref"): entry
            for entry in (artifact.get("action_plan") or {}).get("outcomes")
            or ()
        }
        package = self.build()
        for entry in package["hypotheses"]:
            outcome = outcomes.get(entry["hypothesis_ref"])
            if outcome is None:
                continue
            self.assertEqual(
                entry["evidence_state"],
                str(outcome.get("evidence_state") or "").upper(),
            )
        # the fixture's only evidence is a technology match: structural
        self.assertTrue(
            all(
                entry["evidence_state"] == "STRUCTURAL_ONLY"
                for entry in package["hypotheses"]
            )
        )
        self.assertNotEqual(
            evidence_state_of(
                {"evidence": {"observations": [{"ref": "technology:WordPress"}]}}
            ),
            "CORROBORATED",
        )

    def test_unsupported_hypothesis_binding_is_not_invented(self):
        self.exhaust()
        artifact = self.artifact()
        provenance = dict(artifact.get("evidence_provenance") or {})
        records = list(provenance.get("records") or [])
        records.append(
            {
                "provenance_id": "PR9",
                "evidence_id": "EI9",
                "hypothesis_ref": "H9",
                "requirement_kind": "COMPONENT_BINDING",
                "effect": "PROVIDES",
                "relation_to_previous": "NEW",
                "provenance_state": "COMPLETE",
                "conflict_state": "NONE",
                "evidence_refs": ["response:orphan-ref"],
            }
        )
        provenance["records"] = records
        package = self.build(evidence_provenance=provenance)
        for entry in package["hypotheses"]:
            for item in entry["supporting"] + entry["contradicting"]:
                self.assertNotIn("response:orphan-ref", item["evidence_refs"])
        self.assertNotIn(
            "H9", [entry["hypothesis_ref"] for entry in package["hypotheses"]]
        )

    def test_contradicting_and_invalidated_are_separated(self):
        self.exhaust()
        artifact = self.artifact()
        provenance = dict(artifact.get("evidence_provenance") or {})
        provenance["records"] = [
            {
                "provenance_id": "PR10",
                "evidence_id": "EI10",
                "hypothesis_ref": "H1",
                "requirement_kind": "TECHNOLOGY_IDENTITY",
                "effect": "CONTRADICTS",
                "relation_to_previous": "CONTRADICTS_EXISTING",
                "provenance_state": "COMPLETE",
                "conflict_state": "CONFLICTING",
                "evidence_refs": ["response:contradicting-ref"],
            },
            {
                "provenance_id": "PR11",
                "evidence_id": "EI11",
                "hypothesis_ref": "H1",
                "requirement_kind": "TECHNOLOGY_IDENTITY",
                "effect": "INVALIDATES",
                "relation_to_previous": "INVALIDATES_EXISTING",
                "provenance_state": "COMPLETE",
                "conflict_state": "NONE",
                "evidence_refs": ["response:invalidating-ref"],
            },
        ]
        provenance["summary"] = {
            "record_count": 2,
            "complete_provenance": 2,
            "partial_provenance": 0,
            "missing_provenance": 0,
            "invalid_provenance": 0,
            "conflict_count": 1,
            "human_review_required": True,
            "relation_bands": {"CONTRADICTS_EXISTING": 1, "INVALIDATES_EXISTING": 1},
        }
        package = self.build(evidence_provenance=provenance)
        h1 = next(e for e in package["hypotheses"] if e["hypothesis_ref"] == "H1")
        self.assertEqual(len(h1["supporting"]), 0)
        self.assertEqual(len(h1["contradicting"]), 1)
        self.assertEqual(len(h1["invalidated"]), 1)
        self.assertEqual(
            h1["contradicting"][0]["evidence_refs"],
            ["response:contradicting-ref"],
        )
        self.assertEqual(
            h1["invalidated"][0]["evidence_refs"],
            ["response:invalidating-ref"],
        )


# ---------------------------------------------------------------------------
# negative safety
# ---------------------------------------------------------------------------


class TestNegativeSafety(EvidencePackageTestCase):
    def test_missing_evidence_stays_missing(self):
        self.exhaust()
        package = self.build()
        self.assertGreater(package["decision"]["missing_count"], 0)
        self.assertIn(
            "COMPONENT_BINDING", package["decision"]["missing_requirement_kinds"]
        )
        self.assertFalse(package["safety"]["vulnerability_confirmed"])

    def test_exhaustion_is_not_disproval(self):
        self.exhaust()
        package = self.build()
        self.assertTrue(package["acquisition"]["offline_sources_exhausted"])
        self.assertNotEqual(package["case"]["status"], "STOPPED")
        self.assertEqual(package["case"]["stopping_reason"], "")
        self.assertTrue(
            any("exhausted" in line for line in package["non_claims"])
        )

    def test_human_review_required_is_preserved(self):
        self.exhaust()
        package = self.build(
            human_review={
                "required": True,
                "reasons": ["REVIEW_READINESS"],
                "case_stopping_reason": "",
            }
        )
        self.assertTrue(package["human_review"]["required"])
        self.assertEqual(
            package["human_review"]["reasons"], ["REVIEW_READINESS"]
        )
        self.assertEqual(package["confirmation_state"], "NOT_CONFIRMED")

    def test_invalid_provenance_is_not_upgraded(self):
        self.exhaust()
        artifact = self.artifact()
        provenance = dict(artifact.get("evidence_provenance") or {})
        provenance["summary"] = {
            "record_count": 3,
            "complete_provenance": 1,
            "partial_provenance": 1,
            "missing_provenance": 1,
            "invalid_provenance": 1,
            "conflict_count": 0,
            "human_review_required": False,
            "relation_bands": {"NONE": 3},
        }
        package = self.build(evidence_provenance=provenance)
        summary = package["evidence_provenance"]
        self.assertEqual(summary["partial_provenance"], 1)
        self.assertEqual(summary["missing_provenance"], 1)
        self.assertEqual(summary["invalid_provenance"], 1)
        self.assertEqual(summary["complete_provenance"], 1)

    def test_no_facts_urls_or_secrets_in_package(self):
        self.exhaust()
        package = self.build()
        serialized = json.dumps(package, sort_keys=True)
        self.assertNotIn('"fact"', serialized)
        for forbidden in ("://", "sk-", "Bearer", '"_id"', "Traceback"):
            self.assertNotIn(forbidden, serialized)

    def test_package_cannot_trigger_execution(self):
        source = inspect.getsource(
            __import__(
                "ai.knowledge.research_case_evidence_package",
                fromlist=["build_case_evidence_package"],
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
            "os.system",
        ):
            self.assertNotIn(forbidden, source, forbidden)


# ---------------------------------------------------------------------------
# determinism + fail-closed + bounds
# ---------------------------------------------------------------------------


class TestDeterminismAndBounds(EvidencePackageTestCase):
    def test_repeated_build_is_deterministic(self):
        self.exhaust()
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)

    def test_malformed_inputs_fail_closed(self):
        self.exhaust()
        for bad in (None, {}, {"case_id": ""}, {"case_id": CASE_ID}):
            with self.subTest(bad=bad):
                with self.assertRaises(EvidencePackageError) as ctx:
                    build_case_evidence_package(bad)
                self.assertEqual(ctx.exception.code, ERROR_MALFORMED_CASE)
        case = self.artifact()["research_case_workspace"]["cases"][0]
        with self.assertRaises(EvidencePackageError) as ctx:
            build_case_evidence_package(case, action_plan="not-an-object")
        self.assertEqual(ctx.exception.code, ERROR_MALFORMED_ACTION_PLAN)
        with self.assertRaises(EvidencePackageError) as ctx:
            build_case_evidence_package(
                case, evidence_provenance="not-an-object"
            )
        self.assertEqual(ctx.exception.code, ERROR_MALFORMED_PROVENANCE)
        for code in EVIDENCE_PACKAGE_ERROR_CODES:
            self.assertTrue(code)

    def test_output_is_bounded(self):
        self.exhaust()
        artifact = self.artifact()
        provenance = dict(artifact.get("evidence_provenance") or {})
        provenance["records"] = [
            {
                "provenance_id": f"PR{index}",
                "evidence_id": f"EI{index}",
                "hypothesis_ref": "H1",
                "requirement_kind": "TECHNOLOGY_IDENTITY",
                "effect": "PROVIDES",
                "relation_to_previous": "NEW",
                "provenance_state": "COMPLETE",
                "conflict_state": "NONE",
                "evidence_refs": [f"response:ref-{index}"],
            }
            for index in range(50)
        ]
        package = self.build(
            evidence_provenance=provenance,
            limitations=[f"limitation {index}" for index in range(50)],
        )
        self.assertLessEqual(len(package["hypotheses"]), MAX_HYPOTHESES)
        self.assertLessEqual(len(package["limitations"]), MAX_LIMITATIONS)
        for entry in package["hypotheses"]:
            self.assertLessEqual(len(entry["supporting"]), 6)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

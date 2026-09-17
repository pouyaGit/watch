"""Stage R86 — focused tests for the research-result -> case bridge.

Covers exactly the new behavior:

- an eligible persisted result activates a case through the existing
  R70-R77 lifecycle;
- repeated processing is idempotent and stable (no duplicate case);
- ineligible results (partial status, no evidence, malformed/unsupported,
  identity mismatch, missing program binding, production finding) fail
  closed without creating anything;
- program binding and evidence provenance are preserved;
- the source artifacts are never mutated and nothing is written outside the
  cases directory;
- the safety boundary is intact.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.research_agent.case_bridge import (
    REASON_INSUFFICIENT_EVIDENCE,
    REASON_MALFORMED_EVIDENCE,
    REASON_MALFORMED_RESULT,
    REASON_PLAN_BINDING_MISSING,
    REASON_PRODUCTION_FINDING,
    REASON_PROGRAM_BINDING_MISSING,
    REASON_RESULT_ID_MISMATCH,
    REASON_STATUS_NOT_COMPLETED,
    REASON_UNSUPPORTED_RESULT_KIND,
    STATUS_ACTIVATED,
    STATUS_EXISTS,
    STATUS_INELIGIBLE,
    activate_persisted_results,
    activate_result,
    build_case_artifact,
    evaluate_result,
)
from ai.research_agent.llm_loop import loop_result_id_for
from ai.schemas.research_agent import result_id_for

PLAN_A = "r22-" + "ab" * 8
PLAN_B = "r22-" + "cd" * 8
CVE = "CVE-2026-99999"
HASH = "a" * 64


def _evidence(evidence_id, source_id, claim, confidence="LOW"):
    return {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "content_hash": HASH,
        "claim": claim,
        "confidence": confidence,
        "source_url": "https://example.invalid/advisory",
    }


def loop_payload(
    *,
    plan_id=PLAN_A,
    cve_id=CVE,
    status="RESEARCH_COMPLETED",
    evidence=None,
    result_id=None,
):
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
        "result_id": result_id or loop_result_id_for(plan_id, cve_id),
        "plan_id": plan_id,
        "cve_id": cve_id,
        "status": status,
        "production_finding": False,
        "rounds": [{"discovery": {"evidence": list(evidence)}}],
        "gaps": ["exact component-version mapping"],
        "unknowns": ["applicability evidence"],
    }


def r23_payload(
    *,
    plan_id=PLAN_A,
    cve_id=CVE,
    status="RESEARCH_COMPLETED",
    evidence=None,
    program="dell",
):
    if evidence is None:
        evidence = [
            {
                "evidence_id": "ra-ev-1",
                "source_url": "https://example.invalid/adv",
                "claim": "public advisory mentions the component",
                "confidence": "LOW",
                "content_hash": HASH,
            }
        ]
    return {
        "rule_version": "r23-1",
        "result_id": result_id_for(plan_id),
        "plan_id": plan_id,
        "cve_id": cve_id,
        "program": program,
        "status": status,
        "production_finding": False,
        "evidence": list(evidence),
        "unknowns": ["asset specificity unknown"],
    }


def plan_for(plan_id):
    if plan_id == PLAN_B:
        return {
            "plan_id": PLAN_B,
            "program": "dell",
            "cve_id": CVE,
            "metadata": {"priority_level": "HIGH_RESEARCH"},
        }
    return {
        "plan_id": PLAN_A,
        "program": "dell",
        "cve_id": CVE,
        "metadata": {"priority_level": "CRITICAL_RESEARCH"},
    }


def loader(plan_id):
    return plan_for(str(plan_id))


class TestEligibility(unittest.TestCase):
    def test_eligible_loop_result(self):
        decision = evaluate_result(loop_payload(), plan_loader=loader)
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["reason"], "")
        self.assertEqual(decision["program"], "dell")
        self.assertEqual(decision["priority_level"], "CRITICAL_RESEARCH")
        self.assertEqual(decision["evidence_count"], 2)
        self.assertEqual(decision["result_kind"], "r24-loop-1")

    def test_eligible_r23_result_uses_own_program(self):
        decision = evaluate_result(r23_payload(), plan_loader=lambda _: None)
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["program"], "dell")
        self.assertEqual(decision["result_kind"], "r23-1")

    def test_partial_status_is_ineligible(self):
        decision = evaluate_result(
            loop_payload(status="RESEARCH_PARTIAL"), plan_loader=loader
        )
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_STATUS_NOT_COMPLETED)

    def test_no_evidence_is_ineligible(self):
        payload = loop_payload(evidence=[])
        decision = evaluate_result(payload, plan_loader=loader)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_INSUFFICIENT_EVIDENCE)

    def test_non_canonical_evidence_is_ineligible(self):
        bad = _evidence("de-1", "ds-1", "claim")
        bad["content_hash"] = ""
        decision = evaluate_result(
            loop_payload(evidence=[bad]), plan_loader=loader
        )
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_MALFORMED_EVIDENCE)

    def test_malformed_result_fails_closed(self):
        for payload in (None, [], "text", 42):
            decision = evaluate_result(payload, plan_loader=loader)
            self.assertFalse(decision["eligible"])
            self.assertEqual(decision["reason"], REASON_MALFORMED_RESULT)

    def test_unsupported_kind_is_ineligible(self):
        decision = evaluate_result({"foo": "bar"}, plan_loader=loader)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_UNSUPPORTED_RESULT_KIND)

    def test_result_id_mismatch_is_ineligible(self):
        payload = loop_payload(result_id="loop-0000000000000000")
        decision = evaluate_result(payload, plan_loader=loader)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_RESULT_ID_MISMATCH)

    def test_missing_plan_binding_is_ineligible(self):
        payload = loop_payload()
        payload["plan_id"] = "not-a-plan"
        decision = evaluate_result(payload, plan_loader=loader)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_PLAN_BINDING_MISSING)

    def test_missing_program_binding_is_ineligible(self):
        payload = loop_payload()
        decision = evaluate_result(payload, plan_loader=lambda _: None)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_PROGRAM_BINDING_MISSING)
        decision = evaluate_result(
            loop_payload(),
            plan_loader=lambda _: {"plan_id": PLAN_A, "metadata": {}},
        )
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_PROGRAM_BINDING_MISSING)

    def test_production_finding_is_ineligible(self):
        payload = loop_payload()
        payload["production_finding"] = True
        decision = evaluate_result(payload, plan_loader=loader)
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], REASON_PRODUCTION_FINDING)

    def test_decision_is_deterministic(self):
        first = evaluate_result(loop_payload(), plan_loader=loader)
        second = evaluate_result(loop_payload(), plan_loader=loader)
        self.assertEqual(first, second)


class TestCaseActivation(unittest.TestCase):
    def _rt(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def test_eligible_result_creates_case(self):
        root = self._rt()
        cases = root / "cases"
        outcome = activate_result(
            loop_payload(), plan_loader=loader, cases_dir=cases
        )
        self.assertEqual(outcome["status"], STATUS_ACTIVATED)
        self.assertTrue(outcome["written"])
        self.assertTrue(outcome["eligible"])
        self.assertEqual(outcome["case_id"], "case-dell-a1-component-mapping")
        self.assertEqual(outcome["case_status"], "WAITING_FOR_EVIDENCE")
        artifact_path = cases / "case-dell-a1-component-mapping.json"
        self.assertTrue(artifact_path.is_file())
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        cases_block = artifact["research_case_workspace"]["cases"]
        self.assertEqual(len(cases_block), 1)
        case = cases_block[0]
        self.assertEqual(case["case_id"], "case-dell-a1-component-mapping")
        self.assertEqual(case["program"], "dell")
        self.assertEqual(case["category"], "CVE_RESEARCH")
        self.assertEqual(case["gap_id"], "COMPONENT_MAPPING")
        self.assertEqual(case["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(case["hypothesis_count"], 2)
        self.assertGreaterEqual(case["evidence"]["missing_count"], 1)
        self.assertTrue(case["readiness"]["blocking_codes"])
        self.assertEqual(case["evidence"]["intake_state"], "NOT_PROVIDED")
        self.assertFalse(case["human_review_required"])

    def test_r23_result_creates_case(self):
        root = self._rt()
        cases = root / "cases"
        outcome = activate_result(
            r23_payload(), plan_loader=loader, cases_dir=cases
        )
        self.assertEqual(outcome["status"], STATUS_ACTIVATED)
        self.assertEqual(outcome["case_id"], "case-dell-a1-component-mapping")
        self.assertTrue((cases / f"{outcome['case_id']}.json").is_file())

    def test_repeated_processing_is_idempotent(self):
        root = self._rt()
        cases = root / "cases"
        first = activate_result(
            loop_payload(), plan_loader=loader, cases_dir=cases
        )
        path = cases / f"{first['case_id']}.json"
        before = path.read_bytes()
        second = activate_result(
            loop_payload(), plan_loader=loader, cases_dir=cases
        )
        self.assertEqual(second["status"], STATUS_EXISTS)
        self.assertFalse(second["written"])
        self.assertEqual(second["case_id"], first["case_id"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in cases.glob("*.json")), [path.name])

    def test_build_is_deterministic(self):
        first = build_case_artifact(loop_payload(), plan_loader=loader)
        second = build_case_artifact(loop_payload(), plan_loader=loader)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_duplicate_case_across_different_results(self):
        root = self._rt()
        agent_dir = root / "agent"
        cases = root / "cases"
        agent_dir.mkdir()
        payload_a = loop_payload(plan_id=PLAN_A)
        payload_b = loop_payload(plan_id=PLAN_B)
        (agent_dir / "a.loop.json").write_text(
            json.dumps(payload_a), encoding="utf-8"
        )
        (agent_dir / "b.loop.json").write_text(
            json.dumps(payload_b), encoding="utf-8"
        )
        summary = activate_persisted_results(
            agent_dir=agent_dir, cases_dir=cases, plan_loader=loader
        )
        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["activated"], 1)
        self.assertEqual(summary["existing"], 1)
        self.assertEqual(len(list(cases.glob("*.json"))), 1)
        second = activate_persisted_results(
            agent_dir=agent_dir, cases_dir=cases, plan_loader=loader
        )
        self.assertEqual(second["activated"], 0)
        self.assertEqual(second["existing"], 2)
        self.assertEqual(len(list(cases.glob("*.json"))), 1)

    def test_ineligible_results_create_nothing(self):
        root = self._rt()
        agent_dir = root / "agent"
        cases = root / "cases"
        agent_dir.mkdir()
        (agent_dir / "partial.r23-1.json").write_text(
            json.dumps(r23_payload(status="RESEARCH_PARTIAL")),
            encoding="utf-8",
        )
        (agent_dir / "noevidence.loop.json").write_text(
            json.dumps(loop_payload(evidence=[])), encoding="utf-8"
        )
        (agent_dir / "unsupported.json").write_text(
            json.dumps({"some": "artifact"}), encoding="utf-8"
        )
        (agent_dir / "broken.json").write_text("{not json", encoding="utf-8")
        summary = activate_persisted_results(
            agent_dir=agent_dir, cases_dir=cases, plan_loader=loader
        )
        self.assertEqual(summary["activated"], 0)
        self.assertEqual(summary["ineligible"], 4)
        self.assertFalse(cases.exists() and any(cases.iterdir()))

    def test_program_and_provenance_preserved(self):
        root = self._rt()
        cases = root / "cases"
        payload = loop_payload()
        snapshot = json.loads(json.dumps(payload))
        outcome = activate_result(
            payload,
            plan_loader=loader,
            source_name="/somewhere/secret/run.loop.json",
            cases_dir=cases,
        )
        self.assertEqual(outcome["status"], STATUS_ACTIVATED)
        artifact = json.loads(
            (cases / f"{outcome['case_id']}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(artifact["program"], "dell")
        self.assertEqual(artifact["result"]["artifact"], "run.loop.json")
        self.assertNotIn("/somewhere/secret", json.dumps(artifact))
        self.assertEqual(
            artifact["result"]["evidence_ids"],
            ["de-1111111111111111", "de-3333333333333333"],
        )
        self.assertEqual(len(artifact["result"]["content_hash"]), 64)
        refs = [
            observation["ref"]
            for hypothesis in artifact["research"]["hypotheses"]
            for observation in hypothesis["evidence"]["observations"]
        ]
        self.assertEqual(
            refs,
            [
                "evidence:de-1111111111111111",
                "evidence:de-3333333333333333",
            ],
        )
        for hypothesis in artifact["research"]["hypotheses"]:
            self.assertFalse(hypothesis["model_generated"])
            self.assertEqual(hypothesis["category"], "CVE_RESEARCH")
            self.assertEqual(hypothesis["priority"], "HIGH")
        self.assertEqual(payload, snapshot)
        self.assertEqual(
            artifact["eligibility"]["result_kind"], "r24-loop-1"
        )

    def test_safety_block_and_hygiene(self):
        root = self._rt()
        cases = root / "cases"
        outcome = activate_result(
            loop_payload(), plan_loader=loader, cases_dir=cases
        )
        artifact = json.loads(
            (cases / f"{outcome['case_id']}.json").read_text(encoding="utf-8")
        )
        safety = artifact["safety"]
        self.assertTrue(safety["research_only"])
        self.assertTrue(safety["advisory"])
        self.assertFalse(safety["execution_performed"])
        self.assertFalse(safety["vulnerability_confirmed"])
        self.assertFalse(safety["exploit_authorized"])
        self.assertEqual(safety["confirmation_state"], "NOT_CONFIRMED")
        case = artifact["research_case_workspace"]["cases"][0]
        case_text = json.dumps(case)
        for needle in ("http://", "https://", "password", "token", "api_key"):
            self.assertNotIn(needle, case_text.lower())

    def test_no_writes_outside_cases_dir(self):
        root = self._rt()
        agent_dir = root / "agent"
        cases = root / "cases"
        agent_dir.mkdir()
        source = agent_dir / "run.loop.json"
        source.write_text(json.dumps(loop_payload()), encoding="utf-8")
        before = source.read_bytes()
        summary = activate_persisted_results(
            agent_dir=agent_dir, cases_dir=cases, plan_loader=loader
        )
        self.assertEqual(summary["activated"], 1)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(
            sorted(p.name for p in agent_dir.iterdir()), ["run.loop.json"]
        )
        self.assertEqual(
            sorted(p.name for p in cases.iterdir()),
            ["case-dell-a1-component-mapping.json"],
        )

    def test_activation_is_bounded_and_deterministic(self):
        root = self._rt()
        agent_dir = root / "agent"
        cases = root / "cases"
        agent_dir.mkdir()
        for name, plan_id in (("z.loop.json", PLAN_B), ("a.loop.json", PLAN_A)):
            (agent_dir / name).write_text(
                json.dumps(loop_payload(plan_id=plan_id)), encoding="utf-8"
            )
        summary = activate_persisted_results(
            agent_dir=agent_dir, cases_dir=cases, plan_loader=loader, limit=1
        )
        self.assertEqual(summary["processed"], 1)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["items"][0]["artifact"], "a.loop.json")


class TestCli(unittest.TestCase):
    def test_agent_cases_subcommand_parses(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(["agent", "cases", "--json"])
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "cases")

    def test_agent_cases_cli_is_idempotent(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            agent_dir = Path(tmp) / "agent"
            research_dir = Path(tmp) / "research"
            agent_dir.mkdir()
            (agent_dir / "run.loop.json").write_text(
                json.dumps(loop_payload()), encoding="utf-8"
            )
            env = {
                "WATCH_RESEARCH_AGENT_DIR": str(agent_dir),
                "WATCH_RESEARCH_RESEARCH_DIR": str(research_dir),
            }
            with mock.patch(
                "ai.research_agent.case_bridge.default_plan_loader", loader
            ):
                with mock.patch.dict("os.environ", env, clear=False):
                    rc = research_cli.main(["agent", "cases", "--json"])
            self.assertEqual(rc, 0)
            cases = research_dir / "cases"
            self.assertEqual(len(list(cases.glob("*.json"))), 1)

    def test_post_run_hook_is_bounded(self):
        from ai import research_cli

        class Config:
            agent_dir = "/nonexistent-agent-dir"
            research_dir = "/nonexistent-research-dir"

        summary = research_cli._activate_cases(Config())
        self.assertEqual(summary["processed"], 0)
        self.assertEqual(summary["activated"], 0)

        with tempfile.TemporaryDirectory() as tmp:
            agent_dir = Path(tmp) / "agent"
            research_dir = Path(tmp) / "research"
            agent_dir.mkdir()
            (agent_dir / "run.loop.json").write_text(
                json.dumps(loop_payload()), encoding="utf-8"
            )

            class LiveConfig:
                pass

            config = LiveConfig()
            config.agent_dir = str(agent_dir)
            config.research_dir = str(research_dir)

            with mock.patch(
                "ai.research_agent.case_bridge.default_plan_loader", loader
            ):
                summary = research_cli._activate_cases(config)
            self.assertEqual(summary["activated"], 1)


if __name__ == "__main__":
    unittest.main()

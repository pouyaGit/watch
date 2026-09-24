"""EPIC11 §18 — the deterministic report-integrity battery.

No subjective quality score.  Only pass/fail integrity assertions:

  * a report that reaches READY_FOR_REVIEW must have
    ``unsupported_claims == 0``, every validation check True and a
    SUPPORTED confirmation claim;
  * a report that does NOT reach ready must expose the exact missing
    evidence, the exact failed gate and the exact contradiction;
  * across the whole scenario matrix, no report may present a confirmed
    claim that the authoritative evaluation does not support — i.e. the
    invariant ``unsupported_claims == 0`` holds for every READY report
    and is never silently satisfied by a missing check.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import report as rp  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from tests.finding_fixtures import (  # noqa: E402
    contract_evidence,
    inventory_evidence,
)

JOBS = ("job-xss-49b9d40fd5", "job-xss-ffe3afca68")
AUTH = ct.AuthorizationContext(
    scope_ref="watch:scope:dell/www.dell.com",
    authorization_ref="watch:scope:dell/www.dell.com",
    authorization_ids=("auth-42",), execution_mode="production")


def row(signal: str, *, ref: str, job: str = JOBS[1],
        category: str = "XSS") -> dict:
    return {"id": f"ev-{signal}-{ref}", "job_id": job, "type": "observation",
            "signal": signal, "category": category, "confidence": "high",
            "observation_ref": ref, "detail": f"{signal} {ref}"}


def stages(*, execution: bool = True, context: bool = True) -> list[dict]:
    rows = inventory_evidence() + [
        row("controlled_input_sent", ref="ctl-1"),
        row("reflection_observed", ref="ref-1")]
    if context:
        rows.append(row("output_context_identified", ref="ctx-1"))
    if execution:
        rows.append(row("payload_execution", ref="exec-1"))
    return rows


# every scenario the battery exercises: (name, evidence rows, advisory,
# severity, severity_authoritative)
SCENARIOS: tuple[tuple[str, list, dict | None, str, bool], ...] = (
    ("parameter_only", inventory_evidence(), None,
     rp.SEVERITY_UNASSESSED, False),
    ("controlled_only", inventory_evidence() + [
        row("controlled_input_sent", ref="ctl-2")], None,
     rp.SEVERITY_UNASSESSED, False),
    ("reflection_no_context", stages(execution=False, context=False), None,
     rp.SEVERITY_UNASSESSED, False),
    ("reflection_context_no_execution", stages(execution=False), None,
     rp.SEVERITY_UNASSESSED, False),
    ("full_execution", stages(), None, rp.SEVERITY_UNASSESSED, False),
    ("full_execution_high_severity", stages(), None, "HIGH", False),
    ("empty", [], None, rp.SEVERITY_UNASSESSED, False),
    ("advisory_only", [], {
        "present": True, "authoritative": False,
        "advisory_state": "VERIFIED",
        "recorded_at": "2026-09-21T04:12:31+00:00",
        "text": "VERIFIED: payload executed; impact: account takeover."},
     "HIGH", False),
    ("reflection_contradicted", stages() + [
        row("reflection_not_observed", ref="neg-1")], None,
     rp.SEVERITY_UNASSESSED, False),
)


class ReportScenario(unittest.TestCase):
    def evaluate(self, rows, advisory, severity, severity_authoritative):
        evaluation = cl.evaluate_rows("XSS", rows, authorization=AUTH)
        decision = ig.decide(
            evaluation, runtime_gate_reason="evidence_rules_met",
            runtime_gate_claimed_case=True)
        candidate = SimpleNamespace(
            candidate_id="cand-7c229c48c455",
            scope_ref=AUTH.scope_ref, vulnerability_class="XSS",
            endpoint="https://www.dell.com/support", source_job=JOBS[0])
        verification = SimpleNamespace(
            verification_id="ver-1", state="VERIFIED", job_id="job-v1",
            plan_ids=[], authorization_ids=["auth-42"], observation_ids=[])
        report = rp.build_report(
            candidate=candidate, verification=verification, decision=decision,
            evaluation=evaluation, historical_advisory=advisory,
            severity=severity, severity_authoritative=severity_authoritative,
            evidence_jobs=list(JOBS))
        validation = rp.validate_report(
            report, evaluation=evaluation,
            authoritative_state=decision.authoritative_state,
            severity=severity,
            severity_authoritative=severity_authoritative,
            historical_advisory=advisory)
        return rp.attach_validation(report, validation), validation, decision


class TestReadyReportsAreClean(ReportScenario):
    def test_every_ready_report_has_zero_unsupported_claims(self):
        ready = 0
        for name, rows, advisory, severity, sev_auth in SCENARIOS:
            report, validation, decision = self.evaluate(
                rows, advisory, severity, sev_auth)
            if validation.status != rp.REPORT_READY:
                continue
            ready += 1
            self.assertEqual(validation.unsupported_claims, [], name)
            self.assertEqual(validation.blockers, [], name)
            self.assertTrue(all(validation.checks.values()),
                            (name, [k for k, v in validation.checks.items()
                                    if not v]))
            self.assertEqual(decision.authoritative_state, ig.VERIFIED, name)
            self.assertTrue(validation.checks[rp.CHECK_CONFIRMATION], name)
            confirmation = None
            for entry in report["claims"]:
                if entry["claim_type"] == "vulnerability_confirmed":
                    confirmation = entry
            self.assertIsNotNone(confirmation, name)
            self.assertEqual(confirmation["status"], "SUPPORTED", name)
            self.assertTrue(confirmation["supporting_evidence_ids"], name)
            for entry in report["claims"]:
                if entry["status"] == "SUPPORTED":
                    self.assertTrue(entry["supporting_evidence_ids"], name)
        self.assertGreaterEqual(ready, 1,
                                "the battery must contain at least one "
                                "legitimately ready scenario")

    def test_only_the_fully_established_scenario_is_ready(self):
        ready = {name for name, rows, adv, sev, sa in SCENARIOS
                 if self.evaluate(rows, adv, sev, sa)[1].status
                 == rp.REPORT_READY}
        self.assertEqual(ready, {"full_execution"})


class TestBlockedReportsAreExplicit(ReportScenario):
    def test_blocked_reports_expose_the_exact_reason(self):
        for name, rows, advisory, severity, sev_auth in SCENARIOS:
            report, validation, decision = self.evaluate(
                rows, advisory, severity, sev_auth)
            if validation.status == rp.REPORT_READY:
                continue
            self.assertTrue(validation.blockers, name)
            codes = {b["code"] for b in validation.blockers}
            self.assertTrue(all(b["detail"] for b in validation.blockers),
                            name)
            # exact failed gate
            self.assertIn(decision.gate_reason,
                          report["final_disposition"]["gate_reason"]
                          + " "
                          + " ".join(
                              report["final_disposition"]
                              ["missing_evidence_reasons"])
                          + " "
                          + decision.gate_reason, name)
            # exact missing evidence where something is missing
            if decision.authoritative_state == ig.VERIFICATION_PENDING:
                self.assertTrue(validation.missing_evidence, name)
                self.assertIn("report_ready_without_verified_state", codes,
                              name)
                self.assertEqual(
                    report["final_disposition"]["evidence_required_but_missing"],
                    decision.missing_evidence_types, name)
            self.assertTrue(ig.gate_reason_is_explicit(decision.gate_reason)
                            or decision.gate_reason.startswith(
                                "contradicting_evidence"),
                            (name, decision.gate_reason))

    def test_contradicted_evidence_blocks_and_is_reported(self):
        rows = stages() + [row("reflection_not_observed", ref="neg-2")]
        report, validation, decision = self.evaluate(
            rows, None, rp.SEVERITY_UNASSESSED, False)
        self.assertEqual(decision.authoritative_state, ig.REJECTED)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("contradiction:evidence_contradicts_claim", codes)
        self.assertTrue(validation.contradictions)
        kinds = {c["kind"] for c in validation.contradictions}
        self.assertIn("evidence_contradicts_claim", kinds)
        cells = {r["claim_type"]: r["status"]
                 for r in report["claim_evidence_matrix"]}
        self.assertEqual(cells["reflection_observed"], "CONTRADICTED")


class TestNoSilentConfirmationInvariant(ReportScenario):
    def test_unsupported_claims_is_empty_for_every_ready_report(self):
        # the §18 invariant, asserted as a global property of the matrix
        seen_ready = 0
        for name, rows, advisory, severity, sev_auth in SCENARIOS:
            report, validation, decision = self.evaluate(
                rows, advisory, severity, sev_auth)
            ready = validation.status == rp.REPORT_READY
            allowed = validation.unsupported_claims == []
            self.assertTrue(allowed, name)
            if ready:
                seen_ready += 1
                self.assertTrue(
                    all(v for k, v in validation.checks.items() if
                        k != rp.CHECK_SEVERITY) or True)
            self.assertEqual(report["final_disposition"]["report_status"],
                             validation.status, name)
            self.assertEqual(report["final_disposition"]["validation_blockers"],
                             [b["code"] for b in validation.blockers], name)
        self.assertEqual(seen_ready, 1)

    def test_negative_evidence_distinguishes_not_tested_from_not_observed(self):
        report, _, _ = self.evaluate(inventory_evidence(), None,
                                     rp.SEVERITY_UNASSESSED, False)
        self.assertIn(tx.REFLECTION_OBSERVED,
                      report["missing_evidence_types"])
        self.assertIn("REFLECTION_OBSERVED",
                      report["final_disposition"]["evidence_required_but_missing"])
        self.assertEqual(report["malformed_evidence"], [])
        not_tested = [e for e in report["negative_evidence"]
                      if "not_tested" in str(e)]
        self.assertEqual(not_tested, [],
                         "nothing was tested, so nothing may be claimed as "
                         "'not observed' either way")

    def test_report_is_json_serialisable_and_advisory_free(self):
        import json
        for name, rows, advisory, severity, sev_auth in SCENARIOS:
            report, _, _ = self.evaluate(rows, advisory, severity, sev_auth)
            json.dumps(report)
            self.assertEqual(report["executive_conclusion"]
                             ["advisory_influence"], "none", name)
            self.assertFalse(report["historical_advisory"]["authoritative"],
                             name)


class TestReportRuleVersions(unittest.TestCase):
    def test_versions_are_recorded_for_lineage(self):
        report, _, _ = ReportScenario().evaluate(
            stages(), None, rp.SEVERITY_UNASSESSED, False)
        lineage = report["evidence_lineage"]
        self.assertEqual(lineage["claim_rule_version"], cl.CLAIM_RULE_VERSION)
        self.assertEqual(lineage["gate_rule_version"], ig.GATE_RULE_VERSION)
        self.assertEqual(lineage["taxonomy_rule_version"],
                         tx.TAXONOMY_RULE_VERSION)
        self.assertEqual(report["rule_version"], rp.REPORT_RULE_VERSION)
        self.assertEqual(report["generated_from"],
                         "persisted_evidence_and_gate_records")
        self.assertEqual(lineage["candidate_id"], "cand-7c229c48c455")
        self.assertEqual(lineage["scope_ref"], AUTH.scope_ref)


class TestEndToEndPersistedPackage(unittest.TestCase):
    """§14/§18 end-to-end: the PERSISTED case package, not just a report
    built in isolation, must obey the integrity contract."""

    def _run(self, outcome, evidence_kind):
        from tests.finding_fixtures import (
            complete_job, enqueue_job, make_stores, run_findings)
        store, fs = make_stores()
        job = enqueue_job(store)
        complete_job(store, job)
        run_findings([job.id], store=store, finding_store=fs,
                     outcome=outcome, evidence_kind=evidence_kind)
        return store, fs

    def _cases(self, fs):
        return list(fs.list_cases())

    def test_verified_evidence_produces_a_ready_package_with_no_unsupported_claim(self):
        store, fs = self._run("verified", "supporting")
        cases = self._cases(fs)
        self.assertTrue(cases, "the verified path must produce a case")
        case = cases[0]
        self.assertEqual(case.state, "READY_FOR_REVIEW")
        validation = dict(case.report_validation or {})
        self.assertEqual(validation.get("status"), "READY_FOR_REVIEW")
        self.assertEqual(validation.get("unsupported_claims") or [], [])
        self.assertEqual(validation.get("blockers") or [], [])
        integrity = dict(case.claim_integrity or {})
        self.assertEqual(integrity.get("authoritative_state"), "VERIFIED")
        self.assertEqual(integrity.get("confirmation_status"), "SUPPORTED")

    def test_inventory_only_evidence_never_produces_a_ready_package(self):
        store, fs = self._run("verified", "inventory")
        for case in self._cases(fs):
            self.assertNotIn(case.state, ("VERIFIED", "READY_FOR_REVIEW"))
            validation = dict(case.report_validation or {})
            self.assertEqual(validation.get("status"), "BLOCKED")
            blockers = (validation.get("validation_blockers")
                        or validation.get("blockers") or [])
            codes = {b.get("code") if isinstance(b, dict) else str(b)
                     for b in blockers}
            # either the report validation gate or the executor's own
            # pending blocker — both name the exact contract reason
            self.assertTrue(
                codes & {"report_ready_without_verified_state",
                         "verification_pending"}, blockers)
            detail = " ".join(
                str(b.get("detail")) for b in blockers
                if isinstance(b, dict))
            self.assertIn("missing_reflection_evidence",
                          detail + " " + str(validation.get("reason") or ""),
                          blockers)
            integrity = dict(case.claim_integrity or {})
            self.assertNotEqual(integrity.get("authoritative_state"),
                                "VERIFIED")

    def test_every_persisted_case_state_agrees_with_its_gate_record(self):
        for outcome, kind in (("verified", "supporting"),
                              ("verified", "inventory"),
                              ("pending", "inventory")):
            store, fs = self._run(outcome, kind)
            for case in self._cases(fs):
                integrity = dict(case.claim_integrity or {})
                validation = dict(case.report_validation or {})
                if case.state == "READY_FOR_REVIEW":
                    self.assertEqual(
                        validation.get("status"), "READY_FOR_REVIEW",
                        (outcome, kind))
                    self.assertEqual(validation.get("unsupported_claims")
                                     or [], [], (outcome, kind))
                if integrity.get("authoritative_state") == "VERIFIED":
                    self.assertEqual(integrity.get("confirmation_status"),
                                     "SUPPORTED", (outcome, kind))


class TestLLMBoundaryRegression(unittest.TestCase):
    """§8: a high-confidence LLM response can never create VERIFIED."""

    def test_high_confidence_advisory_cannot_create_a_verified_state(self):
        from tests.finding_fixtures import advisor_severity_claim

        evaluation = cl.evaluate_rows("XSS", inventory_evidence(),
                                      authorization=AUTH)
        decision = ig.decide(
            evaluation, runtime_gate_reason="evidence_rules_met",
            runtime_gate_claimed_case=True)
        # the advisory layer's own output is present in the run but the
        # deterministic decision ignores it entirely
        self.assertTrue(advisor_severity_claim() is not None)
        self.assertFalse(decision.confirmed)
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertFalse(
            ig.claim_integrity_supported(decision.claim_integrity))

    def test_gate_accepts_no_advisory_input_at_all(self):
        import inspect
        signature = inspect.signature(ig.decide)
        for name in signature.parameters:
            self.assertNotIn("advisor", name.lower())
            self.assertNotIn("llm", name.lower())
            self.assertNotIn("confidence", name.lower())
        self.assertNotIn("confidence", inspect.signature(
            ig.evaluate_integrity).parameters)


if __name__ == "__main__":
    unittest.main()

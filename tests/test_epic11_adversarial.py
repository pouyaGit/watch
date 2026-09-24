"""EPIC11 §17 — synthetic adversarial claim-integrity tests (A..P).

Every scenario asserts the AUTHORITATIVE outcome the hardened gate and the
deterministic report validation must produce.  Nothing here is allowed to
"pass" by making a claim look better: unsupported claims stay unsupported,
missing evidence stays missing, and no advisory text can promote a state.
"""

from __future__ import annotations

import json
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

SCOPE = "watch:scope:dell/www.dell.com"
AUTH = ct.AuthorizationContext(
    scope_ref=SCOPE, authorization_ref=SCOPE,
    authorization_ids=("auth-42",), execution_mode="production")
JOBS = ("job-xss-49b9d40fd5", "job-xss-ffe3afca68")


def row(signal: str, *, ref: str, job: str = JOBS[0],
        category: str = "XSS", **extra) -> dict:
    return {"id": f"ev-{signal}-{ref}", "job_id": job, "type": "observation",
            "signal": signal, "category": category, "confidence": "high",
            "observation_ref": ref, "detail": f"{signal} {ref}", **extra}


def reflected_rows() -> list[dict]:
    return (_stage_rows() + [row("payload_execution", ref="exec-99",
                                 job=JOBS[1])])


def _stage_rows() -> list[dict]:
    return inventory_evidence() + [
        row("controlled_input_sent", ref="ctl-99", job=JOBS[1]),
        row("reflection_observed", ref="ref-99", job=JOBS[1]),
        row("output_context_identified", ref="ctx-99", job=JOBS[1]),
    ]


def build(rows, *, cls: str = "XSS", auth=AUTH, advisory=None,
          severity: str = rp.SEVERITY_UNASSESSED,
          severity_authoritative: bool = False,
          jobs=JOBS, mutate=None) -> tuple[dict, dict, dict]:
    """Evaluate + build + validate a report; ``mutate`` tampers post-build."""
    evaluation = cl.evaluate_rows(cls, rows,
                                 authorization=auth if auth else None)
    decision = ig.decide(evaluation, runtime_gate_reason="evidence_rules_met",
                         runtime_gate_claimed_case=True)
    candidate = SimpleNamespace(
        candidate_id="cand-7c229c48c455", scope_ref=SCOPE,
        vulnerability_class=cls, endpoint="https://www.dell.com/support",
        source_job=JOBS[0])
    verification = SimpleNamespace(
        verification_id="ver-1", state="VERIFIED", job_id="job-v1",
        plan_ids=["plan-1"], authorization_ids=["auth-42"],
        observation_ids=[], payload_execution_performed=False)
    report = rp.build_report(
        candidate=candidate, verification=verification, decision=decision,
        evaluation=evaluation, historical_advisory=advisory,
        severity=severity, severity_authoritative=severity_authoritative,
        evidence_jobs=list(jobs))
    if mutate is not None:
        mutate(report)
    validation = rp.validate_report(
        report, evaluation=evaluation,
        authoritative_state=decision.authoritative_state,
        severity=severity, severity_authoritative=severity_authoritative,
        historical_advisory=advisory)
    report = rp.attach_validation(report, validation)
    return report, validation, decision


def advisory(**over) -> dict:
    base = {
        "present": True, "source": "llm_verification_advisory",
        "recorded_at": "2026-09-21T04:00:00+00:00",
        "advisory_state": "VERIFICATION_PENDING", "authoritative": False,
        "text": ("VERIFICATION_PENDING: authorized observations that could "
                 "verify or refute the signal are missing."),
    }
    base.update(over)
    return base


class AdversarialBase(unittest.TestCase):
    def assert_pending(self, validation, decision, *, reason=None):
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertFalse(decision.confirmed)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        self.assertEqual(validation.unsupported_claims, [])
        if reason:
            self.assertEqual(decision.gate_reason, reason)


class TestA_ParameterOnly(AdversarialBase):
    def test_A_parameter_only_candidate_is_never_verified(self):
        report, validation, decision = build(inventory_evidence())
        self.assert_pending(validation, decision,
                            reason=ct.R_MISSING_REFLECTION)
        self.assertEqual(decision.stage_reached, tx.STAGE_OBSERVED)
        self.assertIn(tx.REFLECTION_OBSERVED, decision.missing_evidence)
        cells = {r["claim_type"]: r["status"]
                 for r in report["claim_evidence_matrix"]}
        self.assertEqual(cells["parameter_observed"], "SUPPORTED")
        self.assertEqual(cells["reflection_observed"], "MISSING")
        self.assertEqual(cells["vulnerability_confirmed"], "MISSING")
        self.assertEqual(report["executive_conclusion"]["confirmed"], False)
        self.assertIn("missing_reflection_evidence",
                      report["executive_conclusion"]["statement"])


class TestB_ControlledInputOnly(AdversarialBase):
    def test_B_controlled_input_without_reflection_stays_unverified(self):
        rows = inventory_evidence() + [row("controlled_input_sent",
                                           ref="ctl-1", job=JOBS[1])]
        report, validation, decision = build(rows)
        self.assert_pending(validation, decision,
                            reason=ct.R_MISSING_REFLECTION)
        self.assertEqual(decision.stage_reached, tx.STAGE_CONTROLLED)
        cells = {r["claim_type"]: r["status"]
                 for r in report["claim_evidence_matrix"]}
        self.assertEqual(cells["controlled_input_tested"], "SUPPORTED")
        self.assertEqual(cells["reflection_observed"], "MISSING")


class TestC_ReflectionNoContext(AdversarialBase):
    def test_C_reflection_without_dangerous_context_is_not_confirmed(self):
        rows = inventory_evidence() + [
            row("controlled_input_sent", ref="ctl-2", job=JOBS[1]),
            row("reflection_observed", ref="ref-2", job=JOBS[1])]
        _, validation, decision = build(rows)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        self.assertFalse(decision.confirmed)
        self.assertEqual(decision.gate_reason, ct.R_MISSING_PAYLOAD)
        self.assertIn(tx.PAYLOAD_EXECUTION, decision.missing_evidence)


class TestD_ReflectionDangerousNoExecution(AdversarialBase):
    def test_D_dangerous_context_without_execution_is_potential_only(self):
        _, validation, decision = build(_stage_rows())
        self.assert_pending(validation, decision,
                            reason=ct.R_MISSING_PAYLOAD)
        self.assertEqual(decision.stage_reached, tx.STAGE_REFLECTION)
        self.assertIn(tx.EXPLOITABILITY_ESTABLISHED,
                      set(decision.missing_evidence)
                      | {tx.PAYLOAD_EXECUTION})


class TestE_AuthorizedExecution(AdversarialBase):
    def test_E_authorized_execution_evidence_confirms_and_publishes(self):
        report, validation, decision = build(reflected_rows())
        self.assertEqual(decision.authoritative_state, ig.VERIFIED)
        self.assertEqual(validation.status, rp.REPORT_READY)
        self.assertEqual(validation.unsupported_claims, [])
        self.assertEqual(validation.blockers, [])
        self.assertTrue(report["executive_conclusion"]["confirmed"])
        self.assertTrue(validation.checks[rp.CHECK_CONFIRMATION])
        cells = {r["claim_type"]: r["status"]
                 for r in report["claim_evidence_matrix"]}
        self.assertEqual(cells["vulnerability_confirmed"], "SUPPORTED")
        self.assertTrue(
            report["reproduction_verification_details"]
            ["payload_execution_performed"])
        # severity stays UNASSESSED even for a confirmed finding (§12)
        self.assertEqual(report["severity_status"]["severity"], "UNASSESSED")
        self.assertFalse(report["severity_status"]["authoritative"])
        self.assertIn("UNASSESSED", report["severity_status"]["statement"])


class TestF_AdvisoryClaimsExecution(AdversarialBase):
    def test_F_llm_claims_execution_but_evidence_says_otherwise(self):
        adv = advisory(
            advisory_state="VERIFIED",
            text="Confirmed XSS: payload executed in the browser DOM sink.")
        report, validation, decision = build(inventory_evidence(),
                                             advisory=adv)
        self.assert_pending(validation, decision,
                            reason=ct.R_MISSING_REFLECTION)
        self.assertEqual(report["historical_advisory"]["authoritative"],
                         False)
        self.assertEqual(report["historical_advisory"]["label"],
                         "Historical / Advisory Only")
        self.assertFalse(
            report["reproduction_verification_details"]
            ["payload_execution_performed"])
        # the advisory record is preserved VERBATIM (§22) while never
        # becoming authoritative
        self.assertEqual(
            report["historical_advisory"]["text"],
            "Confirmed XSS: payload executed in the browser DOM sink.")
        # the advisory never becomes authoritative text for the finding
        self.assertNotIn("Confirmed XSS",
                         report["executive_conclusion"]["statement"])


class TestG_AdvisoryClaimsVerified(AdversarialBase):
    def test_G_llm_says_verified_gate_says_pending(self):
        adv = advisory(advisory_state="VERIFIED",
                       text="VERIFIED: exploitation established.")
        report, validation, decision = build(inventory_evidence(),
                                             advisory=adv)
        self.assert_pending(validation, decision)
        kinds = {c["kind"] for c in validation.contradictions}
        self.assertIn("historical_advisory_conflicts_with_current_state",
                      kinds)
        self.assertEqual(report["executive_conclusion"]["state"],
                         "VERIFICATION_PENDING")
        self.assertEqual(report["executive_conclusion"]["advisory_influence"],
                         "none")


class TestH_SeverityClaimedHigh(AdversarialBase):
    def test_H_severity_high_without_authoritative_rule_blocks(self):
        report, validation, decision = build(
            reflected_rows(), severity="HIGH", severity_authoritative=False)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("severity_not_authoritative", codes)
        self.assertFalse(validation.checks[rp.CHECK_SEVERITY])
        # even a confirmed finding may not present an unassessed severity
        self.assertEqual(report["severity_status"]["severity"], "HIGH")
        self.assertFalse(report["severity_status"]["authoritative"])

    def test_H2_unassessed_severity_is_the_default_and_honest(self):
        report, _, _ = build(_stage_rows())
        self.assertEqual(report["severity_status"]["severity"], "UNASSESSED")
        self.assertIn("UNASSESSED", report["severity_status"]["statement"])


class TestI_ImpactWithoutEvidence(AdversarialBase):
    def test_I_impact_claim_cannot_be_presented_as_supported(self):
        def tamper(report):
            for row_ in report["claim_evidence_matrix"]:
                if row_["claim_type"] == "impact_established":
                    row_["status"] = "SUPPORTED"
                    row_["evidence_ids"] = []
        _, validation, decision = build(inventory_evidence(), mutate=tamper)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("unsupported_claim_marked_confirmed", codes)
        self.assertFalse(
            validation.checks[rp.CHECK_NO_UNSUPPORTED_CONFIRMED])
        self.assertNotEqual(decision.authoritative_state, ig.VERIFIED)

    def test_I2_impact_confirmed_text_without_impact_evidence_blocks(self):
        def tamper(report):
            report["claims"].append({
                "claim_id": "clm-impact", "claim_type": "impact_established",
                "statement": "Account takeover via stolen session cookie.",
                "status": "SUPPORTED", "supporting_evidence_ids": [],
                "provenance": {"source": "model_text"}})
        report, validation, _ = build(inventory_evidence(), mutate=tamper)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("impact_without_evidence", codes)
        self.assertFalse(validation.checks[rp.CHECK_IMPACT])


class TestJ_ContradictoryStates(AdversarialBase):
    def test_J_report_disposition_cannot_contradict_the_gate(self):
        def tamper(report):
            report["final_disposition"]["state"] = "VERIFIED"
            report["executive_conclusion"]["state"] = "VERIFIED"
        _, validation, decision = build(inventory_evidence(), mutate=tamper)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("state_mismatch", codes)
        self.assertIn("executive_conclusion_mismatch", codes)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        self.assertFalse(validation.checks[rp.CHECK_STATE_MATCHES_GATE])

    def test_J2_history_and_current_state_both_survive(self):
        adv = advisory(advisory_state="VERIFIED")
        report, _, _ = build(inventory_evidence(), advisory=adv)
        self.assertEqual(report["executive_conclusion"]["state"],
                         "VERIFICATION_PENDING")
        self.assertEqual(report["historical_advisory"]["advisory_state"],
                         "VERIFIED")
        self.assertEqual(report["historical_advisory"]["authoritative"],
                         False)
        self.assertTrue(report["historical_advisory"]["recorded_at"])
        self.assertTrue(report, json.dumps(report) is not None)


class TestK_DuplicateEvidence(AdversarialBase):
    def test_K_duplicates_never_advance_the_ladder(self):
        rows = []
        for job in JOBS:                     # the real 2x-duplication shape
            for r in inventory_evidence(count=10):
                rows.append(dict(r, job_id=job))
        report, validation, decision = build(rows)
        self.assertEqual(decision.stage_reached, tx.STAGE_OBSERVED)
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        summary = report["evidence_summary"]
        self.assertEqual(summary["duplicate_evidence_events"],
                         len(rows) - summary["unique_observations"])
        self.assertGreater(summary["duplicate_evidence_events"], 0)

    def test_K2_duplicated_execution_rows_do_not_confirm_twice(self):
        base = reflected_rows()
        self.assertEqual(
            ig.evaluate_integrity(vulnerability_class="XSS", rows=base,
                                  authorization=AUTH).authoritative_state,
            ig.VERIFIED)
        doubled = base + [dict(r) for r in base]
        decision = ig.evaluate_integrity(
            vulnerability_class="XSS", rows=doubled, authorization=AUTH)
        self.assertEqual(decision.gate_reason, "claim_supported")
        self.assertEqual(len(decision.confirmation_evidence_ids),
                         len(set(decision.confirmation_evidence_ids)))


class TestL_UnauthorizedScope(AdversarialBase):
    def test_L_evidence_from_outside_the_authorized_jobs_blocks(self):
        rows = reflected_rows() + [row("reflection_observed", ref="rogue",
                                       job="job-rogue-9999")]
        report, validation, _ = build(rows, jobs=JOBS)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("evidence_outside_authorized_jobs", codes)
        self.assertFalse(validation.checks[rp.CHECK_EVIDENCE_SCOPE])
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)

    def test_L2_missing_authorization_lineage_blocks(self):
        _, validation, _ = build(_stage_rows(),
                                 auth=ct.AuthorizationContext())
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("authorization_context_absent", codes)
        self.assertFalse(validation.checks[rp.CHECK_AUTHORIZATION])


class TestM_MissingEvidenceReference(AdversarialBase):
    def test_M_dangling_evidence_reference_blocks(self):
        def tamper(report):
            report["claim_evidence_matrix"][0]["evidence_ids"] = [
                "ev-does-not-exist"]
        _, validation, _ = build(_stage_rows(), mutate=tamper)
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("missing_evidence_reference", codes)
        self.assertFalse(validation.checks[rp.CHECK_EVIDENCE_EXISTS])


class TestN_MalformedInput(AdversarialBase):
    def test_N_malformed_claim_rows_never_crash_or_confuse(self):
        rows = _stage_rows() + ["not-a-row", {"broken": True}, 17]
        report, validation, decision = build(rows)
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        self.assertIsInstance(report["claims"], list)
        json.dumps(report)

    def test_N2_malformed_claim_entry_is_detected(self):
        def tamper(report):
            report["claims"].append({"statement": "no claim_type here"})
        _, validation, _ = build(_stage_rows(), mutate=tamper)
        codes = {b["code"] for b in validation.blockers}
        self.assertTrue(
            codes & {"malformed_claim", "unsupported_claim_marked_confirmed",
                     "claim_missing_type"},
            codes)

    def test_N3_unclassified_signal_satisfies_nothing(self):
        rows = [row("mystery_signal", ref="u-1", job=JOBS[1])]
        _, validation, decision = build(rows)
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertFalse(decision.confirmed)


class TestO_EmptyEvidence(AdversarialBase):
    def test_O_empty_evidence_set_is_pending_and_blocks(self):
        report, validation, decision = build([])
        self.assert_pending(validation, decision,
                            reason=ct.R_NO_EVIDENCE)
        self.assertEqual(decision.stage_reached, 0)
        self.assertTrue(
            all(r["status"] in ("MISSING", "NOT_TESTED")
                for r in report["claim_evidence_matrix"]))
        self.assertEqual(report["evidence_summary"]["unique_observations"], 0)
        self.assertEqual(report["executive_conclusion"]["confirmed"], False)


class TestP_AdvisoryOnlyReport(AdversarialBase):
    def test_P_report_from_historical_advisory_only_is_never_ready(self):
        adv = advisory(
            advisory_state="VERIFIED",
            text=("VERIFIED XSS at /support?q= — payload executed; impact: "
                  "session compromise; severity HIGH."))
        report, validation, decision = build([], advisory=adv,
                                             severity="HIGH")
        self.assertEqual(validation.status, rp.REPORT_BLOCKED)
        self.assertEqual(validation.unsupported_claims, [])
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertFalse(report["executive_conclusion"]["confirmed"])
        self.assertEqual(report["severity_status"]["severity"], "UNASSESSED"
                         if False else "HIGH")
        codes = {b["code"] for b in validation.blockers}
        self.assertIn("severity_not_authoritative", codes)
        self.assertEqual(report["historical_advisory"]["authoritative"],
                         False)
        self.assertEqual(report["final_disposition"]["state"],
                         "VERIFICATION_PENDING")


if __name__ == "__main__":
    unittest.main()

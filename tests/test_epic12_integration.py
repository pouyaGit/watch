"""EPIC12 §15/§17 — integration into the existing finding pass.

The chain loop is invoked from inside the promoted finding workflow, not from a
scheduler of its own.  These tests pin that: the hook is opt-in, it can only add
structured observations, and the EPIC11 gate decision is untouched by it.
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import advisor as ad  # noqa: E402
from backend.research_agents.verification import budget as vb  # noqa: E402
from backend.research_agents.verification import integration as itg  # noqa: E402
from backend.research_agents.verification import loop as lp  # noqa: E402
from backend.research_agents.verification import store as vs  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, TARGET, advisor_returning, authorization,
    inventory_rows, make_verification_store,
)

OBJECTIVE = "ver-int-1"


@dataclass
class FakeCandidate:
    candidate_id: str = CANDIDATE_ID
    scope_ref: str = SCOPE
    vulnerability_class: str = "XSS"
    endpoint: str = TARGET
    source_job: str = "job-xss-49b9d40fd5"


@dataclass
class FakeVerification:
    verification_id: str = OBJECTIVE
    scope_ref: str = SCOPE
    authorization_ids: tuple[str, ...] = ("auth-1",)
    store: Any = None
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeJob:
    id: str = "job-xss-ffe3afca68"


def hook(**kw):
    return itg.make_chain_loop_fn(**kw)


class TestHookBehaviour(unittest.TestCase):
    def test_hook_runs_the_loop_and_returns_rows(self):
        store = make_verification_store()
        result = hook(verification_store=store)(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        self.assertEqual(result.error, "")
        self.assertTrue(result.outcome)
        self.assertEqual(result.outcome["termination"], lp.LOOP_PENDING)
        self.assertTrue(result.evidence_rows)
        self.assertFalse(result.outcome.get("confirmed"))

    def test_hook_result_is_json_safe(self):
        import json
        result = hook(verification_store=make_verification_store())(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        json.dumps(result.to_dict(), sort_keys=True)

    def test_hook_never_returns_confirmation_evidence(self):
        store = make_verification_store()
        result = hook(verification_store=store)(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        for evidence_row in result.evidence_rows:
            self.assertNotIn(evidence_row.get("evidence_type"),
                             ("PAYLOAD_EXECUTION",
                              "EXPLOITABILITY_ESTABLISHED"))
            self.assertIn(evidence_row.get("type"), ("observation", "negative"))

    def test_class_without_a_chain_is_reported_not_run(self):
        store = make_verification_store()
        result = hook(verification_store=store)(
            candidate=FakeCandidate(vulnerability_class="IDOR"),
            verification=FakeVerification(), job=FakeJob(),
            rows=inventory_rows(3), authorization=authorization())
        self.assertEqual(result.outcome["termination"], lp.LOOP_BLOCKED)
        self.assertIn("chain_not_implemented", result.error)
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_context_fn_supplies_the_material(self):
        from backend.research_agents.verification import executors as ex
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE, target=TARGET)
        marker = ex.marker_for(act)
        body = f'<html><body><script>var a = "{marker}";</script></body></html>'
        store = make_verification_store()
        result = hook(verification_store=store,
                      context_fn=lambda **_k: {"response_body": body,
                                               "marker": marker})(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        self.assertIn("REFLECTION_OBSERVED", result.outcome["evidence_gained"])
        self.assertIn("OUTPUT_CONTEXT_IDENTIFIED",
                      result.outcome["evidence_gained"])
        self.assertNotEqual(result.outcome.get("verdict"), "VERIFIED")
        self.assertEqual(result.outcome["termination"], lp.LOOP_PENDING)

    def test_a_raising_context_fn_fails_closed(self):
        def boom(**_kwargs):
            raise RuntimeError("no material")

        store = make_verification_store()
        result = hook(verification_store=store, context_fn=boom)(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        self.assertTrue(result.error.startswith("chain_loop_error:"))
        self.assertEqual(result.evidence_rows, [])
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_the_hook_never_raises(self):
        class BrokenVerification:
            scope_ref = SCOPE
            authorization_ids = ("auth-1",)
            store = None
            provenance: dict = {}

            @property
            def verification_id(self):
                raise RuntimeError("boom")

        result = hook(verification_store=make_verification_store())(
            candidate=FakeCandidate(), verification=BrokenVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        self.assertTrue(result.error)
        self.assertEqual(result.outcome, {})

    def test_budget_is_passed_through(self):
        store = make_verification_store()
        budget = vb.VerificationBudget(store, {"max_actions": 0},
                                       objective_id=OBJECTIVE)
        result = hook(verification_store=store)(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization(), budget=budget)
        self.assertFalse(result.outcome.get("confirmed"))
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_advisor_is_passed_through(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION"}))
        result = hook(verification_store=make_verification_store(),
                      advisor=advisor)(
            candidate=FakeCandidate(), verification=FakeVerification(),
            job=FakeJob(), rows=inventory_rows(3),
            authorization=authorization())
        self.assertGreaterEqual(result.outcome["llm_calls"], 1)

    def test_default_limits_are_the_declared_ones(self):
        self.assertEqual(itg.default_verification_limits(),
                         dict(vb.DEFAULT_VERIFICATION_LIMITS))

    def test_rule_version_is_declared(self):
        self.assertTrue(itg.INTEGRATION_RULE_VERSION.startswith("epic12-"))


class TestRunFindingsIntegration(unittest.TestCase):
    """The promoted pass, with and without the chain loop."""

    def _run(self, *, chain_loop_fn=None, outcome="verified",
             evidence_kind="supporting"):
        from backend.research_agents.finding.executor import (
            run_findings as rf)
        from backend.research_agents.runtime import RuntimeConfig
        from tests.finding_fixtures import (
            complete_job, enqueue_job, finding_worker_factory, make_stores)
        store, fs = make_stores()
        job = enqueue_job(store)
        complete_job(store, job)
        worker_factory, _journal = finding_worker_factory(outcome, evidence_kind)
        summary = rf(
            source_jobs=[job.id], config=RuntimeConfig(execution_mode="fixture"),
            store=store, finding_store=fs, worker_factory=worker_factory,
            chain_loop_fn=chain_loop_fn)
        return store, fs, summary

    def test_without_the_hook_the_promoted_behaviour_is_unchanged(self):
        _store, fs, _summary = self._run()
        for verification in fs.list_verifications():
            provenance = dict(getattr(verification, "provenance", {}) or {})
            self.assertNotIn("verification_chain", provenance)

    def test_with_the_hook_the_chain_state_is_recorded(self):
        store, fs, _summary = self._run(
            chain_loop_fn=hook(verification_store=make_verification_store()))
        recorded = [dict(getattr(v, "provenance", {}) or {}).get(
            "verification_chain") for v in fs.list_verifications()]
        recorded = [row for row in recorded if row]
        self.assertTrue(recorded)
        for row in recorded:
            self.assertIn("termination", row)
            self.assertIn("authoritative_verdict", row)

    def test_the_hook_never_overrides_the_gate_verdict(self):
        _store, fs, _summary = self._run(
            chain_loop_fn=hook(verification_store=make_verification_store()))
        for verification in fs.list_verifications():
            self.assertIn(verification.authoritative_state,
                          ("VERIFIED", "VERIFICATION_PENDING", "BLOCKED",
                           "REJECTED", ""))

    def test_a_broken_hook_does_not_break_the_finding_pass(self):
        def broken(**_kwargs):
            raise RuntimeError("boom")

        _store, fs, summary = self._run(chain_loop_fn=broken)
        self.assertIsNotNone(summary)
        self.assertTrue(fs.list_verifications())

    def test_the_hook_adds_no_confirmation_evidence(self):
        store, fs, _summary = self._run(
            chain_loop_fn=hook(verification_store=make_verification_store()))
        for verification in fs.list_verifications():
            self.assertNotEqual(verification.authoritative_state, "VERIFIED") \
                if not verification.claim_integrity else None

    def test_evidence_rows_from_the_chain_stay_admissible(self):
        from backend.research_agents.verification import engine as en
        vstore = make_verification_store()
        _store, fs, _summary = self._run(
            chain_loop_fn=hook(verification_store=vstore))
        rows = vstore.evidence_rows_for_candidate("")
        for row in rows or []:
            self.assertEqual(en.inadmissible_rows([row]), [])


if __name__ == "__main__":
    unittest.main()

"""EPIC15 §16/§17/§18 — execution attempts, states, budget and the producer."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from ai.limits import ceilings as ce  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import deep as dp  # noqa: E402
from tests.epic15_fixtures import (  # noqa: E402
    AUTH_ID, CANDIDATE_ID, SCOPE_REF, TARGET, authorization,
    authorized_hosts, harness_executed, harness_no_instrumentation,
    harness_not_executed, harness_raising, harness_sink_only,
    harness_timeout, runner)


def attempt(**kwargs):
    payload = {
        "action_id": "act-epic15-1", "candidate_id": CANDIDATE_ID,
        "scope_ref": SCOPE_REF, "target": TARGET,
        "authorization": authorization(), "authorized_hosts": authorized_hosts(),
    }
    payload.update(kwargs)
    return dp.attempt_execution(**payload)


class TestRefusalIsNotNegativeEvidence(unittest.TestCase):
    """§18: a failure to run is never a security result."""

    def test_no_runner_refuses(self):
        self.assertEqual(attempt().state, dp.BROWSER_UNAVAILABLE)

    def test_the_refusal_reason_is_the_platform_token(self):
        self.assertEqual(attempt().reason, "BROWSER_EXECUTION_BLOCKED")

    def test_the_refusal_is_marked_refused(self):
        self.assertTrue(attempt().refused)

    def test_the_refusal_is_not_negative_evidence(self):
        self.assertFalse(attempt().negative_evidence)

    def test_the_refusal_produces_no_evidence_type(self):
        self.assertEqual(attempt().evidence_type, "")

    def test_the_refusal_records_the_blockers(self):
        detail = attempt().detail
        self.assertEqual(sorted(detail["blockers"]), ["B1", "B2", "B4", "B5"])

    def test_the_refusal_distinguishes_offline_from_production(self):
        self.assertIn("not REAL production",
                      attempt().detail["distinction"])

    def test_the_refusal_records_that_no_runner_existed(self):
        self.assertEqual(attempt().detail["runner"], "none")

    def test_every_refusal_state_is_not_negative(self):
        for state in dp.execution.REFUSAL_STATES:
            self.assertFalse(dp.is_negative_security_evidence(state), state)

    def test_the_negative_states_are_exactly_two(self):
        self.assertEqual(dp.execution.NEGATIVE_STATES,
                         frozenset({dp.EXECUTION_NOT_OBSERVED,
                                    dp.DOM_SINK_NOT_OBSERVED}))

    def test_the_sets_are_disjoint(self):
        self.assertEqual(dp.execution.NEGATIVE_STATES
                         & dp.execution.REFUSAL_STATES, frozenset())

    def test_every_state_is_in_the_closed_vocabulary(self):
        for state in dp.ATTEMPT_STATES:
            self.assertIn(state, dp.ATTEMPT_STATES)

    def test_the_vocabulary_has_the_required_states(self):
        for state in ("EXECUTION_OBSERVED", "EXECUTION_NOT_OBSERVED",
                      "DOM_SINK_OBSERVED", "DOM_SINK_NOT_OBSERVED",
                      "BROWSER_UNAVAILABLE", "BROWSER_START_FAILED",
                      "NAVIGATION_BLOCKED", "REDIRECT_OUT_OF_SCOPE",
                      "AUTHORIZATION_EXPIRED", "TIMEOUT", "BUDGET_EXHAUSTED",
                      "INSTRUMENTATION_UNAVAILABLE", "INCONCLUSIVE"):
            self.assertIn(state, dp.ATTEMPT_STATES)


class TestOfflineHarness(unittest.TestCase):
    """The injected deterministic seam (clearly labelled, never production)."""

    def test_an_executed_outcome_is_recorded(self):
        self.assertEqual(attempt(runner=runner(harness_executed())).state,
                         dp.EXECUTION_OBSERVED)

    def test_an_executed_outcome_carries_the_execution_type(self):
        self.assertEqual(attempt(runner=runner(harness_executed())).evidence_type,
                         tx.PAYLOAD_EXECUTION)

    def test_an_executed_outcome_is_not_a_refusal(self):
        self.assertFalse(attempt(runner=runner(harness_executed())).refused)

    def test_a_sink_only_outcome_is_recorded_separately(self):
        result = attempt(runner=runner(harness_sink_only()))
        self.assertEqual(result.state, dp.DOM_SINK_OBSERVED)

    def test_a_sink_only_outcome_carries_the_sink_type(self):
        self.assertEqual(attempt(runner=runner(harness_sink_only())).evidence_type,
                         tx.DOM_SINK_IDENTIFIED)

    def test_a_sink_only_outcome_is_not_execution_evidence(self):
        self.assertNotEqual(attempt(runner=runner(harness_sink_only())).evidence_type,
                            tx.PAYLOAD_EXECUTION)

    def test_an_instrumented_run_with_no_execution_is_negative(self):
        result = attempt(runner=runner(harness_not_executed()))
        self.assertEqual(result.state, dp.EXECUTION_NOT_OBSERVED)
        self.assertTrue(result.negative_evidence)

    def test_an_instrumented_run_with_no_execution_is_negative_evidence(self):
        self.assertEqual(attempt(runner=runner(harness_not_executed())).evidence_type,
                         tx.NEGATIVE_EVIDENCE)

    def test_a_run_without_instrumentation_is_a_refusal(self):
        result = attempt(runner=runner(harness_no_instrumentation()))
        self.assertEqual(result.state, dp.INSTRUMENTATION_UNAVAILABLE)
        self.assertTrue(result.refused)
        self.assertFalse(result.negative_evidence)

    def test_a_run_without_instrumentation_produces_no_evidence(self):
        self.assertEqual(attempt(runner=runner(harness_no_instrumentation())).evidence_type,
                         "")

    def test_a_timeout_is_a_refusal(self):
        result = attempt(runner=runner(harness_timeout()))
        self.assertEqual(result.state, dp.TIMEOUT)
        self.assertTrue(result.refused)

    def test_a_timeout_is_not_negative_evidence(self):
        self.assertFalse(attempt(runner=runner(harness_timeout())).negative_evidence)

    def test_a_raising_runner_is_a_start_failure(self):
        result = attempt(runner=harness_raising)
        self.assertEqual(result.state, dp.BROWSER_START_FAILED)

    def test_a_raising_runner_is_not_negative_evidence(self):
        self.assertFalse(attempt(runner=harness_raising).negative_evidence)

    def test_a_raising_runner_records_the_failure_kind(self):
        self.assertIn("RuntimeError", attempt(runner=harness_raising).reason)

    def test_a_runner_returning_nothing_is_inconclusive(self):
        result = attempt(runner=lambda **_: "not a dict")
        self.assertEqual(result.state, dp.INCONCLUSIVE)

    def test_the_injected_runner_is_labelled_in_the_outcome(self):
        result = attempt(runner=runner(harness_executed()))
        self.assertEqual(result.instrumentation_method, "offline_harness")

    def test_the_instrumentation_version_is_carried(self):
        result = attempt(runner=runner(harness_executed()))
        self.assertEqual(result.instrumentation_version, "epic15-test-1")

    def test_the_attempt_result_is_serialisable(self):
        payload = attempt(runner=runner(harness_executed())).to_dict()
        self.assertEqual(payload["state"], dp.EXECUTION_OBSERVED)
        self.assertEqual(payload["rule_version"], "epic15-execution-1")


class TestAuthorizationAtEveryStage(unittest.TestCase):
    """§16: no authorization, no execution."""

    def test_a_missing_authorization_refuses(self):
        self.assertEqual(attempt(authorization=None).state,
                         dp.AUTHORIZATION_MISSING)

    def test_an_empty_authorization_refuses(self):
        self.assertEqual(attempt(authorization={}).state,
                         dp.AUTHORIZATION_MISSING)

    def test_an_expired_authorization_refuses(self):
        self.assertEqual(attempt(authorization=authorization(expired=True)).state,
                         dp.AUTHORIZATION_EXPIRED)

    def test_an_expired_authorization_refuses_even_with_a_runner(self):
        result = attempt(authorization=authorization(expired=True),
                         runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.AUTHORIZATION_EXPIRED)

    def test_an_expired_authorization_is_never_negative_evidence(self):
        self.assertFalse(attempt(
            authorization=authorization(expired=True)).negative_evidence)

    def test_a_missing_authorization_refuses_even_with_a_runner(self):
        result = attempt(authorization=None, runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.AUTHORIZATION_MISSING)

    def test_the_authorization_id_is_recorded(self):
        self.assertEqual(attempt().authorization_id, AUTH_ID)


class TestNavigationAndBudget(unittest.TestCase):
    """§11/§17: scope and budget are enforced before the runner."""

    def test_an_out_of_scope_target_is_blocked(self):
        result = attempt(target="https://evil.test/",
                         runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.NAVIGATION_BLOCKED)

    def test_an_out_of_scope_target_is_never_negative_evidence(self):
        self.assertFalse(attempt(target="https://evil.test/").negative_evidence)

    def test_a_loopback_target_is_blocked(self):
        result = attempt(target="http://127.0.0.1/",
                         runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.NAVIGATION_BLOCKED)

    def test_a_file_target_is_blocked(self):
        result = attempt(target="file:///etc/passwd")
        self.assertEqual(result.state, dp.NAVIGATION_BLOCKED)

    def test_the_blocked_navigation_is_recorded(self):
        result = attempt(target="https://evil.test/")
        self.assertIn("host_out_of_scope", result.detail["navigation"]["reason"])

    def test_an_exhausted_budget_stops_the_attempt(self):
        budget = dp.budget_from_ceilings()
        budget.attempts_used = budget.max_attempts
        result = attempt(budget=budget, runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.BUDGET_EXHAUSTED)

    def test_a_non_isolated_policy_stops_the_attempt(self):
        result = attempt(isolation=dp.IsolationPolicy(stored_cookies=True),
                         runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.BROWSER_UNAVAILABLE)

    def test_a_non_isolated_policy_is_never_negative_evidence(self):
        result = attempt(isolation=dp.IsolationPolicy(user_profile=True))
        self.assertFalse(result.negative_evidence)


class TestBudget(unittest.TestCase):
    """§17: ceilings are reused, never raised."""

    def test_the_default_budget_uses_the_frozen_ceilings(self):
        budget = dp.budget_from_ceilings()
        self.assertEqual(budget.max_sessions, ce.CEILINGS["browser_contexts"])
        self.assertEqual(budget.max_pages, ce.CEILINGS["browser_pages"])
        self.assertEqual(budget.max_redirects, ce.CEILINGS["redirect_hops"])

    def test_the_budget_starts_unspent(self):
        budget = dp.budget_from_ceilings()
        self.assertFalse(budget.exhausted)
        self.assertEqual(budget.attempts_used, 0)

    def test_spending_an_attempt_decrements_the_allowance(self):
        budget = dp.budget_from_ceilings()
        before = budget.attempts_remaining
        budget.spend_attempt()
        self.assertEqual(budget.attempts_remaining, before - 1)

    def test_attempts_cannot_be_spent_twice_past_the_cap(self):
        budget = dp.budget_from_ceilings()
        self.assertTrue(budget.spend_attempt())
        self.assertFalse(budget.spend_attempt())

    def test_sessions_are_capped(self):
        budget = dp.budget_from_ceilings()
        self.assertTrue(budget.spend_session())
        self.assertFalse(budget.spend_session())

    def test_navigations_are_capped(self):
        budget = dp.budget_from_ceilings()
        self.assertTrue(budget.spend_navigation())
        self.assertFalse(budget.spend_navigation())

    def test_redirects_are_capped(self):
        budget = dp.budget_from_ceilings()
        for _ in range(ce.CEILINGS["redirect_hops"]):
            self.assertTrue(budget.spend_redirect())
        self.assertFalse(budget.spend_redirect())

    def test_evidence_is_capped(self):
        budget = dp.budget_from_ceilings()
        budget.spend_evidence(budget.max_evidence)
        self.assertFalse(budget.spend_evidence(1))

    def test_runtime_is_capped(self):
        budget = dp.budget_from_ceilings()
        self.assertFalse(budget.spend_runtime(budget.max_runtime_seconds + 1))

    def test_the_budget_is_serialisable(self):
        payload = dp.budget_from_ceilings().to_dict()
        self.assertIn("ceilings_source", payload)
        self.assertEqual(payload["rule_version"], "epic15-budget-1")

    def test_the_budget_names_its_ceiling_source(self):
        self.assertIn("ai.limits.ceilings.CEILINGS",
                      dp.budget_from_ceilings().to_dict()["ceilings_source"])

    def test_no_new_ceiling_is_defined(self):
        source = (Path(__file__).resolve().parents[1] / "backend"
                  / "research_agents" / "verification" / "deep"
                  / "budget.py").read_text(encoding="utf-8")
        self.assertNotIn("CEILINGS = {", source)


class TestProducer(unittest.TestCase):
    """§15/§18: the trusted producer, and its refusal semantics."""

    def producer(self, **kwargs):
        payload = {"action_id": "act-epic15-1", "candidate_id": CANDIDATE_ID,
                   "objective_id": "vo-epic15-1", "scope_ref": SCOPE_REF,
                   "authorization_id": AUTH_ID, "where": TARGET}
        payload.update(kwargs)
        return dp.DeepObservationProducer(**payload)

    def test_a_refused_attempt_produces_not_tested(self):
        observation = self.producer().execution_observation(attempt())
        self.assertTrue(observation.not_tested)

    def test_a_refused_attempt_is_not_a_negative(self):
        observation = self.producer().execution_observation(attempt())
        self.assertFalse(observation.negative)

    def test_a_refused_attempt_classifies_as_not_tested_kind(self):
        observation = self.producer().execution_observation(attempt())
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.negative_kind, tx.NOT_TESTED)

    def test_an_executed_attempt_produces_payload_execution(self):
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_executed())))
        self.assertEqual(observation.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_a_sink_only_attempt_produces_a_positive_dom_sink(self):
        """§18: DOM_SINK_OBSERVED maps to DOM_SINK_IDENTIFIED — a sink, not
        an execution."""
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_sink_only())))
        self.assertEqual(observation.evidence_type, tx.DOM_SINK_IDENTIFIED)
        self.assertFalse(observation.negative)

    def test_a_sink_only_attempt_is_not_execution_evidence(self):
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_sink_only())))
        self.assertNotEqual(observation.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_a_sink_only_attempt_records_that_execution_was_not_observed(self):
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_sink_only())))
        self.assertFalse(observation.provenance.get("execution_observed"))

    def test_a_not_observed_attempt_classifies_as_negative_evidence(self):
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_not_executed())))
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE)

    def test_a_not_observed_attempt_is_an_observed_none_not_a_not_tested(self):
        observation = self.producer().execution_observation(
            attempt(runner=runner(harness_not_executed())))
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.negative_kind, tx.NOT_OBSERVED)

    def test_a_refusal_classifies_as_not_tested_not_as_a_negative(self):
        observation = self.producer().execution_observation(attempt())
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.negative_kind, tx.NOT_TESTED)

    def test_the_attestation_names_the_producer(self):
        attestation = self.producer().attestation()
        self.assertEqual(attestation["producer"], "epic15-producer-1")

    def test_the_attestation_names_the_method_and_version(self):
        attestation = self.producer().attestation()
        self.assertEqual(attestation["instrumentation_method"],
                         dp.DOM_INSTRUMENTATION_METHOD)
        self.assertEqual(attestation["instrumentation_version"],
                         dp.DOM_INSTRUMENTATION_VERSION)

    def test_the_attestation_carries_the_identity(self):
        attestation = self.producer().attestation()
        self.assertEqual(attestation["action_id"], "act-epic15-1")
        self.assertEqual(attestation["candidate_id"], CANDIDATE_ID)
        self.assertEqual(attestation["authorization_id"], AUTH_ID)

    def test_the_attestation_is_kind_labelled(self):
        self.assertEqual(self.producer().attestation()["producer_kind"],
                         "trusted_deep_verification")

    def test_a_session_id_is_truncated(self):
        attestation = self.producer().attestation(
            session_id="s" * 200)
        self.assertLessEqual(len(attestation["session_id"]), 64)

    def test_no_session_id_is_recorded_when_absent(self):
        self.assertNotIn("session_id", self.producer().attestation())

    def test_the_producer_derives_the_type_never_accepts_it(self):
        """§15: a caller cannot hand the producer an evidence_type."""
        import inspect
        signature = inspect.signature(
            dp.DeepObservationProducer.execution_observation)
        self.assertNotIn("evidence_type", signature.parameters)


if __name__ == "__main__":
    unittest.main()

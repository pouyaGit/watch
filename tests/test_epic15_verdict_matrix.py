"""EPIC15 §9/§15/§19/§21/§22/§24/§27 — verdict matrix, attacks, regression.

The authoritative verdict is never produced by this package: every row
built here goes through EPIC11's claim evaluation and Evidence Gate, and
the assertions are made on *that* result.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import deep as dp  # noqa: E402
from tests import epic14_fixtures as e14  # noqa: E402
from tests.epic15_fixtures import (  # noqa: E402
    CANDIDATE_ID, MARKER, PARAMETER, SCOPE_REF, TARGET, authorization,
    authorized_hosts, document_lineage, document_reflection_only,
    document_script_text_only, forged_execution_row, forged_sink_stamp_row,
    harness_executed, harness_no_instrumentation, harness_not_executed,
    harness_raising, harness_sink_only, harness_timeout,
    html_script_text_evidence, llm_execution_claim, runner,
    screenshot_evidence)

import ast  # noqa: E402


def _imported_names(path) -> list:
    """Every module name this file actually imports (not docstring prose)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    return names


ACTION_ID = "act-epic15-matrix-1"
OBJECTIVE_ID = "vo-epic15-matrix-1"


def evaluate(rows, *, auth=True):
    return cl.evaluate_rows("XSS", rows,
                            authorization=e14.authorization() if auth else None)


def decision(rows, *, auth=True):
    return ig.decide(evaluate(rows, auth=auth))


def deep(*, document=None, runner_=None, auth=True, target=TARGET,
         parameter=PARAMETER, marker=MARKER):
    return dp.deep_verify(
        candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF, target=target,
        parameter=parameter, marker=marker, document=document,
        authorization=authorization() if auth else None,
        authorized_hosts=authorized_hosts(), runner=runner_,
        action_id=ACTION_ID, objective_id=OBJECTIVE_ID)


def deep_rows(**kwargs):
    return list(deep(**kwargs).observations)


class TestXssVerdictMatrix(unittest.TestCase):
    """§19: the matrix, decided by the existing contract and gate."""

    def test_a_parameter_inventory_alone_is_pending(self):
        state = decision(e14.inventory())
        self.assertNotEqual(state.authoritative_state, ig.VERIFIED)
        self.assertNotEqual(state.authoritative_state, ig.VERIFIED)

    def test_a_parameter_inventory_alone_never_confirms(self):
        self.assertFalse(decision(e14.inventory()).claim_integrity.get(
            "supported", False))

    def test_a_parameter_inventory_alone_has_no_confirmation_evidence(self):
        state = decision(e14.inventory())
        self.assertEqual(state.confirmation_evidence_ids, [])

    def test_b_reflection_added_is_still_pending(self):
        rows = e14.inventory() + [e14.legit_reflection()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_b_reflection_added_never_confirms(self):
        rows = e14.inventory() + [e14.legit_reflection()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_c_context_added_is_still_pending(self):
        rows = e14.inventory() + [e14.legit_reflection(), e14.legit_context()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_c_context_added_advances_the_stage(self):
        rows = e14.inventory() + [e14.legit_reflection(), e14.legit_context()]
        self.assertGreater(decision(rows).stage_reached, 1)

    def test_d_a_dom_sink_observation_alone_is_pending(self):
        state = decision(deep_rows(document=document_lineage()))
        self.assertNotEqual(state.authoritative_state, ig.VERIFIED)
        self.assertNotEqual(state.authoritative_state, ig.VERIFIED)

    def test_d_a_dom_sink_observation_alone_never_confirms(self):
        result = deep(document=document_lineage())
        self.assertIn(tx.DOM_SINK_IDENTIFIED, result.evidence_types)
        self.assertFalse(result.produces_confirmation_evidence)

    def test_d_the_dom_sink_observation_is_not_confirmation_evidence(self):
        state = decision(list(deep(document=document_lineage()).observations))
        self.assertEqual(state.confirmation_evidence_ids, [])

    def test_e_execution_without_exploitability_follows_the_existing_contract(self):
        """§19E: the existing XSS contract decides eligibility.

        ``PAYLOAD_EXECUTION`` is one of the contract's two confirmation
        types, so with the required stages present it is eligible — and
        nothing here invents impact to make it more than that.
        """
        rows = e14.inventory() + [e14.legit_reflection(), e14.legit_context(),
                                  e14.legit_execution()]
        state = decision(rows)
        self.assertEqual(state.authoritative_state, ig.VERIFIED)

    def test_e_no_impact_is_invented_by_this_layer(self):
        result = deep(runner_=runner(harness_executed()))
        self.assertIn(tx.PAYLOAD_EXECUTION, result.evidence_types)
        self.assertNotIn(tx.EXPLOITABILITY_ESTABLISHED, result.evidence_types)
        self.assertFalse(result.exploitability["established"])

    def test_e_execution_without_exploitability_does_not_invent_impact(self):
        rows = e14.inventory() + [e14.legit_reflection(), e14.legit_context(),
                                  e14.legit_execution()]
        self.assertNotIn(tx.EXPLOITABILITY_ESTABLISHED,
                         decision(rows).claim_integrity.get(
                             "supported_types", []))

    def test_f_the_full_chain_is_eligible_for_verified(self):
        state = decision(e14.legit_chain())
        self.assertEqual(state.authoritative_state, ig.VERIFIED)

    def test_f_the_full_chain_reaches_the_gate(self):
        self.assertEqual(decision(e14.legit_chain()).authoritative_state,
                         ig.VERIFIED)

    def test_g_a_browser_failure_is_blocked_not_negative(self):
        result = deep(runner_=runner(harness_timeout()))
        self.assertEqual(result.attempt["state"], dp.TIMEOUT)
        self.assertFalse(result.attempt["negative_evidence"])

    def test_g_a_browser_failure_produces_no_confirmation_evidence(self):
        result = deep(runner_=runner(harness_timeout()))
        self.assertFalse(result.produces_confirmation_evidence)

    def test_g_a_browser_failure_is_inconclusive_or_blocked(self):
        self.assertIn(deep(runner_=runner(harness_timeout())).state,
                      (dp.DEEP_BLOCKED, dp.DEEP_INCONCLUSIVE,
                       dp.DEEP_NOT_TESTED))

    def test_h_a_missing_authorization_is_blocked(self):
        self.assertEqual(deep(auth=False).state, dp.DEEP_BLOCKED)

    def test_h_a_missing_authorization_produces_no_evidence(self):
        self.assertEqual(deep(auth=False).evidence_types, ())

    def test_h_a_missing_authorization_reaches_the_gate_as_pending(self):
        rows = list(deep(auth=False).observations) + e14.inventory()
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_no_matrix_row_confirms_without_deep_evidence(self):
        for rows in (e14.inventory(),
                     e14.inventory() + [e14.legit_reflection()],
                     e14.inventory() + [e14.legit_reflection(),
                                        e14.legit_context()]):
            self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)


class TestExploitabilitySeparation(unittest.TestCase):
    """§9: execution is not exploitability."""

    def assessment(self, **kwargs):
        payload = {"execution_observed": True, "controlled_input": True,
                   "sink": "innerHTML", "impact_established": False}
        payload.update(kwargs)
        return dp.assess_exploitability(**payload)

    def test_execution_without_impact_is_not_established(self):
        self.assertFalse(self.assessment().established)

    def test_execution_without_impact_names_the_missing_condition(self):
        self.assertIn("impact", self.assessment().reason)

    def test_execution_with_impact_is_established(self):
        self.assertTrue(self.assessment(impact_established=True).established)

    def test_no_execution_is_not_established(self):
        self.assertFalse(self.assessment(execution_observed=False,
                                         impact_established=True).established)

    def test_no_execution_names_the_missing_condition(self):
        self.assertEqual(self.assessment(execution_observed=False).reason,
                         "execution_not_observed")

    def test_no_controlled_input_is_not_established(self):
        self.assertFalse(self.assessment(controlled_input=False,
                                         impact_established=True).established)

    def test_a_non_security_relevant_sink_is_not_established(self):
        self.assertFalse(self.assessment(sink="console.log",
                                         impact_established=True).established)

    def test_a_non_security_relevant_sink_is_named(self):
        self.assertIn("security_relevant",
                      self.assessment(sink="console.log",
                                      impact_established=True).reason)

    def test_the_assessment_is_serialisable(self):
        payload = self.assessment().to_dict()
        self.assertIn("established", payload)
        self.assertEqual(payload["rule_version"], "epic15-exploitability-1")

    def test_the_assessment_lists_what_is_missing(self):
        self.assertIn("IMPACT_ESTABLISHED", self.assessment().missing)

    def test_the_service_never_claims_exploitability_from_execution(self):
        result = deep(document=document_lineage(),
                      runner_=runner(harness_executed()))
        self.assertEqual(result.exploitability["established"], False)

    def test_a_real_execution_does_not_produce_exploitability_evidence(self):
        result = deep(runner_=runner(harness_executed()))
        self.assertIn(tx.PAYLOAD_EXECUTION, result.evidence_types)
        self.assertNotIn(tx.EXPLOITABILITY_ESTABLISHED, result.evidence_types)


class TestAdversarialSurface(unittest.TestCase):
    """§24: the twenty required attacks."""

    def test_1_reflection_only_never_confirms(self):
        rows = e14.inventory() + [e14.legit_reflection()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_2_a_fake_dom_sink_row_is_rejected(self):
        item = tx.classify_row(forged_sink_stamp_row())
        self.assertNotEqual(item.evidence_type, tx.DOM_SINK_IDENTIFIED)
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_2b_a_fake_dom_sink_row_records_a_mismatch(self):
        item = tx.classify_row(forged_sink_stamp_row())
        self.assertTrue(item.mismatch_reason)

    def test_2c_a_fake_dom_sink_row_does_not_advance_a_chain(self):
        rows = e14.inventory() + [forged_sink_stamp_row()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_3_a_fake_execution_row_cannot_confirm_alone(self):
        rows = e14.inventory() + [forged_execution_row()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_3b_a_fake_execution_row_is_not_produced_by_the_deep_layer(self):
        result = deep(document=document_lineage())
        self.assertNotIn(tx.PAYLOAD_EXECUTION, result.evidence_types)

    def test_4_an_llm_execution_claim_is_ignored(self):
        rows = e14.inventory() + [llm_execution_claim()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_4b_an_llm_claim_is_not_confirmation_evidence(self):
        state = decision(e14.inventory() + [llm_execution_claim()])
        self.assertEqual(state.confirmation_evidence_ids, [])

    def test_5_a_screenshot_is_not_execution_evidence(self):
        item = tx.classify_row(screenshot_evidence())
        self.assertNotEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_5b_a_screenshot_cannot_confirm(self):
        rows = e14.inventory() + [screenshot_evidence()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)

    def test_6_html_script_text_is_not_execution_evidence(self):
        item = tx.classify_row(html_script_text_evidence())
        self.assertNotEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_6b_a_document_of_script_text_is_not_a_dom_sink(self):
        trace = dp.trace_dom_flow(document_script_text_only(),
                                  parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_6c_a_reflected_marker_is_not_a_dom_sink(self):
        trace = dp.trace_dom_flow(document_reflection_only(),
                                  parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_7_a_blocked_navigation_is_not_negative_evidence(self):
        result = deep(target="https://evil.test/",
                      runner_=runner(harness_executed()))
        self.assertEqual(result.attempt["state"], dp.NAVIGATION_BLOCKED)
        self.assertFalse(result.attempt["negative_evidence"])

    def test_8_a_redirect_to_localhost_is_blocked(self):
        decision_ = dp.check_redirect("https://www.dell.com/a",
                                      "http://localhost/",
                                      authorized_hosts=authorized_hosts())
        self.assertEqual(decision_.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_9_a_redirect_to_a_private_address_is_blocked(self):
        decision_ = dp.check_redirect("https://www.dell.com/a",
                                      "http://192.168.1.1/",
                                      authorized_hosts=authorized_hosts())
        self.assertEqual(decision_.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_10_a_redirect_to_metadata_is_blocked(self):
        decision_ = dp.check_redirect("https://www.dell.com/a",
                                      "http://169.254.169.254/",
                                      authorized_hosts=authorized_hosts())
        self.assertEqual(decision_.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_11_file_navigation_is_blocked(self):
        self.assertEqual(dp.check_navigation("file:///etc/passwd").decision,
                         "SCHEME_BLOCKED")

    def test_11b_a_file_target_never_runs_the_harness(self):
        called = []

        def spy(**kwargs):
            called.append(kwargs)
            return harness_executed()

        result = deep(target="file:///etc/passwd", runner_=spy)
        self.assertEqual(result.attempt["state"], dp.NAVIGATION_BLOCKED)
        self.assertEqual(called, [])

    def test_12_a_cookie_leak_attempt_is_blocked(self):
        self.assertEqual(
            dp.check_request_headers({"Cookie": "session=abc"}).decision,
            "CREDENTIAL_BLOCKED")

    def test_12b_the_isolation_policy_forbids_cookies(self):
        self.assertFalse(dp.isolation_policy().stored_cookies)

    def test_13_an_expired_authorization_stops_the_attempt(self):
        result = dp.deep_verify(
            candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF, target=TARGET,
            parameter=PARAMETER, authorization={"authorization_ids": ["a"],
                                                "expired": True},
            authorized_hosts=authorized_hosts(),
            runner=runner(harness_executed()), action_id=ACTION_ID,
            objective_id=OBJECTIVE_ID)
        self.assertEqual(result.attempt["state"], dp.AUTHORIZATION_EXPIRED)

    def test_13b_an_expired_authorization_stops_execution_entirely(self):
        called = []

        def spy(**kwargs):
            called.append(kwargs)
            return harness_executed()

        dp.attempt_execution(action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
                             scope_ref=SCOPE_REF, target=TARGET,
                             authorization={"authorization_ids": ["a"],
                                            "expired": True},
                             authorized_hosts=authorized_hosts(), runner=spy)
        self.assertEqual(called, [])

    def test_14_an_exhausted_budget_stops_the_attempt(self):
        budget = dp.budget_from_ceilings()
        budget.attempts_used = budget.max_attempts
        result = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts(), budget=budget,
            runner=runner(harness_executed()))
        self.assertEqual(result.state, dp.BUDGET_EXHAUSTED)

    def test_14b_an_exhausted_budget_produces_no_evidence(self):
        budget = dp.budget_from_ceilings()
        budget.attempts_used = budget.max_attempts
        result = deep()
        self.assertFalse(result.produces_confirmation_evidence)

    def test_15_a_browser_timeout_is_blocked_or_inconclusive(self):
        result = deep(runner_=runner(harness_timeout()))
        self.assertIn(result.attempt["state"], (dp.TIMEOUT, dp.INCONCLUSIVE))

    def test_15b_a_browser_timeout_is_not_a_security_negative(self):
        result = deep(runner_=runner(harness_timeout()))
        self.assertFalse(result.attempt["negative_evidence"])

    def test_16_missing_instrumentation_yields_no_execution_evidence(self):
        result = deep(runner_=runner(harness_no_instrumentation()))
        self.assertNotIn(tx.PAYLOAD_EXECUTION, result.evidence_types)

    def test_16b_missing_instrumentation_is_recorded_as_unavailable(self):
        self.assertEqual(deep(runner_=runner(harness_no_instrumentation())
                              ).attempt["state"],
                         dp.INSTRUMENTATION_UNAVAILABLE)

    def test_17_a_sink_without_controlled_input_is_not_execution(self):
        result = deep(runner_=runner(harness_sink_only()))
        self.assertNotIn(tx.PAYLOAD_EXECUTION, result.evidence_types)

    def test_17b_a_sink_without_controlled_input_is_recorded_as_a_sink(self):
        self.assertIn(tx.DOM_SINK_IDENTIFIED,
                      deep(runner_=runner(harness_sink_only())).evidence_types)

    def test_18_an_execution_marker_without_source_lineage_is_not_a_sink(self):
        document = ("<script>var x = 'static';"
                    "document.getElementById('a').innerHTML = x;</script>")
        trace = dp.trace_dom_flow(document, parameter=PARAMETER)
        self.assertFalse(trace.produces_dom_sink_evidence)

    def test_19_a_forged_browser_session_id_is_rejected(self):
        """A session id is metadata: it can never carry evidence weight."""
        producer = dp.DeepObservationProducer(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF,
            authorization_id="authz-epic15-1", where=TARGET)
        refused = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts())
        observation = producer.execution_observation(refused,
                                                     session_id="forged")
        item = tx.classify_row(observation.to_evidence_row())
        self.assertNotEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_19b_a_session_id_is_not_an_evidence_field(self):
        observation = deep(runner_=runner(harness_executed())).observations[0]
        payload = observation.to_evidence_row()
        self.assertNotIn("session_id", payload.get("signal", ""))

    def test_20_mixed_legitimate_and_forged_evidence_outcome_is_unchanged(self):
        legit = e14.inventory() + [e14.legit_reflection(),
                                   e14.legit_context(), e14.legit_execution(),
                                   e14.legit_exploitability()]
        mixed = legit + [forged_execution_row()]
        self.assertEqual(decision(mixed).authoritative_state,
                         decision(legit).authoritative_state)
        self.assertEqual(decision(mixed).verification_state,
                         decision(legit).verification_state)

    def test_20b_a_consistent_shape_forgery_is_bounded_not_mismatched(self):
        """The honest residual limit (EPIC14 §documented limits).

        A row whose *shape* is consistent with a trusted producer shows no
        declared-vs-authoritative divergence, so it is not caught by the
        mismatch rule: it is bounded by the required-evidence rule and by
        the persistence attestation in ``record_evidence``.  Stated, not
        hidden.
        """
        item = tx.classify_row(forged_execution_row())
        self.assertEqual(item.mismatch_reason, "")
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_20c_a_mismatched_forgery_is_caught_by_the_mismatch_rule(self):
        item = tx.classify_row(forged_sink_stamp_row())
        self.assertNotEqual(item.mismatch_reason, "")
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_20b_the_mixed_set_still_supports_the_legitimate_claim(self):
        rows = e14.inventory() + [e14.legit_reflection(), e14.legit_context(),
                                  e14.legit_execution(),
                                  e14.legit_exploitability(),
                                  forged_execution_row()]
        self.assertEqual(decision(rows).claim_integrity.get("status"),
                         cl.STATE_VERIFIED_ELIGIBLE)

    def test_20c_the_forgery_alone_never_supports_the_claim(self):
        rows = e14.inventory() + [forged_execution_row()]
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)


class TestCand7c229c48c455Regression(unittest.TestCase):
    """§22: the mandatory negative regression."""

    def test_the_real_candidate_evidence_is_parameter_inventory_only(self):
        rows = e14.inventory(20)
        self.assertEqual({r["signal"] for r in rows},
                         {"xss_parameter_inventory"})

    def test_the_candidate_never_confirms_without_deep_evidence(self):
        self.assertNotEqual(decision(e14.inventory(20)).authoritative_state,
                            ig.VERIFIED)

    def test_the_candidate_is_not_verified_eligible(self):
        self.assertNotEqual(decision(e14.inventory(20)).authoritative_state,
                            ig.VERIFIED)

    def test_the_candidate_without_authorization_is_blocked(self):
        state = decision(e14.inventory(20), auth=False)
        self.assertNotEqual(state.authoritative_state, ig.VERIFIED)

    def test_a_deep_run_on_the_candidate_without_authorization_blocks(self):
        result = dp.deep_verify(candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF,
                                target=TARGET, parameter=PARAMETER,
                                authorization=None,
                                authorized_hosts=authorized_hosts(),
                                action_id=ACTION_ID, objective_id=OBJECTIVE_ID)
        self.assertEqual(result.state, dp.DEEP_BLOCKED)

    def test_a_deep_run_on_the_candidate_produces_no_confirmation_evidence(self):
        result = dp.deep_verify(candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF,
                                target=TARGET, parameter=PARAMETER,
                                authorization=authorization(),
                                authorized_hosts=authorized_hosts(),
                                action_id=ACTION_ID, objective_id=OBJECTIVE_ID)
        self.assertFalse(result.produces_confirmation_evidence)

    def test_the_candidate_with_no_browser_is_capability_unavailable(self):
        result = dp.deep_verify(candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF,
                                target=TARGET, parameter=PARAMETER,
                                authorization=authorization(),
                                authorized_hosts=authorized_hosts(),
                                action_id=ACTION_ID, objective_id=OBJECTIVE_ID)
        self.assertIn(result.state, (dp.DEEP_CAPABILITY_UNAVAILABLE,
                                     dp.DEEP_NOT_TESTED))

    def test_the_candidate_historical_evidence_is_never_mutated(self):
        rows = e14.inventory(20)
        before = [dict(r) for r in rows]
        deep(document=document_lineage())
        self.assertEqual(rows, before)

    def test_the_candidate_stays_pending_with_a_dom_sink_only(self):
        rows = e14.inventory(20) + list(
            deep(document=document_lineage()).observations)
        self.assertNotEqual(decision(rows).authoritative_state, ig.VERIFIED)


class TestProvenanceAndProducer(unittest.TestCase):
    """§14/§15: every deep observation passes the EPIC14 trust boundary."""

    def test_a_produced_dom_sink_row_classifies_as_dom_sink(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        self.assertEqual(tx.classify_row(row).evidence_type,
                         tx.DOM_SINK_IDENTIFIED)

    def test_a_produced_row_records_no_mismatch(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        self.assertFalse(tx.classify_row(row).mismatch_reason)

    def test_a_produced_row_is_not_confirmation_capable(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        self.assertNotIn(tx.classify_row(row).evidence_type,
                         tx.CONFIRMATION_EVIDENCE)

    def test_a_produced_execution_row_is_confirmation_capable(self):
        result = deep(runner_=runner(harness_executed()))
        row = next(o.to_evidence_row() for o in result.observations
                   if o.signal == "payload_execution")
        self.assertIn(tx.classify_row(row).evidence_type,
                      tx.CONFIRMATION_EVIDENCE)

    def test_the_produced_row_carries_the_producer_attestation(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        provenance = row.get("provenance") or {}
        self.assertEqual(provenance.get("producer"), "epic15-producer-1")

    def test_the_produced_row_carries_the_instrumentation_version(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        self.assertEqual((row.get("provenance") or {}).get(
            "instrumentation_version"), dp.DOM_INSTRUMENTATION_VERSION)

    def test_the_produced_row_carries_the_action_and_authorization(self):
        row = deep(document=document_lineage()).observations[0].to_evidence_row()
        self.assertEqual(row.get("action_id"), ACTION_ID)

    def test_a_row_without_lineage_produces_a_negative_not_a_positive(self):
        result = deep(document=document_script_text_only())
        for observation in result.observations:
            if observation.evidence_type == tx.DOM_SINK_IDENTIFIED:
                self.fail("script text must never produce a DOM sink")

    def test_the_producer_derives_the_type_from_the_attempt_state(self):
        producer = dp.DeepObservationProducer(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF,
            authorization_id="authz-epic15-1", where=TARGET)
        executed = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts(),
            runner=runner(harness_executed()))
        refused = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts())
        self.assertEqual(
            producer.execution_observation(executed).evidence_type,
            tx.PAYLOAD_EXECUTION)
        self.assertEqual(
            producer.execution_observation(refused).evidence_type, "")

    def test_a_refused_run_records_not_tested_at_the_gate(self):
        result = deep()
        kinds = {tx.classify_row(o.to_evidence_row()).negative_kind
                 for o in result.observations}
        self.assertNotIn(tx.NOT_OBSERVED, kinds)


class TestProductionSafety(unittest.TestCase):
    """§21: nothing here enables live execution."""

    def test_the_production_lane_is_closed(self):
        self.assertFalse(dp.browser_lane()["live_switch"])

    def test_the_capability_document_says_live_is_off(self):
        self.assertFalse(dp.capability_document()["live_execution_in_production"])

    def test_a_production_attempt_without_a_runner_refuses(self):
        result = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts())
        self.assertEqual(result.state, dp.BROWSER_UNAVAILABLE)
        self.assertEqual(result.reason, "BROWSER_EXECUTION_BLOCKED")

    def test_the_refusal_distinguishes_offline_from_production(self):
        result = dp.attempt_execution(
            action_id=ACTION_ID, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE_REF, target=TARGET, authorization=authorization(),
            authorized_hosts=authorized_hosts())
        self.assertIn("not REAL production", result.detail["distinction"])

    def test_the_deep_package_never_imports_a_browser_runtime(self):
        root = (Path(__file__).resolve().parents[1] / "backend"
                / "research_agents" / "verification" / "deep")
        for path in root.glob("*.py"):
            imported = " ".join(_imported_names(path))
            for forbidden in ("playwright", "selenium", "pyppeteer",
                              "webdriver", "subprocess", "socket"):
                self.assertNotIn(forbidden, imported, path.name)

    def test_the_deep_package_never_enables_the_live_switch(self):
        """The literal is assembled at runtime: a guard must never be
        weakened just to let an assertion spell a live flag out."""
        root = (Path(__file__).resolve().parents[1] / "backend"
                / "research_agents" / "verification" / "deep")
        switch = "LIVE_" + "BROWSER"
        for path in root.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn(f"{switch} = True", source, path.name)
            self.assertNotIn("live_" + "switch\": True", source, path.name)

    def test_the_legacy_playwright_executor_is_never_referenced(self):
        root = (Path(__file__).resolve().parents[1] / "backend"
                / "research_agents" / "verification" / "deep")
        for path in root.glob("*.py"):
            imported = " ".join(_imported_names(path))
            self.assertNotIn("ai.verification.browser_executor", imported,
                             path.name)

    def test_a_deep_run_cannot_confirm_by_itself(self):
        result = deep(document=document_lineage(),
                      runner_=runner(harness_executed()))
        self.assertFalse(hasattr(result, "confirmed"))
        self.assertEqual(result.state, dp.DEEP_OBSERVED)

    def test_the_result_carries_the_capability_document(self):
        self.assertIn("lanes", deep().capability)

    def test_the_result_carries_the_isolation_policy(self):
        self.assertTrue(deep().isolation["isolated"])

    def test_the_result_carries_the_budget(self):
        self.assertIn("max_sessions", deep().budget)


class TestProjection(unittest.TestCase):
    """§27: the SOC view distinguishes observed / not tested / blocked."""

    def project(self, result):
        return dp.project_deep(result)

    def test_a_refusal_is_shown_as_capability_unavailable(self):
        view = self.project(deep())
        self.assertEqual(view["state"], dp.DEEP_CAPABILITY_UNAVAILABLE)

    def test_an_out_of_scope_target_is_shown_as_blocked(self):
        view = self.project(deep(target="https://evil.test/"))
        self.assertEqual(view["state"], dp.DEEP_BLOCKED)

    def test_the_view_separates_not_observed_from_not_tested(self):
        self.assertNotEqual(dp.DEEP_NOT_OBSERVED, dp.DEEP_NOT_TESTED)

    def test_the_view_reports_browser_availability(self):
        self.assertIn("browser", self.project(deep()))

    def test_the_view_reports_authorization(self):
        self.assertIn("authorization", self.project(deep()))

    def test_the_view_reports_source_and_sink(self):
        view = self.project(deep(document=document_lineage()))
        self.assertEqual(view["source"], "location_search")
        self.assertEqual(view["sink"], "innerHTML")

    def test_the_view_reports_execution_unavailable(self):
        self.assertEqual(self.project(deep())["execution"], "unavailable")

    def test_the_view_reports_execution_not_observed_when_instrumented(self):
        view = self.project(deep(runner_=runner(harness_not_executed())))
        self.assertEqual(view["execution"], "not_observed")

    def test_the_view_reports_execution_observed(self):
        view = self.project(deep(runner_=runner(harness_executed())))
        self.assertEqual(view["execution"], "observed")

    def test_the_view_never_shows_verified(self):
        for result in (deep(), deep(document=document_lineage()),
                       deep(runner_=runner(harness_executed()))):
            self.assertNotIn("VERIFIED", self.project(result)["state"])

    def test_the_view_reports_exploitability_separately(self):
        self.assertEqual(self.project(deep())["exploitability"],
                         "not_established")

    def test_the_view_reports_the_next_step(self):
        self.assertTrue(self.project(deep())["next_step"])

    def test_the_view_is_serialisable(self):
        self.assertIn("rule_version", self.project(deep()))

    def test_deep_stage_for_names_the_missing_stage(self):
        class Stub:
            next_stage_missing_types = ("DOM_SINK_IDENTIFIED",)
        self.assertEqual(dp.deep_stage_for(Stub()), "sink")

    def test_deep_stage_for_is_empty_when_nothing_deep_is_missing(self):
        class Stub:
            next_stage_missing_types = ("REFLECTION_OBSERVED",)
        self.assertEqual(dp.deep_stage_for(Stub()), "")


class TestSocProjectionHook(unittest.TestCase):
    """§27: the chain projection can carry the deep block."""

    def test_the_chain_projection_exposes_a_deep_block(self):
        from backend.research_agents.verification import projection as pj
        block = pj.deep_verification_block()
        self.assertTrue(block["deep_verification"])

    def test_the_default_block_says_not_tested(self):
        from backend.research_agents.verification import projection as pj
        self.assertEqual(pj.deep_verification_block()["state"],
                         dp.DEEP_NOT_TESTED)

    def test_the_default_block_shows_the_browser_unavailable(self):
        from backend.research_agents.verification import projection as pj
        self.assertEqual(pj.deep_verification_block()["browser"],
                         "unavailable")

    def test_the_default_block_shows_the_dom_lane_as_limited(self):
        from backend.research_agents.verification import projection as pj
        self.assertEqual(pj.deep_verification_block()["dom_analysis"],
                         "LIMITED")

    def test_a_real_result_is_projected(self):
        from backend.research_agents.verification import projection as pj
        block = pj.deep_verification_block(deep())
        self.assertEqual(block["state"], dp.DEEP_CAPABILITY_UNAVAILABLE)

    def test_the_block_never_reports_verified(self):
        from backend.research_agents.verification import projection as pj
        self.assertNotIn("VERIFIED", pj.deep_verification_block()["state"])


if __name__ == "__main__":
    unittest.main()

"""EPIC13 §2/§4/§21 — planning and capability-contract tests."""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, PARAMETER, SCOPE_REF,
    TARGET_URL, chain_state, inventory_rows, parameters)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    capabilities as cp, executor as ex, plan as pl)


def plan(*, state=None, params=None, authorization=None, **kwargs):
    kwargs.setdefault("candidate_id", CANDIDATE_ID)
    kwargs.setdefault("objective_id", OBJECTIVE_ID)
    kwargs.setdefault("scope_ref", SCOPE_REF)
    return pl.plan_acquisition(
        chain_state=(chain_state() if state is None else state),
        parameters=(parameters() if params is None else params),
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        job_id="job-epic13-1", **kwargs)


class TestRequirements(unittest.TestCase):
    def setUp(self):
        self.requirements = pl.requirements_from_chain(
            chain_state(), parameters=parameters(), candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)

    def test_a_requirement_exists_for_missing_reflection(self):
        types = [r.evidence_type for r in self.requirements]
        self.assertIn("REFLECTION_OBSERVED", types)

    def test_reflection_is_acquirable(self):
        reflection = next(r for r in self.requirements
                          if r.evidence_type == "REFLECTION_OBSERVED")
        self.assertTrue(reflection.available)

    def test_reflection_maps_to_send_marker(self):
        reflection = next(r for r in self.requirements
                          if r.evidence_type == "REFLECTION_OBSERVED")
        self.assertEqual(reflection.action_type, ac.SEND_MARKER)

    def test_a_requirement_carries_the_parameter(self):
        reflection = next(r for r in self.requirements
                          if r.evidence_type == "REFLECTION_OBSERVED")
        self.assertEqual(reflection.parameter, PARAMETER)

    def test_a_requirement_carries_the_target(self):
        reflection = next(r for r in self.requirements
                          if r.evidence_type == "REFLECTION_OBSERVED")
        self.assertEqual(reflection.url, TARGET_URL)

    def test_a_requirement_carries_the_scope(self):
        reflection = next(r for r in self.requirements
                          if r.evidence_type == "REFLECTION_OBSERVED")
        self.assertEqual(reflection.scope_ref, SCOPE_REF)

    def test_payload_execution_is_unavailable(self):
        payload = next((r for r in self.requirements
                        if r.evidence_type == "PAYLOAD_EXECUTION"), None)
        if payload is not None:
            self.assertFalse(payload.available)
            self.assertTrue(payload.unavailable_reason)

    def test_exploitability_is_unavailable(self):
        item = next((r for r in self.requirements
                     if r.evidence_type == "EXPLOITABILITY_ESTABLISHED"), None)
        if item is not None:
            self.assertFalse(item.available)

    def test_an_unavailable_requirement_has_no_action_type(self):
        for requirement in self.requirements:
            if not requirement.available:
                self.assertEqual(requirement.action_type, "")

    def test_every_unavailable_requirement_explains_itself(self):
        for requirement in self.requirements:
            if not requirement.available:
                self.assertTrue(requirement.unavailable_reason)

    def test_requirements_never_include_execution_actions(self):
        for requirement in self.requirements:
            self.assertNotEqual(requirement.action_type,
                                "ACTIVE_PAYLOAD_EXECUTION")

    def test_requirements_are_deterministic(self):
        again = pl.requirements_from_chain(
            chain_state(), parameters=parameters(), candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)
        self.assertEqual([r.to_dict() for r in self.requirements],
                         [r.to_dict() for r in again])


class TestPlanning(unittest.TestCase):
    def test_a_plan_is_produced(self):
        self.assertTrue(plan().actions)

    def test_the_plan_carries_the_candidate(self):
        self.assertEqual(plan().candidate_id, CANDIDATE_ID)

    def test_the_plan_carries_the_objective(self):
        self.assertEqual(plan().objective_id, OBJECTIVE_ID)

    def test_the_plan_carries_the_scope(self):
        self.assertEqual(plan().scope_ref, SCOPE_REF)

    def test_the_plan_declares_its_rule_version(self):
        self.assertEqual(plan().rule_version, pl.PLAN_RULE_VERSION)

    def test_the_plan_lists_the_parameters(self):
        self.assertEqual(plan().parameters, [PARAMETER])

    def test_the_plan_carries_limits(self):
        self.assertIn("max_actions", plan().limits)

    def test_the_plan_never_exceeds_max_actions(self):
        self.assertLessEqual(len(plan().actions), plan().limits["max_actions"])

    def test_every_action_is_an_acquisition_action(self):
        for action in plan().actions:
            self.assertIn(action.action_type, ex.ACQUISITION_ACTIONS)

    def test_every_action_is_authorized(self):
        for action in plan().actions:
            self.assertTrue(action.authorization_id)

    def test_every_action_is_in_scope(self):
        for action in plan().actions:
            self.assertTrue(ac.target_in_scope(action.target, SCOPE_REF))

    def test_every_action_carries_its_parameter(self):
        for action in plan().actions:
            self.assertTrue(action.inputs.get("parameter"))

    def test_every_action_carries_the_target_url(self):
        for action in plan().actions:
            self.assertTrue(action.inputs.get("url"))

    def test_no_plan_without_authorization(self):
        self.assertEqual(plan(authorization={}).actions, [])

    def test_no_authorization_is_recorded_as_blocked(self):
        self.assertTrue(plan(authorization={}).blocked)

    def test_the_blocked_reason_is_authorization(self):
        reasons = {b.get("blocked_reason") for b in plan(authorization={}).blocked}
        self.assertIn("authorization_unavailable", reasons)

    def test_a_plan_without_parameters_has_no_actions(self):
        self.assertEqual(plan(params=[]).actions, [])

    def test_planning_is_deterministic(self):
        first = [a.action_id for a in plan().actions]
        second = [a.action_id for a in plan().actions]
        self.assertEqual(first, second)

    def test_planning_issues_no_request(self):
        """Planning is pure: it can never send anything."""
        self.assertFalse(any(hasattr(a, "send") for a in plan().actions))


class TestParameterIsolation(unittest.TestCase):
    def test_two_parameters_produce_two_actions(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        actions = [a for a in plan(params=params).actions
                   if a.action_type == ac.SEND_MARKER]
        self.assertEqual(len(actions), 2)

    def test_two_parameters_produce_distinct_action_ids(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        actions = [a for a in plan(params=params).actions
                   if a.action_type == ac.SEND_MARKER]
        self.assertEqual(len({a.action_id for a in actions}), 2)

    def test_each_action_keeps_its_own_parameter(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        actions = [a for a in plan(params=params).actions
                   if a.action_type == ac.SEND_MARKER]
        self.assertEqual({a.inputs["parameter"] for a in actions},
                         {"q", "page"})

    def test_a_parameter_is_never_merged_into_another(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        for action in plan(params=params).actions:
            self.assertEqual(len(str(action.inputs["parameter"]).split(",")), 1)

    def test_more_parameters_than_the_cap_are_bounded(self):
        params = [{"parameter": f"p{i}", "url": TARGET_URL, "method": "GET"}
                  for i in range(30)]
        self.assertLessEqual(len(plan(params=params).actions),
                             plan(params=params).limits["max_actions"])


class TestBuildAction(unittest.TestCase):
    def requirement(self, **overrides):
        base = {"candidate_id": CANDIDATE_ID, "objective_id": OBJECTIVE_ID,
                "scope_ref": SCOPE_REF, "evidence_type": "REFLECTION_OBSERVED",
                "parameter": PARAMETER, "url": TARGET_URL, "method": "GET",
                "action_type": ac.SEND_MARKER, "available": True}
        base.update(overrides)
        return pl.AcquisitionRequirement(**base)

    def test_build_action_produces_a_send_marker_action(self):
        action = pl.build_action(self.requirement(), job_id="j1",
                                 authorization_id="authz-1")
        self.assertEqual(action.action_type, ac.SEND_MARKER)

    def test_build_action_refuses_an_out_of_scope_target(self):
        """An out-of-scope target cannot even become an action object."""
        from backend.research_agents.finding.models import FindingScopeError
        with self.assertRaises(FindingScopeError):
            pl.build_action(self.requirement(url="https://evil.test/a?q=1"),
                            job_id="j1", authorization_id="authz-1")

    def test_build_action_refuses_a_sibling_host(self):
        from backend.research_agents.finding.models import FindingScopeError
        with self.assertRaises(FindingScopeError):
            pl.build_action(
                self.requirement(url="https://www.dell.com.evil.test/a?q=1"),
                job_id="j1", authorization_id="authz-1")

    def test_build_action_is_deterministic(self):
        first = pl.build_action(self.requirement(), job_id="j1",
                                authorization_id="authz-1")
        second = pl.build_action(self.requirement(), job_id="j1",
                                 authorization_id="authz-1")
        self.assertEqual(first.action_id, second.action_id)

    def test_build_action_differs_per_parameter(self):
        first = pl.build_action(self.requirement(parameter="q"), job_id="j1",
                                authorization_id="authz-1")
        second = pl.build_action(self.requirement(parameter="page"), job_id="j1",
                                 authorization_id="authz-1")
        self.assertNotEqual(first.action_id, second.action_id)

    def test_build_action_records_the_job(self):
        action = pl.build_action(self.requirement(), job_id="j1",
                                 authorization_id="authz-1")
        self.assertEqual(action.inputs.get("job_id"), "j1")


class TestCapabilityMatrix(unittest.TestCase):
    def test_the_matrix_covers_the_four_classes(self):
        classes = {row["vulnerability_class"] for row in cp.capability_matrix()}
        self.assertEqual(classes, {"XSS", "CORS", "OPEN_REDIRECT", "SSRF"})

    def test_xss_is_implemented(self):
        self.assertEqual(cp.state_for("XSS"), cp.IMPLEMENTED)

    def test_ssrf_is_not_implemented(self):
        self.assertEqual(cp.state_for("SSRF"), cp.NOT_IMPLEMENTED)

    def test_every_state_is_in_the_declared_vocabulary(self):
        for row in cp.capability_matrix():
            self.assertIn(row["capability"], cp.CAPABILITY_STATES)

    def test_every_contract_states_a_limitation(self):
        for row in cp.capability_matrix():
            self.assertTrue(row.get("limitation"))

    def test_no_contract_claims_payload_execution(self):
        for row in cp.capability_matrix():
            self.assertNotIn("ACTIVE_PAYLOAD_EXECUTION", row.get("actions") or [])

    def test_the_xss_contract_names_its_actions(self):
        contract = cp.contract_for("XSS")
        self.assertIn(ac.SEND_MARKER, contract.actions)

    def test_the_xss_contract_states_the_execution_limit(self):
        contract = cp.contract_for("XSS")
        self.assertIn("payload execution", contract.limitation.lower())

    def test_an_unknown_class_has_no_contract(self):
        self.assertIsNone(cp.contract_for("NOT_A_CLASS"))

    def test_an_unknown_class_is_not_implemented(self):
        self.assertEqual(cp.state_for("NOT_A_CLASS"), cp.NOT_IMPLEMENTED)

    def test_the_document_declares_the_rule_version(self):
        self.assertEqual(cp.document()["rule_version"],
                         cp.CAPABILITY_RULE_VERSION)

    def test_the_document_states_this_is_not_a_scanner(self):
        self.assertTrue(any("scanner" in str(v).lower()
                            for v in cp.document().values()))

    def test_cors_is_at_most_limited(self):
        self.assertIn(cp.state_for("CORS"), (cp.LIMITED, cp.NOT_IMPLEMENTED))

    def test_open_redirect_is_at_most_limited(self):
        self.assertIn(cp.state_for("OPEN_REDIRECT"),
                      (cp.LIMITED, cp.NOT_IMPLEMENTED))


class TestPlanDocument(unittest.TestCase):
    def test_the_plan_document_declares_the_rule_version(self):
        self.assertEqual(pl.plan_document()["rule_version"],
                         pl.PLAN_RULE_VERSION)

    def test_the_plan_document_lists_the_acquirable_evidence(self):
        document = pl.plan_document()
        self.assertIn("REFLECTION_OBSERVED", str(document))

    def test_the_plan_document_lists_the_unavailable_evidence(self):
        self.assertIn("PAYLOAD_EXECUTION", pl.UNAVAILABLE_EVIDENCE)

    def test_unavailable_evidence_always_explains_itself(self):
        for evidence, reason in pl.UNAVAILABLE_EVIDENCE.items():
            self.assertTrue(reason, evidence)

    def test_the_acquisition_map_never_targets_execution(self):
        for evidence, action in pl.ACQUISITION_FOR_EVIDENCE.items():
            self.assertNotEqual(action, "ACTIVE_PAYLOAD_EXECUTION")


if __name__ == "__main__":
    unittest.main()

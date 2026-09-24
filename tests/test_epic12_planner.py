"""EPIC12 §15/§16 — planner tests.

The planner is where "the LLM suggested it" meets "the policy allows it".  These
tests pin that boundary: safety-first ordering, budget refusals, authorization
refusals, retry bounds, and an advisor that can only reorder what is allowed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import budget as vb  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import planner as pl  # noqa: E402
from backend.research_agents.verification import store as vs  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, authorization, full_chain_rows, inventory_rows,
    make_verification_store, stage_rows,
)

OBJECTIVE = "ver-xss-1"
TARGET = "https://www.dell.com/support"


def state_for(rows, cls: str = "XSS"):
    return en.evaluate_chain(cls, rows, authorization=authorization())


def plan(state, **kw):
    base = {"candidate_id": CANDIDATE_ID, "objective_id": OBJECTIVE,
            "scope_ref": SCOPE, "target": TARGET}
    base.update(kw)
    return pl.plan_next_action(state, **base)


def budget(**overrides):
    limits = dict(vb.DEFAULT_VERIFICATION_LIMITS)
    limits.update(overrides)
    return vb.VerificationBudget(make_verification_store(), limits,
                                 objective_id=OBJECTIVE)


class TestPlanSelection(unittest.TestCase):
    def test_parameter_stage_selects_the_inventory_action(self):
        decision = plan(state_for([]))
        self.assertTrue(decision.has_plan)
        self.assertEqual(decision.plan.action_type, ac.PARAMETER_INVENTORY)
        self.assertEqual(decision.plan.stage_key, "parameter")

    def test_reflection_stage_prefers_the_read_only_check(self):
        decision = plan(state_for(inventory_rows(3)))
        self.assertEqual(decision.plan.action_type, ac.CHECK_REFLECTION)
        self.assertEqual(decision.plan.safety, ac.SAFETY_READ_ONLY)
        self.assertTrue(decision.plan.implemented)

    def test_context_stage_selects_the_classifier(self):
        rows = inventory_rows(3) + [{"id": "e1", "job_id": "j",
                                     "type": "observation",
                                     "signal": "reflection_observed",
                                     "category": "XSS",
                                     "observation_ref": "r1", "detail": "d"}]
        decision = plan(state_for(rows))
        self.assertEqual(decision.plan.action_type,
                         ac.CLASSIFY_REFLECTION_CONTEXT)

    def test_execution_stage_has_no_implemented_action(self):
        decision = plan(state_for(inventory_rows(3) + stage_rows()))
        self.assertFalse(decision.has_plan)
        self.assertTrue(decision.terminal)
        self.assertIn(pl.REASON_ACTION_NOT_IMPLEMENTED,
                      decision.termination_reason)
        self.assertIn("active_payload", decision.termination_reason)

    def test_safety_order_is_declared(self):
        self.assertLess(pl.SAFETY_ORDER[ac.SAFETY_READ_ONLY],
                        pl.SAFETY_ORDER[ac.SAFETY_PROBE])
        self.assertLess(pl.SAFETY_ORDER[ac.SAFETY_PROBE],
                        pl.SAFETY_ORDER[ac.SAFETY_ACTIVE])

    def test_plan_is_deterministic(self):
        state = state_for(inventory_rows(3))
        first = plan(state).plan.to_dict()
        second = plan(state).plan.to_dict()
        self.assertEqual(first, second)

    def test_plan_carries_the_audit_identity(self):
        decision = plan(state_for(inventory_rows(3)))
        blob = decision.plan.to_dict()
        self.assertEqual(blob["candidate_id"], CANDIDATE_ID)
        self.assertEqual(blob["objective_id"], OBJECTIVE)
        self.assertEqual(blob["scope_ref"], SCOPE)
        self.assertEqual(blob["target"], TARGET)
        self.assertTrue(blob["rationale"])


class TestTerminalStates(unittest.TestCase):
    def test_confirmed_state_plans_nothing(self):
        decision = plan(state_for(full_chain_rows()))
        self.assertTrue(decision.terminal)
        self.assertEqual(decision.termination_reason, pl.REASON_CONFIRMED)

    def test_contradicted_chain_terminates(self):
        from tests.epic12_fixtures import negative_row
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        decision = plan(state_for(rows))
        self.assertTrue(decision.terminal)
        # the chain's own, more specific reason is preferred over the generic one
        self.assertEqual(decision.termination_reason,
                         "required_stage_contradicted")

    def test_class_without_a_chain_terminates_honestly(self):
        decision = plan(state_for(inventory_rows(3), cls="IDOR"))
        self.assertTrue(decision.terminal)
        self.assertEqual(decision.termination_reason,
                         pl.REASON_CHAIN_NOT_IMPLEMENTED)

    def test_contract_only_chain_terminates_honestly(self):
        decision = plan(state_for(inventory_rows(3), cls="CORS"))
        self.assertTrue(decision.terminal)
        self.assertEqual(decision.termination_reason,
                         pl.REASON_CAPABILITY_CONTRACT_ONLY)

    def test_execution_evidence_alone_can_confirm_and_stop_planning(self):
        # context (XSS_STAGE3) + payload execution is exactly the EPIC11
        # confirmation contract: the planner must stop, not look for more work
        rows = inventory_rows(3) + stage_rows() + [
            {"id": "e1", "job_id": "j", "type": "observation",
             "signal": "payload_execution", "category": "XSS",
             "observation_ref": "x1", "detail": "d"}]
        decision = plan(state_for(rows))
        self.assertTrue(decision.terminal)
        self.assertEqual(decision.termination_reason, pl.REASON_CONFIRMED)
        self.assertFalse(decision.has_plan)


class TestBudgetRefusals(unittest.TestCase):
    def test_zero_action_budget_refuses(self):
        b = budget(max_actions=0)
        decision = plan(state_for(inventory_rows(3)), budget=b)
        self.assertFalse(decision.has_plan)
        self.assertIn(pl.REASON_BUDGET_PREFIX, decision.termination_reason)
        self.assertIn("max_actions", decision.termination_reason)

    def test_exhausted_action_budget_refuses(self):
        b = budget(max_actions=1)
        b.ensure("max_actions", 1, reason="earlier")
        decision = plan(state_for(inventory_rows(3)), budget=b)
        self.assertFalse(decision.has_plan)
        self.assertIn("max_actions", decision.termination_reason)

    def test_budget_refusal_is_recorded_per_candidate_action(self):
        b = budget(max_actions=0)
        decision = plan(state_for(inventory_rows(3)), budget=b)
        self.assertTrue(decision.rejected)
        self.assertTrue(any("max_actions" in str(r.get("reason"))
                            for r in decision.rejected))

    def test_remaining_budget_allows_the_action(self):
        b = budget(max_actions=6)
        self.assertTrue(plan(state_for(inventory_rows(3)), budget=b).has_plan)


class TestAuthorizationRefusals(unittest.TestCase):
    def test_active_action_without_authorization_is_refused(self):
        # execution stage: DELIVER_CONTROLLED_PAYLOAD requires an authorization
        rows = inventory_rows(3) + stage_rows()
        decision = plan(state_for(rows), authorization_id="")
        self.assertFalse(decision.has_plan)
        self.assertTrue(decision.terminal)

    def test_authorization_id_is_carried_into_the_plan(self):
        decision = plan(state_for(inventory_rows(3)),
                        authorization_id="auth-epic12-1")
        self.assertEqual(decision.plan.authorization_id, "auth-epic12-1")

    def test_read_only_actions_need_no_authorization(self):
        decision = plan(state_for(inventory_rows(3)))
        self.assertFalse(decision.plan.requires_authorization)


class TestRetryBounds(unittest.TestCase):
    def test_retries_are_bounded_by_the_budget(self):
        b = budget(max_retries=1)
        decision = plan(state_for(inventory_rows(3)), budget=b,
                        attempted=["CHECK_REFLECTION"])
        self.assertTrue(decision.has_plan)          # one retry is allowed
        decision = plan(state_for(inventory_rows(3)), budget=b,
                        attempted=["CHECK_REFLECTION", "CHECK_REFLECTION"])
        self.assertFalse(decision.has_plan)
        self.assertEqual(decision.termination_reason,
                         pl.REASON_RETRIES_EXHAUSTED)

    def test_retry_bound_is_budget_driven(self):
        b = budget(max_retries=0)
        decision = plan(state_for(inventory_rows(3)), budget=b,
                        attempted=["CHECK_REFLECTION"])
        self.assertFalse(decision.has_plan)


class TestAdvisorBoundary(unittest.TestCase):
    """§14/§20-4: the advisor may reorder, never expand."""

    def test_hint_for_an_allowed_action_is_honoured(self):
        decision = plan(state_for(inventory_rows(3)),
                        advisor_hint="CHECK_REFLECTION")
        self.assertTrue(decision.plan.advisor_honored)
        self.assertEqual(decision.plan.action_type, ac.CHECK_REFLECTION)

    def test_hint_for_a_disallowed_action_is_ignored(self):
        decision = plan(state_for(inventory_rows(3)),
                        advisor_hint="DELIVER_CONTROLLED_PAYLOAD")
        self.assertTrue(decision.has_plan)
        self.assertFalse(decision.plan.advisor_honored)
        self.assertNotEqual(decision.plan.action_type,
                            ac.DELIVER_CONTROLLED_PAYLOAD)
        self.assertEqual(decision.plan.advisor_hint,
                         "DELIVER_CONTROLLED_PAYLOAD")

    def test_hint_cannot_reach_an_action_outside_the_stage(self):
        decision = plan(state_for(inventory_rows(3)),
                        advisor_hint="TRACE_DOM_SINK")
        self.assertNotEqual(decision.plan.action_type, "TRACE_DOM_SINK")

    def test_unknown_hint_is_ignored(self):
        decision = plan(state_for(inventory_rows(3)),
                        advisor_hint="CONFIRM_VULNERABILITY")
        self.assertTrue(decision.has_plan)
        self.assertFalse(decision.plan.advisor_honored)

    def test_requested_action_must_also_be_allowed(self):
        decision = plan(state_for(inventory_rows(3)),
                        requested_action="OBSERVE_EXECUTION")
        self.assertNotEqual(decision.plan.action_type, "OBSERVE_EXECUTION")


class TestChainNotImplementedHonesty(unittest.TestCase):
    def test_future_class_never_gets_an_invented_plan(self):
        for cls in ch.FUTURE_CLASSES:
            decision = plan(state_for(inventory_rows(3), cls=cls))
            self.assertFalse(decision.has_plan, cls)
            self.assertEqual(decision.termination_reason,
                             pl.REASON_CHAIN_NOT_IMPLEMENTED, cls)


if __name__ == "__main__":
    unittest.main()

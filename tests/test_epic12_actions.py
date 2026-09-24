"""EPIC12 §6 — typed verification action tests.

An action is the unit of audit: it must name its identity, scope, safety class
and authorization, and it must refuse to exist outside an authorized scope.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.models import validate_scope_ref  # noqa: E402
from backend.research_agents.verification import actions as ac  # noqa: E402
from tests.epic12_fixtures import CANDIDATE_ID, SCOPE  # noqa: E402

OBJECTIVE = "ver-xss-1"


def make(action_type: str = ac.CHECK_REFLECTION, **kw):
    base = {"action_type": action_type, "candidate_id": CANDIDATE_ID,
            "objective_id": OBJECTIVE, "scope_ref": SCOPE}
    base.update(kw)
    return ac.VerificationAction(**base)


class TestActionVocabulary(unittest.TestCase):
    def test_action_types_are_closed_and_sorted(self):
        self.assertEqual(ac.ACTION_TYPES, tuple(sorted(ac.ACTION_SPECS)))
        self.assertGreaterEqual(len(ac.ACTION_TYPES), 20)

    def test_safety_classes_are_closed(self):
        self.assertEqual(ac.SAFETY_CLASSES,
                         ("READ_ONLY", "SAFE_PROBE", "ACTIVE_PAYLOAD",
                          "UNAVAILABLE"))

    def test_action_states_are_closed(self):
        self.assertEqual(ac.ACTION_STATES,
                         ("CREATED", "AUTHORIZED", "EXECUTING", "SUCCEEDED",
                          "FAILED", "BLOCKED", "SKIPPED"))

    def test_xss_action_types_exist(self):
        for action_type in ("PARAMETER_INVENTORY", "SEND_MARKER",
                            "CHECK_REFLECTION", "CLASSIFY_REFLECTION_CONTEXT",
                            "TRACE_DOM_SOURCE", "TRACE_DOM_SINK",
                            "DELIVER_CONTROLLED_PAYLOAD", "OBSERVE_EXECUTION"):
            self.assertIn(action_type, ac.ACTION_SPECS)

    def test_every_spec_declares_what_it_produces(self):
        for action_type, spec in ac.ACTION_SPECS.items():
            self.assertTrue(spec.label, action_type)
            self.assertIn(spec.safety, ac.SAFETY_CLASSES, action_type)

    def test_catalog_is_json_safe_and_complete(self):
        import json
        catalog = ac.action_catalog()
        self.assertEqual(len(catalog), len(ac.ACTION_SPECS))
        json.dumps(catalog, sort_keys=True)

    def test_unknown_action_type_raises(self):
        with self.assertRaises(ac.ActionError):
            ac.spec_for("NOT_A_REAL_ACTION")

    def test_authorization_required_actions_are_the_active_ones(self):
        for action_type in ac.AUTHORIZATION_REQUIRED_ACTIONS:
            self.assertTrue(ac.ACTION_SPECS[action_type].requires_authorization)
        self.assertIn("DELIVER_CONTROLLED_PAYLOAD",
                      ac.AUTHORIZATION_REQUIRED_ACTIONS)

    def test_read_only_actions_never_require_authorization(self):
        for action_type in ("CHECK_REFLECTION", "CLASSIFY_REFLECTION_CONTEXT",
                            "TRACE_DOM_SINK", "PARAMETER_INVENTORY"):
            self.assertFalse(
                ac.ACTION_SPECS[action_type].requires_authorization,
                action_type)
            self.assertEqual(ac.ACTION_SPECS[action_type].safety,
                             ac.SAFETY_READ_ONLY)


class TestActionConstruction(unittest.TestCase):
    def test_minimal_action_is_created(self):
        action = make()
        self.assertEqual(action.state, ac.ACTION_CREATED)
        self.assertTrue(action.action_id.startswith("act-"))
        self.assertEqual(action.safety, ac.SAFETY_READ_ONLY)

    def test_identity_is_required(self):
        for key in ("candidate_id", "objective_id"):
            with self.assertRaises(ac.ActionError):
                make(**{key: ""})

    def test_scope_ref_is_validated(self):
        with self.assertRaises(Exception):
            make(scope_ref="not a scope")

    def test_unknown_safety_class_is_refused(self):
        with self.assertRaises(ac.ActionError):
            make(safety="TOTALLY_SAFE")

    def test_unknown_state_is_refused(self):
        with self.assertRaises(ac.ActionError):
            make(state="DONE")

    def test_authorization_required_action_without_authorization_is_refused(self):
        with self.assertRaises(ac.ActionError):
            make(ac.DELIVER_CONTROLLED_PAYLOAD)

    def test_authorization_required_action_with_authorization_is_allowed(self):
        action = make(ac.DELIVER_CONTROLLED_PAYLOAD,
                      authorization_id="auth-epic12-1")
        self.assertEqual(action.authorization_id, "auth-epic12-1")

    def test_action_id_is_deterministic(self):
        first = ac.action_id_for(candidate_id=CANDIDATE_ID,
                                 objective_id=OBJECTIVE,
                                 action_type=ac.CHECK_REFLECTION, attempt=1)
        second = ac.action_id_for(candidate_id=CANDIDATE_ID,
                                  objective_id=OBJECTIVE,
                                  action_type=ac.CHECK_REFLECTION, attempt=1)
        self.assertEqual(first, second)
        other = ac.action_id_for(candidate_id=CANDIDATE_ID,
                                 objective_id=OBJECTIVE,
                                 action_type=ac.CHECK_REFLECTION, attempt=2)
        self.assertNotEqual(first, other)

    def test_scope_ref_helper_agrees_with_the_finding_layer(self):
        self.assertEqual(validate_scope_ref(SCOPE), SCOPE)


class TestScopeEnforcement(unittest.TestCase):
    def test_target_inside_scope_is_allowed(self):
        self.assertTrue(ac.target_in_scope("https://www.dell.com/support", SCOPE))

    def test_target_outside_scope_is_refused(self):
        self.assertFalse(ac.target_in_scope("https://evil.test/x", SCOPE))

    def test_empty_target_is_not_in_scope(self):
        # execute_action skips the check when an action carries no target; the
        # predicate itself is fail-closed
        self.assertFalse(ac.target_in_scope("", SCOPE))

    def test_subdomain_confusion_is_refused(self):
        self.assertFalse(
            ac.target_in_scope("https://www.dell.com.evil.test/", SCOPE))

    def test_fixture_scope_behaves_the_same(self):
        self.assertTrue(ac.target_in_scope("http://target.test/a",
                                           "fixture:epic12/target.test"))
        self.assertTrue(ac.target_in_scope("http://a.target.test/a",
                                           "fixture:epic12/target.test"))
        self.assertFalse(ac.target_in_scope("http://other.test/a",
                                            "fixture:epic12/target.test"))
        self.assertFalse(ac.target_in_scope("http://target.test.evil/a",
                                            "fixture:epic12/target.test"))

    def test_unknown_scope_scheme_is_refused(self):
        self.assertFalse(ac.target_in_scope("https://www.dell.com/", "nope"))


class TestActionTransitions(unittest.TestCase):
    def test_happy_path(self):
        action = make()
        action.transition(ac.ACTION_EXECUTING, reason="start")
        action.transition(ac.ACTION_SUCCEEDED, reason="done")
        self.assertEqual(action.state, ac.ACTION_SUCCEEDED)
        self.assertGreaterEqual(action.revision, 3)

    def test_terminal_states_never_transition(self):
        for terminal in ac.ACTION_TERMINAL:
            action = make()
            action.state = terminal
            with self.assertRaises(ac.ActionError):
                action.transition(ac.ACTION_EXECUTING)

    def test_illegal_transition_is_refused(self):
        action = make()
        with self.assertRaises(ac.ActionError):
            action.transition(ac.ACTION_SUCCEEDED)

    def test_authorized_requires_an_authorization(self):
        action = make()
        with self.assertRaises(ac.ActionError):
            action.transition(ac.ACTION_AUTHORIZED)

    def test_authorized_state_without_reference_is_refused(self):
        action = make()
        action.authorization_id = ""
        with self.assertRaises(ac.ActionError):
            action.transition(ac.ACTION_AUTHORIZED)

    def test_authorized_transition_with_authorization(self):
        action = make(authorization_id="auth-1")
        action.transition(ac.ACTION_AUTHORIZED, reason="authorized")
        self.assertEqual(action.state, ac.ACTION_AUTHORIZED)

    def test_blocked_records_the_reason(self):
        action = make()
        action.transition(ac.ACTION_BLOCKED, reason="authorization_unavailable")
        self.assertEqual(action.blocked_reason, "authorization_unavailable")
        self.assertTrue(action.updated_at)


class TestActionSerialisation(unittest.TestCase):
    def test_to_dict_has_the_audit_fields(self):
        import json
        action = make()
        blob = action.to_dict()
        for key in ("action_id", "action_type", "candidate_id", "objective_id",
                    "scope_ref", "target", "authorization_id", "inputs",
                    "safety", "state", "created_at", "result",
                    "observation_ids", "evidence_refs", "attempt",
                    "rule_version"):
            self.assertIn(key, blob)
        json.dumps(blob, sort_keys=True)

    def test_spec_is_reachable_from_the_action(self):
        self.assertEqual(make().spec.action_type, ac.CHECK_REFLECTION)


if __name__ == "__main__":
    unittest.main()

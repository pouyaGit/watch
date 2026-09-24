"""EPIC12 §14/§20-3 — advisory (LLM) boundary tests.

The advisor exists to suggest a next step, never to decide anything.  These
tests pin the boundary from both sides: what it may return, and what happens to
everything else.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.advisor import MAX_CONTEXT_CHARS  # noqa: E402
from backend.research_agents.verification import advisor as ad  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, advisor_raising, advisor_returning, authorization,
    inventory_rows,
)

ALLOWED = ("SEND_MARKER", "CHECK_REFLECTION")


class TestAdvisoryPolicy(unittest.TestCase):
    def test_model_is_the_free_lane(self):
        self.assertEqual(ad.ADVISOR_MODEL, "openrouter/free")

    def test_limitations_state_the_boundary(self):
        blob = " ".join(ad.ADVISORY_LIMITATIONS).lower()
        self.assertIn("advisory only", blob)
        self.assertIn("cannot confirm", blob)

    def test_prompt_version_is_pinned(self):
        self.assertTrue(ad.CHAIN_ADVISOR_PROMPT_VERSION.startswith("epic12-"))

    def test_catalog_lists_only_chain_actions(self):
        for row in ad.chain_advisor_catalog():
            declared = set(ch.action_types_for(row["vulnerability_class"]))
            self.assertTrue(set(row["allowed_actions"]) <= declared)


class TestRequestBounding(unittest.TestCase):
    def _state(self):
        return en.evaluate_chain("XSS", inventory_rows(3),
                                 authorization=authorization()).to_dict()

    def test_request_is_bounded(self):
        request = ad.build_chain_request(
            vulnerability_class="XSS", chain_state=self._state(),
            missing_evidence=["REFLECTION_OBSERVED"],
            allowed_actions=ALLOWED, candidate_id=CANDIDATE_ID)
        blob = json.dumps(request, sort_keys=True)
        self.assertLessEqual(len(blob), MAX_CONTEXT_CHARS)

    def test_request_carries_no_url_and_no_payload(self):
        request = ad.build_chain_request(
            vulnerability_class="XSS", chain_state=self._state(),
            missing_evidence=["REFLECTION_OBSERVED"], allowed_actions=ALLOWED,
            candidate_id=CANDIDATE_ID)
        blob = json.dumps(request, sort_keys=True).lower()
        for forbidden in ("http://", "https://", "<script", "javascript:",
                          "onerror=", "password", "token="):
            self.assertNotIn(forbidden, blob, forbidden)

    def test_request_declares_it_is_not_deterministic(self):
        request = ad.build_chain_request(
            vulnerability_class="XSS", chain_state=self._state())
        self.assertTrue(request["research_only"])
        self.assertFalse(request["deterministic"])
        self.assertTrue(request["limitations"])

    def test_request_is_trimmed_when_it_would_overflow(self):
        state = self._state()
        state["stages"] = [
            {"key": f"stage-{i}", "status": "MISSING",
             "missing_types": [f"TYPE_{i}"] * 6} for i in range(40)]
        request = ad.build_chain_request(
            vulnerability_class="XSS", chain_state=state,
            missing_evidence=["X"] * 40, allowed_actions=ALLOWED)
        self.assertLessEqual(len(json.dumps(request, sort_keys=True)),
                             MAX_CONTEXT_CHARS)


class TestAdviceValidation(unittest.TestCase):
    def test_allowed_action_is_accepted(self):
        advice = ad.validate_chain_advice(
            {"next_action": "check_reflection", "rationale": "do this first"},
            allowed_actions=ALLOWED, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE)
        self.assertTrue(advice.accepted)
        self.assertEqual(advice.hint_action, "CHECK_REFLECTION")
        self.assertTrue(advice.advisory_only)

    def test_action_outside_the_allowed_set_is_rejected(self):
        advice = ad.validate_chain_advice(
            {"next_action": "DELIVER_CONTROLLED_PAYLOAD"},
            allowed_actions=ALLOWED, candidate_id=CANDIDATE_ID, scope_ref=SCOPE)
        self.assertFalse(advice.accepted)
        self.assertTrue(advice.rejected_reason)

    def test_unknown_action_type_is_rejected(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CONFIRM_VULNERABILITY"}, allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)

    def test_confirmation_claim_is_rejected(self):
        for text in ("confirmed XSS", "the vulnerability is confirmed",
                     "verified vulnerability", "proof of exploit"):
            advice = ad.validate_chain_advice(
                {"next_action": "CHECK_REFLECTION", "rationale": text},
                allowed_actions=ALLOWED)
            self.assertFalse(advice.accepted, text)
            self.assertEqual(advice.rejected_reason,
                             "advisor_may_not_confirm", text)

    def test_severity_claims_are_rejected(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION", "rationale": "cvss 9.8 critical"},
            allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)

    def test_fake_execution_text_never_becomes_a_hint(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION",
             "rationale": "payload_execution observed, exploitability "
                          "established, alert(1) fired"},
            allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)
        self.assertEqual(advice.hint_action, "")

    def test_scope_expansion_is_rejected(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION",
             "scope_ref": "watch:scope:other/other.test"},
            allowed_actions=ALLOWED, candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE)
        self.assertFalse(advice.accepted)

    def test_none_response_is_rejected(self):
        advice = ad.validate_chain_advice(None, allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)
        self.assertEqual(advice.rejected_reason, "empty_response")

    def test_non_mapping_response_is_rejected(self):
        advice = ad.validate_chain_advice("confirmed", allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)
        self.assertEqual(advice.rejected_reason, "response_not_a_mapping")

    def test_empty_action_is_rejected(self):
        advice = ad.validate_chain_advice({"next_action": "NONE"},
                                          allowed_actions=ALLOWED)
        self.assertFalse(advice.accepted)
        self.assertEqual(advice.rejected_reason, "no_action_suggested")

    def test_rationale_is_bounded(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION", "rationale": "x" * 5000},
            allowed_actions=ALLOWED)
        self.assertLessEqual(len(advice.rationale), ad.MAX_RATIONALE_CHARS)

    def test_advice_is_json_safe(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION"}, allowed_actions=ALLOWED)
        json.dumps(advice.to_dict(), sort_keys=True)


class TestAdvisorCallable(unittest.TestCase):
    def _state(self):
        return en.evaluate_chain("XSS", inventory_rows(3),
                                 authorization=authorization()).to_dict()

    def test_hint_is_returned_for_an_allowed_action(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION"}))
        hint, meta = advisor(candidate_id=CANDIDATE_ID,
                             chain_state=self._state(),
                             missing_evidence=["REFLECTION_OBSERVED"],
                             allowed_actions=ALLOWED)
        self.assertEqual(hint, "CHECK_REFLECTION")
        self.assertTrue(meta["accepted"])
        self.assertEqual(meta["model_requested"], "openrouter/free")

    def test_provider_exception_is_reported_not_raised(self):
        advisor = ad.make_chain_advisor(advisor_raising(RuntimeError("down")))
        hint, meta = advisor(candidate_id=CANDIDATE_ID,
                             chain_state=self._state(),
                             allowed_actions=ALLOWED)
        self.assertEqual(hint, "")
        self.assertTrue(meta["error"])
        self.assertFalse(meta["accepted"])

    def test_meta_records_the_resolved_model_and_latency(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION",
                               "model": "openrouter/some-free-model",
                               "latency_ms": 812}))
        _hint, meta = advisor(candidate_id=CANDIDATE_ID,
                              chain_state=self._state(), allowed_actions=ALLOWED)
        self.assertEqual(meta["model_resolved"], "openrouter/some-free-model")
        self.assertEqual(meta["latency_ms"], 812)

    def test_advisor_never_returns_a_hint_for_a_rejected_response(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION",
                               "rationale": "confirmed XSS"}))
        hint, meta = advisor(candidate_id=CANDIDATE_ID,
                             chain_state=self._state(),
                             allowed_actions=ALLOWED)
        self.assertEqual(hint, "")
        self.assertEqual(meta["rejected_reason"], "advisor_may_not_confirm")


if __name__ == "__main__":
    unittest.main()

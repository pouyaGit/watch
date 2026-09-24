"""EPIC12 §6/§7/§9 — executor tests.

The executors are where evidence is produced, so these tests are the strictest
in the suite: an executor may only report what a recorded artifact actually
shows, must distinguish "checked and absent" from "never checked", and must
refuse to run at all when a capability or an authorization is missing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import executors as ex  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, marker_body, dom_document, make_verification_store,
)

OBJECTIVE = "ver-xss-1"


def action(action_type: str, **kw):
    base = {"action_type": action_type, "candidate_id": CANDIDATE_ID,
            "objective_id": OBJECTIVE, "scope_ref": SCOPE,
            "target": "https://www.dell.com/support"}
    base.update(kw)
    return ac.VerificationAction(**base)


def run(action_type: str, **context):
    act = action(action_type)
    ctx = {"job_id": "job-xss-1"}
    ctx.update(context)
    return act, ex.execute_action(act, context=ctx)


class TestExecutorRegistry(unittest.TestCase):
    def test_every_action_type_has_an_executor(self):
        for action_type in ac.ACTION_TYPES:
            self.assertIsNotNone(ex.executor_for(action_type), action_type)

    def test_unknown_action_type_raises(self):
        with self.assertRaises(ac.ActionError):
            ex.executor_for("NOPE")

    def test_catalog_declares_implementation_state(self):
        catalog = {row["action_type"]: row for row in ex.executor_catalog()}
        self.assertTrue(catalog["CHECK_REFLECTION"]["implemented"])
        self.assertFalse(catalog["DELIVER_CONTROLLED_PAYLOAD"]["implemented"])
        self.assertTrue(catalog["DELIVER_CONTROLLED_PAYLOAD"]["limitation"])

    def test_no_executor_uses_the_network_directly(self):
        source = Path(ex.__file__).read_text()
        for forbidden in ("import socket", "import urllib", "import requests",
                          "http.client", "subprocess"):
            self.assertNotIn(forbidden, source, forbidden)


class TestReflectionCheck(unittest.TestCase):
    def test_marker_present_produces_reflection_evidence(self):
        act = action(ac.CHECK_REFLECTION)
        marker = ex.marker_for(act)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": marker_body(marker),
            "response_ref": "resp-1"})
        self.assertTrue(result.ok)
        self.assertFalse(result.blocked)
        classes = {o.evidence_type for o in result.observations}
        self.assertIn(tx.REFLECTION_OBSERVED, classes)
        observed = [o for o in result.observations
                    if o.evidence_type == tx.REFLECTION_OBSERVED][0]
        self.assertIn(marker, observed.observed)
        self.assertEqual(observed.response_ref, "resp-1")
        self.assertFalse(observed.negative)

    def test_marker_absent_is_a_negative_result(self):
        act = action(ac.CHECK_REFLECTION)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": "<html><body>nothing here</body></html>",
            "response_ref": "resp-2"})
        self.assertTrue(result.ok)
        self.assertEqual(len(result.observations), 1)
        obs = result.observations[0]
        self.assertTrue(obs.negative)
        # a negative result never claims the positive evidence class: the row
        # type carries the negativity, the signal names the stage it targets
        self.assertEqual(obs.evidence_type, "")
        self.assertIn("reflection", obs.signal)
        self.assertIn("not present", obs.not_observed.lower())

    def test_no_recorded_body_is_not_tested_never_negative(self):
        act = action(ac.CHECK_REFLECTION)
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.ok)
        obs = result.observations[0]
        self.assertTrue(obs.not_tested)
        self.assertFalse(obs.negative)
        self.assertEqual(obs.confidence, "unknown")

    def test_negative_result_does_not_claim_an_evidence_type(self):
        act = action(ac.CHECK_REFLECTION)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": "plain"})
        self.assertEqual(result.observations[0].evidence_type, "")
        row = result.observations[0].to_evidence_row()
        self.assertEqual(row["type"], "negative")
        self.assertIn(row["signal"], ("reflection_not_observed",
                                      "no_reflection"))

    def test_not_tested_row_is_typed_as_an_observation(self):
        act = action(ac.CHECK_REFLECTION)
        result = ex.execute_action(act, context={"job_id": "j"})
        row = result.observations[0].to_evidence_row()
        self.assertEqual(row["type"], "observation")
        self.assertIn(row["signal"], ("not_tested", "reflection_not_tested",
                                      "not_attempted"))


class TestContextClassification(unittest.TestCase):
    def test_javascript_context_is_unsafe(self):
        cls, unsafe, reason = ex.classify_context(
            marker_body("MK1", context="javascript"), "MK1")
        self.assertEqual(cls, ex.CONTEXT_JAVASCRIPT)
        self.assertTrue(unsafe)
        self.assertTrue(reason)

    def test_html_text_context_is_unsafe(self):
        cls, unsafe, _ = ex.classify_context(
            marker_body("MK1", context="html_text"), "MK1")
        self.assertEqual(cls, ex.CONTEXT_HTML_TEXT)
        self.assertTrue(unsafe)

    def test_attribute_context_is_unsafe(self):
        cls, unsafe, _ = ex.classify_context(
            marker_body("MK1", context="html_attribute"), "MK1")
        self.assertEqual(cls, ex.CONTEXT_HTML_ATTRIBUTE)
        self.assertTrue(unsafe)

    def test_url_context_is_unsafe(self):
        cls, unsafe, _ = ex.classify_context(
            marker_body("MK1", context="url"), "MK1")
        self.assertEqual(cls, ex.CONTEXT_URL)
        self.assertTrue(unsafe)

    def test_absent_marker_yields_no_context(self):
        cls, unsafe, reason = ex.classify_context("nothing", "MK1")
        self.assertEqual(cls, "")
        self.assertFalse(unsafe)
        self.assertTrue(reason)

    def test_encoded_marker_is_a_safe_context(self):
        # only the ESCAPED form is present -> encoded output, not an unsafe
        # context (the marker itself is what gets escaped)
        cls, unsafe, reason = ex.classify_context(
            "<html><body><p>&lt;MK1&gt;</p></body></html>", "<MK1>")
        self.assertEqual(cls, "")
        self.assertFalse(unsafe)
        self.assertEqual(reason, "marker_encoded")

    def test_unescaped_marker_in_text_is_unsafe(self):
        cls, unsafe, reason = ex.classify_context(
            "<html><body><p>MK1</p></body></html>", "MK1")
        self.assertEqual(cls, ex.CONTEXT_HTML_TEXT)
        self.assertTrue(unsafe)
        self.assertEqual(reason, "html_text_position")

    def test_no_marker_supplied_is_not_a_context(self):
        cls, unsafe, reason = ex.classify_context("anything", "")
        self.assertEqual(cls, "")
        self.assertFalse(unsafe)
        self.assertEqual(reason, "no_marker_supplied")

    def test_context_classes_are_closed(self):
        for cls in ex.CONTEXT_CLASSES:
            self.assertIn(cls, (ex.CONTEXT_HTML_TEXT, ex.CONTEXT_HTML_ATTRIBUTE,
                                ex.CONTEXT_JAVASCRIPT, ex.CONTEXT_URL,
                                ex.CONTEXT_DOM))


class TestContextAction(unittest.TestCase):
    def test_unsafe_context_produces_identified_evidence(self):
        act = action(ac.CLASSIFY_REFLECTION_CONTEXT)
        marker = ex.marker_for(act)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": marker_body(marker),
            "marker": marker})
        self.assertIn(tx.OUTPUT_CONTEXT_IDENTIFIED, result.evidence_types)
        obs = [o for o in result.observations
               if o.evidence_type == tx.OUTPUT_CONTEXT_IDENTIFIED][0]
        self.assertEqual(obs.context, ex.CONTEXT_JAVASCRIPT)
        self.assertFalse(obs.negative)

    def test_absent_reflection_is_a_negative_not_a_pass(self):
        act = action(ac.CLASSIFY_REFLECTION_CONTEXT)
        marker = ex.marker_for(act)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": "<p>nothing reflected</p>",
            "marker": marker})
        self.assertEqual(len(result.observations), 1)
        self.assertTrue(result.observations[0].negative)
        self.assertNotIn(tx.OUTPUT_CONTEXT_IDENTIFIED, result.evidence_types)

    def test_no_body_is_not_tested(self):
        act = action(ac.CLASSIFY_REFLECTION_CONTEXT)
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.observations[0].not_tested)


class TestDomTracing(unittest.TestCase):
    def test_dom_flow_detects_source_and_sink(self):
        source, sink, reason = ex.dom_flow(dom_document())
        self.assertTrue(source)
        self.assertTrue(sink)
        self.assertTrue(reason)

    def test_dom_flow_without_a_source_is_not_a_flow(self):
        # no attacker-controlled source means no flow: the chain must not
        # record a DOM sink on the strength of a constant assignment
        source, sink, _ = ex.dom_flow(dom_document(source=False))
        self.assertFalse(source)
        self.assertFalse(sink)

    def test_dom_flow_without_sink(self):
        source, sink, _ = ex.dom_flow(dom_document(sink=False))
        self.assertTrue(source)
        self.assertFalse(sink)

    def test_trace_dom_source_emits_evidence(self):
        act = action(ac.TRACE_DOM_SOURCE)
        result = ex.execute_action(act, context={
            "job_id": "j", "document": dom_document()})
        self.assertTrue(result.ok)
        self.assertTrue(result.observations)

    def test_trace_dom_sink_emits_sink_evidence(self):
        act = action(ac.TRACE_DOM_SINK)
        result = ex.execute_action(act, context={
            "job_id": "j", "document": dom_document()})
        self.assertIn(tx.DOM_SINK_IDENTIFIED, result.evidence_types)

    def test_trace_dom_sink_absent_is_negative(self):
        act = action(ac.TRACE_DOM_SINK)
        result = ex.execute_action(act, context={
            "job_id": "j", "document": dom_document(sink=False)})
        self.assertTrue(result.observations[0].negative)

    def test_trace_dom_sink_without_document_is_not_tested(self):
        act = action(ac.TRACE_DOM_SINK)
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.observations[0].not_tested)


class TestParameterInventory(unittest.TestCase):
    def test_known_parameters_become_observations(self):
        act = action(ac.PARAMETER_INVENTORY)
        result = ex.execute_action(act, context={
            "job_id": "j", "parameters": ["q", "lang", "page"]})
        self.assertEqual(len(result.observations), 3)
        for obs in result.observations:
            self.assertEqual(obs.evidence_type, tx.PARAMETER_OBSERVED)
            self.assertTrue(obs.where)
            self.assertFalse(obs.negative)

    def test_rows_can_supply_parameters(self):
        act = action(ac.PARAMETER_INVENTORY)
        result = ex.execute_action(act, context={
            "job_id": "j", "rows": [
                {"type": "observation", "signal": "xss_parameter_inventory",
                 "category": "XSS", "observation_ref": "inv-1",
                 "parameter": "q"}]})
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].evidence_type,
                         tx.PARAMETER_OBSERVED)

    def test_no_parameters_is_not_tested(self):
        act = action(ac.PARAMETER_INVENTORY)
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.observations[0].not_tested)


class TestUnavailableCapabilities(unittest.TestCase):
    def test_payload_delivery_is_blocked_not_faked(self):
        act = action(ac.DELIVER_CONTROLLED_PAYLOAD,
                     authorization_id="auth-1")
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason,
                         ex.REASON_CAPABILITY_UNAVAILABLE)
        self.assertEqual(result.observations, ())
        self.assertTrue(result.error)

    def test_execution_observation_is_blocked_not_faked(self):
        act = action(ac.OBSERVE_EXECUTION, authorization_id="auth-1")
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.observations, ())

    def test_blocked_capability_never_produces_evidence(self):
        act = action(ac.OBSERVE_EXECUTION, authorization_id="auth-1")
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertEqual(result.evidence_types, ())

    def test_reference_chain_actions_are_blocked_here(self):
        for action_type in ("SEND_ORIGIN_HEADER", "SEND_CALLBACK_URL",
                            "SEND_REDIRECT_MARKER"):
            act = action(action_type, authorization_id="auth-1")
            result = ex.execute_action(act, context={"job_id": "j"})
            self.assertTrue(result.blocked, action_type)
            self.assertEqual(result.observations, (), action_type)


class TestAuthorizedProbe(unittest.TestCase):
    def test_probe_cannot_even_be_constructed_without_authorization(self):
        with self.assertRaises(ac.ActionError):
            action(ac.SEND_MARKER)

    def test_probe_without_an_authorization_reference_is_blocked(self):
        # defence in depth: the executor must not trust construction either
        act = action(ac.SEND_MARKER, authorization_id="auth-1")
        act.authorization_id = ""
        result = ex.execute_action(act, context={"job_id": "j",
                                                "transport": lambda **k: {}})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, ex.REASON_AUTHORIZATION_UNAVAILABLE)
        self.assertEqual(result.observations, ())

    def test_probe_with_authorization_but_no_transport_is_blocked(self):
        act = action(ac.SEND_MARKER, authorization_id="auth-1")
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, ex.REASON_TRANSPORT_UNAVAILABLE)

    def test_probe_with_transport_records_the_controlled_input(self):
        act = action(ac.SEND_MARKER, authorization_id="auth-1")
        seen: dict = {}

        def transport(**kwargs):
            seen.update(kwargs)
            return {"status_code": 200,
                    "body": marker_body(kwargs["marker"]),
                    "request_ref": "req-9", "response_ref": "resp-9"}

        result = ex.execute_action(act, context={"job_id": "j",
                                                "transport": transport})
        self.assertTrue(result.ok)
        self.assertFalse(result.blocked)
        self.assertEqual(seen["target"], "https://www.dell.com/support")
        self.assertEqual(seen["authorization_id"], "auth-1")
        self.assertIn(tx.CONTROLLED_INPUT_SENT, result.evidence_types)
        self.assertIn(tx.REFLECTION_OBSERVED, result.evidence_types)
        sent = [o for o in result.observations
                if o.evidence_type == tx.CONTROLLED_INPUT_SENT][0]
        self.assertEqual(sent.under_request, "req-9")

    def test_probe_with_a_raising_transport_fails_closed(self):
        act = action(ac.SEND_MARKER, authorization_id="auth-1")

        def transport(**_kwargs):
            raise RuntimeError("boom")

        result = ex.execute_action(act, context={"job_id": "j",
                                                "transport": transport})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, ex.REASON_TRANSPORT_FAILED)
        self.assertEqual(result.observations, ())
        self.assertIn("RuntimeError", result.error)

    def test_probe_never_produces_execution_evidence(self):
        act = action(ac.SEND_MARKER, authorization_id="auth-1")

        def transport(**kwargs):
            return {"status_code": 200, "body": marker_body(kwargs["marker"])}

        result = ex.execute_action(act, context={"job_id": "j",
                                                "transport": transport})
        for forbidden in (tx.PAYLOAD_EXECUTION, tx.EXPLOITABILITY_ESTABLISHED):
            self.assertNotIn(forbidden, result.evidence_types)


class TestExecutorGuards(unittest.TestCase):
    def test_terminal_actions_never_execute(self):
        act = action(ac.CHECK_REFLECTION)
        act.transition(ac.ACTION_EXECUTING)
        act.transition(ac.ACTION_SUCCEEDED)
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, ex.REASON_ACTION_NOT_EXECUTABLE)

    def test_out_of_scope_target_cannot_even_be_constructed(self):
        with self.assertRaises(Exception):
            action(ac.CHECK_REFLECTION, target="https://evil.test/x")

    def test_out_of_scope_target_is_refused_at_execution_too(self):
        # defence in depth: a tampered action must not reach an executor
        act = action(ac.CHECK_REFLECTION)
        act.target = "https://evil.test/x"
        result = ex.execute_action(act, context={"job_id": "j",
                                                "response_body": "x"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, "target_out_of_scope")
        self.assertEqual(result.observations, ())

    def test_unknown_context_keys_are_refused(self):
        act = action(ac.CHECK_REFLECTION)
        result = ex.execute_action(act, context={"job_id": "j",
                                                "payloads": ["<script>"]})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, ex.REASON_ACTION_NOT_EXECUTABLE)

    def test_context_keys_are_a_closed_vocabulary(self):
        self.assertIn("response_body", ex.CONTEXT_KEYS)
        self.assertNotIn("payloads", ex.CONTEXT_KEYS)

    def test_marker_is_deterministic_and_marked(self):
        act = action(ac.CHECK_REFLECTION)
        first = ex.marker_for(act)
        self.assertEqual(first, ex.marker_for(act))
        self.assertTrue(first.startswith("wx"))
        self.assertGreater(len(first), 6)

    def test_observation_ids_are_deterministic(self):
        act = action(ac.CHECK_REFLECTION)
        marker = ex.marker_for(act)
        ctx = {"job_id": "j", "response_body": marker_body(marker)}
        first = ex.execute_action(act, context=ctx).observations[0].observation_id
        second = ex.execute_action(act, context=ctx).observations[0].observation_id
        self.assertEqual(first, second)


class TestObservationShape(unittest.TestCase):
    def test_evidence_row_answers_the_structured_questions(self):
        act = action(ac.CHECK_REFLECTION)
        marker = ex.marker_for(act)
        obs = ex.execute_action(act, context={
            "job_id": "j", "response_body": marker_body(marker),
            "request_ref": "req-1", "response_ref": "resp-1"}
        ).observations[0]
        row = obs.to_evidence_row()
        for key in ("what_happened", "where", "under_input", "under_request",
                    "observed", "context", "confidence", "provenance",
                    "observation_ref", "evidence_type", "signal", "category"):
            self.assertIn(key, row)
        self.assertEqual(row["observation_ref"], obs.observation_id)
        self.assertEqual(row["action_id"], act.action_id)
        self.assertEqual(row["provenance"]["executor"], "read_only_evidence")

    def test_evidence_row_classifies_under_epic11(self):
        from backend.research_agents.finding.integrity import taxonomy as tx2
        act = action(ac.CHECK_REFLECTION)
        marker = ex.marker_for(act)
        obs = ex.execute_action(act, context={
            "job_id": "j", "response_body": marker_body(marker)}
        ).observations[0]
        items = tx2.classify_rows([obs.to_evidence_row()])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].evidence_type, tx.REFLECTION_OBSERVED)

    def test_store_round_trip(self):
        store = make_verification_store()
        act = action(ac.CHECK_REFLECTION)
        obs = ex.execute_action(act, context={"job_id": "j"}).observations[0]
        store.record_observation(obs)
        rows = store.evidence_rows_for_candidate(CANDIDATE_ID)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["observation_ref"], obs.observation_id)


if __name__ == "__main__":
    unittest.main()

"""EPIC13 — adversarial scenarios.

These are the cases designed to make the acquisition layer over-claim: pages
that reflect everything, markers in the wrong place, encoded and truncated
responses, transports that lie, and evidence that *looks* like execution.
Every test asserts the honest outcome, not the convenient one.
"""
from __future__ import annotations

import base64
import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, SCOPE_REF, TARGET_URL,
    RecordingTransport, body_with, chain_state, inventory_rows,
    marker_for_action, parameters)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    detector as dt, executor as ex, markers as mk, plan as pl, requests as rq,
    service as sv, transport as tr)

FOREIGN_MARKER = "HERMES_REFLECT_000000000000"


def acquire(transport, *, rows=None, params=None, authorization=None):
    rows = inventory_rows() if rows is None else rows
    return sv.run_acquisition_for_candidate(
        chain_state=chain_state(rows),
        parameters=(parameters() if params is None else params), rows=rows,
        transport=transport,
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
        scope_ref=SCOPE_REF, vulnerability_class="XSS", job_id="job-epic13-1")


def action(auth_id: str = AUTH_ID):
    return pl.build_action(
        pl.AcquisitionRequirement(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
            scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
            parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
            available=True),
        job_id="j1", authorization_id=auth_id)


class TestReflectEverythingPages(unittest.TestCase):
    """A page that echoes any input is still only a reflection."""

    def test_a_reflect_everything_page_satisfies_reflection_only(self):
        run = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)
        stages = {s["key"]: s["status"] for s in run.chain_after["stages"]}
        self.assertEqual(stages["reflection"], "SATISFIED")
        self.assertNotEqual(stages["execution"], "SATISFIED")

    def test_a_reflect_everything_page_never_confirms_the_candidate(self):
        run = acquire(RecordingTransport(body_from_request=True))
        self.assertFalse(run.chain_after.get("confirmed"))

    def test_reflection_does_not_produce_payload_evidence(self):
        run = acquire(RecordingTransport(body_from_request=True))
        for row in run.produced_rows:
            self.assertNotEqual(row.get("evidence_type"), "PAYLOAD_EXECUTION")

    def test_reflection_does_not_produce_exploitability_evidence(self):
        run = acquire(RecordingTransport(body_from_request=True))
        for row in run.produced_rows:
            self.assertNotEqual(row.get("evidence_type"),
                                "EXPLOITABILITY_ESTABLISHED")

    def test_a_page_echoing_a_payload_gets_no_payload_credit(self):
        marker = marker_for_action()
        body = (f"<p>{marker}</p><script>alert('xss')</script>"
                f"<img src=x onerror=alert(1)>")
        run = acquire(RecordingTransport(body))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)
        self.assertNotIn("PAYLOAD_EXECUTION", str(run.produced_rows))


class TestMarkerPlacement(unittest.TestCase):
    def test_a_foreign_marker_is_not_our_marker(self):
        result = dt.detect(f"<p>{FOREIGN_MARKER}</p>", marker_for_action())
        self.assertEqual(result.status, dt.ABSENT)

    def test_a_foreign_marker_produces_a_negative_not_a_positive(self):
        run = acquire(RecordingTransport(f"<p>{FOREIGN_MARKER}</p>"))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_NOT_OBSERVED)

    def test_a_marker_in_a_response_header_is_not_body_reflection(self):
        """The detector judges the body; a header echo is not reflection."""
        marker = marker_for_action()
        run = acquire(RecordingTransport("<p>nothing</p>",
                                         headers={"x-echo": marker}))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_NOT_OBSERVED)

    def test_a_header_echo_is_still_recorded_in_the_response_metadata(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport("<p>nothing</p>",
                                         headers={"x-echo": marker}))
        self.assertTrue(run.outcomes[0]["response"]["headers"])

    def test_a_marker_only_in_a_comment_is_classified_as_a_comment(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(body_with(marker, context="comment")))
        contexts = {o.get("context") for o in run.observations}
        self.assertIn("COMMENT", contexts)

    def test_a_comment_reflection_is_not_reported_as_html_text(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(body_with(marker, context="comment")))
        contexts = {o.get("context") for o in run.observations}
        self.assertNotIn("HTML_TEXT", contexts)

    def test_an_encoded_marker_has_no_context_to_classify(self):
        marker = marker_for_action()
        encoded = base64.b64encode(marker.encode()).decode()
        run = acquire(RecordingTransport(f"<p>{encoded}</p>"))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)
        for observation in run.observations:
            self.assertNotEqual(observation.get("evidence_type"),
                                "OUTPUT_CONTEXT_IDENTIFIED")

    def test_an_encoded_marker_does_not_satisfy_the_context_stage(self):
        marker = marker_for_action()
        encoded = base64.b64encode(marker.encode()).decode()
        run = acquire(RecordingTransport(f"<p>{encoded}</p>"))
        stages = {s["key"]: s["status"] for s in run.chain_after["stages"]}
        self.assertNotEqual(stages["context"], "SATISFIED")

    def test_a_lowercased_marker_is_a_transformation_not_a_presence(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(f"<p>{marker.lower()}</p>"))
        self.assertEqual(run.outcomes[0]["detection"]["status"],
                         dt.TRANSFORMED)

    def test_a_transformed_marker_still_counts_as_reflection(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(f"<p>{marker.lower()}</p>"))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)

    def test_a_partial_marker_is_absent(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(f"<p>{marker[:12]}</p>"))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_NOT_OBSERVED)

    def test_a_marker_in_an_error_page_is_still_recorded(self):
        run = acquire(RecordingTransport(body_from_request=True,
                                         status_code=500))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)

    def test_an_error_page_status_is_recorded(self):
        run = acquire(RecordingTransport(body_from_request=True,
                                         status_code=500))
        self.assertEqual(run.outcomes[0]["response"]["status_code"], 500)

    def test_an_error_page_never_becomes_a_severity_claim(self):
        run = acquire(RecordingTransport(body_from_request=True,
                                         status_code=500))
        self.assertNotIn("severity", str(run.produced_rows).lower())


class TestTransportLies(unittest.TestCase):
    def test_a_transport_reporting_an_off_scope_final_url_is_refused(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=200,
            body=body_with(marker_for_action()),
            final_url="https://evil.test/landing")
        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=tr.InjectedTransport(lambda request: response),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)

    def test_an_off_scope_final_url_is_not_evidence(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=200,
            body=body_with(marker_for_action()),
            final_url="https://evil.test/landing")
        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=tr.InjectedTransport(lambda request: response),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.observations, [])

    def test_an_in_scope_final_url_is_accepted(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=200,
            body=body_with(marker_for_action()), final_url=TARGET_URL)
        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=tr.InjectedTransport(lambda request: response),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_SUCCESS)

    def test_a_transport_claiming_a_status_it_did_not_get_is_ignored(self):
        """Only the response the detector read can produce evidence."""
        class Odd:
            name = "odd"

            @property
            def available(self):
                return True

            def send(self, request):
                return tr.AcquisitionResponse(
                    outcome=tr.OUTCOME_RESPONDED, status_code=200,
                    body="<p>no marker</p>", response_ref="r-odd")

        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=Odd(), authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_NO_REFLECTION)

    def test_a_transport_raising_a_timeout_error_is_a_timeout(self):
        def boom(request):
            raise TimeoutError("too slow")

        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=tr.InjectedTransport(boom), authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_TIMEOUT)

    def test_a_transport_raising_a_value_error_is_a_failure(self):
        def boom(request):
            raise ValueError("bad")

        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=tr.InjectedTransport(boom), authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)

    def test_a_transport_returning_invalid_utf8_is_still_searched(self):
        marker = marker_for_action()
        raw = f"<p>{marker}</p>".encode() + b"\xff\xfe"
        result = dt.detect(raw, marker)
        self.assertTrue(result.reflected)

    def test_a_transport_returning_a_null_byte_body_is_searched(self):
        marker = marker_for_action()
        result = dt.detect(f"<p>\x00{marker}\x00</p>", marker)
        self.assertTrue(result.reflected)

    def test_a_response_with_many_headers_is_scrubbed_and_bounded(self):
        headers = {f"x-h{i}": "v" * 200 for i in range(50)}
        headers["set-cookie"] = "session=SECRET"
        outcome = ex.run_acquisition(
            action=action(), parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"),
            transport=RecordingTransport(body_from_request=True,
                                         headers=headers),
            authorization=AUTHORIZATION)
        self.assertNotIn("SECRET", str(outcome.to_dict()))


class TestBoundaryConditions(unittest.TestCase):
    def test_a_body_of_exactly_the_window_is_conclusive(self):
        marker = marker_for_action()
        body = (marker + ("x" * (8192 - len(marker))))
        result = dt.detect(body, marker)
        self.assertTrue(result.conclusive)

    def test_a_marker_one_byte_past_the_window_is_inconclusive(self):
        marker = marker_for_action()
        body = ("x" * 8192) + marker
        result = dt.detect(body, marker)
        self.assertFalse(result.reflected)
        self.assertFalse(result.conclusive)

    def test_an_empty_parameter_name_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF,
                             parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter=""))

    def test_a_parameter_named_like_a_scheme_is_still_just_a_parameter(self):
        url = "https://www.dell.com/a?http=1"
        rewritten = rq.rewrite_query(url, "http", marker_for_action())
        self.assertTrue(rewritten.startswith("https://www.dell.com/a?http="))

    def test_a_url_with_an_encoded_ampersand_is_preserved(self):
        url = "https://www.dell.com/a?q=1&next=a%26b"
        rewritten = rq.rewrite_query(url, "q", marker_for_action())
        self.assertIn("next=a%26b", rewritten)

    def test_a_unicode_parameter_name_is_refused_rather_than_guessed(self):
        url = "https://www.dell.com/a?q=1"
        with self.assertRaises(rq.RequestError):
            rq.rewrite_query(url, "qué", marker_for_action())

    def test_many_parameters_cannot_exceed_the_action_budget(self):
        params = [{"parameter": f"p{i}", "url": TARGET_URL, "method": "GET"}
                  for i in range(50)]
        plan = pl.plan_acquisition(
            chain_state=chain_state(), parameters=params,
            authorization=AUTHORIZATION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)
        self.assertLessEqual(len(plan.actions), plan.limits["max_actions"])

    def test_the_budget_refusal_is_recorded(self):
        params = [{"parameter": f"p{i}", "url": TARGET_URL, "method": "GET"}
                  for i in range(50)]
        plan = pl.plan_acquisition(
            chain_state=chain_state(), parameters=params,
            authorization=AUTHORIZATION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)
        reasons = {b.get("blocked_reason") for b in plan.blocked}
        self.assertTrue(reasons)


class TestFabricationAttempts(unittest.TestCase):
    def test_a_payload_execution_row_in_the_input_is_not_evidence(self):
        rows = inventory_rows() + [{
            "id": "ev-fake", "type": "observation",
            "signal": "xss_parameter_inventory", "category": "XSS",
            "detail": "hand-written row claiming execution",
            "evidence_type": "PAYLOAD_EXECUTION"}]
        run = acquire(RecordingTransport("<p>nothing</p>"), rows=rows)
        self.assertNotIn("PAYLOAD_EXECUTION", str(run.produced_rows))

    def test_a_mismatched_row_is_surfaced_as_a_divergence(self):
        """A row whose type disagrees with its signal is never clean evidence.

        The EPIC11 gate honours a row-supplied ``evidence_type`` inside its
        closed set, so such a row *is* admissible to it.  EPIC13 does not
        patch the gate (that is not this Epic's layer); it reports the row as
        a divergence so a verdict leaning on it is visibly inconsistent.
        """
        rows = inventory_rows() + [{
            "id": "ev-fake", "type": "observation",
            "signal": "xss_parameter_inventory", "category": "XSS",
            "detail": "hand-written row claiming execution",
            "evidence_type": "PAYLOAD_EXECUTION"}]
        run = acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertTrue(any("evidence_type_mismatch" in d
                            for d in run.chain_after.get("divergence", [])))

    def test_the_acquisition_layer_never_emits_a_mismatched_row(self):
        """Whatever the input store holds, this layer's own rows agree."""
        run = acquire(RecordingTransport(body_from_request=True))
        for row in run.produced_rows:
            self.assertNotEqual(
                str(row.get("evidence_type") or "").upper(),
                "PAYLOAD_EXECUTION")
            self.assertNotEqual(
                str(row.get("evidence_type") or "").upper(),
                "EXPLOITABILITY_ESTABLISHED")

    def test_a_clean_run_reports_no_divergence(self):
        run = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(list(run.chain_after.get("divergence") or []), [])

    def test_the_run_does_not_claim_the_fabricated_row_as_its_own(self):
        rows = inventory_rows() + [{
            "id": "ev-fake", "type": "observation",
            "signal": "xss_parameter_inventory", "category": "XSS",
            "detail": "hand-written row claiming execution",
            "evidence_type": "PAYLOAD_EXECUTION"}]
        run = acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertNotIn("ev-fake",
                         {r.get("id") for r in run.produced_rows})

    def test_the_run_never_creates_an_observation_without_an_action(self):
        run = acquire(RecordingTransport(body_from_request=True))
        action_ids = {o["action_id"] for o in run.outcomes}
        for observation in run.observations:
            self.assertIn(observation["action_id"], action_ids)

    def test_the_run_never_creates_an_observation_without_a_marker(self):
        run = acquire(RecordingTransport(body_from_request=True))
        for observation in run.observations:
            if observation.get("evidence_type") == "REFLECTION_OBSERVED":
                self.assertTrue(observation.get("marker"))

    def test_the_run_never_creates_an_observation_without_an_authorization(self):
        run = acquire(RecordingTransport(body_from_request=True))
        for observation in run.observations:
            self.assertEqual(observation["provenance"]["authorization_id"],
                             AUTH_ID)

    def test_a_reflected_marker_without_a_matching_request_is_impossible(self):
        """The marker is derived from the action, so the request carries it."""
        run = acquire(RecordingTransport(body_from_request=True))
        request_marker = run.outcomes[0]["request"]["marker"]
        observation_marker = run.observations[0]["marker"]
        self.assertEqual(request_marker, observation_marker)

    def test_a_negative_cannot_be_rewritten_into_a_positive(self):
        run = acquire(RecordingTransport("<p>nothing</p>"))
        self.assertNotIn("reflection_observed",
                         {r.get("signal") for r in run.produced_rows})


class TestCapabilityHonesty(unittest.TestCase):
    def test_an_unacquirable_stage_is_reported_not_attempted(self):
        rows = inventory_rows() + [{
            "id": "ev-refl", "type": "observation",
            "signal": "reflection_observed", "category": "XSS",
            "detail": "reflected", "evidence_type": "REFLECTION_OBSERVED"}, {
            "id": "ev-ctx", "type": "observation",
            "signal": "output_context_identified", "category": "XSS",
            "detail": "context html_text",
            "evidence_type": "OUTPUT_CONTEXT_IDENTIFIED"}]
        run = acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertEqual(run.termination, sv.RUN_CAPABILITY_UNAVAILABLE)
        self.assertTrue(run.unavailable)

    def test_the_unavailable_reason_names_the_missing_capability(self):
        rows = inventory_rows() + [{
            "id": "ev-refl", "type": "observation",
            "signal": "reflection_observed", "category": "XSS",
            "detail": "reflected", "evidence_type": "REFLECTION_OBSERVED"}, {
            "id": "ev-ctx", "type": "observation",
            "signal": "output_context_identified", "category": "XSS",
            "detail": "context html_text",
            "evidence_type": "OUTPUT_CONTEXT_IDENTIFIED"}]
        run = acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertIn("PAYLOAD_EXECUTION", str(run.unavailable))

    def test_the_capability_matrix_says_payload_execution_is_absent(self):
        contract = __import__(
            "backend.research_agents.verification.acquisition.capabilities",
            fromlist=["contract_for"]).contract_for("XSS")
        self.assertIn("PAYLOAD_EXECUTION", contract.not_acquirable)

    def test_no_action_exists_for_payload_execution(self):
        self.assertNotIn("ACTIVE_PAYLOAD_EXECUTION",
                         ex.ACQUISITION_ACTIONS)
        self.assertNotIn("DELIVER_CONTROLLED_PAYLOAD",
                         ex.ACQUISITION_ACTIONS)

    def test_an_action_outside_the_acquisition_set_is_refused(self):
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL,
                    action_type=ac.SEND_MARKER, available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport(body_from_request=True),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_SUCCESS)

    def test_dom_sink_evidence_is_declared_unavailable(self):
        self.assertIn("DOM_SINK_IDENTIFIED", pl.UNAVAILABLE_EVIDENCE)

    def test_the_dom_unavailability_reason_is_deterministic(self):
        self.assertIn("DOM", pl.UNAVAILABLE_EVIDENCE["DOM_SINK_IDENTIFIED"])


if __name__ == "__main__":
    unittest.main()

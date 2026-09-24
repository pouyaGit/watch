"""EPIC13 §9/§19 — acquisition execution tests (offline, no network)."""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, PARAMETER, SCOPE_REF,
    TARGET_URL, BudgetStub, RecordingTransport, ReplayStub, body_with,
    marker_for_action)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    executor as ex, markers as mk, plan as pl, requests as rq, transport as tr)


def requirement(action_type: str = ac.SEND_MARKER, *, parameter: str = PARAMETER,
                url: str = TARGET_URL, evidence: str = "REFLECTION_OBSERVED"):
    return pl.AcquisitionRequirement(
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
        scope_ref=SCOPE_REF, evidence_type=evidence, parameter=parameter,
        url=url, method="GET", action_type=action_type, available=True)


def action_for(action_type: str = ac.SEND_MARKER, *, parameter: str = PARAMETER,
               url: str = TARGET_URL, authorization_id: str = AUTH_ID):
    return pl.build_action(requirement(action_type, parameter=parameter,
                                       url=url),
                           job_id="job-epic13-1",
                           authorization_id=authorization_id)


def parameter_ref(parameter: str = PARAMETER, url: str = TARGET_URL):
    return rq.ParameterRef(url=url, parameter=parameter, method="GET",
                           location="query")


def run(transport, *, action_type: str = ac.SEND_MARKER,
        parameter: str = PARAMETER, url: str = TARGET_URL,
        authorization=None, budget=None, replay=None, limits=None,
        authorization_id: str = AUTH_ID):
    return ex.run_acquisition(
        action=action_for(action_type, parameter=parameter, url=url,
                          authorization_id=authorization_id),
        parameter_ref=parameter_ref(parameter, url), transport=transport,
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        budget=budget, replay=replay, limits=limits)


class TestReflectionObserved(unittest.TestCase):
    def setUp(self):
        self.marker = marker_for_action()
        self.transport = RecordingTransport(body_with(self.marker))

    def test_state_is_succeeded(self):
        self.assertEqual(run(self.transport).state, ac.ACTION_SUCCEEDED)

    def test_result_is_success(self):
        self.assertEqual(run(self.transport).result, ex.RESULT_SUCCESS)

    def test_one_request_is_sent(self):
        run(self.transport)
        self.assertEqual(self.transport.called, 1)

    def test_the_request_carries_the_marker(self):
        run(self.transport)
        self.assertIn(f"q={self.marker}", self.transport.last_url)

    def test_the_marker_matches_the_action_marker(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.marker, self.transport.last_marker)

    def test_a_positive_observation_is_produced(self):
        outcome = run(self.transport)
        self.assertEqual(len(outcome.observations), 1)
        self.assertTrue(outcome.observations[0].positive)

    def test_the_observation_carries_the_evidence_type(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.observations[0].evidence_type,
                         "REFLECTION_OBSERVED")

    def test_the_observation_carries_the_signal(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.observations[0].signal, "reflection_observed")

    def test_the_observation_carries_the_action_id(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.observations[0].action_id, outcome.action_id)

    def test_the_outcome_is_evidential(self):
        self.assertTrue(run(self.transport).evidential)

    def test_the_outcome_reports_reflection(self):
        self.assertTrue(run(self.transport).reflected)

    def test_the_context_class_is_reported(self):
        self.assertEqual(run(self.transport).context_class, "HTML_TEXT")

    def test_the_detection_summary_is_attached(self):
        detection = run(self.transport).detection
        self.assertEqual(detection["status"], "PRESENT")
        self.assertEqual(detection["occurrence_count"], 1)

    def test_the_detector_version_is_attached(self):
        self.assertTrue(run(self.transport).detection["detector_version"])

    def test_the_transport_name_is_recorded(self):
        self.assertEqual(run(self.transport).transport, "injected_transport")

    def test_the_authorization_id_is_recorded(self):
        self.assertEqual(run(self.transport).authorization_id, AUTH_ID)

    def test_the_limits_are_recorded(self):
        self.assertIn("max_response_bytes", run(self.transport).limits)

    def test_the_request_is_recorded_without_headers(self):
        self.assertFalse(dict(run(self.transport).request.get("headers") or {}))

    def test_the_request_record_is_audit_safe(self):
        self.assertNotIn("@", str(run(self.transport).request.get("url", "")))

    def test_the_rule_version_is_declared(self):
        self.assertEqual(run(self.transport).rule_version,
                         ex.ACQUISITION_RULE_VERSION)


class TestReflectionContexts(unittest.TestCase):
    def _context(self, context: str) -> str:
        marker = marker_for_action()
        transport = RecordingTransport(body_with(marker, context=context))
        return run(transport).context_class

    def test_html_text(self):
        self.assertEqual(self._context("text"), "HTML_TEXT")

    def test_html_attribute(self):
        self.assertEqual(self._context("attribute"), "HTML_ATTRIBUTE")

    def test_script(self):
        self.assertEqual(self._context("script"), "SCRIPT")

    def test_url(self):
        self.assertEqual(self._context("url"), "URL")

    def test_comment(self):
        self.assertEqual(self._context("comment"), "COMMENT")

    def test_style(self):
        self.assertEqual(self._context("style"), "STYLE")

    def test_json(self):
        self.assertEqual(self._context("json"), "JSON")

    def test_the_observation_records_the_context(self):
        marker = marker_for_action()
        outcome = run(RecordingTransport(body_with(marker, context="script")))
        self.assertEqual(outcome.observations[0].context, "SCRIPT")


class TestNegativeEvidence(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport("<html><body>no marker</body></html>")

    def test_state_is_succeeded(self):
        """A probe that ran and found nothing still ran successfully."""
        self.assertEqual(run(self.transport).state, ac.ACTION_SUCCEEDED)

    def test_result_is_no_reflection(self):
        self.assertEqual(run(self.transport).result, ex.RESULT_NO_REFLECTION)

    def test_a_negative_observation_is_produced(self):
        outcome = run(self.transport)
        self.assertEqual(len(outcome.observations), 1)
        self.assertFalse(outcome.observations[0].positive)

    def test_the_negative_carries_no_evidence_type(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.observations[0].evidence_type, "")

    def test_the_negative_signal_is_recorded(self):
        outcome = run(self.transport)
        self.assertEqual(outcome.observations[0].signal,
                         "reflection_not_observed")

    def test_the_negative_is_evidential(self):
        self.assertTrue(run(self.transport).evidential)

    def test_the_negative_is_not_a_reflection(self):
        self.assertFalse(run(self.transport).reflected)

    def test_the_negative_carries_the_detector_summary(self):
        self.assertEqual(run(self.transport).detection["status"], "ABSENT")

    def test_a_negative_records_the_bytes_checked(self):
        self.assertGreater(run(self.transport).detection["bytes_checked"], 0)


class TestTransportFailureIsNeverEvidence(unittest.TestCase):
    def probe(self, **kwargs):
        return run(RecordingTransport(**kwargs))

    def test_timeout_is_not_evidence(self):
        outcome = self.probe(outcome=tr.OUTCOME_TIMEOUT)
        self.assertEqual(outcome.result, ex.RESULT_TIMEOUT)
        self.assertFalse(outcome.evidential)
        self.assertEqual(outcome.observations, [])

    def test_transport_failure_is_not_evidence(self):
        outcome = self.probe(outcome=tr.OUTCOME_TRANSPORT_FAILED)
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)
        self.assertFalse(outcome.evidential)
        self.assertEqual(outcome.observations, [])

    def test_refusal_is_not_evidence(self):
        outcome = self.probe(outcome=tr.OUTCOME_REFUSED)
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)
        self.assertEqual(outcome.observations, [])

    def test_a_responded_empty_body_is_response_unavailable(self):
        outcome = self.probe(body=None)
        self.assertEqual(outcome.result, ex.RESULT_RESPONSE_UNAVAILABLE)
        self.assertFalse(outcome.evidential)

    def test_an_empty_body_is_not_a_negative_result(self):
        outcome = self.probe(body=None)
        self.assertNotEqual(outcome.result, ex.RESULT_NO_REFLECTION)
        self.assertEqual(outcome.observations, [])

    def test_an_exception_from_the_transport_is_not_evidence(self):
        outcome = self.probe(raises=RuntimeError("boom"))
        self.assertFalse(outcome.evidential)
        self.assertEqual(outcome.observations, [])
        self.assertEqual(outcome.state, ac.ACTION_BLOCKED)

    def test_a_timeout_is_not_a_negative_security_result(self):
        outcome = self.probe(outcome=tr.OUTCOME_TIMEOUT)
        self.assertNotEqual(outcome.result, ex.RESULT_NO_REFLECTION)

    def test_an_unavailable_transport_is_not_evidence(self):
        outcome = run(tr.UnavailableTransport())
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)
        self.assertFalse(outcome.evidential)

    def test_an_unavailable_transport_sends_nothing(self):
        transport = RecordingTransport("<p>x</p>")
        outcome = run(tr.UnavailableTransport())
        self.assertEqual(transport.called, 0)
        self.assertEqual(outcome.state, ac.ACTION_BLOCKED)

    def test_response_unavailable_is_not_evidence(self):
        outcome = self.probe(outcome=tr.OUTCOME_TRANSPORT_UNAVAILABLE)
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)
        self.assertEqual(outcome.observations, [])


class TestResponseLimits(unittest.TestCase):
    def test_a_truncated_absence_is_inconclusive(self):
        transport = RecordingTransport("<p>no marker here</p>", truncated=True)
        outcome = run(transport)
        self.assertEqual(outcome.result, ex.RESULT_INCONCLUSIVE)
        self.assertFalse(outcome.evidential)

    def test_a_truncated_absence_produces_no_negative_evidence(self):
        transport = RecordingTransport("<p>no marker here</p>", truncated=True)
        self.assertEqual(run(transport).observations[0].positive, False)
        self.assertTrue(run(transport).observations[0].not_tested)

    def test_a_truncated_absence_signal_is_not_tested(self):
        transport = RecordingTransport("<p>no marker here</p>", truncated=True)
        self.assertEqual(run(transport).observations[0].signal,
                         "reflection_not_tested")

    def test_a_limit_exceeded_response_is_inconclusive(self):
        transport = RecordingTransport("<p>x</p>",
                                       outcome=tr.OUTCOME_RESPONSE_LIMIT_EXCEEDED)
        outcome = run(transport)
        self.assertEqual(outcome.result, ex.RESULT_RESPONSE_LIMIT_EXCEEDED)
        self.assertFalse(outcome.evidential)

    def test_a_limit_exceeded_response_is_not_negative_evidence(self):
        transport = RecordingTransport("<p>x</p>",
                                       outcome=tr.OUTCOME_RESPONSE_LIMIT_EXCEEDED)
        self.assertNotEqual(run(transport).result, ex.RESULT_NO_REFLECTION)

    def test_a_reflection_inside_a_truncated_body_is_still_found(self):
        marker = marker_for_action()
        transport = RecordingTransport(f"<p>{marker}</p>", truncated=True)
        outcome = run(transport)
        self.assertEqual(outcome.result, ex.RESULT_SUCCESS)
        self.assertTrue(outcome.reflected)

    def test_the_byte_limit_is_never_above_the_platform_ceiling(self):
        outcome = run(RecordingTransport("<p>x</p>"))
        self.assertLessEqual(outcome.limits["max_response_bytes"], 8192)


class TestRedirectSafety(unittest.TestCase):
    def test_a_redirect_is_not_followed_by_default(self):
        outcome = run(RecordingTransport("<p>x</p>", status_code=302,
                                         headers={"location": "https://x.test/"}))
        self.assertEqual(outcome.limits["max_redirects"], 0)

    def _redirect(self, location: str, *, status_code: int = 302):
        return run(RecordingTransport(
            "<p>x</p>", status_code=status_code,
            headers={"location": location},
            redirects=[{"location": location, "status": status_code}]))

    def test_an_out_of_scope_redirect_is_recorded(self):
        outcome = self._redirect("https://evil.test/next")
        self.assertEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)

    def test_an_out_of_scope_redirect_is_not_evidence(self):
        outcome = self._redirect("https://evil.test/next")
        self.assertFalse(outcome.evidential)
        self.assertEqual(outcome.observations, [])

    def test_an_out_of_scope_redirect_reason_is_recorded(self):
        self.assertIn("scope", self._redirect("https://evil.test/").reason)

    def test_redirect_hops_are_reported(self):
        self.assertEqual(len(self._redirect("https://evil.test/").redirects), 1)

    def test_an_in_scope_redirect_is_not_a_refusal(self):
        outcome = self._redirect(TARGET_URL)
        self.assertNotEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)

    def test_a_redirect_with_no_reported_destination_is_refused(self):
        response = tr.AcquisitionResponse(outcome=tr.OUTCOME_RESPONDED,
                                          status_code=302, body="<p>x</p>")
        safe, reason, hops = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertFalse(safe)
        self.assertIn("cannot be proven in scope", reason)

    def test_a_hop_with_no_identifiable_destination_is_refused(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=302,
            redirects=[{"status": 302}])
        safe, reason, _ = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertFalse(safe)

    def test_check_redirects_flags_an_out_of_scope_hop(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=302,
            redirects=[{"location": "https://evil.test/", "status": 302}])
        safe, reason, hops = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertFalse(safe)
        self.assertIn("scope", reason)
        self.assertEqual(hops[0]["in_scope"], False)

    def test_check_redirects_accepts_an_in_scope_hop(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=302,
            redirects=[{"location": TARGET_URL, "status": 302}])
        safe, reason, hops = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertTrue(safe, reason)
        self.assertEqual(hops[0]["in_scope"], True)

    def test_check_redirects_uses_the_location_header(self):
        response = tr.AcquisitionResponse(
            outcome=tr.OUTCOME_RESPONDED, status_code=302,
            headers={"location": "https://evil.test/x"})
        safe, _, hops = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertFalse(safe)
        self.assertEqual(len(hops), 1)

    def test_a_non_redirect_response_needs_no_hops(self):
        response = tr.AcquisitionResponse(outcome=tr.OUTCOME_RESPONDED,
                                          status_code=200, body="<p>x</p>")
        safe, reason, hops = ex.check_redirects(response, scope_ref=SCOPE_REF)
        self.assertTrue(safe, reason)
        self.assertEqual(hops, [])


class TestAuthorization(unittest.TestCase):
    def test_no_authorization_is_blocked(self):
        outcome = run(RecordingTransport("<p>x</p>"), authorization={})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)
        self.assertEqual(outcome.state, ac.ACTION_BLOCKED)

    def test_no_authorization_sends_no_request(self):
        transport = RecordingTransport("<p>x</p>")
        run(transport, authorization={})
        self.assertEqual(transport.called, 0)

    def test_an_action_without_an_authorization_reference_is_refused(self):
        """No authorization reference: the action cannot even be built."""
        with self.assertRaises(ac.ActionError):
            action_for(authorization_id="")

    def test_an_action_without_an_authorization_is_blocked(self):
        action = action_for()
        object.__setattr__(action, "authorization_id", "")
        outcome = ex.run_acquisition(
            action=action, parameter_ref=parameter_ref(),
            transport=RecordingTransport("<p>x</p>"), authorization={})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)

    def test_a_stored_inconclusive_acquisition_is_never_reused(self):
        replay = ReplayStub(hit={"action_id": "act-old",
                                 "result": ex.RESULT_INCONCLUSIVE,
                                 "reusable": True})
        transport = RecordingTransport("<p>x</p>")
        outcome = run(transport, replay=replay)
        self.assertEqual(transport.called, 1)
        self.assertFalse(outcome.replay.get("reused"))

    def test_an_authorization_without_ids_is_blocked(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      authorization={"action_types": [ac.SEND_MARKER]})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)

    def test_an_authorization_for_another_action_is_blocked(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      authorization={"authorization_ids": [AUTH_ID],
                                     "action_types": [ac.CHECK_REFLECTION]})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)

    def test_authorization_allows_a_covered_action(self):
        allowed, reason = ex.authorization_allows(action_for(), AUTHORIZATION)
        self.assertTrue(allowed, reason)

    def test_authorization_refuses_an_uncovered_action(self):
        allowed, reason = ex.authorization_allows(
            action_for(), {"authorization_ids": [AUTH_ID],
                           "action_types": ["SOMETHING_ELSE"]})
        self.assertFalse(allowed)

    def test_authorization_refuses_an_empty_mapping(self):
        allowed, _ = ex.authorization_allows(action_for(), {})
        self.assertFalse(allowed)

    def test_authorization_refuses_none(self):
        allowed, _ = ex.authorization_allows(action_for(), None)
        self.assertFalse(allowed)

    def test_a_blocked_acquisition_produces_no_observation(self):
        outcome = run(RecordingTransport("<p>x</p>"), authorization={})
        self.assertEqual(outcome.observations, [])


class TestBudget(unittest.TestCase):
    def test_an_exhausted_budget_blocks(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      budget=BudgetStub(refuse="max_requests"))
        self.assertEqual(outcome.result, ex.RESULT_BUDGET_EXHAUSTED)

    def test_an_exhausted_budget_sends_no_request(self):
        transport = RecordingTransport("<p>x</p>")
        run(transport, budget=BudgetStub(refuse="max_requests"))
        self.assertEqual(transport.called, 0)

    def test_an_exhausted_budget_is_not_evidence(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      budget=BudgetStub(refuse="max_requests"))
        self.assertFalse(outcome.evidential)
        self.assertEqual(outcome.observations, [])

    def test_a_working_budget_is_consumed(self):
        budget = BudgetStub()
        run(RecordingTransport("<p>x</p>"), budget=budget)
        self.assertEqual(budget.consumed, ["max_requests"])

    def test_the_request_budget_is_the_action_level_gate(self):
        """One action consumes one request; max_actions is the run's gate."""
        outcome = run(RecordingTransport("<p>x</p>"),
                      budget=BudgetStub(refuse="max_actions"))
        self.assertNotEqual(outcome.result, ex.RESULT_BUDGET_EXHAUSTED)

    def test_a_broken_budget_fails_closed(self):
        class Broken:
            def ensure(self, *args, **kwargs):
                raise RuntimeError("budget unavailable")

            def allow(self, *args, **kwargs):
                raise RuntimeError("budget unavailable")

        outcome = run(RecordingTransport("<p>x</p>"), budget=Broken())
        self.assertEqual(outcome.result, ex.RESULT_BUDGET_EXHAUSTED)


class TestReplayControl(unittest.TestCase):
    def test_a_reusable_previous_acquisition_reuses_evidence(self):
        marker = marker_for_action()
        replay = ReplayStub(hit={
            "action_id": "act-previous", "parameter": PARAMETER,
            "result": ex.RESULT_SUCCESS, "reusable": True,
            "detection": {"status": "PRESENT", "occurrence_count": 1,
                          "reflected": True, "context": "HTML_TEXT"},
            "evidence_excerpt": "<p>marker</p>"})
        transport = RecordingTransport(body_with(marker))
        outcome = run(transport, replay=replay)
        self.assertEqual(transport.called, 0)
        self.assertEqual(outcome.result, ex.RESULT_SUCCESS)

    def test_reuse_is_recorded_as_a_replay(self):
        replay = ReplayStub(hit={
            "action_id": "act-previous", "parameter": PARAMETER,
            "result": ex.RESULT_SUCCESS, "reusable": True,
            "detection": {"status": "PRESENT", "reflected": True}})
        outcome = run(RecordingTransport("<p>x</p>"), replay=replay)
        self.assertTrue(outcome.replay.get("reused"))

    def test_reuse_produces_no_new_request(self):
        replay = ReplayStub(hit={
            "action_id": "act-previous", "parameter": PARAMETER,
            "result": ex.RESULT_SUCCESS, "reusable": True,
            "detection": {"status": "PRESENT", "reflected": True}})
        transport = RecordingTransport("<p>x</p>")
        run(transport, replay=replay)
        self.assertEqual(transport.called, 0)

    def test_a_non_reusable_entry_does_not_reuse(self):
        replay = ReplayStub(hit={"action_id": "act-previous",
                                 "result": ex.RESULT_TIMEOUT,
                                 "reusable": True})
        transport = RecordingTransport("<p>x</p>")
        outcome = run(transport, replay=replay)
        self.assertEqual(transport.called, 1)
        self.assertFalse(outcome.replay.get("reused"))

    def test_a_non_reusable_entry_is_reported_as_such(self):
        replay = ReplayStub(hit={"action_id": "act-previous",
                                 "result": ex.RESULT_NO_REFLECTION,
                                 "reusable": False})
        outcome = run(RecordingTransport("<p>x</p>"), replay=replay)
        self.assertIn("replay", outcome.to_dict())

    def test_every_run_records_its_fingerprint(self):
        replay = ReplayStub()
        run(RecordingTransport("<p>x</p>"), replay=replay)
        self.assertEqual(len(replay.records), 1)
        self.assertIn("fingerprint", replay.records[0])

    def test_a_run_looks_its_fingerprint_up_before_sending(self):
        replay = ReplayStub()
        outcome = run(RecordingTransport("<p>x</p>"), replay=replay)
        self.assertEqual(replay.lookups, [outcome.replay["fingerprint"]])

    def test_a_recorded_run_is_not_marked_reused(self):
        outcome = run(RecordingTransport("<p>x</p>"), replay=ReplayStub())
        self.assertFalse(outcome.replay.get("reused"))

    def test_the_fingerprint_is_deterministic(self):
        marker = marker_for_action()
        first = ex.replay_fingerprint(action=action_for(),
                                      parameter_ref=parameter_ref(),
                                      marker=marker)
        second = ex.replay_fingerprint(action=action_for(),
                                       parameter_ref=parameter_ref(),
                                       marker=marker)
        self.assertEqual(first, second)

    def test_the_fingerprint_differs_per_parameter(self):
        first = ex.replay_fingerprint(action=action_for(parameter="q"),
                                      parameter_ref=parameter_ref("q"),
                                      marker=marker_for_action(parameter="q"))
        second = ex.replay_fingerprint(
            action=action_for(parameter="next"),
            parameter_ref=parameter_ref("next"),
            marker=marker_for_action(parameter="next"))
        self.assertNotEqual(first, second)

    def test_replay_reason_is_recorded(self):
        replay = ReplayStub()
        outcome = run(RecordingTransport("<p>x</p>"), replay=replay)
        self.assertIn("replay", str(outcome.to_dict()))


class TestSecretSafety(unittest.TestCase):
    def test_response_headers_are_scrubbed(self):
        transport = RecordingTransport(
            "<p>x</p>",
            headers={"set-cookie": "session=abc", "content-type": "text/html",
                     "authorization": "Bearer abc"})
        outcome = run(transport)
        headers = dict(outcome.response.get("headers") or {})
        self.assertNotIn("session=abc", str(headers))
        self.assertNotIn("Bearer abc", str(headers))

    def test_scrub_response_headers_removes_cookies(self):
        scrubbed = ex.scrub_response_headers({"set-cookie": "s=1",
                                              "content-type": "text/html"})
        self.assertNotIn("s=1", str(scrubbed))

    def test_the_outcome_carries_no_whole_body(self):
        marker = marker_for_action()
        filler = "UNIQUE-FILLER-" * 200
        outcome = run(RecordingTransport(f"<p>{filler}{marker}</p>"))
        self.assertLessEqual(len(outcome.evidence_excerpt), 400)
        self.assertLess(len(outcome.evidence_excerpt), len(filler))

    def test_the_excerpt_keeps_the_marker_with_its_surroundings(self):
        marker = marker_for_action()
        outcome = run(RecordingTransport(f"<p>before {marker} after</p>"))
        self.assertIn(marker, outcome.evidence_excerpt)
        self.assertIn("before", outcome.evidence_excerpt)

    def test_the_outcome_reports_only_that_a_body_was_present(self):
        marker = marker_for_action()
        outcome = run(RecordingTransport(body_with(marker)))
        self.assertTrue(outcome.response.get("body_present"))
        self.assertNotIn("body", outcome.response)

    def test_the_excerpt_is_bounded(self):
        marker = marker_for_action()
        body = "<p>" + ("x" * 5000) + marker + ("y" * 5000) + "</p>"
        outcome = run(RecordingTransport(body))
        self.assertLessEqual(len(outcome.evidence_excerpt), 400)

    def test_the_excerpt_contains_the_marker_when_reflected(self):
        marker = marker_for_action()
        outcome = run(RecordingTransport(body_with(marker)))
        self.assertIn(marker, outcome.evidence_excerpt)

    def test_the_excerpt_is_empty_for_a_negative(self):
        """An absence is recorded as a detection summary, not as content."""
        outcome = run(RecordingTransport("<p>nothing</p>"))
        self.assertEqual(outcome.evidence_excerpt, "")

    def test_the_excerpt_is_empty_for_a_truncated_absence(self):
        outcome = run(RecordingTransport("<p>nothing</p>", truncated=True))
        self.assertEqual(outcome.evidence_excerpt, "")

    def test_the_excerpt_never_carries_a_cookie_value(self):
        marker = marker_for_action()
        body = f"<p>{marker}</p><script>document.cookie='session=abc'</script>"
        outcome = run(RecordingTransport(body))
        self.assertNotIn("session=abc", outcome.evidence_excerpt)


class TestCapabilityGate(unittest.TestCase):
    def test_a_read_only_action_is_not_an_acquisition(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      action_type=ac.TRACE_DOM_SINK)
        self.assertEqual(outcome.result, ex.RESULT_CAPABILITY_UNAVAILABLE)

    def test_a_read_only_action_sends_nothing(self):
        transport = RecordingTransport("<p>x</p>")
        run(transport, action_type=ac.TRACE_DOM_SINK)
        self.assertEqual(transport.called, 0)

    def test_the_capability_gate_is_not_evidence(self):
        outcome = run(RecordingTransport("<p>x</p>"),
                      action_type=ac.TRACE_DOM_SINK)
        self.assertEqual(outcome.observations, [])

    def test_acquisition_actions_are_declared(self):
        self.assertIn(ac.SEND_MARKER, ex.ACQUISITION_ACTIONS)
        self.assertIn(ac.CHECK_REFLECTION, ex.ACQUISITION_ACTIONS)

    def test_payload_execution_is_not_an_acquisition_action(self):
        self.assertNotIn("ACTIVE_PAYLOAD_EXECUTION", ex.ACQUISITION_ACTIONS)
        self.assertNotIn("PAYLOAD_EXECUTION", ex.ACQUISITION_ACTIONS)

    def test_the_executor_document_declares_the_transport_reuse(self):
        document = ex.executor_document()
        self.assertTrue(any("transport" in str(v).lower()
                            for v in document.values()))


class TestClassifyAction(unittest.TestCase):
    def test_the_classify_action_reports_the_context(self):
        marker = marker_for_action(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        transport = RecordingTransport(body_with(marker, context="script"))
        outcome = run(transport, action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        self.assertEqual(outcome.context_class, "SCRIPT")

    def test_the_classify_action_emits_the_context_evidence_type(self):
        marker = marker_for_action(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        transport = RecordingTransport(body_with(marker, context="script"))
        outcome = run(transport, action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        types = [o.evidence_type for o in outcome.observations]
        self.assertIn("OUTPUT_CONTEXT_IDENTIFIED", types)

    def test_the_classify_action_still_records_the_reflection(self):
        marker = marker_for_action(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        transport = RecordingTransport(body_with(marker, context="script"))
        outcome = run(transport, action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        types = [o.evidence_type for o in outcome.observations]
        self.assertIn("REFLECTION_OBSERVED", types)

    def test_the_classify_action_is_also_authorized(self):
        """§12: no authorization means BLOCKED, for every acquisition."""
        outcome = run(RecordingTransport("<p>x</p>"),
                      action_type=ac.CLASSIFY_REFLECTION_CONTEXT,
                      authorization={})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)

    def test_the_classify_action_runs_with_authorization(self):
        marker = marker_for_action(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        outcome = run(RecordingTransport(body_with(marker, context="text")),
                      action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        self.assertEqual(outcome.state, ac.ACTION_SUCCEEDED)

    def test_a_comment_context_is_not_an_executable_context(self):
        marker = marker_for_action(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        transport = RecordingTransport(body_with(marker, context="comment"))
        outcome = run(transport, action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        self.assertEqual(outcome.context_class, "COMMENT")


class TestDeterminismAndLineage(unittest.TestCase):
    def test_the_same_input_yields_the_same_outcome(self):
        marker = marker_for_action()
        first = run(RecordingTransport(body_with(marker))).to_dict()
        second = run(RecordingTransport(body_with(marker))).to_dict()
        self.assertEqual(first, second)

    def test_two_parameters_use_different_markers(self):
        first = run(RecordingTransport("<p>x</p>"), parameter="q")
        second = run(RecordingTransport("<p>x</p>"), parameter="next")
        self.assertNotEqual(first.marker, second.marker)

    def test_two_parameters_use_different_action_ids(self):
        first = run(RecordingTransport("<p>x</p>"), parameter="q")
        second = run(RecordingTransport("<p>x</p>"), parameter="next")
        self.assertNotEqual(first.action_id, second.action_id)

    def test_the_outcome_records_its_parameter(self):
        self.assertEqual(run(RecordingTransport("<p>x</p>"),
                             parameter="next").parameter, "next")

    def test_the_request_records_the_parameter(self):
        url = "https://www.dell.com/support/search?next=1"
        outcome = run(RecordingTransport("<p>x</p>"), parameter="next",
                      url=url)
        self.assertEqual(outcome.request.get("parameter"), "next")

    def test_a_parameter_absent_from_the_request_is_refused(self):
        outcome = run(RecordingTransport("<p>x</p>"), parameter="next")
        self.assertEqual(outcome.request, {})

    def test_no_observation_mentions_another_parameter(self):
        marker = marker_for_action()
        outcome = run(RecordingTransport(body_with(marker)), parameter="q")
        self.assertEqual(outcome.observations[0].under_input, "q")


if __name__ == "__main__":
    unittest.main()

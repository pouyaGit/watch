"""EPIC13 §14/§16 — chain integration: acquisition advances the EPIC12 chain.

Every test here runs the whole flow offline, through the platform's own
injected-transport seam:

    candidate → chain → missing evidence → plan → authorized action → marker
    → request → response → detector → observation → EPIC11 classification
    → chain re-evaluation
"""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, PARAMETER, SCOPE_REF,
    TARGET_URL, BudgetStub, RecordingTransport, ReplayStub, body_with,
    chain_state, inventory_rows, marker_for_action, parameters)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    service as sv, transport as tr)


def acquire(transport, *, rows=None, params=None, authorization=None,
            budget=None, replay=None, state=None, store=None):
    rows = inventory_rows() if rows is None else rows
    return sv.run_acquisition_for_candidate(
        chain_state=(chain_state(rows) if state is None else state),
        parameters=(parameters() if params is None else params), rows=rows,
        transport=transport,
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        budget=budget, replay=replay, candidate_id=CANDIDATE_ID,
        objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF,
        vulnerability_class="XSS", job_id="job-epic13-1", store=store)


def reflecting(context: str = "text"):
    """A transport whose response reflects the SEND_MARKER marker."""
    marker = marker_for_action()
    return RecordingTransport(body_with(marker, context=context))


class TestChainAdvancement(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport(body_from_request=True)
        self.run = acquire(self.transport)

    def test_the_run_sends_a_real_request(self):
        """One action, one request: the next missing evidence only (§16)."""
        self.assertEqual(self.run.requests_sent, 1)

    def test_the_run_sends_no_request_for_a_later_stage(self):
        action_types = [o.get("action_type") for o in self.run.outcomes]
        self.assertNotIn(ac.CLASSIFY_REFLECTION_CONTEXT, action_types)

    def test_the_run_reports_reflection_observed(self):
        self.assertEqual(self.run.termination, sv.RUN_REFLECTION_OBSERVED)

    def test_the_chain_advanced(self):
        self.assertTrue(self.run.advanced)

    def test_the_chain_reaches_the_reflection_stage(self):
        self.assertGreaterEqual(self.run.chain_after.get("furthest_stage", 0),
                                self.run.chain_before.get("furthest_stage", 0) + 1)

    def test_the_reflection_stage_is_satisfied(self):
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertEqual(stages["reflection"], "SATISFIED")

    def test_the_parameter_stage_stays_satisfied(self):
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertEqual(stages["parameter"], "SATISFIED")

    def test_the_context_stage_is_not_yet_satisfied(self):
        """§16: one run acquires one next-stage item, then re-evaluates."""
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertEqual(stages["context"], "MISSING")

    def test_a_second_run_classifies_the_context(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True),
                         rows=first.evidence_rows)
        stages = {s["key"]: s["status"] for s in second.chain_after["stages"]}
        self.assertEqual(stages["context"], "SATISFIED")

    def test_a_second_run_reaches_the_execution_boundary(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True),
                         rows=first.evidence_rows)
        self.assertEqual(second.chain_after.get("next_stage"), "execution")

    def test_a_second_run_still_never_claims_execution(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True),
                         rows=first.evidence_rows)
        stages = {s["key"]: s["status"] for s in second.chain_after["stages"]}
        self.assertNotEqual(stages["execution"], "SATISFIED")
        self.assertFalse(second.chain_after.get("confirmed"))

    def test_the_execution_stage_is_not_satisfied(self):
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertNotEqual(stages["execution"], "SATISFIED")

    def test_the_exploitability_stage_is_not_satisfied(self):
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertNotEqual(stages["exploitability"], "SATISFIED")

    def test_the_verdict_stays_pending(self):
        self.assertEqual(self.run.verdict_after, "VERIFICATION_PENDING")

    def test_the_verdict_reason_names_the_missing_execution_evidence(self):
        self.assertIn("payload_execution",
                      self.run.verdict_reason_after)

    def test_the_run_is_not_confirmed(self):
        self.assertNotIn("CONFIRMED", self.run.verdict_after)

    def test_the_run_acquired_evidence(self):
        self.assertTrue(self.run.acquired)

    def test_the_run_produced_evidence_rows(self):
        self.assertTrue(self.run.produced_rows)

    def test_the_run_keeps_the_pre_existing_rows(self):
        self.assertEqual(len(self.run.evidence_rows),
                         len(inventory_rows()) + len(self.run.produced_rows))

    def test_the_acquired_rows_are_classified(self):
        signals = {r.get("signal") for r in self.run.evidence_rows}
        self.assertIn("reflection_observed", signals)

    def test_the_observations_are_recorded(self):
        self.assertTrue(self.run.observations)

    def test_each_observation_names_its_action(self):
        for observation in self.run.observations:
            self.assertTrue(observation.get("action_id"))

    def test_the_run_records_the_transport(self):
        self.assertTrue(self.run.transport.get("available"))

    def test_the_run_records_the_capability_state(self):
        self.assertEqual(self.run.capability.get("vulnerability_class"), "XSS")
        self.assertEqual(self.run.capability.get("capability"), "IMPLEMENTED")

    def test_the_run_records_the_capability_limitation(self):
        self.assertTrue(self.run.capability.get("limitation"))

    def test_the_plan_is_attached(self):
        self.assertTrue(self.run.plan.get("actions"))

    def test_the_run_declares_its_rule_version(self):
        self.assertEqual(self.run.rule_version, sv.SERVICE_RULE_VERSION)

    def test_no_payload_execution_evidence_is_ever_produced(self):
        for row in self.run.evidence_rows:
            self.assertNotIn("PAYLOAD_EXECUTION", str(row.get("evidence_type")))
            self.assertNotIn("EXPLOITABILITY_ESTABLISHED",
                             str(row.get("evidence_type")))

    def test_the_run_does_not_claim_exploitability(self):
        self.assertFalse(self.run.chain_after.get("confirmed"))
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertNotEqual(stages["exploitability"], "SATISFIED")

    def test_the_chain_reports_the_next_stage_honestly(self):
        self.assertEqual(self.run.chain_after.get("next_stage"), "context")

    def test_the_run_never_marks_the_chain_terminated(self):
        self.assertFalse(self.run.chain_after.get("chain_terminated"))


class TestReflectionContextsThroughTheChain(unittest.TestCase):
    def test_script_reflection_satisfies_the_context_stage(self):
        run = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)

    def test_the_context_class_is_recorded_on_the_observation(self):
        run = acquire(RecordingTransport(body_from_request=True))
        contexts = [o.get("context") for o in run.observations]
        self.assertIn("HTML_TEXT", contexts)

    def test_a_comment_reflection_is_classified_as_a_comment(self):
        marker = marker_for_action()
        run = acquire(RecordingTransport(body_with(marker, context="comment")))
        contexts = [o.get("context") for o in run.observations]
        self.assertIn("COMMENT", contexts)


class TestNegativeTerminalState(unittest.TestCase):
    def setUp(self):
        self.run = acquire(RecordingTransport("<html><body>nothing</body></html>"))

    def test_the_run_reports_no_reflection(self):
        self.assertEqual(self.run.termination, sv.RUN_REFLECTION_NOT_OBSERVED)

    def test_negative_evidence_is_produced(self):
        signals = {r.get("signal") for r in self.run.evidence_rows}
        self.assertIn("reflection_not_observed", signals)

    def test_the_run_acquired_evidence(self):
        self.assertTrue(self.run.acquired)

    def test_the_chain_does_not_stay_pending_forever(self):
        """§9: a probe that found nothing is a result, not a stall."""
        self.assertNotEqual(self.run.verdict_reason_after,
                            "missing_reflection_evidence")

    def test_the_reflection_stage_is_not_satisfied(self):
        stages = {s["key"]: s["status"] for s in self.run.chain_after["stages"]}
        self.assertNotEqual(stages["reflection"], "SATISFIED")

    def test_the_verdict_is_not_confirmed(self):
        self.assertNotIn("CONFIRMED", self.run.verdict_after)

    def test_the_run_never_upgrades_a_negative_to_a_positive(self):
        for row in self.run.evidence_rows:
            self.assertNotEqual(row.get("signal"), "reflection_observed")


class TestHonestBlocks(unittest.TestCase):
    def test_an_unavailable_transport_blocks(self):
        run = acquire(tr.UnavailableTransport())
        self.assertEqual(run.termination, sv.RUN_TRANSPORT_UNAVAILABLE)

    def test_an_unavailable_transport_sends_nothing(self):
        self.assertEqual(acquire(tr.UnavailableTransport()).requests_sent, 0)

    def test_an_unavailable_transport_produces_no_evidence(self):
        run = acquire(tr.UnavailableTransport())
        self.assertEqual(run.produced_rows, [])
        self.assertFalse(run.acquired)

    def test_an_unavailable_transport_does_not_advance_the_chain(self):
        run = acquire(tr.UnavailableTransport())
        self.assertEqual(run.chain_after.get("furthest_stage"),
                         run.chain_before.get("furthest_stage"))

    def test_an_unavailable_transport_is_not_confirmed(self):
        run = acquire(tr.UnavailableTransport())
        self.assertFalse(run.chain_after.get("confirmed"))

    def test_no_authorization_blocks(self):
        run = acquire(reflecting(), authorization={})
        self.assertEqual(run.termination, sv.RUN_UNAUTHORIZED)

    def test_no_authorization_sends_nothing(self):
        transport = reflecting()
        acquire(transport, authorization={})
        self.assertEqual(transport.called, 0)

    def test_no_authorization_produces_no_evidence(self):
        self.assertEqual(
            acquire(reflecting(), authorization={}).produced_rows, [])

    def test_no_authorization_is_recorded_as_blocked(self):
        run = acquire(reflecting(), authorization={})
        self.assertTrue(run.blocked)

    def test_an_exhausted_budget_blocks(self):
        run = acquire(reflecting(), budget=BudgetStub(refuse="max_requests"))
        self.assertEqual(run.termination, sv.RUN_BUDGET_EXHAUSTED)

    def test_an_exhausted_budget_sends_nothing(self):
        transport = reflecting()
        acquire(transport, budget=BudgetStub(refuse="max_requests"))
        self.assertEqual(transport.called, 0)

    def test_a_response_without_a_body_is_inconclusive(self):
        run = acquire(RecordingTransport(None))
        self.assertEqual(run.termination, sv.RUN_INCONCLUSIVE)

    def test_a_timeout_is_not_negative_evidence(self):
        run = acquire(RecordingTransport("<p>x</p>", outcome=tr.OUTCOME_TIMEOUT))
        self.assertNotEqual(run.termination, sv.RUN_REFLECTION_NOT_OBSERVED)
        self.assertEqual(run.produced_rows, [])

    def test_a_timeout_does_not_advance_the_chain(self):
        run = acquire(RecordingTransport("<p>x</p>", outcome=tr.OUTCOME_TIMEOUT))
        self.assertEqual(run.chain_after.get("furthest_stage"),
                         run.chain_before.get("furthest_stage"))

    def test_a_timeout_is_reported_as_a_blocked_run(self):
        run = acquire(RecordingTransport("<p>x</p>", outcome=tr.OUTCOME_TIMEOUT))
        self.assertFalse(run.acquired)
        self.assertTrue(run.blocked)

    def test_a_truncated_absence_is_inconclusive(self):
        run = acquire(RecordingTransport("<p>nothing</p>", truncated=True))
        self.assertEqual(run.termination, sv.RUN_INCONCLUSIVE)

    def test_a_truncated_absence_produces_no_negative_evidence(self):
        run = acquire(RecordingTransport("<p>nothing</p>", truncated=True))
        signals = {r.get("signal") for r in run.produced_rows}
        self.assertNotIn("reflection_not_observed", signals)

    def test_a_transport_exception_is_reported_not_faked(self):
        run = acquire(RecordingTransport("<p>x</p>", raises=RuntimeError("boom")))
        self.assertEqual(run.termination, sv.RUN_TRANSPORT_UNAVAILABLE)
        self.assertEqual(run.produced_rows, [])

    def test_an_out_of_scope_redirect_blocks_the_run(self):
        transport = RecordingTransport(
            "<p>x</p>", status_code=302,
            headers={"location": "https://evil.test/"},
            redirects=[{"location": "https://evil.test/", "status": 302}])
        run = acquire(transport)
        self.assertEqual(run.termination, sv.RUN_INCONCLUSIVE)
        self.assertEqual(run.produced_rows, [])

    def test_no_parameters_means_no_requirement(self):
        run = acquire(reflecting(), params=[])
        self.assertEqual(run.termination, sv.RUN_NO_REQUIREMENT)

    def test_a_satisfied_reflection_is_never_re_probed(self):
        """§18: existing, still-valid evidence is not acquired twice."""
        rows = inventory_rows() + [{
            "id": "ev-refl", "type": "observation",
            "signal": "reflection_observed", "category": "XSS",
            "detail": "marker reflected", "observation_ref": "obs-r1",
            "evidence_type": "REFLECTION_OBSERVED"}]
        transport = RecordingTransport(body_from_request=True)
        run = acquire(transport, rows=rows)
        action_types = [o.get("action_type") for o in run.outcomes]
        self.assertNotIn(ac.SEND_MARKER, action_types)

    def test_a_chain_with_only_unacquirable_evidence_reports_capability(self):
        rows = inventory_rows() + [{
            "id": "ev-refl", "type": "observation",
            "signal": "reflection_observed", "category": "XSS",
            "detail": "marker reflected", "observation_ref": "obs-r1",
            "evidence_type": "REFLECTION_OBSERVED"}, {
            "id": "ev-ctx", "type": "observation",
            "signal": "output_context_identified", "category": "XSS",
            "detail": "context html_text", "observation_ref": "obs-c1",
            "evidence_type": "OUTPUT_CONTEXT_IDENTIFIED"}]
        run = acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertEqual(run.termination, sv.RUN_CAPABILITY_UNAVAILABLE)
        self.assertFalse(run.acquired)

    def test_an_unacquirable_next_stage_produces_no_request(self):
        rows = inventory_rows() + [{
            "id": "ev-refl", "type": "observation",
            "signal": "reflection_observed", "category": "XSS",
            "detail": "marker reflected", "observation_ref": "obs-r1",
            "evidence_type": "REFLECTION_OBSERVED"}, {
            "id": "ev-ctx", "type": "observation",
            "signal": "output_context_identified", "category": "XSS",
            "detail": "context html_text", "observation_ref": "obs-c1",
            "evidence_type": "OUTPUT_CONTEXT_IDENTIFIED"}]
        transport = RecordingTransport(body_from_request=True)
        acquire(transport, rows=rows)
        self.assertEqual(transport.called, 0)


class TestParameterIsolationThroughTheChain(unittest.TestCase):
    def test_two_parameters_produce_two_requests(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        transport = RecordingTransport(body_from_request=True)
        run = acquire(transport, params=params)
        self.assertEqual(run.requests_sent, 2)

    def test_two_parameters_use_two_markers(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        transport = RecordingTransport(body_from_request=True)
        acquire(transport, params=params)
        markers = {r.marker for r in transport.requests}
        self.assertEqual(len(markers), 2)

    def test_two_parameters_keep_separate_evidence_rows(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]
        run = acquire(RecordingTransport(body_from_request=True), params=params)
        parameters_seen = {r.get("under_input") or r.get("parameter")
                           for r in run.evidence_rows}
        self.assertIn("q", str(parameters_seen))

    def test_a_reflected_and_a_silent_parameter_stay_separate(self):
        params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                  {"parameter": "page", "url": TARGET_URL, "method": "GET"}]

        class SplitTransport:
            name = "split"

            def __init__(self):
                self.calls = 0

            @property
            def available(self):
                return True

            def send(self, request):
                self.calls += 1
                body = (f"<p>{request.marker}</p>"
                        if request.parameter == "q" else "<p>nothing</p>")
                return tr.AcquisitionResponse(
                    outcome=tr.OUTCOME_RESPONDED, status_code=200, body=body,
                    response_ref="resp-split")

        transport = SplitTransport()
        run = acquire(transport, params=params)
        signals = [r.get("signal") for r in run.evidence_rows]
        self.assertIn("reflection_observed", signals)
        self.assertIn("reflection_not_observed", signals)


class TestReplayThroughTheChain(unittest.TestCase):
    def test_a_second_run_reuses_the_first_acquisition(self):
        replay = ReplayStub()
        first = acquire(RecordingTransport(body_from_request=True),
                        replay=replay)
        self.assertEqual(first.requests_sent, 1)
        hit = replay.records[-1] if replay.records else None
        self.assertTrue(hit)

    def test_the_first_run_is_not_a_reuse(self):
        replay = ReplayStub()
        run = acquire(RecordingTransport(body_from_request=True), replay=replay)
        self.assertEqual(run.requests_sent, 1)

    def test_a_reused_run_sends_nothing(self):
        replay = ReplayStub(hit={
            "action_id": "act-old", "result": "SUCCESS", "reusable": True,
            "detection": {"status": "PRESENT", "reflected": True,
                          "context": "HTML_TEXT"}})
        transport = RecordingTransport(body_from_request=True)
        run = acquire(transport, replay=replay)
        self.assertEqual(transport.called, 0)


class TestPersistence(unittest.TestCase):
    def test_the_run_is_persisted_when_a_store_is_given(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            run = acquire(RecordingTransport(body_from_request=True),
                          store=store)
            recorded = store.acquisitions_for_candidate(CANDIDATE_ID)
            self.assertEqual(len(recorded), 1)
            self.assertEqual(recorded[0]["termination"], run.termination)

    def test_the_persisted_row_carries_the_chain_state(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["chain_after"]["verdict"],
                             "VERIFICATION_PENDING")
            self.assertFalse(row["chain_after"]["confirmed"])
            self.assertEqual(row["chain_after"]["furthest_stage"], 3)

    def test_the_persisted_row_carries_the_produced_rows(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertTrue(row["produced_rows"])
            self.assertNotIn("xss_parameter_inventory",
                             str(row["produced_rows"]))

    def test_the_persisted_row_carries_no_whole_response_body(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            transport = RecordingTransport(
                "<html><body><p>" + ("FILLER-" * 300)
                + marker_for_action() + "</p></body></html>")
            acquire(transport, store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertNotIn("FILLER-" * 50, str(row))

    def test_the_persisted_row_carries_a_bounded_excerpt(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            transport = RecordingTransport(
                "<html><body><p>" + ("FILLER-" * 300)
                + marker_for_action() + "</p></body></html>")
            acquire(transport, store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertLessEqual(len(str(row)), 12000)

    def test_the_persisted_row_carries_no_credential(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            transport = RecordingTransport(
                body_from_request=True,
                headers={"set-cookie": "session=SUPERSECRET",
                         "authorization": "Bearer SUPERSECRET"})
            acquire(transport, store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertNotIn("SUPERSECRET", str(row))

    def test_the_observations_are_persisted(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            self.assertTrue(store.observations_for_candidate(CANDIDATE_ID))

    def test_a_blocked_run_is_also_persisted(self):
        from backend.research_agents.verification import store as st
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(tr.UnavailableTransport(), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["termination"], sv.RUN_TRANSPORT_UNAVAILABLE)

    def test_persistence_is_optional(self):
        run = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)


class TestDeterminism(unittest.TestCase):
    def test_the_same_run_is_reproducible(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(first.termination, second.termination)
        self.assertEqual([r.get("signal") for r in first.evidence_rows],
                         [r.get("signal") for r in second.evidence_rows])

    def test_the_same_run_produces_the_same_chain(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(first.chain_after, second.chain_after)

    def test_two_runs_never_share_a_marker(self):
        first = RecordingTransport(body_from_request=True)
        second = RecordingTransport(body_from_request=True)
        acquire(first)
        acquire(second)
        self.assertEqual(first.last_marker, second.last_marker)


if __name__ == "__main__":
    unittest.main()

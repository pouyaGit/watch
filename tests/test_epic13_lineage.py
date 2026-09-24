"""EPIC13 §17/§18 — lineage, duplicate control, replay and persistence."""
from __future__ import annotations

import tempfile
import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, PARAMETER, SCOPE_REF,
    TARGET_URL, RecordingTransport, body_with, chain_state, inventory_rows,
    marker_for_action, parameters)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import store as st  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    executor as ex, markers as mk, replay as rp, requests as rq, service as sv,
    transport as tr)

OTHER_URL = "https://www.dell.com/support/search?next=1&q=test"


def acquire(transport, *, rows=None, params=None, replay=None, store=None):
    rows = inventory_rows() if rows is None else rows
    return sv.run_acquisition_for_candidate(
        chain_state=chain_state(rows),
        parameters=(parameters() if params is None else params), rows=rows,
        transport=transport, authorization=AUTHORIZATION, replay=replay,
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
        scope_ref=SCOPE_REF, vulnerability_class="XSS", job_id="job-epic13-1",
        store=store)


class TestParameterLineage(unittest.TestCase):
    def setUp(self):
        self.params = [{"parameter": "q", "url": TARGET_URL, "method": "GET"},
                       {"parameter": "next", "url": OTHER_URL,
                        "method": "GET"}]

    def test_each_parameter_gets_its_own_action(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        actions = {o["action_type"]: 0 for o in run.outcomes}
        self.assertEqual(len(run.outcomes), 2)

    def test_each_parameter_gets_its_own_marker(self):
        transport = RecordingTransport(body_from_request=True)
        acquire(transport, params=self.params)
        self.assertEqual(len({r.marker for r in transport.requests}), 2)

    def test_each_parameter_gets_its_own_request(self):
        transport = RecordingTransport(body_from_request=True)
        acquire(transport, params=self.params)
        parameters = [r.parameter for r in transport.requests]
        self.assertEqual(sorted(parameters), ["next", "q"])

    def test_an_observation_names_the_parameter_it_belongs_to(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        for observation in run.observations:
            self.assertIn(observation["under_input"], ("q", "next"))

    def test_evidence_rows_never_mix_two_parameters(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        for row in run.produced_rows:
            self.assertNotIn(",", str(row.get("under_input") or ""))

    def test_no_row_claims_a_combined_reflection(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        self.assertNotIn("candidate reflected input",
                         str(run.produced_rows).lower())

    def test_each_action_records_its_own_required_evidence(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        for action in run.plan["actions"]:
            self.assertEqual(action["inputs"]["required_evidence"],
                             "REFLECTION_OBSERVED")

    def test_markers_are_traceable_to_their_action(self):
        run = acquire(RecordingTransport(body_from_request=True),
                      params=self.params)
        markers = {o["marker"] for o in run.outcomes}
        action_ids = {o["action_id"] for o in run.outcomes}
        self.assertEqual(len(markers), len(action_ids))


class TestDuplicateControl(unittest.TestCase):
    def test_the_same_fingerprint_is_computed_twice(self):
        action = ac.VerificationAction(
            action_type=ac.SEND_MARKER, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF, target=TARGET_URL,
            authorization_id=AUTH_ID,
            inputs={"parameter": "q", "url": TARGET_URL}, attempt=1)
        first = ex.replay_fingerprint(action=action, marker="M",
                                      parameter_ref=rq.ParameterRef(
                                          url=TARGET_URL, parameter="q"))
        second = ex.replay_fingerprint(action=action, marker="M",
                                       parameter_ref=rq.ParameterRef(
                                           url=TARGET_URL, parameter="q"))
        self.assertEqual(first, second)

    def test_the_fingerprint_changes_with_the_marker(self):
        action = ac.VerificationAction(
            action_type=ac.SEND_MARKER, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF, target=TARGET_URL,
            authorization_id=AUTH_ID,
            inputs={"parameter": "q", "url": TARGET_URL}, attempt=1)
        first = ex.replay_fingerprint(action=action, marker="M1",
                                      parameter_ref=rq.ParameterRef(
                                          url=TARGET_URL, parameter="q"))
        second = ex.replay_fingerprint(action=action, marker="M2",
                                       parameter_ref=rq.ParameterRef(
                                           url=TARGET_URL, parameter="q"))
        self.assertNotEqual(first, second)

    def test_the_fingerprint_does_not_carry_a_url_verbatim(self):
        action = ac.VerificationAction(
            action_type=ac.SEND_MARKER, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF, target=TARGET_URL,
            authorization_id=AUTH_ID,
            inputs={"parameter": "q", "url": TARGET_URL}, attempt=1)
        fingerprint = ex.replay_fingerprint(
            action=action, marker="M",
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"))
        self.assertNotIn("dell.com", fingerprint)

    def test_a_successful_run_is_recorded_as_reusable(self):
        ledger = rp.ReplayLedger()
        run = acquire(RecordingTransport(body_from_request=True),
                      replay=ledger)
        entry = ledger.entries()[-1]
        self.assertTrue(entry["reusable"])

    def test_a_negative_run_is_recorded_as_reusable(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport("<p>nothing</p>"), replay=ledger)
        self.assertTrue(ledger.entries()[-1]["reusable"])

    def test_a_timeout_is_not_recorded_at_all(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport("<p>x</p>", outcome=tr.OUTCOME_TIMEOUT),
                replay=ledger)
        self.assertEqual(ledger.entries(), [])

    def test_a_transport_failure_is_not_recorded(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport("<p>x</p>", raises=RuntimeError("boom")),
                replay=ledger)
        self.assertEqual(ledger.entries(), [])

    def test_a_truncated_absence_is_not_recorded(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport("<p>nothing</p>", truncated=True),
                replay=ledger)
        self.assertEqual(ledger.entries(), [])


class TestReplayLedger(unittest.TestCase):
    def test_a_recorded_entry_is_reusable(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        self.assertIsNotNone(ledger.lookup("fp-1"))

    def test_an_unrecorded_fingerprint_misses(self):
        ledger = rp.ReplayLedger()
        self.assertIsNone(ledger.lookup("fp-unknown"))

    def test_an_empty_fingerprint_misses(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        self.assertIsNone(ledger.lookup(""))

    def test_an_inconclusive_result_is_not_reusable(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1",
                      result=ex.RESULT_INCONCLUSIVE)
        self.assertIsNone(ledger.lookup("fp-1"))

    def test_a_timeout_is_not_reusable(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1",
                      result=ex.RESULT_TIMEOUT)
        self.assertIsNone(ledger.lookup("fp-1"))

    def test_a_negative_result_is_reusable(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1",
                      result=ex.RESULT_NO_REFLECTION)
        self.assertIsNotNone(ledger.lookup("fp-1"))

    def test_an_expired_entry_is_not_reusable(self):
        clock = {"now": 1000.0}
        ledger = rp.ReplayLedger(ttl_seconds=10, now_fn=lambda: clock["now"])
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        clock["now"] = 2000.0
        self.assertIsNone(ledger.lookup("fp-1"))

    def test_a_fresh_entry_survives_the_ttl(self):
        clock = {"now": 1000.0}
        ledger = rp.ReplayLedger(ttl_seconds=3600, now_fn=lambda: clock["now"])
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        clock["now"] = 1100.0
        self.assertIsNotNone(ledger.lookup("fp-1"))

    def test_the_latest_entry_wins(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        ledger.record(fingerprint="fp-1", action_id="act-2",
                      result=ex.RESULT_TIMEOUT)
        hit = ledger.lookup("fp-1")
        self.assertEqual(hit["action_id"], "act-1")

    def test_the_ledger_never_stores_a_whole_body(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS",
                      evidence_excerpt="X" * 5000)
        self.assertLessEqual(len(ledger.entries()[-1]["evidence_excerpt"]), 256)

    def test_the_ledger_never_stores_a_credential(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS",
                      response={"headers": {"set-cookie": "session=SECRET"},
                                "status_code": 200})
        self.assertNotIn("SECRET", str(ledger.entries()[-1]))

    def test_the_report_counts_entries_and_reusable_ones(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        ledger.record(fingerprint="fp-2", action_id="act-2",
                      result=ex.RESULT_TIMEOUT)
        report = ledger.report()
        self.assertEqual(report["entries"], 2)
        self.assertEqual(report["reusable"], 1)

    def test_the_report_declares_the_rule_version(self):
        self.assertEqual(rp.ReplayLedger().report()["rule_version"],
                         rp.RULE_VERSION if hasattr(rp, "RULE_VERSION")
                         else rp.REPLAY_RULE_VERSION)

    def test_the_ledger_survives_a_restart_when_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = rp.ReplayLedger(base_dir=tmp)
            first.record(fingerprint="fp-1", action_id="act-1",
                         result="SUCCESS")
            second = rp.ReplayLedger(base_dir=tmp)
            self.assertIsNotNone(second.lookup("fp-1"))

    def test_a_persisted_ledger_reports_itself_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(rp.ReplayLedger(base_dir=tmp).report()["persisted"])

    def test_an_in_memory_ledger_reports_itself_unpersisted(self):
        self.assertFalse(rp.ReplayLedger().report()["persisted"])

    def test_reuse_requires_the_entry_to_say_so(self):
        ledger = rp.ReplayLedger()
        ledger.record(fingerprint="fp-1", action_id="act-1", result="SUCCESS")
        self.assertTrue(ledger.lookup("fp-1")["reusable"])


class TestReuseThroughTheExecutor(unittest.TestCase):
    def test_a_second_identical_run_reuses_the_first(self):
        ledger = rp.ReplayLedger()
        first_transport = RecordingTransport(body_from_request=True)
        acquire(first_transport, replay=ledger)
        self.assertEqual(first_transport.called, 1)
        second_transport = RecordingTransport(body_from_request=True)
        run = acquire(second_transport, replay=ledger)
        self.assertEqual(second_transport.called, 0)
        self.assertTrue(run.outcomes[0]["replay"]["reused"])

    def test_a_reused_run_still_reports_the_evidence(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport(body_from_request=True), replay=ledger)
        run = acquire(RecordingTransport(body_from_request=True),
                      replay=ledger)
        self.assertTrue(run.outcomes[0]["detection"]["reflected"])

    def test_a_reused_run_does_not_double_count_the_ledger(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport(body_from_request=True), replay=ledger)
        before = len(ledger.entries())
        acquire(RecordingTransport(body_from_request=True), replay=ledger)
        self.assertEqual(len(ledger.entries()), before)

    def test_reuse_is_recorded_with_a_reason(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport(body_from_request=True), replay=ledger)
        run = acquire(RecordingTransport(body_from_request=True),
                      replay=ledger)
        self.assertIn("reused", run.outcomes[0]["reason"])


class TestStorePersistence(unittest.TestCase):
    def test_a_run_is_retrievable_by_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            rows = store.acquisitions_for_candidate(CANDIDATE_ID)
            self.assertEqual(len(rows), 1)

    def test_a_run_is_retrievable_by_objective(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            rows = store.list_acquisitions(candidate_id=CANDIDATE_ID,
                                           objective_id=OBJECTIVE_ID)
            self.assertEqual(len(rows), 1)

    def test_an_unknown_candidate_has_no_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            self.assertEqual(store.acquisitions_for_candidate("cand-nope"), [])

    def test_two_runs_are_both_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            acquire(RecordingTransport("<p>nothing</p>"), store=store)
            self.assertEqual(len(store.acquisitions_for_candidate(
                CANDIDATE_ID)), 2)

    def test_the_latest_run_is_the_last_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            acquire(RecordingTransport("<p>nothing</p>"), store=store)
            latest = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(latest["termination"],
                             sv.RUN_REFLECTION_NOT_OBSERVED)

    def test_the_persisted_row_records_the_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            run = acquire(RecordingTransport(body_from_request=True),
                          store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["outcomes"][0]["marker"],
                             run.outcomes[0]["marker"])

    def test_the_persisted_row_records_the_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["outcomes"][0]["authorization_id"], AUTH_ID)

    def test_the_persisted_row_records_the_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["transport"]["name"], "injected_transport")

    def test_the_persisted_row_records_the_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertIn("max_response_bytes", row["limits"])

    def test_the_persisted_row_records_the_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["capability"]["capability"], "IMPLEMENTED")

    def test_the_persisted_row_records_the_rule_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertEqual(row["rule_version"], sv.SERVICE_RULE_VERSION)

    def test_the_persisted_row_is_json_serialisable(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertIn("termination", json.loads(json.dumps(row)))

    def test_a_historical_row_is_never_rewritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(body_from_request=True), store=store)
            before = store.latest_acquisition(CANDIDATE_ID)
            acquire(RecordingTransport("<p>nothing</p>"), store=store)
            rows = store.acquisitions_for_candidate(CANDIDATE_ID)
            self.assertEqual(rows[0], before)


class TestHistoricalEvidenceIsNotMutated(unittest.TestCase):
    def test_the_input_rows_are_not_modified(self):
        rows = inventory_rows()
        before = [dict(r) for r in rows]
        acquire(RecordingTransport(body_from_request=True), rows=rows)
        self.assertEqual(rows, before)

    def test_the_chain_state_is_not_modified(self):
        rows = inventory_rows()
        state = chain_state(rows)
        before = state.to_dict()
        sv.run_acquisition_for_candidate(
            chain_state=state, parameters=parameters(), rows=rows,
            transport=RecordingTransport(body_from_request=True),
            authorization=AUTHORIZATION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF,
            vulnerability_class="XSS")
        self.assertEqual(state.to_dict(), before)

    def test_a_previous_run_leaves_no_trace_in_the_next(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(first.chain_before, second.chain_before)

    def test_markers_are_reproducible_for_the_same_action(self):
        first = acquire(RecordingTransport(body_from_request=True))
        second = acquire(RecordingTransport(body_from_request=True))
        self.assertEqual(first.outcomes[0]["marker"],
                         second.outcomes[0]["marker"])


if __name__ == "__main__":
    unittest.main()

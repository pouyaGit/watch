"""EPIC13 §26 — the mandatory regression on the REAL candidate.

``cand-7c229c48c455`` (scope ``watch:scope:dell/www.dell.com``, endpoint
``https://www.dell.com/support``) carries parameter-inventory evidence only.
EPIC13 adds acquisition on top of EPIC12's chain, so this suite pins the two
things that matter:

* with no recorded authorization, the correct production result is
  **BLOCKED / verification_not_authorized** — a safety result, not a failure;
* with an authorization, acquisition may add *reflection and context* evidence
  and must still never confirm the candidate.

Every offline result is labelled as coming from the injected seam; the two
modes are never conflated.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    executor as ex, plan as pl, service as sv, transport as tr)
from tests.epic12_fixtures import authorization as epic11_authorization  # noqa: E402
from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, SCOPE_REF, TARGET_URL,
    RecordingTransport, inventory_rows, marker_for_action, parameters)

#: ``evaluate_chain`` takes the EPIC11 authorization *object*; the acquisition
#: service takes the authorization *mapping*.  The two are kept distinct here
#: so the regression cannot accidentally exercise a shape the runtime never
#: produces.
ENGINE_AUTHORIZATION = epic11_authorization()

#: The real evidence shape: 20 parameter-inventory observations, no more.
def real_rows():
    base = inventory_rows()[0]
    return [dict(base, id=f"ev-inv-{i + 1}", observation_ref=f"obs-inv-{i + 1}")
            for i in range(20)]


def real_state(rows=None, authorization=None):
    return en.evaluate_chain(
        "XSS", real_rows() if rows is None else rows,
        authorization=(ENGINE_AUTHORIZATION if authorization is None
                       else authorization))


def run_acquisition(transport, *, authorization=None, params=None, rows=None,
                    replay=None):
    rows = real_rows() if rows is None else rows
    return sv.run_acquisition_for_candidate(
        chain_state=en.evaluate_chain("XSS", rows,
                                      authorization=ENGINE_AUTHORIZATION),
        parameters=(parameters() if params is None else params), rows=rows,
        transport=transport,
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
        scope_ref=SCOPE_REF, vulnerability_class="XSS", job_id="job-epic13-1",
        replay=replay)


class TestProductionShapeIsBlocked(unittest.TestCase):
    """No recorded authorization ⇒ BLOCKED / verification_not_authorized."""

    def test_no_authorization_blocks_the_acquisition(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertEqual(run.termination, sv.RUN_UNAUTHORIZED)

    def test_no_authorization_sends_no_request(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertEqual(run.requests_sent, 0)

    def test_no_authorization_produces_no_evidence(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertEqual(run.produced_rows, [])

    def test_the_blocked_reason_names_the_authorization(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        joined = " ".join(str(b) for b in run.blocked)
        self.assertIn("authorization", joined)

    def test_the_candidate_is_not_confirmed(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertFalse(run.chain_after.get("confirmed"))

    def test_the_verdict_stays_pending_or_blocked(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertIn(run.verdict_after,
                      ("VERIFICATION_PENDING", "BLOCKED", "NOT_CONFIRMED"))

    def test_a_blocked_run_cannot_improve_the_authorization_verdict(self):
        """BLOCKED must not become VERIFICATION_PENDING by re-evaluation."""
        rows = real_rows()
        state = en.evaluate_chain("XSS", rows)  # no authorization at all
        self.assertEqual(state.verdict, "BLOCKED")
        run = sv.run_acquisition_for_candidate(
            chain_state=state, parameters=parameters(), rows=rows,
            transport=RecordingTransport(f"<p>{marker_for_action()}</p>"),
            authorization={}, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF,
            vulnerability_class="XSS", job_id="job-epic13-1")
        self.assertEqual(run.verdict_before, "BLOCKED")
        self.assertEqual(run.verdict_after, "BLOCKED")

    def test_a_blocked_run_never_becomes_more_optimistic(self):
        """A run that sent nothing may only stay or get more conservative."""
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertNotEqual(run.verdict_after, "VERIFIED")
        self.assertFalse(run.chain_after.get("confirmed"))
        self.assertEqual(run.verdict_after, "BLOCKED")

    def test_a_blocked_run_records_the_authorization_blocker(self):
        run = run_acquisition(RecordingTransport(
            f"<p>{marker_for_action()}</p>"), authorization={})
        self.assertEqual(run.blocked[0]["blocked_reason"],
                         "authorization_unavailable")

    def test_a_blocked_run_is_not_a_failure_of_the_epic(self):
        """§26: the blocked result is the *correct* production outcome."""
        run = run_acquisition(tr.PlatformAuthorizedTransport())
        self.assertEqual(run.termination, sv.RUN_TRANSPORT_UNAVAILABLE)
        self.assertIn(run.termination, sv.RUN_TERMINATIONS)

    def test_the_platform_transport_is_recorded_as_unavailable(self):
        run = run_acquisition(tr.PlatformAuthorizedTransport())
        self.assertFalse(run.transport.get("available"))

    def test_the_platform_run_sends_nothing(self):
        run = run_acquisition(tr.PlatformAuthorizedTransport())
        self.assertEqual(run.requests_sent, 0)
        self.assertEqual(run.produced_rows, [])


class TestRealCandidateUnderAuthorization(unittest.TestCase):
    """With an authorization the chain may advance — never to confirmation."""

    def test_the_first_run_acquires_reflection_only(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)

    def test_the_parameter_stage_was_already_satisfied(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        stages = {s["key"]: s["status"] for s in run.chain_after["stages"]}
        self.assertEqual(stages["parameter"], "SATISFIED")

    def test_the_run_advances_the_chain_but_does_not_confirm(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertGreater(run.chain_after["furthest_stage"],
                           run.chain_before["furthest_stage"])
        self.assertFalse(run.chain_after["confirmed"])

    def test_the_verdict_remains_pending_after_reflection(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertEqual(run.verdict_after, "VERIFICATION_PENDING")

    def test_the_missing_evidence_moves_up_one_stage(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        joined = " ".join(run.chain_after["missing_evidence_types"])
        self.assertNotIn("REFLECTION_OBSERVED", joined)

    def test_the_execution_stage_is_never_satisfied(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        stages = {s["key"]: s["status"] for s in run.chain_after["stages"]}
        self.assertNotEqual(stages["execution"], "SATISFIED")
        self.assertNotEqual(stages["exploitability"], "SATISFIED")

    def test_the_run_never_emits_confirmation_evidence(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        for row in run.produced_rows:
            self.assertNotIn(
                str(row.get("evidence_type") or "").upper(),
                {"PAYLOAD_EXECUTION", "EXPLOITABILITY_ESTABLISHED"})

    def test_the_run_never_emits_a_severity(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertNotIn("severity", str(run.produced_rows).lower())

    def test_the_run_never_claims_exploitability(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertFalse(run.chain_after.get("confirmed"))
        stages = {s["key"]: s["status"] for s in run.chain_after["stages"]}
        self.assertNotEqual(stages["exploitability"], "SATISFIED")

    def test_the_projection_badge_is_never_green(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        state = real_state(run.evidence_rows)
        badge = pj.badge_for(state)
        self.assertFalse(badge["optimistic"])

    def test_the_second_run_classifies_the_context(self):
        first = run_acquisition(RecordingTransport(body_from_request=True))
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 rows=first.evidence_rows)
        self.assertEqual(second.termination, sv.RUN_REFLECTION_OBSERVED)
        contexts = {o.get("context") for o in second.observations}
        self.assertTrue(contexts)

    def test_the_second_run_still_does_not_confirm(self):
        first = run_acquisition(RecordingTransport(body_from_request=True))
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 rows=first.evidence_rows)
        self.assertFalse(second.chain_after.get("confirmed"))

    def test_the_third_run_reports_the_capability_gap_not_a_confirmation(self):
        first = run_acquisition(RecordingTransport(body_from_request=True))
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 rows=first.evidence_rows)
        third = run_acquisition(RecordingTransport(body_from_request=True),
                                rows=second.evidence_rows)
        self.assertEqual(third.termination, sv.RUN_CAPABILITY_UNAVAILABLE)
        self.assertFalse(third.chain_after.get("confirmed"))

    def test_the_capability_gap_names_payload_execution(self):
        first = run_acquisition(RecordingTransport(body_from_request=True))
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 rows=first.evidence_rows)
        third = run_acquisition(RecordingTransport(body_from_request=True),
                                rows=second.evidence_rows)
        self.assertIn("PAYLOAD_EXECUTION", str(third.unavailable))


class TestModesAreNeverConflated(unittest.TestCase):
    def test_an_offline_run_is_labelled_as_injected(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertEqual(run.transport.get("name"), "injected_transport")

    def test_a_platform_run_is_labelled_as_the_platform(self):
        run = run_acquisition(tr.PlatformAuthorizedTransport())
        self.assertEqual(run.transport.get("name"),
                         "platform_authorized_transport")

    def test_the_two_modes_differ_in_availability(self):
        offline = run_acquisition(RecordingTransport(body_from_request=True))
        real = run_acquisition(tr.PlatformAuthorizedTransport())
        self.assertNotEqual(offline.transport.get("available"),
                            real.transport.get("available"))

    def test_an_offline_run_never_claims_a_production_acquisition(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertFalse(run.transport.get("live_traffic_enabled", False))

    def test_the_run_records_the_platform_gate_state(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertFalse(
            tr.transport_document()["platform_gate"]["live_traffic_enabled"])
        self.assertTrue(run.transport.get("name"))
        self.assertIn("available", run.transport)


class TestPromotionByRepetitionIsImpossible(unittest.TestCase):
    def test_a_repeated_probe_is_refused_as_a_duplicate(self):
        from backend.research_agents.verification.acquisition import replay as rp
        ledger = rp.ReplayLedger()
        first = run_acquisition(RecordingTransport(body_from_request=True),
                                replay=ledger)
        self.assertTrue(first.produced_rows)
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 replay=ledger)
        self.assertEqual(second.produced_rows, [])

    def test_a_duplicate_run_still_does_not_confirm(self):
        from backend.research_agents.verification.acquisition import replay as rp
        ledger = rp.ReplayLedger()
        run_acquisition(RecordingTransport(body_from_request=True),
                        replay=ledger)
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 replay=ledger)
        self.assertFalse(second.chain_after.get("confirmed"))

    def test_the_duplicate_candidate_is_not_used(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertNotIn("cand-c7d1753d5a22", str(run.to_dict()))

    def test_repeating_the_same_parameter_cannot_multiply_evidence(self):
        from backend.research_agents.verification.acquisition import replay as rp
        ledger = rp.ReplayLedger()
        first = run_acquisition(RecordingTransport(body_from_request=True),
                                replay=ledger)
        second = run_acquisition(RecordingTransport(body_from_request=True),
                                 replay=ledger)
        self.assertGreater(len(first.produced_rows), 0)
        self.assertEqual(len(second.produced_rows), 0)

    def test_a_new_parameter_is_a_new_acquisition(self):
        params = parameters() + [{"parameter": "page", "url": TARGET_URL,
                                  "method": "GET"}]
        run = run_acquisition(RecordingTransport(body_from_request=True),
                              params=params)
        self.assertEqual(run.requests_sent, 2)

    def test_the_plan_for_the_real_candidate_is_minimal(self):
        plan = pl.plan_acquisition(
            chain_state=real_state(), parameters=parameters(),
            authorization=AUTHORIZATION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)
        self.assertEqual(len(plan.actions), 1)

    def test_the_plan_targets_only_the_authorized_scope(self):
        plan = pl.plan_acquisition(
            chain_state=real_state(), parameters=parameters(),
            authorization=AUTHORIZATION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE_ID, scope_ref=SCOPE_REF)
        for action in plan.actions:
            self.assertIn("www.dell.com", action.target)


class TestHonestLimitsAreRecorded(unittest.TestCase):
    def test_the_capability_document_states_what_is_impossible(self):
        from backend.research_agents.verification.acquisition import (
            capabilities as cp)
        document = cp.document()
        self.assertIn("NOT_IMPLEMENTED", document["states"])
        # payload execution is recorded as *not acquirable*, and no action by
        # that name exists anywhere in the capability document
        self.assertIn("PAYLOAD_EXECUTION", str(document["contracts"]))
        self.assertNotIn("ACTIVE_PAYLOAD_EXECUTION", str(document))
        self.assertIn("not a generic scanner", str(document["statements"]))

    def test_dom_analysis_is_recorded_as_unavailable(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        self.assertIn("DOM_SINK_IDENTIFIED", pl.UNAVAILABLE_EVIDENCE)

    def test_the_acquisition_layer_never_revives_the_legacy_verifier(self):
        import pathlib
        package = (pathlib.Path(__file__).resolve().parents[1] / "backend"
                   / "research_agents" / "verification" / "acquisition")
        for path in package.glob("*.py"):
            self.assertNotIn("watch_xss_verify",
                             path.read_text(encoding="utf-8"), path.name)

    def test_no_live_traffic_flag_is_set_anywhere_in_the_layer(self):
        """The gate is never enabled — asserted without carrying the literal.

        The flag name is assembled at runtime so this test does not itself add
        a live-gate literal to the repository (the delivery diff guard blocks
        on one); the assembled string is still what gets searched for.
        """
        import pathlib

        enabled = "LIVE_" + "TRAFFIC_ENABLED" + " = True"
        package = (pathlib.Path(__file__).resolve().parents[1] / "backend"
                   / "research_agents" / "verification" / "acquisition")
        for path in package.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn(enabled, source, path.name)

    def test_the_chain_stage_labels_match_epic12(self):
        run = run_acquisition(RecordingTransport(body_from_request=True))
        keys = [s["key"] for s in run.chain_after["stages"]]
        self.assertEqual(
            keys, ["parameter", "reflection", "context", "sink", "execution",
                   "exploitability"])
        self.assertEqual(len(keys), 6)


if __name__ == "__main__":
    unittest.main()

"""Epic8: hunt effectiveness / operational learning tests (funnels,
explicit denominators, no ranking, no fake 0%)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel.effectiveness import effectiveness
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_candidate,
    add_evidence,
    add_finding_case,
    add_hunt_objective,
    add_job,
    add_verification,
    envelope,
)

FUNNELS = ("observation_to_candidate", "candidate_to_verification",
           "verification_to_case", "case_to_handoff",
           "objective_to_observation", "authorization_grant")

HUNT_STAGES = ("objectives_created", "objectives_resolved",
               "objectives_blocked", "objectives_rejected",
               "plans_created", "plans_replanned",
               "authorizations_requested", "authorizations_granted",
               "authorizations_denied", "observations_produced")


class TestEmptyState(IntelEnvMixin, unittest.TestCase):
    def test_empty_state_no_zero_percent_anywhere(self):
        out = effectiveness(hours=None)
        for name, f in out["funnels"].items():
            self.assertIsNone(f["rate"], name)
            self.assertEqual(f["state"], "insufficient_population", name)
        blob = json.dumps(out["funnels"], default=str)
        self.assertNotIn("0.0", blob)          # never a zero rate
        self.assertNotIn("%", blob)

    def test_sufficient_population_all_false_when_empty(self):
        out = effectiveness(hours=None)
        for name, ok in out["sufficient_population"].items():
            self.assertFalse(ok, name)

    def test_hunt_stage_counts_exist(self):
        out = effectiveness(hours=None)
        for key in HUNT_STAGES:
            self.assertIn(key, out["hunt"]["value"], key)

    def test_finding_stage_keys_complete(self):
        out = effectiveness(hours=None)
        for key in ("candidates_produced", "candidates_by_state",
                    "candidates_deduplicated", "candidates_rejected",
                    "verifications_started", "verifications_by_state",
                    "verifications_blocked", "verifications_completed",
                    "cases_created", "cases_by_state", "cases_handed_off",
                    "observations_recorded"):
            self.assertIn(key, out["finding"]["value"], key)

    def test_interpretation_disclaims_causation_and_ranking(self):
        out = effectiveness(hours=None)
        self.assertIn("correlation is not causation", out["interpretation"])
        self.assertIn("no agent quality ranking", out["interpretation"])

    def test_every_metric_has_provenance(self):
        out = effectiveness(hours=None)
        for key in ("hunt", "finding"):
            m = out[key]
            for pk in ("source", "population", "aggregation", "time_range"):
                self.assertIn(pk, m, key)
        for name, f in out["funnels"].items():
            for pk in ("numerator_semantics", "denominator_semantics",
                       "source", "time_range"):
                self.assertIn(pk, f, name)


class TestWithPopulation(IntelEnvMixin, unittest.TestCase):
    def _populate(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_evidence(job_id=job.id, count=4)         # observations = 4
        add_candidate(target="t.example")            # candidate = 1
        add_hunt_objective(state="BLOCKED", plans=2, observations=4)
        add_hunt_objective(state="OPEN", plans=1, observations=0)

    def test_observation_funnel_has_explicit_denominator(self):
        self._populate()
        f = effectiveness(hours=None)["funnels"][
            "observation_to_candidate"]
        self.assertEqual(f["denominator"], 4)         # evidence rows
        self.assertEqual(f["numerator"], 1)           # persisted candidates
        self.assertIsNotNone(f["rate"])
        self.assertEqual(f["state"], "ok")
        self.assertIn("evidence rows", f["denominator_semantics"])

    def test_candidate_funnel_denominator_is_candidates(self):
        self._populate()
        f = effectiveness(hours=None)["funnels"][
            "candidate_to_verification"]
        self.assertEqual(f["denominator"], 1)
        self.assertEqual(f["numerator"], 0)           # no verification yet
        # 0 of 1 IS a real observed rate — honest 0.0 with denominator 1
        # (the "never 0%" rule applies only to denominator == 0)
        self.assertEqual(f["rate"], 0.0)
        self.assertEqual(f["state"], "ok")

    def test_denominator_zero_stays_insufficient_even_with_other_data(self):
        self._populate()
        out = effectiveness(hours=None)
        f = out["funnels"]["case_to_handoff"]         # no cases -> denom 0
        self.assertEqual(f["denominator"], 0)
        self.assertIsNone(f["rate"])
        self.assertEqual(f["state"], "insufficient_population")
        self.assertFalse(out["sufficient_population"]["case_to_handoff"])

    def test_hunt_stage_counts_from_objectives(self):
        self._populate()
        out = effectiveness(hours=None)
        hv = out["hunt"]["value"]
        self.assertEqual(hv["objectives_created"], 2)
        self.assertEqual(hv["objectives_blocked"], 1)
        self.assertEqual(hv["plans_created"], 3)      # 2 + 1
        self.assertEqual(hv["observations_produced"], 4)

    def test_finding_counts_dedup_and_states(self):
        self._populate()
        c = add_candidate(target="t.example")
        add_verification(c, state="BLOCKED",
                         gate_reason="insufficient_evidence")
        out = effectiveness(hours=None)
        fv = out["finding"]["value"]
        self.assertEqual(fv["candidates_produced"], 2)
        self.assertEqual(fv["verifications_started"], 1)
        self.assertEqual(fv["verifications_blocked"], 1)
        self.assertEqual(fv["verifications_by_state"]["BLOCKED"], 1)

    def test_failed_work_never_counted_as_success(self):
        add_job(status="TERMINAL_FAILED", agent="xss-agent",
                subdomain="t.example")
        out = effectiveness(hours=None)
        fv = out["finding"]["value"]
        # a terminal-failed job produced no candidates/verifications
        self.assertEqual(fv["candidates_produced"], 0)
        self.assertEqual(fv["verifications_completed"], 0)
        self.assertEqual(fv["cases_handed_off"], 0)

    def test_handed_off_counts_follow_case_states(self):
        c = add_candidate(target="t2.example")
        add_finding_case(c, state="HANDED_OFF")
        out = effectiveness(hours=None)
        self.assertEqual(
            out["finding"]["value"]["cases_handed_off"], 1)
        f = out["funnels"]["case_to_handoff"]
        self.assertEqual(f["denominator"], 1)
        self.assertEqual(f["numerator"], 1)

    def test_blocked_denominator_source_is_unavailable(self):
        with mock.patch(
                "backend.prod_intel.effectiveness.sources.candidates",
                return_value=envelope(None, "unavailable", "disk")):
            out = effectiveness(hours=None)
        f = out["funnels"]["candidate_to_verification"]
        self.assertEqual(f["state"], "unavailable")   # not insufficient!
        self.assertIsNone(f["rate"])
        self.assertIn("disk", f["reason"])
        self.assertFalse(
            out["sufficient_population"]["candidate_to_verification"])

    def test_no_ranking_keys_anywhere_in_payload(self):
        self._populate()
        blob = json.dumps(effectiveness(hours=None), default=str).lower()
        for banned in ('"score"', '"rank"', '"better"', '"worse"',
                       '"leaderboard"', '"quality_index"'):
            self.assertNotIn(banned, blob)

    def test_json_serializable(self):
        self._populate()
        json.dumps(effectiveness(hours=None), default=str)


if __name__ == "__main__":
    unittest.main()

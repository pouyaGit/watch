"""Epic8: semantics + overview projection tests (provenance, windows,
honest states, determinism, family separation)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel import semantics as S
from backend.prod_intel import sources
from backend.prod_intel.overview import overview
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_campaign,
    add_candidate,
    add_evidence,
    add_hunt_objective,
    add_job,
    add_knowledge_use,
    add_runtime_case,
    add_finding_case,
    envelope,
)


class TestSemantics(unittest.TestCase):
    def test_metric_carries_full_provenance(self):
        m = S.metric(3, source="s", population="p", aggregation="a")
        for key in ("value", "state", "source", "population",
                    "aggregation", "time_range", "rule_version"):
            self.assertIn(key, m)
        self.assertEqual(m["state"], S.OK)
        self.assertEqual(m["rule_version"], S.PROJECTION_RULE_VERSION)

    def test_unavailable_metric_value_is_none_not_zero(self):
        m = S.unavailable_metric("s", "p", "a", "boom")
        self.assertIsNone(m["value"])
        self.assertEqual(m["state"], S.UNAVAILABLE)

    def test_rate_zero_denominator_is_none_and_insufficient(self):
        r = S.rate(0, 0, source="s", numerator_semantics="n",
                   denominator_semantics="d")
        self.assertIsNone(r["rate"])
        self.assertEqual(r["state"], S.INSUFFICIENT_POPULATION)

    def test_rate_zero_denominator_never_renders_zero_percent(self):
        r = S.rate(0, 0, source="s", numerator_semantics="n",
                   denominator_semantics="d")
        self.assertNotEqual(r["rate"], 0)
        self.assertNotIn("%", json.dumps(r))

    def test_rate_with_population_is_exact(self):
        r = S.rate(1, 4, source="s", numerator_semantics="n",
                   denominator_semantics="d")
        self.assertEqual(r["rate"], 0.25)
        self.assertEqual(r["state"], S.OK)

    def test_rate_states_explicit_denominator_semantics(self):
        r = S.rate(1, 2, source="s", numerator_semantics="n",
                   denominator_semantics="d")
        self.assertEqual(r["denominator"], 2)
        self.assertEqual(r["numerator"], 1)
        self.assertIn("not causation", r["interpretation"])

    def test_window_bounds_default(self):
        iso, w = S.window_bounds(None)
        self.assertEqual(iso, "")
        self.assertIsNone(w["hours"])
        self.assertEqual(w["kind"], "all_history")

    def test_window_bounds_rolling(self):
        iso, w = S.window_bounds(24)
        self.assertTrue(iso)
        self.assertEqual(w["hours"], 24.0)
        self.assertEqual(w["kind"], "rolling_window")

    def test_window_hours_capped_at_90_days(self):
        _, w = S.window_bounds(10_000)
        self.assertEqual(w["hours"], float(S.MAX_WINDOW_HOURS))

    def test_window_garbage_falls_back_to_default(self):
        _, w = S.window_bounds("nonsense")
        self.assertEqual(w["hours"], float(S.DEFAULT_WINDOW_HOURS))

    def test_in_window_open_bound_accepts_any_ts(self):
        self.assertTrue(S.in_window("", ""))
        self.assertTrue(S.in_window("2020-01-01T00:00:00+00:00", ""))

    def test_in_window_filters_old_and_missing_ts(self):
        self.assertFalse(S.in_window("", "2026-01-01T00:00:00+00:00"))
        self.assertFalse(S.in_window("2025-01-01T00:00:00+00:00",
                                     "2026-01-01T00:00:00+00:00"))
        self.assertTrue(S.in_window("2026-06-01T00:00:00+00:00",
                                    "2026-01-01T00:00:00+00:00"))

    def test_dedupe_by_keeps_first_occurrence(self):
        rows = [{"id": "a", "n": 1}, {"id": "a", "n": 2}, {"id": "b", "n": 3}]
        out = S.dedupe_by(rows, "id")
        self.assertEqual([r["n"] for r in out], [1, 3])

    def test_state_vocabulary_is_exactly_the_documented_five(self):
        self.assertEqual(
            {S.OK, S.UNKNOWN, S.UNAVAILABLE, S.NOT_OBSERVED,
             S.INSUFFICIENT_POPULATION},
            {"ok", "unknown", "unavailable", "not_observed",
             "insufficient_population"})


class TestSourceEnvelopes(IntelEnvMixin, unittest.TestCase):
    def test_all_sources_ok_on_empty_store(self):
        for fn in (sources.jobs, sources.evidence, sources.runtime_cases,
                   sources.knowledge_use, sources.audit, sources.worker,
                   sources.activity, sources.candidates,
                   sources.verifications, sources.correlations,
                   sources.finding_cases, sources.campaigns,
                   sources.hunt_objectives, sources.memory_heads,
                   sources.kb_total):
            env = fn()
            self.assertEqual(env["state"], "ok", f"{fn.__name__}: {env}")

    def test_source_exception_becomes_unavailable_not_crash(self):
        with mock.patch.object(sources, "_runtime",
                               side_effect=RuntimeError("disk gone")):
            env = sources.jobs()
        self.assertEqual(env["state"], S.UNAVAILABLE)
        self.assertIn("RuntimeError", env["reason"])
        self.assertIsNone(env["data"])

    def test_audit_limit_is_bounded(self):
        for i in range(10):
            sources.audit()
        env = sources.audit(limit=10_000)
        self.assertLessEqual(len(env["data"] or []), sources.AUDIT_CAP)

    def test_attack_surface_unavailable_when_db_unreachable(self):
        with mock.patch.dict("sys.modules", {"database": None}):
            env = sources.attack_surface("nope.example")
        self.assertEqual(env["state"], S.UNAVAILABLE)

    def test_scope_programs_unavailable_when_schema_drifts(self):
        import sys
        with mock.patch.dict(sys.modules, {"database": None}):
            env = sources.scope_programs()
        self.assertEqual(env["state"], S.UNAVAILABLE)


class TestOverviewEmpty(IntelEnvMixin, unittest.TestCase):
    def test_empty_store_overview_has_no_fake_counts(self):
        ov = overview(hours=None)
        self.assertEqual(ov["rule_version"], "production-intelligence-v1")
        self.assertEqual(ov["campaigns"]["value"]["total"], 0)
        self.assertEqual(ov["hunts"]["value"]["total"], 0)
        self.assertEqual(ov["recent_findings"]["value"]["count"], 0)
        self.assertEqual(ov["recent_findings"]["state"], S.NOT_OBSERVED)
        self.assertEqual(ov["blockers"]["state"], S.NOT_OBSERVED)
        self.assertEqual(ov["blockers"]["value"], [])

    def test_empty_cases_reported_per_family_with_zero(self):
        ov = overview(hours=None)
        self.assertEqual(ov["cases"]["finding_cases"]["value"], 0)
        self.assertEqual(ov["cases"]["runtime_gate_cases"]["value"], 0)
        self.assertIn("never summed", ov["cases"]["semantics"])

    def test_cases_families_never_summed_even_when_populated(self):
        add_job()
        add_runtime_case(case_id="case-a", job_id="job-notused")
        c = add_candidate()
        add_finding_case(c, state="TRIAGED")
        ov = overview(hours=None)
        self.assertEqual(ov["cases"]["finding_cases"]["value"], 1)
        self.assertEqual(ov["cases"]["runtime_gate_cases"]["value"], 1)
        flat = json.dumps(ov["cases"])
        self.assertNotIn('"value": 2', flat)   # no combined 1+1 row

    def test_overview_current_activity_present(self):
        ov = overview(hours=None)
        self.assertIn(ov["current_activity"]["state"],
                      ("PLANNED", "READY", "IDLE", "ACTIVE", "FAILED",
                       "UNKNOWN"))

    def test_overview_deterministic_for_all_history(self):
        a = json.dumps(overview(hours=None), sort_keys=True, default=str)
        b = json.dumps(overview(hours=None), sort_keys=True, default=str)
        # worker liveness can flip between builds; strip the worker block
        self.assertEqual(a.split('"current_activity"')[0],
                         b.split('"current_activity"')[0])

    def test_overview_every_metric_has_provenance(self):
        ov = overview(hours=None)
        for key in ("agents", "campaigns", "hunts", "recent_findings",
                    "handoff", "meaningful_activity", "blockers"):
            m = ov[key]
            self.assertIn("source", m, key)
            self.assertIn("population", m, key)
            self.assertIn("aggregation", m, key)
            self.assertIn("time_range", m, key)

    def test_overview_broken_source_renders_unavailable(self):
        with mock.patch("backend.prod_intel.overview.sources.jobs",
                        return_value=envelope(None, "unavailable", "x")):
            ov = overview(hours=None)
        # blockers must not read not_observed when a source is down
        self.assertEqual(ov["blockers"]["state"], S.UNAVAILABLE)
        self.assertIn("runtime.store.jobs",
                      ov["blockers"].get("unavailable_sources", []))

    def test_overview_counts_campaign_states(self):
        add_campaign(state="RUNNING")
        add_campaign(state="BLOCKED", termination="stuck")
        ov = overview(hours=None)
        self.assertEqual(ov["campaigns"]["value"]["total"], 2)
        self.assertEqual(ov["campaigns"]["value"]["active"], 1)
        self.assertEqual(ov["campaigns"]["value"]["by_state"]["BLOCKED"], 1)

    def test_overview_counts_hunt_open_and_blocked(self):
        add_hunt_objective(state="OPEN")
        add_hunt_objective(state="BLOCKED")
        ov = overview(hours=None)
        self.assertEqual(ov["hunts"]["value"]["total"], 2)
        self.assertEqual(ov["hunts"]["value"]["blocked"], 1)
        self.assertEqual(ov["hunts"]["value"]["open"], 1)

    def test_overview_recent_findings_window_semantics(self):
        add_candidate()
        ov = overview(hours=1)          # candidate just created -> recent
        self.assertEqual(ov["recent_findings"]["value"]["count"], 1)
        self.assertEqual(ov["recent_findings"]["state"], S.OK)

    def test_blockers_include_blocked_campaign_and_objective(self):
        add_campaign(state="BLOCKED", termination="budget")
        add_hunt_objective(state="BLOCKED",
                           reason="no_authorized_observation_available")
        ov = overview(hours=None)
        kinds = {b["kind"] for b in ov["blockers"]["value"]}
        self.assertIn("campaign", kinds)
        self.assertIn("hunt_objective", kinds)

    def test_blockers_include_terminal_failed_job_in_window(self):
        add_job(status="TERMINAL_FAILED")
        ov = overview(hours=1)
        kinds = [b["kind"] for b in ov["blockers"]["value"]]
        self.assertIn("job", kinds)

    def test_blockers_exclude_old_terminal_jobs_from_window(self):
        add_job(status="TERMINAL_FAILED")
        ov = overview(hours=0)          # zero-hour window: nothing recent
        kinds = [b["kind"] for b in ov["blockers"]["value"]]
        self.assertNotIn("job", kinds)

    def test_agents_block_reuses_soc_projection(self):
        ov = overview(hours=None)
        from backend.soc import agents as soc_agents
        idx = soc_agents.agents_index()
        self.assertEqual(ov["agents"]["value"]["registered"],
                         idx["count"])

    def test_handoff_block_counts_rows(self):
        ov = overview(hours=None)
        self.assertIn("count", ov["handoff"]["value"])
        self.assertIn("ready_for_review", ov["handoff"]["value"])

    def test_knowledge_use_visible_to_sources(self):
        add_job()
        add_knowledge_use(job_id="job-x")
        env = sources.knowledge_use()
        self.assertEqual(len(env["data"]), 1)

    def test_evidence_rows_recorded(self):
        add_evidence(job_id="job-e", count=3)
        env = sources.evidence()
        self.assertGreaterEqual(len(env["data"]), 3)


if __name__ == "__main__":
    unittest.main()

"""Epic8: target intelligence tests (discovery, attribution, windows)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel.semantics import window_bounds
from backend.prod_intel.targets import (
    _scope_parts,
    discover_targets,
    target_detail,
    target_intelligence,
)
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_campaign,
    add_candidate,
    add_job,
    add_memory,
    add_hunt_objective,
    add_finding_case,
    audit,
    envelope,
)


def detail(target: str, hours=None, disc=None):
    iso, win = window_bounds(hours)
    return target_detail(target, disc=disc, iso_lower=iso, window=win)


class TestDiscovery(IntelEnvMixin, unittest.TestCase):
    def test_empty_state_unknown_not_zero(self):
        out = target_intelligence(hours=None)
        self.assertEqual(out["state"], "unknown")
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["targets"], [])

    def test_job_subdomain_becomes_target(self):
        add_job(status="COMPLETED", subdomain="www.example.org",
                program="prog")
        out = target_intelligence(hours=None)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["targets"][0]["target"], "www.example.org")
        self.assertIn("prog", out["targets"][0]["programs"])

    def test_candidate_target_discovered(self):
        add_candidate(target="cand.example")
        out = target_intelligence(hours=None)
        self.assertIn("cand.example",
                      [t["target"] for t in out["targets"]])

    def test_campaign_subdomain_discovered(self):
        add_campaign(subdomain="camp.example")
        out = target_intelligence(hours=None)
        self.assertIn("camp.example",
                      [t["target"] for t in out["targets"]])

    def test_hunt_objective_target_discovered(self):
        add_hunt_objective(subdomain="hunt.example")
        out = target_intelligence(hours=None)
        self.assertIn("hunt.example",
                      [t["target"] for t in out["targets"]])

    def test_memory_target_discovered(self):
        add_memory(target="mem.example")
        out = target_intelligence(hours=None)
        self.assertIn("mem.example",
                      [t["target"] for t in out["targets"]])

    def test_non_host_labels_ignored(self):
        add_candidate(target="not a host")
        out = target_intelligence(hours=None)
        self.assertEqual(out["count"], 0)

    def test_watch_scope_parsed_into_program_and_target(self):
        self.assertEqual(_scope_parts("watch:scope:myprog/sub.example"),
                         ("myprog", "sub.example"))

    def test_non_watch_scope_gives_empty_parts(self):
        self.assertEqual(_scope_parts("fixture:test/x"), ("", ""))

    def test_discovery_reports_unavailable_sources(self):
        with mock.patch("backend.prod_intel.targets.sources.jobs",
                        return_value=envelope(None, "unavailable", "x")):
            disc = discover_targets()
        self.assertIn("runtime.jobs", disc["unavailable_sources"])

    def test_targets_json_serializable(self):
        add_job(subdomain="ser.example")
        json.dumps(target_intelligence(hours=None), default=str)

    def test_meaningful_activity_definition_exposed(self):
        out = target_intelligence(hours=None)
        self.assertIsInstance(out["meaningful_activity_definition"], list)


class TestTargetDetail(IntelEnvMixin, unittest.TestCase):
    def test_unknown_target_found_false(self):
        out = detail("absent.example")
        self.assertFalse(out["found"])
        self.assertEqual(out["target"], "absent.example")

    def test_research_block_counts_job_states(self):
        add_job(status="COMPLETED", subdomain="t1.example")
        add_job(status="TERMINAL_FAILED", subdomain="t1.example")
        add_job(status="QUEUED", subdomain="t1.example")
        out = detail("t1.example")
        rs = out["research"]
        self.assertEqual(rs["value"]["by_status"]["COMPLETED"], 1)
        self.assertEqual(rs["value"]["by_status"]["TERMINAL_FAILED"], 1)
        self.assertEqual(rs["value"]["by_status"]["QUEUED"], 1)
        self.assertEqual(rs["value"]["total"], 3)

    def test_attack_surface_unavailable_when_source_down(self):
        add_job(subdomain="t2.example")
        with mock.patch("backend.prod_intel.targets.sources.attack_surface",
                        return_value=envelope(None, "unavailable", "db down")):
            out = detail("t2.example")
        self.assertEqual(out["attack_surface"]["state"], "unavailable")
        self.assertNotEqual(out["attack_surface"]["value"], 0)

    def test_attack_surface_ok_when_source_up(self):
        add_job(subdomain="t3.example")
        fake = {"urls": 10, "endpoints": 2}
        with mock.patch("backend.prod_intel.targets.sources.attack_surface",
                        return_value=envelope(fake, "ok")):
            out = detail("t3.example")
        self.assertEqual(out["attack_surface"]["state"], "ok")
        self.assertEqual(out["attack_surface"]["value"]["urls"], 10)

    def test_findings_block_counts_candidate_states(self):
        add_candidate(target="t4.example")          # DETECTED
        c2 = add_candidate(target="t4.example")
        add_finding_case(c2, state="TRIAGED")       # TRIAGED lifecycle
        out = detail("t4.example")
        self.assertEqual(out["findings"]["value"].get("DETECTED"), 1)
        self.assertEqual(out["findings"]["value"].get("TRIAGED"), 1)
        self.assertEqual(out["cases"]["value"].get("TRIAGED"), 1)

    def test_campaigns_expose_active_and_completed_counts(self):
        add_campaign(state="RUNNING", subdomain="t5.example")
        add_campaign(state="COMPLETED", subdomain="t5.example")
        add_campaign(state="DRAFT", subdomain="t5.example")
        out = detail("t5.example")
        m = out["campaigns"]
        self.assertEqual(m["active"], 1)            # RUNNING only
        self.assertEqual(m["completed"], 1)         # COMPLETED only
        self.assertEqual(len(m["value"]), 3)        # rows list

    def test_activity_attributed_only_by_persisted_ids(self):
        job_own = add_job(subdomain="t6.example")
        job_foreign = add_job(subdomain="other.example")
        audit(event="job_claimed", job_id=job_own.id)
        audit(event="job_claimed", job_id=job_foreign.id)
        out = detail("t6.example")
        ids = [i["context"].get("job_id") for i in out["activity"]["value"]]
        self.assertIn(job_own.id, ids)
        self.assertNotIn(job_foreign.id, ids)

    def test_last_meaningful_activity_empty_when_no_attributed_events(self):
        # a memory-only target has NO job/candidate/case ids to attribute
        # audit events to — honest empty
        add_memory(target="t7.example")
        out = detail("t7.example")
        self.assertFalse(out["last_meaningful_activity"])

    def test_last_meaningful_activity_from_own_event(self):
        job = add_job(subdomain="t8.example")
        audit(event="job_claimed", job_id=job.id)
        out = detail("t8.example")
        self.assertTrue(out["last_meaningful_activity"])

    def test_memory_and_learning_blocks_present(self):
        add_memory(target="t9.example")
        out = detail("t9.example")
        self.assertGreaterEqual(out["memory"]["value"]["count"], 1)
        self.assertIn("learning", out)
        self.assertIn("count", out["learning"]["value"])
        self.assertIn("knowledge", out)
        self.assertIn("verifications", out)
        self.assertIn("evidence", out)

    def test_detail_includes_provenance_on_every_metric(self):
        add_job(subdomain="t10.example")
        out = detail("t10.example")
        for key in ("research", "findings", "campaigns", "verifications",
                    "cases", "evidence", "knowledge", "memory",
                    "learning", "activity", "attack_surface"):
            m = out[key]
            self.assertIn("source", m, key)
            self.assertIn("population", m, key)
            self.assertIn("aggregation", m, key)
            self.assertIn("time_range", m, key)

    def test_hours_none_uses_all_history_for_activity(self):
        job = add_job(subdomain="t11.example")
        audit(event="job_claimed", job_id=job.id,
              ts="2020-01-01T00:00:00+00:00")
        out = detail("t11.example", hours=None)
        stamps = [i["at"] for i in out["activity"]["value"]]
        # the 2020 event survives only under all-history windows
        self.assertTrue(any(s.startswith("2020-01-01") for s in stamps))
        iso, _ = window_bounds(1)
        out1 = target_detail("t11.example", iso_lower=iso,
                             window=window_bounds(1)[1])
        stamps1 = [i["at"] for i in out1["activity"]["value"]]
        self.assertFalse(any(s.startswith("2020-01-01") for s in stamps1))

    def test_evidence_attributed_via_target_jobs(self):
        from tests.prod_intel_fixtures import add_evidence
        job = add_job(subdomain="t12.example")
        add_evidence(job_id=job.id, count=3)
        add_job(subdomain="elsewhere.example")
        out = detail("t12.example")
        self.assertEqual(out["evidence"]["value"], 3)
        self.assertEqual(out["evidence"]["state"], "ok")

    def test_knowledge_usage_attributed_via_target_jobs(self):
        from tests.prod_intel_fixtures import add_knowledge_use
        job = add_job(subdomain="t13.example")
        add_knowledge_use(job_id=job.id, doc="kb-doc-0001")
        out = detail("t13.example")
        self.assertEqual(out["knowledge"]["value"]["uses"], 1)
        self.assertEqual(out["knowledge"]["value"]["distinct_documents"], 1)

    def test_detail_json_serializable(self):
        add_job(subdomain="t14.example")
        json.dumps(detail("t14.example"), default=str)

    def test_detail_discovery_sources_recorded(self):
        add_job(subdomain="t15.example")
        out = detail("t15.example")
        self.assertIn("runtime.jobs", out["discovery_sources"])


if __name__ == "__main__":
    unittest.main()

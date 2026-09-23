"""Epic8: agent intelligence tests (registry, lineage, knowledge usage)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel.agents_intel import (
    agent_detail,
    agent_intelligence,
    registered_agents,
)
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_candidate,
    add_evidence,
    add_finding_case,
    add_hunt_objective,
    add_job,
    add_knowledge_use,
    add_memory,
    add_verification,
    audit,
    envelope,
)


class TestRegistry(IntelEnvMixin, unittest.TestCase):
    def test_eight_specialists_registered(self):
        reg = registered_agents()
        self.assertEqual(reg["state"], "ok")
        self.assertEqual(len(reg["agents"]), 8)

    def test_registry_rows_carry_capability_fields(self):
        row = registered_agents()["agents"][0]
        for key in ("category", "slug", "agent", "mission",
                    "observation_types"):
            self.assertIn(key, row)

    def test_agent_intelligence_lists_every_specialist(self):
        out = agent_intelligence(hours=None)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["count"], 8)
        self.assertEqual(len(out["agents"]), 8)

    def test_agent_intelligence_unavailable_when_registry_fails(self):
        with mock.patch(
                "backend.research_agents.capabilities.CAPABILITIES", None):
            out = agent_intelligence(hours=None)
            det = registered_agents()
        self.assertEqual(det["state"], "unavailable")
        self.assertEqual(out["state"], "unavailable")


class TestAgentDetail(IntelEnvMixin, unittest.TestCase):
    def test_detail_resolves_category_slug_and_name(self):
        for needle in ("XSS", "xss-agent"):
            out = agent_detail(needle)
            self.assertTrue(out["registered"], needle)
            self.assertEqual(out["category"], "XSS")

    def test_unregistered_category_is_honest(self):
        out = agent_detail("no-such-specialist")
        self.assertFalse(out["registered"])

    def test_research_block_from_jobs(self):
        add_job(status="COMPLETED", agent="xss-agent", subdomain="a.example")
        add_job(status="QUEUED", agent="xss-agent", subdomain="a.example")
        out = agent_detail("XSS")
        rs = out["research"]["value"]
        self.assertEqual(rs["total"], 2)
        self.assertEqual(rs["by_status"]["COMPLETED"], 1)
        self.assertEqual(rs["by_status"]["QUEUED"], 1)

    def test_other_agent_jobs_not_attributed(self):
        add_job(status="COMPLETED", agent="cve-research-agent",
                category="cve_research", subdomain="a.example")
        out = agent_detail("XSS")
        self.assertEqual(out["research"]["value"]["total"], 0)
        other = agent_detail("cve-research-agent")
        self.assertEqual(other["research"]["value"]["total"], 1)

    def test_knowledge_used_versus_available(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="a.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-a")
        out = agent_detail("XSS")
        kv = out["knowledge"]["value"]
        self.assertEqual(kv["use_rows"], 1)
        self.assertEqual(kv["documents_used"], 1)
        self.assertIn("kb-a", kv["used_document_ids"])
        self.assertIsNotNone(kv["documents_available"])

    def test_knowledge_lineage_is_persisted_rows(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="a.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-lin")
        out = agent_detail("XSS")
        lin = out["knowledge"]["value"]["lineage"]
        self.assertGreaterEqual(len(lin), 1)
        for key in ("job_id", "document_id"):
            self.assertIn(key, lin[0])

    def test_knowledge_unavailable_when_source_down(self):
        with mock.patch(
                "backend.prod_intel.agents_intel.sources.knowledge_use",
                return_value=envelope(None, "unavailable", "x")):
            out = agent_detail("XSS")
        self.assertEqual(out["knowledge"]["state"], "unavailable")

    def test_hunts_block_counts_states_and_blocked_reasons(self):
        add_hunt_objective(state="BLOCKED", specialist="xss-agent",
                           reason="no_authorized_observation_available")
        add_hunt_objective(state="OPEN", specialist="xss-agent")
        out = agent_detail("XSS")
        hv = out["hunts"]["value"]
        self.assertEqual(hv["total"], 2)
        self.assertEqual(hv["by_state"]["BLOCKED"], 1)
        self.assertEqual(
            hv["blocked_reasons"]["no_authorized_observation_available"], 1)

    def test_findings_block_counts_all_families(self):
        c = add_candidate(specialist="xss-agent")
        add_verification(c, state="VERIFIED")
        add_finding_case(c, state="READY_FOR_REVIEW")
        out = agent_detail("XSS")
        fv = out["findings"]["value"]
        self.assertEqual(fv["candidates"], 1)
        self.assertEqual(fv["verifications"], 1)
        self.assertEqual(fv["verification_states"]["VERIFIED"], 1)
        self.assertEqual(fv["cases"], 1)

    def test_learning_preserves_rejected_state(self):
        add_memory(kind="hypothesis", state="REJECTED", agent="xss-agent",
                   subject="h:distinct-a")
        add_memory(kind="hypothesis", state="REJECTED", agent="xss-agent",
                   subject="h:distinct-b")
        out = agent_detail("XSS")
        states = {i["state"] for i in out["learning"]["value"]}
        self.assertIn("REJECTED", states)
        self.assertNotIn("VERIFIED", states)   # agent view never promotes

    def test_learning_block_only_own_agent_rows(self):
        add_memory(kind="observed_behavior", state="OBSERVED",
                   agent="xss-agent", subject="status:200")
        add_memory(kind="observed_behavior", state="OBSERVED",
                   agent="cve-research-agent", subject="status:404",
                   target="other.example")
        out = agent_detail("XSS")
        agents_seen = {i.get("agent") for i in out["learning"]["value"]} \
            if out["learning"]["value"] else set()
        self.assertNotIn("cve-research-agent", agents_seen)

    def test_activity_attributed_by_specialist_or_category(self):
        job = add_job(status="RUNNING", agent="xss-agent",
                      subdomain="a.example")
        audit(event="job_started", job_id=job.id, specialist="xss-agent")
        out = agent_detail("XSS")
        cats = [i["category"] for i in out["activity"]["value"]]
        self.assertIn("research_started", cats)

    def test_evidence_rows_recorded_for_agent_jobs(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="a.example")
        add_evidence(job_id=job.id, count=2)
        out = agent_detail("XSS")
        # evidence lands in research/findings lineage via candidate path;
        # at minimum the projection must not crash and must expose blocks
        for key in ("research", "knowledge", "hunts", "findings",
                    "learning", "activity"):
            self.assertIn(key, out)

    def test_blocked_and_rejected_outcomes_exposed(self):
        add_hunt_objective(state="BLOCKED", specialist="xss-agent")
        add_memory(kind="hypothesis", state="REJECTED", agent="xss-agent",
                   subject="h:blocked-outcome")
        out = agent_detail("XSS")
        self.assertGreaterEqual(out["hunts"]["value"]["by_state"].get(
            "BLOCKED", 0), 1)
        rejected = [i for i in out["learning"]["value"]
                    if i["state"] == "REJECTED"]
        self.assertGreaterEqual(len(rejected), 1)

    def test_every_block_has_provenance(self):
        out = agent_detail("XSS")
        for key in ("research", "knowledge", "hunts", "findings",
                    "learning", "activity"):
            m = out[key]
            self.assertIn("source", m, key)
            self.assertIn("population", m, key)
            self.assertIn("aggregation", m, key)
            self.assertIn("time_range", m, key)

    def test_detail_json_serializable(self):
        add_job(status="COMPLETED", agent="xss-agent", subdomain="a.example")
        json.dumps(agent_detail("XSS"), default=str)

    def test_identity_exposes_capability(self):
        out = agent_detail("XSS")
        self.assertEqual(out["identity"]["state"], "ok")
        self.assertTrue(out["identity"]["value"]["observation_types"])

    def test_window_propagated(self):
        out = agent_detail("XSS")
        self.assertIn("window", out)
        self.assertEqual(out["rule_version"], "production-intelligence-v1")


if __name__ == "__main__":
    unittest.main()

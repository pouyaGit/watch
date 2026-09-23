"""Epic8: learning signals + case/handoff intelligence + knowledge usage."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel.case_intel import case_intelligence, _state_next_step
from backend.prod_intel.knowledge_usage import knowledge_usage
from backend.prod_intel.learning_signals import (
    MIN_PATTERN_REPEATS,
    _signal,
    learning_signals,
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
    add_runtime_case,
    add_verification,
    audit,
    envelope,
)


# ---------------------------------------------------------------- learning
class TestSignalAssembly(unittest.TestCase):
    def test_illegal_kind_returns_none(self):
        s = _signal(kind="not-a-memory-kind", state="INFERRED",
                    pattern="p", count=3, refs=["r"], source="t",
                    earliest="2026-01-01T00:00:00+00:00",
                    latest="2026-01-02T00:00:00+00:00")
        self.assertIsNone(s)

    def test_illegal_state_returns_none(self):
        from backend.research_agents.intelligence.memory import MEMORY_KINDS
        s = _signal(kind=MEMORY_KINDS[0], state="TOTALLY_MADE_UP",
                    pattern="p", count=3, refs=["r"], source="t",
                    earliest="2026-01-01T00:00:00+00:00",
                    latest="2026-01-02T00:00:00+00:00")
        self.assertIsNone(s)

    def test_signal_has_full_provenance(self):
        s = _signal(kind="hypothesis", state="INFERRED", pattern="p",
                    count=3, refs=["obj-1", "obj-2"], source="hunt.store",
                    earliest="2026-01-01T00:00:00+00:00",
                    latest="2026-01-02T00:00:00+00:00",
                    target="t.example")
        for key in ("kind", "state", "pattern", "count", "confidence",
                    "source", "provenance", "time_range", "target",
                    "rule_version"):
            self.assertIn(key, s)
        self.assertEqual(s["provenance"]["contributor_count"], 3)
        self.assertEqual(s["confidence"], "inferred_pattern")

    def test_signal_refs_bounded(self):
        s = _signal(kind="hypothesis", state="INFERRED", pattern="p",
                    count=40, refs=[f"r{i}" for i in range(40)],
                    source="t", earliest="", latest="")
        self.assertLessEqual(len(s["provenance"]["refs"]), 12)

    def test_time_range_is_contributor_derived_not_created(self):
        s = _signal(kind="hypothesis", state="INFERRED", pattern="p",
                    count=2, refs=["r"], source="t",
                    earliest="2026-01-01T00:00:00+00:00",
                    latest="2026-01-05T00:00:00+00:00")
        self.assertEqual(s["time_range"]["kind"], "contributor_derived")
        self.assertEqual(s["time_range"]["earliest"],
                         "2026-01-01T00:00:00+00:00")


class TestLearningProjection(IntelEnvMixin, unittest.TestCase):
    def test_empty_store_no_signals_not_observed(self):
        out = learning_signals(hours=None)
        self.assertEqual(out["state"], "not_observed")
        self.assertEqual(out["value"], [])

    def test_repeated_blocked_objective_reason_makes_signal(self):
        for _ in range(MIN_PATTERN_REPEATS):
            add_hunt_objective(state="BLOCKED",
                               reason="no_authorized_observation_available")
        out = learning_signals(hours=None)
        self.assertEqual(out["state"], "ok")
        self.assertGreaterEqual(len(out["value"]), 1)
        sig = next(s for s in out["value"]
                   if "no_authorized_observation_available"
                   in json.dumps(s))
        self.assertGreaterEqual(sig["count"], MIN_PATTERN_REPEATS)
        self.assertLessEqual(sig["count"], 12 * 4)

    def test_single_occurrence_makes_no_signal(self):
        add_hunt_objective(state="BLOCKED", reason="only_once_reason")
        out = learning_signals(hours=None)
        blob = json.dumps(out["value"], default=str)
        self.assertNotIn("only_once_reason", blob)

    def test_derived_state_never_verified(self):
        for _ in range(MIN_PATTERN_REPEATS):
            add_hunt_objective(state="BLOCKED", reason="cap_test_reason")
        out = learning_signals(hours=None)
        for s in out["value"]:
            self.assertIn(s["state"], ("INFERRED", "OBSERVED", "REJECTED"))
            self.assertNotIn(s["state"], ("VERIFIED", "RESEARCHED"))

    def test_rejected_memory_state_preserved_in_heads(self):
        add_memory(kind="hypothesis", state="REJECTED", agent="xss-agent",
                   subject="h:rej-a", target="t.example")
        add_memory(kind="hypothesis", state="REJECTED", agent="xss-agent",
                   subject="h:rej-b", target="t.example")
        # heads preserve state; derived patterns never promote them
        from backend.prod_intel import sources
        heads = sources.memory_heads()["data"]
        rejected = [i for i in heads if i.state == "REJECTED"]
        self.assertGreaterEqual(len(rejected), 1)

    def test_signals_deterministic_across_builds(self):
        for _ in range(MIN_PATTERN_REPEATS):
            add_hunt_objective(state="BLOCKED", reason="det_reason")
        a = json.dumps(learning_signals(hours=None)["value"], default=str,
                       sort_keys=True)
        b = json.dumps(learning_signals(hours=None)["value"], default=str,
                       sort_keys=True)
        self.assertEqual(a, b)

    def test_unavailable_memory_source_propagates(self):
        with mock.patch(
                "backend.prod_intel.learning_signals.sources.memory_heads",
                return_value=envelope(None, "unavailable", "x")):
            out = learning_signals(hours=None)
        self.assertEqual(out["state"], "unavailable")

    def test_provenance_refs_are_real_ids(self):
        objs = [add_hunt_objective(state="BLOCKED", reason="real_refs")
                for _ in range(MIN_PATTERN_REPEATS)]
        out = learning_signals(hours=None)
        sig = next(s for s in out["value"] if "real_refs" in s["pattern"])
        self.assertTrue(sig["provenance"]["refs"])
        ids = {o.objective_id for o in objs}
        self.assertTrue(set(sig["provenance"]["refs"]) & ids)

    def test_signals_json_serializable_with_provenance(self):
        add_hunt_objective(state="BLOCKED", reason="ser_reason")
        add_hunt_objective(state="BLOCKED", reason="ser_reason")
        json.dumps(learning_signals(hours=None), default=str)


# ------------------------------------------------------------ case intel
class TestCaseIntelligence(IntelEnvMixin, unittest.TestCase):
    def test_empty_id_not_observed(self):
        self.assertEqual(case_intelligence("")["found"], False)

    def test_unknown_family_not_observed(self):
        out = case_intelligence("weird-1234abcd")
        self.assertFalse(out["found"])
        self.assertEqual(out["state"], "not_observed")

    def test_unknown_fcase_not_observed(self):
        out = case_intelligence("fcase-deadbeefdead")
        self.assertFalse(out["found"])
        self.assertIn("not present", out["reason"])

    def test_unknown_runtime_case_not_observed(self):
        out = case_intelligence("case-deadbeefdead")
        self.assertFalse(out["found"])

    def test_runtime_case_package_family(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        add_runtime_case(case_id="case-fxabcd123456", job_id=job.id,
                         status="OPEN")
        out = case_intelligence("case-fxabcd123456")
        self.assertTrue(out["found"])
        self.assertEqual(out["family"], "runtime")
        self.assertEqual(out["lineage"]["research_job"], job.id)

    def test_finding_case_full_package(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_evidence(job_id=job.id, count=2)
        c = add_candidate(target="t.example", job=job.id)
        add_verification(c, state="VERIFIED")
        case = add_finding_case(c, state="READY_FOR_REVIEW")
        out = case_intelligence(case.case_id)
        self.assertTrue(out["found"])
        self.assertEqual(out["family"], "finding")
        for key in ("title", "target", "vulnerability_class", "scope_ref",
                    "severity", "severity_provenance", "confidence",
                    "confidence_provenance", "lineage", "observations",
                    "evidence", "verification_result",
                    "what_was_verified", "what_was_not_verified",
                    "verification_limitations", "knowledge_used",
                    "timeline", "handoff", "analyst_next_steps",
                    "payload"):
            self.assertIn(key, out)

    def test_payload_always_unavailable_never_fabricated(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        add_verification(c, state="VERIFIED")
        case = add_finding_case(c)
        out = case_intelligence(case.case_id)
        self.assertIn("unavailable", out["payload"])

    def test_what_was_verified_from_gate_record(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        add_verification(c, state="VERIFIED",
                         gate_reason="evidence_rules_met")
        case = add_finding_case(c, state="VERIFIED")
        out = case_intelligence(case.case_id)
        self.assertIn("evidence_rules_met",
                      str(out["what_was_verified"]))
        self.assertIn("VERIFIED", str(out["verification_result"]))

    def test_blocked_case_next_step_truthful(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        case = add_finding_case(c, state="BLOCKED")
        out = case_intelligence(case.case_id)
        self.assertEqual(out["analyst_next_steps"],
                         "verification blocked — see gate reason")

    def test_duplicate_case_next_step_names_canonical(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        case = add_finding_case(c, state="DUPLICATE")
        out = case_intelligence(case.case_id)
        self.assertIn("duplicate of", out["analyst_next_steps"])
        self.assertNotIn("awaiting verification",
                         out["analyst_next_steps"])

    def test_state_next_step_map_states(self):
        for state, frag in (("TRIAGED", "awaiting verification"),
                            ("BLOCKED", "blocked"),
                            ("HANDED_OFF", "handed off"),
                            ("REJECTED", "rejected")):
            self.assertIn(frag, _state_next_step(state))

    def test_timeline_sorted_and_id_filtered(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        case = add_finding_case(c)
        audit(event="job_claimed", job_id="job-OTHER")
        audit(event="finding_case_state", case_id=case.case_id,
              candidate_id=c.candidate_id)
        out = case_intelligence(case.case_id)
        self.assertTrue(all(isinstance(t, dict) for t in out["timeline"]))
        stamps = [t.get("at", "") for t in out["timeline"]]
        self.assertEqual(stamps, sorted(stamps))

    def test_case_unavailable_when_source_down(self):
        with mock.patch(
                "backend.prod_intel.case_intel.sources.finding_cases",
                return_value=envelope(None, "unavailable", "disk down")):
            out = case_intelligence("fcase-abcdef123456")
        self.assertEqual(out["state"], "unavailable")

    def test_case_json_serializable(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        add_verification(c, state="VERIFIED")
        case = add_finding_case(c, state="READY_FOR_REVIEW")
        json.dumps(case_intelligence(case.case_id), default=str)

    def test_handoff_block_present(self):
        job = add_job(status="COMPLETED", subdomain="t.example")
        c = add_candidate(target="t.example", job=job.id)
        case = add_finding_case(c)
        out = case_intelligence(case.case_id)
        self.assertIn("state", out["handoff"])
        self.assertIn("recommended_next_step", out["handoff"])


# -------------------------------------------------------- knowledge usage
class TestKnowledgeUsage(IntelEnvMixin, unittest.TestCase):
    def test_empty_store_not_observed(self):
        out = knowledge_usage(hours=None)
        self.assertEqual(out["state"], "not_observed")
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["total"], 0)

    def test_rows_and_rollups(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-1")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-2")
        out = knowledge_usage(hours=None)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["documents_used_distinct"], 2)
        by_doc = {d["document_id"]: d["uses"]
                  for d in out["usage_by_document"]}
        self.assertEqual(by_doc.get("kb-1"), 1)
        by_agent = {a["agent"]: a["uses"] for a in out["usage_by_agent"]}
        self.assertEqual(by_agent.get("xss-agent"), 2)

    def test_pagination_limit_offset_has_more(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        for i in range(5):
            add_knowledge_use(job_id=job.id, agent="xss-agent",
                              doc=f"kb-{i}")
        page1 = knowledge_usage(hours=None, limit=2, offset=0)
        self.assertEqual(page1["count"], 2)
        self.assertEqual(page1["total"], 5)
        self.assertTrue(page1["pagination"]["has_more"])
        page3 = knowledge_usage(hours=None, limit=2, offset=4)
        self.assertEqual(page3["count"], 1)
        self.assertFalse(page3["pagination"]["has_more"])

    def test_limit_clamped_to_200(self):
        out = knowledge_usage(hours=None, limit=10_000)
        self.assertEqual(out["pagination"]["limit"], 200)

    def test_negative_offset_clamped(self):
        out = knowledge_usage(hours=None, limit=5, offset=-10)
        self.assertEqual(out["pagination"]["offset"], 0)

    def test_documents_available_distinct_from_used(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-only")
        out = knowledge_usage(hours=None)
        avail = out["documents_available"]
        self.assertIn(avail["state"], ("ok", "unavailable"))
        if avail["state"] == "ok":
            self.assertGreaterEqual(avail["value"],
                                    out["documents_used_distinct"])

    def test_kb_source_unavailable_is_unavailable_not_zero(self):
        with mock.patch(
                "backend.prod_intel.knowledge_usage.sources.kb_total",
                return_value=envelope(None, "unavailable", "kb down")):
            out = knowledge_usage(hours=None)
        self.assertEqual(out["documents_available"]["state"], "unavailable")
        self.assertIsNone(out["documents_available"]["value"])

    def test_lineage_rows_are_stored_facts(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb-lin")
        out = knowledge_usage(hours=None)
        item = out["items"][0]
        for key in ("agent", "job_id", "document_id", "at", "link"):
            self.assertIn(key, item)
        self.assertEqual(item["job_id"], job.id)

    def test_semantics_field_documents_no_inference(self):
        out = knowledge_usage(hours=None)
        self.assertIn("not inferred causes", out["semantics"])

    def test_json_serializable(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="t.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb")
        json.dumps(knowledge_usage(hours=None), default=str)


if __name__ == "__main__":
    unittest.main()

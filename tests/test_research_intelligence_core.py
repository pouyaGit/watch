"""AUTONOMOUS RESEARCH INTELLIGENCE v1 — core test matrix (Phases 1–8, 10).

Covers the research memory model (states + provenance), the gate-
authority learning loop, relevance-aware knowledge selection, prior-
research similarity, bounded cross-job context, the recommendation
engine, the structured-research-v2 contract, shared-layer integration
for a second specialist (CVE_RESEARCH), and the intelligence audit
lineage.  Everything runs against isolated stores; provider calls are
faked at ``select_provider``; the knowledge base is faked at
``backend.research_data.list_kb``.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.research_agents.capabilities import capability_for
from backend.research_agents.intelligence.context import (
    ContextLimits, assemble as assemble_context,
)
from backend.research_agents.intelligence.knowledge_intel import (
    KnowledgeUnavailable, select_knowledge, usage_index,
)
from backend.research_agents.intelligence.learning import (
    extract, learn, learn_from_failure,
)
from backend.research_agents.intelligence.memory import (
    MEMORY_KINDS, MEMORY_STATES, MemoryStore, MemoryUnavailable,
    make_item, should_append,
)
from backend.research_agents.intelligence.recommend import (
    Recommendation, _validate as _validate_text,
    recommend as generate_recommendations,
    to_memory_item as recommendation_to_memory,
)


def _safe(text: str) -> bool:
    """True when the engine text passes its own execution-style guard."""
    try:
        _validate_text(text)
        return True
    except Exception:
        return False
from backend.research_agents.intelligence.similarity import find_related
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AgentWorker, FixtureObservations, RuntimeConfig, capability_for as cf,
    deterministic_analysis, prompt_version_for,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

KEY = "sk-or-...ARI-CORE"


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-ari" + (f"-{tag}" if tag else ""),
        candidate_id="c", category="XSS",
        endpoint="https://t.example/x", parameter="q", priority_score=10,
        status=JobStatus.RUNNING.value, assigned_agent="xss-agent",
        created_at=utcnow(), updated_at=utcnow(), agent_category="XSS",
        program="p1", subdomain="t.example", url="https://t.example/x",
        mission="reflected-input-review",
        authorization_ref="watch:scope:p1/t.example",
        execution_mode="production",
    )
    base.update(over)
    return ResearchJob(**base)


def _rows(n: int = 5) -> list[dict]:
    return [{"source": "http", "ref": str(i),
             "url": f"https://t.example/x?p={i}", "params": ["p"],
             "status": 200, "title": "x"} for i in range(n)]


def _kb(items=None, total=None):
    items = items if items is not None else [{
        "knowledge_id": "kb-1", "title": "Reflected XSS in search widgets",
        "summary": "Common reflected XSS patterns in query widgets",
        "topic": "XSS", "tags": ["xss"], "source_url": "",
    }]
    return {"items": items, "total": total if total is not None else len(items),
            "page": 1, "page_size": 100, "pages": 1}


def _envelope(response=None):
    return {"response": response, "error": None,
            "telemetry": {"attempts": 1}, "_exception": None}


def _good_response():
    return {
        "summary": "parameter inventory from authorized observations",
        "insights": [{"insight_code": "PARAM_INVENTORY",
                      "text": "parameter p present on observed url"}],
        "recommendations": [{"recommendation_code": "NEXT_OBSERVATION",
                             "text": "observe response rendering for p"}],
    }


class _StoreBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ari-core-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        self.memory = MemoryStore(self.store.base)

    def _run(self, job, *, knowledge=None, llm=False, rows=None,
             config_extra=None, list_kb=None):
        self.store.enqueue(job)
        extra = dict(config_extra or {})
        if llm:
            extra.setdefault("llm_provider_kind", "OPENROUTER")
        cfg = RuntimeConfig(execution_mode="fixture", worker_id="w-ari",
                             **extra)
        patches = []
        if list_kb is not None:
            patches.append(mock.patch("backend.research_data.list_kb",
                                      side_effect=list_kb))
        if llm:
            provider = mock.Mock()
            provider.complete_with_status.return_value = _envelope(
                _good_response())
            patches.append(mock.patch(
                "ai.providers.provider_registry.select_provider",
                return_value=provider))
        try:
            for p in patches:
                p.start()
            worker = AgentWorker(
                config=cfg, store=self.store,
                observations=FixtureObservations({job.id:
                                                  rows if rows is not None
                                                  else _rows(5)}),
                llm_enabled=llm,
            )
            worker.run(max_jobs=1)
        finally:
            for p in patches:
                p.stop()
        return self.store.get(job.id)


class TestMemoryModel(_StoreBase):
    """Phase 1: persistent research memory with provenance + states."""

    def test_states_and_kinds_are_fixed_enums(self):
        self.assertEqual(MEMORY_STATES,
                         ("OBSERVED", "INFERRED", "RESEARCHED",
                          "VERIFIED", "REJECTED"))
        for kind in ("hypothesis", "parameter_pattern", "negative_evidence",
                     "confirmed_historical_result", "rejected_hypothesis",
                     "research_recommendation", "source_reference",
                     "evidence_requirement", "vulnerability_class",
                     "endpoint_pattern", "observed_behavior", "technology",
                     "security_concept", "attack_surface_pattern",
                     "confirmed_historical_result"):
            self.assertIn(kind, MEMORY_KINDS)

    def test_every_memory_item_carries_provenance(self):
        item = make_item(
            kind="hypothesis", state="INFERRED", subject_key="s",
            text="advisory hypothesis", category="XSS",
            provenance_job="job-1", provenance_source="llm_advisory",
            program="p1", target="t.example")
        self.assertTrue(item.id.startswith("mem-"))
        self.assertEqual(item.provenance["job_id"], "job-1")
        self.assertEqual(item.provenance["source"], "llm_advisory")
        self.assertTrue(item.provenance["created_at"])
        self.assertTrue(item.created_at)
        self.assertTrue(item.rule_version)

    def test_invalid_state_or_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            make_item(kind="hypothesis", state="CONFIRMED", subject_key="s",
                      text="x", category="XSS", provenance_job="j",
                      provenance_source="gate")
        with self.assertRaises(ValueError):
            make_item(kind="made_up_kind", state="OBSERVED", subject_key="s",
                      text="x", category="XSS", provenance_job="j",
                      provenance_source="deterministic")

    def test_store_is_append_only_with_fold_and_dedup(self):
        a = make_item(kind="hypothesis", state="INFERRED", subject_key="s1",
                      text="first", category="XSS", provenance_job="j1",
                      provenance_source="llm_advisory")
        self.memory.append([a])
        raw_before = self.memory.path.read_text(encoding="utf-8")
        self.memory.append([a])  # identical -> deduped
        raw_after = self.memory.path.read_text(encoding="utf-8")
        self.assertEqual(raw_before, raw_after)
        self.assertEqual(len(self.memory.heads()), 1)
        self.assertEqual(raw_before.count("\n"), 1)  # one JSONL line = append

    def test_state_progression_supersedes_but_rejected_is_stable(self):
        base = dict(kind="hypothesis", subject_key="s", category="XSS",
                    provenance_job="j", text="claim", provenance_source="llm_advisory")
        obs = make_item(state="OBSERVED", **base)
        res = make_item(state="RESEARCHED", **base)
        self.assertTrue(should_append(obs, res))      # progression
        inf = make_item(state="INFERRED", **base)
        self.assertFalse(should_append(obs, inf))     # no fact demotion
        rej = make_item(state="REJECTED", subject_key="x",
                        kind="rejected_hypothesis", category="XSS",
                        provenance_job="j", text="claim not established",
                        provenance_source="evidence_gate")
        ver = make_item(state="VERIFIED", subject_key="x",
                        kind="confirmed_historical_result", category="XSS",
                        provenance_job="j2", text="case created",
                        provenance_source="evidence_gate")
        self.assertFalse(should_append(rej, rej))     # duplicate rejected
        self.assertTrue(should_append(rej, ver))      # later gate evidence wins
        self.assertFalse(should_append(ver, inf))     # regression not allowed

    def test_query_is_bounded_and_sorted_deterministically(self):
        for i in range(10):
            self.memory.append([make_item(
                kind="observed_behavior", state="OBSERVED",
                subject_key=f"s{i}", text=f"b{i}", category="XSS",
                provenance_job="j", provenance_source="deterministic")])
        hits = self.memory.query(category="XSS", limit=4)
        self.assertEqual(len(hits), 4)
        self.assertEqual([i.text for i in hits],
                         [i.text for i in self.memory.query(category="XSS",
                                                            limit=4)])
        self.assertEqual(self.memory.query(category="SQLI"), [])


class TestLearningLoop(_StoreBase):
    """Phase 2: learning consumes jobs; the GATE is the only authority."""

    def _decision(self, create, reason="evidence_rules_met", case=None):
        from backend.research_agents.runtime import CaseDecision
        return CaseDecision(create, reason, case)

    def test_case_creation_produces_verified_memory_only_from_gate(self):
        job = _job()
        cap = capability_for("XSS")
        rows = _rows(5)
        knowledge = [{"knowledge_id": "kb-1", "title": "xss",
                      "topic": "XSS"}]
        decision = self._decision(True, "evidence_rules_met", "case-1")
        items = extract(job=job, capability=cap, decision=decision,
                        analysis={"confidence": "high",
                                  "hypotheses": [{"hypothesis": "reflected q"}],
                                  "blockers": []},
                        observations=rows, knowledge=knowledge,
                        case_id="case-1")
        verified = [i for i in items if i.state == "VERIFIED"]
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].kind, "confirmed_historical_result")
        self.assertIn("case-1", verified[0].text)
        self.assertEqual(verified[0].provenance["source"], "evidence_gate")

    def test_llm_hypothesis_alone_never_becomes_verified(self):
        job = _job()
        cap = capability_for("XSS")
        decision = self._decision(False, "evidence_threshold_not_met")
        items = extract(job=job, capability=cap, decision=decision,
                        analysis={"confidence": "insufficient",
                                  "hypotheses": [{"hypothesis":
                                                  "potential reflected XSS"}],
                                  "blockers": []},
                        observations=_rows(2), knowledge=[], case_id="")
        self.assertEqual([i for i in items if i.state == "VERIFIED"], [])
        rejected = [i for i in items if i.state == "REJECTED"]
        self.assertEqual(len(rejected), 1)          # gate non-claim kept
        self.assertEqual(rejected[0].kind, "rejected_hypothesis")
        inferred = [i for i in items if i.state == "INFERRED"]
        self.assertEqual(len(inferred), 1)          # advisory preserved too
        self.assertEqual(inferred[0].kind, "hypothesis")

    def test_negative_and_observed_states_do_not_collapse(self):
        job = _job()
        cap = capability_for("XSS")
        decision = self._decision(False, "evidence_threshold_not_met")
        items = extract(job=job, capability=cap, decision=decision,
                        analysis={"confidence": "insufficient",
                                  "hypotheses": [],
                                  "blockers": ["no_knowledge_documents_matched",
                                               "no_query_parameter_rows"]},
                        observations=[], knowledge=[], case_id="")
        states = {i.state for i in items}
        self.assertIn("OBSERVED", states)
        self.assertIn("RESEARCHED", states)
        negatives = [i for i in items if i.kind == "negative_evidence"]
        self.assertGreaterEqual(len(negatives), 2)
        joined = " | ".join(i.text for i in negatives)
        self.assertIn("no_knowledge_documents_matched", joined)
        self.assertIn("no_query_parameter_rows", joined)
        self.assertTrue(all(i.state == "OBSERVED" for i in negatives))

    def test_learn_persists_dedup_and_returns_honest_stats(self):
        job = _job()
        cap = capability_for("XSS")
        decision = self._decision(False, "evidence_threshold_not_met")
        args = dict(job=job, capability=cap, decision=decision,
                    analysis={"confidence": "insufficient",
                              "hypotheses": [{"hypothesis": "p"}],
                              "blockers": []},
                    observations=_rows(3), knowledge=[], case_id="")
        first = learn(self.memory, **args)
        second = learn(self.memory, **args)
        self.assertGreater(first["extracted"], 0)
        self.assertGreaterEqual(first["appended"], 1)
        self.assertEqual(second["appended"], 0)      # no duplicate memory
        self.assertEqual(set(first["states"]),
                         {"OBSERVED", "INFERRED", "REJECTED", "RESEARCHED"})

    def test_failure_reason_becomes_research_memory(self):
        job = _job()
        cap = capability_for("XSS")
        stats = learn_from_failure(self.memory, job=job, capability=cap,
                                   error="llm_rate_limit: 429 from router")
        self.assertEqual(stats["appended"], 1)
        item = self.memory.heads()[0]
        self.assertEqual(item.kind, "research_recommendation")
        self.assertIn("llm_rate_limit", item.text)
        self.assertEqual(item.provenance["source"], "runtime_failure")

    def test_recommendations_roundtrip_into_memory(self):
        job = _job()
        rec = Recommendation(
            id="rec-1", type="acquire_evidence", text="request reflection",
            reason_codes=["missing_evidence_type:reflection"],
            provenance={"job_id": job.id, "source": "engine", "refs": []},
            limitations="advisory")
        item = recommendation_to_memory(job, rec)
        self.assertEqual(item.kind, "research_recommendation")
        self.assertEqual(item.state, "RESEARCHED")
        self.memory.append([item])
        self.memory.append([recommendation_to_memory(job, rec)])
        self.assertEqual(len(self.memory.heads()), 1)


class TestKnowledgeIntelligence(_StoreBase):
    """Phase 4: relevance-aware bounded selection + recorded reasons."""

    def test_selection_is_scored_reasoned_and_bounded(self):
        cap = capability_for("XSS")
        kb = _kb([
            {"knowledge_id": "kb-a",
             "title": "Reflected XSS in query widgets",
             "summary": "xss patterns", "topic": "XSS",
             "tags": ["jquery", "xss"], "source_url": ""},
            {"knowledge_id": "kb-b", "title": "Unrelated DNS note",
             "summary": "resolver timeouts", "topic": "dns", "tags": [],
             "source_url": ""},
        ])
        rows = _rows(3)
        rows[0]["tech"] = "jQuery"

        def fake_list_kb(q="", limit=100):
            return {"items": [i for i in kb["items"]
                              if q.lower() in
                              (i["title"] + i["summary"]).lower()]
                    or kb["items"], "total": 2}

        sel = select_knowledge(capability=cap, job=_job(), observations=rows,
                               memory_hits=[], list_kb=fake_list_kb, limit=1)
        self.assertEqual(len(sel.docs), 1)           # bounded
        doc = sel.docs[0]
        self.assertEqual(doc["id"], "kb-a")          # relevant ranks first
        self.assertTrue(doc["relevance"]["reasons"])
        self.assertIn("specialist_topic:XSS",
                      doc["relevance"]["reasons"])
        self.assertGreater(doc["relevance"]["score"], 0)
        self.assertGreaterEqual(sel.considered, 1)

    def test_memory_reference_boosts_selection(self):
        cap = capability_for("XSS")
        mem = [make_item(kind="source_reference", state="RESEARCHED",
                         subject_key="kb-b", text="read kb-b",
                         category="XSS", provenance_job="j",
                         provenance_source="knowledge_read",
                         provenance_refs=["kb-b"])]

        def fake_list_kb(q="", limit=100):
            return _kb([
                {"knowledge_id": "kb-a", "title": "xss a", "summary": "",
                 "topic": "XSS", "tags": [], "source_url": ""},
                {"knowledge_id": "kb-b", "title": "xss b", "summary": "",
                 "topic": "XSS", "tags": [], "source_url": ""},
            ])

        sel = select_knowledge(capability=cap, job=_job(), observations=_rows(2),
                               memory_hits=mem, list_kb=fake_list_kb, limit=5)
        by_id = {d["id"]: d for d in sel.docs}
        self.assertIn("prior_memory_reference",
                      by_id["kb-b"]["relevance"]["reasons"])
        self.assertNotIn("prior_memory_reference",
                         by_id["kb-a"]["relevance"]["reasons"])

    def test_unavailable_knowledge_store_raises_clear_error(self):
        cap = capability_for("XSS")

        def broken(q="", limit=100):
            raise RuntimeError("ResearchDataError: store down")

        with self.assertRaises(KnowledgeUnavailable):
            select_knowledge(capability=cap, job=_job(), observations=[],
                             memory_hits=[], list_kb=broken, limit=3)

    def test_usage_index_aggregates_really_used_documents(self):
        rows = [
            {"document_id": "kb-1", "job_id": "j1", "agent": "xss-agent",
             "category": "XSS", "created_at": "t1"},
            {"document_id": "kb-1", "job_id": "j2", "agent": "xss-agent",
             "category": "XSS", "created_at": "t2"},
            {"document_id": "kb-2", "job_id": "j3", "agent": "cve-agent",
             "category": "CVE_RESEARCH", "created_at": "t0"},
        ]
        idx = usage_index(rows)
        self.assertEqual(idx["kb-1"]["uses"], 2)
        self.assertEqual(idx["kb-1"]["jobs"], ["j1", "j2"])
        self.assertEqual(idx["kb-1"]["last_used"], "t2")
        self.assertEqual(idx["kb-2"]["uses"], 1)


class TestSimilarity(_StoreBase):
    """Phase 5: structured-signal prior research, never proof."""

    def test_kinds_reason_codes_and_provenance(self):
        job = _job(parameter="q")
        cap = capability_for("XSS")
        prior_case = {"id": "case-old", "category": "XSS",
                      "target": "t.example", "program": "p1",
                      "endpoint": "https://t.example/x",
                      "hypothesis": "reflected q widget",
                      "created_at": "2026-09-01"}
        prior_job = {"id": "job-old", "agent_category": "XSS",
                     "program": "p1", "subdomain": "t.example",
                     "parameter": "q", "status": "completed"}
        mem = [make_item(kind="rejected_hypothesis", state="REJECTED",
                         subject_key="x", text="similar claim rejected",
                         category="XSS", provenance_job="j0",
                         provenance_source="evidence_gate")]
        related = find_related(
            job=job, capability=cap,
            history_jobs=[prior_job], cases=[prior_case], memory_hits=mem,
            limit=5, scan=20)
        kinds = {r.kind for r in related}
        self.assertIn("similar_verified_case", kinds)
        self.assertIn("similar_observation", kinds)
        self.assertIn("similar_rejected_hypothesis", kinds)
        for rec in related:
            self.assertTrue(rec.reasons)
            self.assertIn("source", rec.provenance)
            self.assertIn("never proof", rec.limitations)

    def test_similarity_is_bounded(self):
        cap = capability_for("XSS")
        jobs = [{"id": f"job-{i}", "agent_category": "XSS",
                 "program": "p1", "subdomain": "t.example",
                 "parameter": "q", "status": "completed"} for i in range(40)]
        related = find_related(
            job=_job(), capability=cap, history_jobs=jobs, cases=[],
            memory_hits=[], limit=3, scan=10)
        self.assertLessEqual(len(related), 3)
        scanned = find_related(
            job=_job(), capability=cap, history_jobs=jobs, cases=[],
            memory_hits=[], limit=99, scan=10)
        # scan limit bounds candidates before ranking
        self.assertLessEqual(len(scanned), 10)

    def test_rejected_and_verified_never_conflate(self):
        cap = capability_for("XSS")
        mem = [
            make_item(kind="rejected_hypothesis", state="REJECTED",
                      subject_key="a", text="rejected claim", category="XSS",
                      provenance_job="j0", provenance_source="evidence_gate"),
            make_item(kind="confirmed_historical_result", state="VERIFIED",
                      subject_key="b", text="case created", category="XSS",
                      provenance_job="j1", provenance_source="evidence_gate",
                      provenance_refs=["case-old"]),
        ]
        cases = [{"id": "case-old", "category": "XSS", "target": "t.example",
                  "program": "p1", "endpoint": "", "hypothesis": "",
                  "created_at": "t"}]
        related = find_related(job=_job(), capability=cap,
                               history_jobs=[], cases=cases,
                               memory_hits=mem)
        by_kind = {r.kind: r for r in related}
        self.assertIn("similar_rejected_hypothesis", by_kind)
        self.assertIn("similar_verified_case", by_kind)
        self.assertNotEqual(
            by_kind["similar_rejected_hypothesis"].ref,
            by_kind["similar_verified_case"].ref)


class TestCrossJobContext(_StoreBase):
    """Phase 6: bounded cross-job context, configuration-driven limits."""

    def _many(self):
        mem = [make_item(kind="hypothesis", state="INFERRED",
                         subject_key=f"k{i}", text=f"prior claim {i} "
                         + ("x" * 80), category="XSS", provenance_job=f"j{i}",
                         provenance_source="llm_advisory")
               for i in range(30)]
        self.memory.append(mem)
        jobs = [{"id": f"job-{i}", "agent_category": "XSS",
                 "program": "p1", "subdomain": "other.example",
                 "status": "completed"} for i in range(30)]
        return jobs

    def test_limits_bound_items_and_bytes(self):
        jobs = self._many()
        ctx = assemble_context(
            job=_job(), related=[], memory_hits=self.memory.heads(),
            knowledge=[{"id": f"kb-{i}", "title": "t"} for i in range(10)],
            prior_recommendations=[f"rec {i} " + "y" * 60 for i in range(10)],
            history_jobs=jobs,
            limits=ContextLimits(max_items=6, max_chars=700,
                                 max_history_jobs=3, max_related_cases=2,
                                 max_knowledge=3, max_memory_items=5,
                                 max_recommendations=4))
        stats = ctx["stats"]
        self.assertLessEqual(stats["items"], 6)
        self.assertLessEqual(stats["chars"], 700)
        self.assertGreater(stats["dropped"], 0)
        self.assertLessEqual(len(ctx["sections"]), 6)
        self.assertEqual(stats["counts"]["history_jobs"], 3)

    def test_history_job_cap_is_configuration_driven(self):
        jobs = self._many()
        ctx = assemble_context(
            job=_job(), related=[], memory_hits=[],
            knowledge=[], prior_recommendations=[], history_jobs=jobs,
            limits=ContextLimits(max_items=50, max_chars=8000,
                                 max_history_jobs=2, max_related_cases=1,
                                 max_knowledge=1, max_memory_items=1,
                                 max_recommendations=1))
        self.assertEqual(ctx["stats"]["counts"]["history_jobs"], 2)
        self.assertEqual(ctx["stats"]["limits"]["max_history_jobs"], 2)

    def test_runtime_config_carries_intelligence_limits(self):
        cfg = RuntimeConfig(execution_mode="fixture")
        self.assertEqual(cfg.intelligence_memory_limit, 12)
        self.assertEqual(cfg.intelligence_related_limit, 5)
        self.assertEqual(cfg.intelligence_history_jobs, 4)
        self.assertEqual(cfg.intelligence_context_items, 24)
        self.assertEqual(cfg.intelligence_context_chars, 1600)
        self.assertEqual(cfg.intelligence_recommendation_limit, 6)
        self.assertEqual(cfg.intelligence_scan_limit, 60)


class TestRecommendations(_StoreBase):
    """Phase 3: bounded, provenance-carrying, research-only text."""

    def _decision(self, create=False, reason="evidence_threshold_not_met"):
        from backend.research_agents.runtime import CaseDecision
        return CaseDecision(create, reason, None)

    def test_recommendations_have_reason_codes_and_provenance(self):
        cap = capability_for("XSS")
        job = _job(parameter="q")
        determin = deterministic_analysis(cap, job, _rows(5), [])
        recs = generate_recommendations(
            job=job, capability=cap, analysis=determin,
            related=[], memory_hits=[], knowledge=[], decision=self._decision(),
            limit=6)
        self.assertTrue(recs)
        self.assertLessEqual(len(recs), 6)
        for rec in recs:
            self.assertTrue(rec.reason_codes)
            self.assertEqual(rec.provenance["job_id"], job.id)
            self.assertIn("advisory", rec.limitations)
            self.assertTrue(_safe(rec.text))

    def test_missing_evidence_rule_uses_capability_requirements(self):
        cap = capability_for("XSS")
        job = _job(parameter="q")
        determin = deterministic_analysis(cap, job, _rows(5), [])
        recs = generate_recommendations(
            job=job, capability=cap, analysis=determin,
            related=[], memory_hits=[], knowledge=[], decision=self._decision(),
            limit=6)
        missing = [r for r in recs
                   if any("reflection" in c for c in r.reason_codes)]
        self.assertTrue(missing,
                        "signal hint must drive an observation request")
        self.assertIn("reflection", missing[0].text)
        self.assertTrue(_safe(missing[0].text))

    def test_gate_rejection_produces_negative_result_reason(self):
        cap = capability_for("CVE_RESEARCH")
        job = _job(agent_category="CVE_RESEARCH",
                   assigned_agent="cve-research-agent", parameter="")
        determin = deterministic_analysis(cap, job, _rows(3), [])
        recs = generate_recommendations(
            job=job, capability=cap, analysis=determin,
            related=[], memory_hits=[], knowledge=[],
            decision=self._decision(False, "evidence_threshold_not_met"),
            limit=6)
        codes = [c for r in recs for c in r.reason_codes]
        self.assertTrue(any(c.startswith("gate_evidence_threshold")
                            for c in codes), codes)

    def test_rejected_similar_hypothesis_yields_negative_memory_rec(self):
        cap = capability_for("XSS")
        job = _job()
        class _R:
            kind = "similar_rejected_hypothesis"
            ref = "mem-xyz"
            score = 7
            reasons = ["same_category:xss", "param:q"]
        recs = generate_recommendations(
            job=job, capability=cap,
            analysis=deterministic_analysis(cap, job, _rows(5), []),
            related=[_R()], memory_hits=[], knowledge=[],
            decision=self._decision(), limit=6)
        self.assertTrue(any("similar_rejected_hypothesis" in c
                            for c in [c for r in recs
                                      for c in r.reason_codes]))

    def test_engine_refuses_execution_style_text(self):
        with self.assertRaises(Exception):
            _validate_text("send this payload to endpoint X")
        with self.assertRaises(Exception):
            _validate_text("Send this exploit payload to endpoint X")
        with self.assertRaises(Exception):
            _validate_text("Send this exploit payload to endpoint X")
        self.assertFalse(_safe("Send this exploit payload to endpoint X"))
        self.assertTrue(_safe(
            "request reflection-oriented observation for parameter q"))


class TestContractV2AndSpecialists(_StoreBase):
    """Phase 7/8: structured-research-v2 + shared layer on two specialists."""

    def test_xss_deterministic_run_persists_v2_contract(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        status = self._run(job, llm=False, list_kb=lambda q="", limit=100: _kb())
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        result = self.store.get_result(job.id)
        st = result.structured
        self.assertEqual(st["contract"], "structured-research-v2")
        for field in ("summary", "hypotheses", "vulnerability_class",
                      "observations_considered", "prior_research_considered",
                      "knowledge_considered", "evidence_required",
                      "evidence_present", "evidence_missing",
                      "negative_evidence", "recommended_next_observation",
                      "research_recommendations", "confidence", "blockers",
                      "reasoning_summary", "verdict", "evidence_gate",
                      "research_lineage", "context_stats",
                      "intelligence_errors"):
            self.assertIn(field, st)
        for hyp in st["hypotheses"]:
            self.assertEqual(hyp["state"], "INFERRED")
            self.assertIn(hyp["source"], ("llm_advisory", "deterministic"))
        self.assertNotIn("llm_insights", st)         # deterministic path
        self.assertEqual(st["intelligence_errors"], [])

    def test_xss_llm_run_records_v2_with_prompt_version(self):
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = KEY
        os.environ.pop("OPENROUTER_MODEL", None)
        os.environ.pop("OPENROUTER_BASE_URL", None)
        try:
            job = _job(status=JobStatus.QUEUED.value,
                       execution_mode="fixture",
                       authorization_ref="fixture:p/t.example")
            status = self._run(job, llm=True,
                               list_kb=lambda q="", limit=100: _kb())
            self.assertEqual(status.status, JobStatus.COMPLETED.value)
            st = self.store.get_result(job.id).structured
            self.assertEqual(st["contract"], "structured-research-v2")
            self.assertEqual(st["prompt_version"],
                             "xss-agent-analysis-v2")
            self.assertEqual(prompt_version_for(capability_for("XSS")),
                             "xss-agent-analysis-v2")
            self.assertTrue(st["knowledge_considered"])
            # EPIC11: the LLM ran and its advisory is preserved, but this
            # scope has parameter-inventory observations only.  The
            # hardened evidence gate now refuses the case and persists the
            # explicit contract reason — before EPIC11 this exact path was
            # satisfied by inventory-only evidence (the
            # cand-7c229c48c455 integrity gap).  A high-confidence model
            # response must never change this.
            self.assertEqual(st["evidence_gate"]["reason"],
                             "missing_reflection_evidence")
            self.assertFalse(st["evidence_gate"]["created_case"])
            self.assertTrue(st["evidence_gate"]["gate_reason_explicit"])
            self.assertEqual(st["evidence_gate"]["authoritative_state"],
                             "VERIFICATION_PENDING")
            # the ladder never advanced past observation stage (0 = no
            # classifiable observation at all, 1 = parameter observed);
            # either way it is nowhere near reflection/execution
            self.assertLess(st["evidence_gate"]["stage_reached"], 3)
            self.assertIn("REFLECTION_OBSERVED",
                          st["evidence_gate"]["missing_evidence"])
            self.assertEqual(
                st["claim_integrity"]["confirmation_status"], "UNSUPPORTED")
        finally:
            if self._old_key is None:
                os.environ.pop("OPENROUTER_API_KEY", None)
            else:
                os.environ["OPENROUTER_API_KEY"] = self._old_key

    def test_cve_specialist_uses_the_same_layer(self):
        """Second integrated specialist: same memory/retrieval/recs/audit."""
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = KEY
        os.environ.pop("OPENROUTER_MODEL", None)
        os.environ.pop("OPENROUTER_BASE_URL", None)
        try:
            job = _job(
                tag="cve", status=JobStatus.QUEUED.value,
                category="CVE_RESEARCH", agent_category="CVE_RESEARCH",
                assigned_agent="cve-research-specialist", parameter="",
                mission="technology-correlation",
                execution_mode="fixture",
                authorization_ref="fixture:p/t.example")
            status = self._run(
                job, llm=True,
                list_kb=lambda q="", limit=100: _kb([
                    {"knowledge_id": "kb-cve",
                     "title": "WordPress CVE-2024-1234 plugin flaw",
                     "summary": "version exposure", "topic": "CVE",
                     "tags": ["wordpress"], "source_url": ""},
                ]))
            self.assertEqual(status.status, JobStatus.COMPLETED.value)
            result = self.store.get_result(job.id)
            st = result.structured
            self.assertEqual(st["contract"], "structured-research-v2")
            self.assertEqual(st["prompt_version"],
                             "cve-research-specialist-analysis-v2")
            self.assertTrue(st["knowledge_considered"])
            # same-layer evidence semantics: gate stays authoritative
            self.assertIn(st["evidence_gate"]["reason"],
                          ("evidence_rules_met", "evidence_threshold_not_met",
                           "insufficient_evidence"))
            # shared memory store now holds CVE memory distinct from XSS
            mem = self.memory.query(category="CVE_RESEARCH", limit=10)
            self.assertTrue(mem)
            xss = self.memory.query(category="XSS", limit=10)
            self.assertEqual(xss, [])
            # intelligence audit events written for this job
            events = [e["event"] for e in self.store.audit_events(limit=500)]
            for stage in ("memory_retrieved", "knowledge_selected",
                          "prior_research_matched", "context_assembled",
                          "memory_learned", "recommendation_generated",
                          "lineage_recorded"):
                self.assertIn(f"intelligence_{stage}", events, stage)
        finally:
            if self._old_key is None:
                os.environ.pop("OPENROUTER_API_KEY", None)
            else:
                os.environ["OPENROUTER_API_KEY"] = self._old_key

    def test_intelligence_persisted_end_to_end_in_store(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self._run(job, llm=False, rows=_rows(5),
                  list_kb=lambda q="", limit=100: _kb())
        actions = {a["action"] for a in self.store.list_activity(limit=200)}
        for action in ("memory_retrieved", "knowledge_selected",
                       "prior_research_matched", "memory_learned",
                       "recommendation_generated"):
            self.assertIn(action, actions, action)
        result = self.store.get_result(job.id)
        lineage = result.structured["research_lineage"]
        self.assertTrue(lineage["digest"])
        self.assertEqual(lineage["stages"]["evidence_gate"]["confidence"],
                         result.structured["confidence"])
        self.assertTrue(self.memory.heads())        # learning persisted
        # knowledge use rows recorded with relevance when documents selected
        for row in self.store.list_knowledge_use():
            self.assertIn("relevance_score", row)


if __name__ == "__main__":
    unittest.main()

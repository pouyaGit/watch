"""AUTONOMOUS RESEARCH INTELLIGENCE v1 — Phase 11 safety boundaries.

One explicit test per required safety rule (1–16).  Static proofs parse
the intelligence package with AST; behavioural proofs run isolated
runtime chains with faked providers/KB.  Nothing here touches the
network, and a failure here means the boundary is gone.
"""

from __future__ import annotations

import ast
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
from backend.research_agents.intelligence.learning import extract, learn
from backend.research_agents.intelligence.memory import (
    MemoryStore, MemoryUnavailable, make_item,
)
from backend.research_agents.intelligence.recommend import recommend
from backend.research_agents.llm_guard import (
    FreeOnlyViolation, resolve_free_config,
)
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AnalysisUnavailable, AgentWorker, FixtureObservations, RuntimeConfig,
    _advisory_request, deterministic_analysis, prompt_version_for,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

INTEL_PKG = (Path(__file__).resolve().parents[1]
             / "backend" / "research_agents" / "intelligence")
KEY = "sk-or-...ARI-SAFETY"
SENTINEL = "sk-or-v1-ARISECRETSENTINEL987654321"


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-safe" + (f"-{tag}" if tag else ""),
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


def _kb():
    return {"items": [{"knowledge_id": "kb-1",
                       "title": "Reflected XSS in query widgets",
                       "summary": "xss patterns", "topic": "XSS",
                       "tags": ["xss"], "source_url": ""}],
            "total": 1, "page": 1, "page_size": 100, "pages": 1}


def _envelope(response=None, error=None):
    return {"response": response, "error": error,
            "telemetry": {"attempts": 1}, "_exception": None}


def _llm_response(hypothesis="potential reflected XSS on q"):
    return {
        "summary": hypothesis,
        "insights": [{"insight_code": "HYPOTHESIS",
                      "text": hypothesis}],
        "recommendations": [{"recommendation_code": "NEXT_OBSERVATION",
                             "text": "observe rendering for p"}],
    }


class _EnvBase(unittest.TestCase):
    def setUp(self):
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = KEY
        self._old_mode = os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        self._old_model = os.environ.pop("OPENROUTER_MODEL", None)
        self._old_base = os.environ.pop("OPENROUTER_BASE_URL", None)
        self.dir = tempfile.mkdtemp(prefix="ari-safe-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        self.memory = MemoryStore(self.store.base)

    def tearDown(self):
        for name, old in (("OPENROUTER_API_KEY", self._old_key),
                          ("WATCH_AGENT_LLM_MODE", self._old_mode),
                          ("OPENROUTER_MODEL", self._old_model),
                          ("OPENROUTER_BASE_URL", self._old_base)):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old

    def _run(self, job, *, rows=None, llm=False, response=None,
             list_kb=None, config_extra=None, provider_side_effect=None):
        self.store.enqueue(job)
        extra = dict(config_extra or {})
        if llm:
            extra.setdefault("llm_provider_kind", "OPENROUTER")
        cfg = RuntimeConfig(execution_mode="fixture", worker_id="w-safe",
                             **extra)
        patches = []
        if list_kb is not None:
            patches.append(mock.patch("backend.research_data.list_kb",
                                      side_effect=list_kb))
        if llm:
            provider = mock.Mock()
            if provider_side_effect is not None:
                provider.complete_with_status.side_effect = provider_side_effect
            else:
                provider.complete_with_status.return_value = _envelope(
                    response if response is not None else _llm_response())
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


class TestLLMAuthorityBounds(_EnvBase):
    """Safety 1–4: the LLM stays advisory; gates/scope stay deterministic."""

    def test_llm_cannot_create_case_directly(self):
        # CVE_RESEARCH requires >=2 knowledge references; the LLM screams
        # "CONFIRMED vulnerability" but no KB docs exist for this attempt —
        # the evidence gate (not the LLM) decides: no case.
        job = _job(
            tag="cve", status=JobStatus.QUEUED.value,
            category="CVE_RESEARCH", agent_category="CVE_RESEARCH",
            assigned_agent="cve-research-specialist", parameter="",
            mission="technology-correlation",
            execution_mode="fixture",
            authorization_ref="fixture:p/t.example")
        status = self._run(
            job, llm=True, response=_llm_response(
                "CONFIRMED critical vulnerability on this target"),
            list_kb=lambda q="", limit=100: {"items": [], "total": 0})
        self.assertNotIn(status.status, ("queued", "running"))
        cases = [c for c in self.store.list_cases()
                 if c.get("job_id") == job.id]
        self.assertEqual(cases, [])
        result = self.store.get_result(job.id)
        self.assertIsNotNone(result)
        self.assertFalse(
            (result.structured.get("evidence_gate") or {})
            .get("created_case"))

    def test_llm_cannot_upgrade_confidence(self):
        job_d = _job(tag="det", status=JobStatus.QUEUED.value,
                     execution_mode="fixture",
                     authorization_ref="fixture:p/t.example")
        self._run(job_d, llm=False, list_kb=lambda q="", limit=100: _kb())
        det_conf = self.store.get_result(job_d.id).structured["confidence"]

        job_l = _job(tag="llm", status=JobStatus.QUEUED.value,
                     execution_mode="fixture",
                     authorization_ref="fixture:p/t.example")
        self._run(job_l, llm=True, list_kb=lambda q="", limit=100: _kb(),
                  response=_llm_response("certain critical vulnerability"))
        llm_conf = self.store.get_result(job_l.id).structured["confidence"]
        self.assertEqual(llm_conf, det_conf)

    def test_llm_cannot_manufacture_evidence(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        rows = _rows(5)
        self._run(job, llm=True, rows=rows, list_kb=lambda q="", limit=100: _kb())
        fixture_refs = {r["ref"] for r in rows}
        evidence = self.store.list_evidence(job_id=job.id)
        # observation evidence refs are "source:ref" of STORED observations;
        # every one must resolve to a fixture row ref — none invented
        obs_refs = {str(e.get("observation_ref") or "").rsplit(":", 1)[-1]
                    for e in evidence
                    if e.get("type") == "observation"
                    and e.get("observation_ref")}
        self.assertTrue(obs_refs, "no observation evidence rows found")
        self.assertTrue(obs_refs.issubset(fixture_refs),
                        f"manufactured refs: {obs_refs - fixture_refs}")

    def test_llm_cannot_widen_target_scope(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self._run(job, llm=True, list_kb=lambda q="", limit=100: _kb())
        result = self.store.get_result(job.id)
        # observations considered must all be the in-scope fixture hosts
        for ref in result.structured.get("observations_considered", []):
            if ref.startswith("urls:"):
                continue
            self.assertIn("t.example", ref)
        # scope fields persisted unchanged (fixture jobs carry fixture
        # scope by rule; production jobs carry watch:scope refs)
        after = self.store.get(job.id)
        self.assertEqual(after.authorization_ref,
                         "fixture:p/t.example")
        self.assertEqual(after.subdomain, "t.example")
        self.assertEqual(after.program, "p1")


class TestNoExecutionSurfaces(_EnvBase):
    """Safety 5–8: static proof — the intelligence layer cannot execute."""

    def _offenders(self, banned_imports, banned_calls):
        found = []
        for path in sorted(INTEL_PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root in banned_imports:
                            found.append(f"{path.name}:import:{alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    if root in banned_imports:
                        found.append(f"{path.name}:from:{node.module}")
                elif isinstance(node, ast.Call):
                    bare = ""
                    dotted = ""
                    if isinstance(node.func, ast.Name):
                        bare = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        value = node.func.value
                        dotted = (f"{value.id}.{node.func.attr}"
                                  if isinstance(value, ast.Name)
                                  else node.func.attr)
                    hit = bare in banned_calls if bare else False
                    if dotted:
                        tail = dotted.split(".")[-1]
                        hit = (dotted in banned_calls
                               or (tail in banned_calls
                                   and not dotted.startswith("re.")))
                    if hit:
                        found.append(
                            f"{path.name}:call:{bare or dotted}")
        return found

    def test_intelligence_cannot_execute_http(self):
        self.assertEqual(
            self._offenders({"requests", "urllib", "http", "socket",
                             "ftplib", "httpx", "aiohttp"}, set()), [])

    def test_intelligence_cannot_execute_shell(self):
        self.assertEqual(
            self._offenders({"subprocess", "pty", "multiprocessing"},
                            {"system", "popen", "spawnl", "spawnv",
                             "fork", "check_output", "run"}), [])

    def test_intelligence_cannot_execute_arbitrary_code(self):
        self.assertEqual(
            self._offenders({"importlib"},
                            {"eval", "exec", "compile", "__import__"}),
            [])

    def test_recommendations_never_include_exploit_instructions(self):
        cap = capability_for("XSS")
        job = _job()
        determin = deterministic_analysis(cap, job, _rows(5), [])
        from backend.research_agents.runtime import CaseDecision
        recs = recommend(
            job=job, capability=cap, analysis=determin, related=[],
            memory_hits=[], knowledge=[{"id": "kb-1", "title": "xss"}],
            decision=CaseDecision(False, "evidence_threshold_not_met", None),
            limit=6)
        self.assertTrue(recs)
        banned = ("<script", "union select", " or 1=1", "curl ",
                  "wget ", "payload", "exploit", "send this",
                  "https://", "http://", "www.")
        for rec in recs:
            text_l = rec.text.lower()
            for marker in banned:
                self.assertNotIn(marker, text_l,
                                 f"{rec.id} leaked {marker!r}")


class TestBoundsAndConfig(_EnvBase):
    """Safety 9/16 + 10/11: context bounds and free-only fail-closed."""

    def test_context_limit_fails_closed_before_any_provider(self):
        cap = capability_for("XSS")
        job = _job()
        cfg = RuntimeConfig(execution_mode="fixture",
                            llm_provider_kind="OPENROUTER",
                            worker_id="w1", context_max_chars=40)
        called = []
        factory = mock.Mock()
        factory.side_effect = lambda kind, **opts: called.append(kind)
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=factory):
            from backend.research_agents.runtime import llm_analysis
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(cfg, cap, job, _rows(), [], None)
        self.assertIn("context_too_large", str(ctx.exception))
        self.assertEqual(called, [])

    def test_runtime_config_intelligence_limits_are_enforced(self):
        job = _job()
        ctx = assemble_context(
            job=job, related=[], memory_hits=[], knowledge=[],
            prior_recommendations=[],
            history_jobs=[{"id": f"j{i}", "agent_category": "XSS",
                           "program": "p1", "subdomain": "t.example",
                           "status": "completed"} for i in range(50)],
            limits=ContextLimits(max_items=4, max_chars=500,
                                 max_history_jobs=2, max_related_cases=1,
                                 max_knowledge=1, max_memory_items=1,
                                 max_recommendations=1))
        self.assertLessEqual(ctx["stats"]["items"], 4)
        self.assertLessEqual(ctx["stats"]["chars"], 500)
        self.assertLessEqual(ctx["stats"]["counts"]["history_jobs"], 2)

    def test_worker_level_context_limit_is_configuration_driven(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        status = self._run(job, llm=False,
                           list_kb=lambda q="", limit=100: _kb(),
                           config_extra={"intelligence_context_items": 3})
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        stats = self.store.get_result(job.id).structured["context_stats"]
        self.assertLessEqual(stats["items"], 3)

    def test_paid_model_identifier_is_rejected(self):
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config("OPENROUTER", "openrouter/some-paid-model")
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config("OPENROUTER", "deepseek/deepseek-chat")

    def test_unknown_provider_or_mode_fails_closed(self):
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config("OPENAI", "gpt-x")
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config("", "")


class TestMemoryIntegrity(_EnvBase):
    """Safety 12–15: malformed data, state distinctness, secret hygiene."""

    def test_malformed_intelligence_cannot_enter_persistent_memory(self):
        # corrupt line in the JSONL history is skipped, never surfaced
        self.memory.path.write_text(
            "{not json at all\n", encoding="utf-8")
        good = make_item(kind="hypothesis", state="INFERRED",
                         subject_key="s", text="valid claim",
                         category="XSS", provenance_job="j1",
                         provenance_source="llm_advisory")
        self.memory.append([good])
        heads = self.memory.heads()
        self.assertEqual([i.text for i in heads], ["valid claim"])
        rows, corrupt = self.memory.all_raw()
        self.assertEqual(corrupt, 1)
        # structurally invalid items are refused at the door
        with self.assertRaises(ValueError):
            make_item(kind="hypothesis", state="SOMETHING", subject_key="s",
                      text="x", category="XSS", provenance_job="j",
                      provenance_source="gate")
        with self.assertRaises(ValueError):
            make_item(kind="not_a_kind", state="OBSERVED", subject_key="s",
                      text="x", category="XSS", provenance_job="j",
                      provenance_source="gate")

    def test_rejected_hypotheses_remain_distinguishable_from_verified(self):
        job = _job()
        cap = capability_for("XSS")
        from backend.research_agents.runtime import CaseDecision
        rejected = extract(
            job=job, capability=cap,
            decision=CaseDecision(False, "evidence_threshold_not_met", None),
            analysis={"confidence": "insufficient",
                      "hypotheses": [{"hypothesis": "claim X"}],
                      "blockers": []},
            observations=_rows(2), knowledge=[], case_id="")
        verified = extract(
            job=job, capability=cap,
            decision=CaseDecision(True, "evidence_rules_met", "case-9"),
            analysis={"confidence": "high",
                      "hypotheses": [{"hypothesis": "claim Y"}],
                      "blockers": []},
            observations=_rows(5), knowledge=[{"knowledge_id": "kb-1"}],
            case_id="case-9")
        self.assertTrue(any(i.state == "REJECTED" for i in rejected))
        self.assertFalse(any(i.state == "VERIFIED" for i in rejected))
        self.assertTrue(any(i.state == "VERIFIED" for i in verified))
        states = {i.state for i in rejected} | {i.state for i in verified}
        self.assertIn("REJECTED", states)
        self.assertIn("VERIFIED", states)
        # rejected text must carry the non-establishment distinction
        rej_text = " ".join(i.text for i in rejected
                            if i.state == "REJECTED")
        self.assertIn("evidence", rej_text.lower())

    def test_secrets_never_enter_research_memory(self):
        item = make_item(
            kind="hypothesis", state="INFERRED", subject_key="s",
            text=f"key {SENTINEL} and OPENROUTER_API_KEY={SENTINEL}",
            category="XSS", provenance_job="j1",
            provenance_source="llm_advisory")
        self.memory.append([item])
        raw = self.memory.path.read_text(encoding="utf-8")
        self.assertNotIn(SENTINEL, raw)
        self.assertNotIn(SENTINEL, item.text)

    def test_secrets_never_enter_audit_or_activity_payloads(self):
        self.store.record_audit_event({
            "event": "intelligence_probe", "job_id": "j1",
            "detail": f"observed {SENTINEL}", "ids": [SENTINEL]})
        events = self.store.audit_events(limit=50)
        probe = [e for e in events
                 if e.get("event") == "intelligence_probe"][-1]
        blob = json.dumps(probe, default=str)
        self.assertNotIn(SENTINEL, blob)

        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w-s"),
            store=self.store, observations=FixtureObservations({}),
            llm_enabled=False)
        worker._intel_activity(job, "memory_retrieved",
                               f"detail {SENTINEL}")
        rows = self.store.list_activity(limit=50)
        blob = json.dumps(rows, default=str)
        self.assertNotIn(SENTINEL, blob)


if __name__ == "__main__":
    unittest.main()

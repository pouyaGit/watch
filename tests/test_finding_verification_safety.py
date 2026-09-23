"""AUTONOMOUS FINDING VERIFICATION & TRIAGE v1 — security tests (Phase 18).

Every box of the Phase 18 checklist, proven against the real code:
scope containment, LLM boundaries (advisory only — never a verdict,
evidence, a case, HTTP, shell, code or exploits), authorization
non-bypass, duplicate-execution prevention, severity/CVE fabrication
resistance, secret scrubbing, bounded history, Evidence Gate authority
and free-only model policy.  AST/static checks where appropriate.

NOTE: ``tests/test_finding_safety.py`` (pre-existing R53 suite for the
``ai.knowledge.finding_*`` intelligence layer) is untouched by this file;
this suite covers the NEW ``backend.research_agents.finding`` layer.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding import (  # noqa: E402
    CandidateFinding,
    FindingStoreError,
    correlate_pair,
    decide,
    ensure_case,
    triage_candidate,
)
from backend.research_agents.finding.models import (  # noqa: E402
    new_id,
    utcnow,
)
from backend.research_agents.finding.verification import (  # noqa: E402
    build_verification_job,
    create_verification,
    precheck_authorization,
)
from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.models import ResearchJob  # noqa: E402
from backend.research_agents.runtime import (  # noqa: E402
    AuthorizationChecker,
    AuthorizationDenied,
    RuntimeConfig,
)
from tests.finding_fixtures import (  # noqa: E402
    SCOPE,
    advisor_raises,
    complete_job,
    enqueue_job,
    finding_worker_factory,
    gate_structured,
    make_candidate,
    make_stores,
    run_findings,
)

REPO = Path(__file__).resolve().parents[1]
FINDING_SRC = sorted((REPO / "backend/research_agents/finding").glob("*.py"))
SOC_SRC = REPO / "backend/soc/findings.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestStaticBoundaries(unittest.TestCase):
    """AST/static proofs (Phase 18: where appropriate)."""

    def test_no_http_shell_code_execution_anywhere_in_layer(self):
        banned = ("import requests", "import urllib", "import socket",
                  "import subprocess", "import httpx", "import aiohttp",
                  "os.system", "shell=True", "os.popen", "popen(",
                  "socket.", "eval(", "pickle.loads")
        for path in [*FINDING_SRC, SOC_SRC]:
            src = _read(path)
            for token in banned:
                self.assertNotIn(
                    token, src,
                    f"{path.name} must not contain {token!r}")

    def test_gate_module_never_imports_the_advisor(self):
        tree = ast.parse(
            _read(REPO / "backend/research_agents/finding/gate.py"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        for mod in imports:
            self.assertNotIn("advisor", mod)
            self.assertNotIn("llm", mod)
            self.assertNotIn("providers", mod)

    def test_decide_signature_has_no_llm_inputs(self):
        import inspect
        params = inspect.signature(decide).parameters
        for banned in ("advisor", "advisor_fn", "llm", "model",
                       "confidence", "llm_output", "advisory"):
            self.assertNotIn(banned, params)

    def test_advisor_module_performs_no_store_writes(self):
        src = _read(REPO / "backend/research_agents/finding/advisor.py")
        for banned in ("add_case", "add_candidate", "record_evidence",
                       "transition_candidate", "record_case",
                       "put_result", "enqueue"):
            self.assertNotIn(banned, src)

    def test_executor_passes_quality_dicts_and_no_advisor_to_gate(self):
        src = _read(
            REPO / "backend/research_agents/finding/executor.py")
        gate_call = src.split("gate_decide(")[1].split(")\n")[0]
        self.assertIn("quality_rows=quality_dicts", gate_call)
        for banned in ("advisor", "outcome", "confidence_high"):
            self.assertNotIn(banned, gate_call)

    def test_no_models_have_cve_applicability_field(self):
        import dataclasses as dc
        from backend.research_agents.finding.models import (
            CasePackage, VerificationObjective,
        )
        for cls in (CandidateFinding, VerificationObjective, CasePackage):
            names = {f.name for f in dc.fields(cls)}
            for banned in ("cvss", "cve_applicable", "exploitability",
                           "affected_versions", "base_score"):
                self.assertNotIn(banned, names)

    def test_finding_cli_advisor_uses_the_free_only_builder(self):
        src = _read(REPO / "backend/research_agents/cli.py")
        self.assertIn(
            "_build_campaign_advisor(config) if args.llm else None", src)
        self.assertIn("def _build_campaign_advisor", src)
        self.assertIn("resolve_free_config", src)


class TestScopeContainment(unittest.TestCase):
    """[ ] candidate/verification/LLM cannot widen scope (rules 15-16)."""

    def setUp(self):
        self._r, self.fs = make_stores()

    def test_candidate_construction_rejects_bad_scope(self):
        from backend.research_agents.finding import FindingScopeError
        with self.assertRaises(FindingScopeError):
            make_candidate(self.fs, scope="https://attacker.test/any")

    def test_candidate_scope_immutable_through_save(self):
        cand = make_candidate(self.fs)
        original = cand.scope_ref
        cand.scope_ref = "fixture:other/o.test"
        with self.assertRaises(FindingStoreError):
            self.fs.save_candidate(cand)
        self.assertEqual(self.fs.get_candidate(
            cand.candidate_id).scope_ref, original)

    def test_verification_scope_locked_to_candidate(self):
        cand = make_candidate(self.fs)
        ver = create_verification(store=self.fs, candidate=cand,
                                  capability=capability_for("XSS"))
        self.assertEqual(ver.scope_ref, cand.scope_ref)
        ver.scope_ref = "fixture:other/o.test"
        with self.assertRaises(FindingStoreError):
            self.fs.save_verification(ver)

    def test_job_builder_requires_matching_scope(self):
        cand = make_candidate(self.fs)
        ver = create_verification(store=self.fs, candidate=cand,
                                  capability=capability_for("XSS"))
        ver.scope_ref = "fixture:other/o.test"
        with self.assertRaises(ValueError):
            build_verification_job(candidate=cand, verification=ver,
                                   agent_name="xss-agent",
                                   config=RuntimeConfig(
                                       execution_mode="fixture"))

    def test_correlation_and_triage_never_mutate_scope(self):
        a = make_candidate(self.fs)
        b = make_candidate(self.fs, job="j2")
        correlate_pair(a, b)
        triage_candidate(candidate=a, evidence_rows=[],
                         capability=capability_for("XSS"))
        self.assertEqual(self.fs.get_candidate(a.candidate_id).scope_ref,
                         SCOPE)
        self.assertEqual(self.fs.get_candidate(b.candidate_id).scope_ref,
                         SCOPE)

    def test_advisor_request_carries_scope_as_reference_only(self):
        from backend.research_agents.finding.advisor import advisor_request
        cand = make_candidate(self.fs)
        ver = create_verification(store=self.fs, candidate=cand,
                                  capability=capability_for("XSS"))
        req = advisor_request(
            candidate=cand, verification=ver, evidence_summary=[],
            related_research=[], knowledge_count=0,
            allowed_observation_types=["http-rows"],
            budget_remaining={"max_llm_calls": 1})
        blob = json.dumps(req)
        self.assertIn(SCOPE, blob)          # reference present
        self.assertNotIn("http://", blob)   # no fetch targets
        self.assertNotIn("https://", blob)


class TestAuthorizationBoundary(unittest.TestCase):
    """[ ] authorization cannot be bypassed (rule 16-17)."""

    def setUp(self):
        self._r, self.fs = make_stores()

    def _job(self, *, mode: str, ref: str, program: str = "fixture:test",
             subdomain: str = "test", url: str = "https://test/x"
             ) -> ResearchJob:
        return ResearchJob(
            id=new_id("job"), candidate_id="", category="XSS",
            endpoint=url, parameter="q", priority_score=50,
            agent_category="XSS", program=program, subdomain=subdomain,
            url=url, authorization_ref=ref, execution_mode=mode)

    def test_missing_ref_denied(self):
        with self.assertRaises(AuthorizationDenied):
            AuthorizationChecker().verify(self._job(
                mode="fixture", ref=""))

    def test_fixture_scope_in_production_denied(self):
        with self.assertRaises(AuthorizationDenied):
            AuthorizationChecker().verify(self._job(
                mode="production", ref=SCOPE))

    def test_production_scope_missing_program_denied(self):
        with self.assertRaises(AuthorizationDenied):
            AuthorizationChecker().verify(self._job(
                mode="production", ref="watch:scope:t/t.test",
                program="", subdomain=""))

    def test_target_outside_scope_denied(self):
        with self.assertRaises(AuthorizationDenied):
            AuthorizationChecker().verify(self._job(
                mode="production",
                ref="watch:scope:prog/inside.test",
                program="prog", subdomain="inside.test",
                url="https://elsewhere.test/x"))

    def test_precheck_reports_denial_reason(self):
        job = self._job(mode="production", ref=SCOPE)  # fixture ref
        ok, reason = precheck_authorization(job)
        self.assertFalse(ok)
        self.assertIn("authorization", reason)

    def test_precheck_grants_valid_fixture_job(self):
        job = self._job(mode="fixture", ref=SCOPE)
        ok, reason = precheck_authorization(job)
        self.assertTrue(ok)
        self.assertEqual(reason, SCOPE)

    def test_verification_scope_always_equals_candidate_scope(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        cand = make_candidate(fs, job=source.id)
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=finding_worker_factory("verified")[0])
        vers = fs.list_verifications()
        self.assertTrue(vers)
        for ver in vers:
            self.assertEqual(ver.scope_ref, cand.scope_ref)


class TestDuplicateExecution(unittest.TestCase):
    """[ ] duplicate execution prevented (Phase 18): one job per
    verification, WAITING resumes the SAME job."""

    def test_waiting_verification_resumes_same_job_no_second_enqueue(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")

        # run 1: worker refuses to finish -> WAITING (honest, resumable)
        wf1, _j1 = finding_worker_factory("leave_queued")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf1)
        vers = fs.list_verifications()
        self.assertEqual(len(vers), 1)
        self.assertEqual(vers[0].state, "WAITING")
        job_id = vers[0].job_id
        self.assertTrue(job_id)

        # run 2: resumes the SAME job to completion
        wf2, _j2 = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf2)
        vers = fs.list_verifications()
        self.assertEqual(len(vers), 1)            # never a 2nd verification
        self.assertEqual(vers[0].job_id, job_id)  # never a 2nd job
        self.assertEqual(vers[0].state, "VERIFIED")
        self.assertTrue(runtime.list_evidence(job_id=job_id))

    def test_re_extraction_of_same_source_no_second_verification(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        run_findings([source.id], store=runtime, finding_store=fs,
                     extract_only=True)
        count_v1 = len(fs.list_verifications())
        run_findings([source.id], store=runtime, finding_store=fs,
                     extract_only=True)
        self.assertEqual(len(fs.list_verifications()), count_v1)
        states = [c.lifecycle_state for c in fs.list_candidates()]
        self.assertIn("DUPLICATE", states)


class TestSeverityAndCVEFabrication(unittest.TestCase):
    """[ ] severity / CVE applicability cannot be fabricated (rules 21-23)."""

    def setUp(self):
        self._r, self.fs = make_stores()

    def test_model_rejects_severity_without_provenance(self):
        with self.assertRaises(Exception):
            CandidateFinding(
                candidate_id=new_id("cand"), source_job="j",
                scope_ref=SCOPE, vulnerability_class="XSS",
                hypothesis="h", severity="CRITICAL",
                provenance={}, created_at=utcnow(), updated_at=utcnow())

    def test_store_rejects_severity_under_fake_provenance(self):
        cand = make_candidate(self.fs)
        cand.severity = "CRITICAL"
        cand.severity_provenance = "llm_advisor_says_so"
        with self.assertRaises(FindingStoreError):
            self.fs.save_candidate(cand)
        self.assertEqual(self.fs.get_candidate(
            cand.candidate_id).severity, "UNASSESSED")

    def test_store_rejects_fabricated_case_severity(self):
        cand = make_candidate(self.fs)
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="t")
        case = ensure_case(self.fs, cand, reason="t")
        case.severity = "HIGH"
        case.severity_provenance = "gut_feeling"
        with self.assertRaises(FindingStoreError):
            self.fs.save_case(case)

    def test_authoritative_kb_provenance_is_accepted(self):
        cand = make_candidate(self.fs)
        cand.severity = "HIGH"
        cand.severity_provenance = "knowledge_base_cvss:CVE-2024-0001:8.1"
        saved = self.fs.save_candidate(cand)
        self.assertEqual(saved.severity, "HIGH")

    def test_advisor_severity_and_cve_recommendations_rejected(self):
        from backend.research_agents.finding.advisor import (
            map_advisor_response,
        )
        for code in ("SEVERITY_CRITICAL", "CVE_APPLICABILITY_1",
                     "CVSS_98", "EXPLOIT_PAYLOAD_1"):
            out = map_advisor_response(
                {"summary": "x", "insights": [],
                 "recommendations": [{"recommendation_code": code,
                                      "text": "claim"}]},
                candidate_id="cand-1", verification_id="ver-1",
                scope_ref=SCOPE, expected_scope=SCOPE,
                allowed_types={"http-rows"})
            self.assertTrue(
                any("authoritative_field_not_llm_set" in r
                    for r in out.rejected),
                f"{code} must be rejected")

    def test_end_to_end_candidates_stay_unassessed_without_kb(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        run_findings([source.id], store=runtime, finding_store=fs)
        for cand in fs.list_candidates():
            if cand.severity != "UNASSESSED":
                self.assertTrue(cand.severity_provenance.startswith(
                    "knowledge_base_cvss:"))


class TestLLMBoundary(unittest.TestCase):
    """[ ] LLM cannot confirm/create evidence/case/execute anything
    (rules 7-13): proven structurally — no execution capability exists,
    the gate takes no LLM input, advisor output lives in provenance only.
    """

    def test_executor_runs_advisor_only_into_provenance(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")

        def overconfident(request):
            # high-confidence TEXT is fine; it must remain advisory
            return ({"summary": "evidence looks consistent with input",
                     "insights": [{"insight_code": "CONFIDENCE_99",
                                   "text": "99% confident this verifies"}],
                     "recommendations": [{
                         "recommendation_code": "VERIFY_http-rows",
                         "text": "http-rows"}]},
                    {"model_requested": "openrouter/free",
                     "model_resolved": "openrouter/free",
                     "latency_ms": 3})

        run_findings([source.id], store=runtime, finding_store=fs,
                     advisor_fn=overconfident)
        vers = fs.list_verifications()
        self.assertTrue(vers)
        adv = (vers[-1].provenance or {}).get("advisor") or {}
        self.assertEqual(adv.get("confidence"), "advisory")
        self.assertTrue(adv.get("used"))
        # any VERIFIED candidate must trace to an authoritative gate
        for cand in fs.list_candidates():
            if cand.lifecycle_state == "VERIFIED":
                self.assertEqual(vers[-1].gate_reason,
                                 "evidence_rules_met")

    def test_advisor_failure_never_blocks_the_deterministic_path(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        summary, _ = run_findings(
            [source.id], store=runtime, finding_store=fs,
            advisor_fn=advisor_raises(RuntimeError("provider down")))
        self.assertTrue(any("advisor_provider_error" in
                            str(o.get("error") or "")
                            for o in summary.advisor_outcomes))
        ver = fs.list_verifications()[-1]
        # the decision still came from the gate path
        self.assertIn(ver.state,
                      ("VERIFIED", "REJECTED", "INCONCLUSIVE", "BLOCKED",
                       "FAILED", "WAITING", "EXECUTING", "AUTHORIZED"))

    def test_unknown_model_and_paid_model_are_rejected(self):
        from backend.research_agents.llm_guard import (
            FreeOnlyViolation,
            resolve_free_config,
        )
        import inspect
        sig = inspect.signature(resolve_free_config)

        def kwargs(**kw):
            # llm_guard's parameter is `requested_model`
            if "model" in kw and "requested_model" in sig.parameters:
                kw["requested_model"] = kw.pop("model")
            return {k: v for k, v in kw.items() if k in sig.parameters}

        with mock.patch.dict(
                os.environ,
                {"WATCH_AGENT_LLM_MODE": "free",
                 # fake placeholder so the guard's key-presence check can
                 # run; never used for any request (no network here)
                 "OPENROUTER_API_KEY": "sk-test-not-a-real-key"},
                clear=False):
            with self.assertRaises(FreeOnlyViolation):
                resolve_free_config(**kwargs(
                    provider_kind="OPENROUTER", model="openai/gpt-4o"))
            with self.assertRaises(FreeOnlyViolation):
                resolve_free_config(**kwargs(
                    provider_kind="OPENROUTER",
                    model="some-org/not-free-at-all"))
            cfg = resolve_free_config(**kwargs(
                provider_kind="OPENROUTER", model="openrouter/free"))
            self.assertTrue(cfg)
            with self.assertRaises(FreeOnlyViolation):
                resolve_free_config(**kwargs(
                    provider_kind="PAID_ENDPOINT",
                    model="openrouter/free"))

    def test_unknown_observation_type_and_scope_expansion_rejected(self):
        from backend.research_agents.finding.advisor import (
            validate_recommendation,
        )
        ok, reason = validate_recommendation(
            "shell_exec", allowed_types={"http-rows"},
            candidate_id="cand-1", verification_id="ver-1",
            scope_ref=SCOPE, expected_scope=SCOPE)
        self.assertFalse(ok)
        self.assertIn("unknown_observation_type", reason)
        ok2, reason2 = validate_recommendation(
            "http-rows", allowed_types={"http-rows"},
            candidate_id="cand-1", verification_id="ver-1",
            scope_ref="fixture:other/o.test", expected_scope=SCOPE)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "scope_expansion_attempt")


class TestBoundedHistory(unittest.TestCase):
    """[ ] unrestricted history unavailable (rules 27-29)."""

    def test_correlate_all_hard_comparison_bound(self):
        from backend.research_agents.finding.correlate import (
            MAX_COMPARISONS,
            correlate_all,
        )
        _r, fs = make_stores()
        cands = [make_candidate(fs, target=f"t{i}",
                                cls=("XSS" if i % 2 else "SSRF"),
                                endpoint={"url": f"https://t{i}/p",
                                          "method": "GET",
                                          "parameter": f"p{i}"})
                 for i in range(40)]
        self.assertLessEqual(len(correlate_all(cands)), MAX_COMPARISONS)
        self.assertLessEqual(
            len(correlate_all(cands, max_comparisons=5)), 5)

    def test_advisor_request_hard_size_bound(self):
        from backend.research_agents.finding.advisor import advisor_request
        _r, fs = make_stores()
        cand = make_candidate(fs)
        ver = create_verification(store=fs, candidate=cand,
                                  capability=capability_for("XSS"))
        req = advisor_request(
            candidate=cand, verification=ver,
            evidence_summary=[{"evidence_id": "ev-" * 200,
                               "source": "x" * 500}] * 10,
            related_research=[{"left_id": "a", "right_id": "b"}] * 10,
            knowledge_count=999,
            allowed_observation_types=["http-rows"] * 50,
            budget_remaining={"max_llm_calls": 99})
        blob = json.dumps(req, sort_keys=True)
        self.assertLessEqual(len(blob), 4000)


class TestEvidenceGateAuthoritative(unittest.TestCase):
    """[ ] Evidence Gate remains authoritative (rule 5)."""

    def setUp(self):
        self._r, self.fs = make_stores()
        self.cand = make_candidate(self.fs)
        self.ver = create_verification(store=self.fs, candidate=self.cand,
                                       capability=capability_for("XSS"))

    def test_store_will_not_persist_verified_without_gate_met(self):
        from backend.research_agents.finding import FindingStateError
        for hop in ("AUTHORIZED", "EXECUTING"):
            self.fs.transition_verification(self.ver.verification_id, hop)
        with self.assertRaises(FindingStateError):
            self.fs.transition_verification(self.ver.verification_id,
                                            "VERIFIED")

    def test_candidate_verified_blocked_without_gate_result(self):
        from backend.research_agents.finding import FindingStateError
        c = make_candidate(self.fs)
        for hop in ("TRIAGED", "NEEDS_EVIDENCE", "VERIFICATION_PLANNED",
                    "VERIFICATION_PENDING", "VERIFYING"):
            self.fs.transition_candidate(c.candidate_id, hop, reason="w")
        with self.assertRaises(FindingStateError):
            self.fs.transition_candidate(c.candidate_id, "VERIFIED")

    def test_gate_ignores_llm_style_fields_in_structured(self):
        support = [{"evidence_id": "ev-1",
                    "verification_relevance": "verification",
                    "direct": True, "stance": "supporting"}]
        noisy = gate_structured("insufficient_evidence", False,
                                extra={"llm_confidence": "very high",
                                       "analyst_says": "confirmed",
                                       "severity": "CRITICAL"})
        d = decide(candidate=self.cand, verification=self.ver,
                   job_status="COMPLETED", structured=noisy,
                   quality_rows=support, hunt={})
        self.assertNotEqual(d.verification_state, "VERIFIED")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

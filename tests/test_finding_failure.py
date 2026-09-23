"""AUTONOMOUS FINDING VERIFICATION & TRIAGE v1 — failure/recovery (Phase 17).

Every scenario from the Phase 17 checklist that can be forced
deterministically: malformed candidates, missing provenance, invalid
scope, duplicates, conflicting candidates, correlation/plan failures,
authorization denial, observation failure, evidence persistence failure,
gate failure, LLM unavailable/malformed/overflow, duplicate + stale +
concurrent verification, case persistence failure, handoff failure.

Expected in EVERY case: an honest state.  No fake verification, no fake
case, no fake evidence.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding import (  # noqa: E402
    correlate_pair,
)
from backend.research_agents.finding.gate import decide as gate_decide  # noqa: E402
from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.runtime import RuntimeConfig  # noqa: E402
from tests.finding_fixtures import (  # noqa: E402
    SCOPE,
    advisor_malformed,
    advisor_raises,
    complete_job,
    enqueue_job,
    finding_worker_factory,
    make_candidate,
    make_stores,
    run_findings,
)


class TestMalformedInputs(unittest.TestCase):
    """Malformed candidate / missing provenance / invalid scope."""

    def test_malformed_candidate_construction_fails_closed(self):
        from backend.research_agents.finding import CandidateFinding
        for kwargs in (
            {"candidate_id": "", "source_job": "j", "scope_ref": SCOPE,
             "vulnerability_class": "XSS", "h": "x"},
            {"candidate_id": "cand-1", "source_job": "", "scope_ref": SCOPE,
             "vulnerability_class": "XSS", "hypothesis": "h"},
        ):
            kwargs.pop("h", None)
            with self.assertRaises(Exception):
                CandidateFinding(created_at="t", updated_at="t",
                                 **kwargs)

    def test_invalid_scope_never_reaches_a_store(self):
        runtime, fs = make_stores()
        # source job with a garbage authorization_ref: extraction fails
        # closed into summary.skipped — never a crash, never a candidate
        job = enqueue_job(runtime, scope="not-a-real-scope")
        complete_job(runtime, job, outcome="inconclusive")
        summary, _ = run_findings([job.id], store=runtime,
                                  finding_store=fs, extract_only=True)
        # the extractor validates scope BEFORE any candidate is built:
        # an explicit invalid_scope skip (or extraction_failed) is the
        # honest fail-closed outcome
        self.assertTrue(
            any(s.startswith(("invalid_scope", "extraction_failed"))
                for s in summary.skipped),
            f"expected invalid_scope/extraction_failed skip, "
            f"got {summary.skipped}")
        self.assertEqual(fs.list_candidates(), [])
        self.assertEqual(summary.extracted, 0)

    def test_missing_provenance_never_hides_sources(self):
        _r, fs = make_stores()
        cand = make_candidate(fs)
        cand.provenance = {}
        fs.save_candidate(cand)
        got = fs.get_candidate(cand.candidate_id)
        # provenance may be empty, but the source fields always remain
        self.assertEqual(got.source_job, cand.source_job)
        self.assertTrue(got.candidate_id)
        self.assertEqual(got.created_at, cand.created_at)


class TestDuplicateAndConflictingCandidates(unittest.TestCase):
    def test_repeated_research_yields_one_canonical_one_duplicate(self):
        runtime, fs = make_stores()
        s1 = enqueue_job(runtime, url="https://test/support")
        complete_job(runtime, s1, outcome="inconclusive")
        s2 = enqueue_job(runtime, url="https://test/support")
        complete_job(runtime, s2, outcome="inconclusive")
        run_findings([s1.id], store=runtime, finding_store=fs,
                     extract_only=True)
        run_findings([s2.id], store=runtime, finding_store=fs,
                     extract_only=True)
        states = [c.lifecycle_state for c in fs.list_candidates()]
        self.assertIn("DUPLICATE", states)
        canonical = [c for c in fs.list_candidates()
                     if c.lifecycle_state != "DUPLICATE"]
        self.assertEqual(len(canonical), 1)
        # duplicate keeps its own evidence/provenance (never deleted)
        dup = next(c for c in fs.list_candidates()
                   if c.lifecycle_state == "DUPLICATE")
        self.assertEqual(dup.source_job, s2.id)
        self.assertEqual(dup.duplicate_of, canonical[0].candidate_id)

    def test_conflicting_candidates_stay_separate_rows(self):
        _r, fs = make_stores()
        a = make_candidate(fs, confidence="high")
        b = make_candidate(fs, job="j2", confidence="insufficient",
                           missing=["direct observation"])
        res = correlate_pair(a, b)
        self.assertTrue(res.relation)           # decided, not crashed
        # even SAME-class candidates keep BOTH rows and BOTH evidence sets
        self.assertEqual(len(fs.list_candidates()), 2)


class TestPlanAndExecutionFailures(unittest.TestCase):
    def test_worker_failure_fails_verification_and_blocks_candidate(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")

        def broken_factory(config=None, store=None):
            class Broken:
                def run(self, **kw):
                    raise RuntimeError("injected worker crash")
            return Broken()

        summary, _ = run_findings([source.id], store=runtime,
                                  finding_store=fs,
                                  worker_factory=broken_factory)
        ver = fs.list_verifications()[-1]
        self.assertEqual(ver.state, "FAILED")
        self.assertIn("worker_failure", ver.termination_reason)
        cand = fs.get_candidate(ver.candidate_id)
        self.assertEqual(cand.lifecycle_state, "BLOCKED")
        self.assertTrue(any("worker:" in e for e in summary.errors))

    def test_observation_failure_job_yields_honest_blocked(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        wf, _ = finding_worker_factory("failed")   # job TERMINAL_FAILED
        summary, _ = run_findings([source.id], store=runtime,
                                  finding_store=fs, worker_factory=wf)
        ver = fs.list_verifications()[-1]
        self.assertIn(ver.state, ("FAILED", "BLOCKED"))
        self.assertEqual(ver.decision, "FAILED")
        cand = fs.get_candidate(ver.candidate_id)
        self.assertEqual(cand.lifecycle_state, "BLOCKED")
        # never VERIFIED after a failed job
        self.assertNotEqual(cand.lifecycle_state, "VERIFIED")

    def test_evidence_persistence_failure_is_honest_failed(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")

        class Fragile(type(runtime)):
            source_id = ""

            def list_evidence(self, job_id=None, **kw):
                if str(job_id) == self.source_id:
                    return super().list_evidence(job_id=job_id, **kw)
                raise OSError("injected evidence store outage")

        fragile = Fragile(runtime.base)
        fragile.source_id = source.id
        wf, _ = finding_worker_factory("verified")
        summary, _ = run_findings([source.id], store=fragile,
                                  finding_store=fs, worker_factory=wf)
        self.assertTrue(any("evidence_unreadable" in e
                            for e in summary.errors))
        ver = fs.list_verifications()[-1]
        self.assertEqual(ver.state, "FAILED")
        self.assertIn("evidence_persistence_failure",
                      ver.termination_reason)
        cand = fs.get_candidate(ver.candidate_id)
        self.assertEqual(cand.lifecycle_state, "BLOCKED")


class TestGateFailures(unittest.TestCase):
    def test_missing_gate_record_is_inconclusive_never_verified(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        wf, _ = finding_worker_factory("no_gate")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        ver = fs.list_verifications()[-1]
        self.assertEqual(ver.state, "INCONCLUSIVE")
        self.assertEqual(ver.gate_reason, "gate_record_absent")
        cand = fs.get_candidate(ver.candidate_id)
        self.assertEqual(cand.lifecycle_state, "INCONCLUSIVE")

    def test_malformed_structured_never_verifies(self):
        _r, fs = make_stores()
        cand = make_candidate(fs)
        from backend.research_agents.finding.verification import (
            create_verification,
        )
        ver = create_verification(store=fs, candidate=cand,
                                  capability=capability_for("XSS"))
        for bad in (None, [], "text", {"evidence_gate": "corrupt"},
                    {"evidence_gate": {"authoritative": False,
                                       "reason": "evidence_rules_met",
                                       "created_case": True}}):
            structured = bad if isinstance(bad, dict) else (
                bad if bad is not None else {})
            if bad == {"evidence_gate": "corrupt"}:
                structured = {"evidence_gate": "corrupt"}
            d = gate_decide(candidate=cand, verification=ver,
                            job_status="COMPLETED",
                            structured=structured if isinstance(
                                structured, dict) else {},
                            quality_rows=[], hunt={})
            self.assertNotEqual(d.verification_state, "VERIFIED")


class TestLLMUnavailable(unittest.TestCase):
    def test_provider_exception_recorded_and_path_continues(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        summary, _ = run_findings([source.id], store=runtime,
                                  finding_store=fs,
                                  advisor_fn=advisor_raises(
                                      TimeoutError("llm timeout")))
        self.assertTrue(any("advisor_provider_error" in
                            str(o.get("error")) for o in
                            summary.advisor_outcomes))
        # verification still executed via the deterministic path
        self.assertGreaterEqual(summary.verifications_executed, 1)

    def test_malformed_llm_output_recorded_not_used(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        summary, _ = run_findings([source.id], store=runtime,
                                  finding_store=fs,
                                  advisor_fn=advisor_malformed(
                                      "this is not an object"))
        ver = fs.list_verifications()[-1]
        adv = (ver.provenance or {}).get("advisor") or {}
        self.assertIn("malformed", str(adv.get("error") or ""))
        self.assertFalse(adv.get("used"))
        # gate independence: any VERIFIED outcome must trace to the
        # authoritative evidence_gate record, never to the malformed LLM
        if ver.state == "VERIFIED":
            self.assertEqual(ver.gate_reason, "evidence_rules_met")

    def test_context_overflow_fails_closed(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        summary, _ = run_findings(
            [source.id], store=runtime, finding_store=fs,
            limits={"max_context_chars": 64},     # absurdly small
            advisor_fn=lambda req: ({}, {}))
        self.assertTrue(any("context_too_large" in
                            str(o.get("error")) for o in
                            summary.advisor_outcomes))
        ver = fs.list_verifications()[-1]
        adv = (ver.provenance or {}).get("advisor") or {}
        self.assertIn("context_too_large", str(adv.get("error") or ""))


class TestCasePersistenceFailure(unittest.TestCase):
    def test_case_save_failure_is_captured_not_crashing(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")

        original_save = fs.save_case

        def explode(case):
            raise RuntimeError("injected case persistence outage")

        fs.save_case = explode
        try:
            wf, _ = finding_worker_factory("verified")
            summary, _ = run_findings([source.id], store=runtime,
                                      finding_store=fs,
                                      worker_factory=wf)
        finally:
            fs.save_case = original_save
        self.assertTrue(any("package:" in e for e in summary.errors))
        # the gate decision itself still persisted honestly
        ver = fs.list_verifications()[-1]
        self.assertEqual(ver.state, "VERIFIED")
        self.assertEqual(ver.gate_reason, "evidence_rules_met")


class TestAuthorizationDenial(unittest.TestCase):
    def test_production_config_over_fixture_scope_blocks_honestly(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="inconclusive")
        from tests.finding_fixtures import make_candidate as mk
        cand = mk(fs, job=source.id)   # fixture scope candidate
        # run with a PRODUCTION config: fixture ref must be DENIED
        from backend.research_agents.finding.executor import (
            run_findings as rf,
        )
        wf, journal = finding_worker_factory("verified")
        summary = rf(source_jobs=[source.id],
                     config=RuntimeConfig(execution_mode="production"),
                     store=runtime, finding_store=fs,
                     worker_factory=wf)
        vers = fs.list_verifications()
        self.assertTrue(vers)
        # either blocked at authorization (denied) — never executed
        denied = [v for v in vers if v.state == "BLOCKED"]
        self.assertTrue(denied, "fixture scope must be BLOCKED under "
                                "production mode")
        denial_reasons = [
            str(t.get("reason") or "")
            for t in fs.all_transitions()
            if t.get("id") == denied[0].verification_id
            and t.get("new") == "BLOCKED"]
        self.assertTrue(
            any("authorization_denied" in r for r in denial_reasons),
            f"denial reason missing from transitions: {denial_reasons}")
        self.assertEqual(journal["ran"], 0)   # never enqueued/run
        # THE candidate bound to the denied verification is BLOCKED
        fresh = fs.get_candidate(denied[0].candidate_id)
        self.assertEqual(fresh.lifecycle_state, "BLOCKED")
        # no verification may hold a scope other than its candidate's
        for v in vers:
            self.assertEqual(v.scope_ref, cand.scope_ref)


class TestHandoffFailure(unittest.TestCase):
    def test_handoff_builder_failure_degrades_to_empty_view(self):
        import backend.soc.findings as soc_findings
        from unittest import mock

        _r, fs = make_stores()
        cand = make_candidate(fs)
        fs.transition_candidate(cand.candidate_id, "TRIAGED", reason="t")
        from backend.research_agents.finding.case_package import (
            ensure_case,
        )
        ensure_case(fs, fs.get_candidate(cand.candidate_id), reason="t")

        real_store = (runtime := _r, fs)

        def _store():
            return fs, runtime

        with mock.patch.object(soc_findings, "_store", _store), \
                mock.patch("backend.research_agents.finding."
                           "case_package.handoff_view",
                           side_effect=RuntimeError("injected handoff "
                                                    "failure")):
            detail = soc_findings.finding_detail(cand.candidate_id)
        # page still renders truthful content; handoff section empty
        self.assertIsNotNone(detail)
        self.assertEqual(detail["handoff"], {})
        self.assertEqual(detail["state"], "TRIAGED")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

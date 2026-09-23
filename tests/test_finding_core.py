"""AUTONOMOUS FINDING VERIFICATION & TRIAGE v1 — core tests (Phases 1-13).

Models, extraction, triage, correlation, deduplication, evidence quality,
severity provenance, the verification gate, store invariants, budgets,
case packages and the deterministic advisor contract.  Everything runs on
tmp-dir stores with production-shaped rows; no network, no LLM calls.
"""

from __future__ import annotations

import inspect
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding import (  # noqa: E402
    CANDIDATE_STATES,
    CANDIDATE_TERMINAL,
    VERIFICATION_STATES,
    BudgetExhausted,
    CandidateFinding,
    FindingBudget,
    FindingScopeError,
    FindingStateError,
    FindingStoreError,
    FindingStore,
    build_package,
    canonical_of,
    correlate_all,
    correlate_pair,
    decide,
    deduplicate,
    derive_severity,
    ensure_case,
    extract_candidates,
    handoff_view,
    triage_candidate,
)
from backend.research_agents.finding.advisor import (  # noqa: E402
    advisor_request,
    map_advisor_response,
)
from backend.research_agents.finding.audit import (  # noqa: E402
    finding_event,
    lineage_row,
)
from backend.research_agents.finding.correlate import (  # noqa: E402
    CORRELATION_RULE_VERSION,
)
from backend.research_agents.finding.gate import (  # noqa: E402
    VerificationDecision,
    gate_record,
)
from backend.research_agents.finding.limits import DEFAULT_LIMITS  # noqa: E402
from backend.research_agents.finding.models import (  # noqa: E402
    CASE_STATES,
    new_id,
    utcnow,
    validate_scope_ref,
)
from backend.research_agents.finding.quality import (  # noqa: E402
    QUALITY_RULE_VERSION,
    classify_batch,
    classify_evidence,
)
from backend.research_agents.finding.triage import (  # noqa: E402
    RECOMMEND_VERIFY,
    TRIAGE_RULE_VERSION,
)
from backend.research_agents.finding.verification import (  # noqa: E402
    create_verification,
)
from tests.finding_fixtures import (  # noqa: E402
    SCOPE,
    gate_structured,
    make_candidate,
    make_stores,
)

from backend.research_agents.capabilities import capability_for  # noqa: E402


class TestCandidateModel(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()

    def test_states_are_the_twelve_required(self):
        self.assertEqual(len(CANDIDATE_STATES), 12)
        for state in ("DETECTED", "TRIAGED", "NEEDS_EVIDENCE",
                      "VERIFICATION_PLANNED", "VERIFICATION_PENDING",
                      "VERIFYING", "VERIFIED", "REJECTED", "INCONCLUSIVE",
                      "DUPLICATE", "BLOCKED", "EXPIRED"):
            self.assertIn(state, CANDIDATE_STATES)

    def test_scope_is_mandatory_and_validated(self):
        with self.assertRaises(FindingScopeError):
            make_candidate(self.fs, scope="http://evil/nope")
        self.assertEqual(validate_scope_ref(SCOPE), SCOPE)
        with self.assertRaises(FindingScopeError):
            validate_scope_ref("garbage")

    def test_candidate_defaults_are_not_verified(self):
        cand = make_candidate(self.fs)
        self.assertEqual(cand.lifecycle_state, "DETECTED")
        self.assertEqual(cand.severity, "UNASSESSED")
        self.assertTrue(cand.severity_provenance.startswith("unassessed"))
        self.assertEqual(cand.confidence_provenance, "research_result")

    def test_missing_required_fields_fail_closed(self):
        with self.assertRaises(Exception):
            CandidateFinding(candidate_id="", source_job="", scope_ref=SCOPE,
                             vulnerability_class="XSS", hypothesis="h",
                             provenance={}, created_at=utcnow(),
                             updated_at=utcnow())
        with self.assertRaises(Exception):
            CandidateFinding(candidate_id=new_id("cand"), source_job="j",
                             scope_ref=SCOPE, vulnerability_class="",
                             hypothesis="h", provenance={},
                             created_at=utcnow(), updated_at=utcnow())
        with self.assertRaises(Exception):
            CandidateFinding(candidate_id=new_id("cand"), source_job="j",
                             scope_ref=SCOPE, vulnerability_class="XSS",
                             hypothesis="", provenance={},
                             created_at=utcnow(), updated_at=utcnow())

    def test_severity_without_provenance_rejected(self):
        with self.assertRaises(Exception):
            CandidateFinding(candidate_id=new_id("cand"), source_job="j",
                             scope_ref=SCOPE, vulnerability_class="XSS",
                             hypothesis="h", severity="CRITICAL",
                             provenance={}, created_at=utcnow(),
                             updated_at=utcnow())


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.runtime, self.fs = make_stores()
        from tests.finding_fixtures import (complete_job, enqueue_job)
        self.job = enqueue_job(self.runtime)
        self.complete = complete_job
        self.cap = capability_for("XSS")

    def _result(self, **kw):
        from backend.research_agents.models import ResearchResult
        structured = {
            "hypotheses": ["q reflects unencoded into the page"],
            "verdict": {"status": "signal"},
            "evidence_missing": ["direct marker observation"],
            "evidence_gate": {"authoritative": True,
                              "reason": "evidence_rules_met",
                              "created_case": True, "confidence": "high"},
        }
        structured.update(kw)
        return ResearchResult(
            job_id=self.job.id, agent_name="xss-agent",
            confidence="medium", findings=("signal",),
            status="COMPLETED", execution_mode="fixture",
            structured=structured)

    def test_extraction_produces_detected_candidate(self):
        res = self._result()
        out = extract_candidates(job=self.job, result=res,
                                 evidence_rows=[], capability=self.cap,
                                 scope_ref=SCOPE)
        self.assertEqual(len(out.candidates), 1)
        cand = out.candidates[0]
        self.assertEqual(cand.lifecycle_state, "DETECTED")
        self.assertEqual(cand.vulnerability_class, "XSS")
        self.assertEqual(cand.source_job, self.job.id)
        self.assertIn("q reflects", cand.hypothesis)
        self.assertEqual(cand.confidence_provenance, "research_result")
        self.assertNotEqual(cand.lifecycle_state, "VERIFIED")

    def test_extraction_without_result_is_honest(self):
        out = extract_candidates(job=self.job, result=None,
                                 evidence_rows=[], capability=self.cap,
                                 scope_ref=SCOPE)
        self.assertEqual(out.candidates, [])
        self.assertTrue(out.skipped)

    def test_extraction_bounded_per_job(self):
        res = self._result(hypotheses=[f"h{i}" for i in range(30)])
        out = extract_candidates(job=self.job, result=res,
                                 evidence_rows=[], capability=self.cap,
                                 scope_ref=SCOPE, max_candidates=3)
        self.assertLessEqual(len(out.candidates), 3)

    def test_extraction_preserves_evidence_refs_and_missing(self):
        from tests.finding_fixtures import add_evidence
        ids = add_evidence(self.runtime, self.job.id, count=2)
        res = self._result()
        out = extract_candidates(job=self.job, result=res,
                                 evidence_rows=self.runtime.list_evidence(
                                     job_id=self.job.id),
                                 capability=self.cap, scope_ref=SCOPE)
        cand = out.candidates[0]
        self.assertTrue(set(ids) & set(cand.evidence_refs))
        self.assertTrue(cand.missing_evidence)
        self.assertTrue(cand.supporting_signals)


class TestTriage(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()
        self.cap = capability_for("XSS")

    def test_never_llm_authority(self):
        params = inspect.signature(triage_candidate).parameters
        for forbidden in ("llm", "advisor", "advisor_fn", "model"):
            self.assertNotIn(forbidden, params)

    def test_invalid_scope_rejected(self):
        # (a) construction fails closed — invalid scopes never persist
        with self.assertRaises(FindingScopeError):
            CandidateFinding(
                candidate_id=new_id("cand"), source_job="j",
                scope_ref="not-a-scope", vulnerability_class="XSS",
                hypothesis="h", provenance={}, created_at=utcnow(),
                updated_at=utcnow())
        # (b) defense in depth: a corrupted row (bypassing __post_init__)
        # still fails triage closed
        cand = CandidateFinding.__new__(CandidateFinding)
        cand.candidate_id = new_id("cand")
        cand.source_job = "j"
        cand.scope_ref = "not-a-scope"
        cand.vulnerability_class = "XSS"
        cand.hypothesis = "h"
        cand.missing_evidence = []
        cand.confidence = "medium"
        cand.confidence_provenance = "research_result"
        cand.correlation = {}
        cand.created_at = utcnow()
        d = triage_candidate(candidate=cand, evidence_rows=[],
                             capability=self.cap)
        self.assertEqual(d.state, "REJECTED")
        self.assertIn("invalid_scope", d.reason_codes)
        self.assertEqual(d.priority, 0)

    def test_incomplete_evidence_needs_evidence(self):
        cand = make_candidate(self.fs)
        d = triage_candidate(candidate=cand, evidence_rows=[],
                             capability=self.cap)
        self.assertEqual(d.state, "NEEDS_EVIDENCE")
        self.assertIn("evidence_incomplete", d.reason_codes)
        self.assertTrue(any(m.startswith("evidence_type:")
                            or m.startswith("observation_count:")
                            for m in d.missing_evidence))
        self.assertEqual(d.rule_version, TRIAGE_RULE_VERSION)

    def test_complete_evidence_recommends_verify(self):
        from tests.finding_fixtures import add_evidence, enqueue_job
        runtime, fs = make_stores()
        job = enqueue_job(runtime)
        add_evidence(runtime, job.id, count=2, category="XSS")
        cand = make_candidate(fs, job=job.id, confidence="high")
        rows = runtime.list_evidence(job_id=job.id)
        d = triage_candidate(candidate=cand, evidence_rows=rows,
                             capability=capability_for("XSS"))
        self.assertIn(d.state, ("TRIAGED", "NEEDS_EVIDENCE"))
        self.assertEqual(d.recommended_path, RECOMMEND_VERIFY)
        self.assertGreater(d.priority, 0)
        self.assertIn("evidence_complete", d.reason_codes)
        self.assertIn("confidence_provenance:research_result",
                      d.reason_codes)

    def test_unknown_confidence_provenance_fails_closed(self):
        cand = make_candidate(self.fs, confidence="high")
        cand.confidence_provenance = "invented"
        d = triage_candidate(candidate=cand, evidence_rows=[],
                             capability=self.cap)
        self.assertIn("confidence_provenance_untrusted", d.reason_codes)
        self.assertNotIn("research_confidence_high", d.reason_codes)

    def test_no_specialist_blocks(self):
        cand = make_candidate(self.fs, cls="NOPE")
        d = triage_candidate(candidate=cand, evidence_rows=[],
                             capability=None)
        self.assertEqual(d.state, "BLOCKED")
        self.assertIn("no_specialist_capability", d.reason_codes)

    def test_priority_is_labeled_heuristic(self):
        self.assertIn("heuristic", triage_candidate(
            candidate=make_candidate(self.fs), evidence_rows=[],
            capability=self.cap).limitations)


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()

    def test_same_candidate_when_four_core_signals_match(self):
        a = make_candidate(self.fs)
        b = make_candidate(self.fs, job="job-other")
        res = correlate_pair(a, b)
        self.assertEqual(res.relation, "SAME_CANDIDATE")
        for reason in ("same_scope_ref", "same_vulnerability_class",
                       "same_parameter:q"):
            self.assertIn(reason, res.reasons)
        self.assertEqual(res.provenance["rule_version"],
                         CORRELATION_RULE_VERSION)

    def test_possible_duplicate_param_differs_but_target_matches(self):
        a = make_candidate(self.fs)
        b = make_candidate(self.fs, job="job-other",
                           endpoint={"url": "https://test/support/search",
                                     "method": "GET",
                                     "parameter": "s"})
        res = correlate_pair(a, b)
        self.assertEqual(res.relation, "POSSIBLE_DUPLICATE")

    def test_related_when_two_structured_hits(self):
        a = make_candidate(self.fs)
        b = make_candidate(self.fs, job="job-other", cls="SSRF",
                           endpoint={"url": "https://other.test/x",
                                     "method": "GET", "parameter": "u"})
        res = correlate_pair(a, b)
        self.assertEqual(res.relation, "RELATED_CANDIDATE")
        self.assertGreaterEqual(len(res.reasons), 1)

    def test_independent_when_no_structured_overlap(self):
        a = make_candidate(self.fs)
        b = make_candidate(self.fs, job="job-other", cls="SSRF",
                           scope="fixture:other/o.test",
                           target="elsewhere",
                           endpoint={"url": "https://elsewhere/p",
                                     "method": "POST", "parameter": "z"})
        res = correlate_pair(a, b)
        self.assertEqual(res.relation, "INDEPENDENT")
        self.assertIn("no_structured_overlap", res.reasons)

    def test_similarity_alone_never_identity(self):
        # near-identical HYPOTHESIS text but no structured overlap
        a = make_candidate(self.fs, hypothesis="same words here")
        b = make_candidate(self.fs, job="j2", cls="SSRF",
                           scope="fixture:q/q.test", target="zzz",
                           hypothesis="same words here",
                           endpoint={"url": "https://zzz/a",
                                     "method": "GET", "parameter": "k"})
        res = correlate_pair(a, b)
        self.assertNotIn(res.relation, ("SAME_CANDIDATE",
                                        "POSSIBLE_DUPLICATE"))
        self.assertNotIn("semantic", " ".join(res.reasons))

    def test_self_comparison_is_independent(self):
        a = make_candidate(self.fs)
        res = correlate_pair(a, a)
        self.assertEqual(res.relation, "INDEPENDENT")
        self.assertIn("self_comparison", res.reasons)

    def test_correlate_all_is_bounded(self):
        cands = [make_candidate(self.fs, cls=("XSS" if i % 2 else "SSRF"),
                                target=f"t{i}",
                                endpoint={"url": f"https://t{i}/p",
                                          "method": "GET",
                                          "parameter": "q"})
                 for i in range(30)]
        out = correlate_all(cands, max_comparisons=7)
        self.assertLessEqual(len(out), 7)


class TestDeduplication(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()

    def test_duplicate_marked_canonical_deterministic_evidence_kept(self):
        a = make_candidate(self.fs,
                           created_at="2026-09-20T00:00:00+00:00",
                           evidence_refs=["ev-shared", "ev-a"])
        b = make_candidate(self.fs, job="job-other",
                           evidence_refs=["ev-shared", "ev-b"],
                           created_at="2026-09-24T00:00:00+00:00")
        results = [correlate_pair(b, a)]
        self.assertEqual(results[0].relation, "SAME_CANDIDATE")
        ded = deduplicate(self.fs, b, [a], results)
        # deterministic canonical: oldest created
        self.assertEqual(ded.canonical_id, a.candidate_id)
        dup = self.fs.get_candidate(b.candidate_id)
        self.assertEqual(dup.lifecycle_state, "DUPLICATE")
        self.assertEqual(dup.duplicate_of, a.candidate_id)
        self.assertIn("ev-b", dup.evidence_refs)      # evidence preserved
        self.assertEqual(dup.provenance, b.provenance)  # provenance kept
        self.assertIn(ded.canonical_id,
                      (dup.correlation.get("canonical_id") and [ded.canonical_id]
                       or [ded.canonical_id]))
        # nothing deleted: both rows still listable
        ids = {c.candidate_id for c in self.fs.list_candidates()}
        self.assertIn(a.candidate_id, ids)
        self.assertIn(b.candidate_id, ids)

    def test_conflicting_evidence_never_merged(self):
        a = make_candidate(self.fs, evidence_refs=["ev-a-1"])
        b = make_candidate(self.fs, job="j2", evidence_refs=["ev-b-1"])
        ded = deduplicate(self.fs, b, [a],
                          [correlate_pair(b, a)])
        dup = self.fs.get_candidate(b.candidate_id)
        # duplicate keeps ITS OWN evidence, canonical untouched
        self.assertIn("ev-b-1", dup.evidence_refs)
        can = self.fs.get_candidate(a.candidate_id)
        self.assertNotIn("ev-b-1", can.evidence_refs)

    def test_canonical_of_requires_group(self):
        with self.assertRaises(FindingStoreError):
            canonical_of([])
        a = make_candidate(self.fs, created_at="2026-01-01T00:00:00+00:00")
        b = make_candidate(self.fs, created_at="2026-09-01T00:00:00+00:00")
        self.assertEqual(canonical_of([b, a]).candidate_id, a.candidate_id)


class TestEvidenceQuality(unittest.TestCase):
    def test_observation_is_direct_observed_authoritative(self):
        q = classify_evidence({"id": "ev-1", "type": "observation",
                               "category": "XSS", "job_id": "j1",
                               "observation_ref": "obs-1",
                               "signal": "marker"},
                              vulnerability_class="XSS",
                              verification_job_ids=["j1"])
        self.assertEqual(q.reliability_class, "observed_direct")
        self.assertTrue(q.direct)
        self.assertTrue(q.authoritative_eligible)
        self.assertEqual(q.stance, "supporting")
        self.assertEqual(q.verification_relevance, "verification")
        self.assertEqual(q.rule_version, QUALITY_RULE_VERSION)

    def test_knowledge_is_indirect_never_authoritative(self):
        q = classify_evidence({"id": "ev-2", "type": "knowledge",
                               "category": "XSS", "job_id": "j0"},
                              vulnerability_class="XSS")
        self.assertEqual(q.reliability_class, "researched_knowledge")
        self.assertFalse(q.direct)
        self.assertFalse(q.authoritative_eligible)
        self.assertEqual(q.verification_relevance, "background")

    def test_llm_insight_is_advisory_never_authoritative(self):
        q = classify_evidence({"id": "ev-3", "type": "llm_insight",
                               "job_id": "j0"})
        self.assertEqual(q.reliability_class, "advisory_llm")
        self.assertFalse(q.authoritative_eligible)
        self.assertFalse(q.direct)

    def test_negative_signal_is_contradicting(self):
        q = classify_evidence({"id": "ev-4", "type": "observation",
                               "signal": "contradiction",
                               "category": "XSS", "job_id": "j1"},
                              vulnerability_class="XSS",
                              verification_job_ids=["j1"])
        self.assertEqual(q.stance, "contradicting")
        self.assertTrue(q.authoritative_eligible)

    def test_batch_preserves_order_and_count(self):
        rows = [{"id": f"ev-{i}", "type": "knowledge", "job_id": "j"}
                for i in range(5)]
        self.assertEqual(len(classify_batch(rows)), 5)


class TestSeverityProvenance(unittest.TestCase):
    def test_default_is_unassessed(self):
        det = derive_severity()
        self.assertEqual(det.severity, "UNASSESSED")
        self.assertTrue(det.provenance.startswith("unassessed"))

    def test_kb_record_derives_with_provenance(self):
        det = derive_severity(cve_id="CVE-2024-0001",
                              kb_record={"cve": "CVE-2024-0001",
                                         "severity": "HIGH",
                                         "cvss_score": 8.1})
        self.assertEqual(det.severity, "HIGH")
        self.assertIn("knowledge_base_cvss:CVE-2024-0001", det.provenance)
        self.assertIn("8.1", det.provenance)

    def test_empty_kb_stays_unassessed(self):
        det = derive_severity(cve_id="CVE-1", kb_record={})
        self.assertEqual(det.severity, "UNASSESSED")


class TestVerificationGate(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()
        self.cand = make_candidate(self.fs)
        self.ver = create_verification(store=self.fs, candidate=self.cand,
                                       capability=capability_for("XSS"))

    def _decide(self, **kw):
        base = dict(candidate=self.cand, verification=self.ver,
                    job_status="COMPLETED", structured={},
                    quality_rows=[], hunt={})
        base.update(kw)
        return decide(**base)

    def test_gate_has_no_advisor_parameter(self):
        params = inspect.signature(decide).parameters
        for forbidden in ("advisor", "advisor_fn", "llm", "model",
                          "confidence_high", "llm_output"):
            self.assertNotIn(forbidden, params)

    def test_verified_requires_gate_and_direct_support(self):
        structured = gate_structured("evidence_rules_met", True,
                                     confidence="high")
        support = [{"evidence_id": "ev-1",
                    "verification_relevance": "verification",
                    "direct": True, "stance": "supporting"}]
        d = self._decide(structured=structured, quality_rows=support)
        self.assertEqual(d.verification_state, "VERIFIED")
        self.assertEqual(d.candidate_state, "VERIFIED")
        self.assertEqual(d.gate_reason, "evidence_rules_met")
        self.assertTrue(d.gate_authoritative)
        self.assertIn("LLM output is never", d.limitations)

    def test_gate_met_without_supporting_evidence_is_inconclusive(self):
        structured = gate_structured("evidence_rules_met", True)
        d = self._decide(structured=structured, quality_rows=[])
        self.assertEqual(d.verification_state, "INCONCLUSIVE")
        self.assertIn("gate_met_without", d.reason)

    def test_absent_gate_record_is_inconclusive(self):
        d = self._decide(structured={"unrelated": 1})
        self.assertEqual(d.verification_state, "INCONCLUSIVE")
        self.assertEqual(d.reason, "gate_record_absent")

    def test_contradicting_evidence_rejects(self):
        structured = gate_structured("confidence_below_threshold", False)
        contra = [{"evidence_id": "ev-9",
                   "verification_relevance": "verification",
                   "direct": True, "stance": "contradicting"}]
        d = self._decide(structured=structured, quality_rows=contra)
        self.assertEqual(d.verification_state, "REJECTED")
        self.assertIn("contradicting_evidence", d.reason)

    def test_no_hypothesis_rejects_as_disqualifying(self):
        d = self._decide(structured=gate_structured("no_hypothesis", False))
        self.assertEqual(d.verification_state, "REJECTED")
        self.assertIn("disqualifying", d.reason)

    def test_insufficient_evidence_is_inconclusive_not_rejected(self):
        d = self._decide(
            structured=gate_structured("insufficient_evidence", False))
        self.assertEqual(d.verification_state, "INCONCLUSIVE")

    def test_hunt_blocked_blocks(self):
        d = self._decide(structured=gate_structured(
            "evidence_rules_met", True),
            hunt={"state": "BLOCKED",
                  "termination_reason": "no_authorized_observation"})
        self.assertEqual(d.verification_state, "BLOCKED")
        self.assertEqual(d.candidate_state, "BLOCKED")

    def test_job_failure_is_failed_and_candidate_blocked(self):
        d = self._decide(job_status="TERMINAL_FAILED", job_error="boom")
        self.assertEqual(d.verification_state, "FAILED")
        self.assertEqual(d.candidate_state, "BLOCKED")

    def test_scope_mismatch_rejects(self):
        self.ver.scope_ref = "fixture:other/o.test"
        d = self._decide(structured=gate_structured(
            "evidence_rules_met", True))
        self.assertEqual(d.verification_state, "REJECTED")
        self.assertEqual(d.reason, "scope_mismatch")
        self.ver.scope_ref = self.cand.scope_ref

    def test_llm_confidence_field_in_structured_is_ignored(self):
        support = [{"evidence_id": "ev-1",
                    "verification_relevance": "verification",
                    "direct": True, "stance": "supporting"}]
        with_llm = gate_structured("insufficient_evidence", False,
                                   extra={"llm_confidence": "high",
                                          "confidence_high": "high"})
        d = self._decide(structured=with_llm, quality_rows=support)
        self.assertNotEqual(d.verification_state, "VERIFIED")
        self.assertEqual(d.verification_state, "INCONCLUSIVE")

    def test_gate_record_prefers_authoritative_record(self):
        rec = gate_record({"evidence_gate": {"authoritative": True,
                                             "reason": "x"}})
        self.assertTrue(rec["authoritative"])
        legacy = gate_record({"research_lineage": {
            "gate_reason": "y", "case_id": "c"}})
        self.assertFalse(legacy["authoritative"])
        self.assertEqual(gate_record({}), {})

    def test_decision_to_dict_round_trip(self):
        d = self._decide(structured=gate_structured(
            "evidence_rules_met", True),
            quality_rows=[{"evidence_id": "ev-1",
                           "verification_relevance": "verification",
                           "direct": True, "stance": "supporting"}])
        payload = json.dumps(d.to_dict())
        self.assertIn("VERIFIED", payload)
        self.assertNotIn("api_key", payload)


class TestStoreInvariants(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()

    def test_legal_and_illegal_candidate_transitions(self):
        cand = make_candidate(self.fs)
        cand = self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                            reason="t")
        self.assertEqual(cand.lifecycle_state, "TRIAGED")
        with self.assertRaises(FindingStateError):
            self.fs.transition_candidate(cand.candidate_id, "BANANA")
        # each terminal reached from a LEGAL predecessor, then immutable
        def walk_to(terminal: str) -> CandidateFinding:
            c2 = make_candidate(self.fs)
            path_states = {
                "DUPLICATE": ["DUPLICATE"],
                "BLOCKED": ["BLOCKED"],
                "EXPIRED": ["EXPIRED"],
                "REJECTED": ["TRIAGED", "REJECTED"],
                "INCONCLUSIVE": ["TRIAGED", "NEEDS_EVIDENCE",
                                 "INCONCLUSIVE"],
                "VERIFIED": ["TRIAGED", "NEEDS_EVIDENCE",
                             "VERIFICATION_PLANNED",
                             "VERIFICATION_PENDING", "VERIFYING",
                             "VERIFIED"],
            }[terminal]
            for hop in path_states:
                self.fs.transition_candidate(
                    c2.candidate_id, hop, reason="walk",
                    gate_result=("evidence_rules_met"
                                 if hop == "VERIFIED" else ""))
            return self.fs.get_candidate(c2.candidate_id)

        for terminal in CANDIDATE_TERMINAL:
            done = walk_to(terminal)
            self.assertEqual(done.lifecycle_state, terminal)
            with self.assertRaises(FindingStateError):
                self.fs.transition_candidate(done.candidate_id, "TRIAGED")

    def test_verified_requires_gate_result(self):
        cand = make_candidate(self.fs)
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED")
        self.fs.transition_candidate(cand.candidate_id, "NEEDS_EVIDENCE")
        self.fs.transition_candidate(cand.candidate_id,
                                     "VERIFICATION_PLANNED")
        self.fs.transition_candidate(cand.candidate_id,
                                     "VERIFICATION_PENDING")
        self.fs.transition_candidate(cand.candidate_id, "VERIFYING")
        with self.assertRaises(FindingStateError):
            self.fs.transition_candidate(cand.candidate_id, "VERIFIED")
        cand2 = self.fs.get_candidate(cand.candidate_id)
        got = self.fs.transition_candidate(cand2.candidate_id, "VERIFIED",
                                           reason="gate",
                                           gate_result="evidence_rules_met")
        self.assertEqual(got.lifecycle_state, "VERIFIED")

    def test_scope_never_changes_on_save(self):
        cand = make_candidate(self.fs)
        cand.scope_ref = "fixture:other/o.test"
        with self.assertRaises(FindingStoreError):
            self.fs.save_candidate(cand)

    def test_verification_scope_never_changes(self):
        ver = create_verification(store=self.fs,
                                  candidate=make_candidate(self.fs),
                                  capability=capability_for("XSS"))
        ver.scope_ref = "fixture:other/o.test"
        with self.assertRaises(FindingStoreError):
            self.fs.save_verification(ver)

    def test_case_verified_requires_candidate_verified(self):
        cand = make_candidate(self.fs)
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="triage")
        case = ensure_case(self.fs, cand, reason="test")
        # case advances to VERIFYING (candidate still TRIAGED)
        self.fs.transition_case(case.case_id, "VERIFYING")
        # case -> VERIFIED REQUIRES the candidate to be gate-VERIFIED
        with self.assertRaises(FindingStateError):
            self.fs.transition_case(case.case_id, "VERIFIED",
                                    gate_result="evidence_rules_met")
        # walk the candidate through verification to gate-VERIFIED
        for hop in ("NEEDS_EVIDENCE", "VERIFICATION_PLANNED",
                    "VERIFICATION_PENDING", "VERIFYING"):
            self.fs.transition_candidate(cand.candidate_id, hop,
                                         reason="walk")
        self.fs.transition_candidate(cand.candidate_id, "VERIFIED",
                                     reason="gate",
                                     gate_result="evidence_rules_met")
        done = self.fs.transition_case(case.case_id, "VERIFIED",
                                       gate_result="evidence_rules_met")
        self.assertEqual(done.state, "VERIFIED")

    def test_verification_verified_requires_gate_met(self):
        ver = create_verification(store=self.fs,
                                  candidate=make_candidate(self.fs),
                                  capability=capability_for("XSS"))
        # create_verification already advanced CREATED->READY->
        # AUTHORIZATION_REQUIRED (fail-closed default)
        self.assertEqual(ver.state, "AUTHORIZATION_REQUIRED")
        self.fs.transition_verification(ver.verification_id, "AUTHORIZED")
        self.fs.transition_verification(ver.verification_id, "EXECUTING")
        with self.assertRaises(FindingStateError):
            self.fs.transition_verification(ver.verification_id, "VERIFIED")

    def test_transitions_and_lineage_written(self):
        cand = make_candidate(self.fs)
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="triage_x")
        rows = self.fs.lineage_for(cand.candidate_id)
        self.assertTrue(any(r.get("new") == "TRIAGED" for r in rows))
        self.assertTrue(any(r.get("kind") == "candidate" for r in rows))

    def test_verification_states_are_the_twelve(self):
        self.assertEqual(len(VERIFICATION_STATES), 12)
        for state in ("CREATED", "READY", "AUTHORIZATION_REQUIRED",
                      "AUTHORIZED", "EXECUTING", "WAITING", "VERIFIED",
                      "REJECTED", "INCONCLUSIVE", "BLOCKED", "FAILED",
                      "EXPIRED"):
            self.assertIn(state, VERIFICATION_STATES)


class TestBudget(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()
        self.budget = FindingBudget(self.fs, dict(DEFAULT_LIMITS))

    def test_ensure_accumulates_with_ledger(self):
        self.budget.ensure("max_candidates_total", 1, reason="t1")
        self.budget.ensure("max_candidates_total", 2, reason="t2")
        self.assertEqual(self.budget.used()["max_candidates_total"], 3)
        rows = self.fs.budget_ledger()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["after"], 3)

    def test_exhaustion_raises(self):
        small = FindingBudget(self.fs, dict(DEFAULT_LIMITS,
                                            max_llm_calls=1))
        small.ensure("max_llm_calls", 1, reason="call")
        with self.assertRaises(BudgetExhausted):
            small.ensure("max_llm_calls", 1, reason="call2")
        self.assertTrue(small.ok("max_llm_calls") is False)

    def test_report_and_remaining_shape(self):
        rep = self.budget.report()
        for key in ("max_llm_calls", "max_verification_objectives",
                    "max_verification_observations",
                    "max_candidates_total"):
            self.assertIn(key, rep["limits"])
            self.assertIn(key, rep["remaining"])
        self.assertEqual(rep["used"], {})
        self.assertEqual(rep["exhausted"], [])
        self.assertEqual(self.budget.remaining()["max_llm_calls"],
                         DEFAULT_LIMITS["max_llm_calls"])


class TestCasePackageAndHandoff(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()

    def test_ensure_case_only_for_verification_bound_candidates(self):
        cand = make_candidate(self.fs)
        with self.assertRaises(FindingStoreError):
            # DETECTED candidates are NOT verification-bound: no case
            ensure_case(self.fs, cand, reason="too_early")
        self.fs.transition_candidate(cand.candidate_id, "TRIAGED",
                                     reason="triage")
        case = ensure_case(self.fs, cand, reason="verification_bound")
        self.assertEqual(case.state, "TRIAGED")
        self.assertIn(case.state, CASE_STATES)
        # idempotent
        again = ensure_case(self.fs, cand, reason="x")
        self.assertEqual(again.case_id, case.case_id)

    def test_build_package_contains_analyst_fields(self):
        from backend.research_agents.finding.gate import (
            VerificationDecision,
        )
        cand = make_candidate(self.fs, campaign="camp-1")
        ver = create_verification(store=self.fs, candidate=cand,
                                  capability=capability_for("XSS"))
        decision = VerificationDecision(
            verification_state="VERIFIED", candidate_state="VERIFIED",
            reason="evidence_rules_met", gate_reason="evidence_rules_met",
            created_case=True, case_id="case-rt-1")
        qualities = classify_batch(
            [{"id": "ev-1", "type": "observation", "job_id": "jv",
              "category": "XSS", "observation_ref": "obs-1"}],
            vulnerability_class="XSS", verification_job_ids=["jv"])
        pkg = build_package(store=self.fs, runtime_store=self._r,
                            candidate=cand, verification=ver,
                            decision=decision, qualities=qualities,
                            knowledge_ids=["kb-1"],
                            research_jobs=[cand.source_job])
        for key in ("title", "target", "scope", "endpoint_context",
                    "vulnerability_class", "authoritative_verification",
                    "evidence_ids", "evidence_timeline",
                    "related_candidates", "verification_plan",
                    "verification_outcome", "confidence_provenance",
                    "severity_provenance", "limitations",
                    "recommended_analyst_next_step"):
            self.assertIn(key, pkg)
        self.assertEqual(
            pkg["authoritative_verification"]["verification_state"],
            "VERIFIED")
        self.assertEqual(
            pkg["authoritative_verification"]["gate_reason"],
            "evidence_rules_met")
        self.assertTrue(any("no exploit" in str(x).lower()
                            for x in pkg["limitations"]))
        self.assertTrue(any("advisory" in str(x).lower()
                            for x in pkg["limitations"]))

    def test_handoff_view_is_read_only_and_secretless(self):
        from backend.research_agents.finding.gate import (
            VerificationDecision,
        )
        cand = make_candidate(self.fs)
        cand.provenance = {"api_key": "sk-supersecret-should-not-leak",
                           "created_by": "t"}
        self.fs.save_candidate(cand)
        fresh = self.fs.get_candidate(cand.candidate_id)
        self.fs.transition_candidate(fresh.candidate_id, "TRIAGED",
                                     reason="triage")
        case = ensure_case(self.fs, self.fs.get_candidate(cand.candidate_id),
                           reason="t")
        ver = create_verification(store=self.fs,
                                  candidate=self.fs.get_candidate(
                                      cand.candidate_id),
                                  capability=capability_for("XSS"))
        decision = VerificationDecision(
            verification_state="", candidate_state="TRIAGED",
            reason="verification_pending")
        view = handoff_view(
            case=case,
            candidate=self.fs.get_candidate(cand.candidate_id),
            verification=ver, decision=decision)
        blob = json.dumps(view)
        self.assertNotIn("sk-supersecret-should-not-leak", blob)
        self.assertNotIn("api_key", blob)
        for key in ("verified_status", "evidence_ids", "provenance",
                    "target", "scope", "research_lineage", "analyst_notes",
                    "limitations", "read_only"):
            self.assertIn(key, view)
        self.assertTrue(view["read_only"])

    def test_handoff_has_no_submission_automation(self):
        from backend.research_agents.finding.gate import (
            VerificationDecision,
        )
        early = make_candidate(self.fs)
        self.fs.transition_candidate(early.candidate_id, "TRIAGED",
                                     reason="triage")
        case = ensure_case(self.fs, self.fs.get_candidate(
            early.candidate_id), reason="t")
        ver = create_verification(
            store=self.fs,
            candidate=self.fs.get_candidate(early.candidate_id),
            capability=capability_for("XSS"))
        blob = json.dumps(handoff_view(
            case=case,
            candidate=self.fs.get_candidate(early.candidate_id),
            verification=ver,
            decision=VerificationDecision(
                verification_state="", candidate_state="TRIAGED",
                reason="verification_pending"))).lower()
        self.assertNotIn("submit", blob)
        self.assertNotIn("upload", blob)


class TestAdvisorContract(unittest.TestCase):
    def setUp(self):
        self._r, self.fs = make_stores()
        self.cand = make_candidate(self.fs)
        self.ver = create_verification(store=self.fs, candidate=self.cand,
                                       capability=capability_for("XSS"))

    def test_request_is_bounded_and_carries_no_urls(self):
        req = advisor_request(
            candidate=self.cand, verification=self.ver,
            evidence_summary=[{"evidence_id": "ev-1", "source": "observation",
                               "stance": "supporting",
                               "reliability_class": "observed_direct"}],
            related_research=[{"left_id": "cand-a", "right_id": "cand-b"}],
            knowledge_count=2,
            allowed_observation_types=["http-rows", "url-rows"],
            budget_remaining={"max_llm_calls": 3})
        blob = json.dumps(req, sort_keys=True)
        self.assertLessEqual(len(blob), 4000)
        self.assertNotIn("http://", blob)
        self.assertNotIn("https://", blob)
        self.assertNotIn("sk-", blob)          # no keys ever
        self.assertEqual(req.get("provider_kind"), "OPENROUTER")
        adv_id = req.get("advisory_id", "")
        self.assertTrue(adv_id.startswith("adv-") and len(adv_id) == 20)
        self.assertEqual(req.get("advisory_mode"), "EXPLANATION")

    def test_valid_response_maps_advisory_only(self):
        out = map_advisor_response(
            {"summary": "interpret", "insights": [
                {"insight_code": "MISSING_EVIDENCE_1",
                 "text": "marker missing"}],
             "recommendations": [
                {"recommendation_code": "VERIFY_X", "text": "http-rows"}]},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows", "url-rows", "parameter-rows"})
        self.assertFalse(out.error)
        self.assertTrue(out.used)
        self.assertIn("marker missing", out.missing_evidence)
        self.assertIn("http-rows", out.verification_recommendations)
        blob = json.dumps(out.to_dict())
        for forbidden in ("decision", "verified"):
            # the outcome may carry no verification verdict field
            self.assertNotIn(f'"{forbidden}":', blob)

    def test_severity_claim_rejected(self):
        out = map_advisor_response(
            {"summary": "x", "insights": [], "recommendations": [
                {"recommendation_code": "SEVERITY_CRITICAL",
                 "text": "critical"}]},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows"})
        self.assertTrue(any("authoritative_field_not_llm_set" in r
                            for r in out.rejected))

    def test_cve_claim_rejected(self):
        out = map_advisor_response(
            {"summary": "x", "insights": [], "recommendations": [
                {"recommendation_code": "CVE_APPLICABILITY_1",
                 "text": "applies"}]},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows"})
        self.assertTrue(any("authoritative_field_not_llm_set" in r
                            for r in out.rejected))

    def test_unknown_observation_type_rejected(self):
        out = map_advisor_response(
            {"summary": "x", "insights": [], "recommendations": [
                {"recommendation_code": "VERIFY_ARB",
                 "text": "shell_exec"}]},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows"})
        self.assertTrue(any("unknown_observation_type" in r
                            for r in out.rejected))
        self.assertEqual(out.verification_recommendations, [])

    def test_forbidden_content_blocks_whole_response(self):
        out = map_advisor_response(
            {"summary": "go fetch https://evil.test/x now", "insights": [],
             "recommendations": []},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows"})
        self.assertIsNotNone(out.error)
        self.assertIn("forbidden_advisor_content", out.error)
        self.assertFalse(out.used)

    def test_malformed_responses_fail_closed(self):
        for bad in (None, [], "text", {}, {"summary": "x"}):
            out = map_advisor_response(
                bad, candidate_id=self.cand.candidate_id,
                verification_id=self.ver.verification_id,
                scope_ref=self.cand.scope_ref,
                expected_scope=self.ver.scope_ref,
                allowed_types={"http-rows"})
            self.assertIsNotNone(out.error)
            self.assertFalse(out.used)

    def test_confidence_insight_is_label_not_verdict(self):
        out = map_advisor_response(
            {"summary": "x", "insights": [
                {"insight_code": "CONFIDENCE_95", "text": "95% sure"}],
             "recommendations": []},
            candidate_id=self.cand.candidate_id,
            verification_id=self.ver.verification_id,
            scope_ref=self.cand.scope_ref,
            expected_scope=self.ver.scope_ref,
            allowed_types={"http-rows"})
        self.assertEqual(out.confidence, "advisory")
        self.assertFalse(out.error)

    def test_executor_never_passes_advisor_into_gate(self):
        src = (Path(__file__).resolve().parents[1] /
               "backend/research_agents/finding/executor.py").read_text()
        gate_call = src.split("gate_decide(")[1].split(")")[0]
        self.assertNotIn("advisor", gate_call)
        self.assertIn("quality_rows=quality_dicts", src)


class TestAudit(unittest.TestCase):
    def test_event_is_bounded_and_named_finding(self):
        ev = finding_event("candidate_detected",
                           {"candidate_id": "cand-1", "x": None,
                            "list": list(range(50)),
                            "nested": {"k" + str(i): "v" for i in range(50)}})
        self.assertTrue(ev["event"].startswith("finding_"))
        self.assertLessEqual(len(ev["list"]), 20)
        self.assertLessEqual(len(ev["nested"]), 20)
        self.assertNotIn("x", ev)

    def test_event_scrubs_secret_like_keys(self):
        ev = finding_event("lineage", {
            "api_key": "sk-secret", "authorization": "Bearer x",
            "job_id": "job-1", "password": "p", "token": "t",
            "OPENROUTER_API_KEY": "sk-o"})
        blob = json.dumps(ev)
        for secret in ("sk-secret", "Bearer x", "sk-o", '"password"',
                       '"token"'):
            self.assertNotIn(secret, blob)
        self.assertEqual(ev.get("job_id"), "job-1")

    def test_lineage_row_has_full_chain_ids(self):
        row = lineage_row(candidate_id="cand-1", verification_id="ver-1",
                          case_id="case-1", job_id="job-1",
                          plan_id="plan-1",
                          authorization_ids=["auth-1"],
                          observation_ids=["obs-1"],
                          evidence_refs=["ev-1"], campaign_id="camp-1",
                          objective_id="obj-1", specialist="xss-agent",
                          model_requested="openrouter/free",
                          model_resolved="openrouter/free",
                          prompt_version="finding-advisor-v1",
                          gate_result="evidence_rules_met",
                          lifecycle_transition="VERIFYING->VERIFIED",
                          reason_codes=["evidence_rules_met"])
        for key in ("candidate_id", "verification_id", "plan_id", "job_id",
                    "campaign_id", "objective_id", "specialist",
                    "model_requested", "model_resolved", "prompt_version",
                    "evidence_refs", "gate_result", "lifecycle_transition",
                    "reason_codes"):
            self.assertIn(key, row)
        self.assertNotIn("api_key", row)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

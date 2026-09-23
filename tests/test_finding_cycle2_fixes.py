"""Cycle-2 regression suite — production-validation fixes (Sixth Epic).

Three real defects surfaced by running the layer against LIVE Watch
production research data (Phase 19/20 validation, 2026-09-23):

1. deduplicate() ranked and mutated STALE cached candidate objects (the
   executor's ``existing`` snapshot): a verification-bound candidate was
   demoted to DUPLICATE over its persisted state and
   ``save_candidate(stale)`` clobbered its case back-link.
2. a DUPLICATE candidate could keep a live TRIAGED case + pending
   verification — SOC displayed dead-end "awaiting verification" rows.
3. ``verification.authorization_ids`` stayed empty although the
   hunt_authorization audit rows carry the authoritative GRANTED ids,
   and the candidate-detail gate case link resolved empty for decided
   gates.

Each test REDs against the pre-fix code and GREENs after.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from backend.research_agents.capabilities import capability_for
from backend.research_agents.finding.correlate import correlate_pair
from backend.research_agents.finding.dedupe import deduplicate
from backend.research_agents.finding.verification import create_verification
from backend.soc import findings as soc_findings
from tests.finding_fixtures import (
    SCOPE,
    add_evidence,
    complete_job,
    enqueue_job,
    finding_worker_factory,
    gate_structured,
    make_candidate,
    make_case,
    make_stores,
    run_findings,
)


# --------------------------------------------------------------------- #
# Fix 1: dedupe must rank/demote from PERSISTED truth, never a snapshot
# --------------------------------------------------------------------- #
class TestDedupeUsesPersistedTruth(unittest.TestCase):
    def _planned_twin(self, fs):
        """Candidate A processed through planning: TRIAGED -> case ->
        VERIFICATION_PLANNED -> verification objective (production
        sequence before a second same-job candidate is deduplicated)."""
        a = make_candidate(fs, created_at="2026-09-23T01:00:00+00:00")
        a = fs.transition_candidate(a.candidate_id, "TRIAGED",
                                    reason="triage:verify")
        case = make_case(fs, a)          # store back-links a.case_id
        a = fs.transition_candidate(a.candidate_id, "VERIFICATION_PLANNED",
                                    reason="planned")
        ver = create_verification(store=fs, candidate=a,
                                  capability=capability_for("XSS"))
        return a, case, ver

    def test_stale_snapshot_cannot_demote_verification_bound_twin(self):
        _, fs = make_stores()
        a, case, ver = self._planned_twin(fs)
        # exactly the executor's stale cache entry: captured when A was
        # first appended (DETECTED, before its case/verification writes)
        stale_a = replace(a, lifecycle_state="DETECTED", case_id="",
                          revision=1)
        b = make_candidate(fs, created_at="2026-09-23T02:00:00+00:00")
        pair = correlate_pair(b, stale_a)
        self.assertIn(pair.relation, ("SAME_CANDIDATE",
                                      "POSSIBLE_DUPLICATE"))
        ded = deduplicate(fs, b, [stale_a], [pair])
        self.assertEqual(ded.action, "linked_duplicate")
        self.assertEqual(ded.canonical_id, a.candidate_id)

        # persisted truth wins: never demoted, back-link intact
        fresh_a = fs.get_candidate(a.candidate_id)
        self.assertEqual(fresh_a.lifecycle_state, "VERIFICATION_PLANNED")
        self.assertEqual(fresh_a.case_id, case.case_id)
        fresh_b = fs.get_candidate(b.candidate_id)
        self.assertEqual(fresh_b.lifecycle_state, "DUPLICATE")
        self.assertEqual(fresh_b.duplicate_of, a.candidate_id)
        # A's objective untouched (never expired by a bad demotion)
        self.assertNotEqual(
            fs.get_verification(ver.verification_id).state, "EXPIRED")

    def test_fresh_dedup_still_links_a_real_duplicate(self):
        """The freshness fix must not disable deduplication itself."""
        _, fs = make_stores()
        a = make_candidate(fs, created_at="2026-09-23T01:00:00+00:00")
        b = make_candidate(fs, created_at="2026-09-23T02:00:00+00:00")
        pair = correlate_pair(b, a)
        ded = deduplicate(fs, b, [a], [pair])
        self.assertEqual(ded.action, "linked_duplicate")
        fresh_b = fs.get_candidate(b.candidate_id)
        self.assertEqual(fresh_b.lifecycle_state, "DUPLICATE")
        # evidence preserved, never deleted
        self.assertEqual(sorted(fresh_b.evidence_refs),
                         sorted(b.evidence_refs))


# --------------------------------------------------------------------- #
# Fix 2: a DUPLICATE candidate never leaves live work behind
# --------------------------------------------------------------------- #
class TestDuplicateCascade(unittest.TestCase):
    def _planned_twin(self, fs):
        a = make_candidate(fs)
        a = fs.transition_candidate(a.candidate_id, "TRIAGED",
                                    reason="triage:verify")
        case = make_case(fs, a)
        a = fs.transition_candidate(a.candidate_id, "VERIFICATION_PLANNED",
                                    reason="planned")
        ver = create_verification(store=fs, candidate=a,
                                  capability=capability_for("XSS"))
        return a, case, ver

    def test_duplicate_transition_cascades_case_and_verification(self):
        _, fs = make_stores()
        a, case, ver = self._planned_twin(fs)
        fs.transition_candidate(a.candidate_id, "DUPLICATE",
                                reason="duplicate_of:explicit-test")
        self.assertEqual(fs.get_case(case.case_id).state, "DUPLICATE")
        v = fs.get_verification(ver.verification_id)
        self.assertEqual(v.state, "EXPIRED")
        self.assertIn("duplicate", v.termination_reason)
        rows = [r for r in fs.all_transitions()
                if str(r.get("new")) in ("DUPLICATE", "EXPIRED")
                and r.get("kind") in ("case", "verification")]
        self.assertTrue(rows, "cascade must write lineage rows")

    def test_cascade_never_forces_an_illegal_state(self):
        _, fs = make_stores()
        a = make_candidate(fs)
        a = fs.transition_candidate(a.candidate_id, "TRIAGED", reason="t")
        case = make_case(fs, a)
        # BLOCKED->DUPLICATE is not in the case transition map
        fs.transition_case(case.case_id, "BLOCKED", reason="blocked")
        fs.transition_candidate(a.candidate_id, "DUPLICATE",
                                reason="duplicate_of:x")
        self.assertEqual(fs.get_case(case.case_id).state, "BLOCKED")

    def test_duplicate_without_artifacts_is_clean(self):
        _, fs = make_stores()
        a = make_candidate(fs)
        fs.transition_candidate(a.candidate_id, "DUPLICATE",
                                reason="duplicate_of:none")
        self.assertEqual(
            fs.get_candidate(a.candidate_id).lifecycle_state, "DUPLICATE")
        self.assertIsNone(fs.cases_for_candidate(a.candidate_id))


# --------------------------------------------------------------------- #
# Fix 3: authorization ids harvested from authoritative hunt audit rows
# --------------------------------------------------------------------- #
class TestAuthorizationHarvest(unittest.TestCase):
    @staticmethod
    def _harvest_worker_factory(runtime, auth_ids):
        """Scripted worker whose verification result carries NO hunt
        authorization_ids, then writes the hunt_authorization audit rows
        exactly like the real Hunt runtime does (job id known only after
        enqueue, so the rows are written at completion time)."""
        def factory(config=None, store=None):
            st = store or runtime

            class Wrap:
                def run(self, max_jobs: int = 1, **_kw):
                    queued = st.list_jobs(status="QUEUED", limit=10)
                    if not queued:
                        return {"ran": 0}
                    job = queued[0]
                    add_evidence(st, job.id, kind="supporting",
                                 category=job.agent_category)
                    custom = gate_structured(
                        "evidence_rules_met", True,
                        {"objective_id": "hunt-h2",
                         "state": "RESOLVED",
                         "plan_ids": ["plan-h2"],
                         "observation_ids": ["obs-h2", "obs-h3"]})
                    complete_job(st, job, structured=custom)
                    for aid in auth_ids:
                        st.record_audit_event({
                            "event": "hunt_authorization",
                            "job_id": job.id, "auth_id": aid,
                            "plan_id": "plan-h2",
                            "observation_types": ["http-rows"],
                        })
                    return {"ran": 1}
            return Wrap()
        return factory

    def _run(self, auth_ids):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        run_findings(
            [source.id], store=runtime, finding_store=fs,
            worker_factory=self._harvest_worker_factory(runtime, auth_ids))
        return runtime, fs

    def test_phase_b_harvests_authorization_ids_from_audit(self):
        auth_ids = ["authz-35e609a42d32", "authz-42bf89ffbcce"]
        runtime, fs = self._run(auth_ids)
        decided = [v for v in fs.list_verifications()
                   if v.state in ("VERIFIED", "REJECTED", "INCONCLUSIVE")]
        self.assertTrue(decided, "verification must reach a gate decision")
        ver = decided[-1]
        self.assertEqual(list(ver.authorization_ids), auth_ids)
        # the gate audit event carries them too (Phase 16 lineage)
        rows = [r for r in runtime.audit_events(limit=5000)
                if r.get("event") == "finding_verification_gate_decided"]
        self.assertTrue(rows)
        self.assertEqual(list(rows[-1].get("authorization_ids") or []),
                         auth_ids)

    def test_soc_detail_derives_ids_when_objective_predates_harvest(self):
        auth_ids = ["authz-8f8224dd1919"]
        runtime, fs = self._run(auth_ids)
        cand = [c for c in fs.list_candidates()
                if c.lifecycle_state != "DUPLICATE"][0]
        ver = fs.list_verifications(candidate_id=cand.candidate_id)[-1]
        # production shape: stored objective predates the harvest fix
        ver.authorization_ids = []
        fs.save_verification(ver)
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            detail = soc_findings.finding_detail(cand.candidate_id)
        self.assertIsNotNone(detail)
        self.assertEqual(list(detail["authorization_ids"]), auth_ids)


# --------------------------------------------------------------------- #
# Fix 4: the detail gate block always links a real case when decided
# --------------------------------------------------------------------- #
class TestSocGateCaseLink(unittest.TestCase):
    def test_decided_gate_resolves_a_real_case_id(self):
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)
        cand = [c for c in fs.list_candidates()
                if c.lifecycle_state != "DUPLICATE"][0]
        ver = fs.list_verifications(candidate_id=cand.candidate_id)[-1]
        if ver.job_id:
            runtime.record_audit_event({
                "event": "finding_verification_gate_decided",
                "job_id": ver.job_id, "case_id": "case-runtime-1",
                "candidate_id": cand.candidate_id})
        with mock.patch.object(soc_findings, "_store",
                               return_value=(fs, runtime)):
            detail = soc_findings.finding_detail(cand.candidate_id)
        self.assertIsNotNone(detail)
        if not detail["gate"]:
            self.skipTest("fixture produced no gate decision")
        self.assertTrue(detail["gate"]["case_id"],
                        "a decided gate must link a real case")
        expected = ("case-runtime-1" if ver.job_id
                    else fs.get_candidate(cand.candidate_id).case_id)
        self.assertEqual(detail["gate"]["case_id"], expected)
        self.assertEqual(detail["gate"].get("finding_case_id"),
                         fs.get_candidate(cand.candidate_id).case_id)


# --------------------------------------------------------------------- #
# End-to-end production sequence: same-job batch, invariants that the
# 2026-09-23 production run violated before the fixes
# --------------------------------------------------------------------- #
class TestSameJobBatchInvariants(unittest.TestCase):
    def test_batch_run_never_leaves_artifacts_on_a_duplicate(self):
        from backend.research_agents.models import ResearchResult
        runtime, fs = make_stores()
        source = enqueue_job(runtime)
        result = ResearchResult(
            job_id=source.id, agent_name="xss-agent",
            confidence="high", findings=("signal",),
            status="COMPLETED", execution_mode="fixture",
            structured={
                "hypotheses": ["q reflects unencoded into the page",
                               "q reflects unencoded into the response"],
                "verdict": {"status": "signal"},
                "evidence_missing": [],
                "evidence_gate": {"authoritative": True,
                                  "reason": "evidence_rules_met",
                                  "created_case": True,
                                  "confidence": "high"},
            })
        runtime.put_result(result)
        wf, _ = finding_worker_factory("verified")
        summary, _journal = run_findings(
            [source.id], store=runtime, finding_store=fs,
            worker_factory=wf)

        cands = fs.list_candidates()
        self.assertGreaterEqual(len(cands), 2)
        planned = [c for c in cands
                   if c.lifecycle_state != "DUPLICATE"]
        dupes = [c for c in cands if c.lifecycle_state == "DUPLICATE"]
        self.assertTrue(dupes, "same-endpoint twins must deduplicate")
        self.assertTrue(planned, "a canonical candidate must survive")

        for c in dupes:
            case = fs.cases_for_candidate(c.candidate_id)
            if case is not None:
                self.assertEqual(case.state, "DUPLICATE",
                                 "duplicate artifacts must not be live")
            for v in fs.list_verifications(candidate_id=c.candidate_id):
                self.assertEqual(v.state, "EXPIRED",
                                 "duplicate objective must expire")
        for c in cands:
            case = fs.cases_for_candidate(c.candidate_id)
            if case is not None:
                self.assertEqual(c.case_id, case.case_id,
                                 "case back-link must survive dedupe")
        # exactly one canonical family: every duplicate points at a
        # still-existing, non-duplicate candidate
        for c in dupes:
            parent = fs.get_candidate(c.duplicate_of)
            self.assertIsNotNone(parent)
            self.assertNotEqual(parent.lifecycle_state, "DUPLICATE")
        self.assertEqual(summary.errors, [])


if __name__ == "__main__":
    unittest.main()


# --------------------------------------------------------------------- #
# Cycle 3: SOC Cases next_action must be state-truthful
# (a DUPLICATE/BLOCKED row must never say "awaiting verification")
# --------------------------------------------------------------------- #
class TestSocCaseNextActionLabels(unittest.TestCase):
    def _patched(self, runtime):
        import backend.research_agents.runtime_store as rs
        return mock.patch.object(rs, "default_store",
                                 return_value=runtime)

    def test_duplicate_blocked_rows_never_claim_pending_work(self):
        from backend.soc import cases as soc_cases
        runtime, fs = make_stores()

        # verified family from a real run (recommended step present)
        source = enqueue_job(runtime)
        complete_job(runtime, source, outcome="verified")
        wf, _ = finding_worker_factory("verified")
        run_findings([source.id], store=runtime, finding_store=fs,
                     worker_factory=wf)

        # duplicate family: TRIAGED case, then candidate -> DUPLICATE
        # (the store cascade folds the case, exactly like production)
        dup_cand = make_candidate(fs)
        dup_cand = fs.transition_candidate(dup_cand.candidate_id,
                                           "TRIAGED", reason="t")
        dup_case = make_case(fs, dup_cand)
        fs.transition_candidate(dup_cand.candidate_id, "DUPLICATE",
                                reason="duplicate_of:some-canonical")

        # blocked family: TRIAGED case -> BLOCKED directly
        blk_cand = make_candidate(fs)
        blk_cand = fs.transition_candidate(blk_cand.candidate_id,
                                           "TRIAGED", reason="t")
        blk_case = make_case(fs, blk_cand)
        fs.transition_case(blk_case.case_id, "BLOCKED",
                           reason="verification_failed")

        # genuine pending family: TRIAGED case that really awaits work
        pend_cand = make_candidate(fs)
        pend_cand = fs.transition_candidate(pend_cand.candidate_id,
                                            "TRIAGED", reason="t")
        pend_case = make_case(fs, pend_cand)

        with self._patched(runtime):
            payload = soc_cases.cases_index()
        rows = {r["case_id"]: r for r in payload["cases"]
                if r.get("source") == "finding-verification"}

        dup_row = rows[dup_case.case_id]
        self.assertEqual(dup_row["research_state"], "DUPLICATE")
        self.assertIn("duplicate", dup_row["next_action"].lower())
        self.assertNotEqual(dup_row["next_action"],
                            "awaiting verification")

        blk_row = rows[blk_case.case_id]
        self.assertEqual(blk_row["research_state"], "BLOCKED")
        self.assertIn("blocked", blk_row["next_action"].lower())
        self.assertNotEqual(blk_row["next_action"],
                            "awaiting verification")

        # a case that truly has nothing yet keeps the pending label
        pend_row = rows[pend_case.case_id]
        self.assertEqual(pend_row["next_action"], "awaiting verification")

        # the verified row shows the stored analyst step, never pending
        verified_rows = [r for r in rows.values()
                         if r["kind"] == "verified-case"]
        self.assertTrue(verified_rows)
        self.assertNotEqual(verified_rows[0]["next_action"],
                            "awaiting verification")

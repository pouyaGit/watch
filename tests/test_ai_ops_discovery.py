"""EPIC9 §4/§5: fail-closed discovery — every class, every honest
reason, no silent skips, source failures surfaced as errors."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.ai_ops.discovery import (
    BUDGET_DEFERRED, CLASS_CAMPAIGN, CLASS_FINDING, CLASS_HUNT,
    CLASS_JOB, DEPENDENCY_BLOCKED, ALREADY_RUNNING, EXECUTABLE,
    INVALID_STATE, NOT_AUTHORIZED, OUT_OF_WINDOW, RETRY_NOT_DUE,
    TERMINAL, WAITING_FOR_EVIDENCE,
    DiscoveryReport, WorkItem,
    classify_campaign_objective, classify_finding_candidate,
    classify_hunt_objective, classify_job, classify_verification_objective,
    discover,
)


def classify_campaign(campaign, objectives):
    """Test-facing wrapper: classify every objective of one campaign."""
    by_id = {o.objective_id: o for o in objectives}
    return [classify_campaign_objective(campaign, o, by_id)
            for o in objectives]


def classify_candidate(candidate, **kw):
    return classify_finding_candidate(candidate, **kw)


def classify_hunt(objective, **kw):
    return classify_hunt_objective(objective, **kw)


def classify_verification(*, verification_id, state, candidate_id,
                          source_job, scope_ref):
    ver = SimpleNamespace(
        id=verification_id, verification_id=verification_id,
        state=state, candidate_id=candidate_id,
        source_job=source_job, scope_ref=scope_ref)
    return classify_verification_objective(ver)
from tests.ai_ops_fixtures import (
    AiOpsEnvMixin, OTHER_SCOPE, SCOPE,
    make_campaign, make_candidate, make_hunt, make_job, make_objective,
)


class ClassifyJobTests(unittest.TestCase):

    def test_queued_is_executable(self):
        item = classify_job(make_job(status="QUEUED"))
        self.assertEqual(item.work_class, CLASS_JOB)
        self.assertTrue(item.executable)
        self.assertEqual(item.reason, EXECUTABLE)

    def test_new_status_is_executable(self):
        self.assertTrue(classify_job(make_job(status="NEW")).executable)

    def test_claimed_alive_is_already_running(self):
        item = classify_job(make_job(
            status="CLAIMED", lease_owner="w1",
            lease_expires_at="2999-01-01T00:00:00+00:00"))
        self.assertFalse(item.executable)
        self.assertEqual(item.reason, ALREADY_RUNNING)

    def test_waiting_evidence_is_waiting(self):
        item = classify_job(make_job(status="WAITING_EVIDENCE"))
        self.assertEqual(item.reason, WAITING_FOR_EVIDENCE)
        self.assertFalse(item.executable)

    def test_terminal_statuses(self):
        for status in ("COMPLETED", "CANCELLED", "EXPIRED", "TIMEOUT",
                       "FAILED", "TERMINAL_FAILED"):
            item = classify_job(make_job(status=status))
            self.assertEqual(item.reason, TERMINAL, msg=status)
            self.assertFalse(item.executable)

    def test_unknown_status_is_invalid_state(self):
        item = classify_job(make_job(status="SOMETHING_ELSE"))
        self.assertEqual(item.reason, INVALID_STATE)
        self.assertFalse(item.executable)

    def test_carries_target_and_scope(self):
        item = classify_job(make_job(program="www", subdomain="example.com"))
        self.assertIn("watch:scope:", item.scope_ref)
        self.assertTrue(item.work_id.startswith("job:"))


class ClassifyCampaignTests(unittest.TestCase):

    def _pair(self, camp_kw=None, obj_kw=None):
        return (make_campaign(**(camp_kw or {})),
                make_objective(**(obj_kw or {})))

    def test_ready_campaign_ready_objective_executable(self):
        camp, obj = self._pair()
        item = classify_campaign(camp, [obj])
        self.assertEqual(len(item), 1)
        self.assertTrue(item[0].executable)
        self.assertEqual(item[0].work_class, CLASS_CAMPAIGN)
        self.assertEqual(item[0].reason, EXECUTABLE)

    def test_objective_not_ready_is_invalid_state(self):
        camp, obj = self._pair(obj_kw={"state": "QUEUED"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, INVALID_STATE)
        self.assertFalse(item.executable)

    def test_waiting_objective_dependency_blocked(self):
        camp, obj = self._pair(obj_kw={"state": "WAITING"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, DEPENDENCY_BLOCKED)
        self.assertFalse(item.executable)

    def test_needs_evidence_rejected_from_campaign_vocabulary(self):
        # NEEDS_EVIDENCE belongs to hunt/finding vocabularies; the
        # campaign objective vocabulary rejects it at write time
        # (fail closed). §6 coverage for NEEDS_EVIDENCE lives in
        # ClassifyHuntTests / ClassifyFindingTests.
        with self.assertRaises(ValueError):
            self._pair(obj_kw={"state": "NEEDS_EVIDENCE"})

    def test_resolved_objective_terminal(self):
        camp, obj = self._pair(obj_kw={"state": "RESOLVED"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, TERMINAL)

    def test_terminal_campaign_makes_objectives_terminal(self):
        for state in ("COMPLETED", "CANCELLED", "EXPIRED"):
            camp, obj = self._pair(camp_kw={"state": state})
            item = classify_campaign(camp, [obj])[0]
            self.assertEqual(item.reason, TERMINAL, msg=state)
            self.assertFalse(item.executable)

    def test_draft_campaign_invalid_state(self):
        camp, obj = self._pair(camp_kw={"state": "DRAFT"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, INVALID_STATE)

    def test_leased_campaign_already_running(self):
        camp, obj = self._pair(camp_kw={
            "state": "RUNNING", "lease_owner": "w1",
            "lease_expires_at": "2999-01-01T00:00:00+00:00"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, ALREADY_RUNNING)

    def test_expired_lease_falls_through_to_objective_state(self):
        camp, obj = self._pair(camp_kw={
            "state": "RUNNING", "lease_owner": "w1",
            "lease_expires_at": "2000-01-01T00:00:00+00:00"})
        item = classify_campaign(camp, [obj])[0]
        self.assertTrue(item.executable)

    def test_malformed_scope_is_not_authorized(self):
        camp = make_campaign(scope_ref=SCOPE)
        obj = make_objective(scope_ref=SCOPE)
        # bypass post_init validation the way corrupt data would
        object.__setattr__(camp, "scope_ref", "evil:scope:x")
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, NOT_AUTHORIZED)
        self.assertFalse(item.executable)

    def test_retry_backoff_is_retry_not_due(self):
        camp, obj = self._pair(obj_kw={
            "attempts": 1, "updated_at": "2999-01-01T00:00:00+00:00"})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, RETRY_NOT_DUE)

    def test_attempts_exhausted_retry_not_due(self):
        # attempts >= max: never "due" again here; the EXECUTOR owns
        # the authoritative TERMINAL transition (termination_record).
        camp, obj = self._pair(obj_kw={"attempts": 99})
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, RETRY_NOT_DUE)
        self.assertFalse(item.executable)

    def test_unmet_dependency_blocked(self):
        from backend.research_agents.campaign.models import Dependency
        camp = make_campaign()
        obj = make_objective()
        obj.dependencies = [Dependency(
            objective_id=obj.objective_id, depends_on="obj-other")]
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.reason, DEPENDENCY_BLOCKED)

    def test_campaign_id_carried(self):
        camp = make_campaign(campaign_id="camp-zz")
        obj = make_objective(campaign_id="camp-zz")
        item = classify_campaign(camp, [obj])[0]
        self.assertEqual(item.campaign_id, "camp-zz")


class ClassifyHuntTests(unittest.TestCase):

    def test_needs_evidence_waiting(self):
        item = classify_hunt(make_hunt(state="NEEDS_EVIDENCE"))
        self.assertEqual(item.reason, WAITING_FOR_EVIDENCE)
        self.assertFalse(item.executable)

    def test_terminal_states(self):
        for state in ("RESOLVED", "REJECTED", "BLOCKED"):
            item = classify_hunt(make_hunt(state=state))
            self.assertEqual(item.reason, TERMINAL, msg=state)

    def test_open_is_report_only_dependency_blocked(self):
        item = classify_hunt(make_hunt(state="OPEN"))
        self.assertEqual(item.reason, DEPENDENCY_BLOCKED)
        self.assertFalse(item.executable)
        self.assertEqual(item.work_class, CLASS_HUNT)

    def test_hunt_never_executable_directly(self):
        for state in ("OPEN", "READY_FOR_PLANNING", "PLANNED",
                      "OBSERVATION_PENDING", "OBSERVATION_COMPLETE",
                      "NEEDS_EVIDENCE", "RESOLVED", "BLOCKED"):
            self.assertFalse(
                classify_hunt(make_hunt(state=state)).executable,
                msg=state)


class ClassifyFindingTests(unittest.TestCase):

    def test_pending_verification_executable(self):
        item = classify_candidate(make_candidate(
            lifecycle_state="VERIFICATION_PENDING"))
        self.assertTrue(item.executable)
        self.assertEqual(item.work_class, CLASS_FINDING)

    def test_planned_verification_executable(self):
        self.assertTrue(classify_candidate(make_candidate(
            lifecycle_state="VERIFICATION_PLANNED")).executable)

    def test_needs_evidence_candidate_waiting(self):
        item = classify_candidate(make_candidate(
            lifecycle_state="NEEDS_EVIDENCE"))
        self.assertEqual(item.reason, WAITING_FOR_EVIDENCE)
        self.assertFalse(item.executable)

    def test_verified_duplicate_rejected_terminal(self):
        for state in ("VERIFIED", "DUPLICATE", "REJECTED"):
            item = classify_candidate(make_candidate(lifecycle_state=state))
            self.assertEqual(item.reason, TERMINAL, msg=state)

    def test_blocked_candidate_invalid_state(self):
        item = classify_candidate(make_candidate(lifecycle_state="BLOCKED"))
        self.assertEqual(item.reason, INVALID_STATE)

    def test_pipeline_intermediate_states_executable(self):
        # DETECTED/TRIAGED mean the source job can drive the existing
        # finding pipeline forward — genuinely executable work.
        for state in ("DETECTED", "TRIAGED"):
            self.assertTrue(
                classify_candidate(make_candidate(
                    lifecycle_state=state)).executable, msg=state)

    def test_verification_objective_auth_required_not_authorized(self):
        item = classify_verification(
            verification_id="ver-1", state="AUTHORIZATION_REQUIRED",
            candidate_id="cand-1", source_job="job-1", scope_ref=SCOPE)
        self.assertEqual(item.reason, NOT_AUTHORIZED)

    def test_verification_objective_waiting(self):
        item = classify_verification(
            verification_id="ver-1", state="WAITING",
            candidate_id="cand-1", source_job="job-1", scope_ref=SCOPE)
        self.assertEqual(item.reason, WAITING_FOR_EVIDENCE)

    def test_verification_objective_terminal(self):
        item = classify_verification(
            verification_id="ver-1", state="VERIFIED",
            candidate_id="cand-1", source_job="job-1", scope_ref=SCOPE)
        self.assertEqual(item.reason, TERMINAL)

    def test_verification_objective_report_only(self):
        item = classify_verification(
            verification_id="ver-1", state="READY",
            candidate_id="cand-1", source_job="job-1", scope_ref=SCOPE)
        # covered by the candidate pipeline — never a second work item
        self.assertFalse(item.executable)


class DiscoverIntegrationTests(AiOpsEnvMixin):
    """Real stores in an isolated cwd."""

    def test_empty_stores_empty_report(self):
        rep = discover()
        self.assertEqual(rep.items, [])
        self.assertEqual(rep.errors, [])
        counts = rep.counts()
        self.assertEqual(counts["discovered"], 0)
        self.assertEqual(counts["executable"], 0)

    def test_queued_job_discovered_executable(self):
        from backend.research_agents.runtime import RuntimeStore
        from backend.research_agents.models import ResearchJob
        RuntimeStore().enqueue(make_job("job-q1", "QUEUED"))
        rep = discover()
        self.assertEqual(rep.counts()["executable"], 1)
        self.assertEqual(rep.items[0].work_class, CLASS_JOB)

    def test_all_four_classes_discovered(self):
        from backend.research_agents.runtime import RuntimeStore
        from backend.research_agents.campaign.store import CampaignStore
        from backend.research_agents.hunt.store import HuntStore
        from backend.research_agents.finding.store import FindingStore
        RuntimeStore().enqueue(make_job("job-q1", "QUEUED"))
        cs = CampaignStore()
        cs.create_campaign(make_campaign())
        cs.add_objective(make_objective())
        HuntStore().create_objective(make_hunt(state="NEEDS_EVIDENCE"))
        FindingStore().add_candidate(make_candidate(
            lifecycle_state="VERIFIED"))
        rep = discover()
        classes = set(rep.counts()["by_class"])
        self.assertEqual(classes, {CLASS_JOB, CLASS_CAMPAIGN,
                                   CLASS_HUNT, CLASS_FINDING})
        counts = rep.counts()
        # queued job executable; hunt NEEDS_EVIDENCE waiting; the rest
        self.assertEqual(counts["executable"], 2)
        self.assertGreaterEqual(counts["waiting"], 1)

    def test_broken_source_reported_as_error_not_crash(self):
        class Boom:
            def list_jobs(self, **kw):
                raise RuntimeError("store exploded")

        rep = discover(runtime_store=Boom())
        self.assertEqual(rep.items, [])
        self.assertEqual(len(rep.errors), 1)
        self.assertIn("runtime", rep.errors[0]["source"])
        self.assertEqual(rep.errors[0]["error"], "RuntimeError")
        self.assertIn("exploded", rep.errors[0]["detail"])

    def test_every_item_has_a_reason(self):
        from backend.research_agents.runtime import RuntimeStore
        for status in ("QUEUED", "CLAIMED", "WAITING_EVIDENCE",
                       "COMPLETED", "WEIRD"):
            RuntimeStore().enqueue(make_job(f"job-{status}", status))
        rep = discover()
        self.assertGreaterEqual(len(rep.items), 5)
        for item in rep.items:
            self.assertTrue(item.reason, msg=item.work_id)
            self.assertIn(item.work_class,
                          {CLASS_JOB, CLASS_CAMPAIGN, CLASS_HUNT,
                           CLASS_FINDING})

    def test_counts_add_up(self):
        from backend.research_agents.runtime import RuntimeStore
        from backend.research_agents.finding.store import FindingStore
        RuntimeStore().enqueue(make_job("job-a", "QUEUED"))
        RuntimeStore().enqueue(make_job("job-b", "COMPLETED"))
        FindingStore().add_candidate(make_candidate(
            lifecycle_state="VERIFIED"))
        counts = discover().counts()
        self.assertEqual(counts["discovered"],
                         counts["executable"] + counts["waiting"]
                         + counts["blocked"])
        self.assertEqual(counts["non_terminal_blocked"], 0)


if __name__ == "__main__":
    unittest.main()

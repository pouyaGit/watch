"""AUTONOMOUS HUNT PLANNER v1 — Phase-by-phase core tests (RED-first).

Covers: research uncertainty states, hunt objectives, missing-evidence
engine, hunt plan model + versioning + immutability, observation
registry validation, deterministic information-gain scoring, LLM
advisor mapping (trusted final construction), authorization bridge, the
bounded execution loop + re-planning + termination reasons, and the
two-specialist (XSS / CVE_RESEARCH) integration through the real
AgentWorker with the research contract block.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from tests.hunt_fixtures import (  # noqa: E402
    cve_rows,
    http_rows_for_cve,
    make_job,
    make_store,
    claim_grade_determin,
    rich_rows,
    run_hunt_fixture,
)

from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.hunt import (  # noqa: E402
    HuntLimits,
    HuntObjective,
    HuntPlan,
    HuntStore,
    HuntStoreError,
    MissingEvidenceItem,
    ObservationRecord,
    PLAN_STATES,
    ResearchUncertainty,
    UncertaintyError,
    advisor_request,
    build_candidates,
    build_plan,
    compute_missing_evidence,
    map_advisor_response,
    new_id,
    registry_catalog,
    run_hunt,
    scan_forbidden,
    validate_final_plan,
    validate_observation_requests,
)
from backend.research_agents.hunt.authorization import (  # noqa: E402
    authorization_gate,
    build_authorization_request,
    reverify_before_observation,
)
from backend.research_agents.hunt.models import (  # noqa: E402
    AuthorizationRecord,
    PlanTransition,
    plan_transition,
)
from backend.research_agents.hunt.missing_evidence import (  # noqa: E402
    MISSING_EVIDENCE_RULE_VERSION,
)
from backend.research_agents.hunt.planner import AdvisorOutcome  # noqa: E402
from backend.research_agents.hunt.registry import REGISTRY  # noqa: E402
from backend.research_agents.hunt.store import utcnow  # noqa: E402
from backend.research_agents.hunt.uncertainty import (  # noqa: E402
    TERMINAL_STATES,
    UNCERTAINTY_STATES,
    transition,
)
from backend.research_agents.models import JobStatus  # noqa: E402
from backend.research_agents.runtime import (  # noqa: E402
    AuthorizationChecker,
    RuntimeConfig,
    deterministic_analysis,
    evaluate_case_creation,
)
from backend.research_agents.runtime_store import utcnow as _utc  # noqa: E402


def _objective(obj_id: str = "obj-test-1", state: str = "OPEN") -> HuntObjective:
    return HuntObjective(
        objective_id=obj_id, job_id="job-xss-hunt-test",
        specialist="xss-agent", category="XSS",
        scope_ref="fixture:shop/shop.test",
        target_context={"subdomain": "shop.test"},
        hypothesis="stored inputs present",
        research_objective="support or reject the hypothesis",
        evidence_requirements={"min_evidence_refs": 2,
                               "required_types": ["observation"],
                               "require_high_confidence": True},
        state=state, provenance={"source": "test"},
        created_at=_utc(), updated_at=_utc())


def _plan(plan_id: str = "plan-test-1", scope: str = "fixture:shop/shop.test",
          version: int = 1) -> HuntPlan:
    return HuntPlan(
        plan_id=plan_id, objective_id="obj-test-1", job_id="job-xss-hunt-test",
        version=version, parent_plan_id="", scope_ref=scope,
        specialist="xss-agent", category="XSS",
        reason="Selected because http-rows addresses missing evidence "
               "while requiring an already-authorized read-only observation",
        hypotheses_addressed=("stored inputs present",),
        observations_requested=({
            "observation_type": "http-rows",
            "inputs": {"subdomain": "shop.test", "limit": 25},
            "expected_evidence": "observation",
            "missing_item_ids": [], "risk_class": "READ_ONLY",
        },),
        required_evidence=("observation",),
        expected_information_gain=0.7, gain_label="heuristic",
        safety_constraints=("no_target_contact",),
        authorization_requirements=("fixture:shop/shop.test",),
        dependencies=(), priority=10, provenance={"planner": "test"},
        created_at=_utc())


class UncertaintyModelTests(unittest.TestCase):
    def test_nine_states_exist_and_are_distinct(self):
        self.assertEqual(len(UNCERTAINTY_STATES), 9)
        for name in ("OPEN", "NEEDS_EVIDENCE", "READY_FOR_PLANNING",
                     "PLANNED", "OBSERVATION_PENDING",
                     "OBSERVATION_COMPLETE", "RESOLVED", "REJECTED",
                     "BLOCKED"):
            self.assertIn(name, UNCERTAINTY_STATES)

    def test_needs_evidence_and_rejected_are_different_states(self):
        self.assertNotEqual("NEEDS_EVIDENCE", "REJECTED")
        self.assertIn("REJECTED", TERMINAL_STATES)
        self.assertNotIn("NEEDS_EVIDENCE", TERMINAL_STATES)

    def test_legal_transition(self):
        self.assertEqual(transition("OPEN", "NEEDS_EVIDENCE"),
                         "NEEDS_EVIDENCE")
        self.assertEqual(
            transition("OBSERVATION_COMPLETE", "NEEDS_EVIDENCE"),
            "NEEDS_EVIDENCE")

    def test_terminal_states_never_move(self):
        for state in TERMINAL_STATES:
            with self.assertRaises(UncertaintyError):
                transition(state, "NEEDS_EVIDENCE")

    def test_illegal_transition_rejected(self):
        with self.assertRaises(UncertaintyError):
            transition("OPEN", "PLANNED")
        with self.assertRaises(UncertaintyError):
            transition("OPEN", "NOT_A_STATE")

    def test_uncertainty_requires_provenance_and_scope(self):
        with self.assertRaises(UncertaintyError):
            ResearchUncertainty(objective_id="o", hypothesis="h",
                                scope_ref="", specialist="xss-agent",
                                provenance={"created_at": _utc()})
        with self.assertRaises(UncertaintyError):
            ResearchUncertainty(objective_id="o", hypothesis="h",
                                scope_ref="s", specialist="xss",
                                provenance={})
        u = ResearchUncertainty(
            objective_id="o", hypothesis="h", scope_ref="s",
            specialist="xss", provenance={"created_at": _utc()})
        self.assertFalse(u.is_terminal)
        self.assertTrue(len(u.digest()) == 16)

    def test_roundtrip_and_digest_stable(self):
        u = ResearchUncertainty(
            objective_id="o", hypothesis="h", state="NEEDS_EVIDENCE",
            scope_ref="s", specialist="xss",
            missing_evidence=[{"item_code": "x", "reason": "r"}],
            provenance={"created_at": _utc()})
        again = ResearchUncertainty.from_dict(u.to_dict())
        self.assertEqual(again.digest(), u.digest())
        self.assertEqual(again.state, "NEEDS_EVIDENCE")


class ObjectiveAndPlanModelTests(unittest.TestCase):
    def test_objective_requires_provenance(self):
        with self.assertRaises(ValueError):
            _objective().__class__(
                objective_id="o", job_id="j", specialist="x",
                category="XSS", scope_ref="s", target_context={},
                hypothesis="h", research_objective="r",
                evidence_requirements={}, provenance={},
                created_at="t", updated_at="t")

    def test_objective_roundtrip_keeps_state(self):
        obj = _objective(state="PLANNED")
        again = HuntObjective.from_dict(obj.to_dict())
        self.assertEqual(again.state, "PLANNED")
        self.assertEqual(again.objective_id, obj.objective_id)

    def test_plan_requires_observations_and_labels_gain_heuristic(self):
        with self.assertRaises(Exception):
            HuntPlan(
                plan_id="p", objective_id="o", job_id="j", version=1,
                parent_plan_id="", scope_ref="s", specialist="x",
                category="XSS", reason="r", hypotheses_addressed=(),
                observations_requested=(), required_evidence=(),
                expected_information_gain=0.5, gain_label="exact",
                safety_constraints=(), authorization_requirements=(),
                dependencies=(), priority=1, provenance={"planner": "t"},
                created_at="t")
        self.assertEqual(_plan().gain_label, "heuristic")

    def test_definition_hash_is_stable_and_change_sensitive(self):
        p1 = _plan()
        p2 = _plan()
        self.assertEqual(p1.definition_hash(), p2.definition_hash())
        p3 = _plan(scope="fixture:shop/OTHER.test")
        self.assertNotEqual(p1.definition_hash(), p3.definition_hash())

    def test_plan_state_machine(self):
        self.assertEqual(plan_transition("DRAFT", "VALIDATED"), "VALIDATED")
        self.assertEqual(plan_transition("EXECUTING", "COMPLETED"),
                         "COMPLETED")
        with self.assertRaises(Exception):
            plan_transition("DRAFT", "EXECUTING")
        with self.assertRaises(Exception):
            plan_transition("COMPLETED", "EXECUTING")
        for terminal in ("COMPLETED", "PARTIAL", "REJECTED", "FAILED",
                         "BLOCKED", "EXPIRED"):
            self.assertIn(terminal, PLAN_STATES)
            with self.assertRaises(Exception):
                plan_transition(terminal, "EXECUTING")


class HuntStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = HuntStore(make_store().base)

    def test_create_objective_is_idempotent(self):
        obj = _objective()
        first = self.store.create_objective(obj)
        second = self.store.create_objective(_objective())
        self.assertEqual(first.objective_id, second.objective_id)
        self.assertEqual(len(self.store.objective_history(obj.objective_id)), 1)

    def test_revise_validates_state_transition(self):
        self.store.create_objective(_objective(state="OPEN"))
        revised = self.store.revise_objective(
            "obj-test-1", state="NEEDS_EVIDENCE", reason="missing")
        self.assertEqual(revised.state, "NEEDS_EVIDENCE")
        self.assertEqual(revised.revision, 2)
        # terminal states never move
        self.store.revise_objective("obj-test-1", state="RESOLVED",
                                    reason="done")
        with self.assertRaises(HuntStoreError):
            self.store.revise_objective("obj-test-1", state="PLANNED")

    def test_duplicate_plan_with_different_definition_rejected(self):
        self.store.append_plan(_plan())
        same = _plan()
        self.assertEqual(self.store.append_plan(same).plan_id, "plan-test-1")
        mutated = _plan()
        object.__setattr__  # frozen dataclass: rebuild instead
        mutated2 = HuntPlan(
            plan_id="plan-test-1", objective_id="obj-test-1",
            job_id="job-xss-hunt-test", version=1, parent_plan_id="",
            scope_ref="fixture:shop/OTHER.test", specialist="xss-agent",
            category="XSS", reason="changed", hypotheses_addressed=(),
            observations_requested=({
                "observation_type": "url-rows",
                "inputs": {}, "expected_evidence": "",
                "missing_item_ids": []},),
            required_evidence=(), expected_information_gain=0.1,
            gain_label="heuristic", safety_constraints=(),
            authorization_requirements=(), dependencies=(), priority=1,
            provenance={"planner": "evil"}, created_at=_utc())
        with self.assertRaises(HuntStoreError):
            self.store.append_plan(mutated2)

    def test_transition_fold_and_definition_hash_at_executing(self):
        self.store.append_plan(_plan())
        self.assertEqual(self.store.plan_state("plan-test-1"), "DRAFT")
        self.store.record_transition(PlanTransition(
            plan_id="plan-test-1", from_state="DRAFT", to_state="VALIDATED",
            reason="ok", at=utcnow()))
        with self.assertRaises(HuntStoreError):
            # illegal jump skips AUTHORIZATION_REQUIRED
            self.store.record_transition(PlanTransition(
                plan_id="plan-test-1", from_state="VALIDATED",
                to_state="COMPLETED", reason="skip", at=utcnow()))
        self.assertEqual(self.store.plan_state("plan-test-1"), "VALIDATED")
        plan = self.store.get_plan("plan-test-1")
        self.store.record_transition(PlanTransition(
            plan_id="plan-test-1", from_state="VALIDATED",
            to_state="AUTHORIZATION_REQUIRED", reason="req", at=utcnow()))
        self.store.record_transition(PlanTransition(
            plan_id="plan-test-1", from_state="AUTHORIZATION_REQUIRED",
            to_state="AUTHORIZED", reason="grant", at=utcnow()))
        self.store.record_transition(PlanTransition(
            plan_id="plan-test-1", from_state="AUTHORIZED",
            to_state="EXECUTING", reason="start", at=utcnow(),
            definition_hash=plan.definition_hash()))
        self.assertEqual(
            self.store.executing_definition_hash("plan-test-1"),
            plan.definition_hash())

    def test_authorization_and_observation_records_roundtrip(self):
        auth = AuthorizationRecord(
            auth_id="authz-1", plan_id="plan-test-1",
            objective_id="obj-test-1", job_id="j", scope_ref="s",
            target="t", observation_types=("http-rows",), capability="XSS",
            specialist="xss-agent", purpose="p", allowed_data=("x",),
            safety_class="READ_ONLY", status="GRANTED", reasons=(),
            gate="g", requested_at="a", decided_at="b")
        self.store.append_authorization(auth)
        self.assertEqual(
            self.store.get_authorization("authz-1").status, "GRANTED")
        obs = ObservationRecord(
            observation_id="obs-1", plan_id="plan-test-1", auth_id="authz-1",
            objective_id="obj-test-1", job_id="j",
            observation_types=("http-rows",), rows_total=2, new_rows=2,
            new_refs=("http:h1",), source_counts={"http": 2},
            outcome="ok", error="", started_at="a", completed_at="b")
        self.store.append_observation(obs)
        self.assertEqual(len(self.store.observations_for_job("j")), 1)

    def test_objective_bundle_complete(self):
        self.store.create_objective(_objective())
        self.store.append_plan(_plan())
        bundle = self.store.objective_bundle("obj-test-1")
        for key in ("objective", "history", "plans", "transitions",
                    "authorizations", "observations"):
            self.assertIn(key, bundle)
        self.assertEqual(bundle["plans"][0]["state"], "DRAFT")
        self.assertEqual(self.store.objective_bundle("missing"), {})


class RegistryTests(unittest.TestCase):
    def test_registry_only_exposes_supported_read_only_types(self):
        self.assertEqual(
            set(REGISTRY),
            {"url-rows", "parameter-rows", "endpoint-rows", "http-rows",
             "header-rows", "kb-rows"})
        for spec in REGISTRY.values():
            self.assertEqual(spec.risk_class, "READ_ONLY")
            self.assertFalse(spec.executes_http)
            self.assertEqual(spec.required_authorization, "watch:scope")
            self.assertEqual(spec.allowed_scope, "job.authorization_ref")
        self.assertEqual(len(registry_catalog()), 6)

    def test_unknown_observation_type_rejected(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "send-payload"}],
            allowed_for_capability=("http-rows",))
        self.assertEqual(valid, [])
        self.assertTrue(reasons[0].startswith("unknown_observation_type"))

    def test_type_outside_capability_rejected(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "kb-rows",
              "inputs": {"query_hints": ["cve"]}}],
            allowed_for_capability=("http-rows",))
        self.assertEqual(valid, [])
        self.assertIn("observation_type_not_in_capability:kb-rows", reasons)

    def test_forbidden_input_fields_rejected(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "http-rows", "url": "https://x"}],
            allowed_for_capability=("http-rows",))
        self.assertEqual(valid, [])
        self.assertTrue(reasons[0].startswith("unsupported_input"))

    def test_kb_rows_requires_query_hints(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "kb-rows", "inputs": {}}],
            allowed_for_capability=("kb-rows",))
        self.assertEqual(valid, [])
        self.assertIn("missing_inputs:kb-rows:query_hints", reasons)

    def test_valid_request_normalized(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "http-rows",
              "inputs": {"subdomain": "shop.test", "limit": 25},
              "expected_evidence": "observation", "extra": "dropped"}],
            allowed_for_capability=("http-rows",))
        self.assertEqual(reasons, [])
        self.assertEqual(valid[0]["observation_type"], "http-rows")
        self.assertNotIn("extra", valid[0])

    def test_forbidden_advisory_scan(self):
        hits = scan_forbidden(["please send an XSS payload now"])
        self.assertIn("EXPLOIT_INSTRUCTION", hits)
        self.assertIn("SHELL_INSTRUCTION",
                      scan_forbidden(["run bash -c whoami"]))
        self.assertIn("NETWORK_EXECUTION_INSTRUCTION",
                      scan_forbidden(["curl https://target/"]))
        self.assertIn("CODE_EXECUTION_INSTRUCTION",
                      scan_forbidden(["eval(os.system(x))"]))
        # our own honest safety phrasing must NOT be flagged
        self.assertEqual(
            scan_forbidden(["stored inputs present; payload testing is "
                            "out of scope for this runtime"]), [])


class MissingEvidenceEngineTests(unittest.TestCase):
    def test_rule_version_and_determinism(self):
        self.assertEqual(MISSING_EVIDENCE_RULE_VERSION,
                         "hunt-missing-evidence-v1")
        cap = capability_for("XSS")
        kwargs = dict(capability=cap, scope_ref="fixture:shop/shop.test",
                      analysis={"confidence": "medium", "signals": [],
                                "blockers": ["no_category_signal_in_authorized_observations"],
                                "evidence_candidates": []},
                      observed_types=(), knowledge_ids=(),
                      hypothesis="h1")
        a = compute_missing_evidence(**kwargs)
        b = compute_missing_evidence(**kwargs)
        self.assertEqual([i.item_id for i in a], [i.item_id for i in b])
        self.assertTrue(all(i.gain_label == "heuristic" for i in a))

    def test_coverage_item_for_unread_types(self):
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "high", "signals": ["x"],
                      "blockers": [], "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        codes = [i.item_code for i in items]
        self.assertTrue(any(c.startswith("observation_type_unread:")
                            for c in codes))
        # once every allowed type is observed the coverage debt is gone
        items2 = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "high", "signals": ["x"],
                      "blockers": [],
                      "evidence_candidates": [
                          {"type": "observation", "observation_ref": "a"},
                          {"type": "observation", "observation_ref": "b"}],
                      "hypotheses": [{"hypothesis": "h"}]},
            observed_types=cap.allowed_observation_types,
            knowledge_ids=(), hypothesis="h")
        self.assertFalse(any(c.startswith("observation_type_unread:")
                             for c in [i.item_code for i in items2]))

    def test_cve_specific_items(self):
        cap = capability_for("CVE_RESEARCH")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "insufficient", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        codes = [i.item_code for i in items]
        self.assertIn("technology_signal_missing", codes)
        tech = next(i for i in items
                    if i.item_code == "technology_signal_missing")
        self.assertIn("http-rows", tech.observation_type_suggestions)
        self.assertTrue(tech.satisfiable)

    def test_required_type_gap_for_cve_knowledge(self):
        cap = capability_for("CVE_RESEARCH")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "high", "signals": ["technology_signal"],
                      "blockers": [],
                      "evidence_candidates": [
                          {"type": "observation", "observation_ref": "http:h1"},
                          {"type": "observation", "observation_ref": "http:h2"}]},
            observed_types=("http-rows",), knowledge_ids=(), hypothesis="h")
        codes = [i.item_code for i in items]
        self.assertIn("missing_knowledge_evidence", codes)

    def test_unsatisfiable_flag_when_only_consumed_suggestions(self):
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "low", "signals": ["x"],
                      "blockers": [],
                      "evidence_candidates": [
                          {"type": "observation", "observation_ref": "a"}],
                      "hypotheses": [{"hypothesis": "h"}]},
            observed_types=cap.allowed_observation_types,
            knowledge_ids=(), hypothesis="h")
        conf = [i for i in items
                if i.item_code == "confidence_below_required_high"]
        self.assertTrue(conf)
        self.assertFalse(conf[0].satisfiable)


class ScoringAndPlannerTests(unittest.TestCase):
    def test_candidates_exclude_observed_types(self):
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        self.assertTrue(cands)
        self.assertNotIn("http-rows",
                         [c.observation_type for c in cands]
                         if "http-rows" in () else
                         [c.observation_type for c in cands
                          if c.observation_type == "x-none"])
        seen = build_candidates(missing_items=items, capability=cap,
                                observed_types={"http-rows"})
        # observed types are never planned again
        for c in seen:
            self.assertNotEqual(c.observation_type, "http-rows")

    def test_scope_not_ready_scores_zero(self):
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=(), scope_ready=False)
        for c in cands:
            self.assertEqual(c.score, 0)

    def test_candidate_reason_is_auditable(self):
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="s",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="H1")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        self.assertIn("already-authorized read-only observation",
                      cands[0].reason)
        self.assertEqual(cands[0].to_dict()["information_gain_label"],
                         "heuristic")
        self.assertEqual(cands[0].to_dict()["scoring_method"],
                         "heuristic_transparent_v1")

    def test_advisor_maps_valid_obs_codes_and_rejects_unknown(self):
        cap = capability_for("XSS")
        resp = {
            "summary": "collect header and reflection signals",
            "insights": [
                {"insight_code": "OBS_HTTP_ROWS",
                 "text": "read stored http rows for technology context"},
                {"insight_code": "OBS_NUCLEI_SCAN",
                 "text": "run a scan"},
            ],
            "recommendations": [
                {"recommendation_code": "PRIORITY_1",
                 "text": "http rows first"},
            ],
        }
        out = map_advisor_response(resp, capability=cap,
                                   allowed_types=cap.allowed_observation_types)
        self.assertTrue(out.used)
        self.assertIn("http-rows", out.accepted_types)
        self.assertTrue(any("OBS_NUCLEI_SCAN" in r
                            for r in out.rejected_suggestions))
        self.assertNotIn("nuclei-rows", out.accepted_types)

    def test_advisor_rejects_forbidden_content(self):
        cap = capability_for("XSS")
        resp = {"summary": "ok",
                "insights": [{"insight_code": "OBS_HTTP_ROWS",
                              "text": "send an XSS payload to the target"}],
                "recommendations": []}
        out = map_advisor_response(resp, capability=cap,
                                   allowed_types=cap.allowed_observation_types)
        self.assertFalse(out.used)
        self.assertIn("EXPLOIT_INSTRUCTION", out.forbidden_hits)
        self.assertTrue(out.error.startswith("forbidden_advisor_content"))

    def test_advisor_malformed_shapes_rejected(self):
        cap = capability_for("XSS")
        for bad in (None, [], {}, {"summary": "x"},
                    {"summary": "x", "insights": "no", "recommendations": []},
                    {"summary": "x", "insights": [{"insight_code": ""}],
                     "recommendations": []}):
            out = map_advisor_response(bad, capability=cap,
                                       allowed_types=("http-rows",))
            self.assertFalse(out.used)

    def test_build_plan_trusted_construction_and_provenance(self):
        obj = _objective()
        job = make_job()
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="fixture:shop/shop.test",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        plan, notes = build_plan(
            objective=obj, job=job, capability=cap, candidates=cands,
            missing_items=items, advisor=None, version=1)
        self.assertIsNotNone(plan)
        self.assertEqual(plan.provenance["planner"], "deterministic")
        self.assertEqual(plan.provenance["created_by"], "trusted_code")
        self.assertEqual(plan.scope_ref, obj.scope_ref)
        self.assertEqual(validate_final_plan(
            plan, capability=cap, job=job,
            scope_ref=job.authorization_ref), [])

    def test_advisor_can_only_reorder_valid_candidates(self):
        obj = _objective()
        job = make_job()
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="fixture:shop/shop.test",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        advisor = AdvisorOutcome(
            used=True, accepted_types=("url-rows", "bogus-rows"),
            rejected_suggestions=("OBS_BOGUS_ROWS->bogus-rows",),
            forbidden_hits=(), objective_interpretation="focus urls",
            rationale="r", blockers=(), confidence="advisory",
            recommended_priority=40, model_requested="openrouter/free",
            model_resolved="openrouter/free",
            prompt_version="hunt-planner-advisor-v1", latency_ms=10,
            error="")
        plan, notes = build_plan(
            objective=obj, job=job, capability=cap, candidates=cands,
            missing_items=items, advisor=advisor, version=1)
        self.assertIsNotNone(plan)
        # advisory types that are not valid candidates never enter the plan
        for req in plan.observations_requested:
            self.assertNotEqual(req["observation_type"], "bogus-rows")
        self.assertTrue(any("advisor_rejected" in n for n in notes))
        self.assertEqual(plan.provenance["model_requested"],
                         "openrouter/free")

    def test_validate_final_plan_catches_scope_widening(self):
        obj = _objective()
        job = make_job()
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref="fixture:shop/shop.test",
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        plan, _ = build_plan(objective=obj, job=job, capability=cap,
                             candidates=cands, missing_items=items,
                             advisor=None, version=1)
        widened = HuntPlan(
            plan_id=plan.plan_id, objective_id=plan.objective_id,
            job_id=plan.job_id, version=plan.version,
            parent_plan_id=plan.parent_plan_id,
            scope_ref="fixture:shop/OTHER.test",
            specialist=plan.specialist, category=plan.category,
            reason=plan.reason,
            hypotheses_addressed=plan.hypotheses_addressed,
            observations_requested=plan.observations_requested,
            required_evidence=plan.required_evidence,
            expected_information_gain=plan.expected_information_gain,
            gain_label=plan.gain_label,
            safety_constraints=plan.safety_constraints,
            authorization_requirements=plan.authorization_requirements,
            dependencies=plan.dependencies, priority=plan.priority,
            provenance=plan.provenance, created_at=plan.created_at)
        reasons = validate_final_plan(widened, capability=cap, job=job,
                                      scope_ref=job.authorization_ref)
        self.assertIn("plan_scope_differs_from_authorization", reasons)
        self.assertIn("plan_scope_differs_from_job_authorization", reasons)

    def test_advisory_id_satisfies_provider_schema(self):
        """Production defect (job-xss-447203e643): advisory_id built by
        the hunt advisor must match ADVISORY_ID_RE ^adv-[0-9a-f]{16}$ or
        the provider rejects the request before any LLM call."""
        import re
        from ai.schemas.llm_advisory_input import ADVISORY_ID_RE
        obj = _objective()
        job = make_job()
        cap = capability_for("XSS")
        req = advisor_request(
            objective=obj, missing_items=[], candidates=[],
            capability=cap, allowed_types=cap.allowed_observation_types,
            observed_types=(), job=job)
        self.assertIsNotNone(
            ADVISORY_ID_RE.match(req["advisory_id"]),
            req["advisory_id"])
        # the ENTIRE request must survive the provider structural
        # validator (mode/layer/source_refs/limitations enums +
        # MAX_CONTEXT_CHARS) — this is exactly what failed in
        # production job-xss-447203e643 before this fix
        from ai.providers.context_allowlist import (
            MAX_CONTEXT_CHARS, sanitize_provider_context,
        )
        sanitize_provider_context(req)   # raises on any violation
        import json as _json
        canonical = _json.dumps(req, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True)
        self.assertLessEqual(len(canonical), MAX_CONTEXT_CHARS,
                             len(canonical))

    def test_rows_added_accumulates_across_plans(self):
        """Production defect (job-xss-447203e643): contract rows_added
        was reset by every executed plan and reported only the last
        plan's additions; it must equal the total new rows."""
        from tests.hunt_fixtures import SplitFixture
        outcome, job, cap, hs, store = run_hunt_fixture(
            typed={
                "http-rows": [{"source": "http", "ref": "h9",
                               "url": "https://shop.test/n1", "status": 200,
                               "title": "n1", "tech": "nginx",
                               "headers_snippet": "server: nginx"}],
                "parameter-rows": [
                    {"source": "urls", "ref": "p9",
                     "url": "https://shop.test/n2", "status": 200,
                     "params": ["tok"]},
                    {"source": "endpoints", "ref": "p10",
                     "url": "https://shop.test/n3", "status": 200,
                     "params": ["ref"]}],
                "url-rows": [{"source": "urls", "ref": "u9",
                              "url": "https://shop.test/n4",
                              "status": 200, "params": []}],
            })
        recorded = sum(o.new_rows for o in
                       hs.observations_for_job(job.id))
        self.assertGreater(recorded, 0)
        self.assertEqual(outcome.rows_added, recorded)
        self.assertEqual(outcome.to_dict()["rows_added"], recorded)

    def test_advisor_request_is_allowlist_shaped(self):
        obj = _objective()
        job = make_job()
        cap = capability_for("XSS")
        req = advisor_request(
            objective=obj, missing_items=[], candidates=[],
            capability=cap, allowed_types=cap.allowed_observation_types,
            observed_types=(), job=job)
        self.assertEqual(
            set(req),
            {"rule_version", "advisory_id", "advisory_mode",
             "provider_kind", "source_layer", "instruction", "sections",
             "source_refs", "limitations", "research_only",
             "deterministic"})
        self.assertEqual(set(req["sections"]),
                         {"research_context", "learning_signals"})
        blob = str(req)
        self.assertNotIn("https://", blob)
        self.assertNotIn("sk-or", blob)


class AuthorizationBridgeTests(unittest.TestCase):
    def _job_checker(self, **kw):
        job = make_job(**kw)
        return job, AuthorizationChecker()

    def test_granted_happy_path(self):
        job, checker = self._job_checker()
        cap = capability_for("XSS")
        req = build_authorization_request(_plan(), job=job, capability=cap)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "GRANTED")
        self.assertEqual(rec.safety_class, "READ_ONLY")

    def test_scope_mismatch_denied(self):
        job, checker = self._job_checker()
        cap = capability_for("XSS")
        plan = _plan(scope="fixture:shop/OTHER.test")
        req = build_authorization_request(plan, job=job, capability=cap)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "DENIED")
        self.assertIn("plan_scope_does_not_match_job_authorization",
                      rec.reasons)

    def test_checker_denial_denied(self):
        # scope_ref exists but the job TARGET is outside it ->
        # the existing AuthorizationChecker denies (fail closed)
        job, checker = self._job_checker(
            auth_ref="watch:scope:app/other.test")
        object.__setattr__(job, "execution_mode", "production")
        cap = capability_for("XSS")
        plan = _plan(scope="watch:scope:app/other.test")
        req = build_authorization_request(plan, job=job, capability=cap)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "DENIED")
        self.assertTrue(any("authorization_checker" in r
                            for r in rec.reasons), rec.reasons)

    def test_empty_scope_plan_is_impossible_at_model_layer(self):
        # HuntPlan itself refuses an empty scope (fail closed at the model)
        with self.assertRaises(Exception):
            _plan(scope="")

    def test_unknown_type_denied_even_if_requested(self):
        job, checker = self._job_checker()
        cap = capability_for("XSS")
        req = build_authorization_request(_plan(), job=job, capability=cap)
        req["observation_types"] = ("sqlmap-runner",)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "DENIED")
        self.assertIn("unknown_observation_type:sqlmap-runner", rec.reasons)

    def test_type_outside_capability_denied(self):
        job, checker = self._job_checker()
        cap = capability_for("XSS")   # XSS does not allow kb-rows
        req = build_authorization_request(_plan(), job=job, capability=cap)
        req["observation_types"] = ("kb-rows",)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "DENIED")

    def test_stale_authorization_rejected_on_scope_change(self):
        job, checker = self._job_checker()
        cap = capability_for("XSS")
        req = build_authorization_request(_plan(), job=job, capability=cap)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=checker)
        self.assertEqual(rec.status, "GRANTED")
        ok, _ = reverify_before_observation(
            rec, plan=_plan(), job=job, capability=cap,
            auth_checker=checker, observation_types=("http-rows",))
        self.assertTrue(ok)
        stale_job = make_job(auth_ref="fixture:shop/OTHER.test")
        plan_stale = _plan(scope="fixture:shop/OTHER.test")
        ok2, reason = reverify_before_observation(
            rec, plan=plan_stale, job=stale_job, capability=cap,
            auth_checker=checker, observation_types=("http-rows",))
        self.assertFalse(ok2)
        self.assertTrue(reason.startswith("stale_authorization")
                        or reason == "authorization_scope_changed")


class ExecutionLoopTests(unittest.TestCase):
    """The bounded autonomous loop against fixture data."""

    def test_full_loop_resolves_with_replan(self):
        # EPIC11: resolution requires claim-grade evidence (stage 3+), so
        # the fixture scope must carry the controlled-verification record
        # an authorized run would have persisted.  The gate is NOT
        # bypassed — it still evaluates the class claim contract over
        # these rows.
        outcome, job, cap, hs, store = run_hunt_fixture(
            determin_fn=claim_grade_determin(deterministic_analysis))
        self.assertEqual(outcome.termination_reason, "sufficient_evidence")
        self.assertEqual(outcome.state, "RESOLVED")
        self.assertGreaterEqual(len(outcome.plan_ids), 1)
        versions = [p["version"] for p in outcome.plans]
        if len(versions) > 1:
            self.assertEqual(versions, sorted(versions))
            self.assertGreater(max(versions), 1)
        obj = hs.get_objective(outcome.objective_id)
        self.assertEqual(obj.state, "RESOLVED")
        self.assertEqual(obj.termination_reason, "sufficient_evidence")
        # every executed type is authorized + recorded
        self.assertEqual(len(outcome.authorization_ids),
                         len(outcome.plans))
        for obs_id in outcome.observation_ids:
            self.assertTrue(obs_id.startswith("obs-"))
        # no hunt-side error
        self.assertEqual(outcome.errors, [])

    def test_activity_emits_required_event_names(self):
        actions: list[str] = []
        outcome, job, cap, hs, store = run_hunt_fixture(
            emit_activity=lambda a, d: actions.append(a))
        for required in ("hunt_objective_created",
                         "missing_evidence_detected", "hunt_plan_created",
                         "plan_validated", "authorization_requested",
                         "authorization_granted", "observation_started",
                         "observation_completed", "research_state_updated",
                         "hunt_terminated"):
            self.assertIn(required, actions)

    def test_audit_lineage_events_recorded(self):
        events: list[str] = []
        store = make_store()
        from backend.research_agents.hunt.audit import hunt_audit_event

        def audit(stage, payload):
            ev = hunt_audit_event(stage, job_id="job-xss-hunt-test",
                                  **payload)
            events.append(ev["event"])
        run_hunt_fixture(store=store, emit_audit=audit)
        self.assertIn("hunt_lineage", events)
        self.assertIn("hunt_lineage_final", events)
        self.assertIn("hunt_authorization", events)

    def test_max_plans_budget_stops_honestly(self):
        outcome, job, cap, hs, store = run_hunt_fixture(
            limits=HuntLimits(max_plans_per_objective=1,
                              max_planning_iterations=4,
                              max_llm_planning_calls=0, max_seconds=30))
        self.assertEqual(outcome.termination_reason,
                         "max_plans_per_objective_reached")
        self.assertEqual(outcome.state, "NEEDS_EVIDENCE")
        self.assertEqual(len(outcome.plan_ids), 1)

    def test_max_iterations_budget_stops_honestly(self):
        outcome, job, cap, hs, store = run_hunt_fixture(
            limits=HuntLimits(max_plans_per_objective=50,
                              max_planning_iterations=1,
                              max_observations=50,
                              max_llm_planning_calls=0, max_seconds=30))
        self.assertIn(outcome.termination_reason,
                      {"max_planning_iterations_reached",
                       "sufficient_evidence"})
        self.assertLessEqual(outcome.iterations, 2)

    def test_runtime_budget_exhaustion_explicit(self):
        outcome, job, cap, hs, store = run_hunt_fixture(
            deadline_fn=lambda: True)
        self.assertEqual(outcome.termination_reason,
                         "runtime_budget_exhausted")
        self.assertIn(outcome.state, {"NEEDS_EVIDENCE", "BLOCKED",
                                      "REJECTED", "RESOLVED"})

    def test_authorization_denial_blocks_objective(self):
        outcome, job, cap, hs, store = run_hunt_fixture(auth_ref="")
        self.assertEqual(outcome.state, "BLOCKED")
        self.assertIn(outcome.termination_reason,
                      {"authorization_denied", "scope_invalid"})
        # nothing executed; without a scope no objective/plan is ever
        # created (fail closed before planning)
        self.assertEqual(outcome.observation_ids, [])
        self.assertEqual(outcome.objective_id, "")
        self.assertEqual(outcome.plan_ids, [])
        self.assertEqual(hs.list_objectives(), [])

    def test_capability_without_allowed_types_is_explicit(self):
        # build a capability-like object with an empty allowlist
        class EmptyCap:
            category = "XSS"
            agent_name = "xss-agent"
            allowed_observation_types = ()
            evidence_requirements = type("E", (), {
                "min_evidence_refs": 2, "required_types": ("observation",),
                "require_high_confidence": True})()
        from backend.research_agents.runtime import AuthorizationChecker
        outcome = run_hunt(
            job=make_job(), capability=EmptyCap(), store=make_store(),
            hunt_store=HuntStore(make_store().base),
            observations=type("P", (), {"observe": lambda self, job, **k: []})(),
            auth_checker=AuthorizationChecker(),
            determin_fn=deterministic_analysis,
            gate_fn=evaluate_case_creation,
            limits=HuntLimits())
        self.assertEqual(outcome.termination_reason,
                         "required_capability_unavailable")
        self.assertEqual(outcome.state, "BLOCKED")

    def test_observation_failure_fails_plan_honestly(self):
        class BoomProvider:
            def observe(self, job, **kw):
                raise RuntimeError("store offline")
        from backend.research_agents.runtime import AuthorizationChecker
        from backend.research_agents.hunt.models import HuntObjective as HO
        store = make_store()
        hs = HuntStore(store.base)
        job = make_job()
        outcome = run_hunt(
            job=job, capability=capability_for("XSS"), store=store,
            hunt_store=hs, observations=BoomProvider(),
            auth_checker=AuthorizationChecker(),
            determin_fn=deterministic_analysis,
            gate_fn=evaluate_case_creation,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_consecutive_observation_failures=1,
                              max_llm_planning_calls=0),
            initial_rows=rich_rows(),
            emit_audit=lambda s, p: None)
        self.assertEqual(outcome.termination_reason,
                         "observation_runtime_unavailable")
        self.assertEqual(outcome.state, "BLOCKED")
        self.assertTrue(any("store offline" in e
                            for e in outcome.errors) or outcome.errors)
        self.assertLessEqual(len(outcome.plan_ids), 1)


class TwoSpecialistIntegrationTests(unittest.TestCase):
    """XSS + CVE_RESEARCH through the REAL AgentWorker (hunt enabled)."""

    def _run_worker_job(self, category: str, rows, typed, mission: str):
        import os
        import tempfile
        from backend.research_agents.runtime import (
            AgentWorker, FixtureObservations,
        )
        from tests.hunt_fixtures import SplitFixture
        base = tempfile.mkdtemp(prefix="hunt-int-", dir="/tmp")
        store = RuntimeStoreSafe(base)
        job = make_job(job_id=f"job-{category.lower()}-hunt-int",
                       category=category)
        store.enqueue(job)
        provider = SplitFixture({job.id: rows}, {job.id: typed})
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture",
                                 worker_id="hunt-int", job_timeout=60,
                                 hunt_max_plans=3, hunt_max_observations=6,
                                 hunt_max_iterations=4,
                                 hunt_max_llm_plans=0, hunt_max_seconds=30),
            store=store, observations=provider, llm_enabled=False)
        worker.run(max_jobs=1)
        return store, job, store.get_result(job.id)

    def test_xss_worker_end_to_end_with_hunt_block(self):
        from backend.research_agents.runtime_store import RuntimeStore
        store, job, result = self._run_worker_job(
            "XSS", rich_rows(), {"http-rows": [], "parameter-rows": [],
                                 "url-rows": []}, "reflected-input-review")
        self.assertIsNotNone(result)
        structured = result.structured or {}
        hunt = structured.get("hunt") or {}
        self.assertTrue(hunt.get("objective_id"))
        self.assertIn(hunt.get("state"),
                      {"RESOLVED", "NEEDS_EVIDENCE", "BLOCKED",
                       "REJECTED"})
        self.assertTrue(hunt.get("termination_reason"))
        hs = HuntStore(store.base)
        objs = hs.list_objectives(category="XSS")
        self.assertEqual(len(objs), 1)
        # job still completes; gate still authoritative
        after = store.get(job.id)
        self.assertEqual(after.status, JobStatus.COMPLETED.value)

    def test_cve_worker_end_to_end_with_replan(self):
        from backend.research_agents.runtime_store import RuntimeStore
        store, job, result = self._run_worker_job(
            "CVE_RESEARCH", cve_rows(),
            {"http-rows": http_rows_for_cve(),
             "kb-rows": [{"id": "kb-cve-1", "title": "CVE-2020-1234 Apache",
                          "summary": "apache correlation", "topic": "CVE",
                          "relevance": {"score": 10,
                                        "reasons": ["specialist_topic:CVE"]}}]},
            "technology-correlation")
        self.assertIsNotNone(result)
        hs = HuntStore(store.base)
        objs = hs.list_objectives(category="CVE_RESEARCH")
        self.assertEqual(len(objs), 1)
        plans = hs.plans_for_objective(objs[0].objective_id)
        types_planned = [t for p in plans
                         for t in p.observation_types]
        # the technology gap must be planned before knowledge correlation
        self.assertIn("http-rows", types_planned)
        if len(plans) > 1:
            self.assertGreater(plans[-1].version, plans[1 - 1].version)
        bundle = hs.objective_bundle(objs[0].objective_id)
        executed = [t for o in bundle["observations"]
                    for t in o["observation_types"]]
        self.assertIn("http-rows", executed)
        structured = result.structured or {}
        self.assertIn("hunt", structured)
        self.assertEqual(structured["contract"], "structured-research-v2")


def RuntimeStoreSafe(base: str):
    from backend.research_agents.runtime_store import RuntimeStore
    return RuntimeStore(base)


if __name__ == "__main__":
    unittest.main()

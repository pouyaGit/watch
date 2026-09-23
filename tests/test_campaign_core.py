"""AUTONOMOUS SECURITY CAMPAIGN ORCHESTRATOR v1 — core tests.

Covers Phases 1-7 + 9/15 models: campaign/objective state machines,
mandatory scope, dependencies + cycle rejection, deterministic
prioritization with reasons, capability-aware selection, cumulative
budget, R51-bounded advisor request, strict advisor response
validation, cross-objective context provenance, and audit lineage.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from tests.campaign_fixtures import (  # noqa: E402
    SCOPE,
    add_obj,
    advisor_valid,
    make_campaign,
    make_dependency,
    make_stores,
    read_memory_rows,
    run_campaign,
)

from backend.research_agents.campaign import (  # noqa: E402
    Campaign,
    CampaignBudget,
    CampaignObjective,
    CampaignStateError,
    CampaignStoreError,
    CampaignScopeError as ScopeErr,
    CampaignScopeError,
    DependencyCycleError,
    BudgetExhausted,
    advisor_request,
    assert_acyclic,
    map_advisor_response,
    prioritize,
    resolve_all,
    resolve_dependencies,
    select_specialist,
    validate_scope_ref,
    execute_campaign,
)
from backend.research_agents.campaign.advisor import (  # noqa: E402
    apply_advisory,
)
from backend.research_agents.campaign import models as cmodels  # noqa: E402
from backend.research_agents.campaign.audit import (  # noqa: E402
    campaign_event,
    lineage_row,
)
from backend.research_agents.campaign.context import (  # noqa: E402
    extract_context_items,
    record_context,
)
from backend.research_agents.capabilities import capability_for  # noqa: E402
from ai.providers.context_allowlist import (  # noqa: E402
    MAX_CONTEXT_CHARS,
    sanitize_provider_context,
)


def _obj(oid: str, *, campaign_id: str = "cmp-x", priority: int = 50,
         category: str = "XSS", deps=None, state: str = "READY",
         scope: str = SCOPE) -> CampaignObjective:
    return CampaignObjective(
        objective_id=oid, campaign_id=campaign_id, category=category,
        scope_ref=scope, research_question=f"question for {oid} " + "x" * 60,
        hypothesis="h " + "y" * 60, priority=priority, state=state,
        dependencies=list(deps or []))


class TestCampaignModel(unittest.TestCase):
    """Phase 1: campaign model + mandatory scope + state machine."""

    def test_campaign_without_scope_is_impossible(self):
        with self.assertRaises(ScopeErr):
            Campaign(campaign_id="cmp-none", program="p", scope_ref="",
                     campaign_objective="o")

    def test_scope_ref_requires_authorized_prefix(self):
        self.assertEqual(validate_scope_ref(SCOPE), SCOPE)
        self.assertEqual(
            validate_scope_ref("watch:scope:dell/www.dell.com"),
            "watch:scope:dell/www.dell.com")
        for bad in ("", "https://evil.example", "scope:x", "   "):
            with self.assertRaises(CampaignScopeError):
                validate_scope_ref(bad)

    def test_campaign_has_every_required_field(self):
        camp = Campaign(campaign_id="cmp-f", program="p", scope_ref=SCOPE,
                        campaign_objective="q",
                        participating_specialists=("xss-agent",),
                        budget={"x": 1}, limits={"max_objectives": 3})
        d = camp.to_dict()
        for field in ("campaign_id", "program", "scope_ref",
                      "target_context", "campaign_objective",
                      "participating_specialists", "priority", "state",
                      "budget", "limits", "created_at", "updated_at",
                      "provenance"):
            self.assertIn(field, d)

    def test_all_ten_plus_states_declared(self):
        expected = {"DRAFT", "READY", "RUNNING", "PAUSED", "WAITING",
                    "COMPLETED", "BLOCKED", "CANCELLED", "EXPIRED",
                    "FAILED", "BUDGET_EXHAUSTED"}
        self.assertTrue(expected.issubset(set(cmodels.CAMPAIGN_STATES)),
                        set(cmodels.CAMPAIGN_STATES))
        expected_obj = {"QUEUED", "READY", "RUNNING", "WAITING",
                        "BLOCKED", "RESOLVED", "REJECTED", "EXPIRED",
                        "FAILED", "CANCELLED"}
        self.assertTrue(expected_obj.issubset(
            set(cmodels.OBJECTIVE_STATES)), set(cmodels.OBJECTIVE_STATES))

    def test_invalid_transitions_rejected(self):
        camp = Campaign(campaign_id="cmp-t", program="p", scope_ref=SCOPE,
                        campaign_objective="q")
        with self.assertRaises(CampaignStateError):
            camp.transition("COMPLETED")            # DRAFT -> COMPLETED
        with self.assertRaises(CampaignStateError):
            camp.transition("RUNNING")              # DRAFT -> RUNNING
        obj = _obj("obj-t", state="QUEUED")
        with self.assertRaises(CampaignStateError):
            obj.transition("RESOLVED")              # QUEUED -> RESOLVED
        obj = _obj("obj-r", state="RESOLVED")
        with self.assertRaises(CampaignStateError):
            obj.transition("RUNNING")               # terminal is immutable

    def test_terminal_states_are_immutable(self):
        camp = Campaign(campaign_id="cmp-t2", program="p", scope_ref=SCOPE,
                        campaign_objective="q", state="CANCELLED")
        with self.assertRaises(CampaignStateError):
            camp.transition("RUNNING")
        with self.assertRaises(CampaignStateError):
            camp.transition("COMPLETED")

    def test_validate_transition_helpers(self):
        cmodels.validate_campaign_transition("READY", "RUNNING")
        with self.assertRaises(CampaignStateError):
            cmodels.validate_campaign_transition("COMPLETED", "RUNNING")
        cmodels.validate_objective_transition("READY", "RUNNING")
        with self.assertRaises(CampaignStateError):
            cmodels.validate_objective_transition("RESOLVED", "RUNNING")


class TestObjectiveModel(unittest.TestCase):
    """Phase 2: objectives — create, scope enforcement, duplicates."""

    def test_add_objective_requires_matching_scope(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        bad = _obj("obj-bad", campaign_id=camp.campaign_id,
                   scope="fixture:other/else.test")
        with self.assertRaises(CampaignStoreError):
            cs.add_objective(bad, camp)

    def test_duplicate_objective_id_rejected(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp)
        with self.assertRaises(CampaignStoreError):
            cs.add_objective(obj, camp)

    def test_max_objectives_budget_enforced_at_add(self):
        _, cs = make_stores()
        camp = make_campaign(cs, limits={"max_objectives": 1})
        add_obj(cs, camp)
        with self.assertRaises(CampaignStoreError):
            add_obj(cs, camp)

    def test_objective_roundtrip(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        dep_obj = add_obj(cs, camp, question="prereq question")
        dep = make_dependency("later", dep_obj.objective_id)
        obj = _obj("later", campaign_id=camp.campaign_id, deps=[dep])
        stored = cs.add_objective(obj, camp)
        loaded = cs.get_objective(stored.objective_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded.dependencies), 1)
        self.assertEqual(loaded.dependencies[0].depends_on,
                         dep_obj.objective_id)
        self.assertEqual(loaded.dependencies[0].kind, "REQUIRED")


class TestDependencies(unittest.TestCase):
    """Phase 3: bounded dependencies + cycle rejection before execution."""

    def test_waiting_until_prereq_resolves(self):
        a = _obj("obj-a", state="RUNNING")
        b = _obj("obj-b", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-b", "obj-a")])
        by_id = {"obj-a": a, "obj-b": b}
        res_b = resolve_dependencies(b, by_id)
        self.assertEqual(res_b["effect"], "waiting")
        self.assertFalse(res_b["ready"])
        a.state = "RESOLVED"
        res_b = resolve_dependencies(b, by_id)
        self.assertEqual(res_b["effect"], "satisfied")
        self.assertTrue(res_b["ready"])

    def test_rejected_prereq_also_satisfies_required(self):
        # a REJECTED prereq is a concluded research result -> dependent runs
        a = _obj("obj-a2", state="REJECTED")
        b = _obj("obj-b2", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-b2", "obj-a2")])
        res = resolve_dependencies(b, {"obj-a2": a, "obj-b2": b})
        self.assertTrue(res["ready"], res)

    def test_permanently_blocked_prereq_blocks_required(self):
        for bad_state in ("BLOCKED", "FAILED", "EXPIRED", "CANCELLED"):
            a = _obj(f"obj-p-{bad_state}", state=bad_state)
            b = _obj(f"obj-q-{bad_state}", state="QUEUED",
                     deps=[DependencyCycleSafe.dep(
                         f"obj-q-{bad_state}", f"obj-p-{bad_state}")])
            res = resolve_dependencies(
                b, {a.objective_id: a, b.objective_id: b})
            self.assertEqual(res["effect"], "permanently_blocked",
                             bad_state)
            self.assertFalse(res["ready"])

    def test_optional_and_informational_never_block(self):
        a = _obj("obj-o", state="BLOCKED")
        for kind in ("OPTIONAL", "INFORMATIONAL"):
            b = _obj(f"obj-{kind}", state="QUEUED",
                     deps=[DependencyCycleSafe.dep(
                         f"obj-{kind}", "obj-o", kind)])
            res = resolve_dependencies(
                b, {"obj-o": a, f"obj-{kind}": b})
            self.assertTrue(res["ready"], kind)
            self.assertEqual(res["effect"], "informed")

    def test_missing_prereq_fails_closed(self):
        b = _obj("obj-m", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-m", "obj-ghost")])
        res = resolve_dependencies(b, {"obj-m": b})
        self.assertEqual(res["effect"], "permanently_blocked")
        self.assertFalse(res["ready"])

    def test_cycle_detection_before_execution(self):
        a = _obj("obj-ca", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-ca", "obj-cb")])
        b = _obj("obj-cb", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-cb", "obj-ca")])
        with self.assertRaises(DependencyCycleError):
            assert_acyclic([a, b])
        with self.assertRaises(DependencyCycleError):
            resolve_all([a, b])

    def test_store_rejects_cycle_on_add(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp)
        b = _obj("obj-cyc", campaign_id=camp.campaign_id,
                 deps=[make_dependency("obj-cyc", a.objective_id)])
        cs.add_objective(b, camp)
        # now make A depend on B (creates A -> B -> A) via save_objective
        a.dependencies = [make_dependency(a.objective_id,
                                          b.objective_id)]
        with self.assertRaises((CampaignStoreError, DependencyCycleError)):
            cs.save_objective(a)

    def test_resolve_all_is_order_independent(self):
        a = _obj("obj-r1", state="RESOLVED")
        b = _obj("obj-r2", state="QUEUED",
                 deps=[DependencyCycleSafe.dep("obj-r2", "obj-r1")])
        first = resolve_all([a, b])["obj-r2"]["ready"]
        second = resolve_all([b, a])["obj-r2"]["ready"]
        self.assertTrue(first)
        self.assertEqual(first, second)


class DependencyCycleSafe:
    @staticmethod
    def dep(dependent: str, prereq: str, kind: str = "REQUIRED"):
        from backend.research_agents.campaign.models import Dependency
        return Dependency(objective_id=dependent, depends_on=prereq,
                          kind=kind)


class TestPrioritizer(unittest.TestCase):
    """Phase 4: deterministic ordering, reasons, heuristic label."""

    def _order(self, objs, *, specialist_available=None, attempts=None):
        deps = resolve_all(objs)
        return prioritize(
            objs,
            dep_results=deps,
            missing_by_objective={o.objective_id: [] for o in objs},
            previous_research={o.objective_id: {"count": 0,
                                                "confidence": ""}
                               for o in objs},
            specialist_available=specialist_available
            or {o.category: True for o in objs},
            attempts=attempts or {},
            now_iso=cmodels.utcnow(),
            budget_remaining={"observations": 9},
            risk_class={o.objective_id: "medium" for o in objs},
            scope_relevance={o.objective_id: 1.0 for o in objs},
        )

    def test_priority_orders_deterministically(self):
        low = _obj("obj-low", priority=20)
        high = _obj("obj-high", priority=80)
        out = self._order([low, high])
        self.assertEqual(out.order[0], "obj-high")
        self.assertEqual(out.order, ["obj-high", "obj-low"])
        again = self._order([high, low])
        self.assertEqual(out.order, again.order)

    def test_every_ranked_objective_carries_reasons(self):
        out = self._order([_obj("obj-r-a", priority=30),
                           _obj("obj-r-b", priority=60)])
        for ranked in out.ordered:
            self.assertTrue(ranked.reasons, ranked)
            self.assertTrue(all(isinstance(x, str) and x
                                for x in ranked.reasons))
        self.assertTrue(out.ordered[0].reasons)

    def test_score_label_is_heuristic_and_not_optimal(self):
        out = self._order([_obj("obj-h", priority=50)])
        self.assertIn("heuristic", out.scoring_method)
        self.assertNotIn("optimal", out.scoring_method.lower())
        self.assertNotIn("mathematical", out.scoring_method.lower())
        self.assertIn("heuristic", out.version)

    def test_unavailable_specialist_excluded_with_reason(self):
        out = self._order([_obj("obj-x", priority=90, category="XSS")],
                          specialist_available={"XSS": False})
        self.assertEqual(out.order, [])
        self.assertTrue(out.excluded)
        self.assertIn("obj-x", out.excluded[0]["objective_id"])
        self.assertTrue(out.excluded[0]["reason"])

    def test_attempts_penalize_but_do_not_drop(self):
        out1 = self._order([_obj("obj-att", priority=50)],
                           attempts={"obj-att": 0})
        out2 = self._order([_obj("obj-att", priority=50)],
                           attempts={"obj-att": 3})
        self.assertIn("obj-att", out1.order)
        self.assertIn("obj-att", out2.order)
        self.assertGreaterEqual(out1.ordered[0].score,
                                out2.ordered[0].score)

    def test_llm_is_never_the_sole_orderer(self):
        # the deterministic call has no advisor input at all; an LLM can
        # only be consulted by the executor AFTER this ordering exists.
        out = self._order([_obj("obj-d1", priority=10),
                           _obj("obj-d2", priority=90)])
        self.assertEqual(out.order, ["obj-d2", "obj-d1"])
        self.assertEqual(out.scoring_method, "heuristic_transparent_v1")


class TestSelector(unittest.TestCase):
    """Phase 6: capability-aware selection; no invented specialists."""

    def test_xss_objective_gets_xss_capability_agent(self):
        sel = select_specialist(_obj("obj-sx", category="XSS"))
        self.assertTrue(sel.selected)
        self.assertEqual(sel.agent_name,
                         capability_for("XSS").agent_name)
        self.assertTrue(sel.reason)

    def test_cve_objective_gets_cve_agent(self):
        sel = select_specialist(_obj("obj-sc", category="CVE_RESEARCH"))
        self.assertTrue(sel.selected)
        self.assertEqual(sel.agent_name,
                         capability_for("CVE_RESEARCH").agent_name)

    def test_unrelated_declared_specialist_refused(self):
        obj = _obj("obj-sm", category="XSS")
        obj.specialist = capability_for("CVE_RESEARCH").agent_name
        sel = select_specialist(obj)
        self.assertFalse(sel.selected)
        self.assertTrue(sel.reason)

    def test_unknown_category_fails_closed(self):
        sel = select_specialist(_obj("obj-sn", category="NOT_A_SKILL"))
        self.assertFalse(sel.selected)
        self.assertTrue(sel.reason)

    def test_declared_matching_specialist_accepted(self):
        obj = _obj("obj-sok", category="XSS")
        obj.specialist = capability_for("XSS").agent_name
        sel = select_specialist(obj)
        self.assertTrue(sel.selected)
        self.assertEqual(sel.agent_name, obj.specialist)


class TestBudget(unittest.TestCase):
    """Phase 7: cumulative budget, auditable before/after, exhaustion."""

    def test_consumption_is_cumulative_never_per_objective(self):
        _, cs = make_stores()
        camp = make_campaign(cs, limits={"max_observations": 10})
        budget = CampaignBudget(cs, camp)
        budget.consume("observations", 3, reason="objective A",
                       objective_id="obj-a")
        budget.consume("observations", 4, reason="objective B",
                       objective_id="obj-b")
        report = budget.report()
        self.assertEqual(report.used["observations"], 7)
        self.assertEqual(report.remaining["observations"], 3)

    def test_ledger_records_before_and_after(self):
        _, cs = make_stores()
        camp = make_campaign(cs, limits={"max_observations": 10})
        budget = CampaignBudget(cs, camp)
        budget.consume("observations", 3, reason="first",
                       objective_id="obj-a")
        budget.consume("observations", 4, reason="second",
                       objective_id="obj-b")
        rows = cs.budget_ledger(camp.campaign_id)
        obs = [r for r in rows if r["resource"] == "observations"]
        self.assertEqual([(r["before"], r["after"]) for r in obs],
                         [(0, 3), (3, 7)])
        for r in obs:
            self.assertTrue(r["reason"])
            self.assertTrue(r["at"])

    def test_exhaustion_raises_and_is_explicit(self):
        _, cs = make_stores()
        camp = make_campaign(cs, limits={"max_hunt_plans": 2})
        budget = CampaignBudget(cs, camp)
        budget.consume("hunt_plans", 2, reason="used up",
                       objective_id="obj-a")
        with self.assertRaises(BudgetExhausted) as ctx:
            budget.ensure("hunt_plans")
        self.assertEqual(ctx.exception.resource, "hunt_plans")
        self.assertEqual(ctx.exception.limit, 2)
        self.assertEqual(ctx.exception.used, 2)
        self.assertTrue(budget.is_exhausted("hunt_plans"))

    def test_default_limits_cover_every_required_resource(self):
        from backend.research_agents.campaign.store import DEFAULT_LIMITS
        for key in ("max_objectives", "max_completed_objectives",
                    "max_active_objectives", "max_llm_calls",
                    "max_observations", "max_hunt_plans",
                    "max_runtime_seconds", "max_retries",
                    "max_context_chars", "max_knowledge_documents",
                    "max_campaign_lifetime_seconds"):
            self.assertIn(key, DEFAULT_LIMITS, key)
            self.assertGreater(DEFAULT_LIMITS[key], 0, key)


class TestAdvisorRequest(unittest.TestCase):
    """Phase 5 (request half): bounded R51 envelope, worst case <= 4000."""

    def _worst_case_request(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        objs = [add_obj(
            cs, camp, priority=90 - i * 10,
            question=f"objective {i} research question " + "q" * 130,
            hypothesis="h " + "h" * 130)
            for i in range(6)]
        deps = resolve_all(objs)
        reps = {o.objective_id: "xss-agent" for o in objs}
        req = advisor_request(
            campaign=camp, ordered=objs, dep_results=deps,
            budget_report={"used": {"observations": 3},
                           "remaining": {"observations": 9,
                                         "hunt_plans": 6,
                                         "llm_calls": 3},
                           "limits": {"max_observations": 12}},
            executable_ids=[o.objective_id for o in objs],
            specialists=reps,
        )
        return req

    def test_worst_case_passes_provider_sanitizer_and_size_budget(self):
        req = self._worst_case_request()
        canon = json.dumps(req, sort_keys=True, separators=(",", ":"))
        self.assertLessEqual(len(canon), MAX_CONTEXT_CHARS,
                             f"canonical {len(canon)}/{MAX_CONTEXT_CHARS}")
        sanitized = sanitize_provider_context(req)   # raises on violation
        self.assertIsInstance(sanitized, dict)
        self.assertLessEqual(
            int(sanitized.get("context_chars") or 0), MAX_CONTEXT_CHARS)

    def test_request_contract_keys_and_closed_enums(self):
        req = self._worst_case_request()
        self.assertEqual(set(req), {
            "rule_version", "advisory_id", "advisory_mode",
            "provider_kind", "source_layer", "instruction", "sections",
            "source_refs", "limitations", "research_only",
            "deterministic"})
        self.assertRegex(req["advisory_id"], r"^adv-[0-9a-f]{16}$")
        self.assertEqual(req["advisory_mode"], "RESEARCH_PRIORITY")
        self.assertEqual(req["provider_kind"], "OPENROUTER")
        self.assertEqual(req["source_layer"], "MULTI")
        self.assertTrue(req["research_only"])
        self.assertFalse(req["deterministic"])
        self.assertTrue(set(req["sections"]) <=
                        {"research_context", "learning_signals"})

    def test_request_carries_bounded_required_inputs(self):
        req = self._worst_case_request()
        # Phase 5 bounded inputs: campaign objective, scope reference,
        # objective summaries, dependency states, budget, capabilities.
        dumped = json.dumps(req)
        rq = req["sections"]["research_context"]["research_question"]
        self.assertTrue(rq)
        self.assertLessEqual(len(rq), 160)
        self.assertLessEqual(
            len(req["sections"]["learning_signals"]), 6)
        self.assertIn("remaining:", dumped)      # budget remaining present
        self.assertIn("OBJECTIVE_SUMMARY", dumped)
        self.assertIn("BUDGET_STATE", dumped)
        # no unrestricted database contents / history / secrets
        for banned in ("api_key", "Authorization", "sk-or-", "Bearer ",
                       "rows_dump", "full_history"):
            self.assertNotIn(banned, dumped)

    def test_scope_carried_as_reference_only(self):
        req = self._worst_case_request()
        refs = [r["reference"] for r in req["source_refs"]]
        joined = " ".join(refs)
        self.assertIn("fixture:", joined)
        self.assertNotIn("https://", joined)
        self.assertNotIn("http://", joined)


class TestAdvisorResponse(unittest.TestCase):
    """Phase 5 (response half): strict validation, reject invalid recs."""

    def _setup(self, state="READY", in_executable=True, scope=None):
        camp = Campaign(campaign_id="cmp-v", program="p",
                        scope_ref=scope or SCOPE,
                        campaign_objective="q")
        a = _obj("obj-v1", campaign_id="cmp-v", priority=70)
        b = _obj("obj-v2", campaign_id="cmp-v", priority=30,
                 state=state)
        by_id = {"obj-v1": a, "obj-v2": b}
        reps = {"obj-v1": "xss-agent", "obj-v2": "xss-agent"}
        exec_ids = ({"obj-v1", "obj-v2"} if in_executable
                    else {"obj-v1"})
        return camp, by_id, reps, exec_ids

    def _map(self, response, in_executable=True, **kw):
        camp, by_id, reps, exec_ids = self._setup(
            in_executable=in_executable)
        kwargs = dict(campaign_id=camp.campaign_id,
                      scope_ref=camp.scope_ref,
                      objectives_by_id=by_id,
                      executable_ids=exec_ids,
                      deterministic_order=["obj-v1", "obj-v2"],
                      specialists=reps, budget_ok=True)
        kwargs.update(kw)
        return map_advisor_response(response, **kwargs)

    @staticmethod
    def _payload(rec_text, summary="prioritize", rec_code=
                 "OBJECTIVE_PRIORITY_1"):
        return {
            "summary": summary,
            "insights": [{"insight_code": "INFO_VALUE_1",
                          "text": "bounded value"}],
            "recommendations": [{
                "recommendation_code": rec_code, "text": rec_text}]}

    def test_valid_recommendation_reorders_within_executable_set(self):
        out = self._map(self._payload("obj-v2"))
        self.assertTrue(out.used, out.error)
        self.assertEqual(out.reordered[0], "obj-v2")
        self.assertEqual(sorted(out.reordered), ["obj-v1", "obj-v2"])
        final = apply_advisory(["obj-v1", "obj-v2"], out)
        self.assertEqual(final[0], "obj-v2")
        self.assertEqual(sorted(final), ["obj-v1", "obj-v2"])

    def test_unknown_objective_rejected(self):
        out = self._map(self._payload("obj-000000000000"))
        self.assertFalse(out.used)
        self.assertEqual(out.error, "no_objective_recommended")

    def test_non_executable_objective_rejected(self):
        out = self._map(self._payload("obj-v2"), in_executable=False)
        # obj-v2 is READY but deliberately not in the executable set
        self.assertFalse(out.used, out)
        self.assertIn("invalid_recommendation", out.error)
        self.assertTrue(any("obj-v2" in r for r in out.rejected), out)

    def test_terminal_objective_rejected(self):
        camp, by_id, reps, _ = self._setup(in_executable=True)
        # force terminal state
        by_id["obj-v2"].state = "RESOLVED"
        out2 = map_advisor_response(
            self._payload("obj-v2"),
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id=by_id,
            executable_ids={"obj-v1", "obj-v2"},
            deterministic_order=["obj-v1", "obj-v2"],
            specialists=reps, budget_ok=True)
        self.assertFalse(out2.used, out2)
        self.assertTrue(out2.rejected)

    def test_wrong_campaign_rejected(self):
        camp, by_id, reps, _ = self._setup()
        by_id["obj-v2"].campaign_id = "cmp-other"
        out = map_advisor_response(
            self._payload("obj-v2"),
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id=by_id,
            executable_ids={"obj-v1", "obj-v2"},
            deterministic_order=["obj-v1", "obj-v2"],
            specialists=reps, budget_ok=True)
        self.assertFalse(out.used)
        self.assertTrue(out.rejected)

    def test_scope_mismatch_rejected(self):
        camp, by_id, reps, _ = self._setup()
        by_id["obj-v2"].scope_ref = "fixture:other/else.test"
        out = map_advisor_response(
            self._payload("obj-v2"),
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id=by_id,
            executable_ids={"obj-v1", "obj-v2"},
            deterministic_order=["obj-v1", "obj-v2"],
            specialists=reps, budget_ok=True)
        self.assertFalse(out.used)
        self.assertTrue(out.rejected)

    def test_missing_specialist_rejected(self):
        out = self._map(self._payload("obj-v2"),
                        executable_ids={"obj-v1", "obj-v2"},
                        specialists={"obj-v1": "xss-agent"})
        self.assertFalse(out.used, out)
        self.assertTrue(out.rejected or "invalid_recommendation"
                        in out.error, out)

    def test_running_objective_rejected(self):
        out = self._map(self._payload("obj-v2"),
                        executable_ids={"obj-v1", "obj-v2"},
                        running_ids={"obj-v2"})
        self.assertFalse(out.used, out)

    def test_budget_unavailable_rejected(self):
        camp, by_id, reps, _ = self._setup()
        out = map_advisor_response(
            self._payload("obj-v2"),
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id=by_id,
            executable_ids={"obj-v1", "obj-v2"},
            deterministic_order=["obj-v1", "obj-v2"],
            specialists=reps, budget_ok=False)
        self.assertFalse(out.used)

    def test_malformed_shapes_rejected(self):
        for bad in (None, "text", 42, {}, {"summary": "s"},
                    {"summary": "s", "insights": [], "recommendations": []},
                    {"summary": "s", "insights": ["flat-string"],
                     "recommendations": []}):
            out = self._map(bad)
            self.assertFalse(out.used, bad)
            self.assertTrue(out.error.startswith("malformed")
                            or out.error, out.error)

    def test_forbidden_content_rejected(self):
        out = self._map(self._payload(
            "obj-v1", summary="run curl http://internal/admin now"))
        self.assertFalse(out.used)
        self.assertIn("forbidden_advisor_content", out.error)

    def test_advisor_never_adds_candidates(self):
        camp, by_id, reps, _ = self._setup()
        out = map_advisor_response(
            self._payload("obj-v1"),
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id=by_id,
            executable_ids={"obj-v1"},
            deterministic_order=["obj-v1"],
            specialists=reps, budget_ok=True)
        self.assertTrue(out.used)
        self.assertEqual(sorted(out.reordered), ["obj-v1"])
        from backend.research_agents.campaign.advisor import (
            AdvisorOutcome,
        )
        poisoned = AdvisorOutcome(used=True,
                                  reordered=["obj-v1", "obj-zzz"])
        # apply_advisory refuses a reordered list with a foreign id:
        # the deterministic order is returned untouched.
        final = apply_advisory(["obj-v1"], poisoned)
        self.assertEqual(final, ["obj-v1"])


class TestContextAndAudit(unittest.TestCase):
    """Phases 9 + 15: provenance-aware context, lineage without secrets."""

    def test_context_rows_are_labeled_and_provenanced(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp)
        obj.state = "RESOLVED"
        items = extract_context_items(
            campaign_id=camp.campaign_id, objective=obj,
            job_id="job-xss-fake01",
            result={"research_lineage": {"gate_reason":
                                         "evidence_rules_met",
                                         "case_id": "case-1"},
                    "technology": ["nginx"]},
            hunt={"state": "RESOLVED", "rows_added": 3},
            gate_reason="evidence_rules_met", confidence="high")
        self.assertTrue(items)
        stored = record_context(cs, items)
        self.assertEqual(stored, len(items))
        rows = cs.context_for(camp.campaign_id)
        self.assertEqual(len(rows), len(items))
        for row in rows:
            self.assertTrue(row["research_context_only"])
            self.assertEqual(row["source_objective_id"],
                             obj.objective_id)
            self.assertEqual(row["source_job_id"], "job-xss-fake01")
            self.assertEqual(row["scope_ref"], camp.scope_ref)
            self.assertTrue(row["text"])
            self.assertTrue(row["at"])

    def test_context_is_scope_safe(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp)
        cs.record_context({"campaign_id": camp.campaign_id,
                           "source_objective_id": obj.objective_id,
                           "text": "fact", "scope_ref": camp.scope_ref})
        self.assertEqual(
            len(cs.context_for(camp.campaign_id,
                               scope_ref="fixture:other/x.test")), 0)
        self.assertEqual(
            len(cs.context_for("cmp-other")), 0)

    def test_context_is_bounded(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp)
        for i in range(12):
            cs.record_context({"campaign_id": camp.campaign_id,
                               "source_objective_id": obj.objective_id,
                               "text": f"fact {i}",
                               "scope_ref": camp.scope_ref})
        rows = cs.context_for(camp.campaign_id, limit=6)
        self.assertLessEqual(len(rows), 6)

    def test_lineage_row_shape_and_no_secrets(self):
        row = lineage_row(
            campaign_id="cmp-l", objective_id="obj-l", job_id="job-l",
            specialist="xss-agent", requested_model="openrouter/free",
            resolved_model="openrouter/free",
            prompt_version="campaign-advisor-v1",
            prioritizer_version="heuristic_transparent_v1",
            planner_version="hunt-planner-v1",
            budget_before={"used": {}}, budget_after={"used": {}},
            authorization_result="GRANTED", evidence_result="7 rows",
            termination_reason="resolved", plan_ids=["plan-1"],
            auth_ids=["auth-1"], observation_ids=["obs-1"],
            case_id="case-1", stage="objective_terminal")
        dumped = json.dumps(row, sort_keys=True)
        for field in ("campaign_id", "objective_id", "prioritizer_version",
                      "budget_before", "budget_after"):
            self.assertIn(field, row)
        self.assertEqual(row["event"], "campaign_objective_terminal")
        for banned in ("api_key", "sk-or-", "Authorization", "Bearer "):
            self.assertNotIn(banned, dumped)

    def test_campaign_event_shape(self):
        ev = campaign_event("objective_selected",
                            {"campaign_id": "cmp-e", "objective_id":
                             "obj-e"})
        self.assertEqual(ev["event"], "campaign_objective_selected")
        # timestamping happens at persist time (record_audit_event),
        # not in the builder; no secrets ever pass the redaction wall.
        self.assertNotIn("api_key", json.dumps(ev))


class TestExecutionLoopCore(unittest.TestCase):
    """Phases 8/19 (core): multi-objective loop, run bound, honest states."""

    def test_multi_cycle_selects_two_distinct_objectives(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp, priority=80)
        b = add_obj(cs, camp, priority=20)
        s1, j1 = run_campaign(camp.campaign_id, cs, store,
                              max_objectives=1)
        self.assertEqual(s1.executed_this_run, 1)
        s2, j2 = run_campaign(camp.campaign_id, cs, store,
                              max_objectives=1,
                              outcome="completed_no_case")
        ids = ({x["objective_id"] for x in s1.selected}
               | {x["objective_id"] for x in s2.selected})
        self.assertEqual(ids, {a.objective_id, b.objective_id})
        self.assertEqual(len(store.list_jobs()), 2)
        final = cs.get_campaign(camp.campaign_id)
        self.assertEqual(final.state, "COMPLETED")
        self.assertIn("resolved=1 rejected=1", final.termination_reason)
        self.assertEqual(j1["ran"], 1)
        self.assertEqual(j2["ran"], 1)

    def test_run_bound_parks_campaign_waiting_not_terminal(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=80)
        b = add_obj(cs, camp, priority=20)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1)
        self.assertEqual(summ.state, "WAITING")
        self.assertEqual(summ.termination_reason,
                         "per_run_objective_limit")
        final = cs.get_campaign(camp.campaign_id)
        self.assertEqual(final.state, "WAITING")
        self.assertFalse(final.is_terminal)
        self.assertEqual(cs.get_objective(b.objective_id).state, "READY")

    def test_dependency_blocks_second_objective_until_first_resolves(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp, priority=90)
        b = _obj("obj-dep", campaign_id=camp.campaign_id, priority=50,
                 deps=[make_dependency("obj-dep", a.objective_id)])
        cs.add_objective(b, camp)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1)
        executed = [x["objective_id"] for x in summ.selected]
        self.assertEqual(executed, [a.objective_id])
        self.assertNotIn("obj-dep", executed)
        # second run: prereq RESOLVED -> dependent executes
        summ2, _ = run_campaign(camp.campaign_id, cs, store,
                                max_objectives=1,
                                outcome="completed_no_case")
        ids2 = [x["objective_id"] for x in summ2.selected]
        self.assertIn("obj-dep", ids2)

    def test_blocked_prereq_terminal_blocks_dependent_honestly(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp, priority=90)
        b = _obj("obj-depb", campaign_id=camp.campaign_id,
                 deps=[make_dependency("obj-depb", a.objective_id)])
        cs.add_objective(b, camp)
        run_campaign(camp.campaign_id, cs, store, max_objectives=1,
                     outcome="completed_blocked")
        run_campaign(camp.campaign_id, cs, store, max_objectives=2,
                     outcome="completed_blocked")
        self.assertEqual(cs.get_objective(a.objective_id).state,
                         "BLOCKED")
        self.assertEqual(cs.get_objective("obj-depb").state, "BLOCKED")
        final = cs.get_campaign(camp.campaign_id)
        self.assertFalse(final.state == "COMPLETED")
        self.assertEqual(final.state, "BLOCKED")

    def test_job_scope_always_equals_campaign_scope(self):
        from backend.research_agents.campaign.executor import (
            build_objective_job,
        )
        from backend.research_agents.runtime import RuntimeConfig
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:safe/scope.test")
        obj = add_obj(cs, camp)
        job = build_objective_job(
            campaign=camp, objective=obj, agent_name="xss-agent",
            config=RuntimeConfig(execution_mode="fixture"),
            context_digest="ctx")
        self.assertEqual(job.authorization_ref, camp.scope_ref)
        self.assertNotIn("https://", job.authorization_ref)

    def test_advisor_reorder_is_used_but_bounded(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        low = add_obj(cs, camp, priority=20)
        high = add_obj(cs, camp, priority=80)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               advisor_fn=advisor_valid(low.objective_id))
        self.assertEqual(len(summ.advisor_outcomes), 1)
        outcome = summ.advisor_outcomes[0]
        self.assertTrue(outcome["used"], outcome)
        # advisor moved the VALID lower-priority objective to the front
        self.assertEqual(summ.selected[0]["objective_id"],
                         low.objective_id)
        self.assertEqual(len(store.list_jobs()), 1)

    def test_deterministic_order_when_no_advisor(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        low = add_obj(cs, camp, priority=20)
        high = add_obj(cs, camp, priority=80)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1, advisor_fn=None)
        self.assertEqual(summ.advisor_outcomes, [])
        self.assertEqual(summ.selected[0]["objective_id"],
                         high.objective_id)

    def test_verifed_memory_requires_case(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store, max_objectives=1,
                     outcome="completed_case")
        rows = [r for r in read_memory_rows(store.base)
                if str((r.get("provenance") or {}).get("source", ""))
                .startswith(f"campaign:{camp.campaign_id}")]
        self.assertTrue(rows, rows)
        verified = [r for r in rows if r.get("state") == "VERIFIED"]
        self.assertTrue(verified, rows)
        for r in verified:
            self.assertEqual(r.get("kind"),
                             "confirmed_historical_result")

    def test_gate_met_without_case_memory_is_not_verified(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               outcome="completed_gate_met_no_case")
        self.assertEqual(summ.selected[0]["state"], "RESOLVED")
        rows = [r for r in read_memory_rows(store.base)
                if str((r.get("provenance") or {}).get("source", ""))
                .startswith(f"campaign:{camp.campaign_id}")]
        self.assertTrue(rows, rows)
        self.assertFalse([r for r in rows
                          if r.get("state") == "VERIFIED"], rows)

    def test_rejected_objective_preserves_rejected_hypothesis(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               outcome="completed_no_case")
        self.assertEqual(summ.selected[0]["state"], "REJECTED")
        rows = [r for r in read_memory_rows(store.base)
                if r.get("kind") == "rejected_hypothesis"
                and str((r.get("provenance") or {}).get("source", ""))
                .startswith(f"campaign:{camp.campaign_id}")]
        self.assertTrue(rows, rows)
        self.assertTrue(all(r.get("state") == "REJECTED"
                            for r in rows))


if __name__ == "__main__":
    unittest.main()

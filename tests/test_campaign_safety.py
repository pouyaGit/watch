"""AUTONOMOUS SECURITY CAMPAIGN ORCHESTRATOR v1 — security tests.

Phase 17 checklist, proven with static/AST checks where appropriate:
scope, authorization, LLM boundaries, free-only model policy,
dependency cycles, duplicate execution, budget integrity, secret
scrubbing, bounded context, and validated state transitions.
"""

from __future__ import annotations

import ast
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
    append_raw_objective,
    make_campaign,
    make_stores,
    read_memory_rows,
    run_campaign,
)

from backend.research_agents.campaign import (  # noqa: E402
    CampaignScopeError,
    CampaignStateError,
    CampaignStoreError,
    execute_campaign,
)
from backend.research_agents.campaign.audit import lineage_row  # noqa: E402
from backend.research_agents.campaign.models import (  # noqa: E402
    Campaign,
    CampaignObjective,
    new_id,
)
from backend.research_agents.llm_guard import (  # noqa: E402
    FreeOnlyViolation,
    resolve_free_config,
)

PKG_DIR = Path(__file__).resolve().parents[1] / (
    "backend/research_agents/campaign")
SOC_ADAPTER = Path(__file__).resolve().parents[1] / (
    "backend/soc/campaigns.py")

FORBIDDEN_IMPORT_ROOTS = {
    "subprocess", "socket", "requests", "urllib", "urllib3", "httpx",
    "aiohttp", "ftplib", "smtplib", "telnetlib", "paramiko", "pexpect",
    "webbrowser",
}
# campaign delegates ALL execution; it must never import these boundaries
FORBIDDEN_DELEGATION_MODULES = (
    "hunt.executor", "hunt.planner", "ai.authorizer",
    "fixture_observations", "mongo_observations", "file_observations",
    "real_observations",
)
FORBIDDEN_CALLS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("os", "execl"), ("os", "execle"),
}


def _campaign_sources() -> dict[str, str]:
    files = sorted(PKG_DIR.glob("*.py"))
    files.append(SOC_ADAPTER)
    return {f.name: f.read_text(encoding="utf-8") for f in files}


def _trees(sources: dict[str, str]) -> dict[str, ast.AST]:
    return {name: ast.parse(text) for name, text in sources.items()}


class TestStaticSafety(unittest.TestCase):
    """Phase 17 static/AST checks over the campaign package."""

    @classmethod
    def setUpClass(cls):
        cls.sources = _campaign_sources()
        cls.trees = _trees(cls.sources)

    def test_no_network_or_process_imports_anywhere(self):
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    roots = {((node.module or "").split(".")[0])}
                else:
                    continue
                self.assertFalse(roots & FORBIDDEN_IMPORT_ROOTS,
                                 f"{name}: forbidden import {roots}")

    def test_no_os_command_or_dynamic_code_calls(self):
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Attribute) and \
                            isinstance(fn.value, ast.Name):
                        pair = (fn.value.id, fn.attr)
                        self.assertNotIn(pair, FORBIDDEN_CALLS,
                                         f"{name}: forbidden call {pair}")
                    if isinstance(fn, ast.Name):
                        self.assertNotIn(fn.id, ("eval", "exec"),
                                         f"{name}: dynamic code exec")

    def test_campaign_delegates_execution_never_imports_boundaries(self):
        """Rules 5/18/19/20: Gate/Authorization/Observation Runtime/Hunt
        Planner stay the ONLY execution path — the campaign must not
        import them to run things itself."""
        for name, tree in self.trees.items():
            src = self.sources[name]
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    for forbidden in FORBIDDEN_DELEGATION_MODULES:
                        self.assertNotIn(forbidden, mod,
                                         f"{name}: imports {mod}")
            # no direct invocation of hunt execution entry points
            for forbidden_call in ("run_hunt", "execute_hunt"):
                self.assertNotIn(f"{forbidden_call}(", src,
                                 f"{name}: calls {forbidden_call} directly")
        # run_hunt exists and lives in the hunt package only
        hunt_src = (Path(__file__).resolve().parents[1] /
                    "backend/research_agents/hunt/executor.py"
                    ).read_text(encoding="utf-8")
        self.assertIn("def run_hunt", hunt_src)

    def test_free_only_cli_order_guard_before_advisor_build(self):
        cli = (Path(__file__).resolve().parents[1] /
               "backend/research_agents/cli.py").read_text(
                   encoding="utf-8")
        builder = cli[cli.index("def _build_campaign_advisor"):]
        nxt = builder.find("\ndef ", 4)
        if nxt > 0:
            builder = builder[:nxt]
        self.assertIn("resolve_free_config(", builder)
        # the guard is the FIRST thing the advisor does, before any
        # provider can be constructed (free-only, no paid fallback).
        self.assertLess(builder.index("resolve_free_config("),
                        builder.index("select_provider("))
        runner = cli[cli.index("def cmd_campaign("):]
        nxt = runner.find("\ndef ")
        if nxt > 0:
            runner = runner[:nxt]
        i_advisor = runner.index("_build_campaign_advisor(")
        i_run = runner.index("execute_campaign(")
        # advisor built (unguarded = no provider yet) before the loop
        self.assertLess(i_advisor, i_run)

    def test_no_secret_literals_in_campaign_code(self):
        import re
        key_like = re.compile(r"sk-or-[0-9a-f]{6,}")
        for name, text in self.sources.items():
            # detection patterns (redaction logic) are allowed; actual
            # key MATERIAL never is.
            self.assertIsNone(key_like.search(text), name)
            self.assertNotIn("OPENROUTER_API_KEY=", text, name)

    def test_sidebar_lists_campaigns_without_touching_old_nav(self):
        base = (Path(__file__).resolve().parents[1] /
                "web/templates/base.html").read_text(encoding="utf-8")
        self.assertIn('href="/ui/soc/campaigns', base)
        # additive only: every pre-existing nav target still present
        for target in ("/ui/programs", "/ui/domains", "/ui/http",
                       "/ui/wordlists", "/ui/urls", "/ui/endpoints",
                       "/ui/parameters", "/ui/changes", "/ui/soc/",
                       "/ui/soc/agents", "/ui/soc/activity",
                       "/ui/soc/cases", "/ui/kb", "/ui/soc/handoff",
                       "/ui/runs", "/ui/tasks", "/docs"):
            self.assertIn(f'href="{target}', base)

    def test_routes_registered_additively(self):
        soc = (Path(__file__).resolve().parents[1] /
               "backend/routers/soc.py").read_text(encoding="utf-8")
        for route in ('"/ui/soc/campaigns"',
                      '"/ui/soc/campaigns/{campaign_id}"',
                      ("/ui/soc/campaigns/{campaign_id}"
                       "/objectives/{objective_id}")):
            self.assertIn(route, soc)
        # pre-existing routes still registered
        for route in ('"/ui/soc/agents"', '"/ui/soc/cases"'):
            self.assertIn(route, soc)


class TestFreeOnlyPolicy(unittest.TestCase):
    """Rules 1-4 + 28: only openrouter/free; no paid/unknown/missing."""

    def test_paid_model_rejected(self):
        for model in ("deepseek/deepseek-chat", "openai/gpt-4o",
                      "anthropic/claude-3.5"):
            with self.assertRaises(FreeOnlyViolation):
                resolve_free_config(provider_kind="OPENROUTER",
                                    requested_model=model, timeout_seconds=30)

    def test_unknown_model_rejected(self):
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config(provider_kind="OPENROUTER",
                                requested_model="mystery/model-v99",
                                timeout_seconds=30)

    def test_missing_model_rejected(self):
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config(provider_kind="OPENROUTER",
                                requested_model="", timeout_seconds=30)

    def test_missing_provider_configuration_rejected(self):
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config(provider_kind="OPENAI",
                                requested_model="openrouter/free",
                                timeout_seconds=30)

    def test_missing_key_fails_closed(self):
        import os
        saved = os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            with self.assertRaises(FreeOnlyViolation):
                resolve_free_config(
                    provider_kind="OPENROUTER",
                    requested_model="openrouter/free", timeout_seconds=30)
        finally:
            if saved is not None:
                os.environ["OPENROUTER_API_KEY"] = saved


class TestScopeBoundaries(unittest.TestCase):
    """Rules 14-17: campaign and objective can never widen scope."""

    def test_campaign_requires_explicit_scope(self):
        with self.assertRaises(CampaignScopeError):
            Campaign(campaign_id=new_id("cmp"), program="p",
                     scope_ref="", campaign_objective="x")

    def test_add_objective_with_foreign_scope_refused(self):
        _, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        bad = CampaignObjective(
            objective_id=new_id("obj"), campaign_id=camp.campaign_id,
            category="XSS", scope_ref="fixture:b/b.test",
            research_question="q", hypothesis="h")
        with self.assertRaises(CampaignStoreError):
            cs.add_objective(bad, camp)

    def test_scope_mismatch_detected_before_any_execution(self):
        """Tampered objective row -> FAILED scope_mismatch, zero jobs."""
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        obj = add_obj(cs, camp)
        row = obj.to_dict()
        row["scope_ref"] = "fixture:widen/widened.test"
        append_raw_objective(store.base, row)
        summ = execute_campaign(
            camp.campaign_id, store=store, campaign_store=cs,
            max_objectives=1)
        self.assertEqual(summ.state, "FAILED")
        self.assertEqual(summ.termination_reason,
                         "scope_mismatch_detected")
        self.assertEqual(len(store.list_jobs()), 0)
        self.assertIn(obj.objective_id, summ.errors[0])

    def test_queued_job_carries_campaign_scope_authorization(self):
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:safe/scope.test")
        add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               outcome="leave_queued")
        jobs = store.list_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].authorization_ref, camp.scope_ref)
        self.assertNotIn("https://", jobs[0].authorization_ref)

    def test_advisor_recommending_out_of_scope_objective_rejected(self):
        # covered end-to-end in core; assert the scope-mismatch validator
        # directly here as a Phase-17 checklist item.
        from backend.research_agents.campaign.advisor import (
            map_advisor_response,
        )
        camp = Campaign(campaign_id="cmp-sc", program="p",
                        scope_ref=SCOPE, campaign_objective="q")
        obj = CampaignObjective(
            objective_id="obj-sc", campaign_id="cmp-sc", category="XSS",
            scope_ref="fixture:other/else.test", research_question="q",
            hypothesis="h", state="READY")
        out = map_advisor_response(
            {"summary": "s", "insights": [],
             "recommendations": [{"recommendation_code":
                                  "OBJECTIVE_PRIORITY_1",
                                  "text": "obj-sc"}]},
            campaign_id=camp.campaign_id, scope_ref=camp.scope_ref,
            objectives_by_id={"obj-sc": obj},
            executable_ids={"obj-sc"},
            deterministic_order=["obj-sc"],
            specialists={"obj-sc": "xss-agent"}, budget_ok=True)
        self.assertFalse(out.used)
        self.assertTrue(out.rejected)


class TestLLMBoundary(unittest.TestCase):
    """Rules 6-13: advisory only; can never produce evidence/cases."""

    def test_full_run_with_advisor_creates_no_evidence_or_cases(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               outcome="completed_case",
                               advisor_fn=advisor_valid(
                                   obj.objective_id))
        self.assertTrue(summ.advisor_outcomes[0]["used"],
                        summ.advisor_outcomes[0])
        # the campaign layer never writes evidence rows or case rows;
        # those come only from the Evidence Gate inside job execution.
        self.assertEqual(store.list_evidence(), [])
        self.assertEqual(store.list_cases(), [])
        # the campaign DID move the objective using mapped gate truth
        self.assertEqual(cs.get_objective(obj.objective_id).state,
                         "RESOLVED")

    def test_advisor_exception_never_widens_execution(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=50)
        summ, _ = run_campaign(
            camp.campaign_id, cs, store, max_objectives=1,
            advisor_fn=lambda _req: (_ for _ in ()).throw(
                RuntimeError("advisor exploded")))
        self.assertEqual(len(summ.selected), 1)
        self.assertEqual(len(store.list_jobs()), 1)
        # exception recorded as an advisor outcome; deterministic order kept
        self.assertTrue(summ.advisor_outcomes, summ.advisor_outcomes)
        self.assertFalse(summ.advisor_outcomes[0]["used"],
                         summ.advisor_outcomes[0])

    def test_campaign_event_redacts_secret_shaped_values(self):
        from backend.research_agents.campaign.audit import (
            campaign_event,
        )
        ev = campaign_event("objective_started", {
            "campaign_id": "cmp-r",
            "note": "key sk-or-abcdef123 leaked?"})
        self.assertIn("[REDACTED]", json.dumps(ev))
        self.assertNotIn("sk-or-abcdef123", json.dumps(ev))


class TestNoDuplicateExecution(unittest.TestCase):
    """Phase 16/17: duplicate coordinator and duplicate execution."""

    def test_only_one_coordinator_can_hold_the_lease(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        ok_a, why_a = cs.claim_lease(camp.campaign_id, "coord-a",
                                     ttl_seconds=3600)
        ok_b, why_b = cs.claim_lease(camp.campaign_id, "coord-b",
                                     ttl_seconds=3600)
        ok_c, _ = cs.claim_lease(camp.campaign_id, "coord-c",
                                 ttl_seconds=3600)
        self.assertTrue(ok_a, why_a)
        self.assertFalse(ok_b, why_b)
        self.assertFalse(ok_c)

    def test_live_foreign_lease_refuses_run(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        cs.claim_lease(camp.campaign_id, "other-coord", ttl_seconds=3600)
        summ, _ = run_campaign(camp.campaign_id, cs, store)
        self.assertFalse(summ.ok)
        self.assertTrue(summ.reason.startswith("lease_refused"),
                        summ.reason)
        self.assertEqual(len(store.list_jobs()), 0)

    def test_resume_never_enqueues_a_second_job(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        # run 1: job stays pending -> objective WAITING with job linked
        s1, _ = run_campaign(camp.campaign_id, cs, store,
                             outcome="leave_queued")
        self.assertEqual(len(store.list_jobs()), 1)
        # run 2: resume the SAME job (fake now completes it)
        s2, _ = run_campaign(camp.campaign_id, cs, store,
                             outcome="completed_case")
        self.assertEqual(len(store.list_jobs()), 1,
                         "resume must not enqueue a duplicate job")
        self.assertEqual(s2.selected[0]["job_id"],
                         s1.selected[0]["job_id"])
        self.assertEqual(cs.get_objective(obj.objective_id).state,
                         "RESOLVED")

    def test_terminal_objective_never_selected_again(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store,
                     outcome="completed_case")
        jobs_after_first = len(store.list_jobs())
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_case")
        self.assertEqual(summ.selected, [])
        self.assertEqual(len(store.list_jobs()), jobs_after_first)

    def test_blocked_outcome_objective_not_re_executed(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store,
                     outcome="completed_blocked")
        jobs = len(store.list_jobs())
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_blocked")
        self.assertEqual(summ.selected, [])
        self.assertEqual(len(store.list_jobs()), jobs)


class TestBudgetCannotBeBypassed(unittest.TestCase):
    """Phase 7/17: reaching a limit stops honestly, never silently."""

    def test_hunt_plan_budget_stops_second_objective(self):
        store, cs = make_stores()
        camp = make_campaign(cs, limits={"max_hunt_plans": 1})
        first = add_obj(cs, camp, priority=90)
        second = add_obj(cs, camp, priority=80)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=2,
                               outcome="completed_case")
        self.assertEqual(summ.state, "BUDGET_EXHAUSTED")
        self.assertIn("max_hunt_plans", summ.termination_reason)
        self.assertEqual(len(store.list_jobs()), 1,
                         "budget exhaustion must prevent the 2nd job")
        self.assertEqual(summ.selected[0]["objective_id"],
                         first.objective_id)
        untouched = cs.get_objective(second.objective_id)
        self.assertIn(untouched.state, ("QUEUED", "READY"))
        # ledger proves auditable before/after
        rows = [r for r in cs.budget_ledger(camp.campaign_id)
                if r["resource"] == "hunt_plans"]
        self.assertEqual([(r["before"], r["after"]) for r in rows],
                         [(0, 1)])
        final = cs.get_campaign(camp.campaign_id)
        self.assertEqual(final.state, "BUDGET_EXHAUSTED")
        self.assertNotEqual(final.termination_reason, "")

    def test_objective_budget_not_silently_continued(self):
        store, cs = make_stores()
        camp = make_campaign(cs, limits={"max_objectives": 1})
        add_obj(cs, camp, priority=90)
        with self.assertRaises(CampaignStoreError):
            # creation limit enforced — cannot smuggle a second objective
            add_obj(cs, camp)


class TestDependencyCycleRejected(unittest.TestCase):
    """Phase 17: dependency cycles rejected before execution."""

    def test_cycle_cannot_be_created_nor_saved(self):
        from backend.research_agents.campaign.models import Dependency
        _, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp)
        b_id = new_id("obj")
        b_row_obj = CampaignObjective(
            objective_id=b_id, campaign_id=camp.campaign_id,
            category="XSS", scope_ref=camp.scope_ref,
            research_question="b", hypothesis="b",
            dependencies=[Dependency(
                objective_id=b_id, depends_on=a.objective_id,
                kind="REQUIRED")])
        b = cs.add_objective(b_row_obj, camp)
        a.dependencies = [Dependency(objective_id=a.objective_id,
                                     depends_on=b.objective_id,
                                     kind="REQUIRED")]
        from backend.research_agents.campaign import DependencyCycleError
        with self.assertRaises(DependencyCycleError):
            cs.save_objective(a)

    def test_raw_cycle_rows_fail_the_run(self):
        from backend.research_agents.campaign.models import Dependency
        store, cs = make_stores()
        camp = make_campaign(cs)
        a = add_obj(cs, camp)
        b_id = new_id("obj")
        b = CampaignObjective(
            objective_id=b_id, campaign_id=camp.campaign_id,
            category="XSS", scope_ref=camp.scope_ref,
            research_question="b", hypothesis="b",
            dependencies=[Dependency(
                objective_id=b_id, depends_on=a.objective_id,
                kind="REQUIRED")])
        b = cs.add_objective(b, camp)
        # bypass the store guard by rewriting A's raw row with the
        # closing edge of the cycle (simulates an external writer)
        row_a = a.to_dict()
        row_a["dependencies"] = [{"objective_id": a.objective_id,
                                  "depends_on": b.objective_id,
                                  "kind": "REQUIRED"}]
        append_raw_objective(store.base, row_a)
        summ = execute_campaign(camp.campaign_id, store=store,
                                campaign_store=cs, max_objectives=1)
        self.assertFalse(summ.ok)
        self.assertIn("cycle", summ.reason + summ.termination_reason)
        self.assertEqual(len(store.list_jobs()), 0)


class TestStateTransitionsValidated(unittest.TestCase):
    """Phase 17: campaign state transitions validated."""

    def test_store_rejects_illegal_campaign_transition(self):
        _, cs = make_stores()
        camp = make_campaign(cs)
        with self.assertRaises(CampaignStateError):
            cs.transition_campaign(camp.campaign_id, "COMPLETED",
                                   reason="forged")
        with self.assertRaises(CampaignStateError):
            cs.transition_campaign(camp.campaign_id, "RUNNING",
                                   reason="forged")

    def test_terminal_campaign_is_frozen(self):
        from backend.research_agents.campaign.models import Campaign
        _, cs = make_stores()
        camp = make_campaign(cs)
        cs.transition_campaign(camp.campaign_id, "READY",
                               reason="validated")
        cs.transition_campaign(camp.campaign_id, "CANCELLED",
                               reason="operator stop")
        for target in ("RUNNING", "READY", "COMPLETED"):
            with self.assertRaises(CampaignStateError):
                cs.transition_campaign(camp.campaign_id, target,
                                       reason="forged")


class TestStaleAuthorizationRejected(unittest.TestCase):
    """Phase 12/17: stale authorization and stale leases rejected."""

    def test_expired_lease_is_reclaimed_with_fresh_claim(self):
        from datetime import datetime, timedelta, timezone
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        past = (datetime.now(timezone.utc) -
                timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ok, why = cs.claim_lease(
            camp.campaign_id, "crashed-coord", ttl_seconds=1, now=past)
        self.assertTrue(ok, why)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_case")
        self.assertTrue(summ.ok, summ.reason)
        self.assertEqual(len(store.list_jobs()), 1)

    def test_resume_revalidates_scope_before_executing(self):
        # objective tampered AFTER a pending run -> next run refuses
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        obj = add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store,
                     outcome="leave_queued")
        row = obj.to_dict()
        row["scope_ref"] = "fixture:widen/widened.test"
        append_raw_objective(store.base, row)
        summ = execute_campaign(camp.campaign_id, store=store,
                                campaign_store=cs, max_objectives=1)
        self.assertEqual(summ.state, "FAILED")
        self.assertEqual(summ.termination_reason,
                         "scope_mismatch_detected")
        self.assertEqual(len(store.list_jobs()), 1)  # only the old one


class TestSecretsAndBoundedHistory(unittest.TestCase):
    """Phase 17: secrets scrubbed; unrestricted history unavailable."""

    def _request(self):
        from backend.research_agents.campaign.advisor import (
            advisor_request,
        )
        from backend.research_agents.campaign.dependencies import (
            resolve_all,
        )
        camp = make_campaign(make_stores()[1])
        store, cs = make_stores()
        camp = make_campaign(cs)
        objs = [add_obj(cs, camp, priority=90 - i,
                        question=f"q{i} " + "x" * 140)
                for i in range(6)]
        deps = resolve_all(objs)
        return advisor_request(
            campaign=camp, ordered=objs, dep_results=deps,
            budget_report={"used": {}, "remaining": {"llm_calls": 3},
                           "limits": {}},
            executable_ids=[o.objective_id for o in objs],
            specialists={o.objective_id: "xss-agent"
                         for o in objs})

    def test_request_has_no_secret_material(self):
        dumped = json.dumps(self._request())
        for banned in ("sk-or-", "api_key", "Authorization", "Bearer ",
                       "OPENROUTER_API_KEY"):
            self.assertNotIn(banned, dumped)

    def test_request_is_a_closed_bounded_contract(self):
        req = self._request()
        self.assertEqual(sorted(req), sorted([
            "rule_version", "advisory_id", "advisory_mode",
            "provider_kind", "source_layer", "instruction", "sections",
            "source_refs", "limitations", "research_only",
            "deterministic"]))
        dumped = json.dumps(req)
        for banned_key in ('"history"', '"messages"', '"rows_dump"',
                           '"evidence_rows"', '"database"'):
            self.assertNotIn(banned_key, dumped)
        self.assertLessEqual(len(req["sections"]["learning_signals"]), 6)

    def test_lineage_row_scrubs_secrets(self):
        row = lineage_row(
            campaign_id="cmp-s", stage="advisor_outcome",
            extra={"leak": "uses key sk-or-1234567890abcdef"})
        self.assertIn("[REDACTED]", json.dumps(row))
        self.assertNotIn("sk-or-1234567890abcdef", json.dumps(row))


if __name__ == "__main__":
    unittest.main()

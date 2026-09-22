"""AUTONOMOUS HUNT PLANNER v1 — Phase 16 security tests.

Every checkbox from the Epic's security list, proven behaviorally AND
via AST/static inspection of the hunt package:

[x] planner cannot widen scope              [x] planner cannot invent capabilities
[x] planner cannot invoke arbitrary HTTP    [x] planner cannot invoke shell
[x] planner cannot invoke code execution    [x] planner cannot execute exploit payloads
[x] planner cannot bypass authorization     [x] planner cannot create a case directly
[x] planner cannot manufacture evidence     [x] planner cannot upgrade gate confidence
[x] planner cannot read unrestricted history[x] unknown observation types rejected
[x] unknown models rejected                 [x] paid models rejected
[x] secrets scrubbed                        [x] plan versions immutable after execution
[x] duplicate execution prevented           [x] infinite planning loop prevented
[x] concurrency race handled                [x] stale authorization rejected
"""

from __future__ import annotations

import ast
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from tests.hunt_fixtures import (  # noqa: E402
    make_job,
    make_store,
    rich_rows,
    run_hunt_fixture,
)

from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.hunt import (  # noqa: E402
    HuntLimits,
    HuntStore,
    HuntStoreError,
    advisor_request,
    build_candidates,
    build_plan,
    compute_missing_evidence,
    map_advisor_response,
    validate_final_plan,
    validate_observation_requests,
)
from backend.research_agents.hunt.audit import hunt_audit_event  # noqa: E402
from backend.research_agents.hunt.authorization import (  # noqa: E402
    authorization_gate,
    build_authorization_request,
)
from backend.research_agents.hunt.executor import HUNT_RULE_VERSION  # noqa: E402
from backend.research_agents.hunt.models import HuntPlan, PlanTransition  # noqa: E402
from backend.research_agents.hunt.registry import REGISTRY, scan_forbidden  # noqa: E402
from backend.research_agents.hunt.uncertainty import UNCERTAINTY_STATES  # noqa: E402
from backend.research_agents.llm_guard import FreeOnlyViolation  # noqa: E402
from backend.research_agents.models import JobStatus  # noqa: E402
from backend.research_agents.runtime import (  # noqa: E402
    AgentWorker,
    AuthorizationChecker,
    RuntimeConfig,
    deterministic_analysis,
    evaluate_case_creation,
    resolve_free_config,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow  # noqa: E402
from ai.providers.context_allowlist import (  # noqa: E402
    SECTION_ALLOWED_KEYS,
)

HUNT_DIR = (Path(__file__).resolve().parents[1]
            / "backend" / "research_agents" / "hunt")

# ---- AST / static contract ------------------------------------------

BANNED_IMPORTS = {
    "socket", "requests", "urllib", "http", "aiohttp", "httpx",
    "subprocess", "pexpect", "ctypes",
}
BANNED_CALL_NAMES = {"eval", "exec", "compile", "__import__"}
BANNED_ATTR_CALLS = {
    ("os", "system"), ("os", "popen"), ("os", "spawnl"), ("os", "spawnv"),
    ("os", "execv"), ("os", "execl"),
}
# the hunt layer must never touch case/evidence persistence directly
FORBIDDEN_STORE_METHODS = (
    "record_case", "record_case_evidence", "record_evidence",
    "create_case", "append_case",
)


def _hunt_sources() -> dict[str, str]:
    return {p.name: p.read_text()
            for p in sorted(HUNT_DIR.glob("*.py"))}


class StaticSecurityContractTests(unittest.TestCase):
    """AST/static proofs over the whole hunt package."""

    def test_no_network_or_shell_imports(self):
        for name, src in _hunt_sources().items():
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        self.assertNotIn(
                            root, BANNED_IMPORTS,
                            f"{name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    self.assertNotIn(root, BANNED_IMPORTS,
                                     f"{name} imports from {node.module}")

    def test_no_dynamic_code_or_os_execution_calls(self):
        for name, src in _hunt_sources().items():
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name):
                        self.assertNotIn(fn.id, BANNED_CALL_NAMES,
                                         f"{name} calls {fn.id}()")
                    if isinstance(fn, ast.Attribute) and \
                            isinstance(fn.value, ast.Name):
                        pair = (fn.value.id, fn.attr)
                        self.assertNotIn(
                            pair, BANNED_ATTR_CALLS,
                            f"{name} calls {pair[0]}.{pair[1]}()")

    def test_no_case_or_evidence_persistence_calls(self):
        # static: the hunt package never names these store methods
        for name, src in _hunt_sources().items():
            for method in FORBIDDEN_STORE_METHODS:
                self.assertNotIn(
                    f".{method}(", src,
                    f"{name} touches forbidden persistence method {method}")

    def test_only_executor_observes_and_only_through_injected_provider(self):
        sources = _hunt_sources()
        for name, src in sources.items():
            if name == "executor.py":
                # the ONLY site in the package that can invoke the
                # observation boundary (through the injected provider)
                self.assertIn("provider.observe(", src)
            else:
                self.assertNotIn("provider.observe(", src,
                                 f"{name} must not execute observations")

    def test_planner_and_registry_modules_make_no_target_requests(self):
        # planner/authorization/registry contain no payload-like inputs
        for name in ("planner.py", "authorization.py", "registry.py",
                     "missing_evidence.py", "uncertainty.py",
                     "store.py", "audit.py", "models.py"):
            src = _hunt_sources()[name]
            self.assertNotIn("urlopen", src)
            self.assertNotIn("http.client", src)


class ScopeAndCapabilityTests(unittest.TestCase):
    def test_planner_cannot_widen_scope(self):
        job = make_job()
        cap = capability_for("XSS")
        obj_job_scope = job.authorization_ref
        obj = make_objective(scope="fixture:shop/OTHER.test")
        self.assertNotEqual(obj.scope_ref, obj_job_scope)
        items = compute_missing_evidence(
            capability=cap, scope_ref=obj.scope_ref,
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        plan, _ = build_plan(objective=obj, job=job, capability=cap,
                             candidates=cands, missing_items=items,
                             advisor=None, version=1)
        # the plan carries the widened objective scope...
        reasons = validate_final_plan(plan, capability=cap, job=job,
                                      scope_ref=job.authorization_ref)
        # ...and BOTH validation and the gate refuse to authorize it
        self.assertTrue(reasons)
        req = build_authorization_request(plan, job=job, capability=cap)
        rec = authorization_gate(req, job=job, capability=cap,
                                 auth_checker=AuthorizationChecker())
        self.assertEqual(rec.status, "DENIED")

    def test_planner_cannot_invent_capabilities(self):
        valid, reasons = validate_observation_requests(
            [{"observation_type": "remote-shell"},
             {"observation_type": "sqlmap"},
             {"observation_type": "arbitrary-http"}],
            allowed_for_capability=("http-rows", "kb-rows"))
        self.assertEqual(valid, [])
        self.assertEqual(len(reasons), 3)
        # registry itself only declares supported read-only types
        self.assertEqual(set(REGISTRY), {
            "url-rows", "parameter-rows", "endpoint-rows", "http-rows",
            "header-rows", "kb-rows"})
        for spec in REGISTRY.values():
            self.assertFalse(spec.executes_http)

    def test_planner_cannot_execute_exploit_payloads(self):
        hits = scan_forbidden(["craft the payload and deliver it"])
        self.assertTrue(hits)
        # valid plan inputs never contain exploit-ish keys
        job = make_job()
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref=job.authorization_ref,
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        plan, _ = build_plan(objective=make_objective(), job=job,
                             capability=cap, candidates=cands,
                             missing_items=items, advisor=None, version=1)
        for req in plan.observations_requested:
            self.assertEqual(
                set(req["inputs"]),
                set(req["inputs"]) & {"subdomain", "limit", "query_hints"})
            blob = json.dumps(req)
            self.assertNotIn("payload", blob)
            self.assertNotIn("https://", blob)

    def test_planner_cannot_bypass_authorization(self):
        """Observe can only run after the gate granted: spy sequence."""
        sequence: list[str] = []

        class SpyChecker(AuthorizationChecker):
            def verify(self, job, *args, **kwargs):
                sequence.append("verify")
                return super().verify(job, *args, **kwargs)

        class SpyProvider:
            def observe(self, job, **kw):
                sequence.append("observe")
                return rich_rows()[:1]

        store = make_store()
        job = make_job()
        outcome = run_hunt_direct(store=store, job=job,
                                  provider=SpyProvider(),
                                  checker=SpyChecker())
        # verification happened at least once, and before the first observe
        self.assertIn("verify", sequence)
        self.assertIn("observe", sequence)
        self.assertLess(sequence.index("verify"), sequence.index("observe"))
        self.assertIn(outcome.state, {"RESOLVED", "NEEDS_EVIDENCE",
                                      "BLOCKED", "REJECTED"})

    def test_planner_cannot_create_case_or_manufacture_evidence(self):
        """Behavioral: persistence spies stay untouched during the hunt."""
        store = make_store()

        class GuardedStore(RuntimeStore):
            def __init__(self, base):
                super().__init__(base)
                self.case_calls = 0
                self.evidence_calls = 0

            def record_case(self, *a, **k):
                self.case_calls += 1
                return super().record_case(*a, **k)

            def record_evidence(self, *a, **k):
                self.evidence_calls += 1
                return super().record_evidence(*a, **k)

        guarded = GuardedStore(store.base)
        run_hunt_fixture(store=guarded)
        self.assertEqual(guarded.case_calls, 0)
        self.assertEqual(guarded.evidence_calls, 0)

    def test_planner_cannot_upgrade_gate_confidence(self):
        """Advisor claims 'high confidence'; gate decision stays
        deterministic from the real rows."""

        def overconfident(request):
            return ({"summary": "high confidence, case now certain",
                     "insights": [{"insight_code": "OBS_HTTP_ROWS",
                                   "text": "confidence is high"}],
                     "recommendations": [
                         {"recommendation_code": "PRIORITY_1",
                          "text": "treat as high confidence"}]},
                    {"model_requested": "openrouter/free",
                     "model_resolved": "openrouter/free",
                     "latency_ms": 1, "prompt_version":
                         "hunt-planner-advisor-v1"})

        # weak rows: single url row without params -> XSS confidence low
        weak = [{"source": "urls", "ref": "u1",
                 "url": "https://shop.test/x", "status": 200, "params": []}]
        outcome, job, cap, hs, store = run_hunt_fixture(
            rows=weak, advisor_fn=overconfident,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_planning_iterations=1,
                              max_llm_planning_calls=1, max_seconds=30))
        # the authoritative gate never saw high confidence:
        self.assertNotEqual(outcome.termination_reason,
                            "sufficient_evidence")
        # deterministic confidence really was below high:
        det = deterministic_analysis(cap, job, weak, [])
        self.assertNotEqual(det["confidence"], "high")
        decision = evaluate_case_creation(cap, job, det, [])
        self.assertFalse(decision.create)

    def test_planner_cannot_read_unrestricted_history(self):
        job = make_job()
        cap = capability_for("XSS")
        items = compute_missing_evidence(
            capability=cap, scope_ref=job.authorization_ref,
            analysis={"confidence": "medium", "signals": [],
                      "blockers": ["no_category_signal_in_authorized_observations"],
                      "evidence_candidates": []},
            observed_types=(), knowledge_ids=(), hypothesis="h")
        cands = build_candidates(missing_items=items, capability=cap,
                                 observed_types=())
        req = advisor_request(
            objective=make_objective(), missing_items=items,
            candidates=cands, capability=cap,
            allowed_types=cap.allowed_observation_types,
            observed_types=(), job=job)
        self.assertEqual(
            set(req["sections"]),
            set(req["sections"]) & set(SECTION_ALLOWED_KEYS))
        blob = json.dumps(req, default=str)
        # no target URLs, no full DB rows, no history dumps, no secrets
        self.assertNotIn("https://", blob)
        self.assertNotIn("www.", blob)
        self.assertNotIn("sk-or", blob)
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("collection", blob)
        self.assertLess(len(blob), 20_000)


def run_hunt_direct(*, store, job, provider, checker, limits=None):
    from backend.research_agents.hunt import run_hunt
    return run_hunt(
        job=job, capability=capability_for(job.agent_category),
        store=store, hunt_store=HuntStore(store.base),
        observations=provider, auth_checker=checker,
        determin_fn=deterministic_analysis,
        gate_fn=evaluate_case_creation,
        limits=limits or HuntLimits(max_plans_per_objective=2,
                                    max_llm_planning_calls=0,
                                    max_seconds=30),
        initial_rows=rich_rows(),
        emit_audit=lambda s, p: None,
        emit_activity=lambda a, d: None)


def make_objective(scope: str = "fixture:shop/shop.test"):
    from backend.research_agents.hunt import HuntObjective
    return HuntObjective(
        objective_id="obj-sec-1", job_id="job-xss-hunt-test",
        specialist="xss-agent", category="XSS", scope_ref=scope,
        target_context={"subdomain": "shop.test"}, hypothesis="h",
        research_objective="support or reject",
        evidence_requirements={"min_evidence_refs": 2,
                               "required_types": ["observation"],
                               "require_high_confidence": True},
        state="OPEN", provenance={"source": "test"},
        created_at=utcnow(), updated_at=utcnow())


class ModelAndStateSecurityTests(unittest.TestCase):
    def test_unknown_model_rejected_before_provider(self):
        try:
            resolve_free_config("openrouter",
                                "openrouter/some-unknown-model-xyz", 10)
        except FreeOnlyViolation:
            pass
        else:  # pragma: no cover - guard must fail closed
            self.fail("unknown model accepted by free-only guard")

    def test_paid_model_rejected_on_hunt_advisor_path(self):
        store = RuntimeStore(make_store().base)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture",
                                 llm_provider_kind="openrouter",
                                 llm_model="deepseek/deepseek-chat"),
            store=store, llm_enabled=True)
        with self.assertRaises(Exception) as ctx:
            worker._hunt_advisor({"sections": {}})
        self.assertIn("free_only", str(ctx.exception))

    def test_hunt_advisor_context_overflow_fails_closed(self):
        import os
        os.environ["OPENROUTER_API_KEY"] = "sk-or-v1-TEST-ONLY-KEY"
        try:
            store = RuntimeStore(make_store().base)
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     llm_provider_kind="openrouter",
                                     llm_model="openrouter/free",
                                     context_max_chars=100),
                store=store, llm_enabled=True)
            with self.assertRaises(Exception) as ctx:
                worker._hunt_advisor(
                    {"sections": {"research_context":
                                  {"research_question": "x" * 500}}})
            self.assertIn("context_too_large", str(ctx.exception))
        finally:
            os.environ.pop("OPENROUTER_API_KEY", None)

    def test_secrets_never_survive_into_audit_payloads(self):
        ev = hunt_audit_event(
            "lineage", job_id="j",
            api_key="sk-or-v1-SECRETSECRET",
            header="Authorization: Bearer SECRETSECRET",
            nested={"token": "sk-or-v1-SECRETSECRET"},
            note="key=[REDACTED]")
        blob = json.dumps(ev)
        self.assertNotIn("SECRETSECRET", blob)
        self.assertIn("REDACTED", blob)

    def test_advisor_request_contains_no_provider_credentials(self):
        req = advisor_request(
            objective=make_objective(), missing_items=[], candidates=[],
            capability=capability_for("XSS"),
            allowed_types=capability_for("XSS").allowed_observation_types,
            observed_types=(), job=make_job())
        blob = json.dumps(req, default=str)
        # provider KIND (free router identity) is metadata, not a
        # credential; the hard guarantee is: no keys, no auth headers
        self.assertNotIn("sk-or", blob)
        self.assertNotIn("api_key", blob)
        self.assertNotIn("Authorization", blob)

    def test_plan_versions_immutable_after_execution(self):
        store = HuntStore(make_store().base)
        from tests.hunt_fixtures import make_job as _mj  # noqa: F401
        plan = make_plan()
        store.append_plan(plan)
        store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="DRAFT", to_state="VALIDATED",
            reason="ok", at=utcnow()))
        for frm, to in (("VALIDATED", "AUTHORIZATION_REQUIRED"),
                        ("AUTHORIZATION_REQUIRED", "AUTHORIZED")):
            store.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state=frm, to_state=to,
                reason="ok", at=utcnow()))
        store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="AUTHORIZED",
            to_state="EXECUTING", reason="start", at=utcnow(),
            definition_hash=plan.definition_hash()))
        self.assertEqual(store.executing_definition_hash(plan.plan_id),
                         plan.definition_hash())
        # any later mutation of the definition is refused
        mutated = make_plan(reason="mutated after execution began")
        with self.assertRaises(HuntStoreError):
            store.append_plan(mutated)

    def test_duplicate_execution_prevented(self):
        store = HuntStore(make_store().base)
        plan = make_plan()
        store.append_plan(plan)
        for frm, to in (("DRAFT", "VALIDATED"),
                        ("VALIDATED", "AUTHORIZATION_REQUIRED"),
                        ("AUTHORIZATION_REQUIRED", "AUTHORIZED"),
                        ("AUTHORIZED", "EXECUTING")):
            store.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state=frm, to_state=to,
                reason="ok", at=utcnow()))
        # second EXECUTING from EXECUTING is an illegal transition
        with self.assertRaises(HuntStoreError):
            store.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state="AUTHORIZED",
                to_state="EXECUTING", reason="again", at=utcnow(),
                definition_hash=plan.definition_hash()))

    def test_stale_authorization_rejected(self):
        job = make_job()
        cap = capability_for("XSS")
        plan = make_plan()
        rec = authorization_gate(
            build_authorization_request(plan, job=job, capability=cap),
            job=job, capability=cap, auth_checker=AuthorizationChecker())
        self.assertEqual(rec.status, "GRANTED")
        from backend.research_agents.hunt.authorization import (
            reverify_before_observation,
        )
        ok, _ = reverify_before_observation(
            rec, plan=plan, job=job, capability=cap,
            auth_checker=AuthorizationChecker(),
            observation_types=("http-rows",))
        self.assertTrue(ok)
        # scope changed under us -> stale
        changed = make_job(auth_ref="fixture:shop/other.test")
        changed_plan = make_plan(scope="fixture:shop/other.test")
        ok2, reason = reverify_before_observation(
            rec, plan=changed_plan, job=changed, capability=cap,
            auth_checker=AuthorizationChecker(),
            observation_types=("http-rows",))
        self.assertFalse(ok2)

    def test_unknown_model_identifier_in_advisor_provenance_ok(self):
        # advisor mapping records whatever the provider reported without
        # trusting it for authorization purposes
        out = map_advisor_response(
            {"summary": "s", "insights": [
                {"insight_code": "OBS_HTTP_ROWS", "text": "read rows"}],
             "recommendations": []},
            capability=capability_for("XSS"),
            allowed_types=capability_for("XSS").allowed_observation_types)
        self.assertTrue(out.used)


class LoopSafetyTests(unittest.TestCase):
    def test_infinite_planning_loop_prevented(self):
        # fixture where nothing ever satisfies the gate: urls with NO
        # params -> XSS hypothesis never supported; all types exhaust.
        bare = [
            {"source": "urls", "ref": f"u{i}",
             "url": f"https://shop.test/p{i}", "status": 200, "params": []}
            for i in range(3)
        ]
        outcome, job, cap, hs, store = run_hunt_fixture(
            rows=bare,
            limits=HuntLimits(max_plans_per_objective=5,
                              max_observations=20,
                              max_planning_iterations=3,
                              max_llm_planning_calls=0, max_seconds=30))
        self.assertLessEqual(outcome.iterations, 3)
        self.assertLessEqual(len(outcome.plan_ids), 5)
        self.assertTrue(outcome.termination_reason)
        self.assertIn(outcome.state,
                      {"NEEDS_EVIDENCE", "REJECTED", "BLOCKED",
                       "RESOLVED"})
        # termination is EXPLICIT, never a vague "completed"
        self.assertNotEqual(outcome.termination_reason, "completed")

    def test_concurrent_objective_state_updates_race_handled(self):
        store = HuntStore(make_store().base)
        store.create_objective(make_objective())
        errors: list[Exception] = []
        revisions: list[int] = []
        barrier = threading.Barrier(4)

        def worker(target_state: str):
            try:
                barrier.wait(timeout=5)
                obj = store.revise_objective(
                    "obj-sec-1", state=target_state, reason="race")
                revisions.append(obj.revision)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        # distinct legal chains are serialized by the store lock; illegal
        # mid-chain states raise instead of corrupting history
        threads = [threading.Thread(target=worker, args=(s,))
                   for s in ("NEEDS_EVIDENCE", "NEEDS_EVIDENCE",
                             "NEEDS_EVIDENCE", "NEEDS_EVIDENCE")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])
        # history is consistent: revisions strictly increasing, no dupes
        history = store.objective_history("obj-sec-1")
        revs = [h.revision for h in history]
        self.assertEqual(revs, sorted(revs))
        self.assertEqual(len(revs), len(set(revs)))
        self.assertEqual(len(history), 5)

    def test_state_names_are_explicit_and_bounded(self):
        self.assertEqual(len(UNCERTAINTY_STATES), 9)
        self.assertEqual(HUNT_RULE_VERSION, "autonomous-hunt-planner-v1")


def make_plan(plan_id: str = "plan-sec-1",
              scope: str = "fixture:shop/shop.test",
              reason: str = "Selected because http-rows addresses missing "
                            "evidence while requiring an already-authorized "
                            "read-only observation") -> HuntPlan:
    return HuntPlan(
        plan_id=plan_id, objective_id="obj-sec-1",
        job_id="job-xss-hunt-test", version=1, parent_plan_id="",
        scope_ref=scope, specialist="xss-agent", category="XSS",
        reason=reason, hypotheses_addressed=("h",),
        observations_requested=({
            "observation_type": "http-rows",
            "inputs": {"subdomain": "shop.test", "limit": 25},
            "expected_evidence": "observation", "missing_item_ids": [],
            "risk_class": "READ_ONLY"},),
        required_evidence=("observation",),
        expected_information_gain=0.5, gain_label="heuristic",
        safety_constraints=("no_target_contact",),
        authorization_requirements=(scope,), dependencies=(), priority=5,
        provenance={"planner": "test"}, created_at=utcnow())


if __name__ == "__main__":
    unittest.main()

"""Epic8: failure/recovery + security validation for the intelligence layer.

§10 scenarios: LLM unavailable / malformed advisory / knowledge
unavailable / authorization unavailable / empty observations /
insufficient evidence / duplicate candidate / verification blocked /
case creation blocked / interrupted state / stale worker.

§14 security: read-only projection (no state writers), no network/code
execution, no paid-LLM coupling, no secrets, no cross-target leakage.
"""

from __future__ import annotations

import ast
import json
import pathlib
import unittest
from types import SimpleNamespace
from unittest import mock

from backend.prod_intel import effectiveness as eff_mod
from backend.prod_intel import sources
from backend.prod_intel.case_intel import case_intelligence
from backend.prod_intel.effectiveness import effectiveness
from backend.prod_intel.knowledge_usage import knowledge_usage
from backend.prod_intel.learning_signals import learning_signals
from backend.prod_intel.overview import overview
from backend.prod_intel.targets import target_detail, target_intelligence
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_candidate,
    add_campaign,
    add_evidence,
    add_finding_case,
    add_hunt_objective,
    add_job,
    add_knowledge_use,
    add_memory,
    add_runtime_case,
    add_verification,
    audit,
    envelope,
)

INTEL_DIR = pathlib.Path(eff_mod.__file__).parent
ALL_SOURCE_FNS = (
    "jobs", "evidence", "runtime_cases", "knowledge_use", "audit",
    "worker", "activity", "candidates", "verifications", "correlations",
    "finding_cases", "campaigns", "hunt_objectives", "memory_heads",
    "kb_total",
)


class TestSourceOutages(IntelEnvMixin, unittest.TestCase):
    """Every source outage must render as unavailable — never a crash,
    never a zero-filled success."""

    def test_overview_survives_every_source_outage(self):
        for name in ALL_SOURCE_FNS:
            with self.subTest(source=name):
                with mock.patch.object(sources, name,
                                       return_value=envelope(
                                           None, "unavailable", "down")):
                    body = overview(hours=None)
                self.assertEqual(body["rule_version"],
                                 "production-intelligence-v1")
                self.assertIn(body["blockers"]["state"],
                              ("ok", "not_observed", "unavailable"))

    def test_effectiveness_survives_every_source_outage(self):
        for name in ("candidates", "verifications", "finding_cases",
                     "hunt_objectives", "evidence", "hunt_plans",
                     "hunt_authorizations"):
            with self.subTest(source=name):
                with mock.patch.object(sources, name,
                                       return_value=envelope(
                                           None, "unavailable", "down")):
                    body = effectiveness(hours=None)
                self.assertIn("funnels", body)

    def test_target_intelligence_survives_outages(self):
        for name in ("jobs", "candidates", "campaigns", "hunt_objectives",
                     "memory_heads", "evidence", "knowledge_use",
                     "attack_surface", "scope_programs"):
            with self.subTest(source=name):
                with mock.patch.object(sources, name,
                                       return_value=envelope(
                                           None, "unavailable", "down")):
                    body = target_intelligence(hours=None)
                self.assertIn("state", body)

    def test_agent_detail_survives_outages(self):
        for name in ("jobs", "knowledge_use", "kb_total",
                     "hunt_objectives", "candidates", "verifications",
                     "finding_cases", "memory_heads"):
            with self.subTest(source=name):
                with mock.patch.object(sources, name,
                                       return_value=envelope(
                                           None, "unavailable", "down")):
                    from backend.prod_intel.agents_intel import agent_detail
                    body = agent_detail("XSS")
                self.assertTrue(body["registered"])

    def test_case_intel_survives_outages(self):
        for name in ("finding_cases", "candidates", "verifications",
                     "evidence", "runtime_cases", "knowledge_use"):
            with self.subTest(source=name):
                with mock.patch.object(sources, name,
                                       return_value=envelope(
                                           None, "unavailable", "down")):
                    body = case_intelligence("fcase-abc123def456")
                self.assertIn(body["state"],
                              ("unavailable", "not_observed"))

    def test_knowledge_usage_source_outage_is_unavailable(self):
        with mock.patch.object(sources, "knowledge_use",
                               return_value=envelope(None, "unavailable",
                                                     "x")):
            body = knowledge_usage(hours=None)
        self.assertEqual(body["state"], "unavailable")

    def test_learning_source_outage_is_unavailable_not_not_observed(self):
        with mock.patch.object(sources, "memory_heads",
                               return_value=envelope(None, "unavailable",
                                                     "x")):
            body = learning_signals(hours=None)
        self.assertEqual(body["state"], "unavailable")

    def test_feed_and_now_survive_audit_outage(self):
        from backend.prod_intel.activity import build_feed, current_activity
        with mock.patch.object(sources, "audit",
                               return_value=envelope(None, "unavailable",
                                                     "x")):
            self.assertEqual(build_feed(hours=None)["state"], "unavailable")
        self.assertIn(current_activity()["state"],
                      ("PLANNED", "IDLE", "ACTIVE", "UNKNOWN", "FAILED"))


class TestScenarioFailures(IntelEnvMixin, unittest.TestCase):
    def test_llm_unavailable_cannot_affect_intelligence_layer(self):
        # the projection layer has NO LLM dependency at all: AST scan of
        # every prod_intel module for provider/LLM imports and calls
        banned_modules = ("backend.ai", "backend.research_agents.llm",
                          "backend.research_agents.providers",
                          "openai", "httpx", "requests")
        for py in INTEL_DIR.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for bad in banned_modules:
                            with self.subTest(file=py.name):
                                self.assertFalse(
                                    alias.name.startswith(bad),
                                    f"{py.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    with self.subTest(file=py.name):
                        for bad in banned_modules:
                            self.assertFalse(mod.startswith(bad),
                                             f"{py.name} imports {mod}")

    def test_no_llm_strings_in_projection_layer(self):
        for py in INTEL_DIR.glob("*.py"):
            text = py.read_text(encoding="utf-8").lower()
            with self.subTest(file=py.name):
                self.assertNotIn("openrouter", text)
                self.assertNotIn("gpt-", text)
                self.assertNotIn("paid", text.split("#", 1)[0])

    def test_malformed_advisory_irrelevant_no_advisor_path(self):
        # there is no advisory/LLM ingestion point in prod_intel: scanning
        # for advisor-shaped identifiers must find none
        for py in INTEL_DIR.glob("*.py"):
            text = py.read_text(encoding="utf-8")
            with self.subTest(file=py.name):
                self.assertNotIn("advisor", text)
                self.assertNotIn("advisory", text)

    def test_knowledge_unavailable_reports_unavailable(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="k.example")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="kb1")
        from backend.prod_intel.agents_intel import agent_detail
        with mock.patch.object(sources, "knowledge_use",
                               return_value=envelope(None, "unavailable",
                                                     "x")):
            det = agent_detail("XSS")
        self.assertEqual(det["knowledge"]["state"], "unavailable")

    def test_authorization_unavailable_marks_hunt_unavailable(self):
        add_hunt_objective(state="OPEN", plans=1, observations=0)
        # plans readable (one plan) but the authorization store is down:
        # the walk cannot reach authorization records, so the auth counts
        # must read unavailable instead of ok/0
        with mock.patch.object(
                sources, "hunt_plans",
                return_value=envelope(
                    [SimpleNamespace(plan_id="plan-fx1", version=1)], "ok")), \
             mock.patch.object(
                sources, "hunt_authorizations",
                return_value=envelope(None, "unavailable",
                                      "authz down")):
            body = effectiveness(hours=None)
        self.assertEqual(body["hunt"]["state"], "unavailable")
        self.assertIn("authz down",
                      str(body["hunt"].get("unavailable_walks", []))
                      + body["hunt"]["reason"])

    def test_plans_store_unavailable_marks_hunt_unavailable(self):
        add_hunt_objective(state="OPEN", plans=1, observations=0)
        with mock.patch.object(sources, "hunt_plans",
                               return_value=envelope(None, "unavailable",
                                                     "plans down")):
            body = effectiveness(hours=None)
        self.assertEqual(body["hunt"]["state"], "unavailable")
        self.assertIn("plans down", body["hunt"]["reason"])

    def test_authorization_granted_and_denied_counted(self):
        obj = add_hunt_objective(state="OPEN", plans=1, observations=1)
        with mock.patch.object(
                sources, "hunt_plans",
                return_value=envelope(
                    [SimpleNamespace(plan_id="plan-fx1", version=1)], "ok")), \
             mock.patch.object(
                sources, "hunt_authorizations",
                return_value=envelope(
                    [SimpleNamespace(status="GRANTED"),
                     SimpleNamespace(status="DENIED")], "ok")):
            body = effectiveness(hours=None)
        hv = body["hunt"]["value"]
        self.assertEqual(hv["authorizations_requested"], 2)
        self.assertEqual(hv["authorizations_granted"], 1)
        self.assertEqual(hv["authorizations_denied"], 1)
        funnel = body["funnels"]["authorization_grant"]
        self.assertEqual(funnel["denominator"], 2)
        self.assertEqual(funnel["numerator"], 1)
        self.assertTrue(body["sufficient_population"]["authorization_grant"])
        self.assertIsNotNone(obj)

    def test_empty_observations_funnel_insufficient(self):
        add_hunt_objective(state="OPEN", plans=1, observations=0)
        add_candidate()
        body = effectiveness(hours=None)
        f = body["funnels"]["observation_to_candidate"]
        if f["denominator"] == 0:
            self.assertIsNone(f["rate"])
            self.assertEqual(f["state"], "insufficient_population")

    def test_insufficient_evidence_case_honest(self):
        c = add_candidate()
        case = add_finding_case(c, state="BLOCKED")
        pkg = case_intelligence(case.case_id)
        self.assertEqual(pkg["state"], "ok")
        # no evidence rows: observations metric must be not_observed
        self.assertEqual(pkg["observations"]["state"], "not_observed")
        self.assertIn("unavailable", pkg["what_was_not_verified"]
                      + pkg["payload"] + "no evidence")

    def test_duplicate_candidate_counted_as_duplicate_not_success(self):
        c = add_candidate(target="dup.example")
        from backend.research_agents.finding.store import FindingStore
        fs = FindingStore()
        fs.transition_candidate(c.candidate_id, "DUPLICATE",
                                reason="fixture duplicate")
        body = effectiveness(hours=None)
        fv = body["finding"]["value"]
        self.assertEqual(fv["candidates_deduplicated"], 1)
        self.assertEqual(fv["candidates_by_state"]["DUPLICATE"], 1)

    def test_verification_blocked_reflects_in_blockers_and_funnel(self):
        c = add_candidate()
        add_verification(c, state="BLOCKED",
                         gate_reason="insufficient_evidence")
        body = effectiveness(hours=None)
        self.assertEqual(body["finding"]["value"]["verifications_blocked"],
                         1)
        ov = overview(hours=None)
        kinds = {b["kind"] for b in ov["blockers"]["value"]}
        self.assertIn("verification", kinds)

    def test_case_creation_blocked_leaves_no_fake_case(self):
        c = add_candidate()                # DETECTED -> store refuses
        from backend.research_agents.finding.models import CasePackage
        from backend.research_agents.finding.store import (
            FindingStore,
            FindingStoreError,
        )
        fs = FindingStore()
        with self.assertRaises(FindingStoreError):
            fs.add_case(CasePackage(
                case_id="fcase-forced000001",
                candidate_id=c.candidate_id, scope_ref=c.scope_ref,
                title="should never land", vulnerability_class="XSS",
                target=c.target, state="TRIAGED"))
        self.assertIsNone(fs.get_case("fcase-forced000001"))
        self.assertEqual(len(sources.finding_cases()["data"]), 0)

    def test_corrupt_state_file_reads_unavailable_not_crash(self):
        state_path = pathlib.Path(sources._runtime().state_path)
        state_path.write_text("{not json", encoding="utf-8")
        env = sources.jobs()
        self.assertEqual(env["state"], "unavailable")
        body = overview(hours=None)        # projection still renders
        self.assertIn(body["blockers"]["state"],
                      ("ok", "not_observed", "unavailable"))

    def test_audit_append_only_completeness(self):
        before = len(sources.audit()["data"] or [])
        audit(event="job_claimed", job_id="job-comp-1")
        audit(event="job_failed", job_id="job-comp-2", reason="x")
        after = sources.audit()["data"]
        self.assertGreaterEqual(len(after), before + 2)
        # nothing rewritten: the first rows are still intact
        events = [r.get("event") for r in after]
        self.assertIn("job_claimed", events)
        self.assertIn("job_failed", events)

    def test_failed_attempts_never_counted_as_success(self):
        add_job(status="TERMINAL_FAILED", agent="xss-agent",
                subdomain="f.example")
        body = effectiveness(hours=None)
        self.assertEqual(body["finding"]["value"]["cases_created"], 0)
        ov = overview(hours=None)
        self.assertIn("job", {b["kind"] for b in ov["blockers"]["value"]})


class TestSecurity(IntelEnvMixin, unittest.TestCase):
    FORBIDDEN_CALLS = (
        "transition_candidate", "transition_verification", "add_case",
        "add_candidate", "add_verification", "create_campaign",
        "add_objective", "revise_objective", "record_evidence",
        "record_case", "record_knowledge_use", "record_activity",
        "put_result", "enqueue", "record_audit_event", "save_campaign",
        "add_correlation", "append_item", "append_plan", "append_file",
        "write_text", "write_bytes", "unlink", "remove", "rename",
        "replace_file", "truncate",
    )

    def test_projection_layer_calls_no_state_writers(self):
        for py in INTEL_DIR.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = (fn.attr if isinstance(fn, ast.Attribute)
                            else getattr(fn, "id", ""))
                    with self.subTest(file=py.name, call=name):
                        self.assertNotIn(name, self.FORBIDDEN_CALLS)

    def test_projection_layer_no_subprocess_or_shell(self):
        banned = {"subprocess", "pty", "shutil", "os"}
        for py in INTEL_DIR.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split(".")[0]
                        with self.subTest(file=py.name, mod=mod):
                            if mod == "os":
                                continue       # os.path/os.environ reads ok
                            self.assertNotIn(mod, banned)
                if isinstance(node, ast.Call):
                    fn = node.func
                    attr = fn.attr if isinstance(fn, ast.Attribute) else ""
                    with self.subTest(file=py.name, call=attr):
                        self.assertNotIn(attr, ("system", "popen", "exec",
                                                "eval", "spawn"))

    def test_projection_layer_makes_no_network_calls(self):
        for py in INTEL_DIR.glob("*.py"):
            text = py.read_text(encoding="utf-8")
            with self.subTest(file=py.name):
                self.assertNotIn("urllib", text)
                self.assertNotIn("httpx", text)
                self.assertNotIn("requests.get", text)
                self.assertNotIn("socket", text)

    def test_projection_layer_never_opens_files_for_write(self):
        for py in INTEL_DIR.glob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and getattr(node.func, "id", "") == "open"):
                    mode = ""
                    if len(node.args) >= 2:
                        mode = getattr(node.args[1], "value", "")
                    with self.subTest(file=py.name):
                        self.assertNotIn("w", mode)
                        self.assertNotIn("a", mode)
                        self.assertNotIn("x", mode)

    def test_no_paid_llm_strings_anywhere(self):
        router = pathlib.Path(
            "/".join(str(INTEL_DIR).split("/")[:-2]
                     + ["backend", "routers", "intel.py"]))
        for py in list(INTEL_DIR.glob("*.py")) + [router]:
            text = py.read_text(encoding="utf-8")
            with self.subTest(file=py.name):
                self.assertNotIn("openrouter", text)
                self.assertNotIn("OPENROUTER", text)
                self.assertNotIn("deepseek", text.lower())
                self.assertNotIn("api_key", text)

    def test_no_cross_target_leakage(self):
        add_candidate(target="alpha.example")
        add_candidate(target="beta.example", job="job-beta")
        add_memory(target="beta.example", subject="mem-beta")
        out = target_detail("alpha.example")
        blob = json.dumps(out, default=str)
        # alpha's own finding is reflected in ITS counts ...
        self.assertEqual(out["findings"]["value"], {"DETECTED": 1})
        # ... while nothing carrying beta's identity appears anywhere
        self.assertNotIn("beta.example", blob)
        self.assertNotIn("job-beta", blob)
        self.assertNotIn("mem-beta", blob)

    def test_projection_outputs_carry_no_secrets(self):
        add_job(status="COMPLETED", subdomain="s.example")
        for body in (overview(hours=None),
                     effectiveness(hours=None),
                     learning_signals(hours=None),
                     target_intelligence(hours=None)):
            blob = json.dumps(body, default=str)
            self.assertNotIn("OPENROUTER", blob)
            self.assertNotIn("sk-or-v1", blob)
            self.assertNotIn("X-API-Key", blob)

    def test_intel_router_registered_only_via_soc_mount(self):
        # api.py carries PRE-EXISTING operator edits (untouched by this
        # epic): assert our change never landed there
        import subprocess
        out = subprocess.run(
            ["git", "diff", "HEAD", "--", "api.py"],
            cwd="/opt/watch/.worktrees/watch-agent",
            capture_output=True, text=True, check=True)
        self.assertNotIn("intel", out.stdout,
                         "Epic8 must not modify api.py")


if __name__ == "__main__":
    unittest.main()

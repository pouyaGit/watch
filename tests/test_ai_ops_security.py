"""EPIC9 §21: security posture of the AI operations dispatcher."""

from __future__ import annotations

import ast
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ai_ops.discovery import (
    NOT_AUTHORIZED, classify_hunt_objective, classify_campaign_objective,
)
from tests.ai_ops_fixtures import (
    AiOpsEnvMixin, SCOPE, make_campaign, make_hunt, make_objective,
)

REPO = Path(__file__).resolve().parents[1]
AI_OPS_FILES = sorted((REPO / "backend/ai_ops").glob("*.py"))

# 18:00 Tehran = window OPEN (same instant as the dispatcher suite).
OPEN = datetime(2026, 9, 23, 14, 30, tzinfo=timezone.utc)

BANNED_IMPORTS = {
    "subprocess", "socket", "urllib", "http", "requests", "httpx",
    "ssl", "ftplib", "smtplib", "telnetlib", "xmlrpc",
}
BANNED_CALLS = {"eval", "exec", "__import__", "compile"}
# Fragment literals: never embed a contiguous credential-shaped token
# in source (SECRET_CONTENT guard) — assembled at runtime instead.
BANNED_TEXT = ("sk" + "-or" + "-", "OPENROUTER_API_KEY", "api_key=",
               "advisor_fn", "llm_provider", "openrouter", "deepseek",
               "nvidia", "gpt-4", "shell=True", "os.system")


def sources() -> dict[str, str]:
    return {f.name: f.read_text() for f in AI_OPS_FILES}


class ImportBoundaryTests(unittest.TestCase):

    def test_no_network_or_process_imports(self):
        for path in AI_OPS_FILES:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        self.assertNotIn(
                            root, BANNED_IMPORTS,
                            msg=f"{path.name} imports {root}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    self.assertNotIn(
                        root, BANNED_IMPORTS,
                        msg=f"{path.name} imports {node.module}")

    def test_no_dynamic_code_execution(self):
        for name, text in sources().items():
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and \
                        isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, BANNED_CALLS,
                                     msg=f"{name} calls {node.func.id}")

    def test_no_llm_or_secret_text_anywhere_in_ai_ops(self):
        for name, text in sources().items():
            for token in BANNED_TEXT:
                self.assertNotIn(
                    token.lower(), text.lower(),
                    msg=f"{name} contains {token}")


class DiscoveryIsReadOnlyTests(unittest.TestCase):

    def test_discovery_never_writes_domain_state(self):
        text = (REPO / "backend/ai_ops/discovery.py").read_text()
        banned = ("record_evidence(", "record_observation(",
                  "append_observation(", "transition_objective(",
                  "transition_campaign(", "transition_candidate(",
                  "enqueue(", "add_candidate(", "create_objective(",
                  "retry_or_terminal(", "release(", "save_candidate(")
        for token in banned:
            self.assertNotIn(token, text,
                             msg=f"discovery.py performs {token}")

    def test_dispatcher_only_sanctioned_writes(self):
        text = (REPO / "backend/ai_ops/dispatcher.py").read_text()
        banned = ("record_evidence(", "transition_objective(",
                  "transition_campaign(", "transition_candidate(",
                  "retry_or_terminal(")
        for token in banned:
            self.assertNotIn(token, text,
                             msg=f"dispatcher.py performs {token}")
        # sanctioned recovery + activity remain allowed:
        self.assertIn("sweep(", text)


class EvidenceGateNonBypassTests(AiOpsEnvMixin):

    def test_needs_evidence_hunt_stays_blocked_and_unchanged(self):
        from backend.research_agents.hunt.store import HuntStore
        store = HuntStore()
        obj = make_hunt(objective_id="hobj-sec",
                        state="NEEDS_EVIDENCE")
        store.create_objective(obj)
        # classification is permanently non-executable
        item = classify_hunt_objective(store.get_objective("hobj-sec"))
        self.assertFalse(item.executable)
        self.assertEqual(item.reason, "WAITING_FOR_EVIDENCE")

    def test_evidence_gate_is_never_referenced_by_dispatcher(self):
        for name, text in sources().items():
            self.assertNotIn("evidence_rules_met", text, msg=name)
            self.assertNotIn("EvidenceGate", text, msg=name)

    def test_needs_evidence_objective_not_executable_after_full_tick(
            self):
        from backend.ai_ops.dispatcher import run_tick
        from backend.research_agents.hunt.store import HuntStore
        HuntStore().create_objective(
            make_hunt(objective_id="hobj-keep",
                      state="NEEDS_EVIDENCE"))
        rec = run_tick(config=self.config(enabled=True),
                       now_fn=lambda: OPEN, runners={})
        self.assertNotIn("objective:hobj-keep",
                         rec.get("selected", []))
        after = HuntStore().get_objective("hobj-keep")
        self.assertEqual(after.state, "NEEDS_EVIDENCE")


class AuthorizationScopeTests(AiOpsEnvMixin):

    def test_corrupt_campaign_scope_is_not_authorized(self):
        camp = make_campaign(scope_ref=SCOPE)
        obj = make_objective(scope_ref=SCOPE)
        object.__setattr__(camp, "scope_ref", "attacker:scope:x")
        item = classify_campaign_objective(
            camp, obj, {obj.objective_id: obj})
        self.assertEqual(item.reason, NOT_AUTHORIZED)
        self.assertFalse(item.executable)

    def test_corrupt_objective_scope_is_not_authorized(self):
        camp = make_campaign(scope_ref=SCOPE)
        obj = make_objective(scope_ref=SCOPE)
        object.__setattr__(obj, "scope_ref", "")
        item = classify_campaign_objective(
            camp, obj, {obj.objective_id: obj})
        self.assertEqual(item.reason, NOT_AUTHORIZED)

    def test_corrupt_scope_never_reaches_a_runner(self):
        from backend.ai_ops.dispatcher import run_tick
        from backend.research_agents.campaign.store import CampaignStore
        cs = CampaignStore()
        camp = make_campaign()
        cs.create_campaign(camp)
        obj = make_objective()
        cs.add_objective(obj)
        # corrupt the PERSISTED row the way damaged data would
        stored = cs.get_campaign(camp.campaign_id)
        object.__setattr__(stored, "scope_ref", "evil:scope:1")
        cs.save_campaign(stored)
        called: list[str] = []
        rec = run_tick(
            config=self.config(enabled=True), now_fn=lambda: OPEN,
            runners={"CAMPAIGN_OBJECTIVE":
                     lambda i, b: (called.append(i.work_id),
                                   {"executed": 1})[1]})
        self.assertEqual(called, [])
        self.assertEqual(rec.get("selected"), [])
        # The store itself refuses to enumerate a corrupt-scope row
        # (CampaignScopeError on load) -> source error recorded; the
        # classifier would say NOT_AUTHORIZED as belt. Either layer
        # fail-closes; the corrupt row NEVER reaches a runner.
        self.assertTrue(
            rec.get("errors")
            or any(r.get("reason") == NOT_AUTHORIZED
                   for r in rec.get("remaining", [])),
            msg=f"no fail-closed layer fired: {rec}")


class CrossScopeIsolationTests(AiOpsEnvMixin):

    def test_targets_keep_their_own_scope_through_execution(self):
        from backend.ai_ops.dispatcher import run_tick
        from backend.research_agents.campaign.store import CampaignStore
        cs = CampaignStore()
        for cid, scope in (("camp-A", "watch:scope:aaa.example.com"),
                           ("camp-B", "watch:scope:bbb.example.com")):
            cs.create_campaign(make_campaign(campaign_id=cid,
                                              scope_ref=scope))
            cs.add_objective(make_objective(
                campaign_id=cid, objective_id=f"obj-{cid}",
                scope_ref=scope))
        seen: list[tuple[str, str]] = []
        run_tick(config=self.config(enabled=True, max_per_target=1,
                                    max_per_campaign=1),
                 now_fn=lambda: OPEN,
                 runners={"CAMPAIGN_OBJECTIVE":
                          lambda i, b: (seen.append(
                              (i.campaign_id, i.scope_ref)),
                              {"executed": 1})[1]})
        # one per campaign max, each with ITS OWN scope — no blending
        self.assertEqual(len(seen), 2)
        scopes = dict(seen)
        self.assertEqual(scopes["camp-A"], "watch:scope:aaa.example.com")
        self.assertEqual(scopes["camp-B"], "watch:scope:bbb.example.com")

    def test_jobs_carry_their_own_target_scope(self):
        from backend.ai_ops.discovery import classify_job
        from tests.ai_ops_fixtures import make_job
        a = classify_job(make_job("job-1", program="www",
                                  subdomain="a.example.com"))
        b = classify_job(make_job("job-2", program="www",
                                  subdomain="b.example.com"))
        self.assertNotEqual(a.scope_ref, b.scope_ref)
        self.assertIn("a.example.com", a.scope_ref)


if __name__ == "__main__":
    unittest.main()

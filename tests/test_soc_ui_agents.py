"""SOC-2 — AI Agent intelligence pages (RED phase).

Every registered AI agent gets a page /ui/soc/agents/{slug} that shows:
1. identity   — name, purpose, role, current status
2. knowledge  — vulnerability areas, techniques, frameworks, prior topics
3. history    — papers/articles, CVEs analyzed, internal notes, timestamps
4. target cases — target, endpoint, issue category, evidence status
All data must come from real existing sources (registry, memory store,
knowledge store, research loop files, AEC case views).  No fabricated
values, no secrets, bounded output.
"""

from __future__ import annotations

import unittest

# Sources the adapter may legitimately read (asserted indirectly through
# payload shapes below).  The adapter lives in backend/soc/agents.py.


class TestAgentIndex(unittest.TestCase):
    def test_agents_payload_has_registered_agents(self):
        from backend.soc import agents as soc_agents

        payload = soc_agents.agents_index()
        self.assertGreaterEqual(payload["count"], 5)
        names = {a["name"] for a in payload["agents"]}
        self.assertIn("XSS Research Agent", names)
        self.assertIn("IDOR Research Agent", names)

    def test_agent_rows_carry_identity_fields(self):
        from backend.soc import agents as soc_agents

        for agent in soc_agents.agents_index()["agents"]:
            for key in ("slug", "name", "purpose", "role", "status",
                        "queue", "active_jobs", "job_count", "available"):
                self.assertIn(key, agent, f"{agent.get('name')} missing {key}")
            self.assertTrue(agent["slug"].endswith("-agent"), agent["slug"])

    def test_agent_slugs_are_unique_and_resolvable(self):
        from backend.soc import agents as soc_agents

        slugs = [a["slug"] for a in soc_agents.agents_index()["agents"]]
        self.assertEqual(len(slugs), len(set(slugs)))
        for slug in slugs:
            detail = soc_agents.agent_detail(slug)
            self.assertIsNotNone(detail, slug)
            self.assertEqual(detail["identity"]["slug"], slug)

    def test_unknown_slug_returns_none(self):
        from backend.soc import agents as soc_agents

        self.assertIsNone(soc_agents.agent_detail("no-such-agent"))
        self.assertIsNone(soc_agents.agent_detail(""))
        self.assertIsNone(soc_agents.agent_detail("xss"))  # must be xss-agent


class TestAgentDetail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import agents as soc_agents

        cls.xss = soc_agents.agent_detail("xss-agent")
        cls.any = soc_agents.agents_index()
        cls.detail = soc_agents.agent_detail(cls.any["agents"][0]["slug"])

    def test_identity_block_present(self):
        identity = self.detail["identity"]
        for key in ("slug", "name", "purpose", "role", "status",
                    "key", "description"):
            self.assertIn(key, identity)

    def test_knowledge_block_shape(self):
        knowledge = self.detail["knowledge"]
        for key in ("vulnerability_areas", "techniques", "frameworks",
                    "topics"):
            self.assertIn(key, knowledge)
            self.assertIsInstance(knowledge[key], list)

    def test_history_block_shape(self):
        history = self.detail["history"]
        for key in ("papers", "cves", "notes"):
            self.assertIn(key, history)
            self.assertIsInstance(history[key], list)
        for entry in history["cves"]:
            self.assertIn("id", entry)
            self.assertIn("status", entry)

    def test_target_cases_block_shape(self):
        cases = self.detail["target_cases"]
        self.assertIsInstance(cases, list)
        for case in cases:
            for key in ("case_id", "target", "category",
                        "evidence_status", "detail_url"):
                self.assertIn(key, case, case)

    def test_xss_agent_knowledge_is_grounded(self):
        knowledge = self.xss["knowledge"]
        self.assertIsInstance(knowledge["vulnerability_areas"], list)
        # knowledge must come from the real agent definition: XSS agent
        # declares evidence types / strategy in backend/research_agents
        joined = " ".join(str(x) for x in (
            knowledge["vulnerability_areas"] + knowledge["techniques"]))
        self.assertTrue(joined.strip(), "xss knowledge unexpectedly empty")

    def test_history_has_no_secret_fields(self):
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower() in ("password", "cookie", "authorization",
                                     "api_key", "secret", "token"):
                        self.fail(f"secret-shaped key {k} in agent payload")
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
        walk(self.detail)


class TestAgentRouting(unittest.TestCase):
    def test_agent_page_route_resolves_slug(self):
        from backend.routers import soc

        # handler must exist and accept the slug parameter
        self.assertTrue(hasattr(soc, "ui_soc_agent_detail"))
        import inspect
        sig = inspect.signature(soc.ui_soc_agent_detail)
        self.assertIn("slug", sig.parameters)


if __name__ == "__main__":
    unittest.main()
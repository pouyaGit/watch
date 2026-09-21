"""SOC-4 — AI Activity / Mission Control (RED phase).

/ui/soc/activity answers "what is AI doing right now" using existing
orchestrator/runtime data: research-agent jobs, research loop files
(CVEs analyzed), investigation memory, AEC execution-run transitions,
and the real ai-knowledge activity status.  No fake data.
"""

from __future__ import annotations

import unittest


class TestActivityPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import activity as soc_activity

        cls.payload = soc_activity.activity_payload()

    def test_counts_block(self):
        counts = self.payload["counts"]
        for key in ("running_agents", "queued_jobs", "completed_jobs",
                    "blocked_jobs", "waiting_review"):
            self.assertIn(key, counts, f"missing {key}")
            self.assertIsInstance(counts[key], int)

    def test_timeline_present(self):
        self.assertIn("timeline", self.payload)
        self.assertIsInstance(self.payload["timeline"], list)
        for entry in self.payload["timeline"][:5]:
            for key in ("time", "agent", "action", "detail"):
                self.assertIn(key, entry, entry)

    def test_runtime_status_present(self):
        self.assertIn("runtime", self.payload)
        rt = self.payload["runtime"]
        self.assertIn("status", rt)
        self.assertIn("current_stage", rt)
        self.assertIn("current_run", rt)

    def test_timeline_is_bounded(self):
        self.assertLessEqual(len(self.payload["timeline"]), 100)

    def test_no_fabricated_agents_in_timeline(self):
        from backend.research_agents.registry import build_default_registry

        known = {a.name.lower() for a in build_default_registry().list_agents()}
        known |= {"pipeline", "evidence", "research", "system", "runtime",
                  "authorization", "observer", "aec", "gate", "authorizer",
                  "coordinator", "specialist", "executor", "observer"}
        for entry in self.payload["timeline"]:
            agent = (entry.get("agent") or "").lower()
            if agent:
                self.assertTrue(
                    any(k in agent for k in known),
                    f"unrecognized agent label {agent!r}")


if __name__ == "__main__":
    unittest.main()
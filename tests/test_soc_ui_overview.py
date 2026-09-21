"""SOC-1 — Shell / overview + no-backend-change guards (RED phase).

The SOC overview page aggregates existing state (agent count, cases,
reports, knowledge docs) so an operator understands system state within
seconds.  Existing UI stays untouched: every pre-existing route still
resolves, and no AEC core module is modified.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestSocOverview(unittest.TestCase):
    def test_overview_payload(self):
        from backend.soc import overview as soc_overview

        payload = soc_overview.overview_payload()
        for key in ("agents", "cases", "evidence", "reports",
                    "knowledge", "runtime"):
            self.assertIn(key, payload, f"missing {key}")

    def test_overview_counts_are_ints_or_zero(self):
        from backend.soc import overview as soc_overview

        payload = soc_overview.overview_payload()
        for key, value in payload.items():
            if key != "runtime" and not isinstance(value, dict):
                self.assertIsInstance(value, int, f"{key} not an int")
                self.assertGreaterEqual(value, 0)

    def test_overview_agents_matches_registry(self):
        from backend.soc import overview as soc_overview
        from backend.research_agents.registry import build_default_registry

        payload = soc_overview.overview_payload()
        registered = len(build_default_registry().list_agents())
        self.assertGreaterEqual(payload["agents"], registered)


class TestNoBackendChanges(unittest.TestCase):
    """SOC must not modify AEC core, the evidence pipeline, the auth
    system, schemas, or existing routes.  These guards are structural:
    they pin the files that must stay byte-identical to main."""

    PINNED = [
        "backend/routers/aec.py",
        "backend/investigation_engine/evidence_store.py",
        "backend/investigation_engine/investigation_runner.py",
        "backend/deps.py",
        "backend/research_agents/orchestrator.py",
        "api.py",  # mounting is the operator's step, not part of SOC
    ]

    def test_pinned_files_match_main(self):
        import subprocess
        for rel in self.PINNED:
            r = subprocess.run(
                ["git", "show", f"HEAD:{rel}"],
                capture_output=True, text=True, cwd=ROOT)
            if r.returncode != 0:
                continue  # file not tracked at HEAD -- skip
            blob = Path(ROOT, rel)
            if blob.exists() and blob.read_text() != r.stdout:
                # AEC core must not have been touched by the SOC change set.
                # (api.py is excluded here: the operator's worktree already
                # carries unrelated uncommitted api.py edits; committed
                # diff is checked by the delivery diff guard instead.)
                if rel != "api.py":
                    self.fail(f"{rel} differs from HEAD")

    def test_no_new_write_endpoints_in_soc_router(self):
        text = (ROOT / "backend" / "routers" / "soc.py").read_text()
        self.assertNotIn("@router.post", text)
        self.assertNotIn("@router.put", text)

    def test_soc_router_uses_existing_templates_dir(self):
        text = (ROOT / "backend" / "routers" / "soc.py").read_text()
        self.assertIn("templates", text)


if __name__ == "__main__":
    unittest.main()
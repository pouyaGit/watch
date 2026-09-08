"""Focused offline tests for the research-agent VM enablement.

Covers only the newly added/changed surface:

- ``ai.config.require_mongo_uri`` fail-closed behavior.
- ``ai.research_cli check`` offline readiness (mocked MongoDB, no
  network, no LLM, no secrets in output).
- Mongo URI is environment-driven (no hardcoded VPS URI remains in
  the batch entry points).

All tests are offline. No LLM calls, no NVD calls, no live execution.
"""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch


class RequireMongoUriTests(unittest.TestCase):
    def test_refuses_when_unset(self) -> None:
        import ai.config as config

        with patch.object(config, "WATCH_MONGO_URI", ""):
            with self.assertRaises(RuntimeError):
                config.require_mongo_uri()

    def test_returns_configured_uri(self) -> None:
        import ai.config as config

        with patch.object(config, "WATCH_MONGO_URI", "mongodb://localhost:27017/x"):
            self.assertEqual(
                config.require_mongo_uri(), "mongodb://localhost:27017/x"
            )


class NoHardcodedVpsUriTests(unittest.TestCase):
    def test_batch_entry_points_have_no_hardcoded_uri(self) -> None:
        root = Path(__file__).resolve().parent / "researcher"
        for name in ("batch.py", "batch_v3.py", "retry_v3.py"):
            source = (root / name).read_text(encoding="utf-8")
            self.assertNotIn("178.83.45.76", source, name)
            self.assertNotIn("YourStrongPassword", source, name)
            self.assertIn("require_mongo_uri", source, name)


class ResearchCliCheckTests(unittest.TestCase):
    def _run_check(self, env: dict) -> tuple[int, str]:
        from ai.research_cli import main

        with patch.dict(os.environ, env, clear=False):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["check"])
        return code, buf.getvalue()

    def test_check_passes_with_mocks(self) -> None:
        fake_client = MagicMock()
        fake_client.__getitem__.return_value.__getitem__.return_value.count_documents.return_value = 3

        with patch("pymongo.MongoClient", return_value=fake_client):
            code, output = self._run_check(
                {
                    "AI_PROVIDER": "openrouter",
                    "OPENROUTER_API_KEY": "test-key",
                    "OPENROUTER_MODEL": "test-model",
                    "WATCH_MONGO_URI": "mongodb://localhost:27017/watch",
                }
            )
        self.assertEqual(code, 0, output)
        self.assertIn("RUNNABLE", output)
        # Secrets must never appear in CLI output.
        self.assertNotIn("test-key", output)

    def test_check_fails_closed_without_keys(self) -> None:
        env = {
            "AI_PROVIDER": "openrouter",
            "WATCH_MONGO_URI": "mongodb://localhost:27017/watch",
        }
        with patch.dict(os.environ, {}, clear=True):
            os.environ.update(env)
            os.environ.pop("OPENROUTER_API_KEY", None)
            buf = io.StringIO()
            from ai.research_cli import main

            with redirect_stdout(buf):
                code = main(["check"])
        output = buf.getvalue()
        self.assertEqual(code, 1, output)
        self.assertIn("NOT RUNNABLE", output)

    def test_dry_run_surface_present(self) -> None:
        from ai.researcher.nuclei_runner import NucleiRunner

        self.assertTrue(hasattr(NucleiRunner, "dry_run"))


if __name__ == "__main__":
    unittest.main()

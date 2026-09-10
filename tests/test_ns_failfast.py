#!/usr/bin/env python3
"""Focused NS/DNS fail-fast tests (offline, fully mocked).

Verifies that ``utils.common.run_command_in_zsh_ns`` no longer converts a
failing ``dnsx`` run into ``[]``:

  1. successful command -> stdout lines returned, timeout passed through
  2. missing tool / returncode 127 -> ToolError
  3. dnsx bad flag / returncode != 0 -> ToolError
  4. stderr/stdout diagnostics are bounded in the error
  5. timeout -> ToolTimeout
  6. empty stdout + returncode 0 -> [] remains valid
  7. caller compatibility (watch_ns_all propagates, wildcard_detector degrades)

No test uses real network, DNS, MongoDB, or the pipeline; subprocess.run and
the module-level runner imports are mocked.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "ns"))

import utils.common as common
from utils.common import ToolError, ToolTimeout, NS_COMMAND_TIMEOUT


def tearDownModule():
    # database.db opens a lazy MongoClient at import; release it so no
    # ResourceWarning is emitted at interpreter exit.
    try:
        import mongoengine

        mongoengine.disconnect_all()
    except Exception:
        pass


def _proc(returncode=0, stdout="", stderr=""):
    p = mock.Mock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


class TestRunCommandInZshNs(unittest.TestCase):
    def test_success_returns_lines_and_keeps_command_shape(self):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return _proc(0, stdout="a\n\nb\n")

        with mock.patch.object(common.subprocess, "run", side_effect=fake_run):
            out = common.run_command_in_zsh_ns("dnsx -l /tmp/x -silent")

        self.assertEqual(out, ["a", "b"])
        self.assertEqual(captured["kwargs"]["timeout"], NS_COMMAND_TIMEOUT)
        self.assertTrue(captured["kwargs"]["shell"])
        self.assertEqual(captured["kwargs"]["executable"], "/bin/zsh")
        self.assertTrue(captured["kwargs"]["capture_output"])

    def test_nonzero_exit_127_raises_toolerror(self):
        proc = _proc(127, stderr="/bin/zsh: command not found: dnsx")
        with mock.patch.object(common.subprocess, "run", return_value=proc):
            with self.assertRaises(ToolError) as ctx:
                common.run_command_in_zsh_ns("dnsx -l /tmp/x")

        msg = str(ctx.exception)
        self.assertIn("127", msg)
        self.assertIn("command not found", msg)
        self.assertIn("dnsx", msg)

    def test_bad_flag_nonzero_raises(self):
        proc = _proc(2, stdout="flag provided but not defined: -bogus")
        with mock.patch.object(common.subprocess, "run", return_value=proc):
            with self.assertRaises(ToolError) as ctx:
                common.run_command_in_zsh_ns("dnsx -bogus")

        msg = str(ctx.exception)
        self.assertIn("exit 2", msg)
        self.assertIn("flag provided but not defined", msg)

    def test_diagnostics_are_bounded(self):
        proc = _proc(1, stderr="E" * 5000, stdout="O" * 5000)
        with mock.patch.object(common.subprocess, "run", return_value=proc):
            with self.assertRaises(ToolError) as ctx:
                common.run_command_in_zsh_ns("dnsx")

        msg = str(ctx.exception)
        self.assertLess(len(msg), 1400)  # two ~500-char tails + prefix, not 10k
        self.assertIn("...", msg)

    def test_stdout_tail_included_on_failure(self):
        proc = _proc(2, stdout="usage: dnsx ...")
        with mock.patch.object(common.subprocess, "run", return_value=proc):
            with self.assertRaises(ToolError) as ctx:
                common.run_command_in_zsh_ns("dnsx -bogus")
        self.assertIn("stdout:", str(ctx.exception))

    def test_timeout_raises_tooltimeout(self):
        with mock.patch.object(
            common.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd="dnsx", timeout=1),
        ):
            with self.assertRaises(ToolTimeout) as ctx:
                common.run_command_in_zsh_ns("dnsx -l /tmp/x -silent")

        msg = str(ctx.exception)
        self.assertIn("timed out", msg)
        self.assertIn(str(NS_COMMAND_TIMEOUT), msg)

    def test_oserror_raises_toolerror(self):
        with mock.patch.object(common.subprocess, "run", side_effect=OSError("boom")):
            with self.assertRaises(ToolError):
                common.run_command_in_zsh_ns("dnsx")

    def test_empty_stdout_zero_exit_is_empty_list(self):
        proc = _proc(0, stdout="")
        with mock.patch.object(common.subprocess, "run", return_value=proc):
            self.assertEqual(common.run_command_in_zsh_ns("dnsx"), [])

    def test_tooltimeout_is_toolerror_subclass(self):
        self.assertTrue(issubclass(ToolTimeout, ToolError))

    def test_timeout_constant_is_bounded(self):
        self.assertGreater(NS_COMMAND_TIMEOUT, 0)
        self.assertLessEqual(NS_COMMAND_TIMEOUT, 7200)


class TestCallerCompatibility(unittest.TestCase):
    def test_watch_ns_all_propagates_failure(self):
        import watch_ns_all

        with mock.patch.object(
            watch_ns_all, "run_command_in_zsh_ns",
            side_effect=ToolError("dnsx failed (exit 127)"),
        ):
            with self.assertRaises(ToolError):
                watch_ns_all.dnsx(["a.example.com"], "example.com")

    def test_watch_ns_all_success_path_unchanged(self):
        import watch_ns_all

        line = json.dumps({"host": "a.example.com", "a": ["1.2.3.4"]})
        with mock.patch.object(watch_ns_all, "run_command_in_zsh_ns", return_value=[line]), \
                mock.patch.object(watch_ns_all, "WildcardDetector") as detector, \
                mock.patch.object(watch_ns_all, "upsert_lives") as upsert:
            detector.return_value.is_wildcard.return_value = False
            result = watch_ns_all.dnsx(["a.example.com"], "example.com")

        self.assertTrue(result)
        upsert.assert_called_once()

    def test_wildcard_detector_degrades_on_failure(self):
        import wildcard_detector

        with mock.patch.object(
            wildcard_detector, "run_command_in_zsh_ns",
            side_effect=ToolError("dnsx failed (exit 127)"),
        ):
            detector = wildcard_detector.WildcardDetector("example.com")
            ips = detector._resolve_level_ips("*.example.com")

        self.assertEqual(ips, set())

    def test_get_wildcard_ips_degrades_on_failure(self):
        import wildcard_detector

        with mock.patch.object(
            wildcard_detector, "run_command_in_zsh_ns",
            side_effect=ToolError("dnsx failed (exit 127)"),
        ):
            self.assertEqual(
                wildcard_detector.get_wildcard_ips("example.com", num_tests=1),
                set(),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

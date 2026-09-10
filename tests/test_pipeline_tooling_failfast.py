#!/usr/bin/env python3
"""Pipeline tooling fail-fast regression tests (offline, mocked).

Covers the permanent fix for the 12:00 pipeline failure where a missing
``puredns`` binary was interpreted as "0 resolved names" and every domain
was still counted as successfully processed:

  A. run-pipeline.sh is tracked by Git as mode 100755.
  B. A missing required binary fails the job (non-zero / ToolError).
  C. puredns unavailable is NOT interpreted as zero resolved names.
  D. puredns non-zero exit (incl. 127 / timeout) fails instead of [].
  E. puredns success with zero names is a legitimate empty result.
  F. puredns success with results is unchanged.
  G. A failing child reaches the pipeline final exit status (non-zero)
     while independent jobs still run.
  H. An all-success pipeline still exits 0.
  I. process_domain propagates a puredns ToolError without marking the
     domain run.
  J. Tool discovery uses the canonical systemd-compatible PATH and never
     hardcodes /home/pouya_behnia/go/bin.

No test touches the network, DNS, MongoDB, or any external target:
subprocess execution and tool discovery are mocked throughout.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "ns"))

import dns_brute_common as common
from dns_brute_common import ToolError, run_puredns, require_tools
from utils.common import WATCH_TOOL_PATH, require_tool


def _ok_proc(stdout_text=""):
    proc = mock.Mock()
    proc.returncode = 0
    proc.stdout = stdout_text
    proc.stderr = ""
    return proc


def _fail_proc(returncode=1, stderr="boom"):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = ""
    proc.stderr = stderr
    return proc


class TestGitExecutableBit(unittest.TestCase):
    """A. run-pipeline.sh must be tracked as 100755 (direct systemd exec)."""

    def test_run_pipeline_git_mode_is_100755(self):
        out = subprocess.run(
            ["git", "ls-files", "--stage", "run-pipeline.sh"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=30,
        )
        self.assertEqual(out.returncode, 0, msg=out.stderr)
        mode = out.stdout.split()[0]
        self.assertEqual(
            mode,
            "100755",
            msg=f"run-pipeline.sh Git mode is {mode}, expected 100755: {out.stdout.strip()}",
        )


class TestRequireTools(unittest.TestCase):
    """B. Missing required binary => hard failure naming the command."""

    def test_missing_binary_raises_naming_command(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(ToolError) as ctx:
                require_tools(["puredns"])
        self.assertIn("puredns", str(ctx.exception))

    def test_present_binary_resolves(self):
        with mock.patch("shutil.which", return_value="/usr/local/bin/puredns"):
            self.assertEqual(require_tools(["puredns"]), ["/usr/local/bin/puredns"])


class TestRunPuredns(unittest.TestCase):
    """C-F. puredns outcome matrix (mocked process, real parsing)."""

    def setUp(self):
        self.tmp = Path(self._tmp_dir())
        self.candidates = self.tmp / "cands.txt"
        self.candidates.write_text("a.example.com\n")
        self.out = self.tmp / "out.txt"

    @staticmethod
    def _tmp_dir():
        import tempfile

        return tempfile.mkdtemp(prefix="puredns-failfast-")

    def _run(self, which="/usr/local/bin/puredns", proc=None, side_effect=None):
        with mock.patch("shutil.which", return_value=which):
            with mock.patch("subprocess.run", side_effect=side_effect) as mrun:
                if side_effect is None:
                    mrun.return_value = proc
                    if proc is not None and proc.returncode == 0:
                        # emulate a real puredns writing resolved names
                        def _write(argv, **kwargs):
                            fh = kwargs.get("stdout")
                            if fh is not None and hasattr(fh, "write"):
                                fh.write(getattr(proc, "_names", ""))
                            return proc

                        mrun.side_effect = _write
                return run_puredns(self.candidates, self.out)

    def test_c_command_unavailable_raises_not_empty(self):
        """C: missing puredns must raise, never return []."""
        with self.assertRaises(ToolError) as ctx:
            self._run(which=None)
        self.assertIn("puredns", str(ctx.exception))

    def test_d_nonzero_exit_raises(self):
        """D: non-zero exit fails the call (no silent zero-result)."""
        with self.assertRaises(ToolError) as ctx:
            self._run(proc=_fail_proc(1, "resolver failure"))
        self.assertIn("puredns", str(ctx.exception))
        self.assertIn("exit 1", str(ctx.exception))

    def test_d_shell_127_not_found_raises(self):
        """D: the exact 12:00 symptom (127 / 'not found') must raise."""
        with self.assertRaises(ToolError) as ctx:
            self._run(proc=_fail_proc(127, "/bin/sh: 1: puredns: not found"))
        self.assertIn("puredns", str(ctx.exception))

    def test_d_timeout_raises(self):
        """D: timeout discards partial output instead of returning []."""
        with self.assertRaises(ToolError) as ctx:
            self._run(
                side_effect=subprocess.TimeoutExpired(cmd="puredns", timeout=1)
            )
        self.assertIn("puredns", str(ctx.exception))

    def test_d_oserror_raises(self):
        with self.assertRaises(ToolError):
            self._run(side_effect=OSError("exec failed"))

    def test_e_success_empty_is_legitimate_zero(self):
        """E: zero-exit with no names is the ONLY legitimate empty case."""
        proc = _ok_proc()
        proc._names = ""
        self.assertEqual(self._run(proc=proc), [])

    def test_f_success_with_results_unchanged(self):
        """F: normal resolved output still parses as before."""
        proc = _ok_proc()
        proc._names = "a.example.com\nb.example.com\n\n"
        self.assertEqual(
            self._run(proc=proc), ["a.example.com", "b.example.com"]
        )

    def test_missing_resolvers_file_raises(self):
        with mock.patch.object(common, "RESOLVERS", "/nonexistent/resolvers.txt"):
            with self.assertRaises(ToolError) as ctx:
                self._run(proc=_ok_proc())
        self.assertIn("resolvers", str(ctx.exception))


class TestProcessDomainPropagates(unittest.TestCase):
    """I. A puredns ToolError fails the domain without marking it run."""

    @classmethod
    def tearDownClass(cls):
        # database.db opens a lazy MongoClient at import; nothing connects
        # during these tests, but release it so no ResourceWarning is emitted.
        try:
            import mongoengine

            mongoengine.disconnect_all()
        except Exception:
            pass

    def test_puredns_failure_propagates_and_not_marked(self):
        import watch_dns_static as static

        with mock.patch.object(static, "ensure_static_wordlist", return_value=None), \
            mock.patch.object(static, "send_telegram", return_value=None), \
            mock.patch.object(static.subprocess, "run", return_value=_ok_proc()), \
            mock.patch.object(
                static, "run_puredns",
                side_effect=ToolError("puredns resolve failed (exit 127)"),
            ), \
            mock.patch.object(static, "mark_static_run") as mark:
            with self.assertRaises(ToolError):
                static.process_domain("prog", "example.com")
        mark.assert_not_called()


class TestRunAlterx(unittest.TestCase):
    """Dynamic preflight helper: missing/failing alterx must raise."""

    def test_missing_alterx_raises(self):
        import watch_dns_dynamic as dynamic

        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(ToolError) as ctx:
                dynamic.run_alterx(
                    Path("/tmp/known.txt"),
                    Path("/tmp/out.txt"),
                    Path("/tmp/candidates.txt"),
                )
        self.assertIn("alterx", str(ctx.exception))


class TestToolDiscovery(unittest.TestCase):
    """J. Canonical PATH strategy: systemd-compatible, no hardcoded home."""

    def test_no_hardcoded_pouya_behnia_path(self):
        self.assertNotIn("/home/pouya_behnia", WATCH_TOOL_PATH)

    def test_systemd_dirs_covered(self):
        for entry in (
            "/opt/watch/venv/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ):
            self.assertIn(entry, WATCH_TOOL_PATH.split(":"))

    def test_go_bins_covered_without_username(self):
        parts = WATCH_TOOL_PATH.split(":")
        self.assertTrue(
            any(p.endswith("/go/bin") for p in parts),
            msg=f"no go/bin entry in {WATCH_TOOL_PATH}",
        )

    def test_require_tool_finds_real_binary(self):
        # 'sh' exists on every Linux host incl. the systemd environment.
        self.assertTrue(require_tool("sh").endswith("/sh"))


class TestPipelineLib(unittest.TestCase):
    """G-H. pipeline_lib.sh failure propagation (real bash, stub commands)."""

    LIB = str(REPO_ROOT / "pipeline_lib.sh")
    PRELUDE = "unset TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID; source \"$LIB\""

    def _bash(self, body):
        return subprocess.run(
            ["bash", "-c", self.PRELUDE + "\n" + body],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "LIB": self.LIB},
        )

    def test_g_failure_propagates_and_jobs_continue(self):
        res = self._bash(
            "step \"First\" true\n"
            "step \"Bad\" bash -c 'exit 3'\n"
            "rc=$?\n"
            "step \"After\" true\n"
            "pipeline_exit_code\n"
            "final=$?\n"
            "echo \"rc=$rc final=$final\"\n"
            "exit $final\n"
        )
        self.assertIn("===== After =====", res.stdout,
                      msg="independent jobs must still run after a failure")
        self.assertIn("rc=3", res.stdout,
                      msg="step must return the child exit code")
        self.assertEqual(res.returncode, 1,
                         msg=f"pipeline must exit non-zero, got: {res.stdout}")

    def test_h_all_success_exits_zero(self):
        res = self._bash(
            "step \"A\" true\n"
            "step \"B\" true\n"
            "pipeline_exit_code\n"
            "exit $?\n"
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""EPIC10 SS10/SS14/SS16/SS21 -- pipeline integration, reporting, concurrency.

Drives the real DNS execution path (`utils.common.run_command_in_zsh_ns`) with a
mocked subprocess: selection -> chunking -> run -> report -> attempt state, plus
the guarantees the operator needs (pinned caller untouched, no double
processing on a duplicate run, exit-code contract preserved).
"""

import ast
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import utils.common as common  # noqa: E402
from tests.epic10_fixtures import (  # noqa: E402
    IncrementalTestCase,
    static_provider,
)
from utils import dns_incremental  # noqa: E402
from utils.dns_incremental import DnsSelectionError  # noqa: E402

PRODUCTION_ROOT = Path("/opt/watch")
PINNED_ON_THE_DNS_PATH = [
    "ns/watch_ns_all.py",
    "ns/watch_ns.py",
    "ns/wildcard_detector.py",
    "ns/dns_brute_common.py",
    "ns/watch_dns_static.py",
    "ns/watch_dns_dynamic.py",
    "ns/watch_dns_precheck.py",
    "run-pipeline.sh",
    "pipeline_lib.sh",
]


def _proc(returncode=0, stdout="", stderr=""):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


class PipelineTestCase(IncrementalTestCase):
    def setUp(self):
        self.setUpIncremental()
        self._env = mock.patch.dict(os.environ, {
            "DNS_RESOLUTION_STATE_FILE": self.state_file,
            "DNS_RESOLUTION_ENABLED": "true",
        })
        self._env.start()
        self.addCleanup(self._env.stop)

    def tearDown(self):
        self.tearDownIncremental()

    def command(self, names, name="candidates.txt"):
        path = os.path.join(self._tmpdir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(names) + "\n")
        return f"dnsx -l {path} -silent -a -resp -json -t 10 -rl 30"

    def capturing_run(self, stdout=""):
        """subprocess.run stand-in that records each invocation's list.

        The chunk list files are removed in the caller's finally block, so the
        names have to be captured while the command is being executed.
        """
        captured = []

        def fake_run(command, *args, **kwargs):
            match = common._DNSX_LIST_ARG.search(command)
            if match:
                with open(match.group("path"), "r", encoding="utf-8") as handle:
                    captured.append([line.strip() for line in handle
                                     if line.strip()])
            else:
                captured.append(None)
            return _proc(stdout=stdout)

        fake_run.captured = captured
        return fake_run

    def queried_names(self, fake_run):
        return [name for chunk in fake_run.captured if chunk for name in chunk]

    def output_for(self, names):
        return "\n".join(json.dumps({"host": n, "a": ["1.2.3.4"]}) for n in names)


class TestEndToEndSelection(PipelineTestCase, unittest.TestCase):
    def test_only_eligible_names_are_queried(self):
        names = ["fresh1.example.com", "fresh2.example.com", "new.example.com"]
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:2]}
        dns_incremental.set_prior_lookup_provider(static_provider(prior))
        fake_run = self.capturing_run(stdout=self.output_for(["new.example.com"]))
        with mock.patch.object(common.subprocess, "run", side_effect=fake_run):
            lines = common.run_command_in_zsh_ns(self.command(names))
        self.assertEqual(["new.example.com"], self.queried_names(fake_run))
        self.assertEqual(1, len(lines))

    def test_report_is_printed_for_the_run(self):
        names = ["fresh.example.com", "new.example.com"]
        dns_incremental.set_prior_lookup_provider(static_provider(
            {"fresh.example.com": self.resolve("fresh.example.com", hours_ago=1)}))
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc()) as run:
            with mock.patch("builtins.print") as printer:
                common.run_command_in_zsh_ns(self.command(names))
        printed = "\n".join(str(c) for c in printer.call_args_list)
        self.assertIn("DNS Resolution (incremental selection)", printed)
        self.assertIn("Candidates:", printed)
        self.assertIn("DNS Resolution results", printed)

    def test_run_outcome_is_recorded_in_the_state_file(self):
        names = ["a.example.com", "b.example.com"]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(stdout=self.output_for(
                                   ["a.example.com"]))) as run:
            common.run_command_in_zsh_ns(self.command(names))
        state = self.store.load()
        self.assertEqual(0, state["a.example.com"].streak)
        self.assertEqual(1, state["b.example.com"].streak)

    def test_second_run_inside_the_freshness_window_queries_nothing(self):
        """Duplicate pipeline run protection: no double processing."""
        names = ["a.example.com", "b.example.com"]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(stdout=self.output_for(names))):
            common.run_command_in_zsh_ns(self.command(names))
        # the same names now have a prior resolution inside the window
        dns_incremental.set_prior_lookup_provider(static_provider(
            {n: self.resolve(n, hours_ago=0.1) for n in names}))
        with mock.patch.object(common.subprocess, "run") as second:
            common.run_command_in_zsh_ns(self.command(names))
            second.assert_not_called()

    def test_repeated_runs_are_deterministic(self):
        names = [f"h{i}.example.com" for i in range(5)]
        first = self.select(names)
        second = self.select(names)
        self.assertEqual(first.selected, second.selected)
        self.assertEqual(first.counts, second.counts)

    def test_selection_is_independent_of_candidate_order_for_counts(self):
        names = [f"h{i}.example.com" for i in range(6)]
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:3]}
        forward = self.select(names, provider=static_provider(prior))
        backward = self.select(list(reversed(names)), provider=static_provider(prior))
        self.assertEqual(forward.counts, backward.counts)


class TestFailurePropagation(PipelineTestCase, unittest.TestCase):
    def test_chunk_failure_still_raises_tool_error(self):
        names = [f"h{i}.example.com" for i in range(15001)]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(returncode=1, stderr="dnsx boom")):
            with self.assertRaises(common.ToolError):
                common.run_command_in_zsh_ns(self.command(names))

    def test_chunk_timeout_still_raises_tool_timeout(self):
        names = [f"h{i}.example.com" for i in range(15001)]
        with mock.patch.object(common.subprocess, "run",
                               side_effect=__import__("subprocess").TimeoutExpired(
                                   "dnsx", 3600)):
            with self.assertRaises(common.ToolTimeout):
                common.run_command_in_zsh_ns(self.command(names))

    def test_failure_is_reported_with_the_failed_chunk(self):
        names = [f"h{i}.example.com" for i in range(15001)]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(returncode=3, stderr="nope")):
            with mock.patch("builtins.print") as printer:
                with self.assertRaises(common.ToolError):
                    common.run_command_in_zsh_ns(self.command(names))
        printed = "\n".join(str(c) for c in printer.call_args_list)
        self.assertIn("FAILED", printed)

    def test_failure_does_not_mask_the_original_error(self):
        """A reporting error must never replace ToolError/ToolTimeout."""
        names = ["a.example.com"]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(returncode=1, stderr="x")):
            with self.assertRaises(common.ToolError):
                common.run_command_in_zsh_ns(self.command(names))

    def test_temp_files_are_cleaned_up_on_failure(self):
        names = [f"h{i}.example.com" for i in range(15001)]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(returncode=1)):
            with self.assertRaises(common.ToolError):
                common.run_command_in_zsh_ns(self.command(names))
        leftovers = [n for n in os.listdir(self._tmpdir.name)
                     if n not in ("candidates.txt", "state.json")]
        self.assertEqual([], leftovers)

    def test_selector_failure_is_never_swallowed_by_the_report_path(self):
        def exploding(_names):
            raise RuntimeError("db down")
        dns_incremental.set_prior_lookup_provider(exploding)
        with self.assertRaises(DnsSelectionError):
            common.run_command_in_zsh_ns(self.command(["a.example.com"]))


class TestPinnedCallerUntouched(unittest.TestCase):
    def test_dns_path_files_match_production(self):
        """Every pinned file on the DNS path is byte-identical to production."""
        if not PRODUCTION_ROOT.exists():
            self.skipTest("production checkout unavailable")
        for relative in PINNED_ON_THE_DNS_PATH:
            local = REPO_ROOT / relative
            production = PRODUCTION_ROOT / relative
            if not production.exists():
                self.skipTest(f"{relative} not in production")
            self.assertEqual(
                hashlib.sha256(production.read_bytes()).hexdigest(),
                hashlib.sha256(local.read_bytes()).hexdigest(),
                f"{relative} was modified -- it is pinned read-only")

    def test_pinned_caller_has_no_error_handling_around_the_ns_call(self):
        """watch_ns_all.py must let a selector failure exit the process."""
        tree = ast.parse((REPO_ROOT / "ns" / "watch_ns_all.py").read_text())
        # the file legitimately guards json.loads per result line; what must
        # never appear is an except clause *enclosing the NS call itself*
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try) or not node.handlers:
                continue
            for child in ast.walk(node):
                if (isinstance(child, ast.Call)
                        and getattr(child.func, "id", None) == "run_command_in_zsh_ns"):
                    self.fail("watch_ns_all.py wraps the NS call in try/except; "
                              "a selection failure must abort the step")

    def test_pinned_caller_still_passes_the_whole_scope(self):
        """The caller's contract is unchanged: it hands over every candidate."""
        source = (REPO_ROOT / "ns" / "watch_ns_all.py").read_text()
        self.assertIn("obj_subs = Subdomains.objects(scope=domain)", source)
        self.assertIn("dnsx([obj_sub.subdomain for obj_sub in obj_subs], domain)",
                      source)

    def test_pipeline_lock_is_still_in_place(self):
        unit = Path("/etc/systemd/system/watch.service")
        if not unit.exists():
            self.skipTest("watch.service not present")
        self.assertIn("flock", unit.read_text())

    def test_run_pipeline_still_fails_the_run_on_a_step_error(self):
        lib = (REPO_ROOT / "pipeline_lib.sh").read_text()
        self.assertIn("PIPELINE_FAILED", lib)


class TestStateFileHygiene(PipelineTestCase, unittest.TestCase):
    def test_state_file_is_not_created_when_nothing_was_queried(self):
        names = ["fresh.example.com"]
        dns_incremental.set_prior_lookup_provider(static_provider(
            {"fresh.example.com": self.resolve("fresh.example.com", hours_ago=1)}))
        with mock.patch.object(common.subprocess, "run") as run:
            common.run_command_in_zsh_ns(self.command(names))
            run.assert_not_called()
        self.assertFalse(os.path.exists(self.state_file))

    def test_state_file_grows_only_with_unresolved_names(self):
        names = ["a.example.com", "b.example.com"]
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(stdout=self.output_for(names))):
            common.run_command_in_zsh_ns(self.command(names))
        # both resolved: streaks are zero, so nothing is persisted as failing
        state = self.store.load()
        self.assertEqual(0, state["a.example.com"].streak)
        self.assertEqual(0, state["b.example.com"].streak)

    def test_state_file_survives_a_run_boundary(self):
        names = ["a.example.com"]
        with mock.patch.object(common.subprocess, "run", return_value=_proc()):
            common.run_command_in_zsh_ns(self.command(names))
        self.assertEqual(1, self.store.load()["a.example.com"].streak)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Bounded bulk-dnsx chunking (utils.common.run_command_in_zsh_ns).

Regression tests for the watch.service failure of 2026-09-17..2026-09-24:

    the NS step resolves a whole scope in one rate-limited (``-rl 30``) dnsx
    call; the indeed.net scope grew to 206,080 names (>= 6,869s of query time
    at the rate limit) while NS_COMMAND_TIMEOUT is 3,600s, so the call raised
    ToolTimeout, the step exited 1 and the pipeline exited 1 (systemd:
    failed).

These tests pin the repair: a bulk ``dnsx -l <file>`` list larger than
NS_DNSX_CHUNK_SIZE is resolved as several bounded invocations, each with its
own NS_COMMAND_TIMEOUT budget and unchanged fail-fast semantics, and every
other call keeps its exact previous behavior.

Offline: subprocess.run is mocked, no DNS, no MongoDB, no network.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import utils.common as common  # noqa: E402
from utils.common import (  # noqa: E402
    NS_COMMAND_TIMEOUT,
    NS_DNSX_CHUNK_SIZE,
    NS_SECONDS_PER_NAME_AT_RATE_LIMIT,
    ToolError,
    ToolTimeout,
)

DNSX_TAIL = "-silent -a -resp -json -t 10 -rl 30 -r 8.8.8.8,1.1.1.1"


def tearDownModule():
    try:
        import mongoengine

        mongoengine.disconnect_all()
    except Exception:
        pass


def _proc(returncode=0, stdout="", stderr=""):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _names(count, prefix="host"):
    return [f"{prefix}{i}.example.com" for i in range(count)]


class ChunkingTestCase(unittest.TestCase):
    """Shared helper: capture every subprocess.run call and its list file."""

    def setUp(self):
        self.calls = []

    def _run(self, command, side_effect=None):
        def fake_run(cmd, **kwargs):
            list_path = None
            for token_index, token in enumerate(cmd.split()):
                if token == "-l":
                    list_path = cmd.split()[token_index + 1].strip('"')
                    break
            contents = []
            if list_path and Path(list_path).is_file():
                contents = [line.strip() for line
                            in Path(list_path).read_text().splitlines()
                            if line.strip()]
            self.calls.append({"cmd": cmd, "kwargs": kwargs,
                               "list": list_path, "names": contents})
            if side_effect:
                return side_effect(len(self.calls))
            return _proc(0, stdout=f"result-{len(self.calls)}\n")

        with mock.patch.object(common.subprocess, "run",
                               side_effect=fake_run):
            return common.run_command_in_zsh_ns(command)


class TestBulkListIsBounded(ChunkingTestCase):
    def test_large_list_is_split_into_bounded_invocations(self):
        source = common.create_temp_file(_names(60001))
        try:
            out = self._run(f"dnsx -l {source} {DNSX_TAIL}")
        finally:
            Path(source).unlink(missing_ok=True)

        expected_sizes = [NS_DNSX_CHUNK_SIZE] * (60001 // NS_DNSX_CHUNK_SIZE)
        expected_sizes.append(60001 % NS_DNSX_CHUNK_SIZE)
        self.assertEqual(len(self.calls), len(expected_sizes))
        self.assertEqual([len(c["names"]) for c in self.calls], expected_sizes)
        # every name is queried exactly once, in order, and no chunk is larger
        # than the bound
        flat = [name for call in self.calls for name in call["names"]]
        self.assertEqual(flat, _names(60001))
        for call in self.calls:
            self.assertLessEqual(len(call["names"]), NS_DNSX_CHUNK_SIZE)
            # the ceiling is still applied to every single invocation
            self.assertEqual(call["kwargs"]["timeout"], NS_COMMAND_TIMEOUT)
            # the command shape is preserved, only the list file differs
            self.assertTrue(call["cmd"].startswith("dnsx -l "))
            self.assertTrue(call["cmd"].endswith(DNSX_TAIL))
        # results of every chunk are returned to the caller, in order
        self.assertEqual(out, [f"result-{i}" for i in range(1, len(self.calls) + 1)])

    def test_real_production_scale_needs_a_bounded_number_of_calls(self):
        # the real incident scale: 206,080 indeed.net names must now fit in a
        # bounded number of invocations, each far below the ceiling
        source = common.create_temp_file(_names(206080))
        try:
            self._run(f"dnsx -l {source} {DNSX_TAIL}")
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertEqual(len(self.calls),
                         206080 // NS_DNSX_CHUNK_SIZE + 1)
        for call in self.calls:
            worst_case = len(call["names"]) * NS_SECONDS_PER_NAME_AT_RATE_LIMIT
            self.assertLess(worst_case, NS_COMMAND_TIMEOUT)
            # ... and still under the ceiling at the SLOWEST measured rate
            self.assertLess(len(call["names"]) / MEASURED_NAMES_PER_SECOND,
                            NS_COMMAND_TIMEOUT)

    def test_quoted_list_argument_is_split_with_quotes_preserved(self):
        # ns/watch_dns_static.py and ns/watch_dns_dynamic.py use -l "path"
        source = common.create_temp_file(_names(NS_DNSX_CHUNK_SIZE + 5))
        try:
            self._run(f'dnsx -l "{source}" {DNSX_TAIL}')
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertEqual(len(self.calls), 2)
        for call in self.calls:
            self.assertIn('dnsx -l "', call["cmd"])
            self.assertTrue(call["cmd"].endswith(DNSX_TAIL))

    def test_chunk_temp_files_are_removed_after_the_run(self):
        source = common.create_temp_file(_names(NS_DNSX_CHUNK_SIZE * 2 + 1))
        try:
            self._run(f"dnsx -l {source} {DNSX_TAIL}")
            chunk_paths = [call["list"] for call in self.calls]
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertEqual(len(chunk_paths), 3)
        for path in chunk_paths:
            self.assertFalse(Path(path).exists(), path)


class TestFailFastIsPreserved(ChunkingTestCase):
    def test_chunk_timeout_still_raises_and_stops_the_run(self):
        source = common.create_temp_file(_names(NS_DNSX_CHUNK_SIZE + 1))
        try:
            with self.assertRaises(ToolTimeout):
                self._run(f"dnsx -l {source} {DNSX_TAIL}",
                          side_effect=lambda n: _proc(0, stdout="ok\n")
                          if n == 1 else _hang())
        finally:
            Path(source).unlink(missing_ok=True)

        # the second chunk raised; the run stopped instead of masking it
        self.assertEqual(len(self.calls), 2)

    def test_chunk_nonzero_exit_raises_toolerror(self):
        source = common.create_temp_file(_names(NS_DNSX_CHUNK_SIZE * 2))
        try:
            with self.assertRaises(ToolError):
                self._run(f"dnsx -l {source} {DNSX_TAIL}",
                          side_effect=lambda n: _proc(0, stdout="ok\n")
                          if n == 1 else _proc(2, stderr="bad flag"))
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertEqual(len(self.calls), 2)

    def test_chunk_files_are_cleaned_up_even_when_a_chunk_fails(self):
        source = common.create_temp_file(_names(NS_DNSX_CHUNK_SIZE + 1))
        chunk_paths = []
        try:
            with self.assertRaises(ToolError):
                try:
                    self._run(f"dnsx -l {source} {DNSX_TAIL}",
                              side_effect=lambda n: _proc(3, stderr="boom"))
                finally:
                    chunk_paths = [call["list"] for call in self.calls]
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertTrue(chunk_paths)
        for path in chunk_paths:
            self.assertFalse(Path(path).exists(), path)


class TestBackwardCompatibility(ChunkingTestCase):
    def test_small_list_keeps_the_original_single_command(self):
        source = common.create_temp_file(_names(100))
        command = f"dnsx -l {source} {DNSX_TAIL}"
        try:
            self._run(command)
        finally:
            Path(source).unlink(missing_ok=True)

        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["cmd"], command)

    def test_missing_list_file_falls_back_to_the_original_command(self):
        command = "dnsx -l /tmp/does-not-exist-watch.txt -silent"
        self._run(command)

        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["cmd"], command)

    def test_non_dnsx_command_is_untouched(self):
        command = "subfinder -dL /tmp/some-list.txt -silent"
        self._run(command)

        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["cmd"], command)

    def test_dnsx_without_a_list_argument_is_untouched(self):
        command = "dnsx -d example.com -silent"
        self._run(command)

        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["cmd"], command)


#: Measured on this host on 2026-09-24 with the production dnsx command over
#: real indeed.net names: 21.9 names/second on fresh resolvers (20,000 names /
#: 914s) and 11.4 names/second under sustained querying (25,001 names / 2,201s).
#: The `-rl 30` rate limit is a ceiling, not the achievable rate; the slower
#: figure is what the chunk size has to survive.
MEASURED_NAMES_PER_SECOND = 11.4


class TestSizingContract(unittest.TestCase):
    """The chunk size and the ceiling must stay in a proven relationship."""

    def test_chunk_worst_case_keeps_a_multiple_of_margin(self):
        worst_case = NS_DNSX_CHUNK_SIZE * NS_SECONDS_PER_NAME_AT_RATE_LIMIT
        self.assertLess(worst_case * 3, NS_COMMAND_TIMEOUT)

    def test_chunk_survives_a_two_times_slower_resolver(self):
        measured = NS_DNSX_CHUNK_SIZE / MEASURED_NAMES_PER_SECOND
        self.assertLess(measured * 2, NS_COMMAND_TIMEOUT)

    def test_the_real_scope_needs_a_bounded_number_of_chunks(self):
        # the incident scale: 206,080 names must resolve as bounded calls, not
        # as one call that cannot fit the ceiling
        real_scope = 206080
        self.assertGreater(
            real_scope * NS_SECONDS_PER_NAME_AT_RATE_LIMIT, NS_COMMAND_TIMEOUT)
        self.assertGreaterEqual(real_scope // NS_DNSX_CHUNK_SIZE, 8)

    def test_chunk_size_is_positive_and_bounded(self):
        self.assertGreater(NS_DNSX_CHUNK_SIZE, 0)
        self.assertLessEqual(NS_DNSX_CHUNK_SIZE, 50000)


def _hang():
    import subprocess

    raise subprocess.TimeoutExpired(cmd="dnsx", timeout=1)


if __name__ == "__main__":
    unittest.main()

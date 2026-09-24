#!/usr/bin/env python3
"""EPIC10 SS9/SS13 -- chunking boundaries and the selection->chunking order.

Selection happens BEFORE chunking and the 15,000-name bound is preserved
unconditionally (including under FORCE). These tests drive the real
`utils/common._dnsx_run_plan` with a mocked subprocess: no DNS, no network.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import utils.common as common  # noqa: E402
from tests.epic10_fixtures import (  # noqa: E402
    NOW,
    IncrementalTestCase,
    passthrough_provider,
    static_provider,
)
from utils.common import NS_DNSX_CHUNK_SIZE, NS_SECONDS_PER_NAME_AT_RATE_LIMIT  # noqa: E402
from utils.dns_incremental import DnsAttemptStore  # noqa: E402

DNSX_TAIL = "-silent -a -resp -json -t 10 -rl 30 -r 8.8.8.8,1.1.1.1"


def _proc(returncode=0, stdout="", stderr=""):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


class ChunkingTestCase(IncrementalTestCase):
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

    # -- helpers ---------------------------------------------------------
    def list_file(self, names, name="candidates.txt"):
        path = os.path.join(self._tmpdir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(names) + "\n")
        return path

    def command_for(self, path):
        return f"dnsx -l {path} {DNSX_TAIL}"

    def plan(self, names, provider=None, **policy_kwargs):
        if provider is not None:
            from utils import dns_incremental
            dns_incremental.set_prior_lookup_provider(provider)
        path = self.list_file(names)
        return common._dnsx_run_plan(self.command_for(path))

    def names_in_chunk_files(self, plan):
        """Read back every name handed to dnsx, chunk by chunk."""
        per_chunk = []
        for command in plan.commands:
            match = common._DNSX_LIST_ARG.search(command)
            with open(match.group("path"), "r", encoding="utf-8") as handle:
                per_chunk.append([line.strip() for line in handle if line.strip()])
        return per_chunk

    def names(self, count, prefix="host"):
        return [f"{prefix}{i}.example.com" for i in range(count)]


class TestChunkBoundaries(ChunkingTestCase, unittest.TestCase):
    def test_zero_names_keep_the_original_invocation(self):
        # An empty candidate list is a degenerate no-op: nothing can be queried
        # either way, so the selector deliberately leaves the command
        # byte-identical (the pinned caller never reaches dnsx with an empty
        # scope -- it checks `if obj_subs:` first).
        names = []
        path = self.list_file(names)
        command = self.command_for(path)
        plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)
        self.assertEqual([], plan.temp_paths)
        self.assertEqual(0, len(plan.selection.selected))

    def test_zero_selected_from_a_non_empty_list_produces_no_invocation(self):
        # ... whereas a non-empty list with nothing eligible must NOT run dnsx
        names = self.names(5)
        prior = {n: self.resolve(n, hours_ago=1) for n in names}
        plan = self.plan(names, provider=static_provider(prior))
        self.assertEqual([], plan.commands)

    def test_one_name_is_a_single_invocation(self):
        plan = self.plan(self.names(1))
        self.assertEqual(1, len(plan.commands))

    def test_14999_names_are_a_single_invocation(self):
        plan = self.plan(self.names(14999))
        self.assertEqual(1, len(plan.commands))

    def test_exactly_15000_names_are_a_single_invocation(self):
        plan = self.plan(self.names(15000))
        self.assertEqual(1, len(plan.commands))

    def test_15001_names_are_two_invocations(self):
        plan = self.plan(self.names(15001))
        self.assertEqual(2, len(plan.commands))
        self.assertEqual([15000, 1],
                         [len(c) for c in self.names_in_chunk_files(plan)])

    def test_206080_names_are_fourteen_invocations(self):
        plan = self.plan(self.names(206080))
        self.assertEqual(14, len(plan.commands))
        sizes = [len(c) for c in self.names_in_chunk_files(plan)]
        self.assertEqual([15000] * 13 + [11080], sizes)

    def test_every_chunk_respects_the_bound(self):
        plan = self.plan(self.names(206080))
        for chunk in self.names_in_chunk_files(plan):
            self.assertLessEqual(len(chunk), NS_DNSX_CHUNK_SIZE)

    def test_force_keeps_the_chunk_bound(self):
        """FORCE must never mean an unbounded dnsx invocation."""
        plan = self.plan(self.names(206080), provider=static_provider({}),
                         force=True)
        self.assertEqual(14, len(plan.commands))
        for chunk in self.names_in_chunk_files(plan):
            self.assertLessEqual(len(chunk), NS_DNSX_CHUNK_SIZE)

    def test_sizing_contract_still_holds(self):
        worst_case = NS_DNSX_CHUNK_SIZE * NS_SECONDS_PER_NAME_AT_RATE_LIMIT
        self.assertLess(worst_case, common.NS_COMMAND_TIMEOUT)


class TestSelectionHappensBeforeChunking(ChunkingTestCase, unittest.TestCase):
    def test_selection_precedes_chunking(self):
        """The mission's anti-pattern: 206k chunked then all chunks run."""
        names = self.names(206080)
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:200000]}
        plan = self.plan(names, provider=static_provider(prior))
        self.assertEqual(1, len(plan.commands))
        chunked = self.names_in_chunk_files(plan)
        self.assertEqual(6080, sum(len(c) for c in chunked))

    def test_fresh_names_never_reach_dnsx(self):
        names = self.names(10)
        prior = {n: self.resolve(n, hours_ago=1) for n in names}
        plan = self.plan(names, provider=static_provider(prior))
        self.assertEqual([], plan.commands)
        self.assertEqual(0, len(self.names_in_chunk_files(plan)))

    def test_selected_subset_is_chunked_when_it_exceeds_the_bound(self):
        names = self.names(40000)
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:20000]}
        plan = self.plan(names, provider=static_provider(prior))
        self.assertEqual(2, len(plan.commands))
        sizes = [len(c) for c in self.names_in_chunk_files(plan)]
        self.assertEqual([15000, 5000], sizes)

    def test_no_name_is_lost_across_chunks(self):
        names = self.names(40000)
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:20000]}
        plan = self.plan(names, provider=static_provider(prior))
        chunked = [n for chunk in self.names_in_chunk_files(plan) for n in chunk]
        self.assertEqual(names[20000:], chunked)

    def test_no_name_is_duplicated_across_chunks(self):
        plan = self.plan(self.names(31000))
        chunked = [n for chunk in self.names_in_chunk_files(plan) for n in chunk]
        self.assertEqual(len(chunked), len(set(chunked)))

    def test_chunk_order_follows_the_candidate_order(self):
        names = self.names(5)
        plan = self.plan(names)
        chunked = [n for chunk in self.names_in_chunk_files(plan) for n in chunk]
        self.assertEqual(names, chunked)

    def test_duplicate_candidates_are_written_once(self):
        names = ["a.example.com", "b.example.com", "a.example.com"]
        plan = self.plan(names)
        chunked = [n for chunk in self.names_in_chunk_files(plan) for n in chunk]
        self.assertEqual(["a.example.com", "b.example.com"], chunked)

    def test_invalid_candidates_are_not_written_to_any_chunk(self):
        plan = self.plan(["good.example.com", "bad_name", "also_bad"])
        chunked = [n for chunk in self.names_in_chunk_files(plan) for n in chunk]
        self.assertEqual(["good.example.com"], chunked)


class TestUnchangedPassThrough(ChunkingTestCase, unittest.TestCase):
    def test_small_fully_eligible_list_keeps_the_original_command(self):
        names = self.names(3)
        path = self.list_file(names)
        command = self.command_for(path)
        plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)
        self.assertEqual([], plan.temp_paths)

    def test_non_dnsx_command_is_untouched(self):
        command = "curl -s https://example.com"
        plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)
        self.assertIsNone(plan.selection)

    def test_dnsx_without_a_list_argument_is_untouched(self):
        command = f"dnsx -d example.com {DNSX_TAIL}"
        plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)
        self.assertIsNone(plan.selection)

    def test_missing_list_file_is_untouched(self):
        command = self.command_for("/nonexistent/list.txt")
        plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)

    def test_chunked_command_keeps_the_original_tail(self):
        plan = self.plan(self.names(15001))
        for command in plan.commands:
            self.assertTrue(command.endswith(DNSX_TAIL))

    def test_chunked_command_keeps_the_executable(self):
        plan = self.plan(self.names(15001))
        for command in plan.commands:
            self.assertTrue(command.startswith("dnsx -l "))

    def test_quoted_list_path_is_handled(self):
        names = self.names(15001)
        path = self.list_file(names)
        command = f'dnsx -l "{path}" {DNSX_TAIL}'
        plan = common._dnsx_run_plan(command)
        self.assertEqual(2, len(plan.commands))


class TestTempFileHygiene(ChunkingTestCase, unittest.TestCase):
    def test_chunk_files_are_cleaned_up_after_success(self):
        names = self.names(15001)
        path = self.list_file(names)
        command = self.command_for(path)
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(stdout="")):
            common.run_command_in_zsh_ns(command)
        leftovers = [n for n in os.listdir(self._tmpdir.name)
                     if n not in ("candidates.txt", "state.json")]
        self.assertEqual([], leftovers)

    def test_chunk_files_are_cleaned_up_after_failure(self):
        names = self.names(15001)
        path = self.list_file(names)
        command = self.command_for(path)
        with mock.patch.object(common.subprocess, "run",
                               return_value=_proc(returncode=2, stderr="boom")):
            with self.assertRaises(common.ToolError):
                common.run_command_in_zsh_ns(command)
        leftovers = [n for n in os.listdir(self._tmpdir.name)
                     if n not in ("candidates.txt", "state.json")]
        self.assertEqual([], leftovers)

    def test_no_chunk_file_when_nothing_is_filtered(self):
        names = self.names(3)
        path = self.list_file(names)
        plan = common._dnsx_run_plan(self.command_for(path))
        self.assertEqual([], plan.temp_paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)

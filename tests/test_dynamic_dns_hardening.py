#!/usr/bin/env python3
"""Focused Dynamic DNS hardening tests (offline, fully mocked).

Covers the candidate-explosion / timeout hardening added to
``ns/watch_dns_dynamic.py`` and ``ns/dns_brute_common.py``:

  1. normal alterx success (bounded, streamed candidate file)
  2. empty input
  3. duplicate input
  4. malformed hostname
  5. alterx timeout
  6. partial output on timeout is discarded
  7. candidate explosion protection
  8. subprocess non-zero exit
  9. per-domain failure does not stop other domains
 10. deterministic output ordering

No test runs alterx, puredns, dnsx, the network, MongoDB, or the pipeline.
``subprocess.Popen``, alterx resolution, the Mongo cursor, and Telegram are
mocked throughout.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "ns"))

import watch_dns_dynamic as dynamic
from dns_brute_common import (
    ToolError,
    ToolTimeout,
    bounded_deterministic_sample,
    is_valid_hostname,
    stream_valid_candidates,
    DYNAMIC_MAX_CANDIDATES,
)


class _Doc:
    def __init__(self, subdomain):
        self.subdomain = subdomain


class _Query:
    def __init__(self, docs):
        self._docs = docs

    def only(self, *args, **kwargs):
        return self

    def __iter__(self):
        return iter(self._docs)


def _patch_subdomains(docs):
    return mock.patch.object(dynamic.Subdomains, "objects", return_value=_Query(docs))


def _popen_writing(names, returncode=0):
    def factory(argv, **kwargs):
        proc = mock.Mock()
        proc.pid = 4242
        proc.returncode = returncode
        Path(argv[argv.index("-o") + 1]).write_text("\n".join(names))
        proc.communicate.return_value = ("", "alterx: simulated failure")
        return proc

    return factory


class TestHostnameValidation(unittest.TestCase):
    def test_valid_hostnames(self):
        for name in ("www.dell.com", "a.b.c.example.co.uk", "api", "x_1.example.com"):
            self.assertTrue(is_valid_hostname(name), name)

    def test_invalid_hostnames(self):
        for name in ("", "   ", "*.dell.com", "a..b", "-a.com", "a-.com",
                     "bad host", "http://x.com", "a/b.com", None):
            self.assertFalse(is_valid_hostname(name), repr(name))


class TestBuildKnownFile(unittest.TestCase):
    def test_dedups_validates_and_sorts(self):
        docs = [
            _Doc("www.dell.com"), _Doc("api.dell.com"), _Doc("www.dell.com"),
            _Doc(""), _Doc("*.dell.com"), _Doc("bad host"), _Doc(None),
            _Doc("Api.dell.com"),
        ]
        with tempfile.TemporaryDirectory() as td:
            known = Path(td) / "known.txt"
            with _patch_subdomains(docs):
                stats = dynamic.build_known_file("dell.com", known, 1000)
            lines = known.read_text().splitlines()

        self.assertEqual(stats["total"], 8)
        self.assertEqual(stats["malformed"], 4)      # "", "*.dell.com", "bad host", None
        self.assertEqual(stats["duplicates"], 1)     # second "www.dell.com"
        self.assertEqual(stats["unique"], 3)
        self.assertEqual(stats["selected"], 3)
        self.assertFalse(stats["truncated"])
        self.assertEqual(lines, sorted(lines))       # deterministic ordering
        self.assertEqual(
            set(lines), {"www.dell.com", "api.dell.com", "Api.dell.com"}
        )

    def test_empty_input_yields_zero_selected(self):
        with tempfile.TemporaryDirectory() as td:
            known = Path(td) / "known.txt"
            with _patch_subdomains([_Doc(""), _Doc("bad host"), _Doc(None)]):
                stats = dynamic.build_known_file("x.com", known, 1000)
            self.assertEqual(stats["selected"], 0)
            self.assertEqual(stats["unique"], 0)

    def test_truncation_is_deterministic_sorted_sample(self):
        docs = [_Doc("h%05d.x.com" % i) for i in range(5000)]
        with tempfile.TemporaryDirectory() as td:
            known = Path(td) / "known.txt"
            with _patch_subdomains(docs):
                first = dynamic.build_known_file("x.com", known, 100)
                first_lines = known.read_text().splitlines()
                second = dynamic.build_known_file("x.com", known, 100)
                second_lines = known.read_text().splitlines()

        self.assertEqual(first["selected"], 100)
        self.assertEqual(first["unique"], 5000)
        self.assertTrue(first["truncated"])
        self.assertEqual(first_lines, second_lines)          # deterministic
        self.assertEqual(first_lines, sorted(first_lines))   # preserves order
        self.assertEqual(len(set(first_lines)), 100)         # no duplicates

    def test_normal_input_not_truncated(self):
        docs = [_Doc("a.x.com"), _Doc("b.x.com")]
        with tempfile.TemporaryDirectory() as td:
            known = Path(td) / "known.txt"
            with _patch_subdomains(docs):
                stats = dynamic.build_known_file("x.com", known, 1000)
            self.assertEqual(stats["selected"], 2)
            self.assertFalse(stats["truncated"])


class TestStreamValidCandidates(unittest.TestCase):
    def test_caps_and_dedups_preserving_order(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "raw.txt"
            dst = Path(td) / "out.txt"
            src.write_text(
                "a.x.com\nb.x.com\na.x.com\n\nbad host\nc.x.com\n*.x.com\n"
            )
            count = stream_valid_candidates(src, dst, 2)
            written = dst.read_text().splitlines()

        self.assertEqual(count, 2)
        self.assertEqual(written, ["a.x.com", "b.x.com"])

    def test_unbounded_when_max_is_large(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "raw.txt"
            dst = Path(td) / "out.txt"
            src.write_text("a.x.com\nb.x.com\nc.x.com\n")
            count = stream_valid_candidates(src, dst, 10**9)
        self.assertEqual(count, 3)

    def test_bounded_sample_deterministic(self):
        items = ["h%03d.x" % i for i in range(1000)]
        a = bounded_deterministic_sample(items, 10)
        b = bounded_deterministic_sample(items, 10)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 10)
        self.assertEqual(a, sorted(a))


class TestRunAlterx(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.known = Path(self.td.name) / "known.txt"
        self.known.write_text("www.dell.com\napi.dell.com")
        self.raw = Path(self.td.name) / "raw.txt"
        self.cand = Path(self.td.name) / "cand.txt"

    def tearDown(self):
        self.td.cleanup()

    def test_normal_success_streams_candidates(self):
        captured = {}

        def factory(argv, **kwargs):
            captured["argv"] = argv
            return _popen_writing(["a.dell.com", "b.dell.com"])(argv, **kwargs)

        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"), \
                mock.patch.object(dynamic.subprocess, "Popen", side_effect=factory):
            count = dynamic.run_alterx(self.known, self.raw, self.cand)

        self.assertEqual(count, 2)
        self.assertEqual(self.cand.read_text().splitlines(), ["a.dell.com", "b.dell.com"])
        # Invocation hardening: no shell, bounded output, no update check.
        self.assertIn("-silent", captured["argv"])
        self.assertIn("-duc", captured["argv"])
        self.assertIn("-limit", captured["argv"])
        self.assertEqual(
            captured["argv"][captured["argv"].index("-limit") + 1],
            str(DYNAMIC_MAX_CANDIDATES),
        )
        self.assertNotIn("-p", captured["argv"])  # patterns preserved/unchanged

    def test_timeout_discards_partial_output(self):
        def factory(argv, **kwargs):
            proc = mock.Mock()
            proc.pid = 4242
            proc.returncode = None
            Path(argv[argv.index("-o") + 1]).write_text("partial.dell.com")
            proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=argv, timeout=1)
            return proc

        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"), \
                mock.patch.object(dynamic.subprocess, "Popen", side_effect=factory), \
                mock.patch.object(dynamic, "_terminate_process_group") as term:
            with self.assertRaises(ToolTimeout):
                dynamic.run_alterx(self.known, self.raw, self.cand)

        term.assert_called_once()
        self.assertFalse(self.raw.exists())
        self.assertFalse(self.cand.exists())

    def test_nonzero_exit_raises_without_candidates(self):
        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"), \
                mock.patch.object(dynamic.subprocess, "Popen",
                                  side_effect=_popen_writing(["x.dell.com"], returncode=127)):
            with self.assertRaises(ToolError) as ctx:
                dynamic.run_alterx(self.known, self.raw, self.cand)

        self.assertIn("exit 127", str(ctx.exception))
        self.assertFalse(self.cand.exists())
        self.assertFalse(self.raw.exists())

    def test_empty_input_raises(self):
        empty = Path(self.td.name) / "empty.txt"
        empty.write_text("")
        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"):
            with self.assertRaises(ToolError) as ctx:
                dynamic.run_alterx(empty, self.raw, self.cand)
        self.assertIn("empty", str(ctx.exception))

    def test_missing_output_file_is_not_zero_success(self):
        def factory(argv, **kwargs):
            proc = mock.Mock()
            proc.pid = 4242
            proc.returncode = 0
            proc.communicate.return_value = ("", "")
            return proc

        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"), \
                mock.patch.object(dynamic.subprocess, "Popen", side_effect=factory):
            with self.assertRaises(ToolError):
                dynamic.run_alterx(self.known, self.raw, self.cand)

    def test_output_is_capped(self):
        names = ["c%05d.dell.com" % i for i in range(500)]
        with mock.patch.object(dynamic, "require_tool", return_value="/usr/bin/alterx"), \
                mock.patch.object(dynamic.subprocess, "Popen",
                                  side_effect=_popen_writing(names)):
            count = dynamic.run_alterx(self.known, self.raw, self.cand, max_candidates=50)

        self.assertEqual(count, 50)
        self.assertEqual(len(self.cand.read_text().splitlines()), 50)


class TestMainFailSoft(unittest.TestCase):
    def _run_main(self, domains, side_effect, argv_extra=None):
        argv = ["watch_dns_dynamic.py"] + (argv_extra or [])
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(dynamic, "get_feasible_domains_ordered", return_value=domains), \
                mock.patch.object(dynamic, "require_tools", return_value=[]), \
                mock.patch.object(dynamic, "send_telegram", return_value=None), \
                mock.patch.object(dynamic, "process_domain", side_effect=side_effect) as pd:
            rc = dynamic.main()
        return rc, pd

    def test_one_failure_does_not_stop_others(self):
        domains = [("p", "a.com"), ("p", "b.com"), ("p", "c.com")]

        def side_effect(program_name, domain):
            if domain == "b.com":
                raise ToolTimeout("alterx timed out on b.com")
            return 1 if domain == "a.com" else 0

        rc, pd = self._run_main(domains, side_effect)
        self.assertEqual(pd.call_count, 3)
        self.assertEqual(rc, 1)  # exactly one failed domain

    def test_generic_failure_also_isolated(self):
        domains = [("p", "a.com"), ("p", "b.com")]

        def side_effect(program_name, domain):
            if domain == "a.com":
                raise ToolError("boom")
            return 0

        rc, pd = self._run_main(domains, side_effect)
        self.assertEqual(pd.call_count, 2)
        self.assertEqual(rc, 1)

    def test_all_success_returns_zero(self):
        domains = [("p", "a.com"), ("p", "b.com")]
        rc, pd = self._run_main(domains, lambda p, d: 1)
        self.assertEqual(pd.call_count, 2)
        self.assertEqual(rc, 0)

    def test_skipped_domain_is_not_a_failure(self):
        domains = [("p", "a.com")]
        rc, pd = self._run_main(domains, lambda p, d: None)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

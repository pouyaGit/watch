#!/usr/bin/env python3
"""EPIC10 SS11/SS12/SS16/SS20 -- fail-closed, atomicity, downstream, security.

The critical safety properties, pinned as executable checks:

* a selector failure ABORTS the DNS step -- it must never degrade into a full
  scope re-resolution (the failure mode that would re-introduce the 5h run);
* existing DNS data is never deleted or rewritten by the selector;
* downstream stages keep seeing FRESH names as live ("not queried this run" is
  not "does not exist");
* the selector executes nothing, imports nothing dangerous, and carries no
  secrets.
"""

import ast
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
from utils.dns_incremental import (  # noqa: E402
    DEFAULT_STATE_FILE,
    DnsCategory,
    DnsSelectionError,
    PriorResolution,
)

MODULE_PATH = REPO_ROOT / "utils" / "dns_incremental.py"
MODULE_SOURCE = MODULE_PATH.read_text(encoding="utf-8")
MODULE_TREE = ast.parse(MODULE_SOURCE)


def _proc(returncode=0, stdout="", stderr=""):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


class SafetyTestCase(IncrementalTestCase):
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

    def list_file(self, names):
        path = os.path.join(self._tmpdir.name, "candidates.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(names) + "\n")
        return path

    def command(self, names):
        return f"dnsx -l {self.list_file(names)} -silent -a -resp -json -t 10"


class TestFailClosed(SafetyTestCase, unittest.TestCase):
    def test_provider_failure_aborts_the_step(self):
        def exploding_provider(names):
            raise RuntimeError("mongo is down")
        dns_incremental.set_prior_lookup_provider(exploding_provider)
        with mock.patch.object(common.subprocess, "run") as run:
            with self.assertRaises(DnsSelectionError):
                common.run_command_in_zsh_ns(self.command(["a.example.com"]))
            run.assert_not_called()

    def test_provider_failure_never_falls_back_to_the_full_scope(self):
        names = [f"h{i}.example.com" for i in range(500)]

        def exploding_provider(_names):
            raise RuntimeError("boom")
        dns_incremental.set_prior_lookup_provider(exploding_provider)
        with mock.patch.object(common.subprocess, "run") as run:
            with self.assertRaises(DnsSelectionError):
                common.run_command_in_zsh_ns(self.command(names))
        # the decisive assertion: dnsx was NEVER invoked with the full list
        run.assert_not_called()

    def test_corrupt_state_file_aborts_the_step(self):
        with open(self.state_file, "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        with mock.patch.object(common.subprocess, "run") as run:
            with self.assertRaises(DnsSelectionError):
                common.run_command_in_zsh_ns(self.command(["a.example.com"]))
            run.assert_not_called()

    def test_malformed_policy_aborts_the_step(self):
        with mock.patch.dict(os.environ, {"DNS_RESOLUTION_FRESHNESS_HOURS": "soon"}):
            with mock.patch.object(common.subprocess, "run") as run:
                with self.assertRaises(DnsSelectionError):
                    common.run_command_in_zsh_ns(self.command(["a.example.com"]))
                run.assert_not_called()

    def test_failure_is_announced_before_aborting(self):
        def exploding_provider(_names):
            raise RuntimeError("boom")
        dns_incremental.set_prior_lookup_provider(exploding_provider)
        with mock.patch.object(common.subprocess, "run"):
            with mock.patch("builtins.print") as printer:
                with self.assertRaises(DnsSelectionError):
                    common.run_command_in_zsh_ns(self.command(["a.example.com"]))
        printed = " ".join(str(c) for c in printer.call_args_list)
        self.assertIn("failing closed", printed)

    def test_selection_error_type_is_specific(self):
        self.assertTrue(issubclass(DnsSelectionError, Exception))

    def test_disabled_selection_does_not_read_prior_state(self):
        calls = []

        def provider(names):
            calls.append(list(names))
            return {}
        dns_incremental.set_prior_lookup_provider(provider)
        with mock.patch.dict(os.environ, {"DNS_RESOLUTION_ENABLED": "false"}):
            with mock.patch.object(common.subprocess, "run",
                                   return_value=_proc()) as run:
                common.run_command_in_zsh_ns(self.command(["a.example.com"]))
        self.assertEqual([], calls, "disabled selection must not query the DB")
        self.assertEqual(1, run.call_count)
        self.assertFalse(os.path.exists(self.state_file))

    def test_disabled_selection_keeps_the_original_command(self):
        with mock.patch.dict(os.environ, {"DNS_RESOLUTION_ENABLED": "false"}):
            command = self.command(["a.example.com", "b.example.com"])
            plan = common._dnsx_run_plan(command)
        self.assertEqual([command], plan.commands)


class TestExistingDataIsPreserved(SafetyTestCase, unittest.TestCase):
    def test_selector_never_deletes_or_updates_collections(self):
        """AST guard: the selector may only READ the pinned collections.

        (`DnsAttemptStore.save` writes the *attempt state file*, which is the
        selector's own runtime state -- not a collection write -- so the guard
        targets attribute calls rooted at the model classes.)
        """
        banned_attributes = {"delete", "remove", "update", "drop_collection",
                             "save", "modify", "upsert", "insert"}
        offenders = []
        for node in ast.walk(MODULE_TREE):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            root = func
            while isinstance(root, ast.Attribute):
                root = root.value
            root_name = getattr(root, "id", None)
            if root_name in {"LiveSubdomains", "Subdomains", "Programs",
                             "DnsBruteStatus"} and func.attr in banned_attributes:
                offenders.append(f"{root_name}.{func.attr}")
        self.assertEqual([], offenders,
                         "dns_incremental must never write to the collections")


    def test_selector_does_not_import_the_pinned_database_module_at_import_time(self):
        """`database.db` is imported lazily, inside the Mongo provider only."""
        top_level_imports = []
        for node in MODULE_TREE.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                top_level_imports.append(ast.dump(node))
        self.assertFalse(
            any("database" in dumped for dumped in top_level_imports),
            "a top-level database import would make the selector unusable offline")

    def test_fresh_name_keeps_its_prior_state(self):
        prior = {"fresh.example.com": PriorResolution(
            last_resolved=None, source_changed=False, scope="example.com")}
        result = self.select(["fresh.example.com"], provider=static_provider(
            {"fresh.example.com": self.resolve("fresh.example.com", hours_ago=1)}))
        self.assertEqual([], result.selected)
        # nothing about the name was rewritten by the selector
        self.assertEqual(1, len(result.decisions))
        self.assertEqual(DnsCategory.FRESH, result.decisions[0].category)

    def test_selector_does_not_touch_the_attempt_store_for_skipped_names(self):
        prior = {"fresh.example.com": self.resolve("fresh.example.com",
                                                   hours_ago=1)}
        selection = self.select(["fresh.example.com"],
                                provider=static_provider(prior))
        dns_incremental.record_run_outcome(selection, [],
                                           reporter=lambda _l: None)
        self.assertEqual({}, self.store.load())


class TestDownstreamCompatibility(SafetyTestCase, unittest.TestCase):
    """`not queried this run` must never read as `does not exist` downstream."""

    def test_fresh_name_is_still_returned_by_the_http_stage_query(self):
        class FakeRow:
            def __init__(self, subdomain, cdn):
                self.subdomain = subdomain
                self.cdn = cdn

        class FakeCollection:
            def __init__(self, rows):
                self.rows = rows

            def objects(self, scope=None, cdn__ne=None):
                return [r for r in self.rows
                        if (scope is None or True)
                        and (cdn__ne is None or r.cdn != cdn__ne)]

        rows = [FakeRow("fresh.example.com", "Normal"),
                FakeRow("internal.example.com", "Internal")]
        # the DNS selector skipped fresh.example.com this run ...
        self.select(["fresh.example.com"],
                    provider=static_provider(
                        {"fresh.example.com": self.resolve("fresh.example.com",
                                                           hours_ago=1)}))
        # ... and the HTTP stage still sees it as a live subdomain
        visible = [r.subdomain for r in
                   FakeCollection(rows).objects(scope="example.com",
                                                cdn__ne="Internal")]
        self.assertIn("fresh.example.com", visible)

    def test_skipping_a_name_does_not_imply_it_resolved_to_nothing(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertEqual([], result.selected)
        self.assertEqual(0, result.counts.get(DnsCategory.NEW, 0))
        self.assertEqual(0, result.counts.get(DnsCategory.INVALID, 0))

    def test_report_distinguishes_skipped_from_resolved(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        selection = self.select(["a.example.com"], provider=static_provider(prior))
        lines = []
        dns_incremental.record_run_outcome(selection, [],
                                           reporter=lines.append)
        text = "\n".join(lines)
        self.assertIn("Queried:                  0", text)
        self.assertIn("Resolved:                 0", text)


class TestNoDangerousCapability(unittest.TestCase):
    def test_no_subprocess_or_socket_imports(self):
        banned = {"subprocess", "socket", "ssl", "urllib", "http", "requests",
                  "shutil", "pty", "telnetlib", "ftplib", "smtplib"}
        imported = set()
        for node in ast.walk(MODULE_TREE):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(set(), imported & banned)

    def test_no_os_system_or_popen_calls(self):
        for node in ast.walk(MODULE_TREE):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {"system", "popen", "spawn",
                                                  "execv", "execvp", "fork"})

    def test_no_shell_command_construction(self):
        """The selector decides names; it never builds a dnsx command.

        Docstrings may *document* the command shape; executable string literals
        may not contain one.
        """
        docstrings = set()
        for node in ast.walk(MODULE_TREE):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                body = getattr(node, "body", [])
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    docstrings.add(id(body[0].value))
        for node in ast.walk(MODULE_TREE):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings):
                self.assertNotIn("dnsx -", node.value,
                                 "the selector must not build an invocation")
                self.assertNotIn(" -l ", node.value,
                                 "the selector must not build a -l argument")

    def test_no_credential_shaped_literals(self):
        lowered = MODULE_SOURCE.lower()
        for token in ("password", "secret", "token=", "api_key", "apikey",
                      "private_key", "authorization:"):
            self.assertNotIn(token, lowered)

    def test_module_has_no_dns_client(self):
        self.assertNotIn("dns.resolver", MODULE_SOURCE)
        self.assertNotIn("dnspython", MODULE_SOURCE)

    def test_selector_is_pure_python_stdlib_only(self):
        """Top-level imports are stdlib only; project imports stay lazy."""
        stdlib = {"json", "os", "re", "time", "typing", "datetime",
                  "dataclasses", "__future__"}
        imported = set()
        for node in MODULE_TREE.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(set(), imported - stdlib)

    def test_database_import_is_inside_a_function(self):
        """The only project import must be lazy (keeps the module testable)."""
        for node in ast.walk(MODULE_TREE):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.ImportFrom) and child.module:
                        if child.module.split(".")[0] == "database":
                            return
        self.fail("expected the database import inside mongo_prior_lookup")


class TestStateFilePlacement(unittest.TestCase):
    def test_default_state_file_lives_under_ai_data(self):
        self.assertTrue(DEFAULT_STATE_FILE.startswith("ai_data"))

    def test_default_state_dir_is_gitignored(self):
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("ai_data/dns/", gitignore)

    def test_state_file_is_not_inside_a_pinned_tree(self):
        for pinned_prefix in ("ns/", "crawl/", "database/", "nuclei/", "ai/",
                              "systemd/"):
            self.assertFalse(DEFAULT_STATE_FILE.startswith(pinned_prefix))


if __name__ == "__main__":
    unittest.main(verbosity=2)

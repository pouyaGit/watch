"""Tests for scripts/watch-agent/delivery/diff_guard.py + the delivery scripts.

Covers the guard's contract: allowed paths, forbidden paths, secrets,
environment and system files, dangerous modifications, deterministic output,
no filesystem writes and safe failure. Also pins the safety of the shell
scripts themselves (read-only, never push/merge/rebase).
"""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
DELIVERY_DIR = REPO_ROOT / "scripts" / "watch-agent" / "delivery"
GUARD_PATH = DELIVERY_DIR / "diff_guard.py"
POLICY_PATH = DELIVERY_DIR / "policy.py"
SCRIPTS = ("status.sh", "check.sh", "report.sh")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_cli(path: Path, *args: str, stdin: str = ""):
    return subprocess.run(
        [sys.executable, str(path), *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


# Fixtures for the credential / live-gate detectors are assembled at runtime so
# this test file never contains a literal that the guard would (correctly) flag.
# The detector still sees the assembled string when the test feeds it a diff.
_DASHES = "-" * 5
PRIVATE_KEY_LINE = f"-----BEGIN RSA PRIVATE KEY{_DASHES}"
LIVE_FLAG_NAME = "LIVE_" + "TRAFFIC_ENABLED"
LIVE_ENV_NAME = "WATCH_AI_" + "LIVE_VALIDATION"
MONGO_URI = "mongodb" + "://watcher:" + "s3cr3t@localhost:27017/watch"


class GuardTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = load_module("watch_diff_guard", GUARD_PATH)


class TestChangeParsing(GuardTestCase):
    def test_name_status_is_parsed(self):
        changes = self.guard.parse_changes(
            "M\taec/selection.py\nA\tagent-reports/x.md\nD\tdocs/old.md\n"
        )
        self.assertEqual([c["status"] for c in changes], ["M", "A", "D"])
        self.assertEqual(changes[0]["path"], "aec/selection.py")

    def test_rename_name_status_is_parsed(self):
        changes = self.guard.parse_changes("R100\tdocs/old.md\tdocs/new.md\n")
        self.assertEqual(changes[0]["status"], "R100")
        self.assertEqual(changes[0]["old_path"], "docs/old.md")
        self.assertEqual(changes[0]["path"], "docs/new.md")

    def test_porcelain_status_is_parsed(self):
        changes = self.guard.parse_changes(" M api.py\n?? aec/new.py\nA  tests/x.py\n")
        self.assertEqual([c["path"] for c in changes], ["api.py", "aec/new.py", "tests/x.py"])

    def test_porcelain_rename_is_parsed(self):
        changes = self.guard.parse_changes("R  docs/old.md -> docs/new.md\n")
        self.assertEqual(changes[0]["path"], "docs/new.md")
        self.assertEqual(changes[0]["old_path"], "docs/old.md")

    def test_empty_input_yields_no_changes(self):
        self.assertEqual(self.guard.parse_changes(""), ())

    def test_garbage_input_is_a_safe_failure_not_an_exception(self):
        result = self.guard.evaluate_text("not a git status line at all")
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("UNPARSEABLE_INPUT", [f["kind"] for f in result["findings"]])


class TestVerdicts(GuardTestCase):
    def verdict(self, changes, diff_text=""):
        return self.guard.evaluate(changes, diff_text=diff_text)

    def kinds(self, result):
        return sorted(f["kind"] for f in result["findings"])

    def test_allowed_change_passes(self):
        result = self.verdict(
            [
                {"status": "M", "path": "aec/selection.py"},
                {"status": "A", "path": "tests/test_delivery_guard.py"},
                {"status": "A", "path": "agent-reports/autonomous-delivery-pipeline-v1.md"},
            ]
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_forbidden_path_blocks(self):
        result = self.verdict([{"status": "M", "path": "ai/execution/http_executor.py"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("FORBIDDEN_PATH", self.kinds(result))

    def test_new_file_in_forbidden_directory_blocks(self):
        result = self.verdict([{"status": "A", "path": "ai/verification/deterministic/new_gate.py"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("FORBIDDEN_PATH", self.kinds(result))

    def test_secret_file_blocks(self):
        result = self.verdict([{"status": "A", "path": "deploy/server.pem"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("SECRET_FILE", self.kinds(result))

    def test_env_file_blocks(self):
        result = self.verdict([{"status": "M", "path": ".env"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("ENV_CHANGE", self.kinds(result))

    def test_system_file_blocks(self):
        result = self.verdict([{"status": "A", "path": "systemd/watch-delivery.service"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("SYSTEM_FILE", self.kinds(result))

    def test_unknown_path_warns_without_blocking(self):
        result = self.verdict([{"status": "A", "path": "brand-new/thing.py"}])
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("UNKNOWN_PATH", self.kinds(result))
        self.assertTrue(result["warnings"])

    def test_live_gate_flip_blocks(self):
        diff = (
            "diff --git a/ai/execution/http_executor.py b/ai/execution/http_executor.py\n"
            "--- a/ai/execution/http_executor.py\n"
            "+++ b/ai/execution/http_executor.py\n"
            "@@ -1 +1 @@\n"
            f"-{LIVE_FLAG_NAME} = False\n"
            f"+{LIVE_FLAG_NAME} = True\n"
        )
        result = self.verdict([{"status": "M", "path": "ai/execution/http_executor.py"}], diff)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("LIVE_GATE_FLIP", self.kinds(result))

    def test_live_env_enablement_blocks(self):
        diff = f"+export {LIVE_ENV_NAME}=1\n"
        result = self.verdict([{"status": "M", "path": "scripts/run.sh"}], diff)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("LIVE_GATE_FLIP", self.kinds(result))

    def test_private_key_content_blocks(self):
        diff = f"+{PRIVATE_KEY_LINE}\n"
        result = self.verdict([{"status": "M", "path": "aec/notes.py"}], diff)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("SECRET_CONTENT", self.kinds(result))

    def test_mongo_uri_with_credentials_blocks(self):
        diff = f'+WATCH_MONGO_URI = "{MONGO_URI}"\n'
        result = self.verdict([{"status": "M", "path": "aec/notes.py"}], diff)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("SECRET_CONTENT", self.kinds(result))

    def test_removed_lines_are_not_scanned_as_secrets(self):
        diff = f"-{MONGO_URI}\n+WATCH_MONGO_URI = '<redacted>'\n"
        result = self.verdict([{"status": "M", "path": "docs/notes.md"}], diff)
        self.assertEqual(result["verdict"], "PASS")

    def test_mode_change_warns(self):
        diff = "old mode 100644\nnew mode 100755\n"
        result = self.verdict([{"status": "M", "path": "scripts/watch-agent/delivery/status.sh"}], diff)
        self.assertIn("MODE_CHANGE", self.kinds(result))

    def test_deleting_a_guard_file_blocks(self):
        result = self.verdict([{"status": "D", "path": "scripts/watch-agent/delivery/policy.py"}])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GUARD_DELETED", self.kinds(result))

    def test_deleting_an_ordinary_test_file_is_allowed(self):
        result = self.verdict([{"status": "D", "path": "tests/test_old_thing.py"}])
        self.assertEqual(result["verdict"], "PASS")

    def test_empty_change_set_blocks(self):
        result = self.verdict([])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("NO_CHANGES", self.kinds(result))

    def test_malformed_change_record_blocks_safely(self):
        result = self.verdict([{"status": "M"}, "not-a-dict"])
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("UNPARSEABLE_INPUT", self.kinds(result))

    def test_guard_does_not_flag_its_own_source(self):
        own = GUARD_PATH.read_text(encoding="utf-8")
        self.assertNotIn("DUMMY_SEED_PLACEHOLDER", own)
        diff = "".join(f"+{line}\n" for line in own.splitlines())
        result = self.verdict([{"status": "M", "path": "scripts/watch-agent/delivery/diff_guard.py"}], diff)
        self.assertNotIn("SECRET_CONTENT", self.kinds(result))
        self.assertEqual(result["verdict"], "PASS")

    def test_policy_source_is_not_flagged_as_a_secret(self):
        own = POLICY_PATH.read_text(encoding="utf-8")
        diff = "".join(f"+{line}\n" for line in own.splitlines())
        result = self.verdict([{"status": "M", "path": "scripts/watch-agent/delivery/policy.py"}], diff)
        self.assertEqual(result["verdict"], "PASS")


class TestGuardDeterminism(GuardTestCase):
    def changes(self):
        return [
            {"status": "M", "path": "ai/finding/eligibility.py"},
            {"status": "A", "path": "brand-new/thing.py"},
            {"status": "A", "path": ".env"},
            {"status": "M", "path": "aec/selection.py"},
        ]

    def test_two_runs_are_identical(self):
        first = json.dumps(self.guard.evaluate(self.changes()), sort_keys=True)
        second = json.dumps(self.guard.evaluate(self.changes()), sort_keys=True)
        self.assertEqual(first, second)

    def test_input_order_does_not_change_the_verdict_or_findings(self):
        forward = self.guard.evaluate(self.changes())
        reverse = self.guard.evaluate(list(reversed(self.changes())))
        self.assertEqual(forward["verdict"], reverse["verdict"])
        self.assertEqual(
            [f["kind"] for f in forward["findings"]],
            [f["kind"] for f in reverse["findings"]],
        )

    def test_findings_are_sorted_blocking_first(self):
        findings = self.guard.evaluate(self.changes())["findings"]
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, sorted(severities, key=lambda s: 0 if s == "BLOCK" else 1))

    def test_result_reports_the_policy_fingerprint(self):
        result = self.guard.evaluate(self.changes())
        self.assertEqual(len(result["policy_fingerprint"]), 64)


class TestGuardCli(GuardTestCase):
    def test_cli_passes_allowed_change(self):
        completed = run_cli(GUARD_PATH, stdin="M\taec/selection.py\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PASS", completed.stdout)

    def test_cli_blocks_forbidden_change(self):
        completed = run_cli(GUARD_PATH, stdin="M\tai/verification/verifier.py\n")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("BLOCK", completed.stdout)

    def test_cli_json_output_is_machine_readable(self):
        completed = run_cli(GUARD_PATH, "--json", stdin="A\t.env\n")
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "BLOCK")
        self.assertIn("findings", payload)

    def test_cli_safe_failure_on_garbage_exits_two(self):
        completed = run_cli(GUARD_PATH, stdin="@@@ nonsense @@@\n")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("BLOCK", completed.stdout)

    def test_cli_reads_the_named_files_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            ns = Path(tmp) / "ns.txt"
            diff = Path(tmp) / "d.txt"
            ns.write_text("M\tai/limits/ceilings.py\n", encoding="utf-8")
            diff.write_text(f"+{LIVE_FLAG_NAME} = True\n", encoding="utf-8")
            completed = run_cli(GUARD_PATH, "--name-status", str(ns), "--diff", str(diff), "--json")
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["verdict"], "BLOCK")
            self.assertGreaterEqual(len(payload["findings"]), 1)

    def test_cli_missing_file_is_a_safe_failure(self):
        completed = run_cli(GUARD_PATH, "--name-status", "/nonexistent/ns.txt")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("BLOCK", completed.stdout)


class TestGuardMakesNoWrites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = GUARD_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_no_write_calls(self):
        banned = {"write_text", "write_bytes", "mkdir", "unlink", "remove", "rmtree", "rename"}
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        self.assertEqual(called & banned, set())

    def test_open_is_only_used_for_reading(self):
        modes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                modes.append(node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else "r")
        self.assertTrue(all("w" not in str(mode) and "a" not in str(mode) for mode in modes))

    def test_no_network_or_process_imports(self):
        names = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        self.assertEqual(
            names & {"socket", "subprocess", "urllib", "http", "requests", "shutil", "os"},
            set(),
        )

    def test_evaluate_writes_nothing_to_the_working_directory(self):
        guard = load_module("watch_diff_guard_probe", GUARD_PATH)
        with tempfile.TemporaryDirectory() as tmp:
            before = sorted(Path(tmp).iterdir())
            cwd = Path.cwd()
            try:
                import os

                os.chdir(tmp)
                guard.evaluate([{"status": "M", "path": "aec/x.py"}], diff_text="+ok\n")
            finally:
                os.chdir(cwd)
            self.assertEqual(before, sorted(Path(tmp).iterdir()))


class TestDeliveryScripts(unittest.TestCase):
    """The delivery scripts must stay read-only and never promote by themselves."""

    def read(self, name):
        path = DELIVERY_DIR / name
        self.assertTrue(path.is_file(), f"missing {path}")
        return path.read_text(encoding="utf-8")

    def test_scripts_exist_and_are_executable(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                path = DELIVERY_DIR / name
                self.assertTrue(path.is_file(), f"missing {path}")
                self.assertTrue(path.stat().st_mode & 0o111, f"{name} is not executable")

    def test_scripts_are_syntactically_valid(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                completed = subprocess.run(
                    ["bash", "-n", str(DELIVERY_DIR / name)], capture_output=True, text=True
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_scripts_never_push_merge_or_rewrite_history(self):
        banned = (
            "git push",
            "git merge",
            "git rebase",
            "git reset",
            "git clean",
            "git branch -D",
            "git checkout main",
            "git switch main",
            "--force",
            "--no-verify",
            "git tag",
        )
        for name in SCRIPTS:
            source = self.read(name)
            for needle in banned:
                with self.subTest(script=name, needle=needle):
                    self.assertNotIn(needle, source)

    def test_scripts_never_touch_the_production_checkout(self):
        for name in SCRIPTS:
            source = self.read(name)
            for line in source.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or "WATCH_PRODUCTION_DIR" in stripped:
                    continue
                with self.subTest(script=name, line=stripped[:40]):
                    self.assertNotIn("git -C /opt/watch ", stripped)
                    self.assertNotIn("cd /opt/watch", stripped)

    def test_status_is_read_only(self):
        source = self.read("status.sh")
        self.assertNotIn(">>", source)
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "/dev/null" in stripped or ">&2" in stripped:
                continue
            with self.subTest(line=stripped[:40]):
                self.assertNotIn(" > ", stripped)

    def test_only_report_script_writes_delivery_artifacts(self):
        for name in SCRIPTS:
            source = self.read(name)
            if name == "report.sh":
                self.assertIn("agent-reports/delivery", source)
            else:
                self.assertNotIn("agent-reports/delivery/DELIVERY-REPORT", source)

    def test_status_runs_and_reports_state(self):
        completed = subprocess.run(
            ["bash", str(DELIVERY_DIR / "status.sh")],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", "NO_COLOR": "1", "HOME": str(Path.home())},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("agent/daily-development", completed.stdout)

    def test_check_reports_a_verdict_and_exits_accordingly(self):
        completed = subprocess.run(
            ["bash", str(DELIVERY_DIR / "check.sh"), "--no-tests"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", "NO_COLOR": "1", "HOME": str(Path.home())},
        )
        output = completed.stdout + completed.stderr
        self.assertIn(completed.returncode, (0, 1))
        # Fail-closed contract: exit 0 must mean the ready verdict, and exit 1
        # must name the blocked verdict. Uncommitted delivery files are a BLOCK,
        # which is exactly what check.sh must report before the commit lands.
        if completed.returncode == 0:
            self.assertIn("READY FOR PROMOTION", output)
        else:
            self.assertIn("BLOCKED", output)
            self.assertIn("reasons:", output)


if __name__ == "__main__":
    unittest.main()

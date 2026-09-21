"""Tests for scripts/check_aec_readonly.py + aec/readonly_manifest.json (S1).

The execution plan's first line of defence: pin the hash of every file AEC-1
must never modify, *before* writing AEC-1 code, and verify it on every run.

What is asserted here:

- the manifest covers the whole §3.1 read-only contract (restated independently,
  so a convenient omission cannot silently shrink the contract)
- every pinned hash still matches the tree
- the manifest never pins credentials/material it must not read (``.env``),
  never pins AEC-1's own files, and never pins tests
- the checker exits 0 on a clean tree, and exits 1 on a tampered manifest, on a
  changed read-only path, and on a manifest with a vanished file
- the checker is read-only: it runs no mutating git command and writes nothing
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "aec" / "readonly_manifest.json"
CHECKER = REPO_ROOT / "scripts" / "check_aec_readonly.py"
WRAPPER = REPO_ROOT / "scripts" / "check-aec-readonly.sh"

#: Restated §3.1 contract: whole read-only subtrees …
READONLY_DIRS = (
    "ai/authorizer",
    "ai/evidence",
    "ai/execution",
    "ai/finding",
    "ai/limits",
    "ai/live_validation",
    "ai/persistence",
    "ai/scope",
    "ai/verification",
    "crawl",
    "database",
    "nuclei",
    "ns",
    "systemd",
)

#: … and individually pinned entry points.
READONLY_FILES = (
    "ai/schemas/evidence.py",
    "ai/schemas/execution_authorization.py",
    "backend/task_runner.py",
    "backend/tasks_registry.py",
    "pipeline_lib.sh",
    "run-heavy-guarded.sh",
    "run-pipeline.sh",
    "setup-core-pipeline.sh",
    "setup-weekly-jobs.sh",
    "watch_xss_verify.py",
)

#: Prefixes that must never appear in the manifest.
FORBIDDEN_PREFIXES = ("aec/", "tests/", "agent-reports/", "ai_data/", "web/")

SKIP_DIR_NAMES = {"__pycache__", ".git", "node_modules", ".mypy_cache"}


def required_paths() -> set:
    required = set()
    for directory in READONLY_DIRS:
        root = REPO_ROOT / directory
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_dir() or any(part in SKIP_DIR_NAMES for part in path.parts):
                continue
            required.add(path.relative_to(REPO_ROOT).as_posix())
    for relative in READONLY_FILES:
        if (REPO_ROOT / relative).is_file():
            required.add(relative)
    return required


def sha256_of(relative: str) -> str:
    return hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest()


def run_checker(*args):
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )


class TestManifestCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["path"]: entry for entry in cls.manifest["files"]}

    def test_manifest_is_pinned_to_a_rule_version(self):
        self.assertEqual(self.manifest["rule_version"], "aec-readonly/v1")
        self.assertEqual(self.manifest["count"], len(self.manifest["files"]))

    def test_generation_commit_is_recorded_informationally(self):
        commit = self.manifest["generated_from_commit"]
        self.assertTrue(re.fullmatch(r"[0-9a-f]{7,40}", commit), commit)

    def test_manifest_covers_the_whole_read_only_contract(self):
        missing = sorted(required_paths() - set(self.entries))
        self.assertEqual(missing, [], f"unpinned read-only files: {missing[:10]}")

    def test_every_pinned_hash_still_matches_the_tree(self):
        drifted = []
        for relative, entry in sorted(self.entries.items()):
            path = REPO_ROOT / relative
            if not path.is_file():
                drifted.append(f"{relative}: missing")
                continue
            if sha256_of(relative) != entry["sha256"]:
                drifted.append(f"{relative}: hash drift")
        self.assertEqual(drifted, [], f"read-only drift: {drifted[:10]}")

    def test_entries_carry_an_area_and_are_sorted_by_path(self):
        paths = [entry["path"] for entry in self.manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        for entry in self.manifest["files"]:
            self.assertTrue(entry["area"], entry)
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), entry)

    def test_manifest_never_pins_credentials_or_aec_output(self):
        for relative in self.entries:
            self.assertFalse(relative.startswith(FORBIDDEN_PREFIXES), relative)
        self.assertNotIn(".env", self.entries)
        self.assertTrue(
            any(".env" in str(item) for item in self.manifest["excluded"]),
            "the manifest must state that .env is deliberately excluded",
        )

    def test_manifest_contains_no_timestamp_noise(self):
        blob = json.dumps(self.manifest)
        self.assertNotIn("generated_at", blob)
        self.assertNotIn("mtime", blob)


class TestCheckerBehaviour(unittest.TestCase):
    def test_wrapper_script_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.is_file(), f"missing {WRAPPER}")
        self.assertTrue(WRAPPER.stat().st_mode & 0o111, "wrapper must be executable")

    def test_clean_tree_verifies(self):
        result = run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("READ-ONLY VERIFIED", result.stdout)

    def test_json_mode_reports_clean_and_is_machine_readable(self):
        result = run_checker("--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "CLEAN")
        self.assertEqual(payload["violations"], [])
        self.assertEqual(payload["pinned"], len(json.loads(MANIFEST_PATH.read_text())["files"]))

    def test_tampered_manifest_is_caught(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["files"][0]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "manifest.json"
            tampered.write_text(json.dumps(manifest), encoding="utf-8")
            result = run_checker("--manifest", str(tampered))
        self.assertEqual(result.returncode, 1)
        self.assertIn("HASH_DRIFT", result.stdout)
        self.assertIn("VIOLATION", result.stdout)

    def test_vanished_pinned_file_is_caught(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["files"].append({"path": "ai/execution/ghost_module.py", "sha256": "1" * 64, "area": "ai/execution"})
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "manifest.json"
            tampered.write_text(json.dumps(manifest), encoding="utf-8")
            result = run_checker("--manifest", str(tampered))
        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING", result.stdout)

    def test_changed_read_only_path_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths_file = Path(tmp) / "changed.txt"
            paths_file.write_text(" M ai/execution/http_executor.py\n", encoding="utf-8")
            result = run_checker("--paths-file", str(paths_file))
        self.assertEqual(result.returncode, 1)
        self.assertIn("ai/execution/http_executor.py", result.stdout)
        self.assertIn("READ_ONLY_DRIFT", result.stdout)

    def test_changed_untracked_read_only_path_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths_file = Path(tmp) / "changed.txt"
            paths_file.write_text("?? ai/verification/new_gate.py\n", encoding="utf-8")
            result = run_checker("--paths-file", str(paths_file))
        self.assertEqual(result.returncode, 1)
        self.assertIn("ai/verification/new_gate.py", result.stdout)

    def test_unrelated_dirty_paths_are_information_not_violations(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths_file = Path(tmp) / "changed.txt"
            paths_file.write_text("?? web/notes.md\n?? agent-reports/other.md\n", encoding="utf-8")
            result = run_checker("--paths-file", str(paths_file), "--json")
        self.assertEqual(result.returncode, 0, result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "CLEAN")
        self.assertEqual(payload["unrelated_dirty"], 2)

    def test_checker_is_read_only_by_construction(self):
        for path in (CHECKER, WRAPPER):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("git add", "git commit", "git push", "git checkout", "git reset", "git clean"):
                self.assertNotIn(forbidden, text, f"{path.name} must not mutate git state")
            self.assertNotIn("rm -", text, f"{path.name} must not delete anything")

    def test_checker_does_not_modify_the_manifest(self):
        before = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
        run_checker()
        run_checker("--json")
        after = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
        self.assertEqual(before, after)

    def test_unknown_arguments_fail_closed(self):
        result = run_checker("--definitely-not-a-flag")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()

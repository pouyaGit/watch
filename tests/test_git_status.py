"""Tests for the git status readiness fix (Epic 0.2.1).

Bug: status.sh did not reflect check_auth.py's verdict in the required form —
it parsed human prose ("ready via ...") instead of consuming the checker's
JSON contract, so the Push capability display could disagree with the checker.

Required contract:
  READY   -> "push READY"  + "method <name>"
  BLOCKED -> "push BLOCKED" + "reason <CODE>"

Tests:
1. READY checker output displays READY
2. BLOCKED checker output displays BLOCKED
3. JSON parsing failure fails closed
4. No token/password output
5. Existing display contract preserved (redaction, sections, exit 0)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
GIT_DIR = REPO_ROOT / "scripts" / "watch-agent" / "git"
STATUS_SH = GIT_DIR / "status.sh"

FAKE_URL_TOKEN = "faketoken123"
FAKE_URL = f"https://watch-agent:{FAKE_URL_TOKEN}@github.com/example-o/r-demo"


def run(cmd, env=None, cwd=None, timeout=60):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=merged
    )


def git(repo, *args, env=None):
    result = run(["git", "-C", str(repo), *args], env=env)
    assert result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr}"
    return result.stdout.strip()


class Sandbox:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="git-status-"))
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main", env=self.env())
        git(self.repo, "config", "user.email", "status-test@example.invalid", env=self.env())
        git(self.repo, "config", "user.name", "Status Test", env=self.env())
        (self.repo / "file.txt").write_text("data\n")
        git(self.repo, "add", "file.txt", env=self.env())
        git(self.repo, "commit", "-m", "base", env=self.env())
        git(self.repo, "remote", "add", "origin", FAKE_URL, env=self.env())
        self.write_bin(
            "fakessh",
            "#!/bin/sh\n"
            'echo "Hi testuser! You have successfully authenticated." >&2\n'
            "exit 1\n",
        )
        self.write_bin("falsessh", "#!/bin/sh\nexit 255\n")

    def env(self, extra=None):
        base = {
            "HOME": str(self.home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "NO_COLOR": "1",
            "GIT_AUTH_REPO": str(self.repo),
        }
        base.update(extra or {})
        return base

    def write_bin(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    def status(self, extra=None):
        return run(["bash", str(STATUS_SH)], env=self.env(extra))

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestReadinessDisplay(unittest.TestCase):
    def test_ready_checker_output_displays_ready(self):
        box = Sandbox()
        try:
            result = box.status({
                "GIT_AUTH_SSH": str(box.bin / "fakessh"),
                "GIT_AUTH_GH": "/bin/false",
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNotNone(re.search(r"(?m)^\s*push\s+READY\s*$", result.stdout))
            self.assertIsNotNone(re.search(r"(?m)^\s*method\s+ssh\s*$", result.stdout))
        finally:
            box.cleanup()

    def test_blocked_checker_output_displays_blocked(self):
        box = Sandbox()
        try:
            result = box.status({
                "GIT_AUTH_SSH": str(box.bin / "falsessh"),
                "GIT_AUTH_GH": str(box.bin / "falsessh"),
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNotNone(re.search(r"(?m)^\s*push\s+BLOCKED\s*$", result.stdout))
            self.assertIsNotNone(
                re.search(r"(?m)^\s*reason\s+SSH_UNAVAILABLE\b", result.stdout)
            )
        finally:
            box.cleanup()

    def test_json_parsing_failure_fails_closed(self):
        box = Sandbox()
        try:
            garbage = box.write_bin(
                "garbagechecker",
                "#!/bin/sh\necho 'this is not json {{{'\n",
            )
            result = box.status({
                "GIT_AUTH_SSH": str(box.bin / "fakessh"),
                "GIT_AUTH_GH": "/bin/false",
                "GIT_AUTH_CHECKER": str(garbage),
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNotNone(re.search(r"(?m)^\s*push\s+BLOCKED\s*$", result.stdout))
            self.assertIsNone(re.search(r"(?m)^\s*push\s+READY\s*$", result.stdout))
        finally:
            box.cleanup()

    def test_no_token_or_password_output(self):
        box = Sandbox()
        try:
            result = box.status({
                "GIT_AUTH_SSH": str(box.bin / "fakessh"),
                "GIT_AUTH_GH": "/bin/false",
            })
            combined = result.stdout + result.stderr
            self.assertNotIn(FAKE_URL_TOKEN, combined)
            for word in ("password", "passwd", "api_key", "secret"):
                self.assertNotIn(word, combined.lower())
        finally:
            box.cleanup()

    def test_existing_display_contract_preserved(self):
        box = Sandbox()
        try:
            result = box.status({
                "GIT_AUTH_SSH": str(box.bin / "falsessh"),
                "GIT_AUTH_GH": str(box.bin / "falsessh"),
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("[redacted]", result.stdout)
            self.assertIn("github.com/example-o/r-demo", result.stdout)
            for section in ("Authentication", "Remote", "Push capability"):
                self.assertIn(section, result.stdout)
        finally:
            box.cleanup()

    def test_linked_worktree_with_ready_ssh_displays_ready(self):
        """Epic 0.2.2: a linked worktree (.git file) must not read BLOCKED."""
        box = Sandbox()
        try:
            origin = box.tmp / "origin.git"
            run(["git", "init", "--bare", str(origin)],
                env=box.env(), cwd=str(box.tmp))
            git(box.repo, "remote", "set-url", "origin", str(origin), env=box.env())
            git(box.repo, "push", "origin", "main", env=box.env())
            linked = box.tmp / "linked"
            git(box.repo, "worktree", "add", str(linked), env=box.env())
            self.assertFalse((linked / ".git").is_dir())
            # Reported scenario evidence: ssh -T exits 1 *with* the success
            # text, and ls-remote reaches the remote.
            ls_remote = run(
                ["git", "-C", str(linked), "ls-remote", "origin", "HEAD"],
                env=box.env(),
            )
            self.assertEqual(ls_remote.returncode, 0, ls_remote.stderr)
            result = box.status({
                "GIT_AUTH_REPO": str(linked),
                "GIT_AUTH_SSH": str(box.bin / "fakessh"),
                "GIT_AUTH_GH": "/bin/false",
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNotNone(re.search(r"(?m)^\s*push\s+READY\s*$", result.stdout))
            self.assertIsNotNone(re.search(r"(?m)^\s*method\s+ssh\s*$", result.stdout))
        finally:
            box.cleanup()

    def test_linked_worktree_without_auth_still_blocked(self):
        box = Sandbox()
        try:
            linked = box.tmp / "linked"
            git(box.repo, "worktree", "add", str(linked), env=box.env())
            result = box.status({
                "GIT_AUTH_REPO": str(linked),
                "GIT_AUTH_SSH": str(box.bin / "falsessh"),
                "GIT_AUTH_GH": str(box.bin / "falsessh"),
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIsNotNone(re.search(r"(?m)^\s*push\s+BLOCKED\s*$", result.stdout))
            self.assertIsNone(re.search(r"(?m)^\s*push\s+READY\s*$", result.stdout))
        finally:
            box.cleanup()


if __name__ == "__main__":
    unittest.main()

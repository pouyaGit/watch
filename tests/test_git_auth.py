"""Tests for scripts/watch-agent/git/ (Epic 0.2: Credentialless Git Operations v1).

Git authentication for autonomous operation without stored passwords or
tokens: detect existing SSH / credential-helper / gh auth, refuse to proceed
when none is available, and push only through the safe wrapper.

Isolation: tests build throwaway repos under TMPDIR with a hermetic git
config (HOME redirected, GIT_CONFIG_NOSYSTEM=1) and controlled stand-in
binaries for ssh/gh. The real worktree and production are never touched.

Covered behaviors:
1.  No auth returns BLOCKED
2.  SSH available returns READY
3.  Never exposes secret
4.  Push wrapper rejects force flags
5.  Push wrapper rejects missing auth
6.  Status never prints token
7.  Promotion calls safe push wrapper
8.  No repository writes
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
PROMOTION_DIR = REPO_ROOT / "scripts" / "watch-agent" / "promotion"

STATUS_SH = GIT_DIR / "status.sh"
CHECK_AUTH_PY = GIT_DIR / "check_auth.py"
PUSH_SAFE_SH = GIT_DIR / "push_safe.sh"

# A fake credential embedded in a remote URL. Deliberately shaped so the
# delivery diff guard does NOT flag this file (no real credential pattern),
# while still proving redaction works at runtime.
FAKE_URL_TOKEN = "faketoken123"
FAKE_URL = f"https://watch-agent:{FAKE_URL_TOKEN}@github.com/example-o/r-demo"

KNOWN_REASONS = (
    "SSH_UNAVAILABLE",
    "NO_CREDENTIAL_HELPER",
    "GH_NOT_AUTHENTICATED",
    "REMOTE_UNREACHABLE",
)


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
    """Throwaway repo with hermetic git config and controlled helper binaries."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="git-auth-"))
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main", env=self.env())
        git(self.repo, "config", "user.email", "auth-test@example.invalid", env=self.env())
        git(self.repo, "config", "user.name", "Auth Test", env=self.env())
        (self.repo / "file.txt").write_text("data\n")
        git(self.repo, "add", "file.txt", env=self.env())
        git(self.repo, "commit", "-m", "base", env=self.env())
        git(self.repo, "remote", "add", "origin", FAKE_URL, env=self.env())

    def env(self, extra=None):
        base = {
            "HOME": str(self.home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "NO_COLOR": "1",
        }
        base.update(extra or {})
        return base

    def write_bin(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    def no_auth_env(self, extra=None):
        """ssh and gh both fail; no credential helper configured."""
        self.write_bin("falsessh", "#!/bin/sh\nexit 255\n")
        env = self.env({
            "GIT_AUTH_SSH": str(self.bin / "falsessh"),
            "GIT_AUTH_GH": str(self.bin / "falsessh"),
        })
        env.update(extra or {})
        return env

    def ssh_ready_env(self, extra=None):
        self.write_bin(
            "fakessh",
            "#!/bin/sh\n"
            'echo "Hi testuser! You have successfully authenticated." >&2\n'
            "exit 1\n",
        )
        env = self.env({
            "GIT_AUTH_SSH": str(self.bin / "fakessh"),
            "GIT_AUTH_GH": str(self.bin / "falsessh") if (self.bin / "falsessh").exists() else "/bin/false",
        })
        env.update(extra or {})
        return env

    def snapshot(self):
        files = sorted(
            str(p.relative_to(self.repo))
            for p in self.repo.rglob("*")
            if ".git/" not in p.parts
        )
        return (
            git(self.repo, "status", "--porcelain", env=self.env()),
            git(self.repo, "config", "--list", env=self.env()),
            files,
        )

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class GitAuthTestCase(unittest.TestCase):
    def assert_blocked(self, result):
        self.assertNotEqual(result.returncode, 0, f"expected BLOCK, got rc=0: {result.stdout}")
        self.assertIn("BLOCKED", result.stdout + result.stderr)


class TestCheckAuth(GitAuthTestCase):
    def test_no_auth_returns_blocked(self):
        box = Sandbox()
        try:
            result = run(
                [sys.executable, str(CHECK_AUTH_PY), "--repo", str(box.repo)],
                env=box.no_auth_env(),
            )
            self.assert_blocked(result)
            reasons = re.findall(r"reason: ([A-Z_]+)", result.stdout)
            self.assertTrue(reasons, "BLOCKED must name reasons")
            for reason in reasons:
                self.assertIn(reason, KNOWN_REASONS)
            self.assertIn("SSH_UNAVAILABLE", reasons)
            self.assertIn("NO_CREDENTIAL_HELPER", reasons)
            self.assertIn("GH_NOT_AUTHENTICATED", reasons)
        finally:
            box.cleanup()

    def test_ssh_available_returns_ready(self):
        box = Sandbox()
        try:
            result = run(
                [sys.executable, str(CHECK_AUTH_PY), "--repo", str(box.repo)],
                env=box.ssh_ready_env(),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("READY", result.stdout)
            self.assertIn("ssh", result.stdout)
        finally:
            box.cleanup()

    def test_never_exposes_secret(self):
        box = Sandbox()
        try:
            body = CHECK_AUTH_PY.read_text(encoding="utf-8")
            for pattern in (
                r"\bsocket\b", r"urllib", r"\bgetpass\b", r"\bread\s+-s\b",
                r"login", r"passwd",
            ):
                self.assertIsNone(
                    re.search(pattern, body, re.IGNORECASE),
                    f"check_auth.py must not touch credentials: {pattern}",
                )
            out = run(
                [sys.executable, str(CHECK_AUTH_PY), "--repo", str(box.repo), "--json"],
                env=box.no_auth_env(),
            )
            combined = out.stdout + out.stderr
            self.assertNotIn(FAKE_URL_TOKEN, combined)
            for pattern in (
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
                r"\bAKIA[0-9A-Z]{16}\b",
                r"\bghp_[A-Za-z0-9]{20,}\b",
            ):
                self.assertIsNone(re.search(pattern, combined))
        finally:
            box.cleanup()


class TestPushSafe(GitAuthTestCase):
    def test_push_wrapper_rejects_force_flags(self):
        box = Sandbox()
        try:
            for flags in (
                ["--force"], ["--force-with-lease"], ["--no-verify"], ["-f"],
            ):
                result = run(
                    ["bash", str(PUSH_SAFE_SH), "--repo", str(box.repo),
                     "origin", "main", *flags],
                    env=box.ssh_ready_env(),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("force", (result.stdout + result.stderr).lower())
        finally:
            box.cleanup()

    def test_push_wrapper_rejects_missing_auth(self):
        box = Sandbox()
        try:
            origin = self._bare_origin(box)
            git(box.repo, "remote", "set-url", "origin", str(origin), env=box.env())
            before = git(box.repo, "status", "--porcelain", env=box.env())
            result = run(
                ["bash", str(PUSH_SAFE_SH), "--repo", str(box.repo), "origin", "main"],
                env=box.no_auth_env(),
            )
            self.assert_blocked(result)
            self.assertEqual(git(box.repo, "status", "--porcelain", env=box.env()), before)
            unborn = run(
                ["git", "--git-dir", str(origin), "rev-parse", "--verify", "refs/heads/main"],
                env=box.env(),
            )
            self.assertNotEqual(unborn.returncode, 0, "nothing may be pushed on BLOCKED")
        finally:
            box.cleanup()

    def test_push_wrapper_pushes_when_ready(self):
        box = Sandbox()
        try:
            origin = self._bare_origin(box)
            git(box.repo, "remote", "set-url", "origin", str(origin), env=box.env())
            result = run(
                ["bash", str(PUSH_SAFE_SH), "--repo", str(box.repo), "origin", "main"],
                env=box.ssh_ready_env(),
            )
            # The sandbox has no network path to the file:// remote through a
            # real ssh transport, so the push itself may fail — but it must
            # fail *after* auth, never with BLOCKED for missing auth.
            self.assertNotIn("BLOCKED", result.stdout + result.stderr)
        finally:
            box.cleanup()

    @staticmethod
    def _bare_origin(box):
        origin = box.tmp / "origin.git"
        run(["git", "init", "--bare", str(origin)], env=box.env(), cwd=str(box.tmp))
        return origin


class TestStatus(GitAuthTestCase):
    def test_status_never_prints_token(self):
        box = Sandbox()
        try:
            result = run(
                ["bash", str(STATUS_SH)],
                env=box.no_auth_env({"GIT_AUTH_REPO": str(box.repo)}),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn(FAKE_URL_TOKEN, result.stdout + result.stderr)
            self.assertIn("[redacted]", result.stdout)
            self.assertIn("github.com/example-o/r-demo", result.stdout)
        finally:
            box.cleanup()


class TestIntegration(GitAuthTestCase):
    def test_promotion_calls_safe_push_wrapper(self):
        body = (PROMOTION_DIR / "promote.sh").read_text(encoding="utf-8")
        self.assertIn("push_safe.sh", body)
        code = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIsNone(re.search(r"\bgit(_main)?\s+push\b", code))

    def test_no_repository_writes(self):
        box = Sandbox()
        try:
            before = box.snapshot()
            run(["bash", str(STATUS_SH)],
                env=box.no_auth_env({"GIT_AUTH_REPO": str(box.repo)}))
            run([sys.executable, str(CHECK_AUTH_PY), "--repo", str(box.repo)],
                env=box.no_auth_env())
            run([sys.executable, str(CHECK_AUTH_PY), "--repo", str(box.repo), "--json"],
                env=box.no_auth_env())
            self.assertEqual(box.snapshot(), before)
        finally:
            box.cleanup()


if __name__ == "__main__":
    unittest.main()

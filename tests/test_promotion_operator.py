"""Tests for scripts/watch-agent/promotion/ (Epic 0.1: Autonomous Promotion Operator v1).

The promotion operator prepares branch delivery while keeping the main-branch
merge human-approved. Nothing here may merge, push, approve automatically, or
handle credentials.

Isolation: git-mutating tests build throwaway repos under TMPDIR (a bare
origin plus agent/main clones). The real worktree and production are never
touched — tests only read the real delivery scripts as programs.

Covered behaviors:
1.  request generation deterministic
2.  approval required before promotion
3.  wrong commit blocked
4.  missing delivery report blocked
5.  forbidden path blocked
6.  audit events append correctly
7.  no secrets written
8.  no git destructive commands allowed
9.  no automatic merge without approval
10. dry-run works
"""

from __future__ import annotations

import json
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
PROMOTION_DIR = REPO_ROOT / "scripts" / "watch-agent" / "promotion"
DELIVERY_DIR = REPO_ROOT / "scripts" / "watch-agent" / "delivery"

STATUS_SH = PROMOTION_DIR / "status.sh"
REQUEST_SH = PROMOTION_DIR / "request.sh"
APPROVE_SH = PROMOTION_DIR / "approve.sh"
PROMOTE_SH = PROMOTION_DIR / "promote.sh"
AUDIT_PY = PROMOTION_DIR / "audit.py"
TEMPLATE_MD = PROMOTION_DIR / "PROMOTION_REQUEST_TEMPLATE.md"

AGENT_BRANCH = "agent/daily-development"
MAIN_BRANCH = "main"
FIXED_NOW = "20260921-1200"

SECRET_PATTERNS = (
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bghp_[A-Za-z0-9]{20,}\b",
    r"mongodb(?:\+srv)?://[^:@\s/]+:[^@\s]+@",
    r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]",
)


def run(cmd, env=None, cwd=None, timeout=120):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=merged
    )


def git(repo, *args, env=None):
    result = run(["git", "-C", str(repo), *args], env=env)
    assert result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr}"
    return result.stdout.strip()


class TempRepos:
    """Throwaway origin + agent/main clones with local identity configured."""

    def __init__(self, test_case):
        self.test_case = test_case
        self.tmp = Path(tempfile.mkdtemp(prefix="promo-op-"))
        self.origin = self.tmp / "origin.git"
        self.agent = self.tmp / "agent"
        self.main = self.tmp / "main"
        self.out = self.tmp / "out"
        self.out.mkdir()

        run(["git", "init", "--bare", "-b", MAIN_BRANCH, str(self.origin)], cwd=str(self.tmp))
        for clone in (self.agent, self.main):
            run(["git", "clone", str(self.origin), str(clone)], cwd=str(self.tmp))
            git(clone, "config", "user.email", "promo-test@example.invalid")
            git(clone, "config", "user.name", "Promo Test")
        (self.main / "base.txt").write_text("base\n")
        git(self.main, "add", "base.txt")
        git(self.main, "commit", "-m", "base")
        git(self.main, "push", "origin", MAIN_BRANCH)
        git(self.agent, "fetch", "origin")
        git(self.agent, "checkout", "-b", AGENT_BRANCH, f"origin/{MAIN_BRANCH}")
        git(self.main, "fetch", "origin")

    def commit_agent_file(self, name, content, message):
        (self.agent / name).write_text(content)
        git(self.agent, "add", name)
        git(self.agent, "commit", "-m", message)
        # Mirror production: the agent branch is pushed before any promotion.
        git(self.agent, "push", "origin", AGENT_BRANCH)
        return git(self.agent, "rev-parse", "HEAD")

    def env(self, extra=None):
        base = {
            "PROMOTION_WORKTREE_ROOT": str(self.agent),
            "PROMOTION_OUTPUT_DIR": str(self.out),
            "PROMOTION_DELIVERY_DIR": str(DELIVERY_DIR),
            "PROMOTION_MAIN_CHECKOUT": str(self.main),
            "WATCH_AGENT_BRANCH": AGENT_BRANCH,
            "WATCH_MAIN_BRANCH": MAIN_BRANCH,
            "NO_COLOR": "1",
        }
        base.update(extra or {})
        return base

    def delivery_fixture(self, verdict="READY FOR PROMOTION"):
        path = self.out / "delivery-result.json"
        path.write_text(json.dumps({"verdict": verdict}) + "\n")
        return path

    def request_for(self, sha, now=None):
        if now is None:
            self._req_seq = getattr(self, "_req_seq", 0) + 1
            now = f"{FIXED_NOW}-{self._req_seq:02d}"
        env = self.env({"PROMOTION_NOW": now})
        result = run(
            [
                "bash", str(REQUEST_SH),
                "--delivery-result", str(self.delivery_fixture()),
                "--tests-summary", "15 tests, OK (fixture)",
            ],
            env=env,
        )
        assert result.returncode == 0, f"request.sh failed: {result.stderr}"
        matches = sorted(self.out.glob("PROMOTION-REQUEST-*.md"))
        assert matches, "request.sh created no request file"
        return matches[-1]

    def approve_for(self, request_path, operator="test-operator"):
        env = self.env({"PROMOTION_NOW": FIXED_NOW})
        result = run(
            [
                "bash", str(APPROVE_SH),
                "--request", str(request_path),
                "--operator", operator,
                "--confirm", "APPROVE",
            ],
            env=env,
        )
        assert result.returncode == 0, f"approve.sh failed: {result.stderr}"
        return Path(str(request_path) + ".approval.json")

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class PromotionOperatorTestCase(unittest.TestCase):
    def assert_blocked(self, result):
        self.assertNotEqual(result.returncode, 0, f"expected BLOCK, got rc=0: {result.stdout}")
        self.assertIn("BLOCK", result.stdout + result.stderr)


class TestRequestDeterminism(PromotionOperatorTestCase):
    def test_request_generation_deterministic(self):
        repos = TempRepos(self)
        try:
            repos.commit_agent_file("feature.txt", "feature work\n", "add feature")
            first = repos.request_for("HEAD", now=FIXED_NOW)
            first_bytes = first.read_bytes()
            for leftover in list(repos.out.glob("PROMOTION-REQUEST-*.md")):
                leftover.unlink()
            for leftover in list(repos.out.glob("AUDIT*")):
                leftover.unlink()
            second = repos.request_for("HEAD", now=FIXED_NOW)
            self.assertEqual(first_bytes, second.read_bytes())
            self.assertIn(b"No merge.", first_bytes)
            self.assertIn(b"No push.", first_bytes)
        finally:
            repos.cleanup()


class TestPromotionGates(PromotionOperatorTestCase):
    def setUp(self):
        self.repos = TempRepos(self)
        self.sha = self.repos.commit_agent_file("feature.txt", "feature work\n", "add feature")
        self.request = self.repos.request_for(self.sha)

    def tearDown(self):
        self.repos.cleanup()

    def promote(self, *args):
        return run(["bash", str(PROMOTE_SH), *args], env=self.repos.env())

    def test_approval_required_before_promotion(self):
        result = self.promote("--request", str(self.request), "--yes", "--dry-run")
        self.assert_blocked(result)
        self.assertIn("APPROVAL", result.stdout + result.stderr)

    def test_wrong_commit_blocked(self):
        self.repos.approve_for(self.request)
        self.repos.commit_agent_file("more.txt", "more work\n", "add more")
        result = self.promote(
            "--request", str(self.request), "--yes", "--dry-run",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assert_blocked(result)
        self.assertIn("COMMIT", result.stdout + result.stderr)

    def test_missing_delivery_report_blocked(self):
        self.repos.approve_for(self.request)
        env = self.repos.env()
        env["PROMOTION_DELIVERY_DIR"] = str(self.repos.tmp / "no-delivery-here")
        result = run(
            ["bash", str(PROMOTE_SH), "--request", str(self.request), "--yes", "--dry-run"],
            env=env,
        )
        self.assert_blocked(result)
        self.assertIn("DELIVERY", result.stdout + result.stderr)

    def test_forbidden_path_blocked(self):
        (self.repos.agent / "systemd").mkdir(exist_ok=True)
        bad_sha = self.repos.commit_agent_file(
            "systemd/evil.service", "[Unit]\n", "touch systemd"
        )
        bad_request = self.repos.request_for(bad_sha)
        self.repos.approve_for(bad_request)
        result = self.promote(
            "--request", str(bad_request), "--yes", "--dry-run",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assert_blocked(result)
        self.assertIn("FORBIDDEN", result.stdout + result.stderr)

    def test_no_automatic_merge_without_approval(self):
        before = git(self.repos.main, "rev-parse", "HEAD")
        result = self.promote(
            "--request", str(self.request), "--yes",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assert_blocked(result)
        self.assertEqual(git(self.repos.main, "rev-parse", "HEAD"), before)

    def test_no_merge_without_explicit_confirmation(self):
        self.repos.approve_for(self.request)
        before = git(self.repos.main, "rev-parse", "HEAD")
        result = self.promote(
            "--request", str(self.request), "--dry-run",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assert_blocked(result)
        self.assertIn("--yes", result.stdout + result.stderr)
        self.assertEqual(git(self.repos.main, "rev-parse", "HEAD"), before)

    def test_dry_run_works(self):
        self.repos.approve_for(self.request)
        audit_log = self.repos.out / "AUDIT.log"
        audit_before = audit_log.read_bytes() if audit_log.exists() else b""
        before = git(self.repos.main, "rev-parse", "HEAD")
        result = self.promote(
            "--request", str(self.request), "--yes", "--dry-run",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WOULD MERGE", result.stdout)
        self.assertEqual(git(self.repos.main, "rev-parse", "HEAD"), before)
        audit_after = audit_log.read_bytes() if audit_log.exists() else b""
        self.assertEqual(audit_before, audit_after)

    def test_approved_promotion_merges_in_temp_repos(self):
        self.repos.approve_for(self.request)
        result = self.promote(
            "--request", str(self.request), "--yes",
            "--delivery-result", str(self.repos.delivery_fixture()),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PROMOTION_COMPLETED", result.stdout)
        # HEAD is the new merge commit; the approved commit must be in main's
        # history (i.e. exactly what was approved is what landed).
        self.assertIn(
            self.sha, git(self.repos.main, "log", "--pretty=%H", MAIN_BRANCH)
        )


class TestAuditLog(PromotionOperatorTestCase):
    def test_audit_events_append_correctly(self):
        tmp = Path(tempfile.mkdtemp(prefix="promo-audit-"))
        try:
            log = tmp / "AUDIT.log"
            for event in (
                "PROMOTION_REQUESTED",
                "PROMOTION_APPROVED",
                "PROMOTION_BLOCKED",
                "PROMOTION_COMPLETED",
            ):
                result = run(
                    [
                        sys.executable, str(AUDIT_PY), "--log", str(log),
                        "record", "--event", event,
                        "--request", "PROMOTION-REQUEST-X.md",
                        "--commit", "abc123",
                        "--actor", "tester",
                        "--now", FIXED_NOW,
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            listed = run([sys.executable, str(AUDIT_PY), "--log", str(log), "list", "--json"])
            self.assertEqual(listed.returncode, 0, listed.stderr)
            events = [json.loads(line) for line in listed.stdout.splitlines() if line.strip()]
            self.assertEqual([e["seq"] for e in events], [1, 2, 3, 4])
            self.assertEqual(
                [e["event"] for e in events],
                ["PROMOTION_REQUESTED", "PROMOTION_APPROVED", "PROMOTION_BLOCKED", "PROMOTION_COMPLETED"],
            )
            verified = run([sys.executable, str(AUDIT_PY), "--log", str(log), "verify"])
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_audit_rejects_unknown_event(self):
        tmp = Path(tempfile.mkdtemp(prefix="promo-audit-"))
        try:
            result = run(
                [sys.executable, str(AUDIT_PY), "--log", str(tmp / "AUDIT.log"),
                 "record", "--event", "PROMOTION_SOMETHING_ELSE"]
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSafetyProperties(PromotionOperatorTestCase):
    def test_no_git_destructive_commands_allowed(self):
        bodies = {}
        for name in ("status.sh", "request.sh", "approve.sh", "promote.sh"):
            bodies[name] = (PROMOTION_DIR / name).read_text(encoding="utf-8")
        # Match actual git invocations, not prose disclaimers ("no push...").
        destructive = (
            r"\bgit\s+reset\b", r"\bgit\s+clean\b", r"\bgit\s+checkout\b",
            r"\bgit\s+rebase\b", r"--force\b", r"--no-verify\b",
        )
        for name, body in bodies.items():
            for pattern in destructive:
                self.assertIsNone(
                    re.search(pattern, body),
                    f"{name} must not contain destructive git: {pattern}",
                )
        for name in ("status.sh", "request.sh", "approve.sh"):
            for pattern in (r"\bgit\s+push\b", r"\bgit\s+merge\b"):
                self.assertIsNone(
                    re.search(pattern, bodies[name]), f"{name} must never push/merge"
                )

    def test_no_secrets_written(self):
        repos = TempRepos(self)
        try:
            sha = repos.commit_agent_file("feature.txt", "feature work\n", "add feature")
            request = repos.request_for(sha)
            repos.approve_for(request, operator="op-human")
            blobs = []
            for path in sorted(repos.out.iterdir()):
                blobs.append(path.read_bytes().decode("utf-8", "replace"))
            combined = "\n".join(blobs)
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(
                    re.search(pattern, combined), f"secret pattern leaked: {pattern}"
                )
            lowered = combined.lower()
            for word in ("password", "passwd", "api_key", "secret"):
                self.assertNotIn(word, lowered, f"credential word written: {word}")
        finally:
            repos.cleanup()

    def test_scripts_handle_no_credentials(self):
        # Match credential *handling* (flags, prompts, headers, assignments),
        # not prose disclaimers ("no password ... by design").
        handling = (
            r"--(password|passwd|token|secret|api-key)\b",
            r"\bgetpass\b",
            r"\bread\s+-s\b",
            r"\bAuthorization\s*:",
            r"\b[A-Za-z_]*(password|passwd|api_key|auth_token)\s*=\s*['\"]",
        )
        for name in ("status.sh", "request.sh", "approve.sh", "promote.sh", "audit.py"):
            body = (PROMOTION_DIR / name).read_text(encoding="utf-8")
            for pattern in handling:
                self.assertIsNone(
                    re.search(pattern, body, re.IGNORECASE),
                    f"{name} must not handle credentials: {pattern}",
                )

    def test_status_is_read_only(self):
        result = run(["bash", str(STATUS_SH)], env={
            "PROMOTION_WORKTREE_ROOT": str(REPO_ROOT),
            "PROMOTION_OUTPUT_DIR": str(REPO_ROOT / "agent-reports" / "promotions"),
            "NO_COLOR": "1",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(AGENT_BRANCH, result.stdout)


if __name__ == "__main__":
    unittest.main()

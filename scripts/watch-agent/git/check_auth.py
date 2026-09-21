#!/usr/bin/env python3
"""git/check_auth.py — Git authentication readiness checker (Epic 0.2).

Credentialless Git Operations v1: answer whether an authenticated Git
operation can proceed, without touching any credential.

Priority order (first available method wins):

1. Existing SSH authentication (``ssh -T git@github.com`` semantics)
2. A configured Git credential helper (plaintext ``store`` is rejected)
3. GitHub CLI authentication (``gh auth status``)

Output is ``READY`` (exit 0) or ``BLOCKED`` (exit 1) with closed-vocabulary
reasons: SSH_UNAVAILABLE, NO_CREDENTIAL_HELPER, GH_NOT_AUTHENTICATED,
REMOTE_UNREACHABLE.

Pure checker: reads ``git config`` and runs the ssh/gh probes. It never
prints secrets (only method names and reason codes), never writes a file,
never changes configuration, imports no network modules.

Test seam: GIT_AUTH_SSH / GIT_AUTH_GH override the probed binaries
(defaults ``ssh`` / ``gh``). Same code path, controlled binaries.

Usage:
  check_auth.py [--repo DIR] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

REASONS = (
    "SSH_UNAVAILABLE",
    "NO_CREDENTIAL_HELPER",
    "GH_NOT_AUTHENTICATED",
    "REMOTE_UNREACHABLE",
)

SSH_HOST = "git@github.com"
SSH_TIMEOUT = 8


def _git(repo: str | None, *args: str) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if repo:
        cmd += ["-C", repo]
    cmd += list(args)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(cmd, 127, "", "git invocation failed")


def _ssh_ok(ssh_bin: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [ssh_bin, "-T", "-o", "BatchMode=yes",
             "-o", f"ConnectTimeout={SSH_TIMEOUT}", SSH_HOST],
            capture_output=True, text=True, timeout=SSH_TIMEOUT + 5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"ssh probe failed: {error}"
    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 or "successfully authenticated" in combined:
        return True, "ssh authentication available"
    return False, f"ssh exited {result.returncode} without authentication"


def _helper_status(repo: str | None) -> tuple[bool, str, str]:
    result = _git(repo, "config", "--get", "credential.helper")
    helper = result.stdout.strip()
    if not helper:
        return False, "", "no credential helper configured"
    name = helper.split()[0]
    if name == "store" or helper.startswith("store "):
        return False, name, "plaintext store helper is not accepted"
    return True, name, f"credential helper configured: {name}"


def _gh_ok(gh_bin: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [gh_bin, "auth", "status"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"gh probe failed: {error}"
    if result.returncode == 0:
        return True, "github cli authenticated"
    return False, "github cli not authenticated"


def check(repo: str | None) -> dict:
    reasons: list[dict] = []
    ssh_bin = os.environ.get("GIT_AUTH_SSH", "ssh")
    gh_bin = os.environ.get("GIT_AUTH_GH", "gh")

    if repo and not os.path.isdir(os.path.join(repo, ".git")):
        return {
            "verdict": "BLOCKED",
            "method": "",
            "reasons": [{"code": "REMOTE_UNREACHABLE", "detail": "not a git repository"}],
        }
    origin = _git(repo, "config", "--get", "remote.origin.url").stdout.strip()
    if not origin:
        return {
            "verdict": "BLOCKED",
            "method": "",
            "reasons": [{"code": "REMOTE_UNREACHABLE", "detail": "no origin remote"}],
        }

    ok, detail = _ssh_ok(ssh_bin)
    if ok:
        return {"verdict": "READY", "method": "ssh", "reasons": []}
    reasons.append({"code": "SSH_UNAVAILABLE", "detail": detail})

    helper_ok, _name, helper_detail = _helper_status(repo)
    if helper_ok:
        return {"verdict": "READY", "method": "credential-helper", "reasons": []}
    reasons.append({"code": "NO_CREDENTIAL_HELPER", "detail": helper_detail})

    gh_ok, gh_detail = _gh_ok(gh_bin)
    if gh_ok:
        return {"verdict": "READY", "method": "github-cli", "reasons": []}
    reasons.append({"code": "GH_NOT_AUTHENTICATED", "detail": gh_detail})

    return {"verdict": "BLOCKED", "method": "", "reasons": reasons}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Git authentication readiness check")
    parser.add_argument("--repo", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = check(args.repo)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    elif report["verdict"] == "READY":
        print("READY")
        print(f"  method: {report['method']}")
    else:
        print("BLOCKED")
        for reason in report["reasons"]:
            print(f"  reason: {reason['code']} ({reason['detail']})")
    return 0 if report["verdict"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())

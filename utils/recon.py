"""Shared helpers for the vuln/recon heavy lanes (nuclei, secret, gau, ffuf).

Every external tool is invoked with an argv list (never shell=True) and wrapped
in coreutils `timeout -k 10 N` so a hung tool cannot run unbounded.
"""
import html
import os
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse

from database.db import Programs
from database.telegram import send_message
from utils.common import require_tools, tool_env

SEVERITY_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def env_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("", "0", "false", "no", "off")


def env_int(name, default):
    try:
        value = int(os.environ.get(name, ""))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


class Deadline:
    def __init__(self, max_minutes):
        self.end = time.monotonic() + max_minutes * 60 if max_minutes else None

    def expired(self):
        return self.end is not None and time.monotonic() >= self.end

    def remaining(self, cap):
        if self.end is None:
            return cap
        return max(0, min(cap, self.end - time.monotonic()))


def run_tool(argv, timeout_s, capture=False, quiet=False):
    """Run an allowlisted tool under coreutils timeout. Returns (rc, stdout)."""
    wrapped = ["timeout", "-k", "10", str(int(timeout_s)), *argv]
    try:
        proc = subprocess.run(
            wrapped,
            capture_output=capture,
            stdout=subprocess.DEVNULL if quiet and not capture else None,
            text=True,
            errors="replace",
            env=tool_env(),
            timeout=timeout_s + 30,
        )
        return proc.returncode, (proc.stdout if capture else "")
    except subprocess.TimeoutExpired:
        return 124, ""


def scope_index():
    """{program_name: (scopes, ooscopes)} for every program."""
    return {p.program_name: (list(p.scopes or []), list(p.ooscopes or [])) for p in Programs.objects()}


def _host_matches(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def in_scope(host, scopes, ooscopes):
    host = (host or "").strip().lower().rstrip(".")
    if not host or not scopes:
        return False
    if not _host_matches(host, [s.lower() for s in scopes]):
        return False
    return not _host_matches(host, [o.lower() for o in ooscopes])


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def severity_floor():
    value = os.environ.get("TELEGRAM_MIN_SEVERITY", "medium").strip().lower()
    return SEVERITY_RANK.get(value, SEVERITY_RANK["medium"])


def meets_floor(severity):
    return SEVERITY_RANK.get((severity or "unknown").lower(), 0) >= severity_floor()


def alert(text):
    send_message(html.escape(text))

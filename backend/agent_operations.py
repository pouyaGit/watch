"""backend/agent_operations.py — read-only agent workspace / operations data.

Backs the Command Center "Agent Operations" panel. It reports the real facts
about the autonomous development worktree (and the production checkout when no
worktree is present):

- the resolved workspace root and whether it is the agent worktree;
- the current Git branch, read directly from ``.git/HEAD`` (a normal checkout
  or a linked-worktree ``.git`` file are both handled);
- the persisted agent reports under ``agent-reports/*.md`` (metadata + the
  TASK/COMMIT STATUS/PUSH STATUS/READY TO PUSH fields already present in the
  existing report convention);
- a best-effort, read-only tmux server-socket probe.

READ-ONLY by construction: filesystem + Git metadata only. No subprocess, no
network, no Mongo, no LLM, no writes. Missing observability is reported as an
honest empty/unknown state and never invented.

The workspace is resolved from ``WATCH_AGENT_DIR`` (explicit override) else
``<project root>/.worktrees/watch-agent`` when it exists, else the project
root itself. This mirrors the operator helper scripts under
``scripts/watch-agent/`` and the documented two-workspace model.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AGENT_SUBDIR = Path(".worktrees") / "watch-agent"
REPORT_DIRNAME = "agent-reports"

MAX_REPORTS = 25
MAX_REPORT_ACTIVITY = 10
MAX_REPORT_BYTES = 200_000
MAX_EXCERPT = 240
MAX_TITLE = 160

AGENT_BRANCH_DEFAULT = "agent/daily-development"

_HEADING_RE = re.compile(r"^#\s+(.*\S)\s*$")
_NUMBERED_RE = re.compile(r"^\d+[\.\)]\s*")


def _text(value: object, limit: int = 320) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _canonical(path: object) -> Path:
    try:
        return Path(path).resolve()
    except OSError:
        return Path(path)


def agent_branch() -> str:
    """Expected agent branch (``WATCH_AGENT_BRANCH`` else the documented default)."""

    return _text(os.environ.get("WATCH_AGENT_BRANCH"), 96) or AGENT_BRANCH_DEFAULT


def agent_root() -> Path:
    """Resolve the agent workspace root deterministically (read-only)."""

    override = _text(os.environ.get("WATCH_AGENT_DIR"), 1024)
    if override:
        candidate = Path(override)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate
    worktree = PROJECT_ROOT / DEFAULT_AGENT_SUBDIR
    if worktree.is_dir():
        return worktree
    return PROJECT_ROOT


def _git_dir(root: Path) -> Path | None:
    """Return the Git directory for a checkout or linked worktree (or None)."""

    dot = root / ".git"
    try:
        if dot.is_dir():
            return dot
        if dot.is_file():
            raw = dot.read_text(encoding="utf-8", errors="replace").strip()
            if raw.startswith("gitdir:"):
                target = Path(raw.split(":", 1)[1].strip())
                if not target.is_absolute():
                    target = root / target
                return target if target.is_dir() else None
    except OSError:
        return None
    return None


def current_branch(root: object = None) -> str:
    """Current branch from ``.git/HEAD`` ("" when detached or unavailable)."""

    checkout = Path(root) if root is not None else agent_root()
    gitdir = _git_dir(checkout)
    if gitdir is None:
        return ""
    try:
        head = (gitdir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    if head.startswith("ref:"):
        ref = head[4:].strip()
        prefix = "refs/heads/"
        return ref[len(prefix):] if ref.startswith(prefix) else ref
    return ""


def workspace(root: object = None) -> dict:
    """Resolved workspace facts (mode, root, branch). Read-only."""

    resolved = _canonical(root if root is not None else agent_root())
    production = _canonical(PROJECT_ROOT)
    branch = current_branch(resolved)
    if resolved == production and branch == agent_branch():
        # The running checkout is itself on the agent branch (e.g. the API was
        # launched from the worktree): treat it as the agent workspace.
        mode = "AGENT"
    elif resolved == production:
        mode = "PRODUCTION"
    else:
        mode = "AGENT"
    return {
        "mode": mode,
        "root": str(resolved),
        "production_root": str(production),
        "branch": branch,
        "git": _git_dir(resolved) is not None,
        "is_worktree": resolved != production,
        "expected_branch": agent_branch(),
        "branch_ok": (not branch) or branch == agent_branch(),
    }


def reports_dir(root: object = None) -> Path:
    base = Path(root) if root is not None else agent_root()
    return base / REPORT_DIRNAME


def list_reports(root: object = None, *, limit: int = MAX_REPORTS) -> list[dict]:
    """Bounded newest-first agent report metadata (names only, no paths)."""

    directory = reports_dir(root)
    if not directory.is_dir():
        return []
    entries: list[tuple[float, str, int]] = []
    try:
        candidates = list(directory.iterdir())
    except OSError:
        return []
    for path in candidates:
        try:
            if not path.is_file() or path.suffix.lower() != ".md":
                continue
            stat = path.stat()
        except OSError:
            continue
        entries.append((stat.st_mtime, path.name, int(stat.st_size)))
    entries.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    out: list[dict] = []
    for mtime, name, size in entries[: max(limit, 0)]:
        out.append({
            "name": name,
            "title": name[:-3].replace("-", " ").strip() or name,
            "modified_at": datetime.fromtimestamp(mtime, tz=timezone.utc),
            "size_bytes": size,
        })
    return out


def _read_report(path: Path) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_REPORT_BYTES)
    except OSError:
        return ""


def _normalize_heading(line: str) -> str:
    heading = line.strip().lstrip("#").strip()
    return _NUMBERED_RE.sub("", heading).upper()


def _field(text: str, label: str) -> str:
    """First value for ``LABEL`` (inline ``LABEL: value`` or heading + value).

    Mirrors the operator helper convention in ``scripts/watch-agent/review.sh``
    without executing anything. An inline ``LABEL: value`` line always wins,
    so a ``## LABEL`` heading followed by a second ``LABEL: value`` line is
    parsed to just the value.
    """

    wanted = label.strip().upper()
    lines = text.splitlines()

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.upper().startswith(wanted + ":"):
            value = _text(stripped[len(wanted) + 1:])
            if value:
                return value

    for index, raw in enumerate(lines):
        if _normalize_heading(raw) == wanted:
            for nxt in lines[index + 1:]:
                value = nxt.strip().lstrip("#").strip()
                if value:
                    return _text(value)
    return ""


def _task_excerpt(text: str) -> str:
    lines = text.splitlines()
    start = 0
    for index, raw in enumerate(lines):
        if _normalize_heading(raw) == "TASK":
            start = index + 1
            break
    buffer: list[str] = []
    for raw in lines[start:]:
        stripped = raw.strip()
        if buffer and (stripped.startswith("#") or stripped.startswith("---")):
            break
        if stripped:
            buffer.append(stripped)
        if len(" ".join(buffer)) > MAX_EXCERPT:
            break
    return _text(" ".join(buffer), MAX_EXCERPT)


def latest_report(root: object = None) -> dict | None:
    """Newest agent report with its parsed fields (or None)."""

    reports = list_reports(root, limit=1)
    if not reports:
        return None
    entry = reports[0]
    path = reports_dir(root) / entry["name"]
    text = _read_report(path)
    title = ""
    for raw in text.splitlines():
        match = _HEADING_RE.match(raw)
        if match:
            title = _text(match.group(1), MAX_TITLE)
            break
    return {
        **entry,
        "title": title or entry["title"],
        "task": _task_excerpt(text),
        "ready_to_push": _field(text, "READY TO PUSH"),
        "commit_status": _field(text, "COMMIT STATUS"),
        "push_status": _field(text, "PUSH STATUS"),
    }


def recent_report_activity(
    root: object = None, *, limit: int = MAX_REPORT_ACTIVITY
) -> list[dict]:
    """Newest-first agent report activity, normalized to the timeline shape."""

    items: list[dict] = []
    for entry in list_reports(root, limit=limit):
        text = _read_report(reports_dir(root) / entry["name"])
        ready = _field(text, "READY TO PUSH")
        items.append({
            "kind": "AGENT_REPORT",
            "source": "Agent report",
            "title": entry["name"],
            "program": "",
            "ref": entry["name"],
            "status": _text(ready, 24) or "REPORT",
            "at": entry["modified_at"],
            "detail": _task_excerpt(text),
        })
    return items


def tmux_state() -> dict:
    """Best-effort read-only tmux server/socket probe (never spawns a process)."""

    session = _text(os.environ.get("WATCH_AGENT_TMUX_SESSION"), 64) or "watch-agent"
    getuid = getattr(os, "getuid", None)
    uid = getuid() if callable(getuid) else None
    if uid is None:
        return {
            "session": session,
            "server_present": None,
            "state": "UNKNOWN",
            "verified": False,
            "note": "tmux state is unavailable on this platform",
        }
    socket_dir = Path(f"/tmp/tmux-{uid}")
    present = False
    try:
        present = socket_dir.is_dir() and any(socket_dir.iterdir())
    except OSError:
        present = False
    return {
        "session": session,
        "server_present": bool(present),
        "state": "SERVER_PRESENT" if present else "SERVER_ABSENT",
        "verified": False,
        "note": (
            "session state is not persisted; only the tmux server socket is "
            "probed read-only"
        ),
    }


def agent_operations(
    root: object = None, *, report_limit: int = MAX_REPORTS
) -> dict:
    """Compose the bounded Agent Operations projection (read-only)."""

    facts = workspace(root)
    reports = list_reports(facts["root"], limit=report_limit)
    return {
        "available": bool(facts["git"]) or bool(reports),
        "mode": facts["mode"],
        "workspace": facts["root"],
        "production_root": facts["production_root"],
        "branch": facts["branch"],
        "expected_branch": facts["expected_branch"],
        "branch_ok": facts["branch_ok"],
        "is_worktree": facts["is_worktree"],
        "reports_available": bool(reports),
        "report_count": len(reports),
        "recent_reports": reports,
        "latest_report": latest_report(facts["root"]),
        "tmux": tmux_state(),
        "generated_from": "read-only filesystem + git metadata (no subprocess)",
    }


__all__ = [
    "PROJECT_ROOT",
    "DEFAULT_AGENT_SUBDIR",
    "REPORT_DIRNAME",
    "MAX_REPORTS",
    "AGENT_BRANCH_DEFAULT",
    "agent_branch",
    "agent_root",
    "current_branch",
    "workspace",
    "reports_dir",
    "list_reports",
    "latest_report",
    "recent_report_activity",
    "tmux_state",
    "agent_operations",
]

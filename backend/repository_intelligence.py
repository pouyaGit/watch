"""backend/repository_intelligence.py — read-only repository state intelligence.

Explains *why* a checkout is dirty instead of only reporting a raw dirty flag,
so the Command Center can categorize uncommitted work.

**No git command is ever executed.** The module reads Git's own on-disk
metadata read-only (``.git`` / ``HEAD`` and the binary index) plus the working
tree, and classifies the resulting change set deterministically. This keeps
the provider dependency-free and safe to call from a request handler.

Change detection:

- Every path recorded in the Git index is stat-comparison checked against the
  working tree: a missing file is ``deleted_files``; a size or mtime difference
  is a modification candidate, and the candidate is confirmed by computing the
  Git blob SHA-1 and comparing it to the index digest (bounded by a hash
  budget). A same-size/same-mtime file is assumed unchanged, matching Git's
  stat-cache behavior.
- Untracked files are discovered by a bounded, deterministic working-tree walk
  that prunes ignored/vendor/runtime directories. Pruned runtime/ignored
  directories are reported as single bounded markers.

Classification (deterministic, path based):

- ``source_changes``      -- source/tests/docs/config files.
- ``generated_knowledge`` -- the ``ai_data/knowledge/`` SHA-256 content store.
- ``agent_reports``       -- ``agent-reports/`` task/review reports.
- ``runtime_artifacts``   -- generated runtime output/locks/temp files.
- ``ignored_artifacts``   -- ignored vendor/env/IDE/cache paths.
- ``deleted_files``       -- tracked paths missing from the working tree.
- ``unknown_changes``     -- anything not covered above.

Read-only: no writes, no network, no LLM, no subprocess, no git invocation.
Missing index / unreadable paths degrade to an honest, bounded result and are
never invented.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CATEGORIES: tuple[str, ...] = (
    "source_changes",
    "generated_knowledge",
    "agent_reports",
    "runtime_artifacts",
    "ignored_artifacts",
    "deleted_files",
    "unknown_changes",
)

#: Hard bounds so a large checkout can never produce an unbounded payload.
DISPLAY_LIMIT = 60
MAX_FILES_VISITED = 20000
MAX_MARKERS = 30
HASH_BUDGET_BYTES = 64 * 1024 * 1024

_AGENT_REPORT_PREFIX = "agent-reports/"
_GENERATED_KNOWLEDGE_PREFIX = "ai_data/knowledge/"

#: Runtime output roots. Presence is reported as a single marker; the walk
#: never descends into them.
_RUNTIME_DIR_PREFIXES: tuple[str, ...] = (
    "ai_data/research",
    "ai_data/raw",
    "ai_data/cve",
    "crawl/output",
    "dns-bruteforce/work",
    "logs",
    "programs",
    "build",
    "dist",
    "htmlcov",
    "temp",
)

#: Directories silently skipped (caches; never reported as artifacts).
_SILENT_SKIP_DIR_NAMES: frozenset[str] = frozenset({
    ".git", ".worktrees", "__pycache__", ".mypy_cache", ".ruff_cache",
    ".pytest_cache",
})

#: Housekeeping/vendor directories reported once as ignored artifacts.
_IGNORED_DIR_NAMES: frozenset[str] = frozenset({
    "venv", "env", "ENV", "node_modules", ".vscode", ".idea", ".eggs",
})

_RUNTIME_SUFFIXES: tuple[str, ...] = (
    ".lock", ".tmp", ".log", ".db", ".sqlite3", ".pyc", ".pyo", ".bak",
    ".orig", ".rej", ".swp", ".swo",
)

_SOURCE_PREFIXES: tuple[str, ...] = (
    "backend/", "ai/", "web/", "tests/", "scripts/", "docs/", "database/",
    "systemd/", "utils/", "clients/", "enum/", "http/", "nuclei/", "ns/",
    "crawl/", "wordlists/",
)

_SOURCE_SUFFIXES: tuple[str, ...] = (
    ".py", ".html", ".css", ".js", ".sh", ".md", ".txt", ".json", ".toml",
    ".cfg", ".ini", ".yaml", ".yml", ".sql",
)

#: Ignored-but-tracked exceptions that are still source.
_SOURCE_EXCEPTIONS: frozenset[str] = frozenset({
    "programs/watch_sync_programs.py", "programs/test_program.json",
    ".env.example",
})

_IGNORED_FILE_NAMES: frozenset[str] = frozenset({
    "domains.txt", "resolvers.txt", "resume.cfg", ".DS_Store", "Thumbs.db",
})

INDEX_HEADER = b"DIRC"


def _text(value: object, limit: int = 320) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _posix(path: object) -> str:
    return str(path).replace("\\", "/")


# ---------------------------------------------------------------------------
# Path classification (deterministic)
# ---------------------------------------------------------------------------


def _is_runtime(path: str) -> bool:
    normalized = path.rstrip("/")
    for prefix in _RUNTIME_DIR_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return True
    for name in normalized.split("/"):
        if name == "__pycache__":
            return True
    return normalized.endswith(_RUNTIME_SUFFIXES)


def _is_ignored(path: str) -> bool:
    normalized = path.rstrip("/")
    name = normalized.rsplit("/", 1)[-1]
    if normalized in _SOURCE_EXCEPTIONS:
        return False
    if name in _IGNORED_FILE_NAMES:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    if name in _IGNORED_DIR_NAMES:
        return True
    return name.endswith("~")


def classify_path(path: object) -> str:
    """Classify one repository path into a change category (deterministic)."""

    normalized = _posix(path).strip("/")
    if not normalized:
        return "unknown_changes"
    if normalized.startswith(_GENERATED_KNOWLEDGE_PREFIX):
        return "generated_knowledge"
    if normalized.startswith(_AGENT_REPORT_PREFIX):
        return "agent_reports"
    if normalized in _SOURCE_EXCEPTIONS:
        return "source_changes"
    if _is_ignored(normalized):
        return "ignored_artifacts"
    if _is_runtime(normalized):
        return "runtime_artifacts"
    for prefix in _SOURCE_PREFIXES:
        if normalized.startswith(prefix):
            return "source_changes"
    if "/" not in normalized:
        for suffix in _SOURCE_SUFFIXES:
            if normalized.endswith(suffix):
                return "source_changes"
    return "unknown_changes"


# ---------------------------------------------------------------------------
# Git metadata (read-only)
# ---------------------------------------------------------------------------


def resolve_git_dir(root: object) -> Path | None:
    """Return the Git directory for a checkout/worktree, or None."""

    base = Path(root)
    dot = base / ".git"
    try:
        if dot.is_dir():
            return dot
        if dot.is_file():
            for line in dot.read_text(encoding="utf-8",
                                      errors="replace").splitlines():
                if line.strip().startswith("gitdir:"):
                    target = Path(line.split(":", 1)[1].strip())
                    if not target.is_absolute():
                        target = base / target
                    return target if target.is_dir() else None
    except OSError:
        return None
    return None


def read_head(root: object) -> dict:
    """Branch / detached-HEAD facts from ``HEAD`` (no ref resolution)."""

    gitdir = resolve_git_dir(root)
    if gitdir is None:
        return {"branch": "", "detached": False, "head": ""}
    try:
        text = (gitdir / "HEAD").read_text(encoding="utf-8",
                                           errors="replace").strip()
    except OSError:
        return {"branch": "", "detached": False, "head": ""}
    if text.startswith("ref:"):
        ref = text[4:].strip()
        prefix = "refs/heads/"
        return {
            "branch": ref[len(prefix):] if ref.startswith(prefix) else ref,
            "detached": False,
            "head": "",
        }
    return {"branch": "", "detached": True, "head": _text(text, 40)}


def parse_index(index_path: object) -> dict | None:
    """Parse a Git index v2/v3 into ``path -> entry`` (None when unsupported).

    ``entry`` holds the stat cache fields and the staged blob sha1 needed for
    change detection. Index v4 (path compression) is not supported and returns
    ``None`` so the caller degrades to an untracked-only scan.
    """

    path = Path(index_path)
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 12 or data[:4] != INDEX_HEADER:
        return None
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3):
        return None
    out: dict[str, dict] = {}
    offset = 12
    for _ in range(count):
        start = offset
        if offset + 62 > len(data):
            break
        (ctime_s, ctime_ns, mtime_s, mtime_ns, dev, ino, mode, uid, gid,
         size) = struct.unpack(">10I", data[offset:offset + 40])
        sha = data[offset + 40:offset + 60].hex()
        flags = struct.unpack(">H", data[offset + 60:offset + 62])[0]
        name_length = flags & 0x0FFF
        cursor = offset + 62
        if flags & 0x4000 and version >= 3:
            cursor += 2  # extended flags
        if name_length < 0x0FFF:
            raw = data[cursor:cursor + name_length]
            name = raw.decode("utf-8", "surrogateescape")
        else:
            end = data.find(b"\x00", cursor)
            if end < 0:
                break
            name = data[cursor:end].decode("utf-8", "surrogateescape")
            name_length = end - cursor
        raw_length = 62 + name_length + 1
        if flags & 0x4000 and version >= 3:
            raw_length += 2
        entry_length = ((raw_length + 7) // 8) * 8
        offset = start + entry_length
        out[name] = {
            "mtime_s": mtime_s,
            "mtime_ns": mtime_ns,
            "size": size,
            "sha": sha,
            "mode": mode,
        }
    return out


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


def _blob_sha1(full_path: Path, size: int) -> str | None:
    """Git blob object id for a working-tree file (read-only)."""

    digest = hashlib.sha1()
    digest.update(b"blob " + str(int(size)).encode("ascii") + b"\x00")
    try:
        with open(full_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _tracked_changes(root: Path, tracked: dict, *,
                     hash_budget: int) -> dict:
    changes: dict[str, list] = {name: [] for name in CATEGORIES}
    remaining = int(hash_budget)
    for path in sorted(tracked):
        entry = tracked[path] or {}
        full = root / path
        try:
            stat = full.stat()
        except OSError:
            changes["deleted_files"].append(path)
            continue
        if not full.is_file():
            changes["deleted_files"].append(path)
            continue
        expected_size = int(entry.get("size", -1))
        expected_mtime = int(entry.get("mtime_s", -1))
        modified = False
        if expected_size >= 0 and stat.st_size != expected_size:
            modified = True
        elif expected_mtime >= 0 and int(stat.st_mtime) != expected_mtime:
            staged_sha = entry.get("sha") or ""
            if staged_sha and remaining > 0:
                actual = _blob_sha1(full, stat.st_size)
                remaining -= stat.st_size
                if actual is None or actual != staged_sha:
                    modified = True
            else:
                modified = True
        if modified:
            changes[classify_path(path)].append(path)
    return changes


def _scan_untracked(root: Path, tracked_set: set, *,
                    max_files: int) -> tuple[list, list, list, bool, int]:
    """Bounded deterministic walk for untracked files + pruned markers."""

    untracked: list[str] = []
    ignored_markers: set[str] = set()
    runtime_markers: set[str] = set()
    state = {"visited": 0, "truncated": False}

    def walk(directory: Path, rel: str) -> None:
        if state["truncated"]:
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            return
        for entry in entries:
            name = entry.name
            rel_path = f"{rel}/{name}" if rel else name
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if name in _SILENT_SKIP_DIR_NAMES:
                    continue
                if _is_runtime(rel_path + "/"):
                    runtime_markers.add(rel_path + "/")
                    continue
                if name in _IGNORED_DIR_NAMES:
                    ignored_markers.add(rel_path + "/")
                    continue
                walk(Path(entry.path), rel_path)
                continue
            if name in (".git", ".worktrees"):
                continue
            state["visited"] += 1
            if state["visited"] > max_files:
                state["truncated"] = True
                return
            if rel_path in tracked_set:
                continue
            untracked.append(rel_path)

    walk(root, "")
    return (untracked, sorted(ignored_markers), sorted(runtime_markers),
            state["truncated"], state["visited"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _risk(counts: dict, total: int) -> str:
    if total == 0:
        return "none"
    if counts.get("deleted_files") or counts.get("source_changes"):
        return "high"
    if counts.get("unknown_changes"):
        return "medium"
    return "low"


def empty_payload(root: str) -> dict:
    return {
        "available": False,
        "root": root,
        "branch": "",
        "detached": False,
        "index_available": False,
        "summary": {
            "state": "unknown",
            "risk": "unknown",
            "total_changes": 0,
            "counts": {name: 0 for name in CATEGORIES},
            "truncated_categories": [],
        },
        "categories": {name: [] for name in CATEGORIES},
        "scan": {"files_visited": 0, "truncated": False,
                 "display_limit": DISPLAY_LIMIT},
        "generated_from": "read-only git index parse + bounded working-tree scan (no git invocation)",
    }


def analyze(
    root: object = None,
    *,
    tracked: dict | None = None,
    index_path: object = None,
    use_index: bool = True,
    max_files: int = MAX_FILES_VISITED,
    hash_budget: int = HASH_BUDGET_BYTES,
) -> dict:
    """Classify repository state read-only and deterministically.

    ``tracked`` may be supplied directly (tests/fixtures); otherwise the Git
    index under ``root`` is parsed. When neither is available the result is an
    untracked-only scan with ``index_available: false``. Never raises.
    """

    base = Path(root) if root is not None else PROJECT_ROOT
    try:
        base = base.resolve()
    except OSError:
        pass
    if not base.is_dir():
        return empty_payload(str(base))

    try:
        return _analyze(base, tracked=tracked, index_path=index_path,
                        use_index=use_index, max_files=max_files,
                        hash_budget=hash_budget)
    except Exception:
        return empty_payload(str(base))


def _analyze(base: Path, *, tracked, index_path, use_index, max_files,
             hash_budget) -> dict:
    gitdir = resolve_git_dir(base)
    head = read_head(base)

    index_available = tracked is not None
    tracked_map: dict = dict(tracked or {})
    if tracked is None and use_index:
        candidate = (Path(index_path) if index_path is not None
                     else (gitdir / "index" if gitdir is not None else None))
        if candidate is not None:
            parsed = parse_index(candidate)
            if parsed is not None:
                tracked_map = parsed
                index_available = True

    tracked_set = set(tracked_map)
    changes = _tracked_changes(base, tracked_map, hash_budget=hash_budget)
    untracked, ignored_markers, runtime_markers, truncated, visited = (
        _scan_untracked(base, tracked_set, max_files=max_files)
    )
    for path in untracked:
        changes[classify_path(path)].append(path)
    for marker in runtime_markers[:MAX_MARKERS]:
        changes["runtime_artifacts"].append(marker)
    for marker in ignored_markers[:MAX_MARKERS]:
        changes["ignored_artifacts"].append(marker)

    categories: dict[str, list] = {}
    counts: dict[str, int] = {}
    truncated_categories: list[str] = []
    for name in CATEGORIES:
        items = sorted({path for path in changes.get(name, []) if path})
        counts[name] = len(items)
        if len(items) > DISPLAY_LIMIT:
            truncated_categories.append(name)
            items = items[:DISPLAY_LIMIT]
        categories[name] = items

    total = sum(counts.values())
    return {
        "available": True,
        "root": str(base),
        "branch": head.get("branch") or "",
        "detached": bool(head.get("detached")),
        "index_available": index_available,
        "summary": {
            "state": "clean" if total == 0 else "dirty",
            "risk": _risk(counts, total),
            "total_changes": total,
            "counts": counts,
            "truncated_categories": truncated_categories,
        },
        "categories": categories,
        "scan": {
            "files_visited": visited,
            "truncated": truncated,
            "display_limit": DISPLAY_LIMIT,
        },
        "generated_from": "read-only git index parse + bounded working-tree scan (no git invocation)",
    }


__all__ = [
    "PROJECT_ROOT",
    "CATEGORIES",
    "DISPLAY_LIMIT",
    "classify_path",
    "resolve_git_dir",
    "read_head",
    "parse_index",
    "empty_payload",
    "analyze",
]

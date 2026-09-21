#!/usr/bin/env python3
"""AEC-1 read-only boundary checker (S1 — "pin the hashes before writing code").

AEC-1 is additive: it never edits the authority chain, the executors, the
verification gates, the protected subsystems or the systemd units. Saying that in
a document is not a control. This checker makes it mechanical:

1. **Pinned hashes** — ``aec/readonly_manifest.json`` records the sha256 of every
   file in the read-only contract. Any drift is a violation.
2. **Changed-path scope** — every path git reports as changed is classified. A
   change inside the read-only contract is a violation; anything else is counted
   as unrelated work in progress.

It is deliberately **read-only**: it never stages, commits, pushes, checks out,
cleans, or writes anything unless explicitly asked to regenerate the manifest
with ``--generate``.

Exit codes: ``0`` clean · ``1`` violations · ``2`` usage error.

Scope (the §3.1 contract, restated here as the single source of truth — the guard
test asserts this stays a superset of the contract):

* whole subtrees: ``ai/authorizer``, ``ai/evidence``, ``ai/execution``,
  ``ai/finding``, ``ai/limits``, ``ai/live_validation``, ``ai/persistence``,
  ``ai/scope``, ``ai/verification``, ``crawl``, ``database``, ``nuclei``, ``ns``,
  ``systemd``
* single entry points: the two frozen schemas, the task runner/registry, the
  pipeline shell entry points and the XSS verifier.

``.env`` is **not** hashed and is never read: only its key names may be
referenced. ``aec/`` itself is excluded — it is the one place AEC-1 may write.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

RULE_VERSION = "aec-readonly/v1"
MANIFEST_RELATIVE = "aec/readonly_manifest.json"

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

#: Paths the manifest must never pin (state, output, credentials, our own code).
EXCLUDED = (
    ".env (credentials: never read, never hashed — only key names may be referenced)",
    "aec/ (AEC-1's own package — the one place this phase may write)",
    "tests/ (test code changes with every task)",
    "agent-reports/ and ai_data/ (generated artifacts, not contract)",
    "__pycache__/ and *.pyc (build noise)",
)

SKIP_DIR_NAMES = {"__pycache__", ".git", "node_modules", ".mypy_cache"}

KIND_HASH_DRIFT = "HASH_DRIFT"
KIND_MISSING = "MISSING"
KIND_SCOPE_DRIFT = "READ_ONLY_DRIFT"


# --------------------------------------------------------------------------
# Scope + hashing
# --------------------------------------------------------------------------


def area_for(relative: str) -> str:
    for directory in READONLY_DIRS:
        if relative.startswith(directory + "/"):
            return directory
    return "entry-point"


def scope_paths(root: Path) -> list[str]:
    """Every file in the read-only contract, sorted, repo-relative."""
    found: set = set()
    for directory in READONLY_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_dir() or any(part in SKIP_DIR_NAMES for part in path.parts):
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            found.add(path.relative_to(root).as_posix())
    for relative in READONLY_FILES:
        if (root / relative).is_file():
            found.add(relative)
    return sorted(found)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    commit = "unknown"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            commit = result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        pass
    files = [
        {"path": relative, "sha256": sha256_of(root / relative), "area": area_for(relative)}
        for relative in scope_paths(root)
    ]
    return {
        "rule_version": RULE_VERSION,
        "generated_from_commit": commit,
        "generated_by": "scripts/check_aec_readonly.py --generate",
        "excluded": list(EXCLUDED),
        "scope_dirs": list(READONLY_DIRS),
        "scope_files": list(READONLY_FILES),
        "count": len(files),
        "files": files,
    }


# --------------------------------------------------------------------------
# Changed-path parsing
# --------------------------------------------------------------------------


def git_changed_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git status failed: {result.stderr.strip()}")
    return parse_porcelain(result.stdout)


def parse_porcelain(text: str) -> list[str]:
    """Repo-relative paths out of ``git status --porcelain`` output."""
    paths: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        payload = line[3:] if len(line) > 3 else ""
        if " -> " in payload:
            payload = payload.split(" -> ", 1)[1]
        payload = payload.strip().strip('"')
        if payload:
            paths.append(payload)
    return paths


_PORCELAIN_LINE_RE = re.compile(r"^(?:\?\?|!!|[MADRCU][ MADRCU?!]?)\s+(.+)$")


def read_paths_file(path: Path) -> list[str]:
    """Accept either bare paths or ``git status --porcelain`` lines.

    A porcelain line looks like ``" M ai/execution/http_executor.py"`` or
    ``"?? ai/verification/new_gate.py"``; anything else is taken as a bare path.
    Both forms appear in review notes, so both are handled.
    """
    paths: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _PORCELAIN_LINE_RE.match(line.strip())
        if match:
            payload = match.group(1)
            if " -> " in payload:
                payload = payload.split(" -> ", 1)[1]
            candidate = payload.strip().strip('"')
        else:
            candidate = line.strip().strip('"')
        if candidate:
            paths.append(candidate)
    return paths


def in_readonly_scope(relative: str) -> bool:
    for directory in READONLY_DIRS:
        if relative == directory or relative.startswith(directory + "/"):
            return True
    return relative in set(READONLY_FILES)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify(root: Path, manifest: dict, changed: list[str]) -> dict:
    violations: list[dict] = []
    pinned = manifest.get("files", [])

    for entry in pinned:
        relative = entry["path"]
        path = root / relative
        if not path.is_file():
            violations.append({"path": relative, "kind": KIND_MISSING, "detail": "pinned file is gone"})
            continue
        actual = sha256_of(path)
        if actual != entry["sha256"]:
            violations.append(
                {
                    "path": relative,
                    "kind": KIND_HASH_DRIFT,
                    "detail": f"pinned {entry['sha256'][:12]}… now {actual[:12]}…",
                }
            )

    unrelated = 0
    seen: set = set()
    for relative in changed:
        if relative in seen:
            continue
        seen.add(relative)
        if in_readonly_scope(relative):
            violations.append(
                {
                    "path": relative,
                    "kind": KIND_SCOPE_DRIFT,
                    "detail": "path belongs to the read-only contract",
                }
            )
        else:
            unrelated += 1

    violations.sort(key=lambda item: (item["kind"], item["path"]))
    return {
        "rule_version": manifest.get("rule_version", RULE_VERSION),
        "pinned": len(pinned),
        "checked_paths": len(seen),
        "unrelated_dirty": unrelated,
        "violations": violations,
        "verdict": "CLEAN" if not violations else "VIOLATION",
    }


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def render_human(report: dict, manifest_path: Path) -> str:
    lines = [
        "AEC-1 read-only boundary check",
        f"  rule version   : {report['rule_version']}",
        f"  manifest       : {manifest_path}",
        f"  pinned files   : {report['pinned']}",
        f"  changed paths  : {report['checked_paths']} "
        f"({report['unrelated_dirty']} unrelated, informational)",
    ]
    if report["verdict"] == "CLEAN":
        lines.append("")
        lines.append("READ-ONLY VERIFIED — no pinned file drifted, no read-only path changed")
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append(f"VIOLATION(S) FOUND: {len(report['violations'])}")
    for item in report["violations"]:
        lines.append(f"  - [{item['kind']}] {item['path']} — {item['detail']}")
    lines.append("")
    lines.append("This is fail-closed: AEC-1 must not continue until the drift is explained.")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AEC-1 read-only boundary checker")
    parser.add_argument("--root", default=None, help="repository root (default: this script's parent)")
    parser.add_argument("--manifest", default=None, help=f"manifest path (default: {MANIFEST_RELATIVE})")
    parser.add_argument("--paths-file", default=None, help="read changed paths from a file instead of git")
    parser.add_argument("--generate", action="store_true", help="regenerate the manifest and exit")
    parser.add_argument("--json", action="store_true", help="machine-readable output only")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    manifest_path = Path(args.manifest) if args.manifest else root / MANIFEST_RELATIVE

    if args.generate:
        manifest = build_manifest(root)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps({"generated": str(manifest_path), "count": manifest["count"]}, sort_keys=True))
        else:
            print(f"wrote {manifest_path} ({manifest['count']} pinned files, commit {manifest['generated_from_commit']})")
        return 0

    if not manifest_path.is_file():
        print(f"FAIL: manifest not found at {manifest_path}; run --generate first", file=sys.stderr)
        return 1
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as error:
        print(f"FAIL: manifest is not valid JSON: {error}", file=sys.stderr)
        return 1

    try:
        changed = read_paths_file(Path(args.paths_file)) if args.paths_file else git_changed_paths(root)
    except (OSError, RuntimeError) as error:
        print(f"FAIL: cannot determine changed paths: {error}", file=sys.stderr)
        return 1

    report = verify(root, manifest, changed)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        sys.stdout.write(render_human(report, manifest_path))
    return 0 if report["verdict"] == "CLEAN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
